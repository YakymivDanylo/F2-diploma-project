"""POST /documents (server-side issuer signing) and GET /documents/{hash}.

The client sends only {hash, metadata}; this node signs with its own institution's
IssuerKeyPair. Under PBFT a non-primary forwards the already-signed record to the primary
through the RecordForwarder and maps the reply to HTTP. The proposer never re-signs.
"""

from __future__ import annotations

import logging
import time
from typing import Annotated, Any

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, ConfigDict

from blockchain_core import build_proof, create_document_record
from blockchain_core.storage.chain_store import block_to_dict
from node.errors import ApiError
from node.forwarding import ForwardProtocolError, ForwardTimeout, ForwardUnavailable
from node.schemas import HASH_PATTERN, Hash64, validate_metadata_size

logger = logging.getLogger("node.documents")
router = APIRouter()

RETRY_AFTER_SECONDS = "1"
_RETRY = {"Retry-After": RETRY_AFTER_SECONDS}


class SubmitRequest(BaseModel):
  # Unknown fields (signature, issuer_id, a pre-signed record shape) are rejected.
  model_config = ConfigDict(extra="forbid")

  hash: Hash64
  metadata: dict[str, Any]


class SubmitAck(BaseModel):
  status: str
  document_hash: str
  issuer_id: str
  issued_at: int


class ProofStepOut(BaseModel):
  position: str
  sibling_hash: str | None


class DocumentLookup(BaseModel):
  document_hash: str
  issuer_id: str
  issuer_name: str
  issued_at: int
  block_index: int
  chain_valid: bool  # verifiers must not trust a `found` result from an invalid chain
  merkle_root: str
  merkle_proof: list[ProofStepOut]
  record: dict[str, Any]  # the signed leaf content, so the proof is independently checkable


def _retryable(code: str, message: str) -> ApiError:
  return ApiError(503, code, message, headers=_RETRY)


def _duplicate() -> ApiError:
  return ApiError(409, "duplicate_hash", "this document hash is already issued or pending")


# Every reply of the closed enum has exactly one row; None means normal acknowledgement.
REPLY_TO_ERROR: dict[str, ApiError | None] = {
  "accepted": None,
  "duplicate": _duplicate(),
  "not_primary": _retryable("not_primary", "the contacted node is not the primary"),
  "unregistered_issuer": ApiError(403, "unregistered_issuer", "issuer is not registered"),
  "invalid_record": ApiError(422, "invalid_record", "the primary rejected the record"),
  "not_validator": ApiError(502, "not_validator", "forwarding rejected by the primary"),
  "auth_failed": ApiError(502, "auth_failed", "forwarding authentication failed"),
}


def _error_for(code: str) -> ApiError | None:
  error = REPLY_TO_ERROR[code]
  if error is None:
    return None
  return ApiError(error.status_code, error.code, error.message, headers=error.headers)


@router.post("/documents", status_code=202, response_model=SubmitAck)
async def submit_document(body: SubmitRequest, request: Request) -> SubmitAck:
  context = request.app.state.context
  if not request.app.state.accepting:
    raise _retryable("not_ready", "the node is starting up or shutting down")
  validate_metadata_size(body.metadata, context.config.max_metadata_bytes)
  if not context.validity_cache.snapshot.chain_valid:
    # An invalid chain cannot be extended: queueing would accept records that never land.
    raise _retryable("chain_invalid", "the local chain is invalid, see GET /node/info")

  local = True
  primary_id: str | None = None
  if context.config.consensus_mode == "pbft":
    status = context.primary_status()
    if status.kind == "none" or (status.kind == "other" and not status.node_id):
      # view change: no local queuing, no deferred processing
      raise _retryable("no_primary", "no primary is established, retry shortly")
    if status.kind == "other":
      local, primary_id = False, status.node_id

  document_hash = body.hash
  # Check -> sign -> queue is one critical section with no await inside, and the lock is
  # always released before awaiting the primary, so a slow forward never blocks others.
  async with context.submission_lock:
    if (
      context.documents.contains(document_hash)
      or context.mempool.contains(document_hash)
      or document_hash in context.inflight
    ):
      raise _duplicate()
    if len(context.mempool) + len(context.inflight) >= context.config.mempool_max_size:
      raise _retryable("mempool_full", "too many pending records, retry shortly")
    record = create_document_record(
      document_hash=document_hash,
      issuer_id=context.config.issuer_id,
      issued_at=int(time.time() * 1000),
      metadata=body.metadata,
      issuer_private_key=context.state.issuer_key.private_key,
    )
    if local:
      context.mempool.add(record)
      engine = request.app.state.engine
      if engine is not None:
        engine.on_submission(record)
    else:
      context.inflight.add(document_hash)  # same-hash submissions meanwhile get 409

  if not local:
    try:
      code = await context.forwarding.forward(record, primary_id or "")
    except ForwardTimeout:
      raise _retryable("forward_timeout", "the primary did not reply in time") from None
    except ForwardUnavailable:
      raise _retryable("forward_unavailable", "the primary is unreachable") from None
    except ForwardProtocolError:
      raise ApiError(502, "forward_protocol_error", "unexpected reply from the primary") from None
    except Exception as exc:  # transport errors must keep the retryable contract
      logger.warning("forward failed: %s", type(exc).__name__)  # never log the payload
      raise _retryable("forward_unavailable", "the primary is unreachable") from None
    finally:
      context.inflight.discard(document_hash)
    error = _error_for(code)
    if error is not None:
      raise error

  return SubmitAck(
    status="accepted",
    document_hash=record.document_hash,
    issuer_id=record.issuer_id,
    issued_at=record.issued_at,
  )


@router.get("/documents/{document_hash}", response_model=DocumentLookup)
async def get_document(
  request: Request,
  document_hash: Annotated[str, Path(pattern=HASH_PATTERN)],  # validated before any search
) -> DocumentLookup:
  context = request.app.state.context
  indexes = context.documents.block_indexes(document_hash)
  if not indexes:
    raise ApiError(404, "not_found", "no document with this hash has been issued")
  if len(indexes) > 1:  # never silently resolved to the earliest match
    raise ApiError(
      500,
      "chain_integrity_error",
      "the hash appears in more than one block",
      {"block_indexes": indexes},
    )
  block = context.current_blocks()[indexes[0]]
  matches = [r for r in block.document_records if r.document_hash == document_hash]
  if len(matches) != 1:  # stale index or a hash repeated inside one block
    raise ApiError(
      500,
      "chain_integrity_error",
      "the block does not contain the hash exactly once",
      {"block_indexes": [block.index], "occurrences": len(matches)},
    )
  record = matches[0]
  proof = build_proof(block.document_records, document_hash)
  return DocumentLookup(
    document_hash=record.document_hash,
    issuer_id=record.issuer_id,
    issuer_name=context.issuers.name_of(record.issuer_id),
    issued_at=record.issued_at,
    block_index=block.index,
    chain_valid=context.validity_cache.snapshot.chain_valid,
    merkle_root=block.merkle_root,
    merkle_proof=[ProofStepOut(position=s.position, sibling_hash=s.sibling_hash) for s in proof],
    record=next(
      d for d in block_to_dict(block)["document_records"] if d["document_hash"] == document_hash
    ),
  )
