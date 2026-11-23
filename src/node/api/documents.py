"""POST /documents (server-side issuer signing) and GET /documents/{hash}.

The client sends only {hash, metadata}; this node signs with its own institution's
IssuerKeyPair. Under PBFT a non-primary forwards the already-signed record to the primary
through the RecordForwarder and maps the reply to HTTP. The proposer never re-signs.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Annotated, Any

from fastapi import APIRouter, Path, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, ValidationError

from blockchain_core import build_proof, create_document_record
from blockchain_core.storage.chain_store import block_to_dict
from node.admission import is_known, mempool_full
from node.errors import ApiError
from node.forwarding import ForwardProtocolError, ForwardTimeout, ForwardUnavailable
from node.patterns import HASH_PATTERN
from node.schemas import Hash64, validate_metadata_size

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


class _DuplicateKeyError(ValueError):
  pass


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
  result: dict[str, Any] = {}
  for key, value in pairs:
    if key in result:  # last-wins would sign a value the client may not have meant
      raise _DuplicateKeyError(key)
    result[key] = value
  return result


def _body_error(error_type: str, message: str, loc: tuple[Any, ...] = ("body",)) -> Exception:
  return RequestValidationError([{"loc": loc, "msg": message, "type": error_type}])


def _is_json(content_type: str | None) -> bool:
  if content_type is None:
    return True  # like FastAPI: no header, try JSON
  media = content_type.split(";", 1)[0].strip().lower()
  main, _, sub = media.partition("/")
  return main == "application" and (sub == "json" or sub.endswith("+json"))


def parse_submit_body(raw: bytes, content_type: str | None) -> SubmitRequest:
  """Strict JSON: duplicate keys and nesting the decoder cannot handle are 422, never a
  silent last-wins value or a 500. The error shape matches FastAPI's body validation."""
  if not raw:
    raise _body_error("missing", "Field required")
  if not _is_json(content_type):
    raise _body_error("model_attributes_type", "Input should be a valid JSON object")
  try:
    data = json.loads(raw, object_pairs_hook=_unique_keys)
  except _DuplicateKeyError as exc:
    raise _body_error("duplicate_key", f"duplicate JSON key {exc.args[0]!r}") from None
  except RecursionError:
    raise _body_error("json_too_deep", "JSON is nested too deeply") from None
  except (ValueError, UnicodeDecodeError) as exc:
    raise _body_error("json_invalid", f"JSON decode error: {type(exc).__name__}") from None
  try:
    return SubmitRequest.model_validate(data)
  except ValidationError as exc:
    errors = [
      {"loc": ("body", *e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()
    ]
    raise RequestValidationError(errors) from None
  except RecursionError:
    raise _body_error("json_too_deep", "JSON is nested too deeply") from None


_SUBMIT_BODY_SCHEMA = {
  "requestBody": {
    "required": True,
    "content": {"application/json": {"schema": SubmitRequest.model_json_schema()}},
  }
}


@router.post(
  "/documents", status_code=202, response_model=SubmitAck, openapi_extra=_SUBMIT_BODY_SCHEMA
)
async def submit_document(request: Request) -> SubmitAck:
  body = parse_submit_body(await request.body(), request.headers.get("content-type"))
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
    if is_known(context, document_hash):
      raise _duplicate()
    if mempool_full(context):
      raise _retryable("mempool_full", "too many pending records, retry shortly")
    record = create_document_record(
      document_hash=document_hash,
      issuer_id=context.config.issuer_id,
      issued_at=int(time.time() * 1000),
      metadata=body.metadata,
      issuer_private_key=context.state.issuer_key.private_key,
    )
    if local and context.config.consensus_mode == "pbft":
      if context.primary_status().kind != "self":  # a view change began meanwhile
        raise _retryable("no_primary", "no primary is established, retry shortly")
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
    watch = getattr(request.app.state.engine, "watch_forwarded", None)
    if watch is not None:
      watch(document_hash, primary_id)  # a primary that accepts but never proposes

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
  chain_state = context.chain_state
  blocks = chain_state.blocks  # positions and blocks come from the same chain (no await between)
  indexes = chain_state.document_positions(document_hash)
  if not indexes:
    raise ApiError(404, "not_found", "no document with this hash has been issued")
  if len(indexes) > 1:  # never silently resolved to the earliest match
    raise ApiError(
      500,
      "chain_integrity_error",
      "the hash appears in more than one block",
      {"block_indexes": indexes},
    )
  block = blocks[indexes[0]]
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
