from __future__ import annotations

from dataclasses import replace

import pytest

from blockchain_core.block import (
  Block,
  DuplicateDocumentHashError,
  EmptyBatchError,
  InvalidRecordSignatureError,
  attach_proposer_signature,
  build_candidate_block,
)
from blockchain_core.document_record import create_document_record
from blockchain_core.hashing import sha256_hex, sha256_of_canonical
from blockchain_core.keys import generate_keypair
from blockchain_core.merkle import build_root
from blockchain_core.signing import verify_canonical

_ISSUER = generate_keypair()
_ISSUER_ID = "issuer-1"


def _resolve_issuer_key(issuer_id: str):
  if issuer_id == _ISSUER_ID:
    return _ISSUER.public_key
  return None

def _record(seed: int):
  document_hash = sha256_hex(f"document-{seed}".encode())
  return create_document_record(
    document_hash=document_hash,
    issuer_id=_ISSUER_ID,
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed},
    issuer_private_key=_ISSUER.private_key,
  )

def _build(
  records,
  *,
  index=1,
  previous_hash="0" * 64,
  timestamp=1_700_000_000_000,
  proposer_id="node-1",
  algorithm="pow",
  sealed_consensus=None,
) -> Block:
  if sealed_consensus is None:
    sealed_consensus = {"nonce": 0, "difficulty": 1}
  return build_candidate_block(
    records,
    previous_hash=previous_hash,
    index=index,
    timestamp=timestamp,
    proposer_id=proposer_id,
    algorithm=algorithm,
    sealed_consensus=sealed_consensus,
    resolve_issuer_key=_resolve_issuer_key,
  )


def test_build_candidate_block_populates_preimage_and_block_hash():
  records = [_record(0), _record(1)]
  block = _build(records)

  assert block.index == 1
  assert block.previous_hash == "0" * 64
  assert block.proposer_id == "node-1"
  assert block.algorithm == "pow"
  assert block.merkle_root == build_root(records)
  assert block.document_records == tuple(records)
  assert block.block_hash == sha256_of_canonical(block.preimage_dict())
  assert block.proposer_signature is None
  assert block.commit_signatures == ()


def test_mutating_document_records_leaves_block_hash_unchanged_but_merkle_recompute_diverges():
  records = [_record(0), _record(1)]
  block = _build(records)

  mutated = replace(block, document_records=(*records, _record(2)))

  assert mutated.block_hash == block.block_hash
  assert build_root(mutated.document_records) != block.merkle_root


def test_build_candidate_block_rejects_empty_batch():
  with pytest.raises(EmptyBatchError):
    _build([])


def test_build_candidate_block_rejects_batch_with_bad_signature_and_names_the_index():
  good = _record(0)
  tampered = replace(_record(1), metadata={"tampered": True})

  with pytest.raises(InvalidRecordSignatureError) as excinfo:
    _build([good, tampered])

  assert excinfo.value.index == 1
  assert excinfo.value.document_hash == tampered.document_hash


def test_build_candidate_block_rejects_record_from_unresolvable_issuer():
  unknown_issuer_record = create_document_record(
    document_hash=sha256_hex(b"unknown-issuer-doc"),
    issuer_id="issuer-unknown",
    issued_at=1_700_000_000_000,
    metadata={},
    issuer_private_key=generate_keypair().private_key,
  )

  with pytest.raises(InvalidRecordSignatureError) as excinfo:
    _build([unknown_issuer_record])

  assert excinfo.value.index == 0


def test_build_candidate_block_rejects_duplicate_document_hash_within_batch():
  record = _record(0)
  duplicate = create_document_record(
    document_hash=record.document_hash,
    issuer_id=_ISSUER_ID,
    issued_at=record.issued_at,
    metadata={"different": True},
    issuer_private_key=_ISSUER.private_key,
  )

  with pytest.raises(DuplicateDocumentHashError) as excinfo:
    _build([record, duplicate])

  assert excinfo.value.document_hash == record.document_hash


def test_build_candidate_block_is_deterministic_for_identical_input():
  records = [_record(0), _record(1)]
  first = _build(records)
  second = _build(records)

  assert first.block_hash == second.block_hash
  assert first.merkle_root == second.merkle_root


def test_attach_proposer_signature_produces_a_verifiable_signature_over_the_preimage():
  node = generate_keypair()
  block = _build([_record(0)])

  attested = attach_proposer_signature(block, node.private_key)

  assert attested.proposer_signature is not None
  assert verify_canonical(
    node.public_key, attested.preimage_dict(), attested.proposer_signature,
  ) is True


def test_attach_proposer_signature_does_not_change_block_hash():
  node = generate_keypair()
  block = _build([_record(0)])

  attested = attach_proposer_signature(block, node.private_key)

  assert attested.block_hash == block.block_hash
  assert attested.document_records == block.document_records
