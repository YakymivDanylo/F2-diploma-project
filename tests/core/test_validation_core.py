from __future__ import annotations

import time
from dataclasses import replace

import pytest

from blockchain_core.block import Block, attach_proposer_signature, build_candidate_block
from blockchain_core.document_record import create_document_record
from blockchain_core.genesis import build_genesis_block
from blockchain_core.hashing import sha256_hex, sha256_of_canonical
from blockchain_core.keys import generate_keypair
from blockchain_core.merkle import build_root
from blockchain_core.validation import (
  InvalidChainInputError,
  ValidationResult,
  pow_target,
  validate_chain,
)

_ISSUER = generate_keypair()
_ISSUER_ID = "issuer-1"
_NODE = generate_keypair()
_NODE_ID = "node-1"
_OTHER = generate_keypair()
_BASE_TS = 1_700_000_001_000
_STEP = 1_000


def _resolve_issuer_key(issuer_id: str, at_timestamp: int):
  if issuer_id == _ISSUER_ID:
    return _ISSUER.public_key
  return None


def _resolve_node_key(node_id: str, at_timestamp: int):
  if node_id == _NODE_ID:
    return _NODE.public_key
  return None


def _record(seed: int):
  return create_document_record(
    document_hash=sha256_hex(f"document-{seed}".encode()),
    issuer_id=_ISSUER_ID,
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed},
    issuer_private_key=_ISSUER.private_key,
  )


def _signed_block(
  *,
  previous_hash: str,
  index: int,
  timestamp: int,
  seed: int,
  node_key=None,
  proposer_id: str = _NODE_ID,
) -> Block:
  block = build_candidate_block(
    [_record(seed)],
    previous_hash=previous_hash,
    index=index,
    timestamp=timestamp,
    proposer_id=proposer_id,
    algorithm="pow",
    sealed_consensus={"nonce": 0, "difficulty": 1},
    resolve_issuer_key=_resolve_issuer_key,
  )
  return attach_proposer_signature(_mine(block), (node_key or _NODE).private_key)


def _chain_from_specs(specs, *, node_keys=None) -> list[Block]:
  """specs: list of (index, timestamp) for blocks after genesis; re-links each block
  to the previous block's real hash and signs it, so only the spec can be 'wrong'."""
  blocks = [build_genesis_block()]
  for position, (index, timestamp) in enumerate(specs, start=1):
    node_key = node_keys[position - 1] if node_keys else None
    blocks.append(
      _signed_block(
        previous_hash=blocks[-1].block_hash,
        index=index,
        timestamp=timestamp,
        seed=position,
        node_key=node_key,
      )
    )
  return blocks


def _valid_chain(length: int) -> list[Block]:
  """Genesis plus `length` signed blocks."""
  return _chain_from_specs([(i, _BASE_TS + i * _STEP) for i in range(1, length + 1)])


def _validate(blocks, **overrides):
  kwargs = {
    "resolve_node_key": _resolve_node_key,
    "resolve_issuer_key": _resolve_issuer_key,
    "expected_difficulty": 1,
    "validator_set": None,
  }
  kwargs.update(overrides)
  return validate_chain(blocks, **kwargs)


def _rehash(block: Block, **changes) -> Block:
  """Self-consistent tampering: change fields, recompute block_hash, keep old signature."""
  changed = replace(block, **changes)
  return replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))


def _mine(block: Block) -> Block:
  """Search `nonce` until block_hash meets the declared difficulty's target."""
  difficulty = block.sealed_consensus["difficulty"]
  nonce = 0
  while int(block.block_hash, 16) >= pow_target(difficulty):
    nonce += 1
    block = _rehash(block, sealed_consensus={**block.sealed_consensus, "nonce": nonce})
  return block


def _reseal_with_records(block: Block, records) -> Block:
  """Replace records AND recompute merkle_root, hash, and node signature."""
  merkle_root = build_root(records)
  rebuilt = _rehash(block, document_records=tuple(records), merkle_root=merkle_root)
  return attach_proposer_signature(rebuilt, _NODE.private_key)


def _replace_at(blocks: list[Block], position: int, new_block: Block) -> list[Block]:
  result = list(blocks)
  result[position] = new_block
  return result


def _assert_invalid(result: ValidationResult, index: int, failure_type: str) -> None:
  assert result.valid is False
  assert result.first_invalid_index == index
  assert result.failure_type == failure_type


# TC-4.1, TC-4.5
def test_valid_signed_chain_validates():
  result = _validate(_valid_chain(5))

  assert result == ValidationResult(valid=True, first_invalid_index=None, failure_type=None)


def test_valid_chain_with_monotonic_non_decreasing_timestamps_validates():
  specs = [(1, _BASE_TS), (2, _BASE_TS), (3, _BASE_TS + _STEP)]

  assert _validate(_chain_from_specs(specs)).valid is True


# TC-4.11, TC-4.25
def test_genesis_only_chain_is_valid():
  result = _validate([build_genesis_block()])

  assert result.valid is True
  assert result.first_invalid_index is None
  assert result.failure_type is None


def test_result_is_a_frozen_dataclass():
  result = _validate([build_genesis_block()])

  with pytest.raises(AttributeError):
    result.valid = False  # type: ignore[misc]


# TC-4.24
def test_empty_chain_raises_invalid_chain_input_error():
  with pytest.raises(InvalidChainInputError):
    _validate([])


def test_invalid_chain_input_error_is_a_value_error():
  assert issubclass(InvalidChainInputError, ValueError)


# TC-4.3
def test_node_key_rotation_is_resolved_as_of_each_block_timestamp():
  rotation_ts = _BASE_TS + 2 * _STEP + 500

  def resolve_node_key(node_id: str, at_timestamp: int):
    if node_id != _NODE_ID:
      return None
    return _NODE.public_key if at_timestamp < rotation_ts else _OTHER.public_key

  specs = [(i, _BASE_TS + i * _STEP) for i in range(1, 5)]  # ts straddle rotation_ts
  keys = [_NODE, _NODE, _OTHER, _OTHER]
  blocks = _chain_from_specs(specs, node_keys=keys)

  assert _validate(blocks, resolve_node_key=resolve_node_key).valid is True


def test_block_signed_with_pre_rotation_key_after_rotation_fails_signature():
  rotation_ts = _BASE_TS + 2 * _STEP + 500

  def resolve_node_key(node_id: str, at_timestamp: int):
    if node_id != _NODE_ID:
      return None
    return _NODE.public_key if at_timestamp < rotation_ts else _OTHER.public_key

  specs = [(i, _BASE_TS + i * _STEP) for i in range(1, 5)]
  keys = [_NODE, _NODE, _OTHER, _NODE]  # block 4 uses the retired key
  blocks = _chain_from_specs(specs, node_keys=keys)

  _assert_invalid(_validate(blocks, resolve_node_key=resolve_node_key), 4, "signature")


# TC-4.4, TC-4.20
def test_tampered_record_signature_with_resealed_block_fails_signature():
  blocks = _valid_chain(4)
  target = blocks[2]
  record = target.document_records[0]
  other_sig = _record(999).signature
  forged = replace(record, signature=other_sig)
  tampered = _reseal_with_records(target, [forged])

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "signature")


def test_tampered_record_content_with_resealed_block_fails_signature():
  blocks = _valid_chain(4)
  target = blocks[3]
  record = target.document_records[0]
  forged = replace(record, metadata={"seed": "tampered"})
  tampered = _reseal_with_records(target, [forged])

  _assert_invalid(_validate(_replace_at(blocks, 3, tampered)), 3, "signature")


def test_missing_proposer_signature_fails_signature():
  blocks = _valid_chain(3)
  tampered = replace(blocks[2], proposer_signature=None)

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "signature")


# TC-4.28
def test_unknown_proposer_fails_closed_with_signature_failure():
  blocks = _valid_chain(3)

  result = _validate(blocks, resolve_node_key=lambda node_id, at_timestamp: None)

  _assert_invalid(result, 1, "signature")


def test_unknown_issuer_fails_closed_with_signature_failure():
  blocks = _valid_chain(3)

  result = _validate(blocks, resolve_issuer_key=lambda issuer_id, at_timestamp: None)

  _assert_invalid(result, 1, "signature")


# TC-4.13
def test_changed_merkle_root_without_rehash_fails_hash():
  blocks = _valid_chain(4)
  tampered = replace(blocks[2], merkle_root=sha256_hex(b"other-root"))

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "hash")


def test_changed_stored_block_hash_fails_hash():
  blocks = _valid_chain(4)
  tampered = replace(blocks[2], block_hash=sha256_hex(b"bogus"))

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "hash")


# TC-4.14
def test_wrong_previous_hash_with_consistent_block_hash_fails_link():
  blocks = _valid_chain(4)
  tampered = _rehash(blocks[2], previous_hash=sha256_hex(b"wrong-parent"))

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "link")


# TC-4.15
def test_swapped_records_with_untouched_hash_and_root_fail_merkle():
  blocks = _valid_chain(4)
  swapped = replace(blocks[2], document_records=(_record(777),))

  _assert_invalid(_validate(_replace_at(blocks, 2, swapped)), 2, "merkle")


def test_empty_records_on_non_genesis_block_fail_merkle():
  blocks = _valid_chain(4)
  emptied = replace(blocks[2], document_records=())

  _assert_invalid(_validate(_replace_at(blocks, 2, emptied)), 2, "merkle")


# TC-4.16, TC-4.17, TC-4.21
def test_duplicate_index_fails_structural():
  specs = [(1, _BASE_TS), (1, _BASE_TS + _STEP), (2, _BASE_TS + 2 * _STEP)]

  _assert_invalid(_validate(_chain_from_specs(specs)), 2, "structural")


def test_index_gap_fails_structural():
  specs = [(1, _BASE_TS), (3, _BASE_TS + _STEP), (4, _BASE_TS + 2 * _STEP)]

  _assert_invalid(_validate(_chain_from_specs(specs)), 2, "structural")


def test_decreasing_timestamp_fails_structural():
  specs = [(1, _BASE_TS + _STEP), (2, _BASE_TS), (3, _BASE_TS + 2 * _STEP)]

  _assert_invalid(_validate(_chain_from_specs(specs)), 2, "structural")


# TC-4.18
@pytest.mark.parametrize(
  "changes",
  [
    {"timestamp": _BASE_TS + 999_999},
    {"proposer_id": "node-unknown"},
  ],
  ids=["timestamp", "proposer_id"],
)
def test_tip_tamper_with_recomputed_hash_fails_signature(changes):
  blocks = _valid_chain(4)
  tampered = _rehash(blocks[-1], **changes)

  _assert_invalid(_validate(_replace_at(blocks, 4, tampered)), 4, "signature")


# TC-4.19
@pytest.mark.parametrize(
  "changes",
  [
    {"timestamp": _BASE_TS + 123_456},
    {"proposer_id": "node-unknown"},
  ],
  ids=["timestamp", "proposer_id"],
)
def test_middle_block_tamper_is_reported_at_that_block(changes):
  blocks = _valid_chain(6)
  tampered = _rehash(blocks[3], **changes)

  result = _validate(_replace_at(blocks, 3, tampered))

  _assert_invalid(result, 3, "signature")


# modified genesis
@pytest.mark.parametrize(
  "tamper",
  [
    lambda g: replace(g, merkle_root=sha256_hex(b"x")),
    lambda g: _rehash(g, timestamp=g.timestamp + 1),
    lambda g: replace(g, block_hash=sha256_hex(b"fake-genesis")),
  ],
  ids=["merkle_root_no_rehash", "timestamp_rehashed", "block_hash_replaced"],
)
def test_modified_genesis_fails_hash_at_index_zero(tamper):
  blocks = _valid_chain(3)
  blocks[0] = tamper(blocks[0])

  _assert_invalid(_validate(blocks), 0, "hash")


# TC-4.26
def test_long_chain_of_300_blocks_validates_within_time_budget():
  blocks = _valid_chain(300)

  started = time.monotonic()
  result = _validate(blocks)
  elapsed = time.monotonic() - started

  assert result.valid is True
  assert elapsed < 30


# TC-4.27, TC-4.27b
@pytest.mark.parametrize("corrupt_index", [1, 40], ids=["first_after_genesis", "tip"])
def test_corruption_in_long_chain_reports_exact_index(corrupt_index):
  blocks = _valid_chain(40)
  tampered = replace(blocks[corrupt_index], merkle_root=sha256_hex(b"corrupt"))

  result = _validate(_replace_at(blocks, corrupt_index, tampered))

  _assert_invalid(result, corrupt_index, "hash")


def test_earliest_failing_block_is_reported_when_several_are_corrupt():
  blocks = _valid_chain(10)
  blocks = _replace_at(blocks, 7, replace(blocks[7], merkle_root=sha256_hex(b"late")))
  blocks = _replace_at(blocks, 3, replace(blocks[3], merkle_root=sha256_hex(b"early")))

  _assert_invalid(_validate(blocks), 3, "hash")
