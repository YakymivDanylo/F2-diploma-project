"""Hardening tests: genesis pinning, validation totality, extension, chain races, block params."""
from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

import blockchain_core
from blockchain_core import chain as chain_module
from blockchain_core import genesis as genesis_module
from blockchain_core import validation as validation_module
from blockchain_core.block import (
  Block,
  DuplicateDocumentHashError,
  InvalidBlockParametersError,
  InvalidRecordSignatureError,
  attach_proposer_signature,
  build_candidate_block,
)
from blockchain_core.canonical import deep_freeze
from blockchain_core.chain import (
  Chain,
  InvalidBlockHashError,
  NonSequentialIndexError,
  StalePreviousHashError,
)
from blockchain_core.document_record import create_document_record
from blockchain_core.genesis import GENESIS_BLOCK_HASH, build_genesis_block
from blockchain_core.hashing import sha256_hex, sha256_of_canonical
from blockchain_core.keys import generate_keypair
from blockchain_core.merkle import build_root
from blockchain_core.validation import (
  ValidationResult,
  validate_chain,
  validate_extension,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC_DIR = _REPO_ROOT / "src"

_ISSUER = generate_keypair()
_ISSUER_ID = "issuer-1"
_NODE = generate_keypair()
_NODE_ID = "node-1"
_NODE2 = generate_keypair()
_NODE2_ID = "node-2"
_OTHER = generate_keypair()
_BASE_TS = 1_700_000_001_000
_STEP = 1_000


def _resolve_issuer_key(issuer_id: str, at_timestamp: int):
  return _ISSUER.public_key if issuer_id == _ISSUER_ID else None

def _resolve_node_key(node_id: str, at_timestamp: int):
  if node_id == _NODE_ID:
    return _NODE.public_key
  if node_id == _NODE2_ID:
    return _NODE2.public_key
  return None

def _record(seed: int, *, document_hash: str | None = None, key=None):
  return create_document_record(
    document_hash=document_hash or sha256_hex(f"document-{seed}".encode()),
    issuer_id=_ISSUER_ID,
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed},
    issuer_private_key=(key or _ISSUER).private_key,
  )

def _signed_block(
  *, previous_hash, index, timestamp, seed, node_key=None, proposer_id=_NODE_ID,
  records=None, algorithm="pow",
) -> Block:
  block = build_candidate_block(
    records or [_record(seed)],
    previous_hash=previous_hash,
    index=index,
    timestamp=timestamp,
    proposer_id=proposer_id,
    algorithm=algorithm,
    sealed_consensus={"nonce": 0, "difficulty": 1},
    resolve_issuer_key=_resolve_issuer_key,
  )
  return attach_proposer_signature(block, (node_key or _NODE).private_key)

def _valid_chain(length: int) -> list[Block]:
  blocks = [build_genesis_block()]
  for i in range(1, length + 1):
    blocks.append(_signed_block(
      previous_hash=blocks[-1].block_hash, index=i, timestamp=_BASE_TS + i * _STEP, seed=i))
  return blocks

def _validate(blocks, **overrides):
  kwargs = {"resolve_node_key": _resolve_node_key, "resolve_issuer_key": _resolve_issuer_key}
  kwargs.update(overrides)
  return validate_chain(blocks, **kwargs)

def _extend(tip, blocks, **overrides):
  kwargs = {"resolve_node_key": _resolve_node_key, "resolve_issuer_key": _resolve_issuer_key}
  kwargs.update(overrides)
  return validate_extension(tip, blocks, **kwargs)

def _rehash(block: Block, **changes) -> Block:
  changed = replace(block, **changes)
  return replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))

def _reseal_with_records(block: Block, records, key=None) -> Block:
  rebuilt = _rehash(block, document_records=tuple(records), merkle_root=build_root(records))
  return attach_proposer_signature(rebuilt, (key or _NODE).private_key)

def _replace_at(blocks, position, new_block):
  result = list(blocks)
  result[position] = new_block
  return result

def _assert_invalid(result, index, failure_type):
  assert result.valid is False
  assert result.first_invalid_index == index
  assert result.failure_type == failure_type


# ---------------------------------------------------------------- GENESIS

def test_genesis_block_hash_is_pinned_literal():
  """Changing any genesis constant is a breaking network change: every node must agree."""
  assert GENESIS_BLOCK_HASH == "45d36937b17fce502b979f6835e619bef367436b941d58b7e8e9c80d2b070c8a"

@pytest.mark.parametrize("seed", ["0", "1", "12345"])
def test_genesis_hash_is_independent_of_hash_seed(seed):
  env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(_SRC_DIR)}
  code = "from blockchain_core import GENESIS_BLOCK_HASH; print(GENESIS_BLOCK_HASH)"
  completed = subprocess.run(
    [sys.executable, "-c", code],
    cwd=_REPO_ROOT, env=env, capture_output=True, text=True, check=True, timeout=60,
  )

  assert completed.stdout.strip() == GENESIS_BLOCK_HASH

def test_genesis_with_altered_timestamp_constant_fails_hash_at_zero():
  assert genesis_module.GENESIS_TIMESTAMP_MS == build_genesis_block().timestamp
  altered = genesis_module.GENESIS_TIMESTAMP_MS + 1
  forged = replace(build_genesis_block(), timestamp=altered)
  forged = replace(forged, block_hash=sha256_of_canonical(forged.preimage_dict()))

  _assert_invalid(_validate([forged]), 0, "hash")

@pytest.mark.parametrize("field", ["document_records", "proposer_signature", "commit_signatures"])
def test_genesis_with_extra_fields_fails_hash_at_zero(field):
  value = {
    "document_records": (_record(1),),
    "proposer_signature": "ab" * 32,
    "commit_signatures": ("ab" * 32,),
  }[field]
  forged = replace(build_genesis_block(), **{field: value})

  _assert_invalid(_validate([forged]), 0, "hash")

def test_non_block_genesis_is_rejected_without_exception():
  _assert_invalid(_validate(["not a block"]), 0, "hash")
  _assert_invalid(_validate([None]), 0, "hash")

def test_non_block_later_element_is_structural():
  blocks = _valid_chain(2)

  _assert_invalid(_validate([blocks[0], blocks[1], "junk"]), 2, "structural")
  _assert_invalid(_validate([blocks[0], {"index": 1}]), 1, "structural")


# ---------------------------------------------------------------- VALIDATION: hostile input

@pytest.mark.parametrize("change", [
  {"timestamp": "x"},
  {"index": "1"},
  {"previous_hash": None},
  {"proposer_id": 123},
  {"merkle_root": 5},
  {"block_hash": None},
], ids=["timestamp", "index", "previous_hash", "proposer_id", "merkle_root", "block_hash"])
def test_wrong_field_types_are_structural_and_never_raise(change):
  blocks = _valid_chain(2)
  tampered = replace(blocks[1], **change)

  result = _validate(_replace_at(blocks, 1, tampered))

  assert isinstance(result, ValidationResult)
  _assert_invalid(result, 1, "structural")

def test_document_records_as_list_is_structural():
  blocks = _valid_chain(2)
  tampered = replace(blocks[1], document_records=list(blocks[1].document_records))

  _assert_invalid(_validate(_replace_at(blocks, 1, tampered)), 1, "structural")

def test_document_records_with_non_record_is_structural():
  blocks = _valid_chain(2)
  tampered = replace(blocks[1], document_records=("not a record",))

  _assert_invalid(_validate(_replace_at(blocks, 1, tampered)), 1, "structural")

def test_sealed_consensus_replaced_by_list_is_structural():
  blocks = _valid_chain(2)
  tampered = replace(blocks[1], sealed_consensus=[1, 2])

  _assert_invalid(_validate(_replace_at(blocks, 1, tampered)), 1, "structural")

def test_uncanonicalizable_record_metadata_returns_result_not_exception():
  blocks = _valid_chain(2)
  bad_record = replace(blocks[1].document_records[0])
  object.__setattr__(bad_record, "metadata", {"x": 1.5})
  tampered = replace(blocks[1], document_records=(bad_record,))

  result = _validate(_replace_at(blocks, 1, tampered))

  # hash/link pass (records are not in the preimage); the Merkle leaf cannot be encoded.
  _assert_invalid(result, 1, "merkle")

def test_uncanonicalizable_sealed_consensus_is_hash_failure():
  blocks = _valid_chain(2)
  tampered = replace(blocks[1], sealed_consensus={"x": 1.5})

  # preimage cannot be canonicalized -> recompute is None -> "hash", not an exception.
  _assert_invalid(_validate(_replace_at(blocks, 1, tampered)), 1, "hash")

def test_raising_node_resolver_is_signature_failure():
  def boom(identity, at_timestamp):
    raise RuntimeError("registry down")

  _assert_invalid(_validate(_valid_chain(2), resolve_node_key=boom), 1, "signature")

def test_raising_issuer_resolver_is_signature_failure():
  def boom(identity, at_timestamp):
    raise RuntimeError("registry down")

  _assert_invalid(_validate(_valid_chain(2), resolve_issuer_key=boom), 1, "signature")

@pytest.mark.parametrize("algorithm", ["foo", "POW"])
def test_unknown_algorithm_is_structural(algorithm):
  blocks = _valid_chain(2)
  tampered = _rehash(blocks[1], algorithm=algorithm)

  _assert_invalid(_validate(_replace_at(blocks, 1, tampered)), 1, "structural")

def test_genesis_algorithm_at_non_zero_position_is_structural():
  blocks = _valid_chain(2)
  tampered = _rehash(blocks[2], algorithm="genesis")

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "structural")

@pytest.mark.parametrize("bad_position", [1, 2], ids=["second_record", "third_record"])
def test_corrupt_signature_of_second_or_third_record_is_signature_failure(bad_position):
  blocks = _valid_chain(1)
  records = [_record(10), _record(11), _record(12)]
  multi = _signed_block(
    previous_hash=blocks[1].block_hash, index=2, timestamp=_BASE_TS + 2 * _STEP,
    seed=0, records=records)
  corrupted = list(records)
  corrupted[bad_position] = _record(10 + bad_position, key=_OTHER)
  resealed = _reseal_with_records(multi, corrupted)

  _assert_invalid(_validate([*blocks, resealed]), 2, "signature")

def test_valid_multi_record_block_validates():
  blocks = _valid_chain(1)
  multi = _signed_block(
    previous_hash=blocks[1].block_hash, index=2, timestamp=_BASE_TS + 2 * _STEP,
    seed=0, records=[_record(10), _record(11), _record(12)])

  assert _validate([*blocks, multi]).valid is True

def test_duplicate_document_hash_inside_block_is_structural():
  blocks = _valid_chain(1)
  first = _record(10)
  dup = _record(99, document_hash=first.document_hash)
  base = _signed_block(
    previous_hash=blocks[1].block_hash, index=2, timestamp=_BASE_TS + 2 * _STEP, seed=10)
  resealed = _reseal_with_records(base, [first, dup])

  _assert_invalid(_validate([*blocks, resealed]), 2, "structural")

def test_resolvers_receive_block_timestamp_and_proposer():
  node_calls, issuer_calls = [], []

  def node_resolver(identity, at_timestamp):
    node_calls.append((identity, at_timestamp))
    return _resolve_node_key(identity, at_timestamp)

  def issuer_resolver(identity, at_timestamp):
    issuer_calls.append((identity, at_timestamp))
    return _resolve_issuer_key(identity, at_timestamp)

  blocks = _valid_chain(2)
  result = _validate(blocks, resolve_node_key=node_resolver, resolve_issuer_key=issuer_resolver)

  assert result.valid is True
  assert node_calls == [(_NODE_ID, b.timestamp) for b in blocks[1:]]
  assert issuer_calls == [(_ISSUER_ID, b.timestamp) for b in blocks[1:]]

def test_rotation_boundary_resolves_per_resolver_rule():
  rotation = _BASE_TS + 2 * _STEP
  new_node = generate_keypair()

  def node_resolver(identity, at_timestamp):
    if identity != _NODE_ID:
      return None
    return new_node.public_key if at_timestamp >= rotation else _NODE.public_key

  blocks = _valid_chain(1)
  at_boundary = _signed_block(
    previous_hash=blocks[1].block_hash, index=2, timestamp=rotation, seed=2, node_key=new_node)
  before = _signed_block(
    previous_hash=blocks[1].block_hash, index=2, timestamp=rotation - 1, seed=2,
    node_key=new_node)

  assert _validate([*blocks, at_boundary], resolve_node_key=node_resolver).valid is True
  _assert_invalid(_validate([*blocks, before], resolve_node_key=node_resolver), 2, "signature")

def test_wrong_previous_hash_and_bad_signature_reports_link():
  blocks = _valid_chain(2)
  # rehash keeps the (now stale) signature, so both link and signature are wrong.
  tampered = _rehash(blocks[2], previous_hash=sha256_hex(b"elsewhere"))

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "link")

def test_self_consistent_merkle_change_reports_merkle_before_signature():
  blocks = _valid_chain(2)
  tampered = _rehash(blocks[2], merkle_root=sha256_hex(b"other root"))

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "merkle")

@pytest.mark.parametrize("position", [3, 2], ids=["tip", "middle"])
def test_tampered_index_with_recomputed_hash_is_signature_failure(position):
  blocks = _valid_chain(3)
  tampered = _rehash(blocks[position], index=position + 10)

  result = _validate(_replace_at(blocks, position, tampered))

  # Observed: hash, link and merkle pass; the stale proposer signature (it covers
  # `index`) is checked before the index/structure check -> "signature" at that position.
  _assert_invalid(result, position, "signature")

@pytest.mark.parametrize("position", [3, 2], ids=["tip", "middle"])
def test_tampered_previous_hash_with_recomputed_hash_is_link_failure(position):
  blocks = _valid_chain(3)
  tampered = _rehash(blocks[position], previous_hash=sha256_hex(b"nope"))

  # link is checked before signature, so the stale signature is not what is reported.
  _assert_invalid(_validate(_replace_at(blocks, position, tampered)), position, "link")

def test_proposer_repointed_to_another_known_node_is_signature_failure():
  blocks = _valid_chain(2)
  tampered = _rehash(blocks[2], proposer_id=_NODE2_ID)

  _assert_invalid(_validate(_replace_at(blocks, 2, tampered)), 2, "signature")

def test_block_resigned_with_unregistered_attacker_key_is_signature_failure():
  blocks = _valid_chain(1)
  forged = _signed_block(
    previous_hash=blocks[1].block_hash, index=2, timestamp=_BASE_TS + 2 * _STEP, seed=2,
    node_key=_OTHER)

  _assert_invalid(_validate([*blocks, forged]), 2, "signature")

def test_first_block_before_genesis_timestamp_is_structural():
  genesis = build_genesis_block()
  early = _signed_block(
    previous_hash=genesis.block_hash, index=1, timestamp=genesis.timestamp - 1, seed=1)

  _assert_invalid(_validate([genesis, early]), 1, "structural")

def test_validation_result_invariant_and_frozen():
  with pytest.raises(ValueError, match="valid iff"):
    ValidationResult(True, 1, "hash")
  with pytest.raises(ValueError, match="valid iff"):
    ValidationResult(False)
  with pytest.raises(dataclasses.FrozenInstanceError):
    ValidationResult(valid=True).valid = False  # type: ignore[misc]


# ---------------------------------------------------------------- validate_extension

def test_extension_of_valid_chain_matches_full_validation():
  chain = _valid_chain(5)

  extension = _extend(chain[2], chain[3:])

  assert extension.valid is True
  assert extension == _validate(chain)

def test_extension_with_no_new_blocks_is_valid():
  assert _extend(_valid_chain(2)[-1], []).valid is True

@pytest.mark.parametrize("kind", ["signature", "hash", "link", "structural"])
def test_tampered_new_block_matches_full_chain_result(kind):
  chain = _valid_chain(5)
  target = chain[4]
  if kind == "signature":
    forged_signature = attach_proposer_signature(target, _OTHER.private_key).proposer_signature
    tampered = replace(target, proposer_signature=forged_signature)
  elif kind == "hash":
    tampered = replace(target, block_hash=sha256_hex(b"bad"))
  elif kind == "link":
    tampered = _rehash(target, previous_hash=sha256_hex(b"bad"))
  else:
    tampered = replace(target, timestamp="x")
  tampered_chain = _replace_at(chain, 4, tampered)

  full = _validate(tampered_chain)
  extension = _extend(chain[2], tampered_chain[3:])

  # `structural` here comes from a wrong-typed field; position == tip.index + 1 + offset.
  assert full.valid is False
  assert full.failure_type == kind
  assert extension == full
  assert extension.first_invalid_index == 4

def test_extension_rejects_block_linking_to_different_tip():
  chain = _valid_chain(4)

  result = _extend(chain[1], chain[3:])

  _assert_invalid(result, 2, "link")


# ---------------------------------------------------------------- PERFORMANCE (call counting)

@pytest.mark.parametrize("length", [100, 200])
def test_validation_hashes_each_block_exactly_once(monkeypatch, length):
  chain = _valid_chain(length)
  calls = {"n": 0}
  real = validation_module.sha256_of_canonical

  def counting(obj):
    calls["n"] += 1
    return real(obj)

  monkeypatch.setattr(validation_module, "sha256_of_canonical", counting)

  assert _validate(chain).valid is True
  # One recompute per block; genesis is recomputed once for the constants check, so the
  # total is len(chain) (= length non-genesis blocks + 1), i.e. linear and never quadratic.
  assert calls["n"] == len(chain)


# ---------------------------------------------------------------- CHAIN

def test_append_rejects_candidate_with_wrong_block_hash():
  chain = Chain()
  good = _signed_block(previous_hash=chain.tip.block_hash, index=1, timestamp=_BASE_TS, seed=1)

  with pytest.raises(InvalidBlockHashError, match="block_hash"):
    chain.append(replace(good, block_hash=sha256_hex(b"wrong")))
  assert len(chain) == 1

def test_append_rejects_second_genesis():
  chain = Chain()

  with pytest.raises(InvalidBlockHashError, match="genesis"):
    chain.append(build_genesis_block())

def test_blocks_is_tuple_snapshot_unaffected_by_later_appends():
  chain = Chain()
  snapshot = chain.blocks
  chain.append(
    _signed_block(previous_hash=chain.tip.block_hash, index=1, timestamp=_BASE_TS, seed=1))

  assert isinstance(snapshot, tuple)
  assert len(snapshot) == 1
  assert len(chain) == 2
  assert chain.blocks[-1] is chain.tip
  assert len(chain.blocks) == len(chain)

def _race(candidates: list[Block], chain: Chain) -> tuple[int, list[BaseException]]:
  barrier = threading.Barrier(len(candidates))
  successes: list[int] = []
  errors: list[BaseException] = []
  guard = threading.Lock()

  def worker(candidate):
    barrier.wait()
    try:
      chain.append(candidate)
    except BaseException as exc:  # noqa: BLE001 - classified by the assertions
      with guard:
        errors.append(exc)
    else:
      with guard:
        successes.append(1)

  threads = [threading.Thread(target=worker, args=(c,)) for c in candidates]
  for thread in threads:
    thread.start()
  for thread in threads:
    thread.join(timeout=30)
  return len(successes), errors

def _candidates(chain: Chain, count: int, start_seed: int) -> list[Block]:
  tip = chain.tip
  return [
    build_candidate_block(
      [_record(start_seed + i)],
      previous_hash=tip.block_hash,
      index=tip.index + 1,
      timestamp=_BASE_TS + tip.index,
      proposer_id=_NODE_ID,
      algorithm="pow",
      sealed_consensus={"nonce": i},
      resolve_issuer_key=_resolve_issuer_key,
    )
    for i in range(count)
  ]

def test_concurrent_append_race_has_exactly_one_winner_per_round():
  chain = Chain()
  previous_interval = sys.getswitchinterval()
  sys.setswitchinterval(1e-6)
  try:
    for round_number in range(50):
      before = len(chain)
      candidates = _candidates(chain, 16, start_seed=round_number * 100)

      successes, errors = _race(candidates, chain)

      assert successes == 1
      assert len(errors) == 15
      assert all(isinstance(e, StalePreviousHashError | NonSequentialIndexError) for e in errors)
      assert len(chain) == before + 1
  finally:
    sys.setswitchinterval(previous_interval)

def test_widened_check_append_gap_still_has_exactly_one_winner(monkeypatch):
  """Fails without the lock: slow hashing/comparison widens the check-then-append window."""
  class SlowStr(str):
    def __ne__(self, other):
      result = str.__ne__(self, other)
      time.sleep(0.01)
      return result

  real = chain_module.sha256_of_canonical

  def slow_hash(obj):
    time.sleep(0.01)
    return real(obj)

  chain = Chain()
  slow = []
  for candidate in _candidates(chain, 8, start_seed=5000):
    clone = replace(candidate)
    object.__setattr__(clone, "previous_hash", SlowStr(candidate.previous_hash))
    slow.append(clone)
  monkeypatch.setattr(chain_module, "sha256_of_canonical", slow_hash)

  successes, errors = _race(slow, chain)

  assert successes == 1
  assert len(errors) == 7
  assert all(isinstance(e, StalePreviousHashError | NonSequentialIndexError) for e in errors)
  assert len(chain) == 2


# ---------------------------------------------------------------- BLOCK

def _build(**overrides):
  kwargs = {
    "previous_hash": GENESIS_BLOCK_HASH,
    "index": 1,
    "timestamp": _BASE_TS,
    "proposer_id": _NODE_ID,
    "algorithm": "pow",
    "sealed_consensus": {"nonce": 0},
    "resolve_issuer_key": _resolve_issuer_key,
  }
  kwargs.update(overrides)
  return build_candidate_block([_record(1)], **kwargs)

@pytest.mark.parametrize("override", [
  {"algorithm": "genesis"},
  {"algorithm": "foo"},
  {"index": 0},
  {"index": -1},
  {"index": True},
  {"index": "1"},
  {"previous_hash": "A" * 64},
  {"previous_hash": "ab" * 16},
  {"proposer_id": ""},
], ids=["genesis", "unknown_algo", "idx0", "idx_neg", "idx_bool", "idx_str",
        "upper_hash", "short_hash", "empty_proposer"])
def test_build_rejects_invalid_parameters(override):
  with pytest.raises(InvalidBlockParametersError):
    _build(**override)

def test_sealed_consensus_is_detached_from_callers_dict():
  sealed = {"nonce": 1, "nested": {"k": [1, 2]}}
  block = _build(sealed_consensus=sealed)
  original_hash = block.block_hash

  sealed["nonce"] = 999
  sealed["nested"]["k"].append(3)

  assert block.sealed_consensus["nonce"] == 1
  assert sha256_of_canonical(block.preimage_dict()) == original_hash

def test_sealed_consensus_is_read_only_and_deeply_frozen():
  block = _build(sealed_consensus={"nonce": 1, "nested": {"k": [1, 2]}})

  with pytest.raises(TypeError):
    block.sealed_consensus["x"] = 1  # type: ignore[index]
  with pytest.raises(TypeError):
    block.sealed_consensus["nested"]["y"] = 1
  assert isinstance(block.sealed_consensus["nested"]["k"], tuple)

def test_block_equality_independent_of_dict_or_frozen_sealed_consensus():
  base = _build()
  from_dict = replace(base, sealed_consensus={"nonce": 0})
  from_frozen = replace(base, sealed_consensus=deep_freeze({"nonce": 0}))

  assert from_dict == from_frozen == base

def test_preimage_dict_hash_equals_block_hash():
  block = _build()

  assert sha256_of_canonical(block.preimage_dict()) == block.block_hash

def test_batch_with_duplicate_and_bad_signature_reports_signature_first():
  good = _record(1)
  bad_dup = replace(good, signature=_record(1, key=_OTHER).signature)

  with pytest.raises(InvalidRecordSignatureError) as excinfo:
    build_candidate_block(
      [good, bad_dup], previous_hash=GENESIS_BLOCK_HASH, index=1, timestamp=_BASE_TS,
      proposer_id=_NODE_ID, algorithm="pow", sealed_consensus={},
      resolve_issuer_key=_resolve_issuer_key)
  assert excinfo.value.index == 1

def test_batch_with_only_duplicate_raises_duplicate_error():
  good = _record(1)

  with pytest.raises(DuplicateDocumentHashError, match="duplicate document_hash"):
    build_candidate_block(
      [good, good], previous_hash=GENESIS_BLOCK_HASH, index=1, timestamp=_BASE_TS,
      proposer_id=_NODE_ID, algorithm="pow", sealed_consensus={},
      resolve_issuer_key=_resolve_issuer_key)

def test_build_invokes_issuer_resolver_with_issuer_and_timestamp():
  calls = []

  def resolver(identity, at_timestamp):
    calls.append((identity, at_timestamp))
    return _resolve_issuer_key(identity, at_timestamp)

  _build(resolve_issuer_key=resolver, timestamp=_BASE_TS + 7)

  assert calls == [(_ISSUER_ID, _BASE_TS + 7)]


# ---------------------------------------------------------------- PACKAGE

def test_every_name_in_all_is_importable():
  missing = [name for name in blockchain_core.__all__ if not hasattr(blockchain_core, name)]

  assert missing == []

def test_all_contains_public_api():
  expected = {
    "validate_chain", "validate_extension", "Chain", "Block", "build_candidate_block",
    "GENESIS_BLOCK_HASH", "IssuerKeyPair", "NodeKeyPair",
  }

  assert expected <= set(blockchain_core.__all__)

def test_core_package_never_imports_node_layer():
  pattern = re.compile(r"^\s*(from\s+(src\.)?node\b|import\s+(src\.)?node\b)", re.MULTILINE)
  offenders = [
    str(path) for path in (_SRC_DIR / "blockchain_core").rglob("*.py")
    if pattern.search(path.read_text(encoding="utf-8"))
  ]

  assert offenders == []
