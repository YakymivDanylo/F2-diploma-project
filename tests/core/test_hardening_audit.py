"""Hardening pass (audit 2026-11-20): block size bound, record shapes, active-key count,
node-layer failure types, durable renames, key-file permissions and key-role separation.

The PBFT check-order and active-key-count cases live in test_validation_consensus.py.
"""

from __future__ import annotations

import os
import typing
from dataclasses import replace
from pathlib import Path

import pytest

import blockchain_core
from blockchain_core import block as block_module
from blockchain_core import validation as validation_module
from blockchain_core.block import (
  MAX_BLOCK_RECORDS,
  Block,
  InvalidBlockParametersError,
  attach_proposer_signature,
  build_candidate_block,
  sign_commit,
)
from blockchain_core.canonical import CanonicalizationError
from blockchain_core.document_record import DocumentRecord, create_document_record
from blockchain_core.genesis import build_genesis_block
from blockchain_core.hashing import sha256_hex, sha256_of_canonical
from blockchain_core.keys import generate_issuer_keypair, generate_keypair, generate_node_keypair
from blockchain_core.merkle import build_root
from blockchain_core.signing import sign_canonical
from blockchain_core.storage import chain_store as chain_store_module
from blockchain_core.storage import key_store as key_store_module
from blockchain_core.storage.chain_store import (
  JsonChainStore,
  SharedKeyMaterialError,
  SqliteChainStore,
  restore_node_state,
)
from blockchain_core.storage.key_store import (
  KeyStoreInsecureError,
  fsync_directory,
  load_issuer_key_pair,
  load_key_pair,
  load_node_key_pair,
  save_key_pair,
)
from blockchain_core.validation import (
  FailureType,
  ValidationResult,
  ValidatorSet,
  pow_target,
  validate_candidate,
  validate_chain,
)

_ISSUER = generate_issuer_keypair()
_ISSUER_ID = "issuer-1"
_VALIDATOR_IDS = ("v0", "v1", "v2", "v3")
_NODES = {node_id: generate_node_keypair() for node_id in _VALIDATOR_IDS}
_VSET = ValidatorSet(members=frozenset(_VALIDATOR_IDS), n=4, f=1)
_BASE_TS = 1_700_000_001_000
_DIFFICULTY = 1


def _resolve_issuer_key(issuer_id: str, at_timestamp: int):
  return _ISSUER.public_key if issuer_id == _ISSUER_ID else None


def _resolve_node_key(node_id: str, at_timestamp: int):
  pair = _NODES.get(node_id)
  return pair.public_key if pair else None


def _record(seed: int) -> DocumentRecord:
  return create_document_record(
    document_hash=sha256_hex(f"document-{seed}".encode()),
    issuer_id=_ISSUER_ID,
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed},
    issuer_private_key=_ISSUER.private_key,
  )


def _rehash(block: Block, **changes) -> Block:
  changed = replace(block, **changes)
  return replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))


def _candidate(records, algorithm: str = "pow") -> Block:
  genesis = build_genesis_block()
  sealed = {"nonce": 0, "difficulty": _DIFFICULTY} if algorithm == "pow" else {"view_number": 0}
  return build_candidate_block(
    records,
    previous_hash=genesis.block_hash,
    index=1,
    timestamp=_BASE_TS,
    proposer_id="v0",
    algorithm=algorithm,
    sealed_consensus=sealed,
    resolve_issuer_key=_resolve_issuer_key,
  )


def _seal_pow(block: Block) -> Block:
  """Mine, re-merkle and sign: every check except the one under test passes."""
  block = _rehash(block, merkle_root=_merkle(block.document_records))
  nonce = 0
  while int(block.block_hash, 16) >= pow_target(_DIFFICULTY):
    nonce += 1
    block = _rehash(block, sealed_consensus={"nonce": nonce, "difficulty": _DIFFICULTY})
  return attach_proposer_signature(block, _NODES["v0"].private_key)


def _merkle(records) -> str:
  try:
    return build_root(records)
  except CanonicalizationError:  # a malformed field: "structural" is reported first anyway
    return "00" * 32


def _validate_pow(block: Block) -> ValidationResult:
  return validate_chain(
    [build_genesis_block(), block],
    resolve_node_key=_resolve_node_key,
    resolve_issuer_key=_resolve_issuer_key,
    expected_difficulty=_DIFFICULTY,
  )


def _assert_invalid(result: ValidationResult, index: int, failure_type: str) -> None:
  assert result.valid is False
  assert result.first_invalid_index == index
  assert result.failure_type == failure_type


# ---------------------------------------------------------------- 1. MAX_BLOCK_RECORDS


def test_max_block_records_is_500_and_exported_everywhere():
  assert MAX_BLOCK_RECORDS == 500
  assert blockchain_core.MAX_BLOCK_RECORDS == MAX_BLOCK_RECORDS
  assert validation_module.MAX_BLOCK_RECORDS == MAX_BLOCK_RECORDS
  assert "MAX_BLOCK_RECORDS" in blockchain_core.__all__
  assert "MAX_BLOCK_RECORDS" in block_module.__all__
  assert "MAX_BLOCK_RECORDS" in validation_module.__all__


def test_build_candidate_block_refuses_more_than_max_records_before_verifying(monkeypatch):
  calls: list[object] = []
  monkeypatch.setattr(
    block_module, "verify_document_record", lambda record, key: calls.append(record) or True
  )
  records = [_record(1)] * (MAX_BLOCK_RECORDS + 1)

  with pytest.raises(InvalidBlockParametersError, match="at most 500"):
    _candidate(records)
  assert calls == []  # rejected before any signature verification


def test_block_with_exactly_max_records_is_valid():
  records = [_record(seed) for seed in range(MAX_BLOCK_RECORDS)]
  block = _seal_pow(_candidate(records))

  assert len(block.document_records) == MAX_BLOCK_RECORDS
  assert _validate_pow(block).valid


def test_block_over_max_records_is_structural_without_any_signature_check(monkeypatch):
  block = _seal_pow(_candidate([_record(1)]))
  oversized = _seal_pow(replace(block, document_records=(_record(1),) * (MAX_BLOCK_RECORDS + 1)))
  calls: list[object] = []
  monkeypatch.setattr(
    validation_module, "verify_canonical", lambda *args: calls.append(args) or True
  )
  monkeypatch.setattr(
    validation_module, "verify_document_record", lambda *args: calls.append(args) or True
  )

  _assert_invalid(_validate_pow(oversized), 1, "structural")
  assert calls == []


def test_candidate_over_max_records_is_structural():
  genesis = build_genesis_block()
  block = attach_proposer_signature(_candidate([_record(1)], "pbft"), _NODES["v0"].private_key)
  oversized = replace(block, document_records=(block.document_records[0],) * 501)

  result = validate_candidate(
    genesis,
    oversized,
    resolve_node_key=_resolve_node_key,
    resolve_issuer_key=_resolve_issuer_key,
    validator_set=_VSET,
  )

  _assert_invalid(result, 1, "structural")


def test_candidate_skips_the_active_key_count():
  vset = ValidatorSet(members=frozenset({*_VALIDATOR_IDS, "extra"}), n=4, f=1)
  extra = generate_node_keypair()

  def resolver(node_id, at_timestamp):
    return extra.public_key if node_id == "extra" else _resolve_node_key(node_id, at_timestamp)

  genesis = build_genesis_block()
  block = attach_proposer_signature(_candidate([_record(1)], "pbft"), _NODES["v0"].private_key)

  result = validate_candidate(
    genesis,
    block,
    resolve_node_key=resolver,
    resolve_issuer_key=_resolve_issuer_key,
    validator_set=vset,
  )
  assert result.valid
  # ...but the finalized block, even with a full quorum, fails closed.
  final = replace(
    block,
    commit_signatures=tuple(
      sign_commit(block, node_id, _NODES[node_id].private_key) for node_id in _VALIDATOR_IDS
    ),
  )
  _assert_invalid(
    validate_chain(
      [genesis, final],
      resolve_node_key=resolver,
      resolve_issuer_key=_resolve_issuer_key,
      validator_set=vset,
    ),
    1,
    "quorum",
  )


# ---------------------------------------------------------------- 3. record field shapes


def _malformed(record: DocumentRecord, field: str, value: object) -> DocumentRecord:
  forged = replace(record)
  object.__setattr__(forged, field, value)
  return forged


_RECORD = _record(7)


@pytest.mark.parametrize(
  ("field", "value"),
  [
    ("document_hash", _RECORD.document_hash.upper()),
    ("document_hash", _RECORD.document_hash[:-1]),
    ("document_hash", _RECORD.document_hash + "0"),
    ("document_hash", " " + _RECORD.document_hash[1:]),
    ("document_hash", _RECORD.document_hash + "\n"),
    ("document_hash", 12345),
    ("issuer_id", ""),
    ("issuer_id", 1),
    ("issuer_id", None),
    ("issued_at", True),
    ("issued_at", -1),
    ("issued_at", 1.5),
    ("issued_at", "1700000000000"),
    ("signature", 123),
    ("signature", b"ab"),
    ("metadata", ["not", "a", "mapping"]),
    ("metadata", None),
    ("ipfs_cid", 5),
  ],
)
def test_malformed_record_field_is_structural(field, value):
  block = _candidate([_RECORD])
  forged = _seal_pow(replace(block, document_records=(_malformed(_RECORD, field, value),)))

  _assert_invalid(_validate_pow(forged), 1, "structural")


def test_well_formed_record_edge_values_are_accepted():
  record = create_document_record(
    document_hash=sha256_hex(b"edge"),
    issuer_id=_ISSUER_ID,
    issued_at=0,
    metadata={},
    issuer_private_key=_ISSUER.private_key,
  )
  assert _validate_pow(_seal_pow(_candidate([record]))).valid


def test_uppercase_hash_cannot_masquerade_as_a_new_document():
  # Same document, upper-cased hash re-signed by the issuer: without the shape check it
  # would compare unequal to the anchored lower-case hash and bypass uniqueness.
  upper = _RECORD.document_hash.upper()
  forged = _malformed(_RECORD, "document_hash", upper)
  object.__setattr__(
    forged, "signature", sign_canonical(_ISSUER.private_key, forged.unsigned_dict())
  )
  block = _seal_pow(replace(_candidate([_RECORD]), document_records=(forged,)))

  _assert_invalid(_validate_pow(block), 1, "structural")


# ---------------------------------------------------------------- 4. FailureType


def test_failure_type_includes_node_layer_reasons():
  values = set(typing.get_args(FailureType))
  assert {"duplicate_document", "timestamp_in_future"} <= values
  assert {"hash", "link", "merkle", "signature", "structural", "difficulty", "quorum"} <= values
  for reason in ("duplicate_document", "timestamp_in_future"):
    result = ValidationResult(valid=False, first_invalid_index=3, failure_type=reason)
    assert result.failure_type == reason


# ---------------------------------------------------------------- 5. directory fsync


def _record_dir_fsync(monkeypatch) -> list[tuple[str, object]]:
  events: list[tuple[str, object]] = []
  monkeypatch.setattr(key_store_module, "_POSIX", True)
  monkeypatch.setattr(
    key_store_module.os, "open", lambda path, flags, *a: events.append(("open", path)) or 99
  )
  monkeypatch.setattr(key_store_module.os, "fsync", lambda fd: events.append(("fsync", fd)))
  monkeypatch.setattr(key_store_module.os, "close", lambda fd: events.append(("close", fd)))
  return events


def test_fsync_directory_opens_fsyncs_and_closes_the_directory_on_posix(monkeypatch, tmp_path):
  events = _record_dir_fsync(monkeypatch)

  fsync_directory(tmp_path)

  assert events == [("open", tmp_path), ("fsync", 99), ("close", 99)]


def test_fsync_directory_is_a_noop_on_windows(monkeypatch, tmp_path):
  monkeypatch.setattr(key_store_module, "_POSIX", False)
  monkeypatch.setattr(
    key_store_module.os, "open", lambda *a: pytest.fail("must not open on Windows")
  )

  fsync_directory(tmp_path)


@pytest.mark.parametrize("backend", [JsonChainStore, SqliteChainStore], ids=["json", "sqlite"])
def test_chain_store_save_fsyncs_the_directory_after_the_rename(monkeypatch, tmp_path, backend):
  path = tmp_path / "chain.db"
  synced: list[tuple[Path, bool]] = []
  monkeypatch.setattr(
    chain_store_module, "fsync_directory", lambda d: synced.append((d, path.exists()))
  )

  with backend(path) as store:
    store.save([build_genesis_block()])

  assert synced == [(tmp_path, True)]  # after os.replace: the file is already in place


def test_chain_store_directory_fsync_failure_is_a_write_error(monkeypatch, tmp_path):
  def broken(directory):
    raise OSError("EIO")

  monkeypatch.setattr(chain_store_module, "fsync_directory", broken)
  with JsonChainStore(tmp_path / "chain.json") as store:
    with pytest.raises(chain_store_module.ChainStoreWriteError):
      store.save([build_genesis_block()])


def test_real_save_and_load_still_round_trip(tmp_path):
  with JsonChainStore(tmp_path / "chain.json") as store:
    store.save([build_genesis_block()])
    assert store.load() == [build_genesis_block()]


# ---------------------------------------------------------------- 6. key-file permissions


def _saved_key(tmp_path: Path) -> Path:
  path = tmp_path / "node.pem"
  save_key_pair(generate_node_keypair(), path)
  return path


@pytest.mark.parametrize("loader", [load_key_pair, load_node_key_pair, load_issuer_key_pair])
def test_group_or_other_accessible_key_is_refused_on_posix(monkeypatch, tmp_path, loader):
  path = _saved_key(tmp_path)
  if os.name == "posix":
    path.chmod(0o640)
  else:
    # Windows reports 0o666 for every file: exercising the POSIX branch shows it refuses.
    monkeypatch.setattr(key_store_module, "_POSIX", True)

  with pytest.raises(KeyStoreInsecureError, match="group/other"):
    loader(path)


def test_insecure_key_error_is_a_permission_error():
  assert issubclass(KeyStoreInsecureError, PermissionError)
  assert blockchain_core.KeyStoreInsecureError is KeyStoreInsecureError


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
@pytest.mark.parametrize("mode", [0o604, 0o620, 0o660, 0o644, 0o700 | 0o001])
def test_each_group_or_other_bit_is_refused(tmp_path, mode):
  path = _saved_key(tmp_path)
  path.chmod(mode)

  with pytest.raises(KeyStoreInsecureError):
    load_key_pair(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_owner_only_key_loads_on_posix(tmp_path):
  path = _saved_key(tmp_path)
  path.chmod(0o400)

  assert load_node_key_pair(path)


def test_mode_check_is_skipped_on_windows(monkeypatch, tmp_path):
  path = _saved_key(tmp_path)
  if os.name == "posix":
    path.chmod(0o644)
  monkeypatch.setattr(key_store_module, "_POSIX", False)

  assert load_node_key_pair(path)


def test_symlinked_key_is_refused(tmp_path):
  target = _saved_key(tmp_path)
  link = tmp_path / "link.pem"
  try:
    link.symlink_to(target)
  except (OSError, NotImplementedError):
    pytest.skip("cannot create symlinks here")

  with pytest.raises(KeyStoreInsecureError, match="symlink"):
    load_node_key_pair(link)


def test_symlink_check_refuses_even_a_dangling_link(monkeypatch, tmp_path):
  missing = tmp_path / "gone.pem"
  monkeypatch.setattr(Path, "is_symlink", lambda self: self == missing)

  with pytest.raises(KeyStoreInsecureError, match="symlink"):
    load_key_pair(missing)


# ---------------------------------------------------------------- 6. key-role separation


def test_restore_node_state_refuses_the_same_key_for_issuer_and_node(tmp_path):
  shared = generate_keypair()
  save_key_pair(shared, tmp_path / "issuer.pem")
  save_key_pair(shared, tmp_path / "node.pem")

  with JsonChainStore(tmp_path / "chain.json") as store:
    with pytest.raises(SharedKeyMaterialError):
      restore_node_state(
        store,
        issuer_key_path=tmp_path / "issuer.pem",
        node_key_path=tmp_path / "node.pem",
        resolve_node_key=_resolve_node_key,
        resolve_issuer_key=_resolve_issuer_key,
        allow_fresh=True,
      )
  assert blockchain_core.SharedKeyMaterialError is SharedKeyMaterialError


def test_restore_node_state_accepts_distinct_keys(tmp_path):
  save_key_pair(generate_issuer_keypair(), tmp_path / "issuer.pem")
  save_key_pair(generate_node_keypair(), tmp_path / "node.pem")

  with JsonChainStore(tmp_path / "chain.json") as store:
    state = restore_node_state(
      store,
      issuer_key_path=tmp_path / "issuer.pem",
      node_key_path=tmp_path / "node.pem",
      resolve_node_key=_resolve_node_key,
      resolve_issuer_key=_resolve_issuer_key,
      allow_fresh=True,
    )
  assert state.restored.valid


# ---------------------------------------------------------------- 7. signature domains


def test_signed_payload_kinds_have_pairwise_distinct_key_sets():
  record_keys = set(_RECORD.unsigned_dict())
  block_keys = set(build_genesis_block().preimage_dict())
  commit_keys = set(block_module.commit_payload("ab" * 32))

  assert record_keys == {"document_hash", "issuer_id", "issued_at", "metadata", "ipfs_cid"}
  assert block_keys == {
    "index",
    "timestamp",
    "previous_hash",
    "merkle_root",
    "proposer_id",
    "algorithm",
    "sealed_consensus",
  }
  assert "domain" in commit_keys
  assert "domain" not in record_keys | block_keys
  assert record_keys != block_keys
