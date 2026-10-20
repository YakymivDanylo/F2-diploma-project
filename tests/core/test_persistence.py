"""Slice 8: chain store (JSON/SQLite), key-store loaders, restart durability.

Covers BC-TC-8.1 .. 8.10 (UC-8 primary, UC-8-A, UC-8-E1..E5, UC-8-EC1..EC3).
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from dataclasses import FrozenInstanceError, replace

import pytest

from blockchain_core.block import (
  Block,
  attach_proposer_signature,
  build_candidate_block,
  sign_commit,
)
from blockchain_core.chain import Chain
from blockchain_core.document_record import create_document_record
from blockchain_core.genesis import build_genesis_block
from blockchain_core.hashing import sha256_hex, sha256_of_canonical
from blockchain_core.keys import (
  IssuerKeyPair,
  NodeKeyPair,
  generate_issuer_keypair,
  generate_node_keypair,
)
from blockchain_core.signing import sign_canonical, verify_canonical
from blockchain_core.storage import chain_store
from blockchain_core.storage.chain_store import (
  CHAIN_FORMAT,
  CHAIN_FORMAT_VERSION,
  ChainStoreCorruptedError,
  ChainStoreError,
  ChainStoreLockedError,
  ChainStoreMissingError,
  ChainStoreWriteError,
  JsonChainStore,
  NodeState,
  RestoredChain,
  SqliteChainStore,
  block_from_dict,
  block_to_dict,
  decode_chain,
  encode_chain,
  restore_chain,
  restore_node_state,
)
from blockchain_core.storage.key_store import (
  IssuerKeyUnavailableError,
  KeyStoreCorruptedError,
  KeyStoreMissingError,
  NodeKeyUnavailableError,
  load_issuer_key_pair,
  load_node_key_pair,
  save_key_pair,
)
from blockchain_core.validation import ValidatorSet, pow_target

_ISSUER = generate_issuer_keypair()
_ISSUER_ID = "issuer-1"
_VALIDATOR_IDS = ("v0", "v1", "v2", "v3")
_NODES = {node_id: generate_node_keypair() for node_id in _VALIDATOR_IDS}
_VSET = ValidatorSet(members=frozenset(_VALIDATOR_IDS), n=4, f=1)
_BASE_TS = 1_700_000_001_000
_STEP = 1_000
_DIFFICULTY = 1
_BACKENDS = [JsonChainStore, SqliteChainStore]
_BACKEND_IDS = ["json", "sqlite"]


def _resolve_issuer_key(identity: str, at_timestamp: int):
  return _ISSUER.public_key if identity == _ISSUER_ID else None


def _resolve_node_key(identity: str, at_timestamp: int):
  pair = _NODES.get(identity)
  return pair.public_key if pair else None


def _record(seed: int, *, ipfs_cid: str | None = None):
  return create_document_record(
    document_hash=sha256_hex(f"document-{seed}".encode()),
    issuer_id=_ISSUER_ID,
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed, "tags": ["a", "b"], "nested": {"k": "v", "flag": True, "none": None}},
    issuer_private_key=_ISSUER.private_key,
    ipfs_cid=ipfs_cid,
  )


def _candidate(previous: Block, seed: int, algorithm: str, sealed_consensus, **record_kwargs):
  return build_candidate_block(
    [_record(seed, **record_kwargs), _record(seed + 1000)],
    previous_hash=previous.block_hash,
    index=previous.index + 1,
    timestamp=_BASE_TS + (previous.index + 1) * _STEP,
    proposer_id="v0",
    algorithm=algorithm,
    sealed_consensus=sealed_consensus,
    resolve_issuer_key=_resolve_issuer_key,
  )


def _mine(block: Block, difficulty: int) -> Block:
  target = pow_target(difficulty)
  nonce = 0
  while int(block.block_hash, 16) >= target:
    nonce += 1
    changed = replace(block, sealed_consensus={**block.sealed_consensus, "nonce": nonce})
    block = replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))
  return block


def _pow_block(previous: Block, seed: int, *, difficulty: int = _DIFFICULTY, **kwargs) -> Block:
  block = _candidate(previous, seed, "pow", {"nonce": 0, "difficulty": difficulty}, **kwargs)
  return attach_proposer_signature(_mine(block, difficulty), _NODES["v0"].private_key)


def _pow_chain(length: int, *, difficulty: int = _DIFFICULTY) -> list[Block]:
  blocks = [build_genesis_block()]
  for seed in range(1, length + 1):
    kwargs = {"ipfs_cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"}
    blocks.append(
      _pow_block(blocks[-1], seed, difficulty=difficulty, **(kwargs if seed == 1 else {}))
    )
  return blocks


def _pbft_block(previous: Block, seed: int) -> Block:
  block = attach_proposer_signature(
    _candidate(previous, seed, "pbft", {"view_number": 0}), _NODES["v0"].private_key
  )
  commits = tuple(
    sign_commit(block, node_id, _NODES[node_id].private_key) for node_id in _VALIDATOR_IDS[:3]
  )
  return replace(block, commit_signatures=commits)


def _pbft_chain(length: int) -> list[Block]:
  blocks = [build_genesis_block()]
  for seed in range(1, length + 1):
    blocks.append(_pbft_block(blocks[-1], seed))
  return blocks


def _restore(store, **overrides):
  kwargs = {"resolve_node_key": _resolve_node_key, "resolve_issuer_key": _resolve_issuer_key}
  kwargs.update(overrides)
  return restore_chain(store, **kwargs)


def _tamper_json_file(path, edit) -> None:
  document = json.loads(path.read_bytes())
  edit(document)
  path.write_bytes(json.dumps(document).encode())


def _sign_verify_roundtrip(signing_pair, verifying_pair) -> bool:
  payload = {"hello": "world", "n": 1}
  signature = sign_canonical(signing_pair.private_key, payload)
  return verify_canonical(verifying_pair.public_key, payload, signature)


# ---------------------------------------------------------------- block <-> dict


@pytest.mark.parametrize("chain_builder", [_pow_chain, _pbft_chain], ids=["pow", "pbft"])
def test_block_dict_round_trip_is_lossless(chain_builder):
  for block in chain_builder(2):
    restored = block_from_dict(block_to_dict(block))
    assert restored == block
    assert restored.commit_signatures == block.commit_signatures
    assert restored.document_records == block.document_records


def test_block_dict_round_trip_survives_json_text():
  block = _pbft_chain(1)[1]

  restored = block_from_dict(json.loads(json.dumps(block_to_dict(block))))

  assert restored == block
  assert len(restored.commit_signatures) == 3
  assert isinstance(restored.commit_signatures, tuple)


def test_record_fields_round_trip_including_ipfs_cid_and_signature():
  block = _pow_chain(1)[1]

  restored = block_from_dict(block_to_dict(block))

  assert restored.document_records[0].ipfs_cid == block.document_records[0].ipfs_cid
  assert restored.document_records[0].ipfs_cid is not None
  assert restored.document_records[1].ipfs_cid is None
  assert restored.document_records[0].signature == block.document_records[0].signature
  assert restored.document_records[0].metadata == block.document_records[0].metadata


def test_genesis_block_round_trips():
  genesis = build_genesis_block()

  assert block_from_dict(block_to_dict(genesis)) == genesis


def _drop(key):
  return lambda d: d.pop(key)


def _set(key, value):
  return lambda d: d.__setitem__(key, value)


def _set_in_record(key, value):
  return lambda d: d["document_records"][0].__setitem__(key, value)


@pytest.mark.parametrize(
  "mutate",
  [
    _drop("index"),
    _drop("block_hash"),
    _drop("document_records"),
    _set("surprise", 1),
    _set("index", "1"),
    _set("index", True),
    _set("timestamp", 1.5),
    _set("commit_signatures", "not-a-list"),
    _set("commit_signatures", {"a": 1}),
    _set("document_records", [42]),
    _set("document_records", "nope"),
    _set_in_record("metadata", [1, 2]),
    _set_in_record("surprise", 1),
    lambda d: d["document_records"][0].pop("document_hash"),
  ],
  ids=[
    "missing_index",
    "missing_block_hash",
    "missing_records",
    "extra_key",
    "index_str",
    "index_bool",
    "timestamp_float",
    "commits_str",
    "commits_dict",
    "record_not_object",
    "records_not_list",
    "metadata_not_object",
    "extra_record_key",
    "missing_record_field",
  ],
)
def test_block_from_dict_rejects_shape_problems(mutate):
  data = block_to_dict(_pow_chain(1)[1])
  mutate(data)

  with pytest.raises(ChainStoreCorruptedError):
    block_from_dict(data)


def test_block_from_dict_does_not_judge_validity():
  data = block_to_dict(_pow_chain(1)[1])
  data["timestamp"] += 1  # well-formed but no longer matches block_hash

  decoded = block_from_dict(data)

  assert decoded.block_hash == data["block_hash"]


@pytest.mark.parametrize("junk", [None, 5, "x", [1], ()])
def test_block_from_dict_rejects_non_mapping(junk):
  with pytest.raises(ChainStoreCorruptedError):
    block_from_dict(junk)


def test_corrupted_error_is_value_error_and_chain_store_error():
  assert issubclass(ChainStoreCorruptedError, ChainStoreError)
  assert issubclass(ChainStoreCorruptedError, ValueError)
  assert issubclass(ChainStoreLockedError, ChainStoreError)
  assert not issubclass(ChainStoreLockedError, ChainStoreCorruptedError)


# ---------------------------------------------------------------- encode / decode


def test_encode_chain_is_canonical_document():
  blocks = _pow_chain(1)

  document = json.loads(encode_chain(blocks))

  assert document["format"] == CHAIN_FORMAT == "blockchain_core.chain"
  assert document["version"] == CHAIN_FORMAT_VERSION == 2
  assert document["blocks"][1]["commit_signatures"] == []
  assert len(document["blocks"]) == 2


def test_encode_is_deterministic_and_round_trips():
  blocks = _pbft_chain(2)

  assert encode_chain(blocks) == encode_chain(list(blocks))
  assert decode_chain(encode_chain(blocks)) == blocks


def _valid_document() -> dict:
  return json.loads(encode_chain(_pow_chain(1)))


@pytest.mark.parametrize(
  "payload",
  [
    lambda: encode_chain(_pow_chain(1))[:-10],
    lambda: b"",
    lambda: b"{not json",
    lambda: b"\xff\xfe\x00garbage",
    lambda: json.dumps({**_valid_document(), "format": "other.chain"}).encode(),
    lambda: json.dumps({**_valid_document(), "version": 1}).encode(),
    lambda: json.dumps({**_valid_document(), "version": True}).encode(),
    lambda: json.dumps({**_valid_document(), "blocks": []}).encode(),
    lambda: json.dumps({**_valid_document(), "blocks": "x"}).encode(),
    lambda: json.dumps([_valid_document()]).encode(),
    lambda: encode_chain(_pow_chain(1)).replace(b'"version":2', b'"version":2.0'),
    lambda: encode_chain(_pow_chain(1)).replace(b'"version":2', b'"version":NaN'),
    lambda: encode_chain(_pow_chain(1)).replace(b'"version":2', b'"version":Infinity'),
    lambda: encode_chain(_pow_chain(1)).replace(b'"version":2', b'"version":2,"version":2'),
  ],
  ids=[
    "truncated",
    "empty_bytes",
    "invalid_json",
    "non_utf8",
    "wrong_format",
    "unsupported_version",
    "bool_version",
    "empty_blocks",
    "blocks_not_list",
    "top_level_list",
    "float",
    "nan",
    "infinity",
    "duplicate_keys",
  ],
)
def test_decode_chain_rejects_bad_documents(payload):
  with pytest.raises(ChainStoreCorruptedError):
    decode_chain(payload())


def test_decode_chain_rejects_float_inside_a_block():
  document = _valid_document()
  document["blocks"][1]["timestamp"] = 1.5

  with pytest.raises(ChainStoreCorruptedError):
    decode_chain(json.dumps(document).encode())


def test_decode_chain_rejects_float_inside_record_metadata():
  """Metadata is free-form, so only the parser itself can keep floats out of it."""
  document = _valid_document()
  document["blocks"][1]["document_records"][0]["metadata"]["score"] = 0.5

  with pytest.raises(ChainStoreCorruptedError, match="float"):
    decode_chain(json.dumps(document).encode())


def test_decode_chain_rejects_duplicate_keys_inside_a_block():
  text = encode_chain(_pow_chain(1)).decode()
  needle = '"algorithm":"pow"'
  assert needle in text
  duplicated = text.replace(needle, needle + ',"algorithm":"pow"', 1)

  with pytest.raises(ChainStoreCorruptedError):
    decode_chain(duplicated.encode())


# ---------------------------------------------------------------- backends (TC-8.2)


# TC-8.2
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_load_returns_none_when_no_file(tmp_path, backend):
  with backend(tmp_path / "chain.db") as store:
    assert store.load() is None


# TC-8.2
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
@pytest.mark.parametrize("chain_builder", [_pow_chain, _pbft_chain], ids=["pow", "pbft"])
def test_save_then_load_round_trips(tmp_path, backend, chain_builder):
  blocks = chain_builder(3)
  path = tmp_path / "chain.db"

  with backend(path) as store:
    store.save(blocks)
    assert store.load() == blocks

  with backend(path) as reopened:
    loaded = reopened.load()
  assert loaded == blocks
  assert loaded[-1].commit_signatures == blocks[-1].commit_signatures


# TC-8.2
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_save_overwrites_previous_content(tmp_path, backend):
  short, long = _pow_chain(1), _pow_chain(3)

  with backend(tmp_path / "chain.db") as store:
    store.save(long)
    store.save(short)
    assert store.load() == short


# TC-8.2
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_close_is_usable_without_context_manager(tmp_path, backend):
  store = backend(tmp_path / "chain.db")
  store.save(_pow_chain(1))
  store.close()

  with backend(tmp_path / "chain.db") as reopened:
    assert reopened.load() is not None


# TC-8.2
@pytest.mark.parametrize("chain_builder", [_pow_chain, _pbft_chain], ids=["pow", "pbft"])
def test_both_backends_produce_equivalent_state(tmp_path, chain_builder):
  blocks = chain_builder(2)

  with JsonChainStore(tmp_path / "a.json") as json_store:
    json_store.save(blocks)
    from_json = json_store.load()
  with SqliteChainStore(tmp_path / "b.db") as sqlite_store:
    sqlite_store.save(blocks)
    from_sqlite = sqlite_store.load()

  assert encode_chain(from_json) == encode_chain(from_sqlite) == encode_chain(blocks)


# TC-8.2
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_restore_is_identical_across_backends(tmp_path, backend):
  blocks = _pbft_chain(2)
  with backend(tmp_path / "chain.db") as store:
    store.save(blocks)
  with backend(tmp_path / "chain.db") as store:
    restored = _restore(store, validator_set=_VSET)

  assert restored.valid
  assert restored.blocks == tuple(blocks)


# TC-8.4
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_random_bytes_in_place_of_store_file_is_corrupted(tmp_path, backend):
  path = tmp_path / "chain.db"
  path.write_bytes(os.urandom(256) + b"\xff\xfe")

  with backend(path) as store, pytest.raises(ChainStoreCorruptedError):
    store.load()


# TC-8.4
@pytest.mark.parametrize(
  "query",
  [
    "UPDATE blocks SET position = position + 5 WHERE position > 0",
    "DELETE FROM blocks",
    "DELETE FROM meta",
    "UPDATE meta SET value = '1' WHERE key = 'version'",
    "UPDATE blocks SET data = CAST('not json' AS BLOB) WHERE position = 1",
    "DROP TABLE blocks",
  ],
  ids=["position_gap", "no_blocks", "no_meta", "wrong_version", "bad_row", "no_table"],
)
def test_structurally_damaged_sqlite_store_is_corrupted(tmp_path, query):
  path = tmp_path / "chain.db"
  with SqliteChainStore(path) as store:
    store.save(_pow_chain(2))
  connection = sqlite3.connect(path)
  with connection:
    connection.execute(query)
  connection.close()

  with SqliteChainStore(path) as store, pytest.raises(ChainStoreCorruptedError):
    store.load()


# TC-8.4
def test_truncated_json_file_is_corrupted(tmp_path):
  path = tmp_path / "chain.json"
  data = encode_chain(_pow_chain(2))
  path.write_bytes(data[: len(data) // 2])

  with JsonChainStore(path) as store, pytest.raises(ChainStoreCorruptedError):
    store.load()


# TC-8.4
def test_empty_file_is_corrupted_not_fresh(tmp_path):
  path = tmp_path / "chain.json"
  path.write_bytes(b"")

  with JsonChainStore(path) as store, pytest.raises(ChainStoreCorruptedError):
    store.load()


# TC-8.4
def test_json_that_decodes_but_has_bad_block_is_corrupted(tmp_path):
  path = tmp_path / "chain.json"
  path.write_bytes(encode_chain(_pow_chain(1)))
  _tamper_json_file(path, lambda doc: doc["blocks"][1].__setitem__("index", "1"))

  with JsonChainStore(path) as store, pytest.raises(ChainStoreCorruptedError):
    store.load()


# TC-8.4
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_restore_chain_raises_on_corrupted_file(tmp_path, backend):
  path = tmp_path / "chain.db"
  path.write_bytes(b"\x00\x01 definitely not a chain")

  with backend(path) as store, pytest.raises(ChainStoreCorruptedError):
    _restore(store)


# ---------------------------------------------------------------- atomic JSON save


def test_json_save_leaves_no_temp_files(tmp_path):
  path = tmp_path / "chain.json"

  with JsonChainStore(path) as store:
    store.save(_pow_chain(1))
    store.save(_pow_chain(2))

  leftovers = {p.name for p in tmp_path.iterdir()} - {"chain.json", "chain.json.lock"}
  assert leftovers == set()


def test_failed_json_save_keeps_previous_file_intact(tmp_path):
  path = tmp_path / "chain.json"
  good = _pow_chain(1)
  broken = [*good[:-1], replace(good[-1], timestamp=1.5)]

  with JsonChainStore(path) as store:
    store.save(good)
    before = path.read_bytes()
    with pytest.raises((ChainStoreError, ValueError, TypeError)):
      store.save(broken)
    assert path.read_bytes() == before
    assert store.load() == good

  leftovers = {p.name for p in tmp_path.iterdir()} - {"chain.json", "chain.json.lock"}
  assert leftovers == set()


# ---------------------------------------------------------------- locking (TC-8.8)


# TC-8.8
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_second_store_on_same_path_is_locked_out(tmp_path, backend):
  path = tmp_path / "chain.db"

  with backend(path):
    with pytest.raises(ChainStoreLockedError):
      backend(path)


# TC-8.8
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_lock_is_released_after_close_and_with_block(tmp_path, backend):
  path = tmp_path / "chain.db"

  store = backend(path)
  store.close()
  with backend(path):
    pass
  with backend(path):
    pass


# TC-8.8
def test_lock_is_per_path(tmp_path):
  with JsonChainStore(tmp_path / "a.json"), JsonChainStore(tmp_path / "b.json"):
    pass


# TC-8.8
def test_single_writer_requirement_is_documented():
  assert chain_store.__doc__ is not None
  assert "single-writer" in chain_store.__doc__


# ---------------------------------------------------------------- restore_chain


# TC-8.3
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_fresh_start_initializes_genesis_without_creating_file(tmp_path, backend):
  path = tmp_path / "chain.db"

  with backend(path) as store:
    restored = _restore(store, allow_fresh=True)

  assert restored.valid is True
  assert isinstance(restored.chain, Chain)
  assert restored.chain.blocks == (build_genesis_block(),)
  assert restored.blocks == (build_genesis_block(),)
  assert not path.exists()


# Security audit H2: a vanished chain file is never mistaken for a first start
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_missing_chain_without_explicit_init_fails_closed(tmp_path, backend):
  path = tmp_path / "chain.db"

  with backend(path) as store, pytest.raises(ChainStoreMissingError, match="allow_fresh"):
    _restore(store)
  assert not path.exists()


def test_deleted_chain_file_is_not_silently_reset_to_genesis(tmp_path):
  path = tmp_path / "chain.json"
  with JsonChainStore(path) as store:
    store.save(_pow_chain(2))
  path.unlink()  # attacker deletes the chain while the node is down

  with JsonChainStore(path) as store, pytest.raises(ChainStoreMissingError):
    _restore(store, expected_difficulty=_DIFFICULTY)


def test_restored_chain_is_frozen_dataclass(tmp_path):
  with JsonChainStore(tmp_path / "chain.json") as store:
    restored = _restore(store, allow_fresh=True)

  assert isinstance(restored, RestoredChain)
  with pytest.raises(FrozenInstanceError):
    restored.chain = None


@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_valid_pow_chain_restores_and_can_be_extended(tmp_path, backend):
  blocks = _pow_chain(2)
  path = tmp_path / "chain.db"
  with backend(path) as store:
    store.save(blocks)
  with backend(path) as store:
    restored = _restore(store, expected_difficulty=_DIFFICULTY)

  assert restored.valid
  assert restored.validation.valid
  assert restored.chain is not None
  assert restored.chain.blocks == tuple(blocks)
  assert restored.blocks == tuple(blocks)

  restored.chain.append(_pow_block(blocks[-1], 3))
  assert len(restored.chain) == 4


def test_valid_pbft_chain_restores_with_commit_signatures(tmp_path):
  blocks = _pbft_chain(2)
  with SqliteChainStore(tmp_path / "chain.db") as store:
    store.save(blocks)
    restored = _restore(store, validator_set=_VSET)

  assert restored.valid
  assert restored.chain.blocks == tuple(blocks)
  assert all(len(b.commit_signatures) == 3 for b in restored.chain.blocks[1:])
  restored.chain.append(_pbft_block(blocks[-1], 3))
  assert len(restored.chain) == 4


# TC-8.6
def test_tampered_metadata_is_reported_invalid_and_chain_refused(tmp_path):
  path = tmp_path / "chain.json"
  with JsonChainStore(path) as store:
    store.save(_pow_chain(2))
  _tamper_json_file(
    path, lambda doc: doc["blocks"][2]["document_records"][0]["metadata"].__setitem__("seed", 999)
  )

  with JsonChainStore(path) as store:
    restored = _restore(store, expected_difficulty=_DIFFICULTY)

  assert restored.valid is False
  assert restored.chain is None
  assert restored.validation.valid is False
  assert restored.validation.first_invalid_index == 2
  assert restored.validation.failure_type == "merkle"
  assert len(restored.blocks) == 3
  assert restored.blocks[2].document_records[0].metadata["seed"] == 999


# TC-8.6
def test_tampered_timestamp_is_reported_as_hash_failure(tmp_path):
  path = tmp_path / "chain.json"
  with JsonChainStore(path) as store:
    store.save(_pow_chain(2))
  _tamper_json_file(path, lambda doc: doc["blocks"][1].__setitem__("timestamp", 1_700_000_999_999))

  with JsonChainStore(path) as store:
    restored = _restore(store, expected_difficulty=_DIFFICULTY)

  assert restored.valid is False
  assert restored.chain is None
  assert restored.validation.first_invalid_index == 1
  assert restored.validation.failure_type == "hash"
  assert len(restored.blocks) == 3


# TC-8.6
def test_tampered_pbft_commit_signatures_report_quorum(tmp_path):
  path = tmp_path / "chain.json"
  with JsonChainStore(path) as store:
    store.save(_pbft_chain(1))
  _tamper_json_file(path, lambda doc: doc["blocks"][1].__setitem__("commit_signatures", []))

  with JsonChainStore(path) as store:
    restored = _restore(store, validator_set=_VSET)

  assert restored.valid is False
  assert restored.chain is None
  assert restored.validation.first_invalid_index == 1
  assert restored.validation.failure_type == "quorum"


# TC-8.10
def test_changed_expected_difficulty_fails_startup_by_design(tmp_path):
  with JsonChainStore(tmp_path / "chain.json") as store:
    store.save(_pow_chain(2, difficulty=1))
    still_ok = _restore(store, expected_difficulty=1)
    changed = _restore(store, expected_difficulty=2)

  assert still_ok.valid
  assert changed.valid is False
  assert changed.chain is None
  assert changed.validation.first_invalid_index == 1
  assert changed.validation.failure_type == "difficulty"
  assert len(changed.blocks) == 3


def test_chain_store_documents_difficulty_change_as_by_design():
  assert "difficulty" in (chain_store.restore_chain.__doc__ or "")


# ---------------------------------------------------------------- key loaders (TC-8.1/5/7/9)


# TC-8.1
def test_key_pairs_round_trip_with_correct_types(tmp_path):
  issuer, node = generate_issuer_keypair(), generate_node_keypair()
  save_key_pair(issuer, tmp_path / "issuer.pem")
  save_key_pair(node, tmp_path / "node.pem")

  loaded_issuer = load_issuer_key_pair(tmp_path / "issuer.pem")
  loaded_node = load_node_key_pair(tmp_path / "node.pem")

  assert isinstance(loaded_issuer, IssuerKeyPair)
  assert isinstance(loaded_node, NodeKeyPair)
  assert _sign_verify_roundtrip(loaded_issuer, issuer)
  assert _sign_verify_roundtrip(issuer, loaded_issuer)
  assert _sign_verify_roundtrip(loaded_node, node)
  assert _sign_verify_roundtrip(node, loaded_node)


# TC-8.5
def test_missing_issuer_key_has_issuer_wording_and_creates_nothing(tmp_path):
  path = tmp_path / "issuer.pem"

  with pytest.raises(IssuerKeyUnavailableError, match="issuer key material unavailable"):
    load_issuer_key_pair(path)

  assert not path.exists()
  assert list(tmp_path.iterdir()) == []


# TC-8.7
def test_missing_node_key_has_node_wording_and_creates_nothing(tmp_path):
  path = tmp_path / "node.pem"

  with pytest.raises(NodeKeyUnavailableError, match="node key material unavailable"):
    load_node_key_pair(path)

  assert not path.exists()
  assert list(tmp_path.iterdir()) == []


# TC-8.5, TC-8.7
def test_issuer_and_node_missing_errors_are_distinct(tmp_path):
  assert issubclass(IssuerKeyUnavailableError, KeyStoreMissingError)
  assert issubclass(NodeKeyUnavailableError, KeyStoreMissingError)
  assert not issubclass(IssuerKeyUnavailableError, NodeKeyUnavailableError)
  assert not issubclass(NodeKeyUnavailableError, IssuerKeyUnavailableError)

  with pytest.raises(IssuerKeyUnavailableError) as issuer_error:
    load_issuer_key_pair(tmp_path / "does-not-exist-issuer.pem")
  with pytest.raises(NodeKeyUnavailableError) as node_error:
    load_node_key_pair(tmp_path / "does-not-exist-node.pem")

  assert str(issuer_error.value) != str(node_error.value)
  assert "node key material unavailable" not in str(issuer_error.value)
  assert "issuer key material unavailable" not in str(node_error.value)


# TC-8.9
@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not meaningful on Windows")
def test_saved_key_files_are_not_group_or_world_accessible(tmp_path):
  save_key_pair(generate_issuer_keypair(), tmp_path / "issuer.pem")
  save_key_pair(generate_node_keypair(), tmp_path / "node.pem")

  for name in ("issuer.pem", "node.pem"):
    mode = stat.S_IMODE((tmp_path / name).stat().st_mode)
    assert mode & 0o077 == 0


# ---------------------------------------------------------------- restore_node_state (TC-8.1/5/7)


def _node_state_kwargs(tmp_path, **overrides):
  kwargs = {
    "issuer_key_path": tmp_path / "issuer.pem",
    "node_key_path": tmp_path / "node.pem",
    "resolve_node_key": _resolve_node_key,
    "resolve_issuer_key": _resolve_issuer_key,
  }
  kwargs.update(overrides)
  return kwargs


# TC-8.1
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_full_restart_round_trip(tmp_path, backend):
  blocks = _pbft_chain(2)
  issuer, node = generate_issuer_keypair(), generate_node_keypair()
  path = tmp_path / "chain.db"
  save_key_pair(issuer, tmp_path / "issuer.pem")
  save_key_pair(node, tmp_path / "node.pem")
  with backend(path) as store:
    store.save(blocks)

  # "Restart": a brand-new store instance on the same path.
  with backend(path) as new_store:
    state = restore_node_state(new_store, **_node_state_kwargs(tmp_path, validator_set=_VSET))

  assert isinstance(state, NodeState)
  assert state.restored.valid
  assert state.restored.chain.blocks == tuple(blocks)
  assert isinstance(state.issuer_key, IssuerKeyPair)
  assert isinstance(state.node_key, NodeKeyPair)
  assert _sign_verify_roundtrip(state.issuer_key, issuer)
  assert _sign_verify_roundtrip(issuer, state.issuer_key)
  assert _sign_verify_roundtrip(state.node_key, node)
  assert _sign_verify_roundtrip(node, state.node_key)


def test_node_state_is_frozen(tmp_path):
  save_key_pair(generate_issuer_keypair(), tmp_path / "issuer.pem")
  save_key_pair(generate_node_keypair(), tmp_path / "node.pem")
  with JsonChainStore(tmp_path / "chain.json") as store:
    state = restore_node_state(store, **_node_state_kwargs(tmp_path, allow_fresh=True))

  with pytest.raises(FrozenInstanceError):
    state.node_key = None


def test_node_state_on_fresh_start_begins_at_genesis(tmp_path):
  save_key_pair(generate_issuer_keypair(), tmp_path / "issuer.pem")
  save_key_pair(generate_node_keypair(), tmp_path / "node.pem")

  with JsonChainStore(tmp_path / "chain.json") as store:
    state = restore_node_state(store, **_node_state_kwargs(tmp_path, allow_fresh=True))

  assert state.restored.chain.blocks == (build_genesis_block(),)
  assert not (tmp_path / "chain.json").exists()


# TC-8.5
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_missing_issuer_key_fails_fast_even_when_chain_exists(tmp_path, backend):
  save_key_pair(generate_node_keypair(), tmp_path / "node.pem")
  with backend(tmp_path / "chain.db") as store:
    store.save(_pow_chain(1))

    with pytest.raises(IssuerKeyUnavailableError, match="issuer key material unavailable"):
      restore_node_state(store, **_node_state_kwargs(tmp_path, expected_difficulty=_DIFFICULTY))

  assert not (tmp_path / "issuer.pem").exists()


# TC-8.7
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_missing_node_key_fails_fast_even_when_chain_exists(tmp_path, backend):
  save_key_pair(generate_issuer_keypair(), tmp_path / "issuer.pem")
  with backend(tmp_path / "chain.db") as store:
    store.save(_pow_chain(1))

    with pytest.raises(NodeKeyUnavailableError, match="node key material unavailable"):
      restore_node_state(store, **_node_state_kwargs(tmp_path, expected_difficulty=_DIFFICULTY))

  assert not (tmp_path / "node.pem").exists()


# TC-8.5, TC-8.7
def test_both_keys_missing_reports_issuer_first_and_regenerates_nothing(tmp_path):
  with JsonChainStore(tmp_path / "chain.json") as store:
    with pytest.raises(IssuerKeyUnavailableError):
      restore_node_state(store, **_node_state_kwargs(tmp_path))

  assert not (tmp_path / "issuer.pem").exists()
  assert not (tmp_path / "node.pem").exists()


# TC-8.4
def test_node_state_with_corrupted_chain_raises(tmp_path):
  save_key_pair(generate_issuer_keypair(), tmp_path / "issuer.pem")
  save_key_pair(generate_node_keypair(), tmp_path / "node.pem")
  (tmp_path / "chain.json").write_bytes(b'{"format": "blockchain_core.chain", "vers')

  with JsonChainStore(tmp_path / "chain.json") as store:
    with pytest.raises(ChainStoreCorruptedError):
      restore_node_state(store, **_node_state_kwargs(tmp_path))


# TC-8.6
def test_node_state_with_tampered_chain_exposes_invalid_result(tmp_path):
  save_key_pair(generate_issuer_keypair(), tmp_path / "issuer.pem")
  save_key_pair(generate_node_keypair(), tmp_path / "node.pem")
  path = tmp_path / "chain.json"
  with JsonChainStore(path) as store:
    store.save(_pow_chain(1))
  _tamper_json_file(path, lambda doc: doc["blocks"][1].__setitem__("timestamp", 1_700_000_999_999))

  with JsonChainStore(path) as store:
    state = restore_node_state(store, **_node_state_kwargs(tmp_path, expected_difficulty=1))

  assert state.restored.valid is False
  assert state.restored.chain is None
  assert state.restored.validation.first_invalid_index == 1


# ---------------------------------------------------------------- audit hardening


# TC-8.4 (security audit M3): planted schema objects are refused, never executed on save
@pytest.mark.parametrize(
  "statement",
  [
    "CREATE TRIGGER trim AFTER INSERT ON blocks BEGIN DELETE FROM blocks WHERE position > 1; END",
    "CREATE VIEW extra AS SELECT 1",
    "CREATE TABLE extra (x INTEGER)",
    "CREATE INDEX by_data ON blocks (data)",
  ],
  ids=["trigger", "view", "table", "index"],
)
def test_sqlite_store_with_planted_schema_object_is_corrupted(tmp_path, statement):
  path = tmp_path / "chain.db"
  with SqliteChainStore(path) as store:
    store.save(_pow_chain(2))
  connection = sqlite3.connect(path)
  with connection:
    connection.execute(statement)
  connection.close()

  with SqliteChainStore(path) as store, pytest.raises(ChainStoreCorruptedError, match="schema"):
    store.load()


def test_sqlite_save_replaces_the_database_instead_of_reusing_its_schema(tmp_path):
  """A planted trigger cannot survive a save: the file is rebuilt, not updated in place."""
  path = tmp_path / "chain.db"
  blocks = _pow_chain(3)
  with SqliteChainStore(path) as store:
    store.save(blocks[:2])
  connection = sqlite3.connect(path)
  with connection:
    connection.execute(
      "CREATE TRIGGER trim AFTER INSERT ON blocks BEGIN DELETE FROM blocks WHERE position > 1; END"
    )
  connection.close()

  with SqliteChainStore(path) as store:
    store.save(blocks)
    assert store.load() == blocks
  assert sorted(p.name for p in tmp_path.iterdir()) == ["chain.db", "chain.db.lock"]


# TC-8.4 (security audit H2, partial): something other than a regular file is not "fresh"
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_directory_in_place_of_store_is_corrupted_not_fresh(tmp_path, backend):
  path = tmp_path / "chain.db"
  path.mkdir()

  with backend(path) as store, pytest.raises(ChainStoreCorruptedError, match="regular file"):
    store.load()


@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_dangling_symlink_in_place_of_store_is_corrupted_not_fresh(tmp_path, backend):
  path = tmp_path / "chain.db"
  try:
    os.symlink(tmp_path / "gone.db", path)
  except OSError:
    pytest.skip("creating symlinks needs extra privileges on this platform")

  with backend(path) as store, pytest.raises(ChainStoreCorruptedError, match="regular file"):
    store.load()


# TC-8.4 (security audit L1): deep nesting is corrupted, not an unhandled RecursionError
@pytest.mark.parametrize("field", ["sealed_consensus", "metadata"])
def test_deeply_nested_block_is_corrupted_not_recursion_error(field):
  document = _valid_document()
  placeholder = "@@NESTED@@"
  if field == "metadata":
    document["blocks"][1]["document_records"][0]["metadata"] = placeholder
  else:
    document["blocks"][1]["sealed_consensus"] = placeholder
  # Built as text: json.dumps itself cannot encode 5000 levels.
  nested = '{"x":' * 5000 + "{}" + "}" * 5000
  text = json.dumps(document).replace(f'"{placeholder}"', nested)

  with pytest.raises(ChainStoreCorruptedError):
    decode_chain(text.encode())


def test_block_from_dict_rejects_deep_nesting_directly():
  data = block_to_dict(_pow_chain(1)[1])
  nested: dict = {}
  for _ in range(100):
    nested = {"x": nested}
  data["sealed_consensus"] = nested

  with pytest.raises(ChainStoreCorruptedError, match="nesting"):
    block_from_dict(data)


# Security audit MINOR-5: an I/O failure on save is a write error, not "corruption"
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_save_io_failure_raises_write_error(tmp_path, backend):
  path = tmp_path / "chain.db"
  path.mkdir()  # os.replace onto a directory fails

  with backend(path) as store, pytest.raises(ChainStoreWriteError):
    store.save(_pow_chain(1))
  assert not issubclass(ChainStoreWriteError, ChainStoreCorruptedError)
  assert sorted(p.name for p in tmp_path.iterdir()) == ["chain.db", "chain.db.lock"]


# TC-8.5 / TC-8.7 (security audit L3): every unreadable key file is KeyStoreCorruptedError
def test_encrypted_private_key_file_is_corrupted_not_type_error(tmp_path):
  from cryptography.hazmat.primitives import serialization

  path = tmp_path / "issuer.pem"
  path.write_bytes(
    _ISSUER.private_key.private_bytes(
      serialization.Encoding.PEM,
      serialization.PrivateFormat.PKCS8,
      serialization.BestAvailableEncryption(b"secret"),
    )
  )

  with pytest.raises(KeyStoreCorruptedError):
    load_issuer_key_pair(path)


# Format v2: commit votes are {node_id, signature} objects, decoded strictly
@pytest.mark.parametrize(
  "commit",
  [
    "ab" * 32,
    {"node_id": "v0"},
    {"node_id": "v0", "signature": 5},
    {"node_id": 1, "signature": "ab"},
  ],
  ids=["bare_string", "missing_signature", "int_signature", "int_node_id"],
)
def test_malformed_commit_entry_is_corrupted(commit):
  data = block_to_dict(_pbft_chain(1)[1])
  data["commit_signatures"] = [commit]

  with pytest.raises(ChainStoreCorruptedError, match="commit_signatures"):
    block_from_dict(data)


def test_commit_votes_round_trip_with_their_node_ids():
  block = _pbft_chain(1)[1]

  data = block_to_dict(block)

  assert [commit["node_id"] for commit in data["commit_signatures"]] == list(_VALIDATOR_IDS[:3])
  assert block_from_dict(data).commit_signatures == block.commit_signatures
