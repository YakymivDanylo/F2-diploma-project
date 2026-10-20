"""Slice 9: tamper-detection composite suite (Epic 2 acceptance gate).

Covers BC-TC-7.1 .. 7.10 (UC-7 primary, UC-7-A, UC-7-B, UC-7-E1/EC1, UC-7-EC2).

Every scenario builds a legitimate chain (genesis + 4 blocks, two records per block), saves it
with a real store (JSON file or SQLite database) in `tmp_path`, tampers the PERSISTED data,
then opens a NEW store instance and calls `restore_chain`. The outcome is always
`valid is False`, `chain is None`, and the exact `first_invalid_index` / `failure_type`.
`first_invalid_index` is the block's position in the stored list (genesis = 0).

Trust anchors: the issuer public key (document records) and the node public key (block
proposer), both obtained from the key resolvers, i.e. never from the stored data itself.
"Re-mined" means the attacker redid the (cheap, difficulty 1) proof-of-work after the edit.

| Scenario (attacker action)                        | Detecting layer            | failure_type |
|---------------------------------------------------|----------------------------|--------------|
| 7.1 record metadata edited, nothing recomputed    | Merkle root                | merkle       |
| 7.2 timestamp/index/prev_hash edited, no rehash   | block hash (preimage)      | hash         |
| 7.3 tampered record checked on its own            | Merkle proof + issuer sig  | n/a (bool)   |
| 7.4 middle previous_hash edited, hash recomputed  | hash-chain link            | link         |
| 7.5 plain edit of a middle block or of the tip    | block hash, exact position | hash         |
| 7.6a middle preimage edit, rehashed + re-mined    | proposer signature         | signature    |
| 7.6b same, node key compromised (re-signed)       | link of the NEXT block     | link         |
| 7.7 tip preimage edit, rehashed + re-mined        | proposer signature ONLY    | signature    |
| 7.8 record field edit, node key compromised       | issuer sig (2nd layer)     | signature    |
| 7.9 edit re-signed with attacker's own key(s)     | signature vs KNOWN keys    | signature    |
| 7.10 tip timestamp-only edit, rehashed + re-mined | proposer signature         | signature    |
| PBFT commit signatures reduced below quorum       | commit quorum              | quorum       |
| PBFT tip edited, rehashed, proposer re-signed     | commit quorum (stale)      | quorum       |
| Control: untouched chain                          | none (restores valid)      | n/a          |

Notes for the thesis text:
- Hash, merkle and link checks are recomputations over the stored bytes, so an attacker who
  recomputes the values they touch gets past them; signatures cannot be recomputed without
  the private key, so they are the layer that stops a recomputing attacker.
- The tip has no successor, hence no link to break: for the tip the node key (proposer
  signature) is the only trust anchor (7.7, 7.10); once that key is compromised the tip edit
  is undetectable by this layer (7.7 shows the re-signed tip validates).
- A middle-block edit by an attacker holding the node key is still caught by the successor's
  `previous_hash` (7.6b), independently of any signature.
- Record-level integrity is a second, orthogonal layer: the issuer signature fails even
  when the node key is compromised and the block is perfectly re-hashed/re-signed (7.8).
- In PBFT, `commit_signatures` are over the preimage, so a rehashed block is left with stale
  commits and fails the quorum check even though its proposer signature is valid.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from blockchain_core.block import Block, attach_proposer_signature, build_candidate_block
from blockchain_core.document_record import create_document_record, verify_document_record
from blockchain_core.genesis import build_genesis_block
from blockchain_core.hashing import sha256_hex, sha256_of_canonical
from blockchain_core.keys import generate_issuer_keypair, generate_node_keypair
from blockchain_core.merkle import build_proof, build_root, verify_proof
from blockchain_core.signing import sign_canonical, verify_canonical
from blockchain_core.storage.chain_store import (
  JsonChainStore,
  SqliteChainStore,
  block_from_dict,
  block_to_dict,
  encode_chain,
  restore_chain,
)
from blockchain_core.validation import ValidatorSet, pow_target, validate_extension

_ISSUER = generate_issuer_keypair()
_ISSUER_ID = "issuer-1"
_VALIDATOR_IDS = ("v0", "v1", "v2", "v3")
_NODES = {node_id: generate_node_keypair() for node_id in _VALIDATOR_IDS}
_VSET = ValidatorSet(members=frozenset(_VALIDATOR_IDS), f=1)
_ATTACKER_ISSUER = generate_issuer_keypair()
_ATTACKER_NODE = generate_node_keypair()
_BASE_TS = 1_700_000_001_000
_STEP = 1_000
_DIFFICULTY = 1
_BACKENDS = [JsonChainStore, SqliteChainStore]
_BACKEND_IDS = ["json", "sqlite"]
_MIDDLE = 2
_TIP = 4
_FORGED_METADATA = {"seed": 999, "forged": True}


def _resolve_issuer_key(identity: str, at_timestamp: int):
  return _ISSUER.public_key if identity == _ISSUER_ID else None


def _resolve_node_key(identity: str, at_timestamp: int):
  pair = _NODES.get(identity)
  return pair.public_key if pair else None


def _record(seed: int):
  return create_document_record(
    document_hash=sha256_hex(f"document-{seed}".encode()),
    issuer_id=_ISSUER_ID,
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed, "tags": ["a", "b"], "nested": {"k": "v", "flag": True}},
    issuer_private_key=_ISSUER.private_key,
  )


def _candidate(previous: Block, seed: int, algorithm: str, sealed_consensus) -> Block:
  return build_candidate_block(
    [_record(seed), _record(seed + 1000)],
    previous_hash=previous.block_hash,
    index=previous.index + 1,
    timestamp=_BASE_TS + (previous.index + 1) * _STEP,
    proposer_id="v0",
    algorithm=algorithm,
    sealed_consensus=sealed_consensus,
    resolve_issuer_key=_resolve_issuer_key,
  )


def _mine(block: Block, difficulty: int = _DIFFICULTY) -> Block:
  target = pow_target(difficulty)
  nonce = 0
  while int(block.block_hash, 16) >= target:
    nonce += 1
    changed = replace(block, sealed_consensus={**block.sealed_consensus, "nonce": nonce})
    block = replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))
  return block


def _pow_block(previous: Block, seed: int) -> Block:
  block = _candidate(previous, seed, "pow", {"nonce": 0, "difficulty": _DIFFICULTY})
  return attach_proposer_signature(_mine(block), _NODES["v0"].private_key)


def _pbft_block(previous: Block, seed: int) -> Block:
  block = attach_proposer_signature(
    _candidate(previous, seed, "pbft", {"view_number": 0}), _NODES["v0"].private_key
  )
  signatures = tuple(
    sign_canonical(_NODES[node_id].private_key, block.preimage_dict())
    for node_id in _VALIDATOR_IDS[:3]
  )
  return replace(block, commit_signatures=signatures)


def _build_chain(make_block, length: int = 4) -> list[Block]:
  blocks = [build_genesis_block()]
  for seed in range(1, length + 1):
    blocks.append(make_block(blocks[-1], seed))
  return blocks


# Blocks are frozen dataclasses, so the built chains are shared; tests take list() copies.
_POW_CHAIN = _build_chain(_pow_block)
_PBFT_CHAIN = _build_chain(_pbft_block)


def _pow() -> list[Block]:
  return list(_POW_CHAIN)


def _pbft() -> list[Block]:
  return list(_PBFT_CHAIN)


def _forge(block: Block, **changes) -> Block:
  """Attacker edit: change fields, recompute block_hash, re-mine PoW. Signatures untouched."""
  changed = replace(block, **changes)
  rehashed = replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))
  return _mine(rehashed) if rehashed.algorithm == "pow" else rehashed


def _sign(block: Block, node_key_pair) -> Block:
  return attach_proposer_signature(block, node_key_pair.private_key)


def _with_block(blocks: list[Block], position: int, block: Block) -> list[Block]:
  return [*blocks[:position], block, *blocks[position + 1 :]]


def _save(backend, path, blocks) -> None:
  with backend(path) as store:
    store.save(blocks)


def _mutate_persisted(backend, path, edit) -> None:
  """Raw tamper of persisted data: `edit` receives the list of block dicts and mutates it.

  JSON: the file bytes are edited directly. SQLite: load -> mutate -> save through the
  store, modelling an attacker with write access to the database.
  """
  if backend is JsonChainStore:
    document = json.loads(path.read_bytes())
    edit(document["blocks"])
    path.write_bytes(json.dumps(document).encode())
    return
  with backend(path) as store:
    dicts = [block_to_dict(block) for block in store.load()]
    edit(dicts)
    store.save([block_from_dict(data) for data in dicts])


def _attacker_write(backend, path, blocks) -> None:
  """Attacker replaces the stored chain with a rebuilt one (blocks edited via Block objects)."""
  if backend is JsonChainStore:
    path.write_bytes(encode_chain(blocks))
  else:
    _save(backend, path, blocks)


def _consensus(pbft: bool) -> dict:
  """A network runs exactly one mode, so validation gets exactly one consensus parameter."""
  return {"validator_set": _VSET} if pbft else {"expected_difficulty": _DIFFICULTY}


def _restore(backend, path, *, pbft: bool = False):
  with backend(path) as store:  # a NEW store instance: nothing is carried over in memory
    return restore_chain(
      store,
      resolve_node_key=_resolve_node_key,
      resolve_issuer_key=_resolve_issuer_key,
      **_consensus(pbft),
    )


def _extend(trusted_tip: Block, blocks: list[Block], *, pbft: bool = False):
  return validate_extension(
    trusted_tip,
    blocks,
    resolve_node_key=_resolve_node_key,
    resolve_issuer_key=_resolve_issuer_key,
    **_consensus(pbft),
  )


def _assert_detected(restored, index: int, failure_type: str) -> None:
  assert restored.valid is False
  assert restored.chain is None
  assert restored.validation.first_invalid_index == index
  assert restored.validation.failure_type == failure_type
  assert len(restored.blocks) == 5  # the tampered chain is exposed for diagnostics only


def _stored_and_restored(backend, tmp_path, blocks, tamper):
  path = tmp_path / "chain.db"
  _save(backend, path, blocks)
  tamper(backend, path)
  return _restore(backend, path, pbft=blocks[1].algorithm == "pbft")


def _tampered_records(block: Block, **record_changes):
  first = replace(block.document_records[0], **record_changes)
  return (first, *block.document_records[1:])


# ---------------------------------------------------------------- control


# Control (UC-7 precondition): the untampered persisted chain is valid
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
@pytest.mark.parametrize("make_chain", [_pow, _pbft], ids=["pow", "pbft"])
def test_untampered_chain_restores_valid(tmp_path, backend, make_chain):
  blocks = make_chain()
  assert len(blocks) == 5
  assert all(len(block.document_records) >= 2 for block in blocks[1:])

  restored = _stored_and_restored(backend, tmp_path, blocks, lambda b, p: None)

  assert restored.valid is True
  assert restored.chain is not None
  assert restored.blocks == tuple(blocks)


# ---------------------------------------------------------------- TC-7.1 .. 7.3


# TC-7.1
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_record_metadata_edit_is_caught_by_merkle_root(tmp_path, backend):
  def tamper(b, path):
    _mutate_persisted(
      b,
      path,
      lambda blocks: blocks[_MIDDLE]["document_records"][0]["metadata"].update(_FORGED_METADATA),
    )

  restored = _stored_and_restored(backend, tmp_path, _pow(), tamper)

  _assert_detected(restored, _MIDDLE, "merkle")
  assert restored.blocks[_MIDDLE].document_records[0].metadata["seed"] == 999


# TC-7.2
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
@pytest.mark.parametrize(
  ("field", "value"),
  [("timestamp", _BASE_TS + 5_000), ("index", 7), ("previous_hash", "ab" * 32)],
  ids=["timestamp", "index", "previous_hash"],
)
def test_preimage_field_edit_without_rehash_is_caught_by_block_hash(
  tmp_path, backend, field, value
):
  def tamper(b, path):
    _mutate_persisted(b, path, lambda blocks: blocks[_MIDDLE].__setitem__(field, value))

  restored = _stored_and_restored(backend, tmp_path, _pow(), tamper)

  _assert_detected(restored, _MIDDLE, "hash")


# TC-7.3
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_tampered_record_fails_merkle_proof_and_issuer_signature_independently(tmp_path, backend):
  original = _pow()
  original_batch = original[_MIDDLE].document_records
  proof = build_proof(original_batch, original_batch[0].document_hash)

  def tamper(b, path):
    _mutate_persisted(
      b,
      path,
      lambda blocks: blocks[_MIDDLE]["document_records"][0]["metadata"].update(_FORGED_METADATA),
    )

  restored = _stored_and_restored(backend, tmp_path, original, tamper)
  stored_block = restored.blocks[_MIDDLE]
  tampered_record = stored_block.document_records[0]

  assert tampered_record.metadata["seed"] == 999
  assert stored_block.merkle_root == original[_MIDDLE].merkle_root
  # Merkle layer: the proof built from the ORIGINAL batch does not cover the tampered record.
  assert verify_proof(original_batch[0], proof, stored_block.merkle_root) is True
  assert verify_proof(tampered_record, proof, stored_block.merkle_root) is False
  # Issuer-signature layer: fails on its own, without any Merkle or block information.
  assert verify_document_record(original_batch[0], _ISSUER.public_key) is True
  assert verify_document_record(tampered_record, _ISSUER.public_key) is False
  _assert_detected(restored, _MIDDLE, "merkle")


# ---------------------------------------------------------------- TC-7.4, 7.5


# TC-7.4
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_previous_hash_edit_with_recomputed_hash_is_caught_by_link(tmp_path, backend):
  blocks = _pow()
  tampered = _forge(blocks[_MIDDLE], previous_hash="cd" * 32)
  assert tampered.block_hash != blocks[_MIDDLE].block_hash

  restored = _stored_and_restored(
    backend,
    tmp_path,
    blocks,
    lambda b, p: _attacker_write(b, p, _with_block(blocks, _MIDDLE, tampered)),
  )

  _assert_detected(restored, _MIDDLE, "link")


# TC-7.5
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
@pytest.mark.parametrize("position", [1, _MIDDLE, _TIP], ids=["first", "middle", "tip"])
def test_plain_edit_is_reported_at_the_exact_tampered_position(tmp_path, backend, position):
  def tamper(b, path):
    _mutate_persisted(
      b, path, lambda blocks: blocks[position].__setitem__("timestamp", _BASE_TS + 77_000)
    )

  restored = _stored_and_restored(backend, tmp_path, _pow(), tamper)

  _assert_detected(restored, position, "hash")


# ---------------------------------------------------------------- TC-7.6 .. 7.7


# TC-7.6 (a): attacker without the node key
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_middle_block_rehash_without_node_key_is_caught_by_proposer_signature(tmp_path, backend):
  blocks = _pow()
  tampered = _forge(blocks[_MIDDLE], timestamp=blocks[_MIDDLE].timestamp + 1)

  restored = _stored_and_restored(
    backend,
    tmp_path,
    blocks,
    lambda b, p: _attacker_write(b, p, _with_block(blocks, _MIDDLE, tampered)),
  )

  _assert_detected(restored, _MIDDLE, "signature")


# TC-7.6 (b): node key compromised, so only the hash chain remains
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_middle_block_rehash_with_compromised_node_key_is_caught_by_next_blocks_link(
  tmp_path, backend
):
  blocks = _pow()
  tampered = _sign(_forge(blocks[_MIDDLE], timestamp=blocks[_MIDDLE].timestamp + 1), _NODES["v0"])
  # The tampered middle block now passes every per-block check against its predecessor...
  assert _extend(blocks[_MIDDLE - 1], [tampered]).valid is True
  # ...but its successor still points at the ORIGINAL hash.
  assert blocks[_MIDDLE + 1].previous_hash != tampered.block_hash
  assert blocks[_MIDDLE + 1].previous_hash == blocks[_MIDDLE].block_hash

  restored = _stored_and_restored(
    backend,
    tmp_path,
    blocks,
    lambda b, p: _attacker_write(b, p, _with_block(blocks, _MIDDLE, tampered)),
  )

  _assert_detected(restored, _MIDDLE + 1, "link")


def _reorder_tip(tip: Block) -> Block:
  """Content tamper that keeps every record and issuer signature valid: reverse the batch."""
  reordered = tuple(reversed(tip.document_records))
  return _forge(tip, document_records=reordered, merkle_root=build_root(reordered))


# TC-7.7 (central M-1 test): the tip has no successor, so only the proposer signature remains
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_tip_rehash_is_caught_exclusively_by_proposer_signature(tmp_path, backend):
  """The node key is the trust anchor for the tip: nothing else can detect this edit.

  The tampered tip passes the hash, link and merkle layers (and the issuer signatures of its
  untouched records), and re-signing it with the legitimate node key makes the whole chain
  valid again. Only the stale `proposer_signature` exposes the edit.
  """
  blocks = _pow()
  tip = blocks[_TIP]
  tampered = _reorder_tip(tip)

  # Hash, link and merkle layers are satisfied by the attacker's recomputation.
  assert tampered.block_hash != tip.block_hash
  assert sha256_of_canonical(tampered.preimage_dict()) == tampered.block_hash
  assert tampered.previous_hash == blocks[_TIP - 1].block_hash
  assert build_root(tampered.document_records) == tampered.merkle_root
  assert tampered.proposer_signature == tip.proposer_signature
  assert (
    verify_canonical(_NODES["v0"].public_key, tampered.preimage_dict(), tampered.proposer_signature)
    is False
  )
  # Exclusively the signature layer reports it (not "hash"/"link"/"merkle").
  assert _extend(blocks[_TIP - 1], [tampered]).failure_type == "signature"

  restored = _stored_and_restored(
    backend,
    tmp_path,
    blocks,
    lambda b, p: _attacker_write(b, p, _with_block(blocks, _TIP, tampered)),
  )
  _assert_detected(restored, _TIP, "signature")

  # With the node key the very same edit becomes undetectable: the key is the trust anchor.
  resigned = _sign(tampered, _NODES["v0"])
  assert _extend(blocks[_TIP - 1], [resigned]).valid is True
  _attacker_write(backend, tmp_path / "chain.db", _with_block(blocks, _TIP, resigned))
  assert _restore(backend, tmp_path / "chain.db").valid is True


# ---------------------------------------------------------------- TC-7.8, 7.9, 7.10


# TC-7.8
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
@pytest.mark.parametrize(
  ("field", "value"),
  [("metadata", _FORGED_METADATA), ("issued_at", 1_700_000_000_123)],
  ids=["metadata", "issued_at"],
)
def test_record_field_edit_with_compromised_node_key_is_caught_by_issuer_signature(
  tmp_path, backend, field, value
):
  blocks = _pow()
  original = blocks[_MIDDLE]
  records = _tampered_records(original, **{field: value})
  tampered = _sign(
    _forge(original, document_records=records, merkle_root=build_root(records)), _NODES["v0"]
  )

  # Every block-level layer is satisfied, including the proposer signature...
  assert sha256_of_canonical(tampered.preimage_dict()) == tampered.block_hash
  assert build_root(tampered.document_records) == tampered.merkle_root
  assert (
    verify_canonical(_NODES["v0"].public_key, tampered.preimage_dict(), tampered.proposer_signature)
    is True
  )
  # ...yet the record's own issuer signature does not verify.
  assert verify_document_record(tampered.document_records[0], _ISSUER.public_key) is False

  restored = _stored_and_restored(
    backend,
    tmp_path,
    blocks,
    lambda b, p: _attacker_write(b, p, _with_block(blocks, _MIDDLE, tampered)),
  )

  _assert_detected(restored, _MIDDLE, "signature")


def _forge_with_attacker_keys(original: Block, *, record: bool, block: bool) -> Block:
  """Content edit re-signed with attacker-owned keys; `record`/`block` pick which layers."""
  records = original.document_records
  if record:
    first = original.document_records[0]
    forged_record = create_document_record(
      document_hash=first.document_hash,
      issuer_id=first.issuer_id,
      issued_at=first.issued_at,
      metadata=_FORGED_METADATA,
      issuer_private_key=_ATTACKER_ISSUER.private_key,
    )
    assert verify_document_record(forged_record, _ATTACKER_ISSUER.public_key) is True
    records = (forged_record, *original.document_records[1:])
  forged = _forge(
    original,
    document_records=records,
    merkle_root=build_root(records),
    timestamp=original.timestamp + 1,
  )
  return _sign(forged, _ATTACKER_NODE if block else _NODES["v0"])


# TC-7.9
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
@pytest.mark.parametrize(
  ("record", "block"),
  [(True, True), (False, True), (True, False)],
  ids=["record_and_block", "block_only", "record_only"],
)
def test_resigning_with_attackers_own_keys_fails_against_known_public_keys(
  tmp_path, backend, record, block
):
  blocks = _pow()
  tampered = _forge_with_attacker_keys(blocks[_MIDDLE], record=record, block=block)
  if block:
    # Self-consistent for the attacker: it verifies under the attacker's own public key only.
    assert (
      verify_canonical(
        _ATTACKER_NODE.public_key, tampered.preimage_dict(), tampered.proposer_signature
      )
      is True
    )
    assert (
      verify_canonical(
        _NODES["v0"].public_key, tampered.preimage_dict(), tampered.proposer_signature
      )
      is False
    )

  restored = _stored_and_restored(
    backend,
    tmp_path,
    blocks,
    lambda b, p: _attacker_write(b, p, _with_block(blocks, _MIDDLE, tampered)),
  )

  _assert_detected(restored, _MIDDLE, "signature")


# TC-7.10
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_tip_timestamp_only_edit_with_recomputed_hash_is_caught_by_signature(tmp_path, backend):
  blocks = _pow()
  tip = blocks[_TIP]
  tampered = _forge(tip, timestamp=tip.timestamp + 500)  # still >= previous timestamp
  assert tampered.document_records == tip.document_records
  assert tampered.merkle_root == tip.merkle_root

  # The hash-chain layers pass; the verdict is "signature", not "hash"/"link".
  extension = _extend(blocks[_TIP - 1], [tampered])
  assert extension.failure_type == "signature"
  assert extension.first_invalid_index == _TIP

  restored = _stored_and_restored(
    backend,
    tmp_path,
    blocks,
    lambda b, p: _attacker_write(b, p, _with_block(blocks, _TIP, tampered)),
  )

  _assert_detected(restored, _TIP, "signature")


# ---------------------------------------------------------------- PBFT


# PBFT: commit set reduced below quorum (commits are not hashed, so only the quorum catches it)
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
@pytest.mark.parametrize("remaining", [0, 1, 2], ids=["none", "one", "two"])
def test_pbft_commit_signatures_reduced_below_quorum_are_caught(tmp_path, backend, remaining):
  assert len(_PBFT_CHAIN[_MIDDLE].commit_signatures) == _VSET.quorum == 3

  def tamper(b, path):
    _mutate_persisted(
      b,
      path,
      lambda blocks: blocks[_MIDDLE].__setitem__(
        "commit_signatures", blocks[_MIDDLE]["commit_signatures"][:remaining]
      ),
    )

  restored = _stored_and_restored(backend, tmp_path, _pbft(), tamper)

  _assert_detected(restored, _MIDDLE, "quorum")


# PBFT: tampered + rehashed tip, proposer re-signed, commits still over the old preimage
@pytest.mark.parametrize("backend", _BACKENDS, ids=_BACKEND_IDS)
def test_pbft_tip_rehash_with_proposer_resign_is_caught_by_stale_commits(tmp_path, backend):
  blocks = _pbft()
  tip = blocks[_TIP]
  tampered = _sign(_forge(tip, timestamp=tip.timestamp + 500), _NODES["v0"])
  assert tampered.commit_signatures == tip.commit_signatures  # commits cover the old preimage

  extension = _extend(blocks[_TIP - 1], [tampered], pbft=True)
  assert extension.failure_type == "quorum"  # hash, link, merkle and signature all passed

  restored = _stored_and_restored(
    backend,
    tmp_path,
    blocks,
    lambda b, p: _attacker_write(b, p, _with_block(blocks, _TIP, tampered)),
  )

  _assert_detected(restored, _TIP, "quorum")
