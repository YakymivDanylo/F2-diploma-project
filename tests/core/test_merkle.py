from __future__ import annotations

from dataclasses import asdict

import pytest

from blockchain_core.canonical import canonicalize
from blockchain_core.document_record import create_document_record
from blockchain_core.hashing import sha256_hex
from blockchain_core.keys import generate_keypair
from blockchain_core.merkle import (
  DocumentHashNotFoundError,
  EmptyBatchError,
  ProofStep,
  build_proof,
  build_root,
  leaf_hash,
  verify_leaf_hash_proof,
  verify_proof,
)

_ISSUER = generate_keypair()


def _record(seed: int):
  document_hash = sha256_hex(f"document-{seed}".encode())
  return create_document_record(
    document_hash=document_hash,
    issuer_id="issuer-1",
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed},
    issuer_private_key=_ISSUER.private_key,
  )

def _naive_duplicating_root(leaves: list[str]) -> str:
  """A naive last-leaf-duplication Merkle build - the CVE-2012-2459-class scheme
  this project's domain-separated, promotion-based construction is built to avoid.
  """
  level = list(leaves)
  while len(level) > 1:
    if len(level) % 2 == 1:
      level.append(level[-1])
    level = [
      sha256_hex(b"\x01" + bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
      for i in range(0, len(level), 2)
    ]
  return level[0]


def test_leaf_hash_matches_domain_separated_formula():
  record = _record(0)
  expected = sha256_hex(b"\x00" + canonicalize(asdict(record)))
  assert leaf_hash(record) == expected


def test_build_root_of_two_leaves_matches_domain_separated_internal_formula():
  left, right = _record(0), _record(1)
  expected = sha256_hex(
    b"\x01" + bytes.fromhex(leaf_hash(left)) + bytes.fromhex(leaf_hash(right)),
  )
  assert build_root([left, right]) == expected


def test_build_root_degenerates_to_leaf_hash_for_single_record():
  record = _record(0)
  assert build_root([record]) == leaf_hash(record)


def test_build_root_promotes_unpaired_node_unchanged():
  records = [_record(0), _record(1), _record(2)]
  leaves = [leaf_hash(r) for r in records]
  expected = sha256_hex(
    b"\x01" + bytes.fromhex(sha256_hex(
      b"\x01" + bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1]),
    )) + bytes.fromhex(leaves[2]),
  )
  assert build_root(records) == expected


def test_build_root_promotes_consistently_across_multiple_levels():
  records = [_record(i) for i in range(5)]
  root = build_root(records)
  proof = build_proof(records, records[4].document_hash)
  assert [step.position for step in proof] == ["promoted", "promoted", "left"]
  assert verify_proof(records[4], proof, root) is True


def test_build_root_differs_from_naive_last_leaf_duplication_collision():
  records_three = [_record(0), _record(1), _record(2)]
  leaves_three = [leaf_hash(r) for r in records_three]

  naive_three_root = _naive_duplicating_root(leaves_three)

  leaves_four = [*leaves_three, leaves_three[2]]
  naive_four_root = _naive_duplicating_root(leaves_four)
  assert naive_three_root == naive_four_root

  our_root = build_root(records_three)
  assert our_root != naive_three_root
  assert our_root != naive_four_root
  assert our_root != build_root([*records_three, records_three[2]])


def test_build_root_raises_on_empty_batch():
  with pytest.raises(EmptyBatchError):
    build_root([])


def test_build_root_scales_well_for_a_several_hundred_leaf_batch():
  records = [_record(i) for i in range(500)]
  root = build_root(records)
  proof = build_proof(records, records[123].document_hash)
  assert verify_proof(records[123], proof, root) is True


@pytest.mark.parametrize("batch_size", range(1, 18))
def test_build_proof_and_verify_round_trip_for_every_index(batch_size):
  records = [_record(i) for i in range(batch_size)]
  root = build_root(records)
  for record in records:
    proof = build_proof(records, record.document_hash)
    assert verify_proof(record, proof, root) is True


def test_verify_leaf_hash_proof_accepts_a_bare_leaf_hash_without_the_full_record():
  records = [_record(i) for i in range(4)]
  root = build_root(records)
  target = records[2]
  proof = build_proof(records, target.document_hash)
  assert verify_leaf_hash_proof(leaf_hash(target), proof, root) is True


def test_build_proof_raises_for_a_document_hash_absent_from_the_batch():
  records = [_record(i) for i in range(3)]
  with pytest.raises(DocumentHashNotFoundError):
    build_proof(records, sha256_hex(b"never-issued"))


def test_build_proof_raises_on_empty_batch():
  with pytest.raises(EmptyBatchError):
    build_proof([], sha256_hex(b"anything"))


def test_verify_proof_fails_when_a_sibling_hash_is_altered():
  records = [_record(i) for i in range(4)]
  root = build_root(records)
  proof = build_proof(records, records[0].document_hash)
  tampered_step = proof[0]
  tampered = [
    ProofStep(position=tampered_step.position, sibling_hash=sha256_hex(b"tampered")),
    *proof[1:],
  ]
  assert verify_proof(records[0], tampered, root) is False


def test_verify_proof_fails_against_a_different_blocks_root():
  records_a = [_record(i) for i in range(4)]
  records_b = [_record(i) for i in range(10, 14)]
  root_b = build_root(records_b)
  proof_a = build_proof(records_a, records_a[0].document_hash)
  assert verify_proof(records_a[0], proof_a, root_b) is False


def test_build_proof_for_single_document_block_has_empty_path():
  record = _record(0)
  proof = build_proof([record], record.document_hash)
  assert proof == []
  assert verify_proof(record, proof, build_root([record])) is True


@pytest.mark.parametrize(
  ("position", "sibling_hash"),
  [("left", None), ("right", None), ("promoted", sha256_hex(b"unexpected"))],
)
def test_proof_step_rejects_a_position_sibling_hash_mismatch(position, sibling_hash):
  with pytest.raises(ValueError, match="ProofStep"):
    ProofStep(position=position, sibling_hash=sibling_hash)


def test_proof_step_rejects_an_unknown_position():
  with pytest.raises(ValueError, match="unknown ProofStep position"):
    ProofStep(position="up")

def test_verify_proof_fails_instead_of_raising_on_a_malformed_sibling_hash():
  records = [_record(i) for i in range(4)]
  root = build_root(records)
  proof = build_proof(records, records[0].document_hash)
  malformed = [
    ProofStep(position=proof[0].position, sibling_hash="not-a-hex-digest"),
    *proof[1:],
  ]
  assert verify_proof(records[0], malformed, root) is False


def test_verify_leaf_hash_proof_fails_instead_of_raising_on_a_malformed_leaf():
  records = [_record(i) for i in range(4)]
  root = build_root(records)
  proof = build_proof(records, records[0].document_hash)
  assert verify_leaf_hash_proof("not-a-hex-digest", proof, root) is False