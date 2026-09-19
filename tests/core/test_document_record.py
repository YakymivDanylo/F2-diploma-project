from __future__ import annotations

from dataclasses import replace

import pytest

from blockchain_core.document_record import (
  InvalidDocumentHashError,
  MissingDocumentFieldError,
  create_document_record,
  verify_document_record,
)
from blockchain_core.hashing import sha256_hex
from blockchain_core.keys import generate_keypair

VALID_HASH = "a" * 64


def test_create_and_verify_document_record_happy_path():
  issuer = generate_keypair()
  record = create_document_record(
    document_hash=VALID_HASH,
    issuer_id="issuer-1",
    issued_at=1_700_000_000_000,
    metadata={"title": "Diploma"},
    issuer_private_key=issuer.private_key,
  )
  assert record.signature is not None
  assert verify_document_record(record, issuer.public_key) is True


def test_create_document_record_from_raw_bytes_hashes_internally():
  issuer = generate_keypair()
  raw = b"raw document bytes"
  record = create_document_record(
    document_hash=raw,
    issuer_id="issuer-1",
    issued_at=1_700_000_000_000,
    metadata={},
    issuer_private_key=issuer.private_key,
  )
  assert record.document_hash == sha256_hex(raw)
  assert verify_document_record(record, issuer.public_key) is True


def test_create_document_record_stores_optional_ipfs_cid():
  issuer = generate_keypair()
  with_cid = create_document_record(
    VALID_HASH, "issuer-1", 1, {}, issuer.private_key, ipfs_cid="Qm123",
  )
  without_cid = create_document_record(
    VALID_HASH, "issuer-1", 1, {}, issuer.private_key,
  )
  assert with_cid.ipfs_cid == "Qm123"
  assert without_cid.ipfs_cid is None


@pytest.mark.parametrize("bad_hash", ["a" * 63, "a" * 65])
def test_create_document_record_rejects_wrong_length_hash(bad_hash):
  issuer = generate_keypair()
  with pytest.raises(InvalidDocumentHashError):
    create_document_record(bad_hash, "issuer-1", 1, {}, issuer.private_key)


def test_create_document_record_rejects_non_hex_characters():
  issuer = generate_keypair()
  bad_hash = "g" + "a" * 63
  with pytest.raises(InvalidDocumentHashError):
    create_document_record(bad_hash, "issuer-1", 1, {}, issuer.private_key)


@pytest.mark.parametrize(
  ("field", "kwargs"),
  [
    ("document_hash", {"document_hash": ""}),
    ("issuer_id", {"issuer_id": ""}),
    ("issued_at", {"issued_at": None}),
  ],
)
def test_create_document_record_rejects_missing_required_field(field, kwargs):
  issuer = generate_keypair()
  base = {
    "document_hash": VALID_HASH,
    "issuer_id": "issuer-1",
    "issued_at": 1,
    "metadata": {},
    "issuer_private_key": issuer.private_key,
  }
  base.update(kwargs)
  with pytest.raises(MissingDocumentFieldError):
    create_document_record(**base)


def test_create_document_record_allows_same_hash_issued_twice():
  issuer = generate_keypair()
  first = create_document_record(VALID_HASH, "issuer-1", 1, {}, issuer.private_key)
  second = create_document_record(VALID_HASH, "issuer-1", 2, {}, issuer.private_key)
  assert verify_document_record(first, issuer.public_key) is True
  assert verify_document_record(second, issuer.public_key) is True


def test_create_document_record_accepts_large_metadata_payload():
  issuer = generate_keypair()
  metadata = {"title": "x" * 100_000}
  record = create_document_record(VALID_HASH, "issuer-1", 1, metadata, issuer.private_key)
  assert verify_document_record(record, issuer.public_key) is True


@pytest.mark.parametrize("algorithm", ["ecdsa-p256", "rsa"])
def test_create_document_record_works_with_both_algorithms(algorithm):
  issuer = (
    generate_keypair(algorithm, rsa_key_size=2048)
    if algorithm == "rsa"
    else generate_keypair(algorithm)
  )
  record = create_document_record(VALID_HASH, "issuer-1", 1, {}, issuer.private_key)
  assert verify_document_record(record, issuer.public_key) is True


def test_verify_document_record_fails_on_altered_signature_byte():
  issuer = generate_keypair()
  record = create_document_record(VALID_HASH, "issuer-1", 1, {}, issuer.private_key)
  first_char = record.signature[0]
  flipped = "0" if first_char != "0" else "1"
  tampered = replace(record, signature=flipped + record.signature[1:])
  assert verify_document_record(tampered, issuer.public_key) is False


@pytest.mark.parametrize(
  "mutate",
  [
    lambda r: replace(r, document_hash="b" * 64),
    lambda r: replace(r, issuer_id="someone-else"),
    lambda r: replace(r, issued_at=999),
    lambda r: replace(r, metadata={"changed": True}),
  ],
)
def test_verify_document_record_fails_when_any_field_altered_post_signing(mutate):
  issuer = generate_keypair()
  record = create_document_record(VALID_HASH, "issuer-1", 1, {"a": 1}, issuer.private_key)
  tampered = mutate(record)
  assert verify_document_record(tampered, issuer.public_key) is False


def test_verify_document_record_fails_with_wrong_issuer_public_key():
  issuer = generate_keypair()
  other = generate_keypair()
  record = create_document_record(VALID_HASH, "issuer-1", 1, {}, issuer.private_key)
  assert verify_document_record(record, other.public_key) is False


def test_verify_document_record_handles_malformed_signature_without_raising():
  issuer = generate_keypair()
  record = create_document_record(VALID_HASH, "issuer-1", 1, {}, issuer.private_key)
  malformed = replace(record, signature="not-hex-zz")
  assert verify_document_record(malformed, issuer.public_key) is False


def test_verify_document_record_auto_dispatches_ecdsa_and_rsa():
  for algorithm in ("ecdsa-p256", "rsa"):
    issuer = (
      generate_keypair(algorithm, rsa_key_size=2048)
      if algorithm == "rsa"
      else generate_keypair(algorithm)
    )
    record = create_document_record(VALID_HASH, "issuer-1", 1, {}, issuer.private_key)
    assert verify_document_record(record, issuer.public_key) is True


def test_verify_document_record_against_superseded_key_still_succeeds():
  old_issuer = generate_keypair()
  record = create_document_record(VALID_HASH, "issuer-1", 1, {}, old_issuer.private_key)
  new_issuer = generate_keypair()
  assert verify_document_record(record, old_issuer.public_key) is True
  assert verify_document_record(record, new_issuer.public_key) is False
