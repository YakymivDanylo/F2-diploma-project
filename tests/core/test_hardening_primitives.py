"""Regression tests for the security hardening of the core primitives.

Covers canonical encoding, signature malleability / algorithm policy, key roles,
DocumentRecord immutability and key-store file safety.
"""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import os
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
  decode_dss_signature,
  encode_dss_signature,
)

from blockchain_core import canonical
from blockchain_core.block import Block, attach_proposer_signature
from blockchain_core.canonical import CanonicalizationError, canonicalize, deep_freeze
from blockchain_core.document_record import (
  InvalidDocumentHashError,
  MissingDocumentFieldError,
  create_document_record,
  verify_document_record,
)
from blockchain_core.keys import (
  InsufficientKeySizeError,
  IssuerKeyPair,
  KeyPair,
  NodeKeyPair,
  UnsupportedAlgorithmError,
  WrongKeyRoleError,
  generate_issuer_keypair,
  generate_keypair,
  generate_node_keypair,
  is_acceptable_public_key,
  private_key_from_pem,
  private_key_to_pem,
  public_key_from_pem,
  public_key_to_pem,
)
from blockchain_core.signing import sign_bytes, sign_canonical, verify_bytes, verify_canonical
from blockchain_core.storage.key_store import (
  KeyStoreCorruptedError,
  KeyStoreExistsError,
  load_key_pair,
  save_key_pair,
)

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
VECTORS_PATH = Path(__file__).resolve().parent.parent / "vectors" / "canonical_vectors.json"
VECTORS_SHA256 = "4ab333f39e0a38c16588b743f9d7aa71e5f35333986a0aec77ddeb22fd8902b3"
GOOD_HASH = "a" * 64


@pytest.fixture(scope="module")
def rsa_pair() -> KeyPair:
  return generate_keypair("rsa", rsa_key_size=2048)


# ---------------------------------------------------------------- canonical

@pytest.mark.parametrize("value", [
  1.5, b"bytes", {1, 2}, Decimal("1.0"), datetime(2024, 1, 1),
])
def test_canonical_rejects_unsupported_types(value):
  with pytest.raises(CanonicalizationError, match="forbids"):
    canonicalize({"k": value})


def test_canonical_error_is_not_type_error():
  assert not issubclass(CanonicalizationError, TypeError)
  with pytest.raises(CanonicalizationError):
    canonicalize(b"raw")


def test_canonical_tuple_encodes_like_list():
  assert canonicalize({"a": (1, "x", None)}) == canonicalize({"a": [1, "x", None]})


def test_canonical_rejects_float_inside_tuple():
  with pytest.raises(CanonicalizationError, match="float"):
    canonicalize({"a": (1, 2.5)})


def test_canonical_rejects_lone_surrogate_in_value():
  with pytest.raises(CanonicalizationError, match="surrogate"):
    canonicalize({"a": "\ud800"})


def test_canonical_rejects_lone_surrogate_in_key():
  with pytest.raises(CanonicalizationError, match="surrogate"):
    canonicalize({"\ud800": 1})


def test_canonical_int_bounds():
  assert canonicalize(2**64 - 1) == str(2**64 - 1).encode()
  assert canonicalize(-(2**64 - 1)) == str(-(2**64 - 1)).encode()
  with pytest.raises(CanonicalizationError, match="2\\*\\*64"):
    canonicalize(2**64)
  with pytest.raises(CanonicalizationError, match="2\\*\\*64"):
    canonicalize(-(2**64))


def _nest(levels: int):
  value: object = []
  for _ in range(levels - 1):
    value = [value]
  return value


def test_canonical_depth_limit():
  assert canonicalize(_nest(canonical.MAX_DEPTH)) is not None
  with pytest.raises(CanonicalizationError, match="nesting"):
    canonicalize(_nest(canonical.MAX_DEPTH + 2))


def test_canonical_huge_nesting_does_not_hit_recursion_error():
  with pytest.raises(CanonicalizationError, match="nesting"):
    canonicalize(_nest(100_000))


def test_canonical_rejects_non_str_keys_nested_and_in_tuples():
  with pytest.raises(CanonicalizationError, match="non-string keys"):
    canonicalize({"a": {"b": {1: "x"}}})
  with pytest.raises(CanonicalizationError, match="non-string keys"):
    canonicalize(({1: "x"},))
  with pytest.raises(CanonicalizationError, match="non-string keys"):
    canonicalize([({"ok": 1}, {None: 2})])


def test_canonical_mapping_proxy_matches_dict():
  data = {"b": [1, 2], "a": {"z": True}}
  assert canonicalize(MappingProxyType({"b": [1, 2], "a": MappingProxyType({"z": True})})) \
    == canonicalize(data)


def test_deep_freeze_is_immutable():
  frozen = deep_freeze({"a": [1, {"b": [2, 3]}], "c": "x"})
  with pytest.raises(TypeError):
    frozen["c"] = "y"
  with pytest.raises(TypeError):
    frozen["a"][1]["b"] = 0
  assert isinstance(frozen["a"], tuple)
  assert isinstance(frozen["a"][1]["b"], tuple)
  assert not hasattr(frozen["a"], "append")


def test_deep_freeze_preserves_canonical_bytes():
  data = {"a": [1, {"b": [2, 3]}], "c": None, "d": ["x", ["y"]]}
  assert canonicalize(deep_freeze(data)) == canonicalize(data)


def test_deep_freeze_does_not_mutate_input():
  data = {"a": [1, {"b": [2, 3]}]}
  snapshot = copy.deepcopy(data)
  deep_freeze(data)
  assert data == snapshot
  assert isinstance(data["a"], list)
  data["a"].append(4)


# ------------------------------------------------------------ vectors guard

def test_canonical_vectors_file_is_pinned():
  """The vectors are immutable: other implementations rely on these exact bytes.

  A change to tests/vectors/canonical_vectors.json is a change to the wire format and
  must be deliberate - update this pinned digest only together with a format-version bump.
  """
  content = VECTORS_PATH.read_bytes().replace(b"\r\n", b"\n")
  assert hashlib.sha256(content).hexdigest() == VECTORS_SHA256


# ------------------------------------------------------------------ signing

def test_verify_bytes_rejects_non_canonical_signature_encodings():
  pair = generate_keypair()
  data = b"payload"
  sig = sign_bytes(pair.private_key, data)
  assert verify_bytes(pair.public_key, data, sig)
  assert not verify_bytes(pair.public_key, data, sig.upper())
  assert not verify_bytes(pair.public_key, data, sig[:10] + " " + sig[10:])
  assert not verify_bytes(pair.public_key, data, sig + "\n")
  assert not verify_bytes(pair.public_key, data, sig[:-1])
  assert not verify_bytes(pair.public_key, data, "")
  assert not verify_bytes(pair.public_key, data, bytes.fromhex(sig))  # type: ignore[arg-type]
  assert not verify_bytes(pair.public_key, data, None)  # type: ignore[arg-type]
  assert not verify_bytes(pair.public_key, data, 12345)  # type: ignore[arg-type]


def test_verify_bytes_rejects_ed25519_key():
  key = ed25519.Ed25519PrivateKey.generate()
  sig = key.sign(b"payload").hex()
  assert verify_bytes(key.public_key(), b"payload", sig) is False  # type: ignore[arg-type]


def test_verify_bytes_rejects_high_s_variant():
  pair = generate_keypair()
  data = b"malleable"
  sig = sign_bytes(pair.private_key, data)
  assert verify_bytes(pair.public_key, data, sig)
  r, s = decode_dss_signature(bytes.fromhex(sig))
  high = encode_dss_signature(r, P256_ORDER - s).hex()
  assert high != sig
  assert verify_bytes(pair.public_key, data, high) is False


def test_sign_bytes_always_low_s():
  pair = generate_keypair()
  for i in range(50):
    sig = sign_bytes(pair.private_key, f"msg-{i}".encode())
    _, s = decode_dss_signature(bytes.fromhex(sig))
    assert s <= P256_ORDER // 2


def _flip_middle_byte(sig_hex: str) -> str:
  raw = bytearray(bytes.fromhex(sig_hex))
  raw[len(raw) // 2] ^= 0x01
  return bytes(raw).hex()


def test_flipped_middle_byte_fails_ecdsa():
  pair = generate_keypair()
  sig = sign_bytes(pair.private_key, b"data")
  assert not verify_bytes(pair.public_key, b"data", _flip_middle_byte(sig))


def test_flipped_middle_byte_fails_rsa(rsa_pair):
  sig = sign_bytes(rsa_pair.private_key, b"data")
  assert verify_bytes(rsa_pair.public_key, b"data", sig)
  assert not verify_bytes(rsa_pair.public_key, b"data", _flip_middle_byte(sig))


@pytest.mark.parametrize("sig", ["00", "ab" * 3, "00" * 70, "30" + "00" * 20, "ff" * 64])
def test_verify_bytes_garbage_signature_is_false(sig, rsa_pair):
  ec_pair = generate_keypair()
  assert verify_bytes(ec_pair.public_key, b"data", sig) is False
  assert verify_bytes(rsa_pair.public_key, b"data", sig) is False


def test_verify_canonical_unencodable_object_returns_false():
  pair = generate_keypair()
  sig = sign_canonical(pair.private_key, {"a": 1})
  assert verify_canonical(pair.public_key, {"a": 1}, sig) is True
  assert verify_canonical(pair.public_key, {"a": 1.5}, sig) is False
  assert verify_canonical(pair.public_key, {"a": b"x"}, sig) is False


@pytest.mark.parametrize("curve", [ec.SECP256K1(), ec.SECP384R1()])
def test_non_p256_curves_rejected(curve):
  private = ec.generate_private_key(curve)
  public = private.public_key()
  assert is_acceptable_public_key(public) is False
  sig = private.sign(b"data", ec.ECDSA(hashes.SHA256()))
  assert verify_bytes(public, b"data", sig.hex()) is False
  with pytest.raises(UnsupportedAlgorithmError, match="rejected"):
    public_key_from_pem(public_key_to_pem(public))
  with pytest.raises(UnsupportedAlgorithmError, match="rejected"):
    private_key_from_pem(private_key_to_pem(private))


def test_rsa_1024_rejected():
  private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
  public = private.public_key()
  assert is_acceptable_public_key(public) is False
  sig = sign_bytes(private, b"data")
  assert verify_bytes(public, b"data", sig) is False
  with pytest.raises(UnsupportedAlgorithmError, match="rejected"):
    public_key_from_pem(public_key_to_pem(public))
  with pytest.raises(UnsupportedAlgorithmError, match="rejected"):
    private_key_from_pem(private_key_to_pem(private))


def test_rsa_key_size_policy_on_generation():
  with pytest.raises(InsufficientKeySizeError, match="at least 2048"):
    generate_keypair("rsa", rsa_key_size=2047)
  pair = generate_keypair("rsa", rsa_key_size=2048)
  assert pair.private_key.key_size == 2048


def test_is_acceptable_public_key_matrix(rsa_pair):
  assert is_acceptable_public_key(generate_keypair().public_key) is True
  assert is_acceptable_public_key(rsa_pair.public_key) is True
  assert is_acceptable_public_key(
    rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()) is False
  assert is_acceptable_public_key(ec.generate_private_key(ec.SECP256K1()).public_key()) is False
  assert is_acceptable_public_key(ed25519.Ed25519PrivateKey.generate().public_key()) is False
  assert is_acceptable_public_key("not a key") is False
  assert is_acceptable_public_key(None) is False


# --------------------------------------------------------------------- keys

def test_issuer_and_node_pairs_are_distinct_key_pair_types():
  issuer = generate_issuer_keypair()
  node = generate_node_keypair()
  assert isinstance(issuer, IssuerKeyPair)
  assert isinstance(node, NodeKeyPair)
  assert isinstance(issuer, KeyPair)
  assert isinstance(node, KeyPair)
  assert not isinstance(issuer, NodeKeyPair)
  assert not isinstance(node, IssuerKeyPair)
  assert not issubclass(IssuerKeyPair, NodeKeyPair)
  assert not issubclass(NodeKeyPair, IssuerKeyPair)


def test_create_document_record_accepts_issuer_pair_and_bare_key():
  issuer = generate_issuer_keypair()
  from_pair = create_document_record(GOOD_HASH, "iss", 1, {}, issuer)
  from_bare = create_document_record(GOOD_HASH, "iss", 1, {}, issuer.private_key)
  assert verify_document_record(from_pair, issuer.public_key)
  assert verify_document_record(from_bare, issuer.public_key)


def test_create_document_record_rejects_node_pair():
  with pytest.raises(WrongKeyRoleError, match="NodeKeyPair"):
    create_document_record(GOOD_HASH, "iss", 1, {}, generate_node_keypair())


def _bare_block() -> Block:
  return Block(
    index=1, timestamp=1, previous_hash="0" * 64, merkle_root="1" * 64,
    proposer_id="node", algorithm="pow", sealed_consensus={}, document_records=(),
    block_hash="2" * 64,
  )


def test_attach_proposer_signature_accepts_node_pair_and_rejects_issuer_pair():
  node = generate_node_keypair()
  block = attach_proposer_signature(_bare_block(), node)
  assert block.proposer_signature is not None
  assert verify_canonical(node.public_key, block.preimage_dict(), block.proposer_signature)
  with pytest.raises(WrongKeyRoleError, match="IssuerKeyPair"):
    attach_proposer_signature(_bare_block(), generate_issuer_keypair())


def test_issuer_and_node_generators_never_share_key_material(tmp_path):
  issuer = generate_issuer_keypair()
  node = generate_node_keypair()
  assert public_key_to_pem(issuer.public_key) != public_key_to_pem(node.public_key)
  assert private_key_to_pem(issuer.private_key) != private_key_to_pem(node.private_key)
  issuer_path = tmp_path / "issuer.key"
  node_path = tmp_path / "node.key"
  save_key_pair(issuer, issuer_path)
  save_key_pair(node, node_path)
  assert issuer_path.read_bytes() != node_path.read_bytes()
  assert (tmp_path / "issuer.key.pub").read_bytes() != (tmp_path / "node.key.pub").read_bytes()


# ---------------------------------------------------------- document_record

def test_uppercase_document_hash_rejected():
  with pytest.raises(InvalidDocumentHashError, match="lowercase hex"):
    create_document_record("A" * 64, "iss", 1, {}, generate_issuer_keypair())


def test_altering_ipfs_cid_after_signing_fails_verification():
  issuer = generate_issuer_keypair()
  record = create_document_record(GOOD_HASH, "iss", 1, {}, issuer, ipfs_cid="QmOriginal")
  assert verify_document_record(record, issuer.public_key)
  tampered = dataclasses.replace(record, ipfs_cid="QmTampered")
  assert verify_document_record(tampered, issuer.public_key) is False
  assert verify_document_record(dataclasses.replace(record, ipfs_cid=None),
                                issuer.public_key) is False


def test_ipfs_cid_none_vs_value_changes_signed_content():
  issuer = generate_issuer_keypair()
  without = create_document_record(GOOD_HASH, "iss", 1, {}, issuer, ipfs_cid=None)
  with_cid = create_document_record(GOOD_HASH, "iss", 1, {}, issuer, ipfs_cid="QmAbc")
  assert canonicalize(without.unsigned_dict()) != canonicalize(with_cid.unsigned_dict())
  assert without.signed_dict() != with_cid.signed_dict()
  assert verify_document_record(without, issuer.public_key)
  assert verify_document_record(with_cid, issuer.public_key)
  assert verify_document_record(
    dataclasses.replace(without, signature=with_cid.signature), issuer.public_key) is False


def test_record_metadata_is_detached_from_callers_dict():
  issuer = generate_issuer_keypair()
  original = {"title": "Diploma", "tags": ["a", ["b"]], "nested": {"k": "v"}}
  record = create_document_record(GOOD_HASH, "iss", 1, original, issuer)
  original["title"] = "Forged"
  original["tags"].append("c")
  original["nested"]["k"] = "changed"
  assert record.metadata["title"] == "Diploma"
  assert record.metadata["tags"] == ("a", ("b",))
  assert record.metadata["nested"]["k"] == "v"
  assert verify_document_record(record, issuer.public_key)


def test_record_metadata_is_read_only():
  issuer = generate_issuer_keypair()
  record = create_document_record(GOOD_HASH, "iss", 1, {"tags": [1, [2]]}, issuer)
  with pytest.raises(TypeError):
    record.metadata["x"] = 1  # type: ignore[index]
  assert isinstance(record.metadata["tags"], tuple)
  assert isinstance(record.metadata["tags"][1], tuple)


@pytest.mark.parametrize("bad", [1.0, 1700000000000.5, "1700000000000", True, False])
def test_issued_at_must_be_a_real_int(bad):
  with pytest.raises(MissingDocumentFieldError, match="issued_at"):
    create_document_record(GOOD_HASH, "iss", bad, {}, generate_issuer_keypair())


def test_metadata_none_rejected():
  with pytest.raises(MissingDocumentFieldError, match="metadata"):
    create_document_record(GOOD_HASH, "iss", 1, None, generate_issuer_keypair())  # type: ignore[arg-type]


def test_signed_dict_is_unsigned_dict_plus_signature():
  issuer = generate_issuer_keypair()
  record = create_document_record(GOOD_HASH, "iss", 1, {"a": 1}, issuer, ipfs_cid="Qm1")
  assert "signature" not in record.unsigned_dict()
  assert record.signed_dict() == {**record.unsigned_dict(), "signature": record.signature}
  assert record.signed_dict()["signature"] is not None


# ---------------------------------------------------------------- key_store

def test_save_without_force_keeps_existing_file_untouched(tmp_path):
  path = tmp_path / "k.pem"
  save_key_pair(generate_keypair(), path)
  before = path.read_bytes()
  pub_before = (tmp_path / "k.pem.pub").read_bytes()
  with pytest.raises(KeyStoreExistsError, match="already exists"):
    save_key_pair(generate_keypair(), path)
  assert path.read_bytes() == before
  assert (tmp_path / "k.pem.pub").read_bytes() == pub_before
  assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_save_without_force_refuses_when_only_pub_exists(tmp_path):
  path = tmp_path / "k.pem"
  save_key_pair(generate_keypair(), path)
  path.unlink()
  pub_before = (tmp_path / "k.pem.pub").read_bytes()
  with pytest.raises(KeyStoreExistsError, match="already exists"):
    save_key_pair(generate_keypair(), path)
  assert not path.exists()
  assert (tmp_path / "k.pem.pub").read_bytes() == pub_before


def test_save_with_force_overwrites_atomically(tmp_path):
  path = tmp_path / "k.pem"
  save_key_pair(generate_keypair(), path)
  new_pair = generate_keypair()
  save_key_pair(new_pair, path, force=True)
  loaded = load_key_pair(path)
  assert private_key_to_pem(loaded.private_key) == private_key_to_pem(new_pair.private_key)
  assert public_key_to_pem(loaded.public_key) == public_key_to_pem(new_pair.public_key)
  assert (tmp_path / "k.pem.pub").read_bytes() == public_key_to_pem(new_pair.public_key)
  assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_saved_key_round_trips(tmp_path, rsa_pair):
  for name, pair in (("ec.pem", generate_keypair()), ("rsa.pem", rsa_pair)):
    save_key_pair(pair, tmp_path / name)
    loaded = load_key_pair(tmp_path / name)
    assert loaded.algorithm == pair.algorithm
    assert private_key_to_pem(loaded.private_key) == private_key_to_pem(pair.private_key)
    assert public_key_to_pem(loaded.public_key) == public_key_to_pem(pair.public_key)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not enforced on Windows")
def test_private_file_mode_is_0600_and_new_dir_is_0700(tmp_path):
  path = tmp_path / "fresh" / "k.pem"
  save_key_pair(generate_keypair(), path)
  assert (path.stat().st_mode & 0o777) == 0o600
  assert (path.parent.stat().st_mode & 0o777) == 0o700


def test_corrupted_key_file_raises_corrupted_error(tmp_path):
  path = tmp_path / "bad.pem"
  path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n")
  with pytest.raises(KeyStoreCorruptedError, match="corrupted"):
    load_key_pair(path)
  path.write_bytes(b"garbage")
  with pytest.raises(KeyStoreCorruptedError, match="corrupted"):
    load_key_pair(path)


def test_weak_rsa_pem_in_store_raises_corrupted_error(tmp_path):
  weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
  path = tmp_path / "weak.pem"
  path.write_bytes(private_key_to_pem(weak))
  # UnsupportedAlgorithmError is a ValueError, so load_key_pair wraps it.
  with pytest.raises(KeyStoreCorruptedError, match="rejected") as excinfo:
    load_key_pair(path)
  assert isinstance(excinfo.value.__cause__, UnsupportedAlgorithmError)
