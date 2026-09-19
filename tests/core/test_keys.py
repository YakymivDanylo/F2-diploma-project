from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from blockchain_core.keys import (
  InsufficientKeySizeError,
  UnsupportedAlgorithmError,
  algorithm_of,
  generate_keypair,
  private_key_from_pem,
  private_key_to_pem,
  public_key_from_pem,
  public_key_to_pem,
)
from blockchain_core.signing import sign_bytes, verify_bytes
from blockchain_core.storage.key_store import (
  KeyStoreCorruptedError,
  KeyStoreExistsError,
  KeyStoreMissingError,
  load_key_pair,
  save_key_pair,
)


def test_generate_keypair_default_is_ecdsa_p256():
  key_pair = generate_keypair()
  assert key_pair.algorithm == "ecdsa-p256"
  assert isinstance(key_pair.private_key, ec.EllipticCurvePrivateKey)
  assert isinstance(key_pair.private_key.curve, ec.SECP256R1)


def test_generate_keypair_rsa_explicit():
  key_pair = generate_keypair("rsa", rsa_key_size=2048)
  assert key_pair.algorithm == "rsa"
  assert isinstance(key_pair.private_key, rsa.RSAPrivateKey)
  assert key_pair.private_key.key_size == 2048


def test_generate_keypair_rsa_rejects_undersized_key():
  with pytest.raises(InsufficientKeySizeError):
    generate_keypair("rsa", rsa_key_size=1024)


def test_generate_keypair_rejects_unsupported_algorithm():
  with pytest.raises(UnsupportedAlgorithmError):
    generate_keypair("ed25519")


def test_issuer_and_node_keypairs_are_independent_key_material():
  issuer = generate_keypair()
  node = generate_keypair()
  assert private_key_to_pem(issuer.private_key) != private_key_to_pem(node.private_key)


def test_private_and_public_pem_round_trip():
  key_pair = generate_keypair()
  restored_private = private_key_from_pem(private_key_to_pem(key_pair.private_key))
  restored_public = public_key_from_pem(public_key_to_pem(key_pair.public_key))
  assert algorithm_of(restored_private) == "ecdsa-p256"
  assert algorithm_of(restored_public) == "ecdsa-p256"


def test_save_and_load_key_pair_round_trip(tmp_path):
  key_pair = generate_keypair()
  path = tmp_path / "issuer.pem"
  save_key_pair(key_pair, path)
  loaded = load_key_pair(path)
  assert loaded.algorithm == key_pair.algorithm
  assert private_key_to_pem(loaded.private_key) == private_key_to_pem(key_pair.private_key)


def test_save_key_pair_refuses_overwrite_without_force(tmp_path):
  path = tmp_path / "issuer.pem"
  save_key_pair(generate_keypair(), path)
  with pytest.raises(KeyStoreExistsError):
    save_key_pair(generate_keypair(), path)


def test_save_key_pair_overwrites_with_force(tmp_path):
  path = tmp_path / "issuer.pem"
  save_key_pair(generate_keypair(), path)
  second = generate_keypair()
  save_key_pair(second, path, force=True)
  loaded = load_key_pair(path)
  assert private_key_to_pem(loaded.private_key) == private_key_to_pem(second.private_key)


def test_load_key_pair_missing_file_raises(tmp_path):
  with pytest.raises(KeyStoreMissingError):
    load_key_pair(tmp_path / "missing.pem")


def test_load_key_pair_corrupted_file_raises(tmp_path):
  path = tmp_path / "issuer.pem"
  path.write_bytes(b"not a pem key")
  with pytest.raises(KeyStoreCorruptedError):
    load_key_pair(path)


def test_rotated_key_pair_old_signatures_remain_verifiable_against_old_public_key():
  old_key_pair = generate_keypair()
  old_signature = sign_bytes(old_key_pair.private_key, b"payload")
  new_key_pair = generate_keypair()

  assert verify_bytes(old_key_pair.public_key, b"payload", old_signature) is True
  assert verify_bytes(new_key_pair.public_key, b"payload", old_signature) is False