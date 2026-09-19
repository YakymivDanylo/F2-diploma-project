"""Canonical-bytes signing and verification - ECDSA/RSA auto-dispatch"""
from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .canonical import canonicalize
from .keys import PrivateKey, PublicKey, UnsupportedAlgorithmError


def sign_bytes(private_key: PrivateKey, data: bytes) -> str:
  if isinstance(private_key, ec.EllipticCurvePrivateKey):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
  elif isinstance(private_key, rsa.RSAPrivateKey):
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
  else:
    raise UnsupportedAlgorithmError(f"Unsupported private key type: {type(private_key)!r}")
  return signature.hex()

def verify_bytes(public_key: PublicKey, data: bytes, signature_hex: str) -> bool:
  """Verify a lowercase-hex signature over raw bytes; never raises on malformed input."""
  try:
    signature = bytes.fromhex(signature_hex)
  except (ValueError, TypeError):
    return False

  try:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
      public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(public_key, rsa.RSAPublicKey):
      public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    else:
      return False
  except InvalidSignature:
    return False
  return True

def sign_canonical(private_key: PrivateKey, obj: Any) -> str:
  return sign_bytes(private_key, canonicalize(obj))

def verify_canonical(public_key: PublicKey, obj: Any, signature_hex: str) -> bool:
  return verify_bytes(public_key, canonicalize(obj), signature_hex)