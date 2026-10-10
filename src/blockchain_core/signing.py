"""Canonical-bytes signing and verification - ECDSA/RSA auto-dispatch.

Signatures are lowercase hex, and only one encoding of each signature verifies:
non-canonical hex (uppercase, whitespace, odd length) and high-S ECDSA values are
rejected, so a relayer cannot re-encode a signature into a different, still-valid one.
"""
from __future__ import annotations

import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
  decode_dss_signature,
  encode_dss_signature,
)

from .canonical import CanonicalizationError, canonicalize
from .keys import PrivateKey, PublicKey, UnsupportedAlgorithmError, is_acceptable_public_key

_SIGNATURE_HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_HALF_ORDER = _P256_ORDER // 2


def sign_bytes(private_key: PrivateKey, data: bytes) -> str:
  if isinstance(private_key, ec.EllipticCurvePrivateKey):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    if s > _P256_HALF_ORDER:
      s = _P256_ORDER - s
    signature = encode_dss_signature(r, s)
  elif isinstance(private_key, rsa.RSAPrivateKey):
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
  else:
    raise UnsupportedAlgorithmError(f"Unsupported private key type: {type(private_key)!r}")
  return signature.hex()

def verify_bytes(public_key: PublicKey, data: bytes, signature_hex: str) -> bool:
  """Verify a lowercase-hex signature over raw bytes; never raises on malformed input."""
  if not isinstance(signature_hex, str) or not _SIGNATURE_HEX_RE.fullmatch(signature_hex):
    return False
  if not is_acceptable_public_key(public_key):
    return False
  signature = bytes.fromhex(signature_hex)

  try:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
      _, s = decode_dss_signature(signature)
      if s > _P256_HALF_ORDER:
        return False
      public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(public_key, rsa.RSAPublicKey):
      public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    else:
      return False
  except (InvalidSignature, ValueError):
    return False
  return True

def sign_canonical(private_key: PrivateKey, obj: Any) -> str:
  return sign_bytes(private_key, canonicalize(obj))

def verify_canonical(public_key: PublicKey, obj: Any, signature_hex: str) -> bool:
  """Verify over the canonical bytes of `obj`; an un-encodable `obj` is simply invalid."""
  try:
    data = canonicalize(obj)
  except CanonicalizationError:
    return False
  return verify_bytes(public_key, data, signature_hex)
