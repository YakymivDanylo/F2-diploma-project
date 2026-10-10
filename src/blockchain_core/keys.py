"""Key-pair generation, PEM (de)serialization, and algorithm dispatch"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

MIN_RSA_KEY_SIZE = 2048

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
PublicKey = ec.EllipticCurvePublicKey | rsa.RSAPublicKey
KeyResolver = Callable[[str, int], PublicKey | None]
"""`(identity, at_timestamp) -> public key`; `None` is NOT_FOUND and always fails closed."""

class UnsupportedAlgorithmError(ValueError):
    """Raised from an unrecognized key algorithm or key type"""

class WrongKeyRoleError(TypeError):
    """Raised when an IssuerKeyPair is used for a node duty, or a NodeKeyPair for an issuer duty"""

class InsufficientKeySizeError(ValueError):
    """Raised when a requested RSA key size is below the enforced minimum"""

@dataclass(frozen=True)
class KeyPair:
  algorithm: str
  private_key: PrivateKey
  public_key: PublicKey

@dataclass(frozen=True)
class IssuerKeyPair(KeyPair):
  """Key pair that signs `DocumentRecord`s - never interchangeable with a `NodeKeyPair`."""

@dataclass(frozen=True)
class NodeKeyPair(KeyPair):
  """Key pair that signs blocks and consensus messages - never an `IssuerKeyPair`."""

def resolve_signing_key(key: PrivateKey | KeyPair, role: type[KeyPair]) -> PrivateKey:
  """Unwrap a role-typed pair for signing; a pair of the other role is refused.

  A bare private key is accepted unchanged for backward compatibility - role
  separation is only enforceable when the caller holds a typed pair.
  """
  if isinstance(key, KeyPair):
    if not isinstance(key, role):
      raise WrongKeyRoleError(
        f"{type(key).__name__} cannot be used where a {role.__name__} is required")
    return key.private_key
  return key

def is_acceptable_public_key(key: object) -> bool:
  """True only for ECDSA P-256 or RSA >= 2048 bits with e = 65537."""
  if isinstance(key, ec.EllipticCurvePublicKey):
    return isinstance(key.curve, ec.SECP256R1)
  if isinstance(key, rsa.RSAPublicKey):
    return key.key_size >= MIN_RSA_KEY_SIZE and key.public_numbers().e == 65537
  return False

def _require_acceptable(key: PublicKey, kind: str) -> None:
  if not is_acceptable_public_key(key):
    raise UnsupportedAlgorithmError(
      f"{kind} key rejected: only ECDSA P-256 and RSA >= {MIN_RSA_KEY_SIZE} bits (e=65537)")

def generate_keypair(algorithm: str = "ecdsa-p256", *, rsa_key_size: int = 2048) -> KeyPair:
  """Generate a fresh KeyPair; used identically for IssuerKeyPair and NodeKeyPair"""
  if algorithm == "ecdsa-p256":
    private_key: PrivateKey = ec.generate_private_key(ec.SECP256R1())
  elif algorithm == "rsa":
    if rsa_key_size < MIN_RSA_KEY_SIZE:
      raise InsufficientKeySizeError(
        f"RSA key size must be at least {MIN_RSA_KEY_SIZE} bits, got {rsa_key_size}")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_key_size)
  else:
    raise UnsupportedAlgorithmError(f"Unsupported key algorithm: {algorithm!r}")
  return KeyPair(algorithm=algorithm, private_key=private_key, public_key=private_key.public_key())

def generate_issuer_keypair(
  algorithm: str = "ecdsa-p256", *, rsa_key_size: int = 2048,
) -> IssuerKeyPair:
  pair = generate_keypair(algorithm, rsa_key_size=rsa_key_size)
  return IssuerKeyPair(pair.algorithm, pair.private_key, pair.public_key)

def generate_node_keypair(
  algorithm: str = "ecdsa-p256", *, rsa_key_size: int = 2048,
) -> NodeKeyPair:
  pair = generate_keypair(algorithm, rsa_key_size=rsa_key_size)
  return NodeKeyPair(pair.algorithm, pair.private_key, pair.public_key)


def algorithm_of(key: PrivateKey | PublicKey) -> str:
   """Identify algorithm name from a public or private key instance"""
   if isinstance(key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey):
     return "ecdsa-p256"
   if isinstance(key, rsa.RSAPrivateKey | rsa.RSAPublicKey):
     return "rsa"
   raise UnsupportedAlgorithmError(f"Unsupported key type: {type(key)!r}")

def private_key_to_pem(private_key: PrivateKey) -> bytes:
  return private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
  )

def public_key_to_pem(public_key: PublicKey) -> bytes:
  return public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
  )

def private_key_from_pem(data: bytes) -> PrivateKey:
  key = serialization.load_pem_private_key(data, password=None)
  if not isinstance(key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey):
    raise UnsupportedAlgorithmError(f"Unsupported private key type: {type(key)!r}")
  _require_acceptable(key.public_key(), "private")
  return key

def public_key_from_pem(data: bytes) -> PublicKey:
  key = serialization.load_pem_public_key(data)
  if not isinstance(key, ec.EllipticCurvePublicKey | rsa.RSAPublicKey):
    raise UnsupportedAlgorithmError(f"Unsupported public key type: {type(key)!r}")
  _require_acceptable(key, "public")
  return key