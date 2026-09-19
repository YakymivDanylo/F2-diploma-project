"""Key-pair generation, PEM (de)serialization, and algorithm dispatch"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

MIN_RSA_KEY_SIZE = 2048

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
PublicKey = ec.EllipticCurvePublicKey | rsa.RSAPublicKey

class UnsupportedAlgorithmError(ValueError):
    """Raised from an unrecognized key algorithm or key type"""

class InsufficientKeySizeError(ValueError):
    """Raised when a requested RSA key size is below the enforced minimum"""

@dataclass(frozen=True)
class KeyPair:
  algorithm: str
  private_key: PrivateKey
  public_key: PublicKey

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
  return key

def public_key_from_pem(data: bytes) -> PublicKey:
  key = serialization.load_pem_public_key(data)
  if not isinstance(key, ec.EllipticCurvePublicKey | rsa.RSAPublicKey):
    raise UnsupportedAlgorithmError(f"Unsupported public key type: {type(key)!r}")
  return key