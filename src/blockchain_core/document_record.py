"""Signed document records - the unit anchored into a block's Merkle tree."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from .canonical import deep_freeze
from .hashing import HEX64_RE, sha256_hex
from .keys import IssuerKeyPair, KeyPair, PrivateKey, PublicKey, resolve_signing_key
from .signing import sign_canonical, verify_canonical


class InvalidDocumentHashError(ValueError):
  """Raised when document_hash is not a well-formed 64-char lowercase-hex SHA-256 digest."""


class MissingDocumentFieldError(ValueError):
  """Raised when a required DocumentRecord field is missing or empty."""


@dataclass(frozen=True)
class DocumentRecord:
  document_hash: str
  issuer_id: str
  issued_at: int
  metadata: Mapping[str, Any]
  ipfs_cid: str | None = None
  signature: str | None = None

  def __post_init__(self) -> None:
    # Detach from the caller's dict and make it read-only: the signature covers it.
    object.__setattr__(self, "metadata", deep_freeze(self.metadata))

  def unsigned_dict(self) -> dict[str, Any]:
    """Canonical field set that is signed/verified - excludes `signature` itself."""
    return {
      "document_hash": self.document_hash,
      "issuer_id": self.issuer_id,
      "issued_at": self.issued_at,
      "metadata": self.metadata,
      "ipfs_cid": self.ipfs_cid,
    }

  def signed_dict(self) -> dict[str, Any]:
    """Every field, including `signature` - the exact content a Merkle leaf commits to."""
    return {**self.unsigned_dict(), "signature": self.signature}


def _validate_hash(document_hash: str) -> None:
  if not HEX64_RE.fullmatch(document_hash):
    raise InvalidDocumentHashError(
      f"document_hash must be 64 lowercase hex characters, got {document_hash!r}"
    )


def create_document_record(
  document_hash: str | bytes,
  issuer_id: str,
  issued_at: int | None,
  metadata: Mapping[str, Any],
  issuer_private_key: PrivateKey | KeyPair,
  ipfs_cid: str | None = None,
) -> DocumentRecord:
  """Assemble and sign a DocumentRecord with an issuer key.

  `document_hash` may be the 64-hex digest or the raw document bytes (hashed here).
  A `NodeKeyPair` is refused; a bare private key is accepted.
  """
  signing_key = resolve_signing_key(issuer_private_key, IssuerKeyPair)
  if isinstance(document_hash, bytes):
    document_hash = sha256_hex(document_hash)
  if not document_hash:
    raise MissingDocumentFieldError("document_hash is required")
  if not issuer_id:
    raise MissingDocumentFieldError("issuer_id is required")
  if issued_at is None:
    raise MissingDocumentFieldError("issued_at is required")
  if type(issued_at) is not int:
    raise MissingDocumentFieldError("issued_at must be an integer epoch-ms timestamp")
  if not isinstance(metadata, Mapping):
    raise MissingDocumentFieldError("metadata must be a mapping")
  _validate_hash(document_hash)

  record = DocumentRecord(
    document_hash=document_hash,
    issuer_id=issuer_id,
    issued_at=issued_at,
    metadata=metadata,
    ipfs_cid=ipfs_cid,
  )
  signature = sign_canonical(signing_key, record.unsigned_dict())
  return replace(record, signature=signature)


def verify_document_record(record: DocumentRecord, issuer_public_key: PublicKey) -> bool:
  """Verify a DocumentRecord's signature against the issuer's public key."""
  if not record.signature:
    return False
  return verify_canonical(issuer_public_key, record.unsigned_dict(), record.signature)
