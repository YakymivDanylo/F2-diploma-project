from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from .hashing import sha256_hex
from .keys import PrivateKey, PublicKey
from .signing import sign_canonical, verify_canonical

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class InvalidDocumentHashError(ValueError):
  """Raised when document_hash is not a well-formed 64-char lowercase-hex SHA-256 digest."""

class MissingDocumentFieldError(ValueError):
  """Raised when a required DocumentRecord field is missing or empty."""


@dataclass(frozen=True)
class DocumentRecord:
  document_hash: str
  issuer_id: str
  issued_at: int
  metadata: dict[str, Any]
  ipfs_cid: str | None = None
  signature: str | None = None

  def unsigned_dict(self) -> dict[str, Any]:
     """Canonical field set that is signed/verified - excludes `signature` itself."""
     return {
       "document_hash": self.document_hash,
       "issuer_id": self.issuer_id,
       "issued_at": self.issued_at,
       "metadata": self.metadata,
       "ipfs_cid": self.ipfs_cid,
     }
     
def _validate_hash(document_hash: str) -> None:
  if not _HASH_RE.fullmatch(document_hash):
    raise InvalidDocumentHashError(
      f"document_hash must be 64 lowercase hex characters, got {document_hash!r}")

def create_document_record(
 document_hash: str | bytes,
 issuer_id: str,
 issued_at: int | None,
 metadata: dict[str, Any],
 issuer_private_key: PrivateKey,
 ipfs_cid: str | None = None,
) -> DocumentRecord:
   """Assemble and sign a DocumentRecord with the IssuerKeyPair private key."""
   if isinstance(document_hash, bytes):
     document_hash = sha256_hex(document_hash)
   if not document_hash:
      raise MissingDocumentFieldError("document_hash is required")
   if not issuer_id:
      raise MissingDocumentFieldError("issuer_id is required")
   if issued_at is None:
      raise MissingDocumentFieldError("issued_at is required")
   _validate_hash(document_hash)

   record = DocumentRecord(
      document_hash=document_hash,
      issuer_id=issuer_id,
      issued_at=issued_at,
      metadata=metadata,
      ipfs_cid=ipfs_cid,
   )
   signature = sign_canonical(issuer_private_key, record.unsigned_dict())
   return replace(record, signature=signature)

def verify_document_record(record: DocumentRecord, issuer_public_key: PublicKey) -> bool:
    """Verify a DocumentRecord's signature against the issuer's public key."""
    if not record.signature:
      return False
    return verify_canonical(issuer_public_key, record.unsigned_dict(), record.signature)