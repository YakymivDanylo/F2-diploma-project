"""Signed peer registrations for ValidatorSet identities.

`POST /peers/register` and gossiped peer lists decide where this node connects to and syncs
from. For a ValidatorSet identity that address must be vouched for by the validator itself:
the registration carries `issued_at` and a signature, by the validator's node key, over the
canonical `{domain, node_id, host, port, public_key, issued_at}`. It is verified with the key
in the ValidatorSet (never with the key in the request), so knowing a validator's public key is
not enough to move its address to another host. A registration older than the one already
held is refused, so an old signed address cannot be replayed over a newer one. Identities
outside the ValidatorSet carry no quorum weight and keep the unauthenticated path.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from blockchain_core import (
  public_key_from_pem,
  public_key_to_pem,
  sign_canonical,
  verify_canonical,
)
from blockchain_core.keys import PrivateKey, PublicKey

REGISTER_DOMAIN = "node/peer-register/v1"


def registration_payload(
  node_id: str, host: str, port: int, public_key: str, issued_at: int
) -> dict[str, Any]:
  return {
    "domain": REGISTER_DOMAIN,
    "node_id": node_id,
    "host": host,
    "port": port,
    "public_key": public_key,
    "issued_at": issued_at,
  }


def sign_registration(
  private_key: PrivateKey, node_id: str, host: str, port: int, public_key: str, issued_at: int
) -> str:
  return sign_canonical(
    private_key, registration_payload(node_id, host, port, public_key, issued_at)
  )


class RegistrationError(Exception):
  def __init__(self, status: int, code: str, message: str) -> None:
    super().__init__(message)
    self.status, self.code, self.message = status, code, message


def check_registration(
  *,
  node_id: str,
  host: str,
  port: int,
  public_key: str,
  issued_at: int | None,
  signature: str | None,
  resolve_node_key: Callable[[str, int], PublicKey | None],
  now_ms: int,
  max_future_skew_ms: int,
  held_issued_at: int | None,
) -> None:
  """Raise `RegistrationError` unless this is a fresh registration signed by the validator."""
  key = resolve_node_key(node_id, issued_at if issued_at is not None else now_ms)
  try:
    given = public_key_to_pem(public_key_from_pem(public_key.encode("utf-8")))
  except Exception:
    given = None
  if key is None or given != public_key_to_pem(key):
    raise RegistrationError(
      409, "peer_key_mismatch", f"{node_id!r} is a validator and the key does not match"
    )
  if issued_at is None or not signature:
    raise RegistrationError(
      403, "registration_unauthenticated", f"{node_id!r} is a validator: a signature is required"
    )
  if issued_at > now_ms + max_future_skew_ms:
    raise RegistrationError(403, "registration_unauthenticated", "issued_at is in the future")
  payload = registration_payload(node_id, host, port, public_key, issued_at)
  if not verify_canonical(key, payload, signature):
    raise RegistrationError(
      403, "registration_unauthenticated", "the registration signature is invalid"
    )
  if held_issued_at is not None and issued_at < held_issued_at:
    raise RegistrationError(
      409, "stale_registration", "a newer registration for this validator is already held"
    )
