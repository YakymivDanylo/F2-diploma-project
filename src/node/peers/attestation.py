"""Signed peer registrations (proof of possession of the registered node key).

`POST /peers/register` and gossiped peer lists decide where this node connects to and syncs
from, so every registration must be vouched for by the key it registers: it carries
`issued_at` and a signature over the canonical
`{domain, node_id, host, port, public_key, issued_at}` (`public_key` as normalized PEM).

* A ValidatorSet identity is verified with the key the ValidatorSet holds for it NOW (never
  with the key in the request, nor with the key in force at an attacker-chosen `issued_at`),
  so knowing a validator's public key is not enough to move its address to another host.
* Any other identity is verified with the key it registers (proof of possession), so nobody
  can register an id/key pair without holding the private key.

`issued_at` must lie in `[now - REGISTRATION_MAX_AGE_MS, now + max_future_skew_ms]`, and a
registration more than `max_future_skew_ms` older than the one already held is refused
(409 `stale_registration`), so an old signed address cannot be replayed over a newer one.

Why the skew window of tolerance: if a node's clock steps back (NTP correction), its fresh
registrations carry an `issued_at` below the one it signed just before, and a strict
"older than held" rule would lock it out for up to the skew window. Tolerating that window
does not let a replay move an address back: a registration older than the held one is
stored only as a TTL refresh of the held entry at the same host:port, and a changed address
needs `issued_at >= held` (enforced by `PeerRegistry.register`, which also keeps the held
`issued_at` from moving back, so replays cannot walk it back step by step either).
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
REGISTRATION_MAX_AGE_MS = 10 * 60 * 1000  # a signed registration older than this is refused


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


def normalized_pem(public_key: str) -> str | None:
  """The canonical PEM text of `public_key`, or None when it is not a usable public key."""
  try:
    return public_key_to_pem(public_key_from_pem(public_key.encode("utf-8"))).decode("ascii")
  except Exception:
    return None


class RegistrationError(Exception):
  def __init__(self, status: int, code: str, message: str) -> None:
    super().__init__(message)
    self.status, self.code, self.message = status, code, message


def _unauthenticated(message: str) -> RegistrationError:
  return RegistrationError(403, "registration_unauthenticated", message)


def _verify_signed(
  *,
  key: PublicKey,
  pem: str,
  node_id: str,
  host: str,
  port: int,
  issued_at: int | None,
  signature: str | None,
  now_ms: int,
  max_future_skew_ms: int,
  max_age_ms: int,
  held_issued_at: int | None,
) -> None:
  if issued_at is None or not signature:
    raise _unauthenticated(f"{node_id!r}: a signed registration (issued_at, signature) is required")
  if issued_at > now_ms + max_future_skew_ms:
    raise _unauthenticated("issued_at is in the future")
  if issued_at < now_ms - max_age_ms:
    raise _unauthenticated("the registration is stale: issued_at is too old")
  payload = registration_payload(node_id, host, port, pem, issued_at)
  if not verify_canonical(key, payload, signature):
    raise _unauthenticated("the registration signature is invalid")
  # Tolerate a held `issued_at` up to the skew window ahead: after a clock step back the
  # node's fresh registration would otherwise be refused as stale for that long (see module).
  if held_issued_at is not None and issued_at < held_issued_at - max_future_skew_ms:
    raise RegistrationError(
      409, "stale_registration", "a newer registration for this peer is already held"
    )


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
  max_age_ms: int = REGISTRATION_MAX_AGE_MS,
) -> None:
  """Raise `RegistrationError` unless this is a fresh registration signed by the validator
  with the key the ValidatorSet holds for it now."""
  key = resolve_node_key(node_id, now_ms)
  given = normalized_pem(public_key)
  if key is None or given is None or given != public_key_to_pem(key).decode("ascii"):
    raise RegistrationError(
      409, "peer_key_mismatch", f"{node_id!r} is a validator and the key does not match"
    )
  _verify_signed(
    key=key,
    pem=given,
    node_id=node_id,
    host=host,
    port=port,
    issued_at=issued_at,
    signature=signature,
    now_ms=now_ms,
    max_future_skew_ms=max_future_skew_ms,
    max_age_ms=max_age_ms,
    held_issued_at=held_issued_at,
  )


def check_peer_registration(
  *,
  node_id: str,
  host: str,
  port: int,
  public_key: str,
  issued_at: int | None,
  signature: str | None,
  now_ms: int,
  max_future_skew_ms: int,
  held_issued_at: int | None,
  max_age_ms: int = REGISTRATION_MAX_AGE_MS,
) -> None:
  """Raise `RegistrationError` unless this non-validator registration is fresh and signed by
  the private key matching the `public_key` it registers (proof of possession)."""
  given = normalized_pem(public_key)
  if given is None:
    raise _unauthenticated("public_key is not a usable public key")
  _verify_signed(
    key=public_key_from_pem(given.encode("ascii")),
    pem=given,
    node_id=node_id,
    host=host,
    port=port,
    issued_at=issued_at,
    signature=signature,
    now_ms=now_ms,
    max_future_skew_ms=max_future_skew_ms,
    max_age_ms=max_age_ms,
    held_issued_at=held_issued_at,
  )
