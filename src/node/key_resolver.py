"""Time-aware key resolution over the static ValidatorSet and IssuerRegistry.

One immutable `CombinedKeyResolver` is built from both registries. A `ResolverHolder`
publishes the current snapshot: every call site takes `holder.current` once per
validation, so a reload never changes the keys an in-flight validation already uses.

NOT_FOUND is the core's contract: `None` from a resolver always fails closed
(`failure_type = "signature"`), it is never treated as valid and never raises.

A revoked entry (`revoked: true`, a compromised key) never resolves, at any timestamp, so
every block / record it signed fails validation (see `node.registries`).
"""

from __future__ import annotations

from pathlib import Path

from blockchain_core.keys import PublicKey
from node.registries import (
  IssuerRegistry,
  KeyInterval,
  ValidatorRegistry,
  key_intervals,
  load_issuer_registry,
  load_validator_registry,
)


def _key_at(intervals: tuple[KeyInterval, ...], at_timestamp: int) -> PublicKey | None:
  """The key in force at `at_timestamp`: `valid_from <= at_timestamp <= retired_at`.

  Both bounds are inclusive; an absent bound is unbounded (see `node.registries`). A revoked
  interval covers its time span but holds no key, so it resolves to None.
  """
  for interval in intervals:
    if interval.covers(at_timestamp):
      return interval.public_key  # None when revoked; intervals never overlap
  return None


class CombinedKeyResolver:
  """Immutable snapshot of both registries; safe to share across call sites.

  Raises `RegistryError` when one identity's key intervals overlap (a registry built in
  code bypasses the loader's checks, so they are re-applied here).
  """

  def __init__(self, validators: ValidatorRegistry, issuers: IssuerRegistry) -> None:
    self._nodes = key_intervals(validators.entries, "ValidatorSet")
    self._issuers = key_intervals(issuers.entries, "IssuerRegistry")
    self._known_node_ids = frozenset(e.identity for e in validators.entries)
    self._active_node_ids = frozenset(
      e.identity for e in validators.entries if e.retired_at is None and not e.revoked
    )

  def resolve_node_key(self, node_id: str, at_timestamp: int) -> PublicKey | None:
    return _key_at(self._nodes.get(node_id, ()), at_timestamp)

  def resolve_issuer_key(self, issuer_id: str, at_timestamp: int) -> PublicKey | None:
    return _key_at(self._issuers.get(issuer_id, ()), at_timestamp)

  @property
  def known_node_ids(self) -> frozenset[str]:
    """Every ValidatorSet identity, retired ones included: PeerInfo can never claim these."""
    return self._known_node_ids

  @property
  def active_node_ids(self) -> frozenset[str]:
    """Validators with a non-revoked entry without `retired_at`; retired ones stay resolvable
    only, revoked ones never resolve.

    Such an entry may have a `valid_from` in the future, so this is "not retired", not
    "resolves now". Quorum is unaffected: the core excludes members whose key does not
    resolve at a block's timestamp, and the loader caps keys in force at any instant at n.
    """
    return self._active_node_ids


class ResolverHolder:
  """Publishes the current resolver; `reload` swaps the reference atomically."""

  def __init__(self, resolver: CombinedKeyResolver) -> None:
    self._current = resolver

  @property
  def current(self) -> CombinedKeyResolver:
    return self._current

  def reload(self, resolver: CombinedKeyResolver) -> None:
    self._current = resolver

  def reload_from_files(self, validators_path: Path, issuers_path: Path) -> None:
    """Re-read both files; on any error the previous resolver stays in force."""
    resolver = CombinedKeyResolver(
      load_validator_registry(validators_path), load_issuer_registry(issuers_path)
    )
    self.reload(resolver)
