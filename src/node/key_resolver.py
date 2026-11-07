"""Time-aware key resolution over the static ValidatorSet and IssuerRegistry.

One immutable `CombinedKeyResolver` is built from both registries. A `ResolverHolder`
publishes the current snapshot: every call site takes `holder.current` once per
validation, so a reload never changes the keys an in-flight validation already uses.

NOT_FOUND is the core's contract: `None` from a resolver always fails closed
(`failure_type = "signature"`), it is never treated as valid and never raises.
"""

from __future__ import annotations

from pathlib import Path

from blockchain_core.keys import PublicKey
from node.registries import (
  IssuerRegistry,
  KeyEntry,
  ValidatorRegistry,
  load_issuer_registry,
  load_validator_registry,
)


def _group(entries: tuple[KeyEntry, ...]) -> dict[str, tuple[KeyEntry, ...]]:
  """Per identity, entries ordered by rotation time; the active (non-retired) key is last."""
  grouped: dict[str, list[KeyEntry]] = {}
  for entry in entries:
    grouped.setdefault(entry.identity, []).append(entry)
  return {
    identity: tuple(
      sorted(items, key=lambda e: (e.retired_at is None, e.retired_at if e.retired_at else 0))
    )
    for identity, items in grouped.items()
  }


def _key_at(entries: tuple[KeyEntry, ...], at_timestamp: int) -> PublicKey | None:
  """The key in force at `at_timestamp`: a retired key is valid up to and including `retired_at`."""
  for entry in entries:
    if entry.retired_at is None or at_timestamp <= entry.retired_at:
      return entry.public_key
  return None


class CombinedKeyResolver:
  """Immutable snapshot of both registries; safe to share across call sites."""

  def __init__(self, validators: ValidatorRegistry, issuers: IssuerRegistry) -> None:
    self._nodes = _group(validators.entries)
    self._issuers = _group(issuers.entries)
    self._active_node_ids = frozenset(
      e.identity for e in validators.entries if e.retired_at is None
    )

  def resolve_node_key(self, node_id: str, at_timestamp: int) -> PublicKey | None:
    return _key_at(self._nodes.get(node_id, ()), at_timestamp)

  def resolve_issuer_key(self, issuer_id: str, at_timestamp: int) -> PublicKey | None:
    return _key_at(self._issuers.get(issuer_id, ()), at_timestamp)

  @property
  def active_node_ids(self) -> frozenset[str]:
    """Validators without `retired_at`; retired ones stay resolvable but are not counted."""
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
