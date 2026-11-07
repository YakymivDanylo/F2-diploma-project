"""Static, network-wide ValidatorSet and IssuerRegistry loaded from JSON at boot.

Never mutated at runtime and never derived from peers. An identity may appear several
times (key rotation) but at most once without `retired_at`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blockchain_core.keys import PublicKey, public_key_from_pem
from blockchain_core.validation import ValidatorSet as CoreValidatorSet


class RegistryError(ValueError):
  """A registry file is missing, malformed or inconsistent; the node must not start."""


@dataclass(frozen=True)
class KeyEntry:
  identity: str
  public_key: PublicKey
  retired_at: int | None


@dataclass(frozen=True)
class ValidatorRegistry:
  entries: tuple[KeyEntry, ...]
  n: int
  f: int

  def to_core(self) -> CoreValidatorSet:
    """Core view: every node id ever a validator (retired included), no keys."""
    return CoreValidatorSet(
      members=frozenset(entry.identity for entry in self.entries), n=self.n, f=self.f
    )


@dataclass(frozen=True)
class IssuerRegistry:
  entries: tuple[KeyEntry, ...]


def active_entry(entries: tuple[KeyEntry, ...], identity: str) -> KeyEntry | None:
  for entry in entries:
    if entry.identity == identity and entry.retired_at is None:
      return entry
  return None


def _read_object(path: Path, what: str) -> dict[str, Any]:
  try:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
  except OSError as exc:
    raise RegistryError(f"{what}: cannot read {path}: {exc}") from exc
  except ValueError as exc:
    raise RegistryError(f"{what}: {path} is not valid JSON: {exc}") from exc
  if not isinstance(raw, dict):
    raise RegistryError(f"{what}: {path} must contain a JSON object")
  return raw


def _parse_entries(raw: object, *, what: str, id_key: str) -> tuple[KeyEntry, ...]:
  if not isinstance(raw, list) or not raw:
    raise RegistryError(f"{what}: expected a non-empty list")
  entries: list[KeyEntry] = []
  active: set[str] = set()
  for item in raw:
    if not isinstance(item, dict):
      raise RegistryError(f"{what}: every entry must be an object")
    identity = item.get(id_key)
    if not isinstance(identity, str) or not identity:
      raise RegistryError(f"{what}: every entry needs a non-empty {id_key!r}")
    pem = item.get("public_key")
    if not isinstance(pem, str):
      raise RegistryError(f"{what}: {identity!r} needs a PEM 'public_key' string")
    retired_at = item.get("retired_at")
    if retired_at is not None and (type(retired_at) is not int or retired_at < 0):
      raise RegistryError(f"{what}: {identity!r} has an invalid 'retired_at'")
    try:
      key = public_key_from_pem(pem.encode("utf-8"))
    except Exception as exc:
      raise RegistryError(f"{what}: {identity!r} has an unusable public key: {exc}") from exc
    if retired_at is None:
      if identity in active:
        raise RegistryError(f"{what}: {identity!r} has more than one active (non-retired) key")
      active.add(identity)
    entries.append(KeyEntry(identity=identity, public_key=key, retired_at=retired_at))
  return tuple(entries)


def load_validator_registry(path: Path) -> ValidatorRegistry:
  what = "ValidatorSet"
  raw = _read_object(path, what)
  entries = _parse_entries(raw.get("validators"), what=what, id_key="node_id")
  n, f = raw.get("n"), raw.get("f")
  if type(n) is not int or type(f) is not int:
    raise RegistryError(f"{what}: 'n' and 'f' must be integers")
  registry = ValidatorRegistry(entries=entries, n=n, f=f)
  try:
    registry.to_core()  # enforces len(members) >= n >= 3f + 1
  except ValueError as exc:
    raise RegistryError(f"{what}: {exc}") from exc
  return registry


def load_issuer_registry(path: Path) -> IssuerRegistry:
  what = "IssuerRegistry"
  raw = _read_object(path, what)
  return IssuerRegistry(entries=_parse_entries(raw.get("issuers"), what=what, id_key="issuer_id"))
