"""Static, network-wide ValidatorSet and IssuerRegistry loaded from JSON at boot.

Never mutated at runtime and never derived from peers. An identity may appear several
times (key rotation) but at most once without `retired_at`.
"""

from __future__ import annotations

import json
import unicodedata
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
  name: str | None = None  # issuer entries only: optional human-readable institution name


MAX_NAME_LENGTH = 100


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

  def name_of(self, issuer_id: str) -> str:
    """Display name of an issuer; falls back to `issuer_id` (no name, or unknown issuer)."""
    for entry in self.entries:
      if entry.identity == issuer_id and entry.name is not None:
        return entry.name
    return issuer_id


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


def _parse_name(item: dict[str, Any], identity: str, what: str) -> str | None:
  if "name" not in item:
    return None
  name = item["name"]
  if not isinstance(name, str):
    raise RegistryError(f"{what}: {identity!r} has a non-string 'name'")
  name = unicodedata.normalize("NFC", name).strip()
  if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in name):
    raise RegistryError(f"{what}: {identity!r} has control or invisible characters in 'name'")
  if not name:
    raise RegistryError(f"{what}: {identity!r} has an empty 'name'")
  if len(name) > MAX_NAME_LENGTH:
    raise RegistryError(f"{what}: {identity!r} has a 'name' over {MAX_NAME_LENGTH} characters")
  return name


def _check_names(entries: list[KeyEntry], what: str) -> None:
  """One name per issuer across its rotated entries; no two issuers share a name."""
  by_identity: dict[str, str] = {}
  owner: dict[str, str] = {}
  for entry in entries:
    if entry.name is None:
      continue
    known = by_identity.setdefault(entry.identity, entry.name)
    if known != entry.name:
      raise RegistryError(f"{what}: {entry.identity!r} has conflicting 'name' values")
    folded = entry.name.casefold()
    if owner.setdefault(folded, entry.identity) != entry.identity:
      raise RegistryError(f"{what}: 'name' {entry.name!r} is used by more than one issuer")


def _parse_entries(
  raw: object, *, what: str, id_key: str, allow_name: bool = False
) -> tuple[KeyEntry, ...]:
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
    name = _parse_name(item, identity, what) if allow_name else None
    entries.append(KeyEntry(identity=identity, public_key=key, retired_at=retired_at, name=name))
  if allow_name:
    _check_names(entries, what)
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
  return IssuerRegistry(
    entries=_parse_entries(raw.get("issuers"), what=what, id_key="issuer_id", allow_name=True)
  )
