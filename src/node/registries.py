"""Static, network-wide ValidatorSet and IssuerRegistry loaded from JSON at boot.

Never mutated at runtime and never derived from peers. An identity may appear several
times (key rotation) but at most once without `retired_at`.

Each entry's key is in force over a closed interval `[valid_from, retired_at]` (epoch ms,
both inclusive). `retired_at` null means open-ended. `valid_from` is optional: when it is
absent or null the key starts right after the identity's previous key retires, or at the
beginning of time for the identity's first key (the behaviour of files written before
`valid_from` existed). One identity's intervals must not overlap, and at no instant may
more than `n` validator identities have a key in force (otherwise two quorums computed
for `n` could share fewer than `f + 1` nodes).

Operators: a first key with `valid_from` absent or null is valid from the beginning of time,
so it verifies signatures at ANY past timestamp. That is right for the genesis identities,
but an identity added after genesis (a new validator or a new institution) should set
`valid_from` to the instant it joins; otherwise its key could back-date blocks or records to
before it existed.

Revocation: `revoked` (optional, default false) marks a compromised key. Retirement alone
cannot stop back-dating: a retired key still resolves at timestamps inside its interval, so
whoever holds it can still sign blocks / records dated then and serve them through sync. A
revoked entry's key NEVER resolves, at any timestamp, so everything it ever signed stops
validating: old blocks or records signed by a compromised key become invalid and must be
re-validated / re-issued under a non-revoked key. A revoked entry still counts as an
identity occurrence (its interval takes part in the overlap and n-in-force checks, and its
id stays a known ValidatorSet id), but it holds no key. To rotate a revoked identity give the
revoked entry a `retired_at` and add a new entry after it. The node's own keys must resolve
now at boot, so a node whose own key is revoked refuses to start.
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
  valid_from: int | None = None  # first instant (epoch ms) the key is in force; None = see module
  revoked: bool = False  # compromised: the key never resolves, at any timestamp (see module)


@dataclass(frozen=True)
class KeyInterval:
  """When one key is in force: `start`..`end` inclusive; None = unbounded on that side.

  `public_key` is None for a revoked entry: the interval still occupies the identity's
  timeline (overlap and n-in-force checks) but no key resolves in it.
  """

  start: int | None
  end: int | None
  public_key: PublicKey | None

  def covers(self, at_timestamp: int) -> bool:
    return (self.start is None or at_timestamp >= self.start) and (
      self.end is None or at_timestamp <= self.end
    )


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


def _fmt(bound: int | None, open_word: str) -> str:
  return open_word if bound is None else str(bound)


def key_intervals(
  entries: tuple[KeyEntry, ...] | list[KeyEntry], what: str = "registry"
) -> dict[str, tuple[KeyInterval, ...]]:
  """Per identity, the key intervals in time order; raises RegistryError on any overlap."""
  grouped: dict[str, list[KeyEntry]] = {}
  for entry in entries:
    grouped.setdefault(entry.identity, []).append(entry)
  result: dict[str, tuple[KeyInterval, ...]] = {}
  for identity, items in grouped.items():
    items.sort(key=lambda e: (e.retired_at is None, e.retired_at or 0))
    intervals: list[KeyInterval] = []
    for entry in items:
      if (
        entry.valid_from is not None
        and entry.retired_at is not None
        and entry.valid_from > entry.retired_at
      ):
        raise RegistryError(
          f"{what}: {identity!r} has 'valid_from' {entry.valid_from} after "
          f"'retired_at' {entry.retired_at}"
        )
      previous = intervals[-1] if intervals else None
      start = entry.valid_from
      if start is None and previous is not None and previous.end is not None:
        start = previous.end + 1
      if previous is not None and (previous.end is None or start is None or start <= previous.end):
        raise RegistryError(
          f"{what}: {identity!r} has overlapping key intervals: "
          f"[{_fmt(previous.start, 'beginning')}, {_fmt(previous.end, 'open')}] and "
          f"[{_fmt(start, 'beginning')}, {_fmt(entry.retired_at, 'open')}]"
        )
      key = None if entry.revoked else entry.public_key
      intervals.append(KeyInterval(start=start, end=entry.retired_at, public_key=key))
    result[identity] = tuple(intervals)
  return result


def check_concurrent_validators(
  intervals: dict[str, tuple[KeyInterval, ...]], n: int, what: str = "ValidatorSet"
) -> None:
  """Fail if more than `n` identities have a key in force at any instant.

  The count only changes at a key's start or the instant after its end, so checking time 0
  and those boundary points covers every instant.
  """
  points = {0}
  for items in intervals.values():
    for interval in items:
      if interval.start is not None:
        points.add(interval.start)
      if interval.end is not None:
        points.add(interval.end + 1)
  for point in sorted(points):
    in_force = sorted(
      identity
      for identity, items in intervals.items()
      if any(interval.covers(point) for interval in items)
    )
    if len(in_force) > n:
      raise RegistryError(
        f"{what}: {len(in_force)} validators have a key in force at {point} but n={n}: "
        + ", ".join(in_force)
      )


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
    valid_from = item.get("valid_from")
    if valid_from is not None and (type(valid_from) is not int or valid_from < 0):
      raise RegistryError(f"{what}: {identity!r} has an invalid 'valid_from'")
    revoked = item.get("revoked", False)
    if type(revoked) is not bool:
      raise RegistryError(f"{what}: {identity!r} has a non-boolean 'revoked'")
    try:
      key = public_key_from_pem(pem.encode("utf-8"))
    except Exception as exc:
      raise RegistryError(f"{what}: {identity!r} has an unusable public key: {exc}") from exc
    if retired_at is None:
      if identity in active:
        raise RegistryError(f"{what}: {identity!r} has more than one active (non-retired) key")
      active.add(identity)
    name = _parse_name(item, identity, what) if allow_name else None
    entries.append(
      KeyEntry(
        identity=identity,
        public_key=key,
        retired_at=retired_at,
        name=name,
        valid_from=valid_from,
        revoked=revoked,
      )
    )
  key_intervals(entries, what)  # rejects overlapping or inverted intervals
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
  check_concurrent_validators(key_intervals(entries, what), n, what)
  return registry


def load_issuer_registry(path: Path) -> IssuerRegistry:
  what = "IssuerRegistry"
  raw = _read_object(path, what)
  return IssuerRegistry(
    entries=_parse_entries(raw.get("issuers"), what=what, id_key="issuer_id", allow_name=True)
  )
