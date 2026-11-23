"""Key validity intervals: `valid_from`, `retired_at` and the n-in-force cap (audit 2026-11-20)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from node_helpers import pem_of

from blockchain_core import generate_issuer_keypair, generate_node_keypair
from node.key_resolver import CombinedKeyResolver
from node.registries import (
  IssuerRegistry,
  KeyEntry,
  RegistryError,
  ValidatorRegistry,
  load_issuer_registry,
  load_validator_registry,
)

KEYS = {f"node{i}": generate_node_keypair() for i in range(1, 6)}
OLD = generate_node_keypair()
NEW = generate_node_keypair()
ISSUER_OLD = generate_issuer_keypair()
ISSUER_NEW = generate_issuer_keypair()
FUTURE = 10**13


def _validator(node_id: str, pair=None, **extra) -> dict:
  return {"node_id": node_id, "public_key": pem_of(pair or KEYS[node_id]), **extra}


def _base(*, skip: str | None = None) -> list[dict]:
  return [_validator(f"node{i}") for i in range(1, 5) if f"node{i}" != skip]


def _load_validators(tmp_path: Path, entries: list[dict], n: int = 4, f: int = 1):
  path = tmp_path / "validators.json"
  path.write_text(json.dumps({"n": n, "f": f, "validators": entries}), encoding="utf-8")
  return load_validator_registry(path)


def _load_issuers(tmp_path: Path, entries: list[dict]):
  path = tmp_path / "issuers.json"
  path.write_text(json.dumps({"issuers": entries}), encoding="utf-8")
  return load_issuer_registry(path)


def _resolver(validators: ValidatorRegistry, issuers: IssuerRegistry | None = None):
  issuers = issuers or IssuerRegistry(entries=(KeyEntry("i", ISSUER_OLD.public_key, None),))
  return CombinedKeyResolver(validators, issuers)


# --- valid_from is respected ------------------------------------------------------------


def test_node_key_not_resolvable_before_valid_from(tmp_path: Path) -> None:
  entries = [*_base(skip="node4"), _validator("node4", valid_from=5000)]
  resolver = _resolver(_load_validators(tmp_path, entries))
  assert resolver.resolve_node_key("node4", 0) is None
  assert resolver.resolve_node_key("node4", 4999) is None
  assert resolver.resolve_node_key("node4", 5000) == KEYS["node4"].public_key
  assert resolver.resolve_node_key("node4", FUTURE) == KEYS["node4"].public_key
  assert resolver.resolve_node_key("node1", 0) == KEYS["node1"].public_key  # no valid_from


def test_issuer_key_not_resolvable_before_valid_from(tmp_path: Path) -> None:
  issuers = _load_issuers(
    tmp_path,
    [{"issuer_id": "issuer1", "public_key": pem_of(ISSUER_NEW), "valid_from": 7000}],
  )
  resolver = _resolver(_load_validators(tmp_path, _base()), issuers)
  assert resolver.resolve_issuer_key("issuer1", 6999) is None
  assert resolver.resolve_issuer_key("issuer1", 7000) == ISSUER_NEW.public_key


def test_bounded_interval_is_inclusive_on_both_ends(tmp_path: Path) -> None:
  entries = [*_base(skip="node4"), _validator("node4", valid_from=100, retired_at=200)]
  resolver = _resolver(_load_validators(tmp_path, entries))
  assert [resolver.resolve_node_key("node4", t) for t in (99, 100, 200, 201)] == [
    None,
    KEYS["node4"].public_key,
    KEYS["node4"].public_key,
    None,
  ]
  assert "node4" not in resolver.active_node_ids  # retired


def test_future_valid_from_still_counts_as_active(tmp_path: Path) -> None:
  # Documented: active = has a non-retired entry, even if it starts later.
  entries = [*_base(skip="node4"), _validator("node4", valid_from=FUTURE)]
  resolver = _resolver(_load_validators(tmp_path, entries))
  assert "node4" in resolver.active_node_ids
  assert resolver.resolve_node_key("node4", FUTURE - 1) is None


@pytest.mark.parametrize("bad", [-1, "5", 1.5, True])
def test_invalid_valid_from_fails(tmp_path: Path, bad) -> None:
  entries = [*_base(skip="node4"), _validator("node4", valid_from=bad)]
  with pytest.raises(RegistryError, match="valid_from"):
    _load_validators(tmp_path, entries)


def test_valid_from_after_retired_at_fails(tmp_path: Path) -> None:
  entries = [*_base(), _validator("node4", OLD, valid_from=300, retired_at=200)]
  with pytest.raises(RegistryError, match="'valid_from' 300 after 'retired_at' 200"):
    _load_validators(tmp_path, entries)


# --- one identity's intervals must not overlap ------------------------------------------


@pytest.mark.parametrize(
  ("old_extra", "new_extra"),
  [
    ({"retired_at": 1000}, {"valid_from": 1000}),  # touching at one instant
    ({"retired_at": 1000}, {"valid_from": 500}),  # new starts before old retires
    ({"valid_from": 100, "retired_at": 1000}, {"valid_from": 50}),
    ({"retired_at": 1000}, {"valid_from": 0, "retired_at": 2000}),  # both bounded
  ],
)
def test_overlapping_intervals_of_one_validator_fail(tmp_path: Path, old_extra, new_extra) -> None:
  entries = [
    *_base(skip="node2"),
    _validator("node2", OLD, **old_extra),
    _validator("node2", NEW, **new_extra),
  ]
  with pytest.raises(RegistryError, match="'node2' has overlapping key intervals"):
    _load_validators(tmp_path, entries)


def test_two_retired_entries_without_valid_from_chain_correctly(tmp_path: Path) -> None:
  # Second retired entry with no valid_from starts right after the first one retires.
  third = generate_node_keypair()
  entries = [
    *_base(skip="node2"),
    _validator("node2", NEW, retired_at=2000),
    _validator("node2", third),
    _validator("node2", OLD, retired_at=1000),  # file order does not matter
  ]
  resolver = _resolver(_load_validators(tmp_path, entries))
  assert resolver.resolve_node_key("node2", 1000) == OLD.public_key
  assert resolver.resolve_node_key("node2", 1001) == NEW.public_key
  assert resolver.resolve_node_key("node2", 2001) == third.public_key


def test_overlapping_issuer_intervals_fail(tmp_path: Path) -> None:
  with pytest.raises(RegistryError, match="IssuerRegistry: 'issuer1' has overlapping"):
    _load_issuers(
      tmp_path,
      [
        {"issuer_id": "issuer1", "public_key": pem_of(ISSUER_OLD), "retired_at": 1000},
        {"issuer_id": "issuer1", "public_key": pem_of(ISSUER_NEW), "valid_from": 900},
      ],
    )


def test_resolver_rejects_overlap_in_registry_built_in_code() -> None:
  validators = ValidatorRegistry(
    entries=(
      KeyEntry("node1", OLD.public_key, 1000),
      KeyEntry("node1", NEW.public_key, None, valid_from=10),
    ),
    n=1,
    f=0,
  )
  with pytest.raises(RegistryError, match="overlapping"):
    _resolver(validators)


# --- at most n validator identities in force at any instant -----------------------------


def test_replacement_with_future_retired_at_is_rejected(tmp_path: Path) -> None:
  # The audit scenario: node4 replaced by node5 while node4's retired_at is in the future.
  entries = [*_base(skip="node4"), _validator("node4", retired_at=FUTURE), _validator("node5")]
  with pytest.raises(RegistryError) as excinfo:
    _load_validators(tmp_path, entries)
  message = str(excinfo.value)
  assert "5 validators have a key in force at 0 but n=4" in message
  assert "node1, node2, node3, node4, node5" in message


def test_five_identities_overlapping_on_a_window_are_rejected(tmp_path: Path) -> None:
  entries = [
    *_base(skip="node4"),
    _validator("node4", retired_at=2000),
    _validator("node5", valid_from=1500),
  ]
  with pytest.raises(RegistryError, match="in force at 1500 but n=4: .*node4, node5"):
    _load_validators(tmp_path, entries)


def test_extra_identity_beyond_n_is_rejected(tmp_path: Path) -> None:
  with pytest.raises(RegistryError, match="5 validators have a key in force"):
    _load_validators(tmp_path, [*_base(), _validator("node5")])


def test_replacement_by_new_identity_after_retirement_is_accepted(tmp_path: Path) -> None:
  entries = [
    *_base(skip="node4"),
    _validator("node4", retired_at=2000),
    _validator("node5", valid_from=2001),
  ]
  registry = _load_validators(tmp_path, entries)
  resolver = _resolver(registry)
  assert resolver.resolve_node_key("node4", 2000) == KEYS["node4"].public_key
  assert resolver.resolve_node_key("node5", 2000) is None
  assert resolver.resolve_node_key("node4", 2001) is None
  assert resolver.resolve_node_key("node5", 2001) == KEYS["node5"].public_key
  assert resolver.active_node_ids == {"node1", "node2", "node3", "node5"}
  assert registry.to_core().members == {"node1", "node2", "node3", "node4", "node5"}


def test_same_identity_key_rotation_is_accepted(tmp_path: Path) -> None:
  entries = [
    *_base(skip="node2"),
    _validator("node2", OLD, retired_at=1000),
    _validator("node2", NEW, valid_from=1001),
  ]
  resolver = _resolver(_load_validators(tmp_path, entries))
  assert resolver.resolve_node_key("node2", 1000) == OLD.public_key
  assert resolver.resolve_node_key("node2", 1001) == NEW.public_key


def test_rotation_with_gap_is_accepted(tmp_path: Path) -> None:
  entries = [
    *_base(skip="node2"),
    _validator("node2", OLD, retired_at=1000),
    _validator("node2", NEW, valid_from=5000),
  ]
  resolver = _resolver(_load_validators(tmp_path, entries))
  assert resolver.resolve_node_key("node2", 3000) is None


# --- backward compatibility: files without valid_from ----------------------------------


def test_files_without_valid_from_keep_their_meaning(tmp_path: Path) -> None:
  entries = [
    *_base(skip="node2"),
    _validator("node2", NEW, retired_at=None),
    _validator("node2", OLD, retired_at=1000),
  ]
  registry = _load_validators(tmp_path, entries)
  assert all(entry.valid_from is None for entry in registry.entries)
  resolver = _resolver(registry)
  assert resolver.resolve_node_key("node2", 0) == OLD.public_key
  assert resolver.resolve_node_key("node2", 1000) == OLD.public_key
  assert resolver.resolve_node_key("node2", 1001) == NEW.public_key
  assert resolver.resolve_node_key("node1", 0) == KEYS["node1"].public_key


def test_issuer_rotation_without_valid_from_still_loads(tmp_path: Path) -> None:
  issuers = _load_issuers(
    tmp_path,
    [
      {"issuer_id": "issuer1", "public_key": pem_of(ISSUER_OLD), "retired_at": 1000},
      {"issuer_id": "issuer1", "public_key": pem_of(ISSUER_NEW), "valid_from": None},
    ],
  )
  resolver = _resolver(_load_validators(tmp_path, _base()), issuers)
  assert resolver.resolve_issuer_key("issuer1", 1000) == ISSUER_OLD.public_key
  assert resolver.resolve_issuer_key("issuer1", 1001) == ISSUER_NEW.public_key
