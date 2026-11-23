from __future__ import annotations

import pytest
from node_helpers import NodeEnv, issuer_entry, write_issuers

from blockchain_core import generate_issuer_keypair
from node.registries import RegistryError, load_issuer_registry


def _load(env: NodeEnv, entries: list[dict]):
  write_issuers(env, entries)
  return load_issuer_registry(env.issuers_path)


def test_name_exposed_and_defaults_to_issuer_id(node_env: NodeEnv) -> None:  # CN-TC-MI.3
  registry = _load(
    node_env,
    [
      issuer_entry("issuer1", node_env.issuer_key, name="Institution A"),
      issuer_entry("issuer2", generate_issuer_keypair()),
    ],
  )
  assert registry.name_of("issuer1") == "Institution A"
  assert registry.name_of("issuer2") == "issuer2"
  assert registry.name_of("ghost") == "ghost"  # unknown issuer -> its id


def test_registry_without_names_still_loads(node_env: NodeEnv) -> None:  # CN-TC-MI.3
  registry = _load(node_env, [issuer_entry("issuer1", node_env.issuer_key)])
  assert registry.name_of("issuer1") == "issuer1"


def test_name_is_stripped(node_env: NodeEnv) -> None:
  registry = _load(node_env, [issuer_entry("issuer1", node_env.issuer_key, name="  Uni A ")])
  assert registry.name_of("issuer1") == "Uni A"


@pytest.mark.parametrize("bad", ["", "   ", 5, None, ["x"]])
def test_empty_or_non_string_name_fails(node_env: NodeEnv, bad) -> None:  # CN-TC-MI.3
  with pytest.raises(RegistryError, match="name"):
    _load(node_env, [issuer_entry("issuer1", node_env.issuer_key, name=bad)])


def test_name_length_boundary(node_env: NodeEnv) -> None:  # CN-TC-MI.3: 100 ok, 101 fails
  assert _load(node_env, [issuer_entry("issuer1", node_env.issuer_key, name="a" * 100)])
  with pytest.raises(RegistryError, match="100"):
    _load(node_env, [issuer_entry("issuer1", node_env.issuer_key, name="a" * 101)])


def test_duplicate_name_across_issuers_fails(node_env: NodeEnv) -> None:  # CN-TC-MI.3
  with pytest.raises(RegistryError, match="more than one issuer"):
    _load(
      node_env,
      [
        issuer_entry("issuer1", node_env.issuer_key, name="Institution B"),
        issuer_entry("issuer2", generate_issuer_keypair(), name="institution b"),  # same folded
      ],
    )


def test_rotated_entries_must_agree_on_name(node_env: NodeEnv) -> None:  # CN-TC-MI.3
  old = generate_issuer_keypair()
  retired = issuer_entry("issuer1", old, name="Old Name", retired_at=1000)
  with pytest.raises(RegistryError, match="conflicting"):
    _load(node_env, [retired, issuer_entry("issuer1", node_env.issuer_key, name="New Name")])
  same = _load(
    node_env,
    [
      {**retired, "name": "Same"},
      issuer_entry("issuer1", node_env.issuer_key, name="Same"),
    ],
  )
  assert same.name_of("issuer1") == "Same"


def test_validator_entries_ignore_name_field(node_env: NodeEnv) -> None:
  import json

  from node.registries import load_validator_registry

  raw = json.loads(node_env.validators_path.read_text(encoding="utf-8"))
  raw["validators"][0]["name"] = 5  # validators carry no display name; not parsed
  node_env.validators_path.write_text(json.dumps(raw), encoding="utf-8")
  assert load_validator_registry(node_env.validators_path).n == 4
