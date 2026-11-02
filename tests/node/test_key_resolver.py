from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from chain_factory import pow_chain
from node_helpers import NodeEnv, pem_of

from blockchain_core import generate_issuer_keypair, generate_node_keypair
from node.key_resolver import CombinedKeyResolver, ResolverHolder
from node.registries import IssuerRegistry, KeyEntry, RegistryError, ValidatorRegistry
from node.validity_cache import ChainValidator, ValidityCache

OLD = generate_node_keypair()
NEW = generate_node_keypair()
SOLO = generate_node_keypair()
ISSUER_A = generate_issuer_keypair()
ISSUER_B = generate_issuer_keypair()


def _resolver() -> CombinedKeyResolver:
  validators = ValidatorRegistry(
    entries=(
      KeyEntry("node2", OLD.public_key, 1000),  # retired
      KeyEntry("node2", NEW.public_key, None),  # rotated in
      KeyEntry("node1", SOLO.public_key, None),
      KeyEntry("gone", OLD.public_key, 500),  # retired, never replaced
    ),
    n=4,
    f=1,
  )
  issuers = IssuerRegistry(
    entries=(KeyEntry("a", ISSUER_A.public_key, None), KeyEntry("b", ISSUER_B.public_key, None))
  )
  return CombinedKeyResolver(validators, issuers)


def test_rotation_is_time_aware() -> None:  # CN-TC-14.7, CN-TC-1.4
  resolver = _resolver()
  assert resolver.resolve_node_key("node2", 999) is OLD.public_key
  assert resolver.resolve_node_key("node2", 1000) is OLD.public_key  # at retired_at: old key
  assert resolver.resolve_node_key("node2", 1001) is NEW.public_key
  assert resolver.resolve_node_key("node2", 10**15) is NEW.public_key


def test_retired_entry_is_resolvable_but_not_active() -> None:  # CN-TC-14.7
  resolver = _resolver()
  assert resolver.resolve_node_key("gone", 500) is OLD.public_key
  assert resolver.resolve_node_key("gone", 501) is None
  assert resolver.active_node_ids == {"node1", "node2"}


def test_unknown_identity_is_not_found() -> None:  # CN-TC-14.5
  resolver = _resolver()
  assert resolver.resolve_node_key("ghost", 1) is None
  assert resolver.resolve_issuer_key("ghost", 1) is None


def test_issuers_are_disambiguated_by_issuer_id() -> None:  # CN-TC-14.8
  resolver = _resolver()
  assert resolver.resolve_issuer_key("a", 1) is ISSUER_A.public_key
  assert resolver.resolve_issuer_key("b", 1) is ISSUER_B.public_key
  assert resolver.resolve_node_key("a", 1) is None  # node and issuer namespaces are separate


def test_unknown_proposer_is_a_signature_failure(node_env: NodeEnv) -> None:  # CN-TC-14.5
  validators = ValidatorRegistry(
    entries=(KeyEntry("node1", node_env.node_key.public_key, None),), n=1, f=0
  )
  issuers = IssuerRegistry(entries=(KeyEntry("issuer1", node_env.issuer_key.public_key, None),))
  holder = ResolverHolder(CombinedKeyResolver(validators, issuers))
  validator = ChainValidator(holder, expected_difficulty=1, validator_set=None)
  assert validator.full(pow_chain(node_env, 1)).valid
  result = validator.full(pow_chain(node_env, 1, proposer="ghost"))
  assert not result.valid
  assert result.failure_type == "signature"


def test_all_call_sites_share_one_resolver_snapshot(node_env: NodeEnv) -> None:  # CN-TC-14.2
  seen: list[object] = []

  class SpyHolder(ResolverHolder):
    @property
    def current(self) -> CombinedKeyResolver:
      seen.append(self._current)
      return self._current

  validators = ValidatorRegistry(
    entries=(KeyEntry("node1", node_env.node_key.public_key, None),), n=1, f=0
  )
  issuers = IssuerRegistry(entries=(KeyEntry("issuer1", node_env.issuer_key.public_key, None),))
  holder = SpyHolder(CombinedKeyResolver(validators, issuers))
  validator = ChainValidator(holder, expected_difficulty=1, validator_set=None)
  blocks = pow_chain(node_env, 2)
  validator.full(blocks)
  validator.extension(blocks[0], blocks[1:2])
  cache = ValidityCache(validator)
  cache.initialize(blocks[:2])
  cache.on_append(blocks[2])
  assert len(seen) >= 4
  assert all(item is seen[0] for item in seen)


def test_reload_swaps_resolver_without_touching_in_flight(node_env: NodeEnv) -> None:  # 14.4
  holder = ResolverHolder(
    CombinedKeyResolver(
      ValidatorRegistry(entries=(KeyEntry("node1", OLD.public_key, None),), n=1, f=0),
      IssuerRegistry(entries=(KeyEntry("issuer1", ISSUER_A.public_key, None),)),
    )
  )
  in_flight = holder.current
  doc = json.loads(node_env.validators_path.read_text())
  doc["validators"][0]["public_key"] = pem_of(generate_node_keypair())
  node_env.validators_path.write_text(json.dumps(doc), encoding="utf-8")
  holder.reload_from_files(node_env.validators_path, node_env.issuers_path)
  assert holder.current is not in_flight
  assert in_flight.resolve_node_key("node1", 1) is OLD.public_key  # snapshot unchanged
  assert holder.current.resolve_node_key("node1", 1) is not OLD.public_key


def test_failed_reload_keeps_previous_resolver(node_env: NodeEnv) -> None:
  holder = ResolverHolder(_resolver())
  before = holder.current
  node_env.validators_path.write_text("{ nope", encoding="utf-8")
  with pytest.raises(RegistryError):
    holder.reload_from_files(node_env.validators_path, node_env.issuers_path)
  assert holder.current is before


def test_blockchain_core_never_imports_node() -> None:  # CN-TC-14.3
  root = Path(__file__).resolve().parents[2] / "src" / "blockchain_core"
  pattern = re.compile(r"^\s*(from|import)\s+node(\.|\s|$)", re.MULTILINE)
  offenders = [p for p in root.rglob("*.py") if pattern.search(p.read_text(encoding="utf-8"))]
  assert offenders == []
