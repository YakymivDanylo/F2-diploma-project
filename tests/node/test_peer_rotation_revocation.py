"""Wave D hardening: validator key rotation in PeerInfo (R2), clock step back (R11) and
revocation of compromised keys (finding 9 / R8)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from node_helpers import NodeEnv, pem_of

from blockchain_core import generate_issuer_keypair, generate_node_keypair
from blockchain_core.keys import NodeKeyPair
from node.api.peers import PeerOut, gossip_accept
from node.config import load_config
from node.context import BootError
from node.key_resolver import CombinedKeyResolver
from node.main import create_app
from node.peers.attestation import (
  RegistrationError,
  check_peer_registration,
  check_registration,
  sign_registration,
)
from node.peers.registry import PeerKeyMismatchError, PeerRegistry
from node.peers.seed_registration import merge_peer_list
from node.registries import (
  IssuerRegistry,
  KeyEntry,
  RegistryError,
  ValidatorRegistry,
  load_issuer_registry,
  load_validator_registry,
)

HOST_A = "host-a.example"
HOST_B = "host-b.example"
SKEW = 60_000
FAR_FUTURE = 10**15


def _now() -> int:
  return int(time.time() * 1000)


def _app(node_env: NodeEnv):
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"}
  return create_app(load_config(env), mine=False)


def _body(
  node_id: str,
  key: NodeKeyPair,
  *,
  host: str = HOST_A,
  port: int = 9100,
  issued_at: int | None = None,
) -> dict[str, Any]:
  issued_at = _now() - 1000 if issued_at is None else issued_at
  pem = pem_of(key)
  return {
    "node_id": node_id,
    "host": host,
    "port": port,
    "public_key": pem,
    "issued_at": issued_at,
    "signature": sign_registration(key.private_key, node_id, host, port, pem, issued_at),
  }


def _code(response) -> str:
  return response.json()["error"]["code"]


def _rotate(node_env: NodeEnv, node_id: str, new_key: NodeKeyPair, retired_at: int) -> None:
  """Rewrite the ValidatorSet: `node_id`'s current key retires at `retired_at`, `new_key`
  takes over right after."""
  raw = json.loads(node_env.validators_path.read_text(encoding="utf-8"))
  for entry in raw["validators"]:
    if entry["node_id"] == node_id:
      entry["retired_at"] = retired_at
  raw["validators"].append({"node_id": node_id, "public_key": pem_of(new_key)})
  node_env.validators_path.write_text(json.dumps(raw), encoding="utf-8")


# ----------------------------------------------------- R2: rotation replaces the stored key


def test_r2_registry_replaces_the_key_of_a_protected_id() -> None:
  registry = PeerRegistry("self", is_protected=lambda node_id: node_id == "val")
  registry.register("val", HOST_A, 1, "OLD-PEM")
  info = registry.register("val", HOST_B, 2, "NEW-PEM")
  assert info is not None
  stored = registry.get("val")
  assert stored is not None
  assert (stored.public_key, stored.host, stored.port) == ("NEW-PEM", HOST_B, 2)


def test_r2_registry_keeps_the_mismatch_rule_for_non_validators() -> None:
  registry = PeerRegistry("self", is_protected=lambda node_id: node_id == "val")
  registry.register("outsider", HOST_A, 1, "OLD-PEM")
  with pytest.raises(PeerKeyMismatchError):
    registry.register("outsider", HOST_B, 2, "NEW-PEM")
  stored = registry.get("outsider")
  assert stored is not None and (stored.public_key, stored.host) == ("OLD-PEM", HOST_A)


def test_r2_rotated_validator_reregisters_with_its_new_key_and_new_address(
  node_env: NodeEnv,
) -> None:
  old_key = node_env.validator_keys["node2"]
  new_key = generate_node_keypair()
  app = _app(node_env)
  with TestClient(app) as client:
    context = app.state.context
    assert client.post("/peers/register", json=_body("node2", old_key)).status_code == 200
    _rotate(node_env, "node2", new_key, retired_at=_now() - 120_000)
    context.resolvers.reload_from_files(node_env.validators_path, node_env.issuers_path)
    response = client.post("/peers/register", json=_body("node2", new_key, host=HOST_B))
    assert response.status_code == 200, response.json()
    stored = context.peers.get("node2")
    assert stored is not None
    assert stored.public_key == pem_of(new_key)
    assert stored.host == HOST_B
    # the retired key can no longer move the address back
    replay = client.post("/peers/register", json=_body("node2", old_key, host=HOST_A))
    assert replay.status_code == 409 and _code(replay) == "peer_key_mismatch"
    assert context.peers.get("node2").host == HOST_B  # type: ignore[union-attr]


def test_r2_gossiped_validator_entry_replaces_the_stored_key(node_env: NodeEnv, boot) -> None:
  context = boot(node_env.env)
  accept = gossip_accept(context)
  old_key = node_env.validator_keys["node3"]
  new_key = generate_node_keypair()
  old_entry = _body("node3", old_key, issued_at=_now() - 5_000)
  assert merge_peer_list(context.peers, {"peers": [old_entry]}, PeerOut, accept) == 1
  _rotate(node_env, "node3", new_key, retired_at=_now() - 120_000)
  context.resolvers.reload_from_files(node_env.validators_path, node_env.issuers_path)
  # the stale old-key entry is no longer accepted; the new-key entry replaces it
  assert merge_peer_list(context.peers, {"peers": [old_entry]}, PeerOut, accept) == 0
  new_entry = _body("node3", new_key, host=HOST_B)
  assert merge_peer_list(context.peers, {"peers": [new_entry]}, PeerOut, accept) == 1
  stored = context.peers.get("node3")
  assert stored is not None
  assert (stored.public_key, stored.host) == (pem_of(new_key), HOST_B)


def test_r2_non_validator_key_change_is_still_a_409(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env)) as client:
    first = client.post("/peers/register", json=_body("outsider", generate_node_keypair()))
    assert first.status_code == 200
    response = client.post("/peers/register", json=_body("outsider", generate_node_keypair()))
    assert response.status_code == 409 and _code(response) == "peer_key_mismatch"


# ------------------------------------------------------ R11: clock step back within the skew


KEY_R11 = generate_node_keypair()


def _check_outsider(issued_at: int, held: int, now: int) -> None:
  body = _body("outsider", KEY_R11, issued_at=issued_at)
  check_peer_registration(
    **{k: body[k] for k in ("node_id", "host", "port", "public_key", "issued_at", "signature")},
    now_ms=now,
    max_future_skew_ms=SKEW,
    held_issued_at=held,
  )


def test_r11_registration_older_than_held_within_the_skew_is_accepted() -> None:
  now = _now()
  _check_outsider(now - 30_000, held=now, now=now)
  _check_outsider(now - SKEW, held=now, now=now)  # exactly at the boundary: accepted


def test_r11_registration_older_than_held_beyond_the_skew_is_stale() -> None:
  now = _now()
  with pytest.raises(RegistrationError) as caught:
    _check_outsider(now - SKEW - 1, held=now, now=now)
  assert caught.value.status == 409 and caught.value.code == "stale_registration"


def test_r11_validator_check_uses_the_same_tolerance(node_env: NodeEnv) -> None:
  key = node_env.validator_keys["node2"]
  now = _now()

  def resolve(_node_id: str, _at: int):
    return key.public_key

  def check(issued_at: int) -> None:
    body = _body("node2", key, issued_at=issued_at)
    check_registration(
      **{k: body[k] for k in ("node_id", "host", "port", "public_key", "issued_at", "signature")},
      resolve_node_key=resolve,
      now_ms=now,
      max_future_skew_ms=SKEW,
      held_issued_at=now + 20_000,  # signed while the clock ran ahead
    )

  check(now - 1_000)  # the node's clock stepped back: fresh registration still accepted
  with pytest.raises(RegistrationError) as caught:
    check(now + 20_000 - SKEW - 1)
  assert caught.value.code == "stale_registration"


def test_r11_clock_step_back_does_not_lock_a_validator_out(node_env: NodeEnv) -> None:
  key = node_env.validator_keys["node2"]
  app = _app(node_env)
  with TestClient(app) as client:
    ahead = _body("node2", key, host=HOST_A, issued_at=_now() + 30_000)
    assert client.post("/peers/register", json=ahead).status_code == 200
    stepped_back = _body("node2", key, host=HOST_A, issued_at=_now() - 1_000)
    response = client.post("/peers/register", json=stepped_back)
    assert response.status_code == 200, response.json()  # a TTL refresh, same address
    held = app.state.context.peers.get("node2")
    assert held is not None and held.host == HOST_A
    assert (held.issued_at, held.signature) == (ahead["issued_at"], ahead["signature"])
    # N1: moving needs a registration at least as new as the held one
    moved = _body("node2", key, host=HOST_B, issued_at=_now() - 1_000)
    response = client.post("/peers/register", json=moved)
    assert response.status_code == 409 and _code(response) == "stale_registration"
    assert app.state.context.peers.get("node2").host == HOST_A  # type: ignore[union-attr]


# ---------------------------------------------------------------- revocation (finding 9)

VAL = {f"node{i}": generate_node_keypair() for i in range(1, 6)}
ISSUER = generate_issuer_keypair()
ISSUER_NEXT = generate_issuer_keypair()


def _validator(node_id: str, pair: NodeKeyPair | None = None, **extra) -> dict:
  return {"node_id": node_id, "public_key": pem_of(pair or VAL[node_id]), **extra}


def _load_validators(tmp_path: Path, entries: list[dict], n: int = 4, f: int = 1):
  path = tmp_path / "validators.json"
  path.write_text(json.dumps({"n": n, "f": f, "validators": entries}), encoding="utf-8")
  return load_validator_registry(path)


def _load_issuers(tmp_path: Path, entries: list[dict]):
  path = tmp_path / "issuers.json"
  path.write_text(json.dumps({"issuers": entries}), encoding="utf-8")
  return load_issuer_registry(path)


TIMESTAMPS = (0, 1, 999, 1000, 1001, 5_000, _now(), FAR_FUTURE)


def test_revoked_validator_key_never_resolves(tmp_path: Path) -> None:
  entries = [
    _validator("node1"),
    _validator("node2"),
    _validator("node3"),
    _validator("node4", revoked=True),
  ]
  validators = _load_validators(tmp_path, entries)
  issuers = IssuerRegistry(entries=(KeyEntry("i", ISSUER.public_key, None),))
  resolver = CombinedKeyResolver(validators, issuers)
  for at in TIMESTAMPS:
    assert resolver.resolve_node_key("node4", at) is None
    assert resolver.resolve_node_key("node1", at) is not None
  assert "node4" in resolver.known_node_ids  # still a ValidatorSet id: PeerInfo cannot squat it
  assert "node4" not in resolver.active_node_ids


def test_revoked_retired_key_cannot_back_date_but_its_successor_resolves(tmp_path: Path) -> None:
  old, new = generate_node_keypair(), generate_node_keypair()
  entries = [
    _validator("node1"),
    _validator("node2"),
    _validator("node3"),
    _validator("node4", old, retired_at=1000, revoked=True),
    _validator("node4", new),
  ]
  resolver = CombinedKeyResolver(
    _load_validators(tmp_path, entries),
    IssuerRegistry(entries=(KeyEntry("i", ISSUER.public_key, None),)),
  )
  for at in (0, 500, 1000):  # inside the revoked interval: nothing resolves
    assert resolver.resolve_node_key("node4", at) is None
  assert resolver.resolve_node_key("node4", 1001) == new.public_key
  assert resolver.resolve_node_key("node4", FAR_FUTURE) == new.public_key


def test_revoked_issuer_key_never_resolves(tmp_path: Path) -> None:
  issuers = _load_issuers(
    tmp_path,
    [
      {"issuer_id": "uni", "public_key": pem_of(ISSUER), "retired_at": 1000, "revoked": True},
      {"issuer_id": "uni", "public_key": pem_of(ISSUER_NEXT)},
      {"issuer_id": "gone", "public_key": pem_of(generate_issuer_keypair()), "revoked": True},
    ],
  )
  resolver = CombinedKeyResolver(
    ValidatorRegistry(entries=(KeyEntry("node1", VAL["node1"].public_key, None),), n=1, f=0),
    issuers,
  )
  for at in TIMESTAMPS:
    assert resolver.resolve_issuer_key("gone", at) is None
  for at in (0, 1000):
    assert resolver.resolve_issuer_key("uni", at) is None
  assert resolver.resolve_issuer_key("uni", 1001) == ISSUER_NEXT.public_key


def test_revoked_defaults_to_false(tmp_path: Path) -> None:
  validators = _load_validators(tmp_path, [_validator(f"node{i}") for i in range(1, 5)])
  assert all(entry.revoked is False for entry in validators.entries)
  issuers = _load_issuers(tmp_path, [{"issuer_id": "uni", "public_key": pem_of(ISSUER)}])
  assert issuers.entries[0].revoked is False
  explicit = _load_issuers(
    tmp_path, [{"issuer_id": "uni", "public_key": pem_of(ISSUER), "revoked": False}]
  )
  assert explicit.entries[0].revoked is False


@pytest.mark.parametrize("bad", [1, 0, "true", None, [], {}])
def test_revoked_must_be_a_boolean(tmp_path: Path, bad: Any) -> None:
  entries = [*(_validator(f"node{i}") for i in range(1, 4)), _validator("node4", revoked=bad)]
  with pytest.raises(RegistryError, match="revoked"):
    _load_validators(tmp_path, entries)
  with pytest.raises(RegistryError, match="revoked"):
    _load_issuers(tmp_path, [{"issuer_id": "uni", "public_key": pem_of(ISSUER), "revoked": bad}])


def test_revoked_entry_still_counts_for_interval_checks(tmp_path: Path) -> None:
  base = [_validator(f"node{i}") for i in range(1, 4)]
  # a revoked open entry still occupies node4's timeline: a second open key overlaps it
  with pytest.raises(RegistryError):
    _load_validators(
      tmp_path,
      [*base, _validator("node4", revoked=True), _validator("node4", generate_node_keypair())],
    )
  # and it still counts towards the n-in-force cap
  with pytest.raises(RegistryError, match="n=4"):
    _load_validators(tmp_path, [*base, _validator("node4"), _validator("node5", revoked=True)])


def test_node_with_a_revoked_own_key_refuses_to_boot(node_env: NodeEnv, boot) -> None:
  raw = json.loads(node_env.validators_path.read_text(encoding="utf-8"))
  for entry in raw["validators"]:
    if entry["node_id"] == "node1":
      entry["revoked"] = True
  node_env.validators_path.write_text(json.dumps(raw), encoding="utf-8")
  resolver = CombinedKeyResolver(
    load_validator_registry(node_env.validators_path),
    load_issuer_registry(node_env.issuers_path),
  )
  for at in TIMESTAMPS:
    assert resolver.resolve_node_key("node1", at) is None
  with pytest.raises(BootError):
    boot(node_env.env)


def test_node_with_a_revoked_own_issuer_key_refuses_to_boot(node_env: NodeEnv, boot) -> None:
  raw = json.loads(node_env.issuers_path.read_text(encoding="utf-8"))
  raw["issuers"][0]["revoked"] = True
  node_env.issuers_path.write_text(json.dumps(raw), encoding="utf-8")
  with pytest.raises(BootError):
    boot(node_env.env)
