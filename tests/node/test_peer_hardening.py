"""Peer-layer hardening (security audits 2026-11-20): proof of possession for every
registration, bounded registry with TTL eviction, address checks, freshness window, current
validator key, normalized PEM, parallel periodic seed registration, bounded seed transport,
pagination and config guards."""

from __future__ import annotations

import asyncio
import http.server
import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from node_helpers import NodeEnv, pem_of

from blockchain_core import generate_node_keypair
from blockchain_core.keys import NodeKeyPair
from node.api.peers import MAX_PEERS_PAGE, PeerOut, gossip_accept
from node.config import ConfigError, load_config
from node.main import create_app
from node.peers.attestation import (
  REGISTRATION_MAX_AGE_MS,
  RegistrationError,
  check_peer_registration,
  check_registration,
  sign_registration,
)
from node.peers.registry import (
  PEER_TTL_S,
  PeerInfo,
  PeerRegistry,
  PeerRegistryFullError,
  StaleRegistrationError,
  is_loopback_host,
  peer_address_problem,
)
from node.peers.seed_registration import (
  SEED_REFRESH_S,
  SeedResponseError,
  UrllibTransport,
  merge_peer_list,
  register_with_seeds,
)


def _now() -> int:
  return int(time.time() * 1000)


def _app(node_env: NodeEnv, **extra: str):
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1", **extra}
  return create_app(load_config(env), mine=False)


def _body(
  node_id: str,
  key: NodeKeyPair,
  *,
  host: str = "peer.example",
  port: int = 9100,
  issued_at: int | None = None,
  signer: NodeKeyPair | None = None,
  pem: str | None = None,
) -> dict[str, Any]:
  """A registration of `key` signed by `signer` (default: `key` itself)."""
  issued_at = _now() - 1000 if issued_at is None else issued_at
  normalized = pem_of(key)
  signing = signer or key
  return {
    "node_id": node_id,
    "host": host,
    "port": port,
    "public_key": pem or normalized,
    "issued_at": issued_at,
    "signature": sign_registration(signing.private_key, node_id, host, port, normalized, issued_at),
  }


def _code(response) -> str:
  return response.json()["error"]["code"]


def _ids(client: TestClient) -> list[str]:
  return [p["node_id"] for p in client.get("/peers").json()["peers"]]


@pytest.fixture
def client(node_env: NodeEnv) -> Iterator[TestClient]:
  with TestClient(_app(node_env)) as test_client:
    yield test_client


# ------------------------------------------------- 1a. proof of possession


def test_unsigned_non_validator_is_refused(client: TestClient) -> None:
  body = _body("outsider", generate_node_keypair())
  del body["signature"], body["issued_at"]
  response = client.post("/peers/register", json=body)
  assert response.status_code == 403 and _code(response) == "registration_unauthenticated"
  assert _ids(client) == []


def test_non_validator_signed_by_another_key_is_refused(client: TestClient) -> None:
  body = _body("outsider", generate_node_keypair(), signer=generate_node_keypair())
  response = client.post("/peers/register", json=body)
  assert response.status_code == 403 and _code(response) == "registration_unauthenticated"
  assert _ids(client) == []


def test_non_validator_with_proof_of_possession_is_stored(client: TestClient) -> None:
  key = generate_node_keypair()
  body = _body("outsider", key)
  assert client.post("/peers/register", json=body).status_code == 200
  stored = client.get("/peers").json()["peers"][0]
  assert stored["node_id"] == "outsider" and stored["public_key"] == pem_of(key)
  assert stored["signature"] == body["signature"]


def test_gossip_applies_proof_of_possession_to_non_validators(node_env: NodeEnv, boot) -> None:
  context = boot(node_env.env)
  unsigned = _body("unsigned", generate_node_keypair())
  del unsigned["signature"]
  forged = _body("forged", generate_node_keypair(), signer=generate_node_keypair())
  stale = _body("stale", generate_node_keypair(), issued_at=_now() - REGISTRATION_MAX_AGE_MS - 1)
  good = _body("good", generate_node_keypair())
  body = {"peers": [unsigned, forged, stale, good]}
  assert merge_peer_list(context.peers, body, PeerOut, gossip_accept(context)) == 1
  assert [p.node_id for p in context.peers.list()] == ["good"]


# --------------------------------------------- 1b. bounded registry with TTL


class _Clock:
  def __init__(self) -> None:
    self.now = 1_000_000

  def __call__(self) -> int:
    return self.now


def test_registry_default_cap_is_256() -> None:
  registry = PeerRegistry("me")
  for i in range(300):
    registry.register(f"p{i}", "h", 1, "k")
  assert len(registry) == 256


def test_stale_non_validator_entries_are_evicted_on_access() -> None:
  clock = _Clock()
  registry = PeerRegistry("me", clock=clock, is_protected=lambda node_id: node_id == "node2")
  registry.register("outsider", "h", 1, "k")
  registry.register("node2", "h", 2, "k")
  clock.now += PEER_TTL_S * 1000  # exactly at the TTL: still held
  assert {p.node_id for p in registry.list()} == {"outsider", "node2"}
  clock.now += 1
  assert registry.get("outsider") is None
  assert [p.node_id for p in registry.list()] == ["node2"]  # a validator never expires
  assert len(registry) == 1


def test_refresh_keeps_an_entry_alive() -> None:
  clock = _Clock()
  registry = PeerRegistry("me", clock=clock)
  registry.register("outsider", "h", 1, "k")
  for _ in range(3):
    clock.now += PEER_TTL_S * 1000 - 1
    assert registry.register("outsider", "h", 1, "k") is not None
  assert registry.get("outsider") is not None


def test_full_registry_evicts_the_stalest_non_validator() -> None:
  clock = _Clock()
  registry = PeerRegistry(
    "me", max_peers=3, clock=clock, is_protected=lambda node_id: node_id.startswith("node")
  )
  registry.register("node2", "h", 1, "k")  # oldest, but a validator
  clock.now += 10
  registry.register("old", "h", 2, "k")
  clock.now += 10
  registry.register("young", "h", 3, "k")
  clock.now += 10
  registry.register("newcomer", "h", 4, "k")
  assert {p.node_id for p in registry.list()} == {"node2", "young", "newcomer"}


def test_registry_full_of_validators_refuses_new_ids() -> None:
  registry = PeerRegistry("me", max_peers=2, is_protected=lambda _node_id: True)
  registry.register("node2", "h", 1, "k")
  registry.register("node3", "h", 2, "k")
  with pytest.raises(PeerRegistryFullError):
    registry.register("node4", "h", 3, "k")
  assert {p.node_id for p in registry.list()} == {"node2", "node3"}


def test_backward_compatible_positional_register() -> None:
  registry = PeerRegistry("me")
  info = registry.register("node2", "node2", 9002, "pem")
  assert info is not None and (info.host, info.port, info.public_key) == ("node2", 9002, "pem")
  assert registry.register("me", "x", 1, "pem") is None


# -------------------------------------------------------- 1c. address checks


BAD_HOSTS = [
  "127.0.0.1",
  "127.1",  # legacy short form the resolver also accepts
  "2130706433",  # 127.0.0.1 as a decimal
  "localhost",
  "LocalHost",
  "localhost.",
  "node.localhost",
  "169.254.10.1",
  "0.0.0.0",
  "224.0.0.1",
]
GOOD_HOSTS = ["10.1.2.3", "172.16.0.9", "192.168.1.20", "node2", "validator-3.example"]


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_unroutable_addresses_are_rejected(client: TestClient, host: str) -> None:
  response = client.post(
    "/peers/register", json=_body("outsider", generate_node_keypair(), host=host)
  )
  assert response.status_code == 422 and _code(response) == "invalid_peer_address"
  assert _ids(client) == []


@pytest.mark.parametrize("host", GOOD_HOSTS)
def test_private_ranges_and_dns_names_are_accepted(client: TestClient, host: str) -> None:
  response = client.post(
    "/peers/register", json=_body("outsider", generate_node_keypair(), host=host)
  )
  assert response.status_code == 200


def test_our_own_address_is_rejected(node_env: NodeEnv) -> None:
  app = _app(node_env, NODE_HOST="node1.example", NODE_PORT="8001")
  with TestClient(app) as client:
    key = generate_node_keypair()
    own = _body("outsider", key, host="NODE1.example", port=8001)
    response = client.post("/peers/register", json=own)
    assert response.status_code == 422 and _code(response) == "invalid_peer_address"
    other_port = _body("outsider", key, host="node1.example", port=8002)
    assert client.post("/peers/register", json=other_port).status_code == 200


def test_validator_registration_is_address_checked_too(node_env: NodeEnv, client) -> None:
  body = _body("node2", node_env.validator_keys["node2"], host="127.0.0.1")
  response = client.post("/peers/register", json=body)
  assert response.status_code == 422 and _code(response) == "invalid_peer_address"


def test_allow_loopback_peers_admits_loopback_only(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env, ALLOW_LOOPBACK_PEERS="1")) as client:
    for i, host in enumerate(["127.0.0.1", "localhost"]):
      body = _body(f"local{i}", generate_node_keypair(), host=host)
      assert client.post("/peers/register", json=body).status_code == 200
    for host in ["169.254.1.1", "0.0.0.0", "224.0.0.1"]:
      body = _body("other", generate_node_keypair(), host=host)
      assert client.post("/peers/register", json=body).status_code == 422


def test_gossip_drops_unroutable_addresses(node_env: NodeEnv, boot) -> None:
  context = boot(node_env.env)
  body = {
    "peers": [
      _body("loop", generate_node_keypair(), host="127.0.0.1"),
      _body("own", generate_node_keypair(), host="localhost", port=8000),
      _body("fine", generate_node_keypair(), host="10.0.0.7"),
    ]
  }
  assert merge_peer_list(context.peers, body, PeerOut, gossip_accept(context)) == 1
  assert [p.node_id for p in context.peers.list()] == ["fine"]


def test_address_helper_directly() -> None:
  assert is_loopback_host("127.0.0.53") and is_loopback_host("a.b.localhost")
  assert not is_loopback_host("10.0.0.1") and not is_loopback_host("localhost-node")
  assert peer_address_problem("node1", 9001, own_host="node1", own_port=9001) is not None
  assert peer_address_problem("node1", 9002, own_host="node1", own_port=9001) is None
  assert peer_address_problem("127.0.0.1", 1, own_host="x", own_port=1, allow_loopback=True) is None


# ------------------------------------------------------ 2. freshness window


def test_too_old_registrations_are_refused(node_env: NodeEnv, client) -> None:
  old = _now() - REGISTRATION_MAX_AGE_MS - 5_000
  for body in (
    _body("outsider", generate_node_keypair(), issued_at=old),
    _body("node2", node_env.validator_keys["node2"], issued_at=old),
  ):
    response = client.post("/peers/register", json=body)
    assert response.status_code == 403 and _code(response) == "registration_unauthenticated"
    assert "stale" in response.json()["error"]["message"]
  assert _ids(client) == []
  within = _now() - REGISTRATION_MAX_AGE_MS + 60_000
  body = _body("outsider", generate_node_keypair(), issued_at=within)
  assert client.post("/peers/register", json=body).status_code == 200


def test_future_registrations_are_refused(node_env: NodeEnv, client) -> None:
  far = _now() + 10 * 60_000
  for body in (
    _body("outsider", generate_node_keypair(), issued_at=far),
    _body("node2", node_env.validator_keys["node2"], issued_at=far),
  ):
    response = client.post("/peers/register", json=body)
    assert response.status_code == 403 and "future" in response.json()["error"]["message"]


def test_older_than_held_is_still_a_409(client: TestClient) -> None:
  key = generate_node_keypair()
  newer = _body("outsider", key, issued_at=_now() - 1_000)
  older = _body("outsider", key, issued_at=_now() - 300_000, host="other.example")
  assert client.post("/peers/register", json=newer).status_code == 200
  response = client.post("/peers/register", json=older)
  assert response.status_code == 409 and _code(response) == "stale_registration"


# ------------------------------------------- N1: no rollback through the skew tolerance


def test_n1_replaying_older_registrations_cannot_walk_the_address_back(
  node_env: NodeEnv, client: TestClient
) -> None:
  key = node_env.validator_keys["node2"]
  now = _now()
  # genuine history, each step inside the 60 s skew of the previous one
  history = [_body("node2", key, host="a.example", issued_at=now - t) for t in (200_000, 150_000)]
  a_last = _body("node2", key, host="a.example", issued_at=now - 100_000)
  b_old = _body("node2", key, host="b.example", issued_at=now - 90_000)
  b_new = _body("node2", key, host="b.example", issued_at=now - 50_000)
  for body in (*history, a_last, b_old, b_new):
    assert client.post("/peers/register", json=body).status_code == 200
  # an attacker replays the public older registrations, newest first
  assert client.post("/peers/register", json=b_old).status_code == 200  # TTL refresh only
  for replay in (a_last, *reversed(history)):  # a_last lies inside the skew of b_new
    response = client.post("/peers/register", json=replay)
    assert response.status_code == 409 and _code(response) == "stale_registration"
  stored = {p["node_id"]: p for p in client.get("/peers").json()["peers"]}["node2"]
  assert stored["host"] == "b.example"
  assert (stored["issued_at"], stored["signature"]) == (b_new["issued_at"], b_new["signature"])


def test_n1_gossip_replay_cannot_walk_the_address_back(node_env: NodeEnv, boot) -> None:
  context = boot(node_env.env)
  accept = gossip_accept(context)
  key = node_env.validator_keys["node3"]
  now = _now()
  old_a = _body("node3", key, host="a.example", issued_at=now - 40_000)
  new_b = _body("node3", key, host="b.example", issued_at=now - 10_000)
  assert merge_peer_list(context.peers, {"peers": [old_a]}, PeerOut, accept) == 1
  assert merge_peer_list(context.peers, {"peers": [new_b]}, PeerOut, accept) == 1
  assert merge_peer_list(context.peers, {"peers": [old_a]}, PeerOut, accept) == 0
  held = context.peers.get("node3")
  assert held is not None and (held.host, held.issued_at) == ("b.example", new_b["issued_at"])


def test_n1_registry_keeps_the_newest_issued_at() -> None:
  registry = PeerRegistry("me")
  registry.register("p", "a.example", 1, "k", issued_at=1_000, signature="aa")
  # clock step back, same address: a TTL refresh that keeps the held registration
  refreshed = registry.register("p", "a.example", 1, "k", issued_at=900, signature="bb")
  assert refreshed is not None and (refreshed.issued_at, refreshed.signature) == (1_000, "aa")
  # an address change needs a registration at least as new as the held one
  with pytest.raises(StaleRegistrationError):
    registry.register("p", "b.example", 1, "k", issued_at=999, signature="cc")
  with pytest.raises(StaleRegistrationError):
    registry.register("p", "a.example", 2, "k", issued_at=999, signature="cc")
  moved = registry.register("p", "b.example", 1, "k", issued_at=1_000, signature="dd")
  assert moved is not None and (moved.host, moved.signature) == ("b.example", "dd")
  newer = registry.register("p", "c.example", 3, "k", issued_at=2_000, signature="ee")
  assert newer is not None and (newer.host, newer.port, newer.issued_at) == ("c.example", 3, 2_000)


def test_l1_rotated_key_keeps_the_issued_at_high_water_mark() -> None:
  # L1 / CR-3: an older registration under a rotated validator key at the same address stores
  # the pair as signed, but the staleness bound must not regress with it
  registry = PeerRegistry("me", is_protected=lambda node_id: node_id == "v")
  registry.register("v", "a.example", 1, "old-key", issued_at=1_000, signature="aa")
  rotated = registry.register("v", "a.example", 1, "new-key", issued_at=900, signature="bb")
  assert rotated is not None
  assert (rotated.public_key, rotated.issued_at, rotated.signature) == ("new-key", 900, "bb")
  assert rotated.max_issued_at == 1_000 and rotated.held_issued_at == 1_000
  # a move signed between the published issued_at and the high-water mark is still stale
  with pytest.raises(StaleRegistrationError):
    registry.register("v", "b.example", 1, "new-key", issued_at=950, signature="cc")
  # and a further older rotation-branch registration cannot walk the mark back either
  again = registry.register("v", "a.example", 1, "newer-key", issued_at=800, signature="dd")
  assert again is not None and again.held_issued_at == 1_000
  moved = registry.register("v", "b.example", 1, "newer-key", issued_at=1_000, signature="ee")
  assert moved is not None and (moved.host, moved.held_issued_at) == ("b.example", 1_000)
  later = registry.register("v", "c.example", 1, "newer-key", issued_at=5_000, signature="ff")
  assert later is not None and later.max_issued_at == 5_000  # only ever increases


def test_l1_endpoint_judges_freshness_against_the_high_water_mark(node_env: NodeEnv, boot) -> None:
  from node.api.peers import registration_error

  context = boot(node_env.env)  # MAX_FUTURE_SKEW_MS: the 60 s default
  key = node_env.validator_keys["node2"]
  now = _now()
  # published pair from an older rotation-branch registration, high-water mark much newer
  held = PeerInfo(
    "node2", "a.example", 1, pem_of(key), now, now - 500_000, "aa", max_issued_at=now - 1_000
  )
  body = _body("node2", key, host="b.example", issued_at=now - 200_000)
  fields = ("node_id", "host", "port", "public_key", "issued_at", "signature")
  error = registration_error(context, **{k: body[k] for k in fields}, held=held)
  assert error is not None and (error.status, error.code) == (409, "stale_registration")
  without_mark = PeerInfo("node2", "a.example", 1, pem_of(key), now, now - 500_000, "aa")
  assert registration_error(context, **{k: body[k] for k in fields}, held=without_mark) is None


# --------------------------------------------------- CR2 / CR8: shared patterns, keys


def test_register_request_uses_the_shared_wire_patterns(node_env: NodeEnv, client) -> None:
  base = _body("outsider", generate_node_keypair())
  for bad in (
    {"signature": "ab" * 513},  # longer than SIGNATURE_RE's 512 bytes
    {"signature": "abc"},  # not whole bytes
    {"signature": "AB" * 64},  # not canonical lowercase hex
    {"node_id": "x" * 65},
    {"node_id": "bad id"},
  ):
    response = client.post("/peers/register", json={**base, **bad})
    assert response.status_code == 422 and _code(response) == "validation_error"


def test_gossip_stores_the_validator_set_pem_like_the_endpoint(node_env: NodeEnv, boot) -> None:
  context = boot(node_env.env)
  key = node_env.validator_keys["node2"]
  variant = pem_of(key).replace("\n", "\r\n")  # same key, different text
  body = {"peers": [_body("node2", key, pem=variant)]}
  assert merge_peer_list(context.peers, body, PeerOut, gossip_accept(context)) == 1
  stored = context.peers.get("node2")
  assert stored is not None and stored.public_key == pem_of(key)


# ------------------------------------------------------- 2. key in force now


def test_validator_is_verified_with_the_key_in_force_now() -> None:
  old_key, new_key = generate_node_keypair(), generate_node_keypair()
  rotated_at = _now() - 60_000
  asked: list[int] = []

  def resolve(_node_id: str, at_ms: int):
    asked.append(at_ms)
    return old_key.public_key if at_ms < rotated_at else new_key.public_key

  now = _now()
  # signed by the retired key, with an issued_at chosen before the rotation
  body = _body("node2", old_key, issued_at=rotated_at - 1_000)
  with pytest.raises(RegistrationError) as caught:
    check_registration(
      **{k: body[k] for k in ("node_id", "host", "port", "public_key", "issued_at", "signature")},
      resolve_node_key=resolve,
      now_ms=now,
      max_future_skew_ms=60_000,
      held_issued_at=None,
    )
  assert caught.value.code == "peer_key_mismatch"
  assert asked == [now]  # resolved at now, never at the attacker-chosen issued_at
  fresh = _body("node2", new_key)
  check_registration(
    **{k: fresh[k] for k in ("node_id", "host", "port", "public_key", "issued_at", "signature")},
    resolve_node_key=resolve,
    now_ms=_now(),
    max_future_skew_ms=60_000,
    held_issued_at=None,
  )


def test_check_peer_registration_requires_possession() -> None:
  key = generate_node_keypair()
  body = _body("outsider", key, signer=generate_node_keypair())
  with pytest.raises(RegistrationError) as caught:
    check_peer_registration(
      **{k: body[k] for k in ("node_id", "host", "port", "public_key", "issued_at", "signature")},
      now_ms=_now(),
      max_future_skew_ms=60_000,
      held_issued_at=None,
    )
  assert caught.value.status == 403


# ------------------------------------------------------- 2. normalized PEM


def test_validator_key_is_compared_and_stored_as_normalized_pem(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    key = node_env.validator_keys["node2"]
    variant = pem_of(key).replace("\n", "\r\n")  # same key, different text
    body = _body("node2", key, pem=variant)
    assert client.post("/peers/register", json=body).status_code == 200
    stored = app.state.context.peers.get("node2")
    assert stored is not None and stored.public_key == pem_of(key)


def test_non_validator_key_is_stored_as_normalized_pem(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    key = generate_node_keypair()
    variant = pem_of(key).replace("\n", "\r\n")
    assert (
      client.post("/peers/register", json=_body("outsider", key, pem=variant)).status_code == 200
    )
    stored = app.state.context.peers.get("outsider")
    assert stored is not None and stored.public_key == pem_of(key)
    # the stored (key, signature) pair verifies for whoever receives it by gossip
    check_peer_registration(
      node_id="outsider",
      host=stored.host,
      port=stored.port,
      public_key=stored.public_key,
      issued_at=stored.issued_at,
      signature=stored.signature,
      now_ms=_now(),
      max_future_skew_ms=60_000,
      held_issued_at=None,
    )


# --------------------------------------------- 3. parallel, periodic seeds


def _seed_entry(node_id: str) -> dict[str, Any]:
  return {
    "node_id": node_id,
    "host": node_id,
    "port": 8000,
    "public_key": pem_of(generate_node_keypair()),
    "last_seen": None,
  }


def test_seeds_are_registered_in_parallel_and_periodically() -> None:
  registry = PeerRegistry("me")
  calls: dict[str, int] = {"ghost:1": 0, "good:2": 0}
  payloads: list[dict[str, Any]] = []
  sleeps: list[float] = []
  counter = iter(range(10**6))

  class Transport:
    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
      seed = url.split("//")[1].split("/")[0]
      calls[seed] += 1
      payloads.append(payload)
      if seed == "ghost:1":  # the FIRST seed never answers
        raise ConnectionRefusedError(seed)
      return {"peers": [_seed_entry("seed2")]}

  async def fake_sleep(seconds: float) -> None:
    sleeps.append(seconds)
    await asyncio.sleep(0)

  async def scenario() -> None:
    task = asyncio.create_task(
      register_with_seeds(
        ("ghost:1", "good:2"),
        lambda: {"n": next(counter)},  # refreshable payload
        registry,
        Transport(),
        PeerOut,
        sleep=fake_sleep,
      )
    )
    while calls["good:2"] < 3:
      await asyncio.sleep(0)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

  asyncio.run(scenario())
  assert calls["good:2"] >= 3  # re-registered periodically despite the unreachable first seed
  assert calls["ghost:1"] >= 1
  assert SEED_REFRESH_S in sleeps and SEED_REFRESH_S == 30.0
  assert len({p["n"] for p in payloads}) == len(payloads)  # a fresh payload every attempt
  assert [p.node_id for p in registry.list()] == ["seed2"]


def test_a_static_payload_dict_still_works() -> None:
  registry = PeerRegistry("me")
  seen: list[dict[str, Any]] = []

  class Transport:
    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
      seen.append(payload)
      return {"peers": []}

  async def no_sleep(_: float) -> None:
    return None

  asyncio.run(
    register_with_seeds(
      ("a:1",), {"node_id": "me"}, registry, Transport(), PeerOut, sleep=no_sleep, rounds=3
    )
  )
  assert seen == [{"node_id": "me"}] * 3


def test_seed_registration_runs_until_cancelled() -> None:
  registry = PeerRegistry("me")
  calls = 0
  refreshes: list[float] = []

  class Transport:
    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
      nonlocal calls
      calls += 1
      return {"peers": []}

  async def fake_sleep(seconds: float) -> None:
    refreshes.append(seconds)
    await asyncio.sleep(0)

  async def scenario() -> bool:
    task = asyncio.create_task(
      register_with_seeds(
        ("a:1",), {}, registry, Transport(), PeerOut, sleep=fake_sleep, refresh_s=0.01
      )
    )
    while calls < 5 and not task.done():  # counted rounds, no wall-clock timing
      await asyncio.sleep(0)
    finished = task.done()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return finished

  assert asyncio.run(scenario()) is False
  assert calls >= 5 and refreshes[:4] == [0.01] * 4  # still re-registering after 5 rounds


def test_seed_loop_verifies_gossip_off_the_event_loop(node_env: NodeEnv, boot) -> None:
  context = boot(node_env.env)
  threads: list[int] = []
  check = gossip_accept(context)

  def accept(entry: PeerOut, held: PeerInfo | None) -> str | None:
    threads.append(threading.get_ident())
    return check(entry, held)

  class Transport:
    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
      return {"peers": [_body("good", generate_node_keypair())]}

  async def scenario() -> int:
    await register_with_seeds(
      ("a:1",), {}, context.peers, Transport(), PeerOut, accept=accept, rounds=1
    )
    return threading.get_ident()

  loop_thread = asyncio.run(scenario())
  assert threads and loop_thread not in threads  # verified in a worker thread
  assert [p.node_id for p in context.peers.list()] == ["good"]  # applied on the loop


def test_l3_seed_work_runs_on_the_dedicated_executor_not_the_default_one() -> None:
  # L3: the netguard invariant - nothing here may queue on the shared default executor
  names: list[str] = []

  def accept(entry: PeerOut, _held: PeerInfo | None) -> str | None:
    names.append(threading.current_thread().name)
    return pem_of(generate_node_keypair())

  class Transport:
    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
      return {"peers": [_seed_entry("p1")]}

  from concurrent.futures import ThreadPoolExecutor

  default_used: list[object] = []

  class RecordingDefault(ThreadPoolExecutor):
    def submit(self, fn, /, *args, **kwargs):  # type: ignore[override]
      default_used.append(fn)
      return super().submit(fn, *args, **kwargs)

  async def scenario() -> None:
    asyncio.get_running_loop().set_default_executor(RecordingDefault(1))
    await register_with_seeds(
      ("a:1",), {}, PeerRegistry("me"), Transport(), PeerOut, accept=accept, rounds=1
    )

  asyncio.run(scenario())
  assert names and all(name.startswith("seed-peers") for name in names)
  assert default_used == []  # the shared default executor was never used


def test_l3_urllib_transport_uses_the_dedicated_executor(monkeypatch) -> None:
  import node.peers.seed_registration as seed_module

  seen: list[str] = []

  def fake_call(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    seen.append(threading.current_thread().name)
    return {"peers": []}

  monkeypatch.setattr(seed_module.UrllibTransport, "_call", fake_call)
  asyncio.run(UrllibTransport().post_json("http://x:1/peers/register", {}))
  assert seen and seen[0].startswith("seed-peers")
  assert seed_module.SEED_WORKERS == 2


def test_l2_validator_entry_skipped_when_its_key_rotated_after_vetting(
  node_env: NodeEnv, boot
) -> None:
  # L2: `_vet` runs off the loop against a snapshot; the key may rotate before `_apply`
  from node.api.peers import validator_key_now

  context = boot(node_env.env)
  key = node_env.validator_keys["node3"]
  body = {"peers": [_body("node3", key, host="a.example"), _body("good", generate_node_keypair())]}
  rotated_to = pem_of(generate_node_keypair())
  merged = merge_peer_list(
    context.peers, body, PeerOut, gossip_accept(context), key_now=lambda _node_id: rotated_to
  )
  assert merged == 1 and context.peers.get("node3") is None  # the stale vetting is dropped
  assert context.peers.get("good") is not None  # non-validators are not re-checked
  # with the key still in force, the validator entry is registered
  assert (
    merge_peer_list(
      context.peers, body, PeerOut, gossip_accept(context), key_now=validator_key_now(context)
    )
    == 2
  )
  held = context.peers.get("node3")
  assert held is not None and held.public_key == pem_of(key)


def test_l2_key_now_is_wired_through_the_seed_loop(node_env: NodeEnv, boot) -> None:
  context = boot(node_env.env)
  key = node_env.validator_keys["node3"]
  asked: list[str] = []

  def key_now(node_id: str) -> str | None:
    asked.append(node_id)
    return None  # e.g. revoked meanwhile: no key in force

  class Transport:
    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
      return {"peers": [_body("node3", key, host="a.example")]}

  asyncio.run(
    register_with_seeds(
      ("a:1",),
      {},
      context.peers,
      Transport(),
      PeerOut,
      accept=gossip_accept(context),
      key_now=key_now,
      rounds=1,
    )
  )
  assert asked == ["node3"] and context.peers.get("node3") is None


# ------------------------------------------------- 3. bounded transport


class _Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self, *args: Any) -> None:
    return None

  def do_POST(self) -> None:  # noqa: N802
    length = int(self.headers.get("Content-Length", "0"))
    self.rfile.read(length)
    if self.path == "/redirect/peers/register":
      self.send_response(307)
      self.send_header("Location", "http://example.invalid/peers/register")
      self.send_header("Content-Length", "0")
      self.end_headers()
      return
    if self.path == "/big/peers/register":
      payload = b'{"peers": "' + b"x" * (2 * 1024 * 1024) + b'"}'
    elif self.path == "/list/peers/register":
      payload = b"[1, 2]"
    else:
      payload = json.dumps({"peers": []}).encode()
    self.send_response(200)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(payload)))
    self.end_headers()
    try:
      self.wfile.write(payload)
    except OSError:
      pass  # the client gave up at the size cap


@pytest.fixture
def http_seed() -> Iterator[str]:
  server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
  thread = threading.Thread(target=server.serve_forever, daemon=True)
  thread.start()
  try:
    yield f"http://127.0.0.1:{server.server_address[1]}"
  finally:
    server.shutdown()
    server.server_close()


def test_transport_does_not_follow_redirects(http_seed: str) -> None:
  import urllib.error

  with pytest.raises(urllib.error.HTTPError):
    asyncio.run(UrllibTransport().post_json(f"{http_seed}/redirect/peers/register", {}))


def test_transport_caps_the_response_size(http_seed: str) -> None:
  with pytest.raises(SeedResponseError):
    asyncio.run(UrllibTransport().post_json(f"{http_seed}/big/peers/register", {}))


def test_transport_rejects_non_object_bodies_and_accepts_objects(http_seed: str) -> None:
  with pytest.raises(SeedResponseError):
    asyncio.run(UrllibTransport().post_json(f"{http_seed}/list/peers/register", {}))
  assert asyncio.run(UrllibTransport().post_json(f"{http_seed}/ok/peers/register", {})) == {
    "peers": []
  }


def test_transport_has_a_timeout() -> None:
  import socket

  listener = socket.socket()
  listener.bind(("127.0.0.1", 0))
  listener.listen(1)  # accepts the connection but never answers
  port = listener.getsockname()[1]
  try:
    started = time.monotonic()
    with pytest.raises(OSError):  # socket.timeout / TimeoutError are OSError subclasses
      asyncio.run(UrllibTransport(timeout=0.3).post_json(f"http://127.0.0.1:{port}/x", {}))
    assert time.monotonic() - started < 5
  finally:
    listener.close()


# --------------------------------------------------------- 4. pagination


def test_get_peers_is_paginated(client: TestClient) -> None:
  for i in range(5):
    body = _body(f"p{i}", generate_node_keypair(), port=9100 + i)
    assert client.post("/peers/register", json=body).status_code == 200
  page = client.get("/peers", params={"limit": 2, "offset": 1}).json()["peers"]
  assert [p["node_id"] for p in page] == ["p1", "p2"]
  assert [p["node_id"] for p in client.get("/peers?offset=4").json()["peers"]] == ["p4"]
  assert client.get("/peers?offset=10").json() == {"peers": []}
  for query in ("limit=0", f"limit={MAX_PEERS_PAGE + 1}", "offset=-1", "limit=abc"):
    response = client.get(f"/peers?{query}")
    assert response.status_code == 422 and _code(response) == "validation_error"


def test_register_reply_is_bounded(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    registry = app.state.context.peers
    for i in range(MAX_PEERS_PAGE + 20):
      registry.register(f"x{i}", "h.example", 9000, f"k{i}")
    reply = client.post("/peers/register", json=_body("newcomer", generate_node_keypair()))
    assert reply.status_code == 200
    peers = reply.json()["peers"]
    assert len(peers) <= MAX_PEERS_PAGE and peers[0]["node_id"] == "node1"
    assert len(client.get("/peers").json()["peers"]) <= MAX_PEERS_PAGE


# ------------------------------------------------------------- 5. config


@pytest.mark.parametrize("host", [None, "localhost", "127.0.0.1", "node.localhost"])
def test_localhost_node_host_with_seeds_fails(node_env: NodeEnv, host: str | None) -> None:
  env = {**node_env.env, "SEED_PEERS": "seed.example:8000"}
  if host is not None:
    env["NODE_HOST"] = host
  with pytest.raises(ConfigError, match="localhost"):
    load_config(env)


def test_localhost_node_host_is_fine_without_seeds_or_with_allow_loopback(
  node_env: NodeEnv,
) -> None:
  assert load_config({**node_env.env, "NODE_HOST": "localhost"}).node_host == "localhost"
  env = {**node_env.env, "SEED_PEERS": "a:1", "ALLOW_LOOPBACK_PEERS": "1"}
  config = load_config(env)
  assert config.allow_loopback_peers is True and config.node_host == "localhost"
  reachable = {**node_env.env, "SEED_PEERS": "a:1", "NODE_HOST": "node1"}
  assert load_config(reachable).seed_peers == ("a:1",)


def test_max_page_size_has_an_upper_bound(node_env: NodeEnv) -> None:
  assert load_config({**node_env.env, "MAX_PAGE_SIZE": "1000"}).max_page_size == 1000
  with pytest.raises(ConfigError, match="MAX_PAGE_SIZE"):
    load_config({**node_env.env, "MAX_PAGE_SIZE": "1001"})
