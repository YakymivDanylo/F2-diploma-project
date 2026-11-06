from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

from fastapi.testclient import TestClient
from node_helpers import NodeEnv, pem_of

from blockchain_core import generate_node_keypair
from node.api.peers import PeerOut
from node.config import load_config
from node.main import NodeContext, create_app
from node.peers.registry import PeerRegistry
from node.peers.seed_registration import register_with_seeds


def _serve(env: dict[str, str], **kwargs: Any) -> Iterator[tuple[TestClient, NodeContext]]:
  app = create_app(load_config(env), **kwargs)
  with TestClient(app) as client:
    yield client, app.state.context


def _payload(node_id: str = "peerA", host: str = "10.0.0.5", port: int = 9001, pem=None):
  return {
    "node_id": node_id,
    "host": host,
    "port": port,
    "public_key": pem or pem_of(generate_node_keypair()),
  }


def test_register_and_list(node_env: NodeEnv) -> None:  # CN-TC-1.1 / 2.1
  for client, _ in _serve(node_env.env):
    body = _payload()
    response = client.post("/peers/register", json=body)
    assert response.status_code == 200
    ids = [p["node_id"] for p in response.json()["peers"]]
    assert ids == ["node1"]  # the receiver itself, so the registrant learns it
    listed = client.get("/peers").json()["peers"]
    assert [p["node_id"] for p in listed] == ["peerA"]
    assert listed[0]["last_seen"] > 0


def test_response_contains_other_known_peers(node_env: NodeEnv) -> None:  # CN-TC-1.1 (merge)
  for client, _ in _serve(node_env.env):
    client.post("/peers/register", json=_payload("peerA"))
    response = client.post("/peers/register", json=_payload("peerB", port=9002))
    ids = {p["node_id"] for p in response.json()["peers"]}
    assert ids == {"node1", "peerA"}


def test_fresh_node_lists_empty(node_env: NodeEnv) -> None:  # CN-TC-2.2
  for client, _ in _serve(node_env.env):
    response = client.get("/peers")
    assert response.status_code == 200
    assert response.json() == {"peers": []}


def test_reregistration_updates_without_duplicate(node_env: NodeEnv) -> None:  # CN-TC-1.8
  for client, context in _serve(node_env.env):
    pem = pem_of(generate_node_keypair())
    client.post("/peers/register", json=_payload(pem=pem))
    first = client.get("/peers").json()["peers"][0]["last_seen"]
    client.post("/peers/register", json=_payload(host="10.0.0.9", port=9100, pem=pem))
    peers = client.get("/peers").json()["peers"]
    assert len(peers) == 1
    assert (peers[0]["host"], peers[0]["port"]) == ("10.0.0.9", 9100)
    assert peers[0]["last_seen"] >= first
    assert len(context.peers) == 1


def test_key_change_for_known_id_is_rejected(node_env: NodeEnv) -> None:
  for client, _ in _serve(node_env.env):
    client.post("/peers/register", json=_payload())
    response = client.post("/peers/register", json=_payload(host="evil.example"))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "peer_key_mismatch"
    assert client.get("/peers").json()["peers"][0]["host"] == "10.0.0.5"


def test_malformed_payloads_use_envelope(node_env: NodeEnv) -> None:  # CN-TC-1.9
  for client, _ in _serve(node_env.env):
    good = _payload()
    cases = [
      {k: v for k, v in good.items() if k != "public_key"},
      {k: v for k, v in good.items() if k != "host"},
      {**good, "public_key": "not a pem"},
      {**good, "port": 0},
      {**good, "port": 70000},
      {**good, "host": "bad host!"},
      {**good, "node_id": ""},
      {**good, "public_key": "x" * 5000},
    ]
    for case in cases:
      response = client.post("/peers/register", json=case)
      assert response.status_code == 422, case
      assert response.json()["error"]["code"] == "validation_error"
    assert client.get("/peers").json() == {"peers": []}


def test_self_registration_is_ignored(node_env: NodeEnv) -> None:  # CN-TC-1.10
  for client, _ in _serve(node_env.env):
    response = client.post("/peers/register", json=_payload("node1"))
    assert response.status_code == 200
    assert client.get("/peers").json() == {"peers": []}


def test_flood_does_not_change_quorum_values(node_env: NodeEnv) -> None:  # CN-TC-1.11
  for client, context in _serve(node_env.env):
    before = client.get("/node/info").json()
    pem = pem_of(generate_node_keypair())
    for i in range(2000):
      assert client.post("/peers/register", json=_payload(f"sybil{i}", pem=pem)).status_code == 200
    assert len(context.peers) == 2000
    after = client.get("/node/info").json()
    assert (after["n"], after["f"]) == (before["n"], before["f"]) == (4, 1)
    assert after["quorum_status"] == before["quorum_status"]
    assert context.validators.n == 4
    assert all(p["node_id"].startswith("sybil") for p in client.get("/peers").json()["peers"])


class _FakeTransport:
  def __init__(self, failures: int, body: dict[str, Any]) -> None:
    self.failures = failures
    self.body = body
    self.calls: list[str] = []

  async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    self.calls.append(url)
    if len(self.calls) <= self.failures:
      raise ConnectionRefusedError("seed not up yet")
    return self.body


def _own_peer(pem: str) -> dict[str, Any]:
  return {"node_id": "seed1", "host": "seed1", "port": 8000, "public_key": pem, "last_seen": None}


def test_unreachable_seed_is_retried_with_backoff() -> None:  # CN-TC-1.7
  registry = PeerRegistry("me")
  pem = pem_of(generate_node_keypair())
  transport = _FakeTransport(3, {"peers": [_own_peer(pem)]})
  delays: list[float] = []

  async def fake_sleep(seconds: float) -> None:
    delays.append(seconds)

  asyncio.run(
    register_with_seeds(
      ("seed1:8000",), {}, registry, transport, PeerOut, sleep=fake_sleep, max_delay=3.0
    )
  )
  assert len(transport.calls) == 4
  assert delays == [1.0, 2.0, 3.0]  # exponential, capped
  assert [p.node_id for p in registry.list()] == ["seed1"]


def test_multiple_seeds_registered_sequentially_and_merged() -> None:  # CN-TC-1.2
  registry = PeerRegistry("me")
  bodies = {
    "a:1": {"peers": [_own_peer(pem_of(generate_node_keypair()))]},
    "b:2": {
      "peers": [
        {**_own_peer(pem_of(generate_node_keypair())), "node_id": "seed2"},
        {"node_id": "me", "host": "x", "port": 1, "public_key": "junk"},  # skipped
      ]
    },
  }

  class Transport:
    order: list[str] = []

    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
      seed = url.split("//")[1].split("/")[0]
      self.order.append(seed)
      return bodies[seed]

  transport = Transport()
  asyncio.run(register_with_seeds(("a:1", "b:2"), {}, registry, transport, PeerOut))
  assert transport.order == ["a:1", "b:2"]
  assert {p.node_id for p in registry.list()} == {"seed1", "seed2"}


def test_unreachable_seed_does_not_block_startup(node_env: NodeEnv) -> None:  # CN-TC-1.7
  env = {**node_env.env, "SEED_PEERS": "ghost:9"}
  transport = _FakeTransport(10**9, {})

  async def instant_sleep(_: float) -> None:
    await asyncio.sleep(0)

  for client, _ in _serve(env, peer_transport=transport, sleep=instant_sleep):
    assert client.get("/node/info").status_code == 200
    assert client.get("/peers").json() == {"peers": []}


def test_validator_set_is_not_reachable_from_peer_registry() -> None:  # structural separation
  import node.peers.registry as module

  source = open(module.__file__, encoding="utf-8").read()
  assert "node.registries" not in source.split('"""', 2)[2]  # no import of the ValidatorSet
