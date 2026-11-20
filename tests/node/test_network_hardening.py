"""Security-review follow-ups for Slice 15: registry abuse, handshake limits, log floods."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient
from network_helpers import Cluster, make_pair, until
from node_helpers import NodeEnv, pem_of

from blockchain_core import generate_node_keypair
from blockchain_core.keys import NodeKeyPair
from node.config import load_config
from node.main import create_app
from node.network.connection_manager import (
  MAX_CONCURRENT_HANDSHAKES,
  UNAUTHENTICATED_KEY,
  PeerConnectionManager,
)
from node.network.ws_blocks import MAX_SYNC_HINTS
from node.peers.attestation import sign_registration
from node.peers.registry import PeerRegistry, PeerRegistryFullError


def run(coro: Any) -> Any:
  return asyncio.run(coro)


def _register(client: TestClient, node_id: str, pem: str, port: int = 9100):
  body = {"node_id": node_id, "host": "somewhere.example", "port": port, "public_key": pem}
  return client.post("/peers/register", json=body)


def _register_signed(client: TestClient, node_id: str, key: NodeKeyPair, port: int = 9100):
  """A non-validator registration with proof of possession of `key`."""
  pem = pem_of(key)
  issued_at = int(time.time() * 1000)
  body = {
    "node_id": node_id,
    "host": "somewhere.example",
    "port": port,
    "public_key": pem,
    "issued_at": issued_at,
    "signature": sign_registration(
      key.private_key, node_id, "somewhere.example", port, pem, issued_at
    ),
  }
  return client.post("/peers/register", json=body)


def _app(node_env: NodeEnv):
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"}
  return create_app(load_config(env), mine=False)


# ------------------------------------------------------------ registry abuse


def test_a_validator_id_cannot_be_registered_with_a_foreign_key(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    squatter = pem_of(generate_node_keypair())
    response = _register(client, "node2", squatter)  # node2 is a ValidatorSet member
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "peer_key_mismatch"
    assert client.get("/peers").json()["peers"] == []  # nothing was stored
    genuine = pem_of(node_env.validator_keys["node2"])
    issued_at = int(time.time() * 1000)
    signature = sign_registration(
      node_env.validator_keys["node2"].private_key,
      "node2",
      "somewhere.example",
      9100,
      genuine,
      issued_at,
    )
    signed = {
      "node_id": "node2",
      "host": "somewhere.example",
      "port": 9100,
      "public_key": genuine,
      "issued_at": issued_at,
      "signature": signature,
    }
    assert client.post("/peers/register", json=signed).status_code == 200  # the real node can
    assert [p["node_id"] for p in client.get("/peers").json()["peers"]] == ["node2"]


def test_non_validator_ids_still_register_freely(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    assert _register_signed(client, "newcomer", generate_node_keypair()).status_code == 200


def test_validator_ids_are_never_answered_from_peerinfo(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app):
    resolver = app.state.context.resolvers.current
    assert resolver.known_node_ids == {"node1", "node2", "node3", "node4"}


def test_registry_cap(node_env: NodeEnv) -> None:
  # full of protected (ValidatorSet) entries: a new id is refused
  registry = PeerRegistry("me", max_peers=2, is_protected=lambda node_id: node_id in {"a", "b"})
  registry.register("a", "h", 1, "k")
  registry.register("b", "h", 2, "k")
  with pytest.raises(PeerRegistryFullError):
    registry.register("c", "h", 3, "k")
  assert registry.register("a", "h2", 9, "k") is not None  # refreshing a known peer still works
  assert len(registry) == 2


def test_registry_full_is_503_over_http(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    peers = app.state.context.peers
    peers._max_peers = 1
    peers._is_protected = lambda node_id: node_id == "p1"
    assert _register_signed(client, "p1", generate_node_keypair()).status_code == 200
    full = _register_signed(client, "p2", generate_node_keypair())
    assert full.status_code == 503 and full.json()["error"]["code"] == "peer_registry_full"


# --------------------------------------------------------- handshake limits


def test_unauthenticated_connections_are_capped(node_env: NodeEnv) -> None:
  async def go():
    async with Cluster(
      node_env, ids=("node1", "node2"), register_peers=False, options={"handshake_timeout": 1.0}
    ) as c:
      manager: PeerConnectionManager = c["node1"].manager
      silent = [make_pair() for _ in range(MAX_CONCURRENT_HANDSHAKES)]  # connect, never speak
      tasks = [asyncio.create_task(manager.accept_inbound(server)) for _, server in silent]
      await until(lambda: manager.handshakes_in_progress == MAX_CONCURRENT_HANDSHAKES)
      _, extra = make_pair()
      await manager.accept_inbound(extra)  # over the cap: closed at once, no handshake work
      assert extra.closed and extra.close_code == 1013 and extra.sent == []
      for _, server in silent:
        await server.close()
      await asyncio.gather(*tasks)
      assert manager.handshakes_in_progress == 0  # the slots are released afterwards

  run(go())


def test_the_handshake_cap_is_8() -> None:
  # each unauthenticated socket can push one ws_max_size frame before our size check
  assert MAX_CONCURRENT_HANDSHAKES == 8


def test_the_service_counter_cannot_be_spoofed() -> None:
  # a peer cannot register or authenticate under the counter's name
  from node.patterns import NODE_ID_RE

  assert not NODE_ID_RE.fullmatch(UNAUTHENTICATED_KEY)


# ------------------------------------------------------------- bounded state


def test_sync_hints_are_deduplicated_and_bounded(node_env: NodeEnv) -> None:
  from chain_factory import pow_block

  from blockchain_core.storage.chain_store import block_to_dict

  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      n2 = cluster["node2"]
      genesis = n2.context.current_blocks()[0]
      ahead = pow_block(node_env, pow_block(node_env, genesis, 1), 2)
      for _ in range(500):  # a replayed, genuinely signed, future block
        await n2.receiver.handle_block("node1", block_to_dict(ahead))
      assert n2.receiver.needs_sync == ["node1"]
      for i in range(200):
        await n2.receiver.handle_block(f"peer{i}", block_to_dict(ahead))
      assert len(n2.receiver.needs_sync) <= MAX_SYNC_HINTS

  run(go())


def test_flag_logging_is_throttled(node_env: NodeEnv, caplog) -> None:
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      manager = cluster["node2"].manager
      with caplog.at_level(logging.WARNING, logger="node.network"):
        for _ in range(250):
          manager.flag("node1", "malformed_message")
      assert manager.flags["node1"] == 250  # every offence is counted ...
      assert caplog.text.count("flagged peer") <= 8  # ... but not every one is logged

  run(go())


def test_outbound_dials_are_capped_and_validators_come_first(node_env: NodeEnv) -> None:
  dialed: set[str] = set()

  class Refusing:
    async def connect(self, host: str, port: int, path: str):
      dialed.add(host)
      raise ConnectionRefusedError

  async def never(peer_id: str, message: dict) -> None:
    return None

  async def quick(seconds: float) -> None:
    await asyncio.sleep(0.001)

  sybils = [(f"sybil{i}", f"sybil{i}", 9000) for i in range(300)]
  manager = PeerConnectionManager(
    self_id="node1",
    node_key=node_env.node_key.private_key,
    lookup_key=lambda _: None,
    peer_addresses=lambda: [*sybils, ("node2", "node2", 9000)],  # the validator registered last
    known_ids=lambda: {"node2", "node3"},
    connector=Refusing(),
    on_message=never,
    sleep=quick,
    max_dialed=5,
  )

  async def go():
    manager._scan()  # noqa: SLF001 - one deterministic scan instead of waiting for the loop
    for _ in range(5):
      await asyncio.sleep(0)  # every started dial loop makes its first attempt
    await manager.stop()

  run(go())
  # at most max_dialed non-validators; a validator never counts toward the cap and is always
  # dialed, however many Sybils registered before it
  assert len(dialed - {"node2"}) == 5 and "node2" in dialed
  assert len(manager.health()) <= 5 + 2  # dialed peers plus the known validators
