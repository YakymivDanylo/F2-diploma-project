"""H4: signed peer registration of ValidatorSet identities (no address hijack by key replay)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient
from node_helpers import NodeEnv, pem_of

from blockchain_core import generate_node_keypair, save_key_pair
from node.api.peers import PeerOut, registration_error
from node.config import load_config
from node.context import NodeContext
from node.main import create_app
from node.peers.attestation import check_registration, sign_registration
from node.peers.registry import PeerInfo, PeerRegistry
from node.peers.seed_registration import merge_peer_list, register_with_seeds

HOST_A = "host-a.example"
HOST_B = "host-b.example"


def _app(node_env: NodeEnv):
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"}
  return create_app(load_config(env), mine=False)


def _now() -> int:
  return int(time.time() * 1000)


def _signed(
  node_env: NodeEnv,
  node_id: str = "node2",
  host: str = HOST_A,
  port: int = 9100,
  issued_at: int | None = None,
  signer: str | None = None,
) -> dict[str, Any]:
  """A registration body for `node_id`, signed by `signer` (default: the node itself)."""
  issued_at = _now() - 1000 if issued_at is None else issued_at
  pem = pem_of(node_env.validator_keys[node_id])
  key = node_env.validator_keys[signer or node_id]
  return {
    "node_id": node_id,
    "host": host,
    "port": port,
    "public_key": pem,
    "issued_at": issued_at,
    "signature": sign_registration(key.private_key, node_id, host, port, pem, issued_at),
  }


def _unsigned(node_env: NodeEnv, host: str = HOST_B, port: int = 9100) -> dict[str, Any]:
  return {
    "node_id": "node2",
    "host": host,
    "port": port,
    "public_key": pem_of(node_env.validator_keys["node2"]),
  }


def _peers(client: TestClient) -> dict[str, dict[str, Any]]:
  return {p["node_id"]: p for p in client.get("/peers").json()["peers"]}


def _code(response) -> str:
  return response.json()["error"]["code"]


# --------------------------------------------------------- 1. missing / bad signature


def test_h4_genuine_key_without_signature_is_refused(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env)) as client:
    response = client.post("/peers/register", json=_unsigned(node_env))
    assert response.status_code == 403
    assert _code(response) == "registration_unauthenticated"
    assert _peers(client) == {}


def test_h4_signature_by_a_different_key_is_refused(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env)) as client:
    body = _signed(node_env, signer="node3")
    response = client.post("/peers/register", json=body)
    assert response.status_code == 403
    assert _code(response) == "registration_unauthenticated"
    assert _peers(client) == {}


def test_h4_signature_over_another_host_or_port_is_refused(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env)) as client:
    genuine = _signed(node_env, host=HOST_A)
    for tampered in ({**genuine, "host": HOST_B}, {**genuine, "port": 9101}):
      response = client.post("/peers/register", json=tampered)
      assert response.status_code == 403
      assert _code(response) == "registration_unauthenticated"
    assert _peers(client) == {}


def test_h4_signature_without_issued_at_is_refused(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env)) as client:
    body = _signed(node_env)
    del body["issued_at"]
    response = client.post("/peers/register", json=body)
    assert response.status_code == 403
    assert _peers(client) == {}


# ---------------------------------------------------------------- 2. valid signed


def test_h4_valid_signed_registration_is_stored_with_proof(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    body = _signed(node_env)
    response = client.post("/peers/register", json=body)
    assert response.status_code == 200
    stored = _peers(client)["node2"]
    assert stored["host"] == HOST_A
    assert stored["issued_at"] == body["issued_at"]
    assert stored["signature"] == body["signature"]
    held = app.state.context.peers.get("node2")
    assert held is not None and held.issued_at == body["issued_at"]


# ------------------------------------------------------------------- 3. hijack demo


def test_h4_hijack_with_public_key_only_is_rejected(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env)) as client:
    assert client.post("/peers/register", json=_signed(node_env, host=HOST_A)).status_code == 200
    attack = client.post("/peers/register", json=_unsigned(node_env, host=HOST_B))
    assert attack.status_code == 403
    assert _peers(client)["node2"]["host"] == HOST_A


def test_h4_hijack_by_replaying_a_signature_with_a_new_host_is_rejected(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env)) as client:
    genuine = _signed(node_env, host=HOST_A)
    assert client.post("/peers/register", json=genuine).status_code == 200
    replay = {**genuine, "host": HOST_B}  # old signature, attacker's host
    assert client.post("/peers/register", json=replay).status_code == 403
    assert _peers(client)["node2"]["host"] == HOST_A
    assert _peers(client)["node2"]["signature"] == genuine["signature"]


# ----------------------------------------------------- 4. move, replay, retry


def test_h4_legit_move_then_old_replay_is_stale_and_retry_is_idempotent(
  node_env: NodeEnv,
) -> None:
  now = _now()
  old = _signed(node_env, host=HOST_A, issued_at=now - 300_000)  # beyond the 60 s skew
  new = _signed(node_env, host=HOST_B, issued_at=now - 5_000)
  with TestClient(_app(node_env)) as client:
    assert client.post("/peers/register", json=old).status_code == 200
    assert client.post("/peers/register", json=new).status_code == 200
    assert _peers(client)["node2"]["host"] == HOST_B
    stale = client.post("/peers/register", json=old)  # genuinely signed, but older
    assert stale.status_code == 409
    assert _code(stale) == "stale_registration"
    assert _peers(client)["node2"]["host"] == HOST_B
    assert client.post("/peers/register", json=new).status_code == 200  # same issued_at: retry
    assert _peers(client)["node2"]["host"] == HOST_B


# ----------------------------------------------------------- 5. future issued_at


def test_h4_issued_at_beyond_the_skew_is_refused(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    skew = app.state.context.config.max_future_skew_ms
    far = _signed(node_env, issued_at=_now() + skew + 60_000)
    response = client.post("/peers/register", json=far)
    assert response.status_code == 403
    assert _code(response) == "registration_unauthenticated"
    assert _peers(client) == {}
    near = _signed(node_env, issued_at=_now() + skew // 2)  # within tolerance
    assert client.post("/peers/register", json=near).status_code == 200


# ------------------------------------------------------------- 6. key mismatch


def test_h4_wrong_key_for_a_validator_id_is_still_a_409(node_env: NodeEnv) -> None:
  with TestClient(_app(node_env)) as client:
    foreign = generate_node_keypair()
    pem = pem_of(foreign)
    issued_at = _now() - 1000
    body = {
      "node_id": "node2",
      "host": HOST_A,
      "port": 9100,
      "public_key": pem,
      "issued_at": issued_at,
      "signature": sign_registration(foreign.private_key, "node2", HOST_A, 9100, pem, issued_at),
    }
    response = client.post("/peers/register", json=body)
    assert response.status_code == 409
    assert _code(response) == "peer_key_mismatch"
    assert _peers(client) == {}


# ---------------------------------------------------------- 7. non-validators


def _outsider(node_id: str, host: str, port: int) -> dict[str, Any]:
  """A non-validator registration with proof of possession of a fresh key."""
  key = generate_node_keypair()
  pem = pem_of(key)
  issued_at = _now() - 1000
  return {
    "node_id": node_id,
    "host": host,
    "port": port,
    "public_key": pem,
    "issued_at": issued_at,
    "signature": sign_registration(key.private_key, node_id, host, port, pem, issued_at),
  }


def test_h4_non_validator_ids_register_with_proof_of_possession_and_do_not_change_n_f(
  node_env: NodeEnv,
) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    before = app.state.context.resolvers.current.known_node_ids
    for i in range(5):
      body = _outsider(f"newcomer{i}", f"n{i}.example", 9200 + i)
      assert client.post("/peers/register", json=body).status_code == 200
    unsigned = _outsider("nosig", "x.example", 9300)
    del unsigned["signature"], unsigned["issued_at"]
    response = client.post("/peers/register", json=unsigned)
    assert response.status_code == 403 and _code(response) == "registration_unauthenticated"
    peers = _peers(client)
    assert len(peers) == 5 and peers["newcomer0"]["signature"]
    after = app.state.context.resolvers.current
    assert after.known_node_ids == before == {"node1", "node2", "node3", "node4"}
    assert after.active_node_ids == before


# --------------------------------------------------- 8. node's own signed entry


def test_h4_register_response_carries_the_nodes_own_signed_entry(node_env: NodeEnv) -> None:
  app = _app(node_env)
  with TestClient(app) as client:
    response = client.post("/peers/register", json=_signed(node_env))
    own = response.json()["peers"][0]
    config = app.state.context.config
    assert own["node_id"] == "node1"
    assert own["host"] == config.node_host and own["port"] == config.node_port
    assert isinstance(own["issued_at"], int) and own["signature"]
    check_registration(
      node_id=own["node_id"],
      host=own["host"],
      port=own["port"],
      public_key=own["public_key"],
      issued_at=own["issued_at"],
      signature=own["signature"],
      resolve_node_key=lambda _id, _at: node_env.node_key.public_key,
      now_ms=_now(),
      max_future_skew_ms=config.max_future_skew_ms,
      held_issued_at=None,
    )


# ------------------------------------------------------------------ 9. gossip


def _accept_for(context: NodeContext) -> Callable[[PeerOut, PeerInfo | None], str | None]:
  def accept(entry: PeerOut, held: PeerInfo | None) -> str | None:  # like gossip_accept
    error = registration_error(
      context,
      node_id=entry.node_id,
      host=entry.host,
      port=entry.port,
      public_key=entry.public_key,
      issued_at=entry.issued_at,
      signature=entry.signature,
      held=held,
    )
    return None if error is not None else entry.public_key

  return accept


def _gossip_body(node_env: NodeEnv) -> dict[str, Any]:
  return {
    "peers": [
      _unsigned(node_env, host=HOST_B),  # forged: genuine key, no signature
      {**_signed(node_env, node_id="node3", host=HOST_A), "host": HOST_B},  # signature mismatch
      _signed(node_env, node_id="node4", host=HOST_A),  # genuine
      _outsider("outsider", "o.example", 9300),  # non-validator with proof of possession
      {  # non-validator without proof of possession: dropped
        "node_id": "unsigned-outsider",
        "host": "u.example",
        "port": 9301,
        "public_key": pem_of(generate_node_keypair()),
      },
    ]
  }


def test_h4_gossip_drops_unsigned_entries_but_keeps_signed_validators_and_outsiders(
  node_env: NodeEnv, boot
) -> None:
  context = boot(node_env.env)
  merged = merge_peer_list(context.peers, _gossip_body(node_env), PeerOut, _accept_for(context))
  assert merged == 2
  ids = {p.node_id for p in context.peers.list()}
  assert ids == {"node4", "outsider"}
  node4 = context.peers.get("node4")
  assert node4 is not None and node4.signature and node4.host == HOST_A


def test_h4_gossip_cannot_replace_a_held_address_with_an_older_registration(
  node_env: NodeEnv, boot
) -> None:
  context = boot(node_env.env)
  accept = _accept_for(context)
  now = _now()
  newer = _signed(node_env, host=HOST_B, issued_at=now - 1000)
  older = _signed(node_env, host=HOST_A, issued_at=now - 300_000)  # beyond the 60 s skew
  assert merge_peer_list(context.peers, {"peers": [newer]}, PeerOut, accept) == 1
  assert merge_peer_list(context.peers, {"peers": [older]}, PeerOut, accept) == 0
  held = context.peers.get("node2")
  assert held is not None and held.host == HOST_B


def test_h4_register_with_seeds_passes_accept_through(node_env: NodeEnv, boot) -> None:
  context = boot(node_env.env)
  body = _gossip_body(node_env)
  posted: list[tuple[str, dict[str, Any]]] = []

  class FakeTransport:
    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
      posted.append((url, payload))
      return body

  registry = PeerRegistry("node1")
  asyncio.run(
    register_with_seeds(
      ("seed.example:8000",),
      {"node_id": "node1"},
      registry,
      FakeTransport(),
      PeerOut,
      accept=_accept_for(context),
      rounds=1,
    )
  )
  assert posted[0][0] == "http://seed.example:8000/peers/register"
  assert {p.node_id for p in registry.list()} == {"node4", "outsider"}


# ------------------------------------------------------- 10. end-to-end seed flow


def test_h4_seed_registration_payload_from_main_is_accepted_by_the_seed(
  node_env: NodeEnv, tmp_path
) -> None:
  node2_key = node_env.validator_keys["node2"]
  save_key_pair(node2_key, tmp_path / "keys" / "node2.pem")
  env2 = {
    **node_env.env,
    "NODE_ID": "node2",
    "NODE_HOST": "node2.example",
    "NODE_PORT": "8002",
    "NODE_KEY_PATH": str(tmp_path / "keys" / "node2.pem"),
    "CHAIN_PATH": str(tmp_path / "chain2.json"),
    "SEED_PEERS": "node1.example:8001",
    "STARTUP_SYNC_TIMEOUT_S": "0",
    "CONSENSUS_MODE": "pow",
    "EXPECTED_DIFFICULTY": "1",
  }
  app1 = _app(node_env)
  with TestClient(app1) as seed:
    seen: list[dict[str, Any]] = []

    class ForwardToSeed:
      async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        seen.append(payload)
        response = await asyncio.to_thread(seed.post, "/peers/register", json=payload)
        assert response.status_code == 200, response.text
        return response.json()

    app2 = create_app(load_config(env2), peer_transport=ForwardToSeed(), mine=False)
    with TestClient(app2):
      deadline = time.monotonic() + 10
      while not seen and time.monotonic() < deadline:
        time.sleep(0.05)
      assert seen, "node2 never registered with its seed"
      stored = None
      while time.monotonic() < deadline:
        stored = app1.state.context.peers.get("node2")
        if stored is not None:
          break
        time.sleep(0.05)
      assert stored is not None
      assert stored.host == "node2.example" and stored.port == 8002
      assert stored.issued_at is not None and stored.signature
      check_registration(
        node_id="node2",
        host=stored.host,
        port=stored.port,
        public_key=stored.public_key,
        issued_at=stored.issued_at,
        signature=stored.signature,
        resolve_node_key=lambda _id, _at: node2_key.public_key,
        now_ms=_now(),
        max_future_skew_ms=60_000,
        held_issued_at=None,
      )
