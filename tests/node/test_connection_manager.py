from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient
from network_helpers import Cluster, make_pair, until
from node_helpers import NodeEnv
from starlette.websockets import WebSocketDisconnect

from blockchain_core import generate_node_keypair, sign_canonical
from node.config import load_config
from node.main import create_app
from node.network.connection_manager import (
  AUTH_FAILED_CLOSE_CODE,
  HELLO_DOMAIN,
  UNAUTHENTICATED_KEY,
  AuthFailed,
  ConnectionClosed,
  _eph_hex,
  _hello_payload,
  authenticate,
  parse_message,
)


def run(coro: Awaitable[Any]) -> Any:
  return asyncio.run(coro)  # type: ignore[arg-type]


# ----------------------------------------------------------- mutual authentication


def _handshake(a_key, b_key, lookup_a, lookup_b, *, a_id="node1", b_id="node2", expect_b=None):
  async def go():
    a_ws, b_ws = make_pair()
    return await asyncio.gather(
      authenticate(a_ws, my_id=a_id, my_key=a_key, lookup_key=lookup_a, expected_id=expect_b),
      authenticate(b_ws, my_id=b_id, my_key=b_key, lookup_key=lookup_b),
      return_exceptions=True,
    )

  return run(go())


def test_mutual_authentication_succeeds(node_env: NodeEnv) -> None:  # CN-TC-8.1
  keys = node_env.validator_keys
  public = {n: k.public_key for n, k in keys.items()}
  a, b = _handshake(
    keys["node1"].private_key, keys["node2"].private_key, public.get, public.get, expect_b="node2"
  )
  assert (a[0], b[0]) == ("node2", "node1")  # each side learns who the other is


def test_a_peer_without_the_private_key_is_refused(node_env: NodeEnv) -> None:  # CN-TC-8.3
  keys = node_env.validator_keys
  public = {n: k.public_key for n, k in keys.items()}
  impostor = generate_node_keypair()  # claims to be node2 but signs with another key
  a, _ = _handshake(keys["node1"].private_key, impostor.private_key, public.get, public.get)
  assert isinstance(a, AuthFailed)  # the honest side refuses; the impostor gains nothing


def test_unknown_node_id_is_refused(node_env: NodeEnv) -> None:  # CN-TC-8.6
  keys = node_env.validator_keys
  known = {"node1": keys["node1"].public_key}
  a, _ = _handshake(keys["node1"].private_key, keys["node2"].private_key, known.get, known.get)
  assert isinstance(a, AuthFailed)  # node1 has no key on record for 'node2'


def test_dialing_the_wrong_node_is_refused(node_env: NodeEnv) -> None:
  keys = node_env.validator_keys
  public = {n: k.public_key for n, k in keys.items()}
  a, _ = _handshake(
    keys["node1"].private_key, keys["node2"].private_key, public.get, public.get, expect_b="node3"
  )
  assert isinstance(a, AuthFailed)


def test_connecting_to_self_is_refused(node_env: NodeEnv) -> None:
  keys = node_env.validator_keys
  public = {n: k.public_key for n, k in keys.items()}
  a, b = _handshake(
    keys["node1"].private_key, keys["node1"].private_key, public.get, public.get, b_id="node1"
  )
  assert isinstance(a, AuthFailed) and isinstance(b, AuthFailed)


def test_a_proof_from_another_session_is_useless(node_env: NodeEnv) -> None:
  # A proof is bound to both fresh nonces and both ephemeral keys of ONE session pairing.
  keys = node_env.validator_keys
  public = {n: k.public_key for n, k in keys.items()}

  async def go():
    server_ws, client_ws = make_pair()
    task = asyncio.create_task(
      authenticate(
        server_ws, my_id="node1", my_key=keys["node1"].private_key, lookup_key=public.get
      )
    )
    server_hello = json.loads(await client_ws.receive_text())
    await client_ws.send_text(
      json.dumps({"type": "hello", "node_id": "node2", "nonce": "ab" * 16, "eph": "cd" * 32})
    )
    await client_ws.receive_text()  # the server's own proof
    stale = sign_canonical(  # node2 really signed this - but for a different session
      keys["node2"].private_key,
      {
        "domain": HELLO_DOMAIN,
        "signer": "node2",
        "verifier": "node1",
        "signer_nonce": "ab" * 16,
        "verifier_nonce": "00" * 16,
        "signer_eph": "cd" * 32,
        "verifier_eph": server_hello["eph"],
      },
    )
    await client_ws.send_text(json.dumps({"type": "proof", "signature": stale}))
    return await asyncio.gather(task, return_exceptions=True)

  (result,) = run(go())
  assert isinstance(result, AuthFailed)


def test_nothing_is_signed_for_a_stranger(node_env: NodeEnv) -> None:
  # The signing key must not become an oracle: an unknown id gets no proof at all.
  keys = node_env.validator_keys

  async def go():
    server_ws, client_ws = make_pair()
    task = asyncio.create_task(
      authenticate(
        server_ws, my_id="node1", my_key=keys["node1"].private_key, lookup_key=lambda _: None
      )
    )
    await client_ws.receive_text()
    await client_ws.send_text(
      json.dumps({"type": "hello", "node_id": "stranger", "nonce": "ab" * 16, "eph": "cd" * 32})
    )
    outcome = (await asyncio.gather(task, return_exceptions=True))[0]
    return outcome, server_ws.sent

  outcome, sent = run(go())
  assert isinstance(outcome, AuthFailed)
  assert [json.loads(m)["type"] for m in sent] == ["hello"]  # no proof was ever produced


def test_oversized_hello_is_refused_before_parsing(node_env: NodeEnv) -> None:
  keys = node_env.validator_keys

  async def go():
    server_ws, client_ws = make_pair()
    task = asyncio.create_task(
      authenticate(
        server_ws, my_id="node1", my_key=keys["node1"].private_key, lookup_key=lambda _: None
      )
    )
    await client_ws.receive_text()
    await client_ws.send_text('{"type": "hello", "pad": "' + "x" * 5000 + '"}')
    return (await asyncio.gather(task, return_exceptions=True))[0]

  assert isinstance(run(go()), AuthFailed)


def _relayed_session(node_env: NodeEnv):
  """node1 <-> M <-> node2, where M forwards every handshake message verbatim."""
  keys = node_env.validator_keys
  public = {n: k.public_key for n, k in keys.items()}

  async def go():
    a_ws, m_left = make_pair()
    m_right, b_ws = make_pair()

    async def pump(src, dst, tamper=None):
      try:
        while True:
          await dst.send_text(await src.receive_text())
      except Exception:
        return

    pumps = [
      asyncio.create_task(pump(m_left, m_right)),
      asyncio.create_task(pump(m_right, m_left)),
    ]
    (a_id, a_sec), (b_id, b_sec) = await asyncio.gather(
      authenticate(a_ws, my_id="node1", my_key=keys["node1"].private_key, lookup_key=public.get),
      authenticate(b_ws, my_id="node2", my_key=keys["node2"].private_key, lookup_key=public.get),
    )
    return a_sec, b_sec, m_left, m_right, pumps

  return go


def test_a_relay_can_pass_traffic_but_not_alter_it(node_env: NodeEnv) -> None:
  # Relaying the handshake verbatim is the best a man in the middle can do. Afterwards every
  # frame is MAC'd under a key only the two real parties hold, so tampering kills the link.
  async def go():
    a_sec, b_sec, m_left, m_right, pumps = await _relayed_session(node_env)()
    await a_sec.send_text("hello over the relay")
    assert await b_sec.receive_text() == "hello over the relay"  # honest relay: fine
    for task in pumps:
      task.cancel()
    await a_sec.send_text("original")
    frame = await m_left.receive_text()
    counter, mac, _ = frame.split(":", 2)
    await m_right.send_text(f"{counter}:{mac}:altered")  # the relay edits the payload
    with pytest.raises(ConnectionClosed):
      await b_sec.receive_text()

  run(go())


def test_secure_frames_cannot_be_replayed_or_reordered(node_env: NodeEnv) -> None:
  async def go():
    a_sec, b_sec, m_left, m_right, pumps = await _relayed_session(node_env)()
    for task in pumps:
      task.cancel()
    await a_sec.send_text("one")
    first = await m_left.receive_text()
    await m_right.send_text(first)
    assert await b_sec.receive_text() == "one"
    await m_right.send_text(first)  # the same frame again
    with pytest.raises(ConnectionClosed):
      await b_sec.receive_text()

  run(go())


def test_frames_are_bound_to_their_direction(node_env: NodeEnv) -> None:
  async def go():
    a_sec, b_sec, m_left, m_right, pumps = await _relayed_session(node_env)()
    for task in pumps:
      task.cancel()
    await a_sec.send_text("to b")
    frame = await m_left.receive_text()
    await m_left.send_text(frame)  # reflect A's own frame back at A
    with pytest.raises(ConnectionClosed):
      await a_sec.receive_text()

  run(go())


@pytest.mark.parametrize("raw", ["not json", "[]", '{"a": 1, "a": 2}', '{"x": 1.5}', "7"])
def test_parse_message_is_strict(raw: str) -> None:
  with pytest.raises(ValueError):
    parse_message(raw)


# ------------------------------------------------------------- fan-out and links


def test_fan_out_reaches_peers_in_either_direction(node_env: NodeEnv) -> None:  # CN-TC-7.1 / 6.6
  async def go():
    # Only node1 knows the others' addresses; node2/node3 reach node1 over INBOUND links.
    async with Cluster(node_env, register_peers=False) as cluster:
      n1 = cluster["node1"]
      for other in ("node2", "node3"):
        cluster.add_peer(n1, cluster[other])
      await until(lambda: set(n1.manager.connected_ids()) == {"node2", "node3"})
      await until(lambda: "node1" in cluster["node2"].manager.connected_ids())
      got: dict[str, list[dict]] = {"node2": [], "node3": []}
      for node_id in got:

        async def spy(peer_id, message, node_id=node_id):
          got[node_id].append(message)

        cluster[node_id].manager._on_message = spy
      delivered = await n1.manager.broadcast({"type": "ping", "n": 1})
      assert delivered == {"node2": True, "node3": True}
      # now the reverse: node2 never dialed node1, yet can push to it via the inbound link
      back: list[dict] = []

      async def n1_spy(peer_id, message):
        back.append(message)

      n1.manager._on_message = n1_spy
      assert await cluster["node2"].manager.broadcast({"type": "ping", "n": 2}) == {"node1": True}
      await until(lambda: len(back) == 1 and all(len(v) == 1 for v in got.values()))

  run(go())


def test_reconnects_with_capped_exponential_backoff(node_env: NodeEnv) -> None:  # CN-TC-7.2
  async def go():
    async with Cluster(
      node_env, ids=("node1", "node2"), options={"base_delay": 1.0, "max_delay": 8.0}
    ) as cluster:
      await cluster.all_connected()
      n1, n2 = cluster["node1"], cluster["node2"]
      await cluster.network.sever(n2.address)
      await until(lambda: n1.manager.health()["node2"] != "up")
      # while the peer stays down the delays double, then hold at the cap
      await until(lambda: len(n1.manager.dial_delays) >= 8)
      delays = n1.manager.dial_delays[-8:]
      assert delays[0] <= delays[1] and max(delays) == 8.0
      assert delays[-3:] == [8.0, 8.0, 8.0]
      assert all(b in (a * 2, a) for a, b in zip(delays, delays[1:], strict=False))
      await until(lambda: n1.manager.health()["node2"] == "down")  # many failures in a row
      cluster.network.heal(n2.address)
      await cluster.all_connected()  # reconnected on its own
      assert n1.manager.health()["node2"] == "up"
      seen = len(n1.manager.dial_delays)
      await cluster.network.sever(n2.address)  # a fresh outage after a success
      await until(lambda: len(n1.manager.dial_delays) > seen)
      assert n1.manager.dial_delays[seen] == 1.0  # backoff restarted from the base delay

  run(go())


def test_health_states(node_env: NodeEnv) -> None:  # CN-TC-7.2
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      await cluster.all_connected()
      health = cluster["node1"].manager.health()
      assert health["node2"] == "up"
      assert "node1" not in health  # never reports itself
      assert health["node3"] == "down"  # a ValidatorSet member with no address and no link
      await cluster.network.sever(cluster["node2"].address)
      await until(lambda: cluster["node1"].manager.health()["node2"] in ("reconnecting", "down"))

  run(go())


def test_both_directions_up_sends_each_message_once(node_env: NodeEnv) -> None:  # CN-TC-7.5
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      await cluster.all_connected()
      seen: list[dict] = []

      async def spy(peer_id, message):
        seen.append(message)

      cluster["node2"].manager._on_message = spy
      await until(lambda: len(cluster["node2"].manager.connected_ids()) == 1)
      await cluster["node1"].manager.broadcast({"type": "ping"})
      await asyncio.sleep(0.05)
      assert len(seen) == 1

  run(go())


def test_malformed_traffic_flags_the_peer_and_keeps_the_link(node_env: NodeEnv) -> None:
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      await cluster.all_connected()
      n1, n2 = cluster["node1"], cluster["node2"]
      link = n1.manager._links["node2"]
      ws = link.outbound or link.inbound
      await ws.send_text("{ definitely not json")
      await until(lambda: n2.manager.flags.get("node1") == 1)
      assert n2.manager.health()["node1"] == "up"

  run(go())


def test_stop_closes_everything(node_env: NodeEnv) -> None:
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      await cluster.all_connected()
      manager = cluster["node1"].manager
    assert manager.connected_ids() == []

  run(go())


# ------------------------------------------------------- the real WS endpoint


def _client_handshake(ws, key, my_id: str) -> str:
  """The client half of the v2 handshake, spoken by hand over a TestClient socket."""
  eph = _eph_hex(X25519PrivateKey.generate().public_key())
  nonce = "ab" * 16
  server = json.loads(ws.receive_text())
  ws.send_text(json.dumps({"type": "hello", "node_id": my_id, "nonce": nonce, "eph": eph}))
  proof = sign_canonical(
    key, _hello_payload(my_id, server["node_id"], nonce, server["nonce"], eph, server["eph"])
  )
  ws.send_text(json.dumps({"type": "proof", "signature": proof}))
  return server["node_id"]


def test_endpoint_accepts_a_registered_validator(node_env: NodeEnv) -> None:
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"}
  app = create_app(load_config(env), mine=False)
  with TestClient(app) as client, client.websocket_connect("/ws/blocks") as ws:
    assert _client_handshake(ws, node_env.validator_keys["node2"].private_key, "node2") == "node1"
    for _ in range(100):
      if app.state.manager.connected_ids() == ["node2"]:
        break
      time.sleep(0.02)
    assert app.state.manager.connected_ids() == ["node2"]  # authenticated and linked


def test_endpoint_closes_an_impostor(node_env: NodeEnv) -> None:  # CN-TC-8.3 / 8.6
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"}
  app = create_app(load_config(env), mine=False)
  with TestClient(app) as client:
    for key, claimed in (
      (generate_node_keypair().private_key, "node2"),  # right name, wrong key
      (generate_node_keypair().private_key, "stranger"),  # not registered anywhere
    ):
      with client.websocket_connect("/ws/blocks") as ws:
        _client_handshake(ws, key, claimed)
        with pytest.raises(WebSocketDisconnect) as closed:
          for _ in range(5):  # the server's own proof may arrive first; then it hangs up
            ws.receive_text()
        assert closed.value.code == AUTH_FAILED_CLOSE_CODE
    assert app.state.manager.flags[UNAUTHENTICATED_KEY] == 2


def test_endpoint_refuses_while_not_accepting(node_env: NodeEnv) -> None:
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"}
  app = create_app(load_config(env), mine=False)
  with TestClient(app) as client:
    app.state.accepting = False
    with client.websocket_connect("/ws/blocks") as ws, pytest.raises(Exception):  # noqa: B017
      ws.receive_text()
