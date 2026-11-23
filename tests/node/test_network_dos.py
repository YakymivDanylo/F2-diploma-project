"""DoS hardening (audit 2026-11-20): handshake slots per address, short handshake timeout,
non-validator link and frame caps, and block screening off the event loop."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from network_helpers import Cluster, make_pair, until
from node_helpers import NodeEnv

from blockchain_core import generate_node_keypair
from blockchain_core.storage.chain_store import block_to_dict
from node.network.connection_manager import (
  DEFAULT_HANDSHAKE_TIMEOUT,
  MAX_HANDSHAKES_PER_ADDRESS,
  MAX_MESSAGE_BYTES,
  MAX_NON_VALIDATOR_LINKS,
  NON_VALIDATOR_MAX_FRAME,
  SERVER_WS_MAX_SIZE,
  UNAUTHENTICATED_KEY,
  PeerConnectionManager,
  authenticate,
)
from node.network.ws_blocks import BlockReceiver
from node.validation_gateway import InboundVerdict

VALIDATORS = ("node1", "node2", "node3", "node4")


def run(coro: Any) -> Any:
  return asyncio.run(coro)


class _NoDial:
  async def connect(self, host: str, port: int, path: str) -> Any:
    raise OSError("tests never dial")


_NODE1_PUBLIC: list = []


def _manager(node_env: NodeEnv, extra_keys: dict, received: list, **options: Any):
  _NODE1_PUBLIC[:] = [node_env.validator_keys["node1"].public_key]
  public = {n: k.public_key for n, k in node_env.validator_keys.items()}
  public.update({n: k.public_key for n, k in extra_keys.items()})

  async def on_message(peer_id: str, message: dict) -> None:
    received.append((peer_id, message))

  return PeerConnectionManager(
    self_id="node1",
    node_key=node_env.validator_keys["node1"].private_key,
    lookup_key=public.get,
    peer_addresses=lambda: [],
    known_ids=lambda: [n for n in VALIDATORS if n in node_env.validator_keys],
    connector=_NoDial(),
    on_message=on_message,
    **options,
  )


async def _connect(manager: PeerConnectionManager, node_id: str, key, remote=None):
  """Open an inbound link as `node_id`; returns (client channel, server end, serve task)."""
  client, server = make_pair()
  task = asyncio.create_task(manager.accept_inbound(server, remote=remote))
  public = {"node1": _NODE1_PUBLIC[0]}
  _, secure = await authenticate(client, my_id=node_id, my_key=key, lookup_key=public.get)
  return secure, server, task


async def _cleanup(tasks: list[asyncio.Task]) -> None:
  for task in tasks:
    task.cancel()
  await asyncio.gather(*tasks, return_exceptions=True)


# ----------------------------------------------------------- handshake slots


def test_one_address_cannot_hold_more_than_its_share_of_handshakes(node_env: NodeEnv) -> None:
  async def go():
    manager = _manager(node_env, {}, [])
    silent = [make_pair() for _ in range(MAX_HANDSHAKES_PER_ADDRESS)]
    tasks = [
      asyncio.create_task(manager.accept_inbound(server, remote="10.0.0.9")) for _, server in silent
    ]
    await until(lambda: manager.handshakes_in_progress == MAX_HANDSHAKES_PER_ADDRESS)
    _, extra = make_pair()
    await manager.accept_inbound(extra, remote="10.0.0.9")  # same host: refused at once
    assert extra.closed and extra.close_code == 1013 and extra.sent == []
    assert manager.flags[UNAUTHENTICATED_KEY] == 1
    _, other = make_pair()  # another host still gets a slot
    other_task = asyncio.create_task(manager.accept_inbound(other, remote="10.0.0.10"))
    await until(lambda: manager.handshakes_in_progress == MAX_HANDSHAKES_PER_ADDRESS + 1)
    assert not other.closed and other.sent  # it got our hello
    for _, server in [*silent, (None, other)]:
      await server.close()
    await asyncio.gather(*tasks, other_task)
    assert (
      manager.handshakes_in_progress == 0 and not manager._handshakes_by_address
    )  # slots released

  run(go())


def test_a_validator_from_a_busy_address_connects_once_slots_free(node_env: NodeEnv) -> None:
  async def go():
    manager = _manager(node_env, {}, [])
    secure, _, task = await _connect(
      manager, "node2", node_env.validator_keys["node2"].private_key, remote="10.0.0.9"
    )
    await until(lambda: manager.connected_ids() == ["node2"])
    assert not manager._handshakes_by_address  # an authenticated link holds no handshake slot
    await secure.close()
    await asyncio.gather(task)

  run(go())


def test_the_default_handshake_timeout_is_short_and_releases_slots(node_env: NodeEnv) -> None:
  assert DEFAULT_HANDSHAKE_TIMEOUT == 2.0

  async def go():
    manager = _manager(node_env, {}, [])  # default timeout
    silent = [make_pair() for _ in range(MAX_HANDSHAKES_PER_ADDRESS)]
    started = time.monotonic()
    await asyncio.gather(
      *(manager.accept_inbound(server, remote="10.0.0.9") for _, server in silent)
    )
    elapsed = time.monotonic() - started
    assert DEFAULT_HANDSHAKE_TIMEOUT - 0.2 <= elapsed < DEFAULT_HANDSHAKE_TIMEOUT + 1.0
    assert all(server.close_code == 4401 for _, server in silent)
    assert manager.handshakes_in_progress == 0 and not manager._handshakes_by_address

  run(go())


def test_inbound_socket_is_closed_when_cancelled_mid_handshake(node_env: NodeEnv) -> None:
  # like the outbound path: a cancellation (shutdown) during the handshake must not leak it
  async def go():
    manager = _manager(node_env, {}, [], handshake_timeout=30.0)
    _, server = make_pair()
    task = asyncio.create_task(manager.accept_inbound(server, remote="10.0.0.9"))
    await until(lambda: manager.handshakes_in_progress == 1)
    assert server.sent and not server.closed  # our hello went out; the peer stays silent
    task.cancel()
    results = await asyncio.gather(task, return_exceptions=True)
    assert isinstance(results[0], asyncio.CancelledError)  # the cancellation propagates
    assert server.closed  # ... after the socket was closed
    assert manager.handshakes_in_progress == 0 and not manager._handshakes_by_address

  run(go())


# ------------------------------------------------------ non-validator limits


def test_non_validator_links_are_capped(node_env: NodeEnv) -> None:
  strangers = {f"peer{i}": generate_node_keypair() for i in range(MAX_NON_VALIDATOR_LINKS + 1)}

  async def go():
    manager = _manager(node_env, strangers, [])
    tasks = []
    ids = sorted(strangers)
    for node_id in ids[:MAX_NON_VALIDATOR_LINKS]:
      _, _, task = await _connect(manager, node_id, strangers[node_id].private_key)
      tasks.append(task)
    await until(lambda: len(manager.connected_ids()) == MAX_NON_VALIDATOR_LINKS)
    last = ids[-1]
    _, server, task = await _connect(manager, last, strangers[last].private_key)
    await asyncio.wait_for(task, 1.0)  # served and refused right after authenticating
    assert server.closed and server.close_code == 1013
    assert last not in manager.connected_ids()
    # a reconnect by a peer that already holds a link replaces it rather than needing a slot
    _, _, again = await _connect(manager, ids[0], strangers[ids[0]].private_key)
    tasks.append(again)
    await until(lambda: manager._links[ids[0]].inbound is not None)
    # validators are never subject to the cap
    _, _, validator = await _connect(manager, "node2", node_env.validator_keys["node2"].private_key)
    tasks.append(validator)
    await until(lambda: "node2" in manager.connected_ids())
    await _cleanup(tasks)

  run(go())


def test_oversized_frame_from_a_non_validator_is_dropped(node_env: NodeEnv) -> None:
  stranger = {"peerinfo-node": generate_node_keypair()}

  async def go():
    received: list = []
    manager = _manager(node_env, stranger, received)
    big = '{"type":"block","pad":"' + "x" * NON_VALIDATOR_MAX_FRAME + '"}'
    small = '{"type":"block","pad":"ok"}'

    outsider, _, t1 = await _connect(
      manager, "peerinfo-node", stranger["peerinfo-node"].private_key
    )
    await outsider.send_text(big)
    await outsider.send_text(small)
    await until(lambda: len(received) == 1)
    assert received[0] == ("peerinfo-node", {"type": "block", "pad": "ok"})
    assert manager.flags["peerinfo-node"] == 1  # flagged, link kept
    assert "peerinfo-node" in manager.connected_ids()

    validator, _, t2 = await _connect(
      manager, "node2", node_env.validator_keys["node2"].private_key
    )
    await validator.send_text(big)  # validators keep the full MAX_MESSAGE_BYTES budget
    await until(lambda: len(received) == 2)
    assert received[1][0] == "node2" and len(received[1][1]["pad"]) == NON_VALIDATOR_MAX_FRAME
    assert "node2" not in manager.flags
    await _cleanup([t1, t2])

  run(go())


def test_server_frame_limit_matches_the_protocol_limit() -> None:
  assert SERVER_WS_MAX_SIZE == MAX_MESSAGE_BYTES


# ----------------------------------------------------- screening off the loop


def test_block_screening_runs_off_the_event_loop(node_env: NodeEnv) -> None:
  async def go():
    async with Cluster(node_env, ids=("node1", "node2"), mine=False) as cluster:
      node = cluster["node1"]
      genesis = node.context.current_blocks()[0]
      threads: list[int] = []

      class _Gateway:
        def screen(self, block):
          threads.append(threading.get_ident())
          return InboundVerdict("duplicate")

      receiver = BlockReceiver(_Gateway(), None, node.manager)  # type: ignore[arg-type]
      payload = block_to_dict(genesis)
      verdict = await receiver.handle_block("node2", payload)
      assert verdict.kind == "duplicate"
      assert threads and threads[0] != threading.get_ident()

  run(go())
