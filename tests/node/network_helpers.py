"""In-memory WebSocket network and multi-node cluster for the Slice 15 tests."""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import time
from collections.abc import Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path

from node_helpers import NodeEnv, pem_of

from blockchain_core import Block, save_key_pair
from blockchain_core.storage.chain_store import decode_chain
from node.api.chain import chain_page
from node.config import load_config
from node.context import NodeContext
from node.main import create_app
from node.network.connection_manager import ConnectionClosed, PeerConnectionManager

_CLOSED = object()
_CLUSTER_IDS = itertools.count(1)


class LoopEnd:
  """One end of an in-memory duplex connection (a `WsLike`)."""

  def __init__(self, inbox: asyncio.Queue, outbox: asyncio.Queue) -> None:
    self._in, self._out = inbox, outbox
    self.closed = False
    self.close_code: int | None = None
    self.sent: list[str] = []

  async def send_text(self, data: str) -> None:
    if self.closed:
      raise ConnectionClosed
    self.sent.append(data)
    self._out.put_nowait(data)

  async def receive_text(self) -> str:
    item = await self._in.get()
    if item is _CLOSED:
      self._in.put_nowait(_CLOSED)  # stay closed for later reads
      raise ConnectionClosed
    return item

  async def close(self, code: int = 1000) -> None:
    if not self.closed:
      self.closed = True
      self.close_code = code
      self._in.put_nowait(_CLOSED)
      self._out.put_nowait(_CLOSED)


def make_pair() -> tuple[LoopEnd, LoopEnd]:
  a_to_b: asyncio.Queue = asyncio.Queue()
  b_to_a: asyncio.Queue = asyncio.Queue()
  return LoopEnd(b_to_a, a_to_b), LoopEnd(a_to_b, b_to_a)


class LoopbackNetwork:
  """A `Connector` that wires a dial straight into the target manager's `accept_inbound`."""

  def __init__(self) -> None:
    self.managers: dict[tuple[str, int], PeerConnectionManager] = {}
    self.down: set[tuple[str, int]] = set()
    self.pipes: list[tuple[tuple[str, int], tuple[str, int], LoopEnd, LoopEnd]] = []
    self.dials: list[tuple[str, int]] = []
    self._tasks: list[asyncio.Task] = []

  def connector_for(self, dialer: tuple[str, int]) -> _NodeConnector:
    return _NodeConnector(self, dialer)

  async def _connect(self, dialer: tuple[str, int], host: str, port: int) -> LoopEnd:
    address = (host, port)
    self.dials.append(address)
    if {address, dialer} & self.down or address not in self.managers:
      raise ConnectionRefusedError(f"{host}:{port}")
    client, server = make_pair()
    self.pipes.append((dialer, address, client, server))
    self._tasks.append(asyncio.create_task(self.managers[address].accept_inbound(server)))
    return client

  async def sever(self, address: tuple[str, int]) -> None:
    """Drop every live connection to `address` and refuse new ones until `heal`."""
    self.down.add(address)
    for dialer, target, client, server in self.pipes:
      if address in (dialer, target):  # a partition cuts both directions
        await client.close()
        await server.close()

  def heal(self, address: tuple[str, int]) -> None:
    self.down.discard(address)

  async def aclose(self) -> None:
    for task in self._tasks:
      task.cancel()
    await asyncio.gather(*self._tasks, return_exceptions=True)


class _NodeConnector:
  def __init__(self, network: LoopbackNetwork, dialer: tuple[str, int]) -> None:
    self._network, self._dialer = network, dialer

  async def connect(self, host: str, port: int, path: str) -> LoopEnd:
    return await self._network._connect(self._dialer, host, port)


class LoopbackChainFetcher:
  """A `ChainFetcher` that answers `GET /chain` pages from the target node's `ChainState`
  in-process (the same `chain_page` the endpoint uses), honouring `LoopbackNetwork.down`."""

  def __init__(self, network: LoopbackNetwork, contexts: dict[tuple[str, int], NodeContext]):
    self._network, self._contexts = network, contexts
    self.requests: list[tuple[tuple[str, int], int, int]] = []

  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int):
    address = (host, port)
    self.requests.append((address, from_index, to_index))
    await asyncio.sleep(0)
    if address in self._network.down or address not in self._contexts:
      raise ConnectionRefusedError(f"{host}:{port}")
    context = self._contexts[address]
    page = chain_page(
      context.chain_state.blocks, from_index, to_index, context.config.max_page_size
    )
    return page.model_dump()


async def fast_sleep(seconds: float) -> None:
  await asyncio.sleep(min(seconds, 0.005))


async def until(condition: Callable[[], bool], timeout: float = 5.0) -> None:
  deadline = time.monotonic() + timeout
  while not condition():
    if time.monotonic() > deadline:
      raise AssertionError("condition not reached in time")
    await asyncio.sleep(0.005)


@dataclass
class ClusterNode:
  node_id: str
  address: tuple[str, int]
  context: NodeContext
  app: object

  @property
  def manager(self) -> PeerConnectionManager:
    return self.app.state.manager  # type: ignore[attr-defined]

  @property
  def receiver(self):
    return self.app.state.receiver  # type: ignore[attr-defined]

  @property
  def engine(self):
    return self.app.state.engine  # type: ignore[attr-defined]

  @property
  def tip(self) -> int:
    return len(self.context.current_blocks()) - 1


class Cluster:
  """N PoW nodes (difficulty 1) in one event loop, joined by a `LoopbackNetwork`."""

  def __init__(
    self,
    node_env: NodeEnv,
    ids: tuple[str, ...] = ("node1", "node2", "node3"),
    *,
    mode: str = "pow",
    mine: bool = True,
    register_peers: bool = True,
    options: dict | None = None,
  ) -> None:
    self.env = node_env
    self.ids = ids
    self.mode = mode
    self.mine = mine
    self.register_peers = register_peers
    self.options = {
      "scan_interval": 0.01,
      "base_delay": 0.01,
      "max_delay": 0.04,
      "handshake_timeout": 1.0,
      **(options or {}),
    }
    self.network = LoopbackNetwork()
    self.contexts: dict[tuple[str, int], NodeContext] = {}
    self.chain_fetcher = LoopbackChainFetcher(self.network, self.contexts)
    self.dir = node_env.root / f"cluster-{next(_CLUSTER_IDS)}"
    (self.dir / "keys").mkdir(parents=True)
    self.nodes: dict[str, ClusterNode] = {}
    self._stack = AsyncExitStack()

  async def __aenter__(self) -> Cluster:
    for position, node_id in enumerate(self.ids, start=1):
      key_path = self.dir / "keys" / f"{node_id}.pem"
      save_key_pair(self.env.validator_keys[node_id], key_path)
      env = {
        **self.env.env,
        "NODE_ID": node_id,
        "NODE_HOST": node_id,
        "NODE_PORT": str(9000 + position),
        "NODE_KEY_PATH": str(key_path),
        "CHAIN_PATH": str(self.chain_file(node_id)),
        "CONSENSUS_MODE": self.mode,
      }
      if self.mode == "pow":
        env["EXPECTED_DIFFICULTY"] = "1"
      address = (node_id, 9000 + position)
      app = create_app(
        load_config(env),
        mine=self.mine,
        connector=self.network.connector_for(address),
        sleep=fast_sleep,
        network_options=self.options,
        chain_fetcher=self.chain_fetcher,
      )
      await self._stack.enter_async_context(app.router.lifespan_context(app))
      node = ClusterNode(node_id, address, app.state.context, app)
      self.network.managers[address] = node.manager
      self.contexts[address] = node.context
      self.nodes[node_id] = node
    if self.register_peers:
      for node in self.nodes.values():
        for other in self.nodes.values():
          if other is not node:
            self.add_peer(node, other)
    return self

  def add_peer(self, node: ClusterNode, other: ClusterNode) -> None:
    key = self.env.validator_keys[other.node_id]
    node.context.peers.register(other.node_id, other.address[0], other.address[1], pem_of(key))

  async def __aexit__(self, *exc: object) -> None:
    with contextlib.suppress(Exception):
      await self._stack.aclose()
    await self.network.aclose()

  async def all_connected(self) -> None:
    await until(
      lambda: all(
        node.manager.health().get(other) == "up"
        for node in self.nodes.values()
        for other in self.ids
        if other != node.node_id
      )
    )

  def chain_file(self, node_id: str) -> Path:
    return self.dir / f"chain-{node_id}.json"

  def stored_blocks(self, node_id: str) -> list[Block]:
    """The persisted chain, read without taking the store lock the running node holds."""
    return decode_chain(self.chain_file(node_id).read_bytes())

  def __getitem__(self, node_id: str) -> ClusterNode:
    return self.nodes[node_id]
