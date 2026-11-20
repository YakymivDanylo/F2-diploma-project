"""Shared helpers for the Slice 16b chain-sync / fork-resolution / startup-sync tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from typing import Any

from chain_factory import pow_block
from network_helpers import ClusterNode
from node_helpers import NodeEnv

from blockchain_core import Block, ValidationResult
from node.api.chain import chain_page
from node.sync import ChainSync, PeerAddress

_OK = ValidationResult(valid=True)


def run(coro: Any) -> Any:
  return asyncio.run(coro)


def slow_sync_env(node_env: NodeEnv, **extra: str) -> None:
  """Keep the periodic sync out of the way (tests drive `sync_with` themselves)."""
  node_env.env["SYNC_INTERVAL_S"] = "3600"
  node_env.env.update(extra)


def peer_of(node: ClusterNode) -> PeerAddress:
  return PeerAddress(node.node_id, node.address[0], node.address[1])


def sync_of(node: ClusterNode) -> ChainSync:
  return node.app.state.sync  # type: ignore[attr-defined]


def blocks_of(node: ClusterNode) -> tuple[Block, ...]:
  return node.context.chain_state.blocks


async def install(node: ClusterNode, blocks: Sequence[Block]) -> None:
  """Make `blocks` the node's chain through `ChainState.replace` (validated)."""
  assert await node.context.chain_state.replace(blocks, node.context.validator.full)


async def force_install(node: ClusterNode, blocks: Sequence[Block]) -> None:
  """Make a (possibly invalid) chain the node's, so it serves it to its peers."""
  assert await node.context.chain_state.replace(blocks, lambda _blocks: _OK)


def extend(env: NodeEnv, blocks: Sequence[Block], seeds: Sequence[int]) -> list[Block]:
  chain = list(blocks)
  for seed in seeds:
    chain.append(pow_block(env, chain[-1], seed))
  return chain


def lowest_tip(*chains: Sequence[Block]) -> Sequence[Block]:
  return min(chains, key=lambda chain: int(chain[-1].block_hash, 16))


def record_flags(sync: ChainSync) -> list[tuple[str, str]]:
  calls: list[tuple[str, str]] = []
  sync._flag = lambda peer_id, reason: calls.append((peer_id, reason))  # type: ignore[method-assign]
  return calls


def make_sync(
  node: ClusterNode,
  fetcher: Any,
  *,
  mode: str | None = None,
  page_size: int = 100,
  peer_timeout_s: float = 5.0,
  peers: Sequence[PeerAddress] = (),
  sleep: Callable[[float], Any] | None = None,
  expected_difficulty: int | None = None,
  is_validator: Callable[[str], bool] | None = None,
  clock: Callable[[], float] | None = None,
) -> tuple[ChainSync, list[tuple[str, str]]]:
  """A `ChainSync` over the node's real state/validator/gateway but a scripted fetcher."""
  context = node.context
  flags: list[tuple[str, str]] = []
  extra: dict[str, Any] = {} if sleep is None else {"sleep": sleep}
  if is_validator is not None:
    extra["is_validator"] = is_validator
  if clock is not None:
    extra["clock"] = clock
  sync = ChainSync(
    state=context.chain_state,
    validator=context.validator,
    gateway=context.gateway,
    mode=mode or context.config.consensus_mode,  # type: ignore[arg-type]
    peers=lambda: list(peers),
    fetcher=fetcher,
    flag=lambda peer_id, reason: flags.append((peer_id, reason)),
    page_size=page_size,
    peer_timeout_s=peer_timeout_s,
    expected_difficulty=expected_difficulty,
    **extra,
  )
  return sync, flags


class ValidatorSpy:
  """Instance-attribute spy on `ChainValidator.full` / `.extension` (looked up at call time)."""

  def __init__(self, validator: Any) -> None:
    self.validator = validator
    self.full_calls: list[tuple[Block, ...]] = []
    self.extension_calls: list[tuple[Block, tuple[Block, ...]]] = []
    self.results: list[ValidationResult] = []
    real_full, real_extension = validator.full, validator.extension

    def full(blocks: Sequence[Block]) -> ValidationResult:
      self.full_calls.append(tuple(blocks))
      result = real_full(blocks)
      self.results.append(result)
      return result

    def extension(trusted_tip: Block, new_blocks: Sequence[Block]) -> ValidationResult:
      self.extension_calls.append((trusted_tip, tuple(new_blocks)))
      result = real_extension(trusted_tip, new_blocks)
      self.results.append(result)
      return result

    validator.full = full
    validator.extension = extension


class ListFetcher:
  """Serves `GET /chain` pages from a plain list of blocks; `down` makes it refuse."""

  def __init__(self, blocks: Sequence[Block], cap: int = 100) -> None:
    self.blocks = list(blocks)
    self.cap = cap
    self.down = False
    self.requests: list[tuple[str, int, int, int]] = []
    self.mutate: Callable[[dict[str, Any]], Any] | None = None

  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    self.requests.append((host, port, from_index, to_index))
    await asyncio.sleep(0)
    if self.down:
      raise ConnectionRefusedError(f"{host}:{port}")
    page = chain_page(self.blocks, from_index, to_index, self.cap).model_dump()
    return self.mutate(page) if self.mutate is not None else page


class RoutedFetcher:
  """Dispatches by peer host to one fetcher per peer."""

  def __init__(self, routes: dict[str, Any]) -> None:
    self._routes = routes

  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    return await self._routes[host].get_chain_page(host, port, from_index, to_index)


class HangingFetcher:
  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    await asyncio.sleep(3600)
