"""Sync DoS hardening (audit 2026-11-20): a bounded polled set, the common-ancestor pre-check,
per-peer backoff, and `ChainState` keeping long work off the lock and off the event loop."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import threading
from collections.abc import Callable, Sequence
from typing import Any

import pytest
from chain_factory import pbft_block, pbft_chain, pow_block, pow_chain
from network_helpers import Cluster
from node_helpers import NodeEnv
from sync_helpers import (
  ListFetcher,
  RoutedFetcher,
  ValidatorSpy,
  blocks_of,
  extend,
  install,
  make_sync,
  run,
  slow_sync_env,
)

from blockchain_core import Block, ValidationResult
from blockchain_core.storage.chain_store import decode_chain
from node.context import NodeContext
from node.sync import (
  BACKOFF_CAP_S,
  BACKOFF_START_S,
  MAX_EXTRA_PEERS_PER_ROUND,
  PeerAddress,
)
from node.validity_cache import QUORUM_HEALTHY


def _peer(node_id: str) -> PeerAddress:
  return PeerAddress(node_id, node_id, 9000)


def _single(node_env: NodeEnv, mode: str = "pow") -> Cluster:
  slow_sync_env(node_env)
  return Cluster(node_env, ids=("node1",), mode=mode, mine=False, register_peers=False)


class Clock:
  def __init__(self) -> None:
    self.now = 1000.0

  def __call__(self) -> float:
    return self.now


async def _until_set(event: threading.Event) -> None:
  for _ in range(5000):
    if event.is_set():
      return
    await asyncio.sleep(0.001)
  raise AssertionError("event never set")


# --------------------------------------------------------------- 1. the polled set


def test_round_polls_every_validator_plus_a_rotating_window_of_extras(node_env: NodeEnv) -> None:
  chain = pow_chain(node_env, 2)
  validators = {f"v{i}" for i in range(1, 5)}
  extras = [f"x{i:02d}" for i in range(20)]
  # the validators are listed LAST: thousands of registrations ahead of them change nothing
  listing = [_peer(n) for n in extras] + [_peer(n) for n in sorted(validators)]

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, chain)
      fetcher = ListFetcher(chain)
      sync, _ = make_sync(n1, fetcher, peers=listing, is_validator=validators.__contains__)
      windows: list[set[str]] = []
      for _ in range(3):
        before = len(fetcher.requests)
        outcomes = await sync.sync_round()
        polled = {host for host, *_ in fetcher.requests[before:]}
        assert set(outcomes) == polled  # one probe per polled peer, nobody else contacted
        assert validators <= polled  # every validator, every round
        window = polled - validators
        assert len(window) == MAX_EXTRA_PEERS_PER_ROUND
        windows.append(window)
        assert set(outcomes.values()) == {"not_better"}
      # round-robin: x00..x07, x08..x15, then x16..x19 + wrap to x00..x03
      assert windows == [set(extras[:8]), set(extras[8:16]), set(extras[16:] + extras[:4])]

  run(go())


def test_unreachable_extras_are_backed_off_but_validators_never_are(node_env: NodeEnv) -> None:
  chain = pow_chain(node_env, 2)
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, chain)
      dead = ListFetcher(chain)
      dead.down = True
      routes = {"v1": dead, "x1": dead}
      sync, flags = make_sync(
        n1,
        RoutedFetcher(routes),
        peers=[_peer("v1"), _peer("x1")],
        is_validator={"v1"}.__contains__,
        clock=clock,
      )
      assert await sync.sync_round() == {"v1": "unreachable", "x1": "unreachable"}
      clock.now += 1
      assert await sync.sync_round() == {"v1": "unreachable"}  # the extra is backed off
      clock.now += BACKOFF_START_S
      assert set(await sync.sync_round()) == {"v1", "x1"}
      assert flags == []  # being unreachable is not misbehaviour

  run(go())


# ------------------------------------------- 2. pre-check of the first divergent block


@pytest.mark.parametrize("tail", [0, 30], ids=["modified-tip", "modified-tip-and-longer"])
def test_pbft_modified_tip_is_rejected_by_the_precheck_without_downloading(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture, tail: int
) -> None:
  # a peer serves our own chain with a modified (unfinalized) tip: one block is checked against
  # OUR parent, nothing of the chain is downloaded, nothing is validated from genesis
  ours = pbft_chain(node_env, 20)
  forged = dataclasses.replace(pbft_block(node_env, ours[19], 999), commit_signatures=())
  theirs = [*ours[:20], forged]
  for seed in range(1000, 1000 + tail):
    theirs.append(pbft_block(node_env, theirs[-1], seed))
  clock = Clock()

  async def go() -> None:
    async with _single(node_env, mode="pbft") as cluster:
      n1 = cluster["node1"]
      await install(n1, ours)
      fetcher = ListFetcher(theirs)
      sync, flags = make_sync(
        n1, fetcher, mode="pbft", page_size=4, peers=[_peer("node2")], clock=clock
      )
      spy = ValidatorSpy(n1.context.validator)
      with caplog.at_level(logging.ERROR):
        assert await sync.sync_round() == {"node2": "invalid"}

      assert flags == [("node2", "invalid chain: quorum")]
      assert spy.full_calls == []
      ((parent, checked),) = spy.extension_calls  # exactly one block, against our parent
      assert parent.block_hash == ours[19].block_hash
      assert [b.block_hash for b in checked] == [forged.block_hash]
      assert len(fetcher.requests) <= 6  # a probe, a few single-block probes, one page
      assert max(to_index for *_, to_index in fetcher.requests) <= 23  # never the tail
      assert "SAFETY VIOLATION" not in caplog.text
      assert n1.context.validity_cache.snapshot.quorum_status == QUORUM_HEALTHY
      assert blocks_of(n1) == tuple(ours)

      # the next rounds do not even contact the peer while it is backed off
      before = len(fetcher.requests)
      assert await sync.sync_round() == {}
      assert await sync.sync_round() == {}
      assert len(fetcher.requests) == before

  run(go())


def test_pow_deep_fork_with_a_bad_first_block_is_rejected_without_downloading(
  node_env: NodeEnv,
) -> None:
  # the fork has real work everywhere, but its first block re-issues a finalized document: the
  # pre-check finds it before the 30-block tail is fetched
  ours = pow_chain(node_env, 20)
  fork = [*ours[:5], pow_block(node_env, ours[4], 1)]  # seed 1 = ours[1]'s document
  fork = extend(node_env, fork, range(500, 530))

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, ours)
      fetcher = ListFetcher(fork)
      sync, flags = make_sync(n1, fetcher, page_size=4, expected_difficulty=1)
      spy = ValidatorSpy(n1.context.validator)

      assert await sync.sync_with(_peer("node2")) == "invalid"

      assert flags == [("node2", "invalid chain: duplicate_document")]
      assert spy.full_calls == [] and spy.extension_calls == []  # rejected by the node rules
      assert len(fetcher.requests) <= 6
      assert max(to_index for *_, to_index in fetcher.requests) <= 23
      assert blocks_of(n1) == tuple(ours)

      # control: the same depth of fork with a sound first block is adopted, and only the
      # divergent suffix (from the fork point) is validated - from OUR block 4
      good = extend(node_env, ours[:5], range(600, 632))
      fetcher = ListFetcher(good)
      sync, flags = make_sync(n1, fetcher, page_size=4, expected_difficulty=1)
      spy = ValidatorSpy(n1.context.validator)
      assert await sync.sync_with(_peer("node2")) == "adopted" and flags == []
      precheck, (base, suffix) = spy.extension_calls
      assert precheck[0].block_hash == ours[4].block_hash and len(precheck[1]) == 1
      assert base.block_hash == ours[4].block_hash
      assert [b.block_hash for b in suffix] == [b.block_hash for b in good[5:]]
      assert spy.full_calls == []
      assert min(from_index for _, _, from_index, _ in fetcher.requests) >= 1
      assert blocks_of(n1) == tuple(good)

  run(go())


# ----------------------------------------------------------------------- 3. backoff


def test_a_peer_serving_an_invalid_chain_is_backed_off_exponentially(node_env: NodeEnv) -> None:
  chain = pow_chain(node_env, 5)
  tampered = [*chain[:4], dataclasses.replace(chain[4], timestamp=chain[4].timestamp + 1)]
  tampered.append(chain[5])
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, chain[:3])
      fetcher = ListFetcher(tampered)
      sync, flags = make_sync(
        n1,
        fetcher,
        peers=[_peer("bad")],
        clock=clock,
        is_validator=lambda _id: False,
        # no wall-clock deadline in play: under full-suite load a 5 s per-peer timeout could
        # turn a slow validation into "unreachable"; the backoff runs on the injected clock
        peer_timeout_s=600.0,
      )  # a non-validator: 5..300 s (validators: 30 s cap)

      delays: list[float] = []
      for _ in range(8):
        assert await sync.sync_round() == {"bad": "invalid"}
        delay = sync.backoff_for("bad")
        delays.append(delay)
        clock.now += delay - 0.01
        before = len(fetcher.requests)
        assert await sync.sync_round() == {}  # still backed off: not contacted
        assert len(fetcher.requests) == before
        clock.now += 0.02
      assert delays == [5.0, 10.0, 20.0, 40.0, 80.0, 160.0, BACKOFF_CAP_S, BACKOFF_CAP_S]
      assert len(flags) == 8

      fetcher.blocks = list(chain)  # the peer is fixed: a good answer resets the backoff
      assert await sync.sync_round() == {"bad": "adopted"}
      assert sync.backoff_for("bad") == 0.0
      assert await sync.sync_round() == {"bad": "not_better"}  # polled again at once
      assert blocks_of(n1) == tuple(chain)

  run(go())


def test_a_malformed_answer_backs_off_too(node_env: NodeEnv) -> None:
  chain = pow_chain(node_env, 3)
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      fetcher = ListFetcher(chain)
      fetcher.mutate = lambda page: "garbage"
      sync, _ = make_sync(n1, fetcher, peers=[_peer("v1")], clock=clock)  # a validator
      assert await sync.sync_round() == {"v1": "malformed"}
      assert await sync.sync_round() == {}
      clock.now += BACKOFF_START_S
      fetcher.mutate = None
      assert await sync.sync_round() == {"v1": "adopted"}

  run(go())


# ------------------------------------------------- 4. ChainState: lock and event loop


def _hashes(blocks: Sequence[Block]) -> list[str]:
  return [b.block_hash for b in blocks]


def _fresh(context: NodeContext, env: NodeEnv) -> tuple[list[Block], list[Block]]:
  genesis = context.chain_state.blocks[0]
  old = [genesis, pow_block(env, genesis, 1)]
  new = extend(env, [genesis], [101, 102])
  return old, new


@pytest.fixture
def pow_context(node_env: NodeEnv, boot: Callable[[dict[str, str]], NodeContext]) -> NodeContext:
  return boot({**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"})


def test_replace_validates_outside_the_lock_and_a_stale_result_is_refused(
  node_env: NodeEnv, pow_context: NodeContext
) -> None:
  context = pow_context
  state = context.chain_state
  old, new = _fresh(context, node_env)
  started, release = threading.Event(), threading.Event()

  def slow(chain: Sequence[Block]) -> ValidationResult:  # a long validation, in its thread
    started.set()
    release.wait(5)
    return context.validator.full(chain)

  async def scenario() -> None:
    replacing = asyncio.create_task(state.replace(new, slow))
    await _until_set(started)
    assert not state.locked
    # an append completes while the slow validation is still running
    assert await asyncio.wait_for(state.append(old[1]), 1.0) is True
    generation = state.generation
    release.set()
    assert await replacing is False  # stale: validated against a chain that is gone
    assert state.blocks == tuple(old) and state.generation == generation
    assert _hashes(decode_chain(context.store.path.read_bytes())) == _hashes(old)

    # nothing moved meanwhile: the same slow validation is installed
    started.clear()
    assert await state.replace(new, slow) is True
    assert state.blocks == tuple(new)

  asyncio.run(scenario())


class _ParkedStore:
  """Wraps the node's store: `save` records its thread and parks until released."""

  def __init__(self, real: Any) -> None:
    self.real = real
    self.threads: list[int] = []
    self.entered = threading.Event()
    self.release = threading.Event()

  def save(self, blocks: Sequence[Block]) -> None:
    self.threads.append(threading.get_ident())
    self.entered.set()
    self.release.wait(5)
    self.real.save(blocks)

  def __getattr__(self, name: str) -> Any:
    return getattr(self.real, name)


def test_append_checks_and_saves_off_the_event_loop(
  node_env: NodeEnv, pow_context: NodeContext
) -> None:
  context = pow_context
  state = context.chain_state
  old, _ = _fresh(context, node_env)
  store = _ParkedStore(state._store)  # noqa: SLF001
  state._store = store  # noqa: SLF001
  checked_in: list[int] = []
  real_extension = context.validator.extension

  def extension(tip: Block, blocks: Sequence[Block]) -> ValidationResult:
    checked_in.append(threading.get_ident())
    return real_extension(tip, blocks)

  context.validator.extension = extension  # type: ignore[method-assign]

  async def scenario() -> None:
    loop_thread = threading.get_ident()
    appending = asyncio.create_task(state.append(old[1]))
    await _until_set(store.entered)
    ticks = 0
    for _ in range(20):  # the loop keeps running while the save is parked
      await asyncio.sleep(0)
      ticks += 1
    assert ticks == 20 and not appending.done()
    assert state.blocks == tuple(old[:1])  # nothing installed before the commit point
    store.release.set()
    assert await appending is True
    assert state.blocks == tuple(old)
    assert store.threads and all(t != loop_thread for t in store.threads)
    assert checked_in and all(t != loop_thread for t in checked_in)

  asyncio.run(scenario())


def test_append_cancelled_during_its_save_still_installs_what_was_saved(
  node_env: NodeEnv, pow_context: NodeContext
) -> None:
  # memory never lags the disk: the save cannot be called back, so the install completes
  context = pow_context
  state = context.chain_state
  old, _ = _fresh(context, node_env)
  store = _ParkedStore(state._store)  # noqa: SLF001
  state._store = store  # noqa: SLF001

  async def scenario() -> None:
    appending = asyncio.create_task(state.append(old[1]))
    await _until_set(store.entered)
    appending.cancel()
    await asyncio.sleep(0)
    store.release.set()
    with pytest.raises(asyncio.CancelledError):
      await appending
    assert state.blocks == tuple(old)
    assert _hashes(decode_chain(context.store.path.read_bytes())) == _hashes(old)
    assert context.validity_cache.snapshot.tip_index == 1
    assert not state.locked

  asyncio.run(scenario())
