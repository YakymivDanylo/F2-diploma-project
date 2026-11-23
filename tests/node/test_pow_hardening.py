"""PoW anti back-dating (2026-11-20 audit): the broadcast screen bounds a PoW block's timestamp
from below as well as from above, and the miner keeps its timestamp fresh while mining."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from chain_factory import BASE_TS, _record, pbft_block, pow_block
from node_helpers import NodeEnv

from blockchain_core import MAX_BLOCK_RECORDS, build_genesis_block, pow_target
from node.config import load_config
from node.consensus.pow import PowEngine
from node.context import NodeContext, build_node_context

NOW = BASE_TS + 10_000_000  # a fixed "current time" well after the factory's genesis children


def _pow_env(node_env: NodeEnv) -> dict[str, str]:
  return {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"}


class FixedClock:
  """A settable wall clock for the validation gateway (`build_node_context(now_ms=...)`)."""

  def __init__(self, value: int) -> None:
    self.value = value

  def __call__(self) -> int:
    return self.value


@pytest.fixture
def boot_at() -> Iterator[Callable[[dict[str, str], FixedClock], NodeContext]]:
  """Boot a context whose validation gateway reads `clock` (the public `now_ms` seam)."""
  contexts: list[NodeContext] = []

  def _boot(env: dict[str, str], clock: FixedClock) -> NodeContext:
    context = build_node_context(load_config(env), now_ms=clock)
    contexts.append(context)
    return context

  yield _boot
  for context in contexts:
    context.store.close()


class SteppingClock:
  """A fake wall clock that advances by `step` ms on every read."""

  def __init__(self, start: int, step: int) -> None:
    self.value = start
    self.step = step
    self.reads = 0

  def __call__(self) -> int:
    self.value += self.step
    self.reads += 1
    return self.value


async def _until(condition: Callable[[], bool], timeout: float = 10.0) -> None:
  deadline = time.monotonic() + timeout
  while not condition():
    assert time.monotonic() < deadline, "condition not reached in time"
    await asyncio.sleep(0.005)


def _mine(node_env: NodeEnv, scenario, **options: Any) -> Any:
  async def go() -> Any:
    context = build_node_context(load_config(_pow_env(node_env)))
    engine = PowEngine(context, **options)
    try:
      await engine.start()
      return await scenario(context, engine)
    finally:
      await engine.stop()
      context.store.close()

  return asyncio.run(go())


# ---------------------------------------------------------------- screen: lower bound


def test_back_dated_pow_block_is_rejected_fresh_one_passes(node_env: NodeEnv, boot_at) -> None:
  context = boot_at(_pow_env(node_env), FixedClock(NOW))
  skew = context.config.max_future_skew_ms
  genesis = context.current_blocks()[0]

  old = pow_block(node_env, genesis, 1, timestamp=NOW - skew - 1)
  verdict = context.gateway.screen(old)
  assert verdict.kind == "reject" and verdict.reason == "timestamp_too_old"
  assert not verdict.equivocation

  for timestamp in (NOW - skew, NOW, NOW + skew):  # both edges of the window are accepted
    fresh = pow_block(node_env, genesis, 1, timestamp=timestamp)
    assert context.gateway.screen(fresh).kind == "accept", timestamp


def test_back_dating_to_the_tip_timestamp_is_rejected(node_env: NodeEnv, boot_at) -> None:
  # the exact attack: timestamp = tip.timestamp passes core monotonicity, but is long past
  context = boot_at(_pow_env(node_env), FixedClock(NOW))
  genesis = context.current_blocks()[0]
  block = pow_block(node_env, genesis, 1, timestamp=genesis.timestamp)
  assert context.gateway.screen(block).reason == "timestamp_too_old"


def test_old_pbft_block_is_not_rejected_for_its_age(node_env: NodeEnv, boot_at) -> None:
  block = pbft_block(node_env, build_genesis_block(), 1)  # stamped at the factory's BASE_TS
  clock = FixedClock(int(time.time() * 1000))
  context = boot_at(node_env.env, clock)  # PBFT mode
  skew = context.config.max_future_skew_ms
  clock.value = block.timestamp + 100 * skew
  assert context.gateway.screen(block).kind == "accept"
  clock.value = block.timestamp - skew - 1  # the upper bound still applies
  assert context.gateway.screen(block).reason == "timestamp_in_future"


# ---------------------------------------------------------------- miner: fresh timestamps


def test_long_mining_run_produces_a_fresh_timestamp(node_env: NodeEnv) -> None:
  start = int(time.time() * 1000)
  clock = SteppingClock(start, step=60_000)  # every poll is one whole skew window later

  async def scenario(context: NodeContext, engine: PowEngine) -> None:
    skew = context.config.max_future_skew_ms
    engine._target = 0  # unsatisfiable: the attempt runs through many polls
    record = _record(node_env, 1)
    context.mempool.add(record)
    engine.on_submission(record)
    await _until(lambda: clock.reads >= 6)
    assert len(context.current_blocks()) == 1
    enabled_at = clock.value
    engine._target = pow_target(1)  # reachable again
    await _until(lambda: len(context.current_blocks()) == 2)
    block = context.current_blocks()[1]
    assert block.timestamp >= enabled_at  # re-stamped at the poll after the target changed
    assert block.timestamp > start + 4 * skew  # not the stale timestamp the attempt began with
    assert context.validator.full(context.current_blocks()).valid  # hash/signature over it
    assert len(context.mempool) == 0

  _mine(node_env, scenario, attempts_per_poll=20, now_ms=clock)


def test_records_are_reverified_at_the_final_timestamp(node_env: NodeEnv, caplog) -> None:
  start = int(time.time() * 1000)
  clock = SteppingClock(start, step=60_000)

  class RetiredIssuer:
    """The issuer key stops resolving after `cutoff` (retired mid-mining)."""

    def __init__(self, inner: Any, cutoff: int) -> None:
      self._inner, self._cutoff = inner, cutoff

    def resolve_issuer_key(self, issuer_id: str, at_timestamp: int):
      if at_timestamp > self._cutoff:
        return None
      return self._inner.resolve_issuer_key(issuer_id, at_timestamp)

    def __getattr__(self, name: str) -> Any:
      return getattr(self._inner, name)

  async def scenario(context: NodeContext, engine: PowEngine) -> None:
    engine._target = 0
    record = _record(node_env, 1)
    context.mempool.add(record)
    engine.on_submission(record)
    await _until(lambda: clock.reads >= 4)
    context.resolvers.reload(RetiredIssuer(context.resolvers.current, cutoff=clock.value))
    with caplog.at_level(logging.ERROR, logger="node.pow"):
      engine._target = pow_target(1)
      await _until(lambda: len(context.mempool) == 0)
    assert "invalid signature" in caplog.text
    assert len(context.current_blocks()) == 1  # never sealed into an invalid block

  _mine(node_env, scenario, attempts_per_poll=20, now_ms=clock)


# ---------------------------------------------------------------- options


def test_max_batch_is_bounded_by_the_block_record_cap(node_env: NodeEnv, boot) -> None:
  context = boot(_pow_env(node_env))
  PowEngine(context, max_batch=MAX_BLOCK_RECORDS)  # the cap itself is fine
  with pytest.raises(ValueError, match="MAX_BLOCK_RECORDS"):
    PowEngine(context, max_batch=MAX_BLOCK_RECORDS + 1)
