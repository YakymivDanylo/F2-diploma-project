"""Slice 16a: `ChainState` serialises append and replace behind one asyncio lock (UC-17).

Since the 2026-11-20 hardening a replace VALIDATES outside the lock and installs under it only
if the chain did not change meanwhile (stale otherwise); append's checklist and save run in a
worker thread inside the lock.

The project does not use pytest-asyncio, so every scenario is an `async def` driven by
`asyncio.run` from a plain test function.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import random
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from chain_factory import pow_block
from node_helpers import NodeEnv

from blockchain_core import Block, JsonChainStore, ValidationResult
from blockchain_core.storage.chain_store import decode_chain
from node.chain_state import ChainState
from node.context import NodeContext
from node.mempool import DocumentIndex, Mempool
from node.validity_cache import ValidityCache

INTERLEAVINGS = 120


class FlakyStore:
  """A real `JsonChainStore` whose `save` can be told to fail or to park (fault injection)."""

  def __init__(self, real: JsonChainStore) -> None:
    self.real = real
    self.fail: Exception | None = None
    self.hold: threading.Event | None = None  # save parks (in its worker thread) until set
    self.entered = threading.Event()

  def save(self, blocks: Sequence[Block]) -> None:
    self.entered.set()
    if self.hold is not None:
      self.hold.wait(5)
    if self.fail is not None:
      raise self.fail
    self.real.save(blocks)

  def __getattr__(self, name: str):
    return getattr(self.real, name)


@dataclass
class Fixture:
  env: NodeEnv
  context: NodeContext
  root: Path
  stores: list[JsonChainStore]
  counter: list[int]
  caches: dict[int, ValidityCache]

  @property
  def validator(self):
    return self.context.validator

  def make(
    self, blocks: Sequence[Block], *, requeue_dropped: bool = True
  ) -> tuple[ChainState, FlakyStore, Path, Mempool]:
    """A fresh ChainState over a private store file, seeded with `blocks`."""
    self.counter[0] += 1
    path = self.root / f"state-{self.counter[0]}.json"
    real = JsonChainStore(path)
    self.stores.append(real)
    real.save(blocks)
    store = FlakyStore(real)
    cache = ValidityCache(self.validator)
    cache.initialize(blocks)
    mempool = Mempool()
    state = ChainState(
      blocks,
      valid=True,
      store=store,  # type: ignore[arg-type]
      validator=self.validator,
      validity_cache=cache,
      documents=DocumentIndex(blocks),
      mempool=mempool,
      requeue_dropped=requeue_dropped,
    )
    self.caches[id(state)] = cache
    return state, store, path, mempool

  def stored(self, path: Path) -> list[Block]:
    """The persisted chain, read without taking the store lock."""
    return decode_chain(path.read_bytes())


@pytest.fixture
def fx(node_env: NodeEnv, boot: Callable[[dict[str, str]], NodeContext], tmp_path: Path):
  context = boot({**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"})
  fixture = Fixture(node_env, context, tmp_path, [], [0], {})
  yield fixture
  for store in fixture.stores:
    store.close()


@dataclass
class Forks:
  old: list[Block]  # genesis, a1
  new: list[Block]  # genesis, b1, b2  (longer, valid)
  old_ext: list[Block]  # a2, a3 extend `old`
  new_ext: list[Block]  # b3, b4 extend `new`


def _forks(env: NodeEnv, genesis: Block) -> Forks:
  a1 = pow_block(env, genesis, 1)
  a2 = pow_block(env, a1, 2)
  a3 = pow_block(env, a2, 3)
  b1 = pow_block(env, genesis, 101)
  b2 = pow_block(env, b1, 102)
  b3 = pow_block(env, b2, 103)
  b4 = pow_block(env, b3, 104)
  return Forks([genesis, a1], [genesis, b1, b2], [a2, a3], [b3, b4])


@pytest.fixture
def forks(fx: Fixture) -> Forks:
  return _forks(fx.env, fx.context.chain_state.blocks[0])


def _tampered(chain: list[Block]) -> list[Block]:
  bad = dataclasses.replace(chain[-1], block_hash="0" * 64)
  return [*chain[:-1], bad]


def _hashes(blocks: Sequence[Block]) -> list[str]:
  return [b.block_hash for b in blocks]


class Gate:
  """An async `validate` that parks until released, then runs the real FR-25 checklist."""

  def __init__(self, check: Callable[[Sequence[Block]], ValidationResult]) -> None:
    self.started = asyncio.Event()
    self.release = asyncio.Event()
    self._check = check

  async def __call__(self, chain: Sequence[Block]) -> ValidationResult:
    self.started.set()
    await self.release.wait()
    return self._check(chain)


async def _until_set(event: threading.Event) -> None:
  for _ in range(5000):
    if event.is_set():
      return
    await asyncio.sleep(0.001)
  raise AssertionError("event never set")


def _spin(times: int = 5):
  async def run() -> None:
    for _ in range(times):
      await asyncio.sleep(0)

  return run()


# ------------------------------------------------------------------ wiring


def test_context_exposes_chain_state(fx: Fixture) -> None:
  state = fx.context.chain_state
  assert isinstance(state, ChainState)
  assert fx.context.current_blocks() == state.blocks
  assert state.extendable and not state.locked


# ------------------------------------------------------------------ CN-TC-17.1


def test_append_during_replace_validation_is_not_blocked_and_makes_it_stale(
  fx: Fixture, forks: Forks
) -> None:
  # CN-TC-17.1 (validation outside the lock): the append lands at once, and the replace that
  # was validated against the older chain is refused as stale instead of interleaving
  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    gate = Gate(fx.validator.full)
    replacing = asyncio.create_task(state.replace(forks.new, gate))
    await gate.started.wait()
    assert not state.locked  # validating does not hold the lock
    assert await asyncio.wait_for(state.append(forks.old_ext[0]), 1.0) is True
    gate.release.set()
    assert await replacing is False  # stale: the chain changed while it was validated
    assert _hashes(state.blocks) == _hashes([*forks.old, forks.old_ext[0]])
    assert _hashes(fx.stored(path)) == _hashes(state.blocks)
    # retried against the current chain, it is installed, and appends then extend the NEW tip
    assert await state.replace(forks.new, fx.validator.full) is True
    assert await state.append(forks.new_ext[0]) is True
    assert _hashes(state.blocks) == _hashes([*forks.new, forks.new_ext[0]])
    assert _hashes(fx.stored(path)) == _hashes(state.blocks)

  asyncio.run(scenario())


def test_appends_queued_behind_a_replace_install_run_against_the_new_tip(
  fx: Fixture, forks: Forks
) -> None:
  # CN-TC-17.1: the install (save + rebinding) holds the lock; queued appends run afterwards
  async def scenario() -> None:
    state, store, path, _ = fx.make(forks.old)
    store.hold = threading.Event()
    replacing = asyncio.create_task(state.replace(forks.new, fx.validator.full))
    await _until_set(store.entered)  # the replace is saving, inside the lock
    assert state.locked
    old_tip = asyncio.create_task(state.append(forks.old_ext[0]))
    new_tip = asyncio.create_task(state.append(forks.new_ext[0]))
    await _spin()
    assert not old_tip.done() and not new_tip.done()  # both wait for the lock
    assert _hashes(state.blocks) == _hashes(forks.old)  # nothing installed before the save
    store.hold.set()
    assert await replacing is True
    assert await old_tip is False  # no longer extends the tip
    assert await new_tip is True  # it extends the NEW tip
    assert _hashes(state.blocks) == _hashes([*forks.new, forks.new_ext[0]])
    assert _hashes(fx.stored(path)) == _hashes(state.blocks)

  asyncio.run(scenario())


def test_sync_validate_runs_in_worker_thread_outside_the_lock(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.1
  seen: dict[str, object] = {}
  holder: list[ChainState] = []

  def validate(chain: Sequence[Block]) -> ValidationResult:
    seen["thread"] = threading.get_ident()
    seen["locked"] = holder[0].locked
    return fx.validator.full(chain)

  async def scenario() -> None:
    state, _, _, _ = fx.make(forks.old)
    holder.append(state)
    main = threading.get_ident()
    assert await state.replace(forks.new, validate) is True
    assert seen["thread"] != main
    assert seen["locked"] is False
    assert not state.locked

  asyncio.run(scenario())


# ------------------------------------------------------------ CN-TC-17.2 / 17.4


def test_append_first_then_replace_drops_old_append(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.2, CN-TC-17.4
  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    assert await state.append(forks.old_ext[0]) is True
    assert state.tip.block_hash == forks.old_ext[0].block_hash
    assert await state.replace(forks.new, fx.validator.full) is True
    assert _hashes(state.blocks) == _hashes(forks.new)  # wholly new chain
    assert fx.validator.full(state.blocks).valid
    assert _hashes(fx.stored(path)) == _hashes(forks.new)

  asyncio.run(scenario())


def test_replace_first_then_append_extends_new_chain(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.2, CN-TC-17.4
  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    assert await state.replace(forks.new, fx.validator.full) is True
    assert await state.append(forks.old_ext[0]) is False
    assert await state.append(forks.new_ext[0]) is True
    expected = [*forks.new, forks.new_ext[0]]
    assert _hashes(state.blocks) == _hashes(expected)
    assert _hashes(fx.stored(path)) == _hashes(expected)

  asyncio.run(scenario())


def test_cache_document_index_and_mempool_follow_append_and_replace(
  fx: Fixture, forks: Forks
) -> None:
  # CN-TC-17.2
  async def scenario() -> None:
    state, _, _, mempool = fx.make(forks.old)
    cache = _cache_of(fx, state)
    queued = forks.old_ext[0].document_records[0]
    mempool.add(queued)
    assert await state.append(forks.old_ext[0]) is True
    assert len(mempool) == 0  # finalized record left the mempool
    assert state.has_document(queued.document_hash)
    assert state.document_positions(queued.document_hash) == [forks.old_ext[0].index]
    assert cache.snapshot.tip_index == len(state.blocks) - 1 and cache.snapshot.chain_valid

    new_record = forks.new[1].document_records[0]
    mempool.add(new_record)
    assert await state.replace(forks.new, fx.validator.full) is True
    assert not mempool.contains(new_record.document_hash)  # now finalized
    assert state.has_document(new_record.document_hash)
    assert not state.has_document(queued.document_hash)  # dropped with the old branch
    assert cache.snapshot.tip_index == len(forks.new) - 1 and cache.snapshot.chain_valid

  asyncio.run(scenario())


def _cache_of(fx: Fixture, state: ChainState) -> ValidityCache:
  """The ValidityCache `fx.make` built `state` with (the same object ChainState updates)."""
  return fx.caches[id(state)]


# ------------------------------------------------------------------ CN-TC-17.10


def _interleaving(fx: Fixture, forks: Forks, seed: int) -> None:
  rng = random.Random(seed)
  replace_valid = rng.random() < 0.7
  new_chain = forks.new if replace_valid else _tampered(forks.new)
  appends = [b for b in (*forks.old_ext, *forks.new_ext) if rng.random() < 0.75]
  if rng.random() < 0.3:
    rng.shuffle(appends)
  validate_spins = rng.randint(0, 6)
  replace_delay = rng.randint(0, 6)
  append_delays = [rng.randint(0, 8) for _ in appends]
  replace_first = rng.random() < 0.5

  async def validate(chain: Sequence[Block]) -> ValidationResult:
    for _ in range(validate_spins):
      await asyncio.sleep(0)
    return fx.validator.full(chain)

  async def after(delay: int, coro):
    for _ in range(delay):
      await asyncio.sleep(0)
    return await coro

  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    cache = _cache_of(fx, state)
    replace_task = asyncio.create_task(
      after(replace_delay if not replace_first else 0, state.replace(new_chain, validate))
    )
    append_tasks = [
      asyncio.create_task(after(d + (1 if replace_first else 0), state.append(b)))
      for b, d in zip(appends, append_delays, strict=True)
    ]
    replaced = await replace_task
    results = await asyncio.gather(*append_tasks)
    if replace_valid and not replaced:  # stale: only an append on the old chain moves it
      assert any(ok and b in forks.old_ext for b, ok in zip(appends, results, strict=True))
    assert replaced is False or replace_valid
    final = state.blocks
    base, ext = (forks.new, forks.new_ext) if replaced else (forks.old, forks.old_ext)
    assert _hashes(final[: len(base)]) == _hashes(base)  # wholly one side
    extras = final[len(base) :]
    assert all(b in ext for b in extras)  # nothing from the other branch leaked in
    # no successful append of the surviving branch is lost
    won = [b for b, ok in zip(appends, results, strict=True) if ok and b in ext]
    assert sorted(_hashes(extras)) == sorted(_hashes(won))  # applied order may differ
    assert fx.validator.full(final).valid
    assert _hashes(fx.stored(path)) == _hashes(final)
    assert cache.snapshot.tip_index == len(final) - 1
    assert cache.snapshot.chain_valid is True
    assert not state.locked

  asyncio.run(scenario())


def test_many_seeded_interleavings_keep_chain_valid_and_consistent(
  fx: Fixture, forks: Forks
) -> None:
  # CN-TC-17.2, CN-TC-17.4, CN-TC-17.10
  for seed in range(INTERLEAVINGS):
    try:
      _interleaving(fx, forks, seed)
    except AssertionError as exc:
      raise AssertionError(f"interleaving seed {seed} failed: {exc}") from exc


# ------------------------------------------------------------------ CN-TC-17.5


def test_two_blocks_for_same_height_only_one_is_appended(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.5
  tip = forks.old[-1]
  first = forks.old_ext[0]
  rival = pow_block(fx.env, tip, 999)
  assert first.index == rival.index and first.block_hash != rival.block_hash

  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    results = await asyncio.gather(state.append(first), state.append(rival))
    assert sorted(results) == [False, True]
    assert len(state.blocks) == len(forks.old) + 1
    assert state.tip.block_hash == (first if results[0] else rival).block_hash
    assert _hashes(fx.stored(path)) == _hashes(state.blocks)

  asyncio.run(scenario())


# ------------------------------------------------------------------ CN-TC-17.6


def test_reader_sees_old_chain_during_replace_and_new_chain_after(
  fx: Fixture, forks: Forks
) -> None:
  # CN-TC-17.6
  async def scenario() -> None:
    state, _, _, _ = fx.make(forks.old)
    cache = _cache_of(fx, state)
    before = state.blocks
    gate = Gate(fx.validator.full)
    replacing = asyncio.create_task(state.replace(forks.new, gate))
    await gate.started.wait()
    assert not state.locked  # validation runs outside the lock
    for _ in range(3):
      await asyncio.sleep(0)
      assert state.blocks == before
      assert cache.snapshot.tip_index == len(before) - 1 == len(state.blocks) - 1
    gate.release.set()
    assert await replacing is True
    assert state.blocks == tuple(forks.new)
    assert cache.snapshot.tip_index == len(forks.new) - 1 == len(state.blocks) - 1
    assert cache.snapshot.chain_valid is True

  asyncio.run(scenario())


# ------------------------------------------------------------------ CN-TC-17.7


def test_invalid_replace_leaves_chain_untouched_and_queued_append_succeeds(
  fx: Fixture, forks: Forks
) -> None:
  # CN-TC-17.7
  bad = _tampered(forks.new)
  assert not fx.validator.full(bad).valid

  async def scenario() -> None:
    state, _, _, _ = fx.make(forks.old)
    cache = _cache_of(fx, state)
    blocks_before = state.blocks
    gate = Gate(fx.validator.full)
    replacing = asyncio.create_task(state.replace(bad, gate))
    await gate.started.wait()
    # an append during the (outside-the-lock) validation is processed at once
    assert await asyncio.wait_for(state.append(forks.old_ext[0]), 1.0) is True
    gate.release.set()
    assert await replacing is False
    assert state.blocks == (*blocks_before, forks.old_ext[0])
    assert not state.locked
    assert cache.snapshot.tip_index == len(blocks_before)

  asyncio.run(scenario())


def test_invalid_replace_is_byte_identical(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.7
  bad = _tampered(forks.new)

  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    cache = _cache_of(fx, state)
    blocks_before, bytes_before, snap_before = state.blocks, path.read_bytes(), cache.snapshot
    assert await state.replace(bad, fx.validator.full) is False
    assert state.blocks == blocks_before
    assert path.read_bytes() == bytes_before
    assert cache.snapshot == snap_before
    assert not state.locked

  asyncio.run(scenario())


# --------------------------------------------------------- CN-TC-17.8 / 17.9


def test_exception_in_append_releases_lock_and_keeps_chain(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.8
  async def scenario() -> None:
    state, store, path, _ = fx.make(forks.old)
    cache = _cache_of(fx, state)
    blocks_before, bytes_before, snap_before = state.blocks, path.read_bytes(), cache.snapshot
    store.fail = OSError("disk full")
    with pytest.raises(OSError, match="disk full"):
      await state.append(forks.old_ext[0])
    assert not state.locked
    assert state.blocks == blocks_before
    assert path.read_bytes() == bytes_before
    assert cache.snapshot == snap_before
    store.fail = None
    assert await asyncio.wait_for(state.append(forks.old_ext[0]), 1.0) is True

  asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["async_validate", "sync_validate", "save"])
def test_exception_in_replace_releases_lock_and_keeps_chain(
  fx: Fixture, forks: Forks, mode: str
) -> None:
  # CN-TC-17.9
  async def async_boom(chain: Sequence[Block]) -> ValidationResult:
    await asyncio.sleep(0)
    raise RuntimeError("validate exploded")

  def sync_boom(chain: Sequence[Block]) -> ValidationResult:
    raise RuntimeError("validate exploded")

  async def scenario() -> None:
    state, store, path, mempool = fx.make(forks.old)
    cache = _cache_of(fx, state)
    blocks_before, bytes_before, snap_before = state.blocks, path.read_bytes(), cache.snapshot
    pending = forks.new[1].document_records[0]
    mempool.add(pending)
    old_doc = forks.old[1].document_records[0].document_hash
    positions_before = state.document_positions(old_doc)
    validate = {"async_validate": async_boom, "sync_validate": sync_boom}.get(
      mode, fx.validator.full
    )
    if mode == "save":
      store.fail = OSError("disk full")
    with pytest.raises((RuntimeError, OSError)):
      await state.replace(forks.new, validate)
    assert not state.locked
    assert state.blocks == blocks_before
    assert path.read_bytes() == bytes_before
    assert cache.snapshot == snap_before
    assert mempool.snapshot() == [pending]  # mempool untouched
    assert not state.has_document(pending.document_hash)  # document index untouched
    assert state.document_positions(old_doc) == positions_before
    store.fail = None
    assert await asyncio.wait_for(state.append(forks.old_ext[0]), 1.0) is True

  asyncio.run(scenario())


# ------------------------------------------------------------------ CN-TC-17.13


def test_blocks_are_frozen_and_earlier_views_do_not_change(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.13
  async def scenario() -> None:
    state, _, _, _ = fx.make(forks.old)
    taken = state.blocks
    hashes_taken = _hashes(taken)
    block = taken[-1]
    with pytest.raises(dataclasses.FrozenInstanceError):
      block.index = 99  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
      block.block_hash = "f" * 64  # type: ignore[misc]
    with pytest.raises((TypeError, AttributeError)):
      block.sealed_consensus["nonce"] = 12345  # type: ignore[index]
    with pytest.raises(TypeError):
      taken[0] = block  # type: ignore[index]
    assert _hashes(state.blocks) == hashes_taken  # live chain unaffected by the attempts

    assert await state.append(forks.old_ext[0]) is True
    assert _hashes(taken) == hashes_taken  # earlier tuple untouched by append
    assert len(taken) == len(forks.old)
    assert await state.replace(forks.new, fx.validator.full) is True
    assert _hashes(taken) == hashes_taken  # ... and by replace
    assert _hashes(state.blocks) == _hashes(forks.new)

  asyncio.run(scenario())


# ------------------------------------------------------------------ CN-TC-17.14


def test_chain_state_has_no_snapshot_api_and_exactly_one_lock(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.14
  state, _, _, _ = fx.make(forks.old)
  assert not [name for name in dir(state) if "snapshot" in name.lower()]
  locks = [v for v in vars(state).values() if isinstance(v, asyncio.Lock)]
  assert len(locks) == 1


# ------------------------------------------------------------------ architect additions


def test_prefer_runs_under_lock_against_current_chain(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.1, CN-TC-17.4: asked once before validating (skip a worse candidate) and again
  # under the lock against the chain current at install time
  seen: list[tuple[int, int, bool]] = []
  holder: list[ChainState] = []

  def longer(current: tuple[Block, ...], candidate: tuple[Block, ...]) -> bool:
    seen.append((len(current), len(candidate), holder[0].locked))
    return len(candidate) > len(current)

  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)  # old: len 2, new: len 3
    holder.append(state)
    gate = Gate(fx.validator.full)
    replacing = asyncio.create_task(state.replace(forks.new, gate, prefer=longer))
    await gate.started.wait()
    assert seen == [(2, 3, False)]
    gate.release.set()
    assert await replacing is True
    assert seen == [(2, 3, False), (2, 3, True)]  # re-judged under the lock
    assert _hashes(fx.stored(path)) == _hashes(forks.new)

    # a rule that no longer holds at install time refuses the candidate, changing nothing
    state2, _, path2, _ = fx.make(forks.old)
    answers = iter([True, False])
    raw, generation = path2.read_bytes(), state2.generation
    refused = await state2.replace(forks.new, fx.validator.full, prefer=lambda c, n: next(answers))
    assert refused is False
    assert state2.blocks == tuple(forks.old) and state2.generation == generation
    assert path2.read_bytes() == raw

    # a candidate that is not preferred is never even validated
    calls: list[int] = []

    def counting(chain: Sequence[Block]) -> ValidationResult:
      calls.append(len(chain))
      return fx.validator.full(chain)

    assert await state2.replace(forks.new, counting, prefer=lambda c, n: False) is False
    assert calls == []

  asyncio.run(scenario())


def test_prefer_false_changes_nothing(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.4
  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    before, raw, gen = state.blocks, path.read_bytes(), state.generation
    assert await state.replace(forks.new, fx.validator.full, prefer=lambda c, n: False) is False
    assert state.blocks == before and path.read_bytes() == raw and state.generation == gen
    assert not state.locked

  asyncio.run(scenario())


def test_dropped_records_are_requeued_and_finalized_ones_leave_mempool(
  fx: Fixture, forks: Forks
) -> None:
  # CN-TC-17.4
  async def scenario() -> None:
    state, _, _, mempool = fx.make(forks.old)
    assert await state.append(forks.old_ext[0]) is True
    dropped = [forks.old[1].document_records[0], forks.old_ext[0].document_records[0]]
    assert not any(mempool.contains(r.document_hash) for r in dropped)
    finalized = forks.new[1].document_records[0]
    mempool.add(finalized)  # pending, but the new chain finalizes it
    assert await state.replace(forks.new, fx.validator.full) is True
    for record in dropped:
      assert mempool.contains(record.document_hash)  # re-queued, not lost
      assert not state.has_document(record.document_hash)
    assert not mempool.contains(finalized.document_hash)

  asyncio.run(scenario())


def test_dropped_record_also_in_new_chain_is_not_requeued(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.4
  shared = forks.old[1].document_records[0]
  twin = pow_block(fx.env, forks.old[0], 1)  # same document as a1, rebuilt on genesis
  longer = [forks.old[0], twin, pow_block(fx.env, twin, 201)]
  assert twin.document_records[0].document_hash == shared.document_hash

  async def scenario() -> None:
    state, _, _, mempool = fx.make(forks.old)
    assert await state.replace(longer, fx.validator.full) is True
    assert not mempool.contains(shared.document_hash)

  asyncio.run(scenario())


def test_failing_replace_listener_is_logged_and_replace_stands(
  fx: Fixture, forks: Forks, caplog: pytest.LogCaptureFixture
) -> None:
  # CN-TC-17.9 (UC-17 side effects)
  calls: list[int] = []

  def boom(blocks: tuple[Block, ...]) -> None:
    calls.append(len(blocks))
    raise RuntimeError("listener exploded")

  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    state.add_replace_listener(boom)
    state.add_replace_listener(lambda blocks: calls.append(-len(blocks)))
    with caplog.at_level("ERROR", logger="node.chain_state"):
      assert await state.replace(forks.new, fx.validator.full) is True
    assert calls == [len(forks.new), -len(forks.new)]  # later listeners still run
    assert any(r.levelname == "ERROR" and "listener" in r.getMessage() for r in caplog.records)
    assert not state.locked
    assert _hashes(state.blocks) == _hashes(forks.new)
    assert _hashes(fx.stored(path)) == _hashes(forks.new)
    assert await asyncio.wait_for(state.append(forks.new_ext[0]), 1.0) is True

  asyncio.run(scenario())


def test_generation_increments_on_each_successful_change_only(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.2
  async def scenario() -> None:
    state, _, _, _ = fx.make(forks.old)
    g0 = state.generation
    assert await state.append(forks.old_ext[0]) is True
    assert state.generation == g0 + 1
    assert await state.append(forks.old_ext[0]) is False  # rejected: no change
    assert await state.replace(_tampered(forks.new), fx.validator.full) is False
    assert state.generation == g0 + 1
    assert await state.replace(forks.new, fx.validator.full) is True
    assert state.generation == g0 + 2

  asyncio.run(scenario())


def test_list_valued_block_fields_are_coerced_to_tuples(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.13
  def listy(block: Block) -> Block:
    return dataclasses.replace(
      block,
      document_records=list(block.document_records),  # type: ignore[arg-type]
      commit_signatures=list(block.commit_signatures),  # type: ignore[arg-type]
    )

  async def scenario() -> None:
    state, _, path, _ = fx.make(forks.old)
    assert await state.append(listy(forks.old_ext[0])) is True
    held = state.blocks[-1]
    assert isinstance(held.document_records, tuple)
    assert isinstance(held.commit_signatures, tuple)
    assert await state.replace([listy(b) for b in forks.new], fx.validator.full) is True
    assert all(
      isinstance(b.document_records, tuple) and isinstance(b.commit_signatures, tuple)
      for b in state.blocks
    )
    assert _hashes(fx.stored(path)) == _hashes(state.blocks)

  asyncio.run(scenario())


def test_validity_cache_event_signatures(fx: Fixture, forks: Forks) -> None:
  cache = ValidityCache(fx.validator)
  cache.initialize(forks.old)
  with pytest.raises(TypeError):
    cache.on_replace(forks.new)  # type: ignore[call-arg]  # result is now required
  cache.on_replace(forks.new, fx.validator.full(forks.new))
  assert cache.snapshot.tip_index == len(forks.new) - 1 and cache.snapshot.chain_valid
  cache.on_append(forks.new_ext[0])  # result optional: validated against the tip
  assert cache.snapshot.tip_index == len(forks.new) and cache.snapshot.chain_valid
  cache.on_append(forks.new_ext[1], fx.validator.extension(forks.new_ext[0], [forks.new_ext[1]]))
  assert cache.snapshot.tip_index == len(forks.new) + 1


# ------------------------------------------------------------------ review follow-ups


@pytest.mark.parametrize("which", ["plan_append", "plan_replace"])
def test_cache_planning_failure_happens_before_persistence(
  fx: Fixture, forks: Forks, monkeypatch: pytest.MonkeyPatch, which: str
) -> None:
  # CN-TC-17.8, CN-TC-17.9
  async def scenario() -> None:
    state, _, path, mempool = fx.make(forks.old)
    cache = _cache_of(fx, state)
    pending = (
      forks.new[1].document_records[0]
      if which == "plan_replace"
      else (forks.old_ext[0].document_records[0])
    )
    mempool.add(pending)
    old_doc = forks.old[1].document_records[0].document_hash
    blocks_before, bytes_before, snap_before = state.blocks, path.read_bytes(), cache.snapshot
    positions_before, gen_before = state.document_positions(old_doc), state.generation

    def boom(*args, **kwargs):
      raise RuntimeError("planning exploded")

    monkeypatch.setattr(cache, which, boom)
    with pytest.raises(RuntimeError, match="planning exploded"):
      if which == "plan_append":
        await state.append(forks.old_ext[0])
      else:
        await state.replace(forks.new, fx.validator.full)
    assert not state.locked
    assert state.blocks == blocks_before and state.generation == gen_before
    assert path.read_bytes() == bytes_before  # nothing persisted
    assert cache.snapshot == snap_before
    assert mempool.snapshot() == [pending]
    assert not state.has_document(pending.document_hash)
    assert state.document_positions(old_doc) == positions_before
    monkeypatch.delattr(cache, which)
    assert await asyncio.wait_for(state.append(forks.old_ext[0]), 1.0) is True

  asyncio.run(scenario())


def test_requeue_dropped_false_leaves_dropped_records_out(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.4
  async def scenario() -> None:
    state, _, _, mempool = fx.make(forks.old, requeue_dropped=False)
    assert await state.append(forks.old_ext[0]) is True
    dropped = [forks.old[1].document_records[0], forks.old_ext[0].document_records[0]]
    finalized = forks.new[1].document_records[0]
    mempool.add(finalized)
    assert await state.replace(forks.new, fx.validator.full) is True
    assert not any(mempool.contains(r.document_hash) for r in dropped)
    assert not mempool.contains(finalized.document_hash)  # finalized still leaves
    assert len(mempool) == 0

  asyncio.run(scenario())


def _drop_scenario(context: NodeContext, old: list[Block], new: list[Block]) -> list[bool]:
  """Append old[1], replace with `new`; report whether old[1]'s record was re-queued."""

  async def scenario() -> list[bool]:
    state = context.chain_state
    assert await state.append(old[1]) is True
    assert await state.replace(new, context.validator.full) is True
    return [context.mempool.contains(old[1].document_records[0].document_hash)]

  return asyncio.run(scenario())


def test_pow_boot_requeues_dropped_records(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.4 (main.py wiring: requeue_dropped=is_pow)
  assert _drop_scenario(fx.context, forks.old, forks.new) == [True]


def test_pbft_boot_does_not_requeue_dropped_records(
  node_env: NodeEnv, boot: Callable[[dict[str, str]], NodeContext]
) -> None:
  # CN-TC-17.4 (main.py wiring: requeue_dropped=is_pow)
  from chain_factory import pbft_block

  context = boot({**node_env.env, "CONSENSUS_MODE": "pbft"})
  genesis = context.chain_state.blocks[0]
  a1 = pbft_block(node_env, genesis, 1)
  b1 = pbft_block(node_env, genesis, 101)
  b2 = pbft_block(node_env, b1, 102)
  assert _drop_scenario(context, [genesis, a1], [genesis, b1, b2]) == [False]


# --------------------------------------------------- PoW lost race vs persistence error


def _publish_delays(
  fx: Fixture, monkeypatch: pytest.MonkeyPatch, append_behavior: str
) -> list[float]:
  import node.consensus.pow as pow_module
  from node.consensus.pow import PowEngine

  context = fx.context
  engine = PowEngine(context)
  mined = pow_block(fx.env, context.chain_state.tip, 301)
  delays: list[float] = []
  real_sleep = asyncio.sleep

  async def fake_sleep(delay: float, *args, **kwargs):
    delays.append(delay)
    await real_sleep(0)

  async def lost_race(block: Block) -> bool:
    return False

  async def failing(block: Block) -> bool:
    raise OSError("disk full")

  monkeypatch.setattr(pow_module, "PERSIST_RETRY_SECONDS", 777.0)
  monkeypatch.setattr(asyncio, "sleep", fake_sleep)
  monkeypatch.setattr(
    context.chain_state, "append", lost_race if append_behavior == "false" else failing
  )

  async def scenario() -> None:
    await engine._publish(mined, 1, 0, 0.0)  # noqa: SLF001

  asyncio.run(scenario())
  return delays


def test_pow_lost_race_does_not_back_off(fx: Fixture, monkeypatch: pytest.MonkeyPatch) -> None:
  # CN-TC-17.1 (PoW miner: a False append means mine again on the new tip, immediately)
  assert 777.0 not in _publish_delays(fx, monkeypatch, "false")


def test_pow_persistence_error_does_back_off(fx: Fixture, monkeypatch: pytest.MonkeyPatch) -> None:
  # CN-TC-17.8
  assert 777.0 in _publish_delays(fx, monkeypatch, "raise")


# ------------------------------------------------------------ 17.6 through GET /node/info


def test_node_info_is_consistent_while_a_replace_is_in_progress(fx: Fixture, forks: Forks) -> None:
  # CN-TC-17.6
  from types import SimpleNamespace

  from node.api.node_info import node_info

  context = fx.context
  request = SimpleNamespace(
    app=SimpleNamespace(
      state=SimpleNamespace(context=context, manager=SimpleNamespace(health=lambda: {}))
    )
  )

  async def scenario() -> None:
    state = context.chain_state
    assert await state.append(forks.old[1]) is True
    info = await node_info(request)  # type: ignore[arg-type]
    assert info.tip_index == len(state.blocks) - 1 == 1 and info.chain_valid  # after append
    gate = Gate(context.validator.full)
    replacing = asyncio.create_task(state.replace(forks.new, gate))
    await gate.started.wait()
    assert not state.locked  # validation runs outside the lock
    for _ in range(3):
      info = await node_info(request)  # type: ignore[arg-type]
      assert info.tip_index == len(forks.old) - 1 == len(state.blocks) - 1
      assert info.chain_valid
      await asyncio.sleep(0)
    gate.release.set()
    assert await replacing is True
    info = await node_info(request)  # type: ignore[arg-type]
    assert info.tip_index == len(forks.new) - 1 == len(state.blocks) - 1
    assert info.chain_valid

  asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["append", "replace"])
def test_cancelled_caller_whose_save_then_fails_still_sees_the_cancellation(
  fx: Fixture, forks: Forks, operation: str, caplog: pytest.LogCaptureFixture
) -> None:
  # CR4: the cancellation must not be lost when the deferred save raises afterwards
  async def scenario() -> None:
    state, store, path, _ = fx.make(forks.old)
    blocks_before, bytes_before = state.blocks, path.read_bytes()
    store.hold = threading.Event()
    if operation == "append":
      task = asyncio.create_task(state.append(forks.old_ext[0]))
    else:
      task = asyncio.create_task(state.replace(forks.new, fx.validator.full))
    await _until_set(store.entered)  # the save runs in its worker thread
    task.cancel()
    await _spin()
    assert not task.done()  # deferred until the save finished
    store.fail = OSError("disk full")
    store.hold.set()
    with pytest.raises(asyncio.CancelledError) as raised:
      await task
    chain, exc = [], raised.value  # the task re-wraps the CancelledError: walk the chain
    while exc is not None and len(chain) < 5:
      chain.append(exc)
      exc = exc.__cause__ or exc.__context__
    assert any(isinstance(e, OSError) for e in chain)  # chained to the save error
    assert not state.locked
    assert state.blocks == blocks_before  # nothing was installed
    assert path.read_bytes() == bytes_before

  with caplog.at_level(logging.ERROR, logger="node.chain_state"):
    asyncio.run(scenario())
  assert "chain save failed while the caller was cancelled" in caplog.text
  assert "disk full" in caplog.text
