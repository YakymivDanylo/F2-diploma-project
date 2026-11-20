"""Interruptible proof-of-work mining.

The loop varies `sealed_consensus.nonce` inside the hashed preimage in fixed-size chunks and
yields to the event loop between chunks. At each yield it checks whether the chain tip moved
(a competing block was appended, or sync replaced the chain); if so the attempt is abandoned and
the batch, which stays in the mempool until some block includes it, is mined again on the new
tip. Every chain change goes through `ChainState` (the single owner and lock). A mined block is
handed to the `on_block_mined` hook, which the node wires to the WebSocket broadcast
(`/ws/blocks`).

Timestamp freshness: peers reject a PoW block stamped further back than the skew window
(`ValidationGateway.screen`, against back-dating to a time when a since-retired key still
resolved). Mining may take longer than that window, so every poll re-stamps the preimage with
`max(now, tip.timestamp)` - the hash is recomputed per nonce anyway. Record signatures were
verified against the issuer keys valid at the candidate's first timestamp; when the winning
timestamp differs, the candidate is rebuilt with `build_candidate_block` at that timestamp (one
batch re-verification per mined block, against the then-current resolver), so a record whose
issuer key was retired meanwhile is dropped instead of being sealed into an invalid block.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import TYPE_CHECKING

from blockchain_core import (
  MAX_BLOCK_RECORDS,
  Block,
  DocumentRecord,
  InvalidRecordSignatureError,
  attach_proposer_signature,
  build_candidate_block,
  pow_target,
  sha256_of_canonical,
)
from node.metrics import ConsensusMetric

if TYPE_CHECKING:
  from node.context import NodeContext

logger = logging.getLogger("node.pow")

DEFAULT_ATTEMPTS_PER_POLL = 2_000  # nonces tried between two yields = the abort granularity
DEFAULT_MAX_BATCH = MAX_BLOCK_RECORDS
PERSIST_RETRY_SECONDS = 1.0


def _wall_ms() -> int:
  return int(time.time() * 1000)


class PowEngine:
  def __init__(
    self,
    context: NodeContext,
    *,
    attempts_per_poll: int = DEFAULT_ATTEMPTS_PER_POLL,
    max_batch: int = DEFAULT_MAX_BATCH,
    now_ms: Callable[[], int] = _wall_ms,
    monotonic: Callable[[], float] = time.monotonic,
    on_block_mined: Callable[[Block], Awaitable[None]] | None = None,
  ) -> None:
    difficulty = context.config.expected_difficulty
    if difficulty is None:
      raise ValueError("PoW needs EXPECTED_DIFFICULTY")
    if attempts_per_poll < 1 or max_batch < 1:
      raise ValueError("attempts_per_poll and max_batch must be >= 1")
    if max_batch > MAX_BLOCK_RECORDS:
      raise ValueError(f"max_batch must be <= MAX_BLOCK_RECORDS ({MAX_BLOCK_RECORDS})")
    self._context = context
    self._chain_state = context.chain_state
    self._difficulty = difficulty
    self._target = pow_target(difficulty)
    self._attempts_per_poll = attempts_per_poll
    self._max_batch = max_batch
    self._now_ms = now_ms
    self._monotonic = monotonic
    self._on_block_mined = on_block_mined
    self._wake = asyncio.Event()
    self._task: asyncio.Task[None] | None = None
    # A sync replace (UC-3-EC2): a running attempt notices the moved tip at its next poll and
    # is abandoned; the wake restarts mining on the adopted chain (re-queued records included),
    # and lets a node whose invalid local chain was healed by sync start mining at all.
    self._chain_state.add_replace_listener(lambda _blocks: self._wake.set())

  # ------------------------------------------------------------- engine interface

  def on_submission(self, record: DocumentRecord) -> None:
    self._wake.set()

  async def on_inbound_block(self, block: Block) -> bool:
    """Adopt a peer's block if it extends our tip; a running attempt notices at its next poll."""
    adopted = await self._adopt(block)
    if adopted:
      self._wake.set()  # leftover pending records are mined on top of the new tip
    return adopted

  async def start(self) -> None:
    if self._task is None:
      self._task = asyncio.create_task(self._run(), name="pow-miner")
      if len(self._context.mempool):
        self._wake.set()

  async def stop(self) -> None:
    task, self._task = self._task, None
    if task is not None:
      task.cancel()
      with contextlib.suppress(asyncio.CancelledError):
        await task

  # ------------------------------------------------------------------ mining loop

  async def _run(self) -> None:
    while True:
      batch = self._next_batch() if self._chain_state.extendable else []
      if not batch:  # nothing to mine, or an invalid local chain that sync has not healed yet
        self._wake.clear()
        await self._wake.wait()
        continue
      try:
        await self._mine(batch)
      except Exception:
        logger.exception("mining attempt failed")
        await asyncio.sleep(PERSIST_RETRY_SECONDS)

  def _next_batch(self) -> list[DocumentRecord]:
    context = self._context
    stale = [
      r.document_hash
      for r in context.mempool.snapshot()
      if self._chain_state.has_document(r.document_hash)
    ]
    if stale:  # finalized elsewhere meanwhile
      context.mempool.remove(stale)
    return context.mempool.snapshot()[: self._max_batch]

  async def _mine(self, batch: list[DocumentRecord]) -> None:
    tip = self._chain_state.tip
    started_wall, started = self._now_ms(), self._monotonic()
    candidate = self._candidate(batch, tip, max(started_wall, tip.timestamp), {"nonce": 0})
    if candidate is None:
      return

    preimage = dict(candidate.preimage_dict())
    nonce = attempts = 0
    while True:
      for _ in range(self._attempts_per_poll):
        sealed = {"nonce": nonce, "difficulty": self._difficulty}
        preimage["sealed_consensus"] = sealed
        digest = sha256_of_canonical(preimage)
        attempts += 1
        if int(digest, 16) < self._target:
          mined = self._seal(candidate, batch, tip, preimage["timestamp"], sealed, digest)
          if mined is not None:
            await self._publish(mined, attempts, started_wall, started)
          return
        nonce += 1
      await asyncio.sleep(0)  # the abort point: let inbound blocks and requests run
      if self._chain_state.tip.block_hash != tip.block_hash:
        logger.info("mining at height %d abandoned: a competing block was adopted", candidate.index)
        return
      # Keep the timestamp inside the peers' skew window however long mining takes.
      preimage["timestamp"] = max(self._now_ms(), tip.timestamp)

  def _candidate(
    self, batch: list[DocumentRecord], tip: Block, timestamp: int, sealed: dict[str, int]
  ) -> Block | None:
    """`build_candidate_block` at `timestamp` (record signatures verified against the issuer
    keys valid then); an invalid record is dropped from the mempool and None returned."""
    context = self._context
    try:
      return build_candidate_block(
        batch,
        previous_hash=tip.block_hash,
        index=tip.index + 1,
        timestamp=timestamp,
        proposer_id=context.config.node_id,
        algorithm="pow",
        sealed_consensus={**sealed, "difficulty": self._difficulty},
        resolve_issuer_key=context.resolvers.current.resolve_issuer_key,
      )
    except InvalidRecordSignatureError as exc:
      logger.error(
        "dropping a pending record with an invalid signature (batch index %d)", exc.index
      )
      context.mempool.remove([batch[exc.index].document_hash])
      return None

  def _seal(
    self,
    candidate: Block,
    batch: list[DocumentRecord],
    tip: Block,
    timestamp: int,
    sealed: dict[str, int],
    digest: str,
  ) -> Block | None:
    """The signed winning block. If the timestamp moved since the candidate was built, the
    block is rebuilt at it, re-verifying every record against the keys valid at that time."""
    if timestamp == candidate.timestamp:
      mined = replace(candidate, sealed_consensus=sealed, block_hash=digest)
    else:
      rebuilt = self._candidate(batch, tip, timestamp, sealed)
      if rebuilt is None:
        return None  # a record's issuer key no longer resolves: mine the rest again
      if rebuilt.block_hash != digest:  # same preimage by construction; never seal a mismatch
        logger.error("rebuilt block %d does not match the mined hash", rebuilt.index)
        return None
      mined = rebuilt
    return attach_proposer_signature(mined, self._context.state.node_key.private_key)

  async def _publish(self, block: Block, attempts: int, started_wall: int, started: float) -> None:
    try:
      adopted = await self._chain_state.append(block)
    except Exception:
      logger.exception("could not persist/append mined block %d", block.index)
      await asyncio.sleep(PERSIST_RETRY_SECONDS)  # a persistence error; do not spin
      return
    if not adopted:  # lost the race: the tip moved while we waited; mine again on it
      return
    elapsed = max(self._monotonic() - started, 1e-3)
    self._context.metrics.record(
      ConsensusMetric(
        block_index=block.index,
        algorithm="pow",
        proposed_at=started_wall,
        finalized_at=self._now_ms(),
        attempts_or_rounds=attempts,
        hash_rate=attempts / elapsed,
      )
    )
    if self._on_block_mined is not None:
      await self._on_block_mined(block)

  # ----------------------------------------------------------------- chain update

  async def _adopt(self, block: Block) -> bool:
    """`ChainState` validates against the tip, persists, appends, indexes and de-queues."""
    try:
      return await self._chain_state.append(block)
    except Exception:
      logger.exception("could not persist/append block %d", block.index)
      return False
