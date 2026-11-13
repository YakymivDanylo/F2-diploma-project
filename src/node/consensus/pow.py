"""Interruptible proof-of-work mining.

The loop varies `sealed_consensus.nonce` inside the hashed preimage in fixed-size chunks and
yields to the event loop between chunks. At each yield it checks whether the chain tip moved
(a competing block was appended, or sync replaced the chain); if so the attempt is abandoned and
the batch, which stays in the mempool until some block includes it, is mined again on the new
tip. Every chain change goes through `ChainState` (the single owner and lock). Broadcast of a
mined block is a hook (`on_block_mined`) wired by the WebSocket layer in Slice 15.
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
  from node.main import NodeContext

logger = logging.getLogger("node.pow")

DEFAULT_ATTEMPTS_PER_POLL = 2_000  # nonces tried between two yields = the abort granularity
DEFAULT_MAX_BATCH = 500
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
    if difficulty is None or not context.chain_state.extendable:
      raise ValueError("PoW needs EXPECTED_DIFFICULTY and an extendable (valid) chain")
    if attempts_per_poll < 1 or max_batch < 1:
      raise ValueError("attempts_per_poll and max_batch must be >= 1")
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
      batch = self._next_batch()
      if not batch:
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
    context = self._context
    tip = self._chain_state.tip
    started_wall, started = self._now_ms(), self._monotonic()
    resolver = context.resolvers.current
    try:
      candidate = build_candidate_block(
        batch,
        previous_hash=tip.block_hash,
        index=tip.index + 1,
        timestamp=max(started_wall, tip.timestamp),
        proposer_id=context.config.node_id,
        algorithm="pow",
        sealed_consensus={"nonce": 0, "difficulty": self._difficulty},
        resolve_issuer_key=resolver.resolve_issuer_key,
      )
    except InvalidRecordSignatureError as exc:
      logger.error(
        "dropping a pending record with an invalid signature (batch index %d)", exc.index
      )
      context.mempool.remove([batch[exc.index].document_hash])
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
          mined = replace(candidate, sealed_consensus=sealed, block_hash=digest)
          signed = attach_proposer_signature(mined, context.state.node_key.private_key)
          await self._publish(signed, attempts, started_wall, started)
          return
        nonce += 1
      await asyncio.sleep(0)  # the abort point: let inbound blocks and requests run
      if self._chain_state.tip.block_hash != tip.block_hash:
        logger.info("mining at height %d abandoned: a competing block was adopted", candidate.index)
        return

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
