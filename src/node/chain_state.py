"""The single owner of the in-memory chain.

`ChainState` is the only code in `node` that changes the chain. The chain is an immutable
tuple of frozen `Block` objects, rebound - never mutated - inside one critical section guarded
by exactly one `asyncio.Lock`. `append` (a mined or broadcast block) and `replace` (a chain
adopted by sync) are serialised by that lock, so an append can never interleave with a replace:
the result is always wholly old-plus-appends or wholly new-plus-appends (UC-17).

`store.save` is the commit point of both operations: if it raises, the chain is unchanged and
the exception propagates with the lock released. What follows it - rebinding the tuple, the
validity cache, the document index and the mempool - is in-memory only, with no `await` in
between, so a reader on the event loop never observes a half-installed chain. Readers get the
tuple itself: it cannot change under them, and the blocks in it are frozen (UC-17-EC3), which is
the contract the Slice 33b snapshot copy builds on.
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import logging
from collections.abc import Awaitable, Callable, Sequence

from blockchain_core import Block, ValidationResult
from blockchain_core.storage.chain_store import ChainStore
from node.mempool import DocumentIndex, Mempool
from node.validation_gateway import ChainValidator
from node.validity_cache import ValidityCache

logger = logging.getLogger("node.chain_state")

ChainCheck = Callable[[Sequence[Block]], ValidationResult | Awaitable[ValidationResult]]
# prefer(current, candidate): the adoption rule, judged under the lock against the CURRENT chain.
Preference = Callable[[tuple[Block, ...], tuple[Block, ...]], bool]
ReplaceListener = Callable[[tuple[Block, ...]], None]


def _frozen(block: Block) -> Block:
  """Coerce the container fields to tuples, so nothing inside a held block can be mutated."""
  records, commits = block.document_records, block.commit_signatures
  if isinstance(records, tuple) and isinstance(commits, tuple):
    return block
  return dataclasses.replace(
    block, document_records=tuple(records), commit_signatures=tuple(commits)
  )


class ChainState:
  def __init__(
    self,
    blocks: Sequence[Block],
    *,
    valid: bool,
    store: ChainStore,
    validator: ChainValidator,
    validity_cache: ValidityCache,
    documents: DocumentIndex,
    mempool: Mempool,
    requeue_dropped: bool = True,
  ) -> None:
    """`requeue_dropped`: put records of blocks dropped by a replace back into the mempool.
    PoW only - under PBFT a non-primary never holds records in its mempool (FR-22)."""
    if not blocks:
      raise ValueError("a chain always holds at least the genesis block")
    self._blocks: tuple[Block, ...] = tuple(_frozen(b) for b in blocks)
    self._extendable = valid
    self._store = store
    self._validator = validator
    self._cache = validity_cache
    self._documents = documents
    self._mempool = mempool
    self._requeue = requeue_dropped
    self._lock = asyncio.Lock()
    self._listeners: list[ReplaceListener] = []
    self._generation = 0

  # -------------------------------------------------------------------- read view

  @property
  def blocks(self) -> tuple[Block, ...]:
    """A consistent view: the tuple is never mutated, a later append/replace rebinds it."""
    return self._blocks

  @property
  def tip(self) -> Block:
    return self._blocks[-1]

  @property
  def extendable(self) -> bool:
    """False while the local chain is invalid: nothing may be appended to it."""
    return self._extendable

  @property
  def locked(self) -> bool:
    return self._lock.locked()

  @property
  def generation(self) -> int:
    """Grows on every append and replace: a consensus round started at an older generation is
    working on a chain that is no longer current."""
    return self._generation

  @property
  def trusted_blocks(self) -> tuple[Block, ...]:
    """The part of the chain that passed validation: everything while it is valid, else the
    prefix before `first_invalid_index`. Sync judges a candidate against this, so a tampered
    local chain is healed only by a chain that beats its valid prefix - never rolled back to
    a shorter one (UC-3-G)."""
    blocks = self._blocks
    if self._extendable:
      return blocks
    first_invalid = self._cache.snapshot.first_invalid_index
    return blocks if first_invalid is None else blocks[: max(0, first_invalid)]

  def has_document(self, document_hash: str) -> bool:
    return self._documents.contains(document_hash)

  def document_positions(self, document_hash: str) -> list[int]:
    return self._documents.block_indexes(document_hash)

  def report_byzantine_event(self, reason: str, *, offender: str | None = None) -> None:
    """A safety violation (two differently-finalized PBFT blocks at one height, or a member
    signing two different votes for one slot): never resolved by a tie-break, only logged and
    surfaced as `quorum_status` plus an entry in the Byzantine event log."""
    logger.error("SAFETY VIOLATION (Byzantine event): %s", reason)
    self._cache.flag_byzantine_event(reason, offender=offender)

  def add_replace_listener(self, listener: ReplaceListener) -> None:
    """`listener(new_blocks)` runs inside the critical section after a successful replace, once
    all derived state is updated. It must not await `ChainState` (the lock is not reentrant): it
    only sets flags, wakes events or schedules tasks. A failing listener is logged and never
    undoes the replace."""
    self._listeners.append(listener)

  # --------------------------------------------------------------------- mutation

  async def append(self, block: Block) -> bool:
    """Append `block` if it extends the current tip and passes the FR-25 checklist.

    False (nothing changed) when the chain is not extendable, the block is not the tip's
    successor, or it fails validation. A persistence error propagates; the chain is unchanged.
    """
    block = _frozen(block)
    async with self._lock:
      tip = self._blocks[-1]
      if not self._extendable:
        return False
      if block.index != tip.index + 1 or block.previous_hash != tip.block_hash:
        return False  # not our next block (e.g. a replace moved the tip meanwhile)
      if any(self._documents.contains(r.document_hash) for r in block.document_records):
        logger.warning("rejected a block at height %d: re-issues a finalized hash", block.index)
        return False  # cross-block document_hash uniqueness (node-layer policy)
      result = self._validator.extension(tip, [block])
      if not result.valid:
        logger.warning("rejected a block at height %d: failed validation", block.index)
        return False
      position = len(self._blocks)
      new_blocks = (*self._blocks, block)
      snapshot = self._cache.plan_append(block, result)  # fallible work before the commit
      self._store.save(new_blocks)  # the commit point; only infallible steps follow
      self._blocks = new_blocks
      self._generation += 1
      self._cache.install(block, snapshot)
      self._documents.add_block(block, position)  # index first, then de-queue (no gap)
      self._mempool.remove([record.document_hash for record in block.document_records])
      return True

  async def replace(
    self,
    new_chain: Sequence[Block],
    validate: ChainCheck,
    *,
    prefer: Preference | None = None,
  ) -> bool:
    """Install `new_chain` if `validate` (the FR-25 checklist) accepts it.

    `prefer(current, candidate)` is the adoption rule; it runs under the lock against the chain
    current at that moment, so appends that landed while the caller waited for the lock count
    (a candidate that is no longer better is refused). A synchronous `validate` runs in a worker
    thread so a long full-from-genesis validation does not stall the event loop; the lock is
    held meanwhile, so queued appends wait and then run against whichever chain is current.
    Records of dropped blocks that the new chain does not hold go back to the mempool, so an
    acknowledged submission is never silently lost.
    """
    candidate = tuple(_frozen(b) for b in new_chain)  # validate and install this exact object
    async with self._lock:
      if not candidate:
        return False
      if prefer is not None and not prefer(self._blocks, candidate):
        return False
      if inspect.iscoroutinefunction(validate) or inspect.iscoroutinefunction(
        getattr(validate, "__call__", None)  # noqa: B004 - an object with an async __call__
      ):
        result = await validate(candidate)  # type: ignore[misc]
      else:
        outcome = await asyncio.to_thread(validate, candidate)
        result = await outcome if inspect.isawaitable(outcome) else outcome
      if not result.valid:
        logger.warning(
          "refused a replacement chain: %s at index %s",
          result.failure_type,
          result.first_invalid_index,
        )
        return False
      snapshot = self._cache.plan_replace(candidate, result)  # fallible work before the commit
      old = self.trusted_blocks  # only records of validated blocks may be re-queued
      self._store.save(candidate)  # the commit point; only infallible steps follow
      self._blocks = candidate
      self._extendable = True
      self._generation += 1
      self._cache.install(candidate[-1], snapshot)
      self._documents.reset(candidate)
      self._settle_mempool(old, candidate)
      for listener in self._listeners:
        try:
          listener(candidate)
        except Exception:
          logger.exception("a replace listener failed; the replace stands")
      return True

  def _settle_mempool(self, old: tuple[Block, ...], new: tuple[Block, ...]) -> None:
    """Records finalized by the new chain leave the mempool; under PoW, records of dropped
    blocks that the new chain does not hold are re-queued (ignoring the cap: already acked)."""
    kept = {record.document_hash for block in new for record in block.document_records}
    if self._requeue:
      for block in old:
        for record in block.document_records:
          digest = record.document_hash
          if digest not in kept and not self._mempool.contains(digest):
            self._mempool.add(record)
    self._mempool.remove(
      [r.document_hash for r in self._mempool.snapshot() if r.document_hash in kept]
    )
