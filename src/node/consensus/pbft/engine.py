"""PBFT three-phase engine: pre-prepare -> prepare -> commit (UC-6).

One round runs per sequence number `seq` (= the height of the next block) within the current
`view`. The primary of the view builds a candidate block and broadcasts `pre-prepare`; every
replica screens it with the single validation gateway and, if valid, broadcasts `prepare`; a
node that sees a prepare quorum broadcasts its `commit`; a node that holds a commit quorum
attaches the commit votes to the block (a new frozen `Block`, after hashing) and appends it
through `ChainState`, which re-validates it - quorum included - persists it and updates the
validity cache, the document index and the mempool.

Quorum is `ValidatorSet.quorum` from the core (`floor((n+f)/2)+1`, = 2f+1 for n = 3f+1),
counted over distinct ValidatorSet members (and distinct keys) only - never over PeerInfo
peers, which are never sent a PBFT message and whose PBFT messages are dropped.

Concurrency: link readers only pre-filter and enqueue (`submit`); one engine task owns all
round state, so a slow append or send never stalls a peer link. Sends are fire-and-forget.

Safety rules: one candidate per `(view, seq)` - the first valid pre-prepare from the primary is
locked and a primary never proposes a second, different block for a `(view, seq)` it already
proposed; at most one vote per member per phase is counted (a conflicting second vote is kept
as evidence and logged); this node never signs two different hashes for one `(view, seq)`.

Scope (Slice 17): the view is fixed (view change, round timeouts and equivocation REPORTING
are Slice 18), so a round whose primary is down, or whose candidate went stale under a sync
replace, waits for the view change. Round state is in memory only: a node restarted mid-round
forgets its votes (documented limitation; a restarted primary's new candidate is not
accepted by replicas that locked the old one until the view changes).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import Counter, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from blockchain_core import (
  Block,
  CommitSignature,
  DocumentRecord,
  InvalidRecordSignatureError,
  attach_proposer_signature,
  build_candidate_block,
  commit_payload,
  public_key_to_pem,
  verify_canonical,
)
from blockchain_core.storage.chain_store import block_from_dict, block_to_dict
from node.consensus.pbft.messages import (
  COMMIT,
  PRE_PREPARE,
  PREPARE,
  Kind,
  PbftMessage,
  make_message,
  matches_block,
  verify_message,
)
from node.metrics import ConsensusMetric

if TYPE_CHECKING:
  from node.main import NodeContext

logger = logging.getLogger("node.pbft")

DEFAULT_MAX_BATCH = 500
DEFAULT_RESEND_S = 1.0
RETRY_SECONDS = 1.0
TRANSIENT_REASONS = frozenset({"timestamp_in_future", "timestamp_too_old"})
MAX_INBOX = 1024
MAX_INBOX_PER_SENDER = 128

Send = Callable[[dict[str, Any]], Awaitable[object]]


def _wall_ms() -> int:
  return int(time.time() * 1000)


@dataclass
class Round:
  """Votes for one `(view, seq)`. At most ONE vote per member per phase is ever counted."""

  view: int
  seq: int
  candidate: Block | None = None  # the locked pre-prepared block, once screened as valid
  rejected: set[str] = field(default_factory=set)  # candidate hashes that failed screening
  prepares: dict[str, str] = field(default_factory=dict)  # node_id -> block_hash
  commits: dict[str, tuple[str, str]] = field(default_factory=dict)  # node_id -> (hash, sig)
  verified_commits: dict[str, bool] = field(default_factory=dict)  # node_id -> signature ok
  conflicts: list[tuple[Kind, str, str, str]] = field(default_factory=list)  # evidence
  conflicted: set[tuple[Kind, str]] = field(default_factory=set)  # bounds `conflicts`
  prepared: bool = False
  finalizing: bool = False
  failed_votes: frozenset[str] | None = None  # a vote set whose block `ChainState` refused
  outbox: list[dict[str, Any]] = field(default_factory=list)  # our own messages, for resend
  started_wall: int = 0


class PbftEngine:
  def __init__(
    self,
    context: NodeContext,
    *,
    send: Send,
    on_finalized: Callable[[Block], Awaitable[object]] | None = None,
    flag: Callable[[str, str], None] = lambda _peer, _reason: None,
    on_needs_sync: Callable[[str], None] | None = None,
    view: int = 0,
    max_batch: int = DEFAULT_MAX_BATCH,
    resend_s: float = DEFAULT_RESEND_S,
    now_ms: Callable[[], int] = _wall_ms,
    monotonic: Callable[[], float] = time.monotonic,
  ) -> None:
    validator_set = context.validator.validator_set
    if validator_set is None:
      raise ValueError("PBFT needs a ValidatorSet")
    if max_batch < 1 or resend_s <= 0:
      raise ValueError("max_batch must be >= 1 and resend_s > 0")
    self._context = context
    self._chain_state = context.chain_state
    self._validator_set = validator_set
    self._send = send
    self._on_finalized = on_finalized
    self._flag = flag
    self._on_needs_sync = on_needs_sync
    self._view = view
    self._max_batch = max_batch
    self._resend_s = resend_s
    self._now_ms = now_ms
    self._monotonic = monotonic
    self._self_id = context.config.node_id
    self._key = context.state.node_key.private_key
    self._rounds: dict[tuple[int, int], Round] = {}
    self._proposed: dict[tuple[int, int], Block] = {}  # survives abandon: never re-propose
    self._signed: dict[tuple[int, int], str] = {}  # never sign two hashes per (view, seq)
    self._ahead: dict[tuple[str, Kind], PbftMessage] = {}  # one-height look-ahead buffer
    self._inbox: deque[PbftMessage] = deque()
    self._queued: Counter[str] = Counter()
    self._stale_logged: set[tuple[int, int]] = set()
    self._seen_generation = self._chain_state.generation
    self._wake = asyncio.Event()
    self._task: asyncio.Task[None] | None = None
    self._sends: set[asyncio.Task[Any]] = set()
    self._last_resend = 0.0
    self._last_sync_hint = float("-inf")
    self.finalized_rounds = 0
    # A sync replace mid-round (UC-17 side effect): the listener runs inside the ChainState
    # lock, so it only wakes the engine; the engine task drops the stale round itself.
    self._chain_state.add_replace_listener(lambda _blocks: self._wake.set())

  # ---------------------------------------------------------------- views / roles

  @property
  def view(self) -> int:
    return self._view

  @property
  def quorum(self) -> int:
    return self._validator_set.quorum

  def members(self) -> list[str]:
    """ValidatorSet members whose key is in force at the tip's timestamp - chain data, so
    every node at the same tip computes the same list - in a fixed order."""
    at = self._chain_state.tip.timestamp
    resolver = self._context.resolvers.current
    return sorted(
      m for m in self._validator_set.members if resolver.resolve_node_key(m, at) is not None
    )

  def primary_of(self, view: int) -> str | None:
    """Round-robin `view mod n` over the members; None (fail closed) without a quorum of them."""
    members = self.members()
    if len(members) < self.quorum:
      return None
    return members[view % len(members)]

  @property
  def is_primary(self) -> bool:
    return self.primary_of(self._view) == self._self_id

  def round(self, seq: int) -> Round | None:
    return self._rounds.get((self._view, seq))

  # ------------------------------------------------------------- engine interface

  def on_submission(self, record: DocumentRecord) -> None:
    self._wake.set()

  async def on_inbound_block(self, block: Block) -> bool:
    """A finalized block from a peer (WS /ws/blocks): `ChainState` re-checks it, quorum
    included. The engine task notices the moved tip and closes our round for that height."""
    try:
      adopted = await self._chain_state.append(block)
    except Exception:
      logger.exception("could not persist/append block %d", block.index)
      return False
    if adopted:
      self._wake.set()
    return adopted

  async def start(self) -> None:
    if self._task is None:
      self._task = asyncio.create_task(self._run(), name="pbft-engine")

  async def stop(self) -> None:
    task, self._task = self._task, None
    tasks = [*self._sends, *([task] if task is not None else [])]
    for job in tasks:
      job.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

  def submit(self, message: PbftMessage) -> None:
    """Called by the link reader with a decoded message whose `node_id` is the authenticated
    sender. Only cheap, crypto-free filters run here; the engine task does the rest."""
    sender = message.node_id
    if sender == self._self_id or message.view != self._view:
      return  # other views belong to the view change (Slice 18)
    if message.seq <= self._chain_state.tip.index:
      return  # already final here
    if (
      message.kind == PRE_PREPARE
      and message.seq == self._chain_state.tip.index + 1
      and sender != self.primary_of(message.view)
    ):
      self._flag(sender, "pre-prepare from a node that is not the primary")
      return
    if len(self._inbox) >= MAX_INBOX or self._queued[sender] >= MAX_INBOX_PER_SENDER:
      self._flag(sender, "pbft inbox full; message dropped")
      return
    self._queued[sender] += 1
    self._inbox.append(message)
    self._wake.set()

  # ------------------------------------------------------------------ main loop

  async def _run(self) -> None:
    while True:
      self._wake.clear()  # before the step: a wake set while it runs is kept
      try:
        await self._step()
      except Exception:
        logger.exception("PBFT engine step failed")
        await asyncio.sleep(RETRY_SECONDS)
      if self._inbox:
        continue
      remaining = max(0.0, self._resend_s - (self._monotonic() - self._last_resend))
      with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(remaining):
          await self._wake.wait()

  async def _step(self) -> None:
    self._tip_moved()
    while self._inbox:
      message = self._inbox.popleft()
      self._queued[message.node_id] -= 1
      if self._queued[message.node_id] <= 0:
        del self._queued[message.node_id]
      await self._process(message)
      self._tip_moved()
    if self.is_primary and self._chain_state.extendable:
      await self._propose()
    if self._monotonic() - self._last_resend >= self._resend_s:
      self._last_resend = self._monotonic()
      self._resend()
      current = self.round(self._chain_state.tip.index + 1)
      if current is not None:
        current.failed_votes = None  # a refused vote set may be retried once per tick
        await self._advance(current)

  # ---------------------------------------------------------------- proposing

  def _next_batch(self) -> list[DocumentRecord]:
    mempool = self._context.mempool
    stale = [
      r.document_hash for r in mempool.snapshot() if self._chain_state.has_document(r.document_hash)
    ]
    if stale:  # finalized meanwhile
      mempool.remove(stale)
    return mempool.snapshot()[: self._max_batch]

  async def _propose(self) -> None:
    tip = self._chain_state.tip
    seq = tip.index + 1
    current = self._round_for(seq)
    if current.candidate is not None:
      return  # one proposal per (view, seq)
    earlier = self._proposed.get((self._view, seq))
    if earlier is not None:
      # Never a second, different pre-prepare for one (view, seq): re-send the same block if
      # it still extends the tip, else wait for the view change (Slice 18).
      if earlier.previous_hash != tip.block_hash:
        if (self._view, seq) not in self._stale_logged:
          self._stale_logged.add((self._view, seq))
          logger.warning(
            "view %d: proposal %d went stale; waiting for a view change", self._view, seq
          )
        return
      block = earlier
    else:
      batch = self._next_batch()
      if not batch:
        return
      try:
        candidate = build_candidate_block(
          batch,
          previous_hash=tip.block_hash,
          index=seq,
          timestamp=max(self._now_ms(), tip.timestamp),
          proposer_id=self._self_id,
          algorithm="pbft",
          sealed_consensus={"view_number": self._view},
          resolve_issuer_key=self._context.resolvers.current.resolve_issuer_key,
        )
      except InvalidRecordSignatureError as exc:
        logger.error(
          "dropping a pending record with an invalid signature (batch index %d)", exc.index
        )
        self._context.mempool.remove([batch[exc.index].document_hash])
        self._wake.set()
        return
      block = attach_proposer_signature(candidate, self._key)
      self._proposed[(self._view, seq)] = block
      logger.info("view %d: proposing block %d with %d record(s)", self._view, seq, len(batch))
    message = self._sign(PRE_PREPARE, seq, block, payload=block_to_dict(block))
    if message is None:
      return
    current.candidate = block
    current.started_wall = self._now_ms()
    self._emit(current, message)
    await self._advance(current)

  # ---------------------------------------------------------------- sending

  def _sign(self, kind: Kind, seq: int, block: Block, *, payload: Any = None) -> PbftMessage | None:
    """Our vote of `kind` for `block` - refused if we already signed another hash here."""
    key = (self._view, seq)
    held = self._signed.get(key)
    if held is not None and held != block.block_hash:
      logger.error("refusing to sign a second %s for (%d, %d)", kind, self._view, seq)
      return None
    self._signed[key] = block.block_hash
    return make_message(
      kind,
      self._key,
      view=self._view,
      seq=seq,
      block_hash=block.block_hash,
      node_id=self._self_id,
      block=payload,
    )

  def _emit(self, current: Round, message: PbftMessage) -> None:
    wire = message.to_wire()
    current.outbox.append(wire)
    self._spawn_send(wire)

  def _spawn_send(self, wire: dict[str, Any]) -> None:
    task = asyncio.get_running_loop().create_task(self._send(wire))
    self._sends.add(task)
    task.add_done_callback(self._sends.discard)

  def _resend(self) -> None:
    """Re-send our own messages of the open round: covers a link that came up late, or a
    message lost with a broken link. Receivers treat repeats as no-ops."""
    current = self.round(self._chain_state.tip.index + 1)
    if current is not None and not current.finalizing:
      for wire in current.outbox:
        self._spawn_send(wire)

  # -------------------------------------------------------------- inbound messages

  async def _process(self, message: PbftMessage) -> None:
    sender = message.node_id
    if sender not in self._validator_set.members:
      self._flag(sender, "pbft message from a non-validator")  # PeerInfo never votes
      return
    next_seq = self._chain_state.tip.index + 1
    if message.seq < next_seq:
      return
    if message.seq > next_seq + 1:
      now = self._monotonic()
      if (
        self._on_needs_sync is not None
        and now - self._last_sync_hint >= self._resend_s
        and self._verified(message)
      ):
        self._last_sync_hint = now
        self._on_needs_sync(sender)
      return
    if message.seq == next_seq + 1:
      # A faster peer is one height ahead: keep its latest message per kind (bounded) and
      # replay it once our tip catches up.
      if message.kind == COMMIT or self._verified(message):
        self._ahead[(sender, message.kind)] = message
      return
    current = self._round_for(message.seq)
    if message.kind == PRE_PREPARE:
      await self._on_pre_prepare(current, message)
    elif message.kind == PREPARE:
      self._on_prepare(current, message)
    else:
      self._on_commit(current, message)
    await self._advance(current)

  def _verified(self, message: PbftMessage) -> bool:
    key = self._context.resolvers.current.resolve_node_key(message.node_id, self._now_ms())
    if key is None or not verify_message(message, key):
      self._flag(message.node_id, f"{message.kind}: bad signature")
      return False
    return True

  async def _on_pre_prepare(self, current: Round, message: PbftMessage) -> None:
    sender = message.node_id
    primary = self.primary_of(message.view)
    if sender != primary:
      self._flag(sender, "pre-prepare from a node that is not the primary")
      return
    if current.candidate is not None:  # the candidate of a (view, seq) is locked
      if (
        current.candidate.block_hash != message.block_hash
        and (PRE_PREPARE, sender) not in current.conflicted
        and self._verified(message)
      ):
        self._conflict(current, message, current.candidate.block_hash)
      return
    if current.rejected:
      # An honest primary sends ONE candidate per (view, seq): after a rejected one, nothing
      # else is screened for this slot (no repeated crypto / validation work).
      return
    records = message.block.get("document_records")
    if not isinstance(records, list) or len(records) > self._max_batch:
      self._reject_candidate(current, message, "malformed or oversized block")
      return
    if not self._verified(message):
      return
    try:
      block = block_from_dict(message.block)
    except Exception:
      self._reject_candidate(current, message, "malformed block")
      return
    if not matches_block(message, block):
      self._reject_candidate(current, message, "block does not match (view, seq, block_hash)")
      return
    # pure and CPU-heavy (up to one signature check per record): off the event loop
    verdict = await asyncio.to_thread(
      self._context.gateway.screen_candidate,
      block,
      primary_id=primary,
      view=message.view,
      known=self._chain_state.has_document,
    )
    if verdict.reason in TRANSIENT_REASONS:
      # a clock difference or a late re-send, not proof of a faulty primary: not locked out
      logger.info("pre-prepare %d not accepted yet: %s", message.seq, verdict.reason)
      return
    if not verdict.accepted:  # UC-6-E1: an invalid candidate gets no prepare from us
      self._reject_candidate(current, message, verdict.reason)
      return
    if self.round(message.seq) is not current or current.candidate is not None:
      return  # the tip moved or a candidate was locked while we screened
    vote = self._sign(PREPARE, message.seq, block)
    if vote is None:
      current.rejected.add(message.block_hash)  # never re-screened on every resend
      return
    current.candidate = block
    current.started_wall = self._now_ms()
    current.prepares[self._self_id] = block.block_hash
    self._emit(current, vote)

  def _reject_candidate(self, current: Round, message: PbftMessage, reason: str) -> None:
    current.rejected.add(message.block_hash)
    self._flag(message.node_id, f"pre-prepare rejected: {reason}")

  def _on_prepare(self, current: Round, message: PbftMessage) -> None:
    sender = message.node_id
    if sender == self.primary_of(message.view):
      # The primary never sends a prepare: its pre-prepare already is its prepare vote.
      self._flag(sender, "prepare from the primary")
      return
    held = current.prepares.get(sender)
    if held == message.block_hash:
      return  # duplicate delivery: no-op
    if held is not None and (PREPARE, sender) in current.conflicted:
      return  # its equivocation is already on record: no more crypto for this slot
    if not self._verified(message):
      return
    if held is None:
      current.prepares[sender] = message.block_hash
    else:
      self._conflict(current, message, held)

  def _on_commit(self, current: Round, message: PbftMessage) -> None:
    # The commit signature covers only `commit_payload(block_hash)` and is checked at counting
    # time with the key in force at the CANDIDATE's timestamp - exactly as the core will.
    held = current.commits.get(message.node_id)
    if held is None:
      current.commits[message.node_id] = (message.block_hash, message.signature)
    elif held[0] != message.block_hash and (COMMIT, message.node_id) not in current.conflicted:
      self._conflict(current, message, held[0])

  def _conflict(self, current: Round, message: PbftMessage, first: str) -> None:
    """A second, different vote from one member: the first stays counted; this one is kept
    as evidence (bounded) for the equivocation reporting of Slice 18."""
    current.conflicted.add((message.kind, message.node_id))  # one piece of evidence each
    current.conflicts.append((message.kind, message.node_id, first, message.block_hash))
    logger.warning(
      "%s sent conflicting %s votes for (%d, %d); the first is kept",
      message.node_id,
      message.kind,
      message.view,
      message.seq,
    )

  # ---------------------------------------------------------------- quorum logic

  def prepare_votes(self, current: Round) -> int:
    """Distinct members that prepared the candidate. Counting rule (UC-6 step 3, closes M-7):
    the primary's pre-prepare IS its prepare vote - it is counted here once, implicitly - and
    the primary never sends (and we never count) a separate prepare message from it."""
    if current.candidate is None:
      return 0
    target = current.candidate.block_hash
    proposer = current.candidate.proposer_id  # screened == primary when the candidate locked
    explicit = sum(
      1
      for node_id, voted in current.prepares.items()
      if voted == target and node_id != proposer and node_id in self._validator_set.members
    )
    return 1 + explicit

  def commit_votes(self, current: Round) -> dict[str, str]:
    """Matching, valid commit votes by member - one per member AND per key, verified at the
    candidate's timestamp, the same rule the core's quorum check applies. Counted only once
    THIS node is prepared: a commit received earlier is held, never acted on, so commits
    alone can never finalize a block (phase ordering, UC-6-E3)."""
    candidate = current.candidate
    if candidate is None or not current.prepared:
      return {}
    payload = commit_payload(candidate.block_hash)
    resolver = self._context.resolvers.current
    counted: dict[str, str] = {}
    keys: set[bytes] = set()
    for node_id, (voted, signature) in sorted(current.commits.items()):
      if voted != candidate.block_hash or node_id not in self._validator_set.members:
        continue
      key = resolver.resolve_node_key(node_id, candidate.timestamp)
      if key is None:
        continue
      fingerprint = public_key_to_pem(key)
      if fingerprint in keys:
        continue
      ok = current.verified_commits.get(node_id)
      if ok is None:
        ok = current.verified_commits[node_id] = verify_canonical(key, payload, signature)
        if not ok:
          self._flag(node_id, "commit: bad signature")
      if ok:
        counted[node_id] = signature
        keys.add(fingerprint)
    return counted

  async def _advance(self, current: Round) -> None:
    candidate = current.candidate
    if candidate is None or current.finalizing:
      return
    if not current.prepared and self.prepare_votes(current) >= self.quorum:
      vote = self._sign(COMMIT, current.seq, candidate)
      if vote is None:
        return
      current.prepared = True
      current.commits[self._self_id] = (candidate.block_hash, vote.signature)
      self._emit(current, vote)
    votes = self.commit_votes(current)
    if len(votes) >= self.quorum and frozenset(votes) != current.failed_votes:
      await self._finalize(current, candidate, votes)

  async def _finalize(self, current: Round, candidate: Block, votes: dict[str, str]) -> None:
    current.finalizing = True
    block = replace(  # attestations are attached after hashing, on a new frozen Block
      candidate,
      commit_signatures=tuple(
        CommitSignature(node_id=node_id, signature=sig) for node_id, sig in sorted(votes.items())
      ),
    )
    try:
      adopted = await self._chain_state.append(block)
    except Exception:
      logger.exception("could not persist/append finalized block %d", block.index)
      current.finalizing = False  # the next message or the resend tick retries
      return
    if not adopted:
      if self._chain_state.tip.index < block.index:  # not a lost race: the block was refused
        logger.error("finalized block %d was refused by ChainState; round kept open", block.index)
        current.failed_votes = frozenset(votes)
      current.finalizing = False
      return
    self.finalized_rounds += 1
    self._context.metrics.record(
      ConsensusMetric(
        block_index=block.index,
        algorithm="pbft",
        proposed_at=current.started_wall,
        finalized_at=self._now_ms(),
        attempts_or_rounds=1,
      )
    )
    logger.info(
      "view %d: block %d finalized with %d commit(s)", current.view, block.index, len(votes)
    )
    if self._on_finalized is not None:
      task = asyncio.get_running_loop().create_task(self._on_finalized(block))
      self._sends.add(task)
      task.add_done_callback(self._sends.discard)

  # ------------------------------------------------------------------ tip changes

  def _round_for(self, seq: int) -> Round:
    key = (self._view, seq)
    current = self._rounds.get(key)
    if current is None:
      current = self._rounds[key] = Round(view=self._view, seq=seq)
    return current

  def _tip_moved(self) -> None:
    """After an append or a sync replace: drop every round the chain has moved past (a round
    whose candidate no longer extends the tip is abandoned), and replay the look-ahead
    messages for the new next height. The primary then proposes on the new tip."""
    generation = self._chain_state.generation
    if generation == self._seen_generation:
      return
    self._seen_generation = generation
    tip = self._chain_state.tip
    next_seq = tip.index + 1
    for key, current in list(self._rounds.items()):
      stale_parent = (
        current.candidate is not None and current.candidate.previous_hash != tip.block_hash
      )
      if current.seq != next_seq or stale_parent:
        if current.seq >= next_seq and current.candidate is not None:
          logger.info("round %d abandoned: the chain moved under it", current.seq)
        del self._rounds[key]
    for stale in [k for k in self._proposed if k[1] <= tip.index]:
      del self._proposed[stale]
    for stale_key in [k for k in self._signed if k[1] <= tip.index]:
      del self._signed[stale_key]
    self._stale_logged = {k for k in self._stale_logged if k[1] > tip.index}
    ready = [m for m in self._ahead.values() if m.seq == next_seq]
    self._ahead = {k: m for k, m in self._ahead.items() if m.seq > next_seq}
    # pre-prepare first, so the candidate exists when the votes arrive
    for message in sorted(ready, key=lambda m: m.kind == PRE_PREPARE):
      self._inbox.appendleft(message)
      self._queued[message.node_id] += 1
    self._wake.set()
