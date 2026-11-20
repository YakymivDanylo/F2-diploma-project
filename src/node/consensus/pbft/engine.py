"""PBFT engine: pre-prepare -> prepare -> commit rounds (UC-6) and the view change (UC-6-D).

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

View change (Slice 18, see `view_change.py`): a node votes to leave its view when the open
round has made no progress for `round_timeout_s`, when the primary's link has been down that
long, or at once when the primary proposes an invalid block. A view is installed on a quorum
of votes; its primary is `members[view mod n]`. Safety across views rests on LOCKS: a node
that becomes prepared on a block records the prepared certificate (the primary's pre-prepare
signature plus a quorum of prepares) and from then on prepares at that height only that block,
unless a later view brings a certificate from a HIGHER view. View-change votes carry the
voter's lock; the new primary re-proposes the block with the highest certified view, so a block
that may be final somewhere is never replaced. Votes and the lock are persisted (atomically,
before a vote is sent), so a restarted node keeps them. There is no state transfer, checkpoint
or watermark protocol (intentional simplification, UC-6-D): lagging nodes catch up by sync.
A missing state file is accepted only on a fresh chain (or with `allow_missing_state`, the
operator's explicit `PBFT_ALLOW_MISSING_STATE`); otherwise the engine refuses to start.

Faults are classified, never conflated (UC-6-E2 vs UC-6-E5): a member that signs two
different votes for one slot is reported as a Byzantine event (sticky); too few responsive
members is reported as `crash_fault_quorum_loss`; an open view change as
`view_change_in_progress`; one member down is normal operation. Byzantine events (the engine's
own and those `ChainState` reports from sync) are persisted with the voting state and restored
into the validity cache on restart, so the sticky status survives it; only the operator's
explicit `reset_byzantine_events` (`BYZANTINE_RESET_ON_BOOT`) drops them on a boot, and only
when it names the DIGEST of exactly the persisted event list (`byzantine_reset_token`, logged
at every boot that restores events): a one-shot token, so a value left in an env file is refused
as soon as the evidence changed in any way.

Round state and the pure counting rules live in `rounds.py`.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import Counter, deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from blockchain_core import (
  MAX_BLOCK_RECORDS,
  Block,
  CommitSignature,
  DocumentRecord,
  InvalidRecordSignatureError,
  attach_proposer_signature,
  build_candidate_block,
  commit_payload,
  sha256_of_canonical,
  verify_canonical,
)
from blockchain_core.storage.chain_store import block_from_dict, block_to_dict
from node.consensus.pbft.messages import (
  COMMIT,
  NEW_VIEW,
  NO_BLOCK,
  PRE_PREPARE,
  PREPARE,
  VIEW_CHANGE,
  Kind,
  PbftMessage,
  PreparedCert,
  block_view,
  decode_cert,
  decode_message,
  make_message,
  matches_block,
  verify_cert,
  verify_message,
  verify_vote,
)
from node.consensus.pbft.rounds import (
  Lock,
  Round,
  build_certificate,
  count_prepare_votes,
  key_id,
  verified_commit_votes,
)
from node.consensus.pbft.state_store import PbftState, PbftStateError, PbftStateStore
from node.consensus.pbft.view_change import MAX_VIEWS_AHEAD, ViewChangeState
from node.metrics import ConsensusMetric
from node.validity_cache import QUORUM_CRASH_LOSS, QUORUM_HEALTHY, QUORUM_VIEW_CHANGE

if TYPE_CHECKING:
  from node.context import NodeContext

logger = logging.getLogger("node.pbft")

__all__ = ["Lock", "PbftEngine", "Round"]

DEFAULT_MAX_BATCH = MAX_BLOCK_RECORDS  # a block never holds more (the core refuses it)
DEFAULT_RESEND_S = 1.0
# Only the constructor's fallback (tests): the source of truth is config's PBFT_ROUND_TIMEOUT_S,
# which `node.main` always passes as `round_timeout_s`.
DEFAULT_ROUND_TIMEOUT_S = 5.0
RETRY_SECONDS = 1.0
TRANSIENT_REASONS = frozenset({"timestamp_in_future", "timestamp_too_old"})
MAX_INBOX = 1024
MAX_INBOX_PER_SENDER = 128
MAX_WATCHED = 1024
CENSORSHIP_TIMEOUTS = 3  # round timeouts a forwarded, accepted record may take to finalize
MAX_NEW_VIEW_JUMP = 1024  # a proof is quorum-signed; this only bounds the work per message

RESET_TOKEN = re.compile(r"^[0-9a-f]{16}$")  # BYZANTINE_RESET_ON_BOOT


def byzantine_reset_token(events: list[dict[str, Any]]) -> str:
  """The one-shot `BYZANTINE_RESET_ON_BOOT` token for exactly this persisted event list (as
  stored): the first 16 hex chars of SHA-256 over its canonical JSON. Any change to the
  evidence - a new event, or one replaced under the per-offender cap - changes the token, so a
  forgotten value can never erase newer evidence."""
  return sha256_of_canonical(events)[:16]


# send(message, targets): targets None = every ValidatorSet member
Send = Callable[[dict[str, Any], Iterable[str] | None], Awaitable[object]]


def _wall_ms() -> int:
  return int(time.time() * 1000)


class PbftEngine:
  def __init__(
    self,
    context: NodeContext,
    *,
    send: Send,
    on_finalized: Callable[[Block], Awaitable[object]] | None = None,
    flag: Callable[[str, str], None] = lambda _peer, _reason: None,
    on_needs_sync: Callable[[str], None] | None = None,
    peer_up: Callable[[], Iterable[str]] | None = None,
    state_store: PbftStateStore | None = None,
    view: int = 0,
    max_batch: int = DEFAULT_MAX_BATCH,
    resend_s: float = DEFAULT_RESEND_S,
    round_timeout_s: float = DEFAULT_ROUND_TIMEOUT_S,
    allow_missing_state: bool = False,
    reset_byzantine_events: str | None = None,
    now_ms: Callable[[], int] = _wall_ms,
    monotonic: Callable[[], float] = time.monotonic,
  ) -> None:
    validator_set = context.validator.validator_set
    if validator_set is None:
      raise ValueError("PBFT needs a ValidatorSet")
    if reset_byzantine_events is not None and not (
      isinstance(reset_byzantine_events, str) and RESET_TOKEN.fullmatch(reset_byzantine_events)
    ):
      raise ValueError("reset_byzantine_events must be a 16-hex-char reset token")
    if not 1 <= max_batch <= MAX_BLOCK_RECORDS or resend_s <= 0 or round_timeout_s <= 0:
      raise ValueError(
        f"max_batch must be in 1..{MAX_BLOCK_RECORDS}, resend_s and round_timeout_s > 0"
      )
    self._context = context
    self._chain_state = context.chain_state
    self._validator_set = validator_set
    self._send = send
    self._on_finalized = on_finalized
    self._flag = flag
    self._on_needs_sync = on_needs_sync
    self._peer_up = peer_up if peer_up is not None else (lambda: validator_set.members)
    self._store = state_store
    self._max_batch = max_batch
    self._resend_s = resend_s
    self._round_timeout_s = round_timeout_s
    self._now_ms = now_ms
    self._monotonic = monotonic
    self._self_id = context.config.node_id
    self._key = context.state.node_key.private_key

    if allow_missing_state:  # a forgotten flag in an env file silently disables the guard
      logger.warning(
        "PBFT_ALLOW_MISSING_STATE is set: a missing PBFT state file will NOT stop this node "
        "(risk of a conflicting vote); unset it after the one start it was meant for"
      )
    persisted = self._load_state(state_store, allow_missing_state)
    self._persisted = persisted
    if not self._reset_byzantine_events(state_store, persisted, reset_byzantine_events):
      # Events observed before a restart: sticky status and evidence back, not re-reported.
      context.validity_cache.restore_byzantine_events(persisted.byzantine_events)
    self._signed = persisted.signed  # never sign two hashes per (view, seq) - durable
    self._lock: Lock | None = None
    tip_view = self._tip_view()
    self._vc = ViewChangeState(
      self_id=self._self_id,
      quorum=validator_set.quorum,
      f=context.validators.f,
      view=max(view, persisted.view, tip_view),
    )

    self._rounds: dict[tuple[int, int], Round] = {}
    self._proposed: dict[tuple[int, int], Block] = {}  # never re-propose another block
    self._ahead: dict[tuple[str, Kind], PbftMessage] = {}  # one-height look-ahead buffer
    self._future: dict[tuple[str, Kind], PbftMessage] = {}  # messages of a higher view
    self._install_support: tuple[PbftMessage, ...] = ()  # full votes our view installed on
    self._inbox: deque[PbftMessage] = deque()
    self._queued: Counter[str] = Counter()
    self._stale_logged: set[tuple[int, int]] = set()
    self._seen_generation = self._chain_state.generation
    self._wake = asyncio.Event()
    self._task: asyncio.Task[None] | None = None
    self._sends: set[asyncio.Task[Any]] = set()
    self._last_resend = 0.0
    self._last_sync_hint = float("-inf")
    self._vc_wire: dict[str, Any] | None = None
    self._vc_started = 0.0
    self._vc_reason = ""
    self._primary_down_since: float | None = None
    self._peers_seen: set[str] = set()
    self._new_view_sent: dict[str, float] = {}
    self._new_view_seen: dict[str, float] = {}
    self._liveness = QUORUM_HEALTHY
    self._dirty = False
    self.finalized_rounds = 0
    self.view_changes = 0
    self._watched: dict[str, tuple[float, int]] = {}  # forwarded hash -> (deadline, view)
    self._lock = self._restore_lock(persisted.lock)
    self._restore_view_change(persisted.vc_vote)
    # A sync replace mid-round (UC-17 side effect): the listener runs inside the ChainState
    # lock, so it only wakes the engine; the engine task drops the stale round itself.
    self._chain_state.add_replace_listener(lambda _blocks: self._wake.set())

  def _load_state(self, state_file: PbftStateStore | None, allow_missing: bool) -> PbftState:
    """The persisted voting state. A missing file on a chain past genesis fails CLOSED: this
    node may have voted at a height it has not finalized yet, and an empty state would let it
    sign a second vote for that `(view, seq)` or drop its lock. On a fresh chain (tip index 0)
    nothing can have been signed, so the file is created at once - a node that then syncs
    blocks and restarts before it ever votes still finds its (empty) state."""
    if state_file is None:
      return PbftState()
    if state_file.exists():
      return state_file.load()
    tip_index = self._chain_state.tip.index
    if tip_index > 0 and not allow_missing:
      raise PbftStateError(
        f"PBFT state file {state_file.path} is missing but the chain is at height {tip_index}: "
        "this node may already have voted, and starting with an empty state could make it "
        "sign a conflicting vote or forget its lock. Restore the file, or - only if you are "
        "sure the node never voted at the open height - set PBFT_ALLOW_MISSING_STATE=true "
        "for one start."
      )
    if tip_index > 0:
      logger.warning(
        "PBFT state file %s missing at height %d; starting empty (PBFT_ALLOW_MISSING_STATE)",
        state_file.path,
        tip_index,
      )
    state = PbftState()
    state_file.save(state)  # durable at once: a later restart finds it
    return state

  @staticmethod
  def _reset_byzantine_events(
    state_file: PbftStateStore | None, persisted: PbftState, token: str | None
  ) -> bool:
    """`BYZANTINE_RESET_ON_BOOT=<token>`: the operator has dealt with the reported safety
    violation. Every boot that finds persisted events logs their current token. Only when
    `token` equals it are the events dropped (not restored, and cleared from the state file at
    once), so the sticky status starts clean; the votes and the lock are kept untouched. Any
    other value is refused and nothing is discarded (a value forgotten in an env file must not
    erase evidence recorded since); False tells the caller to restore the events as usual."""
    events = persisted.byzantine_events
    current = byzantine_reset_token(events)
    if events:
      logger.warning(
        "%d persisted Byzantine event(s) restored as sticky evidence; after dealing with the "
        "incident, reset them once with BYZANTINE_RESET_ON_BOOT=%s (valid only for exactly "
        "these events) and unset it after that start",
        len(events),
        current,
      )
    if token is None:
      return False
    if token != current:
      logger.warning(
        "BYZANTINE_RESET_ON_BOOT=%s REFUSED: it does not match the %d persisted Byzantine "
        "event(s) (current token %s), so nothing is discarded (a stale value must not erase "
        "newer evidence)",
        token,
        len(events),
        current,
      )
      return False
    logger.warning(
      "BYZANTINE_RESET_ON_BOOT=%s: operator reset of the Byzantine status; %d persisted "
      "event(s) discarded: %s; unset the variable now",
      token,
      len(events),
      events,
    )
    if events:
      persisted.byzantine_events = []
      if state_file is not None:
        state_file.save(persisted)
    return True

  # ---------------------------------------------------------------- views / roles

  @property
  def view(self) -> int:
    return self._vc.view

  @property
  def quorum(self) -> int:
    return self._validator_set.quorum

  @property
  def view_change(self) -> ViewChangeState:
    return self._vc

  @property
  def lock(self) -> Lock | None:
    return self._lock

  @property
  def liveness(self) -> str:
    return self._liveness

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
    return self.primary_of(self.view) == self._self_id

  def primary_status(self) -> tuple[str, str | None]:
    """("self" | "other" | "none", primary id): "none" while a view change is open or no
    quorum of members is responsive - for the `forward_record` / `POST /documents`
    `not_primary` reply."""
    primary = self.primary_of(self.view)
    if primary is None or self._vc.in_progress or self._liveness == QUORUM_CRASH_LOSS:
      return "none", None
    return ("self", primary) if primary == self._self_id else ("other", primary)

  def round(self, seq: int, view: int | None = None) -> Round | None:
    return self._rounds.get((self.view if view is None else view, seq))

  # ------------------------------------------------------------- engine interface

  def on_submission(self, record: DocumentRecord) -> None:
    self._wake.set()

  def watch_forwarded(self, document_hash: str, primary_id: str) -> None:
    """`primary_id` accepted a record we forwarded. If it is not finalized within a few round
    timeouts while that primary stays - and blocks it finalizes meanwhile had room for it -
    we vote to change the view (a censoring primary, UC-16-EC6). The record itself is not
    resurrected: the client must resubmit."""
    if self.primary_of(self.view) != primary_id:
      return  # the view moved while we forwarded: that primary is gone anyway
    if len(self._watched) >= MAX_WATCHED:
      self._watched.pop(next(iter(self._watched)))
    deadline = self._monotonic() + CENSORSHIP_TIMEOUTS * self._round_timeout_s
    self._watched[document_hash] = (deadline, self.view)
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
    if sender == self._self_id:
      return
    if message.kind not in (VIEW_CHANGE, NEW_VIEW):
      if message.view > self.view + MAX_VIEWS_AHEAD:
        return
      if message.seq <= self._chain_state.tip.index:
        return  # already final here
      if (
        message.kind == PRE_PREPARE
        and message.view == self.view
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
      try:
        async with asyncio.timeout(remaining):
          await self._wake.wait()
      except TimeoutError:
        pass

  async def _step(self) -> None:
    self._tip_moved()
    while self._inbox:
      message = self._inbox.popleft()
      self._queued[message.node_id] -= 1
      if self._queued[message.node_id] <= 0:
        del self._queued[message.node_id]
      await self._process(message)
      self._tip_moved()
    if self._persisted.byzantine_events != self._context.validity_cache.byzantine_events:
      self._dirty = True  # an event ChainState reported (e.g. from sync): persist it too
    if self._dirty:
      self._dirty = False
      await self._persist()
    self._watch_peers()
    await self._view_change_step()
    if not self._vc.in_progress and self.is_primary and self._chain_state.extendable:
      await self._propose()
    if self._monotonic() - self._last_resend >= self._resend_s:
      self._last_resend = self._monotonic()
      self._resend()
      for current in self._open_rounds():
        current.failed_votes = None  # a refused vote set may be retried once per tick
        await self._advance(current)
    self._update_liveness()

  def _open_rounds(self) -> list[Round]:
    next_seq = self._chain_state.tip.index + 1
    return [r for r in self._rounds.values() if r.seq == next_seq]

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
    seq, view = tip.index + 1, self.view
    current = self._round_for(seq)
    if current.candidate is not None:
      return  # one proposal per (view, seq)
    carried = self._carried_choice(seq)
    cert: PreparedCert | None = None
    earlier = self._proposed.get((view, seq))
    if earlier is not None:
      # Never a second, different pre-prepare for one (view, seq): re-send the same block if
      # it still extends the tip, else let the view change move on.
      if earlier.previous_hash != tip.block_hash:
        if (view, seq) not in self._stale_logged:
          self._stale_logged.add((view, seq))
          logger.warning("view %d: proposal %d went stale; waiting for a view change", view, seq)
        return
      block = earlier
      if carried is not None and carried.block.block_hash == block.block_hash:
        cert = carried.cert
    elif carried is not None:
      # A block that may already be final somewhere: re-propose it unchanged (same hash, its
      # original view number), justified by its prepared certificate.
      block, cert = carried.block, carried.cert
      self._proposed[(view, seq)] = block
      logger.info("view %d: re-proposing prepared block %d from view %d", view, seq, cert.view)
    else:
      batch = self._next_batch()
      if not batch:
        return
      try:
        candidate = await asyncio.to_thread(
          build_candidate_block,
          batch,
          previous_hash=tip.block_hash,
          index=seq,
          timestamp=max(self._now_ms(), tip.timestamp),
          proposer_id=self._self_id,
          algorithm="pbft",
          sealed_consensus={"view_number": view},
          resolve_issuer_key=self._context.resolvers.current.resolve_issuer_key,
        )
      except InvalidRecordSignatureError as exc:
        logger.error(
          "dropping a pending record with an invalid signature (batch index %d)", exc.index
        )
        self._context.mempool.remove([batch[exc.index].document_hash])
        self._wake.set()
        return
      if self.view != view or self._chain_state.tip is not tip:
        return  # the view or the tip moved while we built it
      block = attach_proposer_signature(candidate, self._key)
      self._proposed[(view, seq)] = block
      logger.info("view %d: proposing block %d with %d record(s)", view, seq, len(batch))
    held = self._signed.get((view, seq))
    if held is not None and held != block.block_hash:
      if (view, seq) not in self._stale_logged:  # e.g. restarted after signing another block
        self._stale_logged.add((view, seq))
        logger.warning("view %d: already signed another block for %d; waiting", view, seq)
      return
    message = await self._sign(PRE_PREPARE, seq, block, payload=block_to_dict(block), cert=cert)
    if message is None:
      return
    current.candidate = block
    current.primary = self._self_id
    current.pre_prepare_signature = message.signature
    current.started_wall = self._now_ms()
    self._open(current)
    self._emit(current, message)
    await self._advance(current)

  def _carried_choice(self, seq: int) -> Lock | None:
    """The certified block with the highest prepared view among our lock and the locks in
    the view-change votes our view was installed on. A lock is trusted only with a valid
    certificate, never because a block carries an old view number."""
    best = self._lock if self._lock is not None and self._lock.cert.seq == seq else None
    for vote in self._install_support:
      if vote.cert is None or vote.block is None or vote.seq != seq:
        continue
      if best is not None and vote.cert.view <= best.cert.view:
        continue
      candidate = self._certified_block(vote.cert, vote.block)
      if candidate is not None:
        best = candidate
    return best

  def _certified_block(self, cert: PreparedCert, raw_block: Any) -> Lock | None:
    try:
      block = block_from_dict(raw_block)
    except Exception:
      return None
    tip = self._chain_state.tip
    if (
      block.block_hash != cert.block_hash
      or block.index != cert.seq
      or block.previous_hash != tip.block_hash
      or (block_view(block) or 0) > cert.view
      or not self._cert_ok(cert)
    ):
      return None
    return Lock(cert, block)

  def _cert_ok(self, cert: PreparedCert) -> bool:
    resolver = self._context.resolvers.current
    now = self._now_ms()
    return verify_cert(
      cert,
      primary_of=self.primary_of,
      members=self._validator_set.members,
      quorum=self.quorum,
      resolve_key=lambda node_id: resolver.resolve_node_key(node_id, now),
      key_id=key_id,
    )

  # ---------------------------------------------------------------- sending

  async def _sign(
    self,
    kind: Kind,
    seq: int,
    block: Block,
    *,
    payload: Any = None,
    cert: PreparedCert | None = None,
    lock: Lock | None = None,
  ) -> PbftMessage | None:
    """Our vote of `kind` for `block` in the current view - refused if we already signed
    another hash for this (view, seq). The vote (and a new lock) is persisted BEFORE it is
    returned for sending, so a restart cannot make this node sign a conflicting one."""
    key = (self.view, seq)
    held = self._signed.get(key)
    if held is not None and held != block.block_hash:
      logger.error("refusing to sign a second %s for (%d, %d)", kind, self.view, seq)
      return None
    self._signed[key] = block.block_hash
    if lock is not None:
      self._lock = lock
    await self._persist()
    return make_message(
      kind,
      self._key,
      view=self.view,
      seq=seq,
      block_hash=block.block_hash,
      node_id=self._self_id,
      block=payload,
      cert=cert,
    )

  async def _persist(self) -> None:
    if self._store is None:
      return
    # The worker thread serializes a SNAPSHOT taken here on the loop: the live `_signed` dict
    # (and the other fields) may change while `to_json` iterates them in the thread.
    self._persisted = PbftState(
      view=self.view,
      signed=dict(self._signed),
      lock=(
        None
        if self._lock is None
        else {"cert": self._lock.cert.to_wire(), "block": block_to_dict(self._lock.block)}
      ),
      vc_vote=dict(self._vc_wire) if self._vc.in_progress and self._vc_wire is not None else None,
      byzantine_events=[dict(e) for e in self._context.validity_cache.byzantine_events],
    )
    await asyncio.to_thread(self._store.save, self._persisted)

  def _restore_lock(self, raw: dict[str, Any] | None) -> Lock | None:
    """The persisted lock. Unreadable fails CLOSED (the node must not forget a lock); a lock
    for a height that is final now (or on another parent) is moot and dropped."""
    if raw is None:
      return None
    try:
      cert = decode_cert(raw["cert"])
      block = block_from_dict(raw["block"])
    except Exception as exc:
      raise PbftStateError(f"persisted PBFT lock is unreadable: {exc}") from exc
    tip = self._chain_state.tip
    if cert.seq != tip.index + 1 or block.previous_hash != tip.block_hash:
      return None
    if block.block_hash != cert.block_hash or not self._cert_ok(cert):
      raise PbftStateError("persisted PBFT lock does not verify")
    return Lock(cert, block)

  def _restore_view_change(self, raw: dict[str, Any] | None) -> None:
    """A view-change vote sent before a restart stays in force (it is re-sent unchanged)."""
    if raw is None:
      return
    try:
      message = decode_message(raw)
    except Exception as exc:
      raise PbftStateError(f"persisted view-change vote is unreadable: {exc}") from exc
    if message.kind == VIEW_CHANGE and message.view > self.view:
      self._vc.start(message.view)
      self._vc.accept(message)
      self._vc_wire = raw
      self._vc_reason = "restored after a restart"
      self._vc_started = self._monotonic()

  def _emit(self, current: Round, message: PbftMessage) -> None:
    wire = message.to_wire()
    current.outbox.append(wire)
    self._spawn_send(wire)

  def _spawn_send(self, wire: dict[str, Any], targets: Iterable[str] | None = None) -> None:
    task = asyncio.get_running_loop().create_task(self._send(wire, targets))
    self._sends.add(task)
    task.add_done_callback(self._sends.discard)

  def _resend(self) -> None:
    """Re-send our own messages: the open round's (covers a link that came up late, or a
    message lost with a broken link - receivers treat repeats as no-ops) or, during a view
    change, our unchanged view-change vote."""
    if self._vc.in_progress and self._vc_wire is not None:
      self._vc.attempts += 1
      self._spawn_send(self._vc_wire)
    for current in self._open_rounds():  # idempotent: our commit may still finish a round
      if not current.finalizing:
        for wire in current.outbox:
          self._spawn_send(wire)

  # -------------------------------------------------------------- inbound messages

  async def _process(self, message: PbftMessage) -> None:
    sender = message.node_id
    if sender not in self._validator_set.members:
      self._flag(sender, "pbft message from a non-validator")  # PeerInfo never votes
      return
    if message.kind == VIEW_CHANGE:
      await self._on_view_change(message)
      return
    if message.kind == NEW_VIEW:
      await self._on_new_view(message)
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
    if message.view > self.view:
      # A view we have not installed yet: keep the latest per (sender, kind), replay it on
      # install. Its sender is ahead of us, so it holds the proof of that view.
      if message.seq == next_seq and (message.kind == COMMIT or self._verified(message)):
        self._future[(sender, message.kind)] = message
      return
    if message.view < self.view:
      # An older view. Commits stay meaningful (a commit quorum proves a block final in any
      # view) if we hold that round; otherwise the sender is behind: send it the proof.
      if message.kind == COMMIT and (message.view, message.seq) in self._rounds:
        current = self._rounds[(message.view, message.seq)]
        self._on_commit(current, message)
        await self._advance(current)
      else:
        self._send_new_view(sender)
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
    if current.candidate is not None:  # the candidate of a (view, seq) is locked in
      if (
        current.candidate.block_hash != message.block_hash
        and (PRE_PREPARE, sender) not in current.conflicted
        and self._verified(message)
      ):
        self._conflict(current, message, current.candidate.block_hash)
      return
    if current.rejected or self._vc.in_progress:
      # An honest primary sends ONE candidate per (view, seq): after a rejected one, nothing
      # else is screened for this slot. During a view change we no longer vote in this view.
      return
    records = message.block.get("document_records")
    if not isinstance(records, list) or len(records) > min(self._max_batch, MAX_BLOCK_RECORDS):
      await self._reject_candidate(current, message, "malformed or oversized block")
      return
    if not self._verified(message):
      return
    try:
      block = block_from_dict(message.block)
    except Exception:
      await self._reject_candidate(current, message, "malformed block")
      return
    if not matches_block(message, block):
      await self._reject_candidate(current, message, "block does not match the message")
      return
    proposed_in = block_view(block)
    if proposed_in is None:
      await self._reject_candidate(current, message, "no view number")
      return
    carried = proposed_in < message.view
    origin_primary = self.primary_of(proposed_in) if carried else sender
    if origin_primary is None:
      await self._reject_candidate(current, message, "no primary for the block's view")
      return
    cert = message.cert
    if carried:
      # A block from an earlier view: acceptable only with a valid prepared certificate for
      # exactly this block, from a view between its own and this one.
      if (
        cert is None
        or cert.block_hash != block.block_hash
        or cert.seq != message.seq
        or not proposed_in <= cert.view < message.view
        or not self._cert_ok(cert)
      ):
        await self._reject_candidate(current, message, "carried block without a valid cert")
        return
    elif cert is not None:
      await self._reject_candidate(current, message, "a fresh block must not carry a cert")
      return
    lock = self._lock
    if (
      lock is not None
      and lock.cert.seq == message.seq
      and lock.cert.block_hash != block.block_hash
      and not (cert is not None and cert.view > lock.cert.view)
    ):
      # Our lock: a block that may be final elsewhere is never replaced, unless a higher
      # view's certificate shows a quorum moved on. Not proof of a faulty primary (it may
      # not have learned our lock), so no flag; the round timeout moves the view on.
      logger.info("view %d: not preparing %d: locked on another block", message.view, message.seq)
      current.rejected.add(message.block_hash)
      return
    # pure and CPU-heavy (up to one signature check per record): off the event loop
    verdict = await asyncio.to_thread(
      self._context.gateway.screen_candidate,
      block,
      primary_id=origin_primary,
      view=proposed_in,
      known=self._chain_state.has_document,
      allow_old=carried,  # a carried block is old by definition
    )
    if verdict.reason in TRANSIENT_REASONS:
      # a clock difference or a late re-send, not proof of a faulty primary: not locked out
      logger.info("pre-prepare %d not accepted yet: %s", message.seq, verdict.reason)
      return
    if not verdict.accepted:  # UC-6-E1: an invalid candidate gets no prepare from us ...
      await self._reject_candidate(current, message, verdict.reason)
      await self._start_view_change(self.view + 1, f"invalid proposal: {verdict.reason}")
      return  # ... and the view moves on at once
    if (
      self._rounds.get((current.view, current.seq)) is not current
      or current.candidate is not None
      or self._vc.in_progress
    ):
      return  # the tip or the view moved, or a candidate was locked in, while we screened
    vote = await self._sign(PREPARE, message.seq, block)
    if vote is None:
      current.rejected.add(message.block_hash)  # never re-screened on every resend
      return
    current.candidate = block
    current.primary = sender
    current.pre_prepare_signature = message.signature
    current.started_wall = self._now_ms()
    self._open(current)  # the round timeout runs from a screened candidate, not a lone vote
    current.prepares[self._self_id] = (block.block_hash, vote.signature)
    self._emit(current, vote)

  async def _reject_candidate(self, current: Round, message: PbftMessage, reason: str) -> None:
    current.rejected.add(message.block_hash)
    self._flag(message.node_id, f"pre-prepare rejected: {reason}")

  def _on_prepare(self, current: Round, message: PbftMessage) -> None:
    sender = message.node_id
    if sender == self.primary_of(message.view):
      # The primary never sends a prepare: its pre-prepare already is its prepare vote.
      self._flag(sender, "prepare from the primary")
      return
    held = current.prepares.get(sender)
    if held is not None and held[0] == message.block_hash:
      return  # duplicate delivery: no-op
    if held is not None and (PREPARE, sender) in current.conflicted:
      return  # its equivocation is already on record: no more crypto for this slot
    if not self._verified(message):
      return
    if held is None:
      current.prepares[sender] = (message.block_hash, message.signature)
    else:
      self._conflict(current, message, held[0])

  def _on_commit(self, current: Round, message: PbftMessage) -> None:
    # The commit signature covers only `commit_payload(block_hash)` and is checked at counting
    # time with the key in force at the CANDIDATE's timestamp - exactly as the core will.
    held = current.commits.get(message.node_id)
    if held is None:
      current.commits[message.node_id] = (message.block_hash, message.signature)
      return
    if held[0] == message.block_hash or (COMMIT, message.node_id) in current.conflicted:
      return
    # Report only two VALID commit signatures for different hashes in one (view, seq). The
    # view label of a commit is not signed (a commit is view-independent), so this evidence is
    # local - it relies on the authenticated link - and is never exported as proof.
    key = self._context.resolvers.current.resolve_node_key(message.node_id, self._now_ms())
    if key is not None and all(
      verify_canonical(key, commit_payload(h), s)
      for h, s in (held, (message.block_hash, message.signature))
    ):
      self._conflict(current, message, held[0])

  def _conflict(self, current: Round, message: PbftMessage, first: str) -> None:
    """A member signed two different votes for one (view, seq): the first stays counted, the
    pair is kept as evidence and reported as a Byzantine (equivocation) event - distinct from
    any crash-fault report (UC-6-E2)."""
    current.conflicted.add((message.kind, message.node_id))  # one piece of evidence each
    current.conflicts.append((message.kind, message.node_id, first, message.block_hash))
    self._report_byzantine(
      message.node_id,
      f"{message.node_id} signed two different {message.kind} votes for "
      f"(view {message.view}, seq {message.seq}): {first[:12]} vs {message.block_hash[:12]}",
    )

  def _report_byzantine(self, offender: str, reason: str) -> None:
    self._flag(offender, "equivocation")
    self._chain_state.report_byzantine_event(reason, offender=offender)
    self._dirty = True  # the event is persisted by this step (see `_step`)

  # ---------------------------------------------------------------- quorum logic

  def prepare_votes(self, current: Round) -> int:
    """Distinct members that prepared the candidate (see `rounds.count_prepare_votes`)."""
    return count_prepare_votes(current, self._validator_set.members)

  def commit_votes(self, current: Round) -> dict[str, str]:
    """Matching, valid commit votes by member, counted once THIS node is prepared (see
    `rounds.verified_commit_votes`)."""
    return verified_commit_votes(
      current,
      self._validator_set.members,
      self._context.resolvers.current.resolve_node_key,
      on_bad_signature=lambda node_id: self._flag(node_id, "commit: bad signature"),
    )

  async def _advance(self, current: Round) -> None:
    candidate = current.candidate
    if candidate is None or current.finalizing:
      return
    if (
      not current.prepared
      and current.view == self.view
      and not self._vc.in_progress  # after a view-change vote we no longer vote in this view
      and self.prepare_votes(current) >= self.quorum
    ):
      cert = build_certificate(current)
      if not self._cert_ok(cert):
        logger.error("prepared certificate for %d does not verify; not committing", current.seq)
        return
      lock = self._lock
      if lock is None or lock.cert.seq != current.seq or cert.view >= lock.cert.view:
        lock = Lock(cert, candidate)
      vote = await self._sign(COMMIT, current.seq, candidate, lock=lock)
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

  # ------------------------------------------------------------------ view change

  def _open(self, current: Round) -> None:
    if current.opened_at is None:
      current.opened_at = self._monotonic()

  def _up_members(self) -> set[str]:
    return set(self._peer_up()) & set(self.members())

  def _watch_peers(self) -> None:
    """Primary failure detection, and the new-view proof for a member that (re)connects."""
    up = self._up_members()
    for peer in up - self._peers_seen:
      self._send_new_view(peer)  # a restarted node learns our view at once
    self._peers_seen = up
    primary = self.primary_of(self.view)
    if primary is None or primary == self._self_id or primary in up:
      self._primary_down_since = None
    elif self._primary_down_since is None:
      self._primary_down_since = self._monotonic()

  async def _view_change_step(self) -> None:
    installable = self._vc.installable()
    if installable is not None:
      await self._install(installable)
    join = self._vc.join_target()
    if join is not None:
      await self._start_view_change(join, f"{self._vc.f + 1} members want view {join}")
    now = self._monotonic()
    if self._vc.in_progress:
      if now - self._vc_started >= self._round_timeout_s * (1 + self._vc.attempts // 8):
        self._vc_started = now
        logger.warning(
          "view change to %d still open (%s; %d re-send(s)); responsive members: %s",
          self._vc.target,
          self._vc_reason,
          self._vc.attempts,
          sorted(self._up_members() | {self._self_id}),
        )
      return
    current = self.round(self._chain_state.tip.index + 1)
    reason = None
    if (
      current is not None
      and current.opened_at is not None
      and not current.finalizing
      and now - current.opened_at >= self._round_timeout_s
    ):
      reason = "round timed out"  # UC-6-E4
    elif (
      self._primary_down_since is not None
      and now - self._primary_down_since >= self._round_timeout_s
    ):
      reason = f"primary {self.primary_of(self.view)} unreachable"
    else:
      # Consumes the overdue watch: the record is not resurrected, its client resubmits.
      reason = self._censorship()
    if reason is not None:
      await self._start_view_change(self.view + 1, reason)

  def _censorship(self) -> str | None:
    """A forwarded record the current primary accepted but has not finalized in time."""
    now = self._monotonic()
    overdue = None
    for document_hash, (deadline, view) in list(self._watched.items()):
      if self._chain_state.has_document(document_hash) or view != self.view:
        del self._watched[document_hash]  # finalized, or that primary is gone anyway
      elif now >= deadline and overdue is None:
        overdue = document_hash
    if overdue is None:
      return None
    del self._watched[overdue]
    return f"a record accepted by primary {self.primary_of(self.view)} was not finalized in time"

  async def _start_view_change(self, target: int, reason: str) -> None:
    if target <= self.view or (self._vc.target is not None and target <= self._vc.target):
      return
    seq = self._chain_state.tip.index + 1
    lock = self._lock if self._lock is not None and self._lock.cert.seq == seq else None
    message = make_message(
      VIEW_CHANGE,
      self._key,
      view=target,
      seq=seq,
      block_hash=lock.cert.block_hash if lock is not None else NO_BLOCK,
      node_id=self._self_id,
      block=block_to_dict(lock.block) if lock is not None else None,
      cert=lock.cert if lock is not None else None,
    )
    self._vc.start(target)
    self._vc.accept(message)
    self._vc_wire = message.to_wire()  # frozen: re-sent unchanged until installed
    self._vc_started = self._monotonic()
    self._vc_reason = reason
    self.view_changes += 1
    logger.warning("view %d -> %d requested: %s", self.view, target, reason)
    await self._persist()  # durable before it is sent
    self._spawn_send(self._vc_wire)
    self._update_liveness()

  async def _on_view_change(self, message: PbftMessage) -> None:
    if not self._verified(message):
      return
    if message.view <= self.view:
      self._send_new_view(message.node_id)  # it is behind: give it the proof of our view
      return
    outcome = self._vc.accept(message)
    if outcome.kind == "conflict" and outcome.previous is not None:
      self._report_byzantine(
        message.node_id,
        f"{message.node_id} sent two view-change votes for view {message.view} naming "
        f"different locked blocks at seq {message.seq}",
      )
    if outcome.kind == "new":
      self._wake.set()

  async def _on_new_view(self, message: PbftMessage) -> None:
    if message.view <= self.view or message.view > self.view + MAX_NEW_VIEW_JUMP:
      return
    now_mono = self._monotonic()
    if now_mono - self._new_view_seen.get(message.node_id, float("-inf")) < self._resend_s:
      return  # at most one proof per member per resend period
    self._new_view_seen[message.node_id] = now_mono
    if not self._verified(message):
      return
    resolver = self._context.resolvers.current
    now = self._now_ms()
    members = set(self.members())
    unique = {v.node_id: v for v in message.votes if v.node_id in members}  # before any crypto
    valid = []
    for vote in unique.values():
      key = (
        resolver.resolve_node_key(vote.node_id, now)
        if vote.node_id in self._validator_set.members
        else None
      )
      if key is not None and verify_vote(vote, key):
        valid.append(vote)
    if not self._vc.accept_install_votes(valid, message.view):
      self._flag(message.node_id, "new-view without a quorum of valid votes")
      return
    if self._vc.adopt(message.view):
      self._vc.install_votes = tuple(valid)
      self._vc.install_view = message.view
      # The proof holds signatures only, no locked blocks: as primary we re-propose our own
      # lock if any; a locked replica refuses anything else, and the view moves on.
      self._install_support = ()
      await self._entered_view(f"new-view proof from {message.node_id}")

  async def _install(self, view: int) -> None:
    self._install_support = self._vc.install(view)
    await self._entered_view("a quorum of view-change votes")

  async def _entered_view(self, how: str) -> None:
    if not self._vc.in_progress:
      self._vc_wire = None  # our vote is satisfied (one for a higher view stays in force)
    self._primary_down_since = None
    logger.warning(
      "view %d installed (%s); primary is %s", self.view, how, self.primary_of(self.view)
    )
    await self._persist()
    ready = [m for m in self._future.values() if m.view == self.view]
    self._future = {k: m for k, m in self._future.items() if m.view > self.view}
    for message in sorted(ready, key=lambda m: m.kind == PRE_PREPARE):
      self._inbox.appendleft(message)
      self._queued[message.node_id] += 1
    self._update_liveness()
    self._wake.set()

  def _send_new_view(self, peer: str) -> None:
    """The proof of our view (the signed votes it was installed on), at most once per resend
    period per peer."""
    votes = self._vc.install_votes
    now = self._monotonic()
    if (
      not votes
      or self._vc.install_view != self.view
      or now - self._new_view_sent.get(peer, float("-inf")) < self._resend_s
    ):
      return
    self._new_view_sent[peer] = now
    message = make_message(
      NEW_VIEW,
      self._key,
      view=self.view,
      seq=self._chain_state.tip.index + 1,
      block_hash=NO_BLOCK,
      node_id=self._self_id,
      votes=votes,
    )
    self._spawn_send(message.to_wire(), [peer])

  def _update_liveness(self) -> None:
    responsive = self._up_members() | {self._self_id}
    if len(responsive) < self.quorum:
      status = QUORUM_CRASH_LOSS  # UC-6-E5: too few members respond - not a Byzantine event
    elif self._vc.in_progress:
      status = QUORUM_VIEW_CHANGE  # UC-12-EC1
    else:
      status = QUORUM_HEALTHY  # includes exactly f members down (UC-6-EC1)
    if status != self._liveness:
      if status == QUORUM_CRASH_LOSS:
        logger.error(
          "crash-fault quorum loss: %d of %d members responsive, %d needed",
          len(responsive),
          len(self.members()),
          self.quorum,
        )
      self._liveness = status
    self._context.validity_cache.set_liveness(status)

  # ------------------------------------------------------------------ tip changes

  def _tip_view(self) -> int:
    tip = self._chain_state.tip
    if tip.algorithm != "pbft":
      return 0
    return block_view(tip) or 0

  def _round_for(self, seq: int) -> Round:
    key = (self.view, seq)
    current = self._rounds.get(key)
    if current is None:
      current = self._rounds[key] = Round(view=self.view, seq=seq)
    return current

  def _tip_moved(self) -> None:
    """After an append or a sync replace: drop every round the chain has moved past (a round
    whose candidate no longer extends the tip is abandoned), adopt the view a finalized block
    proves, and replay the look-ahead messages for the new next height."""
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
    if self._lock is not None and (
      self._lock.cert.seq != next_seq or self._lock.block.previous_hash != tip.block_hash
    ):
      self._lock = None  # that height is final now
    self._stale_logged = {k for k in self._stale_logged if k[1] > tip.index}
    self._future = {k: m for k, m in self._future.items() if m.seq >= next_seq}
    # A finalized block proves a quorum committed in its view: never go back below it.
    if self._vc.adopt(self._tip_view()):
      logger.info("adopted view %d from the finalized tip", self.view)
      self._install_support = ()
      self._primary_down_since = None
      if not self._vc.in_progress:
        self._vc_wire = None
      self._dirty = True  # persisted by the next step
    if self._vc.in_progress:
      supporters = [
        n
        for n, v in self._vc.latest.items()
        if n != self._self_id and self._vc.target is not None and v.view >= self._vc.target
      ]
      if not supporters:
        # Progress happened and nobody else wants the change: drop it and vote in this view
        # again. Peers may still hold our old vote; it names a height that is final now, so
        # it can only ever count toward a view change, never toward a block.
        logger.info("view change to %s cancelled: the chain moved on", self._vc.target)
        self._vc.cancel()
        self._vc.latest.pop(self._self_id, None)
        self._vc_wire = None
        self._dirty = True
    if len(tip.document_records) >= self._max_batch and self._watched:
      # A full block: the primary is busy, not censoring - give watched records more time.
      later = self._monotonic() + CENSORSHIP_TIMEOUTS * self._round_timeout_s
      self._watched = {h: (max(d, later), v) for h, (d, v) in self._watched.items()}
    ready = [m for m in self._ahead.values() if m.seq == next_seq]
    self._ahead = {k: m for k, m in self._ahead.items() if m.seq > next_seq}
    # pre-prepare first, so the candidate exists when the votes arrive
    for message in sorted(ready, key=lambda m: m.kind == PRE_PREPARE):
      self._inbox.appendleft(message)
      self._queued[message.node_id] += 1
    self._wake.set()
