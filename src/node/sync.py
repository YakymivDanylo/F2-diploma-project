"""Chain synchronization and fork resolution (UC-3).

A node pulls `GET /chain` pages from its peers - at startup (bounded by
`STARTUP_SYNC_TIMEOUT_S`), periodically, and on demand when a broadcast block did not extend
its tip. A round polls every ValidatorSet member with a known address plus at most
`MAX_EXTRA_PEERS_PER_ROUND` other `PeerInfo` peers (rotated round-robin), and a peer that served
an invalid or malformed chain is backed off exponentially (a validator for at most
`VALIDATOR_BACKOFF_CAP_S`, never for a link / consistency failure an honest peer produces
before its suffix is downloaded, and a flat `BACKOFF_START_S` when such a failure surfaces only
in the downloaded suffix - escalating once it repeats `SUFFIX_FAILURES_BEFORE_ESCALATION` times
in a row), so neither the size of `PeerInfo` nor a misbehaving peer sets our traffic or our
validation work. The suffix is checked for its link and the future-timestamp cap page by page
while it downloads, so a suffix that breaks is abandoned at the first broken page.

The incoming chain is judged against our TRUSTED blocks (`ChainState.trusted_blocks`: all of
them while valid, else the valid prefix):

* the last block both chains share is located with a probe at our trusted tip and, on
  divergence, a binary search over single-block requests - never by downloading the chain;
* the first block after it is PRE-CHECKED against our own block there (the full single-block
  checklist: proposer signature, hash, link, Merkle root, work / PBFT commit quorum) before
  anything more is downloaded; PoW forks must also show valid work on the probe page;
* the peer's suffix is then validated incrementally from that common ancestor. The base is
  our own trusted block, so this is sound - M-14 forbids an incremental check only from an
  UNTRUSTED base, which this never is. Only a node with no trusted block at all (not even
  genesis) validates a whole peer chain from genesis.

Every path runs the single FR-25 checklist (`ChainValidator`, incl. PBFT commit quorum) plus the
node-layer rules every adopted block must meet: the future-timestamp cap of the broadcast path
and cross-block `document_hash` uniqueness (over our prefix + the suffix). Adoption: PoW longest
valid chain, ties broken by the lowest tip `block_hash` as an unsigned integer
(order-independent); PBFT highest finalized height, and two differently-finalized blocks at one
height (the peer's block validated with its quorum against our parent) are a Byzantine event -
logged and surfaced as `quorum_status`, never tie-broken. Adoption happens only through
`ChainState.replace`, whose `prefer` re-judges the rule under the lock against the chain that is
current by then (an invalid local chain is judged by its valid prefix, so self-healing never
rolls back). A peer that serves an invalid chain is flagged; the local chain is kept.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
from collections.abc import Awaitable, Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from pydantic import ValidationError

from blockchain_core import Block, ValidationResult, pow_target, sha256_of_canonical
from blockchain_core.storage.chain_store import block_from_dict
from blockchain_core.validation import FailureType
from node.api.chain import ChainPage
from node.chain_state import ChainState
from node.netguard import (
  Resolver,
  check_resolved_async,
  prioritized,
  system_resolve,
  validator_traffic,
)
from node.validation_gateway import ChainValidator, ValidationGateway, first_duplicate_document

logger = logging.getLogger("node.sync")

MAX_SYNC_BLOCKS = 100_000  # a peer cannot make us buffer an unbounded chain
DEFAULT_REQUEST_TIMEOUT_S = 5.0  # whole request, not per socket read
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # one page; bounded however the peer sends it
DEFAULT_PEER_TIMEOUT_S = 60.0  # one whole sync with one peer, however many pages
STARTUP_RETRY_S = 0.5
FETCH_WORKERS = 4  # per pool; dedicated pools: stuck fetches never starve validation threads
MAX_EXTRA_PEERS_PER_ROUND = 8  # non-validator PeerInfo peers polled per round (rotated)
BACKOFF_START_S = 5.0  # first backoff after an invalid / malformed answer
BACKOFF_CAP_S = 300.0  # non-validator PeerInfo peers
# A ValidatorSet member is one of the few peers a lagging node can learn the chain from, so a
# validator that served forged data is backed off for at most this long - never minutes.
VALIDATOR_BACKOFF_CAP_S = 30.0
# Failures an HONEST peer produces (pages fetched across its own reorg, a block judged
# "in the future" through clock skew): never a reason to back a validator off.
LINK_FAILURES: frozenset[str] = frozenset({"link", "timestamp_in_future"})
# A validator's suffix failures (above) cost a flat BACKOFF_START_S this many times in a row;
# from the next one on the backoff doubles up to VALIDATOR_BACKOFF_CAP_S, until a round with it
# is confirmed (an honest reorg rarely repeats; a Byzantine validator's broken suffix does).
SUFFIX_FAILURES_BEFORE_ESCALATION = 3

Mode = Literal["pow", "pbft"]
Outcome = Literal["adopted", "not_better", "invalid", "byzantine", "unreachable", "malformed"]
CONFIRMED: frozenset[str] = frozenset({"adopted", "not_better", "byzantine"})


class SyncResponseError(Exception):
  """A peer's `GET /chain` answer is malformed, truncated or inconsistent (UC-3-E3)."""


class SyncConsistencyError(SyncResponseError):
  """The peer's answers contradict each other (an empty page below the tip it advertised, a
  binary search that finds no divergence): what an honest peer serves when its chain moves
  between our requests. Reported like any malformed answer, but never backs a validator off."""


class ChainFetcher(Protocol):
  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    """The decoded JSON body of `GET /chain?from=&to=`; transport errors raise."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, *args: Any, **kwargs: Any) -> None:
    return None  # a peer must not steer our GET to another address


class HttpChainFetcher:
  """Plain-HTTP default (Epic 6 swaps in the single TLS client factory). Every request is
  bounded in total time and size and runs on a small dedicated thread pool - one for
  ValidatorSet members and one for everyone else (chosen by `netguard.validator_traffic`,
  which `ChainSync` sets per peer), so hanging non-validator peers can never occupy the workers
  a validator fetch needs. Before each request the host is resolved (bounded, cached, on the
  netguard pools) and refused if it is, or resolves to, a forbidden address (`node.netguard`;
  the DNS rebinding residual is documented there). The fetch pools belong to the instance
  (threads start lazily); `close()` shuts them down. The netguard resolver pools, by contrast,
  are process-wide by design."""

  def __init__(
    self,
    timeout: float = DEFAULT_REQUEST_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    *,
    allow_loopback: bool = False,
    resolve: Resolver = system_resolve,
  ) -> None:
    self._timeout = timeout
    self._max_bytes = max_bytes
    self._allow_loopback = allow_loopback
    self._resolve = resolve
    self._opener = urllib.request.build_opener(_NoRedirect)
    self._pools = {
      True: ThreadPoolExecutor(max_workers=FETCH_WORKERS, thread_name_prefix="chain-fetch-v"),
      False: ThreadPoolExecutor(max_workers=FETCH_WORKERS, thread_name_prefix="chain-fetch"),
    }

  def close(self) -> None:
    """Shut both fetch pools down without waiting: queued fetches are cancelled, a running one
    ends within the request timeout. A fetch after `close()` raises `RuntimeError`."""
    for pool in self._pools.values():
      pool.shutdown(wait=False, cancel_futures=True)

  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    await check_resolved_async(
      host, port, allow_loopback=self._allow_loopback, resolve=self._resolve
    )
    pool = self._pools[validator_traffic.get()]
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(pool, self._call, host, port, from_index, to_index)

  def _call(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    url = f"http://{host}:{port}/chain?from={from_index}&to={to_index}"
    deadline = time.monotonic() + self._timeout
    chunks: list[bytes] = []
    size = 0
    with self._opener.open(url, timeout=self._timeout) as response:  # noqa: S310
      while chunk := response.read1(65536):
        size += len(chunk)
        if size > self._max_bytes:
          raise SyncResponseError("response exceeds the size limit")
        if time.monotonic() > deadline:
          raise TimeoutError("response took longer than the request timeout")
        chunks.append(chunk)
    try:
      return json.loads(b"".join(chunks))
    except ValueError as exc:  # not JSON, or truncated mid-transfer
      raise SyncResponseError("response is not valid JSON") from exc


@dataclass(frozen=True)
class PeerAddress:
  node_id: str
  host: str
  port: int


def _short(value: object) -> str:
  """Peer-controlled text for a log line: bounded and escaped."""
  return repr(str(value)[:16])


# ------------------------------------------------------------------- adoption rules


def _hash_value(block_hash: str) -> float:
  try:
    return int(block_hash, 16)
  except (TypeError, ValueError):
    return float("inf")  # a malformed hash never wins a tie-break


def pow_prefers(current: Sequence[Block], candidate: Sequence[Block]) -> bool:
  """Longest chain; equal length -> lowest tip hash as an unsigned integer (never arrival)."""
  if not candidate:
    return False
  if len(candidate) != len(current):
    return len(candidate) > len(current)
  return _hash_value(candidate[-1].block_hash) < _hash_value(current[-1].block_hash)


def finalized_height(blocks: Sequence[Block]) -> int:
  """Every block of a valid PBFT chain carries its commit quorum, so the tip is finalized."""
  return blocks[-1].index if blocks else -1


def pbft_prefers(current: Sequence[Block], candidate: Sequence[Block]) -> bool:
  return bool(candidate) and finalized_height(candidate) > finalized_height(current)


# ------------------------------------------------------------------------ the sync


@dataclass
class _Backoff:
  until: float
  delay: float


class ChainSync:
  def __init__(
    self,
    *,
    state: ChainState,
    validator: ChainValidator,
    gateway: ValidationGateway,
    mode: Mode,
    peers: Callable[[], Sequence[PeerAddress]],
    fetcher: ChainFetcher,
    flag: Callable[[str, str], None],
    page_size: int,
    expected_difficulty: int | None = None,
    is_validator: Callable[[str], bool] = lambda _node_id: True,
    peer_timeout_s: float = DEFAULT_PEER_TIMEOUT_S,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
  ) -> None:
    self._state = state
    self._validator = validator
    self._gateway = gateway
    self._mode = mode
    self._peers = peers
    self._fetcher = fetcher
    self._flag = flag
    self._page_size = max(1, page_size)
    self._target = pow_target(expected_difficulty) if expected_difficulty else None
    self._is_validator = is_validator
    self._peer_timeout = peer_timeout_s
    self._sleep = sleep
    self._clock = clock
    self._wake = asyncio.Event()
    self._backoff: dict[str, _Backoff] = {}
    # peer -> its last failure is one an honest peer can produce (LINK_FAILURES,
    # SyncConsistencyError); the value tells whether it surfaced only in the downloaded suffix
    self._consistency: dict[str, bool] = {}
    self._in_suffix: set[str] = set()  # peers whose suffix download began after a precheck
    self._suffix_failures: dict[str, int] = {}  # validator -> consecutive suffix failures
    self._last_extra = ""  # round-robin position over the non-validator peers

  # ------------------------------------------------------------------- scheduling

  def request(self, peer_id: str | None = None) -> None:
    """On-demand sync, e.g. a broadcast block did not extend our tip. Never blocks; hints that
    arrive while a round runs coalesce into one more round."""
    self._wake.set()

  async def run(self, interval_s: float) -> None:
    """Periodic / on-demand sync loop, for as long as the node serves."""
    while True:
      try:
        await asyncio.wait_for(self._wake.wait(), timeout=interval_s)
      except TimeoutError:
        pass
      self._wake.clear()
      try:
        await self.sync_round()
      except Exception:
        logger.exception("chain sync round failed")

  async def startup(self, timeout_s: float) -> bool:
    """Bounded startup sync (UC-3-F / EC4): True once a ValidatorSet member's chain was
    confirmed (adopted or not better); False when `timeout_s` elapsed first - the node then
    serves its local chain and keeps syncing in the background."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while (remaining := deadline - loop.time()) > 0:
      outcomes = await self.sync_round(budget_s=remaining)
      if any(
        outcome in CONFIRMED and self._is_validator(peer_id)
        for peer_id, outcome in outcomes.items()
      ):
        return True
      remaining = deadline - loop.time()
      if remaining <= 0:
        break
      await self._sleep(min(STARTUP_RETRY_S, remaining))
    logger.warning(
      "startup sync timed out after STARTUP_SYNC_TIMEOUT_S=%ss: no peer chain was confirmed; "
      "serving the local chain (chain_valid=%s) and syncing in the background",
      timeout_s,
      self._state.extendable,
    )
    return False

  async def sync_round(self, budget_s: float | None = None) -> dict[str, Outcome]:
    """The polled peers (`round_peers`) at once, each bounded by its own timeout (and by
    `budget_s`), so one slow peer cannot starve the others. Adoptions are serialised by the
    `ChainState` lock and `prefer`, so a worse chain never replaces a better one. A better chain
    judged against a chain that another peer's adoption moved meanwhile is refused as stale and
    adopted by the next round (which re-classifies it against the new chain)."""
    peers = self.round_peers()
    timeout = self._peer_timeout if budget_s is None else min(self._peer_timeout, budget_s)
    results = await asyncio.gather(*(self.sync_with(peer, timeout) for peer in peers))
    return {peer.node_id: outcome for peer, outcome in zip(peers, results, strict=True)}

  def round_peers(self) -> list[PeerAddress]:
    """Who one round polls: every ValidatorSet member with a known address, plus at most
    `MAX_EXTRA_PEERS_PER_ROUND` other `PeerInfo` peers, rotated round-robin across rounds.
    Anyone can get listed in `PeerInfo`, so its size never sets our outbound traffic, and dead
    addresses never crowd out the validators. Peers in backoff are skipped."""
    now = self._clock()
    validators: list[PeerAddress] = []
    extras: dict[str, PeerAddress] = {}
    listed: set[str] = set()
    for peer in self._peers():
      if peer.node_id in listed:
        continue
      listed.add(peer.node_id)
      if self._backed_off(peer.node_id, now):
        continue
      if self._is_validator(peer.node_id):
        validators.append(peer)
      else:
        extras[peer.node_id] = peer
    for node_id in [n for n in self._backoff if n not in listed]:  # forget unlisted peers
      del self._backoff[node_id]
    for node_id in [n for n in self._suffix_failures if n not in listed]:
      del self._suffix_failures[node_id]
    ordered = sorted(extras)
    if len(ordered) > MAX_EXTRA_PEERS_PER_ROUND:
      after = [n for n in ordered if n > self._last_extra]
      wrapped = after + [n for n in ordered if n <= self._last_extra]
      ordered = wrapped[:MAX_EXTRA_PEERS_PER_ROUND]
    if ordered:
      self._last_extra = ordered[-1]
    return validators + [extras[n] for n in ordered]

  # ------------------------------------------------------------------- backoff

  def backoff_for(self, peer_id: str) -> float:
    """The CURRENT backoff delay of `peer_id` in seconds - the length of the last backoff it
    was given (the base the next one doubles), not the time remaining; 0.0 when none is held
    (never backed off, or reset by a good answer)."""
    entry = self._backoff.get(peer_id)
    return 0.0 if entry is None else entry.delay

  def _backed_off(self, node_id: str, now: float) -> bool:
    entry = self._backoff.get(node_id)
    return entry is not None and now < entry.until

  def _note(self, peer: PeerAddress, outcome: Outcome, *, consistency: bool | None = None) -> None:
    """Exponential backoff (BACKOFF_START_S, doubling) after a peer served an invalid or
    malformed chain - or, for a non-validator, could not be reached; reset by a good answer.
    Non-validators are capped at BACKOFF_CAP_S. A ValidatorSet member - the set is small and
    fixed, and it is the peer a restarting node needs - is capped at VALIDATOR_BACKOFF_CAP_S,
    and only for forged / malformed data. A validator that is unreachable, or whose failure was
    a link / consistency one an honest peer produces (`consistency`: LINK_FAILURES,
    `SyncConsistencyError`) detected BEFORE its suffix was downloaded (`False`), is never
    backed off. The same failure surfacing only in a suffix downloaded after the precheck
    passed (`True`) gives a validator a flat BACKOFF_START_S, so an honest reorg costs one short
    pause; only when it happens SUFFIX_FAILURES_BEFORE_ESCALATION times in a row (no confirmed
    round in between) does it escalate exponentially up to VALIDATOR_BACKOFF_CAP_S, so a
    Byzantine validator cannot make us download a suffix that breaks at its end every ~5 s."""
    if outcome in CONFIRMED:
      self._backoff.pop(peer.node_id, None)
      self._suffix_failures.pop(peer.node_id, None)
      return
    validator = self._is_validator(peer.node_id)
    if validator and (outcome == "unreachable" or consistency is False):
      return
    if validator and consistency:
      streak = self._suffix_failures.get(peer.node_id, 0) + 1
      self._suffix_failures[peer.node_id] = streak
      excess = max(0, streak - SUFFIX_FAILURES_BEFORE_ESCALATION)
      delay = min(VALIDATOR_BACKOFF_CAP_S, BACKOFF_START_S * 2 ** min(excess, 16))
      self._backoff[peer.node_id] = _Backoff(self._clock() + delay, delay)
      return
    cap = VALIDATOR_BACKOFF_CAP_S if validator else BACKOFF_CAP_S
    previous = self._backoff.get(peer.node_id)
    delay = min(cap, BACKOFF_START_S if previous is None else previous.delay * 2)
    self._backoff[peer.node_id] = _Backoff(self._clock() + delay, delay)

  # ------------------------------------------------------------------- one peer

  async def sync_with(self, peer: PeerAddress, timeout_s: float | None = None) -> Outcome:
    self._consistency.pop(peer.node_id, None)
    self._in_suffix.discard(peer.node_id)
    # validator traffic resolves and fetches on the reserved pools (`node.netguard`)
    with prioritized(self._is_validator(peer.node_id)):
      outcome = await self._guarded(peer, timeout_s)
    consistency = self._consistency.pop(peer.node_id, None)
    self._in_suffix.discard(peer.node_id)
    self._note(peer, outcome, consistency=consistency)
    return outcome

  def _mark_consistency(self, peer_id: str) -> None:
    self._consistency[peer_id] = peer_id in self._in_suffix

  async def _guarded(self, peer: PeerAddress, timeout_s: float | None) -> Outcome:
    try:
      return await asyncio.wait_for(self._sync_with(peer), timeout=timeout_s or self._peer_timeout)
    except TimeoutError:
      logger.warning("chain sync with %s timed out", peer.node_id)
      return "unreachable"
    except (SyncResponseError, ValidationError) as exc:
      if isinstance(exc, SyncConsistencyError):
        self._mark_consistency(peer.node_id)
      logger.warning(
        "chain sync with %s: malformed response (%s)", peer.node_id, type(exc).__name__
      )
      self._flag(peer.node_id, "malformed chain response")
      return "malformed"
    except asyncio.CancelledError:
      raise
    except Exception as exc:  # unreachable, refused, HTTP error: retry later (UC-3-E2)
      logger.info("chain sync with %s failed: %s", peer.node_id, type(exc).__name__)
      return "unreachable"

  async def _sync_with(self, peer: PeerAddress) -> Outcome:
    trusted = self._state.trusted_blocks
    if not trusted:  # not even our genesis validated: nothing local to build on
      return await self._adopt_full(peer)
    top = len(trusted) - 1
    cache: dict[int, Block] = {}
    target = await self._probe(peer, top, cache)
    if target < top:
      return "not_better"  # the peer is behind our trusted tip
    if cache[top].block_hash == trusted[top].block_hash:  # strict, non-diverging extension
      if target == top:
        return "not_better"  # the same chain
      return await self._adopt_suffix(peer, trusted, top, target, cache)
    # divergence at or below our trusted tip
    if self._mode == "pow":
      if target == top and not pow_prefers(trusted, (*trusted[:-1], cache[top])):
        return "not_better"  # equal length, our tip hash is lower: keep ours, no download
      if not self._claims_real_work([cache[i] for i in sorted(cache)]):
        logger.warning("%s advertised a fork without valid proof of work", peer.node_id)
        self._flag(peer.node_id, "invalid chain: fork without proof of work")
        return "invalid"
    ancestor = await self._common_ancestor(peer, trusted, top, cache)
    if self._mode == "pbft":
      return await self._pbft_divergence(peer, trusted, ancestor, cache)
    return await self._adopt_suffix(peer, trusted, ancestor, target, cache)

  async def _probe(self, peer: PeerAddress, top: int, cache: dict[int, Block]) -> int:
    """The page that starts at our trusted tip. Returns the peer's advertised tip - the bound of
    this whole sync, so a peer that keeps growing cannot keep us fetching forever."""
    target, blocks = await self._page(peer, top)
    if target - top + 1 > MAX_SYNC_BLOCKS:
      raise SyncResponseError("the peer's chain exceeds the sync limit")
    if target >= top and not blocks:
      raise SyncConsistencyError(f"empty page at {top} below the advertised tip {target}")
    for block in blocks:
      cache.setdefault(block.index, block)
    return target

  async def _common_ancestor(
    self, peer: PeerAddress, trusted: tuple[Block, ...], diverged: int, cache: dict[int, Block]
  ) -> int:
    """The index of the last block the peer's chain shares with our trusted chain, given that
    they differ at `diverged`: a binary search with single-block requests down to one page,
    then that page - O(log n) small requests, never the whole chain. Genesis is fixed, and the
    first divergent block is then checked to link to OUR block at the returned index, so a
    peer that lies about its earlier blocks gains nothing."""
    low, high = 0, diverged
    while high - low > self._page_size:
      middle = (low + high) // 2
      block = await self._block_at(peer, middle, middle, cache)
      if block.block_hash == trusted[middle].block_hash:
        low = middle
      else:
        high = middle
    for index in range(low + 1, high + 1):
      if (await self._block_at(peer, index, high, cache)).block_hash != trusted[index].block_hash:
        return index - 1
    raise SyncConsistencyError("the peer's answers about its own chain are inconsistent")

  def _precheck(self, trusted: tuple[Block, ...], ancestor: int, block: Block) -> ValidationResult:
    """The full single-block checklist (proposer signature, hash, link, Merkle root, work or
    PBFT commit quorum) of the first block after the common ancestor, against OUR block there,
    plus the node-layer rules - run before anything more of the peer's chain is downloaded."""
    known = {r.document_hash for b in trusted[: ancestor + 1] for r in b.document_records}
    return self._checked(
      [block],
      lambda: self._validator.extension(trusted[ancestor], [block]),
      known=known.__contains__,
    )

  def _reject(self, peer: PeerAddress, result: ValidationResult) -> Outcome:
    if result.failure_type in LINK_FAILURES:
      self._mark_consistency(peer.node_id)  # e.g. pages fetched across the peer's reorg
    logger.warning(
      "%s served an invalid chain (%s at index %s); keeping the local chain",
      peer.node_id,
      result.failure_type,
      result.first_invalid_index,
    )
    self._flag(peer.node_id, f"invalid chain: {result.failure_type}")
    return "invalid"

  async def _adopt_suffix(
    self,
    peer: PeerAddress,
    trusted: tuple[Block, ...],
    ancestor: int,
    target: int,
    cache: dict[int, Block],
  ) -> Outcome:
    """Adopt our trusted blocks `0..ancestor` + the peer's `ancestor+1..target`. The base is our
    own trusted block, so validating the suffix incrementally from it is sound (M-14 forbids an
    incremental check from an UNTRUSTED base, which this never is)."""
    start = ancestor + 1
    if any(index not in cache for index in range(start, target + 1)):  # more to download
      first = await self._block_at(peer, start, target, cache)
      verdict = await asyncio.to_thread(self._precheck, trusted, ancestor, first)
      if not verdict.valid:
        return self._reject(peer, verdict)
      self._in_suffix.add(peer.node_id)  # failures from here on cost a validator a backoff
    base = trusted[:start]
    try:  # link + future cap checked page by page: a broken suffix is abandoned at once
      suffix = await self._collect(peer, start, target, cache, parent=base[-1])
    except _EarlyReject as early:  # before any signature / Merkle work on the suffix
      return self._reject(peer, early.result)
    candidate = (*base, *suffix)
    known = {r.document_hash for block in base for r in block.document_records}
    verdicts: list[ValidationResult] = []

    def validate(chain: Sequence[Block]) -> ValidationResult:
      new_blocks = chain[start:]
      result = self._checked(
        new_blocks,
        lambda: self._validator.extension(base[-1], new_blocks),
        known=known.__contains__,
      )
      verdicts.append(result)
      return result

    def prefer(current: tuple[Block, ...], chain: tuple[Block, ...]) -> bool:
      # judged against the chain current at install time: our base must still be trusted there
      # (an adoption meanwhile may have dropped it) and the rule must still hold - an invalid
      # local chain is judged by its valid prefix, so healing never rolls back
      now = self._state.trusted_blocks
      still_based = len(now) > ancestor and now[ancestor].block_hash == base[-1].block_hash
      return still_based and self._rule(now, chain)

    mode = "incremental" if ancestor == len(trusted) - 1 else f"incremental from fork point {start}"
    return await self._replace(peer, candidate, validate, prefer, verdicts, mode)

  async def _adopt_full(self, peer: PeerAddress) -> Outcome:
    """Only when no local block is trusted at all (not even genesis): the peer's whole chain is
    validated from genesis."""
    cache: dict[int, Block] = {}
    target = await self._probe(peer, 0, cache)
    if target < 0:
      return "not_better"
    chain = tuple(await self._collect(peer, 0, target, cache))
    verdicts: list[ValidationResult] = []

    def validate(blocks: Sequence[Block]) -> ValidationResult:
      result = self._checked(blocks, lambda: self._validator.full(blocks))
      verdicts.append(result)
      return result

    def prefer(current: tuple[Block, ...], blocks: tuple[Block, ...]) -> bool:
      return self._rule(self._state.trusted_blocks, blocks)

    logger.info(
      "full-from-genesis validation of %s's chain: nothing local is trusted", peer.node_id
    )
    return await self._replace(peer, chain, validate, prefer, verdicts, "full")

  async def _replace(
    self,
    peer: PeerAddress,
    candidate: tuple[Block, ...],
    validate: Callable[[Sequence[Block]], ValidationResult],
    prefer: Callable[[tuple[Block, ...], tuple[Block, ...]], bool],
    verdicts: list[ValidationResult],
    mode: str,
  ) -> Outcome:
    if await self._state.replace(candidate, validate, prefer=prefer):
      logger.info(
        "adopted %s's chain (tip %d, %s validation)", peer.node_id, candidate[-1].index, mode
      )
      return "adopted"
    if verdicts and not verdicts[-1].valid:
      return self._reject(peer, verdicts[-1])
    return "not_better"  # not better, or stale: the next round re-judges it

  async def _pbft_divergence(
    self, peer: PeerAddress, trusted: tuple[Block, ...], ancestor: int, cache: dict[int, Block]
  ) -> Outcome:
    """Two finalized PBFT blocks at one height cannot both be honest: never tie-break. The
    peer's first divergent block must pass the full single-block checklist - commit quorum
    included - against OUR parent block, so an unsigned or unfinalized forgery cannot raise a
    false alarm; nothing more of the peer's chain is downloaded either way."""
    height = ancestor + 1
    block = await self._block_at(peer, height, height, cache)
    result = await asyncio.to_thread(self._precheck, trusted, ancestor, block)
    if not result.valid:
      return self._reject(peer, result)
    self._state.report_byzantine_event(
      f"{peer.node_id} holds a differently-finalized block at height {height} "
      f"({block.block_hash} vs local {trusted[height].block_hash})"
    )
    return "byzantine"

  # -------------------------------------------------------------------- helpers

  def _rule(self, current: Sequence[Block], candidate: Sequence[Block]) -> bool:
    if self._mode == "pow":
      return pow_prefers(current, candidate)
    return pbft_prefers(current, candidate)

  def _claims_real_work(self, blocks: Sequence[Block]) -> bool:
    """Cheap pre-check before any further download: every advertised fork block hashes to its
    `block_hash` and meets the PoW target."""
    if self._target is None:
      return True
    for block in blocks:
      try:
        digest = sha256_of_canonical(block.preimage_dict())
      except Exception:
        return False
      if digest != block.block_hash or int(digest, 16) >= self._target:
        return False
    return True

  def _checked(
    self,
    new_blocks: Sequence[Block],
    run: Callable[[], ValidationResult],
    *,
    known: Callable[[str], bool] = lambda _hash: False,
  ) -> ValidationResult:
    """The FR-25 checklist plus the node-layer rules every adopted block must meet: the
    future-timestamp cap and cross-block document_hash uniqueness."""
    future = self._gateway.first_future_block(new_blocks)
    if future is not None:
      return _invalid(future, "timestamp_in_future")
    duplicate = first_duplicate_document(new_blocks, known)
    if duplicate is not None:
      return _invalid(duplicate, "duplicate_document")
    return run()

  async def _block_at(
    self, peer: PeerAddress, index: int, end: int, cache: dict[int, Block]
  ) -> Block:
    """The peer's block at `index`, fetching `index..end` (at most one page) when missing."""
    if index not in cache:
      _, blocks = await self._page(peer, index, end)
      if not blocks:
        raise SyncConsistencyError(f"empty page at {index} below the advertised tip")
      for block in blocks:
        cache.setdefault(block.index, block)
    return cache[index]

  async def _collect(
    self,
    peer: PeerAddress,
    start: int,
    target: int,
    cache: dict[int, Block],
    *,
    parent: Block | None = None,
  ) -> list[Block]:
    """Blocks `start..target`, fetching only the pages that are not in `cache` yet. With a
    `parent` (a suffix on our own block) every block is checked as soon as its page arrives -
    field comparisons only: it names its predecessor's (claimed) hash and is not stamped beyond
    the future-skew cap - and the first break raises `_EarlyReject` before the next page is
    requested, so a peer cannot make us download a long suffix that breaks at its end (the full
    checklist still re-checks both rules against recomputed hashes)."""
    fetched: list[Block] = []
    previous = parent
    for index in range(start, target + 1):
      block = await self._block_at(peer, index, target, cache)
      if previous is not None:
        if block.previous_hash != previous.block_hash:
          raise _EarlyReject(_invalid(block.index, "link"))
        if self._gateway.first_future_block([block]) is not None:
          raise _EarlyReject(_invalid(block.index, "timestamp_in_future"))
        previous = block
      fetched.append(block)
    return fetched

  async def _page(
    self, peer: PeerAddress, start: int, end: int | None = None
  ) -> tuple[int, list[Block]]:
    """One `GET /chain` page `start..end` (at most `page_size` blocks): the advertised tip and
    the decoded blocks, each checked to sit at its position."""
    last = start + self._page_size - 1 if end is None else min(end, start + self._page_size - 1)
    body = await self._fetcher.get_chain_page(peer.host, peer.port, start, last)
    page = ChainPage.model_validate(body)
    if page.from_index != start:
      raise SyncResponseError(f"asked for index {start}, got a page from {page.from_index}")
    if len(page.blocks) > self._page_size:
      raise SyncResponseError("the page holds more blocks than requested")
    decoded: list[Block] = []
    for offset, raw in enumerate(page.blocks):
      try:
        block = block_from_dict(raw)
      except Exception as exc:
        raise SyncResponseError(f"undecodable block at {start + offset}") from exc
      if block.index != start + offset:
        raise SyncResponseError(f"block at position {start + offset} says {_short(block.index)}")
      decoded.append(block)
    return page.tip_index, decoded


class _EarlyReject(Exception):
  """A downloading suffix broke its link or the future cap: stop fetching, reject it."""

  def __init__(self, result: ValidationResult) -> None:
    super().__init__(result.failure_type)
    self.result = result


def _invalid(index: int, failure_type: FailureType) -> ValidationResult:
  return ValidationResult(valid=False, first_invalid_index=index, failure_type=failure_type)
