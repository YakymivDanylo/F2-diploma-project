"""Chain synchronization and fork resolution (UC-3).

A node pulls `GET /chain` pages from its peers - at startup (bounded by
`STARTUP_SYNC_TIMEOUT_S`), periodically, and on demand when a broadcast block did not extend
its tip. The incoming chain is classified against the local one:

* strict, non-diverging extension (the peer holds our tip at our tip's height): only the new
  blocks are validated, incrementally from our trusted tip;
* divergence before our tip, or a local chain that is itself invalid: the ENTIRE incoming chain
  is fetched and validated from genesis - never incrementally (closes M-14).

Both modes run the single FR-25 checklist (`ChainValidator`, incl. PBFT commit quorum) plus the
node-layer rules every adopted block must meet: the future-timestamp cap of the broadcast path
and cross-block `document_hash` uniqueness. Adoption: PoW longest valid chain, ties broken by
the lowest tip `block_hash` as an unsigned integer (order-independent); PBFT highest finalized
height, and two differently-finalized blocks at one height are a Byzantine event - logged and
surfaced as `quorum_status`, never tie-broken. Adoption happens only through
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
from typing import Any, Literal, Protocol, cast

from pydantic import ValidationError

from blockchain_core import Block, ValidationResult, pow_target, sha256_of_canonical
from blockchain_core.storage.chain_store import block_from_dict
from node.api.chain import ChainPage
from node.chain_state import ChainState
from node.validation_gateway import ChainValidator, ValidationGateway, first_duplicate_document

logger = logging.getLogger("node.sync")

MAX_SYNC_BLOCKS = 100_000  # a peer cannot make us buffer an unbounded chain
DEFAULT_REQUEST_TIMEOUT_S = 5.0  # whole request, not per socket read
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # one page; bounded however the peer sends it
DEFAULT_PEER_TIMEOUT_S = 60.0  # one whole sync with one peer, however many pages
STARTUP_RETRY_S = 0.5
FETCH_WORKERS = 4  # a dedicated pool: stuck fetches never starve validation threads

Mode = Literal["pow", "pbft"]
Outcome = Literal["adopted", "not_better", "invalid", "byzantine", "unreachable", "malformed"]
CONFIRMED: frozenset[str] = frozenset({"adopted", "not_better", "byzantine"})


class SyncResponseError(Exception):
  """A peer's `GET /chain` answer is malformed, truncated or inconsistent (UC-3-E3)."""


class ChainFetcher(Protocol):
  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    """The decoded JSON body of `GET /chain?from=&to=`; transport errors raise."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, *args: Any, **kwargs: Any) -> None:
    return None  # a peer must not steer our GET to another address


class HttpChainFetcher:
  """Plain-HTTP default (Epic 6 swaps in the single TLS client factory). Every request is
  bounded in total time and size and runs on a small dedicated thread pool."""

  _pool = ThreadPoolExecutor(max_workers=FETCH_WORKERS, thread_name_prefix="chain-fetch")

  def __init__(
    self,
    timeout: float = DEFAULT_REQUEST_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
  ) -> None:
    self._timeout = timeout
    self._max_bytes = max_bytes
    self._opener = urllib.request.build_opener(_NoRedirect)

  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    url = f"http://{host}:{port}/chain?from={from_index}&to={to_index}"
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(self._pool, self._call, url)

  def _call(self, url: str) -> Any:
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
    self._wake = asyncio.Event()

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
    """Every known peer at once, each bounded by its own timeout (and by `budget_s`), so one
    slow peer cannot starve the others. Adoptions are serialised by the `ChainState` lock and
    `prefer`, so a worse chain never replaces a better one. A better chain judged against a tip
    that another peer's adoption moved meanwhile is refused as stale and adopted by the next
    round (which re-classifies it against the new tip)."""
    peers = list(self._peers())
    timeout = self._peer_timeout if budget_s is None else min(self._peer_timeout, budget_s)
    results = await asyncio.gather(*(self.sync_with(peer, timeout) for peer in peers))
    return {peer.node_id: outcome for peer, outcome in zip(peers, results, strict=True)}

  # ------------------------------------------------------------------- one peer

  async def sync_with(self, peer: PeerAddress, timeout_s: float | None = None) -> Outcome:
    try:
      return await asyncio.wait_for(self._sync_with(peer), timeout=timeout_s or self._peer_timeout)
    except TimeoutError:
      logger.warning("chain sync with %s timed out", peer.node_id)
      return "unreachable"
    except (SyncResponseError, ValidationError) as exc:
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
    local = self._state.blocks
    if not self._state.extendable:  # an untrusted local tip: never validate incrementally
      return await self._adopt_full(peer, reason="local chain is invalid")
    base = len(local)
    target, tail = await self._fetch(peer, base - 1)
    if target < base - 1 or not tail:
      return "not_better"  # the peer is behind us
    if tail[0].block_hash == local[-1].block_hash:  # strict, non-diverging extension
      if len(tail) == 1:
        return "not_better"  # the same chain
      return await self._adopt_extension(peer, local, tail[1:])
    # divergence at or below our tip
    if self._mode == "pbft":
      return await self._pbft_divergence(peer, height=base - 1)
    if target == base - 1 and not pow_prefers(local, (*local[:-1], tail[0])):
      return "not_better"  # equal length, our tip hash is lower: keep ours, no download
    if not self._claims_real_work(tail):  # forcing a full download must cost real PoW work
      logger.warning("%s advertised a fork without valid proof of work", peer.node_id)
      self._flag(peer.node_id, "invalid chain: fork without proof of work")
      return "invalid"
    return await self._adopt_full(peer, reason="fork diverges before the local tip")

  async def _adopt_extension(
    self, peer: PeerAddress, local: tuple[Block, ...], new_blocks: Sequence[Block]
  ) -> Outcome:
    base = len(local)
    candidate = (*local, *new_blocks)
    trusted_tip = local[-1]
    verdicts: list[ValidationResult] = []

    def validate(chain: Sequence[Block]) -> ValidationResult:
      known = {r.document_hash for block in chain[:base] for r in block.document_records}
      result = self._checked(
        chain[base:],
        lambda: self._validator.extension(trusted_tip, chain[base:]),
        known=known.__contains__,
      )
      verdicts.append(result)
      return result

    def prefer(current: tuple[Block, ...], chain: tuple[Block, ...]) -> bool:
      # appends may have landed while we waited: the candidate must still extend them
      still_extends = len(chain) > len(current) and (
        chain[len(current) - 1].block_hash == current[-1].block_hash
      )
      return still_extends and self._rule(current, chain)

    return await self._replace(peer, candidate, validate, prefer, verdicts, "incremental")

  async def _adopt_full(self, peer: PeerAddress, *, reason: str) -> Outcome:
    _, chain = await self._fetch(peer, 0)
    if not chain:
      return "not_better"
    verdicts: list[ValidationResult] = []

    def validate(blocks: Sequence[Block]) -> ValidationResult:
      result = self._checked(blocks, lambda: self._validator.full(blocks))
      verdicts.append(result)
      return result

    def prefer(current: tuple[Block, ...], blocks: tuple[Block, ...]) -> bool:
      # an invalid local chain is judged by its valid prefix: healing never rolls back
      return self._rule(self._state.trusted_blocks, blocks)

    logger.info("full-from-genesis validation of %s's chain: %s", peer.node_id, reason)
    return await self._replace(peer, tuple(chain), validate, prefer, verdicts, "full")

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
      result = verdicts[-1]
      logger.warning(
        "%s served an invalid chain (%s at index %s); keeping the local chain",
        peer.node_id,
        result.failure_type,
        result.first_invalid_index,
      )
      self._flag(peer.node_id, f"invalid chain: {result.failure_type}")
      return "invalid"
    return "not_better"

  async def _pbft_divergence(self, peer: PeerAddress, *, height: int) -> Outcome:
    """Two finalized PBFT blocks at one height cannot both be honest: never tie-break. Only
    blocks from a fully validated chain are compared, so an unsigned forgery cannot raise a
    false alarm."""
    _, chain = await self._fetch(peer, 0)
    result = await asyncio.to_thread(
      lambda: self._checked(chain, lambda: self._validator.full(chain))
    )
    if not result.valid:
      self._flag(peer.node_id, f"invalid chain: {result.failure_type}")
      return "invalid"
    if len(chain) <= height:
      return "not_better"  # the validated chain does not reach that height after all
    ours = self._state.blocks
    if not self._state.extendable or height >= len(ours):
      return "not_better"
    theirs = chain[height]
    if ours[height].block_hash != theirs.block_hash:
      self._state.report_byzantine_event(
        f"{peer.node_id} holds a differently-finalized block at height {height} "
        f"({theirs.block_hash} vs local {ours[height].block_hash})"
      )
      return "byzantine"
    return "not_better"

  # -------------------------------------------------------------------- helpers

  def _rule(self, current: Sequence[Block], candidate: Sequence[Block]) -> bool:
    if self._mode == "pow":
      return pow_prefers(current, candidate)
    return pbft_prefers(current, candidate)

  def _claims_real_work(self, blocks: Sequence[Block]) -> bool:
    """Cheap pre-check before a full download: every advertised fork block hashes to its
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

  async def _fetch(self, peer: PeerAddress, start: int) -> tuple[int, list[Block]]:
    """Blocks `start..tip` of the peer's chain, page by page; the target tip is the one the
    first page reports, so a peer that keeps growing cannot keep us fetching forever."""
    fetched: list[Block] = []
    next_index = start
    target: int | None = None
    while True:
      body = await self._fetcher.get_chain_page(
        peer.host, peer.port, next_index, next_index + self._page_size - 1
      )
      page = ChainPage.model_validate(body)
      if page.from_index != next_index:
        raise SyncResponseError(f"asked for index {next_index}, got a page from {page.from_index}")
      if len(page.blocks) > self._page_size:
        raise SyncResponseError("the page holds more blocks than requested")
      if target is None:
        target = page.tip_index
        if target - start + 1 > MAX_SYNC_BLOCKS:
          raise SyncResponseError("the peer's chain exceeds the sync limit")
      if next_index > target:
        return target, fetched
      if not page.blocks:
        raise SyncResponseError(f"empty page at {next_index} below the advertised tip {target}")
      for offset, raw in enumerate(page.blocks):
        try:
          block = block_from_dict(raw)
        except Exception as exc:
          raise SyncResponseError(f"undecodable block at {next_index + offset}") from exc
        if block.index != next_index + offset:
          raise SyncResponseError(
            f"block at position {next_index + offset} says {_short(block.index)}"
          )
        fetched.append(block)
      next_index += len(page.blocks)
      if next_index > target:
        return target, fetched[: target - start + 1]


def _invalid(index: int, failure_type: str) -> ValidationResult:
  return ValidationResult(
    valid=False, first_invalid_index=index, failure_type=cast(Any, failure_type)
  )
