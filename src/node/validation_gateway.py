"""The single FR-25 validation entry point.

Every path that judges a chain or a block - boot, cache refresh, PoW mining, peer broadcast,
and later chain sync and PBFT - goes through this module; nothing else in `node` may import
`validate_chain` / `validate_extension` (a static test enforces it). There is no "trusted
peer" shortcut: a block from any sender gets the same checklist.

`ChainValidator` binds the injected consensus parameters and the resolver holder, so each
call site validates with the same checklist and keys. `ValidationGateway.screen` adds the
cheap pre-checks an inbound block needs before the full extension check: authenticity,
duplicate / conflicting / stale classification, and the wall-clock skew window (a PoW block
must also not be older than the window: see `screen`).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from blockchain_core import (
  Block,
  ValidationResult,
  ValidatorSet,
  sha256_of_canonical,
  validate_candidate,
  validate_chain,
  validate_extension,
  verify_canonical,
)
from node.clock import reject_future_timestamp
from node.errors import ApiError
from node.key_resolver import ResolverHolder

logger = logging.getLogger("node.validation")


def first_duplicate_document(
  blocks: Sequence[Block], known: Callable[[str], bool] = lambda _hash: False
) -> int | None:
  """Index of the first block re-issuing a document hash already finalized (in `known` or in
  an earlier block of `blocks`) - the cross-block uniqueness rule the core leaves to the node."""
  seen: set[str] = set()
  for block in blocks:
    hashes = {record.document_hash for record in block.document_records}
    if hashes & seen or any(known(h) for h in hashes):
      return block.index
    seen |= hashes
  return None


def _duplicate(index: int) -> ValidationResult:
  return ValidationResult(valid=False, first_invalid_index=index, failure_type="duplicate_document")


class ChainValidator:
  def __init__(
    self,
    resolvers: ResolverHolder,
    *,
    expected_difficulty: int | None,
    validator_set: ValidatorSet | None,
  ) -> None:
    self._resolvers = resolvers
    self._expected_difficulty = expected_difficulty
    self._validator_set = validator_set

  def full(self, blocks: Sequence[Block]) -> ValidationResult:
    resolver = self._resolvers.current  # one snapshot per validation
    result = validate_chain(
      blocks,
      resolve_node_key=resolver.resolve_node_key,
      resolve_issuer_key=resolver.resolve_issuer_key,
      expected_difficulty=self._expected_difficulty,
      validator_set=self._validator_set,
    )
    if not result.valid:
      return result
    duplicate = first_duplicate_document(blocks)
    return result if duplicate is None else _duplicate(duplicate)

  @property
  def validator_set(self) -> ValidatorSet | None:
    return self._validator_set

  def candidate(self, trusted_tip: Block, block: Block) -> ValidationResult:
    """A PBFT candidate: the extension checklist minus the not-yet-possible commit quorum."""
    if self._validator_set is None:
      return ValidationResult(valid=False, first_invalid_index=block.index, failure_type="quorum")
    resolver = self._resolvers.current
    return validate_candidate(
      trusted_tip,
      block,
      resolve_node_key=resolver.resolve_node_key,
      resolve_issuer_key=resolver.resolve_issuer_key,
      validator_set=self._validator_set,
    )

  def extension(self, trusted_tip: Block, new_blocks: Sequence[Block]) -> ValidationResult:
    resolver = self._resolvers.current
    return validate_extension(
      trusted_tip,
      new_blocks,
      resolve_node_key=resolver.resolve_node_key,
      resolve_issuer_key=resolver.resolve_issuer_key,
      expected_difficulty=self._expected_difficulty,
      validator_set=self._validator_set,
    )


@dataclass(frozen=True)
class InboundVerdict:
  """accept: append it. duplicate: already ours, no-op. needs_sync: not our next block.
  reject: drop it, never append, never re-broadcast."""

  kind: Literal["accept", "duplicate", "needs_sync", "reject"]
  reason: str = ""  # unsigned | unknown_proposer | bad_signature | conflict | timestamp_in_future
  # | timestamp_too_old (PoW only)
  # | a core failure_type: hash, link, merkle, signature, structural, difficulty, quorum
  equivocation: bool = False  # a conflicting block validly signed by a ValidatorSet member

  @property
  def accepted(self) -> bool:
    return self.kind == "accept"


def _reject(reason: str, *, equivocation: bool = False) -> InboundVerdict:
  return InboundVerdict("reject", reason, equivocation)


class ValidationGateway:
  def __init__(
    self,
    validator: ChainValidator,
    resolvers: ResolverHolder,
    chain_view: Callable[[], Sequence[Block]],
    *,
    max_future_skew_ms: int,
    now_ms: Callable[[], int] = lambda: int(time.time() * 1000),
  ) -> None:
    self.validator = validator
    self._resolvers = resolvers
    self._chain_view = chain_view
    self._max_skew = max_future_skew_ms
    self._now_ms = now_ms

  def first_future_block(self, blocks: Sequence[Block]) -> int | None:
    """Index of the first block stamped beyond the future-skew cap (sync applies the same cap
    as the broadcast path), or None."""
    now = self._now_ms()
    for block in blocks:
      try:
        reject_future_timestamp(block.timestamp, now_ms=now, max_skew_ms=self._max_skew)
      except ApiError:
        return block.index
    return None

  def screen_candidate(
    self,
    block: Block,
    *,
    primary_id: str,
    view: int,
    known: Callable[[str], bool],
    allow_old: bool = False,
  ) -> InboundVerdict:
    """Judge a PBFT pre-prepare candidate before voting `prepare` on it (UC-6 step 2).

    The candidate gets the SAME per-block checklist as a finalized block, from our tip, via the
    core's `validate_candidate`: only the commit quorum is skipped (the votes do not exist
    yet). The timestamp must be within the skew window on BOTH sides: a primary must not
    back-date a block to a time when a since-retired key still resolved. `known` is the
    cross-block document-uniqueness rule. `allow_old` skips only the lower bound, for a block
    carried into a later view with a verified prepared certificate (old by definition; its
    `primary_id` / `view` are those of the view it was first proposed in)."""
    if block.algorithm != "pbft" or block.proposer_id != primary_id:
      return _reject("not_primary")
    if dict(block.sealed_consensus) != {"view_number": view} or block.commit_signatures:
      return _reject("structural")
    if not isinstance(block.proposer_signature, str) or not block.proposer_signature:
      return _reject("unsigned")
    blocks = self._chain_view()
    tip = blocks[-1]
    if block.index != tip.index + 1 or block.previous_hash != tip.block_hash:
      return _reject("link")
    now = self._now_ms()
    try:
      reject_future_timestamp(block.timestamp, now_ms=now, max_skew_ms=self._max_skew)
    except ApiError:
      return _reject("timestamp_in_future")
    if not allow_old and block.timestamp < now - self._max_skew:
      return _reject("timestamp_too_old")
    result = self.validator.candidate(tip, block)
    if not result.valid:
      return _reject(result.failure_type or "invalid")
    if first_duplicate_document([block], known) is not None:
      return _reject("duplicate_document")
    return InboundVerdict("accept")

  def finalized_conflict(self, block: Block) -> frozenset[str] | None:
    """The members that committed to BOTH `block` and the different block we hold at its
    height, when `block` is itself FINALIZED (full checklist, commit quorum included, on our
    chain's prefix): two finalized blocks at one height - a safety violation. None when it is
    not one (e.g. a relayed, never-finalized candidate). CPU-heavy: call it off the loop."""
    blocks = self._chain_view()
    validator_set = self.validator.validator_set
    if validator_set is None or not 1 <= block.index < len(blocks):
      return None
    stored = blocks[block.index]
    if stored.block_hash == block.block_hash:
      return None
    if len({c.node_id for c in block.commit_signatures}) < validator_set.quorum:
      return None  # cheap: cannot be finalized, skip the expensive checklist
    if not self.validator.extension(blocks[block.index - 1], [block]).valid:
      return None
    both = {c.node_id for c in block.commit_signatures} & {
      c.node_id for c in stored.commit_signatures
    }
    return frozenset(both)

  def screen(self, block: Block) -> InboundVerdict:
    """Judge a block received from any peer. Pure: it never mutates anything.

    A next-height block must be stamped within the skew window of our clock. For a PoW block
    the window has a lower bound too: otherwise a miner could back-date its block (any
    timestamp >= the tip's passes the core monotonicity check) to a time when a since-retired,
    possibly compromised issuer or node key still resolved. The honest miner keeps its
    timestamp fresh while mining (`PowEngine`). PBFT blocks are exempt from the lower bound: a
    block carried into a later view keeps its original timestamp, and its commit quorum - each
    member screened the candidate's age when it was first proposed - is the guard."""
    signature = block.proposer_signature
    if not isinstance(signature, str) or not signature:
      return _reject("unsigned")  # UC-8-E1
    resolver = self._resolvers.current
    proposer = block.proposer_id
    key = (
      resolver.resolve_node_key(proposer, block.timestamp) if isinstance(proposer, str) else None
    )
    if key is None:  # neither a ValidatorSet member nor a key we can verify (UC-8-E2/EC1)
      return _reject("unknown_proposer")
    # block_hash is not covered by the proposer signature, so recompute it: otherwise a relayed
    # copy with a doctored hash would be mistaken for a duplicate (or for equivocation).
    if sha256_of_canonical(block.preimage_dict()) != block.block_hash:
      return _reject("hash")
    if not verify_canonical(key, block.preimage_dict(), signature):
      return _reject("bad_signature")  # a forged proposer_id is not an equivocation

    blocks = self._chain_view()
    if not blocks:
      return _reject("structural")
    tip = blocks[-1]
    if block.index < 1:
      return _reject("structural")
    if block.index <= tip.index:
      stored = blocks[block.index]
      if stored.block_hash == block.block_hash:
        return InboundVerdict("duplicate")  # UC-7-EC1: idempotent
      # Equivocation = the SAME proposer validly signed two different blocks for one height.
      # Two different miners finding a block at once is an ordinary PoW fork, not a fault.
      byzantine = stored.proposer_id == proposer
      if byzantine:
        logger.warning("equivocation: %s signed two blocks at height %d", proposer, block.index)
      return _reject("conflict", equivocation=byzantine)  # first-finalized wins (UC-8-E4/EC2)
    if block.index > tip.index + 1:
      return InboundVerdict("needs_sync")
    now = self._now_ms()
    try:
      reject_future_timestamp(block.timestamp, now_ms=now, max_skew_ms=self._max_skew)
    except ApiError:
      return _reject("timestamp_in_future")
    if block.algorithm == "pow" and block.timestamp < now - self._max_skew:
      return _reject("timestamp_too_old")
    result = self.validator.extension(tip, [block])
    if not result.valid:
      return _reject(result.failure_type or "invalid")
    return InboundVerdict("accept")
