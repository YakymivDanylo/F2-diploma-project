"""Cached chain validity behind `GET /node/info`.

The cache is initialized at boot and updated only by append/replace events - never by a
timer and never by a request. `ChainValidator` binds the injected consensus parameters and
the resolver holder, so every call site validates with the same checklist and keys.
(Slice 15 promotes this binding into the single FR-25 validation entry point.)
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from blockchain_core import (
  Block,
  ValidationResult,
  ValidatorSet,
  validate_chain,
  validate_extension,
)
from node.key_resolver import ResolverHolder

QUORUM_HEALTHY = "healthy"
QUORUM_INVALID = "quorum_invalid"  # the chain failed the commit-quorum check


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
    return validate_chain(
      blocks,
      resolve_node_key=resolver.resolve_node_key,
      resolve_issuer_key=resolver.resolve_issuer_key,
      expected_difficulty=self._expected_difficulty,
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
class CacheSnapshot:
  chain_valid: bool
  first_invalid_index: int | None
  failure_type: str | None
  tip_index: int
  quorum_status: str


def _snapshot(result: ValidationResult, tip_index: int) -> CacheSnapshot:
  quorum = QUORUM_INVALID if result.failure_type == "quorum" else QUORUM_HEALTHY
  return CacheSnapshot(
    chain_valid=result.valid,
    first_invalid_index=result.first_invalid_index,
    failure_type=result.failure_type,
    tip_index=tip_index,
    quorum_status=quorum,
  )


class ValidityCache:
  def __init__(self, validator: ChainValidator) -> None:
    self._validator = validator
    self._tip: Block | None = None
    self._snapshot: CacheSnapshot | None = None

  @property
  def snapshot(self) -> CacheSnapshot:
    if self._snapshot is None:
      raise RuntimeError("validity cache is not initialized")
    return self._snapshot

  def initialize(self, blocks: Sequence[Block], result: ValidationResult | None = None) -> None:
    """Boot: reuse the restore-time `result` when given, else validate fully once."""
    outcome = result if result is not None else self._validator.full(blocks)
    self._tip = blocks[-1]
    self._snapshot = _snapshot(outcome, len(blocks) - 1)

  def on_replace(self, blocks: Sequence[Block]) -> None:
    self._tip = blocks[-1]
    self._snapshot = _snapshot(self._validator.full(blocks), len(blocks) - 1)

  def on_append(self, block: Block) -> None:
    """Validate only the new block against the trusted tip - O(1), no full revalidation."""
    current = self.snapshot
    tip = self._tip
    if tip is None:
      raise RuntimeError("validity cache is not initialized")
    tip_index = current.tip_index + 1
    if current.chain_valid:
      self._snapshot = _snapshot(self._validator.extension(tip, [block]), tip_index)
    else:  # an invalid chain stays invalid; only the tip moves
      self._snapshot = CacheSnapshot(
        chain_valid=False,
        first_invalid_index=current.first_invalid_index,
        failure_type=current.failure_type,
        tip_index=tip_index,
        quorum_status=current.quorum_status,
      )
    self._tip = block
