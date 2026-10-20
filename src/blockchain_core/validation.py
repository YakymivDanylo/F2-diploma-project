"""Chain validation: core checklist with injected, time-aware key resolvers.

Performs no registry lookup and no network call - every key is obtained through a
caller-supplied resolver, and the consensus parameters (`expected_difficulty`,
`ValidatorSet`) are injected too. This is the single checklist reused by proposal-time,
sync-time, and cache-refresh callers, in full (`validate_chain`) or incrementally
(`validate_extension`) - both run exactly the same per-block checks, so no caller has a
lighter path.

The functions are total over hostile input: a malformed or tampered block yields a
failed `ValidationResult`, never an exception. The deliberate exceptions are inputs
that are not validatable at all: a zero-length chain, or a malformed consensus
parameter supplied by the caller (a configuration error, not an attack on the chain).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .block import Block
from .canonical import CanonicalizationError
from .document_record import DocumentRecord, verify_document_record
from .genesis import GENESIS_BLOCK_HASH, build_genesis_block
from .hashing import sha256_of_canonical
from .keys import KeyResolver, PublicKey
from .merkle import EmptyBatchError, build_root
from .signing import verify_canonical

FailureType = Literal["hash", "link", "merkle", "signature", "structural", "difficulty", "quorum"]

__all__ = [
  "MAX_DIFFICULTY",
  "MIN_DIFFICULTY",
  "FailureType",
  "InvalidChainInputError",
  "KeyResolver",
  "ValidationResult",
  "ValidatorSet",
  "pow_target",
  "validate_chain",
  "validate_extension",
]

MIN_DIFFICULTY = 1
MAX_DIFFICULTY = 256


class InvalidChainInputError(ValueError):
  """Raised when the input is not validatable (zero blocks, malformed consensus parameters)."""


@dataclass(frozen=True)
class ValidationResult:
  valid: bool
  first_invalid_index: int | None = None
  failure_type: FailureType | None = None

  def __post_init__(self) -> None:
    if self.valid != (self.failure_type is None and self.first_invalid_index is None):
      raise ValueError("a result is valid iff it has no failure_type and no first_invalid_index")


def pow_target(difficulty: int) -> int:
  """The numeric PoW target for `difficulty` leading zero bits: a hash passes iff it is below it.

  `block_hash` is read as a 256-bit unsigned big-endian integer, so `hash < 2**(256 - d)`
  is exactly "the top `d` bits are zero" - a numeric comparison, never a count of
  leading `"0"` characters (which only resolves difficulty in steps of 4 bits).
  """
  if type(difficulty) is not int or not MIN_DIFFICULTY <= difficulty <= MAX_DIFFICULTY:
    raise ValueError(
      f"difficulty must be an int in [{MIN_DIFFICULTY}, {MAX_DIFFICULTY}], got {difficulty!r}"
    )
  return 1 << (256 - difficulty)


@dataclass(frozen=True)
class ValidatorSet:
  """Static PBFT membership: the `node_id`s whose commit signatures count, and `f`.

  Keys are not held here - each member's key is resolved through the injected
  `resolve_node_key(node_id, block.timestamp)`, so rotated keys keep validating old
  blocks. Requires `n >= 3f + 1`.
  """

  members: frozenset[str]
  f: int

  def __post_init__(self) -> None:
    if not isinstance(self.members, frozenset) or not self.members:
      raise ValueError("members must be a non-empty frozenset of node ids")
    if not all(isinstance(member, str) and member for member in self.members):
      raise ValueError("every member must be a non-empty string node id")
    if type(self.f) is not int or self.f < 0:
      raise ValueError(f"f must be a non-negative int, got {self.f!r}")
    if len(self.members) < 3 * self.f + 1:
      raise ValueError(f"n={len(self.members)} cannot tolerate f={self.f}: need n >= 3f + 1")

  @property
  def n(self) -> int:
    return len(self.members)

  @property
  def quorum(self) -> int:
    """Distinct commit signers required: `2f + 1` for the canonical `n = 3f + 1`.

    Computed as `floor((n + f) / 2) + 1`, which equals `2f + 1` when `n = 3f + 1` and
    stays safe when `n` is larger: any two quorums then still share at least `f + 1`
    members, so at least one honest node is in both.
    """
    return (self.n + self.f) // 2 + 1


_VALID = ValidationResult(valid=True)


def _fail(index: int, failure_type: FailureType) -> ValidationResult:
  return ValidationResult(valid=False, first_invalid_index=index, failure_type=failure_type)


def _check_parameters(expected_difficulty: int | None, validator_set: ValidatorSet | None) -> None:
  if expected_difficulty is not None and validator_set is not None:
    # One consensus mode per network: accepting both would let each block pick the
    # cheaper check (e.g. a low-difficulty PoW block on a PBFT chain skips the quorum).
    raise InvalidChainInputError("pass expected_difficulty (PoW) or validator_set (PBFT), not both")
  if expected_difficulty is not None:
    try:
      pow_target(expected_difficulty)
    except ValueError as exc:
      raise InvalidChainInputError(f"invalid expected_difficulty: {exc}") from exc
  if validator_set is not None and not isinstance(validator_set, ValidatorSet):
    raise InvalidChainInputError(
      f"validator_set must be a ValidatorSet, got {type(validator_set).__name__}"
    )


def _recompute_hash(block: Block) -> str | None:
  try:
    return sha256_of_canonical(block.preimage_dict())
  except CanonicalizationError:
    return None


def _genesis_matches_constants(block: object) -> bool:
  """Full equality with the frozen genesis - preimage, hash, and every attestation/batch field."""
  expected = build_genesis_block()
  return (
    isinstance(block, Block)
    and block == expected
    and block.block_hash == GENESIS_BLOCK_HASH
    and _recompute_hash(block) == GENESIS_BLOCK_HASH
  )


def _well_formed(block: object) -> bool:
  """Type-level shape only; value mismatches are reported by the specific checks below."""
  return (
    isinstance(block, Block)
    and type(block.index) is int
    and type(block.timestamp) is int
    and isinstance(block.previous_hash, str)
    and isinstance(block.merkle_root, str)
    and isinstance(block.block_hash, str)
    and isinstance(block.proposer_id, str)
    and block.algorithm in ("pow", "pbft")
    and isinstance(block.sealed_consensus, Mapping)
    and isinstance(block.document_records, tuple)
    and all(isinstance(record, DocumentRecord) for record in block.document_records)
    and isinstance(block.commit_signatures, tuple)
  )


def _merkle_ok(block: Block) -> bool:
  try:
    return build_root(block.document_records) == block.merkle_root
  except (EmptyBatchError, CanonicalizationError):
    return False


def _resolve(resolver: KeyResolver, identity: str, timestamp: int) -> PublicKey | None:
  """A resolver that raises is treated exactly like NOT_FOUND: fail closed."""
  try:
    return resolver(identity, timestamp)
  except Exception:
    return None


def _signatures_ok(
  block: Block,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
) -> bool:
  if not block.proposer_id or not block.proposer_signature:
    return False
  node_key = _resolve(resolve_node_key, block.proposer_id, block.timestamp)
  if node_key is None:
    return False
  if not verify_canonical(node_key, block.preimage_dict(), block.proposer_signature):
    return False
  for record in block.document_records:
    issuer_key = _resolve(resolve_issuer_key, record.issuer_id, block.timestamp)
    if issuer_key is None or not verify_document_record(record, issuer_key):
      return False
  return True


def _structure_ok(block: Block, previous: Block) -> bool:
  hashes = [record.document_hash for record in block.document_records]
  return (
    block.index == previous.index + 1
    and block.timestamp >= previous.timestamp
    and len(set(hashes)) == len(hashes)
  )


def _pow_ok(block: Block, expected_difficulty: int | None) -> bool:
  """Declared difficulty must equal the injected one, and the hash must meet its target."""
  if expected_difficulty is None:
    return False
  declared = block.sealed_consensus.get("difficulty")
  if type(declared) is not int or declared != expected_difficulty:
    return False
  return int(block.block_hash, 16) < pow_target(declared)


def _key_fingerprint(key: object) -> bytes | None:
  if not isinstance(key, ec.EllipticCurvePublicKey | rsa.RSAPublicKey):
    return None
  return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _distinct_commit_signers(
  block: Block,
  validator_set: ValidatorSet,
  resolve_node_key: KeyResolver,
) -> set[str]:
  """Members with a valid signature over the preimage; each member is counted once.

  `commit_signatures` carries no signer id, so each signature is attributed to the
  member whose key (active at `block.timestamp`) verifies it. A matched member is
  removed from the candidates, so a repeated signer can never be counted twice, and
  the work stays bounded by `n` verifications per signature. Members that resolve to
  the same public key (a misconfiguration) count as one signer: one key, one vote.
  """
  candidates: dict[str, PublicKey] = {}
  seen_keys: set[bytes] = set()
  for node_id in sorted(validator_set.members):
    key = _resolve(resolve_node_key, node_id, block.timestamp)
    fingerprint = _key_fingerprint(key)
    if key is None or fingerprint is None or fingerprint in seen_keys:
      continue
    seen_keys.add(fingerprint)
    candidates[node_id] = key
  preimage = block.preimage_dict()
  signers: set[str] = set()
  for signature in block.commit_signatures:
    for node_id, key in candidates.items():
      if verify_canonical(key, preimage, signature):
        signers.add(node_id)
        del candidates[node_id]
        break
  return signers


def _quorum_ok(
  block: Block,
  validator_set: ValidatorSet | None,
  resolve_node_key: KeyResolver,
) -> bool:
  if validator_set is None:
    return False
  # A well-formed commit set holds at most one signature per member; anything longer
  # is rejected outright, which also bounds the verification work an attacker can force.
  if len(block.commit_signatures) > validator_set.n:
    return False
  signers = _distinct_commit_signers(block, validator_set, resolve_node_key)
  return len(signers) >= validator_set.quorum


def _consensus_failure(
  block: Block,
  resolve_node_key: KeyResolver,
  expected_difficulty: int | None,
  validator_set: ValidatorSet | None,
) -> FailureType | None:
  """Algorithm-specific checks; a missing parameter fails closed instead of skipping."""
  if block.algorithm == "pow" and not _pow_ok(block, expected_difficulty):
    return "difficulty"
  if block.algorithm == "pbft" and not _quorum_ok(block, validator_set, resolve_node_key):
    return "quorum"
  return None


def _validate_block(
  block: Block,
  previous: Block,
  previous_hash: str,
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None,
  validator_set: ValidatorSet | None,
) -> tuple[FailureType | None, str]:
  """The per-block checklist; returns (failure_type or None, this block's recomputed hash)."""
  if not _well_formed(block):
    return "structural", ""
  recomputed = _recompute_hash(block)
  if recomputed is None or recomputed != block.block_hash:
    return "hash", ""
  if block.previous_hash != previous_hash:
    return "link", recomputed
  if not _merkle_ok(block):
    return "merkle", recomputed
  if not _signatures_ok(block, resolve_node_key, resolve_issuer_key):
    return "signature", recomputed
  if not _structure_ok(block, previous):
    return "structural", recomputed
  failure = _consensus_failure(block, resolve_node_key, expected_difficulty, validator_set)
  return failure, recomputed


def _validate_run(
  blocks: Sequence[Block],
  previous: Block,
  previous_hash: str,
  start_position: int,
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None,
  validator_set: ValidatorSet | None,
) -> ValidationResult:
  for position, block in enumerate(blocks, start=start_position):
    failure, recomputed = _validate_block(
      block,
      previous,
      previous_hash,
      resolve_node_key=resolve_node_key,
      resolve_issuer_key=resolve_issuer_key,
      expected_difficulty=expected_difficulty,
      validator_set=validator_set,
    )
    if failure is not None:
      return _fail(position, failure)
    previous, previous_hash = block, recomputed
  return _VALID


def validate_chain(
  blocks: Sequence[Block],
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None = None,
  validator_set: ValidatorSet | None = None,
) -> ValidationResult:
  """Validate `blocks` front to back and report the earliest failing block.

  Per non-genesis block, in order: `"hash"`, `"link"`, `"merkle"`, `"signature"`
  (proposer and every document record), `"structural"` (index, timestamp, duplicate
  `document_hash` within the block), then the algorithm-specific check:

  - `"pow"`: `sealed_consensus["difficulty"]` must equal `expected_difficulty` and
    `block_hash` must be numerically below `pow_target(difficulty)` - else `"difficulty"`.
  - `"pbft"`: `commit_signatures` must hold valid preimage signatures from at least
    `validator_set.quorum` distinct members, keys resolved at `block.timestamp`; a
    repeated signer counts once - else `"quorum"`.

  A PoW block validated without `expected_difficulty`, or a PBFT block without
  `validator_set`, fails closed with that failure type - omitting a parameter never
  skips consensus verification. Pass exactly one of the two: a network runs one
  consensus mode, so a chain mixing `"pow"` and `"pbft"` blocks is never valid. A block
  whose fields have the wrong types, or an `algorithm` other than pow/pbft, is
  `"structural"`. Genesis must equal the frozen
  genesis block exactly (any difference is `"hash"` at position 0) and is exempt from
  both consensus checks. Unknown identities and resolvers that raise fail closed.

  `first_invalid_index` is the block's position in `blocks`, not its (possibly
  tampered) `index` field. Single pass, each block hashed once - O(n).

  Raises `InvalidChainInputError` for zero blocks, a malformed `expected_difficulty` /
  `validator_set`, or both of them at once.

  Not checked here (node-layer policy, Epic 3): `document_hash` uniqueness across
  blocks, and bounding `timestamp` against wall-clock time or key-revocation times.
  """
  if not blocks:
    raise InvalidChainInputError("cannot validate a chain of zero blocks")
  _check_parameters(expected_difficulty, validator_set)
  genesis = blocks[0]
  if not _genesis_matches_constants(genesis):
    return _fail(0, "hash")
  return _validate_run(
    blocks[1:],
    genesis,
    genesis.block_hash,
    1,
    resolve_node_key=resolve_node_key,
    resolve_issuer_key=resolve_issuer_key,
    expected_difficulty=expected_difficulty,
    validator_set=validator_set,
  )


def validate_extension(
  trusted_tip: Block,
  new_blocks: Sequence[Block],
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None = None,
  validator_set: ValidatorSet | None = None,
) -> ValidationResult:
  """Validate only `new_blocks` appended after an already-validated `trusted_tip`.

  Runs the identical per-block checklist as `validate_chain` - including the PoW and
  PBFT checks - so for a simple extension the result matches a full validation of
  `chain + new_blocks`. `first_invalid_index` is `trusted_tip.index + 1 + offset`. The
  tip is trusted, not re-verified: callers must only pass a tip they validated earlier.
  No new blocks is trivially valid.
  """
  _check_parameters(expected_difficulty, validator_set)
  return _validate_run(
    new_blocks,
    trusted_tip,
    trusted_tip.block_hash,
    trusted_tip.index + 1,
    resolve_node_key=resolve_node_key,
    resolve_issuer_key=resolve_issuer_key,
    expected_difficulty=expected_difficulty,
    validator_set=validator_set,
  )
