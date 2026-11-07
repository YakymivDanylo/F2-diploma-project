"""Slice 7: PoW difficulty/target and PBFT commit-quorum checks in chain validation.

Covers BC-TC-4.2, 4.6, 4.7, 4.8, 4.9, 4.10, 4.11, 4.22, 4.23 (UC-4 steps g/h, UC-4-E7/E8).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from blockchain_core.block import (
  Block,
  CommitSignature,
  attach_proposer_signature,
  build_candidate_block,
  sign_commit,
)
from blockchain_core.document_record import create_document_record
from blockchain_core.genesis import build_genesis_block
from blockchain_core.hashing import sha256_hex, sha256_of_canonical
from blockchain_core.keys import generate_issuer_keypair, generate_node_keypair
from blockchain_core.signing import sign_canonical
from blockchain_core.validation import (
  MAX_DIFFICULTY,
  MIN_DIFFICULTY,
  InvalidChainInputError,
  ValidationResult,
  ValidatorSet,
  pow_target,
  validate_chain,
  validate_extension,
)

_ISSUER = generate_issuer_keypair()
_ISSUER_ID = "issuer-1"
_VALIDATOR_IDS = ("v0", "v1", "v2", "v3")
_NODES = {node_id: generate_node_keypair() for node_id in _VALIDATOR_IDS}
_OUTSIDER_ID = "outsider"
_OUTSIDER = generate_node_keypair()
_VSET = ValidatorSet(members=frozenset(_VALIDATOR_IDS), n=4, f=1)
_BASE_TS = 1_700_000_001_000
_STEP = 1_000
# Not a multiple of 4: a "count leading '0' characters" check can only see 4-bit steps.
_DIFFICULTY = 6


def _resolve_issuer_key(issuer_id: str, at_timestamp: int):
  return _ISSUER.public_key if issuer_id == _ISSUER_ID else None


def _resolve_node_key(node_id: str, at_timestamp: int):
  if node_id == _OUTSIDER_ID:
    return _OUTSIDER.public_key
  pair = _NODES.get(node_id)
  return pair.public_key if pair else None


def _record(seed: int):
  return create_document_record(
    document_hash=sha256_hex(f"document-{seed}".encode()),
    issuer_id=_ISSUER_ID,
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed},
    issuer_private_key=_ISSUER.private_key,
  )


def _rehash(block: Block, **changes) -> Block:
  changed = replace(block, **changes)
  return replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))


def _candidate(previous: Block, seed: int, algorithm: str, sealed_consensus) -> Block:
  return build_candidate_block(
    [_record(seed)],
    previous_hash=previous.block_hash,
    index=previous.index + 1,
    timestamp=_BASE_TS + (previous.index + 1) * _STEP,
    proposer_id="v0",
    algorithm=algorithm,
    sealed_consensus=sealed_consensus,
    resolve_issuer_key=_resolve_issuer_key,
  )


def _search_nonce(block: Block, accept) -> Block:
  """Re-seal with increasing nonces until `accept(int(block_hash, 16))` holds."""
  nonce = 0
  while not accept(int(block.block_hash, 16)):
    nonce += 1
    block = _rehash(block, sealed_consensus={**block.sealed_consensus, "nonce": nonce})
  return block


def _sign(block: Block, node_id: str = "v0") -> Block:
  return attach_proposer_signature(block, _NODES[node_id].private_key)


def _pow_block(previous: Block, seed: int, *, difficulty: int = _DIFFICULTY, accept=None) -> Block:
  block = _candidate(previous, seed, "pow", {"nonce": 0, "difficulty": difficulty})
  target = pow_target(difficulty)
  return _sign(_search_nonce(block, accept or (lambda value: value < target)))


def _pow_chain(length: int, *, difficulty: int = _DIFFICULTY) -> list[Block]:
  blocks = [build_genesis_block()]
  for seed in range(1, length + 1):
    blocks.append(_pow_block(blocks[-1], seed, difficulty=difficulty))
  return blocks


def _preimage_signature(block: Block, key_pair) -> str:
  return sign_canonical(key_pair.private_key, block.preimage_dict())


def _commit(block: Block, node_id: str, key_pair=None) -> CommitSignature:
  keys = {**_NODES, _OUTSIDER_ID: _OUTSIDER}
  return sign_commit(block, node_id, (key_pair or keys[node_id]).private_key)


def _with_commits(block: Block, signer_ids) -> Block:
  commits = tuple(_commit(block, node_id) for node_id in signer_ids)
  return replace(block, commit_signatures=commits)


def _pbft_block(previous: Block, seed: int, signer_ids=_VALIDATOR_IDS[:3]) -> Block:
  block = _sign(_candidate(previous, seed, "pbft", {"view_number": 0}))
  return _with_commits(block, signer_ids)


def _pbft_chain(length: int, signer_ids=_VALIDATOR_IDS[:3]) -> list[Block]:
  blocks = [build_genesis_block()]
  for seed in range(1, length + 1):
    blocks.append(_pbft_block(blocks[-1], seed, signer_ids))
  return blocks


def _validate(blocks, **overrides):
  kwargs = {"resolve_node_key": _resolve_node_key, "resolve_issuer_key": _resolve_issuer_key}
  kwargs.update(overrides)
  return validate_chain(blocks, **kwargs)


def _validate_pow(blocks, **overrides):
  return _validate(blocks, expected_difficulty=_DIFFICULTY, **overrides)


def _validate_pbft(blocks, **overrides):
  return _validate(blocks, validator_set=_VSET, **overrides)


def _assert_invalid(result: ValidationResult, index: int, failure_type: str) -> None:
  assert result.valid is False
  assert result.first_invalid_index == index
  assert result.failure_type == failure_type


# ---------------------------------------------------------------- pow_target


def test_target_is_two_to_the_256_minus_difficulty():
  assert pow_target(1) == 1 << 255
  assert pow_target(_DIFFICULTY) == 1 << 250
  assert pow_target(256) == 1


@pytest.mark.parametrize("difficulty", [MIN_DIFFICULTY - 1, MAX_DIFFICULTY + 1, -1, True, 6.0, "6"])
def test_target_rejects_invalid_difficulty(difficulty):
  with pytest.raises(ValueError, match="difficulty"):
    pow_target(difficulty)


# ---------------------------------------------------------------- PoW (UC-4 step g)


# TC-4.1
def test_valid_pow_chain_validates():
  assert _validate_pow(_pow_chain(3)) == ValidationResult(valid=True)


# TC-4.6
def test_hash_with_right_zero_char_format_but_failing_numeric_target_is_rejected():
  # One leading "0" hex char (what a naive `startswith("0" * (d // 4))` checks), but
  # the hash is >= 2**250, so the top 6 bits are not all zero.
  genesis = build_genesis_block()
  block = _pow_block(genesis, 1, accept=lambda value: 1 << 250 <= value < 1 << 252)

  assert block.block_hash.startswith("0" * (_DIFFICULTY // 4))
  assert int(block.block_hash, 16) >= pow_target(_DIFFICULTY)
  _assert_invalid(_validate_pow([genesis, block]), 1, "difficulty")


# TC-4.22
def test_block_failing_its_own_declared_target_is_rejected():
  genesis = build_genesis_block()
  block = _pow_block(genesis, 1, accept=lambda value: value >= pow_target(_DIFFICULTY))

  _assert_invalid(_validate_pow([genesis, block]), 1, "difficulty")


# TC-4.7
def test_self_consistent_lower_declared_difficulty_is_rejected():
  blocks = _pow_chain(1, difficulty=1)

  assert _validate(blocks, expected_difficulty=1).valid  # internally self-consistent
  _assert_invalid(_validate_pow(blocks), 1, "difficulty")


def test_higher_declared_difficulty_than_expected_is_rejected():
  """The match is exact: a stronger self-declared difficulty is still not the network's."""
  blocks = _pow_chain(1, difficulty=_DIFFICULTY + 2)

  _assert_invalid(_validate_pow(blocks), 1, "difficulty")


def test_difficulty_failure_reported_at_first_offending_block():
  blocks = _pow_chain(2)
  blocks.append(_pow_block(blocks[-1], 3, difficulty=1))

  _assert_invalid(_validate_pow(blocks), 3, "difficulty")


def test_pow_block_without_expected_difficulty_fails_closed():
  _assert_invalid(_validate(_pow_chain(1)), 1, "difficulty")


@pytest.mark.parametrize(
  "sealed",
  [
    {"nonce": 0},
    {"nonce": 0, "difficulty": "6"},
    {"nonce": 0, "difficulty": True},
    {"nonce": 0, "difficulty": None},
  ],
  ids=["missing", "string", "bool", "none"],
)
def test_malformed_declared_difficulty_is_rejected(sealed):
  genesis = build_genesis_block()
  block = _sign(_rehash(_pow_block(genesis, 1), sealed_consensus=sealed))

  _assert_invalid(_validate_pow([genesis, block]), 1, "difficulty")


@pytest.mark.parametrize("expected", [0, MAX_DIFFICULTY + 1, -3, True, "6"])
def test_malformed_expected_difficulty_parameter_raises(expected):
  with pytest.raises(InvalidChainInputError, match="expected_difficulty"):
    _validate(_pow_chain(1), expected_difficulty=expected)


def test_difficulty_is_checked_before_merkle_and_signatures():
  """Proof of work is the cheap filter: an unmined block is rejected before any signature."""
  genesis = build_genesis_block()
  block = _pow_block(genesis, 1, accept=lambda value: value >= pow_target(_DIFFICULTY))
  block = replace(block, proposer_signature=_preimage_signature(block, _OUTSIDER))

  _assert_invalid(_validate_pow([genesis, block]), 1, "difficulty")


def test_hash_chain_checks_take_precedence_over_difficulty():
  blocks = _pow_chain(2)
  unlinked = _rehash(blocks[2], previous_hash="ab" * 32)

  _assert_invalid(_validate_pow([*blocks[:2], unlinked]), 2, "link")


# ---------------------------------------------------------------- ValidatorSet


def _ids(count: int) -> frozenset[str]:
  return frozenset(f"n{i}" for i in range(count))


@pytest.mark.parametrize(
  ("n", "f", "quorum"),
  [(1, 0, 1), (4, 1, 3), (7, 2, 5), (10, 3, 7), (4, 0, 3), (5, 1, 4)],
)
def test_quorum_size(n, f, quorum):
  assert ValidatorSet(members=_ids(n), n=n, f=f).quorum == quorum


def test_quorum_is_two_f_plus_one_for_canonical_n():
  for f in range(6):
    n = 3 * f + 1
    assert ValidatorSet(members=_ids(n), n=n, f=f).quorum == 2 * f + 1


def test_any_two_quorums_share_an_honest_member():
  for n in range(1, 20):
    for f in range(0, (n - 1) // 3 + 1):
      quorum = ValidatorSet(members=_ids(n), n=n, f=f).quorum
      assert 2 * quorum - n >= f + 1


def test_quorum_follows_configured_n_not_the_member_count():
  """Retired validators stay listed for old blocks without raising the quorum."""
  with_retired = ValidatorSet(members=_ids(6), n=4, f=1)

  assert with_retired.quorum == 3


@pytest.mark.parametrize(
  ("members", "n", "f"),
  [
    (frozenset(), 0, 0),
    (frozenset({"a", "b", "c"}), 3, 1),
    (frozenset({"a", ""}), 2, 0),
    (frozenset({"a", 1}), 2, 0),
    ({"a", "b", "c", "d"}, 4, 1),
    (frozenset({"a"}), 1, -1),
    (frozenset({"a"}), 1, True),
    (frozenset({"a", "b", "c"}), 4, 1),
    (frozenset({"a", "b", "c", "d"}), True, 0),
  ],
  ids=[
    "empty",
    "n_lt_3f_plus_1",
    "empty_id",
    "non_str_id",
    "plain_set",
    "negative_f",
    "bool_f",
    "fewer_members_than_n",
    "bool_n",
  ],
)
def test_validator_set_rejects_invalid_configuration(members, n, f):
  with pytest.raises(ValueError):
    ValidatorSet(members=members, n=n, f=f)


def test_wrong_validator_set_type_raises():
  with pytest.raises(InvalidChainInputError, match="ValidatorSet"):
    _validate(_pbft_chain(1), validator_set=frozenset(_VALIDATOR_IDS))


# ---------------------------------------------------------------- PBFT (UC-4 step h)


# TC-4.2
@pytest.mark.parametrize("signers", [_VALIDATOR_IDS[:3], _VALIDATOR_IDS], ids=["2f+1", "all"])
def test_valid_pbft_chain_validates(signers):
  assert _validate_pbft(_pbft_chain(3, signers)) == ValidationResult(valid=True)


def test_quorum_need_not_include_the_proposer():
  assert _validate_pbft(_pbft_chain(2, ("v1", "v2", "v3"))).valid


# TC-4.8
@pytest.mark.parametrize("signers", [(), ("v0",), ("v0", "v1")], ids=["none", "one", "two"])
def test_fewer_than_quorum_distinct_signers_is_rejected(signers):
  _assert_invalid(_validate_pbft(_pbft_chain(1, signers)), 1, "quorum")


# TC-4.9
def test_repeated_identical_signature_counts_once():
  _assert_invalid(_validate_pbft(_pbft_chain(1, ("v0", "v0", "v1"))), 1, "quorum")


def test_repeated_signer_with_distinct_signature_bytes_counts_once():
  """ECDSA is randomized: two signatures by v0 differ as strings but are one signer."""
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, ("v0", "v0", "v1"))

  assert block.commit_signatures[0].signature != block.commit_signatures[1].signature
  _assert_invalid(_validate_pbft([genesis, block]), 1, "quorum")


def test_quorum_with_an_extra_repeated_signer_still_validates():
  assert _validate_pbft(_pbft_chain(1, ("v0", "v1", "v2", "v0"))).valid


def test_more_commit_signatures_than_members_is_rejected():
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, _VALIDATOR_IDS)
  padded = replace(
    block, commit_signatures=(*block.commit_signatures, CommitSignature("v0", "ab" * 64))
  )

  _assert_invalid(_validate_pbft([genesis, padded]), 1, "quorum")


def test_non_member_signature_does_not_count():
  _assert_invalid(_validate_pbft(_pbft_chain(1, ("v0", "v1", _OUTSIDER_ID))), 1, "quorum")


def test_commit_signature_over_another_block_does_not_count():
  genesis = build_genesis_block()
  other = _pbft_block(genesis, 99, ())
  block = _pbft_block(genesis, 1, ("v0", "v1"))
  forged = replace(
    block,
    commit_signatures=(*block.commit_signatures, _commit(other, "v2")),
  )

  _assert_invalid(_validate_pbft([genesis, forged]), 1, "quorum")


@pytest.mark.parametrize(
  "junk",
  ["", "zz", "AB" * 32, "ab" * 32 + " "],
  ids=["empty", "non_hex", "uppercase", "whitespace"],
)
def test_malformed_commit_signature_does_not_count_and_does_not_raise(junk):
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, ("v0", "v1"))
  forged = replace(block, commit_signatures=(*block.commit_signatures, CommitSignature("v2", junk)))

  _assert_invalid(_validate_pbft([genesis, forged]), 1, "quorum")


@pytest.mark.parametrize(
  "entry",
  ["ab" * 32, None, CommitSignature("v2", None), CommitSignature(None, "ab" * 32)],
  ids=["bare_string", "none", "signature_none", "node_id_none"],
)
def test_malformed_commit_entry_is_structural(entry):
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, ("v0", "v1"))
  forged = replace(block, commit_signatures=(*block.commit_signatures, entry))

  _assert_invalid(_validate_pbft([genesis, forged]), 1, "structural")


# Domain separation (security audit H1): only a commit vote over the commit payload counts
def test_proposer_signature_replayed_as_commit_vote_does_not_count():
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, ("v1", "v2"))  # proposer v0 did not vote
  replayed = CommitSignature("v0", block.proposer_signature)
  forged = replace(block, commit_signatures=(*block.commit_signatures, replayed))

  _assert_invalid(_validate_pbft([genesis, forged]), 1, "quorum")


def test_signature_over_the_bare_preimage_does_not_count_as_commit():
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, ("v0", "v1"))
  preimage_vote = CommitSignature("v2", _preimage_signature(block, _NODES["v2"]))
  forged = replace(block, commit_signatures=(*block.commit_signatures, preimage_vote))

  _assert_invalid(_validate_pbft([genesis, forged]), 1, "quorum")


def test_commit_vote_labelled_with_another_members_id_does_not_count():
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, ("v0", "v1"))
  mislabelled = _commit(block, "v2", _NODES["v3"])  # v3's signature claiming to be v2
  forged = replace(block, commit_signatures=(*block.commit_signatures, mislabelled))

  _assert_invalid(_validate_pbft([genesis, forged]), 1, "quorum")


def test_pbft_block_proposed_by_a_non_member_is_rejected():
  genesis = build_genesis_block()
  candidate = _rehash(_candidate(genesis, 1, "pbft", {"view_number": 0}), proposer_id=_OUTSIDER_ID)
  block = attach_proposer_signature(candidate, _OUTSIDER.private_key)
  block = _with_commits(block, ("v0", "v1", "v2"))  # a full quorum of real members

  _assert_invalid(_validate_pbft([genesis, block]), 1, "quorum")


def test_retired_member_listed_in_members_only_counts_while_its_key_resolves():
  vset = ValidatorSet(members=frozenset({*_VALIDATOR_IDS, "retired"}), n=4, f=1)
  retired_key = generate_node_keypair()
  blocks = _pbft_chain(2, ("v0", "v1"))
  for position in (1, 2):
    block = blocks[position]
    blocks[position] = replace(
      block, commit_signatures=(*block.commit_signatures, _commit(block, "retired", retired_key))
    )
  retired_at = blocks[2].timestamp

  def resolver(node_id, at_timestamp):
    if node_id == "retired":
      return retired_key.public_key if at_timestamp < retired_at else None
    return _resolve_node_key(node_id, at_timestamp)

  _assert_invalid(_validate(blocks, validator_set=vset, resolve_node_key=resolver), 2, "quorum")


def test_non_tuple_commit_signatures_is_structural():
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1)
  forged = replace(block, commit_signatures=list(block.commit_signatures))

  _assert_invalid(_validate_pbft([genesis, forged]), 1, "structural")


def test_member_without_resolvable_key_does_not_count():
  def resolver(node_id, at_timestamp):
    return None if node_id == "v2" else _resolve_node_key(node_id, at_timestamp)

  result = _validate_pbft(_pbft_chain(1, ("v0", "v1", "v2")), resolve_node_key=resolver)

  _assert_invalid(result, 1, "quorum")


def test_member_whose_resolver_raises_does_not_count():
  def resolver(node_id, at_timestamp):
    if node_id == "v2":
      raise RuntimeError("registry down")
    return _resolve_node_key(node_id, at_timestamp)

  result = _validate_pbft(_pbft_chain(1, ("v0", "v1", "v2")), resolve_node_key=resolver)

  _assert_invalid(result, 1, "quorum")


def test_commit_keys_are_resolved_at_block_timestamp():
  """A rotated validator key still verifies the commits of blocks made before rotation."""
  old_v2, new_v2 = _NODES["v2"], generate_node_keypair()
  blocks = _pbft_chain(2)
  rotation_ts = blocks[2].timestamp
  calls = []

  def resolver(node_id, at_timestamp):
    calls.append((node_id, at_timestamp))
    if node_id == "v2":
      return (old_v2 if at_timestamp < rotation_ts else new_v2).public_key
    return _resolve_node_key(node_id, at_timestamp)

  _assert_invalid(_validate_pbft(blocks, resolve_node_key=resolver), 2, "quorum")
  assert ("v2", blocks[1].timestamp) in calls
  assert ("v2", blocks[2].timestamp) in calls

  # Re-signing block 2's commit with the post-rotation key makes the chain valid.
  v2_commit = _commit(blocks[2], "v2", new_v2)
  blocks[2] = replace(blocks[2], commit_signatures=(*blocks[2].commit_signatures[:2], v2_commit))
  assert _validate_pbft(blocks, resolve_node_key=resolver).valid


def test_pbft_block_without_validator_set_fails_closed():
  _assert_invalid(_validate(_pbft_chain(1)), 1, "quorum")


def test_quorum_failure_reported_at_first_offending_block():
  blocks = _pbft_chain(2)
  blocks.append(_pbft_block(blocks[-1], 3, ("v0", "v1")))

  _assert_invalid(_validate_pbft(blocks), 3, "quorum")


def test_earlier_checks_take_precedence_over_quorum():
  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, ("v0",))
  tampered = _rehash(block, merkle_root="ab" * 32)

  _assert_invalid(_validate_pbft([genesis, tampered]), 1, "merkle")


# ---------------------------------------------------------------- shared checklist


# TC-4.11
@pytest.mark.parametrize(
  "params",
  [{}, {"expected_difficulty": _DIFFICULTY}, {"validator_set": _VSET}],
  ids=["no_params", "pow_params", "pbft_params"],
)
def test_genesis_is_exempt_from_consensus_checks(params):
  assert _validate([build_genesis_block()], **params).valid


def test_each_algorithm_needs_its_own_parameter():
  _assert_invalid(_validate(_pbft_chain(1), expected_difficulty=_DIFFICULTY), 1, "quorum")
  _assert_invalid(_validate(_pow_chain(1), validator_set=_VSET), 1, "difficulty")


def test_both_consensus_parameters_at_once_raise():
  """One mode per network: with both, each block could pick the cheaper check."""
  with pytest.raises(InvalidChainInputError, match="not both"):
    _validate(_pow_chain(1), expected_difficulty=_DIFFICULTY, validator_set=_VSET)
  with pytest.raises(InvalidChainInputError, match="not both"):
    validate_extension(
      build_genesis_block(),
      [],
      resolve_node_key=_resolve_node_key,
      resolve_issuer_key=_resolve_issuer_key,
      expected_difficulty=_DIFFICULTY,
      validator_set=_VSET,
    )


def test_pow_block_in_a_pbft_chain_is_rejected():
  """A low-difficulty PoW block cannot be slipped into a PBFT chain to dodge the quorum."""
  blocks = _pbft_chain(1)
  blocks.append(_pow_block(blocks[-1], 2, difficulty=1))

  _assert_invalid(_validate_pbft(blocks), 2, "difficulty")


def test_members_sharing_one_public_key_count_as_one_signer():
  """A misconfigured resolver mapping two ids to one key must not double that key's vote."""

  def resolver(node_id, at_timestamp):
    return _resolve_node_key("v0" if node_id == "v1" else node_id, at_timestamp)

  genesis = build_genesis_block()
  block = _pbft_block(genesis, 1, ("v0", "v2"))
  block = replace(
    block, commit_signatures=(*block.commit_signatures, _commit(block, "v1", _NODES["v0"]))
  )

  _assert_invalid(_validate_pbft([genesis, block], resolve_node_key=resolver), 1, "quorum")
  assert _validate_pbft([genesis, _pbft_block(genesis, 1, ("v0", "v2", "v3"))]).valid


# TC-4.10, TC-4.23 (core level: full and incremental validation share one checklist)
def test_full_and_incremental_validation_reject_quorum_deficit_identically():
  blocks = _pbft_chain(2)
  blocks.append(_pbft_block(blocks[-1], 3, ("v0", "v1")))
  kwargs = {
    "resolve_node_key": _resolve_node_key,
    "resolve_issuer_key": _resolve_issuer_key,
    "validator_set": _VSET,
  }

  full = validate_chain(blocks, **kwargs)
  revalidated = validate_chain(list(blocks), **kwargs)
  incremental = validate_extension(blocks[2], blocks[3:], **kwargs)

  assert full == revalidated == incremental
  _assert_invalid(full, 3, "quorum")


def test_full_and_incremental_validation_reject_difficulty_identically():
  blocks = _pow_chain(2)
  blocks.append(_pow_block(blocks[-1], 3, difficulty=1))
  kwargs = {
    "resolve_node_key": _resolve_node_key,
    "resolve_issuer_key": _resolve_issuer_key,
    "expected_difficulty": _DIFFICULTY,
  }

  full = validate_chain(blocks, **kwargs)
  incremental = validate_extension(blocks[2], blocks[3:], **kwargs)

  assert full == incremental
  _assert_invalid(full, 3, "difficulty")


def test_extension_rejects_malformed_parameters():
  blocks = _pow_chain(1)

  with pytest.raises(InvalidChainInputError):
    validate_extension(
      blocks[0],
      blocks[1:],
      resolve_node_key=_resolve_node_key,
      resolve_issuer_key=_resolve_issuer_key,
      expected_difficulty=0,
    )
