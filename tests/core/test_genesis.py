from __future__ import annotations

from blockchain_core.genesis import (
  GENESIS_BLOCK_HASH,
  GENESIS_MERKLE_ROOT,
  GENESIS_PREVIOUS_HASH,
  GENESIS_TIMESTAMP_MS,
  build_genesis_block,
)
from blockchain_core.hashing import sha256_hex, sha256_of_canonical


def test_genesis_block_matches_the_fixed_constants():
  genesis = build_genesis_block()

  assert genesis.index == 0
  assert genesis.timestamp == GENESIS_TIMESTAMP_MS
  assert genesis.previous_hash == GENESIS_PREVIOUS_HASH
  assert genesis.previous_hash == "0" * 64
  assert genesis.merkle_root == GENESIS_MERKLE_ROOT
  assert genesis.algorithm == "genesis"
  assert genesis.sealed_consensus == {}
  assert genesis.proposer_id is None
  assert genesis.proposer_signature is None
  assert genesis.commit_signatures == ()
  assert genesis.document_records == ()


def test_genesis_merkle_root_is_the_rfc6962_hash_of_zero_leaves():
  assert GENESIS_MERKLE_ROOT == sha256_hex(b"")


def test_genesis_block_hash_is_independently_recomputable_from_the_preimage():
  genesis = build_genesis_block()
  assert genesis.block_hash == sha256_of_canonical(genesis.preimage_dict())
  assert genesis.block_hash == GENESIS_BLOCK_HASH


def test_two_independently_constructed_genesis_blocks_are_byte_identical():
  """BC-TC-3.7 / C-1 closure: no shared state, no network call - only the
  module's fixed constants - yet both calls produce an identical block_hash.
  """
  first = build_genesis_block()
  second = build_genesis_block()

  assert first == second
  assert first.block_hash == second.block_hash


def test_a_mismatched_genesis_constant_produces_a_different_block_hash():
  """BC-TC-3.8: documents that customizing any genesis constant is an unsupported
  per-node policy, not a valid alternative configuration - it is simply a
  different, incompatible block_hash.
  """
  genesis = build_genesis_block()
  tampered_preimage = {**genesis.preimage_dict(), "timestamp": GENESIS_TIMESTAMP_MS + 1}

  assert sha256_of_canonical(tampered_preimage) != genesis.block_hash
