"""Deterministic genesis block - fixed constants, byte-identical on every node."""

from __future__ import annotations

from typing import Any

from .block import Block
from .hashing import sha256_of_canonical

GENESIS_TIMESTAMP_MS = 1_700_000_000_000
"""Fixed epoch-ms constant - never computed at runtime, identical on every node."""

GENESIS_MERKLE_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"""RFC 6962-style hash of zero leaves: SHA-256 of the empty byte string.

Hardcoded rather than derived from `merkle.build_root`, because that function has
no defined output for zero records by design (UC-2-E1 reserves the empty-batch
case for genesis only, never produced via the normal block-build flow).
"""

GENESIS_PREVIOUS_HASH = "0" * 64


def _genesis_preimage() -> dict[str, Any]:
  return {
    "index": 0,
    "timestamp": GENESIS_TIMESTAMP_MS,
    "previous_hash": GENESIS_PREVIOUS_HASH,
    "merkle_root": GENESIS_MERKLE_ROOT,
    "proposer_id": None,
    "algorithm": "genesis",
    "sealed_consensus": {},
  }


GENESIS_BLOCK_HASH = sha256_of_canonical(_genesis_preimage())
"""Deterministic function of the fixed constants above - identical on every node,
every process start, with no network communication required (closes C-1)."""


def build_genesis_block() -> Block:
  """The single, network-wide genesis block: no proposer, no attestation, no batch."""
  return Block(
    index=0,
    timestamp=GENESIS_TIMESTAMP_MS,
    previous_hash=GENESIS_PREVIOUS_HASH,
    merkle_root=GENESIS_MERKLE_ROOT,
    proposer_id=None,
    algorithm="genesis",
    sealed_consensus={},
    document_records=(),
    block_hash=GENESIS_BLOCK_HASH,
  )
