from __future__ import annotations

import threading

import pytest

from blockchain_core.block import build_candidate_block
from blockchain_core.chain import Chain, NonSequentialIndexError, StalePreviousHashError
from blockchain_core.document_record import create_document_record
from blockchain_core.genesis import build_genesis_block
from blockchain_core.hashing import sha256_hex
from blockchain_core.keys import generate_keypair

_ISSUER = generate_keypair()
_ISSUER_ID = "issuer-1"


def _resolve_issuer_key(issuer_id: str):
  if issuer_id == _ISSUER_ID:
    return _ISSUER.public_key
  return None

def _record(seed: int):
  return create_document_record(
    document_hash=sha256_hex(f"document-{seed}".encode()),
    issuer_id=_ISSUER_ID,
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed},
    issuer_private_key=_ISSUER.private_key,
  )

def _candidate(*, previous_hash: str, index: int, timestamp: int = 1_700_000_000_001):
  return build_candidate_block(
    [_record(index)],
    previous_hash=previous_hash,
    index=index,
    timestamp=timestamp,
    proposer_id="node-1",
    algorithm="pow",
    sealed_consensus={"nonce": 0, "difficulty": 1},
    resolve_issuer_key=_resolve_issuer_key,
  )


def test_chain_is_never_empty_and_starts_with_genesis_as_tip():
  chain = Chain()

  assert len(chain) == 1
  assert chain.tip == build_genesis_block()
  assert chain.blocks == (build_genesis_block(),)


def test_append_valid_candidate_extends_the_chain_and_becomes_the_new_tip():
  chain = Chain()
  candidate = _candidate(previous_hash=chain.tip.block_hash, index=1)

  chain.append(candidate)

  assert len(chain) == 2
  assert chain.tip == candidate


def test_append_rejects_a_stale_previous_hash():
  chain = Chain()
  stale = _candidate(previous_hash=sha256_hex(b"not-the-real-tip"), index=1)

  with pytest.raises(StalePreviousHashError):
    chain.append(stale)
  assert len(chain) == 1


def test_append_rejects_an_index_that_skips_ahead():
  chain = Chain()
  skipping = _candidate(previous_hash=chain.tip.block_hash, index=2)

  with pytest.raises(NonSequentialIndexError):
    chain.append(skipping)
  assert len(chain) == 1


def test_append_rejects_a_duplicate_index():
  chain = Chain()
  first = _candidate(previous_hash=chain.tip.block_hash, index=1)
  chain.append(first)

  duplicate = _candidate(previous_hash=first.block_hash, index=1, timestamp=1_700_000_000_002)

  with pytest.raises(NonSequentialIndexError):
    chain.append(duplicate)
  assert len(chain) == 2


def test_concurrent_append_for_the_same_next_index_leaves_exactly_one_winner():
  chain = Chain()
  tip_hash = chain.tip.block_hash
  candidate_a = _candidate(previous_hash=tip_hash, index=1, timestamp=1_700_000_000_001)
  candidate_b = _candidate(previous_hash=tip_hash, index=1, timestamp=1_700_000_000_002)

  results: list[Exception | None] = [None, None]

  def _append(position: int, candidate) -> None:
    try:
      chain.append(candidate)
    except (StalePreviousHashError, NonSequentialIndexError) as exc:
      results[position] = exc

  t1 = threading.Thread(target=_append, args=(0, candidate_a))
  t2 = threading.Thread(target=_append, args=(1, candidate_b))
  t1.start()
  t2.start()
  t1.join()
  t2.join()

  assert len(chain) == 2
  assert sum(1 for result in results if result is None) == 1
  assert sum(1 for result in results if result is not None) == 1
