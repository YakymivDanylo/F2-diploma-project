"""Helpers for the Slice 17 PBFT tests: signed candidates and votes, send spies, drains."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from chain_factory import _candidate
from network_helpers import ClusterNode, until
from node_helpers import NodeEnv

from blockchain_core import Block, attach_proposer_signature, build_genesis_block
from blockchain_core.storage.chain_store import block_to_dict
from node.consensus.pbft.messages import COMMIT, PRE_PREPARE, Kind, PbftMessage, make_message

IDS = ("node1", "node2", "node3", "node4")


def now_ms() -> int:
  return int(time.time() * 1000)


def signed_candidate(
  env: NodeEnv,
  seed: int,
  *,
  proposer: str = "node1",
  timestamp: int | None = None,
  view: int = 0,
  previous: Block | None = None,
) -> Block:
  """A proposer-signed PBFT candidate on `previous` (genesis by default), stamped 'now'."""
  parent = previous or build_genesis_block()
  block = _candidate(
    env,
    parent,
    seed,
    "pbft",
    {"view_number": view},
    proposer,
    now_ms() if timestamp is None else timestamp,
  )
  return attach_proposer_signature(block, env.validator_keys[proposer].private_key)


def vote(
  env: NodeEnv,
  kind: Kind,
  node_id: str,
  block: Block,
  *,
  view: int = 0,
  seq: int | None = None,
  block_hash: str | None = None,
) -> PbftMessage:
  """A message of `kind` for `block`, signed with `node_id`'s validator key."""
  return make_message(
    kind,
    env.validator_keys[node_id].private_key,
    view=view,
    seq=block.index if seq is None else seq,
    block_hash=block.block_hash if block_hash is None else block_hash,
    node_id=node_id,
    block=block_to_dict(block) if kind == PRE_PREPARE else None,
  )


def rehash(block: Block, **changes: Any) -> Block:
  """`block` with `changes` applied, re-hashed (so only the changed field is wrong)."""
  from blockchain_core import sha256_of_canonical

  changed = replace(block, **changes)
  return replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))


def resign(env: NodeEnv, block: Block, proposer: str = "node1") -> Block:
  return attach_proposer_signature(block, env.validator_keys[proposer].private_key)


def record_sends(node: ClusterNode) -> list[tuple[dict[str, Any], set[str] | None]]:
  """Spy on everything `node` fans out: (message, `only` filter) in send order."""
  sent: list[tuple[dict[str, Any], set[str] | None]] = []
  original = node.manager.broadcast

  async def spy(message: dict[str, Any], *, only: Iterable[str] | None = None):
    sent.append((message, None if only is None else set(only)))
    return await original(message, only=only)

  node.manager.broadcast = spy  # type: ignore[method-assign]
  return sent


def sent_of(
  sent: list[tuple[dict[str, Any], set[str] | None]], kind: str, seq: int | None = None
) -> list[dict[str, Any]]:
  return [m for m, _ in sent if m.get("type") == kind and (seq is None or m.get("seq") == seq)]


async def drain(node: ClusterNode) -> None:
  """Wait until the engine has worked through everything submitted so far."""
  await until(lambda: not node.engine._inbox)
  await asyncio.sleep(0.03)


def feed(node: ClusterNode, *messages: PbftMessage) -> None:
  for message in messages:
    node.engine.submit(message)


async def propose(node: ClusterNode, env: NodeEnv, seed: int) -> None:
  from chain_factory import _record

  record = _record(env, seed)
  node.context.mempool.add(record)
  node.engine.on_submission(record)


__all__ = [
  "COMMIT",
  "IDS",
  "drain",
  "feed",
  "now_ms",
  "propose",
  "record_sends",
  "rehash",
  "resign",
  "sent_of",
  "signed_candidate",
  "vote",
]
