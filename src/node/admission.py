"""Mempool admission rules shared by the primary's own `POST /documents` and the
`forward_record` intake (UC-4-EC2, UC-16-EC4).

Both callers hold `context.submission_lock` around these checks and the queueing, so the
duplicate check and the insert are one atomic step with no await in between.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from node.context import NodeContext


def is_known(context: NodeContext, document_hash: str) -> bool:
  """Already finalized, already pending here, or being forwarded by this node."""
  return (
    context.chain_state.has_document(document_hash)
    or context.mempool.contains(document_hash)
    or document_hash in context.inflight
  )


def mempool_full(context: NodeContext) -> bool:
  return len(context.mempool) + len(context.inflight) >= context.config.mempool_max_size
