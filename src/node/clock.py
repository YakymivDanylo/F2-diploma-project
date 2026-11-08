"""Wall-clock policy that blockchain_core deliberately does not enforce."""

from __future__ import annotations

from node.errors import ApiError


def reject_future_timestamp(timestamp_ms: int, *, now_ms: int, max_skew_ms: int) -> None:
  """Reject a timestamp more than `max_skew_ms` ahead of the local clock.

  Core validation checks monotonicity only; without this node-layer cap an inflated tip
  timestamp would block every later honest block. Exactly at the cap is accepted.
  """
  if timestamp_ms > now_ms + max_skew_ms:
    raise ApiError(
      422,
      "timestamp_in_future",
      "timestamp is too far ahead of the local clock",
      {"max_skew_ms": max_skew_ms},
    )
