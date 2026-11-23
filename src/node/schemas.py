"""Shared request types: the 64-hex hash constraint and the metadata byte cap."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any

from pydantic import StringConstraints

from blockchain_core import CanonicalizationError, canonicalize
from node.errors import ApiError
from node.patterns import HASH_PATTERN

__all__ = ["HASH_PATTERN", "Hash64", "validate_metadata_size"]

Hash64 = Annotated[str, StringConstraints(pattern=HASH_PATTERN)]


def validate_metadata_size(metadata: Mapping[str, Any], max_bytes: int) -> None:
  """Reject metadata whose canonical encoding exceeds `max_bytes` (exactly at the cap: ok).

  Uses the one canonical encoder, i.e. the exact bytes that will be hashed and signed.
  """
  try:
    size = len(canonicalize(dict(metadata)))
  except CanonicalizationError as exc:
    raise ApiError(422, "invalid_metadata", f"metadata cannot be encoded: {exc}") from exc
  except RecursionError:
    raise ApiError(422, "invalid_metadata", "metadata is nested too deeply") from None
  if size > max_bytes:
    raise ApiError(
      422,
      "metadata_too_large",
      f"metadata is {size} bytes, the limit is {max_bytes}",
      {"size": size, "max_bytes": max_bytes},
    )
