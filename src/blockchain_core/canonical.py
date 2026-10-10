"""Canonical byte-encoding used everywhere a hash or signature is computed.

Allowed values: `str`, `int` (|n| < 2**64), `bool`, `None`, `list`/`tuple` (both encode as
a JSON array), and `dict`/read-only mappings with `str` keys. Anything else - floats, bytes,
sets, lone surrogates, oversized ints, over-deep nesting - raises `CanonicalizationError`,
never a bare `TypeError`/`ValueError`, so callers can fail closed on hostile input.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

MAX_DEPTH = 64
MAX_INT = 2**64


class CanonicalizationError(ValueError):
  """Raised when a structure cannot be canonically encoded."""


def _validate(value: Any, depth: int = 0) -> Any:
  if depth > MAX_DEPTH:
    raise CanonicalizationError(f"canonical encoding forbids nesting deeper than {MAX_DEPTH}")
  if value is None or isinstance(value, bool):
    return value
  if isinstance(value, int):
    if abs(value) >= MAX_INT:
      raise CanonicalizationError("canonical encoding forbids integers with |n| >= 2**64")
    return value
  if isinstance(value, float):
    raise CanonicalizationError(
      "canonical encoding forbids float values: use integer epoch-ms for timestamps"
    )
  if isinstance(value, str):
    try:
      value.encode("utf-8")
    except UnicodeEncodeError as exc:
      raise CanonicalizationError("canonical encoding forbids unpaired surrogates") from exc
    return value
  if isinstance(value, Mapping):
    normalized = {}
    for key, val in value.items():
      if not isinstance(key, str):
        raise CanonicalizationError(f"canonical encoding forbids non-string keys: got {key!r}")
      _validate(key, depth + 1)
      normalized[key] = _validate(val, depth + 1)
    return normalized
  if isinstance(value, list | tuple):
    return [_validate(item, depth + 1) for item in value]
  raise CanonicalizationError(f"canonical encoding forbids values of type {type(value).__name__}")


def canonicalize(obj: Any) -> bytes:
  """Encode `obj` as sorted-key, whitespace-free UTF-8 JSON; see the module docstring."""
  normalized = _validate(obj)
  try:
    return json.dumps(
      normalized,
      sort_keys=True,
      separators=(",", ":"),
      ensure_ascii=False,
    ).encode("utf-8")
  except (TypeError, ValueError, RecursionError) as exc:
    raise CanonicalizationError(f"cannot canonically encode value: {exc}") from exc


def deep_freeze(value: Any) -> Any:
  """Recursively replace dicts with read-only mappings and lists with tuples.

  The result still canonicalizes to the same bytes as the input, but can no longer be
  mutated in place, so a hashed or signed structure cannot silently drift afterwards.
  Unsupported types are left untouched and rejected later by `canonicalize`.
  """
  if isinstance(value, Mapping):
    return MappingProxyType({key: deep_freeze(val) for key, val in value.items()})
  if isinstance(value, list | tuple):
    return tuple(deep_freeze(item) for item in value)
  return value
