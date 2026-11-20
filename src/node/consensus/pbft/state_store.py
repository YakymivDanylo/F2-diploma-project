"""Durable PBFT voting state: what this node signed, the block it is locked on, its view.

Written atomically (temp file, fsync, rename) BEFORE a vote leaves the node, so a restarted
honest node never signs a second hash for a `(view, seq)` it already voted on, and keeps the
lock that the view-change safety argument relies on. A missing file is an empty state; an
unreadable one fails closed at boot (the operator must look at it), like the chain store.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blockchain_core import canonicalize

STATE_VERSION = 1


class PbftStateError(RuntimeError):
  """The persisted PBFT state cannot be read."""


@dataclass
class PbftState:
  view: int = 0
  signed: dict[tuple[int, int], str] = field(default_factory=dict)  # (view, seq) -> hash
  lock: dict[str, Any] | None = None  # {"cert": cert wire, "block": block dict}
  vc_vote: dict[str, Any] | None = None  # our open view-change vote (wire), if any

  def to_json(self) -> dict[str, Any]:
    return {
      "version": STATE_VERSION,
      "view": self.view,
      "signed": [[v, s, h] for (v, s), h in sorted(self.signed.items())],
      "lock": self.lock,
      "vc_vote": self.vc_vote,
    }


def _counter(value: object) -> int:
  if type(value) is not int or value < 0:
    raise ValueError("view / seq must be non-negative integers")
  return value


def _hash(value: object) -> str:
  if not isinstance(value, str) or len(value) != 64:
    raise ValueError("a signed hash must be 64 hex characters")
  return value


def _replace(source: Path, target: Path, attempts: int = 5) -> None:
  """`os.replace`, retried briefly: on Windows it fails while another handle (an antivirus or
  indexer, or a reader) has the target open."""
  for attempt in range(attempts):
    try:
      os.replace(source, target)
      return
    except PermissionError:
      if attempt == attempts - 1:
        raise
      time.sleep(0.02 * (attempt + 1))


def _sync_directory(directory: Path) -> None:
  """Make the rename durable where the platform allows it (POSIX); a no-op on Windows."""
  if os.name != "posix":
    return
  fd = os.open(directory, os.O_RDONLY)
  try:
    os.fsync(fd)
  finally:
    os.close(fd)


def state_path_for(chain_path: Path) -> Path:
  return chain_path.with_name(f"{chain_path.name}.pbft-state.json")


class PbftStateStore:
  def __init__(self, path: Path) -> None:
    self.path = path

  def load(self) -> PbftState:
    if not self.path.exists():
      return PbftState()
    try:
      data = json.loads(self.path.read_text(encoding="utf-8"))
      if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        raise ValueError("unsupported version")
      signed = {(_counter(v), _counter(s)): _hash(h) for v, s, h in data["signed"]}
      lock, vc_vote = data["lock"], data.get("vc_vote")
      if lock is not None and not isinstance(lock, dict):
        raise ValueError("lock must be an object")
      if vc_vote is not None and not isinstance(vc_vote, dict):
        raise ValueError("vc_vote must be an object")
      return PbftState(view=_counter(data["view"]), signed=signed, lock=lock, vc_vote=vc_vote)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
      raise PbftStateError(f"cannot read PBFT state {self.path}: {exc}") from exc

  def save(self, state: PbftState) -> None:
    data = canonicalize(state.to_json())
    temp = self.path.with_name(f".{self.path.name}.{secrets.token_hex(8)}.tmp")
    try:
      with open(temp, "xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
      _replace(temp, self.path)
      _sync_directory(self.path.parent)
    finally:
      with contextlib.suppress(FileNotFoundError):
        os.unlink(temp)
