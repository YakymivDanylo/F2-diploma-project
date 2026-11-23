"""Durable PBFT voting state: what this node signed, the block it is locked on, its view.

Written atomically (temp file, fsync, rename) BEFORE a vote leaves the node, so a restarted
honest node never signs a second hash for a `(view, seq)` it already voted on, and keeps the
lock that the view-change safety argument relies on. An unreadable file fails closed at boot
(the operator must look at it), like the chain store; so does a path that is not a regular
file (a symlink or a directory). A MISSING file is not silently an empty state: the engine
accepts it only on a fresh chain (tip index 0), where nothing can have been signed yet, or
when the operator explicitly allows it (`PBFT_ALLOW_MISSING_STATE`) - a node that lost the
file could otherwise sign a second vote for a `(view, seq)` or forget its lock.

The file also keeps the Byzantine events this node observed (bounded as in the validity cache), so
the sticky `byzantine_event_detected` status and its evidence survive a restart.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blockchain_core import canonicalize

STATE_VERSION = 1
MAX_PERSISTED_EVENTS = 128  # = the validity cache's overall bound (MAX_BYZANTINE_EVENTS)
MAX_EVENT_REASON = 1024


class PbftStateError(RuntimeError):
  """The persisted PBFT state cannot be read."""


@dataclass
class PbftState:
  view: int = 0
  signed: dict[tuple[int, int], str] = field(default_factory=dict)  # (view, seq) -> hash
  lock: dict[str, Any] | None = None  # {"cert": cert wire, "block": block dict}
  vc_vote: dict[str, Any] | None = None  # our open view-change vote (wire), if any
  # Byzantine events observed here: {"reason", "offender", "at_ms"}, most recent last
  byzantine_events: list[dict[str, Any]] = field(default_factory=list)

  def to_json(self) -> dict[str, Any]:
    return {
      "version": STATE_VERSION,
      "view": self.view,
      "signed": [[v, s, h] for (v, s), h in sorted(self.signed.items())],
      "lock": self.lock,
      "vc_vote": self.vc_vote,
      "byzantine_events": [dict(e) for e in self.byzantine_events[-MAX_PERSISTED_EVENTS:]],
    }


def _counter(value: object) -> int:
  if type(value) is not int or value < 0:
    raise ValueError("view / seq must be non-negative integers")
  return value


def _hash(value: object) -> str:
  if not isinstance(value, str) or len(value) != 64:
    raise ValueError("a signed hash must be 64 hex characters")
  return value


def _event(value: object) -> dict[str, Any]:
  if not isinstance(value, dict) or set(value) != {"reason", "offender", "at_ms"}:
    raise ValueError("a byzantine event must be {reason, offender, at_ms}")
  reason, offender, at_ms = value["reason"], value["offender"], value["at_ms"]
  if not isinstance(reason, str) or len(reason) > MAX_EVENT_REASON:
    raise ValueError("a byzantine event reason must be a short string")
  if offender is not None and not isinstance(offender, str):
    raise ValueError("a byzantine event offender must be a string or null")
  if type(at_ms) is not int or at_ms < 0:
    raise ValueError("a byzantine event at_ms must be a non-negative integer")
  return {"reason": reason, "offender": offender, "at_ms": at_ms}


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

  def exists(self) -> bool:
    """Whether the state file exists. Fails closed (`PbftStateError`) on a path that is not a
    regular file - a symlink or a directory is never followed or treated as missing."""
    try:
      mode = os.lstat(self.path).st_mode
    except FileNotFoundError:
      return False
    except OSError as exc:
      raise PbftStateError(f"cannot stat PBFT state {self.path}: {exc}") from exc
    if not stat.S_ISREG(mode):
      raise PbftStateError(f"PBFT state {self.path} is not a regular file")
    return True

  def load(self) -> PbftState:
    """The persisted state; an empty one if the file is missing (whether that is acceptable
    is the engine's decision, see the module docstring)."""
    if not self.exists():
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
      raw_events = data.get("byzantine_events", [])
      if not isinstance(raw_events, list):
        raise ValueError("byzantine_events must be a list")
      events = [_event(e) for e in raw_events[-MAX_PERSISTED_EVENTS:]]
      return PbftState(
        view=_counter(data["view"]),
        signed=signed,
        lock=lock,
        vc_vote=vc_vote,
        byzantine_events=events,
      )
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
