"""Chain persistence: JSON and SQLite backends behind one contract, plus startup restore.

Three independent logical stores make up a node's durable state: the chain (here), the
`IssuerKeyPair`, and the `NodeKeyPair` (`key_store`). Both chain backends persist the
same canonical per-block encoding, so a chain saved by one reloads byte-for-byte
identically from the other.

Loading only checks the *shape* of what is on disk: a truncated, non-JSON or
structurally wrong file raises `ChainStoreCorruptedError` and the node must not start.
A well-formed but tampered chain loads fine and is then judged by `validate_chain`;
`restore_chain` surfaces that result and hands back no extendable `Chain` when it fails.

The store enforces a single-writer requirement: it holds an exclusive OS lock on
`<path>.lock` for its whole lifetime, so a second store on the same path - an accidental
double start, in this process or another - fails with `ChainStoreLockedError` instead of
interleaving writes. The lock is released on `close()` or when the process dies; the
`.lock` file itself is left in place and is harmless.

Changing `expected_difficulty` invalidates every persisted PoW block mined under the
old value (`failure_type == "difficulty"`). That is by design: a new difficulty needs a
fresh chain on every node, not a restart against the old one.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import sqlite3
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, Self

from ..block import Block
from ..canonical import MAX_DEPTH, canonicalize
from ..chain import Chain
from ..document_record import DocumentRecord
from ..keys import IssuerKeyPair, KeyResolver, NodeKeyPair
from ..validation import ValidationResult, ValidatorSet, validate_chain
from .key_store import load_issuer_key_pair, load_node_key_pair

if sys.platform == "win32":
  import msvcrt
else:
  import fcntl

__all__ = [
  "CHAIN_FORMAT",
  "CHAIN_FORMAT_VERSION",
  "ChainStore",
  "ChainStoreCorruptedError",
  "ChainStoreError",
  "ChainStoreLockedError",
  "ChainStoreWriteError",
  "JsonChainStore",
  "NodeState",
  "RestoredChain",
  "SqliteChainStore",
  "block_from_dict",
  "block_to_dict",
  "decode_chain",
  "encode_chain",
  "restore_chain",
  "restore_node_state",
]

CHAIN_FORMAT = "blockchain_core.chain"
CHAIN_FORMAT_VERSION = 1

_BLOCK_KEYS = frozenset(
  {
    "index",
    "timestamp",
    "previous_hash",
    "merkle_root",
    "proposer_id",
    "algorithm",
    "sealed_consensus",
    "document_records",
    "block_hash",
    "proposer_signature",
    "commit_signatures",
  }
)
_RECORD_KEYS = frozenset(
  {"document_hash", "issuer_id", "issued_at", "metadata", "ipfs_cid", "signature"}
)
_DOCUMENT_KEYS = frozenset({"format", "version", "blocks"})


class ChainStoreError(Exception):
  """Base class for chain-store failures."""


class ChainStoreCorruptedError(ChainStoreError, ValueError):
  """Raised when a chain store exists but cannot be decoded into blocks."""


class ChainStoreLockedError(ChainStoreError):
  """Raised when another open store already holds the single-writer lock for a path."""


class ChainStoreWriteError(ChainStoreError):
  """Raised when saving fails for an I/O reason (disk full, permissions) - not corruption."""


# ---------------------------------------------------------------- encoding


def _thaw(value: Any) -> Any:
  """Undo `deep_freeze`: read-only mappings become dicts, tuples become lists."""
  if isinstance(value, Mapping):
    return {key: _thaw(item) for key, item in value.items()}
  if isinstance(value, list | tuple):
    return [_thaw(item) for item in value]
  return value


def block_to_dict(block: Block) -> dict[str, Any]:
  """Every Block field as plain JSON data (dicts, lists, str, int, None)."""
  result: dict[str, Any] = _thaw(
    {
      **block.preimage_dict(),
      "document_records": [record.signed_dict() for record in block.document_records],
      "block_hash": block.block_hash,
      "proposer_signature": block.proposer_signature,
      "commit_signatures": block.commit_signatures,
    }
  )
  return result


def _corrupt(message: str) -> ChainStoreCorruptedError:
  return ChainStoreCorruptedError(f"chain store is corrupted: {message}")


def _require_keys(data: object, expected: frozenset[str], what: str) -> Mapping[str, Any]:
  if not isinstance(data, Mapping):
    raise _corrupt(f"{what} must be an object, got {type(data).__name__}")
  if set(data) != expected:
    missing, extra = sorted(expected - set(data)), sorted(set(data) - expected)
    raise _corrupt(f"{what} has missing keys {missing} / unexpected keys {extra}")
  return data


def _int(data: Mapping[str, Any], key: str, what: str) -> int:
  value = data[key]
  if type(value) is not int:
    raise _corrupt(f"{what}.{key} must be an integer")
  return value


def _str(data: Mapping[str, Any], key: str, what: str, *, optional: bool = False) -> Any:
  value = data[key]
  if not (isinstance(value, str) or (optional and value is None)):
    raise _corrupt(f"{what}.{key} must be a string{' or null' if optional else ''}")
  return value


def _record_from_dict(data: object, what: str) -> DocumentRecord:
  fields = _require_keys(data, _RECORD_KEYS, what)
  metadata = fields["metadata"]
  if not isinstance(metadata, Mapping):
    raise _corrupt(f"{what}.metadata must be an object")
  return DocumentRecord(
    document_hash=_str(fields, "document_hash", what),
    issuer_id=_str(fields, "issuer_id", what),
    issued_at=_int(fields, "issued_at", what),
    metadata=metadata,
    ipfs_cid=_str(fields, "ipfs_cid", what, optional=True),
    signature=_str(fields, "signature", what, optional=True),
  )


# A block dict nests records (2 levels) above the canonical structures they contain.
_MAX_BLOCK_DEPTH = MAX_DEPTH + 3


def _check_depth(data: object) -> None:
  """Reject over-deep nesting iteratively, before anything recursive touches it."""
  stack: list[tuple[object, int]] = [(data, 0)]
  while stack:
    value, depth = stack.pop()
    if depth > _MAX_BLOCK_DEPTH:
      raise _corrupt(f"nesting deeper than {_MAX_BLOCK_DEPTH} levels")
    if isinstance(value, Mapping):
      stack.extend((item, depth + 1) for item in value.values())
    elif isinstance(value, list | tuple):
      stack.extend((item, depth + 1) for item in value)


def block_from_dict(data: object) -> Block:
  """Rebuild a Block from `block_to_dict` output, checking shape only - never validity."""
  _check_depth(data)
  fields = _require_keys(data, _BLOCK_KEYS, "block")
  what = f"block[{fields.get('index')!r}]"
  sealed = fields["sealed_consensus"]
  if not isinstance(sealed, Mapping):
    raise _corrupt(f"{what}.sealed_consensus must be an object")
  records = fields["document_records"]
  if not isinstance(records, list):
    raise _corrupt(f"{what}.document_records must be an array")
  commits = fields["commit_signatures"]
  if not isinstance(commits, list) or not all(isinstance(c, str) for c in commits):
    raise _corrupt(f"{what}.commit_signatures must be an array of strings")
  return Block(
    index=_int(fields, "index", what),
    timestamp=_int(fields, "timestamp", what),
    previous_hash=_str(fields, "previous_hash", what),
    merkle_root=_str(fields, "merkle_root", what),
    proposer_id=_str(fields, "proposer_id", what, optional=True),
    algorithm=_str(fields, "algorithm", what),
    sealed_consensus=sealed,
    document_records=tuple(
      _record_from_dict(record, f"{what}.document_records[{position}]")
      for position, record in enumerate(records)
    ),
    block_hash=_str(fields, "block_hash", what),
    proposer_signature=_str(fields, "proposer_signature", what, optional=True),
    commit_signatures=tuple(commits),
  )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
  result: dict[str, Any] = {}
  for key, value in pairs:
    if key in result:
      raise _corrupt(f"duplicate object key {key!r}")
    result[key] = value
  return result


def _reject_constant(name: str) -> Any:
  raise _corrupt(f"non-finite number {name} is not allowed")


def _reject_float(text: str) -> Any:
  raise _corrupt(f"float {text} is not allowed (integers only)")


def _parse_json(data: bytes) -> Any:
  """Strict JSON: UTF-8 only, no floats/NaN, no duplicate keys - nothing ambiguous."""
  try:
    return json.loads(
      data.decode("utf-8"),
      object_pairs_hook=_reject_duplicate_keys,
      parse_constant=_reject_constant,
      parse_float=_reject_float,
    )
  except ChainStoreCorruptedError:
    raise
  except (UnicodeDecodeError, ValueError, RecursionError) as exc:
    raise _corrupt(f"not valid JSON: {exc}") from exc


def encode_chain(blocks: Sequence[Block]) -> bytes:
  """Canonical bytes of the whole chain document - identical for identical chains."""
  return canonicalize(
    {
      "format": CHAIN_FORMAT,
      "version": CHAIN_FORMAT_VERSION,
      "blocks": [block_to_dict(block) for block in blocks],
    }
  )


def decode_chain(data: bytes) -> list[Block]:
  document = _require_keys(_parse_json(data), _DOCUMENT_KEYS, "chain document")
  if document["format"] != CHAIN_FORMAT:
    raise _corrupt(f"unknown format {document['format']!r}")
  if document["version"] != CHAIN_FORMAT_VERSION or type(document["version"]) is not int:
    raise _corrupt(f"unsupported version {document['version']!r}")
  blocks = document["blocks"]
  if not isinstance(blocks, list) or not blocks:
    raise _corrupt("blocks must be a non-empty array (a chain always holds genesis)")
  return [_decode_block(block) for block in blocks]


def _decode_block(data: object) -> Block:
  try:
    return block_from_dict(data)
  except ChainStoreCorruptedError:
    raise
  except (TypeError, ValueError, RecursionError) as exc:
    raise _corrupt(f"block cannot be rebuilt: {exc}") from exc


# ---------------------------------------------------------------- single-writer lock


def _acquire_lock(lock_path: Path) -> int:
  flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
  fd = os.open(lock_path, flags, 0o644)
  try:
    if sys.platform == "win32":
      msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
      fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
  except OSError as exc:
    os.close(fd)
    raise ChainStoreLockedError(
      f"chain store {lock_path.with_suffix('')} is already open by another writer"
    ) from exc
  return fd


def _release_lock(fd: int) -> None:
  try:
    if sys.platform == "win32":
      os.lseek(fd, 0, os.SEEK_SET)
      msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
      fcntl.flock(fd, fcntl.LOCK_UN)
  finally:
    os.close(fd)


# ---------------------------------------------------------------- backends


def _is_stored(path: Path) -> bool:
  """True for an existing regular file, False when absent; anything else is corrupted.

  A symlink (dangling or not) or a special file in place of the store is never followed
  and never mistaken for "no chain yet".
  """
  try:
    mode = os.lstat(path).st_mode
  except FileNotFoundError:
    return False
  if not stat.S_ISREG(mode):
    raise _corrupt(f"{path} is not a regular file (symlink or special file)")
  return True


class ChainStore(Protocol):
  """The contract every backend honours; `restore_chain` depends only on this."""

  def load(self) -> list[Block] | None:
    """The persisted blocks, or None when nothing was ever saved."""
    ...

  def save(self, blocks: Sequence[Block]) -> None:
    """Replace the persisted chain with `blocks`, atomically."""
    ...

  def close(self) -> None: ...


class _LockedStore:
  def __init__(self, path: str | Path) -> None:
    self.path = Path(path)
    self.path.parent.mkdir(parents=True, exist_ok=True)
    self._lock_fd: int | None = _acquire_lock(self.path.with_name(self.path.name + ".lock"))

  def close(self) -> None:
    if self._lock_fd is not None:
      fd, self._lock_fd = self._lock_fd, None
      _release_lock(fd)

  def _require_open(self) -> None:
    if self._lock_fd is None:
      raise ChainStoreError(f"chain store {self.path} is closed")

  def __enter__(self) -> Self:
    return self

  def __exit__(
    self,
    exc_type: type[BaseException] | None,
    exc: BaseException | None,
    traceback: TracebackType | None,
  ) -> None:
    self.close()


class JsonChainStore(_LockedStore):
  """The whole chain as one canonical JSON document, replaced atomically on save."""

  def load(self) -> list[Block] | None:
    self._require_open()
    if not _is_stored(self.path):
      return None
    return decode_chain(self.path.read_bytes())

  def save(self, blocks: Sequence[Block]) -> None:
    self._require_open()
    data = encode_chain(blocks)  # encode first: a bad block never touches the file
    temp = self.path.with_name(f".{self.path.name}.{secrets.token_hex(8)}.tmp")
    try:
      with open(temp, "xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
      os.replace(temp, self.path)
    except OSError as exc:
      raise ChainStoreWriteError(f"cannot write chain store {self.path}: {exc}") from exc
    finally:
      with contextlib.suppress(FileNotFoundError):
        os.unlink(temp)


_SCHEMA = (
  "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
  "CREATE TABLE blocks (position INTEGER PRIMARY KEY, data BLOB NOT NULL)",
)
# Exactly what `_SCHEMA` creates - a trigger, view or extra table planted in the file
# (e.g. one that silently deletes rows on every save) makes the store corrupted.
_EXPECTED_MASTER = frozenset(
  {
    ("table", "blocks", _SCHEMA[1]),
    ("table", "meta", _SCHEMA[0]),
    ("index", "sqlite_autoindex_meta_1", None),
  }
)


class SqliteChainStore(_LockedStore):
  """One row per block (its canonical encoding); each save writes a fresh database.

  The database is rebuilt in a temporary file and moved into place, so a save is atomic
  and never runs against schema objects an attacker may have planted in the old file.
  Loading opens the file read-only with `trusted_schema` off and requires the schema to
  be exactly the expected two tables.
  """

  def load(self) -> list[Block] | None:
    self._require_open()
    if not _is_stored(self.path):
      return None
    try:
      connection = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True)
      try:
        connection.execute("PRAGMA trusted_schema = OFF")
        master = connection.execute("SELECT type, name, sql FROM sqlite_master").fetchall()
        if len(master) != len(_EXPECTED_MASTER) or frozenset(master) != _EXPECTED_MASTER:
          raise _corrupt(f"unexpected database schema {sorted(master, key=repr)!r}")
        meta = dict(connection.execute("SELECT key, value FROM meta").fetchall())
        rows = connection.execute("SELECT position, data FROM blocks ORDER BY position").fetchall()
      finally:
        connection.close()
    except sqlite3.DatabaseError as exc:
      raise _corrupt(f"not a readable chain database: {exc}") from exc
    if meta != {"format": CHAIN_FORMAT, "version": str(CHAIN_FORMAT_VERSION)}:
      raise _corrupt(f"unexpected database metadata {meta!r}")
    if not rows:
      raise _corrupt("database holds no blocks (a chain always holds genesis)")
    if [position for position, _ in rows] != list(range(len(rows))):
      raise _corrupt("block positions are not contiguous from 0")
    blocks = []
    for _, data in rows:
      if not isinstance(data, bytes):
        raise _corrupt("block row is not a blob")
      blocks.append(_decode_block(_parse_json(data)))
    return blocks

  def save(self, blocks: Sequence[Block]) -> None:
    self._require_open()
    rows = [(position, canonicalize(block_to_dict(block))) for position, block in enumerate(blocks)]
    temp = self.path.with_name(f".{self.path.name}.{secrets.token_hex(8)}.tmp")
    try:
      connection = sqlite3.connect(temp)
      try:
        with connection:
          for statement in _SCHEMA:
            connection.execute(statement)
          connection.executemany(
            "INSERT INTO meta (key, value) VALUES (?, ?)",
            [("format", CHAIN_FORMAT), ("version", str(CHAIN_FORMAT_VERSION))],
          )
          connection.executemany("INSERT INTO blocks (position, data) VALUES (?, ?)", rows)
      finally:
        connection.close()
      os.replace(temp, self.path)
    except (sqlite3.DatabaseError, OSError) as exc:
      raise ChainStoreWriteError(f"cannot write chain database {self.path}: {exc}") from exc
    finally:
      with contextlib.suppress(FileNotFoundError):
        os.unlink(temp)


# ---------------------------------------------------------------- startup restore


@dataclass(frozen=True)
class RestoredChain:
  """The outcome of reloading a chain: an extendable `Chain` only when it validated."""

  chain: Chain | None
  blocks: tuple[Block, ...]
  validation: ValidationResult

  @property
  def valid(self) -> bool:
    return self.validation.valid


@dataclass(frozen=True)
class NodeState:
  restored: RestoredChain
  issuer_key: IssuerKeyPair
  node_key: NodeKeyPair


def restore_chain(
  store: ChainStore,
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None = None,
  validator_set: ValidatorSet | None = None,
) -> RestoredChain:
  """Load and fully validate the persisted chain before the node resumes.

  No persisted chain yet: a fresh `Chain` at the shared genesis (nothing is written).
  Persisted chain fails validation: `chain` is None, so it cannot be extended, and
  `validation` carries the failing index and `failure_type` for the operator.
  A corrupted store raises `ChainStoreCorruptedError` - never a partial chain.
  Restoring a PoW chain under a changed `expected_difficulty` fails with `"difficulty"`
  by design: a new difficulty requires a fresh chain.
  """
  loaded = store.load()
  blocks = tuple(loaded) if loaded is not None else Chain().blocks
  validation = validate_chain(
    blocks,
    resolve_node_key=resolve_node_key,
    resolve_issuer_key=resolve_issuer_key,
    expected_difficulty=expected_difficulty,
    validator_set=validator_set,
  )
  if not validation.valid:
    return RestoredChain(chain=None, blocks=blocks, validation=validation)
  chain = Chain()
  for block in blocks[1:]:
    chain.append(block)
  return RestoredChain(chain=chain, blocks=blocks, validation=validation)


def restore_node_state(
  chain_store: ChainStore,
  *,
  issuer_key_path: str | Path,
  node_key_path: str | Path,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None = None,
  validator_set: ValidatorSet | None = None,
) -> NodeState:
  """Reload all three stores; missing key material fails fast and is never regenerated."""
  issuer_key = load_issuer_key_pair(issuer_key_path)
  node_key = load_node_key_pair(node_key_path)
  restored = restore_chain(
    chain_store,
    resolve_node_key=resolve_node_key,
    resolve_issuer_key=resolve_issuer_key,
    expected_difficulty=expected_difficulty,
    validator_set=validator_set,
  )
  return NodeState(restored=restored, issuer_key=issuer_key, node_key=node_key)
