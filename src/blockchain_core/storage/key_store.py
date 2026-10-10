"""Key-pair persistence: one private-key file (plus `.pub`) per key pair.

Files are created with restrictive permissions from the first byte (no
write-then-chmod window), written to a temporary sibling and then moved into place, so a
crash never leaves a truncated key and a symlink planted at the target is never followed.

On Windows the POSIX mode bits do not restrict who can read a file: protect the key
directory with an ACL instead. Private keys are stored unencrypted (PEM, no passphrase).
"""
from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path

from ..keys import (
  KeyPair,
  algorithm_of,
  private_key_from_pem,
  private_key_to_pem,
  public_key_to_pem,
)


class KeyStoreExistsError(FileExistsError):
  """Raised when save_key_pair targets a path that already holds a key, without force=True."""

class KeyStoreMissingError(FileNotFoundError):
  """Raised when load_key_pair targets a path with no private-key file present."""

class KeyStoreCorruptedError(ValueError):
  """Raised when a key-store file exists but cannot be parsed as a valid private key."""


def _write_file(path: Path, data: bytes, mode: int, *, force: bool) -> None:
  """Write `data` to `path` atomically; without `force`, never replace an existing file."""
  temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
  fd = os.open(temp, flags | getattr(os, "O_NOFOLLOW", 0), mode)
  try:
    with os.fdopen(fd, "wb") as handle:
      handle.write(data)
      handle.flush()
      os.fsync(handle.fileno())
    if force:
      os.replace(temp, path)
    else:
      try:
        os.link(temp, path)
      except FileExistsError as exc:
        raise KeyStoreExistsError(
          f"key store already exists at {path}; pass force=True to overwrite") from exc
  finally:
    with contextlib.suppress(FileNotFoundError):
      os.unlink(temp)

def save_key_pair(key_pair: KeyPair, path: str | Path, *, force: bool = False) -> None:
  """Persist a KeyPair's private key (and matching public key) to dedicated files."""
  private_path = Path(path)
  public_path = private_path.with_name(private_path.name + ".pub")
  if not force and (private_path.exists() or public_path.exists()):
    raise KeyStoreExistsError(
      f"key store already exists at {private_path}; pass force=True to overwrite")
  private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  _write_file(private_path, private_key_to_pem(key_pair.private_key), 0o600, force=force)
  _write_file(public_path, public_key_to_pem(key_pair.public_key), 0o644, force=force)

def load_key_pair(path: str | Path) -> KeyPair:
  """Load a KeyPair from its private-key store file; derives the public key from it."""
  private_path = Path(path)
  if not private_path.exists():
    raise KeyStoreMissingError(f"key store not found at {private_path}")
  try:
    private_key = private_key_from_pem(private_path.read_bytes())
  except ValueError as exc:
    raise KeyStoreCorruptedError(f"key store at {private_path} is corrupted: {exc}") from exc
  return KeyPair(
    algorithm=algorithm_of(private_key),
    private_key=private_key,
    public_key=private_key.public_key(),
  )
