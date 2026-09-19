from __future__ import annotations

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

def save_key_pair(ket_pair: KeyPair, path: str | Path, *, force: bool = False) -> None:
   """Persist a KeyPair's private key (and matching public key) to dedicated files."""
   private_path = Path(path)
   public_path = private_path.with_name(private_path.name + ".pub")
   if private_path.exists() and not force:
     raise KeyStoreExistsError(
       f"key store already exists at {private_path}; pass force=True to overwrite")
   private_path.parent.mkdir(parents=True, exist_ok=True)
   private_path.write_bytes(private_key_to_pem(ket_pair.private_key))
   public_path.write_bytes(public_key_to_pem(ket_pair.public_key))
   try:
     private_path.chmod(0o600)
   except OSError:
     pass

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
    public_key=private_key.public_key()
  )
