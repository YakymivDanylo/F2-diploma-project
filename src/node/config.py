"""Node configuration from environment variables; fail fast on anything unusable."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

ConsensusMode = Literal["pow", "pbft"]
_MODES = ("pow", "pbft")


class ConfigError(ValueError):
  """The environment is missing or holds an unusable value; the node must not start."""


@dataclass(frozen=True)
class NodeConfig:
  node_id: str
  issuer_id: str
  consensus_mode: ConsensusMode
  expected_difficulty: int | None  # PoW only; None under PBFT
  issuer_key_path: Path
  node_key_path: Path
  chain_path: Path
  validators_path: Path
  issuers_path: Path
  seed_peers: tuple[str, ...]
  cors_origins: tuple[str, ...]
  max_page_size: int
  max_metadata_bytes: int
  max_future_skew_ms: int
  init_chain: bool  # explicit initialization: only then may a missing chain become genesis


def _get(env: Mapping[str, str], key: str, default: str | None = None) -> str:
  value = env.get(key)
  if value is None or value.strip() == "":
    if default is None:
      raise ConfigError(f"{key} is required")
    return default
  return value.strip()


def _int(
  env: Mapping[str, str],
  key: str,
  default: int | None,
  *,
  minimum: int,
  maximum: int | None = None,
) -> int:
  raw = _get(env, key, None if default is None else str(default))
  try:
    value = int(raw)
  except ValueError:
    raise ConfigError(f"{key} must be an integer, got {raw!r}") from None
  if value < minimum or (maximum is not None and value > maximum):
    bound = f">= {minimum}" if maximum is None else f"in [{minimum}, {maximum}]"
    raise ConfigError(f"{key} must be {bound}, got {value}")
  return value


def _csv(env: Mapping[str, str], key: str, default: str) -> tuple[str, ...]:
  raw = env.get(key)
  text = default if raw is None else raw
  return tuple(part.strip() for part in text.split(",") if part.strip())


def _flag(env: Mapping[str, str], key: str) -> bool:
  raw = _get(env, key, "0").lower()
  if raw in ("1", "true"):
    return True
  if raw in ("0", "false"):
    return False
  raise ConfigError(f"{key} must be one of 0/1/true/false, got {raw!r}")


def load_config(env: Mapping[str, str] | None = None) -> NodeConfig:
  """Build the config from `env` (default: the process environment).

  Policy for CONSENSUS_MODE: there is NO default. A missing or unrecognized value fails
  startup, so a typo can never silently select the wrong algorithm.
  """
  source = os.environ if env is None else env
  mode = _get(source, "CONSENSUS_MODE")
  if mode == "pow":
    typed_mode: ConsensusMode = "pow"
  elif mode == "pbft":
    typed_mode = "pbft"
  else:
    raise ConfigError(f"CONSENSUS_MODE must be one of {_MODES}, got {mode!r}")
  difficulty = (
    _int(source, "EXPECTED_DIFFICULTY", None, minimum=1, maximum=256)
    if typed_mode == "pow"
    else None
  )
  return NodeConfig(
    node_id=_get(source, "NODE_ID"),
    issuer_id=_get(source, "ISSUER_ID"),
    consensus_mode=typed_mode,
    expected_difficulty=difficulty,
    issuer_key_path=Path(_get(source, "ISSUER_KEY_PATH")),
    node_key_path=Path(_get(source, "NODE_KEY_PATH")),
    chain_path=Path(_get(source, "CHAIN_PATH")),
    validators_path=Path(_get(source, "VALIDATORS_PATH")),
    issuers_path=Path(_get(source, "ISSUERS_PATH")),
    seed_peers=_csv(source, "SEED_PEERS", ""),
    cors_origins=_csv(source, "CORS_ORIGINS", "http://localhost:5173"),
    max_page_size=_int(source, "MAX_PAGE_SIZE", 100, minimum=1),
    max_metadata_bytes=_int(source, "METADATA_MAX_BYTES", 1024, minimum=1),
    max_future_skew_ms=_int(source, "MAX_FUTURE_SKEW_MS", 60_000, minimum=0),
    init_chain=_flag(source, "INIT_CHAIN"),
  )
