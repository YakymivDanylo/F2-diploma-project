"""Node configuration from environment variables; fail fast on anything unusable."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from node.peers.registry import is_loopback_host

ConsensusMode = Literal["pow", "pbft"]
_MODES = ("pow", "pbft")
MIN_FUTURE_SKEW_MS = 1000
_TOKEN = re.compile(r"[0-9a-f]{16}")  # BYZANTINE_RESET_ON_BOOT (see pbft.engine.RESET_TOKEN)


class ConfigError(ValueError):
  """The environment is missing or holds an unusable value; the node must not start."""


@dataclass(frozen=True)
class NodeConfig:
  node_id: str
  issuer_id: str
  node_host: str  # advertised address other nodes use to reach this node
  node_port: int
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
  mempool_max_size: int
  forward_ack_timeout_ms: int  # wait for the primary's reply to a forwarded record
  init_chain: bool  # explicit initialization: only then may a missing chain become genesis
  startup_sync_timeout_s: float  # bound on the load -> sync -> serve wait (UC-3-EC4)
  sync_interval_s: float  # periodic chain sync with peers once serving
  pbft_round_timeout_s: float  # PBFT: a stuck round or unreachable primary -> view change
  allow_loopback_peers: bool = False  # local single-machine development only
  # PBFT: start although the PBFT state file is missing while the chain has blocks (explicit
  # operator decision; by default the engine fails closed: a lost vote record could let this
  # node vote twice in a view it already voted in)
  pbft_allow_missing_state: bool = False
  # PBFT: operator reset of the sticky `byzantine_event_detected` status after the incident was
  # dealt with. A one-shot DIGEST token (16 lowercase hex chars) of exactly the persisted event
  # list, logged at every boot that restores events; the reset happens only when it matches, so
  # a value forgotten in an env file never erases evidence recorded later. None (unset) = none.
  byzantine_reset_on_boot: str | None = None


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


def _strict_int(
  env: Mapping[str, str], key: str, default: int, *, minimum: int, maximum: int | None = None
) -> int:
  """Like `_int`, but a present-yet-blank value fails instead of falling back to the default."""
  raw = env.get(key)
  if raw is None:
    return default
  if raw.strip() == "":
    raise ConfigError(f"{key} must not be empty")
  return _int(env, key, None, minimum=minimum, maximum=maximum)


def _float(env: Mapping[str, str], key: str, default: float, *, minimum: float) -> float:
  raw = _get(env, key, str(default))
  try:
    value = float(raw)
  except ValueError:
    raise ConfigError(f"{key} must be a number, got {raw!r}") from None
  if not value >= minimum or value == float("inf"):  # also rejects nan
    raise ConfigError(f"{key} must be a finite number >= {minimum}, got {raw!r}")
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


def _optional_token(env: Mapping[str, str], key: str) -> str | None:
  """A 16-lowercase-hex-char token, or None when the variable is unset or blank."""
  raw = env.get(key)
  if raw is None or raw.strip() == "":
    return None
  value = raw.strip()
  if not _TOKEN.fullmatch(value):
    raise ConfigError(f"{key} must be the 16-hex-char token logged at boot, got {value[:32]!r}")
  return value


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
  node_host = _get(source, "NODE_HOST", "localhost")
  seed_peers = _csv(source, "SEED_PEERS", "")
  allow_loopback_peers = _flag(source, "ALLOW_LOOPBACK_PEERS")
  if seed_peers and is_loopback_host(node_host) and not allow_loopback_peers:
    raise ConfigError(
      f"NODE_HOST={node_host!r} with SEED_PEERS set: a node announced as localhost is "
      "unreachable from its peers (set a reachable NODE_HOST, or ALLOW_LOOPBACK_PEERS=1 for "
      "single-machine development)"
    )
  return NodeConfig(
    node_id=_get(source, "NODE_ID"),
    issuer_id=_get(source, "ISSUER_ID"),
    node_host=node_host,
    node_port=_int(source, "NODE_PORT", 8000, minimum=1, maximum=65535),
    consensus_mode=typed_mode,
    expected_difficulty=difficulty,
    issuer_key_path=Path(_get(source, "ISSUER_KEY_PATH")),
    node_key_path=Path(_get(source, "NODE_KEY_PATH")),
    chain_path=Path(_get(source, "CHAIN_PATH")),
    validators_path=Path(_get(source, "VALIDATORS_PATH")),
    issuers_path=Path(_get(source, "ISSUERS_PATH")),
    seed_peers=seed_peers,
    cors_origins=_csv(source, "CORS_ORIGINS", "http://localhost:5173"),
    max_page_size=_int(source, "MAX_PAGE_SIZE", 100, minimum=1, maximum=1000),
    max_metadata_bytes=_int(source, "METADATA_MAX_BYTES", 1024, minimum=1, maximum=1_048_576),
    mempool_max_size=_int(source, "MEMPOOL_MAX_SIZE", 10_000, minimum=1),
    # also the staleness bound for inbound PoW blocks: 0 would reject honest blocks after any
    # propagation delay, so at least 1 s
    max_future_skew_ms=_int(source, "MAX_FUTURE_SKEW_MS", 60_000, minimum=MIN_FUTURE_SKEW_MS),
    forward_ack_timeout_ms=_strict_int(
      source, "FORWARD_ACK_TIMEOUT_MS", 2000, minimum=1, maximum=60_000
    ),
    init_chain=_flag(source, "INIT_CHAIN"),
    startup_sync_timeout_s=_float(source, "STARTUP_SYNC_TIMEOUT_S", 10.0, minimum=0.0),
    sync_interval_s=_float(source, "SYNC_INTERVAL_S", 5.0, minimum=0.05),
    pbft_round_timeout_s=_float(source, "PBFT_ROUND_TIMEOUT_S", 5.0, minimum=0.05),
    allow_loopback_peers=allow_loopback_peers,
    pbft_allow_missing_state=_flag(source, "PBFT_ALLOW_MISSING_STATE"),
    byzantine_reset_on_boot=_optional_token(source, "BYZANTINE_RESET_ON_BOOT"),
  )
