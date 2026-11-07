"""Register with configured seed peers at startup; retry with capped backoff, never crash."""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError

from blockchain_core import canonicalize
from node.peers.registry import PeerKeyMismatchError, PeerRegistry

logger = logging.getLogger("node.peers")


class PeerTransport(Protocol):
  async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]: ...


class UrllibTransport:
  """Plain-HTTP default. Epic 6 replaces it with the single TLS client factory."""

  def __init__(self, timeout: float = 5.0) -> None:
    self._timeout = timeout

  async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    def _call() -> dict[str, Any]:
      request = urllib.request.Request(
        url,
        data=canonicalize(payload),
        headers={"Content-Type": "application/json"},
        method="POST",
      )
      with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
        body = json.loads(response.read())
      if not isinstance(body, dict):
        raise ValueError("peer returned a non-object body")
      return body

    return await asyncio.to_thread(_call)


def merge_peer_list(registry: PeerRegistry, body: dict[str, Any], model: type[BaseModel]) -> int:
  """Merge a received peer list; invalid or conflicting entries are skipped."""
  merged = 0
  peers = body.get("peers")
  if not isinstance(peers, list):
    return 0
  for item in peers:
    try:
      entry = model.model_validate(item)
      if registry.register(entry.node_id, entry.host, entry.port, entry.public_key):  # type: ignore[attr-defined]
        merged += 1
    except (ValidationError, PeerKeyMismatchError):
      logger.warning("skipping invalid peer entry from gossip")
  return merged


async def register_with_seeds(
  seeds: tuple[str, ...],
  payload: dict[str, Any],
  registry: PeerRegistry,
  transport: PeerTransport,
  model: type[BaseModel],
  *,
  sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
  initial_delay: float = 1.0,
  max_delay: float = 30.0,
) -> None:
  """Sequentially register with each seed; an unreachable seed is retried until it answers."""
  for seed in seeds:
    delay = initial_delay
    while True:
      try:
        body = await transport.post_json(f"http://{seed}/peers/register", payload)
        merge_peer_list(registry, body, model)
        logger.info("registered with seed peer %s", seed)
        break
      except asyncio.CancelledError:
        raise
      except Exception as exc:
        logger.warning("seed peer %s unreachable (%s); retrying in %.1fs", seed, exc, delay)
        await sleep(delay)
        delay = min(delay * 2, max_delay)
