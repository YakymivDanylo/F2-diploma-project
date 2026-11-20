"""Register with every configured seed peer, in parallel, and keep re-registering.

Each seed has its own loop: register (an unreachable seed is retried with capped exponential
backoff, never crashing the node and never blocking the other seeds), merge the returned peer
list, then wait `refresh_s` and register again. Re-registering keeps the signed `issued_at`
fresh at the seeds and lets a restarted node (or seed) re-learn the full mesh.

Blocking work (the HTTP request, the vetting of a received peer list) runs on a small dedicated
executor (`SEED_WORKERS` threads), never on the shared default executor that ChainState append /
replace, store.save and the prechecks use - the same invariant as `node.netguard`. Like the
netguard pools it is process-wide by design: one node per process, alive as long as the process.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError

from blockchain_core import canonicalize
from node.peers.attestation import normalized_pem
from node.peers.registry import (
  PeerInfo,
  PeerKeyMismatchError,
  PeerRegistry,
  PeerRegistryFullError,
  StaleRegistrationError,
)

logger = logging.getLogger("node.peers")

SEED_REFRESH_S = 30.0  # period of re-registration with every seed
DEFAULT_TIMEOUT_S = 5.0  # whole request, not per socket read
MAX_RESPONSE_BYTES = 1024 * 1024  # a seed reply is at most a page of peers
SEED_WORKERS = 2  # seed requests + gossip vetting; never the shared default executor

_executor = ThreadPoolExecutor(SEED_WORKERS, thread_name_prefix="seed-peers")

Payload = dict[str, Any] | Callable[[], dict[str, Any]]
# (entry, held entry or None) -> the public key to store, or None to skip the entry
Accept = Callable[[Any, PeerInfo | None], str | None]
# protected (ValidatorSet) id -> the key in force for it NOW (as stored), or None
KeyNow = Callable[[str], str | None]


async def _off_loop(fn: Callable[..., Any], *args: Any) -> Any:
  return await asyncio.get_running_loop().run_in_executor(_executor, fn, *args)


class PeerTransport(Protocol):
  async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]: ...


class SeedResponseError(Exception):
  """A seed's reply is oversized, too slow, not JSON or not a JSON object."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, *args: Any, **kwargs: Any) -> None:
    return None  # a seed must not steer our POST to another address


class UrllibTransport:
  """Plain-HTTP default (Epic 6 swaps in the single TLS client factory). Every request is
  bounded in total time and response size, and redirects are never followed."""

  def __init__(
    self, timeout: float = DEFAULT_TIMEOUT_S, max_bytes: int = MAX_RESPONSE_BYTES
  ) -> None:
    self._timeout = timeout
    self._max_bytes = max_bytes
    self._opener = urllib.request.build_opener(_NoRedirect)

  async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = await _off_loop(self._call, url, payload)
    return result

  def _call(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
      url,
      data=canonicalize(payload),
      headers={"Content-Type": "application/json"},
      method="POST",
    )
    deadline = time.monotonic() + self._timeout
    chunks: list[bytes] = []
    size = 0
    with self._opener.open(request, timeout=self._timeout) as response:  # noqa: S310
      while chunk := response.read1(65536):
        size += len(chunk)
        if size > self._max_bytes:
          raise SeedResponseError("response exceeds the size limit")
        if time.monotonic() > deadline:
          raise TimeoutError("response took longer than the request timeout")
        chunks.append(chunk)
    try:
      body = json.loads(b"".join(chunks))
    except ValueError as exc:
      raise SeedResponseError("response is not valid JSON") from exc
    if not isinstance(body, dict):
      raise SeedResponseError("peer returned a non-object body")
    return body


def _any_key(entry: Any, _held: PeerInfo | None) -> str | None:
  return normalized_pem(entry.public_key)


def _vet(
  peers: list[Any],
  model: type[BaseModel],
  accept: Accept,
  held: dict[str, PeerInfo],
) -> list[tuple[Any, str]]:
  """Validate and check every entry against a snapshot of the held entries: the CPU-heavy
  part of a merge (PEM parsing, signature verification). Reads no registry state."""
  vetted: list[tuple[Any, str]] = []
  for item in peers:
    try:
      entry: Any = model.model_validate(item)
    except ValidationError:
      logger.warning("skipping invalid peer entry from gossip")
      continue
    key = accept(entry, held.get(entry.node_id))
    if key is None:
      logger.warning("skipping an unauthenticated or unacceptable peer entry from gossip")
      continue
    vetted.append((entry, key))
  return vetted


def _apply(
  registry: PeerRegistry, vetted: list[tuple[Any, str]], key_now: KeyNow | None = None
) -> int:
  """Register the vetted entries (on the loop). A validator key may rotate between the vetting
  (off the loop, against a snapshot) and now: a protected id is registered only when the key
  it was vetted with is still the key in force (`key_now`, a cheap lookup), else skipped."""
  merged = 0
  for entry, key in vetted:
    if (
      key_now is not None and registry.is_protected(entry.node_id) and key_now(entry.node_id) != key
    ):
      logger.warning("skipping a gossiped validator entry: its key rotated after vetting")
      continue
    try:
      info = registry.register(
        entry.node_id,
        entry.host,
        entry.port,
        key,
        issued_at=getattr(entry, "issued_at", None),
        signature=getattr(entry, "signature", None),
      )
    except (PeerKeyMismatchError, StaleRegistrationError):
      logger.warning("skipping a conflicting peer entry from gossip")
      continue
    except PeerRegistryFullError:
      logger.warning("peer registry is full; skipping gossiped entries")
      break
    if info:
      merged += 1
  return merged


def _peer_items(body: dict[str, Any]) -> list[Any]:
  peers = body.get("peers")
  return peers if isinstance(peers, list) else []


def merge_peer_list(
  registry: PeerRegistry,
  body: dict[str, Any],
  model: type[BaseModel],
  accept: Accept = _any_key,
  key_now: KeyNow | None = None,
) -> int:
  """Merge a received peer list; invalid, conflicting or unaccepted entries are skipped.

  `accept(entry, held)` returns the public key to store for an acceptable entry (`held` is
  the entry this registry holds for that id, or None) and None to reject it, e.g. an entry
  without a valid, fresh signed registration or with a forbidden address. It must not touch
  the registry, so `merge_peer_list_off_loop` can run it in a worker thread. The default
  accepts every entry and stores its normalized PEM. `key_now` (protected id -> the key in
  force now) re-checks validator entries right before they are registered."""
  peers = _peer_items(body)
  if not peers:
    return 0
  held = {info.node_id: info for info in registry.list()}
  return _apply(registry, _vet(peers, model, accept, held), key_now)


async def merge_peer_list_off_loop(
  registry: PeerRegistry,
  body: dict[str, Any],
  model: type[BaseModel],
  accept: Accept = _any_key,
  key_now: KeyNow | None = None,
) -> int:
  """`merge_peer_list` with the validation and signature checks (up to a page of them) on the
  dedicated seed executor: only the registry snapshot and the final `register` calls run on
  the loop. An entry changed meanwhile is still guarded by `register` (key binding, issued_at
  order), and a validator whose key rotated meanwhile by `key_now`."""
  peers = _peer_items(body)
  if not peers:
    return 0
  held = {info.node_id: info for info in registry.list()}
  vetted = await _off_loop(_vet, peers, model, accept, held)
  return _apply(registry, vetted, key_now)


async def _seed_loop(
  seed: str,
  payload: Callable[[], dict[str, Any]],
  registry: PeerRegistry,
  transport: PeerTransport,
  model: type[BaseModel],
  *,
  sleep: Callable[[float], Awaitable[None]],
  initial_delay: float,
  max_delay: float,
  accept: Accept,
  key_now: KeyNow | None,
  refresh_s: float,
  rounds: int | None,
) -> None:
  done = 0
  while rounds is None or done < rounds:
    delay = initial_delay
    while True:
      try:
        body = await transport.post_json(f"http://{seed}/peers/register", payload())
        await merge_peer_list_off_loop(registry, body, model, accept, key_now)
        logger.info("registered with seed peer %s", seed)
        break
      except asyncio.CancelledError:
        raise
      except Exception as exc:
        logger.warning("seed peer %s unreachable (%s); retrying in %.1fs", seed, exc, delay)
        await sleep(delay)
        delay = min(delay * 2, max_delay)
    done += 1
    if rounds is None or done < rounds:
      await sleep(refresh_s)


async def register_with_seeds(
  seeds: tuple[str, ...],
  payload: Payload,
  registry: PeerRegistry,
  transport: PeerTransport,
  model: type[BaseModel],
  *,
  sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
  initial_delay: float = 1.0,
  max_delay: float = 30.0,
  accept: Accept = _any_key,
  key_now: KeyNow | None = None,
  refresh_s: float = SEED_REFRESH_S,
  rounds: int | None = None,
) -> None:
  """Register with all seeds in parallel and re-register every `refresh_s` until cancelled.

  `payload` is the registration body, or a zero-arg callable building a fresh one (a freshly
  signed `issued_at`) for every attempt. `rounds` bounds the successful registrations per seed
  (None: run until cancelled; tests pass a number)."""
  build = payload if callable(payload) else (lambda: payload)
  await asyncio.gather(
    *(
      _seed_loop(
        seed,
        build,
        registry,
        transport,
        model,
        sleep=sleep,
        initial_delay=initial_delay,
        max_delay=max_delay,
        accept=accept,
        key_now=key_now,
        refresh_s=refresh_s,
        rounds=rounds,
      )
      for seed in seeds
    )
  )
