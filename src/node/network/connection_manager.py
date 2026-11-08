"""PeerConnectionManager: every node is a WS server (inbound) and a WS client (outbound).

Links are keyed by the peer's node_id, and a peer may be reachable over an outbound link,
an inbound link, or both; sends use whichever is established (outbound first). Outbound
dialing retries with capped exponential backoff. Every connection starts with a mutual
challenge-response so each side knows the other holds the private key behind a key it
already trusts (ValidatorSet or PeerInfo) before a single message is accepted.

Transport is abstracted (`WsLike`, `Connector`) so the same logic runs over real sockets
and over an in-memory loopback in tests.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import re
import secrets
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from blockchain_core import canonicalize, sign_canonical, verify_canonical
from blockchain_core.keys import PrivateKey, PublicKey

logger = logging.getLogger("node.network")

HELLO_DOMAIN = "node/ws-hello/v2"  # its own domain: a hello proof can never be replayed elsewhere
BLOCKS_PATH = "/ws/blocks"
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
MAX_HANDSHAKE_BYTES = 1024  # hello / proof are tiny; bigger is hostile
MAX_CONCURRENT_HANDSHAKES = 32
AUTH_FAILED_CLOSE_CODE = 4401
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_EPH_RE = re.compile(r"^[0-9a-f]{64}$")
UNAUTHENTICATED_KEY = "#unauthenticated"  # not a valid node_id, so it can never be spoofed

STATUS_UP = "up"
STATUS_RECONNECTING = "reconnecting"
STATUS_DOWN = "down"


class ConnectionClosed(Exception):
  """The peer closed the connection (or it broke)."""


class AuthFailed(Exception):
  """The peer could not prove its identity."""


class WsLike(Protocol):
  async def send_text(self, data: str) -> None: ...

  async def receive_text(self) -> str: ...

  async def close(self, code: int = 1000) -> None: ...


class Connector(Protocol):
  async def connect(self, host: str, port: int, path: str) -> WsLike:
    """Open a connection or raise OSError / ConnectionClosed."""


MessageHandler = Callable[[str, dict[str, Any]], Awaitable[None]]
KeyLookup = Callable[[str], PublicKey | None]


def _reject_float(text: str) -> Any:
  raise ValueError("floats are not allowed in node messages")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
  result: dict[str, Any] = {}
  for key, value in pairs:
    if key in result:
      raise ValueError("duplicate key in message")
    result[key] = value
  return result


def parse_message(raw: str, *, max_len: int = MAX_MESSAGE_BYTES) -> dict[str, Any]:
  """Strict JSON object parse; anything malformed raises ValueError."""
  if len(raw) > max_len:  # checked BEFORE parsing: oversized input costs nothing
    raise ValueError("message too large")
  try:
    data = json.loads(raw, parse_float=_reject_float, object_pairs_hook=_no_duplicate_keys)
  except RecursionError:
    raise ValueError("message nested too deeply") from None
  if not isinstance(data, dict):
    raise ValueError("message must be a JSON object")
  return data


def encode_message(message: dict[str, Any]) -> str:
  return canonicalize(message).decode("utf-8")


def _hello_payload(
  signer: str,
  verifier: str,
  signer_nonce: str,
  verifier_nonce: str,
  signer_eph: str,
  verifier_eph: str,
) -> dict[str, str]:
  # The proof names both parties and covers BOTH fresh nonces and BOTH ephemeral DH keys, so
  # it is valid for exactly one pairing of sessions. A man in the middle can at most relay
  # the handshake verbatim - and then cannot read or alter later frames, which are MAC'd
  # under the key only the two real parties can derive.
  return {
    "domain": HELLO_DOMAIN,
    "signer": signer,
    "verifier": verifier,
    "signer_nonce": signer_nonce,
    "verifier_nonce": verifier_nonce,
    "signer_eph": signer_eph,
    "verifier_eph": verifier_eph,
  }


def _eph_hex(public: X25519PublicKey) -> str:
  return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _session_key(
  secret: bytes, nonces: tuple[str, str], ids: tuple[str, str], sender: str
) -> bytes:
  low_nonce, high_nonce = sorted(nonces)
  low_id, high_id = sorted(ids)
  info = f"{HELLO_DOMAIN}|{low_id}|{high_id}|{low_nonce}|{high_nonce}|sender={sender}".encode()
  return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


class SecureWs:
  """Authenticated framing after the handshake: `counter:mac:payload`.

  Every frame carries a strictly increasing counter and an HMAC-SHA256 under a per-direction
  key, so frames cannot be altered, replayed, reordered or reflected, and a dropped frame
  breaks the session instead of silently shifting it.
  """

  def __init__(self, ws: WsLike, send_key: bytes, recv_key: bytes) -> None:
    self._ws = ws
    self._send_key, self._recv_key = send_key, recv_key
    self._sent = 0
    self._received = 0

  @staticmethod
  def _mac(key: bytes, counter: int, data: str) -> str:
    body = counter.to_bytes(8, "big") + data.encode("utf-8")
    return hmac.new(key, body, "sha256").hexdigest()

  async def send_text(self, data: str) -> None:
    counter = self._sent
    self._sent += 1
    await self._ws.send_text(f"{counter}:{self._mac(self._send_key, counter, data)}:{data}")

  async def receive_text(self) -> str:
    raw = await self._ws.receive_text()
    counter_text, _, rest = raw.partition(":")
    mac, _, data = rest.partition(":")
    if (
      counter_text != str(self._received)
      or len(mac) != 64
      or not hmac.compare_digest(mac, self._mac(self._recv_key, self._received, data))
    ):
      await self._ws.close(1008)
      raise ConnectionClosed
    self._received += 1
    return data

  async def close(self, code: int = 1000) -> None:
    await self._ws.close(code)


async def authenticate(
  ws: WsLike,
  *,
  my_id: str,
  my_key: PrivateKey,
  lookup_key: KeyLookup,
  expected_id: str | None = None,
  timeout: float = 5.0,
) -> tuple[str, SecureWs]:
  """Mutual challenge-response with ephemeral key agreement.

  Returns (authenticated peer node_id, framed channel) or raises AuthFailed. An id we hold no
  key for is dropped BEFORE we sign anything, so this is no signing oracle for strangers.
  """
  my_nonce = secrets.token_hex(16)
  eph_private = X25519PrivateKey.generate()
  my_eph = _eph_hex(eph_private.public_key())
  try:
    async with asyncio.timeout(timeout):
      await ws.send_text(
        encode_message({"type": "hello", "node_id": my_id, "nonce": my_nonce, "eph": my_eph})
      )
      hello = parse_message(await ws.receive_text(), max_len=MAX_HANDSHAKE_BYTES)
      their_id, their_nonce, their_eph = hello.get("node_id"), hello.get("nonce"), hello.get("eph")
      if (
        hello.get("type") != "hello"
        or not isinstance(their_id, str)
        or not _ID_RE.fullmatch(their_id)
        or not isinstance(their_nonce, str)
        or not _NONCE_RE.fullmatch(their_nonce)
        or not isinstance(their_eph, str)
        or not _EPH_RE.fullmatch(their_eph)
      ):
        raise AuthFailed("malformed hello")
      if their_id == my_id:
        raise AuthFailed("connection to self")
      if expected_id is not None and their_id != expected_id:
        raise AuthFailed("unexpected node_id")
      key = lookup_key(their_id)
      if key is None:  # not in ValidatorSet nor PeerInfo (UC-8-EC1): sign nothing for it
        raise AuthFailed("unknown node_id")
      proof = sign_canonical(
        my_key, _hello_payload(my_id, their_id, my_nonce, their_nonce, my_eph, their_eph)
      )
      await ws.send_text(encode_message({"type": "proof", "signature": proof}))
      reply = parse_message(await ws.receive_text(), max_len=MAX_HANDSHAKE_BYTES)
  except TimeoutError:
    raise AuthFailed("handshake timed out") from None
  except (ValueError, ConnectionClosed) as exc:
    raise AuthFailed(f"handshake failed: {type(exc).__name__}") from None
  signature = reply.get("signature")
  if (
    reply.get("type") != "proof"
    or not isinstance(signature, str)
    or not verify_canonical(
      key, _hello_payload(their_id, my_id, their_nonce, my_nonce, their_eph, my_eph), signature
    )
  ):
    raise AuthFailed("identity proof rejected")
  secret = eph_private.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(their_eph)))
  nonces, ids = (my_nonce, their_nonce), (my_id, their_id)
  channel = SecureWs(
    ws,
    send_key=_session_key(secret, nonces, ids, sender=my_id),
    recv_key=_session_key(secret, nonces, ids, sender=their_id),
  )
  return their_id, channel


@dataclass
class _Link:
  outbound: WsLike | None = None
  inbound: WsLike | None = None
  failures: int = 0  # consecutive failed dials since the last established outbound link
  lock: asyncio.Lock | None = None

  @property
  def connected(self) -> bool:
    return self.outbound is not None or self.inbound is not None


class PeerConnectionManager:
  def __init__(
    self,
    *,
    self_id: str,
    node_key: PrivateKey,
    lookup_key: KeyLookup,
    peer_addresses: Callable[[], Iterable[tuple[str, str, int]]],
    known_ids: Callable[[], Iterable[str]],
    connector: Connector,
    on_message: MessageHandler,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    base_delay: float = 0.5,
    max_delay: float = 30.0,
    scan_interval: float = 2.0,
    handshake_timeout: float = 5.0,
    send_timeout: float = 5.0,
    down_after: int = 5,
    max_dialed: int = 64,
  ) -> None:
    self._self_id = self_id
    self._key = node_key
    self._lookup_key = lookup_key
    self._peer_addresses = peer_addresses
    self._known_ids = known_ids
    self._connector = connector
    self._on_message = on_message
    self._sleep = sleep
    self._base, self._max = base_delay, max_delay
    self._scan_interval = scan_interval
    self._handshake_timeout = handshake_timeout
    self._send_timeout = send_timeout
    self._down_after = down_after
    self._max_dialed = max_dialed
    self._links: dict[str, _Link] = {}
    self._dialers: dict[str, asyncio.Task[None]] = {}
    self._readers: set[asyncio.Task[None]] = set()
    self._scanner: asyncio.Task[None] | None = None
    self._flags: Counter[str] = Counter()
    self._handshakes = 0
    self.dial_delays: list[float] = []  # recent backoff delays, for observability and tests

  # ---------------------------------------------------------------- lifecycle

  async def start(self) -> None:
    if self._scanner is None:
      self._scan()
      self._scanner = asyncio.create_task(self._scan_loop(), name="peer-scanner")

  async def stop(self) -> None:
    tasks = [*self._dialers.values(), *self._readers]
    if self._scanner is not None:
      tasks.append(self._scanner)
    self._scanner = None
    for task in tasks:
      task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    self._dialers.clear()
    for link in self._links.values():
      for ws in (link.outbound, link.inbound):
        if ws is not None:
          with contextlib.suppress(Exception):
            await ws.close()
      link.outbound = link.inbound = None

  # ------------------------------------------------------------------ dialing

  def _scan(self) -> None:
    # ValidatorSet members first, then other peers, at most `max_dialed` outbound dial loops:
    # registering thousands of PeerInfo entries must not make us open thousands of sockets.
    validators = set(self._known_ids())
    ordered = sorted(self._addresses(), key=lambda node_id: node_id not in validators)
    for node_id in ordered:
      task = self._dialers.get(node_id)
      active = sum(1 for t in self._dialers.values() if not t.done())
      if node_id != self._self_id and (task is None or task.done()) and active < self._max_dialed:
        self._dialers[node_id] = asyncio.create_task(
          self._dial_loop(node_id), name=f"dial-{node_id}"
        )

  async def _scan_loop(self) -> None:
    while True:
      await self._sleep(self._scan_interval)
      self._scan()

  def _addresses(self) -> dict[str, tuple[str, int]]:
    return {peer_id: (host, port) for peer_id, host, port in self._peer_addresses()}

  def _address_of(self, node_id: str) -> tuple[str, int] | None:
    return self._addresses().get(node_id)

  def _link(self, node_id: str) -> _Link:
    return self._links.setdefault(node_id, _Link(lock=asyncio.Lock()))

  async def _dial_loop(self, node_id: str) -> None:
    link = self._link(node_id)
    attempt = 0
    while True:
      address = self._address_of(node_id)
      ws: Any = None
      try:
        if address is None:
          raise OSError("no known address")
        ws = await self._connector.connect(address[0], address[1], BLOCKS_PATH)
        _, ws = await authenticate(
          ws,
          my_id=self._self_id,
          my_key=self._key,
          lookup_key=self._lookup_key,
          expected_id=node_id,
          timeout=self._handshake_timeout,
        )
      except (OSError, ConnectionClosed, AuthFailed, TimeoutError) as exc:
        link.failures += 1
        logger.info("dial %s failed (%s), attempt %d", node_id, type(exc).__name__, link.failures)
        if ws is not None:
          with contextlib.suppress(Exception):
            await ws.close()
      else:
        link.outbound, link.failures, attempt = ws, 0, 0
        try:
          await self._read_loop(node_id, ws)
        finally:
          link.outbound = None
          with contextlib.suppress(Exception):
            await ws.close()
      delay = min(self._max, self._base * (2**attempt))
      attempt = min(attempt + 1, 32)
      self.dial_delays.append(delay)
      del self.dial_delays[:-64]
      await self._sleep(delay)

  # ---------------------------------------------------------------- inbound

  async def accept_inbound(self, ws: WsLike) -> None:
    """Serve one inbound connection until it closes. Unauthenticated peers get closed."""
    if self._handshakes >= MAX_CONCURRENT_HANDSHAKES:  # unauthenticated sockets are capped
      with contextlib.suppress(Exception):
        await ws.close(1013)
      return
    self._handshakes += 1
    try:
      peer_id, secure = await authenticate(
        ws,
        my_id=self._self_id,
        my_key=self._key,
        lookup_key=self._lookup_key,
        timeout=self._handshake_timeout,
      )
    except AuthFailed as exc:
      logger.warning("rejected inbound connection: %s", exc)
      self._flags[UNAUTHENTICATED_KEY] += 1
      with contextlib.suppress(Exception):
        await ws.close(AUTH_FAILED_CLOSE_CODE)
      return
    finally:
      self._handshakes -= 1
    ws = secure
    link = self._link(peer_id)
    previous, link.inbound = link.inbound, ws
    if previous is not None:  # a newer connection from the same peer replaces the old one
      with contextlib.suppress(Exception):
        await previous.close()
    try:
      await self._read_loop(peer_id, ws)
    finally:
      if link.inbound is ws:
        link.inbound = None
      with contextlib.suppress(Exception):
        await ws.close()

  async def _read_loop(self, peer_id: str, ws: WsLike) -> None:
    task = asyncio.current_task()
    if task is not None:
      self._readers.add(task)
    try:
      while True:
        try:
          raw = await ws.receive_text()
        except ConnectionClosed:
          return
        try:
          message = parse_message(raw)
        except ValueError:
          self.flag(peer_id, "malformed_message")
          continue
        try:
          await self._on_message(peer_id, message)
        except Exception:
          logger.exception("handler failed for a message from %s", peer_id)
    finally:
      if task is not None:
        self._readers.discard(task)

  # ---------------------------------------------------------------- sending

  async def broadcast(self, message: dict[str, Any]) -> dict[str, bool]:
    """Fan out to every connected peer over its established direction. Returns who got it."""
    text = encode_message(message)
    targets = {pid: link for pid, link in self._links.items() if link.connected}
    results = await asyncio.gather(*(self._send(pid, link, text) for pid, link in targets.items()))
    return dict(zip(targets, results, strict=True))

  async def _send(self, peer_id: str, link: _Link, text: str) -> bool:
    assert link.lock is not None
    async with link.lock:  # one writer per link at a time
      for name in ("outbound", "inbound"):
        ws: WsLike | None = getattr(link, name)
        if ws is None:
          continue
        try:
          async with asyncio.timeout(self._send_timeout):
            await ws.send_text(text)
          return True
        except (ConnectionClosed, OSError, TimeoutError, RuntimeError):
          logger.info("send to %s over %s link failed", peer_id, name)
          setattr(link, name, None)
          with contextlib.suppress(Exception):
            await ws.close()
    return False

  # ------------------------------------------------------------ health / flags

  def health(self) -> dict[str, str]:
    """up / reconnecting / down for every peer we know about (never includes self)."""
    result: dict[str, str] = {}
    ids = {*self._known_ids(), *self._links, *self._dialers} - {self._self_id}
    addresses = self._addresses()  # one pass, not one per peer
    for node_id in sorted(ids):
      link = self._links.get(node_id)
      if link is not None and link.connected:
        result[node_id] = STATUS_UP
      elif link is None or link.failures >= self._down_after or node_id not in addresses:
        result[node_id] = STATUS_DOWN
      else:
        result[node_id] = STATUS_RECONNECTING
    return result

  def flag(self, peer_id: str, reason: str) -> None:
    """Record that `peer_id` sent something invalid (feeds Epic 5 analysis)."""
    self._flags[peer_id] += 1
    count = self._flags[peer_id]
    if count <= 5 or count % 100 == 0:  # a flood of bad messages must not flood the log
      logger.warning("flagged peer %s (%d): %s", peer_id, count, reason)

  @property
  def flags(self) -> dict[str, int]:
    return dict(self._flags)

  def connected_ids(self) -> list[str]:
    return sorted(pid for pid, link in self._links.items() if link.connected)


def now_ms() -> int:
  return int(time.time() * 1000)
