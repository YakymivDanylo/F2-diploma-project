"""`forward_record`: a non-primary hands an already-signed record to the PBFT primary (UC-16).

Wire (on the authenticated peer link that carries the PBFT messages, see `ws_pbft.py`):
- `{type: "forward_record", request_id, record, sender_id, sender_signature}` -
  `sender_signature` is the sender's node key over `{domain, request_id, record, sender_id}`
  (its own domain: it can never pass as a vote, a block signature or a record signature);
- `{type: "forward_record_reply", request_id, code}` - exactly one per request, sent after the
  accept/reject decision (never after finalization), `code` from the closed enum.

The primary-side `RecordIntake` runs the binding check order of UC-16 and returns the code of
the FIRST failing check: 1a sender authentication (`auth_failed`), 1b ValidatorSet membership
(`not_validator`), 2 current primary with no view change in flight (`not_primary`), 3 record
shape (`invalid_record`), 5 record signature (`invalid_record`; an unknown issuer is a resolver
miss here - check 4, `unregistered_issuer`, arrives with Epic 6), 6 duplicate against finalized
blocks and the mempool (`duplicate`), else 7 queue (`accepted`). Check 6 and the queueing are
one atomic step under the same lock as the primary's own `POST /documents`. The primary never
re-signs or reassigns a forwarded record. A full mempool answers `not_primary` (retryable).

A non-validator (PeerInfo) peer is answered too - `auth_failed` or, once its signature
verifies, `not_validator` - because the binding order puts authentication first: the node
spends one signature check on it before it learns the sender may not forward at all. That
cost is bounded by the network layer, which caps a non-validator link's frames at 64 KiB (and
by `MAX_IN_FLIGHT_PER_PEER` here), so the order is kept as UC-16 specifies.

The sender-side `WsRecordForwarder` sends to the primary only and accepts a reply only from the
node it sent the request to; a late, duplicated or never-issued reply is dropped by
`PendingForwards`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from typing import TYPE_CHECKING, Any

from blockchain_core import (
  DocumentRecord,
  canonicalize,
  sign_canonical,
  verify_canonical,
  verify_document_record,
)
from blockchain_core.keys import PrivateKey, PublicKey
from blockchain_core.storage.chain_store import record_from_dict
from node.admission import is_known, mempool_full
from node.forwarding import REPLY_CODES, ForwardUnavailable, PendingForwards
from node.patterns import CID_RE, HASH_RE, NODE_ID_RE, REQUEST_ID_RE, SIGNATURE_RE

if TYPE_CHECKING:
  from node.context import NodeContext

logger = logging.getLogger("node.forward")

FORWARD = "forward_record"
FORWARD_REPLY = "forward_record_reply"
FORWARD_TYPES = frozenset({FORWARD, FORWARD_REPLY})
FORWARD_DOMAIN = "node/forward-record/v1"
MAX_TRACKED_REQUESTS = 4096
MAX_IN_FLIGHT_PER_PEER = 4  # forward_record requests judged at once per link; more are dropped

Send = Callable[[dict[str, Any], Iterable[str]], Awaitable[dict[str, bool]]]


def is_forward_message(message: dict[str, Any]) -> bool:
  return message.get("type") in FORWARD_TYPES


def forward_payload(request_id: str, record: dict[str, Any], sender_id: str) -> dict[str, Any]:
  return {
    "domain": FORWARD_DOMAIN,
    "request_id": request_id,
    "record": record,
    "sender_id": sender_id,
  }


def make_forward(
  key: PrivateKey, *, request_id: str, record: DocumentRecord, sender_id: str
) -> dict[str, Any]:
  raw = record.signed_dict()
  return {
    "type": FORWARD,
    "request_id": request_id,
    "record": raw,
    "sender_id": sender_id,
    "sender_signature": sign_canonical(key, forward_payload(request_id, raw, sender_id)),
  }


def _reply(request_id: str, code: str) -> dict[str, Any]:
  assert code in REPLY_CODES  # the closed enum: anything else is a defect (UC-16-E8)
  return {"type": FORWARD_REPLY, "request_id": request_id, "code": code}


class RecordIntake:
  """The primary side: judge one `forward_record` and queue it on `accepted`."""

  def __init__(
    self,
    context: NodeContext,
    *,
    lookup_key: Callable[[str], PublicKey | None],
    is_validator: Callable[[str], bool],
    is_primary: Callable[[], bool],
    on_queued: Callable[[DocumentRecord], None],
    accepting: Callable[[], bool] = lambda: True,
    now_ms: Callable[[], int] = lambda: int(time.time() * 1000),
  ) -> None:
    self._accepting = accepting
    self._context = context
    self._lookup_key = lookup_key
    self._is_validator = is_validator
    self._is_primary = is_primary
    self._on_queued = on_queued
    self._now_ms = now_ms
    self._by_sender: dict[str, set[str]] = {}  # sender -> hashes it has pending here

  @property
  def max_record_bytes(self) -> int:
    """A forwarded record larger than this is dropped before any signature work."""
    return 4 * self._context.config.max_metadata_bytes + 1024

  def _quota_full(self, sender: str) -> bool:
    """One validator may hold at most its fair share of the primary's mempool."""
    context = self._context
    held = {h for h in self._by_sender.get(sender, set()) if context.mempool.contains(h)}
    self._by_sender[sender] = held
    share = max(1, context.config.mempool_max_size // max(1, context.validators.n))
    return len(held) >= share

  async def judge(self, peer_id: str, message: dict[str, Any]) -> str:
    """The reply code for `message` received on `peer_id`'s authenticated link."""
    # 1a. sender authentication: the signed sender is the link's peer, and its key verifies
    sender = message.get("sender_id")
    signature = message.get("sender_signature")
    raw = message.get("record")
    request_id = message.get("request_id")
    key = self._lookup_key(peer_id) if sender == peer_id else None
    if (
      not isinstance(sender, str)
      or not NODE_ID_RE.fullmatch(sender)
      or not isinstance(signature, str)
      or not SIGNATURE_RE.fullmatch(signature)
      or not isinstance(request_id, str)
      or key is None
    ):
      return "auth_failed"
    try:
      payload = forward_payload(request_id, raw, sender)
      # CPU-heavy: off the event loop (a record that cannot be canonicalized fails here)
      signed_ok = await asyncio.to_thread(verify_canonical, key, payload, signature)
    except Exception:
      signed_ok = False
    if not signed_ok:
      return "auth_failed"
    # 1b. ValidatorSet membership (a PeerInfo peer can sign, but never forwards records)
    if not self._is_validator(sender):
      return "not_validator"
    # 2. current primary, no view change in flight - and able to take records at all (serving,
    # valid chain), like POST /documents: never "accepted" for a record that cannot land
    if (
      not self._is_primary()
      or not self._accepting()
      or not self._context.validity_cache.snapshot.chain_valid
    ):
      return "not_primary"
    context = self._context
    # 3. record shape: exact keys and types, hash pattern, metadata size cap
    now = self._now_ms()
    try:
      record = record_from_dict(raw)
      if (
        not HASH_RE.fullmatch(record.document_hash)
        or not NODE_ID_RE.fullmatch(record.issuer_id)
        or not isinstance(record.signature, str)
        or not SIGNATURE_RE.fullmatch(record.signature)
        or (record.ipfs_cid is not None and not CID_RE.fullmatch(record.ipfs_cid))
      ):
        raise ValueError("malformed record")
      if len(canonicalize(dict(record.metadata))) > context.config.max_metadata_bytes:
        raise ValueError("metadata over the size cap")
      if abs(now - record.issued_at) > context.config.max_future_skew_ms:
        raise ValueError("issued_at too far from now")  # forwarded records are signed just now
    except Exception:
      return "invalid_record"
    # (4. no separate IssuerRegistry-membership step as built - the Epic 6 gap: an unknown
    # issuer is a resolver miss and fails at 5)
    # 5. record signature, with the issuer key from the resolver
    issuer_key = context.resolvers.current.resolve_issuer_key(record.issuer_id, now)
    if issuer_key is None or not await asyncio.to_thread(
      verify_document_record, record, issuer_key
    ):
      return "invalid_record"
    # 6 + 7. duplicate check and queueing: one atomic step, shared with POST /documents
    async with context.submission_lock:
      if not self._is_primary():
        return "not_primary"  # a view change began while we checked: never queue then
      if is_known(context, record.document_hash):
        return "duplicate"
      if mempool_full(context) or self._quota_full(sender):
        return "not_primary"  # full (overall, or this sender's share): retryable
      context.mempool.add(record)  # as signed by the sender: never re-signed or reassigned
      self._by_sender.setdefault(sender, set()).add(record.document_hash)
    self._on_queued(record)
    return "accepted"


class ForwardChannel:
  """Both ends of `forward_record` on one node: replies to requests (when PBFT runs here)
  and resolves replies to requests this node sent."""

  def __init__(
    self,
    *,
    intake: RecordIntake | None,
    pending: PendingForwards,
    send: Send,
    flag: Callable[[str, str], None],
  ) -> None:
    self._intake = intake
    self._pending = pending
    self._send = send
    self._flag = flag
    self._sent_to: dict[str, str] = {}  # request_id -> the primary it was sent to
    self._tasks: set[asyncio.Task[Any]] = set()
    self._in_flight: dict[str, int] = {}  # peer -> requests being judged

  def expect(self, request_id: str, primary_id: str) -> None:
    if len(self._sent_to) >= MAX_TRACKED_REQUESTS:  # drop settled / timed-out entries first
      self._sent_to = {r: p for r, p in self._sent_to.items() if self._pending.has(r)}
    if len(self._sent_to) >= MAX_TRACKED_REQUESTS:
      self._sent_to.pop(next(iter(self._sent_to)))
    self._sent_to[request_id] = primary_id

  def forget(self, request_id: str) -> None:
    self._sent_to.pop(request_id, None)

  async def on_message(self, peer_id: str, message: dict[str, Any]) -> None:
    if self._intake is None:
      return  # no PBFT here (PoW mode): no intake channel, ignored with no state change
    if message.get("type") == FORWARD_REPLY:
      self._on_reply(peer_id, message)
      return
    request_id = message.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
      self._flag(peer_id, "malformed forward_record")  # no request id to answer to
      return
    if set(message) != {"type", "request_id", "record", "sender_id", "sender_signature"}:
      # Answerable, but not an authenticated request (e.g. no sender_signature, UC-16-E1).
      self._flag(peer_id, "malformed forward_record")
      await self._send(_reply(request_id, "auth_failed"), [peer_id])
      return
    if self._in_flight.get(peer_id, 0) >= MAX_IN_FLIGHT_PER_PEER:
      self._flag(peer_id, "too many forward_record requests in flight; dropped")
      return  # the sender times out (503, retryable): overload, not a protocol answer
    try:
      size = len(canonicalize(message["record"]))
    except Exception:
      size = 0  # not canonical: check 1a answers it (auth_failed)
    if size > self._intake.max_record_bytes:
      self._flag(peer_id, "oversized forward_record; dropped")
      return
    # Judged off the link reader (the signature checks cost CPU); the reply follows the
    # decision, never the finalization.
    self._in_flight[peer_id] = self._in_flight.get(peer_id, 0) + 1
    task = asyncio.get_running_loop().create_task(self._answer(peer_id, request_id, message))
    self._tasks.add(task)
    task.add_done_callback(self._tasks.discard)

  async def _answer(self, peer_id: str, request_id: str, message: dict[str, Any]) -> None:
    assert self._intake is not None
    try:
      try:
        code = await self._intake.judge(peer_id, message)
      except Exception:
        logger.exception("forward_record handling failed")
        code = "not_primary"  # retryable: the sender's client tries again
      if code != "accepted":
        self._flag(peer_id, f"forward_record rejected: {code}")  # throttled, no key material
      await self._send(_reply(request_id, code), [peer_id])
    except Exception:
      logger.exception("forward_record handling failed")
    finally:
      left = self._in_flight.get(peer_id, 1) - 1
      if left > 0:
        self._in_flight[peer_id] = left
      else:
        self._in_flight.pop(peer_id, None)

  def _on_reply(self, peer_id: str, message: dict[str, Any]) -> None:
    request_id, code = message.get("request_id"), message.get("code")
    if set(message) != {"type", "request_id", "code"} or not isinstance(request_id, str):
      self._flag(peer_id, "malformed forward_record_reply")
      return
    if self._sent_to.get(request_id) != peer_id:
      return  # never issued, already settled, or answered by a node we did not ask
    self._sent_to.pop(request_id, None)
    self._pending.resolve(request_id, code)

  async def stop(self) -> None:
    for task in list(self._tasks):
      task.cancel()
    await asyncio.gather(*self._tasks, return_exceptions=True)


class WsRecordForwarder:
  """The `RecordForwarder` over the authenticated peer link (replaces the Slice 13 stub)."""

  def __init__(
    self,
    *,
    self_id: str,
    key: PrivateKey,
    send: Send,
    channel: Callable[[], ForwardChannel],
  ) -> None:
    self._self_id = self_id
    self._key = key
    self._send = send
    self._channel = channel

  async def send(self, request_id: str, record: DocumentRecord, primary_id: str) -> None:
    if primary_id == self._self_id:  # UC-16-EC5: the primary never forwards to itself
      raise ForwardUnavailable("refusing to forward to self")
    channel = self._channel()
    channel.expect(request_id, primary_id)
    message = make_forward(self._key, request_id=request_id, record=record, sender_id=self._self_id)
    delivered = await self._send(message, [primary_id])
    if not delivered.get(primary_id):
      channel.forget(request_id)
      raise ForwardUnavailable("no established link to the primary")
