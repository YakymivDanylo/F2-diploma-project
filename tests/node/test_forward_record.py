"""Slice 17b: the `forward_record` channel, non-primary -> primary record intake (UC-16).

QA: CN-TC-16.1 .. 16.23 and 16.25 .. 16.33 (16.24 / 16.34 belong to Slice 31b) plus the
as-built censorship watch (UC-16-EC6). Cluster tests run four PBFT nodes in one event loop;
`node1` is the primary of view 0. Tests that count the primary's mempool freeze its proposer
(`freeze`) so the queued record is not drained into a block while we look.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import random
import re
import time
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

import httpx
import pytest
from network_helpers import Cluster, ClusterNode, until
from node_helpers import NodeEnv, pem_of
from sync_helpers import run

from blockchain_core import (
  create_document_record,
  generate_issuer_keypair,
  generate_node_keypair,
  sha256_hex,
  sign_canonical,
  verify_document_record,
)
from node.consensus.pbft.forward import (
  FORWARD,
  FORWARD_REPLY,
  WsRecordForwarder,
  forward_payload,
  make_forward,
)
from node.forwarding import REPLY_CODES, ForwardUnavailable
from node.key_resolver import CombinedKeyResolver

IDS = ("node1", "node2", "node3", "node4")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
FORWARD_KEYS = {"type", "request_id", "record", "sender_id", "sender_signature"}
DEL = object()  # "remove this field"


def digest(label: str) -> str:
  return sha256_hex(f"forward-record-{label}".encode())


def _cluster(node_env: NodeEnv, *, timeout: str = "30", **env: str) -> Cluster:
  node_env.env["PBFT_ROUND_TIMEOUT_S"] = timeout
  node_env.env.update(env)
  return Cluster(node_env, ids=IDS, mode="pbft")


async def ready(c: Cluster) -> Cluster:
  await c.all_connected()
  await until(lambda: all(n.engine.primary_status()[0] != "none" for n in c.nodes.values()))
  return c


async def post(node: ClusterNode, document_hash: str, metadata: dict | None = None):
  transport = httpx.ASGITransport(app=node.app)
  async with httpx.AsyncClient(transport=transport, base_url="http://node") as client:
    return await client.post(
      "/documents", json={"hash": document_hash, "metadata": metadata or {"a": 1}}
    )


def error_code(response: httpx.Response) -> str:
  return response.json()["error"]["code"]


def intake(node: ClusterNode):
  return node.app.state.forward_channel._intake


def channel(node: ClusterNode):
  return node.app.state.forward_channel


def freeze(node: ClusterNode) -> None:
  async def never_propose() -> None:
    return None

  node.engine._propose = never_propose


def thaw(node: ClusterNode) -> None:
  del node.engine._propose  # back to the class method
  node.engine._wake.set()


def chain_count(node: ClusterNode, document_hash: str) -> int:
  return sum(
    1
    for block in node.context.current_blocks()
    for record in block.document_records
    if record.document_hash == document_hash
  )


class Tap:
  """Everything `node` fans out: (message, `only` filter, tip when sent). With `swallow`, a
  `forward_record_reply` is held back (reported as delivered) instead of sent."""

  def __init__(self, node: ClusterNode, *, swallow: bool = False) -> None:
    self.sent: list[tuple[dict[str, Any], set[str] | None, int]] = []
    self.held: list[dict[str, Any]] = []
    self.swallow = swallow
    original = node.manager.broadcast

    async def spy(message: dict[str, Any], *, only: Iterable[str] | None = None):
      targets = None if only is None else set(only)
      self.sent.append((message, targets, node.tip))
      if self.swallow and message.get("type") == FORWARD_REPLY:
        self.held.append(message)
        return dict.fromkeys(targets or (), True)
      return await original(message, only=only)

    node.manager.broadcast = spy  # type: ignore[method-assign]

  def of(self, kind: str) -> list[dict[str, Any]]:
    return [m for m, _, _ in self.sent if m.get("type") == kind]

  @property
  def replies(self) -> list[dict[str, Any]]:
    return self.of(FORWARD_REPLY)


# ------------------------------------------------------------------ message builders


def record_of(env: NodeEnv, document_hash: str, **kw: Any):
  key = kw.get("key") or env.issuer_key
  return create_document_record(
    document_hash=document_hash,
    issuer_id=kw.get("issuer_id", "issuer1"),
    issued_at=kw.get("issued_at", int(time.time() * 1000)),
    metadata=kw.get("metadata", {"a": 1}),
    issuer_private_key=key.private_key,
    ipfs_cid=kw.get("ipfs_cid"),
  )


def fwd(env: NodeEnv, document_hash: str, sender: str = "node2", rid: str | None = None, **kw: Any):
  return plain(
    make_forward(
      env.validator_keys[sender].private_key,
      request_id=rid or str(uuid.uuid4()),
      record=record_of(env, document_hash, **kw),
      sender_id=sender,
    )
  )


def resigned(
  env: NodeEnv, message: dict[str, Any], *, sender: str = "node2", **record_changes: Any
) -> dict[str, Any]:
  """`message` with `record_changes` applied to the record (DEL removes a field), re-signed by
  `sender` so that only the record content is wrong, not the sender authentication."""
  raw = plain(message["record"])
  for name, value in record_changes.items():
    if value is DEL:
      raw.pop(name, None)
    else:
      raw[name] = value
  out = {**message, "record": raw}
  out["sender_signature"] = sign_canonical(
    env.validator_keys[sender].private_key,
    forward_payload(out["request_id"], raw, out["sender_id"]),
  )
  return out


async def judge(node: ClusterNode, message: dict[str, Any], peer: str = "node2") -> str:
  return await intake(node).judge(peer, message)


def plain(value: Any) -> Any:
  """A deep, mutable JSON copy (record dicts hold read-only metadata mappings)."""
  if isinstance(value, Mapping):
    return {k: plain(v) for k, v in value.items()}
  if isinstance(value, list | tuple):
    return [plain(v) for v in value]
  return value


async def settle(node: ClusterNode) -> None:
  """Wait until the channel has answered everything handed to it."""
  await until(lambda: not channel(node)._in_flight and not channel(node)._tasks)


def no_queue(node: ClusterNode) -> None:
  assert len(node.context.mempool) == 0 and not node.context.inflight


# ================================================================== happy path


def test_forward_happy_path_end_to_end(node_env: NodeEnv) -> None:  # 16.1 / 16.2 / 16.29 / 16.31
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      taps = {n: Tap(c[n]) for n in IDS}
      document_hash = digest("happy")
      response = await post(c["node2"], document_hash)
      assert response.status_code == 202 and response.json()["status"] == "accepted"

      forwards = taps["node2"].of(FORWARD)
      assert len(forwards) == 1
      message = forwards[0]
      assert set(message) == FORWARD_KEYS
      assert UUID_RE.match(message["request_id"])
      assert message["sender_id"] == "node2"
      assert message["record"]["issuer_id"] == "issuer1"  # fixed by the sender, never re-assigned
      assert taps["node2"].sent[0][1] == {"node1"}  # to the primary only

      replies = taps["node1"].replies
      assert len(replies) == 1  # exactly one reply per request
      assert replies[0] == {
        "type": FORWARD_REPLY,
        "request_id": message["request_id"],
        "code": "accepted",
      }
      reply_entry = next(e for e in taps["node1"].sent if e[0].get("type") == FORWARD_REPLY)
      assert reply_entry[1] == {"node2"} and reply_entry[2] == 0  # before finalization
      assert len(c["node2"].context.mempool) == 0 and not c["node2"].context.inflight

      await until(lambda: all(n.tip == 1 for n in c.nodes.values()))
      for node in c.nodes.values():
        assert chain_count(node, document_hash) == 1
        stored = node.context.current_blocks()[1].document_records[0]
        assert stored.signed_dict() == message["record"]  # as signed by node2's institution
        assert verify_document_record(stored, node_env.issuer_key.public_key)
      for tap in taps.values():  # 16.31: never addressed to the sender itself
        for m, targets, _ in tap.sent:
          if m.get("type") == FORWARD:
            assert targets is not None and m["sender_id"] not in targets

      # a duplicated reply (EC3) is dropped: no pending request, nothing resolved or flagged
      flags = c["node2"].manager.flags
      await channel(c["node2"]).on_message("node1", replies[0])
      assert len(c["node2"].context.forwarding.pending) == 0
      assert c["node2"].manager.flags == flags

  run(scenario())


def test_primary_local_post_sends_no_forward(node_env: NodeEnv) -> None:  # 16.3
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      taps = {n: Tap(c[n]) for n in IDS}
      response = await post(c["node1"], digest("local"))
      assert response.status_code == 202
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()))
      for tap in taps.values():
        assert tap.of(FORWARD) == [] and tap.replies == []

  run(scenario())


# ================================================================== concurrency / duplicates


@pytest.mark.parametrize(
  "order", [("node2", "node3", "node1"), ("node3", "node2", "node1"), ("node1", "node2", "node3")]
)
def test_concurrent_submissions_of_one_hash_admit_exactly_one(
  node_env: NodeEnv, order: tuple[str, ...]
) -> None:  # 16.4 / 16.8 / 16.30
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      document_hash = digest("race-" + "".join(order))
      responses = await asyncio.gather(*(post(c[name], document_hash) for name in order))
      assert sorted(r.status_code for r in responses) == [202, 409, 409]
      assert {error_code(r) for r in responses if r.status_code == 409} == {"duplicate_hash"}
      assert len(c["node1"].context.mempool) == 1
      for name in ("node2", "node3", "node4"):
        no_queue(c[name])
      thaw(c["node1"])
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()))
      await asyncio.sleep(0.2)
      assert all(chain_count(n, document_hash) == 1 for n in c.nodes.values())
      assert all(n.tip == 1 for n in c.nodes.values())

  run(scenario())


def test_same_forward_delivered_twice_is_queued_once(node_env: NodeEnv) -> None:  # 16.8
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      message = fwd(node_env, digest("twice"))
      assert await judge(c["node1"], message) == "accepted"
      assert await judge(c["node1"], message) == "duplicate"
      assert len(c["node1"].context.mempool) == 1

  run(scenario())


def test_forward_of_a_finalized_hash_is_a_duplicate(node_env: NodeEnv) -> None:  # 16.16
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      document_hash = digest("finalized")
      assert (await post(c["node1"], document_hash)).status_code == 202
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()))
      assert await judge(c["node1"], fwd(node_env, document_hash)) == "duplicate"
      response = await post(c["node2"], document_hash)  # and over HTTP through node2
      assert response.status_code == 409 and error_code(response) == "duplicate_hash"
      await asyncio.sleep(0.2)
      assert all(n.tip == 1 and chain_count(n, document_hash) == 1 for n in c.nodes.values())
      no_queue(c["node1"])

  run(scenario())


def test_forward_of_a_pending_hash_is_a_duplicate_and_leaves_the_mempool(
  node_env: NodeEnv,
) -> None:  # 16.17
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      document_hash = digest("pending")
      assert await judge(c["node1"], fwd(node_env, document_hash)) == "accepted"
      before = c["node1"].context.mempool.snapshot()
      assert await judge(c["node1"], fwd(node_env, document_hash, sender="node3"), "node3") == (
        "duplicate"
      )
      assert c["node1"].context.mempool.snapshot() == before  # same single entry, untouched

  run(scenario())


# ================================================================== view change / not primary


def test_forward_during_a_view_change_then_retry_after_the_election(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.5 / 16.6 / 16.7 / 16.12 / 16.32
    async with _cluster(node_env, timeout="30") as c:
      await ready(c)
      taps = {n: Tap(c[n]) for n in IDS}
      document_hash = digest("view-change")
      await c["node1"].engine._start_view_change(1, "test: leave view 0")
      assert c["node1"].engine.primary_status() == ("none", None)

      # a POST at the node that sees no primary: 503, nothing queued, nothing forwarded
      response = await post(c["node1"], document_hash)
      assert response.status_code == 503 and "Retry-After" in response.headers
      assert error_code(response) == "no_primary"
      no_queue(c["node1"])

      # node2 still forwards to node1; node1 is in a view change -> not_primary, 503
      response = await post(c["node2"], document_hash)
      assert response.status_code == 503 and "Retry-After" in response.headers
      assert error_code(response) == "not_primary"
      assert [r["code"] for r in taps["node1"].replies] == ["not_primary"]
      assert len(taps["node2"].of(FORWARD)) == 1  # no automatic re-forward
      no_queue(c["node1"])
      no_queue(c["node2"])

      # the view change completes: node2 is the primary of view 1
      await c["node3"].engine._start_view_change(1, "test: leave view 0")
      await until(lambda: all(n.engine.view == 1 for n in c.nodes.values()), timeout=10)
      await until(lambda: c["node2"].engine.primary_status() == ("self", "node2"))
      await until(lambda: c["node3"].engine.primary_status() == ("other", "node2"))

      response = await post(c["node3"], document_hash)
      assert response.status_code == 202
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()), timeout=10)
      await asyncio.sleep(0.2)
      assert all(chain_count(n, document_hash) == 1 for n in c.nodes.values())
      assert c["node3"].context.current_blocks()[1].proposer_id == "node2"
      assert (await post(c["node3"], document_hash)).status_code == 409

  run(scenario())


def test_forward_to_a_non_primary_is_not_primary_and_not_queued(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.7 / 16.32 over the real link
    async with _cluster(node_env) as c:
      await ready(c)
      tap = Tap(c["node3"])
      message = fwd(node_env, digest("stale"), sender="node2")
      await channel(c["node3"]).on_message("node2", message)
      await until(lambda: len(tap.replies) == 1)
      assert tap.replies[0]["code"] == "not_primary"
      assert tap.replies[0]["request_id"] == message["request_id"]
      no_queue(c["node3"])
      await asyncio.sleep(0.1)
      assert all(n.tip == 0 for n in c.nodes.values())

  run(scenario())


def test_node2_never_queues_on_any_forward_path(node_env: NodeEnv) -> None:  # 16.32
  async def scenario() -> None:
    async with _cluster(node_env, FORWARD_ACK_TIMEOUT_MS="300") as c:
      await ready(c)
      node2 = c["node2"]
      freeze(c["node1"])
      assert (await post(node2, digest("n2-accepted"))).status_code == 202  # accepted
      no_queue(node2)
      assert (await post(node2, digest("n2-accepted"))).status_code == 409  # rejected
      no_queue(node2)
      forwarder = node2.context.forwarding._forwarder
      forwarder._key = generate_node_keypair().private_key  # auth_failed -> 502
      assert (await post(node2, digest("n2-auth"))).status_code == 502
      no_queue(node2)
      tap = Tap(c["node1"], swallow=True)
      response = await post(node2, digest("n2-timeout"))  # timed out
      assert response.status_code == 503 and error_code(response) == "forward_timeout"
      assert tap.held  # the primary did get it, node2 just never heard back
      no_queue(node2)
      assert len(node2.context.forwarding.pending) == 0

  run(scenario())


# ================================================================== authentication (1a / 1b)


def test_missing_or_invalid_sender_signature_is_auth_failed(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.9 / 16.10 (judge level)
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      good = fwd(node_env, digest("auth"))
      wrong_key = {
        **good,
        "sender_signature": sign_canonical(
          node_env.validator_keys["node3"].private_key,
          forward_payload(good["request_id"], good["record"], "node2"),
        ),
      }
      altered = {**good, "record": {**good["record"], "metadata": {"a": 2}}}  # after signing
      other_request = {**good, "request_id": str(uuid.uuid4())}  # signature binds the request id
      cases = {
        "missing": {k: v for k, v in good.items() if k != "sender_signature"},
        "empty": {**good, "sender_signature": ""},
        "not_hex": {**good, "sender_signature": "zz" * 8},
        "wrong_type": {**good, "sender_signature": 7},
        "wrong_key": wrong_key,
        "altered_record": altered,
        "other_request": other_request,
        "flipped": {
          **good,
          "sender_signature": ("0" if good["sender_signature"][0] != "0" else "1")
          + good["sender_signature"][1:],
        },
        "no_sender": {k: v for k, v in good.items() if k != "sender_id"},
        "sender_not_link_peer": good,  # a valid node2 message arriving on node3's link
      }
      for name, message in cases.items():
        peer = "node3" if name == "sender_not_link_peer" else "node2"
        assert await judge(c["node1"], message, peer) == "auth_failed", name
      no_queue(c["node1"])
      assert await judge(c["node1"], good) == "accepted"  # the untouched message still works

  run(scenario())


def test_missing_sender_signature_over_the_channel_gets_an_auth_failed_reply(
  node_env: NodeEnv,
) -> None:
  async def scenario() -> None:  # 16.9: "Reply auth_failed" on the wire, not only in judge()
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      tap = Tap(c["node1"])
      message = fwd(node_env, digest("no-signature"))
      del message["sender_signature"]
      await channel(c["node1"]).on_message("node2", message)
      await until(lambda: len(tap.replies) == 1, timeout=2)
      assert tap.replies[0]["code"] == "auth_failed"
      assert tap.replies[0]["request_id"] == message["request_id"]
      no_queue(c["node1"])

  run(scenario())


def test_bad_sender_key_maps_to_502_auth_failed_over_http(node_env: NodeEnv) -> None:  # 16.9/16.10
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      c["node2"].context.forwarding._forwarder._key = generate_node_keypair().private_key
      response = await post(c["node2"], digest("http-auth"))
      assert response.status_code == 502 and error_code(response) == "auth_failed"
      no_queue(c["node1"])
      no_queue(c["node2"])

  run(scenario())


def test_peer_info_only_signer_is_not_validator(node_env: NodeEnv) -> None:  # 16.11
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      outsider = generate_node_keypair()
      c["node1"].context.peers.register("outsider", "outsider", 9100, pem_of(outsider))
      message = make_forward(
        outsider.private_key,
        request_id=str(uuid.uuid4()),
        record=record_of(node_env, digest("outsider")),
        sender_id="outsider",
      )
      assert await judge(c["node1"], message, "outsider") == "not_validator"
      # a PeerInfo peer that claims a validator's id cannot borrow it
      claimed = {**message, "sender_id": "node2"}
      assert await judge(c["node1"], claimed, "outsider") == "auth_failed"
      no_queue(c["node1"])

  run(scenario())


# ================================================================== record checks (3 / 5)


def test_malformed_records_are_invalid_record(node_env: NodeEnv) -> None:  # 16.13
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      base = fwd(node_env, digest("shape"))
      cases = {
        "missing_issuer": {"issuer_id": DEL},
        "short_hash": {"document_hash": "ab" * 10},
        "uppercase_hash": {"document_hash": "A" * 64},
        "non_hex_hash": {"document_hash": "g" * 64},
        "hash_not_string": {"document_hash": 7},
        "oversized_metadata": {"metadata": {"k": "x" * 2000}},
        "metadata_not_object": {"metadata": [1, 2]},
        "missing_signature": {"signature": DEL},
        "null_signature": {"signature": None},
        "extra_field": {"surprise": 1},
        "issued_at_text": {"issued_at": "now"},
        "issuer_not_string": {"issuer_id": 5},
      }
      for name, changes in cases.items():
        message = resigned(node_env, base, **changes)
        assert await judge(c["node1"], message) == "invalid_record", name
      assert await judge(c["node1"], {**base, "record": "not an object"}) in {
        "invalid_record",
        "auth_failed",
      }
      no_queue(c["node1"])

  run(scenario())


def test_bad_record_signature_is_invalid_record(node_env: NodeEnv) -> None:  # 16.14
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      stranger = generate_issuer_keypair()
      message = fwd(node_env, digest("bad-sig"), key=stranger)  # well-formed, wrong issuer key
      assert await judge(c["node1"], message) == "invalid_record"
      tampered = resigned(node_env, fwd(node_env, digest("bad-sig-2")), metadata={"a": 99})
      assert await judge(c["node1"], tampered) == "invalid_record"  # content changed after signing
      no_queue(c["node1"])

  run(scenario())


def test_bad_record_signature_maps_to_422_over_http(node_env: NodeEnv) -> None:  # 16.14
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      forwarder = c["node2"].context.forwarding._forwarder
      original = forwarder.send

      async def tampered(request_id: str, record: Any, primary_id: str) -> None:
        bad = create_document_record(
          document_hash=record.document_hash,
          issuer_id=record.issuer_id,
          issued_at=record.issued_at,
          metadata=record.metadata,
          issuer_private_key=generate_issuer_keypair().private_key,
        )
        await original(request_id, bad, primary_id)

      forwarder.send = tampered
      response = await post(c["node2"], digest("http-422"))
      assert response.status_code == 422 and error_code(response) == "invalid_record"
      no_queue(c["node1"])
      no_queue(c["node2"])

  run(scenario())


def test_unknown_issuer_is_invalid_record_before_epic_6(node_env: NodeEnv) -> None:  # 16.15
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      message = fwd(node_env, digest("unknown-issuer"), issuer_id="issuer-unknown")
      assert await judge(c["node1"], message) == "invalid_record"  # resolver miss
      no_queue(c["node1"])

  run(scenario())


# ================================================================== reply handling at the sender


def test_late_reply_and_never_issued_request_id_are_discarded(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.18
    async with _cluster(node_env, FORWARD_ACK_TIMEOUT_MS="200") as c:
      await ready(c)
      node2 = c["node2"]
      tap = Tap(c["node1"], swallow=True)
      response = await post(node2, digest("late"))
      assert response.status_code == 503 and error_code(response) == "forward_timeout"
      assert len(tap.held) == 1
      flags = node2.manager.flags
      await channel(node2).on_message("node1", tap.held[0])  # the late (real) reply
      never = {"type": FORWARD_REPLY, "request_id": str(uuid.uuid4()), "code": "accepted"}
      await channel(node2).on_message("node1", never)
      assert len(node2.context.forwarding.pending) == 0
      no_queue(node2)
      assert node2.manager.flags == flags  # dropped quietly, the peer is not blamed
      assert response.status_code == 503  # the answer already given stands

  run(scenario())


def test_reply_from_a_node_we_did_not_ask_is_ignored_and_first_reply_wins(
  node_env: NodeEnv,
) -> None:
  async def scenario() -> None:  # 16.18 / 16.29
    async with _cluster(node_env, FORWARD_ACK_TIMEOUT_MS="5000") as c:
      await ready(c)
      node2 = c["node2"]
      tap2 = Tap(node2)
      Tap(c["node1"], swallow=True)
      request = asyncio.ensure_future(post(node2, digest("asked")))
      await until(lambda: len(node2.context.forwarding.pending) == 1)
      request_id = tap2.of(FORWARD)[0]["request_id"]

      def reply(code: str) -> dict[str, Any]:
        return {"type": FORWARD_REPLY, "request_id": request_id, "code": code}

      await channel(node2).on_message("node3", reply("accepted"))  # not the primary we asked
      await asyncio.sleep(0.05)
      assert not request.done() and len(node2.context.forwarding.pending) == 1
      await channel(node2).on_message("node1", reply("duplicate"))
      response = await asyncio.wait_for(request, 2)
      assert response.status_code == 409
      await channel(node2).on_message("node1", reply("accepted"))  # duplicated reply
      assert response.status_code == 409 and len(node2.context.forwarding.pending) == 0

  run(scenario())


def test_malformed_forward_messages_are_flagged(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      tap = Tap(c["node1"])
      good = fwd(node_env, digest("flagged"))
      before = c["node1"].manager.flags.get("node2", 0)
      await channel(c["node1"]).on_message("node2", {**good, "request_id": "not-a-uuid"})
      await channel(c["node1"]).on_message("node2", {**good, "extra": 1})
      await channel(c["node1"]).on_message(
        "node2", {"type": FORWARD_REPLY, "request_id": "x", "code": "accepted", "extra": 1}
      )
      assert c["node1"].manager.flags.get("node2", 0) == before + 3
      await asyncio.sleep(0.05)
      # only the message with a usable request_id is answered: auth_failed (not a valid request)
      assert [r["code"] for r in tap.replies] == ["auth_failed"]

  run(scenario())


# ================================================================== reply enum (E8)


def _fuzz(rng: random.Random, env: NodeEnv, base: dict[str, Any]) -> dict[str, Any]:
  junk: list[Any] = [None, 0, -1, 10**30, True, "", "x" * 300, "00" * 40, [], {}, [1], {"a": None}]
  message = plain(base)
  message["request_id"] = str(uuid.uuid4())
  for _ in range(rng.randint(1, 3)):
    target = rng.choice(["message", "record", "record"])
    holder = message if target == "message" else message.get("record")
    if not isinstance(holder, dict):
      continue
    name = rng.choice([*holder, "new_field"])
    action = rng.choice(["delete", "replace", "replace", "add"])
    if action == "delete":
      holder.pop(name, None)
    elif action == "add":
      holder["new_field"] = rng.choice(junk)
    else:
      holder[name] = rng.choice(junk)
  if rng.random() < 0.6 and isinstance(message.get("record"), dict):  # reach the deeper checks
    try:
      message["sender_signature"] = sign_canonical(
        env.validator_keys["node2"].private_key,
        forward_payload(message["request_id"], message["record"], message.get("sender_id")),
      )
    except Exception:
      pass
  return message


def test_every_reply_code_is_in_the_closed_enum_over_a_corpus_and_fuzz(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.19
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      tap = Tap(c["node1"])
      outsider = generate_node_keypair()
      c["node1"].context.peers.register("outsider", "outsider", 9100, pem_of(outsider))
      pending_hash = digest("corpus-pending")
      deep: Any = {"k": 1}
      for _ in range(400):
        deep = {"k": deep}
      base = fwd(node_env, digest("corpus-base"))
      corpus: list[tuple[str, dict[str, Any]]] = [
        ("node2", fwd(node_env, pending_hash)),  # accepted
        ("node2", fwd(node_env, pending_hash)),  # duplicate
        ("node2", {**base, "sender_signature": "00"}),  # auth_failed
        (
          "outsider",
          make_forward(
            outsider.private_key,
            request_id=str(uuid.uuid4()),
            record=record_of(node_env, digest("corpus-outsider")),
            sender_id="outsider",
          ),
        ),  # not_validator
        ("node2", resigned(node_env, base, document_hash="nope")),  # invalid_record (shape)
        ("node2", fwd(node_env, digest("corpus-sig"), key=generate_issuer_keypair())),  # (5)
        ("node2", {**base, "record": {**base["record"], "metadata": deep}}),  # absurd nesting
      ]
      expected: Counter[str] = Counter()
      for peer, message in corpus:
        expected[message["request_id"]] += 1
        await channel(c["node1"]).on_message(peer, message)
        await settle(c["node1"])  # one at a time: the per-peer in-flight cap is tested apart
      rng = random.Random(20261120)
      for _ in range(150):
        message = _fuzz(rng, node_env, base)
        await channel(c["node1"]).on_message("node2", message)
        await settle(c["node1"])
        rid = message.get("request_id")
        answerable = isinstance(rid, str)  # any usable request_id gets exactly one reply
        if answerable and UUID_RE.match(rid):
          expected[rid] += 1
      await until(lambda: len(tap.replies) >= sum(expected.values()), timeout=10)
      await asyncio.sleep(0.1)
      assert Counter(r["request_id"] for r in tap.replies) == expected  # one reply each, no more
      codes = {r["code"] for r in tap.replies}
      assert codes <= REPLY_CODES, codes - REPLY_CODES
      assert all(set(r) == {"type", "request_id", "code"} for r in tap.replies)
      assert {"accepted", "duplicate", "auth_failed", "not_validator", "invalid_record"} <= codes

  run(scenario())


def test_not_primary_is_in_the_enum_and_listed_in_the_corpus(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.19: the remaining reachable code
    async with _cluster(node_env) as c:
      await ready(c)
      assert await judge(c["node3"], fwd(node_env, digest("corpus-np"))) == "not_primary"
      assert "unregistered_issuer" in REPLY_CODES  # present in the enum, unreachable before Epic 6

  run(scenario())


# ================================================================== adjacent-pair check order


def test_order_1a_before_1b_invalid_signature_from_a_non_member(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.20
    async with _cluster(node_env) as c:
      await ready(c)
      outsider = generate_node_keypair()
      c["node1"].context.peers.register("outsider", "outsider", 9100, pem_of(outsider))
      good = make_forward(
        outsider.private_key,
        request_id=str(uuid.uuid4()),
        record=record_of(node_env, digest("1a1b")),
        sender_id="outsider",
      )
      forged = {**good, "sender_signature": "ab" * 64}
      assert await judge(c["node1"], forged, "outsider") == "auth_failed"
      assert await judge(c["node1"], good, "outsider") == "not_validator"  # control
      assert await judge(c["node1"], good, "nobody") == "auth_failed"  # unknown key: still 1a

  run(scenario())


def test_order_1b_before_2_non_validator_at_a_non_primary(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.21
    async with _cluster(node_env) as c:
      await ready(c)
      outsider = generate_node_keypair()
      c["node3"].context.peers.register("outsider", "outsider", 9100, pem_of(outsider))
      message = make_forward(
        outsider.private_key,
        request_id=str(uuid.uuid4()),
        record=record_of(node_env, digest("1b2")),
        sender_id="outsider",
      )
      assert await judge(c["node3"], message, "outsider") == "not_validator"

  run(scenario())


def test_order_2_before_3_malformed_record_at_a_non_primary(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.22
    async with _cluster(node_env) as c:
      await ready(c)
      base = fwd(node_env, digest("23"))
      malformed = resigned(node_env, base, document_hash="bad")
      assert await judge(c["node3"], malformed) == "not_primary"
      assert await judge(c["node1"], malformed) == "invalid_record"  # control at the primary
      no_queue(c["node3"])

  run(scenario())


def test_order_3_before_5_malformed_record_with_unknown_issuer(
  node_env: NodeEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
  async def scenario() -> None:  # 16.23: the shape check wins; the resolver is not consulted
    async with _cluster(node_env) as c:
      await ready(c)
      calls: list[str] = []
      original = CombinedKeyResolver.resolve_issuer_key

      def counting(self: Any, issuer_id: str, at: int):
        calls.append(issuer_id)
        return original(self, issuer_id, at)

      monkeypatch.setattr(CombinedKeyResolver, "resolve_issuer_key", counting)
      base = fwd(node_env, digest("35"), issuer_id="issuer-unknown")
      malformed = resigned(node_env, base, document_hash="not-a-hash")
      assert await judge(c["node1"], malformed) == "invalid_record"
      assert calls == []
      assert await judge(c["node1"], base) == "invalid_record"  # control: now the resolver runs
      assert calls == ["issuer-unknown"]

  run(scenario())


def test_order_5_before_6_bad_signature_for_a_pending_hash(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.25
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      document_hash = digest("56")
      assert await judge(c["node1"], fwd(node_env, document_hash)) == "accepted"
      bad = fwd(node_env, document_hash, key=generate_issuer_keypair())
      assert await judge(c["node1"], bad) == "invalid_record"
      assert len(c["node1"].context.mempool) == 1

  run(scenario())


def test_order_6_before_7_duplicate_then_a_fresh_hash(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.26
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      first = digest("67-first")
      assert await judge(c["node1"], fwd(node_env, first)) == "accepted"
      assert await judge(c["node1"], fwd(node_env, first)) == "duplicate"
      assert len(c["node1"].context.mempool) == 1  # not queued again
      assert await judge(c["node1"], fwd(node_env, digest("67-fresh"))) == "accepted"
      assert len(c["node1"].context.mempool) == 2

  run(scenario())


# ================================================================== edge cases


def test_a_rejected_attempt_leaves_no_lock_and_a_valid_retry_succeeds(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.27 (the duplicate code is excluded: that hash is taken)
    async with _cluster(node_env) as c:
      await ready(c)
      freeze(c["node1"])
      outsider = generate_node_keypair()
      c["node1"].context.peers.register("outsider", "outsider", 9100, pem_of(outsider))
      rejections = {
        "auth_failed": lambda h: (
          {**fwd(node_env, h), "sender_signature": "00" * 8},
          c["node1"],
          "node2",
        ),
        "not_validator": lambda h: (
          make_forward(
            outsider.private_key,
            request_id=str(uuid.uuid4()),
            record=record_of(node_env, h),
            sender_id="outsider",
          ),
          c["node1"],
          "outsider",
        ),
        "not_primary": lambda h: (fwd(node_env, h), c["node3"], "node2"),
        "invalid_shape": lambda h: (
          resigned(node_env, fwd(node_env, h), issuer_id=DEL),
          c["node1"],
          "node2",
        ),
        "invalid_signature": lambda h: (
          fwd(node_env, h, key=generate_issuer_keypair()),
          c["node1"],
          "node2",
        ),
      }
      for name, build in rejections.items():
        document_hash = digest("retry-" + name)
        message, node, peer = build(document_hash)
        assert await judge(node, message, peer) != "accepted", name
        assert not node.context.mempool.contains(document_hash), name
        assert not c["node1"].context.mempool.contains(document_hash), name
        assert document_hash not in node.context.inflight, name
        assert await judge(c["node1"], fwd(node_env, document_hash)) == "accepted", name
      assert len(c["node1"].context.mempool) == len(rejections)

  run(scenario())


def test_repeated_rejects_each_get_a_reply_and_the_link_stays_open(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  async def scenario() -> None:  # 16.28
    async with _cluster(node_env) as c:
      await ready(c)
      tap = Tap(c["node1"])
      sent = []
      with caplog.at_level(logging.INFO):
        for index in range(6):
          message = resigned(node_env, fwd(node_env, digest(f"rej-{index}")), document_hash="bad")
          sent.append(message)
          await channel(c["node1"]).on_message("node2", message)
          await settle(c["node1"])
        await until(lambda: len(tap.replies) == 6)
      assert [r["request_id"] for r in tap.replies] == [m["request_id"] for m in sent]
      assert {r["code"] for r in tap.replies} == {"invalid_record"}
      assert c["node1"].manager.health()["node2"] == "up"
      assert "forward_record rejected: invalid_record" in caplog.text
      for message in sent:  # no key material or signatures in the log
        assert message["sender_signature"] not in caplog.text
      assert "PRIVATE" not in caplog.text and "BEGIN" not in caplog.text
      valid = fwd(node_env, digest("after-rejects"))  # the link still works
      assert (await post(c["node2"], digest("after-rejects-http"))).status_code == 202
      assert await judge(c["node1"], valid) == "accepted"

  run(scenario())


def test_the_forwarder_refuses_to_send_to_itself(node_env: NodeEnv) -> None:  # 16.31
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      tap = Tap(c["node1"])
      record = record_of(node_env, digest("self"))
      with pytest.raises(ForwardUnavailable):
        await c["node1"].context.forwarding.forward(record, "node1")
      calls: list[Any] = []

      async def send(message: dict[str, Any], targets: Iterable[str]) -> dict[str, bool]:
        calls.append(message)
        return {}

      forwarder = WsRecordForwarder(
        self_id="node1",
        key=node_env.validator_keys["node1"].private_key,
        send=send,
        channel=lambda: channel(c["node1"]),
      )
      with pytest.raises(ForwardUnavailable):
        await forwarder.send(str(uuid.uuid4()), record, "node1")
      assert calls == [] and tap.of(FORWARD) == []
      no_queue(c["node1"])

  run(scenario())


def test_forwarder_without_a_link_to_the_primary_is_unavailable(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      await c.network.sever(c["node1"].address)
      await until(lambda: c["node2"].manager.health().get("node1") != "up")
      response = await post(c["node2"], digest("no-link"))
      assert response.status_code == 503 and "Retry-After" in response.headers
      no_queue(c["node2"])

  run(scenario())


# ================================================================== PoW mode (16.33)


def test_pow_node_ignores_forward_record(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # 16.33
    async with Cluster(node_env, ids=("node1", "node2"), mode="pow") as c:
      await c.all_connected()
      node1, node2 = c["node1"], c["node2"]
      assert channel(node1)._intake is None  # no intake channel in PoW
      tap = Tap(node1)
      seen: list[dict[str, Any]] = []
      original = channel(node1).on_message

      async def watch(peer_id: str, message: dict[str, Any]) -> None:
        seen.append(message)
        await original(peer_id, message)

      channel(node1).on_message = watch  # type: ignore[method-assign]
      flags = node1.manager.flags
      messages = [
        fwd(node_env, digest("pow")),
        {"type": FORWARD, "request_id": "garbage"},
        {"type": FORWARD_REPLY, "request_id": str(uuid.uuid4()), "code": "accepted"},
      ]
      for message in messages:
        await node2.manager.broadcast(message, only=["node1"])
      await until(lambda: len(seen) == 3)
      await asyncio.sleep(0.1)
      assert tap.replies == [] and tap.of(FORWARD) == []
      assert node1.manager.flags == flags  # not even a flag
      assert len(node1.context.mempool) == 0 and node1.tip == 0 and node2.tip == 0
      assert node1.manager.health()["node2"] == "up"

  run(scenario())


# ================================================================== censorship watch (UC-16-EC6)


def test_a_primary_that_accepts_but_never_proposes_is_voted_out(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, timeout="0.3") as c:
      await ready(c)
      freeze(c["node1"])  # accepts, never proposes
      with caplog.at_level(logging.WARNING, logger="node.pbft"):
        started = time.monotonic()
        response = await post(c["node2"], digest("censored"))
        assert response.status_code == 202  # the primary did accept
        assert len(c["node1"].context.mempool) == 1
        await asyncio.sleep(0.3)  # well short of 3 round timeouts: no accusation yet
        assert c["node2"].engine.view_changes == 0
        await until(lambda: c["node2"].engine.view_changes >= 1, timeout=10)
        assert time.monotonic() - started >= 0.8  # CENSORSHIP_TIMEOUTS x round timeout
      reason = c["node2"].engine._vc_reason
      assert "record" in reason and "node1" in reason
      assert any(
        "requested" in r.getMessage() and "record" in r.getMessage() for r in caplog.records
      )
      # only the node that watched the record voted: the view does not move on one accusation
      assert [c[n].engine.view_changes for n in ("node1", "node3", "node4")] == [0, 0, 0]
      assert all(n.engine.view == 0 for n in c.nodes.values())

  run(scenario())


def test_a_finalized_forwarded_record_clears_the_watch(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, timeout="0.3") as c:
      await ready(c)
      document_hash = digest("finalizes")
      assert (await post(c["node2"], document_hash)).status_code == 202
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()), timeout=10)
      await until(lambda: not c["node2"].engine._watched, timeout=5)
      await asyncio.sleep(1.2)  # past the 3 x 0.3 s deadline
      assert all(n.engine.view_changes == 0 and n.engine.view == 0 for n in c.nodes.values())
      assert all(n.tip == 1 for n in c.nodes.values())

  run(scenario())


def test_a_rejected_forward_is_not_watched(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, timeout="0.3") as c:
      await ready(c)
      freeze(c["node1"])
      document_hash = digest("rejected-watch")
      assert (await post(c["node1"], document_hash)).status_code == 202  # primary-local
      assert (await post(c["node2"], document_hash)).status_code == 409  # duplicate at primary
      assert c["node2"].engine._watched == {}  # nothing accepted for node2 to watch
      await asyncio.sleep(1.2)
      assert c["node2"].engine.view_changes == 0

  run(scenario())


# ================================================================== intake guards (as built)


def test_in_flight_requests_per_peer_are_capped_and_the_rest_dropped(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      node = c["node1"]
      tap = Tap(node)
      gate = asyncio.Event()
      original = intake(node).judge

      async def slow(peer_id: str, message: dict[str, Any]) -> str:
        await gate.wait()
        return await original(peer_id, message)

      intake(node).judge = slow  # type: ignore[method-assign]
      freeze(node)
      messages = [fwd(node_env, digest(f"cap-{i}")) for i in range(6)]
      before = node.manager.flags.get("node2", 0)
      for message in messages:
        await channel(node).on_message("node2", message)
      assert channel(node)._in_flight == {"node2": 4}
      assert node.manager.flags.get("node2", 0) == before + 2  # two dropped, flagged
      gate.set()
      await settle(node)
      await asyncio.sleep(0.05)
      assert sorted(r["request_id"] for r in tap.replies) == sorted(
        m["request_id"] for m in messages[:4]
      )  # the dropped ones got no reply (their senders time out)
      assert len(node.context.mempool) == 4
      # the slots are free again
      await channel(node).on_message("node2", messages[4])
      await settle(node)
      assert len(tap.replies) == 5

  run(scenario())


def test_oversized_record_is_dropped_before_any_judgement(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      node = c["node1"]
      tap = Tap(node)
      freeze(node)
      huge = fwd(node_env, digest("huge"), metadata={"k": "x" * 6000})
      before = node.manager.flags.get("node2", 0)
      await channel(node).on_message("node2", huge)
      await asyncio.sleep(0.1)
      assert tap.replies == []
      no_queue(node)
      assert node.manager.flags.get("node2", 0) == before + 1
      assert channel(node)._in_flight == {}

  run(scenario())


def test_a_sender_cannot_exceed_its_share_of_the_mempool(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, MEMPOOL_MAX_SIZE="8") as c:  # share = 8 // 4 = 2
      await ready(c)
      node = c["node1"]
      freeze(node)
      codes = [await judge(node, fwd(node_env, digest(f"quota-{i}"))) for i in range(3)]
      assert codes == ["accepted", "accepted", "not_primary"]  # retryable, like a full mempool
      other = fwd(node_env, digest("quota-n3"), sender="node3")
      assert await judge(node, other, "node3") == "accepted"  # node3 has its own share
      assert len(node.context.mempool) == 3
      assert not node.context.mempool.contains(digest("quota-2"))
      node.context.mempool.remove([digest("quota-0")])  # room again once one is drained
      assert await judge(node, fwd(node_env, digest("quota-2"))) == "accepted"

  run(scenario())


def test_issued_at_skew_and_malformed_fields_are_invalid_record(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      node = c["node1"]
      freeze(node)
      now = int(time.time() * 1000)
      old = fwd(node_env, digest("old"), issued_at=now - 120_000)
      assert await judge(node, old) == "invalid_record"
      future = fwd(node_env, digest("future"), issued_at=now + 120_000)
      assert await judge(node, future) == "invalid_record"
      near = fwd(node_env, digest("near"), issued_at=now - 20_000)
      assert await judge(node, near) == "accepted"
      base = fwd(node_env, digest("fields"))
      for name, changes in {
        "issuer_id_chars": {"issuer_id": "bad id!"},
        "odd_signature": {"signature": "abc"},
        "non_hex_signature": {"signature": "zz" * 8},
        "bad_cid": {"ipfs_cid": "not a cid!"},
      }.items():
        assert await judge(node, resigned(node_env, base, **changes)) == "invalid_record", name
      assert len(node.context.mempool) == 1

  run(scenario())


def test_not_accepting_or_invalid_chain_is_not_primary(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      node = c["node1"]
      freeze(node)
      node.app.state.accepting = False
      assert await judge(node, fwd(node_env, digest("starting"))) == "not_primary"
      node.app.state.accepting = True
      cache = node.context.validity_cache
      good = cache._snapshot
      cache._snapshot = dataclasses.replace(good, chain_valid=False)
      assert await judge(node, fwd(node_env, digest("invalid-chain"))) == "not_primary"
      cache._snapshot = good
      no_queue(node)
      assert await judge(node, fwd(node_env, digest("serving"))) == "accepted"

  run(scenario())


def test_a_failing_judge_answers_not_primary(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      node = c["node1"]
      tap = Tap(node)

      async def boom(peer_id: str, message: dict[str, Any]) -> str:
        raise RuntimeError("defect")

      intake(node).judge = boom  # type: ignore[method-assign]
      await channel(node).on_message("node2", fwd(node_env, digest("boom")))
      await until(lambda: len(tap.replies) == 1)
      assert tap.replies[0]["code"] == "not_primary"
      await settle(node)

  run(scenario())


def test_view_moving_during_the_check_is_not_primary_and_queues_nothing(
  node_env: NodeEnv,
) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      node = c["node1"]
      freeze(node)
      state = {"calls": 0}
      real = intake(node)._is_primary

      def flip() -> bool:  # primary at check 2, no longer inside the lock
        state["calls"] += 1
        return real() if state["calls"] == 1 else False

      intake(node)._is_primary = flip
      assert await judge(node, fwd(node_env, digest("flip"))) == "not_primary"
      no_queue(node)

  run(scenario())


# ================================================================== watch guards (as built)


def test_watch_is_ignored_unless_it_names_the_current_primary(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await ready(c)
      engine = c["node2"].engine
      engine.watch_forwarded(digest("other-primary"), "node3")
      assert engine._watched == {}
      engine.watch_forwarded(digest("current-primary"), "node1")
      assert list(engine._watched) == [digest("current-primary")]

  run(scenario())


def _set_batch(c: Cluster, size: int) -> None:
  for node in c.nodes.values():
    node.engine._max_batch = size


def test_a_full_block_postpones_the_watch_deadline(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, timeout="30") as c:
      await ready(c)
      _set_batch(c, 1)  # every block with one record is "full"
      engine = c["node2"].engine
      document_hash = digest("busy-watched")
      engine.watch_forwarded(document_hash, "node1")
      first = engine._watched[document_hash][0]
      await asyncio.sleep(0.1)
      assert (await post(c["node1"], digest("busy-other"))).status_code == 202
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()))
      assert engine._watched[document_hash][0] >= first + 0.09  # busy, not censoring

  run(scenario())


def test_a_block_with_room_does_not_postpone_the_watch(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, timeout="30") as c:
      await ready(c)
      engine = c["node2"].engine
      document_hash = digest("roomy-watched")
      engine.watch_forwarded(document_hash, "node1")
      first = engine._watched[document_hash][0]
      assert (await post(c["node1"], digest("roomy-other"))).status_code == 202
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()))
      assert engine._watched[document_hash][0] == first

  run(scenario())
