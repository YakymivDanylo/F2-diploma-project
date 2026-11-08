from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from chain_factory import pbft_chain, save_chain
from fastapi.testclient import TestClient
from node_helpers import NodeEnv

from blockchain_core import DocumentRecord, sha256_hex, verify_document_record
from node.api.documents import REPLY_TO_ERROR
from node.config import ConfigError, load_config
from node.forwarding import (
  REPLY_CODES,
  ForwardUnavailable,
  PendingForwards,
  PrimaryStatus,
)
from node.main import NodeContext, create_app

H1 = sha256_hex(b"fwd-1")
H2 = sha256_hex(b"fwd-2")
NEVER = object()


class StubForwarder:
  """Replies through the pending table like the Slice 17b channel will."""

  def __init__(
    self,
    reply: Any = "accepted",
    *,
    delay: float | Callable[[DocumentRecord], float] = 0.0,
    raises: Exception | None = None,
  ) -> None:
    self.reply, self.delay, self.raises = reply, delay, raises
    self.calls: list[tuple[str, DocumentRecord, str]] = []
    self.pending: PendingForwards | None = None
    self.replies: list[Any] = []  # optional per-call replies, consumed first

  async def send(self, request_id: str, record: DocumentRecord, primary_id: str) -> None:
    self.calls.append((request_id, record, primary_id))
    if self.raises:
      raise self.raises
    reply = self.replies.pop(0) if self.replies else self.reply
    if reply is NEVER:
      return
    delay = self.delay(record) if callable(self.delay) else self.delay
    assert self.pending is not None
    asyncio.get_running_loop().call_later(delay, self.pending.resolve, request_id, reply)


def _serve(
  node_env: NodeEnv, forwarder: StubForwarder, status: PrimaryStatus | None = None, **env: str
) -> Iterator[tuple[TestClient, NodeContext]]:
  config = load_config({**node_env.env, **env})
  app = create_app(
    config,
    forwarder=forwarder,
    primary_status=lambda: status or PrimaryStatus.other("node2"),
  )
  forwarder.pending = app.state.context.forwarding.pending
  with TestClient(app) as client:
    yield client, app.state.context


def _post(client: TestClient, document_hash: str = H1):
  return client.post("/documents", json={"hash": document_hash, "metadata": {"a": 1}})


ROWS = {
  # reply code -> (status, error code, has Retry-After)
  "accepted": (202, None, False),
  "duplicate": (409, "duplicate_hash", False),
  "not_primary": (503, "not_primary", True),
  "unregistered_issuer": (403, "unregistered_issuer", False),
  "invalid_record": (422, "invalid_record", False),
  "not_validator": (502, "not_validator", False),
  "auth_failed": (502, "auth_failed", False),
}


def test_every_reply_code_has_a_mapping_row() -> None:  # CN-TC-15.2: a new outcome needs a row
  assert set(REPLY_TO_ERROR) == set(REPLY_CODES) == set(ROWS)


@pytest.mark.parametrize("code", sorted(ROWS))
def test_reply_mapping(node_env: NodeEnv, code: str) -> None:  # CN-TC-15.3 .. 15.12, 15.22, 15.27
  status, error, retry = ROWS[code]
  stub = StubForwarder(code)
  for client, context in _serve(node_env, stub):
    response = _post(client)
    assert response.status_code == status
    assert ("Retry-After" in response.headers) == retry
    if retry:
      assert int(response.headers["Retry-After"]) > 0
    if error:
      body = response.json()
      assert set(body["error"]) == {"code", "message", "details"}
      assert body["error"]["code"] == error
    assert len(stub.calls) == 1
    assert len(context.mempool) == 0  # a non-primary never queues, for every outcome
    assert len(context.forwarding.pending) == 0
    assert not context.inflight


def test_accepted_body_matches_a_primary_received_request(node_env: NodeEnv) -> None:  # 15.3
  forwarded = StubForwarder("accepted")
  for client, _ in _serve(node_env, forwarded):
    via_forward = _post(client).json()
  for client, _ in _serve(node_env, StubForwarder(), PrimaryStatus.self_()):
    local = _post(client).json()
  assert via_forward["status"] == local["status"] == "accepted"
  assert set(via_forward) == set(local)


def test_forwarded_record_is_signed_by_this_institution(node_env: NodeEnv) -> None:  # TC-4.2
  stub = StubForwarder("accepted")
  for client, _ in _serve(node_env, stub):
    _post(client)
    _, record, primary_id = stub.calls[0]
    assert primary_id == "node2"
    assert record.issuer_id == "issuer1"
    assert verify_document_record(record, node_env.issuer_key.public_key)


def test_view_change_is_503_and_forwarder_untouched(node_env: NodeEnv) -> None:  # CN-TC-15.6
  stub = StubForwarder()
  for client, context in _serve(node_env, stub, PrimaryStatus.none()):
    response = _post(client)
    assert response.status_code == 503 and "Retry-After" in response.headers
    assert stub.calls == [] and len(context.mempool) == 0


def test_timeout_is_503_forward_timeout(node_env: NodeEnv) -> None:  # CN-TC-15.7
  stub = StubForwarder(NEVER)
  for client, context in _serve(node_env, stub, FORWARD_ACK_TIMEOUT_MS="50"):
    response = _post(client)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "forward_timeout"
    assert "Retry-After" in response.headers
    assert len(context.forwarding.pending) == 0 and not context.inflight


def test_connection_failure_is_503(node_env: NodeEnv) -> None:  # CN-TC-15.8 / 15.19
  for exc in (ConnectionRefusedError, ConnectionResetError):
    stub = StubForwarder(raises=ForwardUnavailable(exc.__name__))
    for client, context in _serve(node_env, stub):
      response = _post(client)
      assert response.status_code == 503 and "Retry-After" in response.headers
      assert len(context.mempool) == 0


def test_not_primary_is_not_reforwarded_automatically(node_env: NodeEnv) -> None:  # CN-TC-15.14
  stub = StubForwarder("not_primary")
  for client, _ in _serve(node_env, stub):
    assert _post(client).status_code == 503
    assert len(stub.calls) == 1
    stub.reply = "accepted"
    assert _post(client).status_code == 202  # the retry is forwarded afresh
    assert len(stub.calls) == 2


def test_lost_reply_then_retry_gets_duplicate(node_env: NodeEnv) -> None:  # CN-TC-15.18
  stub = StubForwarder()
  stub.replies = [NEVER, "duplicate"]
  for client, _ in _serve(node_env, stub, FORWARD_ACK_TIMEOUT_MS="50"):
    first = _post(client)
    assert first.status_code == 503 and first.json()["error"]["code"] == "forward_timeout"
    assert _post(client).status_code == 409


@pytest.mark.parametrize("bad", ["queued", "ACCEPTED", "", None, 7])
def test_reply_outside_the_enum_is_502(node_env: NodeEnv, bad) -> None:  # CN-TC-15.21
  stub = StubForwarder(bad)
  for client, context in _serve(node_env, stub):
    response = _post(client)
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "forward_protocol_error"
    assert len(context.mempool) == 0


def test_late_reply_and_unknown_request_id_are_dropped() -> None:  # CN-TC-15.20 / 15.25
  async def scenario() -> None:
    pending = PendingForwards()
    future = pending.register("live")
    assert pending.resolve("someone-else", "accepted") is False  # unknown id
    assert not future.done()  # the pending request is unaffected
    pending.discard("live")  # e.g. the timeout already fired
    assert pending.resolve("live", "accepted") is False  # late reply discarded
    assert len(pending) == 0

  asyncio.run(scenario())


def test_slow_forward_does_not_block_other_submissions(node_env: NodeEnv) -> None:  # CN-TC-15.23
  stub = StubForwarder("accepted", delay=lambda r: 1.0 if r.document_hash == H1 else 0.0)
  for client, _context in _serve(node_env, stub, FORWARD_ACK_TIMEOUT_MS="5000"):
    with ThreadPoolExecutor(max_workers=1) as pool:
      slow = pool.submit(_post, client, H1)
      deadline = time.monotonic() + 3
      while not stub.calls and time.monotonic() < deadline:
        time.sleep(0.01)
      assert stub.calls, "slow forward never started"
      started = time.monotonic()
      assert _post(client, H2).status_code == 202  # different hash: lock was released
      assert time.monotonic() - started < 0.8
      assert _post(client, H1).status_code == 409  # same hash while in flight
      assert slow.result().status_code == 202
    assert len(stub.calls) == 2  # the same-hash retry never reached the forwarder


def test_known_duplicates_never_reach_the_forwarder(node_env: NodeEnv) -> None:  # CN-TC-15.26
  save_chain(node_env, pbft_chain(node_env, 2))
  stub = StubForwarder()
  for client, context in _serve(node_env, stub, INIT_CHAIN="0"):
    assert _post(client, sha256_hex(b"document-1")).status_code == 409  # finalized
    seeded = DocumentRecord(
      document_hash=H2, issuer_id="issuer1", issued_at=1, metadata={}, signature="00"
    )
    context.mempool.add(seeded)  # pending from an earlier time as primary
    assert _post(client, H2).status_code == 409
    assert stub.calls == []
    assert len(context.mempool) == 1


def test_primary_queues_locally_without_forwarding(node_env: NodeEnv) -> None:  # CN-TC-15.13
  stub = StubForwarder()
  for client, context in _serve(node_env, stub, PrimaryStatus.self_()):
    assert _post(client).status_code == 202
    assert stub.calls == [] and len(context.forwarding.pending) == 0
    assert len(context.mempool) == 1


@pytest.mark.parametrize("value", ["0", "-1", "abc", "", "  "])
@pytest.mark.parametrize("mode", ["pow", "pbft"])
def test_bad_forward_timeout_fails_startup(node_env: NodeEnv, value: str, mode: str) -> None:
  env = {**node_env.env, "CONSENSUS_MODE": mode, "FORWARD_ACK_TIMEOUT_MS": value}
  if mode == "pow":
    env["EXPECTED_DIFFICULTY"] = "1"
  with pytest.raises(ConfigError, match="FORWARD_ACK_TIMEOUT_MS"):  # CN-TC-15.16
    load_config(env)


def test_forward_timeout_boundary_default_and_logging(node_env: NodeEnv, caplog) -> None:
  assert load_config({**node_env.env, "FORWARD_ACK_TIMEOUT_MS": "1"}).forward_ack_timeout_ms == 1
  assert load_config(node_env.env).forward_ack_timeout_ms == 2000  # CN-TC-15.15 / 15.17
  with caplog.at_level(logging.INFO, logger="node"):
    for _ in _serve(node_env, StubForwarder(), FORWARD_ACK_TIMEOUT_MS="500"):
      pass
  assert "FORWARD_ACK_TIMEOUT_MS=500" in caplog.text
