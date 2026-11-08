from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from chain_factory import pbft_chain, save_chain
from fastapi.testclient import TestClient
from node_helpers import NodeEnv, issuer_entry, pem_of, write_issuers

from blockchain_core import (
  DocumentRecord,
  generate_issuer_keypair,
  save_key_pair,
  sha256_hex,
  verify_document_record,
)
from node.clock import reject_future_timestamp
from node.config import load_config
from node.errors import ApiError
from node.forwarding import PrimaryStatus
from node.main import NodeContext, create_app

H1 = sha256_hex(b"submit-1")
H2 = sha256_hex(b"submit-2")


def _serve(env: dict[str, str], **kwargs: Any) -> Iterator[tuple[TestClient, NodeContext]]:
  app = create_app(load_config(env), **kwargs)
  with TestClient(app) as client:
    yield client, app.state.context


def _pow(node_env: NodeEnv, **extra: str) -> dict[str, str]:
  return {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1", **extra}


def _post(client: TestClient, document_hash: str = H1, **extra: Any):
  return client.post("/documents", json={"hash": document_hash, "metadata": {"a": 1}, **extra})


def _as_record(data: dict[str, Any]) -> DocumentRecord:
  return DocumentRecord(**data)


def test_valid_submission_is_signed_by_the_server(node_env: NodeEnv) -> None:  # CN-TC-4.1
  for client, context in _serve(_pow(node_env)):
    response = _post(client)
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted" and body["document_hash"] == H1
    assert body["issuer_id"] == "issuer1"
    (record,) = context.mempool.snapshot()
    assert record.issuer_id == "issuer1" and record.metadata == {"a": 1}
    assert verify_document_record(record, node_env.issuer_key.public_key)


def test_batch_of_documents_is_checked_independently(node_env: NodeEnv) -> None:  # CN-TC-4.3
  for client, context in _serve(_pow(node_env)):
    assert _post(client, H1).status_code == 202
    assert _post(client, H2).status_code == 202
    assert _post(client, H1).status_code == 409
    assert [r.document_hash for r in context.mempool.snapshot()] == [H1, H2]


@pytest.mark.parametrize(
  "extra",
  [
    {"signature": "00"},
    {"issuer_id": "issuer2"},  # CN-TC-MI.11: a client cannot pick the institution
    {"issued_at": 1, "ipfs_cid": "x"},
  ],
)
def test_unsigned_contract_rejects_extra_fields(node_env: NodeEnv, extra) -> None:  # 4.4, MI.11
  for client, context in _serve(_pow(node_env)):
    response = _post(client, **extra)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert len(context.mempool) == 0


def test_missing_fields_are_rejected(node_env: NodeEnv) -> None:  # CN-TC-4.6
  for client, _ in _serve(_pow(node_env)):
    assert client.post("/documents", json={"metadata": {}}).status_code == 422
    assert client.post("/documents", json={"hash": H1}).status_code == 422
    assert client.post("/documents", json={}).status_code == 422


@pytest.mark.parametrize("bad", ["A" * 64, "ab" * 31, "g" * 64, ""])
def test_bad_hash_rejected_before_duplicate_check(node_env: NodeEnv, bad: str) -> None:  # 4.8
  for client, _ in _serve(_pow(node_env)):
    assert _post(client).status_code == 202
    response = _post(client, bad)
    assert response.status_code == 422


def test_oversized_metadata_rejected_before_duplicate_check(node_env: NodeEnv) -> None:  # 4.9
  for client, context in _serve(_pow(node_env, METADATA_MAX_BYTES="50")):
    assert _post(client).status_code == 202
    big = client.post("/documents", json={"hash": H1, "metadata": {"k": "x" * 200}})
    assert big.status_code == 422  # not 409: the cap is checked first
    assert big.json()["error"]["code"] == "metadata_too_large"
    assert len(context.mempool) == 1


def test_finalized_duplicate_is_409_and_signs_nothing(node_env: NodeEnv, monkeypatch) -> None:
  save_chain(node_env, pbft_chain(node_env, 2))  # CN-TC-4.10
  env = {**node_env.env, "INIT_CHAIN": "0"}
  for client, context in _serve(env):
    called: list[dict] = []

    def spy(*, sink: list[dict] = called, **kwargs: object) -> None:
      sink.append(kwargs)

    monkeypatch.setattr("node.api.documents.create_document_record", spy)
    response = _post(client, sha256_hex(b"document-1"))  # already in block 1
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "duplicate_hash"
    assert called == [] and len(context.mempool) == 0


def test_pending_duplicate_is_409(node_env: NodeEnv) -> None:  # CN-TC-4.11 / 4.12
  for client, context in _serve(_pow(node_env)):
    assert _post(client).status_code == 202
    again = _post(client)
    assert again.status_code == 409  # the only path: no silent no-op
    assert len(context.mempool) == 1


def test_concurrent_same_hash_has_one_winner(node_env: NodeEnv) -> None:  # CN-TC-4.13
  for client, context in _serve(_pow(node_env)):
    with ThreadPoolExecutor(max_workers=8) as pool:
      codes = sorted(f.result().status_code for f in [pool.submit(_post, client) for _ in range(8)])
    assert codes == [202] + [409] * 7
    assert len(context.mempool) == 1


def test_node_signs_only_as_its_own_institution(node_env: NodeEnv) -> None:  # CN-TC-MI.6
  issuer2 = generate_issuer_keypair()
  save_key_pair(issuer2, node_env.root / "keys" / "issuer2.pem")
  write_issuers(
    node_env,
    [issuer_entry("issuer1", node_env.issuer_key), issuer_entry("issuer2", issuer2)],
  )
  env = _pow(
    node_env,
    ISSUER_ID="issuer2",
    ISSUER_KEY_PATH=str(node_env.root / "keys" / "issuer2.pem"),
  )
  for client, context in _serve(env):
    assert _post(client).status_code == 202
    (record,) = context.mempool.snapshot()
    assert record.issuer_id == "issuer2"
    assert verify_document_record(record, issuer2.public_key)
    assert not verify_document_record(record, node_env.issuer_key.public_key)


def test_not_ready_node_asks_to_retry(node_env: NodeEnv) -> None:  # CN-TC-4.7
  app = create_app(load_config(_pow(node_env)))
  with TestClient(app) as client:
    app.state.accepting = False
    response = _post(client)
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert response.json()["error"]["code"] == "not_ready"
    assert len(app.state.context.mempool) == 0


def test_no_primary_returns_503_without_queueing(node_env: NodeEnv) -> None:  # CN-TC-4.5 / 15.6
  for client, context in _serve(node_env.env, primary_status=PrimaryStatus.none):
    response = _post(client)
    assert response.status_code == 503
    assert response.headers["Retry-After"].isdigit() and int(response.headers["Retry-After"]) > 0
    assert response.json()["error"]["code"] == "no_primary"
    assert len(context.mempool) == 0 and not context.inflight


def test_future_timestamp_cap() -> None:  # Epic 2 follow-up: node-layer skew policy
  reject_future_timestamp(1_000, now_ms=1_000, max_skew_ms=60_000)
  reject_future_timestamp(61_000, now_ms=1_000, max_skew_ms=60_000)  # exactly at the cap
  with pytest.raises(ApiError) as caught:
    reject_future_timestamp(61_001, now_ms=1_000, max_skew_ms=60_000)
  assert caught.value.code == "timestamp_in_future"


def test_error_responses_use_the_envelope(node_env: NodeEnv) -> None:
  for client, _ in _serve(_pow(node_env)):
    _post(client)
    body = _post(client).json()
    assert set(body) == {"error"} and set(body["error"]) == {"code", "message", "details"}
    assert pem_of(node_env.issuer_key) not in str(body)
