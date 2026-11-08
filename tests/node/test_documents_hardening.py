"""Security-review follow-ups for Slice 13: limits, fail-closed paths, safe names."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest
from chain_factory import pbft_chain, save_chain
from fastapi.testclient import TestClient
from node_helpers import NodeEnv, issuer_entry, write_issuers

from blockchain_core import generate_issuer_keypair, sha256_hex
from node.config import ConfigError, load_config
from node.forwarding import PrimaryStatus
from node.main import NodeContext, create_app
from node.registries import RegistryError, load_issuer_registry

H1 = sha256_hex(b"hard-1")
H2 = sha256_hex(b"hard-2")
H3 = sha256_hex(b"hard-3")


def _serve(env: dict[str, str], **kwargs: Any) -> Iterator[tuple[TestClient, NodeContext]]:
  app = create_app(load_config(env), **kwargs)
  with TestClient(app) as client:
    yield client, app.state.context


def _pow(node_env: NodeEnv, **extra: str) -> dict[str, str]:
  return {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1", **extra}


def _post(client: TestClient, document_hash: str = H1):
  return client.post("/documents", json={"hash": document_hash, "metadata": {"a": 1}})


def test_invalid_chain_rejects_submissions_but_still_serves_lookup(node_env: NodeEnv) -> None:
  blocks = pbft_chain(node_env, 3)
  blocks[2] = replace(blocks[2], timestamp=blocks[2].timestamp + 1)
  save_chain(node_env, blocks)
  for client, context in _serve({**node_env.env, "INIT_CHAIN": "0"}):
    response = _post(client)
    assert response.status_code == 503 and "Retry-After" in response.headers
    assert response.json()["error"]["code"] == "chain_invalid"
    assert len(context.mempool) == 0
    found = client.get(f"/documents/{sha256_hex(b'document-1')}")  # CN-TC-13.4 stays
    assert found.status_code == 200 and found.json()["chain_valid"] is False


def test_valid_chain_lookup_reports_chain_valid(node_env: NodeEnv) -> None:
  save_chain(node_env, pbft_chain(node_env, 1))
  for client, _ in _serve({**node_env.env, "INIT_CHAIN": "0"}):
    assert client.get(f"/documents/{sha256_hex(b'document-1')}").json()["chain_valid"] is True


def test_mempool_is_bounded(node_env: NodeEnv) -> None:
  for client, context in _serve(_pow(node_env, MEMPOOL_MAX_SIZE="2")):
    assert _post(client, H1).status_code == 202
    assert _post(client, H2).status_code == 202
    full = _post(client, H3)
    assert full.status_code == 503 and full.json()["error"]["code"] == "mempool_full"
    assert "Retry-After" in full.headers
    assert _post(client, H1).status_code == 409  # a duplicate is still a duplicate
    assert len(context.mempool) == 2


def test_oversized_body_is_413_before_parsing(node_env: NodeEnv) -> None:
  for client, context in _serve(_pow(node_env, METADATA_MAX_BYTES="100")):
    huge = {"hash": H1, "metadata": {"k": "x" * 200_000}}
    response = client.post("/documents", json=huge)
    assert response.status_code == 413
    assert set(response.json()["error"]) == {"code", "message", "details"}
    assert response.json()["error"]["code"] == "payload_too_large"

    def chunks() -> Iterator[bytes]:  # no Content-Length: counted as it streams
      for _ in range(100):
        yield b'{"hash": "' + b"a" * 1000

    streamed = client.post(
      "/documents", content=chunks(), headers={"content-type": "application/json"}
    )
    assert streamed.status_code == 413
    assert len(context.mempool) == 0
    assert _post(client).status_code == 202  # a normal body is unaffected


def test_other_paths_are_not_body_limited(node_env: NodeEnv) -> None:
  for client, _ in _serve(_pow(node_env, METADATA_MAX_BYTES="100")):
    big = {"node_id": "x", "host": "h", "port": 1, "public_key": "y" * 5000}
    assert client.post("/peers/register", json=big).status_code == 422  # validation, not 413


def test_primary_without_an_id_is_treated_as_no_primary(node_env: NodeEnv) -> None:
  for client, context in _serve(node_env.env, primary_status=lambda: PrimaryStatus("other")):
    response = _post(client)
    assert response.status_code == 503 and response.json()["error"]["code"] == "no_primary"
    assert not context.inflight and len(context.mempool) == 0


class _Blocked:
  async def send(self, request_id, record, primary_id) -> None:
    await asyncio.sleep(3600)


class _Exploding:
  async def send(self, request_id, record, primary_id) -> None:
    raise OSError("connection reset by peer")


def test_blocked_send_times_out_and_frees_the_hash(node_env: NodeEnv) -> None:
  env = {**node_env.env, "FORWARD_ACK_TIMEOUT_MS": "100"}
  for client, context in _serve(
    env, forwarder=_Blocked(), primary_status=lambda: PrimaryStatus.other("node2")
  ):
    response = _post(client)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "forward_timeout"
    assert not context.inflight and len(context.forwarding.pending) == 0
    assert _post(client).status_code == 503  # not stuck behind a leaked in-flight entry


def test_unexpected_transport_error_is_still_retryable(node_env: NodeEnv) -> None:
  for client, context in _serve(
    node_env.env, forwarder=_Exploding(), primary_status=lambda: PrimaryStatus.other("node2")
  ):
    response = _post(client)
    assert response.status_code == 503 and "Retry-After" in response.headers
    assert response.json()["error"]["code"] == "forward_unavailable"
    assert not context.inflight


@pytest.mark.parametrize("bad", ["Uni​versity", "Uni‮versity", "Uni\nversity", "A\x00B"])
def test_names_with_invisible_or_control_characters_fail(node_env: NodeEnv, bad: str) -> None:
  write_issuers(node_env, [issuer_entry("issuer1", node_env.issuer_key, name=bad)])
  with pytest.raises(RegistryError, match="control or invisible"):
    load_issuer_registry(node_env.issuers_path)


def test_names_are_nfc_normalised_for_uniqueness(node_env: NodeEnv) -> None:
  composed, decomposed = "Café Uni", "Café Uni"
  write_issuers(
    node_env,
    [
      issuer_entry("issuer1", node_env.issuer_key, name=composed),
      issuer_entry("issuer2", generate_issuer_keypair(), name=decomposed),
    ],
  )
  with pytest.raises(RegistryError, match="more than one issuer"):
    load_issuer_registry(node_env.issuers_path)


def test_hash_repeated_inside_one_block_is_an_integrity_error(node_env: NodeEnv) -> None:
  blocks = pbft_chain(node_env, 2)
  twice = blocks[1].document_records * 2
  blocks[1] = replace(blocks[1], document_records=twice)
  save_chain(node_env, blocks)
  for client, _ in _serve({**node_env.env, "INIT_CHAIN": "0"}):
    response = client.get(f"/documents/{sha256_hex(b'document-1')}")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "chain_integrity_error"
    assert response.json()["error"]["details"]["occurrences"] == 2


@pytest.mark.parametrize(
  ("key", "value"),
  [
    ("FORWARD_ACK_TIMEOUT_MS", "60001"),
    ("METADATA_MAX_BYTES", "1048577"),
    ("MEMPOOL_MAX_SIZE", "0"),
  ],
)
def test_config_upper_bounds(node_env: NodeEnv, key: str, value: str) -> None:
  with pytest.raises(ConfigError, match=key):
    load_config({**node_env.env, key: value})
  assert load_config({**node_env.env, "FORWARD_ACK_TIMEOUT_MS": "60000"})
