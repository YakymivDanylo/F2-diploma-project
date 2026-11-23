"""2026-11-20 audit follow-ups for the app factory and boot: body limits on every path,
readiness (`serving`) and startup-failure logging, the equivocation LRU, boot validation with
the runtime checklist, own keys in force, strict POST /documents JSON, PBFT_ALLOW_MISSING_STATE.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from chain_factory import pbft_block, pbft_chain, save_chain
from fastapi.testclient import TestClient
from node_helpers import NodeEnv, issuer_entry, pem_of, write_issuers

from blockchain_core import JsonChainStore, sha256_hex
from blockchain_core.storage.chain_store import SharedKeyMaterialError
from blockchain_core.storage.key_store import KeyStoreInsecureError
from node import context as context_module
from node import schemas
from node.config import ConfigError, load_config
from node.consensus.pbft.state_store import PbftStateError, state_path_for
from node.context import BootError, NodeContext, build_node_context
from node.errors import ApiError
from node.main import JudgedSet, create_app

H1 = sha256_hex(b"app-hardening-1")


def _pow(node_env: NodeEnv, **extra: str) -> dict[str, str]:
  return {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1", **extra}


def _serve(env: dict[str, str], **kwargs: Any) -> Iterator[tuple[TestClient, NodeContext]]:
  app = create_app(load_config(env), mine=False, **kwargs)
  with TestClient(app) as client:
    yield client, app.state.context


def _store_is_released(node_env: NodeEnv) -> bool:
  JsonChainStore(Path(node_env.env["CHAIN_PATH"])).close()  # ChainStoreLockedError if held
  return True


def _assert_error(response: Any, status: int, code: str) -> dict[str, Any]:
  assert response.status_code == status, response.text
  error = response.json()["error"]
  assert set(error) == {"code", "message", "details"}
  assert error["code"] == code
  return error


# --- re-exports and wiring ----------------------------------------------------------------


def test_main_re_exports_the_context_api() -> None:
  import node.main as main

  assert main.NodeContext is context_module.NodeContext
  assert main.build_node_context is context_module.build_node_context
  assert main.BootError is context_module.BootError


def test_validators_are_protected_from_peer_eviction(node_env: NodeEnv, boot) -> None:
  context = boot(_pow(node_env))
  assert context.peers.is_protected("node2")
  assert not context.peers.is_protected("stranger")


class _RecordingTransport:
  def __init__(self, failures: int) -> None:
    self.failures = failures
    self.payloads: list[dict[str, Any]] = []

  async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    self.payloads.append(payload)
    if len(self.payloads) <= self.failures:
      raise ConnectionError("seed down")
    return {"peers": []}


def test_seed_payload_is_rebuilt_with_a_fresh_issued_at_per_attempt(node_env: NodeEnv) -> None:
  transport = _RecordingTransport(failures=1)

  async def short_sleep(_seconds: float) -> None:
    import asyncio

    await asyncio.sleep(0.03)

  env = _pow(
    node_env,
    SEED_PEERS="seed.example:9000",
    ALLOW_LOOPBACK_PEERS="1",
    STARTUP_SYNC_TIMEOUT_S="0",
  )
  for _client, _context in _serve(env, peer_transport=transport, sleep=short_sleep):
    deadline = time.monotonic() + 5
    while len(transport.payloads) < 2 and time.monotonic() < deadline:
      time.sleep(0.02)
  assert len(transport.payloads) >= 2
  first, second = transport.payloads[0], transport.payloads[1]
  assert second["issued_at"] > first["issued_at"]
  assert first["signature"] != second["signature"]


# --- 2: body limits on every path ---------------------------------------------------------


def test_peer_registration_body_is_capped_at_8_kib(node_env: NodeEnv) -> None:
  for client, context in _serve(_pow(node_env)):
    big = {"node_id": "x", "host": "h", "port": 1, "public_key": "y" * 9000}
    error = _assert_error(client.post("/peers/register", json=big), 413, "payload_too_large")
    assert error["details"] == {"max_bytes": 8 * 1024}
    assert len(context.peers) == 0


def test_unlisted_paths_get_the_16_kib_default(node_env: NodeEnv) -> None:
  for client, _ in _serve(_pow(node_env)):
    body = b"x" * (16 * 1024 + 1)
    for method, path in (("POST", "/node/info"), ("GET", "/chain"), ("POST", "/nowhere")):
      response = client.request(method, path, content=body)
      error = _assert_error(response, 413, "payload_too_large")
      assert error["details"] == {"max_bytes": 16 * 1024}
    assert client.get("/node/info").status_code == 200  # no body: unaffected


def test_streamed_registration_without_length_is_stopped(node_env: NodeEnv) -> None:
  def chunks() -> Iterator[bytes]:
    for _ in range(20):
      yield b"y" * 1000

  for client, _ in _serve(_pow(node_env)):
    response = client.post(
      "/peers/register", content=chunks(), headers={"content-type": "application/json"}
    )
    _assert_error(response, 413, "payload_too_large")


# --- 3: readiness and startup failures ----------------------------------------------------


def test_node_info_reports_serving(node_env: NodeEnv) -> None:
  for client, _ in _serve(_pow(node_env)):
    body = client.get("/node/info").json()
    assert len(body) == 15
    assert body["serving"] is True


def test_failed_startup_is_logged_and_the_node_stays_not_serving(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  app = create_app(load_config(_pow(node_env)), mine=False)
  app.state.context.peers.register("node2", "node2", 9002, pem_of(node_env.validator_keys["node2"]))

  async def broken_startup(_timeout: float) -> None:
    raise RuntimeError("sync exploded")

  app.state.sync.startup = broken_startup
  with caplog.at_level(logging.ERROR, logger="node"), TestClient(app) as client:
    deadline = time.monotonic() + 5
    while "startup failed" not in caplog.text and time.monotonic() < deadline:
      time.sleep(0.02)
    assert client.get("/node/info").json()["serving"] is False
    response = client.post("/documents", json={"hash": H1, "metadata": {}})
    _assert_error(response, 503, "not_ready")
  failures = [r for r in caplog.records if "startup failed" in r.getMessage()]
  assert failures and failures[0].levelno == logging.ERROR
  assert "sync exploded" in failures[0].getMessage()


# --- 5: equivocation judge LRU ------------------------------------------------------------


def test_judged_set_evicts_the_oldest_instead_of_going_blind() -> None:
  judged = JudgedSet(max_size=3)
  assert all(judged.add((i, "h")) for i in range(3))
  assert not judged.add((0, "h"))  # already judged; refreshed to most recent
  assert judged.add((3, "h"))  # full: evicts (1, "h"), the least recently seen
  assert len(judged) == 3
  assert (1, "h") not in judged and (0, "h") in judged
  assert judged.add((1, "h"))  # judged again after eviction, never refused for good
  for i in range(10_000):
    judged.add((100 + i, "x"))
  assert judged.add((99_999, "new")) and len(judged) == 3


def test_judged_set_rejects_a_non_positive_size() -> None:
  with pytest.raises(ValueError):
    JudgedSet(max_size=0)


# --- 6: boot validation uses the runtime checklist ----------------------------------------


def test_boot_flags_cross_block_duplicate_documents(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  blocks = pbft_chain(node_env, 1)
  blocks.append(pbft_block(node_env, blocks[1], 1))  # re-issues document-1 in block 2
  save_chain(node_env, blocks)
  with caplog.at_level(logging.ERROR, logger="node"):
    context = boot({**node_env.env, "INIT_CHAIN": "0"})
  snapshot = context.validity_cache.snapshot
  assert snapshot.chain_valid is False
  assert snapshot.first_invalid_index == 2
  assert snapshot.failure_type == "duplicate_document"
  assert context.chain_state.blocks[-1].index == 2  # kept for the startup sync to replace
  assert "persisted chain is INVALID" in caplog.text
  assert "first_invalid_index=2" in caplog.text and "duplicate_document" in caplog.text


# --- 7: own keys in force, unusable key material ------------------------------------------


def _future_ms() -> int:
  return int(time.time() * 1000) + 3_600_000


def test_node_key_not_yet_in_force_is_a_boot_error(node_env: NodeEnv) -> None:
  data = json.loads(node_env.validators_path.read_text(encoding="utf-8"))
  data["validators"][0]["valid_from"] = _future_ms()
  node_env.validators_path.write_text(json.dumps(data), encoding="utf-8")
  with pytest.raises(BootError, match="node key of 'node1' is not in force"):
    build_node_context(load_config(_pow(node_env)))
  assert _store_is_released(node_env)


def test_issuer_key_not_yet_in_force_is_a_boot_error(node_env: NodeEnv) -> None:
  write_issuers(node_env, [issuer_entry("issuer1", node_env.issuer_key, valid_from=_future_ms())])
  with pytest.raises(BootError, match="issuer key of 'issuer1' is not in force"):
    build_node_context(load_config(_pow(node_env)))
  assert _store_is_released(node_env)


@pytest.mark.parametrize(
  ("error", "match"),
  [
    (KeyStoreInsecureError("mode 0644 grants group/other access"), "insecure"),
    (SharedKeyMaterialError("same key"), "unusable key material"),
  ],
)
def test_unusable_key_material_is_a_boot_error_with_the_store_closed(
  node_env: NodeEnv, monkeypatch: pytest.MonkeyPatch, error: Exception, match: str
) -> None:
  def refuse(*_args: Any, **_kwargs: Any) -> Any:
    raise error

  monkeypatch.setattr(context_module, "restore_node_state", refuse)
  with pytest.raises(BootError, match=match) as raised:
    build_node_context(load_config(_pow(node_env)))
  assert raised.value.__cause__ is error
  assert _store_is_released(node_env)


# --- 8: strict JSON on POST /documents ----------------------------------------------------


def _raw(client: TestClient, text: str) -> Any:
  return client.post("/documents", content=text, headers={"content-type": "application/json"})


def test_duplicate_top_level_key_is_a_validation_error(node_env: NodeEnv) -> None:
  other = sha256_hex(b"other")
  for client, context in _serve(_pow(node_env)):
    text = f'{{"hash": "{H1}", "hash": "{other}", "metadata": {{}}}}'
    _assert_error(_raw(client, text), 422, "validation_error")
    assert len(context.mempool) == 0


def test_duplicate_metadata_key_is_a_validation_error(node_env: NodeEnv) -> None:
  for client, context in _serve(_pow(node_env)):
    text = f'{{"hash": "{H1}", "metadata": {{"a": 1, "a": 2}}}}'
    error = _assert_error(_raw(client, text), 422, "validation_error")
    assert error["details"]["errors"][0]["type"] == "duplicate_key"
    assert len(context.mempool) == 0


def test_deeply_nested_json_is_422_not_500(node_env: NodeEnv) -> None:
  for client, context in _serve(_pow(node_env, METADATA_MAX_BYTES="8192")):
    depth = 12_000
    text = f'{{"hash": "{H1}", "metadata": {{"a": ' + "[" * depth + "]" * depth + "}}"
    _assert_error(_raw(client, text), 422, "validation_error")
    nested = f'{{"hash": "{H1}", "metadata": {{"a": ' + "[" * 200 + "]" * 200 + "}}"
    _assert_error(_raw(client, nested), 422, "invalid_metadata")
    assert len(context.mempool) == 0


def test_metadata_recursion_error_is_invalid_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
  def explode(_value: Any) -> bytes:
    raise RecursionError("too deep")

  monkeypatch.setattr(schemas, "canonicalize", explode)
  with pytest.raises(ApiError) as raised:
    schemas.validate_metadata_size({"a": 1}, 1024)
  assert (raised.value.status_code, raised.value.code) == (422, "invalid_metadata")


def test_strict_parsing_keeps_the_submit_contract(node_env: NodeEnv) -> None:
  for client, context in _serve(_pow(node_env)):
    _assert_error(_raw(client, "{not json"), 422, "validation_error")
    _assert_error(_raw(client, "[]"), 422, "validation_error")
    _assert_error(client.post("/documents", content=b""), 422, "validation_error")
    text_plain = client.post(
      "/documents",
      content=json.dumps({"hash": H1, "metadata": {}}),
      headers={"content-type": "text/plain"},
    )
    _assert_error(text_plain, 422, "validation_error")
    missing = _assert_error(_raw(client, '{"metadata": {}}'), 422, "validation_error")
    assert missing["details"]["errors"][0]["loc"] == ["body", "hash"]
    ok = client.post("/documents", json={"hash": H1, "metadata": {"a": 1}})
    assert ok.status_code == 202 and ok.json()["document_hash"] == H1
    assert client.post("/documents", json={"hash": H1, "metadata": {}}).status_code == 409
    assert len(context.mempool) == 1


def test_openapi_still_documents_the_submit_body(node_env: NodeEnv) -> None:
  for client, _ in _serve(_pow(node_env)):
    operation = client.get("/openapi.json").json()["paths"]["/documents"]["post"]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert set(schema["properties"]) == {"hash", "metadata"}


# --- 10: PBFT_ALLOW_MISSING_STATE ---------------------------------------------------------


def test_pbft_allow_missing_state_config(node_env: NodeEnv) -> None:
  env = {k: v for k, v in node_env.env.items() if k != "PBFT_ALLOW_MISSING_STATE"}
  assert load_config(env).pbft_allow_missing_state is False
  assert load_config({**env, "PBFT_ALLOW_MISSING_STATE": "true"}).pbft_allow_missing_state
  with pytest.raises(ConfigError, match="PBFT_ALLOW_MISSING_STATE"):
    load_config({**env, "PBFT_ALLOW_MISSING_STATE": "maybe"})


def test_missing_pbft_state_fails_closed_unless_allowed(node_env: NodeEnv) -> None:
  save_chain(node_env, pbft_chain(node_env, 2))
  state_path_for(Path(node_env.env["CHAIN_PATH"])).unlink()  # the state file got lost
  env = {**node_env.env, "INIT_CHAIN": "0", "PBFT_ALLOW_MISSING_STATE": "0"}
  with pytest.raises(PbftStateError, match="PBFT_ALLOW_MISSING_STATE"):
    create_app(load_config(env))
  assert _store_is_released(node_env)  # the failed boot released the chain store
  app = create_app(load_config({**env, "PBFT_ALLOW_MISSING_STATE": "1"}))
  with TestClient(app) as client:
    assert client.get("/node/info").json()["tip_index"] == 2
