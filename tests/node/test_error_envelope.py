from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from node_helpers import NodeEnv
from pydantic import BaseModel

from node.config import load_config
from node.errors import ApiError
from node.main import create_app
from node.schemas import Hash64, validate_metadata_size


class _Body(BaseModel):
  metadata: dict[str, Any]


def _add_probes(app: FastAPI) -> None:
  cap = app.state.context.config.max_metadata_bytes

  @app.get("/probe/{value}")
  async def probe(value: Hash64) -> dict[str, str]:
    return {"value": value}

  @app.post("/probe-meta")
  async def probe_meta(body: _Body) -> dict[str, bool]:
    validate_metadata_size(body.metadata, cap)
    return {"ok": True}

  @app.get("/probe-api")
  async def probe_api() -> None:
    raise ApiError(409, "conflict", "already there", {"hash": "x"})

  @app.get("/probe-boom")
  async def probe_boom() -> None:
    raise RuntimeError("secret internal detail")


def _client(node_env: NodeEnv, **overrides: str) -> Iterator[TestClient]:
  app = create_app(load_config({**node_env.env, **overrides}))
  _add_probes(app)
  with TestClient(app, raise_server_exceptions=False) as client:
    yield client


@pytest.fixture
def client(node_env: NodeEnv) -> Iterator[TestClient]:
  yield from _client(node_env, METADATA_MAX_BYTES="20")


def _assert_envelope(response: Any, status: int, code: str) -> dict[str, Any]:
  assert response.status_code == status
  body = response.json()
  assert set(body) == {"error"}
  assert set(body["error"]) == {"code", "message", "details"}
  assert body["error"]["code"] == code
  assert isinstance(body["error"]["details"], dict)
  return body


def test_api_error_uses_envelope(client: TestClient) -> None:  # CN-TC-EV.1
  body = _assert_envelope(client.get("/probe-api"), 409, "conflict")
  assert body["error"]["details"] == {"hash": "x"}


def test_unknown_route_and_wrong_method_use_envelope(client: TestClient) -> None:
  _assert_envelope(client.get("/nope"), 404, "not_found")
  _assert_envelope(client.post("/probe/" + "a" * 64), 405, "method_not_allowed")


def test_unhandled_exception_hides_detail(client: TestClient) -> None:
  response = client.get("/probe-boom")
  _assert_envelope(response, 500, "internal_error")
  assert "secret" not in response.text


@pytest.mark.parametrize("value", ["a" * 63, "a" * 65, "A" * 64, "g" * 64, "not-a-hash"])
def test_malformed_hash_rejected(client: TestClient, value: str) -> None:  # CN-TC-EV.2
  _assert_envelope(client.get(f"/probe/{value}"), 422, "validation_error")


def test_valid_hash_accepted(client: TestClient) -> None:
  assert client.get("/probe/" + "ab" * 32).status_code == 200


def test_metadata_cap_boundaries(client: TestClient) -> None:  # CN-TC-EV.3, cap = 20 bytes
  at_cap = {"k": "x" * 12}  # {"k":"xxxxxxxxxxxx"} is exactly 20 bytes
  over = {"k": "x" * 13}
  assert client.post("/probe-meta", json={"metadata": {"k": "x"}}).status_code == 200
  assert client.post("/probe-meta", json={"metadata": at_cap}).status_code == 200
  body = _assert_envelope(
    client.post("/probe-meta", json={"metadata": over}), 422, "metadata_too_large"
  )
  assert body["error"]["details"]["max_bytes"] == 20


def test_cors_allows_configured_origin_only(node_env: NodeEnv) -> None:  # CN-TC-EV.4
  headers = {"Access-Control-Request-Method": "GET"}
  for client in _client(node_env, CORS_ORIGINS="http://ui.example"):
    ok = client.options("/probe-api", headers={**headers, "Origin": "http://ui.example"})
    other = client.options("/probe-api", headers={**headers, "Origin": "http://evil.example"})
    assert ok.headers.get("access-control-allow-origin") == "http://ui.example"
    assert "access-control-allow-origin" not in other.headers


def test_cors_is_changeable_by_config_alone(node_env: NodeEnv) -> None:
  for client in _client(node_env, CORS_ORIGINS="http://other.example"):
    response = client.options(
      "/probe-api",
      headers={"Origin": "http://other.example", "Access-Control-Request-Method": "GET"},
    )
    assert response.headers.get("access-control-allow-origin") == "http://other.example"
