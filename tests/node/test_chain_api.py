from __future__ import annotations

from collections.abc import Iterator

from chain_factory import pbft_chain, save_chain
from fastapi.testclient import TestClient
from node_helpers import NodeEnv

from blockchain_core.storage.chain_store import block_to_dict
from node.config import load_config
from node.main import create_app


def _serve(env: dict[str, str]) -> Iterator[TestClient]:
  with TestClient(create_app(load_config(env))) as client:
    yield client


def _env(node_env: NodeEnv, length: int, page: int) -> dict[str, str]:
  save_chain(node_env, pbft_chain(node_env, length))
  return {**node_env.env, "INIT_CHAIN": "0", "MAX_PAGE_SIZE": str(page)}


def test_bounded_range(node_env: NodeEnv) -> None:  # CN-TC-3.6
  blocks = pbft_chain(node_env, 25)
  save_chain(node_env, blocks)
  env = {**node_env.env, "INIT_CHAIN": "0", "MAX_PAGE_SIZE": "100"}
  for client in _serve(env):
    body = client.get("/chain", params={"from": 10, "to": 20}).json()
    assert [b["index"] for b in body["blocks"]] == list(range(10, 21))
    assert (body["from_index"], body["to_index"], body["tip_index"]) == (10, 20, 25)
    assert body["truncated"] is False
    assert body["blocks"][0] == block_to_dict(blocks[10])


def test_no_params_is_capped(node_env: NodeEnv) -> None:  # CN-TC-EV.5
  for client in _serve(_env(node_env, 12, 5)):
    body = client.get("/chain").json()
    assert [b["index"] for b in body["blocks"]] == [0, 1, 2, 3, 4]
    assert body["truncated"] is True
    assert body["tip_index"] == 12


def test_over_max_range_is_truncated(node_env: NodeEnv) -> None:  # CN-TC-3.10
  for client in _serve(_env(node_env, 12, 5)):
    body = client.get("/chain", params={"from": 2, "to": 11}).json()
    assert [b["index"] for b in body["blocks"]] == [2, 3, 4, 5, 6]
    assert body["truncated"] is True and body["to_index"] == 6


def test_short_chain_not_truncated(node_env: NodeEnv) -> None:
  for client in _serve(_env(node_env, 3, 5)):
    body = client.get("/chain").json()
    assert len(body["blocks"]) == 4 and body["truncated"] is False


def test_range_beyond_tip_is_clamped_or_empty(node_env: NodeEnv) -> None:
  for client in _serve(_env(node_env, 3, 5)):
    clamped = client.get("/chain", params={"from": 2, "to": 3}).json()
    assert [b["index"] for b in clamped["blocks"]] == [2, 3]
    empty = client.get("/chain", params={"from": 50}).json()
    assert empty["blocks"] == [] and empty["to_index"] is None


def test_invalid_ranges_use_envelope(node_env: NodeEnv) -> None:
  for client in _serve(_env(node_env, 3, 5)):
    for params in ({"from": 5, "to": 2}, {"from": -1}, {"from": "abc"}):
      response = client.get("/chain", params=params)
      assert response.status_code == 422, params
      assert set(response.json()["error"]) == {"code", "message", "details"}
