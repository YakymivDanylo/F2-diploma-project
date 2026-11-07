from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

from chain_factory import pbft_chain, pow_block, pow_chain, save_chain
from fastapi.testclient import TestClient
from node_helpers import NodeEnv

from blockchain_core import public_key_to_pem
from node.config import load_config
from node.key_resolver import CombinedKeyResolver, ResolverHolder
from node.main import NodeContext, create_app
from node.validity_cache import ChainValidator, ValidityCache

FIELDS = {
  "node_id",
  "algorithm",
  "n",
  "f",
  "node_public_key",
  "tip_index",
  "chain_valid",
  "first_invalid_index",
  "quorum_status",
}


def _serve(env: dict[str, str]) -> Iterator[tuple[TestClient, NodeContext]]:
  app = create_app(load_config(env))
  with TestClient(app) as client:
    yield client, app.state.context


def _pow_env(node_env: NodeEnv) -> dict[str, str]:
  return {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1", "INIT_CHAIN": "0"}


def test_genesis_only_node(node_env: NodeEnv) -> None:  # CN-TC-12.1 / 12.3
  for client, _ in _serve(node_env.env):
    response = client.get("/node/info")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == FIELDS
    assert body["node_id"] == "node1"
    assert body["algorithm"] == "pbft"
    assert (body["n"], body["f"]) == (4, 1)
    assert body["node_public_key"] == public_key_to_pem(node_env.node_key.public_key).decode()
    assert body["tip_index"] == 0
    assert body["chain_valid"] is True
    assert body["first_invalid_index"] is None
    assert body["quorum_status"] == "healthy"


def test_pow_node_reports_configured_n_and_f(node_env: NodeEnv) -> None:  # CN-TC-12.6
  save_chain(node_env, pow_chain(node_env, 3))
  for client, _ in _serve(_pow_env(node_env)):
    body = client.get("/node/info").json()
    assert body["algorithm"] == "pow"
    assert (body["n"], body["f"]) == (4, 1)
    assert body["tip_index"] == 3
    assert body["chain_valid"] is True


def test_valid_pbft_chain(node_env: NodeEnv) -> None:
  save_chain(node_env, pbft_chain(node_env, 2))
  for client, _ in _serve({**node_env.env, "INIT_CHAIN": "0"}):
    body = client.get("/node/info").json()
    assert body["chain_valid"] is True
    assert body["tip_index"] == 2


def test_invalid_chain_is_http_200_with_index(node_env: NodeEnv) -> None:  # CN-TC-12.4
  blocks = pow_chain(node_env, 3)
  blocks[2] = replace(blocks[2], timestamp=blocks[2].timestamp + 1)  # breaks its own hash
  save_chain(node_env, blocks)
  for client, _ in _serve(_pow_env(node_env)):
    response = client.get("/node/info")
    assert response.status_code == 200
    body = response.json()
    assert body["chain_valid"] is False
    assert body["first_invalid_index"] == 2


def test_pbft_block_below_quorum_is_invalid_everywhere(node_env: NodeEnv) -> None:  # CN-TC-12.8
  blocks = pbft_chain(node_env, 1, signers=1)
  save_chain(node_env, blocks)
  for client, context in _serve({**node_env.env, "INIT_CHAIN": "0"}):
    body = client.get("/node/info").json()
    sync_path = context.validator.full(blocks)  # what chain sync would run
    assert body["chain_valid"] is False
    assert body["first_invalid_index"] == 1
    assert body["quorum_status"] == "quorum_invalid"
    assert sync_path.failure_type == "quorum"


def test_append_updates_cache_without_full_revalidation(node_env: NodeEnv) -> None:  # 12.2, 12.7
  blocks = pow_chain(node_env, 200)
  save_chain(node_env, blocks[:-1])
  for client, context in _serve(_pow_env(node_env)):
    calls = {"full": 0}
    original = context.validator.full

    def counting_full(chain, original=original, calls=calls):
      calls["full"] += 1
      return original(chain)

    context.validator.full = counting_full  # type: ignore[method-assign]
    assert client.get("/node/info").json()["tip_index"] == 199
    context.validity_cache.on_append(blocks[-1])
    body = client.get("/node/info").json()
    assert body["tip_index"] == 200
    assert body["chain_valid"] is True
    assert calls["full"] == 0  # the GETs and the append never ran a full validation


def test_bad_append_marks_cache_invalid(node_env: NodeEnv) -> None:
  blocks = pow_chain(node_env, 2)
  save_chain(node_env, blocks[:-1])
  bad = replace(blocks[-1], timestamp=blocks[-1].timestamp + 1)
  for client, context in _serve(_pow_env(node_env)):
    context.validity_cache.on_append(bad)
    body = client.get("/node/info").json()
    assert body["chain_valid"] is False
    assert body["first_invalid_index"] == 2
    context.validity_cache.on_append(pow_block(node_env, blocks[-1], 3))
    again = client.get("/node/info").json()
    assert again["chain_valid"] is False  # an invalid chain stays invalid
    assert again["first_invalid_index"] == 2
    assert again["tip_index"] == 3


def test_missing_consensus_parameters_fail_closed(node_env: NodeEnv) -> None:
  for _, context in _serve(node_env.env):
    holder = ResolverHolder(CombinedKeyResolver(context.validators, context.issuers))
    cache = ValidityCache(ChainValidator(holder, expected_difficulty=None, validator_set=None))
    cache.initialize(pow_chain(node_env, 2))
    assert cache.snapshot.chain_valid is False  # never healthy without the parameters
    assert cache.snapshot.failure_type is not None
