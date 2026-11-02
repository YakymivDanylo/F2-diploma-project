from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from node_helpers import NodeEnv, pem_of

from blockchain_core import generate_issuer_keypair, generate_node_keypair, save_key_pair
from node.config import load_config
from node.main import NodeContext, build_node_context


@pytest.fixture
def node_env(tmp_path: Path) -> NodeEnv:
  node_key = generate_node_keypair()
  issuer_key = generate_issuer_keypair()
  save_key_pair(node_key, tmp_path / "keys" / "node.pem")
  save_key_pair(issuer_key, tmp_path / "keys" / "issuer.pem")
  validators = [{"node_id": "node1", "public_key": pem_of(node_key), "retired_at": None}]
  for i in range(2, 5):
    validators.append(
      {"node_id": f"node{i}", "public_key": pem_of(generate_node_keypair()), "retired_at": None}
    )
  (tmp_path / "validators.json").write_text(
    json.dumps({"n": 4, "f": 1, "validators": validators}), encoding="utf-8"
  )
  (tmp_path / "issuers.json").write_text(
    json.dumps({"issuers": [{"issuer_id": "issuer1", "public_key": pem_of(issuer_key)}]}),
    encoding="utf-8",
  )
  env = {
    "NODE_ID": "node1",
    "ISSUER_ID": "issuer1",
    "CONSENSUS_MODE": "pbft",
    "ISSUER_KEY_PATH": str(tmp_path / "keys" / "issuer.pem"),
    "NODE_KEY_PATH": str(tmp_path / "keys" / "node.pem"),
    "CHAIN_PATH": str(tmp_path / "chain.json"),
    "VALIDATORS_PATH": str(tmp_path / "validators.json"),
    "ISSUERS_PATH": str(tmp_path / "issuers.json"),
    "INIT_CHAIN": "1",
  }
  return NodeEnv(root=tmp_path, env=env, node_key=node_key, issuer_key=issuer_key)


@pytest.fixture
def boot() -> Iterator[Callable[[dict[str, str]], NodeContext]]:
  contexts: list[NodeContext] = []

  def _boot(env: dict[str, str]) -> NodeContext:
    context = build_node_context(load_config(env))
    contexts.append(context)
    return context

  yield _boot
  for context in contexts:
    context.store.close()
