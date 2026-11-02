from __future__ import annotations

import json
import logging

import pytest
from node_helpers import NodeEnv, pem_of

from blockchain_core import ChainStoreMissingError, generate_issuer_keypair, generate_node_keypair
from node.config import ConfigError, load_config
from node.main import BootError
from node.registries import RegistryError, load_validator_registry


def test_valid_env_loads(node_env: NodeEnv) -> None:
  config = load_config(node_env.env)
  assert config.consensus_mode == "pbft"
  assert config.expected_difficulty is None
  assert config.cors_origins == ("http://localhost:5173",)
  assert config.max_page_size == 100
  assert config.init_chain is True


@pytest.mark.parametrize("mode", ["powx", "PoW", "bft"])
def test_invalid_mode_fails_startup(node_env: NodeEnv, mode: str) -> None:  # CN-TC-11.2
  with pytest.raises(ConfigError, match="CONSENSUS_MODE"):
    load_config({**node_env.env, "CONSENSUS_MODE": mode})


def test_missing_mode_fails_startup(node_env: NodeEnv) -> None:  # CN-TC-11.3: no default
  env = {k: v for k, v in node_env.env.items() if k != "CONSENSUS_MODE"}
  with pytest.raises(ConfigError, match="CONSENSUS_MODE"):
    load_config(env)


@pytest.mark.parametrize("value", [None, "0", "257", "abc"])
def test_pow_needs_a_valid_difficulty(node_env: NodeEnv, value: str | None) -> None:
  env = {**node_env.env, "CONSENSUS_MODE": "pow"}
  if value is not None:
    env["EXPECTED_DIFFICULTY"] = value
  with pytest.raises(ConfigError, match="EXPECTED_DIFFICULTY"):
    load_config(env)


@pytest.mark.parametrize(
  ("key", "value"),
  [("MAX_PAGE_SIZE", "0"), ("METADATA_MAX_BYTES", "-1"), ("INIT_CHAIN", "maybe")],
)
def test_bad_numeric_or_flag_values_fail(node_env: NodeEnv, key: str, value: str) -> None:
  with pytest.raises(ConfigError, match=key):
    load_config({**node_env.env, key: value})


def test_boot_logs_registries(node_env, boot, caplog) -> None:  # CN-TC-1.3 / 1.5
  with caplog.at_level(logging.INFO, logger="node"):
    boot(node_env.env)
  assert "n=4" in caplog.text
  assert "f=1" in caplog.text
  assert "issuer1" in caplog.text


@pytest.mark.parametrize("mode", ["pow", "pbft"])
def test_boot_in_each_mode(node_env, boot, mode: str) -> None:  # CN-TC-11.1
  env = {**node_env.env, "CONSENSUS_MODE": mode}
  if mode == "pow":
    env["EXPECTED_DIFFICULTY"] = "1"
  context = boot(env)
  assert context.state.restored.valid
  assert context.config.consensus_mode == mode


def test_core_validator_set_keeps_retired_members(node_env: NodeEnv) -> None:
  doc = json.loads(node_env.validators_path.read_text())
  doc["validators"].append(
    {"node_id": "node2", "public_key": pem_of(generate_node_keypair()), "retired_at": 5}
  )
  node_env.validators_path.write_text(json.dumps(doc))
  core = load_validator_registry(node_env.validators_path).to_core()
  assert core.members == {"node1", "node2", "node3", "node4"}
  assert (core.n, core.f) == (4, 1)


def test_missing_registry_file_fails_fast(node_env, boot) -> None:  # CN-TC-14.6
  node_env.validators_path.unlink()
  with pytest.raises(RegistryError):
    boot(node_env.env)


@pytest.mark.parametrize(
  "mutate",
  [
    lambda doc: doc.update(n=3),  # n < 3f + 1
    lambda doc: doc.update(validators=[]),
    lambda doc: doc["validators"][0].update(public_key="not a pem"),
    lambda doc: doc["validators"].append(dict(doc["validators"][0])),  # two active keys
  ],
)
def test_malformed_validators_fail_fast(node_env, boot, mutate) -> None:  # CN-TC-14.6
  doc = json.loads(node_env.validators_path.read_text())
  mutate(doc)
  node_env.validators_path.write_text(json.dumps(doc))
  with pytest.raises(RegistryError):
    boot(node_env.env)


def test_invalid_json_fails_fast(node_env, boot) -> None:
  node_env.issuers_path.write_text("{ not json", encoding="utf-8")
  with pytest.raises(RegistryError):
    boot(node_env.env)


def test_missing_chain_without_init_fails_closed(node_env, boot) -> None:
  with pytest.raises(ChainStoreMissingError):
    boot({**node_env.env, "INIT_CHAIN": "0"})


def test_node_key_mismatch_fails_fast(node_env, boot) -> None:
  doc = json.loads(node_env.validators_path.read_text())
  doc["validators"][0]["public_key"] = pem_of(generate_node_keypair())
  node_env.validators_path.write_text(json.dumps(doc))
  with pytest.raises(BootError, match="node key"):
    boot(node_env.env)


def test_issuer_key_mismatch_fails_fast(node_env, boot) -> None:
  doc = {"issuers": [{"issuer_id": "issuer1", "public_key": pem_of(generate_issuer_keypair())}]}
  node_env.issuers_path.write_text(json.dumps(doc))
  with pytest.raises(BootError, match="issuer key"):
    boot(node_env.env)


def test_unknown_node_id_fails_fast(node_env, boot) -> None:
  with pytest.raises(BootError, match="NODE_ID"):
    boot({**node_env.env, "NODE_ID": "ghost"})
