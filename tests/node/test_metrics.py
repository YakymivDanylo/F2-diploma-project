from __future__ import annotations

import time
from collections.abc import Callable, Iterator

from fastapi.testclient import TestClient
from node_helpers import NodeEnv

from blockchain_core import sha256_hex
from node.config import load_config
from node.main import NodeContext, create_app
from node.metrics import ConsensusMetric, MetricsRecorder


def _serve(
  node_env: NodeEnv, *, difficulty: int = 1, mode: str = "pow", mine: bool = True
) -> Iterator[tuple[TestClient, NodeContext]]:
  env = {**node_env.env, "CONSENSUS_MODE": mode}
  if mode == "pow":
    env["EXPECTED_DIFFICULTY"] = str(difficulty)
  app = create_app(load_config(env), mine=mine)
  with TestClient(app) as client:
    yield client, app.state.context


def _wait(condition: Callable[[], bool], timeout: float = 10.0) -> None:
  deadline = time.monotonic() + timeout
  while not condition():
    assert time.monotonic() < deadline, "condition not reached in time"
    time.sleep(0.01)


def _mine_blocks(client: TestClient, context: NodeContext, count: int) -> None:
  for seed in range(1, count + 1):
    digest = sha256_hex(f"metrics-{seed}".encode())
    assert client.post("/documents", json={"hash": digest, "metadata": {}}).status_code == 202
    _wait(lambda seed=seed: len(context.current_blocks()) == seed + 1)


def test_fresh_node_returns_an_empty_list(node_env: NodeEnv) -> None:  # CN-TC-9.3
  for client, _ in _serve(node_env):
    response = client.get("/metrics/consensus")
    assert response.status_code == 200 and response.json() == []


def test_finalized_blocks_are_reported(node_env: NodeEnv) -> None:  # CN-TC-9.1
  for client, context in _serve(node_env, difficulty=6):
    _mine_blocks(client, context, 3)
    rows = client.get("/metrics/consensus").json()
    assert [r["block_index"] for r in rows] == [1, 2, 3]
    for row in rows:
      assert row["algorithm"] == "pow"
      assert row["finalized_at"] >= row["proposed_at"] > 0
      assert row["time_to_finalize_ms"] == row["finalized_at"] - row["proposed_at"]
      assert row["attempts_or_rounds"] >= 1
      assert row["hash_rate"] is not None and row["hash_rate"] > 0
    assert set(rows[0]) == {
      "block_index",
      "algorithm",
      "proposed_at",
      "finalized_at",
      "time_to_finalize_ms",
      "attempts_or_rounds",
      "hash_rate",
    }


def test_higher_difficulty_needs_measurably_more_work(node_env: NodeEnv, tmp_path) -> None:
  # CN-TC-5.2: only EXPECTED_DIFFICULTY changes; attempts are reported by the endpoint
  totals = {}
  for difficulty in (1, 10):
    fresh = tmp_path / f"d{difficulty}.json"
    env = NodeEnv(**{**node_env.__dict__, "env": {**node_env.env, "CHAIN_PATH": str(fresh)}})
    for client, context in _serve(env, difficulty=difficulty):
      _mine_blocks(client, context, 4)
      rows = client.get("/metrics/consensus").json()
      totals[difficulty] = sum(r["attempts_or_rounds"] for r in rows)
  assert totals[10] > 20 * totals[1]  # ~1024 vs ~2 expected attempts per block


def test_last_n_range(node_env: NodeEnv) -> None:  # CN-TC-9.2
  for client, context in _serve(node_env):
    _mine_blocks(client, context, 3)
    assert [r["block_index"] for r in client.get("/metrics/consensus?last=2").json()] == [2, 3]
    assert len(client.get("/metrics/consensus?last=50").json()) == 3
    assert client.get("/metrics/consensus?last=0").status_code == 422
    assert client.get("/metrics/consensus?last=abc").status_code == 422


def test_in_flight_attempt_is_not_reported(node_env: NodeEnv) -> None:  # CN-TC-9.4
  for client, context in _serve(node_env, mine=False):
    context.metrics.record(ConsensusMetric(1, "pow", 10, 20, 5, 100.0))
    client.post("/documents", json={"hash": sha256_hex(b"pending"), "metadata": {}})
    assert len(context.mempool) == 1  # a pending, not yet mined, record
    assert [r["block_index"] for r in client.get("/metrics/consensus").json()] == [1]


def test_huge_attempt_counts_are_exact(node_env: NodeEnv) -> None:  # CN-TC-9.5
  huge = 2**80 + 12345
  for client, context in _serve(node_env, mine=False):
    context.metrics.record(ConsensusMetric(1, "pow", 0, 1000, huge, huge / 1000))
    response = client.get("/metrics/consensus")
    assert response.json()[0]["attempts_or_rounds"] == huge  # no overflow, no float rounding
    assert str(huge) in response.text


def test_pbft_node_has_no_pow_rows(node_env: NodeEnv) -> None:
  for client, _ in _serve(node_env, mode="pbft"):
    assert client.get("/metrics/consensus").json() == []


def test_recorder_is_bounded_and_ordered() -> None:
  recorder = MetricsRecorder(max_retained=3)
  for index in range(1, 6):
    recorder.record(ConsensusMetric(index, "pow", 0, 1, 1, 1.0))
  assert [m.block_index for m in recorder.rows()] == [3, 4, 5]
  assert [m.block_index for m in recorder.rows(last=2)] == [4, 5]
  assert len(recorder) == 3
