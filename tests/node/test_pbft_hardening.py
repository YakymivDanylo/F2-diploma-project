"""PBFT hardening (2026-11-20 audits): fail-closed state file, persisted Byzantine events,
the `max_batch` bound, the `rounds.py` split and the non-validator `forward_record` answer."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import threading
from pathlib import Path

import pytest
from network_helpers import Cluster, until
from node_helpers import NodeEnv
from pbft_helpers import IDS, feed, signed_candidate
from sync_helpers import run

from blockchain_core import MAX_BLOCK_RECORDS, Block, commit_payload, sign_commit
from blockchain_core.storage.chain_store import block_to_dict
from node.consensus.pbft.engine import PbftEngine
from node.consensus.pbft.messages import PRE_PREPARE, make_message
from node.consensus.pbft.rounds import (
  Round,
  build_certificate,
  count_prepare_votes,
  key_id,
  verified_commit_votes,
)
from node.consensus.pbft.state_store import (
  MAX_PERSISTED_EVENTS,
  PbftState,
  PbftStateError,
  PbftStateStore,
  state_path_for,
)
from node.validity_cache import (
  MAX_BYZANTINE_EVENTS,
  MAX_EVENTS_PER_OFFENDER,
  QUORUM_BYZANTINE,
  ValidityCache,
)

H1 = "a1" * 32
H2 = "b2" * 32


def _cluster(node_env: NodeEnv, ids: tuple[str, ...] = ("node2",)) -> Cluster:
  node_env.env["PBFT_ROUND_TIMEOUT_S"] = "60"
  return Cluster(node_env, ids=ids, mode="pbft")


async def _null_send(message, targets=None):
  return None


def _finalized(env: NodeEnv, seed: int = 1) -> Block:
  block = signed_candidate(env, seed)
  commits = tuple(
    sign_commit(block, node_id, env.validator_keys[node_id])
    for node_id in ("node1", "node3", "node4")
  )
  return dataclasses.replace(block, commit_signatures=commits)


def _store(node) -> PbftStateStore:
  return PbftStateStore(state_path_for(node.context.config.chain_path))


# ======================================================== 1. missing state fails closed


def test_fresh_chain_creates_the_state_file_at_construction(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      node = c["node2"]
      path = state_path_for(node.context.config.chain_path)
      assert path.is_file()  # written at boot, before this node ever voted
      path.unlink()
      assert node.context.chain_state.tip.index == 0
      PbftEngine(node.context, send=_null_send, state_store=_store(node))
      assert json.loads(path.read_text())["signed"] == []  # recreated at once

  run(scenario())


def test_missing_state_past_genesis_fails_closed(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      node = c["node2"]
      assert await node.engine.on_inbound_block(_finalized(node_env))
      assert node.context.chain_state.tip.index == 1
      path = state_path_for(node.context.config.chain_path)
      path.unlink()
      with pytest.raises(PbftStateError, match="PBFT_ALLOW_MISSING_STATE"):
        PbftEngine(node.context, send=_null_send, state_store=_store(node))
      assert not path.exists()  # refused: nothing was written
      engine = PbftEngine(
        node.context, send=_null_send, state_store=_store(node), allow_missing_state=True
      )
      assert engine.lock is None and path.is_file()  # the operator's override, then durable
      PbftEngine(node.context, send=_null_send, state_store=_store(node))  # now it exists

  run(scenario())


def test_synced_then_restarted_before_voting_is_not_refused(node_env: NodeEnv) -> None:
  # the file was created on the fresh chain; blocks arrive by sync; the restart finds it
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      node = c["node2"]
      assert await node.engine.on_inbound_block(_finalized(node_env))
      await node.engine.stop()
      engine = PbftEngine(node.context, send=_null_send, state_store=_store(node))
      assert engine.view == 0

  run(scenario())


def test_state_path_that_is_a_directory_fails_closed(tmp_path: Path) -> None:
  path = tmp_path / "state.json"
  path.mkdir()
  store = PbftStateStore(path)
  with pytest.raises(PbftStateError, match="not a regular file"):
    store.exists()
  with pytest.raises(PbftStateError):
    store.load()


def test_state_path_that_is_a_symlink_fails_closed(tmp_path: Path) -> None:
  target = tmp_path / "real.json"
  PbftStateStore(target).save(PbftState())
  link = tmp_path / "state.json"
  try:
    os.symlink(target, link)
  except (OSError, NotImplementedError):
    pytest.skip("symlinks are not available here")
  with pytest.raises(PbftStateError, match="not a regular file"):
    PbftStateStore(link).load()


def test_missing_state_file_without_a_store_check_is_empty(tmp_path: Path) -> None:
  store = PbftStateStore(tmp_path / "absent.json")
  assert not store.exists()
  assert store.load() == PbftState()


# ======================================================== 2. Byzantine events persist


def test_state_store_round_trips_byzantine_events(tmp_path: Path) -> None:
  store = PbftStateStore(tmp_path / "state.json")
  events = [{"reason": f"r{i}", "offender": f"o{i % 40}", "at_ms": i} for i in range(140)]
  store.save(PbftState(byzantine_events=events))
  loaded = PbftStateStore(store.path).load()
  assert loaded.byzantine_events == events[-MAX_PERSISTED_EVENTS:]
  assert MAX_PERSISTED_EVENTS == MAX_BYZANTINE_EVENTS  # the whole cache log fits in the file


def test_state_without_byzantine_events_still_loads(tmp_path: Path) -> None:
  path = tmp_path / "state.json"
  path.write_text(json.dumps({"version": 1, "view": 0, "signed": [], "lock": None}))
  assert PbftStateStore(path).load().byzantine_events == []


@pytest.mark.parametrize(
  "events",
  [
    "nope",
    [{"reason": "x", "offender": None}],
    [{"reason": 1, "offender": None, "at_ms": 0}],
    [{"reason": "x", "offender": 7, "at_ms": 0}],
    [{"reason": "x", "offender": None, "at_ms": -1}],
    [{"reason": "x" * 5000, "offender": None, "at_ms": 0}],
  ],
)
def test_malformed_byzantine_events_fail_closed(tmp_path: Path, events) -> None:
  path = tmp_path / "state.json"
  data = {"version": 1, "view": 0, "signed": [], "lock": None, "byzantine_events": events}
  path.write_text(json.dumps(data))
  with pytest.raises(PbftStateError):
    PbftStateStore(path).load()


def test_validity_cache_restores_events_without_reporting_them_anew(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      validator = c["node2"].context.validator
      cache = ValidityCache(validator)
      cache.initialize(c["node2"].context.current_blocks())
      cache.flag_byzantine_event("live", offender="node4", at_ms=99)
      restored = [{"reason": f"old{i}", "offender": "node3", "at_ms": i} for i in range(40)]
      cache.restore_byzantine_events(restored)
      events = cache.byzantine_events
      assert len(events) == MAX_EVENTS_PER_OFFENDER + 1
      assert events[-1] == {"reason": "live", "offender": "node4", "at_ms": 99}
      # per offender: the first kept, then the most recent
      assert [e["reason"] for e in events[:-1]] == ["old0", "old37", "old38", "old39"]
      assert cache.snapshot.quorum_status == QUORUM_BYZANTINE

      fresh = ValidityCache(validator)  # restored before initialize: still sticky
      fresh.restore_byzantine_events(restored[:1])
      fresh.initialize(c["node2"].context.current_blocks())
      assert fresh.snapshot.quorum_status == QUORUM_BYZANTINE
      fresh.restore_byzantine_events([])
      assert len(fresh.byzantine_events) == 1

  run(scenario())


def test_byzantine_events_are_persisted_and_restored_on_restart(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      node = c["node2"]
      path = state_path_for(node.context.config.chain_path)
      # an event ChainState reports outside the engine (e.g. from sync)
      node.context.chain_state.report_byzantine_event("two finalized blocks", offender="node3")
      await until(lambda: json.loads(path.read_text())["byzantine_events"] != [])
      saved = json.loads(path.read_text())["byzantine_events"]
      assert [(e["reason"], e["offender"]) for e in saved] == [("two finalized blocks", "node3")]
      await node.engine.stop()

      # a restart: a fresh validity cache, the same state file
      fresh = ValidityCache(node.context.validator)
      fresh.initialize(node.context.current_blocks())
      context = dataclasses.replace(node.context, validity_cache=fresh)
      PbftEngine(context, send=_null_send, state_store=_store(node))
      assert fresh.byzantine_events == saved  # same evidence, same at_ms: not re-logged
      assert fresh.snapshot.quorum_status == QUORUM_BYZANTINE

  run(scenario())


def test_an_equivocation_the_engine_reports_is_persisted(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      node = c["node2"]
      path = state_path_for(node.context.config.chain_path)
      block_a, block_b = signed_candidate(node_env, 1), signed_candidate(node_env, 2)
      for block in (block_a, block_b):  # the primary (node1) pre-prepares two blocks
        feed(
          node,
          make_message(
            PRE_PREPARE,
            node_env.validator_keys["node1"].private_key,
            view=0,
            seq=1,
            block_hash=block.block_hash,
            node_id="node1",
            block=block_to_dict(block),
          ),
        )
        await until(lambda: node.engine.round(1) and node.engine.round(1).candidate)
      await until(lambda: json.loads(path.read_text())["byzantine_events"] != [])
      [event] = json.loads(path.read_text())["byzantine_events"]
      assert event["offender"] == "node1" and "pbft_pre_prepare" in event["reason"]

  run(scenario())


class ParkedStore(PbftStateStore):
  """`save` parks in its worker thread until released, recording what it was handed."""

  def __init__(self, path: Path) -> None:
    super().__init__(path)
    self.hold = threading.Event()
    self.entered = threading.Event()
    self.handed: list[PbftState] = []

  def save(self, state: PbftState) -> None:
    self.handed.append(state)
    self.entered.set()
    self.hold.wait(5)
    super().save(state)


def test_persist_hands_the_worker_thread_a_snapshot(node_env: NodeEnv, boot) -> None:
  # CR3: `to_json` iterates the state in a worker thread; the loop must not mutate it meanwhile
  context = boot(node_env.env)
  store = ParkedStore(state_path_for(context.config.chain_path))
  store.hold.set()  # the construction-time save of a fresh chain is not parked
  engine = PbftEngine(context, send=_null_send, state_store=store)
  store.hold.clear()
  store.entered.clear()
  engine._signed[(0, 1)] = H1

  async def scenario() -> None:
    saving = asyncio.create_task(engine._persist())
    for _ in range(5000):
      if store.entered.is_set():
        break
      await asyncio.sleep(0.001)
    assert store.entered.is_set()
    handed = store.handed[-1]
    assert handed.signed == {(0, 1): H1}
    assert handed.signed is not engine._signed  # a copy taken on the loop
    assert handed.byzantine_events is not context.validity_cache.byzantine_events
    # the loop keeps working while the thread still serializes
    engine._signed[(0, 2)] = H2
    context.chain_state.report_byzantine_event("later", offender="node3")
    store.hold.set()
    await saving
    assert handed.signed == {(0, 1): H1} and handed.byzantine_events == []

  run(scenario())
  saved = json.loads(store.path.read_text(encoding="utf-8"))
  assert saved["signed"] == [[0, 1, H1]]  # what was on the loop when `_persist` ran


# ======================================================== 4. max_batch bound


def test_max_batch_above_the_block_cap_is_refused(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      context = c["node2"].context
      with pytest.raises(ValueError, match="max_batch"):
        PbftEngine(context, send=_null_send, max_batch=MAX_BLOCK_RECORDS + 1)
      with pytest.raises(ValueError, match="max_batch"):
        PbftEngine(context, send=_null_send, max_batch=0)
      PbftEngine(context, send=_null_send, max_batch=MAX_BLOCK_RECORDS)

  run(scenario())


def test_pre_prepare_size_check_never_exceeds_the_block_cap(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      node = c["node2"]
      node.engine._max_batch = 10 * MAX_BLOCK_RECORDS  # forced past the constructor's bound
      block = signed_candidate(node_env, 1)
      raw = block_to_dict(block)
      raw["document_records"] = raw["document_records"] * (MAX_BLOCK_RECORDS + 1)
      feed(
        node,
        make_message(
          PRE_PREPARE,
          node_env.validator_keys["node1"].private_key,
          view=0,
          seq=1,
          block_hash=block.block_hash,
          node_id="node1",
          block=raw,
        ),
      )
      await until(lambda: node.engine.round(1) is not None and node.engine.round(1).rejected)
      assert node.engine.round(1).candidate is None

  run(scenario())


# ======================================================== 3. rounds.py helpers


def _round_with_candidate(env: NodeEnv) -> tuple[Round, Block]:
  block = signed_candidate(env, 1)
  current = Round(view=0, seq=1, candidate=block, primary="node1", pre_prepare_signature="aa")
  return current, block


def test_count_prepare_votes_counts_the_primary_once_and_only_members(node_env: NodeEnv) -> None:
  current, block = _round_with_candidate(node_env)
  members = set(IDS)
  assert count_prepare_votes(Round(view=0, seq=1), members) == 0
  assert count_prepare_votes(current, members) == 1  # the pre-prepare is the primary's vote
  current.prepares = {
    "node1": (block.block_hash, "bb"),  # the primary: never counted twice
    "node3": (block.block_hash, "cc"),
    "node4": ("f" * 64, "dd"),  # another hash
    "outsider": (block.block_hash, "ee"),  # not a member
  }
  assert count_prepare_votes(current, members) == 2


def test_build_certificate_holds_matching_prepares_sorted(node_env: NodeEnv) -> None:
  current, block = _round_with_candidate(node_env)
  current.prepares = {
    "node4": (block.block_hash, "44"),
    "node1": (block.block_hash, "11"),
    "node3": (block.block_hash, "33"),
    "node2": ("f" * 64, "22"),
  }
  cert = build_certificate(current)
  assert (cert.view, cert.seq, cert.block_hash, cert.primary_signature) == (
    0,
    1,
    block.block_hash,
    "aa",
  )
  assert cert.prepares == (("node3", "33"), ("node4", "44"))


def test_verified_commit_votes_rules(node_env: NodeEnv) -> None:
  current, block = _round_with_candidate(node_env)
  keys = {n: node_env.validator_keys[n] for n in IDS}

  def resolve(node_id: str, at_ms: int):
    assert at_ms == block.timestamp  # keys in force at the candidate's timestamp
    if node_id == "node4":
      return keys["node3"].public_key  # node4 shares node3's key: counted once
    return keys[node_id].public_key if node_id in keys else None

  def commit(node_id: str, signer: str | None = None) -> tuple[str, str]:
    return block.block_hash, sign_commit(block, node_id, keys[signer or node_id]).signature

  current.commits = {
    "node1": commit("node1"),
    "node2": (block.block_hash, sign_commit(block, "node2", keys["node1"]).signature),  # bad
    "node3": commit("node3"),
    "node4": commit("node4", "node3"),
  }
  bad: list[str] = []
  assert verified_commit_votes(current, set(IDS), resolve) == {}  # not prepared yet
  current.prepared = True
  votes = verified_commit_votes(current, set(IDS), resolve, on_bad_signature=bad.append)
  assert set(votes) == {"node1", "node3"}
  assert bad == ["node2"]
  verified_commit_votes(current, set(IDS), resolve, on_bad_signature=bad.append)
  assert bad == ["node2"]  # memoized: each signature is checked (and flagged) once
  assert key_id(keys["node1"].public_key) != key_id(keys["node3"].public_key)
  assert commit_payload(block.block_hash)  # the payload the votes sign


def test_engine_wrappers_match_the_helpers(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      engine = c["node2"].engine
      current, block = _round_with_candidate(node_env)
      current.prepares = {"node3": (block.block_hash, "33")}
      assert engine.prepare_votes(current) == 2
      current.prepared = True
      current.commits = {
        "node1": (
          block.block_hash,
          sign_commit(block, "node1", node_env.validator_keys["node1"]).signature,
        )
      }
      assert set(engine.commit_votes(current)) == {"node1"}

  run(scenario())


# ======================================================== 7. non-validator forward_record


def test_non_validator_forward_record_is_answered_auth_then_not_validator(
  node_env: NodeEnv,
) -> None:
  from node.consensus.pbft.forward import RecordIntake, make_forward

  async def scenario() -> None:
    async with _cluster(node_env) as c:
      context = c["node2"].context
      outsider = node_env.validator_keys["node4"]  # a valid key, but not in the ValidatorSet
      intake = RecordIntake(
        context,
        lookup_key=lambda peer: outsider.public_key if peer == "peerx" else None,
        is_validator=lambda node_id: node_id != "peerx",
        is_primary=lambda: True,
        on_queued=lambda _record: None,
      )
      from chain_factory import _record

      record = _record(node_env, 7)
      request_id = "12345678-1234-1234-1234-123456789abc"
      good = make_forward(
        outsider.private_key, request_id=request_id, record=record, sender_id="peerx"
      )
      forged = make_forward(
        node_env.validator_keys["node1"].private_key,
        request_id=request_id,
        record=record,
        sender_id="peerx",
      )
      assert await intake.judge("peerx", forged) == "auth_failed"  # 1a first ...
      assert await intake.judge("peerx", good) == "not_validator"  # ... then 1b

  run(scenario())
