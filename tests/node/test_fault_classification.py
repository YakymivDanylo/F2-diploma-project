"""Slice 18: crash faults and Byzantine faults are classified, never conflated.

QA: TC-6.5 (one member down is normal), TC-6.8 / UC-6-E2 (equivocation), TC-6.11 / UC-6-E5 (two
of four members down is a crash-fault quorum loss), TC-8.5 / UC-8-E4 (a second FINALIZED block at
a finalized height), TC-12.5 (`/node/info` while a view change is open).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from typing import Any

import httpx
import pytest
from chain_factory import pbft_block, pbft_chain, pow_block, save_chain
from network_helpers import Cluster, until
from node_helpers import NodeEnv
from pbft_helpers import (
  IDS,
  drain,
  feed,
  propose,
  signed_candidate,
  vote,
)
from sync_helpers import run

from blockchain_core import Block
from blockchain_core.storage.chain_store import block_to_dict
from node.consensus.pbft.messages import (
  COMMIT,
  NO_BLOCK,
  PRE_PREPARE,
  PREPARE,
  VIEW_CHANGE,
  make_message,
)
from node.validity_cache import (
  LIVENESS_STATES,
  MAX_BYZANTINE_EVENTS,
  MAX_EVENTS_PER_OFFENDER,
  MAX_OFFENDERS,
  QUORUM_BYZANTINE,
  QUORUM_CRASH_LOSS,
  QUORUM_HEALTHY,
  QUORUM_VIEW_CHANGE,
)

BYZANTINE = QUORUM_BYZANTINE


def _cluster(
  node_env: NodeEnv, ids: tuple[str, ...] = IDS, *, timeout: str = "60", mode: str = "pbft"
) -> Cluster:
  node_env.env["PBFT_ROUND_TIMEOUT_S"] = timeout
  return Cluster(node_env, ids=ids, mode=mode)


def status(node) -> str:
  return node.context.validity_cache.snapshot.quorum_status


def events(node) -> list[dict[str, Any]]:
  return node.context.validity_cache.byzantine_events


def vc_vote(env: NodeEnv, node_id: str, view: int, *, seq: int = 1, block: Block | None = None):
  return make_message(
    VIEW_CHANGE,
    env.validator_keys[node_id].private_key,
    view=view,
    seq=seq,
    block_hash=NO_BLOCK if block is None else block.block_hash,
    node_id=node_id,
    block=None if block is None else block_to_dict(block),
  )


def drop_messages(node, kinds: set[str]) -> None:
  original = node.manager.broadcast

  async def filtered(message, *, only=None):
    if message.get("type") in kinds:
      return None
    return await original(message, only=only)

  node.manager.broadcast = filtered


async def node_info(node) -> dict[str, Any]:
  transport = httpx.ASGITransport(app=node.app)
  async with httpx.AsyncClient(transport=transport, base_url="http://node") as client:
    response = await client.get("/node/info")
  assert response.status_code == 200
  return response.json()


# ============================================================ TC-6.8: vote equivocation


def test_conflicting_prepares_are_one_vote_and_a_byzantine_event(node_env: NodeEnv) -> None:
  block_a, block_b = signed_candidate(node_env, 1), signed_candidate(node_env, 2)

  async def scenario() -> None:  # TC-6.8 / UC-6-E2
    async with _cluster(node_env) as c:
      await c.all_connected()
      node = c["node2"]
      feed(node, vote(node_env, PRE_PREPARE, "node1", block_a))
      await until(lambda: node.engine.round(1) and node.engine.round(1).candidate)
      current = node.engine.round(1)
      feed(node, vote(node_env, PREPARE, "node3", block_a))
      await until(lambda: "node3" in current.prepares)
      assert node.engine.prepare_votes(current) == 3  # primary (implicit) + node2 + node3
      assert events(node) == [] and status(node) == QUORUM_HEALTHY
      # node3 now prepares a DIFFERENT hash for the same (view, seq)
      feed(node, vote(node_env, PREPARE, "node3", block_a, block_hash=block_b.block_hash))
      await until(lambda: current.conflicts)
      assert current.conflicts == [(PREPARE, "node3", block_a.block_hash, block_b.block_hash)]
      assert current.prepares["node3"][0] == block_a.block_hash  # the first stays, counted once
      assert node.engine.prepare_votes(current) == 3  # not double counted
      assert status(node) == BYZANTINE
      assert len(events(node)) == 1 and events(node)[0]["offender"] == "node3"
      assert "node3" in str(events(node)[0]["reason"]) and "prepare" in str(
        events(node)[0]["reason"]
      )
      assert node.manager.flags.get("node3", 0) >= 1
      # a crash-fault classification is a different thing and is NOT what is reported
      await until(lambda: node.engine.liveness == QUORUM_HEALTHY)
      assert node.context.validity_cache.liveness == QUORUM_HEALTHY
      assert status(node) != QUORUM_CRASH_LOSS
      # repeating the conflicting vote is not new evidence
      feed(node, vote(node_env, PREPARE, "node3", block_a, block_hash=block_b.block_hash))
      await drain(node)
      assert len(events(node)) == 1 and len(current.conflicts) == 1
      # an observation is local: nobody else is told that node3 lied
      assert status(c["node4"]) == QUORUM_HEALTHY and events(c["node4"]) == []

  run(scenario())


def test_conflicting_commits_are_one_vote_and_a_byzantine_event(node_env: NodeEnv) -> None:
  block_a, block_b = signed_candidate(node_env, 1), signed_candidate(node_env, 2)

  async def scenario() -> None:  # TC-6.8: commit equivocation
    async with _cluster(node_env) as c:
      await c.all_connected()
      node = c["node2"]
      feed(
        node,
        vote(node_env, PRE_PREPARE, "node1", block_a),
        vote(node_env, PREPARE, "node3", block_a),
      )
      await until(lambda: node.engine.round(1) and node.engine.round(1).prepared)
      current = node.engine.round(1)
      feed(node, vote(node_env, COMMIT, "node3", block_a))
      await until(lambda: "node3" in current.commits)
      feed(node, vote(node_env, COMMIT, "node3", block_a, block_hash=block_b.block_hash))
      await until(lambda: current.conflicts)
      assert current.conflicts[0][:2] == (COMMIT, "node3")
      assert set(node.engine.commit_votes(current)) == {"node2", "node3"}  # node3 counted once
      assert status(node) == BYZANTINE and events(node)[0]["offender"] == "node3"
      assert node.tip == 0
      # honest majority still finalizes the right block, with node3's FIRST commit only
      feed(node, vote(node_env, COMMIT, "node4", block_a))
      await until(lambda: node.tip == 1)
      finalized = node.context.current_blocks()[1]
      assert finalized.block_hash == block_a.block_hash
      signers = [s.node_id for s in finalized.commit_signatures]
      assert len(signers) == len(set(signers)) and "node3" in signers
      assert node.context.validator.full(node.context.current_blocks()).valid
      assert len(events(node)) == 1

  run(scenario())


def test_forged_or_duplicate_votes_are_not_equivocation(node_env: NodeEnv) -> None:
  block_a, block_b = signed_candidate(node_env, 1), signed_candidate(node_env, 2)

  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      node = c["node2"]
      feed(
        node,
        vote(node_env, PRE_PREPARE, "node1", block_a),
        vote(node_env, PREPARE, "node3", block_a),
        vote(node_env, COMMIT, "node3", block_a),
      )
      await until(lambda: node.engine.round(1) and "node3" in node.engine.round(1).commits)
      current = node.engine.round(1)
      # exact duplicates are no-ops
      feed(
        node,
        vote(node_env, PREPARE, "node3", block_a),
        vote(node_env, COMMIT, "node3", block_a),
      )
      # node4's signature under node3's name: nobody can frame node3
      framed_prepare = replace(vote(node_env, PREPARE, "node4", block_b), node_id="node3")
      framed_commit = replace(vote(node_env, COMMIT, "node4", block_b), node_id="node3")
      feed(node, framed_prepare, framed_commit)
      await drain(node)
      assert current.conflicts == [] and events(node) == []
      assert status(node) == QUORUM_HEALTHY
      assert current.prepares["node3"][0] == block_a.block_hash

  run(scenario())


def test_equivocating_non_validator_is_not_a_byzantine_event(node_env: NodeEnv) -> None:
  block_a, block_b = signed_candidate(node_env, 1), signed_candidate(node_env, 2)

  async def scenario() -> None:
    async with _cluster(node_env, ("node2",)) as c:
      node = c["node2"]
      outsider = replace(vote(node_env, PREPARE, "node3", block_a), node_id="node77")
      outsider_b = replace(
        vote(node_env, PREPARE, "node3", block_a, block_hash=block_b.block_hash), node_id="node77"
      )
      feed(node, outsider, outsider_b)
      await drain(node)
      assert events(node) == [] and node.manager.flags.get("node77", 0) >= 1

  run(scenario())


def test_view_change_vote_equivocation_names_the_offender(node_env: NodeEnv) -> None:
  block_a, block_b = signed_candidate(node_env, 1), signed_candidate(node_env, 2)

  async def scenario() -> None:  # two different locked blocks named for one (view, seq)
    async with _cluster(node_env) as c:
      await c.all_connected()
      node = c["node2"]
      feed(node, vc_vote(node_env, "node3", 2, block=block_a))
      await until(lambda: "node3" in node.engine.view_change.latest)
      assert events(node) == []
      feed(node, vc_vote(node_env, "node3", 2, block=block_b))
      await until(lambda: events(node))
      assert status(node) == BYZANTINE and events(node)[0]["offender"] == "node3"
      assert "view-change" in str(events(node)[0]["reason"])
      # the first vote stays the one on record
      assert node.engine.view_change.latest["node3"].block_hash == block_a.block_hash

  run(scenario())


@pytest.mark.parametrize(
  "second",
  ["lock_gained", "lock_released", "tip_moved", "higher_view"],
)
def test_honest_view_change_updates_are_not_equivocation(node_env: NodeEnv, second: str) -> None:
  block_a, block_b = signed_candidate(node_env, 1), signed_candidate(node_env, 2)

  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      node = c["node2"]
      first = (
        vc_vote(node_env, "node3", 2)
        if second == "lock_gained"
        else (vc_vote(node_env, "node3", 2, block=block_a))
      )
      follow_up = {
        "lock_gained": vc_vote(node_env, "node3", 2, block=block_a),
        "lock_released": vc_vote(node_env, "node3", 2),
        "tip_moved": vc_vote(node_env, "node3", 2, seq=2, block=block_b),
        "higher_view": vc_vote(node_env, "node3", 3, block=block_b),
      }[second]
      feed(node, first)
      await until(lambda: "node3" in node.engine.view_change.latest)
      feed(node, follow_up)
      await drain(node)
      assert events(node) == [] and status(node) == QUORUM_HEALTHY
      assert node.manager.flags.get("node3", 0) == 0

  run(scenario())


# ======================================================== TC-8.5: finalized conflicts


async def _finalize_one(c: Cluster, env: NodeEnv) -> None:
  await c.all_connected()
  await propose(c["node1"], env, 1)
  await until(lambda: all(n.tip == 1 for n in c.nodes.values()), timeout=15)


def _block_message(block: Block) -> dict[str, Any]:
  return {"type": "block", "block": block_to_dict(block)}


def test_second_finalized_block_at_a_height_is_a_byzantine_event(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # TC-8.5 / UC-8-E4
    async with _cluster(node_env, timeout="5") as c:
      await _finalize_one(c, node_env)
      node = c["node2"]
      held = node.context.current_blocks()[1]
      genesis = node.context.current_blocks()[0]
      # a block at the same height signed by the same proposer, with a full commit quorum
      rival = pbft_block(node_env, genesis, 99, signers=3)
      assert rival.proposer_id == held.proposer_id and rival.block_hash != held.block_hash
      await node.receiver.on_message("node1", _block_message(rival))  # as over /ws/blocks
      await until(lambda: events(node), timeout=10)
      assert status(node) == BYZANTINE
      assert "two finalized blocks at height 1" in str(events(node)[0]["reason"])
      both = {s.node_id for s in held.commit_signatures} & {
        s.node_id for s in rival.commit_signatures
      }
      assert both and set(str(events(node)[0]["offender"]).split(",")) == both
      assert node.context.current_blocks()[1].block_hash == held.block_hash  # first-finalized wins
      assert node.tip == 1
      # the same rival again, and the held block again, add nothing
      await node.receiver.on_message("node1", _block_message(rival))
      await node.receiver.on_message("node3", _block_message(held))
      await asyncio.sleep(0.3)
      assert len(events(node)) == 1

  run(scenario())


def test_unfinalized_relayed_candidate_is_not_a_byzantine_event(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # TC-8.5: a relayed candidate proves nothing
    async with _cluster(node_env, timeout="5") as c:
      await _finalize_one(c, node_env)
      node = c["node2"]
      genesis = node.context.current_blocks()[0]
      held = node.context.current_blocks()[1]
      relayed = signed_candidate(node_env, 99, previous=genesis)  # no commit signatures at all
      weak = pbft_block(node_env, genesis, 98, signers=2)  # below the quorum of 3
      for block in (relayed, weak):
        verdict = await node.receiver.handle_block("node1", block_to_dict(block))
        assert (verdict.kind, verdict.reason) == ("reject", "conflict")
      await asyncio.sleep(0.5)  # the judge runs off-loop: give it time to (not) report
      assert events(node) == [] and status(node) == QUORUM_HEALTHY
      assert node.context.current_blocks()[1].block_hash == held.block_hash

  run(scenario())


def test_forged_quorum_block_is_not_a_byzantine_event(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, timeout="5") as c:
      await _finalize_one(c, node_env)
      node = c["node2"]
      genesis = node.context.current_blocks()[0]
      rival = pbft_block(node_env, genesis, 99, signers=3)
      # commits that do not belong to this block: its hash is not what they signed
      stolen = node.context.current_blocks()[1].commit_signatures
      forged = replace(rival, commit_signatures=stolen)
      await node.receiver.handle_block("node1", block_to_dict(forged))
      await asyncio.sleep(0.5)
      assert events(node) == [] and status(node) == QUORUM_HEALTHY

  run(scenario())


def test_pow_same_proposer_conflict_is_not_a_byzantine_event(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # no finalized-conflict judging exists for PoW forks
    async with _cluster(node_env, ("node1", "node2"), mode="pow") as c:
      node = c["node2"]
      genesis = node.context.current_blocks()[0]
      now = max(int(time.time() * 1000), genesis.timestamp)  # PoW blocks must not be old
      first = pow_block(node_env, genesis, 1, timestamp=now)
      assert (await node.receiver.handle_block("node1", block_to_dict(first))).accepted
      verdict = await node.receiver.handle_block(
        "node1", block_to_dict(pow_block(node_env, genesis, 2, timestamp=now))
      )
      assert verdict.reason == "conflict" and verdict.equivocation
      await asyncio.sleep(0.2)
      assert events(node) == []

  run(scenario())


# ----------------------------------------------------------- gateway unit tests


def test_gateway_finalized_conflict_rules(node_env: NodeEnv, boot) -> None:
  blocks = pbft_chain(node_env, 2)
  save_chain(node_env, blocks)
  gateway = boot({**node_env.env, "INIT_CHAIN": "0"}).gateway
  genesis = blocks[0]
  assert gateway.finalized_conflict(blocks[1]) is None  # the block we hold
  rival = pbft_block(node_env, genesis, 77, signers=3)
  assert gateway.finalized_conflict(rival) == frozenset({"node1", "node2", "node3"})
  four = replace(  # a different quorum overlapping ours in two members
    pbft_block(node_env, genesis, 78, signers=3),
  )
  assert gateway.finalized_conflict(four) is not None
  assert gateway.finalized_conflict(pbft_block(node_env, genesis, 79, signers=2)) is None
  assert gateway.finalized_conflict(replace(rival, commit_signatures=())) is None
  assert gateway.finalized_conflict(replace(rival, block_hash="0" * 64)) is None  # hash mismatch
  beyond = pbft_block(node_env, blocks[2], 80)  # index 3: not a conflict, a future block
  assert gateway.finalized_conflict(beyond) is None
  assert gateway.finalized_conflict(genesis) is None  # nothing conflicts at index 0


def test_screen_candidate_allow_old_skips_only_the_lower_time_bound(
  node_env: NodeEnv, boot
) -> None:
  context = boot(node_env.env)
  gateway = context.gateway
  genesis = context.current_blocks()[0]
  old = signed_candidate(node_env, 1, timestamp=1_700_000_001_000, previous=genesis)
  kwargs = {"primary_id": "node1", "view": 0, "known": context.chain_state.has_document}
  assert gateway.screen_candidate(old, **kwargs).reason == "timestamp_too_old"
  assert gateway.screen_candidate(old, **kwargs, allow_old=True).accepted
  future = signed_candidate(node_env, 2, timestamp=2**50, previous=genesis)
  assert gateway.screen_candidate(future, **kwargs, allow_old=True).reason == "timestamp_in_future"
  # allow_old does not relax anything else: wrong primary, wrong view, duplicates
  assert gateway.screen_candidate(old, **{**kwargs, "primary_id": "node2"}, allow_old=True).reason
  assert not gateway.screen_candidate(old, **{**kwargs, "view": 1}, allow_old=True).accepted
  assert (
    gateway.screen_candidate(old, **{**kwargs, "known": lambda _h: True}, allow_old=True).reason
    == "duplicate_document"
  )


# ============================================================ validity cache precedence


def test_validity_cache_liveness_and_byzantine_precedence(node_env: NodeEnv, boot) -> None:
  cache = boot(node_env.env).validity_cache
  assert cache.snapshot.quorum_status == QUORUM_HEALTHY and cache.liveness == QUORUM_HEALTHY
  with pytest.raises(ValueError):
    cache.set_liveness("byzantine_event_detected")  # liveness never carries a safety verdict
  with pytest.raises(ValueError):
    cache.set_liveness("nonsense")
  assert LIVENESS_STATES == {QUORUM_HEALTHY, QUORUM_VIEW_CHANGE, QUORUM_CRASH_LOSS}
  for liveness in (QUORUM_VIEW_CHANGE, QUORUM_CRASH_LOSS, QUORUM_HEALTHY):
    cache.set_liveness(liveness)
    assert cache.snapshot.quorum_status == liveness == cache.liveness
  cache.flag_byzantine_event("two blocks", offender="node3")
  assert cache.snapshot.quorum_status == BYZANTINE
  cache.set_liveness(QUORUM_CRASH_LOSS)  # sticky: a later crash fault does not hide it ...
  assert cache.snapshot.quorum_status == BYZANTINE
  assert cache.liveness == QUORUM_CRASH_LOSS  # ... and is still reported on its own
  assert cache.byzantine_events[0]["offender"] == "node3"
  assert cache.byzantine_events[0]["reason"] == "two blocks"
  assert isinstance(cache.byzantine_events[0]["at_ms"], int)
  cache.byzantine_events.clear()  # a copy: callers cannot erase the log
  assert len(cache.byzantine_events) == 1


def test_byzantine_event_log_is_bounded_per_offender(node_env: NodeEnv, boot) -> None:
  cache = boot(node_env.env).validity_cache
  for i in range(MAX_BYZANTINE_EVENTS + 8):
    cache.flag_byzantine_event(f"event {i}", offender="node3")
  reasons = [e["reason"] for e in cache.byzantine_events]
  assert len(reasons) == MAX_EVENTS_PER_OFFENDER
  last = MAX_BYZANTINE_EVENTS + 7
  # the first event is kept for good; newer ones replace the oldest non-first ones
  assert reasons == ["event 0", f"event {last - 2}", f"event {last - 1}", f"event {last}"]


def test_one_offender_flooding_fresh_slots_cannot_evict_other_evidence(
  node_env: NodeEnv, boot
) -> None:
  # N6: a Byzantine member signing conflicts in fresh (view, seq) slots makes a distinct event
  # each time; the evidence against other offenders must survive it
  cache = boot(node_env.env).validity_cache
  cache.flag_byzantine_event("node4 equivocated at (0, 1)", offender="node4", at_ms=1)
  cache.flag_byzantine_event("peer diverged at height 2", offender=None, at_ms=2)
  for seq in range(200):
    cache.flag_byzantine_event(f"node3 equivocated at (0, {seq})", offender="node3", at_ms=10 + seq)
  events = cache.byzantine_events
  assert events[0] == {"reason": "node4 equivocated at (0, 1)", "offender": "node4", "at_ms": 1}
  assert events[1] == {"reason": "peer diverged at height 2", "offender": None, "at_ms": 2}
  node3 = [e["reason"] for e in events if e["offender"] == "node3"]
  assert node3 == [
    "node3 equivocated at (0, 0)",  # its first event, kept
    "node3 equivocated at (0, 197)",
    "node3 equivocated at (0, 198)",
    "node3 equivocated at (0, 199)",
  ]
  assert [e["at_ms"] for e in events] == sorted(e["at_ms"] for e in events)  # chronological


def test_byzantine_event_log_is_bounded_overall(node_env: NodeEnv, boot) -> None:
  cache = boot(node_env.env).validity_cache
  for who in range(MAX_OFFENDERS + 5):
    for i in range(MAX_EVENTS_PER_OFFENDER + 2):
      cache.flag_byzantine_event(f"e{i}", offender=f"o{who}", at_ms=i)
  events = cache.byzantine_events
  assert len(events) == MAX_BYZANTINE_EVENTS == MAX_OFFENDERS * MAX_EVENTS_PER_OFFENDER
  assert len({e["offender"] for e in events}) == MAX_OFFENDERS
  assert all(e["offender"] != f"o{MAX_OFFENDERS}" for e in events)  # beyond the cap: not logged
  assert cache.snapshot.quorum_status == BYZANTINE  # ... yet still sticky Byzantine
  for who in range(MAX_OFFENDERS):  # every logged offender keeps its first event
    assert {"reason": "e0", "offender": f"o{who}", "at_ms": 0} in events


# ================================================ TC-6.11 / TC-6.5: crash faults


def test_two_of_four_down_is_crash_fault_quorum_loss_not_byzantine(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # TC-6.11 / UC-6-E5
    async with _cluster(node_env, timeout="0.3") as c:
      await c.all_connected()
      await c.network.sever(c["node3"].address)
      await c.network.sever(c["node4"].address)
      await propose(c["node1"], node_env, 1)
      live = [c["node1"], c["node2"]]
      await until(lambda: all(status(n) == QUORUM_CRASH_LOSS for n in live), timeout=10)
      for node in live:
        assert node.context.validity_cache.liveness == QUORUM_CRASH_LOSS
        assert node.engine.liveness == QUORUM_CRASH_LOSS
        assert events(node) == []  # nothing was lied about
        assert node.engine.primary_status() == ("none", None)
      await asyncio.sleep(1.5)  # long enough for the round to time out and votes to be re-sent
      for node in c.nodes.values():
        assert node.tip == 0  # no wrong (or any) block was finalized
      for node in live:
        assert status(node) == QUORUM_CRASH_LOSS  # still crash-fault; a view change, if open,
        assert status(node) != BYZANTINE and events(node) == []  # does not relabel it
        info = await node_info(node)
        assert info["quorum_status"] == QUORUM_CRASH_LOSS == info["liveness"]
        assert info["byzantine_events"] == [] and info["tip_index"] == 0
      # recovery: one member returns -> the quorum is possible again, status clears
      c.network.heal(c["node3"].address)
      await until(lambda: all(status(n) == QUORUM_HEALTHY for n in live), timeout=15)
      assert all(events(n) == [] for n in live)

  run(scenario())


def test_one_member_down_is_normal_operation(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # TC-6.5 regression
    async with _cluster(node_env, timeout="0.3") as c:
      await c.all_connected()
      await c.network.sever(c["node4"].address)
      await propose(c["node1"], node_env, 1)
      live = [c["node1"], c["node2"], c["node3"]]
      await until(lambda: all(n.tip == 1 for n in live), timeout=15)
      await asyncio.sleep(0.8)  # past the round timeout: nothing may start a view change
      for node in live:
        assert status(node) == QUORUM_HEALTHY
        assert node.context.validity_cache.liveness == QUORUM_HEALTHY
        assert events(node) == [] and node.engine.view == 0
        assert node.engine.primary_status() == (
          ("self", "node1") if node.node_id == "node1" else ("other", "node1")
        )
        info = await node_info(node)
        assert info["quorum_status"] == QUORUM_HEALTHY and info["byzantine_events"] == []
      assert c["node4"].tip == 0

  run(scenario())


# ===================================================== TC-12.5: /node/info mid-view-change


def test_node_info_reports_the_open_view_change_and_keeps_liveness_separate(
  node_env: NodeEnv,
) -> None:
  block_a, block_b = signed_candidate(node_env, 1), signed_candidate(node_env, 2)

  async def scenario() -> None:  # TC-12.5 / UC-12-EC1
    async with _cluster(node_env, timeout="0.3") as c:
      await c.all_connected()
      node = c["node2"]
      drop_messages(node, {PREPARE})  # only node2 ever opens the round: nobody else follows
      feed(node, vote(node_env, PRE_PREPARE, "node1", block_a))
      await until(lambda: node.engine.view_change.in_progress, timeout=10)
      await until(lambda: status(node) == QUORUM_VIEW_CHANGE, timeout=5)
      info = await node_info(node)
      assert info["quorum_status"] == QUORUM_VIEW_CHANGE == info["liveness"]
      assert info["byzantine_events"] == [] and info["chain_valid"] is True
      assert node.engine.primary_status() == ("none", None)
      assert all(n.engine.view == 0 for n in c.nodes.values())  # a lone vote moves nobody
      # a Byzantine observation outranks it in `quorum_status` but liveness is still shown
      current = node.engine.round(1)
      feed(
        node,
        vote(node_env, PREPARE, "node3", block_a),
        vote(node_env, PREPARE, "node3", block_a, block_hash=block_b.block_hash),
      )
      await until(lambda: current.conflicts, timeout=5)
      info = await node_info(node)
      assert info["quorum_status"] == BYZANTINE
      assert info["liveness"] == QUORUM_VIEW_CHANGE
      assert [e["offender"] for e in info["byzantine_events"]] == ["node3"]
      assert set(info["byzantine_events"][0]) == {"reason", "offender", "at_ms"}
      # the change completes (node3 and node4 vote for view 1): liveness clears, the
      # safety verdict stays until restart
      feed(node, vc_vote(node_env, "node3", 1), vc_vote(node_env, "node4", 1))
      await until(lambda: node.engine.view == 1, timeout=5)
      await until(lambda: node.context.validity_cache.liveness == QUORUM_HEALTHY, timeout=5)
      info = await node_info(node)
      assert info["quorum_status"] == BYZANTINE and info["liveness"] == QUORUM_HEALTHY

  run(scenario())


def test_node_info_during_a_real_view_change_with_a_crashed_primary(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # the open change is visible, then clears once installed
    async with _cluster(node_env, timeout="0.3") as c:
      await c.all_connected()
      # liveness is refreshed on the engine's tick: wait for the post-connect "healthy" first
      await until(lambda: all(status(n) == QUORUM_HEALTHY for n in c.nodes.values()), timeout=5)
      seen: set[str] = set()
      await c.network.sever(c["node1"].address)

      def poll() -> bool:
        seen.add(status(c["node2"]))
        return c["node2"].engine.view == 1 and c["node2"].engine.liveness == QUORUM_HEALTHY

      await until(poll, timeout=10)
      assert seen <= {QUORUM_HEALTHY, QUORUM_VIEW_CHANGE}  # never crash-fault, never Byzantine
      info = await node_info(c["node2"])
      assert info["quorum_status"] == QUORUM_HEALTHY and info["liveness"] == QUORUM_HEALTHY
      assert info["byzantine_events"] == []

  run(scenario())
