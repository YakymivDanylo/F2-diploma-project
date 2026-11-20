"""Slice 16b security-review hardening: concurrent rounds, validator-only startup, rollback
guard, PBFT forgery, PoW pre-check, duplicate documents, response limits, hash parsing."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from chain_factory import pbft_block, pow_block, pow_chain
from network_helpers import Cluster, fast_sleep
from node_helpers import NodeEnv
from sync_helpers import (
  HangingFetcher,
  ListFetcher,
  RoutedFetcher,
  blocks_of,
  extend,
  force_install,
  install,
  make_sync,
  peer_of,
  run,
  slow_sync_env,
  sync_of,
)

from blockchain_core import Block, JsonChainStore, build_genesis_block, pow_target
from node.sync import (
  MAX_SYNC_BLOCKS,
  HttpChainFetcher,
  PeerAddress,
  SyncResponseError,
  pbft_prefers,
  pow_prefers,
)
from node.validity_cache import QUORUM_HEALTHY

GENESIS = build_genesis_block()


def _peer(node_id: str, port: int = 9000) -> PeerAddress:
  return PeerAddress(node_id, node_id, port)


def _pair(node_env: NodeEnv, **kwargs: Any) -> Cluster:
  slow_sync_env(node_env)
  return Cluster(node_env, ids=("node1", "node2"), mine=False, register_peers=False, **kwargs)


# ---------------------------------------------------------- 1. concurrent rounds


def test_round_queries_peers_concurrently_within_the_budget(node_env: NodeEnv) -> None:
  # a hanging peer listed FIRST must not delay the good one or the round beyond the budget
  chain = pow_chain(node_env, 3)

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1 = cluster["node1"]
      routes = {"hang": HangingFetcher(), "good": ListFetcher(chain)}
      sync, _ = make_sync(
        n1, RoutedFetcher(routes), peers=[_peer("hang"), _peer("good")], peer_timeout_s=30
      )
      started = time.monotonic()
      outcomes = await sync.sync_round(budget_s=0.4)
      assert time.monotonic() - started < 2.0  # bounded by the budget, not peer_timeout_s
      assert outcomes == {"hang": "unreachable", "good": "adopted"}
      assert blocks_of(n1) == tuple(chain)

  run(go())


def test_a_round_adopts_the_best_chain_whatever_the_completion_order(node_env: NodeEnv) -> None:
  short = pow_chain(node_env, 2)
  long_fork = extend(node_env, [GENESIS], [31, 32, 33, 34])

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1 = cluster["node1"]
      for order in (("short", "long"), ("long", "short")):
        await install(n1, [GENESIS])
        routes = {"short": ListFetcher(short), "long": ListFetcher(long_fork)}
        sync, _ = make_sync(n1, RoutedFetcher(routes), peers=[_peer(o) for o in order])
        await sync.sync_round()
        # both peers extend the same base: the loser of the race is refused by `prefer`
        # (stale extension) and the next round settles it - the order never matters
        await sync.sync_round()
        assert blocks_of(n1) == tuple(long_fork)

  run(go())


def test_hanging_peer_cannot_eat_the_startup_window(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  chain = pow_chain(node_env, 3)

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1 = cluster["node1"]
      routes = {"hang": HangingFetcher(), "good": ListFetcher(chain)}
      sync, _ = make_sync(
        n1,
        RoutedFetcher(routes),
        peers=[_peer("hang"), _peer("good")],
        peer_timeout_s=30,
        sleep=fast_sleep,
      )
      with caplog.at_level(logging.WARNING, logger="node.sync"):
        assert await sync.startup(1.0) is True
      assert "STARTUP_SYNC_TIMEOUT_S" not in caplog.text
      assert blocks_of(n1) == tuple(chain)

  run(go())


# ------------------------------------------------------ 2. validators end startup


def test_only_a_validator_confirmation_ends_the_startup_wait(node_env: NodeEnv) -> None:
  chain = pow_chain(node_env, 3)

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1 = cluster["node1"]
      fetcher = ListFetcher(chain)
      validators = {"vnode"}
      sync, _ = make_sync(
        n1,
        RoutedFetcher({"plain": fetcher, "vnode": fetcher}),
        peers=[_peer("plain")],
        sleep=fast_sleep,
        is_validator=validators.__contains__,
      )
      assert await sync.startup(0.3) is False  # a PeerInfo-only peer answered: not enough
      assert blocks_of(n1) == tuple(chain)  # ... but its valid chain is still adopted
      assert await sync.startup(0.3) is False  # now "not_better" from a non-validator

      sync, _ = make_sync(
        n1,
        RoutedFetcher({"plain": fetcher, "vnode": fetcher}),
        peers=[_peer("plain"), _peer("vnode")],
        sleep=fast_sleep,
        is_validator=validators.__contains__,
      )
      assert await sync.startup(0.3) is True  # a ValidatorSet member confirmed

  run(go())


# ------------------------------------------------------------ 3. rollback guard


def _tampered_node_cluster(node_env: NodeEnv, chain: list[Block], index: int) -> Cluster:
  """A cluster whose node1 boots from a persisted chain tampered at `index`."""
  cluster = _pair(node_env)
  path = cluster.chain_file("node1")
  store = JsonChainStore(path)
  try:
    store.save(chain)
  finally:
    store.close()
  document = json.loads(path.read_bytes())
  document["blocks"][index]["document_records"][0]["metadata"]["seed"] = 999
  path.write_bytes(json.dumps(document).encode())
  return cluster


def test_self_heal_never_rolls_back_to_a_shorter_chain(node_env: NodeEnv) -> None:
  # UC-3-G: trusted prefix = blocks 0..3 (tamper at 4); a peer with less is not adopted
  chain = pow_chain(node_env, 5)

  async def go() -> None:
    cluster = _tampered_node_cluster(node_env, chain, 4)
    async with cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      state = n1.context.chain_state
      assert not state.extendable and len(state.trusted_blocks) == 4
      local = blocks_of(n1)
      for peer_chain in (chain[:1], chain[:3], chain[:4]):  # genesis, shorter, equal prefix
        await install(n2, peer_chain)
        assert await sync_of(n1).sync_with(peer_of(n2)) == "not_better"
        assert blocks_of(n1) == local and not state.extendable
      await install(n2, chain)  # strictly longer than the valid prefix
      assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"
      assert blocks_of(n1) == tuple(chain) and state.extendable

  run(go())


# ------------------------------------------------- 4. PBFT forged first-page block


@pytest.mark.parametrize("forgery", ["bad-hash", "no-quorum", "unsigned"])
def test_pbft_forged_divergent_block_raises_no_byzantine_alarm(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture, forgery: str
) -> None:
  # the peer's divergent block must pass the full single-block checklist (commit quorum
  # included) against OUR parent before two blocks at one height count as a safety violation
  slow_sync_env(node_env)
  mine = [GENESIS]
  for seed in (1, 2):
    mine.append(pbft_block(node_env, mine[-1], seed))
  rival = pbft_block(node_env, mine[1], 99)
  forged_tip = {
    "bad-hash": dataclasses.replace(mine[2], block_hash="ab" * 32),
    "no-quorum": dataclasses.replace(rival, commit_signatures=()),
    "unsigned": dataclasses.replace(rival, proposer_signature=""),
  }[forgery]
  forged = [*mine[:2], forged_tip]

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1",), mode="pbft", mine=False, register_peers=False
    ) as cluster:
      n1 = cluster["node1"]
      await install(n1, mine)
      sync, flags = make_sync(n1, ListFetcher(forged))
      with caplog.at_level(logging.ERROR):
        outcome = await sync.sync_with(_peer("node2"))
      assert outcome == "invalid"
      assert "SAFETY VIOLATION" not in caplog.text
      assert n1.context.validity_cache.snapshot.quorum_status == QUORUM_HEALTHY
      assert blocks_of(n1) == tuple(mine)
      assert len(flags) == 1 and flags[0][0] == "node2"

  run(go())


# ------------------------------------------------------- 5. PoW fork pre-check


def test_fork_without_proof_of_work_is_refused_before_the_full_download(
  node_env: NodeEnv,
) -> None:
  local = extend(node_env, [GENESIS], [1, 2, 3])
  fork = extend(node_env, [GENESIS], [11, 12, 13, 14, 15])
  fake = [*fork[:2]] + [dataclasses.replace(b, timestamp=b.timestamp + 1) for b in fork[2:]]

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1 = cluster["node1"]
      assert sync_of(n1)._target == pow_target(1)  # main.py passes the difficulty through
      await install(n1, local)
      fetcher = ListFetcher(fake)
      sync, flags = make_sync(n1, fetcher, expected_difficulty=1)

      assert await sync.sync_with(_peer("node2")) == "invalid"

      assert flags == [("node2", "invalid chain: fork without proof of work")]
      assert all(request[2] >= 3 for request in fetcher.requests)  # never from index 0
      assert blocks_of(n1) == tuple(local)

      genuine = ListFetcher(fork)  # control: the same fork with real work is adopted
      sync, flags = make_sync(n1, genuine, expected_difficulty=1)
      assert await sync.sync_with(_peer("node2")) == "adopted" and flags == []

  run(go())


# ---------------------------------------------------- 6. document_hash uniqueness


def test_synced_chain_reissuing_a_finalized_hash_is_invalid(node_env: NodeEnv) -> None:
  chain = pow_chain(node_env, 3)  # records seeds 1..3
  again = pow_block(node_env, chain[-1], 1)  # re-issues seed 1's document_hash

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      # incremental path: the duplicate sits in the new blocks, the original in our chain
      await install(n1, chain)
      await force_install(n2, [*chain, again])
      flags = []
      sync, flags = make_sync(n1, cluster.chain_fetcher)
      assert await sync.sync_with(peer_of(n2)) == "invalid"
      assert flags == [("node2", "invalid chain: duplicate_document")]
      assert blocks_of(n1) == tuple(chain)

      # full path: a fork whose own blocks repeat a hash
      fork = extend(node_env, [GENESIS], [21, 22])
      fork.append(pow_block(node_env, fork[-1], 21))
      fork.append(pow_block(node_env, fork[-1], 24))
      await force_install(n2, fork)
      sync, flags = make_sync(n1, cluster.chain_fetcher)
      assert await sync.sync_with(peer_of(n2)) == "invalid"
      assert flags == [("node2", "invalid chain: duplicate_document")]
      assert blocks_of(n1) == tuple(chain)

      # ChainValidator.full enforces it too, and ChainState.append refuses it
      verdict = n1.context.validator.full([*chain, again])
      assert not verdict.valid and verdict.failure_type == "duplicate_document"
      assert verdict.first_invalid_index == 4
      assert await n1.context.chain_state.append(again) is False
      assert blocks_of(n1) == tuple(chain)

  run(go())


# ------------------------------------------------------ 7. response limits


def _longer_page(page: dict) -> Any:
  return {**page, "blocks": [*page["blocks"], page["blocks"][-1]]}


def _huge_tip(page: dict) -> Any:
  return {**page, "tip_index": MAX_SYNC_BLOCKS + 5}


@pytest.mark.parametrize("mutate", [_longer_page, _huge_tip], ids=["too-long", "huge-tip"])
def test_oversized_page_or_advertised_chain_is_malformed(node_env: NodeEnv, mutate) -> None:
  chain = pow_chain(node_env, 5)

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, chain[:3])
      fetcher = ListFetcher(chain)
      fetcher.mutate = mutate
      sync, flags = make_sync(n1, fetcher, page_size=2)
      assert await sync.sync_with(_peer("node2")) == "malformed"
      assert blocks_of(n1) == tuple(chain[:3]) and len(flags) == 1

  run(go())


class _H(BaseHTTPRequestHandler):
  hits: list[str] = []
  mode = "redirect"

  def do_GET(self) -> None:  # noqa: N802 - http.server API
    self.hits.append(self.path.split("?")[0])
    try:
      if self.mode == "redirect" and self.path.startswith("/chain"):
        self.send_response(302)
        self.send_header("Location", "/elsewhere")
        self.send_header("Content-Length", "0")
        self.end_headers()
      elif self.mode == "big":
        body = b" " * 5000
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
      elif self.mode == "drip":
        self.send_response(200)
        self.send_header("Content-Length", "100")
        self.end_headers()
        for _ in range(100):
          self.wfile.write(b" ")
          self.wfile.flush()
          time.sleep(0.1)
      else:
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")
    except OSError:
      pass  # the client gave up

  def log_message(self, *args: Any) -> None:
    pass


def _http(mode: str) -> tuple[ThreadingHTTPServer, int, list[str]]:
  hits: list[str] = []
  handler = type("H", (_H,), {"mode": mode, "hits": hits})
  server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
  threading.Thread(target=server.serve_forever, daemon=True).start()
  return server, server.server_address[1], hits


def test_http_fetcher_does_not_follow_redirects() -> None:
  server, port, hits = _http("redirect")
  try:
    with pytest.raises(OSError):  # urllib.error.HTTPError(302)
      asyncio.run(
        HttpChainFetcher(timeout=2, allow_loopback=True).get_chain_page("127.0.0.1", port, 0, 1)
      )
    assert hits == ["/chain"]  # /elsewhere was never requested
  finally:
    server.shutdown()
    server.server_close()


def test_http_fetcher_caps_the_response_size() -> None:
  server, port, _ = _http("big")
  try:
    with pytest.raises(SyncResponseError):
      asyncio.run(
        HttpChainFetcher(timeout=2, max_bytes=1000, allow_loopback=True).get_chain_page(
          "127.0.0.1", port, 0, 1
        )
      )
  finally:
    server.shutdown()
    server.server_close()


def test_http_fetcher_enforces_a_whole_request_deadline() -> None:
  # a slow drip never trips the per-read socket timeout, only the total deadline
  server, port, _ = _http("drip")
  try:
    started = time.monotonic()
    with pytest.raises(TimeoutError):
      asyncio.run(
        HttpChainFetcher(timeout=0.5, allow_loopback=True).get_chain_page("127.0.0.1", port, 0, 1)
      )
    assert time.monotonic() - started < 3.0
  finally:
    server.shutdown()
    server.server_close()


# ------------------------------------------------------------- 8. hash parsing


def test_a_non_hex_tip_hash_is_never_preferred() -> None:
  good = [GENESIS, dataclasses.replace(GENESIS, block_hash="7" * 64)]
  for junk in ("not-hex", "", "zz" * 32):
    bad = [GENESIS, dataclasses.replace(GENESIS, block_hash=junk)]
    assert pow_prefers(good, bad) is False
    assert pow_prefers(bad, good) is True  # and a junk local tip loses to a real one
  assert pow_prefers(good, []) is False
  assert pbft_prefers(good, []) is False
