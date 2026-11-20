"""Slice 16b: chain sync - extension / common-ancestor paths, one validator, failure handling.

Multi-node cases run in one event loop on the in-memory `Cluster` (mine=False, no peers
registered: the tests drive `ChainSync.sync_with` themselves).
"""

from __future__ import annotations

import asyncio
import dataclasses
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from chain_factory import pbft_chain, pow_block, pow_chain
from network_helpers import Cluster
from node_helpers import NodeEnv
from sync_helpers import (
  ListFetcher,
  ValidatorSpy,
  blocks_of,
  extend,
  force_install,
  install,
  make_sync,
  peer_of,
  record_flags,
  run,
  slow_sync_env,
  sync_of,
)

from blockchain_core import build_genesis_block
from node.api.chain import chain_page
from node.sync import HttpChainFetcher, PeerAddress, SyncResponseError
from node.validity_cache import QUORUM_INVALID, ValidityCache


def _pair(node_env: NodeEnv, **kwargs: Any) -> Cluster:
  slow_sync_env(node_env)
  return Cluster(node_env, ids=("node1", "node2"), mine=False, register_peers=False, **kwargs)


# --------------------------------------------------------------- incremental vs full


@pytest.mark.parametrize("ahead", [1, 3])
def test_strict_extension_is_validated_incrementally(node_env: NodeEnv, ahead: int) -> None:
  # CN-TC-3.1 / CN-TC-3.4: only the blocks after the local tip are fetched and validated
  slow_sync_env(node_env, MAX_PAGE_SIZE="2")
  chain = pow_chain(node_env, 2 + ahead)

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, chain[:3])
      await install(n2, chain)
      spy = ValidatorSpy(n1.context.validator)
      before = len(cluster.chain_fetcher.requests)

      assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"

      assert spy.full_calls == []  # never the full-from-genesis path
      *prechecks, (trusted, new_blocks) = spy.extension_calls
      assert trusted.index == 2
      assert [b.index for b in new_blocks] == list(range(3, 3 + ahead))
      # past the first page, the first new block is pre-checked before the rest is downloaded
      expected = [] if ahead == 1 else [(chain[2].block_hash, [chain[3].block_hash])]
      assert [(t.block_hash, [b.block_hash for b in bs]) for t, bs in prechecks] == expected
      requested = cluster.chain_fetcher.requests[before:]
      assert requested[0][1] == 2  # the first request starts at the local tip index
      assert all(from_index >= 2 for _, from_index, _ in requested)  # nothing below the tip
      assert blocks_of(n1) == tuple(chain)
      assert cluster.stored_blocks("node1") == chain  # persisted
      snapshot = n1.context.validity_cache.snapshot
      assert snapshot.chain_valid and snapshot.tip_index == len(chain) - 1

  run(go())


def test_divergent_longer_chain_is_validated_from_the_common_ancestor(node_env: NodeEnv) -> None:
  # CN-TC-3.2 (M-14 as amended 2026-11-20): a fork below the local tip is validated from the
  # last block both chains share - OUR trusted block, never an untrusted base - and the whole
  # divergent suffix is validated; nothing is fetched from genesis
  genesis = build_genesis_block()
  local = extend(node_env, [genesis], [1, 2])
  theirs = extend(node_env, [genesis], [11, 12, 13, 14])

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, local)
      await install(n2, theirs)
      spy = ValidatorSpy(n1.context.validator)
      before = len(cluster.chain_fetcher.requests)

      assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"

      assert spy.full_calls == []
      ((trusted, suffix),) = spy.extension_calls  # once, over the WHOLE divergent suffix
      assert trusted.block_hash == genesis.block_hash  # the common ancestor, our own block
      assert [b.block_hash for b in suffix] == [b.block_hash for b in theirs[1:]]
      starts = [from_index for _, from_index, _ in cluster.chain_fetcher.requests[before:]]
      assert starts == [2, 1]  # the probe at our tip, then the page down to the fork point
      assert blocks_of(n1) == tuple(theirs)
      assert cluster.stored_blocks("node1") == theirs
      assert n1.context.validity_cache.snapshot.tip_index == 4
      # dropped local records are not lost: they go back to the mempool (UC-3-EC2 / UC-17)
      dropped = {r.document_hash for b in local[1:] for r in b.document_records}
      assert dropped and all(n1.context.mempool.contains(h) for h in dropped)
      assert n1.context.documents.contains(theirs[1].document_records[0].document_hash)

  run(go())


def test_local_invalid_chain_is_healed_from_its_trusted_prefix(node_env: NodeEnv) -> None:
  # CN-TC-3.2 (A): an untrusted local block is never the base of an incremental check - the
  # base is the tip of the valid prefix, and everything after it is validated
  chain = pow_chain(node_env, 4)

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      bad = list(chain[:3])
      bad[2] = dataclasses.replace(bad[2], timestamp=bad[2].timestamp + 1)
      await force_install(n1, bad)  # extendable, as far as the state knows ...
      n1.context.chain_state._extendable = False  # ... so mark it invalid like a failed boot
      n1.context.validity_cache.initialize(bad)  # first_invalid_index = 2
      assert len(n1.context.chain_state.trusted_blocks) == 2
      await install(n2, chain)
      spy = ValidatorSpy(n1.context.validator)

      assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"

      assert spy.full_calls == []
      ((trusted, suffix),) = spy.extension_calls
      assert trusted.block_hash == chain[1].block_hash  # the trusted tip, not the bad block
      assert [b.index for b in suffix] == [2, 3, 4]
      assert blocks_of(n1) == tuple(chain) and n1.context.chain_state.extendable

  run(go())


# ------------------------------------------------------------ one validator, quorum


@pytest.mark.parametrize("mode", ["pow", "pbft"])
def test_sync_uses_the_same_validator_as_gateway_and_cache(node_env: NodeEnv, mode: str) -> None:
  # CN-TC-3.3 / CN-TC-12.8: one ChainValidator object, no second checklist
  slow_sync_env(node_env)

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1",), mode=mode, mine=False, register_peers=False
    ) as cluster:
      context = cluster["node1"].context
      assert sync_of(cluster["node1"])._validator is context.validator
      assert context.gateway.validator is context.validator
      assert context.validity_cache._validator is context.validator

  run(go())


def test_pbft_chain_without_commit_quorum_is_rejected_by_sync_and_by_the_cache(
  node_env: NodeEnv,
) -> None:
  # CN-TC-3.3 / CN-TC-12.8: the sync verdict equals the cache verdict for the same chain
  slow_sync_env(node_env)
  bad = pbft_chain(node_env, 3, signers=1)  # n=4, f=1: one commit signature is not a quorum

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mode="pbft", mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await force_install(n2, bad)
      flags = record_flags(sync_of(n1))
      spy = ValidatorSpy(n1.context.validator)
      before = blocks_of(n1)

      assert await sync_of(n1).sync_with(peer_of(n2)) == "invalid"

      sync_verdict = spy.results[-1]
      assert not sync_verdict.valid and sync_verdict.failure_type == "quorum"
      assert flags == [("node2", "invalid chain: quorum")]
      assert blocks_of(n1) == before  # nothing adopted

      cache = ValidityCache(n1.context.validator)  # the same chain read by the cache
      cache.initialize(bad)
      snapshot = cache.snapshot
      assert snapshot.chain_valid is False and snapshot.failure_type == "quorum"
      assert snapshot.quorum_status == QUORUM_INVALID
      assert snapshot.first_invalid_index == sync_verdict.first_invalid_index

  run(go())


def test_pbft_chain_with_quorum_is_adopted_by_sync(node_env: NodeEnv) -> None:  # CN-TC-3.3 control
  slow_sync_env(node_env)
  good = pbft_chain(node_env, 3)

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mode="pbft", mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n2, good)
      assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"
      assert blocks_of(n1) == tuple(good)
      assert n1.context.validity_cache.snapshot.quorum_status == "healthy"

  run(go())


# --------------------------------------------------------------- invalid peer chain


@pytest.mark.parametrize("path", ["extension", "full"])
def test_invalid_peer_chain_is_rejected_wholesale_and_peer_flagged(
  node_env: NodeEnv, path: str
) -> None:
  # CN-TC-3.7
  chain = pow_chain(node_env, 5)
  tampered = list(chain)
  tampered[4] = dataclasses.replace(chain[4], timestamp=chain[4].timestamp + 1)  # hash breaks
  if path == "extension":
    local = chain[:3]
  else:
    local = extend(node_env, [chain[0]], [41, 42])  # a divergent fork

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, local)
      await force_install(n2, tampered)
      before_blocks = blocks_of(n1)
      before_file = cluster.chain_file("node1").read_bytes()

      assert await sync_of(n1).sync_with(peer_of(n2)) == "invalid"

      assert blocks_of(n1) == before_blocks  # byte-identical in memory ...
      assert cluster.chain_file("node1").read_bytes() == before_file  # ... and on disk
      assert n1.context.validity_cache.snapshot.tip_index == len(local) - 1
      assert n1.manager.flags.get("node2", 0) >= 1  # the real flag sink

  run(go())


# ------------------------------------------------------------------- unreachable


class _RaisingFetcher:
  def __init__(self, exc: BaseException) -> None:
    self._exc = exc

  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    raise self._exc


class _HangingFetcher:
  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    await asyncio.sleep(3600)


_NOWHERE = PeerAddress("node2", "node2", 9002)


@pytest.mark.parametrize(
  "exc",
  [ConnectionRefusedError("refused"), TimeoutError("timed out"), OSError("network unreachable")],
  ids=["refused", "timeout", "oserror"],
)
def test_unreachable_peer_leaves_the_local_chain_untouched(
  node_env: NodeEnv, exc: BaseException
) -> None:
  # CN-TC-3.8 (UC-3-E2)
  chain = pow_chain(node_env, 3)

  async def go() -> None:
    async with Cluster(node_env, ids=("node1",), mine=False, register_peers=False) as cluster:
      n1 = cluster["node1"]
      await install(n1, chain)
      sync, flags = make_sync(n1, _RaisingFetcher(exc))
      assert await sync.sync_with(_NOWHERE) == "unreachable"
      assert blocks_of(n1) == tuple(chain) and flags == []  # unreachable is not misbehaviour

  run(go())


def test_hanging_peer_is_given_up_on_without_hanging_the_node(node_env: NodeEnv) -> None:
  # CN-TC-3.8: a peer that accepts and never answers
  async def go() -> None:
    async with Cluster(node_env, ids=("node1",), mine=False, register_peers=False) as cluster:
      n1 = cluster["node1"]
      sync, _ = make_sync(n1, _HangingFetcher(), peer_timeout_s=0.2, peers=[_NOWHERE])
      started = time.monotonic()
      outcomes = await asyncio.wait_for(sync.sync_round(), timeout=5)
      assert outcomes == {"node2": "unreachable"}
      assert time.monotonic() - started < 2.0
      assert len(blocks_of(n1)) == 1

  run(go())


def test_round_skips_a_downed_peer_and_adopts_from_the_next(node_env: NodeEnv) -> None:
  # CN-TC-3.8: one dead peer does not stop the round
  chain = pow_chain(node_env, 3)
  slow_sync_env(node_env)

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2", "node3"), mine=False, register_peers=False
    ) as cluster:
      n1, n2, n3 = cluster["node1"], cluster["node2"], cluster["node3"]
      await install(n3, chain)
      await cluster.network.sever(n2.address)
      sync, _ = make_sync(
        n1, cluster.chain_fetcher, peers=[peer_of(n2), peer_of(n3)], peer_timeout_s=2
      )
      assert await sync.sync_round() == {"node2": "unreachable", "node3": "adopted"}
      assert blocks_of(n1) == tuple(chain)

  run(go())


# --------------------------------------------------------------------- malformed


def _no_fields(page: dict) -> Any:
  return {"from_index": 2}


def _not_a_page(page: dict) -> Any:
  return "garbage"


def _null(page: dict) -> Any:
  return None


def _wrong_from(page: dict) -> Any:
  return {**page, "from_index": page["from_index"] + 5}


def _index_mismatch(page: dict) -> Any:
  page["blocks"][0] = {**page["blocks"][0], "index": 99}
  return page


def _undecodable(page: dict) -> Any:
  return {**page, "blocks": [{"nonsense": 1}]}


def _empty_below_tip(page: dict) -> Any:
  return {**page, "blocks": []}


def _not_json(page: dict) -> Any:
  raise SyncResponseError("response is not valid JSON")


def _truncated_later(page: dict) -> Any:
  return {**page, "blocks": []} if page["from_index"] >= 4 else page  # cut off mid-transfer


@pytest.mark.parametrize(
  "mutate",
  [
    _no_fields,
    _not_a_page,
    _null,
    _wrong_from,
    _index_mismatch,
    _undecodable,
    _empty_below_tip,
    _not_json,
    _truncated_later,
  ],
  ids=lambda f: f.__name__.strip("_"),
)
def test_malformed_response_is_reported_not_crashed_on(node_env: NodeEnv, mutate) -> None:
  # CN-TC-3.9 (UC-3-E3)
  chain = pow_chain(node_env, 5)

  async def go() -> None:
    async with Cluster(node_env, ids=("node1",), mine=False, register_peers=False) as cluster:
      n1 = cluster["node1"]
      await install(n1, chain[:3])
      fetcher = ListFetcher(chain)
      fetcher.mutate = mutate
      sync, flags = make_sync(n1, fetcher, page_size=2)

      assert await sync.sync_with(_NOWHERE) == "malformed"

      assert blocks_of(n1) == tuple(chain[:3])
      assert flags == [("node2", "malformed chain response")]

  run(go())


class _Handler(BaseHTTPRequestHandler):
  body: bytes = b""
  blocks: list = []

  def do_GET(self) -> None:  # noqa: N802 - http.server API
    query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
    if self.body:
      payload = self.body
    else:
      start, end = int(query["from"][0]), int(query["to"][0])
      payload = chain_page(self.blocks, start, end, 100).model_dump_json().encode()
    self.send_response(200)
    self.send_header("Content-Length", str(len(payload)))
    self.end_headers()
    self.wfile.write(payload)

  def log_message(self, *args: Any) -> None:
    pass


def _serve(handler: type[_Handler]) -> tuple[ThreadingHTTPServer, int]:
  server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
  threading.Thread(target=server.serve_forever, daemon=True).start()
  return server, server.server_address[1]


def test_http_fetcher_non_json_and_truncated_bodies_are_malformed(node_env: NodeEnv) -> None:
  # CN-TC-3.9: the production fetcher turns bad bytes into SyncResponseError -> "malformed"
  chain = pow_chain(node_env, 3)
  full_page = chain_page(chain, 0, 3, 100).model_dump_json().encode()

  async def go() -> None:
    async with Cluster(node_env, ids=("node1",), mine=False, register_peers=False) as cluster:
      n1 = cluster["node1"]
      for body in (b"<html>502 Bad Gateway</html>", full_page[: len(full_page) // 2], b"\xff\xfe"):
        handler = type("H", (_Handler,), {"body": body})
        server, port = _serve(handler)
        try:
          with pytest.raises(SyncResponseError):
            await HttpChainFetcher(timeout=2, allow_loopback=True).get_chain_page(
              "127.0.0.1", port, 0, 3
            )
          sync, flags = make_sync(n1, HttpChainFetcher(timeout=2, allow_loopback=True))
          assert await sync.sync_with(PeerAddress("node2", "127.0.0.1", port)) == "malformed"
          assert flags == [("node2", "malformed chain response")] and len(blocks_of(n1)) == 1
        finally:
          server.shutdown()
          server.server_close()

  run(go())


def test_http_fetcher_end_to_end_and_refused_port(node_env: NodeEnv) -> None:  # CN-TC-3.4 / 3.8
  chain = pow_chain(node_env, 6)

  async def go() -> None:
    async with Cluster(node_env, ids=("node1",), mine=False, register_peers=False) as cluster:
      n1 = cluster["node1"]
      server, port = _serve(type("H", (_Handler,), {"blocks": chain}))
      try:
        sync, _ = make_sync(n1, HttpChainFetcher(timeout=2, allow_loopback=True), page_size=3)
        assert await sync.sync_with(PeerAddress("node2", "127.0.0.1", port)) == "adopted"
        assert blocks_of(n1) == tuple(chain)
      finally:
        server.shutdown()
        server.server_close()
      # the port is closed now: connection refused -> unreachable
      sync, flags = make_sync(n1, HttpChainFetcher(timeout=2, allow_loopback=True))
      assert await sync.sync_with(PeerAddress("node2", "127.0.0.1", port)) == "unreachable"
      assert flags == []

  run(go())


# ----------------------------------------------------------------- long catch-up


@pytest.mark.parametrize("diverged", [False, True], ids=["extension", "fork"])
def test_long_chain_is_caught_up_over_many_pages(node_env: NodeEnv, diverged: bool) -> None:
  # CN-TC-3.14
  slow_sync_env(node_env, MAX_PAGE_SIZE="4")
  theirs = pow_chain(node_env, 25)
  local = extend(node_env, [theirs[0]], [91, 92]) if diverged else [theirs[0]]

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n2, theirs)
      if diverged:
        await install(n1, local)
      before = len(cluster.chain_fetcher.requests)

      assert await asyncio.wait_for(sync_of(n1).sync_with(peer_of(n2)), timeout=10) == "adopted"

      starts = [from_index for _, from_index, _ in cluster.chain_fetcher.requests[before:]]
      full_pages = [0, 4, 8, 12, 16, 20, 24]  # 26 blocks, 4 per page
      if diverged:  # the probe at the local tip, the page down to the fork point, the rest
        assert starts == [2, 1, 6, 10, 14, 18, 22]
      else:
        assert starts == full_pages
      assert blocks_of(n1) == tuple(theirs)
      assert cluster.stored_blocks("node1") == theirs
      assert n1.context.validity_cache.snapshot.tip_index == 25

  run(go())


# ------------------------------------------------------------- future-timestamp cap


@pytest.mark.parametrize("path", ["extension", "full"])
@pytest.mark.parametrize(("offset_ms", "outcome"), [(10_000, "adopted"), (600_000, "invalid")])
def test_future_timestamp_cap_applies_to_synced_blocks(
  node_env: NodeEnv, path: str, offset_ms: int, outcome: str
) -> None:
  # Slice 16b added requirement (2): MAX_FUTURE_SKEW_MS (default 60 s) covers sync adoption
  chain = pow_chain(node_env, 2)
  stamp = int(time.time() * 1000) + offset_ms
  late = pow_block(node_env, chain[-1], 3, timestamp=stamp)
  theirs = [*chain, late]
  local = chain if path == "extension" else extend(node_env, [chain[0]], [51])

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, local)
      await force_install(n2, theirs)
      flags = record_flags(sync_of(n1))

      assert await sync_of(n1).sync_with(peer_of(n2)) == outcome

      if outcome == "invalid":
        assert blocks_of(n1) == tuple(local)
        assert flags == [("node2", "invalid chain: timestamp_in_future")]
      else:
        assert blocks_of(n1) == tuple(theirs) and flags == []

  run(go())


# --------------------------------------------------------------- stale extension


@pytest.mark.parametrize("peer_tip", [3, 5], ids=["equal-length", "longer"])
def test_a_chain_is_rejudged_against_the_local_chain_that_moved_meanwhile(
  node_env: NodeEnv, peer_tip: int
) -> None:
  # prefer is re-judged under the lock against the CURRENT chain (16a covers the mechanism;
  # this is the sync-level proof): a block appended while we fetched counts
  chain = pow_chain(node_env, 5)
  theirs = chain[: peer_tip + 1]
  rival = pow_block(node_env, chain[2], 99)  # a different block 3 on our own tip
  if peer_tip == 3:  # equal length after the append: the lowest tip hash wins
    expected = "adopted" if int(chain[3].block_hash, 16) < int(rival.block_hash, 16) else None
  else:
    expected = "adopted"  # longer than our chain + the append: still the better chain

  class AppendsWhileFetching:
    def __init__(self, inner: Any, node: Any) -> None:
      self._inner, self._node, self._done = inner, node, False

    async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
      page = await self._inner.get_chain_page(host, port, from_index, to_index)
      if not self._done:
        self._done = True
        assert await self._node.context.chain_state.append(rival)  # lands before the replace
      return page

  async def go() -> None:
    async with _pair(node_env) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, chain[:3])
      await install(n2, theirs)
      sync, flags = make_sync(n1, AppendsWhileFetching(cluster.chain_fetcher, n1))

      outcome = await sync.sync_with(peer_of(n2))

      assert flags == []  # the peer did nothing wrong
      if expected == "adopted":
        assert outcome == "adopted"
        assert blocks_of(n1) == tuple(theirs)
        rival_record = rival.document_records[0].document_hash
        assert n1.context.mempool.contains(rival_record)  # the dropped append is re-queued
      else:
        assert outcome == "not_better"
        assert blocks_of(n1) == (*chain[:3], rival)  # the append stands
      assert cluster.stored_blocks("node1") == list(blocks_of(n1))

  run(go())
