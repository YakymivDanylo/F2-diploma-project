"""Slice 16b: bounded startup sync, tamper self-heal, INIT_CHAIN, and the boot order.

The node under test is driven through its real lifespan (`create_app` +
`app.router.lifespan_context`); its peer is a `ListFetcher` that can be switched down and up.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest
from chain_factory import pbft_chain, pow_chain, save_chain
from fastapi import FastAPI
from network_helpers import LoopbackNetwork, fast_sleep, until
from node_helpers import NodeEnv, pem_of
from sync_helpers import ListFetcher, run

from blockchain_core import Block, JsonChainStore, sha256_hex
from blockchain_core.storage.chain_store import ChainStoreMissingError, decode_chain
from node.config import load_config
from node.main import build_node_context, create_app

_NETWORK_OPTIONS = {
  "scan_interval": 0.01,
  "base_delay": 0.01,
  "max_delay": 0.04,
  "handshake_timeout": 1.0,
}


def _app(
  node_env: NodeEnv,
  fetcher: ListFetcher,
  *,
  mode: str = "pow",
  mine: bool = True,
  peers: Sequence[str] = ("node2",),
  **env: str,
) -> FastAPI:
  config = {"CONSENSUS_MODE": mode, "SYNC_INTERVAL_S": "0.05", **env}
  if mode == "pow":
    config["EXPECTED_DIFFICULTY"] = "1"
  app = create_app(
    load_config({**node_env.env, **config}),
    mine=mine,
    connector=LoopbackNetwork().connector_for(("node1", 8000)),  # every dial is refused
    sleep=fast_sleep,
    network_options=_NETWORK_OPTIONS,
    chain_fetcher=fetcher,
  )
  for position, peer_id in enumerate(peers, start=2):
    app.state.context.peers.register(
      peer_id, peer_id, 9000 + position, pem_of(node_env.validator_keys[peer_id])
    )
  return app


def _client(app: FastAPI) -> httpx.AsyncClient:
  return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://node1")


def _submit(client: httpx.AsyncClient, seed: int) -> Any:
  digest = sha256_hex(f"startup-{seed}".encode())
  return client.post("/documents", json={"hash": digest, "metadata": {"seed": seed}})


async def _info(client: httpx.AsyncClient) -> dict[str, Any]:
  return (await client.get("/node/info")).json()


def _stored(node_env: NodeEnv) -> list[Block]:
  return decode_chain(Path(node_env.env["CHAIN_PATH"]).read_bytes())


def _tamper_persisted(node_env: NodeEnv, blocks: list[Block], index: int = 2) -> bytes:
  """Persist `blocks`, then edit one record's metadata on disk (a Merkle-root mismatch)."""
  save_chain(node_env, blocks)
  path = Path(node_env.env["CHAIN_PATH"])
  document = json.loads(path.read_bytes())
  document["blocks"][index]["document_records"][0]["metadata"]["seed"] = 999
  path.write_bytes(json.dumps(document).encode())
  return path.read_bytes()


# ------------------------------------------------------------------- CN-TC-MI.13


def test_unreachable_peers_do_not_block_serving_past_the_timeout(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  # CN-TC-MI.13 (UC-3-F, UC-3-EC4)
  peer_chain = pow_chain(node_env, 5)
  fetcher = ListFetcher(peer_chain)
  fetcher.down = True

  async def go() -> None:
    app = _app(node_env, fetcher, mine=False, STARTUP_SYNC_TIMEOUT_S="0.4")
    context = app.state.context
    with caplog.at_level(logging.INFO):
      async with app.router.lifespan_context(app):
        started = time.monotonic()
        async with _client(app) as client:
          await asyncio.sleep(0.1)  # inside the startup window
          early = await _submit(client, 1)
          assert early.status_code == 503 and early.headers["Retry-After"]
          assert early.json()["error"]["code"] == "not_ready"
          assert len(context.mempool) == 0 and app.state.accepting is False

          await until(lambda: app.state.accepting, timeout=3.0)
          waited = time.monotonic() - started
          assert 0.2 < waited < 1.5  # neither aborted early nor waited past the bound
          warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
          assert any("STARTUP_SYNC_TIMEOUT_S" in r.getMessage() for r in warnings)
          assert any("no peer chain was confirmed" in r.getMessage() for r in warnings)
          assert (await _submit(client, 2)).status_code == 202  # serving its LOCAL chain
          assert (await _info(client))["tip_index"] == 0

          fetcher.down = False  # the peer comes up with a longer valid chain
          await until(lambda: len(context.chain_state.blocks) == len(peer_chain), timeout=5.0)
          info = await _info(client)
          assert info["tip_index"] == 5 and info["chain_valid"] is True
          assert context.chain_state.blocks == tuple(peer_chain)
          assert len(context.mempool) == 1  # the record accepted meanwhile is still pending

  run(go())


def test_a_reachable_peer_ends_the_startup_wait_early(node_env: NodeEnv) -> None:
  # CN-TC-MI.13 / UC-3-F: the timeout is a bound, not a delay
  peer_chain = pow_chain(node_env, 3)
  fetcher = ListFetcher(peer_chain)

  async def go() -> None:
    app = _app(node_env, fetcher, mine=False, STARTUP_SYNC_TIMEOUT_S="30")
    started = time.monotonic()
    async with app.router.lifespan_context(app):
      await until(lambda: app.state.accepting, timeout=5.0)
      assert time.monotonic() - started < 5.0
      assert app.state.context.chain_state.blocks == tuple(peer_chain)

  run(go())


# ------------------------------------------------------------------- CN-TC-MI.15 / 16


def test_tampered_persisted_chain_is_replaced_from_a_peer_before_serving(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  # CN-TC-MI.15 (UC-3-G): tamper self-heal
  chain = pow_chain(node_env, 5)
  tampered_bytes = _tamper_persisted(node_env, chain[:4])
  fetcher = ListFetcher(chain)

  async def go() -> None:
    with caplog.at_level(logging.INFO):
      app = _app(node_env, fetcher, STARTUP_SYNC_TIMEOUT_S="10")
    assert "first_invalid_index=2" in caplog.text  # logged at boot
    state = app.state.context.chain_state
    assert not state.extendable
    assert app.state.context.validity_cache.snapshot.first_invalid_index == 2

    async with app.router.lifespan_context(app):
      async with _client(app) as client:
        await until(lambda: app.state.accepting, timeout=5.0)
        info = await _info(client)  # the healed chain is in place BEFORE serving began
        assert info["chain_valid"] is True and info["first_invalid_index"] is None
        assert info["tip_index"] == 5
        assert state.blocks == tuple(chain) and state.extendable
        assert _stored(node_env) == chain  # persisted
        assert Path(node_env.env["CHAIN_PATH"]).read_bytes() != tampered_bytes

        # mining resumes on the adopted chain
        assert (await _submit(client, 1)).status_code == 202
        await until(lambda: state.tip.index == 6, timeout=5.0)
        assert state.tip.previous_hash == chain[5].block_hash

    context = build_node_context(
      load_config({**node_env.env, "EXPECTED_DIFFICULTY": "1", "CONSENSUS_MODE": "pow"})
    )
    try:  # a restart finds a valid chain
      assert context.state.restored.valid and len(context.current_blocks()) == 7
    finally:
      context.store.close()

  run(go())


def test_tampered_chain_with_no_peer_is_served_as_invalid_until_a_peer_heals_it(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  # CN-TC-MI.16 (UC-3-G): no reachable peer -> invalid but available; later healed
  chain = pow_chain(node_env, 5)
  tampered_bytes = _tamper_persisted(node_env, chain[:4])
  fetcher = ListFetcher(chain)
  fetcher.down = True

  async def go() -> None:
    app = _app(node_env, fetcher, STARTUP_SYNC_TIMEOUT_S="0.3")
    state = app.state.context.chain_state
    async with app.router.lifespan_context(app):
      async with _client(app) as client:
        await until(lambda: app.state.accepting, timeout=3.0)
        info = await _info(client)
        assert info["chain_valid"] is False and info["first_invalid_index"] == 2
        assert Path(node_env.env["CHAIN_PATH"]).read_bytes() == tampered_bytes  # untouched
        refused = await _submit(client, 1)  # an invalid chain cannot be extended
        assert refused.status_code == 503 and refused.json()["error"]["code"] == "chain_invalid"
        await asyncio.sleep(0.2)  # periodic sync keeps failing quietly
        assert not state.extendable

        fetcher.down = False  # a peer with the valid chain appears
        await until(lambda: state.extendable, timeout=5.0)
        info = await _info(client)
        assert info["chain_valid"] is True and info["first_invalid_index"] is None
        assert state.blocks == tuple(chain) and _stored(node_env) == chain
        assert (await _submit(client, 2)).status_code == 202  # accepted again

  run(go())


def test_tampered_chain_without_any_configured_peer_serves_immediately(
  node_env: NodeEnv,
) -> None:
  # CN-TC-MI.16: nothing to wait for - no startup wait, chain_valid false, store untouched
  chain = pow_chain(node_env, 3)
  tampered_bytes = _tamper_persisted(node_env, chain)

  async def go() -> None:
    app = _app(node_env, ListFetcher(chain), peers=())
    async with app.router.lifespan_context(app):
      assert app.state.accepting is True
      async with _client(app) as client:
        info = await _info(client)
        assert info["chain_valid"] is False and info["first_invalid_index"] == 2
    assert Path(node_env.env["CHAIN_PATH"]).read_bytes() == tampered_bytes

  run(go())


# ------------------------------------------------------------------- CN-TC-MI.17


def test_init_chain_is_ignored_when_a_chain_is_persisted(node_env: NodeEnv, boot) -> None:
  # CN-TC-MI.17 (UC-3-EC5 / UC-1-EC4)
  chain = pow_chain(node_env, 3)
  save_chain(node_env, chain)
  before = Path(node_env.env["CHAIN_PATH"]).read_bytes()
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1", "INIT_CHAIN": "1"}

  context = boot(env)
  assert context.current_blocks() == tuple(chain) and context.state.restored.valid

  async def go() -> None:
    app = _app(node_env, ListFetcher(chain), peers=(), INIT_CHAIN="1")
    async with app.router.lifespan_context(app):
      async with _client(app) as client:
        assert (await _info(client))["tip_index"] == 3

  context.store.close()
  run(go())
  assert Path(node_env.env["CHAIN_PATH"]).read_bytes() == before  # not re-initialised


def test_empty_store_without_init_chain_fails_closed(node_env: NodeEnv) -> None:  # CN-TC-MI.17
  env = {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"}
  del env["INIT_CHAIN"]
  assert not Path(env["CHAIN_PATH"]).exists()
  with pytest.raises(ChainStoreMissingError):
    create_app(load_config(env))
  assert not Path(env["CHAIN_PATH"]).exists() or not _stored_or_empty(env["CHAIN_PATH"])


def _stored_or_empty(path: str) -> list[Block]:
  store = JsonChainStore(path)
  try:
    return list(store.load() or [])
  finally:
    store.close()


def test_init_chain_on_an_empty_store_starts_at_genesis(node_env: NodeEnv, boot) -> None:
  # CN-TC-MI.17: the one legitimate use of the flag
  context = boot({**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1"})
  assert len(context.current_blocks()) == 1 and context.state.restored.valid


# ------------------------------------------------------------------- CN-TC-MI.18


@pytest.mark.parametrize("mode", ["pow", "pbft"])
def test_nothing_starts_or_serves_before_the_startup_sync_returns(
  node_env: NodeEnv, mode: str
) -> None:
  # CN-TC-MI.18: load -> sync -> serve (mining / consensus engine start only after the sync)
  chain = pow_chain(node_env, 3) if mode == "pow" else pbft_chain(node_env, 3)
  save_chain(node_env, chain[:2])  # the node boots with a persisted (valid) prefix
  fetcher = ListFetcher(chain)
  events: list[str] = []

  async def go() -> None:
    release = asyncio.Event()
    app = _app(node_env, fetcher, mode=mode, STARTUP_SYNC_TIMEOUT_S="30")
    state = app.state.context.chain_state
    assert len(state.blocks) == 2  # 1. load: the persisted chain is in memory before any sync

    sync = app.state.sync
    real_startup = sync.startup

    async def startup(timeout_s: float) -> bool:
      events.append(f"sync:begin tip={state.tip.index} accepting={app.state.accepting}")
      await release.wait()  # hold the sync open: nothing may start meanwhile
      outcome = await real_startup(timeout_s)
      events.append(f"sync:end tip={state.tip.index} accepting={app.state.accepting}")
      return outcome

    sync.startup = startup
    engine = app.state.engine
    if mode == "pow":
      assert engine is not None
      real_start = engine.start

      async def start() -> None:
        events.append(f"engine.start accepting={app.state.accepting}")
        await real_start()

      engine.start = start
    else:
      assert engine is None  # no PoW miner exists under PBFT

    async with app.router.lifespan_context(app):
      async with _client(app) as client:
        await asyncio.sleep(0.15)
        assert events == ["sync:begin tip=1 accepting=False"]  # still syncing: nothing else ran
        assert app.state.accepting is False
        assert (await _submit(client, 1)).status_code == 503

        release.set()  # 2. sync completes ...
        await until(lambda: app.state.accepting, timeout=5.0)  # 3. ... then serve
        expected = ["sync:begin tip=1 accepting=False", "sync:end tip=3 accepting=False"]
        if mode == "pow":
          expected.append("engine.start accepting=False")
        assert events == expected
        assert state.blocks == tuple(chain)

  run(go())
