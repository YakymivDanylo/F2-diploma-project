"""Wave D network / sync hardening (security review 2026-11-20).

R1: a replace validated from a still-trusted ancestor survives local appends meanwhile.
R4: validators are backed off for at most 30 s, never for link / consistency failures.
R5: dial loops end when their peer is evicted; validators never count toward `max_dialed`.
R6: outbound hosts are resolved and refused when they point at loopback / link-local /
    unspecified / multicast addresses (`node.netguard`); no test needs real DNS.
Final review (2026-11-20): N2 bounded, cached DNS on dedicated pools and reserved validator
fetch workers; N3 bounded link / flag state; N5 no socket leak on a cancelled dial; N7 a late
suffix break backs a validator off; N9 more forbidden ranges; CR5 no dial-loop overlap.
"""

from __future__ import annotations

import asyncio
import dataclasses
import threading
import time
from collections.abc import Sequence
from typing import Any

import pytest
from chain_factory import pow_block, pow_chain
from network_helpers import Cluster, make_pair
from node_helpers import NodeEnv
from sync_helpers import (
  ListFetcher,
  ValidatorSpy,
  blocks_of,
  extend,
  install,
  make_sync,
  run,
  slow_sync_env,
)

from blockchain_core import Block, ValidationResult
from node import netguard
from node.netguard import (
  RESOLVE_WORKERS,
  UnsafeAddressError,
  check_resolved,
  check_resolved_async,
  prioritized,
)
from node.network.connection_manager import (
  MAX_FLAGGED_IDS,
  MAX_NON_VALIDATOR_LINKS,
  UNAUTHENTICATED_KEY,
  PeerConnectionManager,
)
from node.network.ws_blocks import WebsocketsConnector
from node.sync import (
  BACKOFF_CAP_S,
  BACKOFF_START_S,
  FETCH_WORKERS,
  SUFFIX_FAILURES_BEFORE_ESCALATION,
  VALIDATOR_BACKOFF_CAP_S,
  HttpChainFetcher,
  PeerAddress,
)


def _peer(node_id: str) -> PeerAddress:
  return PeerAddress(node_id, node_id, 9000)


def _single(node_env: NodeEnv) -> Cluster:
  slow_sync_env(node_env)
  return Cluster(node_env, ids=("node1",), mode="pow", mine=False, register_peers=False)


def _hashes(blocks: Sequence[Block]) -> list[str]:
  return [b.block_hash for b in blocks]


class Clock:
  def __init__(self) -> None:
    self.now = 1000.0

  def __call__(self) -> float:
    return self.now


# ------------------------------------------------------------------------- R1


class SuffixGate:
  """Parks the first multi-block `extension` call (sync's suffix validation, in its worker
  thread) until released; single-block calls (local appends) pass straight through."""

  def __init__(self, validator: Any) -> None:
    self.entered = threading.Event()
    self.release = threading.Event()
    self._armed = True
    real = validator.extension

    def extension(tip: Block, new_blocks: Sequence[Block]) -> ValidationResult:
      if self._armed and len(new_blocks) > 1:
        self._armed = False
        self.entered.set()
        self.release.wait(10)
      return real(tip, new_blocks)

    validator.extension = extension

  async def wait_entered(self) -> None:
    for _ in range(5000):
      if self.entered.is_set():
        return
      await asyncio.sleep(0.001)
    raise AssertionError("the suffix validation never started")


def test_r1_local_appends_during_a_slow_replace_do_not_make_a_winning_fork_stale(
  node_env: NodeEnv,
) -> None:
  # a PoW node on a minority fork keeps mining while it validates the majority suffix: the
  # suffix was validated from the shared ancestor (genesis, ours), so the appends cannot
  # invalidate it - it still wins under the lock and is installed
  local = pow_chain(node_env, 1)  # genesis, a1
  majority = extend(node_env, local[:1], [101, 102, 103, 104, 105])  # genesis, b1..b5

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, local)
      state = n1.context.chain_state
      gate = SuffixGate(n1.context.validator)
      sync, _ = make_sync(n1, ListFetcher(majority), peers=[_peer("v1")])
      syncing = asyncio.create_task(sync.sync_with(_peer("v1")))
      await gate.wait_entered()
      mined = [local[-1]]
      for seed in (2, 3):  # appends keep landing while the replace validates
        block = pow_block(node_env, mined[-1], seed)
        assert await asyncio.wait_for(state.append(block), 2.0) is True
        mined.append(block)
      generation = state.generation
      gate.release.set()
      assert await syncing == "adopted"
      assert _hashes(blocks_of(n1)) == _hashes(majority)
      assert state.generation == generation + 1

  run(go())


def test_r1_a_replace_is_still_refused_when_local_appends_overtake_it(node_env: NodeEnv) -> None:
  local = pow_chain(node_env, 1)
  fork = extend(node_env, local[:1], [101, 102, 103])  # genesis, b1..b3 (length 4)

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, local)
      state = n1.context.chain_state
      gate = SuffixGate(n1.context.validator)
      sync, _ = make_sync(n1, ListFetcher(fork), peers=[_peer("v1")])
      syncing = asyncio.create_task(sync.sync_with(_peer("v1")))
      await gate.wait_entered()
      chain = list(local)
      for seed in (2, 3, 4, 5):  # local chain grows to length 6 > 4
        chain.append(pow_block(node_env, chain[-1], seed))
        assert await state.append(chain[-1]) is True
      gate.release.set()
      assert await syncing == "not_better"
      assert _hashes(blocks_of(n1)) == _hashes(chain)

  run(go())


def test_r1_a_replace_whose_base_was_dropped_meanwhile_is_stale(node_env: NodeEnv) -> None:
  # the candidate extends a1; another adoption meanwhile dropped a1 - its base is gone, so it
  # is refused even though it is longer than the chain now current
  local = pow_chain(node_env, 1)  # genesis, a1
  candidate = extend(node_env, local, [201, 202, 203, 204, 205])  # genesis, a1, p2..p6
  other = extend(node_env, local[:1], [301, 302, 303])  # genesis, q1..q3 (drops a1)

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, local)
      gate = SuffixGate(n1.context.validator)
      sync, _ = make_sync(n1, ListFetcher(candidate), peers=[_peer("v1")])
      syncing = asyncio.create_task(sync.sync_with(_peer("v1")))
      await gate.wait_entered()
      await install(n1, other)  # full validation: not gated
      gate.release.set()
      assert await syncing == "not_better"  # stale; the next round re-judges it
      assert _hashes(blocks_of(n1)) == _hashes(other)

  run(go())


# ------------------------------------------------------------------------- R4


def _tampered(chain: list[Block]) -> list[Block]:
  bad = dataclasses.replace(chain[4], timestamp=chain[4].timestamp + 1)  # a forged hash
  return [*chain[:4], bad, chain[5]]


def test_r4_a_validator_serving_forged_data_is_backed_off_for_at_most_30s(
  node_env: NodeEnv,
) -> None:
  chain = pow_chain(node_env, 5)
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, chain[:3])
      sync, _ = make_sync(
        n1, ListFetcher(_tampered(chain)), peers=[_peer("v1")], clock=clock, peer_timeout_s=600.0
      )  # every peer is a validator by default
      delays: list[float] = []
      for _ in range(5):
        assert await sync.sync_round() == {"v1": "invalid"}
        delay = sync.backoff_for("v1")
        delays.append(delay)
        clock.now += delay + 0.01
      assert delays == [BACKOFF_START_S, 10.0, 20.0, 30.0, 30.0]
      assert VALIDATOR_BACKOFF_CAP_S == 30.0

  run(go())


def test_r4_non_validators_keep_the_5_to_300s_backoff(node_env: NodeEnv) -> None:
  chain = pow_chain(node_env, 5)
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, chain[:3])
      sync, _ = make_sync(
        n1,
        ListFetcher(_tampered(chain)),
        peers=[_peer("x1")],
        clock=clock,
        peer_timeout_s=600.0,
        is_validator=lambda _id: False,
      )
      delays: list[float] = []
      for _ in range(8):
        assert await sync.sync_round() == {"x1": "invalid"}
        delays.append(sync.backoff_for("x1"))
        clock.now += delays[-1] + 0.01
      assert delays[0] == BACKOFF_START_S and delays[-1] == BACKOFF_CAP_S == 300.0

  run(go())


class ReorgingFetcher(ListFetcher):
  """Serves `before` for the first request, then `after`: the peer reorged between pages."""

  def __init__(self, before: Sequence[Block], after: Sequence[Block]) -> None:
    super().__init__(before)
    self._after = list(after)

  async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
    page = await super().get_chain_page(host, port, from_index, to_index)
    self.blocks = list(self._after)
    return page


@pytest.mark.parametrize("validator", [True, False], ids=["validator", "non-validator"])
def test_r4_pages_fetched_across_a_peer_reorg_never_back_a_validator_off(
  node_env: NodeEnv, validator: bool
) -> None:
  base = pow_chain(node_env, 2)  # genesis, 1, 2 - ours
  before = extend(node_env, base, [3, 4, 5, 6])
  after = extend(node_env, base, [13, 14, 15, 16])  # the peer's chain after its reorg
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, base)
      fetcher = ReorgingFetcher(before, after)
      sync, flags = make_sync(
        n1,
        fetcher,
        page_size=2,
        peers=[_peer("p1")],
        clock=clock,
        peer_timeout_s=600.0,
        is_validator=lambda _id: validator,
      )
      assert await sync.sync_round() == {"p1": "invalid"}  # block 3 (old) + 4 (new): no link
      assert flags and "link" in flags[-1][1]
      # N7: the break surfaced in the suffix downloaded after the precheck passed, so even a
      # validator pauses - for a flat BACKOFF_START_S, never escalating
      assert sync.backoff_for("p1") == BACKOFF_START_S
      assert await sync.sync_round() == {}
      if validator:
        # M1: flat 5 s for SUFFIX_FAILURES_BEFORE_ESCALATION in a row, then escalating
        expected = [BACKOFF_START_S, BACKOFF_START_S, 10.0, 20.0]
        for delay in expected:
          clock.now += sync.backoff_for("p1") + 0.01
          fetcher.blocks = list(before)
          assert await sync.sync_round() == {"p1": "invalid"}
          assert sync.backoff_for("p1") == delay
        assert SUFFIX_FAILURES_BEFORE_ESCALATION == 3
        clock.now += sync.backoff_for("p1") + 0.01
        fetcher.blocks = list(after)
        fetcher._after = list(after)  # noqa: SLF001 - the peer's chain settled
        assert await sync.sync_round() == {"p1": "adopted"}
        assert _hashes(blocks_of(n1)) == _hashes(after)
        assert sync.backoff_for("p1") == 0.0  # a confirmed round resets the streak too

  run(go())


@pytest.mark.parametrize("validator", [True, False], ids=["validator", "non-validator"])
def test_r4_inconsistent_answers_never_back_a_validator_off(
  node_env: NodeEnv, validator: bool
) -> None:
  chain = pow_chain(node_env, 3)
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      fetcher = ListFetcher(chain)
      # an empty page below the tip it advertises: what a peer whose chain moved serves
      fetcher.mutate = lambda page: {**page, "blocks": [], "to_index": None}
      sync, _ = make_sync(
        n1,
        fetcher,
        peers=[_peer("p1")],
        clock=clock,
        peer_timeout_s=600.0,
        is_validator=lambda _id: validator,
      )
      assert await sync.sync_round() == {"p1": "malformed"}
      if validator:
        assert sync.backoff_for("p1") == 0.0
        fetcher.mutate = None
        assert await sync.sync_round() == {"p1": "adopted"}
      else:
        assert await sync.sync_round() == {}  # backed off

  run(go())


# ------------------------------------------------------------------------- R5


class HoldingConnector:
  """Records every dial and never completes it."""

  def __init__(self) -> None:
    self.dialed: list[str] = []
    self._never = asyncio.Event()

  async def connect(self, host: str, port: int, path: str) -> Any:
    self.dialed.append(host)
    await self._never.wait()
    raise OSError("unreachable")


def _dial_manager(
  node_env: NodeEnv,
  addresses: list[tuple[str, str, int]],
  validators: set[str],
  max_dialed: int,
  connector: Any = None,
  **options: Any,
) -> tuple[PeerConnectionManager, Any]:
  connector = connector if connector is not None else HoldingConnector()

  async def on_message(peer_id: str, message: dict) -> None:
    return None

  manager = PeerConnectionManager(
    self_id="node1",
    node_key=node_env.validator_keys["node1"].private_key,
    lookup_key=lambda _id: None,
    peer_addresses=lambda: list(addresses),
    known_ids=lambda: set(validators),
    connector=connector,
    on_message=on_message,
    max_dialed=max_dialed,
    **options,
  )
  return manager, connector


async def _settle() -> None:
  for _ in range(5):
    await asyncio.sleep(0)


def test_r5_early_sybils_cannot_hold_the_slots_a_later_validator_needs(node_env: NodeEnv) -> None:
  async def go() -> None:
    addresses = [(f"sybil{i:02d}", f"sybil{i:02d}", 9000) for i in range(64)]
    validators = {"node1", "node2", "node3", "node4"}
    manager, connector = _dial_manager(node_env, addresses, validators, max_dialed=64)
    try:
      manager._scan()  # noqa: SLF001
      await _settle()
      assert len(connector.dialed) == 64  # every slot is held by a sybil
      addresses += [("node2", "node2", 8000), ("node3", "node3", 8000)]  # learned later
      manager._scan()  # noqa: SLF001
      await _settle()
      assert {"node2", "node3"} <= set(connector.dialed)  # dialed anyway
      assert len(manager.dialing()) == 66  # validators do not count
    finally:
      await manager.stop()

  run(go())


def test_r5_dial_loops_of_evicted_peers_end_and_free_their_slot(node_env: NodeEnv) -> None:
  async def go() -> None:
    addresses = [("node2", "node2", 8000)] + [(f"x{i}", f"x{i}", 9000) for i in range(3)]
    manager, connector = _dial_manager(node_env, addresses, {"node1", "node2"}, max_dialed=2)
    try:
      manager._scan()  # noqa: SLF001
      await _settle()
      assert manager.dialing() == {"node2", "x0", "x1"}
      addresses[:] = [a for a in addresses if a[0] not in ("x0", "node2")]  # evicted / no address
      manager._scan()  # noqa: SLF001
      await _settle()
      # the evicted peer's loop ended and its slot went to a listed peer; a validator's loop
      # is never cancelled, even without an address
      assert manager.dialing() == {"node2", "x1", "x2"}
      assert connector.dialed.count("x2") == 1 and connector.dialed.count("x0") == 1
    finally:
      await manager.stop()

  run(go())


def test_finding5_non_validator_link_bound_is_8() -> None:
  assert MAX_NON_VALIDATOR_LINKS == 8


# ------------------------------------------------------------------------- R6


def _resolver(table: dict[str, list[str]]):
  calls: list[str] = []

  def resolve(host: str, port: int) -> list[str]:
    calls.append(host)
    return table[host]

  return resolve, calls


@pytest.mark.parametrize(
  "addresses",
  [
    ["127.0.0.1"],
    ["169.254.169.254"],  # cloud metadata
    ["0.0.0.0"],
    ["224.0.0.1"],
    ["::1"],
    ["fe80::1%eth0"],
    ["::ffff:127.0.0.1"],
    ["203.0.113.7", "127.0.0.1"],  # ANY resolved address counts
  ],
)
def test_r6_names_resolving_to_forbidden_addresses_are_refused(addresses: list[str]) -> None:
  resolve, _ = _resolver({"evil.example": addresses})
  with pytest.raises(UnsafeAddressError):
    check_resolved("evil.example", 80, allow_loopback=False, resolve=resolve)


def test_r6_allow_loopback_admits_loopback_only() -> None:
  resolve, _ = _resolver({"local": ["127.0.0.1", "::1"], "meta": ["169.254.169.254"]})
  check_resolved("local", 80, allow_loopback=True, resolve=resolve)
  with pytest.raises(UnsafeAddressError):
    check_resolved("meta", 80, allow_loopback=True, resolve=resolve)
  for literal in ("0.0.0.0", "224.0.0.1", "169.254.1.1"):
    with pytest.raises(UnsafeAddressError):
      check_resolved(literal, 80, allow_loopback=True, resolve=resolve)


def test_r6_private_and_public_addresses_pass_and_literals_skip_the_lookup() -> None:
  resolve, calls = _resolver({"node2": ["172.18.0.3"], "peer.example": ["203.0.113.7"]})
  check_resolved("node2", 8000, allow_loopback=False, resolve=resolve)
  check_resolved("peer.example", 8000, allow_loopback=False, resolve=resolve)
  for literal in ("10.0.0.5", "[2001:db8::1]"):
    check_resolved(literal, 8000, allow_loopback=False, resolve=resolve)
  with pytest.raises(UnsafeAddressError):
    check_resolved("127.0.0.1", 8000, allow_loopback=False, resolve=resolve)
  assert calls == ["node2", "peer.example"]  # literal IPs were judged without a lookup


def test_r6_a_failed_or_empty_lookup_is_an_oserror() -> None:
  def failing(host: str, port: int) -> list[str]:
    raise OSError("no such host")

  with pytest.raises(OSError):
    check_resolved("nowhere", 1, allow_loopback=False, resolve=failing)
  with pytest.raises(UnsafeAddressError):
    check_resolved("empty", 1, allow_loopback=False, resolve=lambda h, p: [])


def test_r6_async_check_resolves_off_the_event_loop() -> None:
  loop_thread: list[int] = []
  resolved_in: list[int] = []

  def resolve(host: str, port: int) -> list[str]:
    resolved_in.append(threading.get_ident())
    return ["127.0.0.1"]

  async def go() -> None:
    loop_thread.append(threading.get_ident())
    with pytest.raises(UnsafeAddressError):
      await check_resolved_async("evil", 1, allow_loopback=False, resolve=resolve)
    await check_resolved_async("evil", 1, allow_loopback=True, resolve=resolve)

  run(go())
  assert resolved_in and all(t != loop_thread[0] for t in resolved_in)


def test_r6_the_chain_fetcher_refuses_before_any_request() -> None:
  resolve, calls = _resolver({"evil": ["169.254.169.254"]})
  fetcher = HttpChainFetcher(timeout=1, resolve=resolve)
  with pytest.raises(UnsafeAddressError):
    run(fetcher.get_chain_page("evil", 80, 0, 1))
  assert calls == ["evil"]


def test_r6_a_sync_with_a_peer_resolving_to_loopback_is_unreachable(node_env: NodeEnv) -> None:
  resolve, _ = _resolver({"evil": ["127.0.0.1"]})

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      before = blocks_of(n1)
      sync, flags = make_sync(n1, HttpChainFetcher(timeout=1, resolve=resolve))
      assert await sync.sync_with(PeerAddress("x1", "evil", 8000)) == "unreachable"
      assert blocks_of(n1) == before and flags == []

  run(go())


def test_r6_the_ws_connector_refuses_before_dialing() -> None:
  resolve, calls = _resolver({"evil": ["127.0.0.1"], "meta": ["169.254.169.254"]})

  async def go() -> None:
    with pytest.raises(UnsafeAddressError):  # an OSError: the dial loop backs off and retries
      await WebsocketsConnector(resolve=resolve).connect("evil", 8000, "/ws/blocks")
    with pytest.raises(UnsafeAddressError):
      await WebsocketsConnector(allow_loopback=True, resolve=resolve).connect(
        "meta", 8000, "/ws/blocks"
      )

  run(go())
  assert calls == ["evil", "meta"]
  assert issubclass(UnsafeAddressError, OSError)


# --------------------------------------------------------------- final review: N9


@pytest.mark.parametrize(
  "address",
  [
    "0.1.2.3",  # 0.0.0.0/8 "this network", not just 0.0.0.0
    "0.255.255.255",
    "::7f00:1",  # IPv4-compatible ::127.0.0.1
    "::a00:5",  # IPv4-compatible ::10.0.0.5: the whole ::/96 is refused
    "fd00:ec2::254",  # IPv6 cloud metadata
  ],
)
def test_n9_this_network_ipv4_compatible_and_ipv6_metadata_are_refused(address: str) -> None:
  resolve, _ = _resolver({"evil.example": [address]})
  for allow_loopback in (False, True):
    with pytest.raises(UnsafeAddressError):
      check_resolved("evil.example", 80, allow_loopback=allow_loopback, resolve=resolve)
    with pytest.raises(UnsafeAddressError):
      check_resolved(address, 80, allow_loopback=allow_loopback, resolve=resolve)


def test_n9_neighbours_of_the_new_ranges_still_pass() -> None:
  resolve, _ = _resolver({"ok": ["fd00:ec2::253", "1.0.0.1", "2001:db8::7f00:1"]})
  check_resolved("ok", 80, allow_loopback=False, resolve=resolve)
  check_resolved("::1", 80, allow_loopback=True, resolve=resolve)  # loopback stays admissible


# --------------------------------------------------------------- final review: N2


def test_n2_hanging_dns_times_out_on_its_own_pool_and_never_blocks_to_thread() -> None:
  release = threading.Event()

  def hanging(host: str, port: int) -> list[str]:
    release.wait(30)
    return ["203.0.113.7"]

  async def go() -> None:
    checks = [
      asyncio.create_task(
        check_resolved_async(f"slow{i}", 1, allow_loopback=False, resolve=hanging, timeout=1.0)
      )
      for i in range(40)  # more lookups than any default executor has threads
    ]
    await asyncio.sleep(0.05)
    started = time.monotonic()
    assert await asyncio.gather(*(asyncio.to_thread(lambda: 42) for _ in range(8))) == [42] * 8
    assert time.monotonic() - started < 0.5 and not any(c.done() for c in checks)
    workers = [t for t in threading.enumerate() if t.name.startswith("dns_")]
    assert 0 < len(workers) <= RESOLVE_WORKERS  # a small bounded pool, not the default one
    outcomes = await asyncio.gather(*checks, return_exceptions=True)
    assert all(isinstance(o, TimeoutError) for o in outcomes)  # an OSError: "unreachable"

  try:
    run(go())
  finally:
    release.set()


def test_n2_a_validator_lookup_never_waits_behind_hanging_non_validator_lookups() -> None:
  release = threading.Event()

  def hanging(host: str, port: int) -> list[str]:
    release.wait(30)
    return ["203.0.113.7"]

  async def go() -> None:
    stuck = [
      asyncio.create_task(
        check_resolved_async(f"sybil{i}", 1, allow_loopback=False, resolve=hanging, timeout=5.0)
      )
      for i in range(RESOLVE_WORKERS * 3)
    ]
    await asyncio.sleep(0.05)
    fast, _ = _resolver({"node2": ["172.18.0.3"], "x1": ["172.18.0.4"]})
    with prioritized(True):
      await asyncio.wait_for(
        check_resolved_async("node2", 8000, allow_loopback=False, resolve=fast), 1.0
      )
    other = asyncio.create_task(  # a non-validator lookup queues behind the stuck ones
      check_resolved_async("x1", 8000, allow_loopback=False, resolve=fast, timeout=5.0)
    )
    await asyncio.sleep(0.1)
    assert not other.done()
    release.set()
    await asyncio.gather(*stuck, other)

  try:
    run(go())
  finally:
    release.set()


def test_n2_successful_lookups_are_cached_for_the_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
  resolve, calls = _resolver({"node2": ["172.18.0.3"], "bad": ["127.0.0.1"]})

  async def go() -> None:
    for _ in range(3):
      await check_resolved_async("node2", 8000, allow_loopback=False, resolve=resolve)
    assert calls == ["node2"]  # one lookup within the TTL
    for _ in range(2):  # the cached answer is still judged on every call
      with pytest.raises(UnsafeAddressError):
        await check_resolved_async("bad", 8000, allow_loopback=False, resolve=resolve)
    await check_resolved_async("bad", 8000, allow_loopback=True, resolve=resolve)
    assert calls == ["node2", "bad"]
    monkeypatch.setattr(netguard, "RESOLVE_CACHE_TTL_S", 0.0)  # an expired entry is refreshed
    netguard.clear_resolution_cache()
    await check_resolved_async("node2", 8000, allow_loopback=False, resolve=resolve)
    await check_resolved_async("node2", 8000, allow_loopback=False, resolve=resolve)
    assert calls == ["node2", "bad", "node2", "node2"]

  run(go())


def test_n2_validator_fetches_never_wait_behind_hanging_non_validator_fetches() -> None:
  release = threading.Event()
  fetcher = HttpChainFetcher(timeout=1)

  def call(host: str, port: int, from_index: int, to_index: int) -> Any:
    if host == "203.0.113.5":  # a non-validator that never answers
      release.wait(30)
    return {"host": host}

  fetcher._call = call  # type: ignore[method-assign]  # noqa: SLF001 - no real HTTP

  async def go() -> None:
    hanging = [
      asyncio.create_task(fetcher.get_chain_page("203.0.113.5", 80, 0, 1))
      for _ in range(FETCH_WORKERS * 2)
    ]
    await asyncio.sleep(0.05)
    with prioritized(True):  # what ChainSync sets for a ValidatorSet member
      page = await asyncio.wait_for(fetcher.get_chain_page("203.0.113.6", 80, 0, 1), 1.0)
    assert page == {"host": "203.0.113.6"}
    other = asyncio.create_task(fetcher.get_chain_page("203.0.113.6", 80, 0, 1))
    await asyncio.sleep(0.1)
    assert not other.done()  # every non-validator worker is held by the hanging peer
    release.set()
    await asyncio.gather(*hanging, other)

  try:
    run(go())
  finally:
    release.set()


def test_n2_chain_sync_marks_validator_traffic_per_peer(node_env: NodeEnv) -> None:
  seen: dict[str, bool] = {}

  class Recording(ListFetcher):
    async def get_chain_page(self, host: str, port: int, from_index: int, to_index: int) -> Any:
      seen[host] = netguard.validator_traffic.get()
      return await super().get_chain_page(host, port, from_index, to_index)

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      sync, _ = make_sync(
        n1,
        Recording(blocks_of(n1)),
        peers=[_peer("v1"), _peer("x1")],
        is_validator={"v1"}.__contains__,
      )
      await sync.sync_round()
      assert seen == {"v1": True, "x1": False}
      assert netguard.validator_traffic.get() is False  # reset after each peer

  run(go())


# --------------------------------------------------------------- final review: N7


def test_n7_a_suffix_breaking_at_its_end_is_refused_cheaply_and_backs_a_validator_off(
  node_env: NodeEnv,
) -> None:
  base = pow_chain(node_env, 2)
  served = extend(node_env, base, list(range(3, 11)))
  served[-1] = dataclasses.replace(served[-1], previous_hash="f" * 64)  # breaks at the end
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, base)
      spy = ValidatorSpy(n1.context.validator)
      sync, flags = make_sync(
        n1, ListFetcher(served), page_size=2, peers=[_peer("v1")], clock=clock, peer_timeout_s=600
      )
      assert await sync.sync_round() == {"v1": "invalid"}
      assert flags and "link" in flags[-1][1]
      assert len(spy.extension_calls) == 1  # only the one-block precheck: no full validation
      assert sync.backoff_for("v1") == BACKOFF_START_S  # even a validator, after a precheck
      assert await sync.sync_round() == {}
      assert blocks_of(n1) == tuple(base)

  run(go())


# ------------------------------------------------------- final security review: M1


def _future_ms() -> int:
  return int(time.time() * 1000) + 3_600_000  # an hour ahead: beyond any skew cap


@pytest.mark.parametrize("breakage", ["link", "timestamp_in_future"])
def test_m1_a_suffix_download_stops_at_the_first_broken_page(
  node_env: NodeEnv, breakage: str
) -> None:
  base = pow_chain(node_env, 2)  # genesis, 1, 2 - ours
  served = extend(node_env, base, [3, 4])
  if breakage == "link":
    served.append(dataclasses.replace(pow_block(node_env, served[-1], 5), previous_hash="f" * 64))
  else:
    served.append(pow_block(node_env, served[-1], 5, timestamp=_future_ms()))
  served = extend(node_env, served, list(range(6, 41)))  # a long tail after the break
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, base)
      spy = ValidatorSpy(n1.context.validator)
      fetcher = ListFetcher(served)
      sync, flags = make_sync(
        n1, fetcher, page_size=2, peers=[_peer("v1")], clock=clock, peer_timeout_s=600
      )
      assert await sync.sync_round() == {"v1": "invalid"}
      assert flags and breakage in flags[-1][1]
      # probe (2..3) + the page holding the break (4..5); nothing after it was requested
      assert [r[2] for r in fetcher.requests] == [2, 4]
      assert len(spy.extension_calls) == 1  # only the one-block precheck
      assert sync.backoff_for("v1") == BACKOFF_START_S  # classified as before: a suffix failure
      assert blocks_of(n1) == tuple(base)

  run(go())


def test_m1_repeated_suffix_failures_escalate_a_validator_backoff_until_confirmed(
  node_env: NodeEnv,
) -> None:
  base = pow_chain(node_env, 2)
  good = extend(node_env, base, list(range(3, 11)))
  broken = [*good[:-1], dataclasses.replace(good[-1], previous_hash="f" * 64)]
  clock = Clock()

  async def go() -> None:
    async with _single(node_env) as cluster:
      n1 = cluster["node1"]
      await install(n1, base)
      fetcher = ListFetcher(broken)
      sync, _ = make_sync(
        n1, fetcher, page_size=2, peers=[_peer("v1")], clock=clock, peer_timeout_s=600
      )
      delays: list[float] = []
      for _ in range(7):
        assert await sync.sync_round() == {"v1": "invalid"}
        delays.append(sync.backoff_for("v1"))
        assert await sync.sync_round() == {}  # skipped while backed off
        clock.now += delays[-1] + 0.01
      assert SUFFIX_FAILURES_BEFORE_ESCALATION == 3
      assert delays == [5.0, 5.0, 5.0, 10.0, 20.0, 30.0, 30.0]
      assert max(delays) == VALIDATOR_BACKOFF_CAP_S
      # an unreachable round in between neither resets nor extends the streak
      fetcher.down = True
      assert await sync.sync_round() == {"v1": "unreachable"}
      fetcher.down = False
      assert await sync.sync_round() == {"v1": "invalid"}
      assert sync.backoff_for("v1") == 30.0
      clock.now += 30.01
      fetcher.blocks = list(good)  # a confirmed round resets the streak
      assert await sync.sync_round() == {"v1": "adopted"}
      assert sync.backoff_for("v1") == 0.0
      later = extend(node_env, good, list(range(11, 15)))
      fetcher.blocks = [*later[:-1], dataclasses.replace(later[-1], previous_hash="f" * 64)]
      assert await sync.sync_round() == {"v1": "invalid"}
      assert sync.backoff_for("v1") == BACKOFF_START_S  # the streak starts over

  run(go())


def test_cr1_each_http_fetcher_owns_its_pools_and_closes_them() -> None:
  first, second = HttpChainFetcher(timeout=1), HttpChainFetcher(timeout=1)
  assert first._pools is not second._pools  # noqa: SLF001 - no class-level sharing
  assert first._pools[True] is not second._pools[True]  # noqa: SLF001
  assert "_pools" not in vars(HttpChainFetcher)
  first._call = lambda *args: {"ok": True}  # type: ignore[method-assign]  # noqa: SLF001

  async def go() -> None:
    assert await first.get_chain_page("203.0.113.5", 80, 0, 1) == {"ok": True}
    first.close()
    with pytest.raises(RuntimeError):
      await first.get_chain_page("203.0.113.5", 80, 0, 1)

  run(go())
  second.close()


# --------------------------------------------------------- final review: N3 / N5 / CR5


def test_n3_links_of_unlisted_peers_are_pruned_and_health_stays_bounded(
  node_env: NodeEnv,
) -> None:
  async def go() -> None:
    addresses = [(f"x{i}", f"x{i}", 9000) for i in range(10)]
    manager, _ = _dial_manager(node_env, addresses, {"node1", "node2"}, max_dialed=64)
    try:
      manager._scan()  # noqa: SLF001
      await _settle()
      assert set(manager.health()) == {"node2"} | {f"x{i}" for i in range(10)}
      addresses.clear()  # every one of them evicted from PeerInfo
      manager._scan()  # noqa: SLF001 - their loops are retired ...
      await _settle()
      manager._scan()  # noqa: SLF001 - ... and, once they ended, their links are forgotten
      assert set(manager.health()) == {"node2"}  # the validator is always reported
      assert manager.dialing() == frozenset()
    finally:
      await manager.stop()

  run(go())


def test_n3_flag_counters_are_bounded_and_keep_validators(node_env: NodeEnv) -> None:
  async def go() -> None:
    manager, _ = _dial_manager(node_env, [], {"node1", "node2"}, max_dialed=1)
    client, server = make_pair()
    serving = asyncio.create_task(manager.accept_inbound(server))
    await client.send_text("not json")  # a failed handshake: the unauthenticated counter
    await serving
    manager.flag("node2", "malformed_message")
    for i in range(MAX_FLAGGED_IDS + 500):
      manager.flag(f"sybil{i}", "malformed_message")
    flags = manager.flags
    assert len(flags) <= MAX_FLAGGED_IDS
    assert flags["node2"] == 1 and flags[UNAUTHENTICATED_KEY] == 1  # never evicted
    assert "sybil0" not in flags and flags[f"sybil{MAX_FLAGGED_IDS + 499}"] == 1  # LRU

  run(go())


class OpeningConnector:
  """Opens an in-memory socket whose far end never answers the handshake."""

  def __init__(self) -> None:
    self.opened: list[Any] = []

  async def connect(self, host: str, port: int, path: str) -> Any:
    client, _server = make_pair()
    self.opened.append(client)
    return client


def test_n5_a_dial_cancelled_mid_handshake_closes_its_socket(node_env: NodeEnv) -> None:
  async def go() -> None:
    addresses = [("x0", "x0", 9000), ("x1", "x1", 9000)]
    manager, connector = _dial_manager(
      node_env,
      addresses,
      {"node1"},
      max_dialed=8,
      connector=OpeningConnector(),
      handshake_timeout=60.0,
    )
    try:
      manager._scan()  # noqa: SLF001
      await _settle()
      assert len(connector.opened) == 2 and not any(ws.closed for ws in connector.opened)
      addresses.pop(0)  # x0 evicted while its handshake waits
      manager._scan()  # noqa: SLF001
      await _settle()
      assert connector.opened[0].closed  # cancelled during authenticate: closed, not leaked
      assert not connector.opened[1].closed
    finally:
      await manager.stop()
    assert all(ws.closed for ws in connector.opened)  # stopping cancels and closes the rest

  run(go())


class SlowToStopConnector:
  """A dial that, once cancelled, takes a while to wind down."""

  def __init__(self) -> None:
    self.dialed: list[str] = []
    self.release = asyncio.Event()

  async def connect(self, host: str, port: int, path: str) -> Any:
    self.dialed.append(host)
    try:
      await asyncio.Event().wait()
    except asyncio.CancelledError:
      await self.release.wait()
      raise
    raise OSError("unreachable")


def test_cr5_no_new_dial_loop_while_the_retired_one_winds_down(node_env: NodeEnv) -> None:
  async def go() -> None:
    addresses = [("x0", "x0", 9000)]
    connector = SlowToStopConnector()
    manager, _ = _dial_manager(node_env, addresses, {"node1"}, max_dialed=8, connector=connector)
    try:
      manager._scan()  # noqa: SLF001
      await _settle()
      addresses.clear()  # evicted: its loop is cancelled but still winding down
      manager._scan()  # noqa: SLF001
      await _settle()
      addresses.append(("x0", "x0", 9000))  # re-registered at once
      manager._scan()  # noqa: SLF001
      await _settle()
      assert "x0" not in manager.dialing() and connector.dialed == ["x0"]  # no overlap
      connector.release.set()
      await _settle()
      manager._scan()  # noqa: SLF001
      await _settle()
      assert "x0" in manager.dialing() and connector.dialed == ["x0", "x0"]
    finally:
      connector.release.set()
      await manager.stop()

  run(go())
