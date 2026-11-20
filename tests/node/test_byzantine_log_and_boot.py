"""Final security review follow-ups (wave D) for boot and the PBFT engine:

- R3: the Byzantine event log is deduplicated on (reason, offender), so a divergence that sync
  re-detects every round cannot evict the original evidence; `BYZANTINE_RESET_ON_BOOT` is the
  operator's explicit reset of the sticky status (events dropped, state file cleared, WARNING).
  M2: the reset is a one-shot DIGEST token of exactly the persisted event list (logged at every
  boot that restores events), so a value forgotten in an env file is refused (WARNING) once the
  evidence changed in any way - even when the number of events stayed the same.
- R9: `PBFT_ALLOW_MISSING_STATE` logs a WARNING on every boot while it is set.
- Finding 13: boot applies the future-timestamp cap; a persisted block stamped beyond the skew
  window makes the chain invalid at that index.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest
from chain_factory import pbft_chain, pow_block, pow_chain, save_chain
from node_helpers import NodeEnv

from node.config import ConfigError, load_config
from node.consensus.pbft.engine import PbftEngine, byzantine_reset_token
from node.consensus.pbft.state_store import PbftState, PbftStateStore, state_path_for
from node.main import create_app
from node.validity_cache import (
  MAX_BYZANTINE_EVENTS,
  QUORUM_BYZANTINE,
  QUORUM_HEALTHY,
)

H = "ab" * 32
EVENTS = [
  {"reason": "two finalized blocks at height 1", "offender": "node3", "at_ms": 11},
  {"reason": "equivocation", "offender": "node4", "at_ms": 22},
]


async def _null_send(message, targets=None):
  return None


def _state_path(node_env: NodeEnv) -> Path:
  return state_path_for(Path(node_env.env["CHAIN_PATH"]))


def _persist_events(node_env: NodeEnv, events: list[dict]) -> PbftStateStore:
  """A restarted node's state file: a vote it signed and the events it had observed."""
  store = PbftStateStore(_state_path(node_env))
  store.save(PbftState(view=0, signed={(0, 1): H}, byzantine_events=[dict(e) for e in events]))
  return store


def _pow(node_env: NodeEnv, **extra: str) -> dict[str, str]:
  return {**node_env.env, "CONSENSUS_MODE": "pow", "EXPECTED_DIFFICULTY": "1", **extra}


# ============================================================ R3 (a): dedupe


def test_repeated_event_is_not_appended_again(node_env: NodeEnv, boot) -> None:
  cache = boot(node_env.env).validity_cache
  cache.flag_byzantine_event("original evidence", offender="node3", at_ms=1)
  for round_no in range(MAX_BYZANTINE_EVENTS * 3):  # sync re-detects it every round
    cache.flag_byzantine_event("peer node3 diverged at height 4", at_ms=100 + round_no)
  events = cache.byzantine_events
  assert events == [
    {"reason": "original evidence", "offender": "node3", "at_ms": 1},
    {"reason": "peer node3 diverged at height 4", "offender": None, "at_ms": 100},
  ]  # the first sighting is kept; the original evidence was not evicted
  assert cache.snapshot.quorum_status == QUORUM_BYZANTINE
  for event in events:  # the stored shape the state-file loader accepts is unchanged
    assert set(event) == {"reason", "offender", "at_ms"}


def test_same_reason_with_another_offender_is_a_distinct_event(node_env: NodeEnv, boot) -> None:
  cache = boot(node_env.env).validity_cache
  cache.flag_byzantine_event("equivocation", offender="node3", at_ms=1)
  cache.flag_byzantine_event("equivocation", offender="node4", at_ms=2)
  cache.flag_byzantine_event("equivocation", offender="node3", at_ms=3)
  assert [(e["offender"], e["at_ms"]) for e in cache.byzantine_events] == [
    ("node3", 1),
    ("node4", 2),
  ]


def test_restore_deduplicates_against_events_reported_since_boot(node_env: NodeEnv, boot) -> None:
  cache = boot(node_env.env).validity_cache
  cache.flag_byzantine_event("equivocation", offender="node4", at_ms=500)  # re-seen after boot
  cache.flag_byzantine_event("new", offender="node2", at_ms=600)
  cache.restore_byzantine_events([*EVENTS, dict(EVENTS[0])])  # a duplicated row in the file
  assert cache.byzantine_events == [
    *EVENTS,  # the persisted (original) sightings win
    {"reason": "new", "offender": "node2", "at_ms": 600},
  ]


def test_engine_does_not_rewrite_the_state_file_for_a_repeated_event(
  node_env: NodeEnv, boot
) -> None:
  context = boot(node_env.env)
  store = _persist_events(node_env, EVENTS)
  PbftEngine(context, send=_null_send, state_store=store)
  context.chain_state.report_byzantine_event(EVENTS[0]["reason"], offender="node3")
  assert context.validity_cache.byzantine_events == EVENTS  # nothing new to persist


# ============================================================ R3 (b): operator reset


TOKEN = byzantine_reset_token(EVENTS)


def test_reset_token_is_a_16_hex_digest_of_the_stored_events() -> None:
  from blockchain_core import sha256_of_canonical

  assert TOKEN == sha256_of_canonical(EVENTS)[:16]
  assert len(TOKEN) == 16 and set(TOKEN) <= set("0123456789abcdef")
  # same count, different evidence (an event replaced under the per-offender cap): new token
  replaced = [EVENTS[0], {**EVENTS[1], "at_ms": 23}]
  assert byzantine_reset_token(replaced) != TOKEN
  assert byzantine_reset_token([dict(e) for e in EVENTS]) == TOKEN  # deterministic


def test_byzantine_reset_on_boot_config(node_env: NodeEnv) -> None:
  assert load_config(node_env.env).byzantine_reset_on_boot is None  # unset: no reset
  for blank in ("", "  "):
    env = {**node_env.env, "BYZANTINE_RESET_ON_BOOT": blank}
    assert load_config(env).byzantine_reset_on_boot is None
  for raw in (TOKEN, f" {TOKEN} ", "0123456789abcdef"):
    env = {**node_env.env, "BYZANTINE_RESET_ON_BOOT": raw}
    assert load_config(env).byzantine_reset_on_boot == raw.strip()
  for bad in ("2", "yes", "true", TOKEN[:15], TOKEN + "0", "ABCDEF0123456789", "g" * 16):
    with pytest.raises(ConfigError, match="BYZANTINE_RESET_ON_BOOT"):
      load_config({**node_env.env, "BYZANTINE_RESET_ON_BOOT": bad})


@pytest.mark.parametrize("bad", [True, 2, "2", "ABCDEF0123456789", "abc", b"0123456789abcdef"])
def test_engine_refuses_a_reset_value_that_is_not_a_token(node_env: NodeEnv, boot, bad) -> None:
  context = boot(node_env.env)
  with pytest.raises(ValueError, match="reset_byzantine_events"):
    PbftEngine(
      context,
      send=_null_send,
      state_store=_persist_events(node_env, EVENTS),
      reset_byzantine_events=bad,
    )


def test_persisted_events_are_restored_without_the_reset(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  context = boot(node_env.env)
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    PbftEngine(context, send=_null_send, state_store=_persist_events(node_env, EVENTS))
  assert context.validity_cache.byzantine_events == EVENTS
  assert context.validity_cache.snapshot.quorum_status == QUORUM_BYZANTINE
  hint = [r for r in caplog.records if f"BYZANTINE_RESET_ON_BOOT={TOKEN}" in r.getMessage()]
  assert len(hint) == 1 and hint[0].levelno == logging.WARNING  # the token, on every boot
  assert "2 persisted Byzantine event(s)" in hint[0].getMessage()


def test_no_token_warning_without_persisted_events(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  context = boot(node_env.env)
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    PbftEngine(context, send=_null_send, state_store=_persist_events(node_env, []))
  assert "BYZANTINE_RESET_ON_BOOT" not in caplog.text


def test_reset_drops_events_clears_the_state_file_and_warns(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  context = boot(node_env.env)
  store = _persist_events(node_env, EVENTS)
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    PbftEngine(context, send=_null_send, state_store=store, reset_byzantine_events=TOKEN)
  assert context.validity_cache.byzantine_events == []
  assert context.validity_cache.snapshot.quorum_status == QUORUM_HEALTHY
  saved = json.loads(_state_path(node_env).read_text(encoding="utf-8"))
  assert saved["byzantine_events"] == []  # cleared on disk at once
  assert saved["signed"] == [[0, 1, H]]  # the vote record is untouched
  warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
  assert any("operator reset of the Byzantine status" in r.getMessage() for r in warnings)
  # the next boot without the flag finds nothing to restore
  PbftEngine(context, send=_null_send, state_store=PbftStateStore(store.path))
  assert context.validity_cache.byzantine_events == []


@pytest.mark.parametrize(
  "stale",
  [
    "0123456789abcdef",  # an arbitrary token
    byzantine_reset_token(EVENTS[:1]),  # the token of the evidence before a new event
    byzantine_reset_token([EVENTS[0], {**EVENTS[1], "at_ms": 23}]),  # same count, replaced
  ],
)
def test_reset_with_a_stale_token_discards_nothing_and_warns(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture, stale: str
) -> None:
  # M2: a value left in the env file after an earlier reset must not erase NEW evidence
  context = boot(node_env.env)
  store = _persist_events(node_env, EVENTS)
  before = store.path.read_bytes()
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    PbftEngine(context, send=_null_send, state_store=store, reset_byzantine_events=stale)
  assert context.validity_cache.byzantine_events == EVENTS  # restored as usual
  assert context.validity_cache.snapshot.quorum_status == QUORUM_BYZANTINE
  assert store.path.read_bytes() == before  # the state file is not touched
  refused = [r for r in caplog.records if "REFUSED" in r.getMessage()]
  assert len(refused) == 1 and refused[0].levelno == logging.WARNING
  assert f"BYZANTINE_RESET_ON_BOOT={stale} REFUSED" in refused[0].getMessage()
  assert f"current token {TOKEN}" in refused[0].getMessage()
  assert "operator reset of the Byzantine status" not in caplog.text


def test_reset_with_no_persisted_events_discards_nothing(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  context = boot(node_env.env)
  store = _persist_events(node_env, [])
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    PbftEngine(context, send=_null_send, state_store=store, reset_byzantine_events=TOKEN)
  assert context.validity_cache.byzantine_events == []
  assert "REFUSED" in caplog.text  # a token for other evidence: refused, harmless


def test_reset_flag_reaches_the_engine_through_create_app(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  save_chain(node_env, pbft_chain(node_env, 1))
  _persist_events(node_env, EVENTS)
  env = {**node_env.env, "INIT_CHAIN": "0"}
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    app = create_app(load_config(env))
  try:
    assert app.state.context.validity_cache.byzantine_events == EVENTS  # default: restored
  finally:
    app.state.context.store.close()
  assert f"BYZANTINE_RESET_ON_BOOT={TOKEN}" in caplog.text  # the boot names the token
  caplog.clear()
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    stale = create_app(load_config({**env, "BYZANTINE_RESET_ON_BOOT": "0123456789abcdef"}))
  try:
    assert stale.state.context.validity_cache.byzantine_events == EVENTS
  finally:
    stale.state.context.store.close()
  assert "REFUSED" in caplog.text
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    app = create_app(load_config({**env, "BYZANTINE_RESET_ON_BOOT": TOKEN}))
  try:
    assert app.state.context.validity_cache.byzantine_events == []
    assert app.state.context.validity_cache.snapshot.quorum_status == QUORUM_HEALTHY
  finally:
    app.state.context.store.close()
  assert json.loads(_state_path(node_env).read_text())["byzantine_events"] == []
  assert "operator reset of the Byzantine status" in caplog.text


# ============================================================ R9: PBFT_ALLOW_MISSING_STATE


def test_allow_missing_state_warns_even_when_the_file_exists(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  context = boot(node_env.env)
  store = _persist_events(node_env, [])
  assert store.exists()
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    PbftEngine(context, send=_null_send, state_store=store, allow_missing_state=True)
  assert any(
    r.levelno == logging.WARNING and "PBFT_ALLOW_MISSING_STATE is set" in r.getMessage()
    for r in caplog.records
  )


def test_no_missing_state_warning_without_the_flag(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  context = boot(node_env.env)
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    PbftEngine(context, send=_null_send, state_store=_persist_events(node_env, []))
  assert "PBFT_ALLOW_MISSING_STATE" not in caplog.text


def test_allow_missing_state_warns_on_boot_through_create_app(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    app = create_app(load_config({**node_env.env, "PBFT_ALLOW_MISSING_STATE": "1"}))
  app.state.context.store.close()
  assert "PBFT_ALLOW_MISSING_STATE is set" in caplog.text


# ============================================================ finding 13: future cap at boot


def _future_chain(node_env: NodeEnv, ahead_ms: int):
  blocks = pow_chain(node_env, 2)
  blocks.append(pow_block(node_env, blocks[-1], 3, timestamp=int(time.time() * 1000) + ahead_ms))
  blocks.append(pow_block(node_env, blocks[-1], 4, timestamp=blocks[-1].timestamp + 1))
  return blocks


def test_boot_marks_a_future_stamped_block_invalid(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  save_chain(node_env, _future_chain(node_env, 3_600_000))  # one hour ahead
  env = _pow(node_env, INIT_CHAIN="0", MAX_FUTURE_SKEW_MS="60000")
  with caplog.at_level(logging.ERROR, logger="node"):
    context = boot(env)
  snapshot = context.validity_cache.snapshot
  assert snapshot.chain_valid is False
  assert snapshot.first_invalid_index == 3
  assert snapshot.failure_type == "timestamp_in_future"
  assert snapshot.tip_index == 4
  assert context.chain_state.extendable is False  # nothing is appended; startup sync heals it
  assert "persisted chain is INVALID" in caplog.text and "timestamp_in_future" in caplog.text


def test_boot_accepts_a_block_within_the_skew_window(node_env: NodeEnv, boot) -> None:
  save_chain(node_env, _future_chain(node_env, 30_000))  # 30 s ahead, cap 2 h
  context = boot(_pow(node_env, INIT_CHAIN="0", MAX_FUTURE_SKEW_MS="7200000"))
  assert context.validity_cache.snapshot.chain_valid is True


def test_an_earlier_checklist_failure_wins_over_a_later_future_block(
  node_env: NodeEnv, boot
) -> None:
  blocks = _future_chain(node_env, 3_600_000)
  save_chain(node_env, blocks)
  path = Path(node_env.env["CHAIN_PATH"])
  data = json.loads(path.read_text(encoding="utf-8"))
  blocks_key = "blocks" if isinstance(data, dict) else None
  rows = data[blocks_key] if blocks_key else data
  rows[1]["proposer_signature"] = rows[2]["proposer_signature"]  # break block 1
  path.write_text(json.dumps(data), encoding="utf-8")
  context = boot(_pow(node_env, INIT_CHAIN="0"))
  snapshot = context.validity_cache.snapshot
  assert snapshot.chain_valid is False
  assert snapshot.first_invalid_index == 1
  assert snapshot.failure_type != "timestamp_in_future"


# ============================================================ N4: revocation breaks history


def _revoke_validator(node_env: NodeEnv, node_id: str) -> None:
  path = node_env.validators_path
  data = json.loads(path.read_text(encoding="utf-8"))
  for entry in data["validators"]:
    if entry["node_id"] == node_id:
      entry["revoked"] = True
  path.write_text(json.dumps(data), encoding="utf-8")


def test_boot_names_a_revoked_key_that_signed_the_invalid_history(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  save_chain(node_env, pbft_chain(node_env, 2))  # commits by node1, node2, node3
  _revoke_validator(node_env, "node3")
  with caplog.at_level(logging.ERROR, logger="node"):
    context = boot({**node_env.env, "INIT_CHAIN": "0"})
  snapshot = context.validity_cache.snapshot
  assert not snapshot.chain_valid and snapshot.first_invalid_index == 1
  revoked = [r for r in caplog.records if "REVOKE" in r.getMessage()]
  assert len(revoked) == 1 and revoked[0].levelno == logging.ERROR
  message = revoked[0].getMessage()
  assert "'node3'" in message and "index 1" in message
  assert "revocation invalidates history signed by that key" in message
  assert "roll back or re-issue the chain" in message and "see docs" in message


def test_no_revocation_error_when_the_revoked_identity_did_not_sign(
  node_env: NodeEnv, boot, caplog: pytest.LogCaptureFixture
) -> None:
  save_chain(node_env, pbft_chain(node_env, 2, signers=2))  # invalid: no commit quorum
  _revoke_validator(node_env, "node4")  # never signed anything here
  with caplog.at_level(logging.ERROR, logger="node"):
    context = boot({**node_env.env, "INIT_CHAIN": "0"})
  assert not context.validity_cache.snapshot.chain_valid
  assert "persisted chain is INVALID" in caplog.text
  assert "REVOKE" not in caplog.text


def test_revoked_signers_cover_proposers_commits_and_issuers_up_to_the_index(
  node_env: NodeEnv,
) -> None:
  from types import SimpleNamespace

  from node.context import _revoked_signers

  def entry(identity: str, revoked: bool) -> SimpleNamespace:
    return SimpleNamespace(identity=identity, revoked=revoked)

  chain = pbft_chain(node_env, 3)  # proposer node1; commits node1..node3; issuer1 records
  validators = SimpleNamespace(entries=(entry("node1", True), entry("node4", True)))
  issuers = SimpleNamespace(entries=(entry("issuer1", True),))
  assert _revoked_signers(validators, issuers, chain, 1) == ["issuer1", "node1"]
  assert _revoked_signers(validators, issuers, chain[:1], None) == []  # genesis: no signers
  none = SimpleNamespace(entries=(entry("node1", False),))
  assert _revoked_signers(none, SimpleNamespace(entries=()), chain, 2) == []
