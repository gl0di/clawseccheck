"""B333 / B353 gated on whether a configured agent runs the Codex app-server harness.

Both mechanisms are inert off that harness, and the checks used to say only "this audit does
not determine which". ``clawseccheck.harnessruntime`` now answers yes / no / unknown; this
file pins what each answer does to each check, and that the ``unknown`` branch is the OLD
wording byte for byte (so every hermetic run, every pre-9.4 build and every fingerprint
keeps its verdict).

The port itself is validated in ``test_harnessruntime_battery.py`` /
``test_harnessruntime_dist_grounding.py``; nothing here re-derives vendor semantics.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck import harnessruntime as hr
from clawseccheck.catalog import PASS, WARN
from clawseccheck.collector import collect

VALIDATED = "2026.9.4"
BELOW = "2026.8.2"

_APPROVE = {"mcp": {"servers": {"ops": {"command": "c",
                                        "codex": {"defaultToolsApprovalMode": "approve"}}}}}


def _models(defaults_model="anthropic/claude-x", **extra):
    return {"agents": {"defaults": {"model": defaults_model, **extra}}}


def _cfg(base, *parts):
    out = json.loads(json.dumps(base))
    for p in parts:
        for k, v in p.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k].update(v)
            else:
                out[k] = v
    return out


def _run(cfg, check_id, installed=VALIDATED):
    home = Path(tempfile.mkdtemp(prefix="b708-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = installed
    return next(f for f in C.run_all(ctx) if f.id == check_id)


def _b353(cfg, installed=VALIDATED):
    return _run(cfg, "B353", installed)


def _b333(cfg, installed=VALIDATED):
    return _run(cfg, "B333", installed)


def _tools_server(tools, **spec):
    return {"mcp": {"servers": {"ops": {"command": "c", "tools": tools, **spec}}}}


_RO = [{"name": "read_things", "annotations": {"readOnlyHint": True}}]


# ======================================================================================
# 1. B353 -- the three answers
# ======================================================================================

def test_b353_yes_from_a_codex_pin_states_the_harness_as_fact():
    f = _b353(_cfg(_APPROVE, _models(models={"anthropic/claude-x": {"agentRuntime": {"id": "codex"}}})))
    assert f.status == WARN
    assert "configured to run the Codex app-server harness" in f.detail
    assert "does not determine" not in f.detail
    assert any("codex harness:" in e for e in (f.evidence or []))
    assert "is inert on your setup" not in f.fix, "the conditional escape hatch is now false"


def test_b353_yes_from_an_openai_primary():
    f = _b353(_cfg(_APPROVE, _models("openai/gpt-5")))
    assert f.status == WARN
    assert "configured to run the Codex app-server harness" in f.detail


def test_b353_no_is_a_pass_that_says_what_it_cannot_see():
    f = _b353(_cfg(_APPROVE, _models("anthropic/claude-x")))
    assert f.status == PASS
    assert "no configured model resolves to the Codex" in f.detail
    assert "cron job's own model override" in f.detail and "/model" in f.detail
    assert "ops" in f.detail, "the pre-approving server is still named"


def test_b353_unknown_is_todays_wording_byte_for_byte():
    """No model configured -> the default (OpenAI) applies -> unknown. The finding must be
    exactly what a build the gate does not cover emits for the same config."""
    cfg = _cfg(_APPROVE, {"agents": {"defaults": {}}})
    gated = _b353(cfg, VALIDATED)
    old = _b353(cfg, BELOW)
    assert gated.status == old.status == WARN
    assert gated.detail == old.detail
    assert gated.fix == old.fix
    assert "does not determine" in gated.detail


def test_b353_below_the_validated_build_never_gates():
    cfg = _cfg(_APPROVE, _models("anthropic/claude-x"))
    f = _b353(cfg, BELOW)
    assert f.status == WARN and "does not determine" in f.detail


def test_b353_hermetic_run_with_no_known_build_stays_unknown():
    home = Path(tempfile.mkdtemp(prefix="b708-"))
    p = home / "openclaw.json"
    p.write_text(json.dumps(_cfg(_APPROVE, _models())), encoding="utf-8")
    os.chmod(p, 0o600)
    ctx = collect(home)
    assert getattr(ctx, "installed_dist_version", None) in (None, "")
    f = next(f for f in C.run_all(ctx) if f.id == "B353")
    assert f.status == WARN and "does not determine" in f.detail


def test_a_config_stamp_at_the_floor_counts_but_an_older_one_does_not():
    base = _cfg(_APPROVE, _models())
    # a stamp NEWER than the validated window is not extrapolated from: it degrades to WARN
    for stamp, expect in (("2026.9.4", PASS), ("2026.9.9", WARN), ("2026.7.1", WARN),
                          ("2026.8.2", WARN)):
        cfg = _cfg(base, {"meta": {"lastTouchedVersion": stamp}})
        home = Path(tempfile.mkdtemp(prefix="b708-"))
        p = home / "openclaw.json"
        p.write_text(json.dumps(cfg), encoding="utf-8")
        os.chmod(p, 0o600)
        f = next(f for f in C.run_all(collect(home)) if f.id == "B353")
        assert f.status == expect, (stamp, f.status)


def test_b353_never_emits_fail():
    for m in ("openai/gpt-5", "anthropic/c", None):
        cfg = _cfg(_APPROVE, _models(m) if m else {"agents": {"defaults": {}}})
        assert _b353(cfg).status != "FAIL"


# ======================================================================================
# 2. B333 -- the same three answers on the modern leg
# ======================================================================================

def test_b333_yes():
    f = _b333(_cfg(_tools_server(_RO), _models("openai/gpt-5")))
    assert f.status == WARN
    assert "configured to run the Codex app-server harness" in f.detail
    assert "WHETHER THAT IS LIVE HERE" not in f.detail
    assert "If none does" not in f.fix


def test_b333_no_is_a_pass_with_the_runtime_caveat():
    f = _b333(_cfg(_tools_server(_RO), _models("anthropic/claude-x")))
    assert f.status == PASS
    assert "no configured model resolves to the Codex" in f.detail
    assert "cron job's own model override" in f.detail


def test_b333_unknown_keeps_the_conditional_sentence():
    cfg = _cfg(_tools_server(_RO), {"agents": {"defaults": {}}})
    gated, old = _b333(cfg, VALIDATED), _b333(cfg, "2026.8.1")
    assert gated.status == old.status == WARN
    assert gated.detail == old.detail and gated.fix == old.fix
    assert "WHETHER THAT IS LIVE HERE" in gated.detail


def test_b333_legacy_build_is_untouched():
    f = _b333(_cfg(_tools_server(_RO), _models("anthropic/claude-x")), "2026.7.1-2")
    assert f.status == WARN and "does not read destructiveHint/readOnlyHint" in f.detail


# ======================================================================================
# 3. The `no` preconditions -- flip each one and the answer must leave `no`
#    (a mutation check: a deleted precondition turns exactly one of these red)
# ======================================================================================

_V = hr.ORACLE_MIN


def _ans(cfg):
    return hr.codex_harness_reach(cfg, _V, environ={}).answer


def test_the_no_baseline():
    assert _ans(_models("anthropic/c")) == hr.NO


def test_no_precondition_every_agent_names_a_model():
    assert _ans({"agents": {"defaults": {"model": "anthropic/c"},
                            "entries": {"a": {"model": "anthropic/d"}, "b": {}}}}) == hr.NO
    assert _ans({"agents": {"defaults": {}, "entries": {"a": {"model": "anthropic/d"}, "b": {}}}}) \
        == hr.UNKNOWN
    assert _ans({"agents": {"defaults": {}}}) == hr.UNKNOWN
    # a record with only fallbacks has no primary: the agent starts on the build default
    assert _ans(_models({"fallbacks": ["anthropic/c"]})) == hr.UNKNOWN


def test_no_precondition_no_openai_ref_anywhere():
    for extra in ({"heartbeat": {"model": "openai/gpt-5"}}, {"subagents": {"model": "openai/g"}},
                  {"imageModel": "openai/gpt-image-1"}, {"models": {"openai/gpt-5": {}}}):
        assert _ans(_models("anthropic/c", **extra)) == hr.UNKNOWN, extra
    assert _ans({**_models("anthropic/c"), "tts": {"summaryModel": "openai/x"}}) == hr.UNKNOWN


def test_no_precondition_every_ref_names_a_provider():
    assert _ans(_models("anthropic/c", heartbeat={"model": "gpt-5"})) == hr.UNKNOWN
    assert _ans(_models("sonnet")) == hr.UNKNOWN


def test_no_precondition_no_plugin_pin():
    assert _ans({**_models("anthropic/c"), "models": {"providers": {"x": {"agentRuntime": {"id": "foo"}}}}}) \
        == hr.UNKNOWN
    assert _ans({**_models("anthropic/c"), "models": {"providers": {"x": {"agentRuntime": {"id": "pi"}}}}}) \
        == hr.NO
    # the deprecated whole-agent spelling is read by the runtime, so `no` may not ignore it
    assert _ans(_models("anthropic/c", agentRuntime={"id": "codex"})) == hr.UNKNOWN


def test_no_precondition_a_known_build_inside_the_validated_window():
    assert hr.codex_harness_reach(_models("anthropic/c"), None).answer == hr.UNKNOWN
    assert hr.codex_harness_reach(_models("anthropic/c"), (2026, 9, 3)).answer == hr.UNKNOWN
    assert hr.codex_harness_reach(_models("anthropic/c"), (2026, 9, 5)).answer == hr.UNKNOWN
    assert hr.codex_harness_reach(_models("anthropic/c"), (2027, 1, 1)).answer == hr.UNKNOWN


def test_no_precondition_one_provider_spelled_two_ways():
    """The vendor MERGES two spellings of one provider key, and the merge throws on some
    shapes, so the port must not answer. Without the bail this config is a definite `no`."""
    cfg = {**_models("anthropic/c"),
           "models": {"providers": {"anthropic": {}, " Anthropic ": {}}}}
    assert _ans(cfg) == hr.UNKNOWN
    one = {**_models("anthropic/c"), "models": {"providers": {"anthropic": {}}}}
    assert _ans(one) == hr.NO


@pytest.mark.parametrize("cfg", [
    {"models": {"providers": {"openai": {"baseUrl": "http://x/v1"}}}, **_models("openai/gpt-5")},
    _models("openai/gpt-5", params={"temperature": 1}),
    _models("openai/gpt-5", models={"openai/gpt-5": {"agentRuntime": {"id": "pi"}}}),
    {"env": {"OPENAI_BASE_URL": "http://x"}, **_models("openai/gpt-5")},
], ids=["authored-route", "params", "competing-pin", "env-block"])
def test_yes_via_openai_needs_nothing_that_could_move_the_route(cfg):
    assert _ans(cfg) == hr.UNKNOWN


def test_yes_via_openai_respects_the_process_environment():
    assert hr.codex_harness_reach(_models("openai/gpt-5"), _V, environ={}).answer == hr.YES
    assert hr.codex_harness_reach(_models("openai/gpt-5"), _V,
                                  environ={"OPENAI_BASE_URL": "http://x"}).answer == hr.UNKNOWN


def test_an_openai_default_that_every_agent_overrides_is_not_yes():
    """`agents.defaults.model` is openai but the only agent runs anthropic: nothing runs
    Codex from config, yet `no` is refused because the defaults ref exists."""
    cfg = {"agents": {"defaults": {"model": "openai/gpt-5"},
                      "entries": {"a": {"model": "anthropic/c"}}}}
    assert _ans(cfg) == hr.UNKNOWN


# ======================================================================================
# 4. Tool-name truncation no longer corrupts the toolFilter reachability gate
# ======================================================================================

def _long(n=250):
    return "t" * n


def _annotated(name):
    return [{"name": name, "annotations": {"readOnlyHint": True}}]


def test_a_truncated_name_is_reachable_under_a_matching_include():
    """Before: the name was cut to 200 chars, then compared to an `include` naming the full
    250, so the tool looked filtered OUT and B333 reported nothing (false negative)."""
    name = _long()
    cfg = _cfg(_tools_server(_annotated(name), toolFilter={"include": [name]}), _models("openai/gpt-5"))
    f = _b333(cfg)
    assert f.status == WARN
    assert "(name truncated)" in f.detail


def test_a_truncated_name_under_an_exclude_is_conservatively_reported_and_marked():
    """Before: the same cut made an `exclude` for the full name miss, so the excluded tool
    WAS reported with a confident name. Still reported (we cannot tell), but marked."""
    name = _long()
    cfg = _cfg(_tools_server(_annotated(name), toolFilter={"exclude": [name]}), _models("openai/gpt-5"))
    f = _b333(cfg)
    assert f.status == WARN and "(name truncated)" in f.detail


def test_an_ordinary_name_still_honours_the_filter():
    cfg = _cfg(_tools_server(_annotated("read_things"), toolFilter={"exclude": ["read_things"]}),
               _models("openai/gpt-5"))
    assert _b333(cfg).status == PASS


def test_the_truncation_flag_is_only_set_past_the_cap():
    from clawseccheck import mcpsurface
    s = mcpsurface.from_tool_defs("s", [{"name": "a" * 200}, {"name": "a" * 201}])
    assert [t.name_truncated for t in s.tools] == [False, True]
