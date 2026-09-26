"""B351 (re-grounded) — code mode swaps the model's tool surface for `exec` + `wait`.

Was a FALSE PASS from OpenClaw 2026.8.1 onward: a THIRD activation layer (a per-exact-
model-key override, `agent.models[K].codeMode` / `agents.defaults.models[K].codeMode`)
that the check never read, on top of the two it already knew about. On top of that,
2026.9.6 changed the DEFAULT for an entirely-unset `tools.codeMode` from hardcoded-off
to automatic activation (`"auto"`) with an unsandboxed `node:vm` executor by default.

Grounded on the real resolver, EXECUTED across npm tarballs 7.1 through 9.6:

    normalizeCodeModeRawConfig(v)   code-mode-D5mNEiYV.js:36-41
        true    -> {enabled: true}    <- the boolean shorthand is REAL
        false   -> {enabled: false}
        "auto"  -> {enabled: "auto"}  <- valid from 8.1, not yet the unset-key DEFAULT
        record  -> itself
        else    -> undefined

    resolveCodeModeConfig(...), the real 4-input precedence (JS `??`, not `||`):
        agent.models[key].codeMode
          ?? agent.tools.codeMode.enabled
          ?? defaults.models[key].codeMode
          ?? global tools.codeMode.enabled (or the version default, if entirely unset)

Three lying-PASSes are pinned here: reading `.enabled` off the boolean shorthand sees
nothing and reports "off"; reading only `tools.codeMode` misses an `agents.list[]` entry
that turns it on independently; and reading only the first two layers misses
`agents.defaults.models[K].codeMode` / an agent's own `models[K].codeMode`, which is what
made this check lie for a full release cycle (2026.8.1 - 9.6, confirmed executable).

The default-flip itself follows the SAME version-forked-verdict pattern this project
already uses for B363/B-833 (see `_code_mode_default` in `checks/_shared.py` and
`tests/test_b833_cross_context_default_flip.py`): the build is injected through
`Context.installed_dist_version` or `meta.lastTouchedVersion`, offline and read-only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, MEDIUM, PASS, UNKNOWN, WARN
from clawseccheck.collector import agent_roster
from clawseccheck.checks import (
    CHECKS,
    _B351_DEFAULT_UNKNOWN,
    _CODE_MODE_AUTO_DEFAULT_MIN,
    _CODE_MODE_OFF_MEASURED_MIN,
    _b351_enabled,
    _b351_executor,
    _b351_first_set,
    _b351_normalize_agent_id,
    _b351_raw_code_mode,
    _b351_read_enabled,
    _b351_resolvable_agents,
    _b351_resolve,
    _code_mode_default,
    check_code_mode_tool_surface,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _f(name: str):
    return check_code_mode_tool_surface(collect(FIXTURES / name))


def _ctx(cfg, tmp_path, version=None):
    return Context(home=tmp_path, config=cfg, config_found=True,
                   installed_dist_version=version)


def _stamped(version, cfg=None):
    out = dict(cfg or {})
    out["meta"] = {"lastTouchedVersion": version}
    return out


# --------------------------------------------------------------- off stays quiet
@pytest.mark.parametrize("name", [
    "clean_b351_codemode_false_shorthand",
    "clean_b351_codemode_object_disabled",
    "clean_b351_codemode_defaults_model_disabled",
])
def test_clean_fixtures_pass(name):
    """These all set an EXPLICIT false somewhere in the chain, so the verdict is
    PASS regardless of which OpenClaw build is installed (unlike the fully-unset
    shape below, which now honestly reports UNKNOWN absent build info)."""
    f = _f(name)
    assert f.status == PASS, f"{name}: expected PASS, got {f.status}: {f.detail}"
    assert "OpenClaw Code Mode (tools.codeMode) is off" in f.detail


def test_the_fully_unset_fixture_is_now_unknown_not_a_hedged_pass():
    """THE regression this re-grounding exists to fix, in miniature: a config that never
    mentions tools.codeMode used to PASS unconditionally. It now honestly reports UNKNOWN
    when the installed OpenClaw build cannot be determined (the hermetic test harness,
    like a library caller that never asked for dist info) -- releases up to 2026.9.5
    leave it off when unset, 2026.9.6+ auto-activates it for some models.
    """
    f = _f("clean_b351_codemode_absent")
    assert f.status == UNKNOWN, f"expected UNKNOWN, got {f.status}: {f.detail}"
    assert "could not be determined" in f.detail


# --------------------------------------------------------------- lying-PASS #1
def test_the_boolean_shorthand_is_not_missed():
    """`codeMode: true` has no `.enabled` key at all.

    A check written as `dig(cfg, "tools.codeMode.enabled")` returns None here and reports
    the feature off — on the shape most likely to be typed by hand. This is the whole
    reason the check mirrors the vendor's normaliser instead of reading a nested key.
    """
    f = _f("bad_b351_codemode_true_shorthand")
    assert f.status == WARN, f"got {f.status}: {f.detail}"
    assert "on for every agent" in f.detail


# --------------------------------------------------------------- lying-PASS #2
def test_an_agent_can_turn_it_on_while_global_is_off():
    """The per-agent override, which a global-only read cannot see."""
    f = _f("bad_b351_codemode_agent_only")
    assert f.status == WARN, f"got {f.status}: {f.detail}"
    assert "off globally but ON for" in f.detail
    assert "builder" in f.detail
    assert any("builder" in e for e in (f.evidence or [])), "the agent must reach evidence"


def test_the_agent_that_did_not_enable_it_is_not_named():
    """`main` carries no codeMode; naming it would misattribute the finding."""
    f = _f("bad_b351_codemode_agent_only")
    assert "main" not in f.detail.replace("domain", "")


# --------------------------------------------------------------- narrowing is not a hole
def test_global_on_with_an_agent_narrowed_off_still_reports():
    """Global-on remains on for any agent id NOT in agents.list.

    `resolveAgentEntry` returns undefined for an unlisted id, so `agentRaw` is undefined
    and the global value is used wholesale — narrowing one listed agent does not turn the
    feature off. The detail must say so rather than implying it is contained.
    """
    f = _f("bad_b351_codemode_global_on_agent_narrowed")
    assert f.status == WARN
    assert "on globally" in f.detail and "narrowed off" in f.detail


def test_an_agent_object_without_enabled_inherits_global(tmp_path):
    """`{...globalRaw, ...agentRaw}`: an agent object carrying only tuning keys does NOT
    reset `enabled`, so global's value survives the spread."""
    cfg = {"tools": {"codeMode": {"enabled": True}},
           "agents": {"list": [{"id": "a", "tools": {"codeMode": {"timeoutMs": 100}}}]}}
    assert check_code_mode_tool_surface(_ctx(cfg, tmp_path)).status == WARN


# --------------------------------------------------------------- the vendor's own gate
def test_only_a_real_boolean_enables_it(tmp_path):
    """`readBoolean(raw.enabled, false)` — a truthy non-bool is NOT on."""
    for truthy in ("true", 1, "yes", [1]):
        cfg = {"tools": {"codeMode": {"enabled": truthy}}}
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
        assert f.status == PASS, f"{truthy!r}: got {f.status}"


def test_the_normaliser_matches_the_vendors_shapes():
    assert _b351_raw_code_mode(True) == {"enabled": True}
    assert _b351_raw_code_mode(False) == {"enabled": False}
    assert _b351_raw_code_mode({"enabled": True}) == {"enabled": True}
    for junk in ("on", 1, [], None, 0.5):
        assert _b351_raw_code_mode(junk) is None, junk
    assert _b351_enabled({}) is False
    assert _b351_enabled({"enabled": True}) is True
    assert _b351_enabled({"enabled": "true"}) is False


# --------------------------------------------------------------- UNKNOWN, not a fake PASS
def test_an_unread_config_is_unknown(tmp_path):
    f = check_code_mode_tool_surface(Context(home=tmp_path, config={}, config_found=False))
    assert f.status == UNKNOWN
    assert f.not_applicable is False, "nothing was read — this is a real UNKNOWN"


def test_a_read_but_empty_config_is_not_applicable(tmp_path):
    f = check_code_mode_tool_surface(Context(home=tmp_path, config={}, config_found=True))
    assert f.status == UNKNOWN and f.not_applicable is True


# --------------------------------------------------------------- hostile shapes
def test_malformed_shapes_do_not_raise(tmp_path):
    for cfg in (
        {"tools": "minimal"},
        {"tools": {"codeMode": "on"}},
        {"tools": {"codeMode": []}},
        {"agents": {"list": "not-a-list"}},
        {"agents": {"list": [None, 7, "x"]}},
        {"tools": {"codeMode": True}, "agents": {"list": [{"tools": "no"}]}},
    ):
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
        assert f.status in (PASS, WARN, UNKNOWN), cfg
        assert "\n" not in f.detail


def test_an_agent_with_no_id_is_labelled_by_the_id_it_resolves_to(tmp_path):
    """An entry with no `id` is NOT skipped — `normalizeAgentId(undefined)` returns the
    default agent id, so the vendor reaches it as `main`. Labelling it by list index
    would name something the resolver never produces."""
    cfg = {"agents": {"list": [{"tools": {"codeMode": True}}]}}
    f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
    assert f.status == WARN
    assert "agents.list[main]" in f.detail


# ------------------------------------------------- agent identity is the vendor's
# Found by an independent adversarial pass: the check looped raw list entries while the
# vendor resolves by NORMALISED id, first match wins. It reported an agent that cannot
# exist. Every expectation below was produced by EXECUTING the installed dist's own
# `normalizeAgentId`, not by reading its regex.

_VENDOR_NORMALIZED = {
    None: "main", "": "main", "   ": "main", "!!!": "main",
    "main": "main", "Main": "main", "  MAIN  ": "main",
    "Legacy": "legacy", "my agent": "my-agent", "-x-": "x", "builder": "builder",
    "a" * 70: "a" * 64,
}


@pytest.mark.parametrize("raw,expected", list(_VENDOR_NORMALIZED.items()))
def test_the_id_port_matches_the_vendor(raw, expected):
    assert _b351_normalize_agent_id(raw) == expected


def test_a_non_string_id_is_treated_as_absent():
    """The schema types `id` as a string, so a number never loads; the vendor would
    throw on `(5).trim()`. Treating it as absent is the non-crashing equivalent."""
    assert _b351_normalize_agent_id(5) == "main"


def test_a_shadowed_duplicate_agent_is_not_reported(tmp_path):
    """THE FALSE POSITIVE. `"Main"` and `"main"` normalise to one id, and
    `resolveAgentEntry` takes the FIRST match — so the second entry is unreachable and
    its codeMode never applies. Verified against the real dist: `listAgentIds` yields
    `["main"]` and resolving `main` gives enabled=false.
    """
    cfg = {"tools": {"codeMode": False},
           "agents": {"list": [{"id": "Main", "name": "Primary"},
                               {"id": "main", "name": "Legacy",
                                "tools": {"codeMode": True}}]}}
    f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
    assert f.status == PASS, f"shadowed entry must not fire: {f.detail}"


def test_the_first_entry_wins_including_when_it_enables(tmp_path):
    """The positive control for the test above: swap the order and it MUST fire, so the
    de-dup cannot be a blanket silencer."""
    cfg = {"tools": {"codeMode": False},
           "agents": {"list": [{"id": "main", "tools": {"codeMode": True}},
                               {"id": "Main"}]}}
    f = check_code_mode_tool_surface(_ctx(cfg, tmp_path))
    assert f.status == WARN and "agents.list[main]" in f.detail


def test_an_unnamed_entry_collides_with_an_explicit_main(tmp_path):
    """The collision is not hypothetical: no-id normalises to `main`, so an entry with
    no id and one called `main` are the same agent.

    Nothing in this config sets tools.codeMode anywhere, so a definite build is
    supplied (any pre-9.6 release resolves an entirely-unset key OFF) -- otherwise this
    would only prove UNKNOWN, which says nothing about the collision this test exists
    to pin. See ``test_the_fully_unset_fixture_is_now_unknown_not_a_hedged_pass`` for
    that build-unknown case on its own.
    """
    cfg = {"agents": {"list": [{"id": "main"}, {"tools": {"codeMode": True}}]}}
    assert check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.8.1")).status == PASS
    # B-699: the helper now takes the normalised roster, so the same collision is asserted
    # through `agent_roster` — which is also what proves it holds for `agents.entries`.
    ids = [aid for aid, _ in _b351_resolvable_agents(agent_roster(cfg))]
    assert ids == ["main"], ids


# ------------------------------------------------- the claim is scoped to one engine
def test_the_pass_text_names_the_engine_it_actually_read(tmp_path):
    """A second, unrelated path reaches the same user-visible property:
    `plugins.entries.<name>.config.appServer.codeModeOnly` drives Codex app-server runs
    through a different engine this check does not read. An unqualified "code mode is
    off" would be believed and would be wrong there, so the verdict names OpenClaw Code
    Mode specifically. A definite pre-9.6 build is supplied so this resolves PASS rather
    than the now-honest UNKNOWN an unset key gets absent build info.
    """
    f = check_code_mode_tool_surface(
        _ctx({"tools": {"profile": "minimal"}}, tmp_path, "2026.8.1"))
    assert f.status == PASS
    assert "OpenClaw Code Mode (tools.codeMode) is off" in f.detail


# --------------------------------------------------------------- wiring and doctrine
def test_the_check_is_actually_registered():
    assert check_code_mode_tool_surface in CHECKS


def test_it_never_fails():
    for name in ("bad_b351_codemode_true_shorthand", "bad_b351_codemode_agent_only",
                 "bad_b351_codemode_global_on_agent_narrowed"):
        assert _f(name).status != "FAIL", name


def test_catalog_entry_matches_what_the_check_emits():
    meta = BY_ID["B351"]
    assert meta.severity == MEDIUM and meta.surface == "tools"
    emitted = _f("bad_b351_codemode_true_shorthand")
    assert emitted.id == "B351" and emitted.title == meta.title


# =========================================================================================
# THE BUILD ANSWER — _code_mode_default, mirroring test_b833_cross_context_default_flip.py's
# TestCrossContextDefault pattern exactly.
# =========================================================================================
class TestCodeModeDefault:
    @pytest.mark.parametrize("installed, expected", [
        ("2026.9.5", "off"),
        ("2026.9.5-1", "off"),
        ("2026.9.4", "off"),
        ("2026.8.1", "off"),
        ("2026.7.1", "off"),          # the oldest release whose resolver was read
        ("2026.7.1-2", "off"),
        ("2026.6.34", "unknown"),     # older than the measured series: never extrapolated
        ("2026.6.9", "unknown"),
        ("0.0.0", "unknown"),         # not a calendar release: no confident safe verdict
        ("2026.9", "unknown"),        # ... nor is a two-part string
        ("2026.9.6", "auto"),
        ("2026.9.6-1", "auto"),       # a suffix on the threshold itself sorts at/above it
        ("2026.10.1", "auto"),        # calendar-numeric, not lexicographic
        ("2027.1.1", "auto"),
        ("2026.9.6-beta.1", "unknown"),   # a pre-release is unorderable, never assumed
        ("not a version", "unknown"),
        ("", "unknown"),
    ])
    def test_installed_version_decides_outright(self, tmp_path, installed, expected):
        assert _code_mode_default(_ctx({}, tmp_path, installed)) == expected

    def test_an_installed_version_beats_a_contradicting_stamp(self, tmp_path):
        ctx = _ctx(_stamped("2026.9.6"), tmp_path, "2026.9.5")
        assert _code_mode_default(ctx) == "off"
        ctx = _ctx(_stamped("2026.9.5"), tmp_path, "2026.9.6")
        assert _code_mode_default(ctx) == "auto"

    def test_a_stamp_at_or_after_the_flip_proves_auto(self, tmp_path):
        assert _code_mode_default(_ctx(_stamped("2026.9.6"), tmp_path)) == "auto"
        assert _code_mode_default(_ctx(_stamped("2026.9.8"), tmp_path)) == "auto"

    @pytest.mark.parametrize("stamp", ["2026.9.5", "2026.8.1", "2026.7.1-2", "", None])
    def test_a_stale_stamp_never_proves_off(self, tmp_path, stamp):
        cfg = {} if stamp is None else _stamped(stamp)
        assert _code_mode_default(_ctx(cfg, tmp_path)) == "unknown"

    def test_no_version_at_all_is_unknown(self, tmp_path):
        assert _code_mode_default(_ctx({}, tmp_path)) == "unknown"

    def test_the_thresholds_are_the_measured_releases(self):
        assert _CODE_MODE_AUTO_DEFAULT_MIN == (2026, 9, 6)
        assert _CODE_MODE_OFF_MEASURED_MIN == (2026, 7, 1)


# =========================================================================================
# THE PRIMITIVE HELPERS — _b351_first_set (JS `??`), _b351_read_enabled, and the "auto"
# literal in the vendor's own normaliser.
# =========================================================================================
class TestB351PrimitiveHelpers:
    def test_first_set_skips_only_none(self):
        assert _b351_first_set(None, None, False) is False
        assert _b351_first_set(None, "yes", True) == "yes"
        assert _b351_first_set(None, None, None) is None
        assert _b351_first_set(False, True) is False  # the FIRST non-None wins, not the truthiest

    def test_read_enabled_only_trusts_bool_or_the_auto_literal(self):
        assert _b351_read_enabled(True) is True
        assert _b351_read_enabled(False) is False
        assert _b351_read_enabled("auto") == "auto"
        for junk in ("true", 1, [1], "Auto", None, "yes", 0):
            assert _b351_read_enabled(junk) is False, junk

    def test_the_auto_literal_normalises_like_the_boolean_shorthand(self):
        assert _b351_raw_code_mode("auto") == {"enabled": "auto"}
        assert _b351_raw_code_mode("Auto") is None  # case-sensitive, matches the schema literal


# =========================================================================================
# THE THIRD ACTIVATION LAYER — the real vendor precedence chain, `_b351_resolve`, unit
# tested directly before trusting the full-check integration below.
# =========================================================================================
class TestB351Resolve:
    def test_degenerates_to_the_old_two_layer_merge_when_there_is_no_model_key(self):
        # an agent object missing `enabled` inherits whatever the global scope resolves to
        agent_no_enabled = {"tools": {"codeMode": {"timeoutMs": 100}}}
        assert _b351_resolve({"enabled": True}, "off", agent_no_enabled, {}, None) is True
        # the agent's own `enabled` wins over global
        agent_false = {"tools": {"codeMode": {"enabled": False}}}
        assert _b351_resolve({"enabled": True}, "off", agent_false, {}, None) is False

    def test_third_layer_defaults_models_override_beats_a_global_false(self):
        """THE confirmed real-world bug: global false, agents.defaults.models[K]: true
        resolves ON -- and did so from OpenClaw 2026.8.1 onward, not just 9.6."""
        defaults_models = {"anthropic/claude-opus-4-8": {"codeMode": True}}
        val = _b351_resolve({"enabled": False}, "off", {},
                             defaults_models, "anthropic/claude-opus-4-8")
        assert val is True

    def test_agents_own_model_key_false_wins_over_defaults_true_for_the_same_key(self):
        """The two dicts are NEVER merged: an agent's own explicit false for a model key
        wins over defaults.models[K]: true for that SAME key."""
        defaults_models = {"p/m": {"codeMode": True}}
        agent_entry = {"models": {"p/m": {"codeMode": False}}}
        assert _b351_resolve(None, "off", agent_entry, defaults_models, "p/m") is False

    def test_a_model_key_unset_everywhere_falls_through_to_the_global_source(self):
        assert _b351_resolve({"enabled": True}, "off", {}, {}, "p/m") is True
        assert _b351_resolve(None, "off", {}, {}, "p/m") is False
        assert _b351_resolve(None, "auto", {}, {}, "p/m") == "auto"
        assert _b351_resolve(None, "unknown", {}, {}, "p/m") is _B351_DEFAULT_UNKNOWN

    def test_an_invalid_but_non_none_value_wins_and_is_then_read_as_false(self):
        """`_b351_first_set` must not skip a truthy-junk value just because it is not a
        real boolean/"auto" -- it WINS the `??` chain outright and is only THEN read as
        False, exactly like the vendor never re-consulting a later `??` operand."""
        agent_entry = {"models": {"p/m": {"codeMode": "yes"}}}
        defaults_models = {"p/m": {"codeMode": True}}
        assert _b351_resolve(None, "auto", agent_entry, defaults_models, "p/m") is False

    def test_a_dotted_model_key_is_read_by_plain_dict_get_not_dig(self):
        key = "gpt-5.6-sol"
        defaults_models = {key: {"codeMode": True}}
        assert _b351_resolve(None, "off", {}, defaults_models, key) is True

    def test_global_raw_present_but_missing_enabled_falls_back_to_false_not_the_default(self):
        """An explicit-but-incomplete tools.codeMode object (only `executor` set, no
        `enabled`) is not the same shape as an ENTIRELY absent key -- the version default
        applies only to the latter. This still resolves to a safe answer (False), never
        a silently-true one."""
        assert _b351_resolve({"executor": "quickjs"}, "auto", {}, {}, None) is False


# =========================================================================================
# THE EXECUTOR — _b351_executor, unit tested directly.
# =========================================================================================
class TestB351Executor:
    def test_pre_9_6_default_is_always_quickjs_wasi_regardless_of_an_executor_key(self):
        assert _b351_executor({"enabled": True, "executor": "node"}, None, "off") == "quickjs-wasi"
        assert _b351_executor({"enabled": True}, None, "off") == "quickjs-wasi"

    def test_9_6_default_with_no_executor_key_is_node(self):
        assert _b351_executor(None, None, "auto") == "node"
        assert _b351_executor({"enabled": "auto"}, None, "auto") == "node"

    def test_an_explicit_quickjs_executor_is_honoured_on_auto(self):
        assert _b351_executor({"enabled": "auto", "executor": "quickjs"}, None, "auto") == "quickjs"

    def test_an_agents_own_executor_overrides_the_global_one_entirely(self):
        global_raw = {"enabled": True, "executor": "quickjs"}
        agent_raw = {"executor": "node"}
        assert _b351_executor(global_raw, agent_raw, "auto") == "node"

    def test_an_unrecognised_executor_value_is_treated_as_absent(self):
        assert _b351_executor({"executor": "wasm"}, None, "auto") == "node"

    def test_unknown_build_reports_the_explicit_executor_if_set_else_unknown(self):
        assert _b351_executor({"executor": "quickjs"}, None, "unknown") == "quickjs"
        assert _b351_executor(None, None, "unknown") == "unknown"


# =========================================================================================
# THE VERSION REGIMES — an entirely-unset tools.codeMode, through the full check.
# =========================================================================================
class TestVersionRegimes:
    def test_pre_2026_7_1_is_unknown_never_extrapolated(self, tmp_path):
        f = check_code_mode_tool_surface(_ctx({"tools": {}}, tmp_path, "2026.6.9"))
        assert f.status == UNKNOWN
        assert "could not be determined" in f.detail

    def test_2026_7_1_through_9_5_resolves_off(self, tmp_path):
        for version in ("2026.7.1", "2026.8.1", "2026.9.5"):
            f = check_code_mode_tool_surface(_ctx({"tools": {}}, tmp_path, version))
            assert f.status == PASS, f"{version}: {f.status}: {f.detail}"

    def test_2026_9_6_and_later_auto_activates_and_warns(self, tmp_path):
        for version in ("2026.9.6", "2026.10.1"):
            f = check_code_mode_tool_surface(_ctx({"tools": {}}, tmp_path, version))
            assert f.status == WARN, f"{version}: {f.status}: {f.detail}"
            assert "auto-activated" in f.detail
            assert "automatic-activation default" in f.detail

    def test_unknown_build_is_unknown_not_a_hedged_pass(self, tmp_path):
        f = check_code_mode_tool_surface(_ctx({"tools": {}}, tmp_path))
        assert f.status == UNKNOWN
        assert "could not be determined" in f.detail


# =========================================================================================
# THE THIRD LAYER, THROUGH THE FULL CHECK — fixture-based (usual clean/bad convention) plus
# the agent-vs-implicit-default distinction inline.
# =========================================================================================
class TestThirdLayerIntegration:
    def test_defaults_models_override_beats_a_global_false(self):
        f = _f("bad_b351_codemode_defaults_model_override")
        assert f.status == WARN
        assert 'agents.defaults.models["anthropic/claude-opus-4-8"].codeMode' in f.detail

    def test_the_clean_defaults_models_fixture_passes(self):
        f = _f("clean_b351_codemode_defaults_model_disabled")
        assert f.status == PASS

    def test_an_agents_own_model_override_protects_that_agent_but_not_an_unnamed_one(
            self, tmp_path):
        """`w`'s own explicit false for the model key wins for `w` specifically (its own
        label never appears), but nothing here protects an UNNAMED agent (e.g. the
        implicit default "main") from inheriting agents.defaults.models[key]: true -- so
        the overall verdict is still WARN, naming only the scope(s) actually exposed."""
        cfg = {
            "tools": {"codeMode": False},
            "agents": {"entries": {"w": {"models": {"p/m": {"codeMode": False}}}},
                       "defaults": {"models": {"p/m": {"codeMode": True}}}},
        }
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == WARN
        assert "agents.entries.w" not in f.detail
        assert 'agents.defaults.models["p/m"].codeMode' in f.detail

    def test_a_declared_agent_with_no_override_still_inherits_the_defaults_models_key(
            self, tmp_path):
        cfg = {
            "tools": {"codeMode": False},
            "agents": {"entries": {"builder": {}},
                       "defaults": {"models": {"p/m": {"codeMode": True}}}},
        }
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == WARN
        assert 'models["p/m"].codeMode' in f.detail


# =========================================================================================
# THE GLOBAL/AGENT DEFAULT ASYMMETRY.
# =========================================================================================
class TestGlobalAgentDefaultAsymmetry:
    def test_an_agent_missing_enabled_inherits_whatever_the_global_scope_resolves_to(
            self, tmp_path):
        cfg = {"agents": {"entries": {"w": {"tools": {"codeMode": {"timeoutMs": 5}}}}}}
        assert check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.8.1")).status == PASS
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.6"))
        assert f.status == WARN
        assert "auto" in f.detail

    def test_the_global_scope_missing_enabled_means_off_pre_9_6_and_auto_9_6_plus(
            self, tmp_path):
        cfg = {"tools": {}}
        assert check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.8.1")).status == PASS
        assert check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.6")).status == WARN


# =========================================================================================
# THE "auto" LITERAL, EXPLICITLY SET — valid in the schema from 2026.8.1, even though it is
# not yet the unset-key DEFAULT until 9.6.
# =========================================================================================
class TestExplicitAutoLiteral:
    @pytest.mark.parametrize("version", ["2026.8.1", "2026.9.5", "2026.9.6"])
    def test_an_explicit_auto_string_warns_on_every_build_that_has_it_in_schema(
            self, tmp_path, version):
        f = check_code_mode_tool_surface(
            _ctx({"tools": {"codeMode": "auto"}}, tmp_path, version))
        assert f.status == WARN, f"{version}: {f.status}: {f.detail}"
        assert "auto-activated" in f.detail

    def test_an_explicit_auto_object_form_also_warns(self, tmp_path):
        cfg = {"tools": {"codeMode": {"enabled": "auto"}}}
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == WARN


# =========================================================================================
# EXECUTOR NAMING, THROUGH THE FULL CHECK.
# =========================================================================================
class TestExecutorNamingIntegration:
    def test_pre_9_6_explicit_true_names_quickjs_wasi_byte_identical_to_the_shipped_text(
            self, tmp_path):
        """`baseline.fingerprint()` hashes `detail`: this exact string must never move for
        this shape, or every real pre-9.6 user's `.clawseccheckignore` entry for it
        orphans silently."""
        f = check_code_mode_tool_surface(
            _ctx({"tools": {"codeMode": True}}, tmp_path, "2026.8.1"))
        assert f.status == WARN
        assert f.detail == (
            "tools.codeMode is on for every agent. Those agent runs expose only `exec` "
            "and `wait` to the model and hide the normal tools behind a QuickJS-WASI "
            "catalog bridge, so any tools.allow / tools.profile / tools.deny policy "
            "describes a surface the model does not see directly."
        )

    def test_9_6_unspecified_executor_names_node(self, tmp_path):
        f = check_code_mode_tool_surface(
            _ctx({"tools": {"codeMode": True}}, tmp_path, "2026.9.6"))
        assert f.status == WARN
        assert "node:vm" in f.detail and "not a security boundary" in f.detail

    def test_9_6_explicit_quickjs_executor_names_it(self, tmp_path):
        cfg = {"tools": {"codeMode": {"enabled": True, "executor": "quickjs"}}}
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.6"))
        assert f.status == WARN
        assert "bundled, sandboxed QuickJS-WASI" in f.detail

    def test_unknown_build_names_both_possibilities(self, tmp_path):
        f = check_code_mode_tool_surface(_ctx({"tools": {"codeMode": True}}, tmp_path))
        assert f.status == WARN
        assert "could not be determined" in f.detail
        assert "QuickJS-WASI" in f.detail and "Node executor" in f.detail


# =========================================================================================
# MIXED EXECUTORS ACROSS SCOPES (C-135 finding). The 2026.9.6+ `executor` key is read
# per-scope -- an agent's own key fully overrides the global one, never merged -- so one
# scope can genuinely run the sandboxed QuickJS-WASI bridge while a sibling runs the
# unsandboxed Node executor. A finding that picks ONE representative executor and applies
# its text to every named scope states a FALSE fact about whichever scope disagrees --
# reproduced against the real 2026.9.6 resolver (4,000-config differential fuzz, 614/3314
# WARNs genuinely mixed, 148 of those would have named quickjs while a hot scope ran node).
# Every case here is only possible via the 9.6+ executor key -- no pre-9.6 build can mix,
# since _b351_executor returns the same "quickjs-wasi" for every scope when the version
# default is "off" -- so none of these shapes exist in the corpus yet and none of the
# existing byte-identical pins above can be affected by this fix.
# =========================================================================================
def _mixed_executor_clauses(detail: str) -> tuple:
    """(node_clause, quickjs_clause): the two `;`-separated clauses of the mixed-executor
    sentence, isolated from the LEAD sentence (which names the same scope labels for an
    unrelated reason and would otherwise pollute a naive substring/partition check)."""
    mixed = detail.split("do NOT all use the same executor: ", 1)[1]
    clauses = mixed.split("; ")
    node_clause = next(c for c in clauses if "unsandboxed Node" in c)
    quickjs_clause = next(c for c in clauses if "sandboxed QuickJS-WASI" in c)
    return node_clause, quickjs_clause


class TestMixedExecutorNaming:
    def test_agent_explicit_quickjs_vs_sibling_agent_implicit_node(self, tmp_path):
        """The literal reviewer-confirmed repro: global off, agent `a` explicitly pins
        the sandboxed executor, agent `b` uses the boolean shorthand (no executor key of
        its own, and global sets none either) so it inherits 9.6's unsandboxed default."""
        cfg = {"tools": {"codeMode": False},
               "agents": {"list": [
                   {"id": "a", "tools": {"codeMode": {"enabled": True, "executor": "quickjs"}}},
                   {"id": "b", "tools": {"codeMode": True}},
               ]}}
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.6"))
        assert f.status == WARN
        assert "do NOT all use the same executor" in f.detail
        assert "agents.list[a]" in f.detail and "agents.list[b]" in f.detail
        # the claim must be scoped to the RIGHT agent, not blanket-applied
        node_clause, quickjs_clause = _mixed_executor_clauses(f.detail)
        assert "agents.list[b]" in node_clause and "agents.list[a]" not in node_clause
        assert "agents.list[a]" in quickjs_clause and "agents.list[b]" not in quickjs_clause

    def test_global_explicit_quickjs_vs_agent_explicit_node_override(self, tmp_path):
        """Global pins the sandboxed executor and is itself ON; one agent explicitly
        overrides ITS OWN executor to node (object-spread precedence: the agent's own
        `executor` key fully replaces global's, it does not merge)."""
        cfg = {"tools": {"codeMode": {"enabled": True, "executor": "quickjs"}},
               "agents": {"list": [
                   {"id": "w", "tools": {"codeMode": {"executor": "node"}}},
               ]}}
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.6"))
        assert f.status == WARN
        assert "do NOT all use the same executor" in f.detail
        assert "tools.codeMode" in f.detail and "agents.list[w]" in f.detail
        node_clause, quickjs_clause = _mixed_executor_clauses(f.detail)
        assert "agents.list[w]" in node_clause and "tools.codeMode" not in node_clause
        assert "tools.codeMode" in quickjs_clause and "agents.list[w]" not in quickjs_clause

    def test_third_layer_on_with_one_agent_overriding_to_node(self, tmp_path):
        """Global is explicitly OFF but pins the sandboxed executor for whenever it
        WOULD apply; agents.defaults.models turns Code Mode on for a model key both
        agents share. Agent `w` overrides its own executor to node; agent `x` has no
        override of its own and inherits global's quickjs pin for that same key."""
        cfg = {
            "tools": {"codeMode": {"enabled": False, "executor": "quickjs"}},
            "agents": {
                "list": [
                    {"id": "w", "tools": {"codeMode": {"executor": "node"}}},
                    {"id": "x"},
                ],
                "defaults": {"models": {"p/m": {"codeMode": True}}},
            },
        }
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.6"))
        assert f.status == WARN
        assert "do NOT all use the same executor" in f.detail
        assert 'agents.list[w].models["p/m"].codeMode' in f.detail
        assert 'agents.list[x].models["p/m"].codeMode' in f.detail
        node_clause, quickjs_clause = _mixed_executor_clauses(f.detail)
        assert "agents.list[w]" in node_clause and "agents.list[x]" not in node_clause
        assert "agents.list[x]" in quickjs_clause and "agents.list[w]" not in quickjs_clause

    def test_a_homogeneous_9_6_shape_is_unaffected_by_the_mixed_path(self, tmp_path):
        """Guard against a regression in the other direction: when every on/auto scope
        genuinely agrees, the single-executor text must still be used verbatim (no
        "do NOT all use the same executor" sentence must ever appear)."""
        cfg = {"tools": {"codeMode": True},
               "agents": {"list": [{"id": "a", "tools": {"codeMode": True}}]}}
        f = check_code_mode_tool_surface(_ctx(cfg, tmp_path, "2026.9.6"))
        assert f.status == WARN
        assert "do NOT all use the same executor" not in f.detail
        assert "node:vm" in f.detail
