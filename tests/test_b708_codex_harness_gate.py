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

import pytest

import clawseccheck.checks as C
from clawseccheck import harnessruntime as hr
from clawseccheck.catalog import PASS, WARN
from clawseccheck.collector import collect

_TMP_PATH_FACTORY = None


@pytest.fixture(autouse=True, scope="module")
def _tmp_path_factory_bridge(tmp_path_factory):
    """Bridge for `_run()` below (and the two standalone call sites further down), plain
    helpers/tests called/run many times rather than fixtures themselves — keeps every
    throwaway home inside pytest's own tmp tree instead of system /tmp. Mirrors
    `_oracle_scratch` in tests/test_toolgrant_dist_grounding.py."""
    global _TMP_PATH_FACTORY
    previous = _TMP_PATH_FACTORY
    _TMP_PATH_FACTORY = tmp_path_factory
    yield
    _TMP_PATH_FACTORY = previous

#: Derived from the port's own window, not written out: a re-baseline moves it (2026.9.4 ->
#: 2026.9.5 did, because the vendor's answers changed), and a literal here would silently go
#: on testing the build the port is no longer validated on. Whether the window matches the
#: INSTALLED dist is grounded separately, in ``test_harnessruntime_dist_grounding``.
VALIDATED = ".".join(str(x) for x in hr.ORACLE_MAX)
ABOVE_WINDOW = (hr.ORACLE_MAX[0], hr.ORACLE_MAX[1], hr.ORACLE_MAX[2] + 1)
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
    home = _TMP_PATH_FACTORY.mktemp("b708")
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
    home = _TMP_PATH_FACTORY.mktemp("b708")
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
    for stamp, expect in ((VALIDATED, PASS), ("2026.9.9", WARN), ("2026.7.1", WARN),
                          ("2026.8.2", WARN)):
        cfg = _cfg(base, {"meta": {"lastTouchedVersion": stamp}})
        home = _TMP_PATH_FACTORY.mktemp("b708")
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


# A legacy Codex provider spelling is migrated by the vendor's doctor onto the Codex harness:
# ``LEGACY_CODEX_PROVIDER_IDS`` (``codex``, ``openai-codex``; ``modelRefUsesCodexRuntime`` answers
# true for them, executed against the installed dist 2026.9.5) and the migration table
# ``LEGACY_RUNTIME_MODEL_PROVIDER_ALIASES`` (``codex``, ``codex-cli``; ``modelRefUsesCodexRuntime``
# answers false for ``codex-cli``, so THAT spelling rests on the migration table alone). At run
# time, before any migration, ``resolveAgentHarnessPolicy`` answers ``auto`` for all of them --
# so refusing a ``no`` here is a deliberately conservative reading, not a claim that the
# un-migrated config already runs Codex. The battery's oracle -- the runtime collector -- never
# sees the migration and calls them Codex-free, so it could not catch a ``no`` here.
_LEGACY_CODEX_REFS = ["openai-codex/gpt-5.5", "codex/gpt-5.5", "Codex/gpt-5", " OpenAI-Codex/x ",
                      "openai-codex/gpt-5.5@work", "codex-cli/gpt-5.5", " Codex-CLI/x"]


@pytest.mark.parametrize("ref", _LEGACY_CODEX_REFS)
def test_no_precondition_a_legacy_codex_provider_is_never_a_no(ref):
    assert _ans(_models(ref)) == hr.UNKNOWN
    assert _ans(_models("anthropic/c", heartbeat={"model": ref})) == hr.UNKNOWN
    assert _ans(_models({"primary": "anthropic/c", "fallbacks": [ref]})) == hr.UNKNOWN
    assert _ans(_models("anthropic/c", models={ref: {}})) == hr.UNKNOWN
    assert _ans({"agents": {"defaults": {"model": "anthropic/c"},
                            "entries": {"a": {"model": ref}}}}) == hr.UNKNOWN
    assert _ans({**_models("anthropic/c"), "channels": {"modelByChannel": {"x": {"y": ref}}}}) \
        == hr.UNKNOWN


def test_a_legacy_codex_provider_control_is_still_a_no_when_the_ref_is_ordinary():
    """Control for the test above: the same locations with an ordinary provider stay `no`,
    so the parametrised test bites on the provider and not on the shape."""
    assert _ans(_models("anthropic/c", heartbeat={"model": "anthropic/d"})) == hr.NO
    assert _ans(_models({"primary": "anthropic/c", "fallbacks": ["anthropic/d"]})) == hr.NO
    assert _ans(_models("anthropic/c", models={"anthropic/d": {}})) == hr.NO
    assert _ans({**_models("anthropic/c"),
                 "channels": {"modelByChannel": {"x": {"y": "anthropic/d"}}}}) == hr.NO
    # an openai-LOOKING provider that is not one of the two legacy spellings is not migrated
    assert _ans(_models("openai-compat/gpt-5")) == hr.NO


def test_b353_a_legacy_codex_ref_is_not_an_inert_pass():
    """The end-to-end shape of the reported bug: an MCP server pre-approving every tool on a
    config whose only model is a legacy Codex spelling used to read PASS "inert"."""
    for ref in _LEGACY_CODEX_REFS[:3]:
        f = _b353(_cfg(_APPROVE, _models(ref)))
        assert f.status == WARN and "does not determine" in f.detail, ref


@pytest.mark.parametrize("picker", [["codex"], ["Codex-App-Server"], ["auto", "codex"], ["foo"]])
def test_no_precondition_a_picker_runtime_is_not_ignored(picker):
    """The vendor's collector counts ``models[ref].pickerRuntimes`` like a pin, so a `no`
    over a config that offers a plugin runtime would disagree with it."""
    entry = {"pickerRuntimes": picker}
    assert _ans(_models("anthropic/c", models={"anthropic/c": entry})) == hr.UNKNOWN
    assert _ans({"agents": {"defaults": {"model": "anthropic/c"},
                            "entries": {"a": {"models": {"anthropic/c": entry}}}}}) == hr.UNKNOWN
    assert _ans({"agents": {"defaults": {"model": "anthropic/c"},
                            "list": [{"id": "a", "models": {"anthropic/c": entry}}]}}) == hr.UNKNOWN


@pytest.mark.parametrize("picker", [[], ["auto"], ["default"], ["pi"], ["openclaw"], "codex",
                                    [7, None]])
def test_a_picker_runtime_that_names_nothing_the_vendor_would_count_stays_a_no(picker):
    assert _ans(_models("anthropic/c", models={"anthropic/c": {"pickerRuntimes": picker}})) \
        == hr.NO


def _harness_build(installed, stamp=None):
    from clawseccheck.checks import _mcp

    class _Ctx:
        installed_dist_version = installed
        config = {"meta": {"lastTouchedVersion": stamp}} if stamp else {}

    return _mcp._harness_build(_Ctx())


def test_an_unorderable_installed_build_never_falls_through_to_the_stamp():
    """``2026.9.6-beta.1`` is KNOWN and newer than the validated build; reading the config's
    old stamp instead would call it the validated one and defeat the ceiling."""
    for installed in ("2026.9.6-beta.1", "2026.9.6-rc.2", f"{VALIDATED}-beta.1", "garbage", 5):
        assert _harness_build(installed, stamp=VALIDATED) is None, installed
    assert hr.codex_harness_reach(_models("anthropic/c"),
                                  _harness_build("2026.9.6-beta.1", VALIDATED)).answer \
        == hr.UNKNOWN


def test_an_absent_installed_build_still_uses_an_in_window_stamp():
    for installed in (None, ""):
        assert _harness_build(installed, stamp=VALIDATED) == hr.ORACLE_MAX
        assert _harness_build(installed, stamp="2026.9.9") is None
        assert _harness_build(installed) is None
    # a correction release of the validated build is orderable, stays inside the window, and
    # the (older) stamp plays no part in it
    assert hr.codex_harness_reach(_models("anthropic/c"),
                                  _harness_build(f"{VALIDATED}-1", stamp="2026.7.1")).answer \
        == hr.NO


# Bundled plugins read their OWN config key and hand the value to an agent turn; the vendor's
# ``collectConfiguredModelRefs`` never lists those, so neither the port's ``model_refs`` nor the
# differential oracle sees them. ``imap``'s ``accounts.<id>.model`` (a hook agent turn),
# ``active-memory``'s ``model`` and ``memory-core``'s dreaming models are the verified ones.

def _plugins(**cfg):
    return {**_models("anthropic/c"), "plugins": {"entries": cfg}}


@pytest.mark.parametrize("plugin_cfg", [
    {"imap": {"config": {"accounts": {"a": {"model": "openai/gpt-5.5"}}}}},
    {"active-memory": {"config": {"model": "openai/gpt-5.5"}}},
    {"active-memory": {"config": {"model": "codex/gpt-5.5"}}},
    {"memory-core": {"config": {"dreaming": {"light": {"model": "openai-codex/x"}}}}},
    {"x": {"config": {"defaultModel": "openai/gpt-5"}}},
    {"x": {"config": {"summaryModel": "codex-cli/x"}}},
    {"x": {"config": {"model": {"primary": "anthropic/c", "fallbacks": ["openai/gpt-5"]}}}},
    {"x": {"config": {"models": ["anthropic/c", "openai/gpt-5"]}}},
    {"x": {"config": {"channels": [{"deep": {"nest": {"embeddingModel": "openai/e"}}}]}}},
], ids=["imap", "active-memory", "active-memory-legacy", "dreaming", "defaultModel",
        "summaryModel-cli", "record-fallback", "list", "deep"])
def test_no_precondition_a_plugin_model_on_a_codex_provider_is_never_a_no(plugin_cfg):
    assert _ans(_plugins(**plugin_cfg)) == hr.UNKNOWN


@pytest.mark.parametrize("model", ["gpt-5.5", "sonnet"])
def test_no_precondition_a_plugin_model_with_no_provider_cannot_be_seen(model):
    assert _ans(_plugins(x={"config": {"model": model}})) == hr.UNKNOWN


def test_a_plugin_config_with_ordinary_or_no_models_stays_a_no():
    """Control: the walk only bites on a model-shaped key whose provider is Codex-bound (or
    unseeable), so ordinary plugin configs keep the definite answer."""
    assert _ans(_plugins(x={"config": {"model": "anthropic/claude-x"}})) == hr.NO
    # a URL, a sentence, or a NON-Codex provider name is not a Codex route
    assert _ans(_plugins(x={"config": {"provider": "anthropic", "url": "https://api.openai.com/v1",
                                       "note": "route via openai for tts"}})) == hr.NO
    assert _ans(_plugins(x={"config": {"models": ["anthropic/c", "google/g"]}})) == hr.NO
    assert _ans(_plugins()) == hr.NO
    assert _ans({**_models("anthropic/c"), "plugins": {"allow": ["x"]}}) == hr.NO


# Round 2: a key-name rule alone is not sound. A reference can sit under ANY key, in any
# shape, and only the shapes with a known meaning may be waved through.

@pytest.mark.parametrize("plugin_cfg", [
    {"x": {"config": {"modelRef": "openai/gpt-5.5"}}},
    {"x": {"config": {"llm": "openai/gpt-5.5", "engine": "codex/x"}}},
    {"x": {"config": {"modelFallback": "openai/gpt-5.5"}}},
    {"x": {"config": {"nested": [["openai/gpt-5.5"]]}}},
    {"x": {"config": {"models": {"openai/gpt-5.5": {}}}}},
    {"x": {"config": {"picks": {"openai/gpt-5.5": {"weight": 1}}}}},
    {"x": {"config": {"model": {"provider": "openai", "id": "gpt-5.5"}}}},
    {"x": {"config": {"model": {"ref": "openai/gpt-5.5"}}}},
    {"x": {"config": {"models": [{"provider": "openai", "id": "gpt-5.5"}]}}},
    {"x": {"config": {"models": [["openai/gpt-5.5"]]}}},
    {"x": {"config": {"model": {"primary": "anthropic/c", "extra": "anthropic/d"}}}},
    {"x": {"config": {"model": {"primary": 5}}}},
    {"x": {"config": {"model": {"fallbacks": "anthropic/c"}}}},
], ids=["modelRef", "llm-engine", "modelFallback", "nested-list", "map-keyed-by-ref",
        "map-key-other-name", "provider-id-record", "ref-record", "list-of-records",
        "list-of-lists", "record-extra-key", "non-str-primary", "fallbacks-not-a-list"])
def test_no_precondition_a_plugin_reference_in_a_shape_we_do_not_read_is_unknown(plugin_cfg):
    assert _ans(_plugins(**plugin_cfg)) == hr.UNKNOWN


def test_no_precondition_a_codex_provider_string_anywhere_outside_plugins_is_unknown():
    """Rule A is not scoped to ``plugins``: a provider-qualified Codex string under ANY key, or
    as a map key, refuses ``no`` (e.g. a channel's model, which the vendor collector skips)."""
    base = _models("anthropic/c")
    for extra in ({"channels": {"clickclack": {"model": "openai/gpt-5.5"}}},
                  {"reef": {"guard": {"pinnedModel": "codex/x"}}},
                  {"channels": {"x": {"accounts": {"a": {"anything": "openai-codex/x"}}}}},
                  {"skills": {"picks": {"codex-cli/x": True}}}):
        assert _ans({**base, **extra}) == hr.UNKNOWN, extra


@pytest.mark.parametrize("value", [None, True, 5, 5.5, "", "  ", ["anthropic/c"],
                                   {"primary": "anthropic/c", "fallbacks": ["google/g"]}])
def test_a_plugin_model_value_with_a_known_codex_free_meaning_stays_a_no(value):
    assert _ans(_plugins(x={"config": {"model": value}})) == hr.NO


# Round 3: an open-ended plugin key space. A plugin can pair a bare provider with a model id
# taken from elsewhere (``llm-task``'s ``defaultProvider`` + the agent primary's model name is
# routed by the vendor to Codex when the provider is openai), and any key mentioning "model" can
# carry an id.

@pytest.mark.parametrize("plugin_cfg", [
    {"llm-task": {"config": {"defaultProvider": "openai"}}},
    {"x": {"config": {"provider": " OpenAI "}}},
    {"x": {"config": {"providers": ["anthropic", "codex"]}}},
    {"x": {"config": {"llm": {"provider": "openai", "id": "gpt-5"}}}},
    {"x": {"config": {"engine": {"provider": "openai-codex"}}}},
    {"x": {"config": {"modelId": "gpt-5.5"}}},
    {"x": {"config": {"model_id": "gpt-5.5"}}},
    {"x": {"config": {"modelName": "gpt-5.5"}}},
    {"x": {"config": {"modelOverride": "gpt-5.5"}}},
    {"x": {"config": {"DefaultModel": "gpt-5.5"}}},
    {"llm-task": {"config": {"defaultModel": "gpt-5.5"}}},
], ids=["defaultProvider", "provider-mixed-case", "provider-in-list", "provider-id-record",
        "legacy-provider-record", "modelId", "model_id", "modelName", "modelOverride",
        "DefaultModel-case", "llm-task-defaultModel"])
def test_no_precondition_a_plugin_that_can_pair_a_codex_provider_with_a_model_is_unknown(
        plugin_cfg):
    assert _ans(_plugins(**plugin_cfg)) == hr.UNKNOWN


def test_a_plugin_provider_that_is_not_codex_bound_stays_a_no():
    assert _ans(_plugins(x={"config": {"defaultProvider": "anthropic", "modelId": "anthropic/c"}})) \
        == hr.NO
    assert _ans(_plugins(x={"config": {"provider": "google", "modelTimeoutMs": 5000}})) == hr.NO


@pytest.mark.parametrize("cfg", [
    _models("${MODEL_PROVIDER}/gpt-5.5"),
    _models({"primary": "anthropic/c", "fallbacks": ["${P}/gpt-5.5"]}),
    _models("anthropic/c", heartbeat={"model": "${P}/gpt-5.5"}),
    {**_models("anthropic/c"), "hooks": {"mappings": [{"model": "${P}/gpt-5.5"}]}},
    _plugins(x={"config": {"model": "${P}/gpt-5.5"}}),
], ids=["primary", "fallback", "heartbeat", "hook", "plugin"])
def test_no_precondition_an_environment_substitution_in_the_provider_is_unknown(cfg):
    """``resolveConfigEnvVars`` substitutes ``${VAR}`` into ANY config string, so
    ``${P}/gpt-5.5`` is ``openai/gpt-5.5`` when ``P=openai``. The provider half is unknowable."""
    got = hr.codex_harness_reach(cfg, _V, environ={})
    assert got.answer == hr.UNKNOWN
    assert "environment substitution" in got.reasons[0]


def test_an_environment_substitution_that_is_not_a_provider_stays_a_no():
    """Control: ``${VAR}`` is everywhere in real configs (tokens, paths); only the provider half
    of a MODEL reference matters."""
    cfg = {**_models("anthropic/c"), "gateway": {"auth": {"token": "${OPENCLAW_TOKEN}"}},
           "skills": {"load": {"extraDirs": ["${HOME}/skills"]}}}
    assert _ans(cfg) == hr.NO
    assert _ans(_models("anthropic/${MODEL}")) == hr.NO


@pytest.mark.parametrize("value,fragment", [
    ({"primary": "anthropic/c", "fallbacks": "anthropic/d"}, "has a shape this determination does not read"),
    ({"fallbacks": {"a": 1}}, "has a shape this determination does not read"),
    ([True, "anthropic/x"], "has a shape this determination does not read"),
    ([None], "has a shape this determination does not read"),
    ({"primary": ["anthropic/c"]}, "has a shape this determination does not read"),
])
def test_an_unrecognised_plugin_model_shape_says_why_it_is_unknown(value, fragment):
    """Pins each shape branch by its REASON, not just the answer: the catch-all at the bottom of
    ``codex_harness_reach`` would otherwise turn a deleted branch into the same `unknown`."""
    got = hr.codex_harness_reach(_plugins(x={"config": {"model": value}}), _V, environ={})
    assert got.answer == hr.UNKNOWN
    assert fragment in got.reasons[0], got.reasons


def test_a_plugin_config_too_large_to_enumerate_is_unknown_not_partial():
    big = {f"k{i}": {"n": i} for i in range(hr._WALK_MAX_NODES)}
    got = hr.codex_harness_reach(_plugins(x={"config": big}), _V, environ={})
    assert got.answer == hr.UNKNOWN and "too large" in got.reasons[0]


def test_a_plugin_config_nested_past_the_depth_bound_is_unknown_not_partial():
    node = {"model": "anthropic/c"}
    for _ in range(hr._WALK_MAX_DEPTH + 2):
        node = {"deeper": node}
    got = hr.codex_harness_reach(_plugins(x={"config": node}), _V, environ={})
    assert got.answer == hr.UNKNOWN and "too deep" in got.reasons[0]


def test_a_bare_plugin_model_id_says_why_it_is_unknown():
    """Pins the branch by its REASON: the catch-all at the bottom of ``codex_harness_reach``
    would otherwise turn a deleted branch into the same `unknown` and hide it."""
    got = hr.codex_harness_reach(_plugins(x={"config": {"model": "gpt-5.5"}}), _V, environ={})
    assert got.answer == hr.UNKNOWN
    assert "not a provider/model reference" in got.reasons[0]


def test_b353_a_plugin_hook_model_is_not_an_inert_pass():
    """End to end: an approve-all MCP server on a config whose ONLY Codex route is a plugin's
    hook-turn model used to read PASS "inert"."""
    cfg = _cfg(_APPROVE, _plugins(imap={"config": {"accounts": {"a": {"model": "openai/gpt-5.5"}}}}))
    f = _b353(cfg)
    assert f.status == WARN and "does not determine" in f.detail


# ======================================================================================
# C-560: Rule A no longer over-refuses on a local-model catalog label or an `agents.list`
# the vendor never reads because a sibling `entries` key is present -- each narrowed on its
# OWN provable shape, never by trusting a key NAME alone (round 2-3 of the earlier C-135
# passes already showed a reference can sit under any key, so that would be unsound).
# ======================================================================================

def _catalog(provider, field, value):
    return {**_models("anthropic/c"),
            "models": {"providers": {provider: {"models": [{field: value}]}}}}


@pytest.mark.parametrize("field", ["id", "name"])
@pytest.mark.parametrize("provider", ["lmstudio", "ollama", "openrouter"])
def test_a_local_model_catalog_label_is_not_a_route(field, provider):
    """A catalog entry's `id`/`name` labels one of THIS provider's own models -- the model
    resolves through the provider key itself (e.g. `lmstudio/openai/gpt-oss-20b`), whatever the
    label happens to spell."""
    assert _ans(_catalog(provider, field, "openai/gpt-oss-20b")) == hr.NO
    assert _ans(_catalog(provider, field, "codex/anything")) == hr.NO


@pytest.mark.parametrize("field", ["id", "name"])
@pytest.mark.parametrize("provider", ["openai", "codex", "codex-cli", "openai-codex", " OpenAI "])
def test_a_catalog_label_under_a_codex_bound_provider_still_refuses(field, provider):
    """Negative control: the skip is keyed off the PROVIDER the entry is filed under, not off
    `id`/`name` being harmless field names in general -- under an openai/legacy-Codex provider
    the same label shape still refuses."""
    assert _ans(_catalog(provider, field, "openai/gpt-oss-20b")) == hr.UNKNOWN


def test_a_catalog_label_outside_the_recognised_shape_still_refuses():
    """Control: only the EXACT `models.providers.<p>.models[i].id`/`.name` leaf is exempt."""
    # not inside a `models[]` array entry at all
    cfg = {**_models("anthropic/c"),
           "models": {"providers": {"lmstudio": {"id": "openai/gpt-oss-20b"}}}}
    assert _ans(cfg) == hr.UNKNOWN
    # nested one level deeper inside the catalog entry
    cfg2 = {**_models("anthropic/c"),
            "models": {"providers": {"lmstudio":
                       {"models": [{"compat": {"id": "openai/gpt-oss-20b"}}]}}}}
    assert _ans(cfg2) == hr.UNKNOWN
    # a sibling field other than id/name inside the catalog entry
    cfg3 = {**_models("anthropic/c"),
            "models": {"providers": {"lmstudio":
                       {"models": [{"description": "openai/gpt-oss-20b"}]}}}}
    assert _ans(cfg3) == hr.UNKNOWN


def test_an_ignored_agents_list_beside_entries_is_not_a_route():
    """B-699 / collector.agent_roster: once `entries` exists, `list` is never consulted by the
    vendor -- not even to decide a string inside it is Codex-free, since nothing dispatches
    through an unread key at all."""
    cfg = {"agents": {"defaults": {"model": "anthropic/c"},
                      "entries": {"a": {"model": "anthropic/d"}},
                      "list": [{"model": "openai/gpt-5"}]}}
    assert _ans(cfg) == hr.NO
    # An EMPTY entries record also makes the vendor's migration delete `list`.
    cfg2 = {"agents": {"defaults": {"model": "anthropic/c"}, "entries": {},
                       "list": [{"id": "a", "model": "openai/gpt-5"}]}}
    assert _ans(cfg2) == hr.NO


def test_a_null_entries_does_not_license_skipping_the_list():
    """C-135 review of C-560: this exact config was previously pinned as NO, and that was
    the defect. The runtime roster reader treats `entries: null` as present, but the vendor's
    legacy migration drops `list` only when `entries` is a record (legacy-38PBEy7q.mjs:
    1983-1999); with null it MOVES the list into entries, and a gateway start offers that repair
    as one yes/no prompt. Executed in memory by the reviewer, the migrated config sends agent
    `a` to the Codex harness. A migration can change the answer, so `no` may not be given."""
    for entry in ({"id": "a", "model": "openai/gpt-5"}, {"model": "openai/gpt-5"}):
        cfg = {"agents": {"defaults": {"model": "anthropic/c"}, "entries": None,
                          "list": [entry]}}
        assert _ans(cfg) == hr.UNKNOWN, entry


def test_a_catalog_label_is_exempt_only_under_a_real_provider_key():
    """C-135 review of C-560: a dot-joined path cannot tell a dotted provider key from a
    deeper nesting, so `models.providers.openai.extra.models.0.id` used to capture
    `openai.extra`, read it as a non-Codex provider, and exempt a leaf filed under `openai`.
    The capture is now accepted only when it is an actual key of `models.providers`."""
    nested = {**_models("anthropic/c"),
              "models": {"providers": {"openai": {"extra": {"models": [{"id": "openai/gpt-5.5"}]}}}}}
    assert _ans(nested) == hr.UNKNOWN
    deeper = {**_models("anthropic/c"),
              "models": {"providers": {"lmstudio": {"models": [
                  {"id": "local", "compat": {"models": [{"id": "openai/gpt-5.5"}]}}]}}}}
    assert _ans(deeper) == hr.UNKNOWN
    # Control: a provider key that genuinely contains a dot still resolves and is exempted,
    # which is the case the greedy capture was written for.
    dotted = {**_models("anthropic/c"),
              "models": {"providers": {"my.proxy": {"models": [{"id": "openai/gpt-oss-20b"}]}}}}
    assert _ans(dotted) == hr.NO


def test_an_unignored_agents_list_control_still_refuses():
    """Negative control: when `entries` is ABSENT, `list` IS the active roster, and a stray
    Codex-bound reference inside it -- one `model_refs` itself would not enumerate -- still
    refuses, proving the skip is gated on `entries` being present and not a blanket exemption
    of `agents.list`."""
    cfg = {"agents": {"defaults": {"model": "anthropic/c"},
                      "list": [{"id": "a", "model": "anthropic/d",
                               "strayfield": "openai/gpt-5"}]}}
    assert _ans(cfg) == hr.UNKNOWN


def test_a_provider_literally_named_models_still_resolves_correctly():
    """Regex-boundary adversarial case: a provider key spelled ``models`` (itself matching a
    literal segment the path-matching relies on) must not confuse which segment is the
    provider -- greedy backtracking still finds the real, rightmost catalog-field split."""
    cfg = {**_models("anthropic/c"),
           "models": {"providers": {"models": {"models": [{"id": "openai/gpt-oss-20b"}]}}}}
    assert _ans(cfg) == hr.NO


def test_a_plugins_own_agents_shaped_config_is_not_exempted():
    """Adversarial: a THIRD-PARTY plugin's open-ended config can coincidentally nest an
    ``agents``/``entries``/``list`` shape of its own. The ignore-list skip is anchored on the
    REAL top-level ``agents`` path (``path == "agents"``), so a plugin's own lookalike must
    still refuse -- trusting it would let an attacker-controlled plugin config launder a
    Codex-bound string past Rule A by naming its own keys after the real roster shape."""
    cfg = {**_models("anthropic/c"),
           "plugins": {"entries": {"x": {"config": {
               "agents": {"entries": {"z": {}}, "list": [{"model": "openai/gpt-5"}]}
           }}}}}
    assert _ans(cfg) == hr.UNKNOWN


def test_no_precondition_a_known_build_inside_the_validated_window():
    assert hr.codex_harness_reach(_models("anthropic/c"), None).answer == hr.UNKNOWN
    assert hr.codex_harness_reach(_models("anthropic/c"), (2026, 9, 3)).answer == hr.UNKNOWN
    assert hr.codex_harness_reach(_models("anthropic/c"), ABOVE_WINDOW).answer == hr.UNKNOWN
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
# 3.5 B-883 -- a config shape a KNOWN OpenClaw legacy migration rewrites before the harness
#     is resolved. The runtime-collector oracle this port is graded against reads the config
#     AS WRITTEN, never the migrated one, so it agrees with a `no` the migrated config would
#     not earn. Both shapes below were confirmed against the installed dist 2026.9.5's
#     ``legacy-config-migrations.runtime.models-*.mjs`` (``migrateLegacyOpenAICodexProvider``,
#     ``LEGACY_CODEX_PROVIDER_IDS``) and ``legacy-config-record-shared.ts``
#     (``visitAgentEntries``), not simulated -- neither is executed here (no vendor JS).
# ======================================================================================

@pytest.mark.parametrize("provider_id", ["codex", "openai-codex", " Codex ", "OpenAI-Codex",
                                         "OPENAI-CODEX"])
def test_b883_a_legacy_codex_provider_block_is_never_a_no(provider_id):
    """``models.providers.codex`` / ``.openai-codex`` is moved to ``models.providers.openai``
    by the vendor's doctor migration, and every model under it is stamped with an
    ``agentRuntime: {id: "codex"}`` pin -- something no ``_pin`` call here ever sees, because
    the PROVIDER itself (not an ``agentRuntime`` field) is what marks the block."""
    cfg = {**_models("anthropic/c"),
           "models": {"providers": {provider_id: {"models": [{"id": "gpt-5.5"}]}}}}
    got = hr.codex_harness_reach(cfg, _V, environ={})
    assert got.answer == hr.UNKNOWN
    assert "legacy Codex provider id" in got.reasons[0]
    # a bare provider block with no `models` array is still the same legacy id
    assert _ans({**_models("anthropic/c"),
                "models": {"providers": {provider_id: {}}}}) == hr.UNKNOWN


def test_b883_legacy_codex_provider_block_control_stays_no():
    """Control for the test above: an ordinary provider key, and specifically ``codex-cli``
    (a legacy REF-string alias, never a recognised ``models.providers.<id>`` BLOCK id per the
    vendor's ``LEGACY_CODEX_PROVIDER_IDS``), keep the definite `no`. Pins the table's exact
    boundary -- widening it to ``_LEGACY_CODEX_PROVIDERS`` (which includes "codex-cli") would
    break this."""
    assert _ans({**_models("anthropic/c"),
                "models": {"providers": {"anthropic": {"models": [{"id": "x"}]}}}}) == hr.NO
    assert _ans({**_models("anthropic/c"),
                "models": {"providers": {"codex-cli": {"models": [{"id": "x"}]}}}}) == hr.NO


def test_b883_entries_null_beside_a_populated_list_is_never_a_no():
    """``agents.entries: null`` is schema-valid alone ("no entries"); a populated
    ``agents.list`` beside it is what makes the pair schema-invalid AS WRITTEN. The runtime
    (and this port's roster) then never consults ``list`` -- the KEY alone decides. But the
    vendor's own migration visitor (``visitAgentEntries``, shared by many doctor migrations)
    falls back to ``list`` whenever ``entries`` is not a record, null included, so a pin (or
    any other migration-relevant field) sitting inside that ``list`` is invisible here."""
    cfg = {"agents": {"defaults": {"model": "anthropic/c"}, "entries": None,
                      "list": [{"agentRuntime": {"id": "codex"}}]}}
    got = hr.codex_harness_reach(cfg, _V, environ={})
    assert got.answer == hr.UNKNOWN
    assert "agents.entries is null" in got.reasons[0]
    # an ordinary model ref hidden the same way is just as invisible to the roster, and just
    # as reachable by the migration's fallback visitor
    ordinary = {"agents": {"defaults": {"model": "anthropic/c"}, "entries": None,
                           "list": [{"model": "openai/gpt-5"}]}}
    assert _ans(ordinary) == hr.UNKNOWN


def test_b883_entries_null_control_stays_no_without_a_populated_record_list():
    """Mutation check on both halves of the B-883 guard: no ``list`` key, an empty ``list``,
    and a ``list`` with no record entries all keep the definite `no` -- there is nothing a
    migration's visitor could find to rewrite. Deleting the ``isinstance(..., list)`` guard
    or the ``any(_is_record(e) ...)`` guard turns exactly one of these red."""
    base_model = {"model": "anthropic/c"}
    assert _ans({"agents": {"defaults": base_model, "entries": None}}) == hr.NO
    assert _ans({"agents": {"defaults": base_model, "entries": None, "list": []}}) == hr.NO
    assert _ans({"agents": {"defaults": base_model, "entries": None,
                            "list": ["not-a-record", 5, None]}}) == hr.NO
    # an EMPTY (but present) `entries` record is a real record, so the vendor's own visitor
    # returns early on it and never reads `list` either -- unaffected by this guard
    assert _ans({"agents": {"defaults": base_model, "entries": {},
                            "list": [{"agentRuntime": {"id": "codex"}}]}}) == hr.NO


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
