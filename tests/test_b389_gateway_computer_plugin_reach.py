"""B389 — the Gateway's own unmanaged-desktop `computer` control
route (computer.invoke/computer.status), reachable without passing through
gateway.nodes.commands.deny or any per-action confirmation.

Grounded against the installed dist (openclaw@2026.9.5): see
clawseccheck/checks/_config.py::check_gateway_computer_plugin_reach's own docstring for
the full citation trail. The design point these tests pin: the WARN requires BOTH an
explicit `plugins.entries.cua-computer.enabled: true` (the plugin ships enabled by
default, but this specific Gateway route does not fire on that alone) AND a declared
scope granted the `computer` tool while unsandboxed — neither condition alone is enough.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import BY_ID, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import CHECKS, check_gateway_computer_plugin_reach
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _f(name: str):
    return check_gateway_computer_plugin_reach(collect(FIXTURES / name))


def _ctx(cfg, tmp_path):
    return Context(home=tmp_path, config=cfg, config_found=True)


# ------------------------------------------------------------------ fixture-level
def test_clean_fixture_passes():
    f = _f("clean_b389_computer_plugin_off")
    assert f.status == PASS, f"expected PASS, got {f.status}: {f.detail}"


def test_bad_fixture_warns():
    f = _f("bad_b389_computer_plugin_reach")
    assert f.status == WARN, f"expected WARN, got {f.status}: {f.detail}"
    assert "computer" in f.detail
    assert "global" in f.evidence


def test_malformed_plugins_fixture_is_unknown():
    f = _f("unknown_b389_malformed_plugins")
    assert f.status == UNKNOWN, f"expected UNKNOWN, got {f.status}: {f.detail}"


def test_it_never_fails():
    for name in ("bad_b389_computer_plugin_reach",):
        assert _f(name).status != "FAIL", name


def test_an_unreadable_config_is_unknown_not_pass(tmp_path):
    f = check_gateway_computer_plugin_reach(collect(tmp_path))
    assert f.status == UNKNOWN, f"expected UNKNOWN, got {f.status}: {f.detail}"


# ------------------------------------------------------------------ the trigger's two halves
def test_plugin_enabled_default_alone_does_not_warn(tmp_path):
    """The plugin ships `enabledByDefault: true`, but the Gateway route additionally
    requires an EXPLICIT `plugins.entries.cua-computer.enabled: true` in the raw
    config — a config that never touches the plugins block at all must not warn just
    because the tool is granted."""
    ctx = _ctx({"tools": {"allow": ["computer"]}}, tmp_path)
    assert check_gateway_computer_plugin_reach(ctx).status == PASS


def test_plugin_enabled_without_any_tool_grant_does_not_warn(tmp_path):
    ctx = _ctx({
        "plugins": {"entries": {"cua-computer": {"enabled": True}}},
        "tools": {"profile": "minimal"},
    }, tmp_path)
    f = check_gateway_computer_plugin_reach(ctx)
    assert f.status == PASS, f.detail


def test_both_conditions_together_warn(tmp_path):
    ctx = _ctx({
        "plugins": {"entries": {"cua-computer": {"enabled": True}}},
        "tools": {"allow": ["computer"]},
    }, tmp_path)
    assert check_gateway_computer_plugin_reach(ctx).status == WARN


def test_plugins_enabled_false_kill_switch_wins_over_the_entry(tmp_path):
    ctx = _ctx({
        "plugins": {"enabled": False, "entries": {"cua-computer": {"enabled": True}}},
        "tools": {"allow": ["computer"]},
    }, tmp_path)
    assert check_gateway_computer_plugin_reach(ctx).status == PASS


def test_full_sandbox_mode_suppresses_the_warn(tmp_path):
    """sandbox.mode 'all' routes the agent's `computer` tool through a contained
    desktop instead (resolveSandboxToolPolicyForAgent's containedToolNames), so a
    fully-sandboxed scope is a genuine mitigation, not merely hoped-for."""
    ctx = _ctx({
        "plugins": {"entries": {"cua-computer": {"enabled": True}}},
        "tools": {"allow": ["computer"]},
        "agents": {"defaults": {"sandbox": {"mode": "all"}}},
    }, tmp_path)
    assert check_gateway_computer_plugin_reach(ctx).status == PASS


def test_a_powerful_profile_alone_does_not_grant_computer(tmp_path):
    """`computer` is granted by NONE of minimal/coding/messaging — only `full` or an
    explicit allow/alsoAllow naming it (or its group). A `coding` profile must not
    warn on its own."""
    ctx = _ctx({
        "plugins": {"entries": {"cua-computer": {"enabled": True}}},
        "tools": {"profile": "coding"},
    }, tmp_path)
    assert check_gateway_computer_plugin_reach(ctx).status == PASS


def test_profile_full_does_grant_computer(tmp_path):
    ctx = _ctx({
        "plugins": {"entries": {"cua-computer": {"enabled": True}}},
        "tools": {"profile": "full"},
    }, tmp_path)
    assert check_gateway_computer_plugin_reach(ctx).status == WARN


def test_per_agent_grant_narrows_the_named_scope(tmp_path):
    """A global profile that does not grant `computer`, widened for one agent via
    alsoAllow, must name only that agent's scope, not "global"."""
    ctx = _ctx({
        "plugins": {"entries": {"cua-computer": {"enabled": True}}},
        "tools": {"profile": "minimal"},
        "agents": {"list": [{"id": "bot", "tools": {"alsoAllow": ["computer"]}}]},
    }, tmp_path)
    f = check_gateway_computer_plugin_reach(ctx)
    assert f.status == WARN
    assert "global" not in f.evidence
    assert any("agents.list" in e for e in f.evidence)


# ------------------------------------------------------------------ Golden Rule #4
def test_malformed_plugins_block_is_unknown_not_pass(tmp_path):
    for malformed in ([], 7, "on"):
        ctx = _ctx({"plugins": malformed, "tools": {"allow": ["computer"]}}, tmp_path)
        f = check_gateway_computer_plugin_reach(ctx)
        assert f.status == UNKNOWN, f"{malformed!r}: got {f.status}: {f.detail}"


# ------------------------------------------------------------------ wiring, not just the fn
def test_the_check_is_actually_registered():
    assert check_gateway_computer_plugin_reach in CHECKS


def test_catalog_entry_matches_what_the_check_emits():
    meta = BY_ID["B389"]
    assert meta.severity == HIGH
    assert meta.surface == "gateway"
    assert meta.scored is False
    emitted = _f("bad_b389_computer_plugin_reach")
    assert emitted.id == "B389"
    assert emitted.title == meta.title
    assert emitted.severity == meta.severity


def test_owner_facing_text_never_names_the_check_id():
    """§2 doctrine: say what the risk is, not which check found it."""
    for name in (
        "clean_b389_computer_plugin_off",
        "bad_b389_computer_plugin_reach",
        "unknown_b389_malformed_plugins",
    ):
        f = _f(name)
        assert "B389" not in f.detail
        assert "B389" not in f.fix
