"""C-673: B353 must not clear the Codex appServer auto-approve posture when it cannot tell
whether any agent runs the Codex harness.

With no ``plugins.entries.codex`` block, ``_codex_appserver_yolo_reach`` folded every reach
answer except ``yes`` into a confident "no", and "no" made B353 answer PASS. A reach of
``unknown`` is what ``harnessruntime.codex_harness_reach`` returns for EVERY config on an
OpenClaw build outside ``ORACLE_MIN..ORACLE_MAX`` (and for an unorderable build string, and
for a model reference it cannot resolve), so each OpenClaw release turned this branch into a
false PASS until the window was raised. Only a definite ``no`` may clear it.

Builds are expressed through the window's own bounds, never as literals.
"""
import json
import os

import pytest

import clawseccheck.checks as C
from clawseccheck import harnessruntime as hr
from clawseccheck.catalog import PASS, WARN
from clawseccheck.collector import collect


def _dotted(parts):
    return ".".join(str(x) for x in parts)


IN_WINDOW = _dotted(hr.ORACLE_MAX)
ABOVE = _dotted(hr.ORACLE_MAX[:2] + (hr.ORACLE_MAX[2] + 1,))
assert hr.ORACLE_MIN[2] > 0, "the 'below the window' build needs a patch number to subtract from"
BELOW = _dotted(hr.ORACLE_MIN[:2] + (hr.ORACLE_MIN[2] - 1,))
PRERELEASE = IN_WINDOW + "-beta.1"  # cannot be ordered, so the build reads as unknown

#: The three out-of-window shapes plus the in-window one, as (id, installed build).
_UNKNOWN_REACH_BUILDS = [
    pytest.param(ABOVE, id="above-the-window"),
    pytest.param(BELOW, id="below-the-window"),
    pytest.param(PRERELEASE, id="unorderable-prerelease"),
]


def _cfg(model="openai/gpt-5.5", **top):
    cfg = {
        "gateway": {"bind": "loopback", "auth": {"mode": "token",
                                                 "token": "${OPENCLAW_GATEWAY_TOKEN}"}},
        "agents": {"defaults": {"model": model}, "entries": {"main": {"default": True}}},
        "mcp": {"servers": {"ops": {"command": "ops-mcp", "args": []}}},
    }
    cfg.update(top)
    return cfg


def _b353(tmp_path, cfg, installed):
    path = tmp_path / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(tmp_path)
    ctx.installed_dist_version = installed
    finding = next(f for f in C.run_all(ctx) if f.id == "B353")
    return finding, C._codex_appserver_yolo_reach(ctx)


# ---- the bug: no codex entry, reach unknown -> "unknown" + the disclosed WARN ----------

@pytest.mark.parametrize("installed", _UNKNOWN_REACH_BUILDS)
def test_no_codex_entry_with_an_unknown_reach_is_warn_unknown(tmp_path, installed):
    f, (answer, _reasons, hedges) = _b353(tmp_path, _cfg(), installed)
    assert (f.status, answer) == (WARN, "unknown")
    # The cause is named, and the text does not tell a possibly-Codex-free setup it is exposed.
    joined = " ".join(hedges)
    assert "cannot determine, on this OpenClaw build, whether any agent runs the Codex " \
           "app-server harness" in joined
    assert "not a build this determination was validated on" in joined
    detail = f.detail or ""
    assert "WHETHER THAT IS LIVE HERE" in detail
    assert "At least one of your agents is configured to run the Codex" not in detail


def test_no_codex_entry_with_an_unresolvable_model_in_window_is_warn_unknown(tmp_path):
    """In the window the build is fine; the reach is unknown because the default model is a
    bare alias this port cannot resolve to a provider."""
    cfg = _cfg(model="my-alias")
    assert hr.codex_harness_reach(cfg, hr.ORACLE_MAX).answer == hr.UNKNOWN  # the premise
    f, (answer, _reasons, hedges) = _b353(tmp_path, cfg, IN_WINDOW)
    assert (f.status, answer) == (WARN, "unknown")
    joined = " ".join(hedges)
    assert "cannot determine, on this OpenClaw build, whether any agent runs the Codex " \
           "app-server harness" in joined
    assert "provider/model" in joined  # the unresolved reference is the named cause


def test_unknown_reach_is_never_upgraded_to_yes(tmp_path):
    for installed in (ABOVE, BELOW, PRERELEASE):
        home = tmp_path / installed
        home.mkdir()
        _f, (answer, _r, _h) = _b353(home, _cfg(), installed)
        assert answer == "unknown"


# ---- controls: what keeps answering "no" -------------------------------------------------

def test_control_a_definite_no_reach_stays_pass_no(tmp_path):
    f, (answer, _r, hedges) = _b353(tmp_path, _cfg(model="anthropic/claude-x"), IN_WINDOW)
    assert hr.codex_harness_reach(_cfg(model="anthropic/claude-x"), hr.ORACLE_MAX).answer == hr.NO
    assert (f.status, answer, hedges) == (PASS, "no", [])


def test_control_a_yes_reach_in_window_stays_warn_unknown(tmp_path):
    f, (answer, _r, _h) = _b353(tmp_path, _cfg(), IN_WINDOW)
    assert hr.codex_harness_reach(_cfg(), hr.ORACLE_MAX).answer == hr.YES
    assert (f.status, answer) == (WARN, "unknown")


@pytest.mark.parametrize("installed", _UNKNOWN_REACH_BUILDS)
def test_control_an_explicitly_disabled_codex_entry_stays_no_out_of_window(tmp_path, installed):
    cfg = _cfg(plugins={"entries": {"codex": {"enabled": False}}})
    f, (answer, _r, _h) = _b353(tmp_path, cfg, installed)
    assert (f.status, answer) == (PASS, "no")


@pytest.mark.parametrize("plugins", [
    {"deny": ["codex"]},
    {"allow": ["telegram"]},
    {"enabled": False},
], ids=["deny", "allow-without-codex", "plugins-disabled"])
@pytest.mark.parametrize("installed", _UNKNOWN_REACH_BUILDS)
def test_control_a_blocking_gate_stays_no_out_of_window(tmp_path, installed, plugins):
    f, (answer, _r, _h) = _b353(tmp_path, _cfg(plugins=plugins), installed)
    assert (f.status, answer) == (PASS, "no")


@pytest.mark.parametrize("installed", _UNKNOWN_REACH_BUILDS)
def test_control_a_non_full_exec_mode_stays_no_out_of_window(tmp_path, installed):
    f, (answer, _r, _h) = _b353(tmp_path, _cfg(tools={"exec": {"mode": "ask"}}), installed)
    assert (f.status, answer) == (PASS, "no")
