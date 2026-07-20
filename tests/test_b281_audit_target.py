"""B-281 (ENV-1) — audit-target transparency + config-path resolution.

The collector used to hardcode ``home / "openclaw.json"`` while OpenClaw's own resolver
reads OPENCLAW_CONFIG_PATH first-unconditionally, reaches a different home through
OPENCLAW_HOME, follows OPENCLAW_STATE_DIR (what ``openclaw --profile`` sets), and prefers
an existing legacy ``clawdbot.json``. A stale hardened config could therefore score A while
the live agent ran a wide-open one.

Every assertion below drives the REAL functions (collector.resolve_*, the registered check,
render_report/render_json) — never a re-implementation of their logic.
"""
import json
import os
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_audit_target_divergence
from clawseccheck.collector import (
    OPENCLAW_LEGACY_CONFIG_FILENAMES,
    audits_default_state_dir,
    collect,
    openclaw_effective_home,
    openclaw_state_dir,
    resolve_product_config_path,
)
from clawseccheck.report import render_json, render_report
from clawseccheck.scoring import compute


def _write_config(path: Path, body: str = '{"gateway": {"bind": "loopback"}}') -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(0o600)
    return path


def _home_env(tmp_path: Path, **extra) -> dict:
    env = {"HOME": str(tmp_path)}
    env.update({k: v for k, v in extra.items() if v is not None})
    return env


# --------------------------------------------------------------------------
# Layer 1: the resolver mirror, driven with an INJECTED env (hermetic, no
# monkeypatching) so each dist branch is pinned independently.
# --------------------------------------------------------------------------

def test_effective_home_prefers_openclaw_home_over_HOME(tmp_path):
    """home-dir-CJKEsOtx.js:34-42 — OPENCLAW_HOME beats HOME."""
    other = tmp_path / "other"
    env = _home_env(tmp_path, OPENCLAW_HOME=str(other))
    assert openclaw_effective_home(env) == other
    assert openclaw_effective_home(_home_env(tmp_path)) == tmp_path


@pytest.mark.parametrize("junk", ["", "   ", "undefined", "null"])
def test_effective_home_treats_junk_openclaw_home_as_unset(tmp_path, junk):
    """normalize$1 (home-dir-CJKEsOtx.js:13-17) rejects these as unset, not as paths."""
    env = _home_env(tmp_path, OPENCLAW_HOME=junk)
    assert openclaw_effective_home(env) == tmp_path


def test_openclaw_home_tilde_expands_against_the_os_home(tmp_path):
    """A leading ~ expands against the OS home (resolveRawHomeDir :37-39)."""
    env = _home_env(tmp_path, OPENCLAW_HOME="~/profile")
    assert openclaw_effective_home(env) == tmp_path / "profile"


def test_state_dir_prefers_existing_legacy_clawdbot(tmp_path):
    """resolveStateDir :53-60 — an existing ~/.clawdbot wins when ~/.openclaw is absent."""
    (tmp_path / ".clawdbot").mkdir()
    assert openclaw_state_dir(_home_env(tmp_path)) == tmp_path / ".clawdbot"
    # ...but ~/.openclaw wins the moment it exists.
    (tmp_path / ".openclaw").mkdir()
    assert openclaw_state_dir(_home_env(tmp_path)) == tmp_path / ".openclaw"


def test_state_dir_override_wins_over_both(tmp_path):
    (tmp_path / ".openclaw").mkdir()
    env = _home_env(tmp_path, OPENCLAW_STATE_DIR=str(tmp_path / "profile"))
    assert openclaw_state_dir(env) == tmp_path / "profile"


def test_config_path_override_is_unconditional(tmp_path):
    """resolveConfigPath :137-138 returns the override FIRST, even when the default exists."""
    _write_config(tmp_path / ".openclaw" / "openclaw.json")
    target = _write_config(tmp_path / "work" / "openclaw.json")
    env = _home_env(tmp_path, OPENCLAW_CONFIG_PATH=str(target))
    path, reason = resolve_product_config_path(env)
    assert path == target
    assert "OPENCLAW_CONFIG_PATH" in reason


def test_product_path_follows_state_dir_profile(tmp_path):
    """`openclaw --profile x` sets OPENCLAW_STATE_DIR; the config follows it."""
    _write_config(tmp_path / ".openclaw" / "openclaw.json")
    profile = _write_config(tmp_path / ".openclaw-work" / "openclaw.json")
    env = _home_env(tmp_path, OPENCLAW_STATE_DIR=str(tmp_path / ".openclaw-work"))
    path, _ = resolve_product_config_path(env)
    assert path == profile


def test_product_path_finds_legacy_config_with_no_env_at_all(tmp_path):
    """The env-free divergence: a migrated user's clawdbot.json, zero variables set."""
    legacy = _write_config(tmp_path / ".clawdbot" / "clawdbot.json")
    path, reason = resolve_product_config_path(_home_env(tmp_path))
    assert path == legacy
    assert "legacy" in reason or "candidate" in reason


# --------------------------------------------------------------------------
# resolve_config_in_home — the hermetic, env-free half used by collect()
# --------------------------------------------------------------------------

def test_collect_reads_a_legacy_clawdbot_json(tmp_path):
    """The pre-fix collector opened only "openclaw.json" and reported config_found=False
    here, so every config check went UNKNOWN on a config that was really being used."""
    home = tmp_path / ".openclaw"
    _write_config(home / OPENCLAW_LEGACY_CONFIG_FILENAMES[0],
                  '{"gateway": {"bind": "0.0.0.0"}}')
    ctx = collect(home)
    assert ctx.config_found is True
    assert ctx.config_path.name == "clawdbot.json"
    assert ctx.config["gateway"]["bind"] == "0.0.0.0"


def test_canonical_config_wins_over_legacy_when_both_exist(tmp_path):
    home = tmp_path / ".openclaw"
    _write_config(home / "openclaw.json", '{"gateway": {"bind": "loopback"}}')
    _write_config(home / "clawdbot.json", '{"gateway": {"bind": "0.0.0.0"}}')
    ctx = collect(home)
    assert ctx.config_path.name == "openclaw.json"
    assert ctx.config["gateway"]["bind"] == "loopback"


def test_missing_config_still_names_the_canonical_path(tmp_path):
    """found=False must still report WHERE it looked, or the error names nothing."""
    home = tmp_path / ".openclaw"
    home.mkdir()
    ctx = collect(home)
    assert ctx.config_found is False
    assert ctx.config_path == home / "openclaw.json"
    assert any("config not found" in e for e in ctx.errors)


# --------------------------------------------------------------------------
# B183 — the divergence check itself
# --------------------------------------------------------------------------

def _ctx_at_default_home(tmp_path, monkeypatch, **env):
    """A ctx whose home IS the machine's default state dir, so B183's gate is open."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for var in ("OPENCLAW_CONFIG_PATH", "OPENCLAW_HOME", "OPENCLAW_STATE_DIR"):
        monkeypatch.delenv(var, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    home = tmp_path / ".openclaw"
    _write_config(home / "openclaw.json")
    return collect(home)


def test_b183_passes_when_env_is_unset(tmp_path, monkeypatch):
    ctx = _ctx_at_default_home(tmp_path, monkeypatch)
    assert audits_default_state_dir(ctx.home) is True
    f = check_audit_target_divergence(ctx)
    assert f.status == PASS


def test_b183_warns_when_config_path_points_elsewhere(tmp_path, monkeypatch):
    """The headline attack: a stale hardened config audited while the agent runs another."""
    live = _write_config(tmp_path / "work" / "openclaw.json")
    ctx = _ctx_at_default_home(tmp_path, monkeypatch, OPENCLAW_CONFIG_PATH=str(live))
    f = check_audit_target_divergence(ctx)
    assert f.status == WARN
    # The report must name BOTH files — naming only one is what made this invisible.
    blob = f.detail + " " + " ".join(f.evidence)
    assert str(live) in blob
    assert str(ctx.config_path) in blob


def test_b183_warns_on_a_state_dir_profile(tmp_path, monkeypatch):
    """`openclaw --profile work` diverges through OPENCLAW_STATE_DIR, not CONFIG_PATH."""
    _write_config(tmp_path / ".openclaw-work" / "openclaw.json")
    ctx = _ctx_at_default_home(
        tmp_path, monkeypatch, OPENCLAW_STATE_DIR=str(tmp_path / ".openclaw-work"))
    assert check_audit_target_divergence(ctx).status == WARN


def test_b183_warns_on_a_legacy_state_dir_with_no_env_set(tmp_path, monkeypatch):
    """The env-free divergence, found by an adversarial probe against the first gate.

    A user migrated from clawdbot has only ``~/.clawdbot``. A BARE run (no arguments)
    audits argparse's ``~/.openclaw`` default, which does not exist, while the agent reads
    ``~/.clawdbot/clawdbot.json``. The first version of the gate required an exact match
    against the resolved state dir, so ``~/.openclaw`` failed it and the check went silent
    on the one case with no environment variable involved at all.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    for var in ("OPENCLAW_CONFIG_PATH", "OPENCLAW_HOME", "OPENCLAW_STATE_DIR"):
        monkeypatch.delenv(var, raising=False)
    legacy = _write_config(tmp_path / ".clawdbot" / "clawdbot.json")
    home = tmp_path / ".openclaw"   # the CLI default; deliberately does not exist
    ctx = collect(home)
    assert ctx.config_found is False
    assert audits_default_state_dir(home) is True
    f = check_audit_target_divergence(ctx)
    assert f.status == WARN
    assert str(legacy) in f.detail + " ".join(f.evidence)


def test_b183_unknown_wording_does_not_claim_an_explicit_target_wrongly(tmp_path, monkeypatch):
    """The UNKNOWN branch says the scan 'targets X explicitly'. After the gate fix that
    is only reachable for a genuinely explicit --home, so the sentence stays true."""
    monkeypatch.setenv("HOME", str(tmp_path))
    elsewhere = tmp_path / "somewhere_else"
    _write_config(elsewhere / "openclaw.json")
    f = check_audit_target_divergence(collect(elsewhere))
    assert f.status == UNKNOWN
    # The canonical default must NEVER reach this branch.
    assert audits_default_state_dir(tmp_path / ".openclaw") is True


@pytest.mark.parametrize("spelling", ["exact", "trailing_space", "tilde"])
def test_b183_no_false_positive_when_env_names_the_same_file(tmp_path, monkeypatch, spelling):
    """FP guard: the variable being SET is not a divergence. Compare realpaths.

    A naive "OPENCLAW_CONFIG_PATH is set -> warn" fires on every one of these, all of
    which designate precisely the file being audited.
    """
    home = tmp_path / ".openclaw"
    value = {
        "exact": str(home / "openclaw.json"),
        "trailing_space": f"  {home / 'openclaw.json'}  ",
        "tilde": "~/.openclaw/openclaw.json",
    }[spelling]
    ctx = _ctx_at_default_home(tmp_path, monkeypatch, OPENCLAW_CONFIG_PATH=value)
    assert check_audit_target_divergence(ctx).status == PASS


def test_b183_no_false_positive_through_a_symlink(tmp_path, monkeypatch):
    """Reached via a symlink, the env still designates the audited file. realpath, not ==."""
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".openclaw"
    real = _write_config(home / "openclaw.json")
    link = tmp_path / "alias.json"
    link.symlink_to(real)
    monkeypatch.setenv("OPENCLAW_CONFIG_PATH", str(link))
    for var in ("OPENCLAW_HOME", "OPENCLAW_STATE_DIR"):
        monkeypatch.delenv(var, raising=False)
    ctx = collect(home)
    assert os.path.realpath(str(link)) == os.path.realpath(str(real))
    assert check_audit_target_divergence(ctx).status == PASS


def test_b183_is_unknown_under_an_explicit_home(tmp_path, monkeypatch):
    """A deliberately targeted --home is not a divergence, even with the env set.

    This is also the hermeticity guard: a fixture scan must never absorb the auditor's
    own environment into a verdict (Golden Rule #5).
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPENCLAW_CONFIG_PATH", str(tmp_path / "somewhere" / "openclaw.json"))
    elsewhere = tmp_path / "fixtures" / "home_x"
    _write_config(elsewhere / "openclaw.json")
    ctx = collect(elsewhere)
    f = check_audit_target_divergence(ctx)
    assert f.status == UNKNOWN
    assert "explicitly" in f.detail


def test_b183_never_fails(tmp_path, monkeypatch):
    """A divergence means 'this report may describe the wrong file', not a misconfig."""
    live = _write_config(tmp_path / "work" / "openclaw.json")
    ctx = _ctx_at_default_home(tmp_path, monkeypatch, OPENCLAW_CONFIG_PATH=str(live))
    assert check_audit_target_divergence(ctx).status in (PASS, WARN, UNKNOWN)
    assert check_audit_target_divergence(ctx).status != "FAIL"


def test_b183_is_registered_and_unscored():
    from clawseccheck.catalog import BY_ID
    from clawseccheck.checks import CHECKS
    assert check_audit_target_divergence in CHECKS
    assert BY_ID["B183"].scored is False


# --------------------------------------------------------------------------
# Transparency: the audited path reaches BOTH output surfaces
# --------------------------------------------------------------------------

def test_json_and_text_reports_name_the_audited_file(tmp_path):
    home = tmp_path / ".openclaw"
    _write_config(home / "openclaw.json")
    ctx, findings, score = audit(home)

    payload = json.loads(render_json(findings, score, ctx=ctx))
    assert payload["audited_config_path"] == str(home / "openclaw.json")

    text = render_report(findings, score, ctx=ctx)
    assert f"Audited config: {home / 'openclaw.json'}" in text


def test_reports_name_a_legacy_file_by_its_real_name(tmp_path):
    """Transparency has to survive the legacy case, or it re-hides the divergence."""
    home = tmp_path / ".openclaw"
    _write_config(home / "clawdbot.json")
    ctx, findings, score = audit(home)
    assert "clawdbot.json" in render_report(findings, score, ctx=ctx)
    assert json.loads(render_json(findings, score, ctx=ctx))[
        "audited_config_path"].endswith("clawdbot.json")


def test_render_report_tolerates_a_ctx_free_call():
    """ctx=None is a supported call shape; the new line must simply not appear."""
    findings = []
    text = render_report(findings, compute(findings), ctx=None)
    assert "Audited config:" not in text
