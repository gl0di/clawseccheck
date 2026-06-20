"""Tests for the risk engine (clawcheck/risk.py).

Covers:
  - Each rule firing on a crafted config
  - Empty config -> no paths
  - render_risk_paths output shape (chain arrows, ascii-safe)
  - --risk-paths CLI flag
  - render_json includes "risk_paths"
  - A-F score is UNCHANGED whether or not risk is passed (determinism)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawcheck.collector import Context
from clawcheck.checks import run_all
from clawcheck.scoring import compute
from clawcheck.risk import RiskPath, risk_paths, render_risk_paths
from clawcheck.report import render_json, render_report
from clawcheck.catalog import CRITICAL, HIGH, MEDIUM, FAIL
from clawcheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ctx(cfg: dict) -> Context:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    return ctx


def _findings(ctx: Context):
    return run_all(ctx)


def _paths(cfg: dict, extra_findings=None):
    ctx = _ctx(cfg)
    f = _findings(ctx)
    if extra_findings:
        f = list(f) + list(extra_findings)
    return risk_paths(ctx, f)


# ──────────────────────────────────────────────────────────────────────────────
# Rule RISK-01: open sender + exec/write tool  -> CRITICAL
# ──────────────────────────────────────────────────────────────────────────────

def test_risk01_open_telegram_group_plus_exec_is_critical():
    cfg = {
        "channels": {"telegram": {"groupPolicy": "open", "dmPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    paths = _paths(cfg)
    ids = [p.id for p in paths]
    assert "RISK-01" in ids
    r01 = next(p for p in paths if p.id == "RISK-01")
    assert r01.severity == CRITICAL
    assert "telegram" in r01.chain[0]
    # chain arrows present in render
    rendered = render_risk_paths([r01])
    assert "->" in rendered or "→" in rendered


def test_risk01_no_open_channel_no_critical():
    cfg = {
        "channels": {"telegram": {"groupPolicy": "allowlist", "dmPolicy": "allowlist"}},
        "tools": {"exec": {"security": "full"}},
    }
    paths = _paths(cfg)
    assert not any(p.id == "RISK-01" for p in paths)


def test_risk01_open_channel_no_exec_no_critical():
    cfg = {
        "channels": {"telegram": {"groupPolicy": "open"}},
        "tools": {"profile": "minimal"},
    }
    paths = _paths(cfg)
    assert not any(p.id == "RISK-01" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Rule RISK-02: Lethal Trifecta  -> HIGH
# ──────────────────────────────────────────────────────────────────────────────

def test_risk02_lethal_trifecta_fires():
    cfg = {
        # untrusted input: open channel
        "channels": {"telegram": {"dmPolicy": "open"}},
        # sensitive data: gateway auth password
        "gateway": {"auth": {"password": "s3cr3t"}},
        # outbound: elevated tools
        "tools": {"elevated": {"allowFrom": {"telegram": ["owner"]}}},
    }
    paths = _paths(cfg)
    ids = [p.id for p in paths]
    assert "RISK-02" in ids
    r02 = next(p for p in paths if p.id == "RISK-02")
    assert r02.severity == HIGH
    assert len(r02.chain) == 3


def test_risk02_only_two_legs_no_trifecta():
    cfg = {
        "channels": {"telegram": {"dmPolicy": "open"}},
        "gateway": {"auth": {"password": "s3cr3t"}},
        # no outbound
    }
    paths = _paths(cfg)
    assert not any(p.id == "RISK-02" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Rule RISK-03: sandbox off + untrusted ingress + exec  -> HIGH
# ──────────────────────────────────────────────────────────────────────────────

def test_risk03_sandbox_off_plus_open_channel_plus_exec():
    cfg = {
        "channels": {"discord": {"dmPolicy": "open"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
        "tools": {"exec": {"security": "full"}},
    }
    paths = _paths(cfg)
    ids = [p.id for p in paths]
    assert "RISK-03" in ids
    r03 = next(p for p in paths if p.id == "RISK-03")
    assert r03.severity == HIGH
    assert "sandbox" in r03.chain[1].lower()


def test_risk03_sandbox_on_no_fire():
    cfg = {
        "channels": {"discord": {"dmPolicy": "open"}},
        "agents": {"defaults": {"sandbox": {"mode": "non-main"}}},
        "tools": {"exec": {"security": "full"}},
    }
    paths = _paths(cfg)
    assert not any(p.id == "RISK-03" for p in paths)


def test_risk03_sandbox_off_no_exec_no_fire():
    cfg = {
        "channels": {"discord": {"dmPolicy": "open"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
        "tools": {"profile": "minimal"},
    }
    paths = _paths(cfg)
    assert not any(p.id == "RISK-03" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Rule RISK-04: mutable identity + elevated tools  -> HIGH
# ──────────────────────────────────────────────────────────────────────────────

def test_risk04_dangerous_name_matching_plus_elevated():
    cfg = {
        "channels": {"slack": {"dangerouslyAllowNameMatching": True}},
        "tools": {"elevated": {"allowFrom": {"slack": ["owner"]}}},
    }
    paths = _paths(cfg)
    ids = [p.id for p in paths]
    assert "RISK-04" in ids
    r04 = next(p for p in paths if p.id == "RISK-04")
    assert r04.severity == HIGH


def test_risk04_b30_fail_plus_exec():
    from clawcheck.catalog import Finding
    fake_b30 = Finding(
        id="B30", title="Mutable identity", severity=HIGH,
        status=FAIL, detail="test", fix="test",
        framework="Identity", scored=False,
    )
    cfg = {
        "tools": {"exec": {"security": "full"}},
    }
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b30]
    paths = risk_paths(ctx, f)
    assert any(p.id == "RISK-04" for p in paths)


def test_risk04_name_matching_no_elevated_no_fire():
    cfg = {
        "channels": {"slack": {"dangerouslyAllowNameMatching": True}},
        "tools": {"profile": "minimal"},
    }
    paths = _paths(cfg)
    assert not any(p.id == "RISK-04" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Rule RISK-05: browser SSRF + secrets reachable  -> HIGH
# ──────────────────────────────────────────────────────────────────────────────

def test_risk05_ssrf_policy_plus_secrets():
    cfg = {
        "browser": {"ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
        "gateway": {"auth": {"password": "mysecret"}},
    }
    paths = _paths(cfg)
    ids = [p.id for p in paths]
    assert "RISK-05" in ids
    r05 = next(p for p in paths if p.id == "RISK-05")
    assert r05.severity == HIGH


def test_risk05_b38_fail_plus_secrets():
    from clawcheck.catalog import Finding
    fake_b38 = Finding(
        id="B38", title="Browser SSRF", severity=HIGH,
        status=FAIL, detail="test", fix="test",
        framework="SSRF", scored=False,
    )
    cfg = {"gateway": {"auth": {"password": "mysecret"}}}
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b38]
    paths = risk_paths(ctx, f)
    assert any(p.id == "RISK-05" for p in paths)


def test_risk05_ssrf_no_secrets_no_fire():
    cfg = {
        "browser": {"ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
    }
    paths = _paths(cfg)
    assert not any(p.id == "RISK-05" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Rule RISK-06: control plane reachable from open surface  -> CRITICAL
# ──────────────────────────────────────────────────────────────────────────────

def test_risk06_b32_fail_plus_open_channel():
    from clawcheck.catalog import Finding
    fake_b32 = Finding(
        id="B32", title="Control plane exposed", severity=CRITICAL,
        status=FAIL, detail="test", fix="test",
        framework="Control Plane", scored=False,
    )
    cfg = {"channels": {"telegram": {"dmPolicy": "open"}}}
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b32]
    paths = risk_paths(ctx, f)
    r06 = next((p for p in paths if p.id == "RISK-06"), None)
    assert r06 is not None
    assert r06.severity == CRITICAL


def test_risk06_b32_fail_no_open_surface_no_fire():
    from clawcheck.catalog import Finding
    fake_b32 = Finding(
        id="B32", title="Control plane exposed", severity=CRITICAL,
        status=FAIL, detail="test", fix="test",
        framework="Control Plane", scored=False,
    )
    cfg = {"channels": {"telegram": {"dmPolicy": "allowlist"}}}
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b32]
    paths = risk_paths(ctx, f)
    assert not any(p.id == "RISK-06" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Rule RISK-07: self-modification (writable bootstrap + exec, no approval)  -> HIGH
# ──────────────────────────────────────────────────────────────────────────────

def test_risk07_b20_fail_plus_exec_no_approval():
    from clawcheck.catalog import Finding
    fake_b20 = Finding(
        id="B20", title="Bootstrap writable", severity=HIGH,
        status=FAIL, detail="test", fix="test",
        framework="Write Integrity", scored=True,
    )
    cfg = {"tools": {"exec": {"security": "full"}}}
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b20]
    paths = risk_paths(ctx, f)
    assert any(p.id == "RISK-07" for p in paths)
    r07 = next(p for p in paths if p.id == "RISK-07")
    assert r07.severity == HIGH


def test_risk07_b22_fail_plus_exec_no_approval():
    from clawcheck.catalog import Finding
    fake_b22 = Finding(
        id="B22", title="Self-modification", severity=HIGH,
        status=FAIL, detail="test", fix="test",
        framework="Write Integrity", scored=True,
    )
    cfg = {"tools": {"exec": {"security": "full"}}}
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b22]
    paths = risk_paths(ctx, f)
    assert any(p.id == "RISK-07" for p in paths)


def test_risk07_with_approval_no_fire():
    from clawcheck.catalog import Finding
    fake_b20 = Finding(
        id="B20", title="Bootstrap writable", severity=HIGH,
        status=FAIL, detail="test", fix="test",
        framework="Write Integrity", scored=True,
    )
    cfg = {
        "tools": {"exec": {"security": "full"}, "requireApproval": True},
    }
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b20]
    paths = risk_paths(ctx, f)
    assert not any(p.id == "RISK-07" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Rule RISK-08: session cross-user + multi-user channel  -> MEDIUM
# ──────────────────────────────────────────────────────────────────────────────

def test_risk08_dm_scope_main_plus_group_channel():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"slack": {"groupPolicy": "allowlist"}},
    }
    paths = _paths(cfg)
    ids = [p.id for p in paths]
    assert "RISK-08" in ids
    r08 = next(p for p in paths if p.id == "RISK-08")
    assert r08.severity == MEDIUM


def test_risk08_b39_fail_plus_group_channel():
    from clawcheck.catalog import Finding
    fake_b39 = Finding(
        id="B39", title="Session cross-user", severity=MEDIUM,
        status=FAIL, detail="test", fix="test",
        framework="Session Isolation", scored=False,
    )
    cfg = {"channels": {"discord": {"groupPolicy": "open"}}}
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b39]
    paths = risk_paths(ctx, f)
    assert any(p.id == "RISK-08" for p in paths)


def test_risk08_dm_scope_main_no_group_channel_no_fire():
    cfg = {
        "session": {"dmScope": "main"},
        "channels": {"slack": {"dmPolicy": "allowlist"}},  # no groupPolicy
    }
    paths = _paths(cfg)
    assert not any(p.id == "RISK-08" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Empty config -> no paths
# ──────────────────────────────────────────────────────────────────────────────

def test_empty_config_no_paths():
    paths = _paths({})
    assert paths == []


def test_minimal_config_no_paths():
    cfg = {
        "gateway": {"bind": "127.0.0.1:8080", "auth": {"mode": "token",
                    "token": "a-very-long-token-of-32-characters"}},
        "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
        "logging": {"redactSensitive": "tools"},
    }
    paths = _paths(cfg)
    assert paths == []


# ──────────────────────────────────────────────────────────────────────────────
# Deduplication and ordering
# ──────────────────────────────────────────────────────────────────────────────

def test_paths_sorted_critical_before_high_before_medium():
    from clawcheck.catalog import Finding
    fake_b32 = Finding(
        id="B32", title="Control plane exposed", severity=CRITICAL,
        status=FAIL, detail="test", fix="test",
        framework="Control Plane", scored=False,
    )
    cfg = {
        "channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
        "gateway": {"auth": {"password": "s3cr3t"}},
        "tools_elevated": {"allowFrom": {"telegram": ["*"]}},
        "session": {"dmScope": "main"},
    }
    ctx = _ctx(cfg)
    f = _findings(ctx) + [fake_b32]
    paths = risk_paths(ctx, f)
    # severity ordering must be non-decreasing (CRITICAL=0, HIGH=1, MEDIUM=2)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    orders = [sev_order[p.severity] for p in paths]
    assert orders == sorted(orders)


def test_paths_deduplicated_by_id():
    # Even if two rules could produce the same id (hypothetically), ids are unique
    cfg = {
        "channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    paths = _paths(cfg)
    ids = [p.id for p in paths]
    assert len(ids) == len(set(ids))


# ──────────────────────────────────────────────────────────────────────────────
# render_risk_paths: chain arrows and ascii-safety
# ──────────────────────────────────────────────────────────────────────────────

def test_render_risk_paths_contains_chain_arrow():
    p = RiskPath(
        id="RISK-01", severity=CRITICAL,
        title="Test chain",
        chain=["step A", "step B", "step C"],
        why="because", fix="do this",
    )
    out = render_risk_paths([p])
    assert "step A" in out
    assert "step B" in out
    assert "step C" in out
    # must have an arrow connector
    assert (" -> " in out or " → " in out)


def test_render_risk_paths_ascii_only_no_non_ascii():
    p = RiskPath(
        id="RISK-01", severity=CRITICAL,
        title="Test chain",
        chain=["step A", "step B"],
        why="because — this is why",  # em dash
        fix="fix → this",             # right arrow
    )
    out = render_risk_paths([p], ascii_only=True)
    out.encode("ascii")   # must not raise
    assert " -> " in out  # ascii arrow used


def test_render_risk_paths_empty_returns_no_chains_message():
    out = render_risk_paths([])
    assert "No dangerous capability chains detected" in out
    # ascii_only version also stays ascii
    out_ascii = render_risk_paths([], ascii_only=True)
    out_ascii.encode("ascii")


def test_render_risk_paths_has_header():
    p = RiskPath(
        id="RISK-02", severity=HIGH,
        title="Trifecta",
        chain=["a", "b", "c"],
        why="why", fix="fix",
    )
    out = render_risk_paths([p])
    assert "Highest-risk paths" in out


def test_render_risk_paths_shows_severity_tag():
    p = RiskPath(
        id="RISK-03", severity=HIGH,
        title="Sandbox issue",
        chain=["x", "y"],
        why="w", fix="f",
    )
    out = render_risk_paths([p])
    assert "[HIGH]" in out


# ──────────────────────────────────────────────────────────────────────────────
# CLI --risk-paths flag
# ──────────────────────────────────────────────────────────────────────────────

def test_cli_risk_paths_flag_returns_zero(capsys, tmp_path):
    cfg = tmp_path / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "127.0.0.1"}}')
    rc = main(["--home", str(tmp_path), "--no-native", "--risk-paths"])
    assert rc == 0
    out = capsys.readouterr().out
    # either the "no chains" message or a risk path section
    assert ("No dangerous capability chains" in out
            or "Highest-risk paths" in out)


def test_cli_risk_paths_flag_prints_chains_on_vuln_config(capsys, tmp_path):
    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({
        "channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }))
    rc = main(["--home", str(tmp_path), "--no-native", "--risk-paths", "--ascii"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Highest-risk paths" in out
    # The human section shows severity + title + chain (the RISK-0x id lives in --json, not here).
    assert "CRITICAL" in out
    assert "->" in out  # the capability chain is rendered as "A -> B -> C"


# ──────────────────────────────────────────────────────────────────────────────
# render_json includes risk_paths key
# ──────────────────────────────────────────────────────────────────────────────

def test_render_json_includes_risk_paths_key(tmp_path):
    cfg_path = tmp_path / "openclaw.json"
    cfg_path.write_text(json.dumps({
        "channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }))
    from clawcheck import audit
    from clawcheck.risk import risk_paths as compute_paths
    ctx, findings, score = audit(tmp_path)
    paths = compute_paths(ctx, findings)
    out = render_json(findings, score, risk=paths)
    data = json.loads(out)
    assert "risk_paths" in data
    assert isinstance(data["risk_paths"], list)
    assert len(data["risk_paths"]) > 0
    rp = data["risk_paths"][0]
    assert "id" in rp
    assert "severity" in rp
    assert "title" in rp
    assert "chain" in rp
    assert isinstance(rp["chain"], list)
    assert "why" in rp
    assert "fix" in rp


def test_render_json_risk_none_omits_key():
    from clawcheck import audit
    ctx, findings, score = audit(FIXTURES / "home_safe")
    out = render_json(findings, score)
    data = json.loads(out)
    assert "risk_paths" not in data


def test_render_json_risk_empty_list_includes_key():
    from clawcheck import audit
    ctx, findings, score = audit(FIXTURES / "home_safe")
    out = render_json(findings, score, risk=[])
    data = json.loads(out)
    assert "risk_paths" in data
    assert data["risk_paths"] == []


# ──────────────────────────────────────────────────────────────────────────────
# CLI --json flag includes risk_paths
# ──────────────────────────────────────────────────────────────────────────────

def test_cli_json_includes_risk_paths(capsys, tmp_path):
    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({
        "channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }))
    rc = main(["--home", str(tmp_path), "--no-native", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "risk_paths" in data
    assert len(data["risk_paths"]) > 0


# ──────────────────────────────────────────────────────────────────────────────
# Score determinism: A-F score UNCHANGED whether or not risk is passed
# ──────────────────────────────────────────────────────────────────────────────

def test_score_unchanged_with_and_without_risk(tmp_path):
    cfg_path = tmp_path / "openclaw.json"
    cfg_path.write_text(json.dumps({
        "channels": {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
        "gateway": {"auth": {"password": "s3cr3t"}},
    }))
    from clawcheck import audit
    from clawcheck.risk import risk_paths as compute_paths
    ctx, findings, score_without = audit(tmp_path)
    paths = compute_paths(ctx, findings)

    # Score with risk rendered in JSON
    out_with = json.loads(render_json(findings, score_without, risk=paths))
    out_without = json.loads(render_json(findings, score_without))

    assert out_with["score"] == out_without["score"]
    assert out_with["grade"] == out_without["grade"]
    assert out_with["capped"] == out_without["capped"]
    assert out_with["raw_score"] == out_without["raw_score"]


def test_score_unchanged_vuln_fixture():
    from clawcheck import audit
    from clawcheck.risk import risk_paths as compute_paths
    ctx, findings, score = audit(FIXTURES / "home_vuln")
    compute_paths(ctx, findings)  # smoke: must run without affecting the score
    # Score is driven only by findings, not by risk paths
    score2 = compute(findings)
    assert score.score == score2.score
    assert score.grade == score2.grade


def test_score_unchanged_safe_fixture():
    from clawcheck import audit
    from clawcheck.risk import risk_paths as compute_paths
    ctx, findings, score = audit(FIXTURES / "home_safe")
    compute_paths(ctx, findings)  # smoke: must run without affecting the score
    score2 = compute(findings)
    assert score.score == score2.score
    assert score.grade == score2.grade


# ──────────────────────────────────────────────────────────────────────────────
# render_report: risk section appended when risk is provided
# ──────────────────────────────────────────────────────────────────────────────

def test_render_report_with_risk_includes_section():
    from clawcheck import audit
    from clawcheck.risk import risk_paths as compute_paths
    ctx, findings, score = audit(FIXTURES / "home_vuln")
    paths = compute_paths(ctx, findings)
    out_with = render_report(findings, score, risk=paths)
    out_without = render_report(findings, score)
    if paths:
        assert "Highest-risk paths" in out_with
        assert "Highest-risk paths" not in out_without
    else:
        # safe fixture: no paths -> both identical-ish
        assert out_with == out_without


def test_render_report_without_risk_byte_identical():
    """render_report(risk=None) must be byte-identical to render_report() (no kwarg)."""
    from clawcheck import audit
    ctx, findings, score = audit(FIXTURES / "home_safe")
    assert render_report(findings, score, risk=None) == render_report(findings, score)


def test_render_json_without_risk_byte_identical():
    """render_json(risk=None) must be byte-identical to render_json() (no kwarg)."""
    from clawcheck import audit
    ctx, findings, score = audit(FIXTURES / "home_safe")
    assert render_json(findings, score, risk=None) == render_json(findings, score)


# ──────────────────────────────────────────────────────────────────────────────
# Fleet configs: none must gain a new FAIL on existing checks
# (risk paths are a separate layer; scored findings must not change)
# ──────────────────────────────────────────────────────────────────────────────

FLEET_CONFIGS = [
    "/home/glodi/Backups/.openclaw/openclaw.json",
    "/home/glodi/Backups/.openclaw-analyst/openclaw.json",
    "/home/glodi/Backups/.openclaw-architect/openclaw.json",
    "/home/glodi/Backups/.openclaw-builder/openclaw.json",
    "/home/glodi/Backups/.openclaw-designer/openclaw.json",
    "/home/glodi/Backups/.openclaw-qa/openclaw.json",
    "/home/glodi/Backups/n/.openclaw/openclaw.json",
]


@pytest.mark.parametrize("cfg_path", [p for p in FLEET_CONFIGS if Path(p).is_file()])
def test_fleet_config_score_unaffected_by_risk(cfg_path):
    """Risk paths are additive; the A-F score must not change."""
    from clawcheck import audit
    from clawcheck.risk import risk_paths as compute_paths
    home = str(Path(cfg_path).parent)
    ctx, findings, score = audit(home)
    compute_paths(ctx, findings)  # smoke: must run without affecting the score
    score2 = compute(findings)
    assert score.score == score2.score, f"Score changed for {cfg_path}"
    assert score.grade == score2.grade, f"Grade changed for {cfg_path}"


@pytest.mark.parametrize("cfg_path", [p for p in FLEET_CONFIGS if Path(p).is_file()])
def test_fleet_config_risk_paths_are_list(cfg_path):
    """risk_paths() always returns a list (possibly empty) for fleet configs."""
    from clawcheck import audit
    from clawcheck.risk import risk_paths as compute_paths
    home = str(Path(cfg_path).parent)
    ctx, findings, score = audit(home)
    paths = compute_paths(ctx, findings)
    assert isinstance(paths, list)
    for p in paths:
        assert isinstance(p, RiskPath)
        assert p.severity in (CRITICAL, HIGH, MEDIUM)
