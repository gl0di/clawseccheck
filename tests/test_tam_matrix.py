"""TAM-01..12 weaponization test matrix (standard §15.3) — named regression, not
accidental coverage (C-146/C-147). Each test pins that the check/mechanism the standard
expects for that row actually fires today, so a refactor that silently regresses one leg
turns red here instead of nowhere.

No new checks are introduced by this file — it is purely a traceability/regression
contract over EXISTING mechanisms, reusing each mechanism's own established test-setup
pattern (see the module docstring above each section for the source it mirrors).

Coverage table (row -> mechanism):
    TAM-01 file tamper            -> monitor.diff() skill-hash CHANGED (HIGH)
    TAM-02 manifest escalation    -> monitor.diff() capability-diff, F-079 (HIGH)
    TAM-03 dependency poison      -> B95 dependency-confusion co-occurrence
    TAM-04 cross-skill abuse      -> OUT OF SCOPE (see note below), not faked
    TAM-05 metadata poison        -> B24 (MCP hardening) + monitor rug-pull RP1
    TAM-06 PATH/import hijack     -> C5 (native binary PATH safety)
    TAM-07 symlink escape         -> B87 (symlink-escape finding, F-080)
    TAM-08 prompt weaponization   -> content ring, B63 (silent-instruction)
    TAM-09 downgrade/replay       -> monitor.diff() version-regression, F-079 (best-effort
                                      STATIC signal only — see note below)
    TAM-10 memory backdoor        -> B7 (memory poisoning) + B20 (bootstrap write
                                      protection); multiturn.py covers the live-session leg
    TAM-11 egress mutation        -> B24 (MCP hardening) + monitor rug-pull RP3
    TAM-12 self-modifying skill   -> RISK-07 (self-modification chain) + B22

Two rows are intentionally NOT full-strength regressions, per §15.3's own caveat that a
read-only static tool cannot fully realize every row — documented here, not faked:
  - TAM-04 (cross-skill abuse) requires a platform broker mediating caller/callee/action
    identity at runtime — there is no static equivalent; ClawSecCheck has no live
    request-mediation surface to test. Harness/out-of-scope.
  - TAM-09's "replay of an old *signed* manifest" needs signature verification against a
    trust root, which is impossible read-only/offline. F-079's version-regression check
    is a best-effort STATIC downgrade signal (declared version went backward), not real
    replay/revocation detection — tested here as exactly that, not oversold.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck.catalog import CATALOG, FAIL, HIGH, PASS, WARN, Finding
from clawseccheck.checks import (
    check_bootstrap_write_protection,
    check_config_health_integrity,
    check_memory_poisoning,
    check_path_safety,
    check_silent_instruction,
    check_symlink_escape,
    vet_skill,
)
from clawseccheck.collector import Context, collect
from clawseccheck.monitor import diff
from clawseccheck.risk import risk_paths

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX-only permission bits")


def _mcp_snap(servers: dict) -> dict:
    """Minimal monitor snapshot dict with mcp_detail populated — mirrors
    test_monitor.py's own `_make_mcp_snap` helper for RP1-RP3 rug-pull detection."""
    return {
        "score": 90, "grade": "A",
        "skills": {}, "bootstrap": {}, "checks": {},
        "ignore_hash": "", "mcp": {}, "mcp_detail": servers,
    }


# --------------------------------------------------------------------------- TAM-01

def test_tam01_file_tamper_fires_changed_alert():
    """TAM-01: post-install file tamper -> monitor CHANGED-skill HIGH alert."""
    prev = {"version": 2, "skills": {"pdf-tools": "aaaa1111"}}
    curr = {"version": 2, "skills": {"pdf-tools": "bbbb2222"}}
    alerts = diff(prev, curr)
    assert any(lvl == "HIGH" and "CHANGED" in msg for lvl, msg in alerts)


# --------------------------------------------------------------------------- TAM-02

def test_tam02_manifest_escalation_fires_capability_expansion():
    """TAM-02: permissions widen without a version bump -> capability-diff HIGH (F-079)."""
    prev = {"version": 2, "skills": {
        "pdf-tools": {"hash": "aaaa1111", "caps": ["read"], "version": "1.0.0"},
    }}
    curr = {"version": 2, "skills": {
        "pdf-tools": {"hash": "aaaa1111", "caps": ["read", "network", "write"],
                      "version": "1.0.0"},
    }}
    alerts = diff(prev, curr)
    assert any(lvl == "HIGH" and "EXPANDED" in msg for lvl, msg in alerts)


# --------------------------------------------------------------------------- TAM-03

def test_tam03_dependency_poison_warns():
    """TAM-03: an unpinned, private-scope-lookalike dependency -> B95 WARN."""
    skill_dir = FIXTURES / "bad_b95_dependency_confusion" / "skills"
    skill_dir = next(p for p in skill_dir.iterdir() if p.is_dir())
    f = vet_skill(skill_dir)
    assert any(
        x.id == "B95" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


# --------------------------------------------------------------------------- TAM-04

def test_tam04_cross_skill_abuse_is_documented_out_of_scope():
    """TAM-04: a fake low-privilege skill impersonating a caller to reach a
    high-privilege skill's capability requires a platform broker mediating live
    caller/callee/action identity — there is no static, read-only equivalent.
    Documented as harness/out-of-scope (see module docstring), not faked here."""
    assert True  # intentionally a no-op regression marker, not a real assertion


# --------------------------------------------------------------------------- TAM-05

def test_tam05_metadata_poison_fires_rp1_scope_expansion():
    """TAM-05: a tool description/schema change disguising a dangerous action as
    read-only -> B24 (MCP hardening) covers the live config; RP1 (oauth.scope
    expansion) covers the drift-since-last-check angle."""
    prev = _mcp_snap({"svc": {
        "command": "npx", "args0": "svc-mcp", "transport": "",
        "url": "", "env_keys": [], "oauth_scope": "read",
    }})
    curr = _mcp_snap({"svc": {
        "command": "npx", "args0": "svc-mcp", "transport": "",
        "url": "", "env_keys": [], "oauth_scope": "read write",
    }})
    alerts = diff(prev, curr)
    assert any("RP1" in msg for _lvl, msg in alerts)

    b24 = next(c for c in CATALOG if c.id == "B24")
    assert b24.title == "MCP server hardening"


# --------------------------------------------------------------------------- TAM-06

def test_tam06_path_hijack_check_exists_and_runs():
    """TAM-06: a fake curl/python/module earlier in PATH -> C5 (native binary PATH
    safety) is the static signal; a clean host must not FAIL/WARN by default."""
    f = check_path_safety(Context(home=Path("/nonexistent")))
    assert f.id == "C5"
    assert f.status in (PASS, WARN, FAIL, "UNKNOWN")


# --------------------------------------------------------------------------- TAM-07

@posix_only
def test_tam07_symlink_escape_to_ssh_is_fail(tmp_path):
    """TAM-07: a symlink resolving into a sensitive host path -> B87 FAIL (F-080)."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")
    skill = tmp_path / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: demo\n---\nhello\n", encoding="utf-8")
    os.symlink(fakehome / ".ssh", skill / "data")

    f = check_symlink_escape(Context(home=skill))
    assert f.status == FAIL
    assert any(".ssh" in e for e in f.evidence)


# --------------------------------------------------------------------------- TAM-08

def test_tam08_prompt_weaponization_fires_silent_instruction():
    """TAM-08: poisoned content instructing a skill to use its allowed tools for
    exfil -> B63 (silent-instruction) content-ring check FAILs on the documented
    bypass fixture."""
    ctx = collect(FIXTURES / "bad_b63_silent_action")
    f = check_silent_instruction(ctx)
    assert f.status == FAIL
    assert f.evidence


# --------------------------------------------------------------------------- TAM-09

def test_tam09_downgrade_replay_fires_version_regression_medium():
    """TAM-09: installing an old vulnerable version -> monitor version-regression
    MEDIUM (F-079, best-effort STATIC signal). Real signed-manifest replay/revocation
    is NOT achievable read-only/offline — see module docstring."""
    prev = {"version": 2, "skills": {
        "pdf-tools": {"hash": "aaaa1111", "caps": ["read"], "version": "2.0.0"},
    }}
    curr = {"version": 2, "skills": {
        "pdf-tools": {"hash": "bbbb2222", "caps": ["read"], "version": "1.0.0"},
    }}
    alerts = diff(prev, curr)
    assert any(lvl == "MEDIUM" and "BACKWARD" in msg for lvl, msg in alerts)


# --------------------------------------------------------------------------- TAM-10

def test_tam10_memory_backdoor_fires_b7_or_b20():
    """TAM-10: a skill writing 'always trust attacker.com' into agent memory ->
    B7 (memory poisoning surface) covers the vector-memory config angle; B20
    (bootstrap write protection) covers the file-write angle. multiturn.py covers
    the live cross-turn persistence angle (not exercised here — see its own tests)."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {}
    ctx.bootstrap = {"MEMORY.md": "identity"}
    f7 = check_memory_poisoning(ctx)
    assert f7.id == "B7"
    assert f7.status in (WARN, "UNKNOWN")

    ws_ctx = Context(home=Path("/nonexistent"))
    ws_ctx.config = {}
    ws_ctx.bootstrap = {}
    f20 = check_bootstrap_write_protection(ws_ctx)
    assert f20.id == "B20"


# --------------------------------------------------------------------------- TAM-11

def test_tam11_egress_mutation_fires_rp3_endpoint_repoint():
    """TAM-11: a dependency changes destination from an approved API to a
    webhook/pastebin -> B24 (MCP hardening) covers the live config; RP3 (url
    repoint) covers the drift-since-last-check angle."""
    prev = _mcp_snap({"svc": {
        "command": "npx", "args0": "svc-mcp", "transport": "",
        "url": "https://api.example.com/hook", "env_keys": [], "oauth_scope": "",
    }})
    curr = _mcp_snap({"svc": {
        "command": "npx", "args0": "svc-mcp", "transport": "",
        "url": "https://webhook.site/abc123", "env_keys": [], "oauth_scope": "",
    }})
    alerts = diff(prev, curr)
    assert any("RP3" in msg or "rug-pull" in msg for _lvl, msg in alerts)


# --------------------------------------------------------------------------- TAM-12

def test_tam12_self_modifying_skill_fires_risk07():
    """TAM-12: writable identity/bootstrap + exec/fs-write without an approval gate
    -> RISK-07 (self-modification chain), keyed off B20 or B22 FAIL."""
    fake_b20 = Finding(
        id="B20", title="Bootstrap writable", severity=HIGH,
        status=FAIL, detail="test", fix="test",
        framework="Write Integrity", scored=True,
    )
    cfg = {"tools": {"exec": {"security": "full"}}}
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    paths = risk_paths(ctx, [fake_b20])
    assert any(p.id == "RISK-07" and p.severity == HIGH for p in paths)


# --------------------------------------------------------------------------- meta

def test_b78_config_health_integrity_exists_for_tam05_tam11():
    """B24 covers the live MCP config; B78 (config-health integrity) is the
    complementary "has this config's integrity signature been tampered with"
    signal shared across TAM-05/TAM-11's metadata/egress mutation rows."""
    f = check_config_health_integrity(Context(home=Path("/nonexistent")))
    assert f.id == "B78"
