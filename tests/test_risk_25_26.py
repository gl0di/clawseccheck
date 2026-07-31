"""RISK-25 (I-030) and RISK-26 (I-031): pure finding-correlation chains.

Both rules read NO config themselves -- only `_finding_status(findings, "<id>")` on
findings already emitted by other checks (B325/B174 for RISK-25; B175/B26/B171/B179 for
RISK-26). See clawseccheck/risk.py around "I-030 / RISK-25" and "I-031 / RISK-26" for the
design rationale. That is the whole safety argument these tests exist to pin: since
every leg is a synthetic Finding injected here (never a crafted config), a chain firing
can only ever be attributed to the correlation logic itself, never to some check this
file accidentally re-triggers.

Idiom mirrors tests/test_risk.py's RISK-23 section (`_anchor` / `extra_findings=`):
anchors/legs are synthetic Findings appended to a real (empty-config) run_all() result,
relying on `_finding_status`'s documented "last entry wins" override semantics.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, HIGH, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks import run_all
from clawseccheck.collector import Context
from clawseccheck.risk import risk_paths

# ──────────────────────────────────────────────────────────────────────────────
# Helpers (mirrors tests/test_risk.py's _ctx / _paths / _anchor)
# ──────────────────────────────────────────────────────────────────────────────


def _ctx(cfg: dict) -> Context:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    return ctx


def _paths(cfg: dict, extra_findings=None):
    ctx = _ctx(cfg)
    f = run_all(ctx)
    if extra_findings:
        f = list(f) + list(extra_findings)
    return risk_paths(ctx, f)


def _leg(cid: str, status: str = WARN) -> Finding:
    """A synthetic Finding used purely to set one leg's status for correlation."""
    return Finding(cid, "synthetic leg", HIGH, status, "detail", "fix", "Test")


def _ids(paths):
    return [p.id for p in paths]


# ──────────────────────────────────────────────────────────────────────────────
# RISK-25 -- B325 (WARN) + B174 (WARN|FAIL)
# ──────────────────────────────────────────────────────────────────────────────


def test_risk25_both_legs_fire():
    paths = _paths({}, extra_findings=[_leg("B325", WARN), _leg("B174", WARN)])
    p = next((p for p in paths if p.id == "RISK-25"), None)
    assert p is not None, _ids(paths)
    assert p.id == "RISK-25"
    assert p.severity == MEDIUM


def test_risk25_b174_fail_also_fires():
    """Docstring says B174 in (WARN, FAIL) satisfies the leg -- pin the FAIL branch too."""
    paths = _paths({}, extra_findings=[_leg("B325", WARN), _leg("B174", FAIL)])
    assert any(p.id == "RISK-25" for p in paths), _ids(paths)


def test_risk25_only_b325_no_fire():
    paths = _paths({}, extra_findings=[_leg("B325", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_only_b174_no_fire():
    paths = _paths({}, extra_findings=[_leg("B174", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_neither_leg_no_fire():
    paths = _paths({})
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b325_pass_does_not_count():
    """B325 must be exactly WARN -- a PASS (canonical feed) must not satisfy the leg."""
    paths = _paths({}, extra_findings=[_leg("B325", PASS), _leg("B174", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b325_fail_does_not_count():
    """B325 is documented WARN-only (never FAIL); the rule's own predicate is
    `!= WARN: return None`, so even a hypothetical FAIL must not satisfy this leg."""
    paths = _paths({}, extra_findings=[_leg("B325", FAIL), _leg("B174", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b325_unknown_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B325", UNKNOWN), _leg("B174", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b174_pass_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B325", WARN), _leg("B174", PASS)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b174_unknown_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B325", WARN), _leg("B174", UNKNOWN)])
    assert not any(p.id == "RISK-25" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# RISK-26 -- B175 (FAIL only) + at least one of B26/B171/B179 (WARN|FAIL)
# ──────────────────────────────────────────────────────────────────────────────


def test_risk26_b175_plus_b26_fires():
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B26", WARN)])
    p = next((p for p in paths if p.id == "RISK-26"), None)
    assert p is not None, _ids(paths)
    assert p.id == "RISK-26"
    assert p.severity == HIGH
    assert "quoted/history" in " ".join(p.chain).lower()


def test_risk26_b175_plus_b171_fires():
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B171", WARN)])
    p = next((p for p in paths if p.id == "RISK-26"), None)
    assert p is not None, _ids(paths)
    assert "command surface" in " ".join(p.chain).lower()


def test_risk26_b175_plus_b179_fires():
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B179", WARN)])
    p = next((p for p in paths if p.id == "RISK-26"), None)
    assert p is not None, _ids(paths)
    assert "webhook" in " ".join(p.chain).lower()


def test_risk26_b175_plus_b171_fail_also_fires():
    """Ingress arms accept WARN OR FAIL -- pin the FAIL branch too, not just WARN."""
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B171", FAIL)])
    assert any(p.id == "RISK-26" for p in paths), _ids(paths)


def test_risk26_all_three_ingress_arms_all_named_in_chain():
    paths = _paths({}, extra_findings=[
        _leg("B175", FAIL), _leg("B26", WARN), _leg("B171", WARN), _leg("B179", WARN),
    ])
    p = next(p for p in paths if p.id == "RISK-26")
    chain_text = " ".join(p.chain).lower()
    assert "quoted/history" in chain_text
    assert "command surface" in chain_text
    assert "webhook" in chain_text


def test_risk26_only_b175_no_ingress_no_fire():
    """Leg A alone (no untrusted-ingress arm at all) must not fire."""
    paths = _paths({}, extra_findings=[_leg("B175", FAIL)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_only_ingress_leg_no_b175_no_fire():
    """Ingress arm alone, without B175==FAIL, must not fire."""
    paths = _paths({}, extra_findings=[_leg("B26", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)
    paths = _paths({}, extra_findings=[_leg("B171", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)
    paths = _paths({}, extra_findings=[_leg("B179", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_neither_leg_no_fire():
    paths = _paths({})
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_b175_warn_does_not_count_as_leg_a():
    """Docstring is explicit: only B175==FAIL proves the full unattended pipeline; its
    WARN branches (dormant-tool or partial-gap) must NOT satisfy this leg."""
    paths = _paths({}, extra_findings=[_leg("B175", WARN), _leg("B26", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_b175_pass_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B175", PASS), _leg("B26", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_b175_unknown_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B175", UNKNOWN), _leg("B26", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_ingress_leg_pass_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B26", PASS)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_ingress_leg_unknown_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B26", UNKNOWN)])
    assert not any(p.id == "RISK-26" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Both rules: robustness on empty / unrelated findings -- must never raise
# ──────────────────────────────────────────────────────────────────────────────


def test_empty_findings_list_does_not_raise():
    ctx = _ctx({})
    paths = risk_paths(ctx, [])
    assert not any(p.id in ("RISK-25", "RISK-26") for p in paths)


def test_unrelated_findings_only_does_not_raise():
    ctx = _ctx({})
    unrelated = [
        Finding("B1", "unrelated", HIGH, FAIL, "detail", "fix", "Test"),
        Finding("B999", "unrelated", MEDIUM, WARN, "detail", "fix", "Test"),
    ]
    paths = risk_paths(ctx, unrelated)
    assert not any(p.id in ("RISK-25", "RISK-26") for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Regression: existing chains must fire exactly as tests/test_risk.py already pins,
# i.e. RISK-25/RISK-26 must not have altered any other rule's behaviour as a side
# effect (both live in the same `risk_paths` dispatch list).
# ──────────────────────────────────────────────────────────────────────────────


def test_existing_risk01_unaffected():
    cfg = {
        "channels": {"telegram": {"groupPolicy": "open", "dmPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    paths = _paths(cfg)
    ids = _ids(paths)
    assert "RISK-01" in ids
    r01 = next(p for p in paths if p.id == "RISK-01")
    assert r01.severity == "CRITICAL"
    assert "telegram" in r01.chain[0]


def test_existing_risk23_unaffected():
    paths = _paths({}, extra_findings=[_leg("B99"), _leg("B150")])
    p = next((p for p in paths if p.id == "RISK-23"), None)
    assert p is not None, _ids(paths)
    assert p.severity == HIGH
