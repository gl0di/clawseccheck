"""A truncated content ring must cost coverage, never a finding already computed.

The per-skill inventory used to compute the base skill verdict and the content ring
inside ONE budgeted block, so a deadline firing inside the ring abandoned the block and
discarded the verdict the engine had ALREADY produced. Measured on a real hostile skill,
a genuine DANGEROUS verdict was replaced by "per-skill scan budget exhausted" — the scan
got slower and the answer got *safer*, which is the failure mode this project treats as
worse than a crash.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.collector import (
    Context,
    _read_skill_text,
    read_skill_js,
    read_skill_python,
    read_skill_shell,
)
from clawseccheck.report import _skill_inventory
from clawseccheck.scanbudget import ScanBudgetExceeded

# Chosen deliberately: this fixture's BASE check (check_installed_skills) is itself
# actionable, so a lost base verdict is observable. A fixture caught only by a ring check
# would report UNKNOWN under truncation for the correct reason — the engine genuinely
# never ran the check that sees it — and could not distinguish the regression.
MALICIOUS = Path("fixtures/bad_b13_fetch_to_exec/skills/bootstrap-helper")


def _ctx_for(target: Path) -> Context:
    ctx = Context(home=target)
    ctx.installed_skills = {target.name: _read_skill_text(target, ctx)}
    ctx.installed_skill_py = {target.name: read_skill_python(target, ctx)}
    ctx.installed_skill_shell = {target.name: read_skill_shell(target, ctx)}
    ctx.installed_skill_js = {target.name: read_skill_js(target, ctx)}
    ctx.installed_skill_dirs = {target.name: target}
    return ctx


def _starve_the_ring(monkeypatch):
    """Make the ring behave exactly as an outer hard deadline firing inside it."""
    def _boom(*_a, **_kw):
        raise ScanBudgetExceeded

    monkeypatch.setattr("clawseccheck.checks._run_content_ring", _boom)


@pytest.mark.skipif(not MALICIOUS.is_dir(), reason=f"fixture missing: {MALICIOUS}")
def test_truncated_ring_keeps_the_base_verdict(monkeypatch):
    """The actionable verdict survives; only coverage is lost."""
    full = _skill_inventory(_ctx_for(MALICIOUS))[0]
    assert full["status"] in (FAIL, WARN), "fixture no longer produces an actionable verdict"

    _starve_the_ring(monkeypatch)
    truncated = _skill_inventory(_ctx_for(MALICIOUS))[0]

    assert truncated["status"] == full["status"], (
        "a ring cut short discarded the already-computed verdict "
        f"({full['status']} -> {truncated['status']})"
    )
    assert truncated["verdict"] == full["verdict"]


@pytest.mark.skipif(not MALICIOUS.is_dir(), reason=f"fixture missing: {MALICIOUS}")
def test_truncated_ring_still_says_coverage_was_lost(monkeypatch):
    """Keeping the verdict must not mean hiding the gap — both have to be true."""
    _starve_the_ring(monkeypatch)
    row = _skill_inventory(_ctx_for(MALICIOUS))[0]
    assert any("coverage is incomplete" in r for r in row["reasons"]), (
        f"no coverage-gap reason surfaced: {row['reasons']}"
    )


def test_truncated_ring_on_a_benign_skill_is_not_reported_clean(tmp_path, monkeypatch):
    """With nothing else to go on, a partial scan must not read as a clean one."""
    ctx = Context(home=tmp_path)
    ctx.installed_skills = {"demo": "---\nname: demo\ndescription: d\n---\n\n# Demo\n"}
    ctx.installed_skill_py = {"demo": []}
    ctx.installed_skill_shell = {"demo": []}
    ctx.installed_skill_js = {"demo": []}
    ctx.installed_skill_dirs = {"demo": tmp_path}

    _starve_the_ring(monkeypatch)
    row = _skill_inventory(ctx)[0]
    assert row["status"] != PASS
    assert any("coverage is incomplete" in r for r in row["reasons"])


@pytest.mark.skipif(not MALICIOUS.is_dir(), reason=f"fixture missing: {MALICIOUS}")
def test_a_budget_exhausted_before_the_base_check_is_still_unknown(monkeypatch):
    """The other half of the contract: if the BASE check never finished, there is no
    verdict to keep, and UNKNOWN is the honest answer."""
    def _boom(*_a, **_kw):
        raise ScanBudgetExceeded

    monkeypatch.setattr("clawseccheck.checks.check_installed_skills", _boom)
    row = _skill_inventory(_ctx_for(MALICIOUS))[0]
    assert row["status"] == UNKNOWN
    assert any("budget exhausted" in r for r in row["reasons"])
