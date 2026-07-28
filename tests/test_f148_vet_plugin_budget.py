"""vet_plugin() gets a per-target CPU-time ceiling.

The vet paths run the content ring outside run_all's own scanbudget (C-159)
protection, so this cost was previously unbounded. Cost is driven by INPUT SIZE,
not content hostility — super-linearly (10KB 0.03s, 100KB 0.52s, 500KB 10.6s,
1MB 41.2s of CPU against collector._MAX_BYTES_PER_SKILL = 1_000_000), so a large
BENIGN target is the expensive case, not a hostile one (the real hostile
`clawstealth` fixture costs 7.93s — less than a large benign target); see the
calibration note on scanbudget.DEFAULT_VET_TARGET_BUDGET_S and the docstring on
checks/_mcp.py:vet_plugin. This pins four things for vet_plugin() specifically:

  1. Normal/clean runs are unaffected by the new default budget (no regression,
     no spurious coverage-gap note).
  2. A budget hit degrades HONESTLY: never a silent PASS, always an explicit
     coverage-gap note naming the reason.
  3. ScanBudgetExceeded raised inside a dispatched stage (e.g. vet_skill) is
     never swallowed by a generic `except Exception` (C-175) — it must reach
     the honest-degradation path, not read as "nothing found here".
  4. The vet_plugin() docstring's coverage-finding promise is actually true: a
     budget hit folds a synthetic VET-COVERAGE finding into the result (same
     shape checks/_vet.py's coverage_gap_finding() emits), which rides
     ring_findings into dossier.build_profile()'s danger axis and floors the
     overall verdict — never a fabricated PASS/A grade for a scan that was cut
     short. (This was previously false: pre-fix, a budget-truncated plugin
     graded N/A with no VET-COVERAGE finding anywhere in ring_findings — see
     test_budget_hit_folds_vet_coverage_finding_into_ring_findings and
     test_budget_hit_dossier_profile_never_reads_clean below, whose whole
     point is to fail if that regresses.)

Deterministic and offline: the budget is exhausted via monkeypatching, never by
sleeping for real wall-clock time.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import vet_plugin
from clawseccheck.dossier import NA, build_profile
from clawseccheck.scanbudget import DEFAULT_VET_TARGET_BUDGET_S, ScanBudgetExceeded

_EMPTY_SCHEMA = {"type": "object", "additionalProperties": False}


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _mk_plugin(root: Path, manifest: dict | None = None, pkg: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if manifest is None:
        manifest = {"id": "demo", "configSchema": _EMPTY_SCHEMA, "skills": ["./skills"]}
    _write(root / "openclaw.plugin.json", json.dumps(manifest))
    if pkg is not None:
        _write(root / "package.json", json.dumps(pkg))
    return root


def _clean_plugin(tmp_path: Path) -> Path:
    root = _mk_plugin(tmp_path / "plug")
    _write(
        root / "skills" / "hello" / "SKILL.md",
        "---\nname: hello\ndescription: greet the user politely\n---\nSay hello politely.",
    )
    return root


# --------------------------------------------------------------------------- #
# 1. Clean case: default budget doesn't change verdict/evidence.               #
# --------------------------------------------------------------------------- #
def test_clean_plugin_unaffected_by_default_budget(tmp_path):
    root = _clean_plugin(tmp_path)
    f = vet_plugin(root)
    assert f.status == PASS, f.detail
    assert f.id == "PLUGIN-VET"
    assert "1 bundled skill(s)" in f.detail
    ev = "\n".join(f.evidence)
    # no spurious coverage-gap note on a normal run that never hit the ceiling
    assert "time budget" not in ev
    assert "unverified" not in ev


def test_clean_plugin_same_with_explicit_default_budget_kwarg(tmp_path):
    # The new kwarg is additive: passing the documented default explicitly must
    # be indistinguishable from omitting it (every pre-existing caller omits it).
    root = _clean_plugin(tmp_path)
    f_default = vet_plugin(root)
    f_explicit = vet_plugin(root, target_budget_s=DEFAULT_VET_TARGET_BUDGET_S)
    assert f_default.status == f_explicit.status == PASS
    assert f_default.detail == f_explicit.detail
    assert f_default.evidence == f_explicit.evidence


# --------------------------------------------------------------------------- #
# 2. Budget-exhausted case: honest degradation, never a silent PASS.           #
# --------------------------------------------------------------------------- #
def test_budget_exhausted_before_any_work_degrades_to_unknown_with_reason(tmp_path, monkeypatch):
    root = _clean_plugin(tmp_path)
    # Force the very first cooperative check to report the deadline already passed —
    # deterministic, no real wall-clock time burned.
    monkeypatch.setattr("clawseccheck.checks._mcp.cpu_exceeded", lambda deadline: True)
    f = vet_plugin(root, target_budget_s=0.001)
    assert f.status != PASS
    assert f.status == UNKNOWN, f.detail
    ev = "\n".join(f.evidence)
    assert "time budget" in ev
    assert "0.001" in ev or "budget" in ev.lower()


def test_budget_exhausted_mid_sweep_still_reports_partial_findings_honestly(tmp_path, monkeypatch):
    # A budget hit partway through (after the bundled-skill loop already ran) must
    # still surface the coverage-gap note even though earlier work succeeded.
    root = _mk_plugin(
        tmp_path / "plug",
        manifest={"id": "demo", "configSchema": _EMPTY_SCHEMA, "skills": ["./skills"]},
    )
    _write(
        root / "skills" / "hello" / "SKILL.md",
        "---\nname: hello\ndescription: greet the user politely\n---\nSay hello politely.",
    )
    _write(root / "extra.json", json.dumps({"mcpServers": {"x": {"command": "echo"}}}))

    calls = {"n": 0}

    def _flip_after_first(deadline):
        # Let the bundled-skill loop's first check through, then report exhausted.
        calls["n"] += 1
        return calls["n"] > 1

    monkeypatch.setattr("clawseccheck.checks._mcp.cpu_exceeded", _flip_after_first)
    f = vet_plugin(root, target_budget_s=5.0)
    assert f.status != PASS
    assert f.status == UNKNOWN, f.detail
    assert "unverified" in "\n".join(f.evidence)
    assert calls["n"] >= 2  # the loop actually reached (and tripped) the later check


# --------------------------------------------------------------------------- #
# 3. ScanBudgetExceeded raised inside a dispatched stage is never swallowed.   #
# --------------------------------------------------------------------------- #
def test_scan_budget_exceeded_in_vet_skill_not_swallowed_into_pass(tmp_path, monkeypatch):
    root = _clean_plugin(tmp_path)

    def _boom(_sd):
        raise ScanBudgetExceeded

    monkeypatch.setattr("clawseccheck.checks._mcp.vet_skill", _boom)
    f = vet_plugin(root)
    assert f.status != PASS
    assert f.status == UNKNOWN, f.detail
    ev = "\n".join(f.evidence)
    # C-175: a bare `except Exception` catching this first would record it as
    # "bundled skill could not be vetted", NOT the honest budget-exhaustion note.
    assert "could not be vetted" not in ev
    assert "time budget" in ev


def test_scan_budget_exceeded_in_vet_mcp_not_swallowed_into_pass(tmp_path, monkeypatch):
    root = _mk_plugin(tmp_path / "plug", manifest={"id": "demo", "configSchema": _EMPTY_SCHEMA})
    _write(root / "mcp.json", json.dumps({"mcpServers": {"x": {"command": "echo"}}}))

    def _boom(_fp):
        raise ScanBudgetExceeded

    monkeypatch.setattr("clawseccheck.checks._mcp.vet_mcp", _boom)
    f = vet_plugin(root)
    assert f.status != PASS
    assert f.status == UNKNOWN, f.detail
    assert "time budget" in "\n".join(f.evidence)


# --------------------------------------------------------------------------- #
# 4. Docstring contract: a budget hit folds a real VET-COVERAGE finding in,   #
#    which reaches the risk dossier's danger axis and floors the verdict.     #
# --------------------------------------------------------------------------- #
def test_budget_hit_folds_vet_coverage_finding_into_ring_findings(tmp_path, monkeypatch):
    root = _clean_plugin(tmp_path)
    monkeypatch.setattr("clawseccheck.checks._mcp.cpu_exceeded", lambda deadline: True)
    f = vet_plugin(root, target_budget_s=0.001)

    coverage = [r for r in f.ring_findings if r.id == "VET-COVERAGE"]
    assert len(coverage) == 1, f.ring_findings
    cov = coverage[0]
    # Same shape checks/_vet.py's coverage_gap_finding() emits for vet_skill's own
    # content-ring truncation (the docstring's "same id/convention" claim).
    assert cov.status == UNKNOWN
    assert cov.severity == HIGH
    assert cov.scored is False
    assert "coverage is incomplete" in cov.detail


def test_clean_plugin_never_carries_a_vet_coverage_finding(tmp_path):
    # Negative control: a run that never hits the budget must not fold in the
    # synthetic finding — it is specific to budget_hit, not always present.
    root = _clean_plugin(tmp_path)
    f = vet_plugin(root)
    assert all(r.id != "VET-COVERAGE" for r in f.ring_findings)


def test_budget_hit_reports_the_truncation_exactly_once(tmp_path, monkeypatch):
    # C-307: pre-fix, a budget hit stated the SAME coverage-gap fact twice in the
    # rendered evidence — once as a plain-text note (`notes` -> evidence) and once
    # as the synthetic VET-COVERAGE finding folded into `subs` (-> evidence via the
    # `actionable` list). One home now: the synthetic finding. Pin the count, not
    # just presence, on both a distinctive shared phrase and the finding-count.
    root = _clean_plugin(tmp_path)
    monkeypatch.setattr("clawseccheck.checks._mcp.cpu_exceeded", lambda deadline: True)
    f = vet_plugin(root, target_budget_s=0.001)

    ev_text = "\n".join(f.evidence)
    # This exact phrase appeared in BOTH the old note and the old finding detail —
    # a real duplication marker, not an incidental substring.
    phrase = "bundled skills, embedded MCP specs, or runtime JS/TS files"
    assert ev_text.count(phrase) == 1, f.evidence
    # Same fact, different angle: the coverage information rides on exactly one
    # evidence line (the synthetic finding's own "STATUS: detail" line), never a
    # second free-standing note alongside it.
    coverage_lines = [e for e in f.evidence if "coverage is incomplete" in e]
    assert len(coverage_lines) == 1, f.evidence
    # And it is still there at all — dedup must never mean losing the disclosure.
    assert "coverage is incomplete" in ev_text


def test_budget_hit_dossier_profile_never_reads_clean(tmp_path, monkeypatch):
    # This pins the bug the docstring previously overclaimed being fixed: pre-fix, a
    # budget-truncated plugin's dossier profile graded N/A/UNKNOWN — indistinguishable
    # from "nothing to assess" — because no finding from the truncation ever reached
    # the danger axis. Post-fix, the VET-COVERAGE finding reaches
    # dossier._AXIS_BY_ID's danger mapping, which dossier._danger_coverage_gap()
    # recognizes (matching the "coverage is incomplete" detail substring) and floors
    # the overall verdict to WARN — never PASS, never a bare N/A grade. cli.py's own
    # --vet-plugin exit-code mapping (unowned by this file, unchanged) treats a
    # WARN/FAIL overall_status as rc=1, so this WARN floor is exactly what makes the
    # process exit code reflect an incomplete scan.
    root = _clean_plugin(tmp_path)
    monkeypatch.setattr("clawseccheck.checks._mcp.cpu_exceeded", lambda deadline: True)
    f = vet_plugin(root, target_budget_s=0.001)

    profile = build_profile(f, str(root), "plugin")
    assert profile.overall_status in (WARN, FAIL)
    assert profile.overall_grade not in ("A", NA)
    danger = next(a for a in profile.axes if a.axis == "danger")
    assert danger.status != PASS
    assert danger.status != NA
