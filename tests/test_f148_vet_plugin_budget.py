"""F-148: vet_plugin() gets a per-target wall-clock ceiling.

The vet paths run the content ring outside run_all's own scanbudget (C-159)
protection, so cost driven by content hostility (not size) was previously
unbounded. This pins three things for vet_plugin() specifically:

  1. Normal/clean runs are unaffected by the new default budget (no regression,
     no spurious coverage-gap note).
  2. A budget hit degrades HONESTLY: never a silent PASS, always an explicit
     coverage-gap note naming the reason.
  3. ScanBudgetExceeded raised inside a dispatched stage (e.g. vet_skill) is
     never swallowed by a generic `except Exception` (C-175) — it must reach
     the honest-degradation path, not read as "nothing found here".

Deterministic and offline: the budget is exhausted via monkeypatching, never by
sleeping for real wall-clock time.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import vet_plugin
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
