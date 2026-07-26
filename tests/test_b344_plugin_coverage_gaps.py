"""B-344 — every way `vet_plugin` ends up with a PARTIAL scan must say so in a Finding.

F-148 already fixed one of three: a CPU-budget exhaustion (`budget_hit`) folds a
synthetic VET-COVERAGE finding into `ring_findings`, which `dossier._normalize_pool`
flattens, `_AXIS_BY_ID` routes to the danger axis, and `cli.py` turns into a non-zero
exit. The other two reached nothing but `notes` — human text that lands in `evidence`
but is not a Finding, so no axis ever saw it:

  * the `_PLUGIN_FILE_CAP` tree-sweep cap (`truncated`) lifted the verdict floor to
    UNKNOWN, but an UNKNOWN-only plugin profile grades N/A and exits 0;
  * an oversized runtime JS/TS file did not even reach that floor — a plugin whose only
    runtime file was a too-large bundle graded a confident A/PASS and exited 0 on a file
    that was never read.

Both are now emitted through the same `coverage_gap_finding()` factory, each naming its
OWN limit: two simultaneous gaps must produce two findings stating two different reasons,
never one merged string that contradicts itself.

Deterministic and offline: the JS cap is lowered by monkeypatch rather than by writing a
2MB file, and every fixture is built under pytest's tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import vet_plugin
from clawseccheck.checks._mcp import _PLUGIN_FILE_CAP
from clawseccheck.cli import main
from clawseccheck.dossier import NA, build_profile

_EMPTY_SCHEMA = {"type": "object", "additionalProperties": False}


def _mk_plugin(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "openclaw.plugin.json").write_text(
        json.dumps({"id": "demo", "configSchema": _EMPTY_SCHEMA}), encoding="utf-8"
    )
    return root


def _fill(root: Path, n: int) -> None:
    """*n* inert extra files, so the tree holds exactly n + 1 (the manifest)."""
    pad = root / "data"
    pad.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (pad / f"f{i:05d}.txt").write_text("x", encoding="utf-8")


def _coverage(f):
    return [r for r in f.ring_findings if r.id == "VET-COVERAGE"]


# --------------------------------------------------------------------------- #
# 1. The file cap.                                                             #
# --------------------------------------------------------------------------- #
def test_file_cap_emits_a_coverage_finding_naming_the_file_cap(tmp_path):
    root = _mk_plugin(tmp_path / "plug")
    _fill(root, _PLUGIN_FILE_CAP + 5)
    f = vet_plugin(root)

    cov = _coverage(f)
    assert len(cov) == 1, [r.detail for r in f.ring_findings]
    assert cov[0].status == UNKNOWN
    assert cov[0].severity == HIGH
    assert cov[0].scored is False
    # the load-bearing substring dossier._danger_coverage_gap matches on
    assert "coverage is incomplete" in cov[0].detail
    # names its OWN limit, and claims no other
    assert f"{_PLUGIN_FILE_CAP}-file cap" in cov[0].detail
    assert "budget" not in cov[0].detail.lower()


def test_file_cap_no_longer_grades_na_and_exits_zero(tmp_path, capsys):
    root = _mk_plugin(tmp_path / "plug")
    _fill(root, _PLUGIN_FILE_CAP + 5)
    f = vet_plugin(root)

    profile = build_profile(f, str(root), "plugin")
    assert profile.overall_status in (WARN, FAIL)
    assert profile.overall_grade not in ("A", NA)
    danger = next(a for a in profile.axes if a.axis == "danger")
    assert danger.status not in (PASS, NA)

    rc = main(["--vet-plugin", str(root)])
    capsys.readouterr()
    assert rc != 0


def test_exactly_at_the_file_cap_is_not_a_coverage_gap(tmp_path):
    """The cap test runs BEFORE the append, so a tree holding exactly _PLUGIN_FILE_CAP
    files — every one of which WAS swept — must not claim a gap. With the old
    append-then-test order this would have become a brand-new false WARN the moment the
    finding above started moving the verdict."""
    root = _mk_plugin(tmp_path / "plug")
    _fill(root, _PLUGIN_FILE_CAP - 1)  # + the manifest == exactly the cap
    f = vet_plugin(root)
    assert _coverage(f) == []
    assert f.status == PASS, f.detail


# --------------------------------------------------------------------------- #
# 2. The oversized-JS cap — the gap that did not even reach the UNKNOWN floor. #
# --------------------------------------------------------------------------- #
def test_oversized_js_bundle_emits_a_coverage_finding(tmp_path, monkeypatch):
    root = _mk_plugin(tmp_path / "plug")
    (root / "bundle.js").write_text("const a = 1;\n" * 40, encoding="utf-8")
    monkeypatch.setattr("clawseccheck.checks._mcp._PLUGIN_JS_MAX_BYTES", 8)
    f = vet_plugin(root)

    cov = _coverage(f)
    assert len(cov) == 1, [r.detail for r in f.ring_findings]
    assert "coverage is incomplete" in cov[0].detail
    assert "lexical scan cap" in cov[0].detail
    assert "bundle.js" in cov[0].detail
    # It used to grade a confident PASS on a file that was never read.
    assert f.status != PASS


def test_oversized_js_bundle_no_longer_grades_a_and_exits_zero(tmp_path, monkeypatch,
                                                               capsys):
    root = _mk_plugin(tmp_path / "plug")
    (root / "bundle.js").write_text("const a = 1;\n" * 40, encoding="utf-8")
    monkeypatch.setattr("clawseccheck.checks._mcp._PLUGIN_JS_MAX_BYTES", 8)
    f = vet_plugin(root)

    profile = build_profile(f, str(root), "plugin")
    assert profile.overall_status in (WARN, FAIL)
    assert profile.overall_grade not in ("A", NA)

    monkeypatch.setattr("clawseccheck.checks._mcp._PLUGIN_JS_MAX_BYTES", 8)
    rc = main(["--vet-plugin", str(root)])
    capsys.readouterr()
    assert rc != 0


# --------------------------------------------------------------------------- #
# 3. Two simultaneous gaps -> two findings, two distinct reasons.              #
# --------------------------------------------------------------------------- #
def test_two_gaps_produce_two_distinctly_worded_findings(tmp_path, monkeypatch):
    root = _mk_plugin(tmp_path / "plug")
    (root / "bundle.js").write_text("const a = 1;\n" * 40, encoding="utf-8")
    _fill(root, _PLUGIN_FILE_CAP + 5)
    monkeypatch.setattr("clawseccheck.checks._mcp._PLUGIN_JS_MAX_BYTES", 8)
    f = vet_plugin(root)

    cov = _coverage(f)
    assert len(cov) == 2, [r.detail for r in cov]
    details = sorted(r.detail for r in cov)
    assert details[0] != details[1]
    joined = "\n".join(details)
    assert f"{_PLUGIN_FILE_CAP}-file cap" in joined
    assert "lexical scan cap" in joined
    # Neither finding borrows the other's cause.
    file_cap = next(d for d in details if "-file cap" in d)
    js_cap = next(d for d in details if "lexical scan cap" in d)
    assert "lexical scan cap" not in file_cap
    assert "-file cap" not in js_cap


# --------------------------------------------------------------------------- #
# 4. Negative control — a clean plugin must be untouched by all of this.       #
# --------------------------------------------------------------------------- #
def test_clean_plugin_output_is_unchanged(tmp_path):
    root = _mk_plugin(tmp_path / "plug")
    (root / "index.js").write_text("export const hello = () => 'hi';\n", encoding="utf-8")
    f = vet_plugin(root)
    assert f.status == PASS, f.detail
    assert _coverage(f) == []
    # The only coverage line a clean plugin carries is the pre-existing node_modules
    # exclusion note — no cap/budget truncation is claimed.
    assert f.evidence == [
        "coverage: node_modules/ (third-party npm deps) excluded from the content scan"
    ]
