"""B-877 — a config-blind A1 WARN must not read as an active CRITICAL trifecta.

On a config-blind run (and more generally whenever A1 is WARN — see
`checks/_config.py::check_trifecta`'s four hedge branches: thin-surface B-033,
resolved-default B-499, substituted-dm B-609, sensitive-data-undetermined) the
dashboard headline used to read::

    Nothing failed outright — most serious open item: CRITICAL — Lethal Trifecta

directly above the finding's own row, which opens::

    why: Active legs 0/3: none. Rule: keep ≤2 of 3. ...

A1 is WARN, not FAIL — by design (B-033/B-803, pinned by C-426 and
tests/test_b803_config_blind_attested_roster.py) the WARN means the legs could not be
FULLY DETERMINED this run, not that a CRITICAL trifecta is confirmed active. Printing
A1's catalog severity next to its title, and "0/3: none" with no qualifier, said the
opposite of what is true.

Decision (Dave, 2026-09-20): reword ONLY the headline (`_urgent_headline`) and the
per-finding row framing (`_render_finding`) in report.py, keyed on A1's own STATUS —
the same predicate `_trifecta_ratio` already uses for exactly this "?/3, not a count"
distinction (B-587) — never on parsing which of the four hedge branches fired. A1's
status/severity/score, `f.detail` (checks/_config.py owns it; `baseline.fingerprint()`
hashes it) and the B-803/C-426 pins are all untouched; this is a display-only change
covering the dashboard and the plain text report (both route through `_render_finding`
and `_urgent_headline`).

A metamorphic case is pinned in both directions: a real 3-leg A1 FAIL is a different
status and must keep its unqualified strong wording.

Offline; writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, UNKNOWN, WARN, Finding
from clawseccheck.checks import check_trifecta
from clawseccheck.collector import collect
from clawseccheck.report import _render_finding, _urgent_headline

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
# A1 WARN, thin-surface hedge, on a perfectly READABLE config (not the blind case) —
# the shipped fixture test_b587_trifecta_certainty.py already uses for exactly this.
THIN_SURFACE_HOME = FIXTURES / "bad_b103_ftp"
# A1 FAIL, a genuine 3/3 trifecta — the metamorphic control.
FAIL_HOME = FIXTURES / "bad_b229_mcp_fs_root_trifecta"

_UNDETERMINED_CLAUSE = "could not be fully determined this run"
_UNDETERMINED_TAG = "legs undetermined this run"


def _a1(status: str, legs: list[str] | None = None,
        detail: str = "Active legs 0/3: none. Rule: keep ≤2 of 3.") -> Finding:
    return Finding(id="A1", title="Lethal Trifecta", severity=CRITICAL, status=status,
                   detail=detail, fix="f", framework="x", evidence=legs or [])


def _other_warn(sev: str = HIGH) -> Finding:
    """A non-A1 WARN, to prove the reword is scoped to A1 only."""
    return Finding(id="B99", title="Some Other Check", severity=sev, status=WARN,
                   detail="why", fix="f", framework="x", evidence=[])


# ────────────────────────────────────────────────────────────── the headline ──

def test_headline_does_not_claim_an_active_critical_trifecta_for_a1_warn():
    headline = _urgent_headline([_a1(WARN)])
    assert "CRITICAL — Lethal Trifecta" not in headline, (
        f"headline still reads as an active CRITICAL trifecta: {headline!r}")
    assert _UNDETERMINED_CLAUSE in headline or "could not determine" in headline, headline
    # Still leads with the same "Nothing failed outright" shape every other WARN-only
    # headline uses (test_c426_bare_run_ungraded.py pins the three legal shapes).
    assert headline.startswith("Nothing failed outright"), headline


def test_headline_still_names_the_catalog_severity_as_conditional():
    """The reader must still learn A1's severity — just not as a bare assertion."""
    headline = _urgent_headline([_a1(WARN)])
    assert CRITICAL in headline


def test_headline_keeps_strong_wording_for_a_real_a1_fail():
    """Metamorphic case: a genuine 3-leg FAIL is a different status (routed through the
    FAIL-only bucket, never the WARN bucket this fix touches) and must be unaffected."""
    headline = _urgent_headline([_a1(FAIL, ["untrusted input", "sensitive data", "outbound actions"])])
    assert headline == "Most urgent: CRITICAL — Lethal Trifecta", headline


def test_headline_for_a_non_a1_warn_is_unchanged():
    """Scoping regression guard: only A1 gets the reword."""
    headline = _urgent_headline([_other_warn()])
    assert headline == "Nothing failed outright — most serious open item: HIGH — Some Other Check"


# ─────────────────────────────────────────────────────────── the row framing ──

def test_row_tags_a1_warn_as_undetermined_not_a_confirmed_trifecta():
    lines: list = []
    f = _a1(WARN, detail="Active legs 0/3: none. Rule: keep ≤2 of 3."
                          " Cannot determine from config: untrusted input, outbound actions.")
    _render_finding(lines, f)
    header = lines[0]
    assert _UNDETERMINED_TAG in header, header
    assert CRITICAL in header  # severity token/marker is untouched


def test_row_why_line_leads_with_the_undetermined_clause_without_mutating_detail():
    lines: list = []
    original_detail = ("Active legs 0/3: none. Rule: keep ≤2 of 3."
                        " Cannot determine from config: untrusted input, outbound actions.")
    f = _a1(WARN, detail=original_detail)
    _render_finding(lines, f)
    why_line = next(ln for ln in lines if ln.strip().startswith("why:"))
    assert _UNDETERMINED_CLAUSE in why_line, why_line
    # The original detail text is still there in full, just reframed ahead of it —
    # nothing about checks/_config.py's own wording (or the B-803/C-426 pins on it) moved.
    assert "Active legs 0/3: none" in why_line
    assert "Cannot determine from config: untrusted input, outbound actions." in why_line
    # And critically: the Finding's own `detail` attribute (what baseline.fingerprint()
    # hashes, and what --json/--explain/SARIF publish) is byte-identical to what
    # checks/_config.py produced — this is a display-only change.
    assert f.detail == original_detail


def test_row_is_unaffected_for_a_real_a1_fail():
    """Metamorphic case, row side: a genuine 3-leg FAIL keeps its plain row — no
    undetermined tag, no prefixed why-line."""
    lines: list = []
    f = _a1(FAIL, ["untrusted input", "sensitive data", "outbound actions"],
            detail="Active legs 3/3: untrusted input, sensitive data, outbound actions.")
    _render_finding(lines, f)
    header = lines[0]
    why_line = next(ln for ln in lines if ln.strip().startswith("why:"))
    assert _UNDETERMINED_TAG not in header, header
    assert _UNDETERMINED_CLAUSE not in why_line, why_line
    assert why_line.strip() == "why: Active legs 3/3: untrusted input, sensitive data, outbound actions."


def test_row_is_unaffected_for_a_non_a1_warn():
    lines: list = []
    _render_finding(lines, _other_warn())
    header = lines[0]
    why_line = next(ln for ln in lines if ln.strip().startswith("why:"))
    assert _UNDETERMINED_TAG not in header, header
    assert _UNDETERMINED_CLAUSE not in why_line, why_line


def test_row_is_unaffected_for_a1_unknown():
    """UNKNOWN is a different, pre-existing shape (the engine could not run A1 at all,
    e.g. `_config_unreadable`) — this fix must not widen past WARN."""
    lines: list = []
    f = _a1(UNKNOWN, detail="A1 could not be assessed: unreadable config.")
    _render_finding(lines, f)
    header = lines[0]
    assert _UNDETERMINED_TAG not in header, header


# ───────────────────────────────────────────── the engine itself is untouched ──

def test_config_blind_a1_is_still_warn_with_the_same_hedge_wording(tmp_path):
    """Same predicate test_b803_config_blind_attested_roster.py already pins — repeated
    here so this task's own DoD ("A1 status/severity/score unchanged") has its own
    regression guard, independent of that file ever being touched."""
    ctx = collect(tmp_path)
    assert ctx.config_found is False
    a1 = check_trifecta(ctx)
    assert a1.status == WARN
    assert a1.severity == CRITICAL
    assert "Cannot determine from config: untrusted input, outbound actions." in a1.detail


def test_thin_surface_fixture_a1_status_and_detail_unchanged():
    ctx = collect(THIN_SURFACE_HOME)
    a1 = check_trifecta(ctx)
    assert a1.status == WARN
    assert a1.severity == CRITICAL
    assert "Cannot determine from config" in a1.detail


def test_the_real_finding_from_a_blind_run_gets_the_reworded_headline_and_row(tmp_path):
    """End-to-end: feed the ACTUAL engine output (not a hand-built stand-in) through
    both renderers, so a future change to check_trifecta's status/detail shape is
    exercised by this test too."""
    ctx = collect(tmp_path)
    a1 = check_trifecta(ctx)
    assert a1.status == WARN  # sanity: this run is exercising the WARN path

    headline = _urgent_headline([a1])
    assert "CRITICAL — Lethal Trifecta" not in headline
    assert _UNDETERMINED_CLAUSE in headline or "could not determine" in headline

    lines: list = []
    _render_finding(lines, a1)
    assert _UNDETERMINED_TAG in lines[0]
    why_line = next(ln for ln in lines if ln.strip().startswith("why:"))
    assert _UNDETERMINED_CLAUSE in why_line
    assert "Active legs" in why_line  # checks/_config.py's own wording still present


# ──────────────────────────────────────────────────────── full CLI, both surfaces ──

def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--data-dir", str(tmp_path / "state"),
         "--no-history", "--no-deptree", "--no-color", *args],
        cwd=REPO_ROOT, capture_output=True, text=True)


def test_plain_text_report_on_a_blind_run_does_not_read_as_an_active_trifecta(tmp_path):
    # A placeholder file (not a bare directory) so the CLI's Screen-13 onboarding
    # welcome (cli.py::_onboarding_reason, "empty") does not short-circuit the run
    # before it ever reaches the audit — this is still a config-blind run (no
    # openclaw.json anywhere under it), just not a LITERALLY empty directory.
    empty = tmp_path / "empty_home"
    empty.mkdir()
    (empty / "not-an-openclaw-config.txt").write_text("placeholder", encoding="utf-8")
    out = _run(tmp_path, "--home", str(empty)).stdout
    assert "most serious open item: CRITICAL — Lethal Trifecta" not in out, out
    assert _UNDETERMINED_CLAUSE in out or "could not determine" in out


def test_dashboard_on_a_blind_run_does_not_read_as_an_active_trifecta(tmp_path):
    empty = tmp_path / "empty_home"
    empty.mkdir()
    out = _run(tmp_path, "--home", str(empty), "--dashboard").stdout
    assert "most serious open item: CRITICAL — Lethal Trifecta" not in out, out
    assert _UNDETERMINED_CLAUSE in out or "could not determine" in out


def test_json_a1_severity_and_status_unchanged_on_a_blind_run(tmp_path):
    """The DoD's own "assert it": --json (unaffected by this display-only fix) still
    publishes A1 at its real severity/status."""
    empty = tmp_path / "empty_home"
    empty.mkdir()
    out = _run(tmp_path, "--home", str(empty), "--json").stdout
    a1 = next(f for f in json.loads(out)["findings"] if f["id"] == "A1")
    assert a1["status"] == WARN
    assert a1["severity"] == CRITICAL
    assert "Cannot determine from config" in a1["detail"]


def test_full_report_on_a_real_fail_keeps_the_strong_headline(tmp_path):
    """Metamorphic case at the CLI level: a real 3/3 FAIL fixture must still print the
    unqualified 'Most urgent: CRITICAL' headline — this fix must not blunt a real one."""
    out = _run(tmp_path, "--home", str(FAIL_HOME)).stdout
    assert re.search(r"Most urgent: CRITICAL", out), out
