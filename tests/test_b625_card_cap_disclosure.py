"""CLAWSECCHECK-B-625 — the one genuine renderer omission in the behavioral/cap
signal->surface map: `render_card` (the `--card` shareable badge) accepted a capped
score and rendered nothing about it, the same Golden Rule #4 shape already fixed on
`render_dashboard`'s card in B-465/B-467.

This is distinct from the other six rows in the task's matrix (`--sarif`/`--html`/
`--pdf`/`--brief`/`--monitor`/`--judge-packet`), which were fixed earlier by wiring
`--dashboard --full` through `_resolve_mode`/`_DASHBOARD_SIDE_OUTPUTS` (976f9d8) and by
SARIF's own `capsFired` block (ecce717). `render_card` had zero references to
`_cap_cascade`/capped/behavioral state until this change — confirmed by reading it, not
assumed from the docstring.

The fix reuses the SAME shared `_cap_cascade` / `_cap_primary_reason_text` /
`_cap_also_clause` machinery `render_report` and `render_dashboard` already share (B-380),
rather than a fourth hand-rolled copy of the six-signal priority ladder — so a signal
added to that table is automatically picked up here too.

Offline, stdlib only, writes nothing outside pytest's own machinery.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from clawseccheck.catalog import CRITICAL, LOW, FAIL, PASS, Finding
from clawseccheck.cli import main
from clawseccheck.layers import (
    LAYER_LIVE_BEHAVIOUR,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    STATUS_RAN,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
)
from clawseccheck.report import render_card
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = FIXTURES / "home_safe"
TRIFECTA = FIXTURES / "traj_behavioral_trifecta"  # fires T1, per test_f154_behavioral_cap.py
BASE = ["--no-native", "--no-host", "--no-sockets", "--no-history"]


def _f(fid: str, title: str, severity: str, status: str) -> Finding:
    return Finding(fid, title, severity, status, "detail", "fix", "framework")


def _ledger(*, complete: bool = True) -> LayerLedger:
    states = {ln: LayerState(status=STATUS_RAN) for ln in LAYER_ORDER}
    if not complete:
        states[LAYER_SELF_REPORT] = LayerState(status=STATUS_UNAVAILABLE)
        states[LAYER_LIVE_BEHAVIOUR] = LayerState(status=STATUS_UNAVAILABLE)
    return LayerLedger(states=states)


def _severity_capped_findings() -> list[Finding]:
    # Enough clean PASS weight to keep the RAW score high, so the CRITICAL FAIL's cap
    # (not just its own weight loss) is what pulls the final score down -- the shape
    # `score.raw_score > score.score` requires.
    return [_f(f"P{i}", "clean", LOW, PASS) for i in range(20)] + \
        [_f("B1", "Lethal trifecta reachable", CRITICAL, FAIL)]


def _box_rows(card: str) -> list[str]:
    return [ln for ln in card.splitlines() if ln.startswith(("|", "│"))]


# --------------------------------------------------------- the omission is fixed

def test_a_severity_capped_score_is_disclosed_on_the_card():
    score = compute(_severity_capped_findings(), ledger=_ledger())
    assert score.raw_score > score.score, "fixture must actually be capped"
    card = render_card(score, _severity_capped_findings(), ascii_only=True)
    assert f"capped from {score.raw_score}/100" in card
    assert "open CRITICAL finding" in card
    assert str(score.score) in card


def test_a_behavioral_capped_score_is_disclosed_on_the_card():
    """F-154's cap-only channel: this is the specific signal the parent signal->surface
    map task named as unobtainable through --card."""
    findings = [_f(f"P{i}", "clean", LOW, PASS) for i in range(5)]
    score = compute(findings, ledger=_ledger(), behavioral_fired_ids={"T1"})
    assert score.behavioral_capped is True
    card = render_card(score, findings, ascii_only=True)
    assert f"capped from {score.raw_score}/100" in card
    assert "behavioral" in card.lower()


def test_an_ungraded_but_capped_run_states_the_cap_without_a_grade_number():
    """No grade to attach 'capped from N/100' to -- mirrors render_dashboard's own
    ungraded cap branch (_UNGRADED_CAP_TAIL)."""
    findings = _severity_capped_findings()
    score = compute(findings, ledger=_ledger(complete=False))
    assert score.graded is False
    card = render_card(score, findings, ascii_only=True)
    assert "capped from" not in card, "no grade exists to cap"
    assert "open CRITICAL finding" in card
    assert "no grade to cap" in card


def test_box_art_still_closes_on_both_sides_when_capped():
    score = compute(_severity_capped_findings(), ledger=_ledger())
    card = render_card(score, _severity_capped_findings(), ascii_only=True)
    rows = _box_rows(card)
    assert rows, "expected a boxed card"
    widths = {len(ln) for ln in rows}
    assert len(widths) == 1, f"card rows have ragged widths: {sorted(widths)}"
    lines = [ln for ln in card.splitlines() if ln.strip()]
    assert len(lines[0]) == len(lines[-1])


def test_unicode_card_also_discloses_the_cap():
    score = compute(_severity_capped_findings(), ledger=_ledger())
    card = render_card(score, _severity_capped_findings(), ascii_only=False)
    assert f"capped from {score.raw_score}/100" in card
    # The mascot line is deliberately padded to width-1 (double-width emoji
    # compensation, pre-existing and unrelated to this fix) so it is excluded from the
    # uniform-width check; every OTHER row, including the new cap line, must match the
    # border.
    box_lines = [ln for ln in card.splitlines() if ln.strip().startswith(("┌", "└"))]
    top, bot = box_lines[0], box_lines[-1]
    assert len(top) == len(bot)
    non_mascot_rows = [ln for ln in _box_rows(card) if "audited by" not in ln]
    assert {len(ln) for ln in non_mascot_rows} == {len(top)}


# --------------------------------------------------------- byte-identity preserved

def test_an_uncapped_graded_card_is_byte_identical_to_before():
    """The load-bearing regression guard: the overwhelmingly common case (nothing
    capped the score) must render exactly as it did before this change."""
    findings = [_f("P1", "clean", LOW, PASS)]
    score = compute(findings, ledger=_ledger())
    assert score.raw_score == score.score, "fixture must genuinely be uncapped"
    card = render_card(score, findings, ascii_only=True)
    assert "capped" not in card
    rows = _box_rows(card)
    assert {len(ln) for ln in rows} == {41}, "39 + the two borders, the established width"


def test_an_uncapped_ungraded_card_carries_no_cap_line_either():
    findings = [_f("P1", "clean", LOW, PASS)]
    score = compute(findings, ledger=_ledger(complete=False))
    card = render_card(score, findings, ascii_only=True)
    assert "capped" not in card
    assert "no grade to cap" not in card


# --------------------------------------------------------- CLI end-to-end: a REAL
# fired behavioral detector reaching --html and --sarif through --dashboard --full.
# The remaining gap the parent signal->surface map task named after the CLI flag
# matrix and this card fix: earlier commits (976f9d8, ecce717) wired the CHANNEL, but
# nothing proved a genuine T1/T2/T3/B191 firing (not a hand-built ScoreResult) reaches
# the actual written file. Uses the same real fixture and helper shape
# `test_f154_behavioral_cap.py::TestCliEndToEnd` already established for `--json`.

def _combined_home(tmp_path: Path, traj_fixture: Path) -> Path:
    home = tmp_path / "home"
    shutil.copytree(SAFE, home)
    for p in traj_fixture.rglob("*"):
        if p.is_file():
            rel = p.relative_to(traj_fixture)
            dst = home / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(p, dst)
    return home


def test_a_real_fired_detector_reaches_the_written_html_file(tmp_path):
    home = _combined_home(tmp_path, TRIFECTA)
    out = tmp_path / "out.html"
    main(["--home", str(home)] + BASE + ["--dashboard", "--full", "--html", str(out)])
    html = out.read_text(encoding="utf-8")
    assert "behavioral detector fired" in html
    assert "T1" in html


def test_a_real_fired_detector_reaches_the_written_sarif_file(tmp_path):
    home = _combined_home(tmp_path, TRIFECTA)
    out = tmp_path / "out.sarif"
    main(["--home", str(home)] + BASE + ["--dashboard", "--full", "--sarif", str(out)])
    payload = json.loads(out.read_text(encoding="utf-8"))
    run = payload["runs"][0]
    caps = run["properties"]["analysisCompleteness"]["capsFired"]
    assert any(c["cap"] == "behavioral_capped" for c in caps), caps
    behavioral = next(c for c in caps if c["cap"] == "behavioral_capped")
    assert "T1" in behavioral.get("reason", "")


def test_a_real_fired_detector_is_visible_without_dashboard_riding(tmp_path):
    """Control: the SAME fixture through the plain --full --json path (no --dashboard,
    no --html/--sarif) already proves T1 fires on this trajectory -- confirming the two
    tests above are exercising a real signal, not a fixture that never fires at all."""
    home = _combined_home(tmp_path, TRIFECTA)
    import subprocess
    import sys
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", str(home), *BASE,
         "--full", "--json"],
        cwd=Path(__file__).resolve().parent.parent, capture_output=True, text=True,
    )
    payload = json.loads(proc.stdout)
    assert payload["behavioral_capped"] is True
    assert payload["behavioral_cap_reason"] == "T1 behavioral trifecta"
