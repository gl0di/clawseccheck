"""B-586: the shareable badge could never carry a grade.

One command line — `--full --attest a.json --judged-bundle b.json`, the shape that does
produce a grade — gave four different answers depending on which export rode along::

    --save r.txt   ->  Score: 49/100   Grade: F
    --card         ->  OpenClaw Security: F  ( 49/100)
    --badge b.svg  ->  aria-label="OpenClaw Security: no grade yet"
    --html h.html  ->  No grade yet — 2 of 5 layers did not run…

`SKILL.md` offers "share grade — `--badge grade.svg` or `--card`" as a single line, and
only half of it could; the HTML report pointed at that same dead end ("Use the shareable
badge instead"). `--badge`/`--html`/`--sarif` each WON the mode race against
`--dashboard`, ran their own bare audit, and rendered that.

The fix is composition, not honouring `--full` inside those modes, and
`_build_layer_ledger`'s own docstring says why: marking the sweep phases "ran" is a
promise the caller must keep, and a bare `--badge --full` never runs them — so honouring
it there would fabricate a completed sweep (Golden Rule #4). They ride `--dashboard`
instead, which genuinely runs the sweep, exactly as `--pdf` has since C-373/C-374.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")

_ATTEST = '{"schema": "clawseccheck-attest/1", "tools": ["read"], "network": "none"}'
_BUNDLE = ('{"liveTest": {"verdicts": [{"tool": "canary", "id": "canary", '
           '"verdict": "RESISTANT"}]}}')


def _complete_check(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess:
    """The documented complete check — the only shape that reaches all five layers."""
    attest = tmp_path / "a.json"
    attest.write_text(_ATTEST, encoding="utf-8")
    bundle = tmp_path / "b.json"
    bundle.write_text(_BUNDLE, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", SAFE, "--dashboard", "--full",
         "--attest", str(attest), "--judged-bundle", str(bundle),
         "--data-dir", str(tmp_path / "state"), "--no-history", *extra],
        cwd=REPO_ROOT, capture_output=True, text=True)


def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", SAFE,
         "--data-dir", str(tmp_path / "state"), "--no-history", *args],
        cwd=REPO_ROOT, capture_output=True, text=True)


# --------------------------------------------------------------- the headline case

def test_a_complete_check_produces_a_graded_badge(tmp_path):
    """The defect in one assertion. `--badge` is the artifact people actually share."""
    badge = tmp_path / "grade.svg"
    proc = _complete_check(tmp_path, "--badge", str(badge))
    assert badge.exists(), proc.stderr[:300]
    label = re.search(r'aria-label="([^"]+)"', badge.read_text(encoding="utf-8"))
    assert label, "the badge carries no accessible label"
    assert "no grade yet" not in label.group(1)
    assert re.search(r"\b[A-F]\b", label.group(1)), label.group(1)


def test_a_complete_check_produces_a_graded_html_report(tmp_path):
    html = tmp_path / "report.html"
    _complete_check(tmp_path, "--html", str(html))
    text = html.read_text(encoding="utf-8")
    assert "No grade yet" not in text
    assert re.search(r"Grade\s*[A-F]\b", text), "the report states no grade"


def test_a_complete_check_produces_a_sarif_that_says_the_analysis_was_complete(tmp_path):
    """B-585 added `graded`/`layersRan` to the SARIF and could only pin the true branch at
    the unit level, because no invocation could reach it. This is that invocation."""
    out = tmp_path / "results.sarif"
    _complete_check(tmp_path, "--sarif", str(out))
    ac = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["properties"]["analysisCompleteness"]
    assert ac["graded"] is True
    assert ac["layersRan"] == ac["layersTotal"]
    assert ac["missingLayers"] == []


def test_every_artifact_from_one_run_agrees_about_the_grade(tmp_path):
    """The actual defect was DISAGREEMENT between artifacts of a single audit — `--save`
    said F 49/100 while the badge beside it said "no grade yet". Assert the agreement,
    not each file in isolation, or the next divergence passes again."""
    badge, html, sarif = (tmp_path / "a.svg", tmp_path / "a.html", tmp_path / "a.sarif")
    proc = _complete_check(tmp_path, "--badge", str(badge), "--html", str(html),
                           "--sarif", str(sarif))
    card_graded = "No grade yet" not in proc.stdout
    assert card_graded, proc.stdout[:200]
    assert "no grade yet" not in badge.read_text(encoding="utf-8")
    assert "No grade yet" not in html.read_text(encoding="utf-8")
    assert json.loads(sarif.read_text(encoding="utf-8"))[
        "runs"][0]["properties"]["analysisCompleteness"]["graded"] is True


# ------------------------------------------------------- what must NOT have changed

@pytest.mark.parametrize("flag,name", [("--badge", "b.svg"), ("--html", "h.html"),
                                       ("--sarif", "s.sarif")])
def test_the_standalone_mode_is_untouched(tmp_path, flag, name):
    """`--badge x.svg` alone still writes an ungraded badge from a bare run and says so —
    the overwhelmingly common invocation, and the one that must not change."""
    dest = tmp_path / name
    proc = _run(tmp_path, flag, str(dest))
    assert proc.returncode == 0
    assert dest.exists()
    if flag == "--badge":
        assert "no grade yet" in dest.read_text(encoding="utf-8")


@pytest.mark.parametrize("flag,name", [("--badge", "b.svg"), ("--html", "h.html"),
                                       ("--sarif", "s.sarif")])
def test_a_bare_full_still_says_full_has_no_effect(tmp_path, flag, name):
    """C-374's decision, kept: `--badge --full` without `--dashboard` genuinely does not
    run the sweep, so it must keep saying so rather than quietly implying it did. That
    honest note is what the composition exists to make unnecessary, never to silence."""
    proc = _run(tmp_path, flag, str(tmp_path / name), "--full")
    assert f"--full has no effect with {flag}" in proc.stderr


def test_the_note_no_longer_calls_a_written_file_ignored(tmp_path):
    """Before: `note: --badge, --html, --sarif ignored (running --dashboard)` on a run
    that wrote all three. A note claiming a file was dropped when it is on disk is the
    same class of untruth as the missing grade — just pointed the other way."""
    badge = tmp_path / "n.svg"
    proc = _complete_check(tmp_path, "--badge", str(badge))
    assert badge.exists()
    assert "--badge" not in proc.stderr or "ignored" not in proc.stderr


def test_an_earlier_mode_still_loses_them_and_still_says_so(tmp_path):
    """The B-067 boundary, unmoved: `--risk-paths` returns before the side-output write,
    so nothing is produced and every requested flag stays in the ignored note. Exempting
    them unconditionally would hide a genuinely dropped request."""
    badge = tmp_path / "lost.svg"
    proc = _run(tmp_path, "--risk-paths", "--dashboard", "--badge", str(badge))
    assert not badge.exists()
    assert "--badge" in proc.stderr and "ignored (running --risk-paths)" in proc.stderr


def test_a_rider_still_gets_the_file_written(tmp_path):
    """`--dashboard --trend --badge b.svg`: the rider is elected, the dashboard does not
    render, and the badge is still written — from the bare audit, which is what it would
    have been anyway. B-530 made exactly this call for `--pdf`; the badge follows it."""
    badge = tmp_path / "rider.svg"
    proc = _run(tmp_path, "--dashboard", "--trend", "--badge", str(badge))
    assert proc.returncode == 0
    assert badge.exists()
    assert "no grade yet" in badge.read_text(encoding="utf-8")


def test_the_file_is_written_exactly_once(tmp_path):
    """Two write sites now exist (early, and deferred after the score recompute). A run
    that hit both would render the artifact twice and announce it twice — the second
    silently overwriting the first with a DIFFERENT grade."""
    badge = tmp_path / "once.svg"
    proc = _complete_check(tmp_path, "--badge", str(badge))
    assert proc.stdout.count("badge written to") == 1, proc.stdout[:300]
