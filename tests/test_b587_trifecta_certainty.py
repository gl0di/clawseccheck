"""B-587: the trifecta sub-score published a determined count when nothing was determined.

`--home <an empty directory> --card` printed::

    │  OpenClaw Security: no grade yet (2/5 layers ran)│
    │  Lethal Trifecta: 0/3                            │
    │  audited by ClawSecCheck 🦞                      │

`0/3` is the **best possible** trifecta result, printed for a run that read no config at
all — on the five-line artifact designed to be pasted somewhere else, where a footnote on
another surface does not travel.

**The task under-scoped it, and the fixtures said so.** This is not a blind-config bug.
A1 has a second uncertainty branch on a perfectly READABLE config — the B-033 thin-surface
guard: runtime tools granted at session start (`message`, `exec_command`, `web_*`) never
appear in `openclaw.json`, so a leg that looks OFF can be live. Measured on a shipped
fixture, `--home fixtures/bad_b103_ftp --card` printed `Lethal Trifecta: 0/3` while that
run's A1 read *"Cannot determine from config: untrusted input, outbound actions"* and its
own fix line ended *"or treat as possible 3/3"*.

So the predicate is A1's own certainty, and the blind config is one instance of it. It is
keyed on A1's **status**, never its prose: `PASS` (every leg determined) and `FAIL` (three
active, by construction) are the two states where `len(evidence)` is a determination.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, PASS, UNKNOWN, WARN, Finding
from clawseccheck.report import _trifecta_ratio, render_card
from clawseccheck.scoring import compute

REPO_ROOT = Path(__file__).resolve().parents[1]
# A1 is WARN here with two legs undetermined, and the config is READABLE — the case the
# original report missed.
UNDETERMINED_HOME = str(REPO_ROOT / "fixtures" / "bad_b103_ftp")


def _a1(status: str, legs: list[str]) -> Finding:
    return Finding(id="A1", title="Lethal Trifecta", severity=CRITICAL, status=status,
                   detail="d", fix="f", framework="x", evidence=legs)


def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--data-dir", str(tmp_path / "state"),
         "--no-history", *args],
        cwd=REPO_ROOT, capture_output=True, text=True)


# ------------------------------------------------------------------ the producer

def test_a_determined_count_is_still_a_count():
    assert _trifecta_ratio([_a1(PASS, [])]) == "0/3"
    assert _trifecta_ratio([_a1(PASS, ["untrusted input"])]) == "1/3"
    assert _trifecta_ratio([_a1(PASS, ["untrusted input", "sensitive data"])]) == "2/3"
    assert _trifecta_ratio([_a1(FAIL, ["a", "b", "c"])]) == "3/3"


def test_an_undetermined_run_is_not_a_count():
    """A1 WARN is the thin-surface guard: at least one leg could not be determined, and
    the active count is a FLOOR. `0/3` there reads as the best possible result."""
    assert _trifecta_ratio([_a1(WARN, [])]) == "?/3"
    assert _trifecta_ratio([_a1(WARN, ["untrusted input"])]) == "?/3"
    assert _trifecta_ratio([_a1(UNKNOWN, [])]) == "?/3"


def test_no_a1_at_all_is_unchanged():
    """`?/3` for an absent A1 predates this change — which is why widening that state
    introduces no new shape for any consumer to meet."""
    assert _trifecta_ratio([]) == "?/3"


# --------------------------------------------------------------------- the card

def test_the_card_no_longer_publishes_a_clean_count_for_a_config_it_never_read(tmp_path):
    empty = tmp_path / "empty_home"
    empty.mkdir()
    out = _run(tmp_path, "--home", str(empty), "--card").stdout
    assert "Lethal Trifecta: 0/3" not in out
    assert "?/3" in out and "unverified" in out


def test_the_card_is_honest_on_a_readable_config_too(tmp_path):
    """The half the original report missed. If this ever regresses to `0/3`, the fix has
    been narrowed back to the blind-config case."""
    out = _run(tmp_path, "--home", UNDETERMINED_HOME, "--card").stdout
    assert "Lethal Trifecta: 0/3" not in out
    assert "?/3" in out and "unverified" in out


def test_a_real_determination_still_prints_the_number(tmp_path):
    """The fix must not turn every card into a `?` — that would trade one useless answer
    for another."""
    out = _run(tmp_path, "--home", str(REPO_ROOT / "fixtures" / "home_vuln"), "--card").stdout
    assert re.search(r"Lethal Trifecta: [0-3]/3", out), out
    assert "unverified" not in out


def test_the_card_box_never_grows_past_the_width_c428_fixed():
    """C-428 sized the graded card at 39 columns so it renders byte-identically to before
    the ungraded work. `(legs unverified)` — my first wording — pushed the line to 40 and
    grew the box; a word is not worth breaking that for. Pinned so the next edit to this
    string has to notice."""
    findings = [_a1(WARN, [])]
    card = render_card(compute(findings), findings, ascii_only=True)
    rows = [ln for ln in card.splitlines() if ln.startswith(("+", "|"))]
    assert {len(ln) for ln in rows} == {41}, rows      # 39 + the two borders


# ------------------------------------------------- the other three consumers agree

def test_every_surface_reports_the_same_uncertainty(tmp_path):
    """`_trifecta_ratio` feeds the card, the HTML badge, the PDF badge and `--json`. All
    four published the same misleading count, so all four are fixed by the producer —
    asserted together, because a per-surface fix is how they drift."""
    html = tmp_path / "r.html"
    proc = _run(tmp_path, "--home", UNDETERMINED_HOME, "--json")
    assert json.loads(proc.stdout)["trifecta"] == "?/3"

    _run(tmp_path, "--home", UNDETERMINED_HOME, "--html", str(html))
    assert re.search(r"Lethal Trifecta:</strong>\s*\?/3", html.read_text(encoding="utf-8"))

    card = _run(tmp_path, "--home", UNDETERMINED_HOME, "--card").stdout
    assert "?/3" in card


def test_the_engine_itself_was_never_wrong(tmp_path):
    """A1's own finding always said so — WARN, with the undetermined legs named in its
    detail and "or treat as possible 3/3" in its fix. Only the ratio that summarised it
    dropped that. Pinned so a future 'simplification' of A1's status cannot silently make
    the ratio confident again."""
    proc = _run(tmp_path, "--home", UNDETERMINED_HOME, "--json")
    a1 = next(f for f in json.loads(proc.stdout)["findings"] if f["id"] == "A1")
    assert a1["status"] == WARN
    assert "Cannot determine from config" in a1["detail"]
