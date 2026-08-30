"""B-593: the ungraded cap line denied the finding it was reporting.

Measured against the live OpenClaw agent on 2026-08-20, the pasted card read::

    🦞 ClawSecCheck · OpenClaw Security Audit · Most urgent: CRITICAL — Lethal Trifecta …
    No grade yet — 3 of 5 layers did not run: …  ·  26 issues
    ⚠️ open CRITICAL finding — it would have capped the grade; this run has none.

    · Most urgent ·
    🔴 CRITICAL  Lethal Trifecta …
    🔴 CRITICAL  Gateway exposure & channel authentication

"none" was meant to be the GRADE. The grammatical subject of the sentence is the cap
reason, which for `_CAP_SEVERITY` is literally "open CRITICAL finding" — so the line reads
"this run has no open CRITICAL finding", one line below a headline naming one and two lines
above a list of two. On the one artifact `SKILL.md` tells the host agent to paste.

The graded sibling never had the problem: "capped from 86/100 — open CRITICAL finding"
gives the sentence a number to attach to. Only the ungraded branch — added by C-423 so that
an ungraded run would still disclose its cap — inverted the fact it exists to disclose.

Fixed at the wording, in one shared constant, because three sites say this sentence:
`render_report`'s F-155 and F-154 ungraded paragraphs and `render_dashboard`'s card line.

The four tests that used to pin the old literal now assert the shared constant instead —
their own comments say they protect the DISCLOSURE, not the phrasing (see
`test_b467_b471_agent_path.py`). That leaves nobody pinning the meaning, which is what this
file is for: the wording may change again, but it must never again be readable as a denial.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.catalog import CRITICAL, FAIL, Finding
from clawseccheck.report import (
    _CAP_BEHAVIORAL,
    _CAP_CONFIG_BLIND,
    _CAP_DEGRADED,
    _CAP_LIVE,
    _CAP_RUNTIME,
    _CAP_SEVERITY,
    _UNGRADED_CAP_TAIL,
    _UNGRADED_CAP_TAIL_SENTENCE,
    _cap_cascade,
    render_dashboard,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")

# Every `_cap_signal_active` flag, and a stand-in that trips exactly one of them. The
# helpers read the score with `getattr(..., default)` throughout (its own docstring says
# so), so a duck-typed object is the documented way to reach a single branch.
_PRIMARY_SETUP = {
    _CAP_LIVE: {"live_injection_capped": True, "live_injection_cap_reason": "canary"},
    _CAP_CONFIG_BLIND: {"config_blind_capped": True, "config_blind_reason": "absent"},
    _CAP_DEGRADED: {"degraded_capped": True, "degraded_count": 3},
    _CAP_SEVERITY: {"cap_severity": CRITICAL},
    _CAP_RUNTIME: {"runtime_capped": True, "runtime_cap_reason": "exfil"},
    _CAP_BEHAVIORAL: {"behavioral_capped": True, "behavioral_cap_reason": "T1"},
}


class _Score:
    """A ScoreResult stand-in carrying only what the cap cascade and the card read."""

    def __init__(self, **flags):
        self.score = None
        self.grade = None
        self.raw_score = 86
        self.capped = True
        self.graded = False
        self.missing_layers = (("live_behaviour", "unavailable"),)
        self.not_checked = ()
        self.config_blind_capped = False
        self.config_blind_reason = None
        self.__dict__.update(flags)


def _finding() -> Finding:
    return Finding(id="A1", title="Lethal Trifecta", severity=CRITICAL, status=FAIL,
                   detail="d", fix="f", framework="x", evidence=["a", "b", "c"])


def _cap_line(text: str, needle: str = "capped the grade") -> str:
    """The one rendered line that carries the cap disclosure.

    The two branches word it differently on purpose — the graded one leads with
    "capped from 86/100", the ungraded one has no number to lead with — so the caller
    says which it expects rather than the helper guessing.
    """
    hits = [ln for ln in text.splitlines() if needle in ln]
    assert len(hits) == 1, f"expected exactly one {needle!r} line, got {hits}"
    return hits[0]


# ------------------------------------------------------------------ the headline case

def test_the_card_no_longer_denies_the_finding_it_is_reporting(tmp_path):
    """The defect end to end, through the real CLI on a shipped fixture."""
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, "--dashboard",
         "--data-dir", str(tmp_path / "state"), "--no-history"],
        cwd=REPO_ROOT, capture_output=True, text=True, env={**_env(), "HOME": str(tmp_path)})
    out = proc.stdout
    line = _cap_line(out)

    assert "open CRITICAL finding" in line          # the disclosure survives (C-423)
    assert "has none" not in line                   # …and no longer reads as a denial
    assert "no grade to cap" in line

    # The premise: the same screen really is reporting a CRITICAL. Without this, the
    # assertions above could pass on a run with nothing to contradict.
    assert "CRITICAL" in out.split("· Most urgent ·")[-1]


def _env() -> dict:
    import os
    return dict(os.environ)


# ------------------------------------------------- coherent for every cap primary

@pytest.mark.parametrize("primary", sorted(_PRIMARY_SETUP))
def test_the_sentence_names_the_grade_for_every_cap_primary(primary):
    """The reported case was `_CAP_SEVERITY`, but all six share the sentence. Rewording
    only the one that was noticed is how the next reader finds the same bug wearing a
    different reason."""
    score = _Score(**_PRIMARY_SETUP[primary])
    assert _cap_cascade(score)[0] == primary, "stand-in did not reach the intended branch"

    line = _cap_line(render_dashboard([_finding()], score))
    assert "grade" in line
    assert "has none" not in line
    assert line.endswith(_UNGRADED_CAP_TAIL)


def test_a_co_occurring_signal_still_rides_the_same_sentence():
    """`_cap_also_clause` injects "; also X" before the tail. The tail must remain the
    end of the sentence, not get orphaned mid-line."""
    score = _Score(**{**_PRIMARY_SETUP[_CAP_SEVERITY], **_PRIMARY_SETUP[_CAP_DEGRADED]})
    line = _cap_line(render_dashboard([_finding()], score))
    assert "; also " in line
    assert line.endswith(_UNGRADED_CAP_TAIL)
    assert "has none" not in line


# ------------------------------------------------------- what must NOT have changed

def test_the_graded_branch_is_untouched():
    """This fix is scoped to the branch that has no number. The graded sentence was never
    ambiguous — "capped from 86/100" gives it a subject — and must not move."""
    graded = _Score(**_PRIMARY_SETUP[_CAP_SEVERITY])
    graded.graded = True
    graded.score = 49
    graded.grade = "F"
    graded.missing_layers = ()

    line = _cap_line(render_dashboard([_finding()], graded), needle="capped from")
    assert "capped from 86/100 — open CRITICAL finding" in line
    assert _UNGRADED_CAP_TAIL not in line


def test_an_uncapped_ungraded_run_says_nothing_at_all():
    """No cap, no sentence — a run that was not capped must not gain a line claiming it
    would have been."""
    out = render_dashboard([_finding()], _Score())
    assert "capped the grade" not in out


# --------------------------------------------------------- one wording, three sites

def test_the_three_sites_share_one_constant():
    """Source-level guard. The sentence is said by render_report's F-155 paragraph, its
    F-154 paragraph, and render_dashboard's card. They drifted into three hand-rolled
    copies once; a fourth copy must fail the build rather than wait to be noticed."""
    src = (REPO_ROOT / "clawseccheck" / "report.py").read_text(encoding="utf-8")
    body = src.split("_UNGRADED_CAP_TAIL_SENTENCE = ", 1)[1]
    # No literal re-spelling of the sentence anywhere below the definition. Keyed on the
    # distinctive clause rather than "capped the grade", which also occurs in prose
    # comments about scoring.CONFIG_BLIND_CAP and would make this guard cry wolf.
    #
    # B-600: this guard missed a FOURTH site for a whole release. The I-025 runtime-signal
    # paragraph split the sentence across two source lines -- `"...It would have capped"`
    # then `" the grade; this run has none."` -- so the phrase never appeared contiguously
    # and neither a grep nor this assertion saw it. Whitespace and the string-concatenation
    # seam are collapsed first, so a line break can no longer hide a copy.
    flat = re.sub(r'"\s*\n\s*"', "", body)          # adjacent implicit-concat literals
    flat = " ".join(flat.split())
    assert "would have capped the grade" not in flat, \
        "a hand-rolled copy of the cap sentence reappeared in report.py"
    # Exact counts, not a lower bound: a new consumer has to come here and say so.
    #
    # The SENTENCE form is pinned at ZERO, and that is the load-bearing number. It used to
    # serve render_report's three ungraded paragraphs (F-155 live-test, F-154 behavioural,
    # I-025 runtime signal); B-600's follow-up took it off all three, because each fires on
    # its own raw flag and so cannot say WHICH signal led, while the cascade line can and
    # does. Three private copies of one sentence are what made 56 of the 64 signal
    # combinations state it two to four times. Pinning zero is what stops a fourth
    # paragraph from quietly growing its own copy again; the constant itself stays defined
    # and is still checked by test_the_two_forms_differ_only_in_capitalisation.
    #
    # The TAIL form serves the three sites in report.py that follow it with an em dash:
    # render_report's cascade line, render_dashboard's card, and render_html's ungraded cap
    # paragraph. render_report's arrived last -- B-600 fixed the card and the HTML, and the
    # 2026-08-21 review found the text report still silently dropping an ordinary severity
    # cap the other three disclosed. pdf.py:632 is the fourth and final consumer, checked by
    # tests/test_b600_ungraded_cap_reaches_every_surface.py.
    # Count real INTERPOLATIONS, not occurrences of the name: the derivation line and the
    # prose comments mention it too, and counting those makes the pin drift for reasons
    # that have nothing to do with a new consumer appearing.
    _uses = [ln for ln in body.splitlines()
             if "_UNGRADED_CAP_TAIL" in ln and ('f"' in ln or "f'" in ln)]
    _sentence = [ln for ln in _uses if "_UNGRADED_CAP_TAIL_SENTENCE" in ln]
    _tail = [ln for ln in _uses if ln not in _sentence]
    assert len(_sentence) == 0, _sentence      # took off all three paragraphs by B-600
    assert len(_tail) == 3, _tail              # card, render_html, render_report's generic line


def test_the_two_forms_differ_only_in_capitalisation():
    """The card follows an em dash (lowercase); the report paragraphs follow a full stop
    (capitalised). Deriving one from the other keeps them one fact."""
    assert _UNGRADED_CAP_TAIL_SENTENCE.lower() == _UNGRADED_CAP_TAIL
    assert _UNGRADED_CAP_TAIL[0].islower() and _UNGRADED_CAP_TAIL_SENTENCE[0].isupper()
