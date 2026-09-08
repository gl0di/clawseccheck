"""The ungraded cap sentence is said once per run, not once per disclosure site.

B-600 gave the card, the HTML and the PDF an ungraded cap line. The 2026-08-21 review then
found `render_report` still silent on an ordinary severity cap, and the obvious repair --
copying the card's `elif primary is not None:` branch into `render_report` verbatim -- was
wrong in a way no existing test could see.

`render_report` is not shaped like the other three. They have ONE disclosure site each; it
had four, because the I-025 / F-155 / F-154 paragraphs each carried a private copy of the
shared sentence and each fires on its own raw flag, not on the cascade's primary. Adding a
fifth site made 56 of the 64 signal combinations state the same sentence two to four times.

Two things let that through, and this file is the counter to both:

1. **Nothing in the tree counted.** Measured 2026-08-30: every assertion on this sentence
   anywhere in `tests/` is `in`, `not in` or `endswith`. Duplication was invisible by
   construction, so a full suite went green on the four-times version.
2. **Both real fixtures produce the same combination.** `home_vuln` and `home_safe` each
   activate `cap_severity` alone, which is one of the eight combinations where the correct
   fix and the broken one are byte-identical. No fixture-driven test can tell them apart,
   so the signals are driven directly here rather than through the CLI.

The shipped shape: the paragraphs keep their framing and their reason phrase but no longer
carry the sentence, and the cascade line says it once -- with RANK, which is the thing only
it can say. On `severity + runtime` the text used to print the secondary signal and omit
the primary; the card never did.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import copy
import itertools
import re
import zlib

import pytest

from clawseccheck.catalog import Finding
from clawseccheck.pdf import render_pdf
from clawseccheck.report import (
    _UNGRADED_CAP_TAIL,
    _cap_cascade,
    render_dashboard,
    render_html,
    render_report,
)
from clawseccheck.scoring import compute

# The generic line uses the lowercase constant; the paragraphs used to use the capitalised
# `_UNGRADED_CAP_TAIL_SENTENCE`. Counting either form ALONE misses the other half -- the
# first version of this measurement did exactly that and reported "no duplication" on a
# tree that was duplicating. Match on the shared substring instead.
_COMMON = _UNGRADED_CAP_TAIL[1:]

# The em dash folds to "-" in the PDF: base-14 fonts only (textnorm.asciify).
_TAIL_PDF = _UNGRADED_CAP_TAIL.replace("—", "-")

# Each cap signal with the attributes `_cap_signal_active` actually reads.
_SIGNALS = (
    ("live", {"live_injection_capped": True, "live_injection_cap_reason": "canary:canary"}),
    ("config_blind", {"config_blind_capped": True}),
    ("degraded", {"degraded_capped": True, "degraded_count": 2}),
    ("severity", {"cap_severity": "CRITICAL"}),
    ("runtime", {"runtime_capped": True, "runtime_cap_reason": "skill_indicator"}),
    ("behavioral", {"behavioral_capped": True, "behavioral_cap_reason": "T1"}),
)
_NAMES = [name for name, _ in _SIGNALS]

_FINDINGS = [Finding(id="B2", title="ok", severity="LOW", status="PASS",
                     detail="d", fix="f", framework="x")]

_ALL_COMBINATIONS = [
    frozenset(combo)
    for size in range(len(_SIGNALS) + 1)
    for combo in itertools.combinations(_NAMES, size)
]


def _ungraded(active):
    """A ScoreResult with `active` capping it and no grade to cap."""
    score = copy.copy(compute(_FINDINGS))
    object.__setattr__(score, "graded", False)
    for name, fields in _SIGNALS:
        if name in active:
            for key, value in fields.items():
                object.__setattr__(score, key, value)
    return score


def _pdf_text(raw: bytes) -> str:
    """Every Tj string in the document, joined and whitespace-normalised.

    Joined, not a list, ON PURPOSE. `pdf.py` wraps to the page width, so a cap line whose
    reason phrase is long is split mid-sentence across two Tj strings -- measured: the
    `live` reason breaks the sentence at "...capped the grad" / "e, but this run has no
    grade to cap." A per-line `any(TAIL in ln)` therefore reports the PDF as SILENT for
    four of the six signals while the sentence is plainly there. The sibling file
    tests/test_b600_ungraded_cap_reaches_every_surface.py still matches per line and passes
    only because its fixture produces the one short reason ("an open CRITICAL finding").
    """
    out: list[str] = []
    for stream in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        data = stream.group(1)
        try:
            data = zlib.decompress(data)
        except Exception:
            pass
        for tj in re.finditer(rb"\((?:\\.|[^\\()])*\)\s*Tj", data):
            parts = re.findall(rb"\((?:\\.|[^\\()])*\)", tj.group(0))
            out.append(b"".join(p[1:-1] for p in parts).decode("latin-1"))
    return " ".join(" ".join(out).split())


# ------------------------------------------------------- said once, over every combination

@pytest.mark.parametrize("active", _ALL_COMBINATIONS,
                         ids=lambda a: "+".join(sorted(a)) or "nothing")
def test_the_text_report_says_it_exactly_once_per_capped_run(active):
    """One cap, one sentence -- whichever signals fired and however many.

    Asserted over all 64 combinations rather than a sample: the defect this pins showed up
    in 56 of them and in neither of the two the fixtures can produce.
    """
    out = render_report(_FINDINGS, _ungraded(active))
    said = [ln.strip() for ln in out.splitlines() if _COMMON in ln]
    assert len(said) == (1 if active else 0), said


def test_every_combination_really_is_covered():
    """A count asserted over a sample proves nothing about the combinations it skipped."""
    assert len(_ALL_COMBINATIONS) == 2 ** len(_SIGNALS) == 64


def test_a_run_with_nothing_capped_gains_no_sentence():
    """The mirror of the assertion above: "always say it once" must not become "always"."""
    assert _COMMON not in render_report(_FINDINGS, _ungraded(frozenset()))


def test_no_paragraph_carries_its_own_copy_of_the_sentence():
    """The defect in one assertion. Each per-signal paragraph keeps its framing and its
    reason phrase; only the cascade line carries the shared sentence, because only it knows
    which signal LED and which merely also fired."""
    for active in _ALL_COMBINATIONS:
        out = render_report(_FINDINGS, _ungraded(active))
        strays = [ln.strip() for ln in out.splitlines()
                  if _COMMON in ln and ("(I-025)" in ln or "(F-155)" in ln or "(F-154)" in ln)]
        assert not strays, (sorted(active), strays)


# ------------------------------------------------------- and every surface still gets it

@pytest.mark.parametrize("name,fields", _SIGNALS, ids=_NAMES)
def test_every_signal_reaches_every_surface_on_an_ungraded_run(name, fields):
    """The DoD limb, per signal rather than per fixture.

    The four surfaces agreed *separately* for months while disagreeing, and the guard that
    was supposed to catch it asserted three surfaces positively and the fourth only as the
    absence of a contradiction. Each signal is driven directly, so a re-narrowed gate on any
    one of them fails here instead of passing because the fixture happened not to set it.
    """
    score = _ungraded(frozenset({name}))
    assert _cap_cascade(score)[0] == name

    text = render_report(_FINDINGS, score)
    for surface, body in (("text", text),
                          ("card", render_dashboard(_FINDINGS, score)),
                          ("html", render_html(_FINDINGS, score))):
        assert _UNGRADED_CAP_TAIL in body, f"{name} silently dropped by {surface}"
    assert _TAIL_PDF in _pdf_text(render_pdf(_FINDINGS, score)), \
        f"{name} silently dropped by pdf"

    assert text.count(_UNGRADED_CAP_TAIL) == 1, f"{name} stated more than once in text"


# ------------------------------------------------------------ what must NOT have changed

def test_a_graded_run_keeps_its_number_and_never_grows_the_tail():
    """This is the branch with no number. The graded banner was never wrong."""
    score = copy.copy(compute(_FINDINGS))
    object.__setattr__(score, "graded", True)
    object.__setattr__(score, "cap_severity", "CRITICAL")
    out = render_report(_FINDINGS, score)
    assert _cap_cascade(score)[0] == "severity"
    assert "capped from" in out
    assert _COMMON not in out
