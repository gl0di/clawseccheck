"""B-486 — `--exhaustive` was sold as removing the time budget. It raises it.

`docs/USAGE.md` promised "every log/transcript sink (not cut off by the time budget)",
and B164's own skip sentence told the operator to "re-run with --exhaustive to include
them". Both promise completeness the flag does not deliver.

Measured on this box's real 135-sink corpus, two consecutive runs, unchanged corpus,
identical flags:

    run 1   All 135 log/transcript sink(s) scanned        64.2s
    run 2   5 log/transcript sink(s) not scanned          64.8s

`EXHAUSTIVE_LIMITS` sets `log_max_total_bytes` unbounded (B-484), so the binding
constraint is `log_check_budget_s`, and the corpus costs about as much as that budget
allows — so the run lands on its own ceiling and finishes or does not by chance. Whether
the thorough mode is thorough depends on how busy the machine is that minute, which is
the same nondeterminism B-484 removed from the default path, surviving on the path sold
as the fix for it.

**What is NOT wrong:** the code's own disclosure. When the clock fires,
`skipped_for_time > 0`, the skip sentence prints, and F-164 SC-5's affirmative "All N …
scanned" branch correctly does not. There is no lying completeness claim in the output.
The false claim was in the *docs* and in the *remedy wording*, and that is what this
change corrects — direction 3 of the four the task lists.

**Deliberately not done here:** raising `log_check_budget_s`. Its own in-source comment
records that `check_budget_s` is the SIGALRM hard deadline `run_all()` wraps every check
in, so raising the log budget without raising that cascade just moves the kill point to a
signal, degrading the check to UNKNOWN and capping the grade. That is a measured change
to budget constants, not a wording fix, and it stays open on the task.

This module pins the wording contract, not the timing — a timing assertion would be
exactly as load-dependent as the bug.

Stdlib-only, offline, writes nothing.
"""
from __future__ import annotations

import inspect
from pathlib import Path

from clawseccheck.checks import _egress

_DOCS = Path("docs/USAGE.md")
_SKILL_MD = Path("SKILL.md")

# The phrasings that promise the flag finishes. Any of them reappearing means someone
# re-introduced the claim the measurement above disproves.
_COMPLETENESS_PROMISES = (
    "not cut off by the time budget",
    "--exhaustive to include them",
)


def _sources() -> dict:
    return {
        "docs/USAGE.md": _DOCS.read_text(encoding="utf-8"),
        "SKILL.md": _SKILL_MD.read_text(encoding="utf-8"),
        "checks/_egress.py": inspect.getsource(_egress),
    }


def test_nothing_promises_exhaustive_removes_the_budget():
    offenders = [
        f"{name}: {promise!r}"
        for name, text in _sources().items()
        for promise in _COMPLETENESS_PROMISES
        # The in-source retraction notes quote the old wording to explain it; only a
        # live claim counts, so skip lines that are comments.
        if any(promise in ln and not ln.lstrip().startswith("#")
               for ln in text.splitlines())
    ]
    assert not offenders, (
        "a completeness promise for --exhaustive is back; the flag raises the scan "
        f"budget, it does not remove it: {offenders}")


def test_the_remedy_still_points_at_exhaustive():
    """Softening the promise must not delete the advice — it is still the right remedy."""
    src = inspect.getsource(_egress)
    assert "re-run with --exhaustive" in src, (
        "the skip disclosure stopped naming --exhaustive at all; the flag genuinely does "
        "raise the budget substantially and remains what an operator should reach for")


def test_the_remedy_says_the_flag_states_its_own_coverage():
    """The honest replacement for "include them": go look at what it reports."""
    # Anchored on a fragment that survives however the literals happen to be split
    # across lines — the first sentence breaks mid-phrase after "it states ".
    src = inspect.getsource(_egress)
    assert src.count("its own coverage either way") >= 2, (
        "both skip sentences should point the reader at --exhaustive's own disclosure "
        "rather than at a guarantee")


def test_the_docs_describe_a_raised_budget_not_a_removed_one():
    text = _DOCS.read_text(encoding="utf-8")
    assert "raised, not removed" in text
    assert "is disclosed, never silently dropped" in text or \
           "is disclosed, not silently dropped" in text


def test_the_affirmative_completeness_branch_is_still_conditional():
    """F-164 SC-5: "All N scanned" must stay gated on actually having scanned all N.

    If this ever becomes unconditional the output starts lying in the other direction,
    which is worse than the doc claim this task fixed.
    """
    # Anchor on the sentence itself, not on the first "All " in the module — that one
    # is in a docstring, and matching it made this test assert nothing at all.
    src = inspect.getsource(_egress)
    needle = 'All {len(sinks)} log/transcript sink(s) scanned.'
    idx = src.find(needle)
    assert idx != -1, "the affirmative completeness sentence disappeared"
    window = src[max(0, idx - 800):idx]
    assert "elif lim.exhaustive" in window, (
        "the affirmative 'All N scanned' sentence is no longer gated on --exhaustive "
        "having actually reached every sink")
