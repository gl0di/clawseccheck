"""C-429 — report how much of the catalog reached no verdict, and why. Never penalise it.

`scoring.compute` drops UNKNOWN from the denominator, so an undetermined check neither
earns nor costs a point. B-504 observed 25 of 100 scored checks undetermined, 18 of them
HIGH, and proposed capping the grade on that density. This is the split-out third of that
task, and the measurement says the cap is the wrong instrument:

* **A real run has no grade to cap.** Through the CLI on the maintainer's own machine the
  default run reports "no grade yet — 3 of 5 layers did not run", and `--full` still
  misses 2 of 5. E-077 withholds the letter entirely on an incomplete check, which is a
  stronger statement than any cap.
* **Half the undetermined population is not blindness.** Measured through the CLI: of 24
  undetermined, 12 are ``not_applicable`` — a surface positively confirmed ABSENT. Capping
  on the raw count would charge a user for not enabling a feature, the exact false FAIL
  the task warned about. The genuinely blind population is 12, of which 8 are HIGH — half
  what B-504's framing implied, because that framing counted both groups together.
* **Nothing was ``engine_degraded``.** A check that broke already caps via
  ``DEGRADED_CHECK_CAP``; this population is disjoint from it.

So the deliverable is the discrimination the cap would have needed, exposed rather than
acted on: ``no_signal`` is the honest "could not see" count and the only one worth gating
on. A CI consumer can assert on it; the tool does not assert on the user's behalf.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, Finding
from clawseccheck.report import undetermined_summary


def _f(fid, severity, status, *, scored=True, not_applicable=False, engine_degraded=False):
    f = Finding(fid, f"check {fid}", severity, status, "detail", "fix", "framework")
    f.scored = scored
    f.not_applicable = not_applicable
    f.engine_degraded = engine_degraded
    return f


def test_the_three_reasons_are_counted_separately():
    """The whole point: 'I looked and there is nothing here' is not 'I could not look'."""
    findings = [
        _f("A", HIGH, UNKNOWN),                              # blind
        _f("B", HIGH, UNKNOWN, not_applicable=True),         # confirmed absent
        _f("C", LOW, UNKNOWN, engine_degraded=True),         # broken check
        _f("D", HIGH, PASS),
    ]
    s = undetermined_summary(findings)
    assert s == {
        "scored_checks": 4,
        "undetermined": 3,
        "confirmed_absent": 1,
        "engine_degraded": 1,
        "no_signal": 1,
        "no_signal_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
    }


def test_a_confirmed_absent_surface_is_not_counted_as_blindness():
    """The false-FAIL the cap would have produced, pinned as an accounting rule: a user
    who has not enabled a feature must not read as a user we could not see."""
    findings = [_f(str(i), HIGH, UNKNOWN, not_applicable=True) for i in range(20)]
    s = undetermined_summary(findings)
    assert s["undetermined"] == 20
    assert s["no_signal"] == 0
    assert s["no_signal_by_severity"]["high"] == 0


def test_unscored_findings_are_excluded():
    """`scored=False` means 'does not move the score'. A density about the score has to
    use the same population the score does, or it describes a different run."""
    findings = [_f("A", HIGH, UNKNOWN, scored=False), _f("B", HIGH, UNKNOWN)]
    s = undetermined_summary(findings)
    assert s["scored_checks"] == 1
    assert s["undetermined"] == 1


def test_severity_split_covers_every_band():
    findings = [
        _f("A", CRITICAL, UNKNOWN), _f("B", HIGH, UNKNOWN),
        _f("C", MEDIUM, UNKNOWN), _f("D", LOW, UNKNOWN),
    ]
    assert undetermined_summary(findings)["no_signal_by_severity"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 1,
    }


def test_a_fully_determined_run_reports_zero_rather_than_omitting_the_block():
    """Absence of the number and a number of zero are different claims; the block is
    always present so a consumer never has to guess which it got."""
    s = undetermined_summary([_f("A", HIGH, PASS), _f("B", LOW, FAIL)])
    assert s["undetermined"] == 0
    assert s["no_signal"] == 0
    assert s["scored_checks"] == 2


def test_it_never_reports_a_cap_or_a_penalty():
    """C-429 is disclosure. If a future change makes this population move the score, it
    must be a deliberate decision with its own C-135 — not a quiet addition here."""
    s = undetermined_summary([_f("A", HIGH, UNKNOWN)])
    assert not any("cap" in k or "penal" in k for k in s)


def test_the_summary_appears_in_the_json_payload():
    """End to end, not a helper in isolation — the block exists for a CI consumer."""
    import json

    from clawseccheck.collector import Context
    from clawseccheck.report import render_json
    from clawseccheck.scoring import compute
    from pathlib import Path

    findings = [_f("A", HIGH, UNKNOWN), _f("B", HIGH, PASS)]
    ctx = Context(home=Path("/nonexistent"))
    payload = json.loads(render_json(findings, compute(findings), ctx=ctx))
    assert payload["undetermined"]["no_signal"] == 1
    assert payload["undetermined"]["scored_checks"] == 2
