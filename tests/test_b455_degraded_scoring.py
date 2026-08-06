"""B-455 — an unparseable bundled script must degrade B13, not vanish from the score.

## The bug

`check_installed_skills` (B13) returns UNKNOWN when a bundled `.py` cannot be parsed by
the AST/taint layer ("could not analyze <skill>: <path> — parse error(s)"). That UNKNOWN
carried `engine_degraded=False`, so `scoring._degraded_signal` did not count it and
`scoring.compute()`'s `scored` filter dropped the check from the denominator entirely —
the check silently left the score instead of capping it.

That is precisely the B-399 amplifier ("an engine-side UNKNOWN must never score
identically to a clean PASS") reappearing at a producer B-399 did not reach. A parse
failure is engine-side by B-399's own definition: the layer tried to read something it
needed and failed, as opposed to finding nothing to check.

## Why it was structural, not an oversight

`_finding()` (checks/_shared.py) has accepted `engine_degraded` since B-399. `_custom()`
— the sibling constructor every dynamic-severity check uses, B13's `_b13_verdict` chain
included — **had no such parameter at all**, so those checks were incapable of setting
the flag no matter how they were written. The fix adds the parameter (defaulting False,
so all pre-existing callers are byte-identical) and threads it through `_b13_verdict` to
the one winner that warrants it, `parse_error_paths`.

## Measured, end to end through the real `audit()` on a home with one prose-`.py` skill

    before:  B13 UNKNOWN engine_degraded=False   _degraded_signal -> (True, 2)
    after:   B13 UNKNOWN engine_degraded=True    _degraded_signal -> (True, 3)

The `(True, 2)` before is NOT the check working: it is the same unparseable file crashing
two *other* checks (`check_persona_jailbreak`, `check_overt_secret_exfil`) into
`"ERR:"`-prefixed UNKNOWNs, which B-313's branch already counted. The cap fired by
coincidence, through a different mechanism, and would stop firing the moment those two
checks stopped crashing. `test_b13_is_counted_on_its_own_merits` below pins the
difference so the coincidence can never be mistaken for the contract again.

## Scope

The **vet** path (`--vet`) grades through `dossier._grade_profile`, not `scoring.compute`,
and is NOT fixed by this change — a skill with an unparseable bundled `.py` still reports
grade A there. That is a separate defect with its own reproduction and root cause
(`dossier._danger_coverage_gap`'s predicate), tracked separately; it is deliberately not
folded in here.
"""
from __future__ import annotations

from pathlib import Path

import clawseccheck
from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks._shared import _custom
from clawseccheck.scoring import _degraded_signal

_MANIFEST = """\
---
name: notes-helper
description: Keeps short notes for the user.
---

# Notes helper

Stores and retrieves short notes.
"""

_PROSE_PY = """\
This file is prose, not Python.

It documents how the helper works: it reads notes and prints them.
Nothing here parses as Python source at all -- there is no valid statement.
"""

_VALID_PY = '''\
"""Print stored notes."""


def main() -> None:
    print("notes")
'''


def _home(tmp_path: Path, helper: str | None) -> Path:
    """A minimal OpenClaw home holding one skill. *helper* None ships no python at all."""
    skill = tmp_path / "workspace" / "skills" / "notes-helper"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(_MANIFEST)
    if helper is not None:
        (skill / "scripts").mkdir()
        (skill / "scripts" / "helper.py").write_text(helper)
    return tmp_path


def _b13(findings: list):
    matches = [f for f in findings if f.id == "B13"]
    assert matches, "B13 did not run — the fixture is not exercising check_installed_skills"
    return matches[0]


# --------------------------------------------------------------- the fix, end to end


def test_unparseable_bundled_py_marks_b13_engine_degraded(tmp_path):
    """The engine tried to parse a file it needed and failed — that is engine-side."""
    _, findings, _ = clawseccheck.audit(_home(tmp_path, _PROSE_PY))
    b13 = _b13(findings)
    assert b13.status == UNKNOWN
    assert b13.engine_degraded is True
    assert "parse error" in b13.detail


def test_b13_is_counted_on_its_own_merits(tmp_path):
    """B13 must reach `_degraded_signal` itself, not ride on the two checks the same
    unparseable file happens to crash. Guards the coincidence documented above."""
    _, findings, _ = clawseccheck.audit(_home(tmp_path, _PROSE_PY))

    counted = [
        f for f in findings
        if f.id.startswith("ERR:") or (f.status == UNKNOWN and f.engine_degraded)
    ]
    assert _b13(findings) in counted

    # and the signal still fires with the crashed checks excluded — i.e. B13 alone is
    # enough. Without the fix this drops to (False, 0).
    without_err = [f for f in findings if not f.id.startswith("ERR:")]
    assert _degraded_signal(without_err) == (True, 1)


# ------------------------------------------------------- the other direction (B-092)


def test_valid_python_leaves_b13_undegraded(tmp_path):
    """The control: same skill, parseable helper. Nothing degraded."""
    _, findings, _ = clawseccheck.audit(_home(tmp_path, _VALID_PY))
    b13 = _b13(findings)
    assert b13.status == PASS
    assert b13.engine_degraded is False
    assert _degraded_signal(findings) == (False, 0)


def test_no_python_at_all_leaves_b13_undegraded(tmp_path):
    """"Nothing to check" is NOT "could not check" — B-092/B-399's central distinction.

    A skill shipping no code is a legitimately clean result. If this ever starts flagging
    engine_degraded, DEGRADED_CHECK_CAP would fire on ordinary prose-only skills, which is
    a Golden Rule #5 problem of its own.
    """
    _, findings, _ = clawseccheck.audit(_home(tmp_path, None))
    b13 = _b13(findings)
    assert b13.engine_degraded is False
    assert _degraded_signal(findings) == (False, 0)


# ------------------------------------------------------------- the constructor itself


def test_custom_defaults_engine_degraded_false():
    """Every pre-existing `_custom()` caller must be unaffected by the new parameter."""
    f = _custom("B13", "HIGH", UNKNOWN, "detail", "fix")
    assert f.engine_degraded is False


def test_custom_can_set_engine_degraded():
    """The capability B13's chain was structurally missing before this change."""
    f = _custom("B13", "HIGH", UNKNOWN, "detail", "fix", engine_degraded=True)
    assert f.engine_degraded is True
