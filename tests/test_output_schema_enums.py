"""The frozen --json contract must not promise values the code cannot emit.

``docs/OUTPUT_SCHEMA.md`` is the one document whose entire promise is that it is
exact: integrators are told they may branch on it. It drifted anyway -- it
documented ``computed_risk`` as ``"CRITICAL"/"HIGH"/"MEDIUM"/"LOW"`` while
:func:`clawseccheck.sar._compute_risk` has only ever returned ``"high"`` or
``"medium"``. Wrong case *and* a wrong value set, so an integrator branching on
``"HIGH"`` got a silent no-match on every run.

A prose fix alone just resets the clock, so the enum is derived from the code
here rather than copied. Only enums that can be enumerated mechanically are
pinned; anything that cannot be is left to review rather than guarded by a
comment promising vigilance.
"""

import re
from pathlib import Path

from clawseccheck.sar import _B62_HIGH_SURPRISE, _compute_risk

SCHEMA = Path(__file__).resolve().parent.parent / "docs" / "OUTPUT_SCHEMA.md"


def _emittable_computed_risk():
    """Every value ``_compute_risk`` can actually return, by exercising it.

    Both branches are driven from the real high-surprise set, so adding a
    family cannot silently change the answer.
    """
    empty = frozenset()
    one_high = frozenset({next(iter(_B62_HIGH_SURPRISE))})
    return {_compute_risk(empty), _compute_risk(one_high), _compute_risk(frozenset(_B62_HIGH_SURPRISE))}


def _documented_values(field):
    """The backtick-quoted string literals on the schema row for *field*."""
    for line in SCHEMA.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"| `{field}`"):
            return set(re.findall(r'`"([^"]*)"`', line))
    raise AssertionError(f"no schema row for {field!r} -- did the table move?")


def test_computed_risk_row_lists_exactly_what_the_code_emits():
    documented = _documented_values("computed_risk")
    emittable = _emittable_computed_risk()
    assert documented == emittable, (
        f"docs/OUTPUT_SCHEMA.md promises computed_risk in {sorted(documented)} but "
        f"clawseccheck.sar._compute_risk can only emit {sorted(emittable)}. This is the "
        "frozen --json contract: a value documented but never emitted makes an "
        "integrator's branch dead code, silently."
    )


def test_computed_risk_is_lower_case_and_binary():
    """Guards the two specific ways the row was wrong, not just the set equality.

    Set equality above would also pass if someone 'fixed' the doc by changing the
    code to match it. These pin the code's own contract independently.
    """
    emittable = _emittable_computed_risk()
    assert emittable == {"high", "medium"}
    assert all(v == v.lower() for v in emittable)
