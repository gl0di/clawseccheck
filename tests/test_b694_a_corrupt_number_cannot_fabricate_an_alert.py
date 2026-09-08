"""A corrupted number in the snapshot cannot become a measurement.

`state.json` carries no chain and no signature — the event journal is hash-chained, the
file that decides every monitor verdict is not (`SECURITY_MODEL.md`; CLAWSECCHECK-C-464
tracks the asymmetry). So a corrupted or planted field is exactly the input the diff arms
have to be robust to.

`monitordims/_shared._num` learned that in B-270 and says why: *"bool is excluded because
`True < 2` compares as 1 and would silently fabricate a score-drop alert out of a corrupted
field."* The `raw_score` backstop next door re-derived its own type check and dropped the
clause, so `"raw_score": true` passed every guard and fired a HIGH reading **"the underlying
pass-rate fell 74 -> True"** — a confident measurement of a degradation that did not happen,
rendered with the boolean verbatim.

That backstop is the ONLY thing that catches posture worsening once an open FAIL has pinned
the displayed score (C-418), so the failure direction is the awkward one: a fabricated HIGH
on a healthy machine trains the user to disbelieve the one alert that matters.

The fix is one predicate with two answers — `_num_or_none` for callers that must SKIP an
absent figure, `_num` for callers where zero is the right default — rather than a third
hand-rolled `isinstance`. The census at the bottom is BEHAVIOURAL rather than AST-based on
purpose: a syntax census would have to carve out `_execpolicy` (whose operands come from an
internal rank table, so a snapshot can choose a key but never supply a value) and
`_provenance` (which already carries the clause inline), and an exception list is the thing
that rots.

Offline, stdlib only, writes nothing outside tmp_path.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.monitor import diff_with_notes
from clawseccheck.monitordims._score import _diff_score
from clawseccheck.monitordims._shared import NOTE_NO_PRIOR_RECORD, _num, _num_or_none

REPO_ROOT = Path(__file__).resolve().parents[1]
_SCOPE = "same-scope-hash"


def _arm(p_raw, c_raw):
    """The raw_score backstop, driven directly, with everything else held equal."""
    alerts: list = []
    notes: list = []
    _diff_score(
        True, True, alerts,
        {"score": 49, "grade": "F", "raw_score": c_raw, "raw_score_scope": _SCOPE}, False,
        lambda category, sentence: notes.append((category, sentence)),
        {"score": 49, "grade": "F", "raw_score": p_raw, "raw_score_scope": _SCOPE}, False,
    )
    return alerts, notes


# ------------------------------------------------------------------ the regression itself

@pytest.mark.parametrize("p_raw,c_raw", [
    (74, True),
    (74, False),
    (True, 60),
    (False, 60),
    (True, True),
], ids=["true-curr", "false-curr", "true-prev", "false-prev", "both"])
def test_a_boolean_never_becomes_a_measurement(p_raw, c_raw):
    """`isinstance(True, int)` is True and `True < 74` is `1 < 74`, so before the fix each of
    these fired a HIGH. `False` matters as much as `True`: `False < 74` is `0 < 74`, the
    larger fabricated fall of the two."""
    alerts, notes = _arm(p_raw, c_raw)
    assert alerts == [], alerts
    assert any(category == NOTE_NO_PRIOR_RECORD for category, _ in notes), notes


@pytest.mark.parametrize("bad", ["60", None, [], {}, float("nan")],
                         ids=["string", "none", "list", "dict", "nan"])
def test_other_corruptions_neither_crash_nor_alert(bad):
    """The type check exists because an ordered comparison against a string raises
    TypeError. NaN is the odd one: it IS a float, so it reaches the comparison — and every
    ordered comparison with NaN is False, so it cannot fabricate a fall either."""
    alerts, _notes = _arm(74, bad)
    assert alerts == [], alerts


def test_a_real_fall_still_alerts():
    """The positive control. Without it, "never alert" passes every assertion above."""
    alerts, notes = _arm(74, 60)
    assert len(alerts) == 1, alerts
    level, text = alerts[0]
    assert level == "HIGH"
    assert "74 -> 60" in text, text
    assert notes == [], notes


def test_a_rise_is_not_an_alert_and_not_a_note():
    """The other side of the control: the backstop reports a FALL, not any movement."""
    alerts, notes = _arm(74, 80)
    assert alerts == [] and notes == [], (alerts, notes)


def test_floats_are_still_compared():
    """`_num_or_none` accepts int and float; only bool is excluded. A fix that narrowed this
    to `int` would silently stop comparing a fractional pass-rate."""
    alerts, _ = _arm(74.0, 60.5)
    assert len(alerts) == 1, alerts


# --------------------------------------------------------------------- one predicate

def test_the_two_helpers_share_one_predicate():
    """`_num` delegates to `_num_or_none`, so "what counts as a number here" is defined once.
    Anything the strict reader rejects, the defaulting one must also reject — otherwise the
    two answers diverge and the next caller picks the wrong one."""
    sentinel = -12345
    for value in (True, False, "60", None, [], {}, object()):
        snap = {"k": value}
        assert _num_or_none(snap, "k") is None, value
        assert _num(snap, "k", default=sentinel) == sentinel, value
    for value in (0, 74, -3, 74.0, 60.5):
        snap = {"k": value}
        assert _num_or_none(snap, "k") == value
        assert _num(snap, "k", default=sentinel) == value


def test_absent_skips_rather_than_defaulting_to_zero():
    """Why the strict reader exists at all. `_num`'s `default=0` is right where a missing
    figure should compare as zero; here it would read the ARRIVAL of a baseline as a rise
    from 0, so the backstop needs None and the branch that skips on it."""
    assert _num_or_none({}, "raw_score") is None
    assert _num({}, "raw_score") == 0
    alerts, notes = _arm(None, 60)
    assert alerts == [], alerts
    assert any(c == NOTE_NO_PRIOR_RECORD for c, _ in notes), notes


# ------------------------------------------------------- the census, over the whole diff

def _numeric_paths(node, prefix=()):
    """Every (path, value) in a snapshot whose value is a real number."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _numeric_paths(value, prefix + (key,))
    elif isinstance(node, bool):
        return
    elif isinstance(node, (int, float)):
        yield prefix, node


def _set_path(snap: dict, path, value):
    cursor = snap
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value


@pytest.fixture(scope="module")
def real_snapshot():
    """A REAL snapshot, not a hand-built one.

    The first version of this census used a dict I wrote by hand and it covered five of the
    six numeric fields a real snapshot carries — it missed `memory.*`, `skills_capped_count`
    and `version`, i.e. it was measuring my own sample. Built once per module; the diffs
    below are cheap, the audit is not.
    """
    from clawseccheck.checks import run_all
    from clawseccheck.collector import collect
    from clawseccheck.monitor import snapshot
    from clawseccheck.scoring import compute
    ctx = collect(str(REPO_ROOT / "fixtures" / "home_safe"))
    findings = run_all(ctx)
    return snapshot(ctx, findings, compute(findings, ctx))


def test_no_numeric_field_in_a_real_snapshot_can_be_corrupted_into_an_alert(real_snapshot):
    """The durable half, and behavioural rather than syntactic.

    An AST census would have to carve out `monitordims/_execpolicy.py` (its operands come
    from an internal rank table, so a snapshot chooses a key and never supplies a value) and
    `monitordims/_provenance.py` (which already carries the clause inline). An exception list
    is what rots; this asserts the property itself, so a NEW arm that hand-rolls its own
    `isinstance(x, int)` on a numeric field is caught without anyone updating a list.

    It earned that immediately: driven against the `raw_score` fix alone it found a SECOND
    instance I had not — `Security score dropped: F 49 -> F True`, where the comparison was
    bool-safe via `_num` but `_num`'s default of 0 turned a corrupted score into a
    catastrophic fall, and the alert text printed the raw value.

    No NEW alert at all, not merely no boolean in the rendered string. That is the real
    property: two identical snapshots hold no change, and corrupting one field does not
    create one — it creates an INABILITY to compare, which is a note's job. Asserting on the
    text alone would pass a fabricated "score dropped 49 -> 0", which is what a STRING
    corruption produces through the same default.
    """
    import copy
    base = copy.deepcopy(real_snapshot)
    quiet_alerts, _ = diff_with_notes(copy.deepcopy(base), copy.deepcopy(base))
    numeric = [path for path, _ in _numeric_paths(base)]
    assert len(numeric) >= 5, ("vacuous: too few numbers to corrupt", numeric)

    for path in numeric:
        for corruption in (True, False, "49", None, "", []):
            curr = copy.deepcopy(base)
            _set_path(curr, path, corruption)
            alerts, _notes = diff_with_notes(copy.deepcopy(base), curr)
            new = [a for a in alerts if a not in quiet_alerts]
            assert not new, (path, corruption, new)
