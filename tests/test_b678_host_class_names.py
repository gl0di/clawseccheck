"""CLAWSECCHECK-B-678 — the host disclosure names what it could not confirm.

The `host` dimension only alerts on `present -> absent`, so a class whose earlier state was
`unknown` can stop without a word. Measured on a real machine, five of seven classes are
`unknown` — most of this dimension is not, in fact, watching for disappearance.

That limit was already disclosed, and the disclosure was a bare COUNT: "5 security tool(s)
on this machine could not be confirmed as running last time". C-441 made exactly this
change for watched dimensions and recorded why: a count "tells the reader nothing they can
act on". Knowing that endpoint protection is the unconfirmed one is a different fact from
knowing that some number of things are.

RETRACTED from the task as filed: it also claimed the coverage page "counts `host` at full
weight". It does not — `len(WATCHED_DIMENSIONS)` is never rendered anywhere, verified by
grep over `report.py` / `cli.py` / `coverage.py`. There was no over-claim to correct.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.hostwatch import CLASSES
from clawseccheck.monitordims._host import (
    _HOST_CLASS_NAMES,
    _diff_host_monitors,
    _name_host_classes,
)
from clawseccheck.monitordims._shared import _DIMENSION_NAME_CAP


def _run(prev, curr):
    alerts, notes = [], []
    _diff_host_monitors((prev, curr), alerts, lambda c, m: notes.append((c, m)))
    return alerts, notes


def test_every_class_the_scanner_can_report_has_a_name():
    """A replicated vocabulary with no guard is one that drifts. `hostwatch.CLASSES` is the
    source of truth; a class added there and not here would fall back to its raw key and
    print `egress_posture` at a user."""
    missing = [c for c in CLASSES if c not in _HOST_CLASS_NAMES]
    assert not missing, f"no user-facing name for {missing} — add it to _HOST_CLASS_NAMES"
    spare = [c for c in _HOST_CLASS_NAMES if c not in CLASSES]
    assert not spare, f"names for classes the scanner no longer reports: {spare}"


def test_the_note_names_the_unconfirmed_classes():
    prev = {"edr_av": "unknown", "network_ids": "unknown", "firewall": "present"}
    curr = {"edr_av": "unknown", "network_ids": "unknown", "firewall": "present"}
    alerts, notes = _run(prev, curr)
    assert alerts == []
    assert len(notes) == 1
    message = notes[0][1]
    assert "2 security tool(s)" in message
    assert "endpoint protection" in message
    assert "network intrusion detection" in message


def test_the_cap_is_stated_rather_than_applied_silently():
    """A truncation the reader cannot see reads as 'that was all of them'."""
    many = {c: "unknown" for c in list(_HOST_CLASS_NAMES)[: _DIMENSION_NAME_CAP + 1]}
    clause = _name_host_classes(many)
    assert " and 1 more" in clause, clause


def test_an_absent_class_on_both_sides_still_produces_no_note():
    """The C-418 pin this change must not disturb: `absent -> absent` is a confident
    verdict on both sides with nothing that could have stopped. A note there would be false
    AND permanent — a machine with no EDR would see it on every run forever, which trains
    the reader to ignore the whole block."""
    prev = curr = {"edr_av": "absent", "firewall": "present"}
    alerts, notes = _run(prev, curr)
    assert (alerts, notes) == ([], [])


def test_a_real_disappearance_still_alerts_high():
    """Do not regress the half that works."""
    alerts, _ = _run({"edr_av": "present"}, {"edr_av": "absent"})
    assert len(alerts) == 1 and alerts[0][0] == "HIGH"
    assert "edr_av" in alerts[0][1]


def test_an_unnamed_class_degrades_to_its_key_rather_than_vanishing():
    """If the guard above is ever bypassed, the sentence must still account for the class.
    Silently dropping it would understate the gap, which is the failure this note exists to
    prevent."""
    assert "brand_new_class" in _name_host_classes(["brand_new_class"])
