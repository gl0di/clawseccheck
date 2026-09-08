"""A blind run must still say how much of the memory surface it could not watch.

``_append_memory_alerts`` states, in its own comment, that the cap disclosure "is
deliberately NOT gated" — it describes THIS run's coverage rather than a comparison, so
it is true regardless of whether a comparison was possible. It was gated anyway: the
blind-run guard was a bare ``return`` placed above it, so a run that could not read
openclaw.json skipped the disclosure along with the removal loop it was meant to skip.

That combination is not a corner: a home whose memory files live under a
config-declared workspace is exactly the home where an unreadable config makes files
vanish from view, and a truncated memory set is exactly where an unread note can hide a
payload. Both true at once produced silence about both.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.monitor import _MEMORY_MAX_FILES, _append_memory_alerts


def _snap_with_capped(paths):
    return {
        "memory": {},
        "memory_capped": sorted(paths),
        "bootstrap": {},
    }


def _disclosures(alerts):
    return [m for lvl, m in alerts if "NOT monitored" in m]


def test_the_cap_disclosure_survives_a_blind_run():
    capped = [f"memory/note{i}.md" for i in range(_MEMORY_MAX_FILES + 3)]
    alerts: list = []
    _append_memory_alerts(_snap_with_capped([]), _snap_with_capped(capped), alerts,
                          trust_removals=False)
    found = _disclosures(alerts)
    assert found, "a blind run must still disclose unmonitored memory files"
    assert str(len(capped)) in found[0]


def test_it_is_the_same_disclosure_a_sighted_run_gives():
    """Not a second, weaker sentence for the blind case — the identical statement, because
    the fact it states does not depend on whether a comparison was possible."""
    capped = ["memory/big.md", "memory/huge.md"]
    blind: list = []
    sighted: list = []
    _append_memory_alerts(_snap_with_capped([]), _snap_with_capped(capped), blind,
                          trust_removals=False)
    _append_memory_alerts(_snap_with_capped([]), _snap_with_capped(capped), sighted,
                          trust_removals=True)
    assert _disclosures(blind) == _disclosures(sighted)


def test_a_blind_run_still_reports_no_removals():
    """The behaviour the guard exists for is unchanged: a file that dropped out of a
    collapsed config view is a collection artifact, not a deletion."""
    prev = {"memory": {"memory/gone.md": {"hash": "a"}}, "memory_capped": [],
            "bootstrap": {}}
    curr = {"memory": {}, "memory_capped": [], "bootstrap": {}}
    alerts: list = []
    _append_memory_alerts(prev, curr, alerts, trust_removals=False)
    assert not [m for _, m in alerts if "removed since last check" in m]


def test_a_sighted_run_still_reports_removals():
    prev = {"memory": {"memory/gone.md": {"hash": "a"}}, "memory_capped": [],
            "bootstrap": {}}
    curr = {"memory": {}, "memory_capped": [], "bootstrap": {}}
    alerts: list = []
    _append_memory_alerts(prev, curr, alerts, trust_removals=True)
    assert [m for _, m in alerts if "removed since last check" in m]


def test_nothing_is_disclosed_when_nothing_was_capped():
    alerts: list = []
    _append_memory_alerts(_snap_with_capped([]), _snap_with_capped([]), alerts,
                          trust_removals=False)
    assert not _disclosures(alerts)
