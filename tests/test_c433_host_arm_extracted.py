"""C-433 — the first per-dimension extraction, pinned.

`_diff_host_monitors` was lifted out of `diff_with_notes`. This is the shape the task asks
for and NOT the by-function shape it rejected three times: the arm travels with its own
dimension rather than with "all the diff code".

**Why this arm went first, measured rather than guessed.** Its entire free-variable set
inside `diff_with_notes` was `_host_pair`, `alerts`, `note` and module constants — three
parameters. The task's blocking analysis said a per-dimension cut meant threading 61 shared
locals; that figure is an aggregate over the whole 1,635-line function and does not describe
the arms, which read three or four names each. The 61 live in the blind-run preamble, which
is why the preamble moves last.

**The verification harness for the move was blind at first, and that is the lesson worth
carrying into the next extraction.** The initial contract check compared `diff_with_notes`
output across the two fixture homes and reported "identical" — but disabling the arm
entirely *also* produced identical output, because neither fixture home carries a `host`
dimension at all. A negative measured without a positive control is worthless. The cases
below are the ones that actually exercise the arm.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import pytest

from clawseccheck import monitor
from clawseccheck.monitor import diff_with_notes

_PRESENT = {"network_ids": "present", "edr_av": "present", "file_integrity": "unknown"}
_GONE = {"network_ids": "absent", "edr_av": "present", "file_integrity": "unknown"}
_ALL_UNKNOWN = {"network_ids": "unknown", "edr_av": "unknown", "file_integrity": "unknown"}


def _snap(host=None, **kw) -> dict:
    base = {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {}, "graded": True, "score": 50, "raw_score": 50, "grade": "F",
        "scope": ["host"], "watched": list(monitor.WATCHED_DIMENSIONS),
        "config_ever_seen": True, "config_file_sha256": "a" * 64,
    }
    if host is not None:
        base["host"] = host
    base.update(kw)
    return base


def _host_alerts(prev, curr):
    alerts, _notes = diff_with_notes(prev, curr)
    return [(lvl, m) for lvl, m in alerts if "Host monitor" in m]


def _host_notes(prev, curr):
    _alerts, notes = diff_with_notes(prev, curr)
    return [(c, s) for c, s in notes if "security tool" in s]


def test_the_arm_is_a_module_level_function_now():
    """The structural claim. If a later change inlines it back, the extraction has been
    undone and the per-dimension pattern this establishes is gone with it."""
    assert callable(getattr(monitor, "_diff_host_monitors", None))


def test_a_watcher_that_disappears_still_alerts():
    """The positive control, and the case the first harness could not see. Without this,
    every 'output is unchanged' claim about the move is satisfied by an arm that never
    runs."""
    hits = _host_alerts(_snap(_PRESENT), _snap(_GONE))
    assert len(hits) == 1, hits
    assert hits[0][0] == "HIGH", hits
    assert "network_ids" in hits[0][1], hits


def test_an_unchanged_host_says_nothing():
    assert not _host_alerts(_snap(_PRESENT), _snap(_PRESENT))


def test_a_watcher_that_was_never_confirmed_is_disclosed_not_alerted():
    """C-418's rule, preserved across the move: only present -> absent alerts, and a class
    that was already `unknown` gets a note instead of silence."""
    assert not _host_alerts(_snap(_ALL_UNKNOWN), _snap(_ALL_UNKNOWN))
    assert _host_notes(_snap(_ALL_UNKNOWN), _snap(_ALL_UNKNOWN))


def test_absent_on_one_side_is_neither_alert_nor_note():
    """The dimension simply was not recorded. Reporting it would put a permanent entry in
    the un-compared list on every machine that never enables host detection."""
    assert not _host_alerts(_snap(), _snap(_PRESENT))
    assert not _host_notes(_snap(), _snap(_PRESENT))


@pytest.mark.parametrize("pair", [None])
def test_the_function_tolerates_no_pair(pair):
    """It is called unconditionally now; the None guard moved inside. A caller that stops
    checking must not get an exception."""
    monitor._diff_host_monitors(pair, [], lambda *_a, **_k: None)
