"""B-500 — the checks dimension alerted on 2 of its 25 possible transitions.

`checks` stores one status per catalog entry and is the only monitoring surface for most
of the subject: 88 of 188 catalog entries never move the score at all, so for those a
regression can surface nowhere else. The comparison walked the CURRENT ids only and its
arms required `curr == FAIL` or `prev == PASS` exactly, which left twenty-three cells
silent — including every path into UNKNOWN.

Measured on the maintainer's own machine: 78 of 184 checks sit in WARN or UNKNOWN. Going
grey is cheaper for an attacker than going red *and* it raises the displayed score, because
UNKNOWN leaves the score's denominator entirely. A check that crashed was worse still: the
isolation wrapper replaces its catalog id with an `ERR:<funcname>` key, so the id VANISHES
and no arm ever visited it — a CRITICAL FAIL becoming a crash disappeared in silence.

This arm is also the epic's largest false-alarm risk, and the first attempt at it was
blocked by an independent pass with four reproduced false alarms — including two produced
by nothing more exotic than `--no-host` on an unchanged machine.

The rule that came out of that, and the one this file exists to hold: **an alert requires
positive evidence, never the absence of a marker.** The first design gated on "this id is
not in `checks_not_applicable`", reasoning that an unmarked UNKNOWN must be real blindness.
It is not: the flag is set per-emitter, so B331/B332/B333 report the literal string "No MCP
servers configured." WITHOUT it while B15/B24/B166 report the same string WITH it, and only
15 of 48 UNKNOWNs on the maintainer's machine carry it at all. Connecting a first MCP
server therefore produced a finding for an ordinary action.

So the split is: `engine_degraded` — a check that demonstrably broke — alerts. Everything
else is disclosed as a coverage note through the C-418 mechanism. The silence still ends;
the claim just stops outrunning the evidence. Two runs of different scope are not compared
at all, because a check that "went dark" because the operator passed `--no-host` did not
go dark.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.monitor import diff, diff_with_notes

_NA_CHECK = "B24"     # a real catalog id whose surface is legitimately absent on many homes
_CRIT_CHECK = "B2"    # CRITICAL in the catalog


def _snap(checks, na=(), deg=(), **over):
    snap = {
        "version": 5,
        "checks": dict(checks),
        "checks_not_applicable": sorted(na),
        "checks_degraded": sorted(deg),
    }
    snap.update(over)
    return snap


def _levels(alerts):
    return [lvl for lvl, _ in alerts]


# ---------------------------------------------------------------- newly alerting

def test_a_failing_check_going_dark_is_disclosed_but_not_asserted():
    """An unresolved FAIL that becomes UNKNOWN stops counting against the score entirely,
    so the grade can RISE on the strength of a check ceasing to work. That is worth saying.

    It is NOT worth *alerting*, because the cause cannot be evidenced: the only marker that
    would separate "the surface went away" from "the check broke" is `not_applicable`, and
    only a subset of emitters set it — 15 of 48 UNKNOWNs on the maintainer's own machine.
    Alerting on the ABSENCE of a marker is alerting on the absence of evidence."""
    alerts, notes = diff_with_notes(_snap({_CRIT_CHECK: FAIL}), _snap({_CRIT_CHECK: UNKNOWN}))
    assert alerts == []
    assert any("no longer determine their state" in m for _, m in notes), notes


def test_a_warning_check_going_dark_is_disclosed_too():
    _, notes = diff_with_notes(_snap({_CRIT_CHECK: WARN}), _snap({_CRIT_CHECK: UNKNOWN}))
    assert any("no longer determine their state" in m for _, m in notes)


def test_a_crashed_check_says_it_crashed_rather_than_that_it_went_quiet():
    """Distinct wording because the user action differs: a crash is a bug to report, a
    surface going away is a configuration change."""
    alerts, _ = diff_with_notes(_snap({_CRIT_CHECK: WARN}),
                                _snap({_CRIT_CHECK: UNKNOWN}, deg=[_CRIT_CHECK]))
    assert alerts and "Stopped working" in alerts[0][1]
    assert "unverified rather than resolved" in alerts[0][1]


def test_a_verdict_lost_to_a_crash_is_announced_once_at_run_level():
    """The isolation wrapper does not set the id to UNKNOWN — it removes the id and adds an
    `ERR:<funcname>` key. Nothing visited the removed id, so the verdict it carried was
    dropped in silence.

    ONE alert, not one per id: `ERR:<funcname>` cannot be mapped back to the catalog id
    that produced it, so saying "THIS check crashed" is a guess — and a wrong one whenever
    the same release also removed other checks. Both facts are stated, with no invented
    link between them."""
    alerts, _ = diff_with_notes(_snap({_CRIT_CHECK: FAIL}),
                                _snap({"ERR:check_gateway": UNKNOWN}))
    assert _levels(alerts) == [BY_ID[_CRIT_CHECK].severity]
    assert "crashed or timed out" in alerts[0][1]
    assert "unverified rather than resolved" in alerts[0][1]


def test_a_blind_check_that_starts_warning_is_a_note_not_a_finding():
    """Reproduced as a false alarm before this was downgraded: connecting a first MCP
    server made this arm announce a finding for an entirely ordinary action."""
    alerts, notes = diff_with_notes(_snap({_NA_CHECK: UNKNOWN}), _snap({_NA_CHECK: WARN}))
    assert alerts == []
    assert any("could not determine last time" in m for _, m in notes), notes


# ---------------------------------------------------------------- must stay silent

def test_a_feature_appearing_for_the_first_time_is_not_a_finding():
    """THE false alarm this arm exists to avoid. A surface confirmed absent last run and
    present now is a user configuring something, not a check losing its footing. On the
    maintainer's machine ten checks sit in exactly this state."""
    alerts, _ = diff_with_notes(_snap({_NA_CHECK: UNKNOWN}, na=[_NA_CHECK]),
                                _snap({_NA_CHECK: WARN}))
    assert alerts == [], alerts


def test_a_surface_going_away_is_not_a_check_going_dark():
    """The mirror case: FAIL -> UNKNOWN is silent when the thing it inspected is confirmed
    gone, because there is nothing left to fail."""
    alerts, _ = diff_with_notes(_snap({_CRIT_CHECK: FAIL}),
                                _snap({_CRIT_CHECK: UNKNOWN}, na=[_CRIT_CHECK]))
    assert alerts == []


def test_the_unchanged_and_improving_cells_stay_silent():
    for prev, curr in [(WARN, WARN), (UNKNOWN, UNKNOWN), (FAIL, FAIL), (PASS, PASS),
                       (WARN, PASS), (FAIL, PASS), (UNKNOWN, PASS)]:
        alerts, _ = diff_with_notes(_snap({_CRIT_CHECK: prev}), _snap({_CRIT_CHECK: curr}))
        assert alerts == [], (prev, curr, alerts)


def test_a_check_this_version_added_cannot_regress():
    """Absent from the previous snapshot means there is no earlier verdict to have fallen
    from, so WARN/UNKNOWN on arrival is not news."""
    for status in (WARN, UNKNOWN):
        alerts, _ = diff_with_notes(_snap({}), _snap({_CRIT_CHECK: status}))
        assert alerts == [], (status, alerts)


def test_a_check_removed_by_an_upgrade_is_a_note_not_an_alert():
    """No `ERR:` key means the id no longer exists in this build. That is a catalog change,
    not an event, and it self-heals on the next run."""
    alerts, notes = diff_with_notes(_snap({_CRIT_CHECK: FAIL}), _snap({}))
    assert alerts == []
    assert any("did not run this time" in m for _, m in notes)


def test_a_blind_run_does_not_fire_the_new_arms():
    """A run that cannot read the config turns a swathe of checks UNKNOWN at once;
    announcing each would bury the single honest alert that already explains it."""
    for blind_side in ("prev", "curr"):
        prev = _snap({_CRIT_CHECK: FAIL}, config_parse_error=(blind_side == "prev"))
        curr = _snap({_CRIT_CHECK: UNKNOWN}, config_parse_error=(blind_side == "curr"))
        alerts, _ = diff_with_notes(prev, curr)
        assert not [m for _, m in alerts if "No longer determinable" in m], blind_side


# ---------------------------------------------------------------- the reason record

def test_an_older_baseline_stands_down_instead_of_guessing():
    """Without the recorded reasons the benign and the real case are the same string, so
    the arms that need them do not run — and the run says so rather than staying quiet."""
    prev = {"version": 4, "checks": {_CRIT_CHECK: FAIL}}     # no reason lists
    curr = _snap({_CRIT_CHECK: UNKNOWN})
    alerts, notes = diff_with_notes(prev, curr)
    assert not [m for _, m in alerts if "No longer determinable" in m]
    assert any("not applicable" in m for _, m in notes)


def test_the_migration_from_the_previous_snapshot_version_is_silent():
    """The regression that matters on any schema bump: a baseline written before this
    change, compared against one written after it, must emit nothing."""
    curr = _snap({_CRIT_CHECK: PASS})
    prev = {k: v for k, v in curr.items()
            if k not in ("checks_not_applicable", "checks_degraded")}
    prev["version"] = 4
    assert diff(prev, curr) == []
    assert diff(curr, prev) == []


def test_the_shim_still_returns_only_alerts():
    prev, curr = _snap({_CRIT_CHECK: FAIL}), _snap({_CRIT_CHECK: UNKNOWN})
    assert diff(prev, curr) == diff_with_notes(prev, curr)[0]


# ------------------------------------------------ regressions for reproduced false alarms

def test_two_runs_of_different_scope_are_not_compared_at_all():
    """FA-1/FA-2, reproduced by an independent pass: toggling --no-host/--no-sockets
    produced five false alerts in EACH direction on a machine where nothing had changed.
    The runs examined different subjects; a difference between them is arithmetic."""
    wide = _snap({_CRIT_CHECK: WARN, "B50": PASS}, scope=["host", "sockets"])
    narrow = _snap({_CRIT_CHECK: UNKNOWN, "B50": UNKNOWN}, scope=[])
    for prev, curr in ((wide, narrow), (narrow, wide)):
        alerts, notes = diff_with_notes(prev, curr)
        assert alerts == [], alerts
        assert any("do not cover the same ground" in m for _, m in notes)


def test_scope_is_recorded_from_what_actually_ran_not_from_cli_flags():
    """The first fix recorded the CLI's own opt-out list, which is populated only on the
    CLI path — so a library caller passing include_host=False reproduced the identical
    false alerts with an empty list. What matters is what ran."""
    from clawseccheck import audit
    from clawseccheck.monitor import snapshot
    from pathlib import Path
    fixtures = Path(__file__).resolve().parent.parent / "fixtures" / "home_safe"
    wide = snapshot(*audit(fixtures, include_host=True, include_sockets=True))
    narrow = snapshot(*audit(fixtures, include_host=False, include_sockets=False))
    assert wide["scope"] and wide["scope"] != narrow["scope"]
    assert diff(wide, narrow) == [] and diff(narrow, wide) == []


def test_one_unrelated_crash_does_not_reclassify_every_removed_check():
    """FA-3: the crash predicate was global, so a single unrelated crash turned three
    ids removed by an upgrade into three false "Stopped reporting" lines — contradicting
    the arm's own stated rule that a catalog removal must not alert."""
    prev = _snap({"B1": PASS, "B10": PASS, "B11": PASS, "B12": PASS})
    curr = _snap({"B1": PASS, "ERR:check_unrelated": UNKNOWN})
    alerts, notes = diff_with_notes(prev, curr)
    assert alerts == [], alerts
    assert any("did not run this time" in m for _, m in notes)


def test_a_new_ignore_rule_is_not_reported_as_a_crash():
    """FA-4: suppressed findings are excluded from the snapshot, so a new ignore rule makes
    ids vanish. Blaming that on a crash is a second, false explanation for something the
    user just did on purpose — and the ignore change is already alerted separately."""
    prev = _snap({"B1": PASS, "B10": FAIL, "B11": WARN}, ignore_hash="aaa")
    curr = _snap({"B1": PASS, "ERR:check_unrelated": UNKNOWN}, ignore_hash="bbb")
    alerts, _ = diff_with_notes(prev, curr)
    assert [m for _, m in alerts if "crashed" in m] == []
    assert any("clawseccheckignore" in m for _, m in alerts)
