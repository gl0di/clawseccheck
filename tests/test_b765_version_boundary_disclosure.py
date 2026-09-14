"""B-765: an existing check id's verdict moving across a ClawSecCheck upgrade must not
read as an ordinary, unqualified config regression in --monitor.

The concrete failure this closes: a user upgrades ClawSecCheck, changes nothing in their
config, and B175's own logic improvement (correctly reading OpenClaw 2026.8.1's real
defaults) makes it fire where an older build's logic did not. Before this fix, the alert
and the hash-chained journal entry both read exactly like a real drift event — same
wording, same severity, same icon — with nothing anywhere naming which ClawSecCheck
build produced either side of the comparison.

Never call this "fabricated": the verdict genuinely differs between the two runs; nothing
is invented. What is wrong is the ATTRIBUTION a reader makes ("my config changed") when
the true cause may be the tool. See monitordims/_checks.py's _version_disclaimer
docstring for the same distinction, and the B-269 prev_blind precedent this mirrors.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.catalog import BY_ID
from clawseccheck.monitor import diff_with_notes, snapshot
from clawseccheck.monitordims._checks import _capped, _version_disclaimer


def _checks_snap(checks, **extra):
    snap = {"score": 90, "grade": "A", "raw_score": 90, "raw_score_scope": "fixed-scope",
            "graded": True, "checks": dict(checks), "skills": {}, "bootstrap": {},
            "ignore_hash": ""}
    snap.update(extra)
    return snap


# ---------------------------------------------------------------------------------------
# 1. snapshot() writes the field unconditionally
# ---------------------------------------------------------------------------------------

def test_snapshot_writes_the_producer_version_unconditionally():
    from pathlib import Path

    from clawseccheck import __version__
    from clawseccheck.collector import Context
    from clawseccheck.scoring import compute

    ctx = Context(home=Path("/nonexistent"))
    findings: list = []
    score = compute(findings)
    snap = snapshot(ctx, findings, score)
    assert snap["clawseccheck_version"] == __version__
    assert "clawseccheck_version" in snap["watched"], (
        "the manifest a user reads to see what this build compares must list the new key"
    )


# ---------------------------------------------------------------------------------------
# 2. diff_with_notes tri-state: known / unknown / same / absent-on-both-sides
# ---------------------------------------------------------------------------------------

def test_a_known_version_boundary_down_ranks_and_names_both_versions():
    prev = _checks_snap({"A1": "PASS"}, clawseccheck_version="4.0.0")
    curr = _checks_snap({"A1": "FAIL"}, clawseccheck_version="4.0.1")
    alerts, _ = diff_with_notes(prev, curr)
    hit = [a for a in alerts if "Now FAILING" in a[1]]
    assert hit, alerts
    sev, msg = hit[0]
    assert sev == "MEDIUM", (
        f"A1 is CRITICAL ({BY_ID['A1'].severity}); a version-crossed FAIL must be capped "
        f"at MEDIUM, got {sev}"
    )
    assert "4.0.0" in msg and "4.0.1" in msg
    assert "possibly attributable to a clawseccheck upgrade" in msg.lower()
    assert "fabricated" not in msg.lower()


def test_an_unrecorded_baseline_hedges_without_naming_a_version():
    """The literal B-765 repro: the FIRST run after upgrading across the release that adds
    this field. prev has no clawseccheck_version at all -- not "same", not "different",
    a genuine third state that must not guess."""
    prev = _checks_snap({"A1": "PASS"})
    curr = _checks_snap({"A1": "FAIL"}, clawseccheck_version="4.0.1")
    alerts, _ = diff_with_notes(prev, curr)
    hit = [a for a in alerts if "Now FAILING" in a[1]]
    assert hit, alerts
    sev, msg = hit[0]
    assert sev == "MEDIUM"
    assert "cannot be ruled out" in msg
    assert "4.0.1" not in msg, "must not assert a match/mismatch it cannot prove"
    assert "fabricated" not in msg.lower()


def test_the_same_producer_version_reports_plainly_no_disclaimer():
    """The control: a same-version transition must render byte-identically to before this
    fix existed, or the fix would mute real drift along with the false attribution."""
    prev = _checks_snap({"A1": "PASS"}, clawseccheck_version="4.0.1")
    curr = _checks_snap({"A1": "FAIL"}, clawseccheck_version="4.0.1")
    alerts, _ = diff_with_notes(prev, curr)
    hit = [a for a in alerts if "Now FAILING" in a[1]]
    assert hit, alerts
    sev, msg = hit[0]
    assert sev == BY_ID["A1"].severity == "CRITICAL"
    assert msg == "Now FAILING: Lethal Trifecta (untrusted input \u00d7 sensitive data \u00d7 outbound)."
    assert "possibly attributable" not in msg.lower()


def test_absent_on_both_sides_is_also_the_no_boundary_case():
    """Two hand-built snapshots that never set the key at all (every pre-B-765 test in
    this suite) must be completely unaffected -- the gate gives up on `curr` first."""
    prev = _checks_snap({"A1": "PASS"})
    curr = _checks_snap({"A1": "FAIL"})
    alerts, _ = diff_with_notes(prev, curr)
    hit = [a for a in alerts if "Now FAILING" in a[1]]
    assert hit, alerts
    sev, msg = hit[0]
    assert sev == "CRITICAL"
    assert "possibly attributable" not in msg.lower()


# ---------------------------------------------------------------------------------------
# 3. All three emission sites get the down-rank + disclosure
# ---------------------------------------------------------------------------------------

def test_pass_to_warn_is_down_ranked_and_disclosed_across_a_boundary():
    prev = _checks_snap({"B2": "PASS"}, clawseccheck_version="4.0.0")
    curr = _checks_snap({"B2": "WARN"}, clawseccheck_version="4.0.1")
    alerts, _ = diff_with_notes(prev, curr)
    hit = [a for a in alerts if "No longer passing" in a[1]]
    assert hit, alerts
    sev, msg = hit[0]
    assert sev == "LOW", "one step under the arm's un-crossed MEDIUM ceiling"
    assert "possibly attributable to a clawseccheck upgrade" in msg.lower()
    assert "was PASS, now WARN" in msg
    # the pre-existing tail clause must survive verbatim, not just the new sentence
    assert "unchanged grade does not mean this did not get worse" in msg


def test_pass_to_warn_same_version_stays_at_medium_no_disclosure():
    prev = _checks_snap({"B2": "PASS"}, clawseccheck_version="4.0.1")
    curr = _checks_snap({"B2": "WARN"}, clawseccheck_version="4.0.1")
    alerts, _ = diff_with_notes(prev, curr)
    hit = [a for a in alerts if "No longer passing" in a[1]]
    assert hit, alerts
    sev, msg = hit[0]
    assert sev == "MEDIUM"
    assert "possibly attributable" not in msg.lower()


def test_pass_to_unknown_is_down_ranked_and_disclosed_across_a_boundary():
    prev = _checks_snap({"B2": "PASS"}, clawseccheck_version="4.0.0")
    curr = _checks_snap({"B2": "UNKNOWN"}, clawseccheck_version="4.0.1")
    alerts, _ = diff_with_notes(prev, curr)
    hit = [a for a in alerts if "No longer determinable" in a[1]]
    assert hit, alerts
    sev, msg = hit[0]
    assert sev == "LOW"
    assert "possibly attributable to a clawseccheck upgrade" in msg.lower()
    assert "was PASS, now UNKNOWN" in msg
    assert "excluded from the score while UNKNOWN" in msg


# ---------------------------------------------------------------------------------------
# 4. prev_blind still takes precedence -- version-boundary handling never overrides it
# ---------------------------------------------------------------------------------------

def test_a_blind_prior_run_still_wins_over_a_version_boundary():
    """The prev_blind branch `continue`s before this code is ever reached -- a version
    boundary must not change that, or a genuinely untrustworthy baseline would start
    being read as a soft, version-attributable regression instead."""
    prev = _checks_snap({"A1": "PASS"}, clawseccheck_version="4.0.0", config_parse_error=True)
    curr = _checks_snap({"A1": "FAIL"}, clawseccheck_version="4.0.1")
    alerts, _ = diff_with_notes(prev, curr)
    hit = [a for a in alerts if "Now FAILING" in a[1]]
    assert hit, alerts
    sev, msg = hit[0]
    assert sev == "MEDIUM"
    assert "could not read the config" in msg, (
        "the prev_blind wording must win -- it is a stronger, better-evidenced claim "
        "than a version boundary would be"
    )
    assert "possibly attributable to a ClawSecCheck upgrade" not in msg


# ---------------------------------------------------------------------------------------
# 5. The two module-level helpers, pinned directly
# ---------------------------------------------------------------------------------------

def test_capped_never_raises_severity():
    assert _capped("LOW", "MEDIUM") == "LOW"
    assert _capped("HIGH", "MEDIUM") == "MEDIUM"
    assert _capped("CRITICAL", "LOW") == "LOW"
    assert _capped("MEDIUM", "MEDIUM") == "MEDIUM"


def test_version_disclaimer_never_says_fabricated():
    known = _version_disclaimer(("known", "4.0.0", "4.0.1"))
    unknown = _version_disclaimer(("unknown", "", "4.0.1"))
    for msg in (known, unknown):
        assert "fabricated" not in msg.lower()
        assert "possibly attributable to a clawseccheck upgrade" in msg.lower()
    assert "4.0.0" in known and "4.0.1" in known
    assert "4.0.0" not in unknown and "predates this build" in unknown
