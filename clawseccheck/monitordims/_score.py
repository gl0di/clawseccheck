"""The `score` / `grade` / `raw_score` dimensions — the audit's own verdict, over time.

A score is only comparable against a score taken over the same SCOPE, so the arm reads
`raw_score_scope` and stands down rather than reporting a drop that is really a change in
what was measured. That guard is why `raw_score_scope` is in the watched manifest at all:
its absence from a baseline suppresses the drop alert outright.
"""

from __future__ import annotations
from ..catalog import FAIL, FAIL_WEIGHT_STATUSES, UNKNOWN  # noqa: F401
from ._shared import (  # noqa: F401
    NOTE_NO_PRIOR_RECORD,
    NOTE_RECORD_DAMAGED,
    NOTE_UNDETERMINED,
    _h,
    RAW_DEGRADED,
    RAW_NO_FIGURE,
    RAW_NO_SCOPE,
    RAW_SCOPE_MOVED,
    _num,
    _num_or_none,
    raw_backstop,
)


def _diff_score(
        _both_graded,
        _same_scope_flags,
        alerts,
        curr,
        curr_blind,
        note,
        prev,
        prev_blind,
) -> None:
    """C-433: the score/grade dimension's diff arm.

    A score is only comparable against one taken over the same SCOPE, so the arm reads
    `raw_score_scope` and stands down rather than reporting a fall that is really a change
    in what was measured.
    """
    # B-269: a partially-evaluated run is not comparable to a full one in EITHER direction
    # — a blind run's score is inflated by UNKNOWN-exclusion, so the run after it would
    # report a fabricated "score dropped" as the real checks come back. The coverage
    # alert above says so explicitly instead.
    # `_same_scope_flags`: a score taken with --no-host is not the same measurement as
    # one taken without it, so a fall between them is arithmetic, not drift.
    if not (prev_blind or curr_blind) and _same_scope_flags and _both_graded:
        # B-694: `_num_or_none`, not `_num`. `_num`'s default of 0 is the hazard
        # `monitor.py`'s own snapshot comment already names for an ABSENT score -- "would
        # fabricate a catastrophic drop on a config that did not change" -- and a CORRUPTED
        # score has the identical shape with no guard: `"score": true` or `"score": "49"`
        # both default to 0 and fire "Security score dropped: F 49 -> F True", printing the
        # corrupted value verbatim because the text read `.get()` rather than the checked
        # number. Absence is handled one layer up by `_both_graded`; this is the case where
        # the flag says graded and the field does not hold a number.
        p_score = _num_or_none(prev, "score")
        c_score = _num_or_none(curr, "score")
        if p_score is None or c_score is None:
            note(NOTE_RECORD_DAMAGED,
                 "The security score was not compared — one of the two records does not "
                 "hold a number there.")
        elif c_score < p_score:
            alerts.append(("HIGH", f"Security score dropped: {prev.get('grade')} {p_score} "
                                   f"-> {curr.get('grade')} {c_score}."))
        else:
            # B-273: the displayed score is capped by the most severe open FAIL
            # (scoring.py FAIL_CAPS — CRITICAL pins it at 49), so on any config already
            # holding a CRITICAL FAIL it is a constant and the comparison above can never
            # fire however much worse the config gets. Measured on a copy of a real home:
            # gateway auth token->none (B32 PASS->WARN) AND a standing allow-always
            # `/bin/sh *` exec grant (B172 PASS->WARN) applied together reported
            # "No new threats since last check", 49 -> 49, in the very run whose own
            # snapshot recorded both regressions. The uncapped pass-rate absorbs the
            # headroom the cap hides, so it still moves.
            #
            # Guarded on BOTH sides being present: a snapshot written before raw_score was
            # recorded has no baseline to compare, and inventing one from `score` would
            # read the cap's arrival as a quality drop. Absent = skip for one run, the
            # same idiom the mcp_detail / memory / RP2 blocks use. Self-healing.
            #
            # C-135/FIX1: ALSO guarded on both sides recording the IDENTICAL raw_score_scope
            # (see _raw_score_scope). raw_score's denominator is exactly the scored/
            # non-UNKNOWN/non-suppressed check set that run, and that set grows every time a
            # release ships new checks — so two snapshots straddling an upgrade compare
            # different denominators even though nothing on disk moved. Measured on the real
            # ~/.openclaw: extending the finding list by two new WARN checks alone (no config
            # change) fell raw 83 -> 82 while the capped score stayed 49 -> 49, and this was
            # the ONLY alert produced — a false, unactionable "review the check-level alerts"
            # pointing at alerts that correctly do not exist. A scope mismatch — including an
            # absent hash from a pre-this-fix snapshot — skips the comparison for one run,
            # same self-healing idiom as the presence guard above.
            # B-694: through the shared predicate, not a re-derived `isinstance(x, int)`.
            # `isinstance(True, int)` is True, so the hand-rolled check let a corrupted
            # `"raw_score": true` compare as 1 and fabricate a HIGH reading "fell 74 ->
            # True". `_shared._num` had already learned that (B-270) and said why; this
            # site had its own copy without the clause. `_num_or_none`, not `_num`: an
            # absent figure must SKIP the comparison, and `_num`'s default of 0 would
            # read the arrival of a baseline as a rise.
            #
            # B-691: the DECISION moved to `_shared.raw_backstop`, unchanged. `--trend`
            # makes the same temporal claim over the same two fields and had none of the
            # rules above — it printed a flat arrow across a run that gained four HIGH
            # FAILs. Keeping the rules here and restating them there is the shape B-689,
            # B-692 and B-693 each turned out to be. The note TEXTS stay here: they address
            # a monitor user, and the trend addresses its own reader.
            verdict, p_raw, c_raw = raw_backstop(
                prev, curr, "raw_score_scope", "raw_score")
            # C-418: this backstop is the ONLY thing that catches posture worsening once an
            # open FAIL has pinned the displayed score, so a run where it cannot fire is a
            # run with a real hole in it — and the hole was previously invisible.
            # Presence BEFORE equality: `same_scope` is also False when the key is simply
            # absent, and reporting that as "this version checks a different set of things"
            # states a specific fact the code has no evidence for — an older baseline
            # carries no scope hash at all, which says nothing about whether the check set
            # moved.
            if verdict == RAW_NO_SCOPE:
                note(NOTE_NO_PRIOR_RECORD,
                     "The underlying pass-rate was not compared — your saved record does "
                     "not say which checks its figure covered, so the two numbers cannot "
                     "be lined up.")
            elif verdict == RAW_SCOPE_MOVED:
                note(NOTE_NO_PRIOR_RECORD,
                     "The underlying pass-rate was not compared with last time: this "
                     "version checks a different set of things than the run that saved "
                     "your baseline did.")
            elif verdict == RAW_NO_FIGURE:
                note(NOTE_NO_PRIOR_RECORD,
                     "The underlying pass-rate was not compared — your saved record does "
                     "not carry that figure.")
            elif verdict == RAW_DEGRADED:
                alerts.append((
                    "HIGH",
                    f"Security posture degraded while the displayed score stayed at "
                    f"{curr.get('grade')} {curr.get('score')}: the underlying pass-rate "
                    f"fell {p_raw} -> {c_raw}. The score is already pinned by an open "
                    "FAIL, so it cannot fall further and an unchanged grade does NOT mean "
                    "nothing got worse. Review the check-level alerts in this run.",
                ))


def _raw_score_scope(findings) -> str:
    """C-135/FIX1: a hash of exactly the check ids ``scoring.compute()`` folded into THIS
    run's ``raw_score`` denominator — scored, not UNKNOWN/ARCHIVE, and not suppressed
    unless it is a FAIL. Mirrors ``scoring.compute()``'s own ``scored`` selection by hand
    (kept in sync deliberately rather than imported, since ``scoring.py`` is a sibling
    module this fix does not touch).

    ``raw_score`` is a weighted PASS-RATE, and its denominator is exactly this set's total
    weight. That denominator grows every time a release ships new checks, so two
    snapshots straddling an upgrade compare different denominators even though nothing on
    disk moved. Measured first-hand on the real ``~/.openclaw``: extending the finding
    list by two new WARN checks alone (no config change) dropped raw 83 -> 82 while the
    displayed score stayed 49 -> 49 (already pinned by an open CRITICAL FAIL) — and the
    ONLY alert the old code produced was "Security posture degraded ... Review the
    check-level alerts in this run", whose own closing sentence points at check-level
    alerts that correctly do not exist. This campaign alone moved the catalog from 143 to
    148 checks, so the defect would have fired on the project's own next release.

    The sibling PASS->FAIL arm below already carries the matching guard for exactly this
    reason (``pc.get(cid) == PASS``, chosen so "a check newly added by an upgrade, absent
    from the previous snapshot, cannot fire") — that reasoning had not been carried to
    ``raw_score``, whose own presence guard only covered a snapshot with NO ``raw_score``
    key at all (self-healing after one run, but blind to every subsequent upgrade). This
    hash extends the same protection: ``diff()`` trusts the raw-score backstop only when
    both snapshots recorded the IDENTICAL scope; a mismatch — including an absent hash
    from a pre-this-fix snapshot — skips the comparison for one run rather than fabricate
    a verdict against a moved denominator, the same self-healing, absent-key-is-a-no-op
    idiom every other dimension in this module already uses.
    """
    ids = sorted(
        f.id for f in findings
        if f.scored
        # B-751: mirrors scoring.compute()'s exclusions, which is why this moved with it.
        # The traversal status was excluded alongside UNKNOWN, so the drift signature did
        # not move when a zip-slip appeared in a watched home.
        and f.status != UNKNOWN
        and (not getattr(f, "suppressed", False)
             or f.status in FAIL_WEIGHT_STATUSES)
    )
    return _h(",".join(ids))
