"""The `behavioral_*` dimensions — what the agent actually DID, between two runs.

F-173. `behavioral.py` produces the detector results; this compares two runs of them. The
keys are CONDITIONAL: their absence means the behavioural layer did not run this invocation,
never that it ran and found nothing. Reporting those two the same way is the fail-open shape
this dimension exists to avoid, so the arm answers UNKNOWN rather than passing over a layer
that was never executed.
"""

from __future__ import annotations
from ._shared import (  # noqa: F401
    NOTE_CONFIG_BLIND,
    NOTE_INSPECTION_CAPPED,
    NOTE_NO_PRIOR_RECORD,
    NOTE_UNDETERMINED,
)


def _diff_behavioral(
        _c_fired,
        _check_title,
        _p_fired,
        alerts,
        curr,
        curr_blind,
        note,
        prev,
        prev_blind,
) -> None:
    """C-433: the behavioural dimension's diff arm, lifted verbatim out of `diff_with_notes`.

    Takes nine parameters because that is what the statement measurably read, not because
    it is entangled: it writes nothing any later arm reads. The whole `if` travelled with
    its condition — rebuilding a compound guard as one clause is how the previous batch
    re-created a B-269 fabrication, so the condition is moved rather than re-derived.
    """
    if not isinstance(_c_fired, list):
        note(NOTE_UNDETERMINED,
             "What your agent actually did was not examined this run, so nothing in this "
             "report covers its behaviour — only how it is set up.")
    else:
        if curr.get("behavioral_capped"):
            note(NOTE_INSPECTION_CAPPED,
                 "There is more saved agent activity than can be replayed in one run, so "
                 "only the most recent part of it was examined for behaviour patterns.")
        _b_unknown = curr.get("behavioral_undetermined")
        if isinstance(_b_unknown, list) and _b_unknown:
            # Neither the count's catalog TITLE nor the phrase "the activity log" — both
            # were in the first version and both were wrong here. The titles are written
            # for the check catalog ("OpenClaw's runtime audit_events trail — coverage,
            # policy-blocked tools, and evasive tool names") and read as jargon in a
            # sentence aimed at someone who just wants to know if their agent is fine. And
            # "from the activity log" presupposes there is one: measured on a fresh home
            # with no recorded activity at all, B191 is UNKNOWN and this note fires, so the
            # wording has to be true for "there is nothing to read" as well as for "what
            # was read did not settle it".
            note(NOTE_UNDETERMINED,
                 f"{len(_b_unknown)} thing(s) about how your agent has been behaving could "
                 f"not be determined — there may be too little recorded activity to judge "
                 f"yet. Run --behavioral to see which.")
        if isinstance(_p_fired, list):
            if prev_blind or curr_blind:
                note(NOTE_CONFIG_BLIND,
                     "Behaviour patterns were not compared with last time: judging them "
                     "needs your settings file, and one of the two runs could not read it.")
            else:
                _b_new = sorted(set(_c_fired) - set(_p_fired))
                if _b_new:
                    # F-182: severity depends on whether the two runs actually READ the
                    # whole trajectory, and until now the answer was recorded and never
                    # consulted. `behavioral_capped` is written into the snapshot on both
                    # sides; only `curr`'s copy was ever read, and only to raise a note.
                    #
                    # The INFO below is correct WHEN the window was capped: the replay holds
                    # only recent activity, so a detector firing now and not last time can
                    # mean nothing more than the window sliding over older events, and
                    # paging on window movement is a false alarm. But when NEITHER run hit
                    # the cap, both replays were complete, that ambiguity does not exist,
                    # and "newly fired" means newly DONE — the agent did something it had
                    # not done before. At INFO that sat below the shipped cron recipe's
                    # `--fail-on medium`, so the one signal in this whole watch about what
                    # the agent actually DID, rather than how it is configured, could never
                    # reach anyone.
                    #
                    # `is False`, not falsy: an ABSENT flag (an older baseline, or a run
                    # that did not record one) must read as capped. Absence is not evidence
                    # that the replay was complete, and the failure it would cause is the
                    # loud kind — paging on a window slide.
                    #
                    # MEDIUM is the ceiling for the reason the `plugins` arm states: no
                    # HIGH or CRITICAL ships on fixture evidence alone.
                    #
                    # An earlier version of this comment claimed the branch had ONLY fixture
                    # evidence "by construction", because this machine's own OpenClaw home
                    # is capped. That was an overstatement and it is corrected here rather
                    # than quietly dropped: `files_capped` is a property of how much
                    # recorded activity a home holds, not of the fleet. Measured through the
                    # real audit path — `~/.openclaw` True, `fixtures/home_safe` False,
                    # `fixtures/traj_outcome_anomaly` False with T2 fired — so the branch IS
                    # reachable end to end, and
                    # `tests/test_f182_behaviour_newly_done.py::test_the_paging_branch_is_
                    # reachable_through_the_real_cli` exercises it through `main()`.
                    #
                    # What remains true: no run against a home with a LOT of recorded
                    # activity exercises it, so the calibration is unvalidated for exactly
                    # the users who have the most history.
                    # `behavioral_incomplete`, NOT `behavioral_capped`. The first version
                    # of this gate used the cap alone, and a measurement broke it: an
                    # unreadable sidecar (mode 000, a broken link, a race) leaves
                    # `files_capped` False while nothing was parsed at all, so the gate
                    # called an empty replay complete and paged on a detector that was newly
                    # SEEN. `analysis_incompleteness` covers six reasons; the cap is one.
                    #
                    # Still `is False`, and now it matters twice over: a baseline written
                    # before this key existed has no opinion about completeness, and reading
                    # its absence as "complete" would page on the first run after an upgrade.
                    _complete = (prev.get("behavioral_incomplete") is False
                                 and curr.get("behavioral_incomplete") is False)
                    _titles = ", ".join(_check_title(c) for c in _b_new)
                    if _complete:
                        alerts.append((
                            "MEDIUM",
                            f"{len(_b_new)} behaviour pattern(s) appear in what your agent "
                            f"actually did, and did not last time: {_titles}. Both checks "
                            f"replayed its activity in full, so this is something new it "
                            f"did rather than something newly visible. Run --behavioral "
                            f"for the detail."))
                    else:
                        alerts.append((
                            "INFO",
                            f"{len(_b_new)} behaviour pattern(s) now appear in your agent's "
                            f"replayable activity and did not last time: "
                            f"{_titles}. That window only "
                            f"holds the most recent activity, so this may be newly seen "
                            f"rather than newly done. Run --behavioral for the detail."))
