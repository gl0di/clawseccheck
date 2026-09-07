"""The `checks` dimension — each individual check's verdict, and what moved.

The largest arm in the subsystem, because a status transition is not one comparison but a
matrix: PASS -> FAIL is a regression, FAIL -> PASS is a repair, and anything -> UNKNOWN is
neither — it is the check losing sight of its subject, which reads like good news on a
screen that only counts failures.

`checks_not_applicable` and `checks_degraded` are read alongside, so a check that stopped
applying is distinguished from one that stopped being able to answer.
"""

from __future__ import annotations
from ..catalog import (  # noqa: F401
    ACTIONABLE_STATUSES, BY_ID, FAIL, FAIL_WEIGHT_STATUSES, PASS, UNKNOWN, WARN,
)
from ._shared import NOTE_INSPECTION_CAPPED, NOTE_UNDETERMINED  # noqa: F401


def _diff_check_transitions(
        _check_sev,
        _check_title,
        _deg_curr,
        _na_curr,
        _na_prev,
        _newly_visible,
        _reasons_known,
        _same_scope_flags,
        _went_dark,
        alerts,
        cc,
        curr_blind,
        pc,
        prev_blind,
) -> None:
    """C-433: the `checks` dimension's diff arm — every per-check status transition.

    The largest arm in the subsystem, and the one with the most parameters (14). That
    count is what the statement measurably read; it writes nothing a later arm reads, so
    it is a wide signature rather than a coupled one.

    Most of the bulk is the reasoning each transition has to carry: which way is a
    regression, which is a repair, and which is the check losing sight of its subject and
    therefore neither.
    """
    for cid, status in cc.items():
        # B-755: both halves compared against the bare literal, so a check that acquired a
        # CONFIRMED archive escape between two runs announced nothing at all — the single
        # most consequential silence in the subsystem, since --monitor is what a cron job
        # reads. Reversed, it was also a false alarm: FAIL-weight -> FAIL would have
        # reported a brand-new failure where the verdict had not moved.
        if status in FAIL_WEIGHT_STATUSES and pc.get(cid) not in FAIL_WEIGHT_STATUSES:
            # B-269: a check that read UNKNOWN only because the PREVIOUS run could not
            # parse the config was not passing then — re-reading it as FAIL now is the
            # config becoming legible again, not a new failure. Writing that into the
            # hash-chained journal would make a fabricated claim permanent.
            #
            # NARROWS, does not close: a snapshot records only the status, not WHY a check
            # was UNKNOWN, so this also mutes the rare check that read UNKNOWN during the
            # blind window for a config-independent reason and genuinely turned FAIL on the
            # very next run. That is a bounded one-run false negative (the FAIL is still in
            # the run's own report, and the next diff sees FAIL on both sides), accepted in
            # preference to writing a fabricated "Now FAILING" into a tamper-evident
            # journal. Distinguishing the two would need a per-check reason code in the
            # snapshot, which is a schema change (SNAPSHOT_VERSION) beyond this fix.
            # A blind run's checks dict is not a valid comparison baseline in ANY status,
            # not just UNKNOWN. Measured on the real ~/.openclaw: with openclaw.json
            # momentarily absent, A1 reads WARN (not UNKNOWN) off the collapsed
            # ctx.config == {} view, and the run scores C/79 against the true F/49. So a
            # guard keyed only on UNKNOWN let a definite "Now FAILING: Lethal Trifecta"
            # reach the tamper-evident journal on the very next run with nothing changed.
            #
            # Going silent instead would trade that lie for a false negative — a genuine
            # regression landing right after a blind window would never be announced. So
            # the alert still fires, but it is DOWN-RANKED and re-worded to disclose that
            # the comparison crossed a window where the baseline could not be trusted.
            # This follows the project rule that an ambiguous signal is reported at WARN
            # strength rather than asserted or suppressed.
            # prev UNKNOWN out of a blind run carries no information at all — the check
            # was not passing then, so announcing a transition would be pure fabrication.
            # That case stays fully muted.
            if prev_blind and pc.get(cid) == UNKNOWN:
                continue
            title = BY_ID[cid].title if cid in BY_ID else cid
            if prev_blind:
                alerts.append((
                    "MEDIUM",
                    f"Now FAILING: {title} — but the previous run could not read the "
                    "config, so its recorded state is not a trustworthy baseline. This "
                    "may be the config becoming legible again rather than a new failure. "
                    "Re-run to get a clean comparison.",
                ))
                continue
            # B-280: the catalog's own severity for this check, not a flat literal. The
            # line above already resolves BY_ID[cid] for the title; hardcoding "HIGH"
            # rendered A1 and B2 — both CRITICAL in catalog.py — as `[!]` HIGH, sorting
            # them BELOW a routine CRITICAL "NEW MCP server connected" in render_monitor's
            # severity order, and persisting the understatement into events.jsonl. The full
            # audit renders the same A1 as `[X] CRITICAL`, so the tool was contradicting
            # itself about the same finding. "HIGH" stays the fallback for a cid absent
            # from the catalog, where there is no severity to read.
            alerts.append((getattr(BY_ID[cid], "severity", "HIGH") if cid in BY_ID else "HIGH",
                           f"Now FAILING: {title}."))
            # Honest labelling — what the prev_blind guard above does and does NOT fix.
            #
            # CLOSED here: no drift alert derived from a blind run's checks dict can reach
            # the journal any more, whatever status that run happened to record.
            #
            # NOT CLOSED, and not closable from monitor.py: the blind run's own verdict is
            # still wrong at the source. A check that mixes config-derived evidence without
            # calling checks/_shared.py's opt-in _config_unreadable() guard (B-228) keeps
            # computing a real-looking verdict from the collapsed ctx.config == {} view
            # that B-269 already established is untrustworthy. A1 (check_trifecta in
            # checks/_config.py) is one such check, so a blind run reports C/79 on a host
            # whose true grade is F/49 — an inflated grade, not merely a spurious alert.
            # Fixing that means giving A1 and its siblings the same opt-in guard B11 has,
            # which is a checks/_config.py change with its own adversarial review. Filed as
            # a follow-up; this module can only refuse to compare against the bad baseline,
            # which is what it now does.
            #
            # Accepted cost of keying on prev_blind alone: a check that genuinely turns FAIL
            # on the run right after a blind one is not announced for that one run. Bounded
            # and self-healing — the FAIL is still in that run's own report, and the next
            # diff sees FAIL on both sides. Preferred over writing a fabricated claim into
            # a tamper-evident journal, and consistent with the score-drop guard's identical
            # refusal to compare across a blind run.

        # B-273: a check leaving PASS for WARN or UNKNOWN used to be completely silent —
        # the loop above only ever fired on a transition INTO FAIL — and with the displayed
        # score pinned by an open CRITICAL FAIL there was no backstop underneath it either.
        # Both halves of that measured repro (gateway auth token->none, B32 PASS->WARN; a
        # standing allow-always `/bin/sh *` grant, B172 PASS->WARN) are real security
        # regressions that produced "No new threats since last check". The status is
        # already in the snapshot; nothing was missing but the comparison.
        #
        # Deliberately narrow, because this is the arm that could produce noise:
        #   * only transitions OUT OF PASS — a check that was already WARN and stays WARN
        #     says nothing new, and on the real home 70 of 143 checks sit in WARN/UNKNOWN.
        #     Requiring `pc.get(cid) == PASS` (not `!= status`) also means a check newly
        #     added by an upgrade, absent from the previous snapshot, cannot fire.
        #   * suppressed on a blind run in EITHER direction, same as the score-drop guard
        #     directly above: a run that cannot read openclaw.json turns a swathe of checks
        #     UNKNOWN at once, and announcing each as a regression would bury the single
        #     honest "could not read openclaw.json" alert that already explains it.
        #   * MEDIUM — below the FAIL alert, which now carries the check's true catalog
        #     severity (B-280). PASS->WARN is a real regression but a weaker claim than a
        #     FAIL, and this is an advisory alert, not a scored finding.
        # `_same_scope_flags` added by B-500: this arm predates the scope record and fired
        # "No longer determinable: Host firewall active" simply because the operator passed
        # --no-host. Pre-existing, and the same unsoundness the new arms are gated against —
        # comparing two runs that examined different subjects.
        elif (not (prev_blind or curr_blind) and _same_scope_flags
              and pc.get(cid) == PASS and status in (WARN, UNKNOWN)):
            title = BY_ID[cid].title if cid in BY_ID else cid
            if status == WARN:
                alerts.append((
                    "MEDIUM",
                    f"No longer passing: {title} — was PASS, now WARN. The overall score "
                    "may not move if it is already capped by an open FAIL, so an unchanged "
                    "grade does not mean this did not get worse.",
                ))
            else:
                # UNKNOWN is not merely "less information": an UNKNOWN check drops out of
                # the score DENOMINATOR entirely (scoring.py), so making a check
                # undeterminable can raise the displayed score. That makes it worth saying
                # out loud rather than treating as a neutral loss of coverage.
                alerts.append((
                    "MEDIUM",
                    f"No longer determinable: {title} — was PASS, now UNKNOWN. This check "
                    "is excluded from the score while UNKNOWN, so coverage dropped without "
                    "the grade reflecting it. Confirm the state it inspects is still "
                    "readable.",
                ))

        # B-500: a check that already carried a verdict and has now gone dark. Strictly
        # worse than the verdict staying put — an open FAIL that becomes UNKNOWN stops
        # counting against the score at all, so the grade can RISE on the strength of a
        # check ceasing to work. `curr not applicable` is excluded because that is the
        # benign shape: the surface it inspects is confirmed gone (the user removed their
        # MCP config), not the check losing its footing.
        elif (_reasons_known and _same_scope_flags and not (prev_blind or curr_blind)
              and status == UNKNOWN and pc.get(cid) in ACTIONABLE_STATUSES
              and cid not in _na_curr):
            title, was = _check_title(cid), pc[cid]
            if cid in _deg_curr:
                alerts.append((
                    _check_sev(cid, "HIGH"),
                    f"Stopped working: {title} — this check crashed or timed out, so its "
                    f"previous {was} verdict is now unverified rather than resolved.",
                ))
            else:
                # NOT an alert without positive evidence that the check broke. `cid not in
                # _na_curr` is the ABSENCE of a marker, and absence is not evidence: only
                # 15 of the 48 UNKNOWN findings on the maintainer's own machine carry
                # `not_applicable` at all, so "unmarked" means "nobody set the flag", not
                # "this check lost its footing". Asserting a regression on that would fire
                # whenever a surface goes away without its check having been migrated to
                # the flag. Stated as a coverage note instead — true either way, and it
                # still ends the silence this task exists to end.
                _went_dark.append((cid, was))

        # B-500: a check that could not determine its state last time and now reports a
        # problem. NOT framed as a regression — it may always have been true and merely
        # unseeable — but it is news, and it was silent before.
        #
        # This is the arm with the real false-alarm risk, and it is gated on the REASON,
        # never the status: a surface confirmed absent last run and present now is a user
        # configuring a feature for the first time. On the maintainer's own machine that is
        # a live case, not a hypothetical — four MCP checks and six browser checks all sit
        # at "not configured". Announcing those as findings the moment someone connects a
        # server is precisely the noise that teaches people to stop reading the monitor.
        elif (_reasons_known and _same_scope_flags and not (prev_blind or curr_blind)
              and status == WARN and pc.get(cid) == UNKNOWN and cid not in _na_prev):
            # A NOTE, never an alert. Reproduced: connecting a first MCP server made this
            # arm announce a finding for an entirely ordinary action, because `not
            # applicable` is set by only a subset of emitters — B331/B332/B333 report the
            # literal string "No MCP servers configured." WITHOUT it, while B15/B24/B166
            # report the SAME string WITH it. The split is per-emitter, not per-surface, so
            # the flag cannot carry the weight of an alert. Toggling --no-host produced
            # five more of these on an unchanged machine.
            _newly_visible.append(cid)


def _diff_vanished_checks(
        _check_sev,
        _check_title,
        _ignore_moved,
        _same_scope_flags,
        _vanished,
        alerts,
        cc,
        curr_blind,
        note,
        pc,
        prev_blind,
) -> None:
    """Checks that were in the baseline and are not in this run at all.

    Distinct from a status change: a check that disappears takes its verdict with it, and
    on a screen that counts failures that reads as an improvement.
    """
    if _vanished and _same_scope_flags and not _ignore_moved:
        _n_crashed = sum(1 for k in cc if str(k).startswith("ERR:"))
        _lost_verdicts = sorted(c for c in _vanished if pc.get(c) in ACTIONABLE_STATUSES)
        if _n_crashed and _lost_verdicts and not (prev_blind or curr_blind):
            # ONE run-level alert, not one per id. The crash marker is `ERR:<funcname>`,
            # which cannot be mapped back to the catalog id that produced it, so claiming
            # per-id that THIS check crashed is a guess — and a wrong one whenever an
            # upgrade removed other checks in the same release, which reproduced as three
            # false "Stopped reporting" lines from a single unrelated crash. What IS
            # evidenced: this run had crashes, and these ids carried unresolved verdicts
            # and returned nothing. Both facts, no invented link between them.
            _names = ", ".join(_check_title(c) for c in _lost_verdicts[:3])
            _sev = max((_check_sev(c) for c in _lost_verdicts),
                       key=lambda v: ("LOW", "MEDIUM", "HIGH", "CRITICAL").index(v)
                       if v in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else 0)
            alerts.append((
                _sev,
                f"{_n_crashed} check(s) crashed or timed out this run, and "
                f"{len(_lost_verdicts)} check(s) that previously reported a problem "
                f"produced no result at all (e.g. {_names}). Their verdicts are "
                f"unverified rather than resolved.",
            ))
        else:
            note(NOTE_UNDETERMINED,
                 f"{len(_vanished)} check(s) that ran last time did not run this time — "
                 f"most likely removed or renamed by an update.")
