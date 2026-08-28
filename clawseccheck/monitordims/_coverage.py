"""The `not_compared` dimension — what the watch could not compare, watched for GROWTH.

B-676. `--monitor`'s incompleteness disclosure never reached the one consumer the feature
exists for. Three decisions, each right on its own:

  * `cli.py` computes `fully_compared` and a list of `notes` naming every comparison the
    run declined to make;
  * the exit code is DELIBERATELY a pure function of `alerts`/`persisted`, because moving
    it would change what `0` already promises the published cron recipe;
  * that recipe (`docs/USAGE.md`) branches on `$?` alone.

So a run that hit a cap, carried a blind config forward, or skipped a sub-key comparison
exits 0 and is indistinguishable, to a cron job, from a complete clean run.

## Why the two fixes the task proposed are both dead, measured

Both rested on `fully_compared` carrying information. It does not. Measured on this tree,
five consecutive runs over an UNCHANGED `fixtures/home_safe`, and five more over the real
machine's own home:

    run 1  notes=0  fully_compared=False      (first run: nothing was compared at all)
    run 2  notes=4  fully_compared=False
    run 3  notes=4  fully_compared=False      <- byte-identical note set
    run 4  notes=4  fully_compared=False
    run 5  notes=4  fully_compared=False
    real   notes=6  fully_compared=False      <- also byte-identical across runs 3-5

`fully_compared` is False on EVERY run of a healthy machine, and not only because a bare
monitor run earns no grade. Three of those four standing notes are permanent structural
conditions this tool cannot remove: the per-user crontab spool is mode 1730 and needs a
subprocess (`hostpersist.py`), five of seven host-monitor classes resolve `unknown`
(`_host.py`), and the behavioural window rotates. So "tell the agent when the run was not
fully compared" and "exit non-zero when it was not" both reduce to "do this every single
time" — an alarm that always fires is one nobody reads.

## What carries information instead: the DELTA

The note set is stable. That is the measured property this dimension is built on: on an
unchanged machine the same comparisons are skipped for the same reasons, run after run, so
a comparison the watch made last time and cannot make now is a real event — the watch got
quieter, which is exactly the condition under which a real change passes unseen.

That is a drift signal, so it belongs where every other drift signal is: in `alerts`. The
exit-code contract does not move at all — a coverage regression simply becomes an alert,
and `--fail-on medium` picks it up like any other.

## What is deliberately NOT reported

  * **A coverage IMPROVEMENT** — an entry that disappeared. The watch seeing more is not an
    event to page anyone about, and reporting it would double the noise for nothing.
  * **The first comparison after this key appears.** `not_compared` is written only on a
    run with a usable baseline, so a first run stores nothing rather than storing `[]`.
    An empty list would mean "last time the watch compared everything", which is false, and
    the next run would report all four standing limitations as newly lost — measured as
    exactly the 0 -> 4 step between run 1 and run 2 above.
  * **Anything at all on the run after an upgrade.** A build that adds a note kind changes
    the note set without anything on the machine moving. `watched` already records the
    manifest the writing build used, so a differing manifest explains the delta and the arm
    stands down with a note instead.
"""

from __future__ import annotations

import re

from ._shared import (  # noqa: F401
    NOTE_CONFIG_BLIND,
    NOTE_NO_PRIOR_RECORD,
    NOTE_UNDETERMINED,
)

#: Categories a louder alert already accounts for, excluded from the signature entirely.
#:
#: `NOTE_CONFIG_BLIND` is the whole list, and it is here because of a measured duplication,
#: not on principle: an unreadable `openclaw.json` already raises its own HIGH naming
#: exactly what was not evaluated ("MCP, channel and gateway drift were NOT evaluated and
#: 159 check(s) report UNKNOWN"), and the four config_blind notes are that same sentence
#: broken up. Without this exclusion the blind run reported the identical fact five times.
#: The same discipline `_note_unmodelled_config_edit` applies with its `_named_config_drift`
#: term: a run that has already told the user something about a cause does not get to say
#: it again through a second channel.
#:
#: Excluding it from the SIGNATURE (not merely from the alert) is what keeps the arm
#: symmetric: a blind run then stores the same entries a sighted one does, so the config
#: becoming readable again is not reported as coverage returning.
_COVERAGE_ALREADY_ANNOUNCED = frozenset({NOTE_CONFIG_BLIND})

#: Counts inside a sentence are not a coverage change. "5 security tool(s) could not be
#: confirmed" becoming 6 is the same comparison being skipped for the same reason, and
#: alerting on it would make the arm fire every time a machine gained a tool.
_COVERAGE_DIGITS_RE = re.compile(r"\d+")

#: A bound on the stored list. Notes are 4-6 on the two real populations measured, so this
#: is a backstop against a pathological run rather than a budget — and it is DISCLOSED
#: when it bites, because a silently truncated record would make the entries past the cap
#: read as "newly lost" on the next run.
_COVERAGE_MAX_ENTRIES = 60

#: How many regressions to name before falling back to a count. A burst of twenty alerts
#: about the watch getting quieter would bury the drift alerts they sit beside.
_COVERAGE_NAME_CAP = 3


def _coverage_key(category: str, sentence: str) -> str:
    """The stable identity of one skipped comparison: its category and its shape."""
    return f"{category}|{_COVERAGE_DIGITS_RE.sub('#', sentence or '')}"


def _coverage_signature(notes) -> list:
    """The sorted, number-normalized, capped record of what this run could not compare."""
    keys = set()
    for entry in notes or ():
        try:
            category, sentence = entry
        except (TypeError, ValueError):
            continue
        if category in _COVERAGE_ALREADY_ANNOUNCED:
            continue
        keys.add(_coverage_key(str(category), str(sentence)))
    return sorted(keys)[:_COVERAGE_MAX_ENTRIES]


def _coverage_live_text(notes) -> dict:
    """normalized key -> the live sentence, so an alert quotes real text, not the shape."""
    out = {}
    for entry in notes or ():
        try:
            category, sentence = entry
        except (TypeError, ValueError):
            continue
        if category in _COVERAGE_ALREADY_ANNOUNCED:
            continue
        out.setdefault(_coverage_key(str(category), str(sentence)), str(sentence))
    return out


def _diff_coverage(prev, curr, notes, alerts, note) -> None:
    """Alert when this run could not make a comparison the last run made.

    Called from `cli.py` rather than from `diff_with_notes`, and that is not an oversight:
    three of the note appends (`monitor_notes.append(...)` for the re-vet cap, the history
    write failure and the skill re-vet overflow) happen in the shell AFTER `diff_with_notes`
    returns. An arm inside `diff_with_notes` would compare against a note set that is not
    yet complete, and would report those three as newly lost on the following run.
    """
    if not isinstance(prev, dict) or not isinstance(curr, dict):
        return
    recorded = prev.get("not_compared")
    if not isinstance(recorded, list):
        # No prior record: a baseline predating this key, or one written by a run that had
        # no usable baseline of its own and therefore compared nothing. Silent by design —
        # see the module docstring's second exclusion.
        return
    if prev.get("watched") != curr.get("watched"):
        note(NOTE_NO_PRIOR_RECORD,
             "What this check is able to compare changed because ClawSecCheck itself was "
             "updated since the last run, so this run cannot tell you whether it is now "
             "looking at less than before. The next run can.")
        return

    live = _coverage_live_text(notes)
    now = _coverage_signature(notes)
    lost = [key for key in now if key not in set(recorded)]
    if not lost:
        return

    for key in lost[:_COVERAGE_NAME_CAP]:
        alerts.append((
            "MEDIUM",
            "This check could not make a comparison it made at the last check: "
            f"{live.get(key, '(reason not recorded)')} Nothing on your machine has "
            "necessarily changed — but the watch is looking at less than it was, so a "
            "real change could now pass unseen."))
    if len(lost) > _COVERAGE_NAME_CAP:
        alerts.append((
            "MEDIUM",
            f"{len(lost) - _COVERAGE_NAME_CAP} further comparison(s) this check made at "
            "the last check could not be made this time. Re-run with --verbose to see "
            "what was skipped."))
    if len(now) >= _COVERAGE_MAX_ENTRIES:
        note(NOTE_UNDETERMINED,
             "This run skipped more comparisons than it records, so the list it will "
             "compare against next time is incomplete.")
