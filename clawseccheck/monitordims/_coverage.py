"""The `not_compared` dimension - what the watch could not compare, watched for GROWTH.

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
time" - an alarm that always fires is one nobody reads.

## What carries information instead: the DELTA

The note set is stable. That is the measured property this dimension is built on: on an
unchanged machine the same comparisons are skipped for the same reasons, run after run, so
a comparison the watch made last time and cannot make now is a real event - the watch got
quieter, which is exactly the condition under which a real change passes unseen.

That is a drift signal, so it belongs where every other drift signal is: in `alerts`. The
exit-code contract does not move at all - a coverage regression simply becomes an alert,
and `--fail-on medium` picks it up like any other.

## Per-name comparisons are judged by name (C-718)

Six notes count names - tool servers, skills, contact channels - and their sentence carries
only the count. Keyed on the sentence with its digits removed, "skipped for server B" and
"now skipped for server A as well" were one entry, with two opposite results: a name that
was merely NEW on the last run raised "a comparison it made at the last check" one run
later (nothing had been compared for it), and a real loss for one name was never reported
once any other name stood in the record. So `diff_with_notes` can hand back the names
behind each of those notes (as digests), the record stores the names a comparison cannot
be made for in the snapshot's own state, and the arm compares names. A blind spot that
comes with a name the watch sees for the first time is said on that run, in its own
sentence (unless the same comparison is reported as lost on that run). Every other note,
and a record written before names were stored, is judged by key exactly as before.

## What is deliberately NOT reported

  * **A coverage IMPROVEMENT** - an entry that disappeared. The watch seeing more is not an
    event to page anyone about, and reporting it would double the noise for nothing.
  * **The first comparison after this key appears.** `not_compared` is written only on a
    run with a usable baseline, so a first run stores nothing rather than storing `[]`.
    An empty list would mean "last time the watch compared everything", which is false, and
    the next run would report all four standing limitations as newly lost - measured as
    exactly the 0 -> 4 step between run 1 and run 2 above.
  * **Anything at all on the run after an upgrade.** A build that adds a note kind changes
    the note set without anything on the machine moving. `watched` already records the
    manifest the writing build used, so a differing manifest explains the delta and the arm
    stands down with a note instead.
"""

from __future__ import annotations

import hashlib
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

#: C-718: a note that says the PREVIOUS run lacked something, not this one. "N check(s) began
#: reporting a problem they could not determine last time" fires exactly on the run where
#: a check moves from UNKNOWN to WARN or FAIL (connecting a first MCP server does it). It
#: still ALERTS - this arm is the only place that transition reaches the user, and a check
#: that starts reporting a problem is the last thing a watch may go quiet about - but under
#: its own sentence: "a comparison it made at the last check" was the opposite of what
#: happened, since last time the check could not report at all. Its sibling, "N check(s)
#: that previously reported a problem can no longer determine their state", is a real loss
#: and keeps the loss wording. Matched on the sentence because notes are bare (category,
#: text) pairs; the producer's wording is pinned by tests/test_c718_post_record_quiet.py.
_COVERAGE_GAIN_RE = re.compile(r"began reporting a problem they could not determine last time")

#: C-718: the two notes above describe something that HAPPENED between two runs, not a
#: comparison that stays impossible. They are never stored in the record: stored, the
#: number-normalised key made a second transition on the very next run (a different check
#: going dark, or starting to report) read as already known, and it raised nothing.
_COVERAGE_EVENT_RE = re.compile(
    r"began reporting a problem they could not determine last time"
    r"|previously reported a problem can no longer determine their state")


#: C-718: the stored list holds two kinds of string. Keys come first, as they always did.
#: After this marker comes one member entry per key, ``@member:<digest>,<digest>,...:<key>``:
#: for a comparison that is made per NAME (a tool server, a skill, a channel), which names
#: it cannot be made for. A key never starts with ``@`` (it starts with a note category),
#: so the two cannot be confused, and a version that predates this reads a member entry as
#: a key it never matches. The marker itself is what tells "this record knows its members,
#: and there are none" from "this record was written before members existed".
_COVERAGE_MEMBERS_MARK = "@members:v1"
_COVERAGE_MEMBER_PREFIX = "@member:"

#: A backstop, like _COVERAGE_MAX_ENTRIES, on the names stored across all keys. A key whose
#: names would cross it is stored with NO names (``@member::<key>``), which the reader takes
#: as "judge this key the old way, by key" - never as "no name is skipped for it".
_COVERAGE_MAX_MEMBERS = 2000


def _coverage_member_digest(name) -> str:
    """A short, stable stand-in for one member name. The name itself is never stored here
    or printed from here: it is user- or package-chosen text, and the record only ever
    needs to know whether it is the same name as last time."""
    raw = str(name).encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()[:16]


def _coverage_member_entries(members) -> list:
    """``{key: [digest, ...]}`` as the strings stored after the marker, one per key."""
    out: list = []
    stored = 0
    for key in sorted(members or {}):
        digests = sorted(set(members[key]))
        if stored + len(digests) > _COVERAGE_MAX_MEMBERS:
            digests = []            # over the cap: this key falls back to key judgement
        stored += len(digests)
        out.append(f"{_COVERAGE_MEMBER_PREFIX}{','.join(digests)}:{key}")
    return out


def _coverage_recorded_members(recorded) -> "dict | None":
    """``{key: {digest, ...} | None}`` from a stored list, or ``None`` when the list predates
    member entries (no marker). A key mapped to ``None`` was over the cap when written and
    is judged by key. A key that is ABSENT had no skipped name when the record was written."""
    if not isinstance(recorded, list) or _COVERAGE_MEMBERS_MARK not in recorded:
        return None
    out: dict = {}
    for entry in recorded:
        if not (isinstance(entry, str) and entry.startswith(_COVERAGE_MEMBER_PREFIX)):
            continue
        digests, sep, key = entry[len(_COVERAGE_MEMBER_PREFIX):].partition(":")
        if not (sep and key):
            continue
        out[key] = {d for d in digests.split(",") if d} or None
    return out


def _coverage_standing(signature) -> list:
    """The KEYS of a signature that are worth comparing against: not the event notes, and
    not the member entries or their marker."""
    return [key for key in signature or ()
            if isinstance(key, str) and not key.startswith("@")
            and not _COVERAGE_EVENT_RE.search(key)]


#: A bound on the stored list. Notes are 4-6 on the two real populations measured, so this
#: is a backstop against a pathological run rather than a budget - and it is DISCLOSED
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


def _diff_coverage(prev, curr, notes, alerts, note, members_now=None, ahead_notes=None,
                   members_ahead=None) -> None:
    """Alert when this run could not make a comparison the last run made.

    Called from `cli.py` rather than from `diff_with_notes`, and that is not an oversight:
    three of the note appends (`monitor_notes.append(...)` for the re-vet cap, the history
    write failure and the skill re-vet overflow) happen in the shell AFTER `diff_with_notes`
    returns. An arm inside `diff_with_notes` would compare against a note set that is not
    yet complete, and would report those three as newly lost on the following run.

    C-718. A note is judged in one of two ways:

    * BY KEY, as before: it is lost when its key is not in the record. Every note that is
      not counted per name is judged this way, and so is everything when the record was
      written before members existed or the caller passed no ``members_now``.
    * BY MEMBER, for the per-name comparisons (``members_now`` holds the names this run
      skipped the comparison for, from ``diff_with_notes(members_out=...)``): it is lost
      when a name is skipped now that the record does not list for that key. The key
      alone decided this before, and it carries only a count with its digits removed, so
      two opposite mistakes followed. A name that was NEW on the last run - nothing was
      skipped for it then - raised "a comparison it made at the last check" one run later,
      which was false. And once one name stood in the record, a real loss for another
      name was never reported.

    ``ahead_notes`` / ``members_ahead`` (``monitor._coverage_ahead``) are what an unchanged
    NEXT run will skip against ``curr``. A name in there that is neither skipped now nor in
    the record is a blind spot that opens with this run, and it is said now, in its own
    words, on the run that first sees it - unless the same comparison is reported as lost
    on that run, which is the one line that comparison gets.
    """
    if not isinstance(prev, dict) or not isinstance(curr, dict):
        return
    recorded = prev.get("not_compared")
    if not isinstance(recorded, list):
        # No prior record: a baseline predating this key, or one written by a run that had
        # no usable baseline of its own and therefore compared nothing. Silent by design -
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
    known_keys = set(_coverage_standing(recorded))
    recorded_members = _coverage_recorded_members(recorded)
    by_member = recorded_members is not None and isinstance(members_now, dict)

    def names_on_record(key):
        """The names the record lists for *key* (a set, empty when it lists none), or
        ``None`` when this key cannot be judged by member at all."""
        if not by_member:
            return None
        return recorded_members.get(key, set())

    gained, lost = [], []
    for key in now:
        on_record = names_on_record(key) if key in (members_now or {}) else None
        if _COVERAGE_GAIN_RE.search(key):
            gained.append(key)          # an event: never stored, so always fresh
        elif on_record is not None:
            if set(members_now[key]) - on_record:
                lost.append(key)
        elif key not in known_keys:
            lost.append(key)

    opening = []
    if by_member and isinstance(members_ahead, dict):
        ahead_live = _coverage_live_text(ahead_notes)
        for key in sorted(members_ahead):
            on_record = names_on_record(key)
            if on_record is None or key in lost:
                continue
            fresh_names = set(members_ahead[key]) - set(members_now.get(key, ())) - on_record
            if fresh_names:
                opening.append((ahead_live.get(key, "(reason not recorded)"), len(fresh_names)))

    for text, count in opening[:_COVERAGE_NAME_CAP]:
        # The sentence quoted carries the TOTAL for its comparison; `count` is how many of
        # those are first seen by this check. "First seen" rather than "added": a name can
        # also come into view because the inspection window moved (skills past the
        # collection cap after others were removed), with nothing added at all.
        alerts.append((
            "MEDIUM",
            f"A new blind spot opens with this check: {text} {count} of them "
            f"{'is' if count == 1 else 'are'} seen by this check for the first time \u2014 "
            "this is not a comparison that was lost \u2014 and from now on a change there "
            "could pass unseen."))
    if len(opening) > _COVERAGE_NAME_CAP:
        alerts.append((
            "MEDIUM",
            f"{len(opening) - _COVERAGE_NAME_CAP} further blind spot(s) open with this check. "
            "Re-run with --verbose to see what will not be compared."))
    if not (gained or lost):
        return

    for key in gained[:_COVERAGE_NAME_CAP]:
        alerts.append((
            "MEDIUM",
            f"{live.get(key, 'A check began reporting a problem it could not determine last time.')} "
            "The full report names the finding; treat it as you would a new one."))
    for key in lost[:_COVERAGE_NAME_CAP]:
        alerts.append((
            "MEDIUM",
            "This check could not make a comparison it made at the last check: "
            f"{live.get(key, '(reason not recorded)')} Nothing on your machine has "
            "necessarily changed \u2014 but the watch is looking at less than it was, so a "
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
