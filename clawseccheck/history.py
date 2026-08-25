"""Local score history for --trend: append-only JSONL, chmod 600, stdlib only.

This module is the ONLY writer of history records. record() runs by default on
every audit — cli.py appends one score line unless --no-history is passed (--trend
and --monitor have their own record call-sites). The file stays local and
owner-only under ~/.clawseccheck/; nothing is ever uploaded. Opt out with
--no-history.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from . import brand
from .locking import journal_lock
from .monitor import (
    SCHEMA_VERSION, _chain_hash, _iter_jsonl, _last_chain_hash, _rotate_journal, _schema_ok,
    chain_provenance_note, verify_chain,
)
from .safeio import secure_append_text, secure_dir

DEFAULT_HISTORY = "~/.clawseccheck/history.jsonl"

# F-128: run-source tags. "audit" is a real invocation; "test"/"dev" (or any other
# value an env override supplies) mark development/CI noise. The tag makes such a row
# LEGIBLE — render_trend prints it inline as "[test]" — it does NOT hide the row. This
# comment used to say the tag existed "so --trend can filter it out by default"; that
# filter was deleted, and render_trend's own design note (below) explains at length why
# a hidden row silently rewrote the trend. Two readings of the same field, 270 lines
# apart, is how B-519 stayed invisible: a tag that reads like containment is not
# containment, and the suite went on appending thousands of rows to the real store.
# "legacy" is not assignable here — it is load()'s own label for a pre-F-128 entry that
# predates the source concept entirely (see load()).
_SOURCE_ENV = "CLAWSECCHECK_RUN_SOURCE"


def _run_source(source: str | None = None) -> str:
    """Resolve the run-source tag (F-128) for a new history entry.

    Priority, highest first:
      1. an explicit *source* argument (a caller that already knows better);
      2. the ``CLAWSECCHECK_RUN_SOURCE`` env override (CI/dev harnesses can
         tag their own runs, e.g. "dev");
      3. ``PYTEST_CURRENT_TEST`` — pytest sets this automatically for every
         test, so the suite's own audit runs self-tag as "test" with no
         per-call-site plumbing;
      4. otherwise "audit" — a real, non-test invocation.
    """
    if source:
        return source
    env_source = os.environ.get(_SOURCE_ENV)
    if env_source:
        return env_source
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return "test"
    return "audit"


def _sanitize_home(value: str | None) -> str | None:
    """Run an audited-home string through report._sanitize before it is stored.

    Strips terminal-control/bidi/zero-width characters and redacts any
    secret-shaped substring (same treatment every other untrusted string gets
    before it reaches a report or a journal) — a no-op for an ordinary path
    like ``~/.openclaw``. Local import: report.py sits in the same "Layer 3"
    cluster as history.py (CLAUDE.md §3), and this keeps the coupling
    load-bearing only where it is actually used.
    """
    if not value:
        return value
    from .report import _sanitize  # noqa: PLC0415
    return _sanitize(str(value))


def record(score, path: str = DEFAULT_HISTORY, when: str | None = None, *,
           home: str | None = None, source: str | None = None) -> "str | None":
    """Append one JSON line {date, ts, score, grade, home, source, chain_hash}
    to the history file.

    Returns None on success, the OSError text when the append FAILED (B-581, same
    shape as monitor.record_events under B-278). Still never RAISES — this is called
    on every default audit, so a planted symlink or an unwritable directory must not
    take the run down — but the failure is no longer invisible to a caller that asks.
    The default audit path (``_record_history_point``, cli.py) still discards the
    return value on purpose: it degrades quietly there, exactly as before. ``--trend``
    (cli.py) is the one caller that reports it, because ``--trend``'s whole job is to
    record this run's point — a dropped write there is the more serious of the two
    failures this task exists to surface (see the module the caller lives in).

    Parameters
    ----------
    score:
        A ScoreResult (or any object with .score: int and .grade: str).
    path:
        Path to the history JSONL file.  ``~`` is expanded.
    when:
        Either a bare ISO date (``YYYY-MM-DD``) or a full ISO datetime
        (``YYYY-MM-DDTHH:MM:SS``). Defaults to ``datetime.now()``. A bare date
        still sets 'date' for back-compat display/sorting; 'ts' is then that
        date at midnight. Mainly a testing knob — real callers leave it None
        and get the actual wall-clock time.
    home:
        The audited home path (e.g. ``~/.openclaw``), sanitized (see
        _sanitize_home) before being stored. None if the caller doesn't know
        it — the field is still written, as None, so every F-128-era entry has
        a consistent shape.
    source:
        Explicit run-source override. None lets _run_source() auto-detect it
        (see there) — "test" under pytest, "audit" otherwise, or the
        ``CLAWSECCHECK_RUN_SOURCE`` env value when set.

    F-128: 'ts' (full ISO datetime, seconds precision) and the 'home'/'source'
    tags let a trend tell a real audit apart from a development or test run.
    All three are additive and, like every other field, inside the hashed
    payload — chain_hash covers them the same as 'date'/'score'/'grade'. A
    pre-F-128 entry that lacks them still loads (history.load() fills the
    honest gap: ts=None, home=None, source="legacy") and still renders.

    F-094: each entry carries a 'chain_hash' — sha256(prev_chain_hash +
    canonical_json(entry)), the same tamper-evident scheme monitor.py's event
    journal already uses (see verify()/monitor.verify_chain). A planted or edited
    line breaks the chain from that point forward.

    C-162: each entry also carries '_schema' INSIDE the hashed payload, so a
    planted/edited _schema value is itself tamper-evident (see verify_chain).

    B-509: a run whose five-layer check was incomplete has no grade, and its row
    OMITS 'score'/'grade' and carries "graded": false instead. A graded row is
    unchanged, key order included. '_schema' is deliberately NOT bumped for this:
    the constant is shared with the events journal and the coverage ledger, so a
    bump would make an older build skip every new EVENT too. The cost of leaving
    it is that an older build silently drops ungraded rows from --trend rather
    than disclosing them — the same trade C-250's retention marker already made.

    B-108: the read-last-hash→append critical section runs under an advisory
    ``journal_lock`` so two concurrent audits can't both read the same prev
    chain_hash and each append, which would otherwise leave a spurious
    "chain BROKEN" that neither writer actually caused.

    C-164: after appending, the file is opportunistically rotated (pruned +
    re-chained) once it exceeds the retention cap, so history.jsonl never grows
    unbounded — see monitor._rotate_journal.
    """
    if when is None:
        now = datetime.now()
        date = now.strftime("%Y-%m-%d")
        ts = now.isoformat(timespec="seconds")
    else:
        date = when[:10]
        ts = when if "T" in when else f"{when}T00:00:00"

    p = Path(path).expanduser()
    # B-509: a run whose five-layer check was incomplete carries no grade, and this is
    # the last writer that used to republish one anyway — the report withheld the letter
    # while the journal recorded it, so --trend read the phantom back as a real point.
    #
    # The ungraded row OMITS 'score'/'grade' rather than writing them as null, because
    # that choice decides how an OLDER shipped build behaves when it meets one: an absent
    # key hits load()'s existing `except KeyError: continue`, the same already-in-production
    # path the C-250 retention marker takes, so the row is skipped. An explicit null passes
    # the key check, flows through as score=None, and the old render_trend's `curr > prev`
    # raises TypeError. Omission degrades; null crashes.
    #
    # A GRADED row's payload stays byte-identical to before this change — no 'graded' key
    # on the hot path. A row that has a score IS a graded row, exactly as it always was;
    # stamping "graded": true would churn every future row's shape for zero information.
    # 'graded' sits INSIDE the hashed payload, so it is tamper-evident like '_schema': it
    # cannot be flipped without breaking the chain.
    #
    # getattr, not score.graded: tests/test_c250_journal_honesty.py records through a
    # duck-typed score object that carries only .score/.grade, and so does any caller
    # predating ScoreResult.graded. Absent means graded, matching scoring.compute()'s own
    # "ledger=None means graded" default.
    graded = bool(getattr(score, "graded", True))
    # int()/str() are evaluated only on the graded branch: on an ungraded run score.score
    # is None, and int(None) raises a TypeError the `except OSError` below does NOT catch
    # — an uncaught crash on every default audit, not a quiet degrade.
    #
    # The key ORDER of a graded row is preserved exactly (date, score, grade, ts, …): the
    # chain hash is order-independent (_chain_hash canonicalizes with sort_keys=True), but
    # the line written to disk is json.dumps(row) without it, so reordering here would
    # change the on-disk bytes of every future graded row for no reason.
    graded_fields = (
        {"score": int(score.score), "grade": str(score.grade)} if graded
        else {}
    )
    base = {
        "date": date,
        **graded_fields,
        "ts": ts,
        "home": _sanitize_home(home),
        "source": _run_source(source),
        "_schema": SCHEMA_VERSION,
        **({} if graded else {"graded": False}),
    }
    # Symlink-safe: dir 0700 and an O_NOFOLLOW append, so a planted symlink at
    # history.jsonl can never redirect this default-path write to another file.
    # record() runs by default on every audit, so it degrades quietly (refuse =
    # skip) instead of crashing the audit when the target is a symlink/unwritable.
    try:
        secure_dir(p.parent)
        with journal_lock(p):
            prev_hash = _last_chain_hash(p)
            row = {**base, "chain_hash": _chain_hash(prev_hash, base)}
            secure_append_text(p, json.dumps(row) + "\n")
            _rotate_journal(p)
    except OSError as exc:
        return str(exc)
    return None


def verify(path: str = DEFAULT_HISTORY,
           cause: "list | None" = None) -> "tuple[bool | None, str]":
    """Verify the hash-chain integrity of the score history file.

    Delegates to monitor.verify_chain (same generic entry-agnostic algorithm), and so
    has the same THREE outcomes (B-589): (True, "OK…") for a chain that holds — including
    a legacy file whose rows carry no 'chain_hash', whose count is disclosed —
    (False, "broken at entry N") on the first tampered/reordered/deleted entry, and
    (None, …) when there is no chain here to verify at all: absent, empty, holding no
    parseable row, or unreadable.

    An absent history used to return (True, "OK"), so deleting the store passed the check
    that exists to catch deletion. See verify_chain's docstring for why the answer is a
    third value and not (False, …). Test ``is True``/``is False``/``is None``; a bare
    ``if ok:`` reports "no chain here" as tampering.

    ``cause`` is passed straight through — see verify_chain for the ``CHAIN_*`` codes.
    """
    return verify_chain(path, cause=cause)


def load(path: str = DEFAULT_HISTORY) -> list[dict]:
    """Read the JSONL history file and return a list of
    {date, score, grade, ts, home, source, graded} dicts.

    Silently returns [] on any read problem, same as always — a caller that needs to
    know WHY (B-581) wants ``load_with_problem`` instead, which this delegates to.

    Blank lines and malformed JSON lines are skipped gracefully. A line whose
    '_schema' (C-162) is a newer major than this build understands is skipped too
    (no crash, no misparse) — absent/legacy or current '_schema' loads normally.
    Returns an empty list if the file does not exist.

    Each surviving line is classified rather than KeyError-skipped outright:

      - no 'date' at all -> not a history row (e.g. the C-250 retention marker
        _rotate_journal prepends when it backs history.jsonl) -> skipped.
      - 'score' present without 'grade', or vice versa -> a partial/malformed
        row -> skipped.
      - both present, and 'graded' is absent or not explicitly False -> a
        normal GRADED row: 'score'/'grade' load as written.
      - 'graded' explicitly False -> an UNGRADED row (the five-layer check did
        not complete for that run): 'score'/'grade' load as None even if a
        (contradictory) score/grade value is present on disk — an explicit
        "graded": false wins and withholds rather than publishes.

    The returned 'graded' key is always a bool. 'score'/'grade' are always
    present on the row (None for an ungraded one) so `"score" in row` stays
    true for every returned row, same as before.

    F-128: 'ts'/'home'/'source' are additive fields a pre-F-128 entry never
    wrote. Rather than guess, a missing 'ts'/'home' loads as None and a
    missing 'source' loads as "legacy" — distinct from "audit" on purpose,
    since a legacy entry predates the real-vs-dev/test distinction entirely
    and must not silently masquerade as a verified real-audit run.
    """
    rows, _problem = load_with_problem(path)
    return rows


def load_with_problem(path: str = DEFAULT_HISTORY) -> "tuple[HistoryRows, OSError | None]":
    """Same rows as ``load()``, plus the ``OSError`` that made the read fail — if any.

    B-581: ``load()`` alone cannot tell a genuine first run (no history has ever been
    written at the caller's own default path) apart from a user-NAMED path that could
    not be opened; both produced an empty list and neither carried an exception object
    a caller could act on. This is ``cli._read_verdicts_payload``'s shape (B-561)
    applied to a loader that already exists, so the classification lives here once
    instead of being duplicated at each call site.

    Deliberately no ``Path.is_file()`` pre-check (the previous shape): on Python 3.12
    ``is_file()`` itself raises ``PermissionError`` for a stat-inaccessible path rather
    than returning False, so a pre-check made outside a try/except would crash on
    exactly the case this function exists to report instead of catching it. Attempting
    the read directly and letting ``_iter_jsonl``'s own ``p.open(...)`` raise means
    every OSError shape — missing, a directory, unreadable — is caught by the single
    ``except OSError`` below, the same as ``_read_verdicts_payload``.

    Whether a caller SHOWS the returned OSError is a decision cli.py makes from
    ``_explicit_paths`` — an absence at the default location is a genuine first run and
    must stay silent; this function reports what happened, not what it means.
    """
    p = Path(path).expanduser()
    rows = HistoryRows()
    try:
        # C-164: stream line-by-line via _iter_jsonl (not read_text().splitlines())
        # so memory stays flat even on a large history file. _iter_jsonl already
        # skips blank/corrupt/non-dict lines.
        for obj in _iter_jsonl(p):
            if not _schema_ok(obj):
                continue
            if "date" not in obj:
                # B-580: still not a row — but the retention marker is the file's own
                # record of what it no longer contains, and dropping it here is what let
                # `--trend` claim completeness over a pruned history. Carried on the list,
                # never in it.
                if "retention_pruned" in obj:
                    rows.retention_notice = str(obj.get("message") or "") or None
                    try:
                        rows.retention_pruned = int(obj.get("retention_pruned") or 0)
                    except (TypeError, ValueError):
                        rows.retention_pruned = 0
                continue                      # retention marker / non-history entry
            has_score = obj.get("score") is not None
            has_grade = obj.get("grade") is not None
            if has_score != has_grade:
                continue                      # partial/malformed row
            graded = has_score and obj.get("graded", True) is not False
            row = {
                "date": obj["date"],
                "score": obj["score"] if graded else None,
                "grade": obj["grade"] if graded else None,
                "graded": graded,
            }
            row["ts"] = obj.get("ts")
            row["home"] = obj.get("home")
            row["source"] = obj.get("source", "legacy")
            rows.append(row)
    except OSError as exc:
        return HistoryRows(), exc

    return rows, None


class HistoryRows(list):
    """The rows `load()` returns, carrying what the file said about what is NOT in them.

    B-580. `--trend` rendered every row it was given and said so — "Every row is shown,
    always, in the order recorded" — while the retention marker sitting on the file's first
    line, announcing that 1,001 older runs had been pruned, was dropped by `load()` before
    any renderer could see it. The oldest quarter of the history was gone and the trend, a
    claim about a shape over time, started silently mid-history.

    Why the notice rides as an ATTRIBUTE rather than as an element: `monitor._rotate_journal`
    shapes the marker deliberately without `date`/`score`/`grade` so that `load()`'s row
    guard skips it, and its own docstring gives the reason — "a marker meant for a human
    reading the events journal must not corrupt the trend". Making it a row would do exactly
    that, and would also be counted in "N of M runs". An attribute cannot be mistaken for a
    run by any consumer: `load()`'s other two callers read `rows[-1]["date"]` and pass the
    list on, and neither can see this.

    The events side solved the same problem by keeping the marker as `events[0]` and letting
    `render_events` lift it into the header. That works there because an events journal row
    and the marker are the same shape. Here they are not, on purpose.
    """

    #: The marker's own sentence, verbatim, or None when the file records no pruning.
    retention_notice: "str | None" = None

    #: Count of runs the marker says were evicted, or 0. This is the count for THAT
    #: rotation, not a cumulative total: rotation keeps `entries[-keep:]`, so a previous
    #: marker — being the oldest line — is itself evicted by the next one. Reported as the
    #: file records it rather than summed into a number no file ever stated.
    retention_pruned: int = 0


def render_trend(rows: list[dict], ascii_only: bool = False,
                 chain_status: "tuple[bool | None, str] | None" = None) -> str:
    """Return a compact human-readable trend string.

    Every row is shown, always, in the order recorded — each GRADED line
    carries a timestamp, GRADE, SCORE, an arrow (▲▼· or ^v=) relative to the
    *previous GRADED* row's score, and a ``[source]`` tag (plus the audited
    home path, when known). An UNGRADED row (the five-layer check did not
    complete for that run — see ``graded`` below) carries no GRADE, no SCORE,
    and no arrow; it renders its timestamp, the words "no grade", and its
    ``[source]``/home the same way a graded row does.

    Parameters
    ----------
    rows:
        List of {date, score, grade, ts, home, source, graded} dicts (as
        returned by load()), in chronological order. A plain
        {date, score, grade} dict (no ts/home/source/graded keys) works too —
        it renders with a "legacy" tag and is treated as graded. A row is
        UNGRADED only when it explicitly carries ``"graded": False`` (or, as
        load() always sets it now, has ``score is None``); its own
        ``score``/``grade`` values, if any, are never rendered.
    ascii_only:
        Use ASCII arrows (^, v, =) instead of unicode (▲, ▼, ·).
    chain_status:
        B-582: the caller's own ``(ok, msg)`` from ``monitor.verify_chain(path)``
        (or ``history.verify``, the same call), run over the SAME file these
        ``rows`` were just loaded from. ``None`` (the default) renders no
        provenance line at all — existing callers/tests that never pass this are
        unaffected. Negative-only via ``monitor.chain_provenance_note``: a broken
        chain appends one disclosure line (rows still render, never withheld, and
        it is never called tampering — see that function's own docstring); a
        verified chain appends nothing — silence means verified, the same as
        every other "nothing to disclose" convention in this renderer.

    Design note (this replaces a default-on filter): an earlier version of
    this function hid rows whose ``source`` wasn't "audit"/"legacy" and only
    said so when *every* row was hidden — in the ordinary mixed case a
    development/test/CI run vanished with no disclosure at all, and the
    arrows were silently recomputed over the remaining subset, rewriting the
    trend narrative (e.g. erasing two real "test"-tagged entries could flip
    an apparent regression into an apparent improvement). The filter was also
    trivially defeated: tagging a real audit's own run with
    ``CLAWSECCHECK_RUN_SOURCE`` made it disappear from its own trend. Rather
    than patch the disclosure message or add a CLI flag to reach the
    now-removed ``include_all`` kwarg, the filter is deleted: every row
    renders, unconditionally, with its source visible inline so a "test" or
    "dev" run is legible as exactly that instead of being dropped or
    disguised as a real "audit".

    C-426: an UNGRADED row (five-layer check incomplete — see ``ScoreResult.
    graded``) is rendered the same unconditional way, never hidden and never
    given a flat arrow — a flat arrow is a positive claim of "same score" and
    would misrepresent a run that has none. Its arrow is skipped entirely and
    the comparison for the *next* graded row skips over the hole (tracked via
    ``last_graded_score``, not ``rows[i - 1]``, which would otherwise compare
    against a ``None`` and crash). A one-line disclosure is appended whenever
    at least one hole exists, naming the count so an ungraded run is legible
    as "incomplete", not silently absent or silently averaged over.

    B-579: a row whose ``source`` is exactly ``"view"`` is produced by the act
    of running ``--trend`` itself (see ``history.record``'s call site in
    ``cli.py``), not by a check the user asked for. It renders unconditionally,
    same as every other row — tag included, "Tag, do not drop" — but it is
    excluded from both the numerator and denominator of the "N of M runs have
    no grade" ratio, and a SECOND line names the split whenever that exclusion
    would otherwise leave the ratio's total silently short of the row count on
    screen. Before this, a single bare ``--trend`` into a fresh store read
    "1 of 1 runs have no grade" — the tool grading the very row it had just
    created by being run, and every subsequent look made the ratio worse.
    """
    if not rows:
        return "No history yet. Run --trend again later to see your trend."

    if ascii_only:
        arrow_up, arrow_down, arrow_flat = "^", "v", "="
    else:
        arrow_up, arrow_down, arrow_flat = "▲", "▼", "·"

    # Mascot header line, once (design-system Foundations); --ascii drops it and
    # folds the separator (brand.header()). This used to be two separate lines
    # ("🦞 ClawSecCheck" then "ClawSecCheck - Score Trend"), repeating the
    # wordmark — collapsed to the one brand header line.
    lines = [brand.header(subtitle="Score Trend", ascii_only=ascii_only), ""]
    last_graded_score = None
    holes = 0
    # B-579: a "view" row is produced by the ACT of running --trend, not by a check the
    # user asked for (see history.record's B-579 call site). It still renders — every row
    # always does, unconditionally, tag visible — but it is excluded from BOTH sides of
    # the "N of M runs have no grade" ratio below, or the tool would grade its own look:
    # three bare --trend runs into one fresh store used to read "3 of 3 runs have no
    # grade", which is the trend viewer reporting on rows it created by being run.
    checkable = 0
    for row in rows:
        is_graded = row.get("graded", True) is not False and row.get("score") is not None
        is_view = row.get("source") == "view"
        label = row.get("ts") or row["date"]

        if not is_graded:
            if not is_view:
                holes += 1
            line = f"{label}  no grade  [{row.get('source', 'legacy')}]"
        else:
            if last_graded_score is None:
                arrow = arrow_flat
            elif row["score"] > last_graded_score:
                arrow = arrow_up
            elif row["score"] < last_graded_score:
                arrow = arrow_down
            else:
                arrow = arrow_flat
            last_graded_score = row["score"]
            line = f"{label}  {row['grade']}  {row['score']}  {arrow}  [{row.get('source', 'legacy')}]"

        if not is_view:
            checkable += 1
        home = row.get("home")
        if home:
            line += f"  {home}"
        lines.append(line)

    if holes:
        lines.append("")
        lines.append(
            f"{holes} of {checkable} runs have no grade: the five-layer check did not "
            "complete for them, so no letter or score was recorded. They are shown "
            "above in order; the arrows compare each graded run to the previous "
            "GRADED run."
        )
        # B-579: the ratio above deliberately does not cover every row on screen when a
        # "view" row is present (see the loop above) — say so explicitly, or a reader
        # counting the rows above gets a different total than the sentence just gave them
        # and cannot tell whether that is a filter or a miscount. Named, not silent.
        view_count = len(rows) - checkable
        if view_count:
            if view_count == 1:
                noun, verb_record, verb_be = "row", "records", "is"
            else:
                noun, verb_record, verb_be = "rows", "record", "are"
            lines.append(
                f"{checkable} of {len(rows)} rows shown above are counted in that ratio; "
                f"the other {view_count} {noun}, tagged [view], {verb_record} only the act "
                f"of looking at this trend and {verb_be} excluded from it."
            )

    # B-580: what this trend does NOT cover. Said after the rows, because it qualifies the
    # shape the reader has just looked at — the pruned runs are the OLDEST, i.e. the
    # baseline against which "improving" would be judged.
    notice = getattr(rows, "retention_notice", None)
    if notice:
        lines.append("")
        lines.append(
            "Not every recorded run is above: " + notice.strip()
            + " The trend therefore starts mid-history; the pruned runs are the oldest."
        )

    # B-582: the chain check this store has always had, run on the path a human
    # actually reads instead of only on a standalone --verify-history invocation
    # nobody runs unless they already suspect something.
    if chain_status is not None:
        note = chain_provenance_note(*chain_status)
        if note:
            lines.append("")
            lines.append(note)

    return "\n".join(lines)
