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
    verify_chain,
)
from .safeio import secure_append_text, secure_dir

DEFAULT_HISTORY = "~/.clawseccheck/history.jsonl"

# F-128: run-source tags. "audit" is a real invocation; "test"/"dev" (or any other
# value an env override supplies) mark development/CI noise so --trend can filter
# it out by default. "legacy" is not assignable here — it is load()'s own label
# for a pre-F-128 entry that predates the source concept entirely (see load()).
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
           home: str | None = None, source: str | None = None) -> None:
    """Append one JSON line {date, ts, score, grade, home, source, chain_hash}
    to the history file.

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
    base = {
        "date": date,
        "score": int(score.score),
        "grade": str(score.grade),
        "ts": ts,
        "home": _sanitize_home(home),
        "source": _run_source(source),
        "_schema": SCHEMA_VERSION,
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
    except OSError:
        pass


def verify(path: str = DEFAULT_HISTORY) -> "tuple[bool, str]":
    """Verify the hash-chain integrity of the score history file.

    Delegates to monitor.verify_chain (same generic entry-agnostic algorithm).
    Returns (True, "OK") for an absent/empty/legacy-no-chain-hash file, or
    (False, "broken at entry N") on the first tampered/reordered/deleted entry.
    """
    return verify_chain(path)


def load(path: str = DEFAULT_HISTORY) -> list[dict]:
    """Read the JSONL history file and return a list of
    {date, score, grade, ts, home, source} dicts.

    Blank lines and malformed JSON lines are skipped gracefully. A line whose
    '_schema' (C-162) is a newer major than this build understands is skipped too
    (no crash, no misparse) — absent/legacy or current '_schema' loads normally.
    Returns an empty list if the file does not exist.

    F-128: 'ts'/'home'/'source' are additive fields a pre-F-128 entry never
    wrote. Rather than guess, a missing 'ts'/'home' loads as None and a
    missing 'source' loads as "legacy" — distinct from "audit" on purpose,
    since a legacy entry predates the real-vs-dev/test distinction entirely
    and must not silently masquerade as a verified real-audit run.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        return []

    rows: list[dict] = []
    try:
        # C-164: stream line-by-line via _iter_jsonl (not read_text().splitlines())
        # so memory stays flat even on a large history file. _iter_jsonl already
        # skips blank/corrupt/non-dict lines.
        for obj in _iter_jsonl(p):
            if not _schema_ok(obj):
                continue
            try:
                # Validate expected keys exist
                row = {"date": obj["date"], "score": obj["score"], "grade": obj["grade"]}
            except KeyError:
                continue  # skip incomplete lines
            row["ts"] = obj.get("ts")
            row["home"] = obj.get("home")
            row["source"] = obj.get("source", "legacy")
            rows.append(row)
    except OSError:
        return []

    return rows


def render_trend(rows: list[dict], ascii_only: bool = False) -> str:
    """Return a compact human-readable trend string.

    Every row is shown, always, in the order recorded — each line carries a
    timestamp, GRADE, SCORE, an arrow (▲▼· or ^v=) relative to the *previous*
    row's score, and a ``[source]`` tag (plus the audited home path, when
    known).

    Parameters
    ----------
    rows:
        List of {date, score, grade, ts, home, source} dicts (as returned by
        load()), in chronological order. A plain {date, score, grade} dict
        (no ts/home/source keys) works too — it renders with a "legacy" tag.
    ascii_only:
        Use ASCII arrows (^, v, =) instead of unicode (▲, ▼, ·).

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
    for i, row in enumerate(rows):
        if i == 0:
            arrow = arrow_flat
        else:
            prev_score = rows[i - 1]["score"]
            curr_score = row["score"]
            if curr_score > prev_score:
                arrow = arrow_up
            elif curr_score < prev_score:
                arrow = arrow_down
            else:
                arrow = arrow_flat

        label = row.get("ts") or row["date"]
        line = f"{label}  {row['grade']}  {row['score']}  {arrow}  [{row.get('source', 'legacy')}]"
        home = row.get("home")
        if home:
            line += f"  {home}"
        lines.append(line)

    return "\n".join(lines)
