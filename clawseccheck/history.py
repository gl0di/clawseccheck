"""Local score history for --trend: append-only JSONL, chmod 600, stdlib only.

This module is the ONLY writer of history records. record() runs by default on
every audit — cli.py appends one score line unless --no-history is passed (--trend
and --monitor have their own record call-sites). The file stays local and
owner-only under ~/.clawseccheck/; nothing is ever uploaded. Opt out with
--no-history.
"""
from __future__ import annotations

import json
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


def record(score, path: str = DEFAULT_HISTORY, when: str | None = None) -> None:
    """Append one JSON line {date, score, grade, chain_hash} to the history file.

    Parameters
    ----------
    score:
        A ScoreResult (or any object with .score: int and .grade: str).
    path:
        Path to the history JSONL file.  ``~`` is expanded.
    when:
        ISO date string (``YYYY-MM-DD``).  Defaults to today's date.

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
        when = datetime.now().strftime("%Y-%m-%d")

    p = Path(path).expanduser()
    base = {"date": when, "score": int(score.score), "grade": str(score.grade),
            "_schema": SCHEMA_VERSION}
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
    """Read the JSONL history file and return a list of {date, score, grade} dicts.

    Blank lines and malformed JSON lines are skipped gracefully. A line whose
    '_schema' (C-162) is a newer major than this build understands is skipped too
    (no crash, no misparse) — absent/legacy or current '_schema' loads normally.
    Returns an empty list if the file does not exist.
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
                rows.append({"date": obj["date"], "score": obj["score"], "grade": obj["grade"]})
            except KeyError:
                continue  # skip incomplete lines
    except OSError:
        return []

    return rows


def render_trend(rows: list[dict], ascii_only: bool = False) -> str:
    """Return a compact human-readable trend string.

    Each row shows DATE  GRADE  SCORE plus an arrow (▲▼· or ^v=) relative to
    the previous row's score.  If rows is empty a friendly message is returned.

    Parameters
    ----------
    rows:
        List of {date, score, grade} dicts, in chronological order.
    ascii_only:
        Use ASCII arrows (^, v, =) instead of unicode (▲, ▼, ·).
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

        lines.append(f"{row['date']}  {row['grade']}  {row['score']}  {arrow}")

    return "\n".join(lines)
