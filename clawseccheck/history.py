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

from .monitor import _chain_hash, _last_chain_hash, verify_chain
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
    """
    if when is None:
        when = datetime.now().strftime("%Y-%m-%d")

    p = Path(path).expanduser()
    base = {"date": when, "score": int(score.score), "grade": str(score.grade)}
    # Symlink-safe: dir 0700 and an O_NOFOLLOW append, so a planted symlink at
    # history.jsonl can never redirect this default-path write to another file.
    # record() runs by default on every audit, so it degrades quietly (refuse =
    # skip) instead of crashing the audit when the target is a symlink/unwritable.
    try:
        secure_dir(p.parent)
        prev_hash = _last_chain_hash(p)
        row = {**base, "chain_hash": _chain_hash(prev_hash, base)}
        secure_append_text(p, json.dumps(row) + "\n")
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

    Blank lines and malformed JSON lines are skipped gracefully.
    Returns an empty list if the file does not exist.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        return []

    rows: list[dict] = []
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            # Validate expected keys exist
            rows.append({"date": obj["date"], "score": obj["score"], "grade": obj["grade"]})
        except (json.JSONDecodeError, KeyError):
            continue  # skip corrupt/incomplete lines

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

    # 🦞 mascot header line, once (design-system Foundations); --ascii drops it to
    # stay pure-ASCII, matching render_dashboard/render_card's convention.
    lines = [] if ascii_only else ["🦞 ClawSecCheck"]
    lines += ["ClawSecCheck - Score Trend", ""]
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
