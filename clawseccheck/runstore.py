"""Local per-run finding snapshots for --diff (C-524): OPT-IN, append-only JSONL,
chmod 600, stdlib only.

Unlike history.py (records a score/grade line on every default audit) or
monitor.py's baseline (one CURRENT snapshot, overwritten each --monitor run), this
store keeps MULTIPLE addressable past runs and writes NOTHING unless a caller
explicitly asks: --save-run (cli.py). A full findings list is far heavier per row
than a score triple, so unlike history.jsonl this is never on by default — a user
who never passes --save-run pays nothing in disk growth.

Run id = the same 'ts' stamp history.record() already produces (an ISO datetime,
seconds precision) — no second identity invented. --save-run prints the id it
saved under; a user also finds valid ids in --trend's own timestamps.

Same local-store idiom as history.py/monitor.py: journal_lock + a sha256 hash
chain (_chain_hash/_last_chain_hash/_rotate_journal, shared with history.jsonl
and events.jsonl via monitorstore.py) and errors="replace" on read.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .locking import journal_lock
from .monitorstore import (
    SCHEMA_VERSION,
    _chain_hash,
    _iter_jsonl,
    _last_chain_hash,
    _rotate_journal,
    _schema_ok,
)
from .safeio import secure_append_text, secure_dir

DEFAULT_RUNS = "~/.clawseccheck/runs.jsonl"

# Opt-in and far heavier per row than history.jsonl (a full findings list, not a
# score triple) — kept much smaller so a store nobody ever prunes by hand still
# stays bounded. _rotate_journal prepends a disclosed RETENTION-MARKER row (same
# shape/behaviour as events.jsonl's) once this is exceeded, same as history.py.
_RUNS_MAX_LINES = 60
_RUNS_KEEP = 50


def save_run(findings, path: str = DEFAULT_RUNS, when: "str | None" = None, *,
             home: "str | None" = None, version: "str | None" = None) -> "str | None":
    """Append one run's full finding list, keyed by run id (its 'ts').

    Returns the run id on success, or None if the write failed — never raises,
    the same fail-open, best-effort local-store contract history.record() and
    monitor.record_events() already use (a planted symlink or an unwritable
    directory must not take a --save-run invocation down harder than that).

    *findings* is serialized through report._finding_to_dict — the same frozen
    public shape --json already emits per finding, sanitized the same way, so a
    stored run and a live --json run describe a finding identically.
    """
    from .report import _finding_to_dict, _sanitize  # noqa: PLC0415 (layer-3 sibling; same idiom history.py's _sanitize_home uses)

    ts = when if when is not None else datetime.now().isoformat(timespec="seconds")
    p = Path(path).expanduser()
    base = {
        "ts": ts,
        "home": _sanitize(home) if home else home,
        "version": str(version) if version else None,
        "_schema": SCHEMA_VERSION,
        "findings": [_finding_to_dict(f) for f in findings],
    }
    try:
        secure_dir(p.parent)
        with journal_lock(p):
            prev_hash = _last_chain_hash(p)
            row = {**base, "chain_hash": _chain_hash(prev_hash, base)}
            secure_append_text(p, json.dumps(row) + "\n")
            _rotate_journal(p, max_lines=_RUNS_MAX_LINES, keep=_RUNS_KEEP)
    except OSError:
        return None
    return ts


def load_run(run_id: str, path: str = DEFAULT_RUNS) -> "dict | None":
    """Return the stored run whose 'ts' == *run_id*, or None if absent/unreadable/
    not found.

    If *run_id* collides (two runs saved within the same second — the same
    granularity limit history.jsonl's own 'ts' already has), the LAST matching
    row wins: "the most recent write is authoritative", the same reading
    baseline.load_ignore() and history.load() already give a duplicate key.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        return None
    match = None
    try:
        for entry in _iter_jsonl(p):
            if _schema_ok(entry) and "findings" in entry and entry.get("ts") == run_id:
                match = entry
    except OSError:
        return None
    return match


def list_run_ids(path: str = DEFAULT_RUNS) -> "list[str]":
    """Every stored run id (its 'ts'), oldest first. Empty list when absent/unreadable
    or the file holds no real run row (only a retention marker, say)."""
    p = Path(path).expanduser()
    if not p.is_file():
        return []
    try:
        return [e["ts"] for e in _iter_jsonl(p)
                if _schema_ok(e) and "findings" in e and "ts" in e]
    except OSError:
        return []


def _fingerprint_of(finding: dict) -> str:
    """Same identity `.clawseccheckignore` entries already use (baseline.fingerprint:
    ``<id>:<sha1-8-of-detail>``), applied to a stored finding dict rather than a live
    ``Finding`` object -- so a PASS-worded detail change never reads as a fake
    regression, and a genuinely different detail string is what counts as "a different
    finding", exactly as it already does for a suppression entry."""
    from types import SimpleNamespace  # noqa: PLC0415 (used only here)

    from .baseline import fingerprint as _fingerprint  # noqa: PLC0415 (leaf sibling)
    return _fingerprint(SimpleNamespace(id=finding["id"], detail=finding["detail"]))


def diff_runs(run1: dict, run2: dict) -> dict:
    """Bucket the PROBLEM findings (status != PASS) of two stored runs (see
    ``save_run``/``load_run``) into 'new' and 'fixed', by fingerprint identity —
    see ``_fingerprint_of``.

    'new': a fingerprint present in run2's problem set, absent from run1's.
    'fixed': the reverse — present in run1's problem set, absent from run2's.

    A check whose SEVERITY/status changed (e.g. WARN -> FAIL, same check id) shows in
    BOTH lists, under its two different fingerprints — read together, that pair IS the
    regression; it is not double-counted anywhere else and nothing here collapses it
    into one "changed" bucket, because the task's own ask is exactly these two. This is
    the same accepted ambiguity ``baseline.dead_entries()`` already documents for a
    fingerprint that stops matching ("the issue was fixed, OR its wording changed") —
    read the two buckets by check id, not in isolation, when both show the same id.

    'unchanged_count' is every check id present in BOTH runs whose finding fingerprint
    (over every status, not only problem ones) is identical — including a clean PASS
    that stayed PASS. Deliberately a COUNT, not a list: on a real config the large
    majority of checks are exactly this, and listing them would bury the two lists
    that actually matter.

    'scope_note' is non-None when the two runs did not examine the same set of check
    ids at all (e.g. one used --no-host, or a ClawSecCheck upgrade added/removed
    checks between them) — when that holds, a 'fixed' entry among the missing ids may
    only mean the check did not run the second time, not that the issue was resolved.
    Never guessed away: the two lists above are computed exactly as defined regardless,
    and this note is the reader's warning to treat entries touching those ids with that
    caveat in mind.
    """
    f1 = {f["id"]: f for f in run1.get("findings", [])}
    f2 = {f["id"]: f for f in run2.get("findings", [])}

    problem1 = {_fingerprint_of(f): f for f in f1.values() if f["status"] != "PASS"}
    problem2 = {_fingerprint_of(f): f for f in f2.values() if f["status"] != "PASS"}

    def _sort_key(f):
        return (f["id"], f["detail"])

    new = sorted((f for fp, f in problem2.items() if fp not in problem1), key=_sort_key)
    fixed = sorted((f for fp, f in problem1.items() if fp not in problem2), key=_sort_key)

    all_fp1 = {id_: _fingerprint_of(f) for id_, f in f1.items()}
    all_fp2 = {id_: _fingerprint_of(f) for id_, f in f2.items()}
    unchanged_count = sum(
        1 for id_, fp in all_fp1.items() if id_ in all_fp2 and all_fp2[id_] == fp
    )

    scope_note = None
    if set(f1) != set(f2):
        only1 = sorted(set(f1) - set(f2))
        only2 = sorted(set(f2) - set(f1))
        parts = []
        if only1:
            _shown = ", ".join(only1[:5]) + ("…" if len(only1) > 5 else "")
            parts.append(f"{len(only1)} check id(s) only in run1 ({_shown})")
        if only2:
            _shown = ", ".join(only2[:5]) + ("…" if len(only2) > 5 else "")
            parts.append(f"{len(only2)} check id(s) only in run2 ({_shown})")
        scope_note = (
            "the two runs did not audit the same check set — " + "; ".join(parts) +
            " — a 'fixed' entry touching one of those ids may mean the check simply "
            "did not run the other time, not that the issue was resolved"
        )

    return {
        "run1_ts": run1.get("ts"), "run2_ts": run2.get("ts"),
        "new": new, "fixed": fixed,
        "unchanged_count": unchanged_count,
        "scope_note": scope_note,
    }


def render_diff_json(diff: dict, *, version: str) -> str:
    """The standalone ``--diff --json`` artifact, as a string.

    Routed through ``adjudication._emit_json`` (sanitize-on-emit over the WHOLE tree)
    rather than a bare ``json.dumps`` — B-693's rule applies here too: "the producer
    already sanitized it" (``save_run`` does, via ``report._finding_to_dict``) is not a
    property this boundary may assume, it enforces it, the same as every other
    machine-readable artifact this tool emits.
    """
    from .adjudication import _emit_json  # noqa: PLC0415 (layer-3 sibling; same idiom history.py's _sanitize_home uses)

    payload = {
        "tool": "clawseccheck",
        "version": version,
        "run1": diff["run1_ts"],
        "run2": diff["run2_ts"],
        "new": diff["new"],
        "fixed": diff["fixed"],
        "unchangedCount": diff["unchanged_count"],
        "scopeNote": diff["scope_note"],
    }
    return _emit_json(payload)
