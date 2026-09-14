"""C-520: a persistent, mutable Incident record with an open-to-closed lifecycle.

Local, opt-in, append-only JSONL, chmod 600 — same idiom as runstore.py (C-524) and
sbom_runs.py (C-521), reusing monitorstore.py's generic hash-chain primitives
(_chain_hash/_rotate_journal/_iter_jsonl/_last_chain_hash/_schema_ok) rather than
reinventing them.

Deliberately NOT a single mutable JSON document the way monitorstore.py's state.json
is: an incident's own lifecycle (open -> investigating -> mitigated -> closed) is
itself the kind of tamper-evident history this tool insists on for everything else it
tracks, so it gets the same treatment -- every "created" or "transition" is one
appended, hash-chained row, never an in-place edit. Current state is *derived* by
folding a given incident id's rows, the same relationship monitorstore.py's
baseline-witness events have to the state they corroborate.

This is a pure, mechanical store: it knows how to create/load/list/transition a
record, and validates the status vocabulary + the transition graph. It does NOT know
*how* to derive an incident's finding ids, PID, or monitor-journal watermark from a
live audit run -- that domain knowledge (which findings are "actionable", where a PID
ever shows up in evidence text) stays in incident.py, which already owns the
"assemble evidence from an audited Context" concern. See incident.py's
`open_incident_from_audit` for the caller that bridges the two.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
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

DEFAULT_INCIDENTS = "~/.clawseccheck/incidents.jsonl"

# Incidents are meant to be rare, significant events (unlike the frequent per-run
# snapshots runs.jsonl/sbom_runs.jsonl keep only the last 50 of) -- retention is sized
# like monitorstore.py's own events.jsonl, not like those two.
_INCIDENTS_MAX_LINES = 5000
_INCIDENTS_KEEP = 4000

STATUS_OPEN = "open"
STATUS_INVESTIGATING = "investigating"
STATUS_MITIGATED = "mitigated"
STATUS_CLOSED = "closed"

#: The closed set the DoD asks for -- not a free string. Order matters: it is also the
#: forward-progression sequence _is_valid_transition walks.
_STATUS_ORDER = (STATUS_OPEN, STATUS_INVESTIGATING, STATUS_MITIGATED, STATUS_CLOSED)
INCIDENT_STATUSES: frozenset = frozenset(_STATUS_ORDER)


def _is_valid_transition(old_status: str, new_status: str) -> bool:
    """Mirrors the "forward is disciplined, backward is free" rule this task's own
    description cites for Pulse's own task lifecycle: a forward move is only ever the
    single next step (open -> investigating -> mitigated -> closed, never a skip), a
    backward move to any earlier status is always allowed (an incident reopened,
    or a mitigation that turns out incomplete), and staying at the same status is
    rejected as a no-op rather than silently accepted."""
    if old_status not in INCIDENT_STATUSES or new_status not in INCIDENT_STATUSES:
        return False
    old_i = _STATUS_ORDER.index(old_status)
    new_i = _STATUS_ORDER.index(new_status)
    if new_i == old_i:
        return False
    if new_i < old_i:
        return True
    return new_i == old_i + 1


@dataclass
class Incident:
    """The folded, current-state view of one incident id's rows. Never constructed
    directly by a caller outside this module -- see create_incident/load_incident."""

    id: str
    status: str
    created_at: "str | None"
    finding_ids: tuple = ()
    pid: "str | None" = None
    process_name: "str | None" = None
    monitor_watermark: "str | None" = None
    #: Append-only transition log, starting with the initial "open" entry -- each item
    #: is {"status": ..., "ts": ...}.
    history: tuple = field(default_factory=tuple)


def _incident_to_dict(inc: Incident) -> dict:
    """The frozen public shape for --incident-open/--incident-mark/--incident-show
    --json -- snake_case, matching report._finding_to_dict's own convention rather
    than sbom_runs.py's CycloneDX/SPDX-influenced camelCase (that shape borrows an
    external standard's vocabulary; this one has none to borrow)."""
    return {
        "id": inc.id,
        "status": inc.status,
        "created_at": inc.created_at,
        "finding_ids": list(inc.finding_ids),
        "pid": inc.pid,
        "process_name": inc.process_name,
        "monitor_watermark": inc.monitor_watermark,
        "history": [dict(h) for h in inc.history],
    }


def _fold_incident_rows(rows: "list[dict]") -> "Incident | None":
    """Rebuild the current state of one incident id from its own rows, in file order.

    Returns None when no "created" row is present -- including the case where only
    "transition" rows survive a journal rotation (_INCIDENTS_KEEP is sized generously
    exactly to make this rare in practice, but the fold must still fail safe rather
    than fabricate a status/finding-id list it cannot ground). A transition row seen
    before any "created" row for the same id (same rotation scenario) is likewise
    ignored, not misread as the incident's origin.
    """
    created: "dict | None" = None
    history: "list[dict]" = []
    status = STATUS_OPEN
    for row in rows:
        event = row.get("event")
        if event == "created":
            created = row
            status = row.get("status", STATUS_OPEN)
            history = [{"status": status, "ts": row.get("ts")}]
        elif event == "transition" and created is not None:
            status = row.get("to_status", status)
            history.append({"status": status, "ts": row.get("ts")})
    if created is None:
        return None
    return Incident(
        id=created.get("id"),
        status=status,
        created_at=created.get("ts"),
        finding_ids=tuple(created.get("finding_ids") or ()),
        pid=created.get("pid"),
        process_name=created.get("process_name"),
        monitor_watermark=created.get("monitor_watermark"),
        history=tuple(history),
    )


def load_incident(incident_id: str, path: "str | Path" = DEFAULT_INCIDENTS) -> "Incident | None":
    p = Path(path).expanduser()
    if not p.is_file():
        return None
    try:
        rows = [e for e in _iter_jsonl(p) if _schema_ok(e) and e.get("id") == incident_id]
    except OSError:
        return None
    return _fold_incident_rows(rows)


def list_incident_ids(path: "str | Path" = DEFAULT_INCIDENTS) -> "list[str]":
    """Every id that has a live "created" row, in first-seen (creation) order. An id
    whose "created" row was rotated away is not listed -- same fail-safe rule
    load_incident applies."""
    p = Path(path).expanduser()
    if not p.is_file():
        return []
    seen: "dict[str, None]" = {}
    try:
        for e in _iter_jsonl(p):
            if _schema_ok(e) and e.get("event") == "created":
                iid = e.get("id")
                if iid:
                    seen.setdefault(iid, None)
    except OSError:
        return []
    return list(seen)


def _append_row(row: dict, path: "str | Path") -> bool:
    p = Path(path).expanduser()
    try:
        secure_dir(p.parent)
        with journal_lock(p):
            prev_hash = _last_chain_hash(p)
            chained = {**row, "chain_hash": _chain_hash(prev_hash, row)}
            secure_append_text(p, json.dumps(chained) + "\n")
            _rotate_journal(p, max_lines=_INCIDENTS_MAX_LINES, keep=_INCIDENTS_KEEP)
    except OSError:
        return False
    return True


def create_incident(
    finding_ids: "list[str]",
    *,
    pid: "str | None" = None,
    process_name: "str | None" = None,
    monitor_watermark: "str | None" = None,
    path: "str | Path" = DEFAULT_INCIDENTS,
    when: "str | None" = None,
) -> "Incident | None":
    """Persist a new incident (status=open). *finding_ids* is never validated against
    a live catalog here -- that grounding (only real, actionable finding ids get
    linked) is incident.py's job, before this is ever called.

    Incident id = its own creation timestamp -- no second identity invented, the same
    reasoning runstore.py/sbom_runs.py already give for reusing history.py's timestamp
    shape as their own run id. Two opens within the same wall-clock second collide and
    the second's "created" row wins on fold (last-write-wins) -- the same narrow,
    accepted exposure those two stores already carry for their own ids.

    Returns None (never raises) on a write failure -- same contract as
    runstore.save_run/sbom_runs.save_sbom_run.
    """
    ts = when if when is not None else datetime.now().isoformat(timespec="seconds")
    incident_id = ts
    row = {
        "ts": ts,
        "event": "created",
        "id": incident_id,
        "status": STATUS_OPEN,
        "finding_ids": list(finding_ids),
        "pid": pid,
        "process_name": process_name,
        "monitor_watermark": monitor_watermark,
        "_schema": SCHEMA_VERSION,
    }
    if not _append_row(row, path):
        return None
    return load_incident(incident_id, path=path)


def mark_incident(
    incident_id: str,
    new_status: str,
    *,
    path: "str | Path" = DEFAULT_INCIDENTS,
    when: "str | None" = None,
) -> "tuple[Incident | None, str | None]":
    """Transition *incident_id* to *new_status*. Returns (updated_incident, None) on
    success, or (None, reason) where reason is one of "invalid_status" (not one of
    INCIDENT_STATUSES), "not_found" (no live "created" row for that id), or
    "invalid_transition" (a real incident, a real status, but a move
    _is_valid_transition rejects -- a forward skip, a no-op, or garbage ordering).

    C-135: the read of *current* status and the append are one critical section, both
    under the SAME journal_lock acquisition -- not read-then-separately-locked-append.
    Two concurrent --incident-mark calls against the same id (e.g. both racing "open ->
    investigating") could otherwise both read "open" before either appended, and both
    pass validation, leaving two identical transition rows in the history instead of
    one succeeding and the second correctly re-validating against the first's result.
    """
    if new_status not in INCIDENT_STATUSES:
        return None, "invalid_status"
    p = Path(path).expanduser()
    ts = when if when is not None else datetime.now().isoformat(timespec="seconds")
    try:
        secure_dir(p.parent)
        with journal_lock(p):
            current = load_incident(incident_id, path=p)
            if current is None:
                return None, "not_found"
            if not _is_valid_transition(current.status, new_status):
                return None, "invalid_transition"
            row = {
                "ts": ts,
                "event": "transition",
                "id": incident_id,
                "from_status": current.status,
                "to_status": new_status,
                "_schema": SCHEMA_VERSION,
            }
            prev_hash = _last_chain_hash(p)
            chained = {**row, "chain_hash": _chain_hash(prev_hash, row)}
            secure_append_text(p, json.dumps(chained) + "\n")
            _rotate_journal(p, max_lines=_INCIDENTS_MAX_LINES, keep=_INCIDENTS_KEEP)
    except OSError:
        return None, "write_failed"
    return load_incident(incident_id, path=p), None


def render_incident_json(record: dict, *, version: str) -> str:
    """The standalone --incident-open/--incident-mark/--incident-show --json artifact.
    Routed through adjudication._emit_json (sanitize-on-emit over the whole tree), same
    as runstore.render_diff_json/sbom_runs.render_sbom_diff_json — the shared boundary
    every machine-readable artifact this tool emits goes through."""
    from .adjudication import _emit_json  # noqa: PLC0415

    payload = {"tool": "clawseccheck", "version": version, **record}
    return _emit_json(payload)
