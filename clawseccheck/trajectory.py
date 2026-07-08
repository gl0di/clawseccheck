"""Read-only scan of OpenClaw trajectory sidecars for log-observed tool use.

OpenClaw writes a per-session trajectory sidecar next to each session file:
``<home>/agents/<agent>/sessions/<session>.trajectory.jsonl`` (on by default; see
``docs/tools/trajectory.md``). Each line is a JSON envelope with a ``type``
discriminator; ``type == "tool.call"`` records carry the tool VERB in ``data.name``.
Grounded against a live install — see ``docs/research/openclaw-schema-recon.md`` §9.1.

This module extracts the SET of tool verbs the agent actually invoked (``data.name``)
so a check can report *proven* — log-observed, not self-reported — tool use. It is the
log-observed upgrade to the attestation self-report path.

Security (§8): this reads the user's own logs, which may contain secrets. It reads ONLY
``data.name`` (the tool identity, not a secret) and the version marker — it NEVER reads
``data.arguments``, ``data.output``, ``data.result`` or ``data.contentItems`` (the
sensitive call/return payloads). Stdlib-only, read-only, no network.
"""
from __future__ import annotations

import json
from pathlib import Path

# Version gate: only parse the format we have grounded. Any other value -> we don't guess.
_TRACE_SCHEMA = "openclaw-trajectory"
_SCHEMA_VERSION = 1

# Bounds so a large/padded fleet of session logs can't blow up the scan (DoS guard).
_MAX_FILES = 60
_MAX_BYTES_PER_FILE = 8_000_000


def find_trajectory_files(home: Path, *, max_files: int = _MAX_FILES) -> list[Path]:
    """Return trajectory sidecar paths under *home* (newest-first, capped at *max_files*).

    Read-only glob of the grounded sidecar layout
    ``agents/*/sessions/*.trajectory.jsonl`` (recon §9.1). Returns ``[]`` on any error, or
    when *home* is not a ``Path``, so callers can treat "no on-disk record" uniformly. Only
    paths are returned — no file contents are read here (§8).
    """
    if not isinstance(home, Path):
        return []
    try:
        files = list(home.glob("agents/*/sessions/*.trajectory.jsonl"))
    except OSError:
        return []
    try:
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        pass
    return files[:max_files]


def read_proven_tools(
    home: Path,
    *,
    max_files: int = _MAX_FILES,
    max_bytes_per_file: int = _MAX_BYTES_PER_FILE,
) -> tuple[set[str], dict]:
    """Return ``(verbs, meta)`` for tool verbs observed in trajectory sidecars under *home*.

    ``verbs`` is the set of raw ``data.name`` values from ``tool.call`` records in files
    whose ``traceSchema``/``schemaVersion`` match the grounded format. ``meta`` reports
    ``present`` (any trajectory file found), ``files_scanned``, and ``unknown_version``
    (a trajectory line carried an unrecognised schema version — caller should treat the
    proven set as incomplete / UNKNOWN rather than authoritative).

    Only ``data.name`` is read; call/return payloads are never touched.
    """
    verbs: set[str] = set()
    meta = {"present": False, "files_scanned": 0, "unknown_version": False}
    files = find_trajectory_files(home, max_files=max_files)
    if not files:
        return verbs, meta
    meta["present"] = True

    for path in files:
        try:
            read = 0
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    read += len(line)
                    if read > max_bytes_per_file:
                        break
                    # Cheap pre-filter: skip the big model/context lines without JSON-parsing
                    # them; tool.call lines are small and carry the marker text.
                    if '"tool.call"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    if rec.get("traceSchema") != _TRACE_SCHEMA:
                        continue
                    if rec.get("schemaVersion") != _SCHEMA_VERSION:
                        meta["unknown_version"] = True
                        continue
                    if rec.get("type") != "tool.call":
                        continue
                    data = rec.get("data")
                    name = data.get("name") if isinstance(data, dict) else None
                    if isinstance(name, str) and name.strip():
                        verbs.add(name.strip())
        except OSError:
            continue
        meta["files_scanned"] += 1

    return verbs, meta


# Event types read_events() understands. Every other `type` value is skipped —
# never guessed at (§4: no fabricated facts about an ungrounded event shape).
_EVENT_TYPES = ("tool.call", "tool.result", "prompt.submitted")


def _event_outcome(rec_type: str, data: dict) -> str | None:
    """Classify a tool.result's outcome from status/isError/success (§9.1 grounded).

    Returns "success", "failed", or None (ambiguous/not a tool.result — never guessed).
    Never reads output/result/contentItems — those are the sensitive payload (§8).
    """
    if rec_type != "tool.result":
        return None
    status = data.get("status")
    is_error = data.get("isError")
    success = data.get("success")
    if status == "failed" or is_error is True or success is False:
        return "failed"
    if status == "completed" or success is True:
        return "success"
    return None


def read_events(
    home: Path,
    *,
    max_files: int = _MAX_FILES,
    max_bytes_per_file: int = _MAX_BYTES_PER_FILE,
    explicit_path: str | None = None,
) -> tuple[list[dict], dict]:
    """Return (events, meta) — §8-safe event metadata for the behavioral engine.

    Each event is ``{type, name, ts, seq, sessionId, turnId, threadId, outcome}`` for
    ``tool.call``/``tool.result``/``prompt.submitted`` records (§9.1 grounded envelope).
    ``name`` and ``outcome`` are ``None`` where the event type doesn't carry them
    (e.g. ``prompt.submitted`` has no tool name; only ``tool.result`` has an outcome).
    ``sessionId`` (top-level, not sensitive — a session identifier) lets a caller scope
    grouping to one session, since ``seq`` is a per-session counter (§9.1), not globally
    unique across trajectory files (C-170 adversarial finding).

    NEVER reads ``data.arguments``/``data.output``/``data.result``/``data.contentItems``
    — the sensitive call/return payloads (§8). Only tool/event identity and sequencing
    metadata. Same version gate and DoS bounds as ``read_proven_tools``.

    ``explicit_path`` scans a single given ``.trajectory.jsonl`` file instead of
    globbing *home* (mirrors ``trajaudit.analyze``'s CLI PATH argument).
    """
    events: list[dict] = []
    meta = {"present": False, "files_scanned": 0, "unknown_version": False}

    if explicit_path:
        p = Path(explicit_path).expanduser()
        files = [p] if p.is_file() else []
    else:
        files = find_trajectory_files(home, max_files=max_files)
    if not files:
        return events, meta
    meta["present"] = True

    for path in files:
        try:
            read = 0
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    read += len(line)
                    if read > max_bytes_per_file:
                        break
                    # Cheap pre-filter: skip lines that can't be one of our event
                    # types without JSON-parsing every line (most lines are other
                    # event types we don't read, e.g. model.completed).
                    if not any(f'"{t}"' in line for t in _EVENT_TYPES):
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    if rec.get("traceSchema") != _TRACE_SCHEMA:
                        continue
                    if rec.get("schemaVersion") != _SCHEMA_VERSION:
                        meta["unknown_version"] = True
                        continue
                    rec_type = rec.get("type")
                    if rec_type not in _EVENT_TYPES:
                        continue
                    data = rec.get("data")
                    if not isinstance(data, dict):
                        data = {}
                    name = data.get("name")
                    events.append({
                        "type": rec_type,
                        "name": name.strip() if isinstance(name, str) and name.strip() else None,
                        "ts": rec.get("ts"),
                        "seq": rec.get("seq"),
                        "sessionId": rec.get("sessionId"),
                        "turnId": data.get("turnId"),
                        "threadId": data.get("threadId"),
                        "outcome": _event_outcome(rec_type, data),
                    })
        except OSError:
            continue
        meta["files_scanned"] += 1

    return events, meta
