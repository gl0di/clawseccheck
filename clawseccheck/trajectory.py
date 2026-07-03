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
