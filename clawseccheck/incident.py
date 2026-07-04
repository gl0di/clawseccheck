"""`--incident`: a local, read-only evidence-pack builder (standard §20.2 IR playbook).

B85 already checks that a tamper-resistant tool-use trail EXISTS; this module actually
ASSEMBLES a preservation bundle from what an audit pass already collected — a
"preservation aid for step 3/6 of the incident-response playbook", never automated
remediation. It gathers pointers and hashes; it never rotates, deletes, or mutates
anything, and it never touches the network.

Every piece is reused from an existing, already-shipped producer rather than
reinvented: the findings snapshot is the same `_finding_to_dict` shape every other
JSON export uses; the skill/MCP inventory is `sbom.build_sbom()` (F-085) verbatim;
the credential rotation list is B41's own (already PII-safe) evidence list; the
trajectory-sidecar hashes reuse `trajectory.find_trajectory_files()` (B85's own
file-discovery, still never reading `data.arguments`/output — only whole-file
bytes for hashing, which never exposes call contents); monitor event history is
`monitor.load_events()` verbatim.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from . import trajectory as _trajectory
from .monitor import DEFAULT_EVENTS, load_events
from .sbom import build_sbom

INCIDENT_VERSION = 1

_MAX_TRAJECTORY_BYTES = 8_000_000  # mirrors trajectory.py's own per-file scan cap


def _trajectory_hash_entries(home) -> list[dict]:
    """Hash each trajectory sidecar file's raw bytes — never parses/reads call
    content. A hash lets an investigator later prove a file wasn't altered
    without this pack itself having read anything sensitive out of it."""
    if not isinstance(home, Path):
        return []
    entries: list[dict] = []
    for path in _trajectory.find_trajectory_files(home):
        try:
            data = path.read_bytes()[:_MAX_TRAJECTORY_BYTES]
            rel = path.relative_to(home)
        except (OSError, ValueError):
            continue
        entries.append({
            "path": str(rel),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    return entries


def _credential_rotation_list(findings) -> list[str]:
    """B41's own evidence — provider names + a gateway-token marker, never
    account/email fragments or token values (B41 already enforces this)."""
    b41 = next((f for f in findings if f.id == "B41"), None)
    return list(b41.evidence) if b41 is not None and b41.evidence else []


def build_incident(ctx, findings, score, *, when: str | None = None) -> dict:
    """Build the evidence-pack dict from an already-audited Context. Pure aside
    from the trajectory-file/event-log reads reused above — no writes, no network."""
    from . import __version__  # noqa: PLC0415 (avoid import-order coupling)
    from .report import _finding_to_dict  # noqa: PLC0415

    if when is None:
        when = datetime.now().isoformat(timespec="seconds")

    return {
        "tool": "clawseccheck",
        "version": __version__,
        "purpose": (
            "Preservation aid for step 3/6 of the incident-response playbook — a local, "
            "read-only evidence bundle. It gathers pointers and hashes; it does NOT "
            "rotate, delete, or remediate anything."
        ),
        "generated_at": when,
        "score": {"score": score.score, "grade": score.grade},
        "findings": [_finding_to_dict(f) for f in findings],
        "sbom": build_sbom(ctx),
        "trajectory_hashes": _trajectory_hash_entries(ctx.home),
        "credential_rotation_list": _credential_rotation_list(findings),
        "monitor_events": load_events(DEFAULT_EVENTS),
    }


def render_incident(ctx, findings, score, *, when: str | None = None) -> str:
    """Return the evidence pack as a stably-ordered JSON string."""
    payload = build_incident(ctx, findings, score, when=when)
    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)
