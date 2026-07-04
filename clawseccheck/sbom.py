"""AI-BOM export (`--sbom`): a local, deterministic bill-of-materials JSON.

Standalone export format — NOT a human report. Summarizes the installed-skill /
MCP-server inventory an `audit()` pass already collected, in a stable machine-readable
shape so it can be diffed, archived, or fed to other local tooling. Local file / stdout
only; never uploaded anywhere.

Hashing and field extraction deliberately REUSE monitor.py's existing helpers
(`_h`, `_SKILL_VERSION_RE`) and monitor.py's `_mcp_detail_sig` so the BOM's hashes
line up with monitor.py's own drift-detection snapshots (same hash scheme, same
inputs) — this module does not invent a second hashing convention.

Redaction discipline (ZKDS): the BOM NEVER contains secret/credential VALUES — only
key names, hashes and structural metadata. MCP env vars reuse `_mcp_detail_sig`'s
existing `key:*` marking for secret-shaped key names; values are never read here.
"""
from __future__ import annotations

import json

from .checks import _dep_names_in_skill, _unpinned_deps_in_skill
from .monitor import _SKILL_VERSION_RE, _h, _mcp_detail_sig

SBOM_VERSION = 1


def _skill_entry(name: str, blob: str) -> dict:
    m = _SKILL_VERSION_RE.search(blob)
    declared_deps = sorted(set(_dep_names_in_skill(blob)))
    unpinned_deps = sorted({
        line.split("'")[1]
        for line in _unpinned_deps_in_skill(name, blob)
        if "'" in line
    })
    return {
        "name": name,
        "version": m.group(1) if m else None,
        "hash": _h(blob),
        "declared_deps": declared_deps,
        "unpinned_deps": unpinned_deps,
    }


def _mcp_entry(name: str, detail: dict) -> dict:
    env_keys = detail.get("env_keys") or []
    # "pinned" here means the command's first arg carries a version pin (e.g. an
    # npx `pkg@1.2.3` spec) — a coarse, best-effort supply-chain signal derived
    # from the same args0 field monitor.py already extracts; never fabricated.
    args0 = str(detail.get("args0") or "")
    pinned = "@" in args0.rsplit("/", 1)[-1][1:] if args0 else False
    return {
        "name": name,
        "hash": _h(json.dumps(detail, sort_keys=True, default=str)),
        "transport": detail.get("transport") or "",
        "command": detail.get("command") or "",
        "env_keys": list(env_keys),
        "pinned": pinned,
    }


def build_sbom(ctx) -> dict:
    """Build the BOM dict from an audited Context. Pure/deterministic (no I/O)."""
    from . import __version__  # noqa: PLC0415 (avoid import-order coupling)

    skills = [
        _skill_entry(name, blob)
        for name, blob in sorted(ctx.installed_skills.items())
    ]

    mcp_detail = _mcp_detail_sig(ctx)
    mcp_servers = [
        _mcp_entry(name, detail)
        for name, detail in sorted(mcp_detail.items())
    ]

    return {
        "version": SBOM_VERSION,
        "generated_by": f"clawseccheck v{__version__}",
        "skills": skills,
        "mcp_servers": mcp_servers,
    }


def render_sbom(ctx) -> str:
    """Return the BOM as a deterministic, stably-ordered JSON string."""
    payload = build_sbom(ctx)
    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)
