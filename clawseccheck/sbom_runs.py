"""Local per-run SBOM snapshots for --sbom-diff (C-521): OPT-IN, append-only JSONL,
chmod 600, stdlib only.

Same idiom as runstore.py (--save-run/--diff, C-524) — reuses monitorstore.py's
generic hash-chain primitives (_chain_hash/_rotate_journal/_iter_jsonl/_last_chain_hash/
_schema_ok, all proven to operate on an arbitrary dict row, not just Finding shapes)
rather than reinventing them. But a SEPARATE store and SEPARATE diff function, not a
parameterization of runstore.py: runstore.diff_runs() is hard-coded to Finding fields
(id/status/detail/severity/title, plus baseline.fingerprint()'s finding-identity
concept) throughout, and an SBOM component (name/version/hash, no severity or status
at all) is a different enough shape that bolting it onto that function would mean
threading a shape-selector through code that currently has none — the same call this
project made when C-524 itself reused monitorstore.py's primitives without touching
history.py's or monitor.py's own, more specific, call sites.

Stores the NATIVE build_sbom(ctx) payload (sbom.py), never a format-specific
CycloneDX/SPDX rendering: --format is a presentation-time transform (see
render_sbom_cyclonedx/render_sbom_spdx), and SPDX's own creationInfo.created is
wall-clock "now" by SPDX convention — diffing rendered TEXT would manufacture a
difference on every run of an unchanged setup. Diffing the underlying component list
instead is immune to that: two runs of one unchanged setup diff to empty.

Run id = the same 'ts' stamp runstore.save_run() already stamps its own rows with —
no second identity invented, same reasoning that module gave for reusing history.py's
timestamp shape.
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

DEFAULT_SBOM_RUNS = "~/.clawseccheck/sbom_runs.jsonl"

_SBOM_RUNS_MAX_LINES = 60
_SBOM_RUNS_KEEP = 50

_COMPONENT_KINDS = ("skills", "mcp_servers", "plugins")


def save_sbom_run(sbom: dict, path: str = DEFAULT_SBOM_RUNS, when: "str | None" = None, *,
                  version: "str | None" = None) -> "str | None":
    """Persist one --sbom snapshot (the native build_sbom(ctx) dict). Returns the run
    id ('ts') on success, or None on write failure — never raises, same contract as
    runstore.save_run."""
    ts = when if when is not None else datetime.now().isoformat(timespec="seconds")
    p = Path(path).expanduser()
    base = {
        "ts": ts,
        "version": str(version) if version else None,
        "_schema": SCHEMA_VERSION,
        "sbom": sbom,
    }
    try:
        secure_dir(p.parent)
        with journal_lock(p):
            prev_hash = _last_chain_hash(p)
            row = {**base, "chain_hash": _chain_hash(prev_hash, base)}
            secure_append_text(p, json.dumps(row) + "\n")
            _rotate_journal(p, max_lines=_SBOM_RUNS_MAX_LINES, keep=_SBOM_RUNS_KEEP)
    except OSError:
        return None
    return ts


def load_sbom_run(run_id: str, path: str = DEFAULT_SBOM_RUNS) -> "dict | None":
    """Return the stored run whose 'ts' == run_id, last-write-wins on collision."""
    p = Path(path).expanduser()
    if not p.is_file():
        return None
    match = None
    try:
        for entry in _iter_jsonl(p):
            if _schema_ok(entry) and "sbom" in entry and entry.get("ts") == run_id:
                match = entry
    except OSError:
        return None
    return match


def list_sbom_run_ids(path: str = DEFAULT_SBOM_RUNS) -> "list[str]":
    p = Path(path).expanduser()
    if not p.is_file():
        return []
    try:
        return [e["ts"] for e in _iter_jsonl(p)
                if _schema_ok(e) and "sbom" in e and "ts" in e]
    except OSError:
        return []


def _component_identity(kind: str, entry: dict) -> tuple:
    """(kind, name) — except a component build_sbom() never actually produces: one
    missing its own "name" (a malformed/legacy-schema stored row; every real
    _skill_entry/_mcp_entry/_plugin_entry sets it unconditionally). Every such entry
    used to collapse onto the SAME (kind, "") identity, which silently turned a real
    add-one/remove-one pair into a false "changed" report on whichever fields
    happened to differ between the two unrelated nameless entries (C-135) — exactly
    the shape this feature exists to catch, reported about the wrong thing. Falling
    back to the entry's own hash keeps two DIFFERENT nameless entries distinct;
    two with the SAME hash (byte-identical content) collapsing is the one residual
    case left, and arguably correct there since same hash means same content."""
    name = entry.get("name")
    if name:
        return (kind, name)
    fallback = entry.get("hash") or repr(sorted(entry.items()))
    return (kind, f"<unnamed:{fallback}>")


def _flatten_components(run: dict) -> "dict[tuple, dict]":
    sbom = run.get("sbom") or {}
    out = {}
    for kind in _COMPONENT_KINDS:
        for entry in sbom.get(kind) or []:
            out[_component_identity(kind, entry)] = entry
    return out


def diff_sbom_runs(run1: dict, run2: dict) -> dict:
    """Buckets every component (skills + mcp_servers + plugins) from two stored SBOM
    runs into added/removed/changed by (kind, name) identity.

    'changed' names exactly which fields moved (version and/or hash) rather than just
    flagging that something did — a hash change with an UNCHANGED version is precisely
    the supply-chain-swap signal this feature exists to catch (same content-identity a
    version bump alone cannot express), and reporting both means a reader is never left
    guessing which one moved.
    """
    c1 = _flatten_components(run1)
    c2 = _flatten_components(run2)

    added = sorted((k for k in c2 if k not in c1), key=lambda k: (k[0], k[1]))
    removed = sorted((k for k in c1 if k not in c2), key=lambda k: (k[0], k[1]))
    changed = []
    for k in sorted(set(c1) & set(c2), key=lambda k: (k[0], k[1])):
        e1, e2 = c1[k], c2[k]
        moved = {}
        for field in ("version", "hash"):
            if e1.get(field) != e2.get(field):
                moved[field] = {"from": e1.get(field), "to": e2.get(field)}
        if moved:
            # C-135: "name" comes from the entry's OWN field, not the identity tuple
            # (k[1] can be the synthetic "<unnamed:...>" fallback _component_identity
            # uses for a nameless entry) — added/removed already do this by spreading
            # the original entry; changed must not assert the internal fallback marker
            # as if it were real component data.
            changed.append({"kind": k[0], "name": e1.get("name"), "changed": moved})

    return {
        "run1_ts": run1.get("ts"),
        "run2_ts": run2.get("ts"),
        "added": [{"kind": k[0], **c2[k]} for k in added],
        "removed": [{"kind": k[0], **c1[k]} for k in removed],
        "changed": changed,
        "unchanged_count": len(set(c1) & set(c2)) - len(changed),
    }


def render_sbom_diff_json(diff: dict, *, version: str) -> str:
    """The standalone --sbom-diff --json artifact. Routed through
    adjudication._emit_json (sanitize-on-emit over the whole tree), same as
    runstore.render_diff_json — the shared boundary every machine-readable artifact
    this tool emits goes through."""
    from .adjudication import _emit_json  # noqa: PLC0415

    payload = {
        "tool": "clawseccheck",
        "version": version,
        "run1": diff["run1_ts"],
        "run2": diff["run2_ts"],
        "added": diff["added"],
        "removed": diff["removed"],
        "changed": diff["changed"],
        "unchangedCount": diff["unchanged_count"],
    }
    return _emit_json(payload)
