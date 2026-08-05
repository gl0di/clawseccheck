"""Coverage engine for the Dashboard: surface → 7-family roll-up + coverage map.

Pure stdlib, Python 3.9+, deterministic, read-only.

Grounded against docs/research/output-redesign-dashboard.md (2026-06-27) and
docs/research/openclaw-schema-recon.md.

Entry point:  ``coverage(findings) -> dict``
"""
from __future__ import annotations

from .catalog import BY_ID, FAMILY_OF, SUBJECT_LABEL, SUBJECT_OF, SUBJECT_ORDER, SURFACES, Finding

# ── Derived surface / family constants ───────────────────────────────────────

# The 14 bucket surfaces in canonical order (the "trifecta" cross-cutting chip
# is deliberately excluded — it is a headline chip, not a coverage bucket).
_BUCKET_SURFACES: tuple[str, ...] = tuple(s for s in SURFACES if s != "trifecta")

# Family order: first-encounter traversal of _BUCKET_SURFACES via FAMILY_OF.
# Deterministic across Python versions (dict.fromkeys preserves insertion order
# since Python 3.7 and tuple() freezes it further).
_FAMILY_ORDER: tuple[str, ...] = tuple(
    dict.fromkeys(FAMILY_OF[s] for s in _BUCKET_SURFACES)
)

# Per-family member surfaces, in _BUCKET_SURFACES order (deterministic).
_FAMILY_SURFACES: dict[str, tuple[str, ...]] = {
    fam: tuple(s for s in _BUCKET_SURFACES if FAMILY_OF[s] == fam)
    for fam in _FAMILY_ORDER
}

# ── Static known gaps — grounded against openclaw-schema-recon.md ─────────────
# not_checkable: no OpenClaw config control exists that we could audit; these are
# permanently out of static-analysis scope.  Do NOT add entries without a grounding
# reference in that recon doc.
_NOT_CHECKABLE: list[str] = [
    "outbound egress allowlist",   # OpenClaw has no built-in egress allowlist to audit
    "talk.* surface",              # no stable / confirmable schema
    "per-agent tool allowlist",    # config expresses per-agent deny only, no allow
]

# roadmap: real OpenClaw surfaces ClawSecCheck does not yet cover (buildable but not built).
_ROADMAP: list[str] = []

# ── Helpers ───────────────────────────────────────────────────────────────────

_CHECKED_STATUSES: frozenset[str] = frozenset({"PASS", "FAIL", "WARN"})


def _empty_counts() -> dict[str, int]:
    return {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}


def _tally(findings: list[Finding]) -> dict[str, int]:
    """Count findings by status into lowercase keys."""
    counts = _empty_counts()
    for f in findings:
        key = f.status.lower()
        if key in counts:
            counts[key] += 1
    return counts


def _worst(counts: dict[str, int]) -> str:
    """Return the worst status label from an aggregated count dict.

    Priority: fail > warn > pass > unknown.
    """
    if counts["fail"]:
        return "fail"
    if counts["warn"]:
        return "warn"
    if counts["pass"]:
        return "pass"
    return "unknown"


# ── Public API ────────────────────────────────────────────────────────────────

def coverage(findings: list[Finding]) -> dict:
    """Compute the coverage map over the 14 OpenClaw bucket surfaces.

    Findings whose `id` is not in BY_ID (e.g. MCP-VET diagnostic findings)
    and findings from the "trifecta" surface are silently ignored — they carry
    no bucket-surface assignment.

    Surface states:
        "checked" — ≥1 finding for this surface returned PASS / FAIL / WARN.
        "partial" — all findings returned UNKNOWN (needs --attest / --host /
                    config present to resolve), or no findings produced at all.

    Args:
        findings: list of Finding objects from a scan run (e.g. checks.run_all).

    Returns:
        {
            "surfaces": {
                slug: {
                    "state": "checked" | "partial",
                    "counts": {"pass": N, "warn": N, "fail": N, "unknown": N},
                }
            },
            "families": {
                family: {
                    "surfaces": [slug, ...],  # in canonical _BUCKET_SURFACES order
                    "counts": {"pass": N, "warn": N, "fail": N, "unknown": N},
                    "worst": "fail" | "warn" | "pass" | "unknown",
                }
            },
            "gaps": {
                "not_checkable": [str, ...],  # static, grounded list
                "roadmap": [str, ...],        # extensible; empty now
            },
            "summary": {
                "checked": N,        # surfaces with ≥1 non-UNKNOWN finding
                "partial": M,        # surfaces where all findings are UNKNOWN
                "not_checkable": K,  # len(_NOT_CHECKABLE)
                "roadmap": J,        # len(_ROADMAP)
            },
        }
    """
    # Group findings by bucket surface.  Findings not in BY_ID or on the
    # "trifecta" surface are skipped (no bucket assignment).
    surface_findings: dict[str, list[Finding]] = {s: [] for s in _BUCKET_SURFACES}
    for f in findings:
        meta = BY_ID.get(f.id)
        if meta is None or meta.surface == "trifecta" or meta.surface not in surface_findings:
            continue
        surface_findings[meta.surface].append(f)

    # ── Per-surface state + counts ─────────────────────────────────────────
    surfaces: dict[str, dict] = {}
    checked = 0
    partial = 0
    for slug in _BUCKET_SURFACES:  # deterministic: canonical tuple order
        flist = surface_findings[slug]
        counts = _tally(flist)
        state = "checked" if any(f.status in _CHECKED_STATUSES for f in flist) else "partial"
        surfaces[slug] = {"state": state, "counts": counts}
        if state == "checked":
            checked += 1
        else:
            partial += 1

    # ── 7-family roll-up ───────────────────────────────────────────────────
    families: dict[str, dict] = {}
    for fam in _FAMILY_ORDER:  # deterministic: canonical derived tuple order
        member_surfaces = _FAMILY_SURFACES[fam]
        agg = _empty_counts()
        for slug in member_surfaces:
            for key in agg:
                agg[key] += surfaces[slug]["counts"][key]
        families[fam] = {
            "surfaces": list(member_surfaces),
            "counts": agg,
            "worst": _worst(agg),
        }

    return {
        "surfaces": surfaces,
        "families": families,
        "gaps": {
            "not_checkable": list(_NOT_CHECKABLE),
            "roadmap": list(_ROADMAP),
        },
        "summary": {
            "checked": checked,
            "partial": partial,
            "not_checkable": len(_NOT_CHECKABLE),
            "roadmap": len(_ROADMAP),
        },
    }


# ── F-165: per-subject (F-163 8-subject taxonomy) scanned-vs-total ────────────
# Distinct question from `coverage()` above: that answers "what did the 14 SURFACES
# find" (checked/partial/not_checkable by SECURITY FAMILY); this answers "was every
# CHECK this subject owns actually reached", at the coarser 8-SUBJECT (owner-facing)
# grouping `catalog.SUBJECT_OF` already defines for the Inventory-by-subject block.
_BUCKET_SUBJECTS: tuple[str, ...] = tuple(
    dict.fromkeys(s for s in SUBJECT_OF.values() if s not in ("skills", "mcp", "plugins"))
)
# "skills"/"mcp"/"plugins" are deliberately excluded: those three subjects get a
# PER-INSTANCE scanned-vs-total (one installed skill/configured server/swept plugin
# at a time, from the skill/plugin sweep and the MCP inventory) rather than this
# CHECK-granularity bucket count — see pipeline.build_coverage_page, the function
# that combines both kinds into the full 8-subject page.


def subject_coverage(findings: list[Finding]) -> dict:
    """Per-bucket-subject scanned-vs-total, at CHECK granularity.

    "scanned" = this subject has >=1 check that returned a conclusive PASS/FAIL/WARN
    (the same `_CHECKED_STATUSES` `coverage()` above uses); "total" = every CATALOG
    check id routed to this subject via `SUBJECT_OF`. `not_scanned` names the check
    ids that stayed UNKNOWN (or never fired at all this run) — never merely counted.

    Args:
        findings: list of Finding objects from a scan run (e.g. checks.run_all).

    Returns:
        {subject: {"total": int, "scanned": int, "not_scanned": [check_id, ...]}}
        for each subject in `_BUCKET_SUBJECTS`.
    """
    ids_by_subject: dict[str, list[str]] = {s: [] for s in _BUCKET_SUBJECTS}
    for cid, meta in BY_ID.items():
        subject = SUBJECT_OF.get(meta.surface)
        if subject in ids_by_subject:
            ids_by_subject[subject].append(cid)

    latest: dict[str, Finding] = {f.id: f for f in findings if f.id in BY_ID}

    result: dict[str, dict] = {}
    for subject in _BUCKET_SUBJECTS:
        cids = sorted(ids_by_subject[subject])
        not_scanned = [
            cid for cid in cids
            if latest.get(cid) is None or latest[cid].status not in _CHECKED_STATUSES
        ]
        result[subject] = {
            "total": len(cids),
            "scanned": len(cids) - len(not_scanned),
            "not_scanned": not_scanned,
        }
    return result


def _sweep_coverage(sweep) -> dict:
    """(total, scanned, not_scanned) for a skill/plugin sweep, in the shape
    `build_coverage_page` wants — or the honest "never swept this run" entry when
    `sweep` is None (a plain audit without ``--full``, or ``--fast``).

    ``sweep`` is any duck-typed sweep exposing ``.no_roots``/``.no_targets``/
    ``.counts()``/``.not_scanned()`` (``cli.SkillSweep`` or the plugin sweep — see
    ``pipeline.resolve_plugin_sweep``'s docstring for why neither is imported here by
    type). "total" counts every target the sweep accounted for, INCLUDING ones it
    never finished (SKIPPED/TRUNCATED) — the same "no silent gaps" counting
    ``SkillSweep`` itself already uses (``counts()['total'] + counts()['skipped']``,
    since ``counts()['total']`` there already excludes SKIPPED rows). "scanned"
    excludes BOTH SKIPPED and TRUNCATED (``sweep.not_scanned()`` names both) — a
    partially scanned target is not claimed fully covered."""
    if sweep is None:
        return {"total": None, "scanned": None, "not_scanned": [],
                "note": "not scanned this run (needs --full)"}
    if sweep.no_roots or sweep.no_targets:
        return {"total": 0, "scanned": 0, "not_scanned": [], "note": "none installed"}
    c = sweep.counts()
    not_scanned = [str(t) for t in sweep.not_scanned()]  # already sanitized by the sweep
    total = c["total"] + c["skipped"]
    return {"total": total, "scanned": total - len(not_scanned),
            "not_scanned": not_scanned, "note": None}


def build_coverage_page(ctx, findings: list[Finding], *, skill_sweep=None,
                        plugin_sweep=None) -> dict:
    """The full 8-subject (F-163 taxonomy) "was everything looked at" page: answers a
    different question than the Inventory-by-subject block (`report.build_inventory`,
    "what did we FIND") — this states scanned-vs-total, with every skip named, never
    merely counted (the epic's own "no silent gaps" requirement, E-069).

    `openclaw`/`host`/`agents`/`channels`/`logs` come from `subject_coverage` above
    (CHECK-granularity bucket coverage); `skills`/`plugins` come from the duck-typed
    sweep objects (either may be None when this run never swept that subject); `mcp`
    is always fully scanned (MCP vetting is not sweep-budgeted) — 0 of 0 reads as
    "none configured".

    V1 scope note (F-165): file/byte-level detail for `logs` ("N of M
    trajectory files, X of Y MB scanned") is intentionally NOT in this page yet — that
    data exists today only as prose inside B164/trajaudit/behavioral's own Finding
    text, not as structured counts. `logs` here is CHECK-granularity, same as the
    other bucket subjects, honest but coarser than the epic's target shape. Tracked as
    a separate follow-up rather than blocking this page on a new cross-module
    structured-stats channel. Consumed today by ``--full`` (text, via
    ``pipeline.render_sections``) and ``--full --json`` (``coveragePage``); dashboard/
    HTML/PDF reuse is also a follow-up (those render paths don't run through
    ``pipeline.run_pipeline`` today).
    """
    if ctx is None:
        return {}
    from .report import _mcp_inventory  # noqa: PLC0415 — deferred: report.py locally
    # imports `coverage.coverage` the same way (see this file's own `coverage()`
    # docstring precedent); keeping both directions deferred avoids the two modules
    # ever needing a load-order guarantee neither currently promises.

    page: dict[str, dict] = dict(subject_coverage(findings))

    for subject, sweep in (("skills", skill_sweep), ("plugins", plugin_sweep)):
        page[subject] = _sweep_coverage(sweep)

    n_mcp = len(_mcp_inventory(ctx))
    page["mcp"] = {"total": n_mcp, "scanned": n_mcp, "not_scanned": [],
                    "note": "none configured" if n_mcp == 0 else None}
    return page


def coverage_page_lines(page: dict, *, ascii_only: bool = False) -> list[str]:
    """Text rendering of `build_coverage_page`'s output — one function, reused by the
    ``--full`` narrative section (`pipeline.render_sections`) and, eventually,
    dashboard/HTML/PDF (see that function's own V1 scope note). ``ascii_only`` is
    accepted for signature parity with every other renderer in this codebase; the
    output here is already plain ASCII (no glyphs to degrade)."""
    del ascii_only
    if not page:
        return []
    lines: list[str] = []
    for subject in SUBJECT_ORDER:
        entry = page.get(subject)
        if entry is None:
            continue
        label = SUBJECT_LABEL[subject]
        if entry["total"] is None:
            lines.append(f" {label}: {entry['note']}")
            continue
        if entry["total"] == 0:
            lines.append(f" {label}: 0 of 0 ({entry['note']})")
            continue
        lines.append(f" {label}: {entry['scanned']} of {entry['total']} scanned")
        if entry["not_scanned"]:
            shown = ", ".join(entry["not_scanned"][:8])
            more = f" (+{len(entry['not_scanned']) - 8} more)" if len(entry["not_scanned"]) > 8 else ""
            lines.append(f"   not scanned: {shown}{more}")
    return lines
