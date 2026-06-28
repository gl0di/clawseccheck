"""Coverage engine for the Dashboard: surface → 7-family roll-up + coverage map.

Pure stdlib, Python 3.9+, deterministic, read-only.

Grounded against docs/research/output-redesign-dashboard.md (2026-06-27) and
docs/research/openclaw-schema-recon.md.

Entry point:  ``coverage(findings) -> dict``
"""
from __future__ import annotations

from .catalog import BY_ID, FAMILY_OF, SURFACES, Finding

# ── Derived surface / family constants ───────────────────────────────────────

# The 13 bucket surfaces in canonical order (the "trifecta" cross-cutting chip
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
    """Compute the coverage map over the 13 OpenClaw bucket surfaces.

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
