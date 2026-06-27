"""Render ClawSecCheck findings as a SARIF 2.1.0 JSON string.

LOCAL FILE ONLY — this function returns a string; it never writes or uploads anything.
The schema URI below is a string literal; it is never fetched.

Usage::

    from clawseccheck.sarif import render_sarif
    sarif_text = render_sarif(findings, score, tool_version="1.0.0")
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from .catalog import CATALOG, CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding, remediation_for
from .report import _sanitize
from .scoring import ScoreResult

if TYPE_CHECKING:
    from .collector import Context

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_INFO_URI = "https://github.com/gl0di/clawseccheck"

# severity -> SARIF defaultConfiguration.level
_SEV_LEVEL = {
    CRITICAL: "error",
    HIGH: "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _build_analysis_completeness(
    findings: list[Finding],
    checks_run: int,
    checks_total: int,
) -> dict:
    """Return the ``analysisCompleteness`` metablock for SARIF run.properties.

    Parameters
    ----------
    findings:
        All findings from the audit (all statuses including PASS/UNKNOWN/suppressed).
    checks_run:
        Number of checks actually executed in this run.
    checks_total:
        Total checks registered in the CHECKS catalogue; ``-1`` when unknown.
    """
    return {
        "checksRun": checks_run,
        "checksTotal": checks_total,
        "unknownCount": sum(1 for f in findings if f.status == UNKNOWN),
        "passCount": sum(1 for f in findings if f.status == PASS),
        "warnCount": sum(1 for f in findings if f.status == WARN),
        "failCount": sum(1 for f in findings if f.status == FAIL),
        "suppressedCount": sum(1 for f in findings if f.suppressed),
        "limitations": [
            "host-posture checks require --host",
            "attestation checks require --attest",
        ],
    }


def render_sarif(
    findings: list[Finding],
    score: ScoreResult | None = None,
    tool_version: str = "0.0.0",
    ctx: Context | None = None,
) -> str:
    """Return a SARIF 2.1.0 JSON string representing *findings*.

    Only FAIL and WARN findings that are not suppressed produce ``results``
    entries. PASS, UNKNOWN, and suppressed findings are silently omitted.
    The output is deterministic: rules follow CATALOG order; results follow the
    order of *findings* (caller is responsible for ordering if needed).

    Parameters
    ----------
    findings:
        List of :class:`clawseccheck.catalog.Finding` objects from :func:`clawseccheck.checks.run_all`.
    score:
        Optional :class:`clawseccheck.scoring.ScoreResult` from :func:`clawseccheck.scoring.compute`.
        Not embedded in SARIF output; accepted for call-site symmetry with the full audit
        and may be omitted (e.g. the vetting modes, which produce no score).
    tool_version:
        Version string embedded in ``tool.driver.version``.

    Returns
    -------
    str
        JSON string (``ensure_ascii=True``, ``indent=2``).  No file I/O is performed.
    """
    # Build rules from the canonical catalog order (deterministic).
    rules = [
        {
            "id": meta.id,
            "name": meta.title,
            "shortDescription": {"text": meta.title},
            "defaultConfiguration": {
                "level": _SEV_LEVEL.get(meta.severity, "note"),
            },
        }
        for meta in CATALOG
    ]

    # Build results: only FAIL / WARN, not suppressed.
    _catalog_ids = {meta.id for meta in CATALOG}
    results = []
    for f in findings:
        if f.suppressed:
            continue
        if f.status not in (FAIL, WARN):
            continue
        level = "error" if f.status == FAIL else "warning"
        message_text = _sanitize(f.detail if f.detail else f.title)
        result = {
            "ruleId": f.id,
            "level": level,
            "message": {"text": message_text},
            "properties": {"confidence": getattr(f, "confidence", "HIGH"),
                           "evidence": [_sanitize(e) for e in (f.evidence or [])]},
        }
        # SARIF `fixes`: description-only (no artifactChanges — ClawSecCheck never edits
        # files). Built from the paste-ready remediation when the check has one.
        rem = remediation_for(f.id)
        fix_texts = list(rem["commands"])
        for c in rem["config"]:
            if c.get("set") is None:
                fix_texts.append(f"set {c['path']}: {c.get('note', '')}".rstrip(": "))
            else:
                fix_texts.append(f"set {c['path']} = {json.dumps(c['set'])} ({c.get('note', '')})")
        if fix_texts:
            result["fixes"] = [{"description": {"text": _sanitize(tx)}} for tx in fix_texts]
        results.append(result)
        # Vetting findings (e.g. MCP-VET) carry ids outside the scored CATALOG.
        # Keep the SARIF self-consistent: every referenced ruleId must have a rule.
        if f.id not in _catalog_ids:
            _catalog_ids.add(f.id)
            rules.append({
                "id": f.id,
                "name": _sanitize(f.title),
                "shortDescription": {"text": _sanitize(f.title)},
                "defaultConfiguration": {"level": _SEV_LEVEL.get(f.severity, "note")},
            })

    sarif_log = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ClawSecCheck",
                        "version": tool_version,
                        "informationUri": _INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    # Always emit the analysisCompleteness metablock so consumers know the
    # scope of the run regardless of whether a full Context is available.
    try:
        from .checks import CHECKS as _CHECKS  # noqa: PLC0415
        _checks_total = len(_CHECKS)
    except Exception:
        _checks_total = -1
    _checks_run = _checks_total if _checks_total >= 0 else len(findings)
    _run = sarif_log["runs"][0]
    if "properties" not in _run:
        _run["properties"] = {}
    _run["properties"]["analysisCompleteness"] = _build_analysis_completeness(
        findings, _checks_run, _checks_total
    )

    if ctx is not None:
        total_files_inspected = getattr(ctx, "total_files_inspected", 0)
        excluded_binary_files_count = getattr(ctx, "excluded_binary_files_count", 0)
        archives_unpacked = getattr(ctx, "archives_unpacked", 0)
        limit_hits = list(getattr(ctx, "limit_hits", []))
        path_traversal_violations = list(getattr(ctx, "path_traversal_violations", []))
        file_manifest = dict(getattr(ctx, "file_manifest", {}))

        simulated_effects = []
        installed_skill_py = getattr(ctx, "installed_skill_py", None)
        if installed_skill_py:
            from .skillast import simulate_effects
            for skill, files in installed_skill_py.items():
                if not isinstance(files, list):
                    continue
                for item in files:
                    try:
                        if isinstance(item, tuple) and len(item) >= 2:
                            relpath, source = item[0], item[1]
                        else:
                            continue
                        effects = simulate_effects(source, relpath)
                        for effect in [dict(e) for e in effects if isinstance(e, dict)]:
                            effect["skill"] = skill
                            effect["file"] = relpath
                            simulated_effects.append(effect)
                    except Exception:
                        pass

        completeness = {
            "total_files_inspected": total_files_inspected,
            "excluded_binary_files_count": excluded_binary_files_count,
            "archives_unpacked": archives_unpacked,
            "limit_hits": limit_hits,
            "path_traversal_violations": path_traversal_violations,
            "file_manifest": file_manifest,
            "simulated_effects": simulated_effects,
        }
        run = sarif_log["runs"][0]
        if "properties" not in run:
            run["properties"] = {}
        run["properties"]["analysis_completeness"] = completeness

        # F-018: per-skill effect profile derived from ctx.effect_profiles.
        # Each key is a skill name; value is a list of entry-point dicts produced by
        # simulate_effects (annotated with "file" by check_installed_skills).
        # Emitted only when at least one skill has a non-empty profile.
        effect_profiles = getattr(ctx, "effect_profiles", {})
        if effect_profiles:
            run["properties"]["effectProfile"] = {
                skill: list(entries)
                for skill, entries in effect_profiles.items()
            }

    return json.dumps(sarif_log, ensure_ascii=True, indent=2)
