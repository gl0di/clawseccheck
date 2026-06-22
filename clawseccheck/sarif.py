"""Render ClawSecCheck findings as a SARIF 2.1.0 JSON string.

LOCAL FILE ONLY — this function returns a string; it never writes or uploads anything.
The schema URI below is a string literal; it is never fetched.

Usage::

    from clawseccheck.sarif import render_sarif
    sarif_text = render_sarif(findings, score, tool_version="1.0.0")
"""
from __future__ import annotations

import json

from .catalog import CATALOG, CRITICAL, FAIL, HIGH, WARN, Finding
from .report import _sanitize
from .scoring import ScoreResult

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_INFO_URI = "https://github.com/gl0di/clawseccheck"

# severity -> SARIF defaultConfiguration.level
_SEV_LEVEL = {
    CRITICAL: "error",
    HIGH: "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def render_sarif(
    findings: list[Finding],
    score: ScoreResult | None = None,
    tool_version: str = "0.0.0",
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
        results.append(
            {
                "ruleId": f.id,
                "level": level,
                "message": {"text": message_text},
                "properties": {"confidence": getattr(f, "confidence", "HIGH"),
                               "evidence": [_sanitize(e) for e in (f.evidence or [])]},
            }
        )
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

    return json.dumps(sarif_log, ensure_ascii=True, indent=2)
