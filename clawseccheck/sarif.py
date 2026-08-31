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

from . import brand
from .catalog import CATALOG, CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, Finding, remediation_for
from .dossier import axis_for
from .layers import LAYER_ORDER
from .report import (
    _redact_home_paths,
    _sanitize,
    _sanitize_tree,
    finding_counts_by_severity,
    self_excluded_line,
    surfaced_despite_suppression,
)
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


def _sarif_text(s: str) -> str:
    """Sanitize *and* fold an operator home-directory prefix, for every string that
    reaches SARIF `results[]` -- the artifact CLAUDE.md's own framing calls out as
    handed to CI dashboards / pasted into public issues (B-620).

    `_sanitize` alone (ANSI/OSC/control-char strip + `logsafe.redact`) does not fold a
    path. B-620's own fix already reuses `_redact_home_paths` for the
    `analysis_completeness.limit_hits` copy; this is the same helper applied to the
    PRIMARY payload -- `message.text` / `properties.evidence` -- which is where the
    leak was actually confirmed this round: `checks/_capability.py`'s C5 (native binary
    PATH safety) builds its WARN `detail`/`evidence` from resolved, absolute
    `Path` ancestors (e.g. ``/home/<user>/.npm-global/...``), and nothing between that
    check and this renderer folds it. Fixed at the renderer, not at C5 (or any other
    producer) deliberately: SARIF is the one channel every producer funnels through, so
    this covers producers that were never individually audited for the same shape.

    Also applied to `fixes[].description.text` (checked: sourced only from `catalog.
    REMEDIATION`'s static string literals today, so no live path was found there --
    wrapped anyway so a future REMEDIATION entry that interpolates a path doesn't leak
    silently) and to `vetProfile.axes[].reason` (traced to `dossier._reason_and_fix`,
    which returns `worst.detail` verbatim -- the SAME `Finding.detail` this function
    already redacts for `results[].message.text`, so leaving it unwrapped here would
    have reopened the identical leak one field over).
    """
    return _redact_home_paths(_sanitize(s))


def _build_analysis_completeness(
    findings: list[Finding],
    checks_run: int,
    checks_total: int,
    self_excluded: "list[str] | tuple[str, ...]" = (),
    score=None,
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
    self_excluded:
        Skills dropped from the installed-skill content scan by the collector's identity
        oracle -- in practice ClawSecCheck's own installed copy. B-560: SARIF was the
        CI-facing surface that never said so, and a pipeline reading it could not tell
        "scanned and clean" from "not scanned". It belongs here rather than as a
        ``result``: it is a statement about the run's reach, which is what this block is.
    score:
        The run's :class:`~clawseccheck.scoring.ScoreResult`, when there is one. Adds the
        five-layer state (B-585) -- see below. ``None`` on the ``--vet`` paths, and its
        keys are then ABSENT rather than false: mode C produces no grade by construction,
        so ``graded: false`` there would imply a letter was withheld when none ever
        existed. `docs/OUTPUT_SCHEMA.md` documents that absence as a state.

    B-585, the defect this parameter closes. On a home with no OpenClaw config at all
    this block read::

        {"checksRun": 184, "checksTotal": 184, "failCount": 0,
         "limitations": ["host-posture checks require --host",
                         "attestation checks require --attest"]}

    A field named *analysisCompleteness* reporting 184 of 184 checks run, zero failures,
    and no limitation worth naming -- for an audit that could not read a single byte of
    configuration. 155 of those 184 were UNKNOWN, which was in the payload, but the
    headline pair is what a dashboard renders. Meanwhile ``--json`` on the same run
    carried ``graded: false``, ``missing_layers``, ``config_blind_capped: true`` and
    ``config_blind_reason: "absent"``, and the dashboard card said it out loud.

    The counts were never wrong -- 184 checks really did run. They answer a question
    about CHECKS, and the block's name promises one about the ANALYSIS, which since
    E-077 is the five-layer ledger. So the layer figures are published beside them
    rather than the counts being changed: "184 of 184" can no longer be read as a
    complete analysis while ``layersRan`` says 2 of 5.

    Deliberately NOT published here: ``score``/``grade``. They are ``None`` on an
    ungraded run, and a consumer reading a ``0`` where ``null`` was meant would rank a
    blind audit as a perfect one -- the leak C-423 closed in ``render_json``'s projection
    block and C-426 closed in ``_percentile_line``. This publishes the STATE, never a
    number the report withheld.
    """
    block: dict = {
        "checksRun": checks_run,
        "checksTotal": checks_total,
        "unknownCount": sum(1 for f in findings if f.status == UNKNOWN),
        # F-138/B1: how many of the (still-full) unknownCount above are UNKNOWN because
        # the check's surface doesn't exist here, vs genuinely undetermined. Additive —
        # runs[0].properties.* is explicitly outside the frozen public contract (see
        # docs/OUTPUT_SCHEMA.md), so unknownCount itself stays the whole count and does
        # not shrink for whatever already consumes it.
        "notApplicableCount": sum(1 for f in findings if getattr(f, "not_applicable", False)),
        "passCount": sum(1 for f in findings if f.status == PASS),
        "warnCount": sum(1 for f in findings if f.status == WARN),
        "failCount": sum(1 for f in findings if f.status == FAIL),
        "suppressedCount": sum(1 for f in findings if f.suppressed),
        # I3: per-severity counts of UNSUPPRESSED FAIL findings — the same numbers
        # `--fail-on SEVERITY` (cli.py) gates on and report.py's --json carries as
        # `fail_counts_by_severity`. Deliberately distinct from `failCount` two lines
        # above: that one is an unconditional total (suppressed FAILs included, no
        # severity split); this one is the CI-assertable, suppression-aware figure —
        # see finding_counts_by_severity()'s docstring (report.py) for the exact
        # predicate. camelCase key to match this block's existing convention
        # (checksRun/failCount/…); lowercase severity sub-keys to match report.py's.
        "failCountsBySeverity": finding_counts_by_severity(findings),
        # B-560: camelCase to match this block's convention. Always present, empty list
        # when nothing was excluded — an absent key would make "no exclusions" and "this
        # producer is too old to say" the same thing to a consumer.
        "selfExcludedSkills": sorted(self_excluded),
        "limitations": [
            "host-posture checks require --host",
            "attestation checks require --attest",
        ] + ([self_excluded_line(sorted(self_excluded))] if self_excluded else []),
    }
    if score is None:
        return block

    missing = [
        {"layer": layer, "status": status}
        for layer, status in (getattr(score, "missing_layers", ()) or ())
    ]
    graded = bool(getattr(score, "graded", True))
    blind_reason = getattr(score, "config_blind_reason", None)
    block["graded"] = graded
    # `missing_layers` is every layer whose status is not "ran" (LayerLedger.missing), so
    # the arithmetic is exact rather than a second count that could drift from it.
    block["layersTotal"] = len(LAYER_ORDER)
    block["layersRan"] = len(LAYER_ORDER) - len(missing)
    block["missingLayers"] = missing
    # A layer that RAN but could not exhaust its subject — a different question from a
    # layer that never ran, and the reason both are published (ScoreResult's own
    # docstring makes the same distinction).
    block["notChecked"] = list(getattr(score, "not_checked", ()) or ())
    # B-166 already surfaced a present-but-unparseable config in the sibling
    # `analysis_completeness` block; a wholly ABSENT one (B-363) was surfaced nowhere in
    # SARIF. `config_blind_reason` answers both in one field, exactly as it does for
    # `--json`, so a consumer never has to re-derive the state from two booleans.
    block["configBlind"] = {
        "capped": bool(getattr(score, "config_blind_capped", False)),
        "reason": blind_reason,
    }
    # B-690: `configBlind` is ONE of the six signals that can cap the score, and it was the
    # only one this block published. A run capped by an open CRITICAL, a fired behavioural
    # detector, a corroborated runtime indicator or a submitted VULNERABLE live-test verdict
    # emitted SARIF saying nothing about any of it — with `configBlind.capped: false` present
    # and looking like an answer. That matters more here than in a report a human reads: this
    # artifact goes to CI and code-scanning consumers that act on it unaccompanied.
    #
    # ALWAYS present, empty list when nothing capped — the rule this block already states for
    # `selfExcludedSkills` (B-560): an absent key would make "nothing capped this run" and
    # "this producer is too old to say" the same thing to a consumer.
    #
    # The same `capsFired` name and shape the judge packet uses, from the same producer, not
    # a second ladder beside it — B-689/B-692/B-693/B-694 were each one rule kept by hand in
    # two places. Lazy import for the same reason `history._sanitize_home` gives for reaching
    # into `report`: both modules are Layer 3 and the coupling is load-bearing only here.
    #
    # `configBlind` is kept unchanged rather than folded in. It is documented, it is the one
    # signal a consumer may already read, and breaking it to tidy a duplication would trade a
    # silence for a regression. `tests/test_b690_every_cap_reaches_sarif.py` pins that the two
    # cannot disagree.
    from .adjudication import caps_fired  # noqa: PLC0415 — see the comment above
    block["capsFired"] = caps_fired(score)
    if block["capsFired"]:
        block["limitations"].append(
            "the score was capped: " + ", ".join(c["what"] for c in block["capsFired"])
            + " — it reports a ceiling, not a measurement of everything below it"
        )
    if blind_reason:
        block["limitations"].append(
            f"openclaw.json was {blind_reason} this run — findings describe what could "
            "NOT be checked, not a clean configuration"
        )
    if not graded:
        block["limitations"].append(
            "no grade: " + ", ".join(
                f"{m['layer']} ({m['status']})" for m in missing
            ) + " — this run did not complete the five-layer check"
        )
    return block


def render_sarif(
    findings: list[Finding],
    score: ScoreResult | None = None,
    tool_version: str = "0.0.0",
    ctx: Context | None = None,
    profile=None,
) -> str:
    """Return a SARIF 2.1.0 JSON string representing *findings*.

    Only FAIL and WARN findings that are not suppressed produce ``results``
    entries. PASS and UNKNOWN are omitted, as are ordinary suppressed findings —
    except a score-capping suppressed CRITICAL/HIGH FAIL (or sensitive check id),
    which is emitted WITH a SARIF ``suppressions`` array so it stays visible to a
    consumer (e.g. GitHub code scanning) rather than being silently hidden (B-163).
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

    # Build results: FAIL / WARN. Ordinary suppressed findings are skipped, but a
    # score-capping suppressed CRITICAL/HIGH FAIL (or sensitive id) is kept and flagged
    # with a SARIF `suppressions` array so it stays visible, not silently dropped (B-163).
    _catalog_ids = {meta.id for meta in CATALOG}
    results = []
    for f in findings:
        surfaced_suppressed = surfaced_despite_suppression(f)
        if f.suppressed and not surfaced_suppressed:
            continue
        if f.status not in (FAIL, WARN):
            continue
        level = "error" if f.status == FAIL else "warning"
        message_text = _sarif_text(f.detail if f.detail else f.title)
        result = {
            "ruleId": f.id,
            "level": level,
            "message": {"text": message_text},
            "properties": {"confidence": getattr(f, "confidence", "HIGH"),
                           "evidence": [_sarif_text(e) for e in (f.evidence or [])]},
        }
        # Risk-dossier axis (additive) so a SARIF viewer can group findings by axis.
        _ax = axis_for(f)
        if _ax is not None:
            result["properties"]["axis"] = _ax
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
            result["fixes"] = [{"description": {"text": _sarif_text(tx)}} for tx in fix_texts]
        if surfaced_suppressed:
            # SARIF-native suppression: the result stays in `results` (visible in the UI)
            # but is marked suppressed, so a gate that respects suppressions won't fail on
            # it while a reviewer still sees the hidden CRITICAL/HIGH (B-163).
            result["suppressions"] = [{
                "kind": "external",
                "justification": "suppressed via .clawseccheckignore; still counts against real security",
            }]
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
                        # Display name, single-sourced from brand.py (C-241); value is
                        # unchanged ("ClawSecCheck") — see tests/test_sarif.py.
                        "name": brand.WORDMARK,
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
        findings, _checks_run, _checks_total,
        self_excluded=list(getattr(ctx, "self_excluded_skills", None) or []),
        score=score,
    )

    if ctx is not None:
        total_files_inspected = getattr(ctx, "total_files_inspected", 0)
        excluded_binary_files_count = getattr(ctx, "excluded_binary_files_count", 0)
        archives_unpacked = getattr(ctx, "archives_unpacked", 0)
        # B-620: at least one `limit_hits` producer (collector._config_workspace_dirs,
        # for a `workspace` value resolved via `~` expansion) interpolates a resolved
        # ABSOLUTE path, and this block used to copy the list verbatim -- so a SARIF file
        # could carry the operator's real `/home/<user>/...`. Reuse
        # `report._redact_home_paths` (B-381's precedent for this exact shape, already
        # applied to the --dashboard card) rather than reimplementing path folding a
        # second time -- this repo has been burned by divergent redaction tables before.
        # A NEW list of plain strings is built here; `ctx.limit_hits` (its `LimitHit`
        # objects, read verbatim by B13/dossier.py leg 2/cli.sweep_installed_skills) is
        # never touched.
        limit_hits = [_redact_home_paths(str(h)) for h in (getattr(ctx, "limit_hits", None) or [])]
        path_traversal_violations = list(getattr(ctx, "path_traversal_violations", []))
        file_manifest = dict(getattr(ctx, "file_manifest", {}))
        disclosures = [
            {"kind": d.kind, "subject": d.subject, "detail": d.detail}
            for d in (getattr(ctx, "disclosures", None) or [])
        ]

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
            "disclosures": disclosures,
            "simulated_effects": simulated_effects,
            # B-166: surface a present-but-unparseable openclaw.json so a SARIF consumer
            # doesn't read an UNKNOWN-only run over a broken config as a clean scan.
            "config_parse_error": bool(getattr(ctx, "config_parse_error", False)),
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

    # Risk-dossier summary (additive, non-breaking — an extension property outside the
    # frozen SARIF contract). Per-finding results stay finding-oriented; this carries the
    # axis roll-up + Mode C's install-recommendation verdict so a viewer can show the
    # dossier alongside the results.
    #
    # C427: no letter grade / numeric score here — "verdict" is `profile.verdict`
    # (dossier.verdict_for(profile.overall_status), computed once in build_profile), the
    # exact same value the text dossier / --json / --advise render, so SARIF cannot
    # disagree with them.
    if profile is not None:
        run = sarif_log["runs"][0]
        run.setdefault("properties", {})
        run["properties"]["vetProfile"] = {
            "targetType": profile.target_type,
            "verdict": profile.verdict,
            "axes": [
                {
                    "axis": a.axis,
                    "status": a.status,
                    "reason": _sarif_text(a.reason),
                    "findingIds": [x.id for x in a.findings],
                }
                for a in profile.axes
            ],
        }

    return json.dumps(_sanitize_tree(sarif_log), ensure_ascii=True, indent=2)
