"""Risk dossier: aggregate a vet engine's Findings into a 5-axis ``VetProfile``.

``--vet`` used to emit a flat "is this malicious?" verdict. The dossier reframes the
*same* signals into five axes that answer, together, "how risky is this to install?":

    danger       — how dangerous it is to use (active malice, known-bad).  FLOOR axis.
    build        — how it is built (least-privilege, pinning, authoring hygiene).
    behavior     — how it thinks / behaves (override, jailbreak, forged provenance).
    persistence  — what it stores for the future (dormant / staged code, install hooks).
    connections  — whom it connects with (outbound surface, exfil channels).

This module is a pure *aggregation + grading* layer. It does NOT scan: the four vet
engines (``vet_skill`` / ``vet_plugin`` / ``vet_mcp`` / ``vet_source`` in ``the checks engine``)
stay the signal producers. ``build_profile`` reads their existing ``Finding`` output plus
the ``ctx`` they attach, buckets each finding to an axis using the catalog's own AST /
surface metadata (no per-finding hand-wiring), and rolls the axes up to an A–F grade via
``scoring.grade_for`` — never touching ``scoring.compute`` / ``FAIL_CAPS``.

Honesty rules (project law §2.4 / §5):
  * An axis a target type *structurally cannot* produce is ``N/A`` — excluded from the
    grade denominator, never a fabricated PASS/FAIL (e.g. an MCP server spec has no
    dormant code → ``persistence`` = N/A; ``vet_source`` never fetches → every axis but
    ``danger`` = N/A).
  * An axis with a producer but no measurable input is ``UNKNOWN`` (e.g. a skill with no
    Python → ``connections`` / ``persistence`` cannot be measured) — distinct from PASS.
  * ``danger == FAIL`` floors the overall grade to F regardless of the other axes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from dataclasses import replace as dc_replace

from .catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN, ast_for
from .scoring import grade_for

# Fifth status, local to the dossier (catalog has no "not applicable" concept).
NA = "N/A"

# Fixed render / iteration order.
AXES: tuple[str, ...] = ("danger", "build", "behavior", "persistence", "connections")
AXIS_LABEL: dict[str, str] = {
    "danger": "Danger",
    "build": "Build quality",
    "behavior": "Behavior",
    "persistence": "Persistence",
    "connections": "Connections",
}

# Overall verdict word, keyed by overall_status (mirrors report._VET_VERDICT).
VERDICT_WORD: dict[str, str] = {
    FAIL: "DANGEROUS",
    WARN: "SUSPICIOUS",
    PASS: "SAFE",
    UNKNOWN: "UNKNOWN",
}

# ── Finding → axis bucketing ──────────────────────────────────────────────────
# Step 1: explicit id overrides — for findings whose AST class is ambiguous across
# axes, or which are synthetic verdict ids carrying no catalog metadata. A value of
# None marks a synthetic aggregate handled specially (container decomposition / per-
# reason routing), never bucketed as itself.
_AXIS_BY_ID: dict[str, str | None] = {
    "B13": "danger",  # malware verdict (AST01∧AST02) — danger dominates
    "B90": "danger",  # reassembled split base64 payload = active malicious code
    "B89": "persistence",  # dormant / unreachable-yet-code-bearing = staged
    "B86": "persistence",  # writable import path = staging / tamper surface
    "B87": "persistence",  # symlink escape to a sensitive path = staged exfil primitive
    "B62": "build",  # capability over-grant = a build-quality / least-privilege defect
    "B59": "connections",  # markdown-image data-exfil = outbound channel
    "SOURCE-VET": "danger",  # reputation gate is a pure danger/identity verdict
    "PLUGIN-VET": None,  # container aggregate — decomposed into its sub-findings
    "MCP-VET": None,  # multi-reason verdict — routed per-reason via axis_reasons
}

# Step 2: AST class → axis (the grounded default; ast_for() at catalog.py).
_AXIS_BY_AST: dict[str, str] = {
    "AST01": "danger",  # Malicious Skills
    "AST02": "build",  # Supply Chain Compromise (pinning / integrity)
    "AST03": "build",  # Over-Privileged (least-privilege is a build property)
    "AST04": "build",  # Insecure Metadata (authoring hygiene)
    "AST05": "behavior",  # Untrusted External Instructions (override / jailbreak)
    "AST06": "build",  # Weak Isolation
    "AST07": "build",  # Update Drift
    "AST08": "build",  # Poor Scanning
    "AST09": "build",  # No Governance
    "AST10": "build",  # Cross-Platform Reuse
}

# When a finding maps to several axes, the most-severe axis wins (deterministic).
_AXIS_PRECEDENCE: tuple[str, ...] = ("danger", "behavior", "persistence", "connections", "build")

# Step 3: surface fallback for the rare CATALOG finding with no AST tag.
_SURFACE_AXIS: dict[str, str] = {
    "secrets": "connections",
    "monitoring": "connections",
    "channels": "connections",
    "sessions": "connections",
    "skills": "build",
    "mcp": "build",
    "update": "build",
    "tools": "build",
    "agents": "build",
    "gateway": "build",
    "host": "build",
    "hooks": "persistence",
    "bootstrap": "behavior",
}

# Per-type axis applicability. False → the axis is N/A for that target type (structurally
# cannot be produced), excluded from the grade denominator.
_AXIS_APPLICABILITY: dict[str, dict[str, bool]] = {
    "skill": {a: True for a in AXES},
    "plugin": {a: True for a in AXES},
    # An MCP server spec is a live connection, not on-disk content — it stores no
    # dormant/staged code.
    "mcp": {**{a: True for a in AXES}, "persistence": False},
    # A source reputation gate never fetches the artifact — only its identity (danger)
    # is assessable; build/behavior/persistence/connections of unseen code are not.
    "source": {"danger": True, "build": False, "behavior": False,
               "persistence": False, "connections": False},
}

# B-160: "SKILL_ARCHIVE_PATH_TRAVERSAL" is a real third status the checks engine emits
# for B13 (report.py / scoring.py deliberately exclude it from the *scored* audit, same
# as UNKNOWN — see scoring.compute). But it is a confirmed known-bad signal (zip-slip),
# not an honesty exclusion, so the --vet danger axis must rank/grade it like FAIL —
# otherwise _worst() picks it as low as PASS and _grade_profile drops it from `scorable`
# entirely, letting a detected archive path-traversal attack render as A/SAFE.
_STATUS_RANK: dict[str, int] = {
    FAIL: 3, "SKILL_ARCHIVE_PATH_TRAVERSAL": 3, WARN: 2, UNKNOWN: 1, PASS: 0,
}
# Overall-grade caps so the letter never contradicts the verdict word: any WARN keeps it
# below A (an artifact with a real caveat is not "A / SAFE"); a non-danger FAIL costs a
# further grade (mirrors scoring.FAIL_CAPS[HIGH] — "one real failure always costs a grade").
_WARN_CAP = 89
_NON_DANGER_FAIL_CAP = 79
# B-092: a Danger-axis UNKNOWN caused by a coverage-limit hit (a payload padded past the
# per-skill/500-file scan cap could hide unscanned) must never read as "A / SAFE" — cap it at
# the top of the C band, same ceiling scoring.py gives a real HIGH finding.
_COVERAGE_GAP_DANGER_CAP = 79


@dataclass
class AxisResult:
    axis: str  # danger | build | behavior | persistence | connections
    status: str  # FAIL | WARN | PASS | UNKNOWN | N/A
    reason: str
    fix: str = ""
    findings: list = field(default_factory=list)  # Findings bucketed here (empty for N/A)


@dataclass
class VetProfile:
    target: str
    target_type: str  # skill | plugin | mcp | source
    overall_status: str  # FAIL | WARN | PASS | UNKNOWN
    overall_grade: str  # A..F, or "N/A" when nothing is assessable
    score: int  # 0..100 (0 when not assessable)
    axes: list  # AxisResult, in AXES order
    findings: list  # flat pool (for JSON detail / SARIF results)
    unmapped: list = field(default_factory=list)  # finding ids that resolved to no axis


def axis_for(finding) -> str | None:
    """Resolve one finding to its axis slug, or None for synthetic aggregates / no match.

    Order: explicit id override → AST-class map (most-severe axis) → surface fallback.
    """
    fid = finding.id
    if fid in _AXIS_BY_ID:
        return _AXIS_BY_ID[fid]
    axes = {_AXIS_BY_AST[c] for c in ast_for(fid) if c in _AXIS_BY_AST}
    if axes:
        for ax in _AXIS_PRECEDENCE:
            if ax in axes:
                return ax
    meta = BY_ID.get(fid)
    if meta is not None and meta.surface:
        return _SURFACE_AXIS.get(meta.surface)
    return None


def _worst(findings: list):
    """The finding with the worst (highest-ranked) status, or None if empty."""
    if not findings:
        return None
    return max(findings, key=lambda f: _STATUS_RANK.get(f.status, 0))


def _danger_coverage_gap(danger_bucket: list, ctx) -> bool:
    """True iff the Danger axis is UNKNOWN *because scanning hit a coverage limit* —
    e.g. a payload padded past the per-skill/500-file scan cap in collector.py — rather
    than the benign "nothing to scan" UNKNOWN (no code, no MCP servers, etc.).

    B-092: those two UNKNOWN flavors must not be conflated. "Nothing to scan" is a
    legitimately clean result and stays excluded from scoring as before. "Scan coverage
    hit a limit" means real content may exist and was never looked at — that is not
    benign, so the caller floors the headline grade instead of letting it read A/SAFE.

    Primary signal: ``ctx.limit_hits`` (collector.py appends to it on every size/file/
    nesting cap hit). Falls back to matching the bucket's own UNKNOWN finding detail text
    when no ctx is attached (e.g. a hand-built Finding in a unit test) — the checks engine's B13
    limit-hit branch always phrases it "coverage is incomplete".
    """
    if not danger_bucket:
        return False
    if any(s.status == UNKNOWN for s in danger_bucket) and getattr(ctx, "limit_hits", None):
        return True
    return any(
        f.status == UNKNOWN and "coverage is incomplete" in (f.detail or "")
        for f in danger_bucket
    )


def _normalize_pool(engine_output) -> list:
    """Flatten an engine's return into a single finding pool.

    skill / plugin / source return a primary Finding carrying `.ring_findings`; mcp
    returns a list. PLUGIN-VET is a container: its dispatched sub-findings ride on
    `.ring_findings`, so flattening surfaces them for bucketing (the container id itself
    maps to None and is dropped from axes).
    """
    if isinstance(engine_output, list):
        return list(engine_output)
    primary = engine_output
    return [primary, *getattr(primary, "ring_findings", [])]


def _route_axis_reasons(f, buckets: dict, *, fallback_axis: str | None) -> bool:
    """Route a multi-reason verdict into axes via its own `.axis_reasons`.

    Shared by MCP-VET (vet_mcp) and PLUGIN-VET (vet_plugin): both tag `.axis_reasons` as
    ``{axis: [[status, reason], ...]}``; each axis gets a view of the finding with only
    its reasons and its own worst severity — so e.g. an unpinned MCP spec lands under
    Build (WARN) while a wildcard-env passthrough lands under Connections, instead of
    everything reading as Danger. Returns whether anything was routed.

    `fallback_axis`: when no reasons were routed, bucket the whole finding there instead
    (conservative, never falsely clean) — MCP-VET falls back to "danger" (a clean or
    unparseable verdict still carries real signal). PLUGIN-VET passes ``None``: an empty
    `.axis_reasons` there means the container carried no signal of its own beyond its
    already-flattened, already-bucketed dispatched sub-findings (B-149), so it is simply
    dropped, same as before this routing existed.
    """
    reasons = getattr(f, "axis_reasons", None) or {}
    routed = False
    for axis, entries in reasons.items():
        if axis not in buckets or not entries:
            continue
        worst = FAIL if any(e[0] == FAIL for e in entries) else WARN
        detail = "; ".join(str(e[1]) for e in entries)
        buckets[axis].append(dc_replace(f, status=worst, detail=detail))
        routed = True
    if not routed and fallback_axis is not None:
        buckets[fallback_axis].append(f)
    return routed


def _skill_capabilities(ctx) -> tuple[bool, set]:
    """(has_executable_code, reachable_capability_families) for the vetted skill(s).

    Reads only ctx data populated by the engine (ctx.effect_profiles from F-018,
    ctx.installed_skill_py) — no re-scan, no checks import. Families are the raw effect
    names: network / exec / write / read / eval / cred.
    """
    if ctx is None:
        return (False, set())
    installed = getattr(ctx, "installed_skills", None) or {}
    py_map = getattr(ctx, "installed_skill_py", None) or {}
    effect_profiles = getattr(ctx, "effect_profiles", None) or {}
    has_py = any(py_map.get(name) for name in installed)
    families: set[str] = set()
    for name in installed:
        for ep in effect_profiles.get(name, []):
            for eff in ep.get("reachable_effects", []):
                families.add(eff)
    return (has_py, families)


def _reason_and_fix(bucket: list, axis: str, *, empty_reason: str) -> tuple[str, str]:
    worst = _worst(bucket)
    # B-160: "SKILL_ARCHIVE_PATH_TRAVERSAL" carries a real detail/fix like FAIL does —
    # without it here the axis grades F but the rendered reason falls back to the
    # generic "no malware signature" text instead of the actual traversal detail.
    if worst is not None and worst.status in (FAIL, WARN, UNKNOWN, "SKILL_ARCHIVE_PATH_TRAVERSAL"):
        return (worst.detail, worst.fix)
    return (empty_reason, "")


def _axis_status(bucket: list, applicable: bool, *, no_signal_status: str) -> str:
    """Roll a bucket up to an axis status.

    Not applicable → N/A. Otherwise the worst finding status, or `no_signal_status` when
    the bucket is empty (PASS when the producer looked and found nothing; UNKNOWN when the
    producer could not measure this axis at all).
    """
    if not applicable:
        return NA
    worst = _worst(bucket)
    if worst is None:
        return no_signal_status
    if worst.status == "SKILL_ARCHIVE_PATH_TRAVERSAL":
        # B-160: a real known-bad signal, not an honesty exclusion — grade it as FAIL
        # even though scoring.py's separately-scored audit deliberately excludes it.
        return FAIL
    return worst.status


def build_profile(engine_output, target: str, target_type: str) -> VetProfile:
    """Aggregate an engine's Findings into a VetProfile for `target_type`.

    `engine_output` is the engine's existing return: a Finding (skill/plugin/source) or a
    list[Finding] (mcp). No engine is modified — this only re-reads and re-groups.
    """
    pool = _normalize_pool(engine_output)
    applicability = _AXIS_APPLICABILITY.get(target_type, _AXIS_APPLICABILITY["skill"])

    if not pool:
        # Degenerate: nothing was produced — honest "not assessable", never a fake PASS.
        axes = [
            AxisResult(a, NA if not applicability.get(a, True) else UNKNOWN,
                       _na_reason(a, target_type) if not applicability.get(a, True)
                       else "nothing to assess")
            for a in AXES
        ]
        return VetProfile(target, target_type, UNKNOWN, "N/A", 0, axes, [], [])

    # Bucket every finding into an axis (or unmapped / decomposed-container).
    buckets: dict[str, list] = {a: [] for a in AXES}
    unmapped: list[str] = []
    for f in pool:
        ax = axis_for(f)
        if ax is not None:
            buckets[ax].append(f)
        elif f.id == "PLUGIN-VET":
            # Container aggregate: its dispatched sub-findings ride on .ring_findings and
            # are already flattened into the pool, so they bucket on their own. The
            # container's OWN signal (manifest sanity / npm lifecycle scripts / floating
            # deps / skills-entry escape / native stowaways — B-149) is never carried by a
            # sub-finding, so it rides on .axis_reasons instead and is routed here; no
            # fallback bucket when empty, since an empty .axis_reasons means the container
            # itself found nothing beyond what its sub-findings already bucketed.
            _route_axis_reasons(f, buckets, fallback_axis=None)
        elif f.id == "MCP-VET":
            # Per-reason routing (danger/build/behavior/connections) is populated on
            # .axis_reasons by the MCP engine; until then, keep the whole verdict on the
            # danger axis so a dangerous server can never read as falsely clean.
            _route_axis_reasons(f, buckets, fallback_axis="danger")
        else:
            # A real finding that maps nowhere is a coverage gap we surface, never swallow.
            unmapped.append(f.id)

    # Per-type capability signal (skill/plugin code analysis) enriches connections /
    # persistence: it decides PASS ("looked, clean") vs UNKNOWN ("no code to measure").
    ctx = getattr(pool[0], "ctx", None) if pool else None
    has_code, families = _skill_capabilities(ctx)
    code_measurable = has_code or target_type not in ("skill", "plugin")
    # Was anything actually assessed? A definite finding (PASS/WARN/FAIL) anywhere, or —
    # for a skill/plugin — content that was read. If the artifact is missing / unreadable /
    # empty (only UNKNOWN findings, e.g. "no MCP servers"), the empty axes must read
    # UNKNOWN, never a fabricated PASS/grade.
    assessed = any(f.status in (PASS, WARN, FAIL) for f in pool) or (
        target_type in ("skill", "plugin") and bool(getattr(ctx, "installed_skills", None))
    )

    axes: list[AxisResult] = []
    for axis in AXES:
        applicable = applicability.get(axis, True)
        bucket = buckets[axis]
        if not assessed:
            no_signal = UNKNOWN
        elif axis in ("connections", "persistence"):
            no_signal = PASS if code_measurable else UNKNOWN
        else:
            no_signal = PASS
        status = _axis_status(bucket, applicable, no_signal_status=no_signal)
        if not applicable:
            reason, fix = _na_reason(axis, target_type), ""
        elif status == PASS:
            reason, fix = _clean_reason(axis, families), ""
        elif status == UNKNOWN and not bucket:
            reason, fix = _unmeasurable_reason(axis), ""
        else:
            reason, fix = _reason_and_fix(bucket, axis, empty_reason=_clean_reason(axis, families))
        axes.append(AxisResult(axis=axis, status=status, reason=reason, fix=fix, findings=list(bucket)))

    danger_coverage_gap = _danger_coverage_gap(buckets["danger"], ctx)
    overall_status, score, grade = _grade_profile(axes, danger_coverage_gap=danger_coverage_gap)
    return VetProfile(
        target=target,
        target_type=target_type,
        overall_status=overall_status,
        overall_grade=grade,
        score=score,
        axes=axes,
        findings=pool,
        unmapped=unmapped,
    )


def _grade_profile(axes: list, *, danger_coverage_gap: bool = False) -> tuple[str, int, str]:
    """Roll axis results up to (overall_status, score, grade). Reuses scoring.grade_for.

    ``danger_coverage_gap`` (B-092): the Danger axis reads UNKNOWN not because there was
    nothing to scan, but because scanning hit a size/file cap — a payload padded past the
    cap could be hiding unscanned. That must never roll up to a confident "A / SAFE"
    headline one line above the axis's own "coverage incomplete" note, so it is treated
    like a real non-danger-axis problem: WARN-equivalent overall status (→ verdict
    SUSPICIOUS, the existing non-SAFE word — no new verdict enum value) and the same
    grade ceiling a HIGH finding gets, never A/B.
    """
    by_axis = {a.axis: a for a in axes}

    # Danger floor: a confirmed-dangerous artifact is F, full stop.
    danger = by_axis.get("danger")
    if danger is not None and danger.status == FAIL:
        return (FAIL, 0, "F")

    scorable = [a for a in axes if a.status in (PASS, WARN, FAIL)]  # exclude N/A + UNKNOWN
    if not scorable:
        if danger_coverage_gap:
            # Every axis is otherwise N/A/UNKNOWN, but the Danger scan itself was
            # incomplete — that is not the honest "nothing to assess" N/A; it is a real
            # coverage gap on the floor axis, so it gets the same ceiling a HIGH finding
            # would (never a fabricated N/A / SAFE).
            return (WARN, _COVERAGE_GAP_DANGER_CAP, grade_for(_COVERAGE_GAP_DANGER_CAP))
        # Nothing measurable (e.g. source with only N/A axes, or an unreadable target).
        return (UNKNOWN, 0, "N/A")

    earned = sum(1.0 if a.status == PASS else 0.5 if a.status == WARN else 0.0 for a in scorable)
    score = round(earned / len(scorable) * 100)
    # Caps keep the grade coherent with the verdict word (a WARN is never "A").
    if any(a.status == WARN for a in scorable):
        score = min(score, _WARN_CAP)
    if any(a.status == FAIL for a in scorable):
        score = min(score, _NON_DANGER_FAIL_CAP)
    if danger_coverage_gap:
        score = min(score, _COVERAGE_GAP_DANGER_CAP)
    grade = grade_for(score)

    if any(a.status == FAIL for a in axes):
        overall = FAIL
    elif any(a.status == WARN for a in axes) or danger_coverage_gap:
        overall = WARN
    elif any(a.status == PASS for a in axes):
        overall = PASS
    else:
        overall = UNKNOWN
    return (overall, score, grade)


# ── Reason phrasing (English-only, project law §9) ────────────────────────────
def _clean_reason(axis: str, families: set) -> str:
    if axis == "danger":
        return "no malware signature or known-bad indicator"
    if axis == "build":
        return "no least-privilege, pinning, or authoring-hygiene issue found"
    if axis == "behavior":
        return "no override, jailbreak, or forged-provenance directive found"
    if axis == "persistence":
        return "no dormant or staged code detected"
    if axis == "connections":
        if "network" in families:
            return "reaches the network for its stated purpose; no exfiltration signal"
        return "no outbound network surface"
    return "no issue found"


def _unmeasurable_reason(axis: str) -> str:
    if axis == "connections":
        return "no executable code to analyze for outbound connections"
    if axis == "persistence":
        return "no executable code to analyze for staged / persistent behavior"
    return "not measurable"


def _na_reason(axis: str, target_type: str) -> str:
    if target_type == "mcp" and axis == "persistence":
        return "a live server spec stores no on-disk code — not applicable"
    if target_type == "source":
        return "identity-only reputation gate — the artifact is not fetched, so this is not assessable"
    return "not applicable for this artifact type"
