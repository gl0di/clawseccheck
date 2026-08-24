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
from .skillast import capability_families

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

# Overall verdict word, keyed by overall_status (mirrors report._VET_VERDICT). Used ONLY
# by the --full pipeline's own analyst-facing surfaces (the Inventory subject block, the
# plugin sweep) -- those are a different feature from Mode C ("before you install") and
# are unaffected by C427; kept for that reason.
VERDICT_WORD: dict[str, str] = {
    FAIL: "DANGEROUS",
    WARN: "SUSPICIOUS",
    PASS: "NO KNOWN ISSUE",
    UNKNOWN: "UNKNOWN",
}

# C427: Mode C's own vocabulary -- unifies what --vet/--vet-plugin/--vet-mcp/--vet-source/
# --vet-all/--advise all say. --advise shipped this vocabulary first (F-067); Mode C's
# text dossier previously spoke VERDICT_WORD above PLUS an A-F letter -- both are retired
# from every Mode C rendered surface in favor of this one.
_MODE_C_VERDICT: dict[str, str] = {
    FAIL: "DO-NOT-INSTALL",
    WARN: "CAUTION",
    PASS: "INSTALL",
    UNKNOWN: "CAUTION",
}


def verdict_for(overall_status: str) -> str:
    """Map a VetProfile's `overall_status` to Mode C's install-recommendation word.

    `overall_status` is itself the categorical rollup `_grade_profile` derives from the
    same axis pass that produces the (now internal-only) numeric score/grade -- a Danger
    FAIL floors score to 0/F, a non-danger FAIL or a Danger-axis coverage gap caps score
    at 79/C, any remaining WARN caps at 89/B, and an all-clean profile scores 100/A -- so
    this only has to translate the category, not re-derive a threshold on the raw number:

        FAIL    -> DO-NOT-INSTALL  (a real known-bad or floored/capped failure)
        WARN    -> CAUTION         (a real caveat somewhere -- never "A"-equivalent)
        PASS    -> INSTALL         (nothing found across every assessable axis)
        UNKNOWN -> CAUTION         (not assessable -- never presented as a green light)

    This is the ONE place that mapping is made: the text dossier, --json, --advise, and
    SARIF's vetProfile all read `VetProfile.verdict` (computed once, in `build_profile`,
    via this function) rather than keeping their own copy -- so they cannot disagree.
    Any status this dict doesn't recognize (defensive only -- `_grade_profile` never
    returns one) also reads CAUTION, the conservative default.
    """
    return _MODE_C_VERDICT.get(overall_status, "CAUTION")

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
    "B338": "connections",  # covert tunnel / mesh-VPN enrollment = outbound channel (E-065)
    "B339": None,  # cloud IMDS credential fetch — dual-axis via axis_reasons (E-065/C-322)
    "SOURCE-VET": "danger",  # reputation gate is a pure danger/identity verdict
    # F-148: the content ring was cut short by the scan budget, so part of the skill was
    # never assessed. Mapped to danger deliberately — the ring feeds several axes, but
    # danger is the only one carrying a coverage-gap lever (_danger_coverage_gap /
    # _COVERAGE_GAP_DANGER_CAP), and under-reporting an unscanned skill is the failure
    # this exists to prevent. Unmapped, it would land in `unmapped`, which is cosmetic
    # and never reaches _grade_profile — a truncated scan would keep grading A.
    "VET-COVERAGE": "danger",
    "PLUGIN-VET": None,  # container aggregate — decomposed into its sub-findings
    "MCP-VET": None,  # multi-reason verdict — routed per-reason via axis_reasons
    # C-255: pre-install prose-attestation findings (adjudication.py) — a declared-
    # purpose mismatch, an injected/manipulative instruction, or an attempt to talk
    # the reviewing agent into trusting the skill are all manipulation/override
    # concerns, the same category AST05 (behavior) already covers.
    "ATTEST-PROSE-MISMATCH": "behavior",
    "ATTEST-PROSE-INJECTION": "behavior",
    "ATTEST-PROSE-SOCIAL-ENG": "behavior",
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
# B-092 / B-485: a Danger-axis UNKNOWN caused by a coverage gap — content that exists but
# was never covered, whether because a payload was padded past the per-skill/500-file scan
# cap, a file could not be read, or the AST layer could not parse it — must never read as
# "A / SAFE". Cap it at the top of the C band, same ceiling scoring.py gives a real HIGH
# finding. See `_danger_coverage_gap` for how that state is detected.
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
    # C427: the ONE Mode C verdict word -- "INSTALL" | "CAUTION" | "DO-NOT-INSTALL",
    # computed once here (via `verdict_for`) and read by every renderer (text dossier,
    # --json, --advise, SARIF's vetProfile) instead of each recomputing its own mapping.
    verdict: str
    # C427: `overall_grade` and `score` are INTERNAL ONLY from here down -- Mode C (the
    # --vet/--advise family) no longer renders an A-F letter or the raw number on any
    # surface (text dossier, --json, --advise, SARIF's vetProfile); they collided with
    # Mode A's own system-audit grade, a different scale about a different question. The
    # fields stay because _grade_profile's coverage-gap cap machinery (well-tested,
    # untouched by C427) and existing unit tests key off them directly. No renderer may
    # print either field -- call `verdict_for(overall_status)` instead.
    overall_grade: str  # A..F, or "N/A" when nothing is assessable -- NEVER rendered
    score: int  # 0..100 (0 when not assessable) -- NEVER rendered
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
    """True iff the Danger axis is UNKNOWN because scanning could not COVER what is
    there — rather than the benign "there was nothing to scan" UNKNOWN (no code, no MCP
    servers, a docs-only skill).

    B-092: those two UNKNOWN flavors must not be conflated. "Nothing to scan" is a
    legitimately clean result and stays excluded from scoring as before. "Could not read
    / could not finish reading what is there" means real content may exist and was never
    looked at — so the caller floors the headline instead of letting it read INSTALL.

    Three legs, in order. The first two are STRUCTURAL — a flag a producer set, or a
    counter the collector bumped — and are the primary signal:

    1. ``Finding.engine_degraded`` on an UNKNOWN in the bucket. catalog.py defines this
       field as "the single source of truth for 'this UNKNOWN is engine-side'": the check
       ran, tried to reach a verdict, and could not for a reason on OUR side (a crash, a
       budget escape, an input that turned out unreadable/unparseable). That is precisely
       this predicate's question, already answered by the producer.
    2. ``ctx.limit_hits`` — collector.py appends to it on every size/file/nesting cap hit
       and on an unreadable file (``note_limit``), which is how B13's own cap and
       unreadable-file branches disclose a truncated scan.
    3. The literal ``"coverage is incomplete"`` phrasing in an UNKNOWN's ``detail``. This
       is a DOCUMENTED FALLBACK ONLY, kept for hand-built ``Finding`` objects in unit
       tests that carry neither a real ``ctx`` nor the flag (see
       ``tests/test_b092_coverage_gap.py``). It must never be the primary: matching
       English prose means any producer that rewords its detail silently loses the
       signal, and any producer that never used that wording never had it.

    B-485: leg 1 is new and is what closes the reported route. B13's parse-error branch
    (checks/_vet.py) already sets ``engine_degraded=True`` on its UNKNOWN — "could not
    analyze <file> — parse error(s); file(s) not scanned by the AST/taint layer" — but it
    calls no ``note_limit`` and does not use the phrase leg 3 keys on, so a skill whose
    bundled script the AST layer could not read rolled all the way up to INSTALL, one
    line under the Danger axis printing that it never got to look. The same hole covered
    every future producer of an engine-side UNKNOWN that happens not to hit a collector
    cap; keying on the flag closes the class, not the one instance.

    Measured FP direction before landing leg 1 (the flip set = targets where this returns
    True and the pre-B-485 predicate returned False): 0 of 16 real installed skills on
    BOTH python3.12 and the python3.9 CI floor; 1 of ~1,119 fixture targets, namely
    ``fixtures/unknown_b347_deaddrop_unparseable`` — the fixture whose name declares it
    UNKNOWN. No narrower trigger and no WARN-instead-of-floor variant is warranted at
    that rate, so this floors like the other legs.

    Known residual, NOT closed here (both need a producer change, not a predicate one):
    a ring check that raises is swallowed by ``_run_content_ring``'s bare ``except``,
    which emits no finding at all — an empty bucket carries no signal for any predicate
    to read; and a binary blob excluded from scanning discloses no coverage gap (it
    reaches the headline only via the separate stowaway WARN).
    """
    if not danger_bucket:
        return False
    unknowns = [f for f in danger_bucket if f.status == UNKNOWN]
    if not unknowns:
        return False
    # (1) structural, per finding: the producer flagged this UNKNOWN as engine-side.
    if any(getattr(f, "engine_degraded", False) for f in unknowns):
        return True
    # (2) structural, per run: the collector recorded a cap hit / unreadable file.
    if getattr(ctx, "limit_hits", None):
        return True
    # (3) documented prose fallback — hand-built Findings with no ctx and no flag.
    return any("coverage is incomplete" in (f.detail or "") for f in unknowns)


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
    """(has_executable_code, capability_families_PRESENT) for the vetted skill(s).

    Reads only ctx data populated by the engine (ctx.installed_skill_py) — no re-scan of
    disk, no checks import. Families are `skillast.CAPABILITY_FAMILIES`: network / exec /
    write / read / cred.

    B-592: this used to return the union of `ctx.effect_profiles[*]["reachable_effects"]`,
    which is TAINT reachability — "did untrusted data reach this sink". The only consumer
    is `_clean_reason`'s wording choice, and against that question taint is the wrong
    predicate: a skill whose entire body is
    `urllib.request.urlopen("https://collector.example.net/ping")` taints nothing, so the
    axis fell through to "no outbound network surface" — an assertion that the artifact
    has no network capability, printed on the pre-install gate, about a skill that exists
    to make an outbound call. Presence is the predicate that sentence needs. The taint
    view is untouched and still lives where it belongs (the findings themselves, and
    `--emit-manifest`'s `analysis:` block).
    """
    if ctx is None:
        return (False, set())
    installed = getattr(ctx, "installed_skills", None) or {}
    py_map = getattr(ctx, "installed_skill_py", None) or {}
    has_py = any(py_map.get(name) for name in installed)
    families: set[str] = set()
    for name in installed:
        families |= capability_families(py_map.get(name))
    return (has_py, families)


def _pool_capabilities(pool) -> tuple[bool, set]:
    """(has_executable_code, capability_families) folded over every Context in ``pool``.

    B-628: ``build_profile`` used to ask this of ``pool[0].ctx`` alone. On the skill path
    that is the whole story -- ``pool[0]`` is ``vet_skill``'s primary and ``_vet.py`` sets
    ``primary.ctx = ctx`` on it. On the PLUGIN path ``pool[0]`` is the ``PLUGIN-VET``
    container built by ``_plugin_finding``, which never sets ``.ctx``, so ``has_code`` was
    ``False`` **by construction for every plugin ever vetted** -- and the Persistence and
    Connections axes printed "no executable code to analyze" about plugins whose bundled
    Python the same dossier convicted on the danger axis four lines above.

    Two sources, because one is not enough and an earlier version of this function
    claimed otherwise:

    * ``f.ctx`` on any pool member. Note that ``_vet.py`` sets this on the PRIMARY only --
      ring findings are pool members since B-614 but carry no ctx of their own.
    * ``f.bundled_contexts`` on the plugin container. This is the one that matters for the
      COMMON case: ``vet_plugin``'s ``actionable`` filter keeps only FAIL/WARN/UNKNOWN
      sub-findings, so a bundled skill that vets **PASS is dropped from the pool entirely**
      and takes its ctx with it. Reading only ``.ctx`` therefore fixed the dirty plugin and
      left the clean one exactly as broken -- found by C-135 adversarial review, not by
      the tests, which had paired a dirty positive with a prose-only negative and so could
      not tell "no code" apart from "code we dropped".

    A plugin bundling only prose contributes no context from either source and still folds
    to ``False``, so the honest UNKNOWN is preserved -- that is the negative control this
    must never break.

    Deliberately narrow: the ``ctx`` variable in ``build_profile`` is left pointing at
    ``pool[0]`` for its two other consumers (``assessed`` and ``_danger_coverage_gap``).
    Those are blind on the plugin path for the same missing-attribute reason, and fixing
    them moves a score cap rather than a sentence -- a separate change with its own
    measurement.
    """
    has_code = False
    families: set = set()
    seen: list = []
    for f in pool:
        for ctx in [getattr(f, "ctx", None), *(getattr(f, "bundled_contexts", None) or [])]:
            if ctx is None or any(ctx is s for s in seen):
                continue
            seen.append(ctx)
            code, fams = _skill_capabilities(ctx)
            has_code = has_code or code
            families |= fams
    return (has_code, families)


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
        return VetProfile(target, target_type, UNKNOWN, verdict_for(UNKNOWN), "N/A", 0, axes, [], [])

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
        elif f.id == "B339":
            # E-065/C-322: B339 (cloud IMDS credential fetch) is FAIL-only and, on FAIL,
            # sets .axis_reasons to BOTH danger (so the F floor at _grade_profile still
            # applies — this is as unambiguously malicious as B13's malware verdict) and
            # connections (the specific axis the HF-incident review exists to make
            # honest — before this routing, a credential-stealing skill's Connections
            # axis silently read PASS because nothing bucketed there). Its non-FAIL
            # (PASS/UNKNOWN) branches leave .axis_reasons empty and fall through here
            # unchanged onto "connections" — the natural single axis for "no exfil
            # signal found" — never onto "danger", which would misfile an ordinary clean
            # result under the malware-verdict axis.
            _route_axis_reasons(f, buckets, fallback_axis="connections")
        else:
            # A real finding that maps nowhere is a coverage gap we surface, never swallow.
            unmapped.append(f.id)

    # Per-type capability signal (skill/plugin code analysis) enriches connections /
    # persistence: it decides PASS ("looked, clean") vs UNKNOWN ("no code to measure").
    ctx = getattr(pool[0], "ctx", None) if pool else None
    # B-628: folded over the WHOLE pool, not pool[0] -- a plugin container carries no ctx
    # of its own, so asking it alone made every plugin answer "no executable code".
    has_code, families = _pool_capabilities(pool)
    # B-628 / C-135: finding code in ONE bundled skill must not license an affirmative
    # "no dormant or staged code detected" over content the scan never opened.
    #
    # The predicate is the synthetic `VET-COVERAGE` id -- `coverage_gap_finding`'s, whose
    # whole purpose is to say "part of this target was never inspected" (both its legs:
    # the ring's budget ceiling and vet_plugin's tree-sweep file cap). Round 2 of C-135
    # killed two weaker predicates, and both failures are worth keeping written down:
    #
    #   * `engine_degraded` alone is too WIDE. B13's parse-error branch sets it per FILE
    #     on a scan that otherwise COMPLETED, so a skill shipping one unparseable file
    #     read "the scan was cut short" -- a fresh false sentence, on the skill path this
    #     change claimed not to touch. Measured across all 292 shipped fixture skill
    #     roots, exactly one flipped that way.
    #   * gating the WORDING on `has_code` is backwards. `has_code` is precisely what a
    #     truncated scan fails to establish, so the corner the wording was added for --
    #     scan truncated, code present but unseen -- still printed "no executable code to
    #     analyze". Reviewer's repro reached it at the DEFAULT 900s budget through the
    #     file cap, with no clock pressure at all.
    scan_truncated = any(
        getattr(f, "id", None) == "VET-COVERAGE" and f.status == UNKNOWN for f in pool
    )
    # C-135 round 3: `has_code` answers "did any analysed context contain Python", which
    # is NOT authority to assert PASS over the whole artifact. On the plugin path the
    # sweep has no reader for .py outside a dispatched skill dir, so a plugin whose only
    # dangerous file is a root-level install.py had `has_code=True` (from a clean bundled
    # skill), nothing truncated, and printed "no dormant or staged code detected" over
    # fetch-to-exec. Measured against the pre-change tree: those axes read UNKNOWN before
    # and PASS after, so this was introduced here, not inherited.
    unread_code = [f for fx in pool for f in (getattr(fx, "unanalysed_code", None) or [])]
    code_measurable = (
        (has_code and not scan_truncated and not unread_code)
        or target_type not in ("skill", "plugin")
    )
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
            reason, fix = _unmeasurable_reason(
                axis, truncated=scan_truncated, unanalysed=bool(unread_code)), ""
        else:
            reason, fix = _reason_and_fix(bucket, axis, empty_reason=_clean_reason(axis, families))
        axes.append(AxisResult(axis=axis, status=status, reason=reason, fix=fix, findings=list(bucket)))

    danger_coverage_gap = _danger_coverage_gap(buckets["danger"], ctx)
    overall_status, score, grade = _grade_profile(axes, danger_coverage_gap=danger_coverage_gap)
    return VetProfile(
        target=target,
        target_type=target_type,
        overall_status=overall_status,
        verdict=verdict_for(overall_status),
        overall_grade=grade,
        score=score,
        axes=axes,
        findings=pool,
        unmapped=unmapped,
    )


def _grade_profile(axes: list, *, danger_coverage_gap: bool = False) -> tuple[str, int, str]:
    """Roll axis results up to (overall_status, score, grade). Reuses scoring.grade_for.

    C427: the returned ``grade`` (and ``score``) are an INTERNAL quantity from here on --
    no renderer may print either. They still exist because the coverage-gap cap below is
    well-tested and expressed as a number (``min(score, _COVERAGE_GAP_DANGER_CAP)``), and
    rewriting that as verdict-tier logic for a presentation-only change would touch
    working logic for no reason. Every rendered surface instead calls
    ``verdict_for(overall_status)`` (defined above `VetProfile`), which derives the
    install-recommendation word directly from ``overall_status`` -- do not re-expose
    ``grade``/``score`` to a renderer; that is exactly the "two different A's on two
    different scales" bug C427 removed.

    ``danger_coverage_gap`` (B-092, widened by B-485): the Danger axis reads UNKNOWN not
    because there was nothing to scan, but because content that IS there was never
    covered — padded past a size/file cap, unreadable, or unparseable by the AST layer.
    That must never roll up to a confident "A / SAFE" headline one line above the axis's
    own "could not analyze" note, so it is treated like a real non-danger-axis problem:
    WARN-equivalent overall status (→ verdict CAUTION, the existing non-clean word — no
    new verdict enum value) and the same grade ceiling a HIGH finding gets, never A/B.
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
        # Both branches state what this axis DID, never what the artifact is. E-065/C-322
        # already removed one such claim here ("reaches the network for its stated
        # purpose" asserted an alignment check that never ran); B-592 removes the other
        # two. "no exfiltration signal found" was false whenever the exfil finding fired
        # and routed to the Danger axis instead — a DO-NOT-INSTALL screen carried it next
        # to "credential-file contents flow into a network sink". And "no outbound
        # network surface" asserted the ABSENCE of a capability nothing had measured
        # (see `_skill_capabilities`), on the screen a user reads to decide whether to
        # install. Neither sentence can be repaired by widening detection: they were
        # describing the wrong subject.
        if "network" in families:
            return "outbound network calls present; no connection-axis finding fired"
        return "no outbound network call found in the analysed code"
    return "no issue found"


def _unmeasurable_reason(axis: str, *, truncated: bool = False,
                        unanalysed: bool = False) -> str:
    """Why an axis could not be measured -- and the three reasons are not one reason.

    B-628: "no executable code to analyze" is a claim about the ARTIFACT, and it is false
    whenever code is present. Two distinct ways it can be present and still unmeasured:

    * ``truncated`` -- the scan started and stopped early (budget, file cap, JS size cap).
    * ``unanalysed`` -- the scan ran to completion and there was simply no reader for the
      file. C-135 round 3: `vet_plugin` analyses .json, native headers and JS/TS, while
      Python is analysed only inside a dispatched skill dir. A plugin shipping
      fetch-to-exec as a root-level `install.py` is opened by nobody, and the reviewer
      measured this axis printing an affirmative PASS over exactly that.

    Truncation wins the wording when both hold: "we stopped early" already implies the
    rest is unknown, while naming an unread file would suggest the rest WAS read.
    """
    if truncated:
        if axis == "connections":
            return "the scan was cut short before the outbound surface could be measured"
        if axis == "persistence":
            return "the scan was cut short before staged / persistent behavior could be measured"
        return "the scan was cut short before this could be measured"
    if unanalysed:
        if axis == "connections":
            return ("executable code is present that this scan has no reader for, so the "
                    "outbound surface was not measured")
        if axis == "persistence":
            return ("executable code is present that this scan has no reader for, so "
                    "staged / persistent behavior was not measured")
        return "executable code is present that this scan has no reader for"
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
