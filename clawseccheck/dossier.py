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

# ── Scan-coverage vocabulary (shared by every consumer) ───────────────────────
# The wording `checks/_vet.py:coverage_gap_finding` puts in the detail of the synthetic
# UNKNOWN it emits when part of a target was never inspected. Named once here because
# TWO consumers key on it — this module's `_danger_coverage_gap` and `cli.py`'s
# `_vet_coverage_incomplete` — and they used to carry two copies of the literal.
COVERAGE_GAP_PROSE = "coverage is incomplete"

# The extensions the DEEP-CODE layer actually reads: an exact mirror of the three
# collector readers' own filters (`read_skill_python` → .py/.ipynb,
# `read_skill_shell` → .sh/.bash/.zsh, `read_skill_js` → .js/.ts/.mjs/.cjs). Anything
# outside this set reaches the regex/prose content ring — `_read_skill_text`
# concatenates every TEXT-classified file regardless of extension — but never reaches
# skillast, the taint engine, or the effect profiles that populate
# `ctx.installed_skill_py` / `ctx.effect_profiles`. Kept here as documentation of the
# boundary the two sets below are defined against; not itself consulted at runtime.
_DEEP_ANALYZED_EXTS = frozenset({
    ".py", ".ipynb", ".sh", ".bash", ".zsh", ".js", ".ts", ".mjs", ".cjs",
})

# B-485 route 4, TIER 1 — "unrouted": a file the existing analyzer WOULD have handled,
# withheld from it by nothing but its suffix. Python is read from `.py`, so a
# `payload.pyw` (valid Python; `ast.parse` reads it unchanged) is Python the AST/taint
# layer never saw; `skillast.analyze_shell` and the JS rules are regex passes over
# source text, so `.ksh/.csh/.fish` and `.cts/.mts` are equally within their reach. A
# ROUTING gap, not a capability limit — the analyzer exists AND works on these bytes —
# and it is precisely the rename-to-blind-the-scanner evasion, so it floors the verdict
# (see `_danger_coverage_gap`).
#
# The membership test is "would the analyzer we already have work on this file?", which
# is why `.pyx` is NOT here: Cython is not Python, `ast.parse` cannot read `cdef`, and a
# `.pyx` renamed to `.py` would come back as a parse error — already covered by the
# engine_degraded leg. It sits in tier 2 instead.
#
# FP measured before choosing that severity, on the 35,035 real published skills in the
# ClawBench corpus: **0** skills carry any extension in this set (0.000%). Also 0 of the
# 307 skill directories in `fixtures/` + the installed fleet. `.jsx`/`.tsx` satisfy the
# membership test above and are still deliberately NOT here: they hit 78 of those 35,035
# skills (0.223%), essentially all React templates, and a CAUTION — which `--vet` turns
# into rc=1, an install gate — on 78 benign packages is not shippable. That exception is
# the rule this set is governed by: measurement outranks the principle, so re-measure
# before adding an extension rather than reasoning about whether it "should" be rare.
_UNROUTED_CODE_EXTS = frozenset({
    ".pyw", ".pyi",                      # Python — read_skill_python takes .py/.ipynb
    ".ksh", ".csh", ".tcsh", ".fish",    # shell  — read_skill_shell takes .sh/.bash/.zsh
    ".cts", ".mts",                      # TS     — read_skill_js takes .js/.ts/.mjs/.cjs
})

# TIER 2 — "unanalyzed": a language this tool has NO deep analyzer for at all. The file
# was still read and regex/prose-scanned (proved: a `.rb` carrying a pipe-to-shell from
# a non-reputable host still FAILs B13), so the Danger verdict over it is a real ring
# result, not a fabrication — but it never got taint analysis, reachability, or an
# effect profile, and the Persistence/Connections axes must stop claiming there was "no
# executable code to analyze" when a Ruby or PowerShell program is sitting in the tree.
#
# Disclosure only — NO verdict floor, deliberately. This is a permanent, structural
# limit of the scanner (there is no PowerShell/Ruby/PHP analyzer to route to), so
# flooring on it would park 141 of 35,035 real skills (0.402% — 132 of them ordinary
# `.ps1` installers) at CAUTION forever, with no action the owner could take to clear
# it. A caveat the user cannot act on and that never changes is noise, not a finding;
# the honest form is a stated coverage boundary, which is what this produces.
_UNANALYZED_LANG_EXTS = frozenset({
    ".ps1", ".psm1",                                  # PowerShell
    ".bat", ".cmd",                                   # Windows batch
    ".vbs", ".vbe", ".wsf", ".hta",                   # Windows Script Host
    ".rb", ".rake", ".gemspec",                       # Ruby
    ".pl", ".pm",                                     # Perl
    ".php", ".phtml",                                 # PHP
    ".pyx",                                           # Cython — ast.parse cannot read it
    ".lua", ".r", ".jl", ".tcl", ".groovy", ".awk",   # misc interpreters
    ".applescript", ".scpt",                          # AppleScript
    ".jsx", ".tsx",                                   # JS-family, see the 0.223% note above
})

# Human-readable language name per extension, for the disclosure sentence. Naming the
# LANGUAGE (not just the suffix) is what makes the note actionable: "1 file this scanner
# does not analyze (PowerShell)" tells the reader what to go read by hand.
_LANG_BY_EXT: dict[str, str] = {
    ".pyw": "Python", ".pyi": "Python", ".pyx": "Cython",
    ".ksh": "shell", ".csh": "shell", ".tcsh": "shell", ".fish": "shell",
    ".cts": "TypeScript", ".mts": "TypeScript",
    ".ps1": "PowerShell", ".psm1": "PowerShell",
    ".bat": "Windows batch", ".cmd": "Windows batch",
    ".vbs": "VBScript", ".vbe": "VBScript", ".wsf": "Windows Script Host",
    ".hta": "HTML application",
    ".rb": "Ruby", ".rake": "Ruby", ".gemspec": "Ruby",
    ".pl": "Perl", ".pm": "Perl",
    ".php": "PHP", ".phtml": "PHP",
    ".lua": "Lua", ".r": "R", ".jl": "Julia", ".tcl": "Tcl",
    ".groovy": "Groovy", ".awk": "awk",
    ".applescript": "AppleScript", ".scpt": "AppleScript",
    ".jsx": "JSX", ".tsx": "TSX",
}

# How many file names a disclosure sentence names before eliding.
_GAP_FILES_SHOWN = 3


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


def scan_gap_disclosed(f) -> bool:
    """True when finding `f` ITSELF discloses that the scan did not cover its target.

    This is the one per-finding coverage-gap test in the codebase. Both consumers call
    it — this module's `_danger_coverage_gap` (which grades) and `cli.py`'s
    `_vet_coverage_incomplete` (which decides the ``--vet-all`` row state and tally).
    They ask different *questions* — "is the Danger axis's verdict complete?" vs "did
    this sweep row inspect all of its target?" — but the atom underneath is identical,
    and until B-485 they were two hand-written copies of it that had already drifted:
    `cli.py`'s docstring claimed to mirror this module while matching only the English
    substring, so the `engine_degraded` leg added here on 2026-08-14 reached the grade
    and never reached the sweep tally. A parse-error skill printed "could not assess"
    and was then counted in "1 safe".

    Two legs, in the order of how much they know:

    1. ``Finding.engine_degraded`` — catalog.py's single source of truth for "this
       UNKNOWN is engine-side": the check ran, tried for a verdict, and could not for a
       reason on OUR side. Structural; survives any rewording.
    2. The literal ``COVERAGE_GAP_PROSE`` in ``.detail``. A DOCUMENTED FALLBACK for
       hand-built ``Finding`` objects in unit tests that carry neither a real ctx nor
       the flag. Never the primary: matching English means a producer that rewords its
       detail silently loses the signal.
    """
    if getattr(f, "status", None) != UNKNOWN:
        return False
    if getattr(f, "engine_degraded", False):
        return True
    return COVERAGE_GAP_PROSE in (getattr(f, "detail", "") or "")


def code_coverage_gaps(ctx) -> tuple[list[str], list[str]]:
    """``(unrouted, unanalyzed)`` — the target's code files the deep layer never read.

    B-485 route 4. ``ctx.file_manifest`` is the collector's own record of every file it
    collected for this target and what it did with it, so this reads a fact the run
    already established rather than re-walking the tree (this module does not scan —
    see the module docstring).

    The split is by whether the miss was a routing gap or a capability limit; see
    ``_UNROUTED_CODE_EXTS`` / ``_UNANALYZED_LANG_EXTS`` for the measured reasoning and
    the FP numbers that set each tier's severity. Both lists are sorted so the rendered
    sentence is deterministic across runs.

    NOT a re-implementation of "was there code?": ``_skill_capabilities`` answers that
    from ``ctx.installed_skill_py``, which by construction only ever holds ``.py`` —
    which is exactly why it answered "no executable code to analyze" over a skill whose
    only script was ``post_install.pyw``. This function is the missing other half of
    that question, and its result is what stops that sentence being printed as fact.
    """
    manifest = getattr(ctx, "file_manifest", None) or {}
    unrouted: list[str] = []
    unanalyzed: list[str] = []
    for relpath in manifest:
        ext = relpath[relpath.rfind("."):].lower() if "." in relpath else ""
        if ext in _UNROUTED_CODE_EXTS:
            unrouted.append(relpath)
        elif ext in _UNANALYZED_LANG_EXTS:
            unanalyzed.append(relpath)
    return (sorted(unrouted), sorted(unanalyzed))


def vet_scan_incomplete(f) -> bool:
    """True when a ``vet_*`` result `f` did not fully inspect its target.

    The consumer-level predicate: `scan_gap_disclosed` over the whole result (the
    primary finding AND its ``.ring_findings``, since a worse WARN/FAIL can outrank a
    coverage UNKNOWN into the ring pool — see ``checks/_vet.py``'s ``_VET_MERGE_RANK``),
    plus the route-4 leg for code the deep layer was never handed.

    Only ``unrouted`` (tier 1) counts here, matching `_danger_coverage_gap`: a target is
    "partially scanned" for the sweep tally on the same evidence that stops it reading
    INSTALL, so the narrative row and the dossier verdict can never disagree about
    whether the same skill was fully covered.
    """
    pool = [f, *(getattr(f, "ring_findings", None) or [])]
    if any(scan_gap_disclosed(fx) for fx in pool):
        return True
    unrouted, _unanalyzed = code_coverage_gaps(getattr(f, "ctx", None))
    return bool(unrouted)


def _danger_coverage_gap(danger_bucket: list, ctx) -> bool:
    """True iff the Danger verdict rests on a scan that could not COVER what is there —
    rather than on the benign "there was nothing to scan" (no code, no MCP servers, a
    docs-only skill), which is a legitimately clean result.

    B-092: those two must not be conflated. "Could not read / could not finish reading /
    was never handed to the analyzer" means real content exists and was not analyzed —
    so the caller floors the headline instead of letting it read INSTALL.

    Legs, in the order of how much they know:

    0. ``code_coverage_gaps(ctx)[0]`` — a file in a language this tool analyzes that was
       never routed to the analyzer (B-485 route 4; see `_UNROUTED_CODE_EXTS`). This one
       is deliberately evaluated FIRST and OUTSIDE the "is the bucket UNKNOWN?" gate
       below, because it is the only leg that fires while the Danger axis reads **PASS**:
       the regex/prose ring did read the file and found nothing, so a finding exists and
       it is a clean one. That was route 4's whole shape — a positive fabricated clean,
       not a silence. Byte-identical `bad_b13_fetch_to_exec` payload: `.py` →
       DO-NOT-INSTALL, `.pyw` → INSTALL / rc=0 with "no malware signature" over it,
       because `read_skill_python` only takes `.py` so the taint chain never ran.
       Unlike the 2026-08-08 retraction recorded in `checks/_vet.py`'s ring handler —
       which turned on whether OUR interpreter could parse a file, and so gave opposite
       verdicts for the same bytes on 3.9 and 3.12 — a file extension is a stable fact
       about the tree. Same bytes, same verdict, every interpreter.
    1. ``scan_gap_disclosed`` on an UNKNOWN in the bucket — the producer flagged it
       engine-side (or, fallback, said so in prose). See that function.
    2. ``ctx.limit_hits`` — collector.py appends on every size/file/nesting cap hit and
       on an unreadable file (``note_limit``), which is how B13's own cap and
       unreadable-file branches disclose a truncated scan.

    Tier 2 (`_UNANALYZED_LANG_EXTS` — a language with no analyzer at all) is NOT a leg
    here: it is disclosed on the axis reasons and never floors the verdict. The measured
    reason is on that constant; the short form is that flooring a permanent capability
    limit would put 0.402% of real skills at CAUTION forever with no remedy available to
    their owners.

    Measured FP for leg 0 on the 35,035-skill ClawBench corpus of real published skills:
    **0** (0.000%), and 0 across `fixtures/` + the installed fleet. Measured FP for leg 1
    when it landed: 0 of 16 real installed skills on both 3.12 and the 3.9 CI floor, and
    1 of ~1,119 fixture targets (``fixtures/unknown_b347_deaddrop_unparseable``, the
    fixture whose name declares it UNKNOWN).

    Known residuals, NOT closed here — all three need a producer change, not a predicate
    one. (a) A ring check that raises is swallowed by ``_run_content_ring``'s bare
    ``except``, emitting no finding at all; an empty bucket carries no signal any
    predicate can read. (b) A binary blob excluded from scanning discloses no coverage
    gap (it reaches the headline only via the separate stowaway WARN). (c) Leg 0
    DISCLOSES the unrouted file; it does not analyze it. The actual close is widening the
    three reader filters in ``collector.py`` so `.pyw` reaches `read_skill_python` — that
    file is owned elsewhere, and until it changes a `.pyw` payload is reported as
    uncovered, not as detected.
    """
    # (0) route 4 — fires even when the bucket's worst finding is a PASS.
    unrouted, _unanalyzed = code_coverage_gaps(ctx)
    if unrouted:
        return True
    if not danger_bucket:
        return False
    unknowns = [f for f in danger_bucket if f.status == UNKNOWN]
    if not unknowns:
        return False
    # (1) structural, per finding: the producer flagged this UNKNOWN as engine-side
    #     (with the documented prose fallback for hand-built test Findings).
    if any(scan_gap_disclosed(f) for f in unknowns):
        return True
    # (2) structural, per run: the collector recorded a cap hit / unreadable file.
    return bool(getattr(ctx, "limit_hits", None))


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
    has_code, families = _skill_capabilities(ctx)
    code_measurable = has_code or target_type not in ("skill", "plugin")
    # Was anything actually assessed? A definite finding (PASS/WARN/FAIL) anywhere, or —
    # for a skill/plugin — content that was read. If the artifact is missing / unreadable /
    # empty (only UNKNOWN findings, e.g. "no MCP servers"), the empty axes must read
    # UNKNOWN, never a fabricated PASS/grade.
    assessed = any(f.status in (PASS, WARN, FAIL) for f in pool) or (
        target_type in ("skill", "plugin") and bool(getattr(ctx, "installed_skills", None))
    )

    # B-485 route 4: code the deep layer was never handed. Read once here; it qualifies
    # the Danger reason, replaces the "no executable code" sentences, and (tier 1 only)
    # floors the verdict via `_danger_coverage_gap`.
    unrouted, unanalyzed = code_coverage_gaps(ctx)

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
            if axis == "danger" and (unrouted or unanalyzed):
                # The ring genuinely looked and found nothing, so the finding is real —
                # but it did not cover these files as code, and "no malware signature"
                # alone reads as a completed clean. Qualify it, and for tier 1 stop
                # calling it a PASS at all: the analyzer for that language exists and
                # simply was not run, which is the rename-to-blind-the-scanner evasion.
                reason = f"{reason} — {_gap_phrase(unrouted, unanalyzed)}"
                if unrouted:
                    status = UNKNOWN
        elif status == UNKNOWN and not bucket:
            reason, fix = _unmeasurable_reason(axis, unrouted, unanalyzed), ""
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
        if "network" in families:
            # E-065/C-322: the prior wording ("reaches the network for its stated
            # purpose") claimed this axis had verified the network use matches the
            # skill's declared purpose — it never did; PASS here means only that no
            # bucketed finding fired, an absence, not a positive alignment check.
            return "no exfiltration signal found"
        return "no outbound network surface"
    return "no issue found"


def _gap_phrase(unrouted: list, unanalyzed: list) -> str:
    """Name what the deep-code layer did not read, in one clause.

    Deliberately states BOTH halves of the truth: the files were read and content-ring
    scanned (they were — `_read_skill_text` concatenates every TEXT file whatever its
    extension), and they were not analyzed as code. Saying only "not scanned" would be a
    fresh false statement in the opposite direction, which Golden Rule #4 forbids just as
    firmly as the claim this replaces.
    """
    files = unrouted + unanalyzed
    langs = sorted({_LANG_BY_EXT.get(p[p.rfind("."):].lower(), "unknown") for p in files})
    shown = ", ".join(files[:_GAP_FILES_SHOWN])
    if len(files) > _GAP_FILES_SHOWN:
        shown += f", +{len(files) - _GAP_FILES_SHOWN} more"
    return (
        f"{len(files)} bundled file(s) were text-scanned but NOT analyzed as code "
        f"({'/'.join(langs)}): {shown}"
    )


def _unmeasurable_reason(axis: str, unrouted: list = (), unanalyzed: list = ()) -> str:
    """Why an axis could not be measured.

    B-485 route 4: the bare "no executable code to analyze" sentences below are a claim
    about the ARTIFACT, and they were being printed over skills that ship a working
    program — because `_skill_capabilities` derives "has code" from
    ``ctx.installed_skill_py``, which by construction only ever contains ``.py``. A
    `post_install.pyw`, a `setup.ps1`, an `install.rb`: each produced "no executable code
    to analyze for staged / persistent behavior" with that code sitting in the tree, and
    that is a fabricated fact, not a cautious one. When such files exist, state what was
    actually not done instead. The axis STATUS is unchanged (UNKNOWN either way) — this
    is the honest reason for an already-honest status, so it costs nothing in the
    false-positive direction on any target.
    """
    if unrouted or unanalyzed:
        return _gap_phrase(list(unrouted), list(unanalyzed))
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
