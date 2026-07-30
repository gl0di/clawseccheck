"""``--full`` pipeline orchestration — the phases that run after the report body.

``--full`` is no longer "audit + self-test + vet-mcp": it is a pipeline whose later
phases each answer a question the audit itself cannot. This module owns the phases that
run *after* the human report body has been rendered, plus the roll-up that turns them
into one combined result:

======  =========================  ==============================================
phase   what                       who runs it
======  =========================  ==============================================
P6      installed-skill sweep      ``cli.py`` (already landed); RECORDED here
P7      installed-plugin sweep     here, via ``checks/_mcp.sweep_plugins``
P8      behavioural replay         here, via ``behavioral.render_behavioral_analysis``
P9      adjudication               here, via ``adjudication.build_judge_packet`` &c.
P10     combined render / roll-up  here (``render_sections`` / ``quiet_lines`` /
                                   ``PipelineResult.to_json``)
======  =========================  ==============================================

**Layer 3.** It consumes the checks engine, the renderers and ``adjudication``; it is
imported only by ``cli.py`` and must never import it back. That constraint is what
decides the P6 split below.

**Why P6 is recorded rather than run here.** The installed-skill sweep
(``cli.sweep_installed_skills``) lives in the Layer-4 shell, because it narrates as it
goes. Calling it from here would be a ``pipeline -> cli`` import, i.e. a cycle. So the
caller runs P6 exactly as it always has — byte-identical output, byte-identical
ordering — and hands the finished sweep to :func:`record_skill_sweep`, which folds it
into the same phase ledger as the phases this module does run. Nothing about P6's
behaviour changes; it simply becomes visible in ``phases[]`` / ``complete`` /
``notScanned[]`` alongside the rest.

**Honest degradation is the whole point** (Golden Rule #4). Four states are modelled
distinctly and none of them is ever allowed to read as a clean pass:

``ran``          the phase executed and its result is below.
``skipped``      the operator asked for it to be skipped (``--fast``).
``not_reached``  the pipeline deadline passed before this phase started.
``unavailable``  this build does not carry an implementation of the phase.
``error``        the phase raised; the failure is reported, never swallowed.

A phase that did not run **still prints its section header** and one line saying so.
Silence would be indistinguishable from "nothing to report", which is exactly the
guessed-PASS this project forbids.

**No waiting, ever.** The adjudication phase emits a packet for a host agent to answer
and returns immediately. There is no ``input()``, no ``sys.stdin.read()``, no
``time.sleep``, no ``select`` and no wait-for-verdicts timeout anywhere in this module:
``--full`` in CI has no agent, and an unanswered judge is a *pending* state, not a
failing one. It never moves the score, the grade or the exit code.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .attest import template as attest_template
from .behavioral import render_behavioral_analysis
from .report import _sanitize
from .scanbudget import (
    DEFAULT_FULL_BUDGET_S, DEFAULT_VET_ALL_BUDGET_S, budget_deadline, budget_exceeded,
)
from .trajaudit import render_trajectory_analysis

# ── phase identity ───────────────────────────────────────────────────────────

PHASE_SKILL_SWEEP = "skill_sweep"
PHASE_PLUGIN_SWEEP = "plugin_sweep"
PHASE_BEHAVIORAL = "behavioral"
PHASE_ADJUDICATION = "adjudication"

#: Execution order. The roll-up preserves it so ``phases[]`` reads as a timeline.
PHASE_ORDER = (
    PHASE_SKILL_SWEEP,
    PHASE_PLUGIN_SWEEP,
    PHASE_BEHAVIORAL,
    PHASE_ADJUDICATION,
)

STATUS_RAN = "ran"
STATUS_SKIPPED = "skipped"
STATUS_NOT_REACHED = "not_reached"
STATUS_UNAVAILABLE = "unavailable"
STATUS_ERROR = "error"

#: Statuses that mean "this phase cannot vouch for anything" — they make the run
#: incomplete. ``ran`` is the only status that does not, and even then the phase's own
#: ``complete`` flag can still be False (a sweep that hit its budget mid-fleet).
_INCOMPLETE_STATUSES = frozenset({
    STATUS_SKIPPED, STATUS_NOT_REACHED, STATUS_UNAVAILABLE, STATUS_ERROR,
})

# Section banners. Deliberately distinct strings from the two banners --full already
# prints ("CLAWSECCHECK SELF-TEST" / "CLAWSECCHECK VET-MCP"), which the --quiet
# collapse test asserts are ABSENT from quiet output — a new banner that contained
# either as a substring would break that assertion from the far side.
_SECTION_TITLE = {
    PHASE_SKILL_SWEEP: "SKILL SWEEP",
    PHASE_PLUGIN_SWEEP: "PLUGIN SWEEP",
    PHASE_BEHAVIORAL: "BEHAVIORAL REPLAY",
    PHASE_ADJUDICATION: "ADJUDICATION",
}

# The one-line prefix each phase uses in --full --quiet, mirroring the existing
# "SELF-TEST:" / "VET-MCP:" / "SKILL SWEEP:" summary lines.
_QUIET_PREFIX = _SECTION_TITLE

#: The symbol ``checks/_mcp.py`` is expected to expose for P7. Resolved by NAME at call
#: time rather than imported at module load, so this file needs no edit when the plugin
#: sweep lands: adding ``sweep_plugins`` to that module is the whole change, and until
#: then P7 reports ``unavailable`` honestly instead of failing to import.
PLUGIN_SWEEP_ATTR = "sweep_plugins"

#: Upper bound on a ``--judged-bundle`` file. A bundle carries one own-config verdicts
#: object plus one per swept target, so it is allowed to be larger than a single
#: ``--judged`` payload (2 MB) — but it is still untrusted input and still bounded.
MAX_BUNDLE_BYTES = 8_000_000


# ── budget ───────────────────────────────────────────────────────────────────

def start_deadline(budget_s: float = DEFAULT_FULL_BUDGET_S) -> float | None:
    """Open the pipeline's wall-clock window; ``None`` disables the cap.

    Call this once, at the top of ``--full``'s appended-section block, so the time the
    earlier phases spend is charged against the same window the later ones draw from.
    """
    return budget_deadline(budget_s)


def remaining_s(deadline: float | None) -> float:
    """Seconds left on ``deadline``. ``float('inf')`` when uncapped, never negative."""
    if deadline is None:
        return float("inf")
    return max(deadline - time.monotonic(), 0.0)


def sub_budget(deadline: float | None, phase_default: float) -> float:
    """A phase's budget: ``min(its own default, what is left of the pipeline's)``.

    This reproduces, **cooperatively**, the "an inner block is implicitly clamped to the
    outer's remaining time" property that ``scanbudget.check_deadline`` gets from its
    stack of absolute deadlines — as a plain monotonic float, and deliberately NOT by
    nesting a real ``check_deadline`` block.

    That is mandatory, not stylistic. A nested ``SIGALRM`` arm's disarm-on-exit would
    *delete the outer deadline* rather than bound the call, so from the moment the inner
    block returned nothing could interrupt a hung scan for the rest of the run — the
    exact fail-open the vet paths already document and avoid the same way. The pipeline
    must not reintroduce it one layer up.

    Deadline checks therefore happen **between** phases, never inside one: a phase
    already underway always finishes rather than being cut off part-way through.
    """
    left = remaining_s(deadline)
    if left == float("inf"):
        return phase_default
    return min(phase_default, left)


# ── one phase's outcome ──────────────────────────────────────────────────────

@dataclass
class PhaseResult:
    """What one pipeline phase did, with no rendering baked in.

    Separating the outcome from its rendering is what lets the verbose section, the
    ``--quiet`` one-liner and the ``--json`` payload all read a single run — and, the
    reason it is a requirement rather than a preference, what makes ``has_fail``
    provably identical on the quiet and verbose branches instead of two hand-written
    tallies that can disagree.
    """

    name: str
    status: str
    elapsed_s: float = 0.0
    #: False when the phase could not account for everything it is responsible for.
    complete: bool = True
    #: One plain-English sentence: what happened, and what was NOT done.
    detail: str = ""
    #: Every target this phase cannot vouch for, named. No silent caps here.
    not_scanned: list[str] = field(default_factory=list)
    #: FAIL-only, mirroring the vet-mcp / skill-sweep contribution to ``--exit-code``.
    has_fail: bool = False
    #: Verbose section body (without the banner, which :func:`render_sections` adds).
    lines: list[str] = field(default_factory=list)
    #: The ``--full --quiet`` one-liner. Empty means "use ``detail``".
    quiet_line: str = ""
    #: Machine-readable payload for ``--full --json``, or None.
    data: object = None
    #: True when this module renders the section itself. False for a phase the caller
    #: already printed (P6 when it ran) — recorded here, rendered there.
    section: bool = True

    @property
    def ran(self) -> bool:
        return self.status == STATUS_RAN

    def to_json(self) -> dict:
        """The ``phases[]`` entry. Prose is sanitized; nothing here is terminal-bound."""
        return {
            "name": self.name,
            "status": self.status,
            # Wall-clock, so this key is NOT byte-stable across two runs. It is the one
            # deliberately non-deterministic value in the payload; every verdict-bearing
            # key beside it is deterministic. Rounded so a diff of two runs shows a
            # small, obviously-timing delta rather than float noise.
            "elapsed_s": round(self.elapsed_s, 3),
            "complete": self.complete,
            "detail": _sanitize(self.detail),
            "notScanned": [_sanitize(n) for n in self.not_scanned],
        }


def _skipped(name: str, reason: str, *, section: bool = True) -> PhaseResult:
    return PhaseResult(name=name, status=STATUS_SKIPPED, complete=False,
                       detail=reason, section=section)


def _not_reached(name: str, budget_s: float) -> PhaseResult:
    return PhaseResult(
        name=name, status=STATUS_NOT_REACHED, complete=False,
        detail=(f"not run — the {budget_s:g}s pipeline budget was already spent before "
                "this phase started. Nothing here was inspected."),
    )


# ── P6: installed-skill sweep (run by the caller, recorded here) ─────────────

def record_skill_sweep(sweep, *, elapsed_s: float = 0.0) -> PhaseResult:
    """Fold an already-executed installed-skill sweep into the phase ledger.

    ``sweep`` is whatever ``cli.sweep_installed_skills`` returned. Only its published
    surface is read (``no_roots`` / ``no_targets`` / ``counts()`` / ``has_fail`` /
    ``complete`` / ``not_scanned()``), so this stays a contract rather than a reach into
    the caller's internals.

    **Duck-typed on purpose — do NOT "fix" this into an import.** The obvious tidy-up is
    ``from .cli import SkillSweep`` for a type annotation. That is a Layer 3 -> Layer 4
    import, i.e. an import cycle, because ``cli`` imports this module. The same reasoning
    applies to P7 in the other direction: ``checks/_mcp`` is Layer 2 and equally cannot
    import ``SkillSweep`` from the Layer-4 shell, so the plugin sweep will return its own
    type. Structural typing is what lets one set of roll-up code serve both without
    dragging the sweep dataclass down a layer — a relocation deliberately not attempted
    here, since it would rewrite landed, output-pinned code for a cosmetic gain.

    ``section=False``: the caller has already printed this phase's section in its
    established position and byte-for-byte shape. Re-rendering it here would duplicate
    it; recording it is what makes it visible in ``phases[]``.
    """
    if sweep is None:
        return _skipped(PHASE_SKILL_SWEEP, "not run.", section=False)
    if sweep.no_roots:
        detail = "no skills directory found — nothing to sweep."
    elif sweep.no_targets:
        detail = "no installed skills found — nothing to sweep."
    else:
        c = sweep.counts()
        detail = (f"{c['total']} installed skill(s) vetted — {c['fails']} dangerous, "
                  f"{c['warns']} suspicious, {c['safe']} no known issue")
        if c["truncated"]:
            detail += f", {c['truncated']} partially scanned"
        if c["skipped"]:
            detail += f", {c['skipped']} not scanned (budget exceeded)"
        detail += "."
    return PhaseResult(
        name=PHASE_SKILL_SWEEP,
        status=STATUS_RAN,
        elapsed_s=elapsed_s,
        complete=bool(sweep.complete),
        detail=detail,
        not_scanned=list(sweep.not_scanned()),
        has_fail=bool(sweep.has_fail),
        section=False,
    )


# ── P7: installed-plugin sweep ───────────────────────────────────────────────

def resolve_plugin_sweep():
    """The installed-plugin sweep callable, or ``None`` when this build has none.

    Looked up by name on ``clawseccheck.checks._mcp`` rather than imported at module
    load. Two properties follow, and both are the point:

    * this module needs **no edit** when the sweep lands — defining
      ``sweep_plugins(home_dir, sweep_budget_s=..., narrate=...)`` in that module is the
      entire change; and
    * until it lands, P7 degrades to a printed, honest ``unavailable`` line instead of
      an ImportError at startup.

    The expected return value is duck-typed on the installed-skill sweep's published
    surface (``no_roots`` / ``no_targets`` / ``counts()`` / ``has_fail`` / ``complete``
    / ``not_scanned()``) — see :func:`_sweep_phase_from`.
    """
    try:
        from . import checks as _checks  # noqa: PLC0415 — deferred on purpose, see above
        mcp = getattr(_checks, "_mcp", None)
    except Exception:  # noqa: BLE001 — a missing optional phase must never break --full
        return None
    fn = getattr(mcp, PLUGIN_SWEEP_ATTR, None)
    return fn if callable(fn) else None


def _sweep_phase_from(name: str, sweep, *, unit: str, elapsed_s: float,
                      full_detail_flag: str) -> PhaseResult:
    """Build a :class:`PhaseResult` from any sweep exposing the published surface."""
    if sweep.no_roots:
        detail = f"no {unit} directory found — nothing to sweep."
        lines = [detail]
    elif sweep.no_targets:
        detail = f"no installed {unit}s found — nothing to sweep."
        lines = [detail]
    else:
        c = sweep.counts()
        detail = (f"{c['total']} installed {unit}(s) vetted — {c['fails']} dangerous, "
                  f"{c['warns']} suspicious, {c['safe']} no known issue")
        if c.get("truncated"):
            detail += f", {c['truncated']} partially scanned"
        if c.get("skipped"):
            detail += f", {c['skipped']} not scanned (budget exceeded)"
        detail += "."
        lines = [detail, f"Full detail: {full_detail_flag}."]
    return PhaseResult(
        name=name,
        status=STATUS_RAN,
        elapsed_s=elapsed_s,
        complete=bool(sweep.complete),
        detail=detail,
        not_scanned=[_sanitize(str(t)) for t in sweep.not_scanned()],
        has_fail=bool(sweep.has_fail),
        lines=lines,
        data=_sweep_data(sweep),
    )


def _sweep_data(sweep) -> dict:
    """Machine-readable roll-up of any sweep, for ``--full --json``."""
    return {
        "no_roots": bool(sweep.no_roots),
        "no_targets": bool(sweep.no_targets),
        "complete": bool(sweep.complete),
        "counts": dict(sweep.counts()),
        "not_scanned": [_sanitize(str(t)) for t in sweep.not_scanned()],
    }


def run_plugin_sweep(home_dir, *, deadline: float | None = None,
                     ascii_only: bool = False) -> PhaseResult:
    """P7 — vet every installed plugin, under the pipeline's remaining budget."""
    fn = resolve_plugin_sweep()
    if fn is None:
        return PhaseResult(
            name=PHASE_PLUGIN_SWEEP,
            status=STATUS_UNAVAILABLE,
            complete=False,
            detail=("the installed-plugin sweep is not available in this build — no "
                    "plugin was inspected. Vet a plugin directly with --vet-plugin."),
        )
    budget_s = sub_budget(deadline, DEFAULT_VET_ALL_BUDGET_S)
    started = time.monotonic()
    try:
        sweep = fn(Path(home_dir), ascii_only=ascii_only,
                   sweep_budget_s=budget_s, narrate=False)
    except Exception as exc:  # noqa: BLE001 — one phase must not take the audit down
        return PhaseResult(
            name=PHASE_PLUGIN_SWEEP, status=STATUS_ERROR, complete=False,
            elapsed_s=time.monotonic() - started,
            detail=(f"the plugin sweep could not complete ({_sanitize(str(exc))}) — no "
                    "plugin verdict below can be relied on."),
        )
    return _sweep_phase_from(PHASE_PLUGIN_SWEEP, sweep, unit="plugin",
                             elapsed_s=time.monotonic() - started,
                             full_detail_flag="--vet-plugin <path>")


# ── P8: behavioural replay ───────────────────────────────────────────────────

def run_behavioral(ctx, *, ascii_only: bool = False) -> PhaseResult:
    """P8 — the behavioural/trajectory detectors, over the audit's OWN ``ctx``.

    Reusing ``ctx`` is not a micro-optimisation: ``trajaudit``'s per-context memo lives
    on that object, so a fresh ``Context`` here would silently discard it and re-pay the
    whole sidecar glob. Passing the audit's context costs zero additional I/O.

    F-151: this phase used to render ONLY ``behavioral.render_behavioral_analysis`` —
    ``trajaudit.render_trajectory_analysis``, the renderer that actually produces the
    ``⚠ INCIDENT SIGNAL`` line, was reachable only from the standalone
    ``--analyze-trajectory`` CLI branch, never from ``--full``. It is appended here as
    an ADDITIONAL block in this SAME phase/section — the existing behavioural block's
    own render is untouched — reusing the identical ``ctx`` so nothing is re-collected.
    A crash in this second renderer degrades to one honest line rather than losing the
    whole phase: the behavioural block above already rendered successfully, and a
    second, independent renderer's failure must not erase it.

    Advisory only, both renderers, w.r.t. ``--exit-code``: this phase reports
    ``has_fail=False`` unconditionally, the same visibility-only contract the skill
    sweep's WARN rows already have — nothing here computes a Finding or sets
    ``has_fail``, so that invariant holds structurally regardless of what either
    renderer prints.

    F-154: the SCORE/GRADE half of that claim is narrower than it used to be. A fired
    T1/T2/T3/B191 detector MAY now cap the A-F grade (never raise it, never earn/cost
    an ordinary scored point) — but that cap is computed by `cli.py`, EARLIER in the
    same `--full` invocation, from its own `behavioral.analyze(ctx)` call (see
    `scoring.BEHAVIORAL_SIGNAL_CAP`), never by this phase's own render. This function
    still never touches `ctx`/scoring itself, and the trajectory-incident renderer
    (`render_trajectory_analysis`, the INCIDENT SIGNAL line) stays advisory-only in
    both directions — its own runtime cap (I-025/RUNTIME_SIGNAL_CAP) is likewise
    computed elsewhere, never here.
    """
    started = time.monotonic()
    try:
        rendered = render_behavioral_analysis(ctx, ascii_only=ascii_only)
    except Exception as exc:  # noqa: BLE001 — see run_plugin_sweep
        return PhaseResult(
            name=PHASE_BEHAVIORAL, status=STATUS_ERROR, complete=False,
            elapsed_s=time.monotonic() - started,
            detail=(f"the behavioural replay could not complete "
                    f"({_sanitize(str(exc))}) — no trajectory was analysed."),
        )
    # C8: trajectory-derived thread labels reach this text, so every line is sanitized
    # before it can reach a terminal. Sanitizing per LINE (not the whole blob) keeps the
    # renderer's own layout intact — _sanitize folds newlines to spaces.
    lines = [_sanitize(ln) for ln in rendered.splitlines()]

    incident = False
    try:
        traj_rendered = render_trajectory_analysis(ctx, ascii_only=ascii_only)
        lines.append("")
        lines.extend(_sanitize(ln) for ln in traj_rendered.splitlines())
        # Structural substring check (not a security-relevant keyword match): the
        # renderer emits the literal phrase "INCIDENT SIGNAL" on both the unicode and
        # --ascii-only branches (only the leading glyph differs), so this cannot miss
        # or over-fire relative to what the lines above already say.
        incident = "INCIDENT SIGNAL" in traj_rendered
    except Exception as exc:  # noqa: BLE001 — see the docstring: must not lose the
                              # behavioural block already rendered above.
        lines.append("")
        lines.append(_sanitize(
            f"trajectory incident analysis could not complete ({exc}) — no trajectory "
            "was analysed."
        ))

    if incident:
        detail = ("trajectory replay complete — an INCIDENT SIGNAL was found in the "
                  "trajectory incident analysis below (that signal itself is advisory "
                  "only; a fired behavioral detector above it may separately have "
                  "capped the grade — see F-154).")
        quiet_line = ("behavioural replay complete — INCIDENT SIGNAL found (advisory). "
                     "Full detail: --analyze-trajectory.")
    else:
        detail = ("trajectory replay complete — a fired behavioral detector may have "
                  "capped the grade (F-154); this replay itself never scores a FAIL.")
        quiet_line = ("behavioural replay complete (advisory). Full detail: --behavioral "
                     "/ --analyze-trajectory.")

    return PhaseResult(
        name=PHASE_BEHAVIORAL,
        status=STATUS_RAN,
        elapsed_s=time.monotonic() - started,
        detail=detail,
        lines=lines,
        quiet_line=quiet_line,
    )


# ── P9: adjudication ─────────────────────────────────────────────────────────

def _vet_packets(vet_targets, *, version: str) -> list[dict]:
    """One judge packet per swept target, each bound to its own resolved path.

    The authority rule flips between buckets, and the buckets are kept structurally
    apart so it cannot be crossed by accident: the single top-level ``judgePacket``
    covers the user's OWN config (advisory, may downgrade), while each entry here
    covers UNTRUSTED third-party content and may only ever escalate. They are never
    merged into one array, and each carries the fingerprint that binds a verdicts file
    to this specific run.
    """
    from .adjudication import (  # noqa: PLC0415 — see the module note on layering
        _vet_run_fingerprint, build_vet_judge_packet,
    )
    packets: list[dict] = []
    for target, engine_output in vet_targets:
        if engine_output is None:
            continue
        try:
            items = build_vet_judge_packet(engine_output, str(target))
            fingerprint = _vet_run_fingerprint(str(target))
        except Exception:  # noqa: BLE001 — one unpackageable target must not lose the rest
            continue
        packets.append({
            "target": _sanitize(Path(str(target)).name or str(target)),
            "targetFingerprint": fingerprint,
            "judgePacket": items,
        })
    packets.sort(key=lambda p: (p["target"], p["targetFingerprint"]))
    return packets


def _vet_second_opinion(vet_targets, vet_judged: list) -> list[dict]:
    """F-152: escalate-only second opinion for the untrusted ``vetJudged`` bucket.

    The authority split from ``_vet_packets``'s own docstring holds here too, and this
    is the function that enforces it for ``--full``: ``judged`` (the sibling bucket,
    handled entirely by ``adjudication._second_opinion`` in :func:`run_adjudication`)
    may only ANNOTATE the user's OWN config — it never reaches this function at all.
    This bucket covers UNTRUSTED swept content and may only ever ESCALATE, which is
    delegated entirely to ``adjudication.escalate_vet_output`` — the exact, already
    fingerprint-checked, already-tested function the standalone ``--vet-judged`` CLI
    path uses — so this wiring cannot invent a softer or looser rule than that path
    already enforces.

    **Binding is by ``targetFingerprint`` ONLY, never by name** (C-135, 2026-07-22,
    documented at length on ``adjudication._vet_run_fingerprint``): two different vet
    targets can share a bare name, so matching on it would let a verdicts entry meant
    for one target apply to a different one. Each ``vet_targets`` entry's OWN
    fingerprint is computed fresh here and looked up directly — there is no name-keyed
    fallback path for an entry whose fingerprint matches no actual swept target to fall
    into; it is simply never selected, i.e. rejected wholesale, exactly like a
    fingerprint mismatch already degrades to "no verdicts submitted" in the standalone
    path.

    A malformed or hostile entry (unserializable, or one whose escalation raises) is
    skipped — one bad target must never lose the rest, mirroring every other per-target
    loop in this module (:func:`_vet_packets`, :func:`run_plugin_sweep`).
    """
    if not vet_judged:
        return []
    from .adjudication import (  # noqa: PLC0415 — see the module note on layering
        _vet_pool, _vet_run_fingerprint, _vet_target_name, escalate_vet_output,
    )

    by_fingerprint: dict[str, dict] = {}
    for entry in vet_judged:
        fp = entry.get("targetFingerprint")
        # First entry for a given fingerprint wins; a duplicate is simply ignored —
        # this is advisory, untrusted input, never a crash (split_judged_bundle's own
        # contract), and there is no ordering guarantee worth picking a "later wins"
        # rule over for it.
        if isinstance(fp, str) and fp and fp not in by_fingerprint:
            by_fingerprint[fp] = entry

    rows: list[dict] = []
    for target, engine_output in vet_targets:
        if engine_output is None:
            continue
        entry = by_fingerprint.get(_vet_run_fingerprint(str(target)))
        if entry is None:
            continue
        try:
            verdicts_raw = json.dumps(entry)
        except (TypeError, ValueError):
            continue
        try:
            escalated = escalate_vet_output(engine_output, verdicts_raw, target=str(target))
        except Exception:  # noqa: BLE001 — one bad target must not lose the rest
            continue
        target_name = _sanitize(_vet_target_name(str(target)))
        # escalate_vet_output preserves the ORIGINAL pool's order and length, only ever
        # appending new pre-install-attestation findings past it (adjudication.py's own
        # docstring) — zip() over the shorter (original) length is therefore exactly
        # "compare each original finding against its own escalated self", never a
        # misalignment, and it naturally excludes the appended tail from this
        # already-existing-finding comparison.
        before = _vet_pool(engine_output)
        after = _vet_pool(escalated)
        for f_before, f_after in zip(before, after):
            if f_after.status == f_before.status:
                continue
            rows.append({
                "finding_id": _sanitize(str(f_after.id)),
                "target": target_name,
                "engine_disposition": _sanitize(str(f_before.status)),
                "judge_verdict": _sanitize(str(f_after.status)),
                "annotation": _sanitize(
                    f"engine: {f_before.status} -> escalated to {f_after.status} by "
                    "host-agent judge (vetJudged, escalate-only)"
                ),
            })
    return rows


def run_adjudication(ctx, findings, *, vet_targets=(), version: str = "",
                     bundle: dict | None = None) -> PhaseResult:
    """P9 — assemble the judge packet, and fold in a submitted bundle if there is one.

    Emit-and-return: this phase never waits for an answer. With no bundle it reports
    how many items are awaiting adjudication and how to produce the packet; that is a
    *pending* state, neither a pass nor a failure, and it never moves the grade.

    Cheap by construction — it re-runs no check, reading only the already-computed
    ``findings`` and the already-built ``ctx``. That is why there is no ``--no-judge``:
    there would be nothing to opt out of.
    """
    from .adjudication import (  # noqa: PLC0415 — see the module note on layering
        _parse_verdicts, _second_opinion, build_judge_packet,
    )
    started = time.monotonic()
    try:
        packet = build_judge_packet(ctx, findings)
    except Exception as exc:  # noqa: BLE001 — see run_plugin_sweep
        return PhaseResult(
            name=PHASE_ADJUDICATION, status=STATUS_ERROR, complete=False,
            elapsed_s=time.monotonic() - started,
            detail=(f"the judge packet could not be assembled "
                    f"({_sanitize(str(exc))}) — nothing was offered for adjudication."),
        )
    packets = _vet_packets(vet_targets, version=version)
    vet_item_total = sum(len(p["judgePacket"]) for p in packets)

    data: dict = {
        "judgePacket": packet,
        "vetPackets": packets,
        "attestTemplate": attest_template(),
        "verdictsSubmitted": False,
    }
    lines: list[str] = []
    if packet or packets:
        lines.append(
            f"{len(packet)} own-config item(s) and {vet_item_total} item(s) across "
            f"{len(packets)} swept target(s) are in the borderline band."
        )
    else:
        lines.append("Nothing is in the borderline band — no item needs adjudication.")

    second_opinion: list[dict] = []
    if bundle and bundle.get("judged") is not None:
        verdicts_map = _parse_verdicts(json.dumps(bundle["judged"]))
        try:
            second_opinion = _second_opinion(ctx, findings, verdicts_map)
        except Exception:  # noqa: BLE001 — an advisory panel must never break the run
            second_opinion = []
        data["secondOpinion"] = second_opinion
        data["verdictsSubmitted"] = True
        reviewed = sum(1 for row in second_opinion if row.get("judge_verdict"))
        lines.append(
            f"{reviewed} of {len(second_opinion)} borderline item(s) carry a submitted "
            "verdict. Advisory only: the grade and the findings above are unchanged."
        )
        for row in second_opinion[:12]:
            lines.append(
                f"  - {_sanitize(str(row.get('finding_id')))} "
                f"[{_sanitize(str(row.get('target')))}]: "
                f"{_sanitize(str(row.get('annotation')))}"
            )
        if len(second_opinion) > 12:
            lines.append(f"  - (+{len(second_opinion) - 12} more)")
        quiet_line = (f"{reviewed} of {len(second_opinion)} borderline item(s) judged "
                      "(advisory; grade unchanged).")
        detail = quiet_line
    else:
        lines.append(
            "No verdicts submitted — these item(s) are awaiting adjudication. Produce "
            "the packet with: --full --json; return the answers with: "
            "--full --judged-bundle <file>."
        )
        detail = (f"{len(packet) + vet_item_total} item(s) awaiting adjudication — no "
                  "verdicts submitted.")
        quiet_line = detail + " Produce the packet with: --full --json."

    # F-152: vetJudged — the SECOND, structurally separate authority bucket. `judged`
    # above may only ANNOTATE (adjudication._second_opinion never touches a Finding's
    # status); this bucket may only ESCALATE, and only for the swept target whose OWN
    # targetFingerprint the entry actually matches — see _vet_second_opinion's
    # docstring for the full binding rule. Deliberately a SEPARATE code path and a
    # SEPARATE data key from `judged`/secondOpinion above, never merged into one list:
    # an own-config annotation and an untrusted-content escalation must never be
    # representable as the same kind of row.
    vet_judged = bundle.get("vetJudged") if bundle else None
    if vet_judged:
        try:
            vet_second_opinion = _vet_second_opinion(vet_targets, vet_judged)
        except Exception:  # noqa: BLE001 — an advisory panel must never break the run
            vet_second_opinion = []
        data["vetSecondOpinion"] = vet_second_opinion
        data["verdictsSubmitted"] = True
        if vet_second_opinion:
            lines.append(
                f"{len(vet_second_opinion)} vet-target finding(s) ESCALATED by a "
                "submitted vetJudged verdict (escalate-only — untrusted swept content "
                "can never downgrade a finding this way)."
            )
            for row in vet_second_opinion[:12]:
                lines.append(
                    f"  - {row['finding_id']} [{row['target']}]: "
                    f"{row['engine_disposition']} -> {row['judge_verdict']}"
                )
            if len(vet_second_opinion) > 12:
                lines.append(f"  - (+{len(vet_second_opinion) - 12} more)")
            vet_quiet = f"{len(vet_second_opinion)} vet-target finding(s) escalated."
        else:
            lines.append(
                "vetJudged verdicts were submitted, but none escalated any swept "
                "target's finding (no targetFingerprint matched a currently swept "
                "target, or every submitted verdict was SAFE/unrecognized)."
            )
            vet_quiet = "0 vet-target finding(s) escalated."
        quiet_line = f"{quiet_line} {vet_quiet}"
        detail = quiet_line

    return PhaseResult(
        name=PHASE_ADJUDICATION,
        status=STATUS_RAN,
        elapsed_s=time.monotonic() - started,
        detail=detail,
        lines=lines,
        quiet_line=quiet_line,
        data=data,
    )


# ── phase 2: the judged bundle ───────────────────────────────────────────────

def split_judged_bundle(raw: str) -> dict:
    """Split a ``--judged-bundle`` payload into its four independent buckets.

    Returns ``{"attestation": obj|None, "judged": obj|None, "vetJudged": [...],
    "liveTest": obj|None}``.

    Bounded and never raises — this is untrusted input, and it is advisory data that
    must never be able to crash or otherwise perturb the audit itself. Anything
    malformed simply yields an absent bucket.

    Splitting first, then handing each piece to the *existing* hardened consumer, is
    deliberate: growing ``--judged``'s own parser to carry N per-target buckets would
    put a bounded, adversarially test-pinned parser at risk for no gain.

    F-155: ``liveTest`` is the fourth bucket, added on this same terms — it is NOT a
    second submission channel (the task's own instruction: reuse this bundle's shape
    rather than inventing one). Its own contents are validated separately by
    :func:`live_test_cap_signal`; this function only does the same coarse
    "is it even a dict" gate every other bucket already gets.
    """
    empty: dict = {"attestation": None, "judged": None, "vetJudged": [], "liveTest": None}
    if not isinstance(raw, str):
        return empty
    if len(raw.encode("utf-8", "surrogatepass")) > MAX_BUNDLE_BYTES:
        return empty
    try:
        data = json.loads(raw)
    except ValueError:
        return empty
    if not isinstance(data, dict):
        return empty
    out = dict(empty)
    if isinstance(data.get("attestation"), dict):
        out["attestation"] = data["attestation"]
    if isinstance(data.get("judged"), dict):
        out["judged"] = data["judged"]
    vet_judged = data.get("vetJudged")
    if isinstance(vet_judged, list):
        out["vetJudged"] = [e for e in vet_judged if isinstance(e, dict)]
    if isinstance(data.get("liveTest"), dict):
        out["liveTest"] = data["liveTest"]
    return out


def read_judged_bundle(path: str) -> dict:
    """:func:`split_judged_bundle` over a file (``-`` reads stdin). Never raises."""
    if path == "-":
        import sys  # noqa: PLC0415 — only needed on this one branch
        try:
            raw = sys.stdin.read(MAX_BUNDLE_BYTES + 1)
        except Exception:  # noqa: BLE001
            raw = ""
    else:
        try:
            raw = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw = ""
    return split_judged_bundle(raw)


# ── liveTest bucket (F-155) ───────────────────────────────────────────────────
#
# The fourth --judged-bundle bucket: a host agent's self-tested canary/dryrun/redteam/
# multiturn verdict, fed back so `scoring.compute`'s cap-only LIVE_INJECTION_CAP can see
# it. This is NOT a second submission channel — it rides the same bundle file, the same
# MAX_BUNDLE_BYTES bound, and the same "never raises, degrade to inert on anything
# malformed" discipline `_parse_verdicts` (adjudication.py) already established for the
# `judged`/`vetJudged` buckets.
#
# Self-attestation guard (scoring.LIVE_INJECTION_CAP's docstring): the verdict is
# produced by the AGENT UNDER TEST, so only "VULNERABLE" may ever have an effect —
# structurally, not by convention. `live_test_cap_signal` never even looks for a
# "RESISTANT" or unrecognized verdict to react to; the only thing this module ever
# extracts is the presence of at least one VULNERABLE entry.

# The only four harnesses that can ever submit a live-test verdict — matches the modules
# this task names (canary.py/dryrun.py/redteam.py/multiturn.py) exactly.
LIVE_TEST_TOOLS = frozenset({"canary", "redteam", "dryrun", "multiturn"})

# Exactly the two verdicts these harnesses' own evaluate() functions ever return
# (canary.evaluate / redteam.evaluate / dryrun.evaluate all return one of these two
# literal strings) — never a third value.
_LIVE_TEST_VERDICTS = frozenset({"VULNERABLE", "RESISTANT"})

# Bounded, structural scenario-id shape (e.g. "canary", "PI-01", "DR-07", "MT-02") — the
# real ids every harness's own make_*() emits are short alnum-plus-hyphen tokens. Enforced
# here because a validated id ends up embedded verbatim in `LiveTestSignal.reason`, a
# stable label `scoring`/`report` read — this is untrusted input from the agent under
# test, so it is validated the same "narrow shape, never free text" way as
# adjudication.py's `_CONFIG_PATH_RE`/`_LDH_HOST_RE`, never trusted as arbitrary prose.
_LIVE_TEST_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")

# F-155: only a SEEDED run's tokens are deterministic/reproducible (canary.make_canary /
# redteam.make_suite / dryrun.make_scenarios all draw a fresh `secrets` value unless an
# explicit seed is supplied) — see LIVE_INJECTION_CAP's docstring for why an unseeded
# verdict must still cap THIS run but never reach history.jsonl/trend/baseline. A seed
# longer than this is treated as malformed (not reproducible) rather than parsed further;
# generous above any real --seed value (an operator-chosen string, or canary/redteam's own
# `secrets.token_hex(8)` default — 16 hex chars).
_MAX_LIVE_TEST_SEED_LEN = 128


@dataclass
class LiveTestSignal:
    """F-155: the reduced, cap-only signal from one --judged-bundle ``liveTest`` bucket.

    ``hit`` is True iff at least one structurally-valid entry carried a VULNERABLE
    verdict — see the self-attestation guard above; RESISTANT and unrecognized/malformed
    entries can never set this True.
    ``reason`` is a stable, bounded label (e.g. ``"redteam:PI-01"``) built only from
    allow-listed tool names and regex-validated scenario ids — never free text copied
    from the submission. None when ``hit`` is False.
    ``reproducible`` is True only when the bucket also carried a well-formed, non-empty,
    bounded ``seed`` string — the gate `cli.py` uses to decide whether this run's
    verdict may be recorded into history.jsonl/trend/baseline.
    """

    hit: bool = False
    reason: str | None = None
    reproducible: bool = False


def _valid_live_test_entries(bucket) -> list[tuple[str, str, str]]:
    """Every structurally-valid ``(tool, id, verdict)`` triple in *bucket*'s
    ``"verdicts"`` list.

    Bounded and defensive — this is untrusted input from the agent under test. Any
    entry that is not a dict, names an unrecognized tool, carries an id outside
    ``_LIVE_TEST_ID_RE``'s shape, or carries anything but exactly "VULNERABLE"/
    "RESISTANT" is simply dropped — mirroring `adjudication._parse_verdicts`'
    per-entry tolerance (one bad entry never loses the rest, and never raises).
    """
    if not isinstance(bucket, dict):
        return []
    entries = bucket.get("verdicts")
    if not isinstance(entries, list):
        return []
    out: list[tuple[str, str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        tool, entry_id, verdict = entry.get("tool"), entry.get("id"), entry.get("verdict")
        if not (isinstance(tool, str) and tool in LIVE_TEST_TOOLS):
            continue
        if not (isinstance(entry_id, str) and _LIVE_TEST_ID_RE.match(entry_id)):
            continue
        if verdict not in _LIVE_TEST_VERDICTS:
            continue
        out.append((tool, entry_id, verdict))
    return out


def _live_test_reproducible(bucket) -> bool:
    """True only when *bucket* carries a well-formed, non-empty, bounded ``seed``.

    Deliberately structural, not a claimed boolean: a client-supplied
    ``"reproducible": true`` field would let any submission (seeded or not) simply
    assert its way past the history-recording gate, so this derives the fact from the
    same real signal (a usable seed string) `canary`/`redteam`/`dryrun` themselves need
    to reproduce their tokens, and ignores any such field entirely.
    """
    if not isinstance(bucket, dict):
        return False
    seed = bucket.get("seed")
    return isinstance(seed, str) and 0 < len(seed) <= _MAX_LIVE_TEST_SEED_LEN


# How many VULNERABLE entries' labels `reason` names before collapsing the rest to a
# "(+N more)" tail — bounded so a submission with many entries cannot inflate the label
# without limit; mirrors adjudication.py's own "first 12, then (+N more)" convention.
_MAX_LIVE_TEST_REASON_ENTRIES = 6


def live_test_cap_signal(bucket) -> LiveTestSignal:
    """F-155: reduce a ``--judged-bundle`` ``"liveTest"`` bucket to a cap-only signal.

    *bucket* is whatever :func:`split_judged_bundle` put at ``["liveTest"]`` — ``None``
    when the bundle carried no such bucket, or carried one that failed the coarse
    "is it a dict" gate. Never raises regardless of what *bucket* actually contains.

    The self-attestation guard is enforced HERE, structurally: this function only ever
    looks for a VULNERABLE entry among the ones :func:`_valid_live_test_entries`
    validated. There is no branch anywhere in this function, or in
    `scoring._live_injection_cap_signal` downstream, that reacts to a RESISTANT verdict
    or to an absent submission — both simply produce no VULNERABLE entries to find, so
    the natural "nothing found" result (``LiveTestSignal()``, every field at its
    zero-effect default) is what they get, not a special case carved out for them.
    """
    entries = _valid_live_test_entries(bucket)
    vulnerable = [(tool, entry_id) for tool, entry_id, verdict in entries if verdict == "VULNERABLE"]
    if not vulnerable:
        return LiveTestSignal()
    labels = [f"{tool}:{entry_id}" for tool, entry_id in vulnerable[:_MAX_LIVE_TEST_REASON_ENTRIES]]
    reason = "; ".join(labels)
    if len(vulnerable) > _MAX_LIVE_TEST_REASON_ENTRIES:
        reason += f" (+{len(vulnerable) - _MAX_LIVE_TEST_REASON_ENTRIES} more)"
    return LiveTestSignal(hit=True, reason=reason, reproducible=_live_test_reproducible(bucket))


# ── the pipeline roll-up (P10) ───────────────────────────────────────────────

@dataclass
class PipelineResult:
    """Every phase's outcome plus the roll-ups the three output paths read."""

    phases: list[PhaseResult] = field(default_factory=list)
    budget_s: float = DEFAULT_FULL_BUDGET_S
    fast: bool = False

    def add(self, phase: PhaseResult) -> PhaseResult:
        self.phases.append(phase)
        return phase

    def by_name(self, name: str) -> PhaseResult | None:
        for p in self.phases:
            if p.name == name:
                return p
        return None

    @property
    def has_fail(self) -> bool:
        """FAIL-only, joining the ``--exit-code`` disjunction on exactly the terms the
        vet-mcp and skill-sweep contributions already sit on.

        A WARN does not trip it, and neither does an incomplete phase: an ABSENT
        verdict is not a FAIL, and reddening the gate on truncation would silently
        redden every CI run that passes today. Incompleteness is reported by the
        printed section and by ``complete``/``notScanned[]``, never by the exit code.
        """
        return any(p.has_fail for p in self.phases)

    @property
    def complete(self) -> bool:
        """True only when every phase ran AND accounted for everything it covers."""
        return all(
            p.status not in _INCOMPLETE_STATUSES and p.complete for p in self.phases
        )

    def not_scanned(self) -> list[str]:
        """Every target no phase could vouch for, named. The narrative print may elide
        with "(+N more)"; this may not."""
        out: list[str] = []
        for p in self.phases:
            out.extend(p.not_scanned)
        return out

    def to_json(self) -> dict:
        """The additive top-level keys ``--full --json`` gains.

        Additive by construction: every existing key keeps its meaning and its value,
        so a consumer that reads by key — which is how the payload is consumed — cannot
        be tripped by this.

        C8: the whole tree goes through ``report._sanitize_tree`` on the way out. The
        judge packets carry evidence excerpts lifted verbatim from untrusted skill and
        plugin content, so "the producer already sanitized it" is not a property this
        boundary may assume — it enforces it, exactly as the existing ``--json``
        renderer does for the audit payload.
        """
        payload: dict = {
            "phases": [p.to_json() for p in self.phases],
            "complete": self.complete,
            "notScanned": self.not_scanned(),
        }
        adj = self.by_name(PHASE_ADJUDICATION)
        if adj is not None and isinstance(adj.data, dict):
            for key in ("judgePacket", "vetPackets", "attestTemplate", "secondOpinion",
                       "vetSecondOpinion"):
                if key in adj.data:
                    payload[key] = adj.data[key]
        plugins = self.by_name(PHASE_PLUGIN_SWEEP)
        if plugins is not None and isinstance(plugins.data, dict):
            payload["pluginSweep"] = plugins.data
        from .report import _sanitize_tree  # noqa: PLC0415 — see the docstring
        return _sanitize_tree(payload)


def _banner(title: str) -> list[str]:
    return ["", "=" * 60, f"CLAWSECCHECK {title}", "=" * 60]


def render_sections(result: PipelineResult, ascii_only: bool = False) -> list[str]:
    """P10 verbose — the appended sections, as lines, in phase order.

    A phase that did not run still gets its banner and one honest line saying what was
    not done. Silence would be indistinguishable from "nothing to report".
    """
    lines: list[str] = []
    for phase in result.phases:
        if not phase.section:
            continue
        title = _SECTION_TITLE.get(phase.name, phase.name.replace("_", " ").upper())
        lines.extend(_banner(title))
        if phase.ran and phase.lines:
            lines.extend(phase.lines)
        else:
            marker = "[?]" if ascii_only else "❔"
            lines.append(f"{marker} {_sanitize(phase.detail)}")
        if phase.ran and phase.not_scanned:
            bullet = "*" if ascii_only else "•"
            lines.append("Not scanned — these are NOT counted as safe:")
            for name in phase.not_scanned[:12]:
                lines.append(f"  {bullet} {name}")
            if len(phase.not_scanned) > 12:
                lines.append(f"  {bullet} (+{len(phase.not_scanned) - 12} more)")
    return lines


def quiet_lines(result: PipelineResult) -> list[str]:
    """P10 quiet — one honest line per phase, the same collapse ``--quiet`` already
    applies to the self-test and vet-mcp sections.

    Built from the SAME :class:`PhaseResult` objects the verbose branch renders, so the
    two can state different amounts of detail but can never state different facts.
    """
    lines: list[str] = []
    for phase in result.phases:
        if not phase.section:
            continue
        prefix = _QUIET_PREFIX.get(phase.name, phase.name.replace("_", " ").upper())
        body = phase.quiet_line if (phase.ran and phase.quiet_line) else phase.detail
        lines.append(f"{prefix}: {_sanitize(body)}")
    return lines


def run_pipeline(ctx, findings, *, home_dir, skill_sweep=None,
                 skill_sweep_elapsed_s: float = 0.0, vet_targets=(),
                 deadline: float | None = None, budget_s: float = DEFAULT_FULL_BUDGET_S,
                 fast: bool = False, ascii_only: bool = False, version: str = "",
                 bundle: dict | None = None) -> PipelineResult:
    """Run P7-P9 and roll them up with the already-executed P6.

    ``deadline`` is injectable so a test can pin the budget's behaviour without
    sleeping; when omitted, one is opened from ``budget_s``.

    ``--fast`` skips the deep phases (P6-P8) and keeps P9, which costs nothing to emit:
    it re-runs no check and reads only what the audit already computed. A flag whose
    only effect would be to suppress a cheap deterministic artifact would be flag
    surface for nothing.
    """
    if deadline is None:
        deadline = start_deadline(budget_s)
    result = PipelineResult(budget_s=budget_s, fast=fast)

    fast_note = "skipped — --fast was given; no target here was inspected."

    # P6 — recorded, not run (see the module docstring).
    if fast:
        result.add(_skipped(PHASE_SKILL_SWEEP, fast_note))
    else:
        result.add(record_skill_sweep(skill_sweep, elapsed_s=skill_sweep_elapsed_s))

    # P7 — installed-plugin sweep.
    if fast:
        result.add(_skipped(PHASE_PLUGIN_SWEEP, fast_note))
    elif budget_exceeded(deadline):
        result.add(_not_reached(PHASE_PLUGIN_SWEEP, budget_s))
    else:
        result.add(run_plugin_sweep(home_dir, deadline=deadline, ascii_only=ascii_only))

    # P8 — behavioural replay.
    if fast:
        result.add(_skipped(PHASE_BEHAVIORAL, fast_note))
    elif budget_exceeded(deadline):
        result.add(_not_reached(PHASE_BEHAVIORAL, budget_s))
    else:
        result.add(run_behavioral(ctx, ascii_only=ascii_only))

    # P9 — adjudication. Deliberately NOT gated on --fast or on the budget: it re-runs
    # no check, so there is no expense to skip, and the borderline band is exactly what
    # a user running a shortened pipeline still wants to hand to their agent.
    result.add(run_adjudication(ctx, findings, vet_targets=vet_targets,
                                version=version, bundle=bundle))
    return result
