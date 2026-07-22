"""Deterministic scoring: weighted pass-rate with honesty hard-caps.

- PASS -> full weight, WARN -> half weight, FAIL -> 0, UNKNOWN -> excluded.
- Hard caps per FAILed severity so a FAIL always costs a grade and a more-
  dangerous config can never out-grade a safer one (B-011):
      CRITICAL FAIL -> <= 49 (F)   HIGH FAIL -> <= 79 (C)
      MEDIUM   FAIL -> <= 89 (B)   LOW  FAIL -> <= 94 (A-)
  The most-severe failing cap wins.  Before B-011, MEDIUM/LOW FAILs had no cap
  and were diluted by a large PASS pool — a single real failure could still
  show an "A".
- Nothing scorable (empty / all-UNKNOWN / all-advisory) -> "not assessable",
  reported distinctly instead of mislabeled as a worst-possible F (B-014).
- Two CAP-ONLY signals never earn/cost an ordinary scored point, only ever lower the
  ceiling, applied after the severity caps above: a corroborated runtime signal
  (RUNTIME_SIGNAL_CAP, I-025/B-309) and an unreadable/unparseable primary config
  (CONFIG_BLIND_CAP, B-306) — the latter closes the "config went dark mid-audit and the
  grade rose because its own FAILs correctly degraded to UNKNOWN" gap.
"""
from __future__ import annotations

from dataclasses import dataclass, replace as dc_replace

from .catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, WEIGHT, Finding

GRADES = [(90, "A"), (80, "B"), (70, "C"), (50, "D"), (0, "F")]

# Per-severity hard cap a FAIL of that severity imposes on the final score.
FAIL_CAPS = {CRITICAL: 49, HIGH: 79, MEDIUM: 89, LOW: 94}
# Most-severe first — used to label which severity drove the cap.
_SEV_ORDER = (CRITICAL, HIGH, MEDIUM, LOW)

# I-025/B-309: the ONLY runtime (behaviour-proven) signal permitted to touch the A-F
# grade, and ONLY as a hard CAP — never an ordinary scored point. ARGUMENTS-
# CORROBORATED: a trajaudit indicator match membership-tests an already-known
# indicator (a path/host the user's own skill or bootstrap file names) against REAL
# runtime tool-call arguments. B164's exfil_evidence class was ALSO cap-eligible under
# Dave's original 2026-07-20 ruling, but that exception was RETRACTED (Dave's
# 2026-07-22 ruling, after four C-135 rounds and three independent adversarial reviews
# proved no sound host/verb gate exists for this tool's own audience — see
# `_runtime_cap_signal`'s docstring and logscan.py's retraction note). B164 —
# including exfil_evidence, same-line or cross-line — is WARN-only, permanently. The
# trajaudit indicator's Finding never becomes `scored=True` — it stays excluded from
# the `scored` filter above exactly as before; this cap is a SEPARATE, additional path
# that never touches `earned`/`total`. Every runtime-consuming check (B83, B84, B85,
# B164, B180, T1/T2/T3) stays permanently unable to reach the grade any other way — see
# tests/test_i025_runtime_cap.py's enumeration, which pins each one's scored/cap status
# so a future flag flip anywhere in that set turns red.
#
# The cap mirrors FAIL_CAPS' "one real problem always costs a grade" philosophy, set at
# the same ceiling as a HIGH-severity static FAIL: a corroborated runtime signal is
# proof a chain was attempted, not a config heuristic, so a config-clean agent whose own
# trajectory sidecar proves lethal-trifecta-class behavior can never show better than a
# C — exactly the "grade A/97 while the log proves the trifecta" gap I-025 reported.
RUNTIME_SIGNAL_CAP = FAIL_CAPS[HIGH]

# B-306 (C-135 follow-up, aggregate-grade half): a present-but-unparseable/unreadable
# openclaw.json (``ctx.config_parse_error``, B-166) collapses EVERY ctx.config-derived
# check's view to an empty dict. B-306's own check-level fix made A1/B41 (and the ~10
# checks `_config_unreadable()` already guarded) degrade to UNKNOWN instead of computing
# a real-looking WARN/PASS off that empty dict — necessary, but not sufficient: FAIL_CAPS
# above only binds when some check is STILL a FAIL after the run, and UNKNOWN findings
# impose no cap at all. So converting a config-derived FAIL into an UNKNOWN can silently
# *raise* the achievable grade even though the audit saw strictly LESS evidence, not
# more — the exact "hiding evidence improves the grade" defect FAIL_CAPS exists to
# prevent, one layer up. Measured end-to-end on a scratch copy of a real, genuinely
# vulnerable config (never the user's actual file): readable -> F/49 (A1 FAIL); the same
# bytes truncated mid-object -> C/79 with the check-level fix alone, and F/49 -> A/98 in
# a second real-shaped repro where a second config-derived FAIL (B2) also went UNKNOWN in
# the same run and no independent-of-config FAIL remained to cap anything.
#
# Structural fix, not a per-check patch: cap ANY run where ``ctx.config_parse_error`` is
# true at the same ceiling FAIL_CAPS already assigns a proven CRITICAL FAIL. This is
# sound, not a keyword/threshold guess, because:
#   - ``ctx.config_parse_error`` is real, collector-derived STATE (B-166) — a data-shape
#     fact about whether the collector's own JSON parse succeeded — never a text/keyword
#     match, and it is the exact same signal `_config_unreadable()` already gates 10+
#     checks on, so this reuses an already-adversarially-reviewed boolean rather than
#     inventing a new one.
#   - A1 (Lethal Trifecta, the check this file's config feeds most directly) is itself
#     CRITICAL-severity — so "the audit could not read the config that would have driven
#     A1" is properly treated the same as "cannot rule out a CRITICAL", a worst-case (not
#     average-case) assumption, exactly like Golden Rule #4 ("report UNKNOWN, never a
#     fake PASS/FAIL") applied one layer up, at the grade instead of the per-check status.
#   - It is a hard CAP only — mirrors RUNTIME_SIGNAL_CAP's shape immediately above,
#     never touches `earned`/`total`, and is provably inert whenever ctx is None or
#     ctx.config_parse_error is False (every pre-existing call site/test that never
#     passes a blind ctx is unaffected).
CONFIG_BLIND_CAP = FAIL_CAPS[CRITICAL]


def grade_for(score: int) -> str:
    for threshold, letter in GRADES:
        if score >= threshold:
            return letter
    return "F"


@dataclass
class ScoreResult:
    score: int
    grade: str
    capped: bool
    raw_score: int
    failed_critical: int
    failed_high: int
    failed_medium: int = 0
    failed_low: int = 0
    assessable: bool = True
    cap_severity: str | None = None
    # I-025/B-309: True only when the RUNTIME_SIGNAL_CAP actually bound (lower than
    # whatever the severity-driven cap above already produced) — mirrors how
    # `cap_severity` only ever names the cap that was actually binding. False whenever no
    # eligible runtime signal fired, OR one fired but a tighter severity FAIL cap already
    # capped the score at least as hard (e.g. a CRITICAL FAIL's <=49 already dominates the
    # <=79 runtime cap — the runtime signal is real but non-binding in that case).
    runtime_capped: bool = False
    # Stable, testable label(s) for whichever eligible runtime signal(s) fired — never a
    # free-text sentence (report.py owns user-facing wording). None when runtime_capped
    # is False. See `_runtime_cap_signal` for the exact reason strings.
    runtime_cap_reason: str | None = None
    # B-306 (C-135 follow-up): True only when CONFIG_BLIND_CAP actually bound (lower than
    # whatever the severity/runtime caps above already produced) — same "only-when-
    # actually-binding" discipline as `runtime_capped`. False whenever ctx is None,
    # ctx.config_parse_error is False, or a tighter cap already applied (e.g. a genuine
    # CRITICAL FAIL that is NOT itself config-derived already forced <=49 — the config-
    # blind cap is real but non-binding in that case).
    config_blind_capped: bool = False


def _runtime_cap_signal(findings: list[Finding], ctx) -> tuple[bool, str | None]:
    """I-025/B-309: the ONE arguments-corroborated runtime signal eligible to CAP the
    grade, and nothing else.

    * trajaudit indicator match — needs *ctx* (installed_skills/bootstrap/home).
      ``ctx=None`` (e.g. `project()`'s what-if re-computation, which only ever has
      `findings`) means this half is simply invisible to that call site — a known,
      documented blind spot, never a false positive.

    Dave's original 2026-07-20 ruling also made B164's exfil_evidence class eligible to
    CAP (a same-line secret + exfil-transport verb + known drop-host). Four C-135
    rounds (follow-ups #1-#4) progressively narrowed that host/verb gate trying to make
    it sound, and THREE independent adversarial reviews of the final attempt (an
    "attacker-exclusive" OOB/canary host set — interactsh/oast, Burp Collaborator,
    dnslog, Canarytokens) converged that no sound gate exists: this tool's own audience
    (security-conscious operators) legitimately sends secrets to that exact class of
    infrastructure during authorized security testing, so the benign and malicious
    cases are byte-identical on a single log line — only intent/provenance
    distinguishes them, which a regex over one log line cannot recover. Dave's
    2026-07-22 ruling RETRACTED the exception entirely (see logscan.py's retraction
    note above `_scan_line_content`'s Class 2 comment for the full history):
    exfil_evidence — same-line or cross-line — is WARN-only, permanently, and B164
    findings are no longer read here at all. The trajaudit-indicator match below is the
    only remaining cap source.

    Returns ``(hit, reason)``; *reason* is a stable, testable label (never rendered
    prose — report.py builds the user-facing sentence from it).
    """
    reasons: list[str] = []
    if ctx is not None:
        from . import trajaudit  # noqa: PLC0415 -- lazy: mirrors checks/_egress.py's own
                                  # precedent for a Layer-3-sibling import kept out of
                                  # this module's top-level import cost for every caller
                                  # that never supplies ctx (tamperscore.py, tests, …).
        sig = trajaudit.grade_cap_signal(ctx)
        if sig["hit"]:
            reasons.append("trajaudit indicator match")
    return (bool(reasons), "; ".join(reasons) if reasons else None)


def compute(findings: list[Finding], ctx=None) -> ScoreResult:
    """Weighted pass-rate + severity FAIL caps (module docstring), plus I-025/B-309's
    cap-only runtime signal and B-306's cap-only config-blind signal.

    *ctx* is optional and additive — every existing call site that omits it (or passes
    ``None``) simply never sees the trajaudit-indicator cap (the only remaining runtime
    cap source; see `_runtime_cap_signal`), and the B-306 config-blind cap is inert too
    (``config_blind_capped`` stays False).
    Pass the audited `Context` when it is available (see `_runtime_cap_signal`) so a
    `trajaudit`-style indicator match can also be seen, and so a run where
    ``ctx.config_parse_error`` is True (openclaw.json present but unparseable/unreadable,
    B-166) cannot show a better grade than the CRITICAL-FAIL ceiling (CONFIG_BLIND_CAP)
    just because its config-derived checks correctly degraded to UNKNOWN instead of a
    fabricated PASS/WARN.

    B-306 (C-135 follow-up #2 — real end-to-end bypass, 2026-07-21): the two cap signals
    above are read ONCE, up front, BEFORE the ``total == 0`` "nothing scorable" check —
    not just after it. A run can reach ``total == 0`` while ``ctx.config_parse_error`` is
    True (a truncated/unreadable ``openclaw.json`` plus a ``.clawseccheckignore`` that
    happens to suppress the only checks — B9/B16 — that keep scoring off a blind
    ``ctx.config == {}``): with the caps applied only AFTER the early return, that run
    fell through to the neutral "N/A" result below, reporting `capped=False`,
    `config_blind_capped=False`, and a grey/neutral grade instead of the CRITICAL-ceiling
    F this project's own doctrine already assigns "cannot read the config" everywhere
    else. See the `total == 0` branch below for the fix.
    """
    # Suppression is a reporting/triage decision, not proof that a real FAIL stopped
    # existing. Keep suppressed FAILs in the score so an ignore entry cannot turn a
    # vulnerable system into an A/100. Suppressed PASS/WARN/UNKNOWN findings retain the
    # historical baseline behaviour and stay outside the raw denominator.
    scored = [
        f for f in findings
        if f.scored
        and f.status not in (UNKNOWN, "SKILL_ARCHIVE_PATH_TRAVERSAL")
        and (not getattr(f, "suppressed", False) or f.status == FAIL)
    ]
    total = sum(WEIGHT[f.severity] for f in scored)

    # B-306 (C-135 follow-up #2): read both cap-only signals BEFORE the `total == 0`
    # short-circuit, not after it — a structural reordering, not a new signal. Both are
    # the exact same real, collector/trajaudit-derived facts the total != 0 path already
    # trusts below; nothing here is a keyword/text match, so this cannot regress into the
    # keyword-widening pattern this project has already learned to avoid.
    # B-306 safe-symlink split: a config that is present-but-unparseable is genuinely
    # blind ONLY when the bytes could not be read. A dotfiles-style openclaw.json symlink
    # whose target left ~/.openclaw but is a readable regular file the user owns is NOT
    # blind — the collector followed it and audited the real bytes, so it must never trip
    # CONFIG_BLIND_CAP (that F cap is the exact false positive this split removes). The
    # collector already resolves this by keeping ``config_parse_error`` False for the safe
    # case; the ``config_symlink_escapes_home`` term is a scoring-layer invariant lock so
    # the two states can never re-conflate here even if a future collector change surfaced
    # both flags at once. It is STRUCTURAL collector state (B-166 family), never a
    # text/keyword match, so it cannot regress into keyword-widening.
    config_blind = (
        ctx is not None
        and getattr(ctx, "config_parse_error", False)
        and not getattr(ctx, "config_symlink_escapes_home", False)
    )
    runtime_hit, runtime_reason = _runtime_cap_signal(findings, ctx)

    if total == 0:
        if not config_blind and not runtime_hit:
            # Nothing measurable and no cap signal fired either — the honest "not
            # assessable" result (B-014), completely unchanged from before B-306.
            return ScoreResult(0, "N/A", False, 0, 0, 0, assessable=False)
        # B-306 (C-135 follow-up #2): nothing else scored this run, BUT a blind config
        # (ctx.config_parse_error) or a corroborated runtime signal (trajaudit) fired.
        # Those are real, structural facts, never a guess — exactly what
        # CONFIG_BLIND_CAP/RUNTIME_SIGNAL_CAP already treat as "cannot rule out a
        # CRITICAL/HIGH" one severity-cap tier up when *something else* is scored too.
        # Falling back to a neutral "N/A" here would be the identical lying-clean bypass
        # reached through the OTHER short-circuit — the exact defect this task closes.
        # The result mirrors what a single scored FAIL of that severity, with nothing
        # else measured, already produces via the ordinary path below (a lone FAIL
        # contributes 0 earned weight against its own nonzero total -> raw 0 -> grade F)
        # — not a new invented number, and `capped` stays False because there is no raw
        # value above 0 for this run to have been reduced FROM.
        return ScoreResult(
            score=0,
            grade=grade_for(0),
            capped=False,
            raw_score=0,
            failed_critical=0,
            failed_high=0,
            failed_medium=0,
            failed_low=0,
            assessable=True,
            cap_severity=None,
            runtime_capped=runtime_hit,
            runtime_cap_reason=runtime_reason if runtime_hit else None,
            config_blind_capped=config_blind,
        )

    earned = 0.0
    for f in scored:
        w = WEIGHT[f.severity]
        if f.status == PASS:
            earned += w
        elif f.status == WARN:
            earned += w * 0.5
        # FAIL contributes 0

    raw = round(earned / total * 100)

    failed = {sev: sum(1 for f in scored if f.status == FAIL and f.severity == sev)
              for sev in _SEV_ORDER}

    score = raw
    cap_severity = None
    for sev in _SEV_ORDER:  # most-severe cap wins, and labels the cap
        if failed[sev]:
            capped_to = min(score, FAIL_CAPS[sev])
            if capped_to < score:
                score = capped_to
                if cap_severity is None:
                    cap_severity = sev

    # B-306 (C-135 follow-up) — cap-only, applied BEFORE the runtime cap so a config-blind
    # run and a corroborated-runtime run compose (both apply; whichever is tighter wins).
    # Gated purely on ctx.config_parse_error (real collector state, B-166) — never on
    # counting UNKNOWNs or matching any text, so it cannot be gamed by wording and cannot
    # regress into the keyword-widening pattern this project has already learned to avoid.
    # `config_blind` was already computed above (before the `total == 0` check) — reused
    # here unchanged, not recomputed, so both paths can never disagree on the same signal.
    config_blind_capped = False
    if config_blind:
        pre_blind_score = score
        score = min(score, CONFIG_BLIND_CAP)
        config_blind_capped = score < pre_blind_score

    # I-025/B-309 — cap-only runtime signal, applied AFTER the severity caps above and
    # never touching `earned`/`total`: neither eligible producer's Finding is `scored`,
    # so this is a wholly separate path, exactly as the ruling requires ("does not
    # otherwise participate in scoring"). `runtime_capped` only records True when this
    # cap was actually binding (see its field docstring) — a CRITICAL/HIGH FAIL that
    # already capped at least as hard leaves it False even if the runtime signal fired.
    # `runtime_hit`/`runtime_reason` were already computed above (before the `total == 0`
    # check) — reused here unchanged, never re-scanned a second time.
    runtime_capped = False
    if runtime_hit:
        pre_runtime_score = score
        score = min(score, RUNTIME_SIGNAL_CAP)
        runtime_capped = score < pre_runtime_score

    return ScoreResult(
        score=score,
        grade=grade_for(score),
        capped=score != raw,
        raw_score=raw,
        failed_critical=failed[CRITICAL],
        failed_high=failed[HIGH],
        failed_medium=failed[MEDIUM],
        failed_low=failed[LOW],
        assessable=True,
        cap_severity=cap_severity,
        runtime_capped=runtime_capped,
        runtime_cap_reason=runtime_reason if runtime_capped else None,
        config_blind_capped=config_blind_capped,
    )


def assessment_coverage(findings: list[Finding]) -> dict:
    """How much of the scoreable catalog this run could actually assess.

    Mirrors ``compute``'s finding-selection exactly (``scored`` + not a
    suppressed/non-scoreable status), except it does NOT drop UNKNOWN —
    UNKNOWN is exactly what this measures. Pure, no I/O.

    Returns a dict:
        {"scored_total": int, "assessable": int, "unknown": int,
         "assessable_frac": float, "unknown_frac": float}

    ``assessable + unknown == scored_total`` always holds. When
    ``scored_total == 0`` both fractions are ``0.0`` (nothing to divide by).
    """
    in_scope = [
        f for f in findings
        if f.scored and f.status != "SKILL_ARCHIVE_PATH_TRAVERSAL"
        and not getattr(f, "suppressed", False)
    ]
    scored_total = len(in_scope)
    unknown = sum(1 for f in in_scope if f.status == UNKNOWN)
    assessable = scored_total - unknown

    if scored_total == 0:
        return {
            "scored_total": 0,
            "assessable": 0,
            "unknown": 0,
            "assessable_frac": 0.0,
            "unknown_frac": 0.0,
        }

    return {
        "scored_total": scored_total,
        "assessable": assessable,
        "unknown": unknown,
        "assessable_frac": assessable / scored_total,
        "unknown_frac": unknown / scored_total,
    }


def project(findings: list[Finding], ctx=None) -> dict:
    """What-if projection: estimate the score impact of fixing FAIL findings.

    *ctx* is optional (default ``None``, unchanged behaviour) and, when supplied, is
    threaded into every internal `compute()` call so I-025/B-309's cap-only runtime
    signal stays consistent between the "current" figure here and the real score the
    caller already reported (B-013 self-contradiction discipline) — fixing a FAIL never
    un-proves a corroborated runtime observation, so the cap (if any) applies to every
    projected figure exactly like it applies to "current".

    Returns a dict with three keys:

    - ``"current"``:    ``{"score": int, "grade": str}``
    - ``"top1"``:       ``{"finding_id": str, "projected_score": int,
                           "projected_grade": str, "delta": int}`` or ``None``
                        if there are no fixable (scored, non-suppressed) FAILs.
    - ``"cumulative"``: ``{"projected_score": int, "projected_grade": str,
                           "delta": int}`` — result of flipping all
                        CRITICAL + HIGH FAILs to PASS simultaneously.

    Selection rules for ``top1``:
    - Candidates: scored, non-suppressed FAIL findings only.
    - Primary key: highest projected score (compute with that one finding flipped
      to PASS; all others unchanged).
    - Tie-break 1: cap-lifting candidates (CRITICAL or HIGH severity) preferred.
    - Tie-break 2: severity order (CRITICAL > HIGH > MEDIUM > LOW).
    - Tie-break 3: WEIGHT (heavier first).
    - Tie-break 4: finding ``id`` alphabetically (stable across calls).

    Input findings are **never mutated**; modified copies are built with
    ``dataclasses.replace``.  Projection is *estimated* — labeling is the
    renderer's responsibility.
    """
    current_result = compute(findings, ctx)
    current_score = current_result.score
    current_grade = current_result.grade

    fixable = [
        f for f in findings
        if f.scored and not getattr(f, "suppressed", False) and f.status == FAIL
    ]

    # ── top1: the single highest-leverage fix ────────────────────────────────
    top1: dict | None = None
    if fixable:
        # Pre-compute projected score for each candidate (one compute() per candidate).
        # Uses object identity (``is``) to replace only the target finding.
        candidates: list[tuple[Finding, int, str]] = []
        for f in fixable:
            modified = [
                dc_replace(x, status=PASS) if x is f else x
                for x in findings
            ]
            proj = compute(modified, ctx)
            candidates.append((f, proj.score, proj.grade))

        def _rank(item: tuple) -> tuple:
            f, proj_score, _ = item
            return (
                -proj_score,                              # highest projected score first
                -int(f.severity in (CRITICAL, HIGH)),    # cap-lifting preferred
                _SEV_ORDER.index(f.severity),             # most-severe first
                -WEIGHT[f.severity],                      # heavier weight first
                f.id,                                     # stable alphabetic tie-break
            )

        best_f, best_score, best_grade = sorted(candidates, key=_rank)[0]
        top1 = {
            "finding_id": best_f.id,
            "projected_score": best_score,
            "projected_grade": best_grade,
            "delta": best_score - current_score,
        }

    # ── cumulative: fix all Critical + High FAILs simultaneously ─────────────
    # Use object-id set to avoid hashability requirements on Finding.
    crit_high_oids = {id(f) for f in fixable if f.severity in (CRITICAL, HIGH)}
    if crit_high_oids:
        modified_all = [
            dc_replace(x, status=PASS) if id(x) in crit_high_oids else x
            for x in findings
        ]
        cum_result = compute(modified_all, ctx)
        cumulative = {
            "projected_score": cum_result.score,
            "projected_grade": cum_result.grade,
            "delta": cum_result.score - current_score,
        }
    else:
        cumulative = {
            "projected_score": current_score,
            "projected_grade": current_grade,
            "delta": 0,
        }

    return {
        "current": {"score": current_score, "grade": current_grade},
        "top1": top1,
        "cumulative": cumulative,
    }
