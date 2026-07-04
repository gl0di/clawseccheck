"""Tamper Score sub-grade: a presentation-layer-only view of tamper-defense posture.

This is NOT a second scoring engine — it never touches ``scoring.compute()`` or the
main A-F grade. It re-slices a subset of already-computed findings (the checks that
speak to "can someone tamper with this agent's config/memory/identity, and would you
notice") into a second, smaller weighted pass-rate, purely for a supplementary
"Tamper posture" line in the human report.

Ingredients (severity per catalog.py, as of this writing):
  - B20  (MEDIUM)  Bootstrap / memory write protection
  - B22  (HIGH)    Self-modification risk (identity/skill files writable + tools enabled)
  - B42  (MEDIUM)  Skill/plugin install-time policy (postinstall hooks, writable dirs)
  - B78  (HIGH)    Config-health integrity alert (observed suspicious signature)
  - B85  (MEDIUM)  Incident readiness — tool-use trail present and tamper-resistant
  - B86  (MEDIUM)  Import-path hijack surface (sys.path from writable/relative location)
  - C5   (LOW)     Native binary PATH safety
  - monitor_state_present (synthetic, HIGH) — is `--monitor` baseline tracking in use at all

A check ID absent from this run's findings (e.g. suppressed away entirely, or a future
catalog change) is EXCLUDED from the denominator — never scored as a fabricated PASS.
"""
from __future__ import annotations

from .catalog import FAIL, HIGH, LOW, MEDIUM, PASS, WARN, WEIGHT, Finding
from .scoring import ScoreResult, grade_for

# Check IDs that make up the tamper-defense sub-grade.
TAMPER_CHECK_IDS: tuple[str, ...] = ("B20", "B22", "B42", "B78", "B85", "B86", "C5")

# Synthetic ingredient label for the monitor-state presence signal (not a Finding.id).
_MONITOR_LABEL = "monitor-state"

# Per-ingredient hard caps this sub-grade imposes on itself, most-severe first.
# Mirrors the style of dossier.py's _WARN_CAP / _NON_DANGER_FAIL_CAP and scoring.py's
# FAIL_CAPS — a real tamper-relevant FAIL (or missing baseline) always costs a grade.
_B22_FAIL_CAP = 49
_B78_FAIL_CAP = 49
_NO_MONITOR_CAP = 79
_OTHER_FAIL_CAP = 79
_WARN_CAP = 89


def tamper_subgrade(findings: list, monitor_state_present: bool) -> ScoreResult:
    """Compute a tamper-defense sub-grade over a fixed ingredient list.

    Presentation-layer only: reuses ``scoring.ScoreResult`` and ``scoring.grade_for``
    so ``report.py`` can render it exactly like the main score, but this never feeds
    back into ``scoring.compute()`` or the main A-F grade.

    Args:
        findings: the full findings list for this run (only B20/B22/B42/B78/B85/B86/C5
            are consulted; everything else is ignored).
        monitor_state_present: whether a ``--monitor`` baseline snapshot exists for
            this run — treated as a synthetic HIGH-severity ingredient.

    Returns:
        A ``ScoreResult``. When ``findings`` contributes none of the seven
        check-derived ingredients (e.g. an empty list — the run genuinely has no
        tamper-relevant findings to look at), returns the same "not assessable" shape
        ``scoring.compute()`` uses: ``score=0, grade="N/A", assessable=False`` — even
        though ``monitor_state_present`` is always a real bool, a sub-grade built on a
        single synthetic ingredient with zero real findings behind it would read as a
        fabricated verdict, so it is deliberately withheld rather than shown as a real
        A or F.
    """
    by_id = {f.id: f for f in findings}

    # (label, severity, status) for every ingredient that is actually present this run.
    ingredients: list[tuple[str, str, str]] = []
    for check_id in TAMPER_CHECK_IDS:
        f: Finding | None = by_id.get(check_id)
        if f is None:
            continue  # not present this run -> excluded, never a fabricated pass
        ingredients.append((check_id, f.severity, f.status))

    if not ingredients:
        # None of the seven check-derived ingredients are present this run — the
        # synthetic monitor-state signal alone is not enough to call this "assessed".
        return ScoreResult(0, "N/A", False, 0, 0, 0, assessable=False)

    # Synthetic ingredient: having drift-monitoring at all is a first-class tamper
    # defense, weighted as HIGH severity.
    monitor_status = PASS if monitor_state_present else FAIL
    ingredients.append((_MONITOR_LABEL, HIGH, monitor_status))

    total = sum(WEIGHT[sev] for _label, sev, _status in ingredients)

    earned = 0.0
    for _label, sev, status in ingredients:
        w = WEIGHT[sev]
        if status == PASS:
            earned += w
        elif status == WARN:
            earned += w * 0.5
        # FAIL contributes 0

    raw = round(earned / total * 100)

    score = raw
    cap_severity: str | None = None

    def _apply_cap(cap: int, label: str) -> None:
        nonlocal score, cap_severity
        capped_to = min(score, cap)
        if capped_to < score:
            score = capped_to
            cap_severity = label

    # Most-severe cap first so the tightest cap wins and labels the result.
    b22 = by_id.get("B22")
    if b22 is not None and b22.status == FAIL:
        _apply_cap(_B22_FAIL_CAP, "B22-FAIL")

    b78 = by_id.get("B78")
    if b78 is not None and b78.status == FAIL:
        _apply_cap(_B78_FAIL_CAP, "B78-FAIL")

    if not monitor_state_present:
        _apply_cap(_NO_MONITOR_CAP, "no-monitor")

    for check_id in ("B20", "B42", "B85", "B86", "C5"):
        f = by_id.get(check_id)
        if f is not None and f.status == FAIL:
            _apply_cap(_OTHER_FAIL_CAP, f"{check_id}-FAIL")

    if any(status == WARN for _label, _sev, status in ingredients):
        _apply_cap(_WARN_CAP, "WARN")

    return ScoreResult(
        score=score,
        grade=grade_for(score),
        capped=(score != raw),
        raw_score=raw,
        failed_critical=0,
        failed_high=sum(1 for _l, sev, st in ingredients if sev == HIGH and st == FAIL),
        failed_medium=sum(1 for _l, sev, st in ingredients if sev == MEDIUM and st == FAIL),
        failed_low=sum(1 for _l, sev, st in ingredients if sev == LOW and st == FAIL),
        assessable=True,
        cap_severity=cap_severity,
    )
