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
"""
from __future__ import annotations

from dataclasses import dataclass

from .catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, WEIGHT, Finding

GRADES = [(90, "A"), (80, "B"), (70, "C"), (50, "D"), (0, "F")]

# Per-severity hard cap a FAIL of that severity imposes on the final score.
FAIL_CAPS = {CRITICAL: 49, HIGH: 79, MEDIUM: 89, LOW: 94}
# Most-severe first — used to label which severity drove the cap.
_SEV_ORDER = (CRITICAL, HIGH, MEDIUM, LOW)


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


def compute(findings: list[Finding]) -> ScoreResult:
    scored = [f for f in findings if f.scored and f.status not in (UNKNOWN, "SKILL_ARCHIVE_PATH_TRAVERSAL")
              and not getattr(f, "suppressed", False)]
    total = sum(WEIGHT[f.severity] for f in scored)
    if total == 0:
        # Nothing measurable — distinct "not assessable" result, not a real F.
        return ScoreResult(0, "N/A", False, 0, 0, 0, assessable=False)

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
    )
