"""Deterministic scoring: weighted pass-rate with honesty hard-caps.

- PASS -> full weight, WARN -> half weight, FAIL -> 0, UNKNOWN -> excluded.
- Hard caps: any FAILed CRITICAL -> score capped at 49; any FAILed HIGH -> 79.
  (You can never show an "A" with a critical hole open.)
"""
from __future__ import annotations

from dataclasses import dataclass

from .catalog import CRITICAL, FAIL, HIGH, PASS, UNKNOWN, WARN, WEIGHT, Finding

GRADES = [(90, "A"), (80, "B"), (70, "C"), (50, "D"), (0, "F")]


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


def compute(findings: list[Finding]) -> ScoreResult:
    scored = [f for f in findings if f.scored and f.status != UNKNOWN]
    total = sum(WEIGHT[f.severity] for f in scored)
    if total == 0:
        return ScoreResult(0, "F", False, 0, 0, 0)

    earned = 0.0
    for f in scored:
        w = WEIGHT[f.severity]
        if f.status == PASS:
            earned += w
        elif f.status == WARN:
            earned += w * 0.5
        # FAIL contributes 0

    raw = round(earned / total * 100)

    failed_crit = sum(1 for f in scored if f.status == FAIL and f.severity == CRITICAL)
    failed_high = sum(1 for f in scored if f.status == FAIL and f.severity == HIGH)

    score = raw
    if failed_crit:
        score = min(score, 49)
    elif failed_high:
        score = min(score, 79)

    return ScoreResult(
        score=score,
        grade=grade_for(score),
        capped=score != raw,
        raw_score=raw,
        failed_critical=failed_crit,
        failed_high=failed_high,
    )
