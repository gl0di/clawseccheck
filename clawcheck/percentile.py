"""Offline, illustrative percentile ranking for ClawCheck scores.

This module provides a BUILT-IN reference distribution — it is NOT telemetry,
NOT collected from real users, and involves NO network calls whatsoever.
Everything is computed locally, deterministically, from a hand-crafted
illustrative CDF that represents a plausible spread of security postures.

The REFERENCE list is a sorted sequence of (score, cumulative_percentile) pairs
that together define a piecewise-linear cumulative distribution function (CDF).
It encodes the assumption that most unconfigured installations cluster in the
40-70 score range, with few at the extremes — a defensible shape for a first-
run self-audit tool whose users have not yet acted on any recommendations.

This is an OFFLINE, ILLUSTRATIVE reference profile. It must never be presented
as reflecting live data, aggregate telemetry, or any population of real users.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Reference CDF
# ---------------------------------------------------------------------------
# Each entry is (score, cumulative_percentile): the percentage of the
# reference distribution that falls AT OR BELOW that score value.
# The list must be sorted ascending by score; the final entry must be (100, 100).
# Intermediate values are interpolated linearly.
#
# Rationale for this shape:
#   score  0 -> virtually nobody scores this low (fresh installs still pass basics)
#   score 20 -> bottom tail; severely misconfigured systems
#   score 40 -> below-average; common in default/unreviewed setups
#   score 55 -> median (p50); typical first-run result
#   score 70 -> above-average; some hardening applied
#   score 85 -> strong posture; most recommendations addressed
#   score 95 -> near-perfect; very few reach this level
#   score 100-> perfect score; top of distribution
REFERENCE: list[tuple[int, int]] = [
    (0,   1),
    (20,  5),
    (40, 25),
    (55, 50),
    (70, 72),
    (85, 90),
    (95, 97),
    (100, 100),
]


def percentile(score: int) -> int:
    """Return the percentile (0..100) for *score* within the reference profile.

    The result is the percentage of the reference distribution at or below
    *score*. The function is monotone non-decreasing; percentile(100) == 100.

    This is a purely local computation — no network, no telemetry.

    Args:
        score: An integer in 0..100 (clamped silently if out of range).

    Returns:
        An integer in 0..100 representing the percentile rank.
    """
    score = max(0, min(100, int(score)))

    # Exact match on a knot point.
    for s, p in REFERENCE:
        if score == s:
            return p

    # Below the first knot.
    if score < REFERENCE[0][0]:
        return REFERENCE[0][1]

    # Above the last knot (shouldn't happen after clamping to 100, but be safe).
    if score > REFERENCE[-1][0]:
        return REFERENCE[-1][1]

    # Piecewise-linear interpolation between the two bracketing knots.
    for i in range(len(REFERENCE) - 1):
        s0, p0 = REFERENCE[i]
        s1, p1 = REFERENCE[i + 1]
        if s0 <= score <= s1:
            if s1 == s0:
                return p0
            fraction = (score - s0) / (s1 - s0)
            return round(p0 + fraction * (p1 - p0))

    # Fallback (unreachable with a well-formed REFERENCE).
    return REFERENCE[-1][1]


def render_percentile(score: int, ascii_only: bool = False) -> str:
    """Return a one-line human-readable percentile label for *score*.

    The wording explicitly identifies the source as an offline, illustrative
    reference profile so it is never confused with live or crowd-sourced data.

    Args:
        score: An integer in 0..100.
        ascii_only: Unused; reserved for future ASCII-safe formatting.
                    Included for API consistency with other render functions.

    Returns:
        A string such as:
        "You score better than ~42% of the reference profile (offline, illustrative)."
    """
    p = percentile(score)
    return (
        f"You score better than ~{p}% of the reference profile "
        "(offline, illustrative)."
    )
