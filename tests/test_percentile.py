"""Tests for clawcheck.percentile — offline illustrative reference distribution."""
from __future__ import annotations

from clawcheck.percentile import REFERENCE, percentile, render_percentile


# ---------------------------------------------------------------------------
# percentile() — correctness and contract tests
# ---------------------------------------------------------------------------

def test_percentile_100_is_100():
    assert percentile(100) == 100


def test_percentile_0_is_small():
    """Score of 0 should land well below the 50th percentile."""
    assert percentile(0) < 50


def test_percentile_bounds_are_0_to_100():
    for s in range(0, 101):
        p = percentile(s)
        assert 0 <= p <= 100, f"percentile({s}) = {p} out of [0, 100]"


def test_percentile_monotone_spot_check():
    """Key spot-check: percentile is non-decreasing at three representative points."""
    assert percentile(20) <= percentile(50) <= percentile(90)


def test_percentile_monotone_full():
    """percentile must be non-decreasing over the entire 0..100 range."""
    values = [percentile(s) for s in range(101)]
    for i in range(len(values) - 1):
        assert values[i] <= values[i + 1], (
            f"percentile not monotone: percentile({i})={values[i]} "
            f"> percentile({i + 1})={values[i + 1]}"
        )


def test_percentile_deterministic():
    """Repeated calls with the same input must return identical results."""
    for s in (0, 30, 55, 80, 100):
        first = percentile(s)
        for _ in range(5):
            assert percentile(s) == first, f"percentile({s}) is not deterministic"


def test_percentile_knot_points_match_reference():
    """Every declared REFERENCE knot (score, p) must satisfy percentile(score) == p."""
    for score, expected_p in REFERENCE:
        assert percentile(score) == expected_p, (
            f"percentile({score}) = {percentile(score)}, expected {expected_p} "
            f"from REFERENCE"
        )


def test_percentile_clamps_above_100():
    """Scores above 100 should be clamped and return the same as percentile(100)."""
    assert percentile(101) == percentile(100) == 100
    assert percentile(999) == 100


def test_percentile_clamps_below_0():
    """Scores below 0 should be clamped and return the same as percentile(0)."""
    assert percentile(-1) == percentile(0)
    assert percentile(-50) == percentile(0)


def test_percentile_interpolation_between_knots():
    """A midpoint between two knots should fall between their percentile values."""
    # Use the first pair from REFERENCE: (0, 1) and (20, 5).
    s0, p0 = REFERENCE[0]
    s1, p1 = REFERENCE[1]
    mid = (s0 + s1) // 2
    p_mid = percentile(mid)
    assert p0 <= p_mid <= p1, (
        f"Interpolated percentile({mid})={p_mid} not in [{p0}, {p1}]"
    )


# ---------------------------------------------------------------------------
# render_percentile() — output format tests
# ---------------------------------------------------------------------------

def test_render_contains_percent_value():
    """The rendered string must contain the numeric percentile for the score."""
    for score in (0, 50, 100):
        p = percentile(score)
        rendered = render_percentile(score)
        assert str(p) in rendered, (
            f"render_percentile({score}) missing percentile value {p}: {rendered!r}"
        )


def test_render_contains_offline():
    """The rendered string must contain 'offline' to signal no network data."""
    for score in (0, 45, 100):
        rendered = render_percentile(score)
        assert "offline" in rendered.lower(), (
            f"render_percentile({score}) missing 'offline': {rendered!r}"
        )


def test_render_contains_reference():
    """The rendered string must contain 'reference' to signal illustrative data."""
    for score in (0, 60, 100):
        rendered = render_percentile(score)
        assert "reference" in rendered.lower(), (
            f"render_percentile({score}) missing 'reference': {rendered!r}"
        )


def test_render_is_single_line():
    """render_percentile must return exactly one line (no embedded newlines)."""
    for score in (0, 55, 100):
        rendered = render_percentile(score)
        assert "\n" not in rendered, (
            f"render_percentile({score}) contains a newline: {rendered!r}"
        )


def test_render_deterministic():
    """render_percentile must return the same string on repeated calls."""
    for score in (10, 70, 100):
        first = render_percentile(score)
        for _ in range(5):
            assert render_percentile(score) == first, (
                f"render_percentile({score}) is not deterministic"
            )


def test_render_ascii_only_flag_accepted():
    """ascii_only=True must be accepted without error (API compatibility)."""
    result = render_percentile(50, ascii_only=True)
    assert isinstance(result, str)
    assert len(result) > 0


def test_render_100_says_100_percent():
    """A perfect score must report 100% in the rendered output."""
    rendered = render_percentile(100)
    assert "100" in rendered
