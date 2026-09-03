"""B-717: the `[view]` tag went unexplained whenever nothing else was ungraded.

`render_trend` renders a `[view]`-tagged row for every bare `--trend` invocation
(B-579: looking at the trend must not degrade it, so the act of looking is recorded
and tagged rather than dropped). The sentence explaining what that tag MEANS lived
inside the `if holes:` block, next to the "N of M runs have no grade" disclosure.

`holes` counts ungraded rows that are **not** view rows, so `holes == 0` is reached
by two ordinary populations:

* every real run completed the five-layer check, and the user looked at the trend;
* a fresh store where the only rows so far are the looking itself.

In both, `[view]` rows rendered with no explanation anywhere on screen. The second
is the worse one: the entire display is `[view]` rows and nothing says what that is.

The explanation must therefore be reachable whenever a `[view]` row is on screen,
independent of `holes`. It cannot simply be dedented: the existing wording refers to
"that ratio", meaning the holes sentence printed above it, and that sentence does not
exist when `holes == 0` — a dangling reference is not an explanation.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

from clawseccheck.history import render_trend

# The marker every one of these cases is about. Kept as one constant so a reworded
# explanation moves this test in one place rather than in five assertions.
TAG = "[view]"


def _graded(date, score=70, grade="C", source="audit"):
    return {"date": date, "score": score, "grade": grade, "graded": True,
            "source": source}


def _view(date):
    """A row recorded by the act of looking: structurally ungraded, source 'view'."""
    return {"date": date, "score": None, "grade": None, "graded": False,
            "source": "view"}


def _ungraded_real(date):
    """A real run whose five-layer check did not complete -- this one IS a hole."""
    return {"date": date, "score": None, "grade": None, "graded": False,
            "source": "audit"}


def _explains_the_tag(out: str) -> bool:
    """True when the output says what a [view] row IS, not merely that one exists.

    Deliberately not a substring match on the whole sentence: the wording is allowed
    to change, the guarantee is not. We require the tag to be named somewhere OTHER
    than on a row line -- i.e. in prose that mentions looking/trend rather than in a
    `date  no grade  [view]` row.
    """
    prose = [ln for ln in out.splitlines() if TAG in ln and "no grade" not in ln]
    return any("look" in ln.lower() for ln in prose)


def test_a_view_row_beside_only_graded_runs_is_explained():
    """holes == 0 because every real run is graded; a [view] row is still on screen."""
    out = render_trend([_graded("2026-09-01"), _graded("2026-09-02"), _view("2026-09-03")])

    # Positive control: the case really is the one under test.
    assert "no grade:" not in out, (
        "expected holes == 0 for this population -- if the holes sentence is present "
        "the fixture no longer exercises B-717's branch"
    )
    assert TAG in out, "the [view] row itself must still render (B-579)"

    assert _explains_the_tag(out), (
        "a [view] row rendered with no explanation of what the tag means:\n\n" + out
    )


def test_a_store_holding_only_view_rows_is_explained():
    """The fresh-store case: nothing but the act of looking, so the whole screen is
    [view] rows -- and `checkable` is 0, so even a holes sentence would say '0 of 0'."""
    out = render_trend([_view("2026-09-01"), _view("2026-09-02")])

    assert "no grade:" not in out, "expected holes == 0 when every row is a view row"
    assert out.count(TAG) >= 2, "both view rows must render"

    assert _explains_the_tag(out), (
        "a store consisting entirely of [view] rows explained none of them:\n\n" + out
    )


def test_the_explanation_does_not_dangle_when_no_ratio_was_printed():
    """Guards the fix from being a bare dedent.

    The pre-existing wording says the ratio covers some rows "and the other N, tagged
    [view], ..." -- which only parses when the ratio was printed. With holes == 0 there
    is no ratio, so any sentence pointing back at one is a broken reference.
    """
    out = render_trend([_graded("2026-09-01"), _view("2026-09-02")])
    assert "no grade:" not in out

    assert "that ratio" not in out, (
        "the explanation refers back to a ratio that was never printed:\n\n" + out
    )


def test_the_holes_case_still_explains_the_tag():
    """Regression control for B-579: when holes > 0 the disclosure must still appear,
    and must still account for the view rows excluded from its ratio."""
    out = render_trend([_graded("2026-09-01"), _ungraded_real("2026-09-02"),
                        _view("2026-09-03")])

    assert "no grade:" in out, "the holes disclosure must survive this change"
    assert _explains_the_tag(out), "B-579's own case regressed:\n\n" + out


def test_no_view_row_means_no_explanation():
    """Negative control: the explanation is tied to a [view] row being on screen, not
    emitted unconditionally. Without one, nothing about looking should be said."""
    out = render_trend([_graded("2026-09-01"), _ungraded_real("2026-09-02")])

    assert TAG not in out
    assert "look" not in out.lower(), (
        "explained a tag that is not on screen:\n\n" + out
    )
