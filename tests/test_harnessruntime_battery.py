"""Offline replay of the vendor differential for ``clawseccheck.harnessruntime``.

``tests/data/harnessruntime_battery.json`` was produced by EXECUTING OpenClaw's own
``collectConfiguredAgentHarnessRuntimes`` / ``collectConfiguredModelRefs`` /
``resolveAgentHarnessPolicy`` (see ``tests/_harnessoracle.py``) -- the battery existed
before the port did, so it is an independent oracle rather than a fit to the port. This file
replays it with no node and no dist, the same split as ``test_toolgrant_battery.py``; the
live regeneration + drift check is ``test_harnessruntime_dist_grounding.py`` (local-only).

THE CONTRACT is soundness, not agreement. ``unknown`` is always a permitted answer; what is
never permitted is a definite answer the vendor contradicts:

* port ``yes`` => the vendor's oracle set contains ``codex``
* port ``no``  => the vendor's oracle set does not contain ``codex``, AND (the default-model
  trap) the vendor could not have been answering ``[]`` merely because nothing was
  configured -- asserted separately below on the rows that name no model.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import harnessruntime as hr

DATA = json.loads((Path(__file__).parent / "data" / "harnessruntime_battery.json")
                  .read_text(encoding="utf-8"))
ROWS = DATA["rows"]
BUILD = tuple(int(x) for x in DATA["build"].split("."))


def _reach(row, version=BUILD):
    return hr.codex_harness_reach(row["cfg"], version, environ=row["env"])


@pytest.mark.parametrize("row", ROWS, ids=[r["label"] for r in ROWS])
def test_port_is_sound_against_the_vendor(row):
    got = _reach(row)
    oracle = row["oracle"]
    if "error" in oracle:
        # The vendor itself threw on this shape: nothing definite can be claimed.
        assert got.answer == hr.UNKNOWN, (row["label"], got, oracle)
        return
    has_codex = "codex" in oracle["runtimes"]
    if got.answer == hr.YES:
        assert has_codex, (row["label"], got, oracle)
    elif got.answer == hr.NO:
        assert not has_codex, (row["label"], got, oracle)


def test_model_refs_equal_the_vendors_enumeration_exactly():
    """An under-enumeration is what would let ``no`` ignore a ref that runs Codex."""
    checked = 0
    for row in ROWS:
        if "error" in row["oracle"]:
            continue
        ours = [v for _, v in hr.model_refs(row["cfg"])]
        assert ours == row["oracle"]["refs"], (row["label"], ours, row["oracle"]["refs"])
        checked += 1
    assert checked > 300


def test_battery_is_a_real_sweep_and_not_vacuous():
    """A port that always answered ``unknown`` would pass the soundness test above. Every
    answer must occur, and definite answers must be a large share of the hand+grammar rows
    (the corpus rows mostly name no model, so they are legitimately ``unknown``)."""
    designed = [r for r in ROWS if not r["label"].startswith(("fixture:", "fuzz:"))]
    answers = [_reach(r).answer for r in designed]
    assert set(answers) == {hr.YES, hr.NO, hr.UNKNOWN}
    definite = sum(1 for a in answers if a != hr.UNKNOWN)
    assert definite >= len(designed) * 0.5, (definite, len(designed))
    fuzz = [_reach(r).answer for r in ROWS if r["label"].startswith("fuzz:")]
    assert len(fuzz) >= 300 and set(fuzz) == {hr.YES, hr.NO, hr.UNKNOWN}
    assert len(ROWS) >= 700
    fixture_rows = [r for r in ROWS if r["label"].startswith("fixture:")]
    assert len(fixture_rows) >= 50, "the local config corpus is part of the battery"
    # the vendor side is not one-sided either
    assert {"codex" in r["oracle"].get("runtimes", []) for r in ROWS} == {True, False}


def test_the_oracle_never_says_no_because_nothing_was_configured():
    """The default-model trap, pinned on the data: the vendor collector returns [] for a
    config naming no model, yet the build's default model is an OpenAI one. The port must
    not answer ``no`` there."""
    for label in ("empty", "entries-agent-no-model-no-defaults", "roster-only-no-defaults",
                  "number-model", "empty-string-model", "bare-model-no-slash",
                  "entries-agent-no-model-defaults-anthropic"):
        row = next(r for r in ROWS if r["label"] == label)
        got = _reach(row)
        if label == "entries-agent-no-model-defaults-anthropic":
            # defaults name a model, so every agent inherits an explicit non-openai one.
            assert got.answer == hr.NO
        else:
            assert got.answer == hr.UNKNOWN, (label, got)


# ------------------------------------------------------------------ version gate

def _step(version, delta):
    """The build immediately below/above the window — where extrapolating is most tempting.

    Derived from the constants rather than written as a literal: every re-baseline moves the
    window (2026.9.4 -> 2026.9.5 did), and a literal here only records where the window used
    to be. What the constants must NOT be trusted for is whether they match the INSTALLED
    build — ``test_harnessruntime_dist_grounding`` grounds that against the real dist."""
    major, minor, patch = version[0], version[1], version[2]
    if patch + delta < 0:
        return (major, minor - 1, 99)
    return (major, minor, patch + delta)


BELOW_WINDOW = _step(hr.ORACLE_MIN, -1)
ABOVE_WINDOW = _step(hr.ORACLE_MAX, +1)


@pytest.mark.parametrize("version", [None, (), BELOW_WINDOW, ABOVE_WINDOW,
                                     (2026, 8, 2), (2026, 7, 1, 2), (2026, 10, 1), (2027, 1, 1)])
def test_outside_the_validated_window_or_unknown_is_always_unknown(version):
    for label in ("openai-primary", "anthropic-primary", "pin-provider-codex"):
        row = next(r for r in ROWS if r["label"] == label)
        assert _reach(row, version).answer == hr.UNKNOWN


def test_inside_the_validated_window_answers_are_definite():
    row = next(r for r in ROWS if r["label"] == "openai-primary")
    assert _reach(row, hr.ORACLE_MIN).answer == hr.YES
    assert _reach(row, hr.ORACLE_MAX).answer == hr.YES
    # a correction release of the validated build is the same code family
    assert _reach(row, hr.ORACLE_MAX + (1,)).answer == hr.YES


def test_a_newer_build_is_never_definite_until_the_battery_is_rerun():
    """The dangerous direction is a wrong `no` (a live WARN turned PASS). A build newer than the
    one the port was validated on is an unmodelled input, so it must degrade, not extrapolate.

    Not hypothetical: regenerating this battery on 2026.9.5 changed the VENDOR's own answer on
    six of the 770 rows — 9.5 throws (``Object.keys(undefined)`` on ``params: null``, and
    ``value?.id?.trim`` on a numeric ``agentRuntime.id``) where 9.4 returned a runtime."""
    for label in ("openai-primary", "anthropic-primary", "pin-provider-codex"):
        row = next(r for r in ROWS if r["label"] == label)
        for newer in (ABOVE_WINDOW, (2026, 10, 1), (2027, 1, 1), (2026, 9, 9)):
            assert _reach(row, newer).answer == hr.UNKNOWN, (label, newer)


def test_reasons_carry_paths_never_values():
    row = next(r for r in ROWS if r["label"] == "pin-provider-codex")
    got = _reach(row)
    assert got.reasons and all("codex" not in r.replace("agentRuntime", "") for r in got.reasons)


def test_a_non_dict_config_is_unknown():
    for cfg in (None, [], "x", 5):
        assert hr.codex_harness_reach(cfg, BUILD).answer == hr.UNKNOWN
