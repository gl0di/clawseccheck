"""C-804 - OpenClaw 2026.11.5 stopped routing pre-GPT-5 OpenAI models to the Codex harness.

`withRuntimePolicy` (provider-policy-api-*.mjs) drops `codex` from an OpenAI route when the model
id matches `OPENAI_PRE_GPT5_MODEL_ID_PATTERN` = /^(?:ft:)?(?:gpt-3\\.5|gpt-4|o[134])/. The port
applies it from 2026.11.5; earlier builds keep the old rule. Separately,
`cloudWorkers.requiredProfile` makes `resolveAgentHarnessPolicy` return the embedded runtime for
every ref, which the port does not model, so it answers UNKNOWN there on every build.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import harnessruntime as hr

OLD, NEW, NEWEST = (2026, 11, 4), (2026, 11, 5), (2026, 11, 6)
NEWER = (2026, 11, 7)  # C-810: the battery is unchanged on 2026.11.7


def _cfg(model):
    return {"agents": {"defaults": {"model": model}}}


@pytest.mark.parametrize("ref", ["openai/o3", "openai/o1", "openai/o4-mini", "openai/gpt-4o",
                                 "openai/gpt-4.1", "openai/gpt-3.5-turbo", "openai/ft:gpt-4o-mini",
                                 "OpenAI/O3", "openai/o3:work"])
def test_a_pre_gpt5_openai_model_no_longer_implies_codex_from_2026_11_5(ref):
    assert hr.codex_harness_reach(_cfg(ref), OLD, environ={}).answer == hr.YES
    for build in (NEW, NEWEST, NEWER):
        got = hr.codex_harness_reach(_cfg(ref), build, environ={})
        assert got.answer != hr.YES, (ref, build, got)


@pytest.mark.parametrize("ref", ["openai/gpt-5", "openai/codex-mini", "openai/o5",
                                 "openai/zzz-not-a-model", "openai/gpt-5.1"])
def test_other_openai_models_still_imply_codex(ref):
    for build in (OLD, NEW, NEWEST, NEWER):
        assert hr.codex_harness_reach(_cfg(ref), build, environ={}).answer == hr.YES, (ref, build)


def test_the_pattern_is_the_vendors_verbatim():
    assert hr._OPENAI_PRE_GPT5_MODEL_ID_RE.pattern == r"^(?:ft:)?(?:gpt-3\.5|gpt-4|o[134])"
    assert hr._PRE_GPT5_RULE_MIN == (2026, 11, 5)


def test_the_real_battery_row_that_moved_is_not_a_yes():
    """fuzz:185 is the row the 2026.11.5 battery broke: the vendor says no codex there."""
    data = json.loads((Path(__file__).parent / "data" / "harnessruntime_battery.json")
                      .read_text(encoding="utf-8"))
    row = next(r for r in data["rows"] if r["label"] == "fuzz:185")
    assert row["oracle"]["runtimes"] == []
    assert hr.codex_harness_reach(row["cfg"], NEWEST, environ=row["env"] or {}).answer != hr.YES
    # positive control: under the old rule the port would claim YES there
    assert hr.codex_harness_reach(row["cfg"], OLD, environ=row["env"] or {}).answer == hr.YES


@pytest.mark.parametrize("profile,gated", [
    ("gpu", True), ({}, True), ([], True), (1, True),
    ("", False), (None, False), (0, False), (False, False),
])
def test_a_required_cloud_worker_profile_makes_the_answer_unknown_on_every_build(profile, gated):
    cfg = {"agents": {"defaults": {"model": "openai/gpt-5"}},
           "cloudWorkers": {"requiredProfile": profile}}
    for build in (OLD, NEWEST):
        got = hr.codex_harness_reach(cfg, build, environ={})
        if gated:
            assert got.answer == hr.UNKNOWN and "requiredProfile" in got.reasons[0], (profile, got)
        else:
            assert got.answer == hr.YES, (profile, got)
