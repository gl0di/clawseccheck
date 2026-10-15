"""C-678: the grounding gap is machine-visible in `--json` and `--sarif`.

C-571/C-615 put the "this build's checks were grounded up to X, you run Y" disclosure on
every human surface (text, card, HTML, PDF). The two machine surfaces were left out, so a
CI pipeline that gates on `--json`/`--sarif` read a run on an un-grounded OpenClaw build
as plain clean. This pins the dedicated `grounding` object on both:

    {"grounded_max": "2026.9.9", "installed": "2026.9.10",
     "newer_than_grounded": true, "detail": "<the one sentence>"}

`newer_than_grounded` is a tri-state on purpose: `false` = the installed build is inside
the window, `null` = we cannot place it (unknown / unparseable / pre-release / too short),
`true` = past it. The key is ALWAYS present, so an absent key can never be read as "no gap".
Presentation only: score, grade, caps and every finding are untouched.

Builds are derived from `GROUNDED_MAX_VERSION`, never written as literals, so a
re-grounding bump needs no edit here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import clawseccheck
from clawseccheck import checks
from clawseccheck.cli import main
from clawseccheck.collector import collect
from clawseccheck.openclawdist import GROUNDED_MAX_VERSION
from clawseccheck.report import _grounding_gap_sentence, render_json
from clawseccheck.sarif import render_sarif
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_Y, _M, _P = GROUNDED_MAX_VERSION
_GROUNDED = f"{_Y}.{_M}.{_P}"
_NEWER = f"{_Y}.{_M}.{_P + 1}"
_OLDER = f"{_Y}.{_M}.{_P - 1}"

_KEYS = {"grounded_max", "installed", "newer_than_grounded", "detail"}


def _ctx_findings_score(installed):
    ctx = collect(FIXTURES / "home_safe")
    ctx.installed_dist_version = installed
    findings = checks.run_all(ctx)
    return ctx, findings, compute(findings, ctx=ctx)


def _json_block(ctx, findings, score) -> dict:
    return json.loads(render_json(findings, score, ctx=ctx))["grounding"]


def _sarif_block(ctx, findings, score) -> dict:
    log = json.loads(render_sarif(findings, score, tool_version="0.0.0", ctx=ctx))
    return log["runs"][0]["properties"]["grounding"]


_SURFACES = {"json": _json_block, "sarif": _sarif_block}


@pytest.mark.parametrize("surface", sorted(_SURFACES))
@pytest.mark.parametrize("installed", [_GROUNDED, _OLDER])
def test_in_window_build_is_false_with_no_detail(surface, installed):
    ctx, findings, score = _ctx_findings_score(installed)
    block = _SURFACES[surface](ctx, findings, score)
    assert set(block) == _KEYS
    assert block == {
        "grounded_max": _GROUNDED,
        "installed": installed,
        "newer_than_grounded": False,
        "detail": None,
    }
    assert _grounding_gap_sentence(ctx) is None


@pytest.mark.parametrize("surface", sorted(_SURFACES))
def test_build_one_patch_above_the_ceiling_carries_the_gap(surface):
    ctx, findings, score = _ctx_findings_score(_NEWER)
    block = _SURFACES[surface](ctx, findings, score)
    sentence = _grounding_gap_sentence(ctx)
    assert sentence is not None
    assert block["newer_than_grounded"] is True
    assert block["grounded_max"] == _GROUNDED
    assert block["installed"] == _NEWER
    # The ONE sentence, byte for byte -- not a second literal, not the marker-wrapped line.
    assert block["detail"] == sentence
    assert "⚠" not in block["detail"]
    assert not block["detail"].startswith("[!]")
    assert _GROUNDED in block["detail"] and _NEWER in block["detail"]


@pytest.mark.parametrize("surface", sorted(_SURFACES))
@pytest.mark.parametrize(
    "installed",
    [
        None,
        "",
        "not a version",
        f"{_Y}.{_M}",                 # too short to be a calendar release
        "0.0.0",
        f"{_NEWER}-beta.1",           # pre-release token: cannot be ordered
        f"{_NEWER}-rc.2",
        12345,                        # not a string
    ],
)
def test_unknown_or_unorderable_build_is_null_and_claims_no_gap(surface, installed):
    ctx, findings, score = _ctx_findings_score(installed)
    block = _SURFACES[surface](ctx, findings, score)
    assert block == {
        "grounded_max": _GROUNDED,
        "installed": None,
        "newer_than_grounded": None,
        "detail": None,
    }
    assert _grounding_gap_sentence(ctx) is None


def test_correction_release_of_the_ceiling_build_is_in_window():
    """`grounding_gap` compares three components; a `-1` correction sorts alongside."""
    ctx, findings, score = _ctx_findings_score(f"{_GROUNDED}-1")
    block = _json_block(ctx, findings, score)
    assert block["newer_than_grounded"] is False
    assert block["installed"] == _GROUNDED  # rebuilt from the three ints, not the raw string


def test_installed_is_rebuilt_from_ints_never_the_raw_string():
    ctx, findings, score = _ctx_findings_score(f"v{_NEWER}+build7")
    for block in (_json_block(ctx, findings, score), _sarif_block(ctx, findings, score)):
        assert block["newer_than_grounded"] is True
        assert block["installed"] == _NEWER


@pytest.mark.parametrize("surface", sorted(_SURFACES))
def test_key_is_present_without_a_context(surface):
    """The library shape (no ctx) still carries the key, as `null`, never an absent one."""
    ctx, findings, score = _ctx_findings_score(_NEWER)
    if surface == "json":
        block = json.loads(render_json(findings, score))["grounding"]
    else:
        block = json.loads(render_sarif(findings, score))["runs"][0]["properties"]["grounding"]
    assert block == {
        "grounded_max": _GROUNDED,
        "installed": None,
        "newer_than_grounded": None,
        "detail": None,
    }


def test_json_and_sarif_agree_for_the_same_run():
    ctx, findings, score = _ctx_findings_score(_NEWER)
    assert _json_block(ctx, findings, score) == _sarif_block(ctx, findings, score)


def test_presentation_only_nothing_else_in_the_json_moves():
    """Same findings, same score object: only `grounding` differs between a gap and no gap."""
    ctx, findings, score = _ctx_findings_score(_GROUNDED)
    clean = json.loads(render_json(findings, score, ctx=ctx))
    sarif_clean = json.loads(render_sarif(findings, score, ctx=ctx))
    ctx.installed_dist_version = _NEWER
    gap = json.loads(render_json(findings, score, ctx=ctx))
    sarif_gap = json.loads(render_sarif(findings, score, ctx=ctx))
    assert clean["grounding"] != gap["grounding"]
    clean.pop("grounding")
    gap.pop("grounding")
    assert clean == gap
    for log in (sarif_clean, sarif_gap):
        log["runs"][0]["properties"].pop("grounding")
    assert sarif_clean == sarif_gap


def test_cli_json_carries_the_gap(monkeypatch, capsys):
    monkeypatch.setattr(clawseccheck, "_installed_dist_version", lambda *a, **k: _NEWER)
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-history",
          "--no-sockets", "--no-deptree", "--no-host", "--json"])
    block = json.loads(capsys.readouterr().out)["grounding"]
    assert block["newer_than_grounded"] is True
    assert block["installed"] == _NEWER
    assert block["detail"]


def test_cli_sarif_carries_the_gap_and_in_window_is_false(monkeypatch, tmp_path):
    for installed, expected in ((_NEWER, True), (_GROUNDED, False)):
        monkeypatch.setattr(clawseccheck, "_installed_dist_version", lambda *a, _v=installed, **k: _v)
        out = tmp_path / f"{installed}.sarif"
        main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-history",
              "--no-sockets", "--no-deptree", "--no-host", "--sarif", str(out)])
        block = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["properties"]["grounding"]
        assert block["newer_than_grounded"] is expected
        assert (block["detail"] is not None) is expected
