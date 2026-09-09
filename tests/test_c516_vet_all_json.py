"""C-516: --vet-all --json.

Every other vet-* mode (--vet-skill/--vet-plugin/--vet-mcp/--vet-source) already supports
--json via report.render_vet_json; --vet-all was the one left text-only, printing a
"note: --json has no effect with --vet-all" to stderr and the ordinary prose to stdout
regardless of the flag. Not a structural gap: SkillSweep.findings already carries exactly
what a single-target --vet-skill --json call builds a profile from.

Covers: valid JSON parses, the per-skill payload shape matches render_vet_json's own
(reused via report._vet_json_payload, not reinvented), a real FAIL/WARN skill surfaces in
the envelope, the discovery-incomplete completeness signal (CLAWSECCHECK-B-787's same
vocabulary) reaches this surface too, and the flag-coherence "no effect" note is gone for
this specific combination while every other mode's note is untouched.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

from clawseccheck import cli
from clawseccheck.cli import main, vet_all
from clawseccheck.cli import SkillSweep

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_CLEAN_MD = """\
---
name: word-counter
description: Count the words in a file the user names.
---
# Word Counter
Count the words in a file the user names. Ask before reading other files.
"""


def _make_skill(base: Path, name: str, content: str = _CLEAN_MD) -> Path:
    skill_dir = base / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
    return skill_dir


# ---------------------------------------------------------------------------
# valid JSON, shape, and the no-effect note
# ---------------------------------------------------------------------------

def test_vet_all_json_produces_valid_parseable_json(tmp_path, capsys):
    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")
    rc = main(["--vet-all", "--json", "--home", str(tmp_path)])
    out = capsys.readouterr().out
    payload = json.loads(out)  # raises if not valid JSON
    assert rc == 0
    assert payload["tool"] == "clawseccheck"
    assert payload["mode"] == "vet-all"
    assert payload["complete"] is True
    assert payload["notScanned"] == []
    assert payload["discoveryIncompleteReasons"] == []
    assert {s["target_type"] for s in payload["skills"]} == {"skill"}
    assert {Path(s["target"]).name for s in payload["skills"]} == {"alpha", "beta"}


def test_vet_all_json_no_effect_note_is_gone(tmp_path, capsys):
    """The generic _flag_coherence_notes mechanism must no longer fire for this pair --
    confirmed by checking stderr is silent about it, not just that stdout parses."""
    _make_skill(tmp_path, "alpha")
    main(["--vet-all", "--json", "--home", str(tmp_path)])
    err = capsys.readouterr().err
    assert "--json" not in err
    assert "has no effect" not in err


def test_vet_all_without_json_is_unaffected(tmp_path, capsys):
    """Regression: the plain-text path (no --json) must render exactly as before --
    prose, not JSON."""
    _make_skill(tmp_path, "alpha")
    rc = main(["--vet-all", "--home", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "alpha" in out
    assert "Aggregate summary" in out
    try:
        json.loads(out)
        raise AssertionError("plain --vet-all output must not parse as JSON")
    except json.JSONDecodeError:
        pass


def test_vet_all_json_matches_single_skill_vet_json_shape(tmp_path, capsys):
    """The per-skill entries must carry the SAME keys render_vet_json's own top-level
    payload does (reused via report._vet_json_payload) -- not a parallel, drifting shape."""
    _make_skill(tmp_path, "alpha")
    main(["--vet-all", "--json", "--home", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    skill = payload["skills"][0]
    single_rc = main(["--vet-skill", str(tmp_path / "skills" / "alpha"), "--json"])
    single = json.loads(capsys.readouterr().out)
    assert single_rc == 0
    assert set(skill.keys()) == set(single.keys())
    assert skill["target_type"] == single["target_type"] == "skill"


# ---------------------------------------------------------------------------
# a real FAIL/WARN skill surfaces in the envelope
# ---------------------------------------------------------------------------

def test_vet_all_json_surfaces_a_real_warn_verdict():
    """fixtures/bad_b98_manifest_absent/skills/net-fetcher: subprocess(shell=True) with no
    allowed-tools manifest -- a real, pre-existing WARN-capable fixture, not synthesized
    for this test."""
    home = FIXTURES / "bad_b98_manifest_absent"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = vet_all(home, ascii_only=True, json_output=True)
    payload = json.loads(buf.getvalue())
    assert len(payload["skills"]) == 1
    skill = payload["skills"][0]
    assert skill["verdict"] != "INSTALL"
    assert rc == 1


# ---------------------------------------------------------------------------
# discovery-incomplete completeness signal (same vocabulary as B-787)
# ---------------------------------------------------------------------------

def test_vet_all_json_discloses_discovery_incomplete_reasons(tmp_path, monkeypatch, capsys):
    """B-787's same discovery_incomplete_reasons signal must reach this envelope too --
    not a second, invented completeness vocabulary."""
    def fake(home_dir, ascii_only=False, sweep_budget_s=0.0, narrate=True, ctx=None):
        return SkillSweep(
            home_dir=Path(home_dir), checked_dirs=[Path(home_dir)],
            rows=[("clean-one", "PASS", 0)],
            findings=[], truncated=True,
            discovery_incomplete_reasons=["skill discovery under '/x' stopped early"],
        )
    monkeypatch.setattr(cli, "sweep_installed_skills", fake)
    rc = main(["--vet-all", "--json", "--home", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["complete"] is False
    assert payload["discoveryIncompleteReasons"] == ["skill discovery under '/x' stopped early"]
    assert rc == 1


def test_vet_all_json_empty_fleet_still_emits_envelope(tmp_path, capsys):
    """no_targets must still emit a parseable envelope (empty skills[]), not silence --
    a --json caller has nowhere else to read the completeness signal from."""
    rc = main(["--vet-all", "--json", "--home", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["skills"] == []
    assert rc == 0
