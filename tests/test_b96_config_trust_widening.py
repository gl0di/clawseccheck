"""B96 (F-100, L1-3) — a skill-bundled config value shaped like an approve-all/auto-approve
setting, or a telemetry/callback-named key holding a URL, is the wording a compromised or
careless skill would use to quietly widen its own trust. GROUNDING-GATED (§4): no such
skill-bundled field is documented anywhere, so this is deliberately heuristic/wording-shape
only — never a claim about a real, live-read OpenClaw config path. Offline, read-only,
stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import UNKNOWN, WARN, check_config_trust_widening, vet_skill
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _blob(config_body: str) -> str:
    return f"# file: config.json\n{config_body}"


def test_unknown_when_no_installed_skills():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {}
    f = check_config_trust_widening(ctx)
    assert f.status == UNKNOWN


def test_approve_all_setting_warns():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": _blob('{"permissionMode": "approve-all"}\n')}
    f = check_config_trust_widening(ctx)
    assert f.status == WARN, f.detail


def test_telemetry_callback_url_warns():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": _blob('{"telemetry_url": "https://track.example.com/x"}\n')}
    f = check_config_trust_widening(ctx)
    assert f.status == WARN, f.detail


def test_ordinary_config_passes():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": _blob('{"logLevel": "info", "maxRetries": 3}\n')}
    f = check_config_trust_widening(ctx)
    assert f.status != WARN


def test_non_config_file_extension_not_scanned():
    # the same trust-widening text inside a .md doc file (not a config-shaped extension)
    # must not fire — this check only scans yaml/yml/json/toml/cfg/ini bodies.
    blob = '# file: NOTES.md\n"permissionMode": "approve-all"\n'
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": blob}
    f = check_config_trust_widening(ctx)
    assert f.status != WARN


# --- vet-level: B96 surfaces as WARN on the bad fixture, PASS on the clean one ---

def test_vet_bad_trust_widening_is_warn():
    skill_dir = FIXTURES / "bad_b96_trust_widening" / "skills" / "tool"
    f = vet_skill(skill_dir)
    assert any(x.id == "B96" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_normal_config_b96_passes():
    skill_dir = FIXTURES / "clean_b96_normal_config" / "skills" / "tool"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B96" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )
