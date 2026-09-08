"""B-507 — "Skills (N installed)" was false in both directions.

1. ClawSecCheck's own genuine install is content-verified out of ctx.installed_skills
   (B-265, deliberate and unchanged) but the exclusion was completely undisclosed --
   the inventory count just quietly shrank by one, and nothing in the text or --json
   output ever named the excluded skill.
2. Skills discovered via the `plugin-skills` symlink root (OpenClaw-core / plugin
   extensions bundled inside a plugin's own package, e.g. browser-automation/canvas)
   were folded into the same "(N installed)" figure as a marketplace-installed skill,
   implying the user chose them when they did not and cannot remove them independently
   of the plugin.

This file pins the fix: both are now disclosed, in the text renderer AND the additive
JSON `inventory.self_excluded` field, without weakening B-265's content verification --
a look-alike named "clawseccheck" that fails the engine-marker check must still be
scanned normally and must NOT be reported as self-excluded.

Offline, read-only, stdlib only; everything is built under pytest's tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.collector import _OWN_ENGINE_MARKERS, Context, collect
from clawseccheck.report import build_inventory, render_json, render_subject_inventory
from clawseccheck.scoring import compute


def _cfg(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8")
    cfg.chmod(0o600)


def _skill_md(d: Path, name: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A helper skill.\n---\n\nDoes something local.\n",
        encoding="utf-8",
    )


def _write_own_engine(skill_dir: Path) -> None:
    """A genuine, content-verified ClawSecCheck install under `skill_dir` (B-265)."""
    _skill_md(skill_dir, "clawseccheck")
    checks = skill_dir / "checks"
    checks.mkdir(parents=True, exist_ok=True)
    (checks / "_engine.py").write_text("\n".join(_OWN_ENGINE_MARKERS), encoding="utf-8")


def _render(ctx) -> tuple[str, dict]:
    """(text, json) rendered the same way the CLI does, from the SAME ctx/findings."""
    text = render_subject_inventory([], ctx, ascii_only=True)
    score = compute([], ctx=ctx)
    payload = json.loads(render_json([], score, ctx=ctx))
    return text, payload["inventory"]


# ------------------------------------------------------ genuine own install, disclosed

def test_genuine_own_install_alongside_another_skill_is_disclosed(tmp_path):
    home = tmp_path / ".openclaw"
    _cfg(home)
    _write_own_engine(home / "skills" / "clawseccheck")
    _skill_md(home / "skills" / "notes-helper", "notes-helper")

    ctx = collect(home)
    # B-265 still holds: the genuine install never enters the graded roster.
    assert ctx.installed_skills == {"notes-helper": ctx.installed_skills["notes-helper"]}
    assert ctx.self_excluded_skills == ["clawseccheck"]

    text, inv = _render(ctx)
    # The count must NOT be silently reduced to "(1 installed)" with no trace at all --
    # the excluded skill must be named somewhere in the block.
    assert "clawseccheck" in text
    assert "not graded" in text or "self-excluded" in text
    assert "(1 installed" in text  # only notes-helper counts as a graded install
    assert inv["self_excluded"] == ["clawseccheck"]
    assert "notes-helper" in {s["name"] for s in inv["skills"]}
    assert "clawseccheck" not in {s["name"] for s in inv["skills"]}


# ------------------------------------------------------- look-alike must NOT be cloaked

def test_lookalike_named_clawseccheck_without_engine_is_scanned_not_self_excluded(tmp_path):
    """B-265's guarantee, pinned from the disclosure angle: a directory that merely
    CALLS itself clawseccheck (no engine markers) must be graded normally and must
    never be reported as self-excluded -- that would let a malicious skill borrow the
    real install's "not graded" pass."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    squat = home / "skills" / "clawseccheck"
    _skill_md(squat, "clawseccheck")
    (squat / "README.md").write_text("Not the real thing.\n", encoding="utf-8")

    ctx = collect(home)
    assert "clawseccheck" in ctx.installed_skills, "look-alike must be scanned, not cloaked"
    assert ctx.self_excluded_skills == []

    text, inv = _render(ctx)
    assert inv["self_excluded"] == []
    assert "clawseccheck" in {s["name"] for s in inv["skills"]}
    assert "not graded" not in text
    assert "self-excluded" not in text
    assert "(1 installed)" in text


# ------------------------------------------------------------- bundled-only wording

def test_only_bundled_extension_wording_does_not_claim_user_installed(tmp_path):
    """A skill reached only via the plugin-skills symlink root (an OpenClaw/plugin
    extension bundled inside the plugin's own package, not user-chosen or separately
    removable) must not be presented as "(N installed)" -- that flatly overstates what
    the user did."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    plugin_pkg = tmp_path / "npm-global" / "some-plugin" / "skills" / "browser-automation"
    _skill_md(plugin_pkg, "browser-automation")
    (home / "plugin-skills").mkdir(parents=True, exist_ok=True)
    (home / "plugin-skills" / "browser-automation").symlink_to(plugin_pkg, target_is_directory=True)

    ctx = collect(home)
    assert ctx.installed_skills.keys() == {"browser-automation"}
    assert ctx.installed_skill_bundled == {"browser-automation"}
    assert ctx.self_excluded_skills == []

    text, inv = _render(ctx)
    assert "1 installed" not in text  # must not claim the user installed it
    assert "bundled" in text
    assert inv["skills"][0]["name"] == "browser-automation"


def test_zero_installed_skills_only_bundled_wording_never_claims_installed(tmp_path):
    """Degenerate case named explicitly in the task: nothing user-installed at all, only
    a bundled extension -- 'Skills (none installed)' must not be reachable here since
    something WAS found, and the count line must still never say the user installed it."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    plugin_pkg = tmp_path / "npm-global" / "openclaw" / "dist" / "extensions" / "canvas" / "skills" / "canvas"
    _skill_md(plugin_pkg, "canvas")
    (home / "plugin-skills").mkdir(parents=True, exist_ok=True)
    (home / "plugin-skills" / "canvas").symlink_to(plugin_pkg, target_is_directory=True)

    ctx = collect(home)
    text, inv = _render(ctx)
    assert "none installed" not in text
    assert "1 installed" not in text
    assert "bundled" in text
    assert inv["skills"][0]["name"] == "canvas"


# -------------------------------------------------------------- text/json agreement

def test_text_and_json_agree_on_self_excluded_and_installed_counts(tmp_path):
    home = tmp_path / ".openclaw"
    _cfg(home)
    _write_own_engine(home / "skills" / "clawseccheck")
    _skill_md(home / "skills" / "alpha", "alpha")
    _skill_md(home / "skills" / "beta", "beta")

    ctx = collect(home)
    text, inv = _render(ctx)

    assert len(inv["self_excluded"]) == 1
    assert f"({len(inv['self_excluded'])} self-excluded" in text or "1 self-excluded" in text
    assert len(inv["skills"]) == 2
    assert "(2 installed" in text
    assert {s["name"] for s in inv["skills"]} == {"alpha", "beta"}


# ----------------------------------------------------------------- neutral ctx shape

def test_self_excluded_field_defaults_empty_on_a_bare_context():
    ctx = Context(home=Path("/nonexistent-b507-test-home"))
    assert ctx.self_excluded_skills == []
    assert ctx.installed_skill_bundled == set()
    inv = build_inventory([], ctx)
    assert inv["self_excluded"] == []
