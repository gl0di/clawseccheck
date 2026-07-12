"""B104 (task F-089) — decommissioning / offboarding hygiene.

Read-only reconciliation for leftover attack surface after an incomplete offboarding:
duplicate skill installs (same declared name in >1 dir — stale auto-loadable copy) and
dead MCP entries (a configured stdio server whose absolute command path is gone).

§5: OpenClaw AUTO-LOADS skills by directory presence, so "installed but unreferenced" is
NOT an orphan signal — that sub-check is UNKNOWN-by-design and omitted. A bare MCP command
(npx/node) is never flagged (PATH/runtime-resolved); only an absolute missing path is.
Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_offboarding_hygiene
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_clean_wired_skills_pass():
    f = check_offboarding_hygiene(collect(FIXTURES / "clean_b104_wired"))
    assert f.status == PASS, f.detail


def test_duplicate_and_dead_mcp_warn():
    f = check_offboarding_hygiene(collect(FIXTURES / "bad_b104_offboarding"))
    assert f.status == WARN, f.detail
    ev = " ".join(f.evidence or [])
    assert "installed in 2 locations" in ev and "dupe" in ev   # duplicate skill
    assert "command path is missing" in ev                       # dead MCP


def test_no_home_is_unknown():
    c = Context(home=Path("/nonexistent-openclaw-home-xyz"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = {}
    assert check_offboarding_hygiene(c).status == UNKNOWN


def test_bare_mcp_command_not_flagged(tmp_path):
    # a bare command (npx) is PATH/runtime-resolved — never a dead-entry finding (§5).
    (tmp_path / "skills").mkdir()
    c = Context(home=tmp_path)
    c.config = {"mcp": {"servers": {"ok": {"command": "npx", "args": ["-y", "x"]}}}}
    c.bootstrap = {}
    c.installed_skills = {}
    assert check_offboarding_hygiene(c).status == PASS


def test_single_unreferenced_skill_is_not_orphaned(tmp_path):
    # §5: a single skill present but not referenced anywhere must NOT be flagged — OpenClaw
    # auto-loads by dir presence, so unreferenced is normal, not an orphan.
    sd = tmp_path / "skills" / "lonely"
    sd.mkdir(parents=True)
    (sd / "SKILL.md").write_text("---\nname: lonely\n---\n\nbody\n", encoding="utf-8")
    c = Context(home=tmp_path)
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = {}
    assert check_offboarding_hygiene(c).status == PASS


# --- F-122: cross-tier NAME shadowing across the precedence-ordered load roots ---

def _mk_skill(root: Path, name: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(f"---\nname: {name}\n---\n\nbody\n", encoding="utf-8")


def _ctx(home: Path, config=None) -> Context:
    c = Context(home=home)
    c.config = config or {}
    c.bootstrap = {}
    c.installed_skills = {}
    return c


def test_cross_tier_shadowing_warns(tmp_path):
    """F-122: the same declared name in a HIGHER-precedence tier (workspace) and a lower one
    (managed ~/.openclaw/skills) silently shadows — WARN naming the shadowing (winning) tier."""
    _mk_skill(tmp_path / "skills" / "helper", "helper")                # managed
    _mk_skill(tmp_path / "workspace" / "skills" / "helper", "helper")  # workspace (wins)
    f = check_offboarding_hygiene(_ctx(tmp_path))
    assert f.status == WARN, f.detail
    ev = " ".join(f.evidence or [])
    assert "shadows" in ev and "workspace" in ev and "helper" in ev


def test_same_tier_duplicate_is_hygiene_not_shadowing(tmp_path):
    """Two copies in the SAME tier are stale-copy hygiene, not cross-tier shadowing."""
    _mk_skill(tmp_path / "skills" / "a", "dup")
    _mk_skill(tmp_path / "skills" / "b", "dup")
    f = check_offboarding_hygiene(_ctx(tmp_path))
    assert f.status == WARN, f.detail
    ev = " ".join(f.evidence or [])
    assert "installed in 2 locations" in ev and "shadows" not in ev


def test_extra_dir_shadowing_via_config(tmp_path):
    """F-122: a skills.load.extraDirs copy (lowest tier) sharing a name with a managed skill is
    cross-tier shadowing surface — the managed copy wins over the extra/plugin tier."""
    _mk_skill(tmp_path / "skills" / "helper", "helper")   # managed
    extra = tmp_path / "ext"
    _mk_skill(extra / "helper", "helper")                 # extra/plugin tier
    f = check_offboarding_hygiene(_ctx(tmp_path, {"skills": {"load": {"extraDirs": [str(extra)]}}}))
    assert f.status == WARN, f.detail
    ev = " ".join(f.evidence or [])
    assert "shadows" in ev and "managed" in ev


def test_distinct_names_across_tiers_pass(tmp_path):
    """Different names in different tiers is the normal case — no collision, PASS."""
    _mk_skill(tmp_path / "skills" / "alpha", "alpha")
    _mk_skill(tmp_path / "workspace" / "skills" / "beta", "beta")
    assert check_offboarding_hygiene(_ctx(tmp_path)).status == PASS
