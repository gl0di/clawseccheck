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
