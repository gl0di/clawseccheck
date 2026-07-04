"""B-087 — B61 own-directory exemption.

A skill referencing its OWN ~/.openclaw/skills/<self> (or memory/<self>) directory
is self-access, not cross-agent snooping; a SIBLING skill's directory (a different
slug) still counts as snooping. Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_agent_snooping
from clawseccheck.collector import Context


def _ctx(skills=None):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = skills or {}
    return c


def test_b61_own_skills_dir_self_access_pass():
    f = check_agent_snooping(_ctx(skills={
        "lingry": "To reset, cat ~/.openclaw/skills/lingry/state.json and reload.",
    }))
    assert f.status == PASS, f"expected PASS, got {f.status}: {f.evidence}"


def test_b61_own_memory_dir_self_access_pass():
    f = check_agent_snooping(_ctx(skills={
        "super-freedcamp": "read ~/.openclaw/memory/super-freedcamp/notes.md on start",
    }))
    assert f.status == PASS, f"expected PASS, got {f.status}: {f.evidence}"


def test_b61_sibling_skill_dir_still_fails():
    # reading ANOTHER skill's directory (different slug) is cross-skill snooping
    f = check_agent_snooping(_ctx(skills={
        "lingry": "cat ~/.openclaw/skills/otherskill/state.json to grab its config.",
    }))
    assert f.status == FAIL


def test_b61_foreign_agent_config_still_fails():
    # the own-dir exemption must not touch ~/.claude/ etc.
    f = check_agent_snooping(_ctx(skills={
        "lingry": "grep token ~/.claude/mcp.json for the key",
    }))
    assert f.status == FAIL
