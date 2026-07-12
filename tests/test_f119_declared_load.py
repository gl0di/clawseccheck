"""F-119 — declared-but-unresolved skill-load surface (B158) + plugins.load.paths discovery.

B158 is advisory / WARN-only: the audit can only scan what is on disk, so a config that
declares a skill-load source (skills.load.extraDirs, plugins.load.paths, or a .clawhub/
lock.json skillFile) resolving to nothing is an unaudited auto-load gap. Declared-but-absent
is legitimate on a fresh host — never a FAIL.
"""

from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_declared_skill_reconciliation
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home, cfg, found=True):
    c = Context(home=Path(home))
    c.config = cfg
    c.config_found = found
    c.bootstrap = {}
    c.limit_hits = []
    return c


def test_b158_unknown_no_config(tmp_path):
    assert check_declared_skill_reconciliation(_ctx(tmp_path, {}, found=False)).status == UNKNOWN


def test_b158_warn_absent_extradir(tmp_path):
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, {"skills": {"load": {"extraDirs": ["ghost-skills"]}}})
    )
    assert f.status == WARN
    assert any("ghost-skills" in e for e in f.evidence)


def test_b158_pass_present_extradir(tmp_path):
    (tmp_path / "real-skills").mkdir()
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, {"skills": {"load": {"extraDirs": ["real-skills"]}}})
    )
    assert f.status == PASS


def test_b158_warn_absent_plugin_load_path(tmp_path):
    f = check_declared_skill_reconciliation(
        _ctx(tmp_path, {"plugins": {"load": {"paths": ["plugins/ghost"]}}})
    )
    assert f.status == WARN


def test_b158_warn_lock_skillfile_gone(tmp_path):
    lock = tmp_path / ".clawhub"
    lock.mkdir()
    (lock / "lock.json").write_text(
        json.dumps({"skills": {"acme": {"skillFile": "skills/acme/SKILL.md"}}})
    )
    f = check_declared_skill_reconciliation(_ctx(tmp_path, {"skills": {}}))
    assert f.status == WARN
    assert any("acme" in e for e in f.evidence)


def test_b158_bad_fixture_warns():
    f = check_declared_skill_reconciliation(collect(FIXTURES / "bad_f119_missing_extradir"))
    assert f.status == WARN, f"Expected WARN, got {f.status}: {f.detail}"


def test_b158_clean_fixture_passes():
    f = check_declared_skill_reconciliation(collect(FIXTURES / "clean_f119_present_extradir"))
    assert f.status == PASS, f"Expected PASS, got {f.status}: {f.detail}"


def test_f119_plugins_load_paths_discovery(tmp_path):
    """F-119(b): a skill bundled under a plugins.load.paths entry (<plugin>/skills/) is
    discovered and enters the scanned surface, instead of being silently invisible."""
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"plugins": {"load": {"paths": ["plugins/acme"]}}})
    )
    sk = tmp_path / "plugins" / "acme" / "skills" / "bundled"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("---\nname: bundled\ndescription: x\n---\n# body")
    ctx = collect(tmp_path)
    assert "bundled" in ctx.installed_skills


def test_b158_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_f119_missing_extradir", include_native=False)
    assert "B158" in {f.id for f in findings}
