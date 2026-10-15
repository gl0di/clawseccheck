"""C-658 (slice 2): a symlink loop at a skill directory must not change C015 by interpreter.

`check_secrets_at_rest_home` resolves the SKILL_DIRS skip roots up front. `Path.resolve()` on
a symlink loop raises `RuntimeError` on 3.9-3.12 and returns the path on 3.14, and nothing
caught it: on 3.12 the check became an `ERR:` engine-degraded UNKNOWN (which caps the whole
audit) while 3.14 said PASS. A loop has no inode behind it, so there is nothing under it to
scan and it is not a skip root; the rest of the home is scanned exactly as before. The
outcome pinned here is the same on every interpreter: PASS for a clean home, the usual WARN
for a home that holds a secret, never an `ERR:` finding.

The `--vet-plugin` half of the task (a manifest `skills` entry that is a loop) is owned by
C-659 and pinned in `test_c659_manifest_skills_entries.py`; the parametrised cases at the end
of this file re-pin it through both the library and the CLI so a regression there shows up
beside the C015 cells.

Nothing here reads a Python version: the same assertions hold on every interpreter CI runs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_secrets_at_rest_home, run_all, vet_plugin
from clawseccheck.cli import main
from clawseccheck.collector import SKILL_DIRS, collect

pytestmark = pytest.mark.skipif(os.name != "posix", reason="symlinks are POSIX-only here")


def _secret() -> str:
    return "ghp" + "_" + "A" * 36


def _home(tmp_path: Path, *, with_secret: bool = False) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "127.0.0.1"}}\n', encoding="utf-8")
    cfg.chmod(0o600)
    if with_secret:
        env = home / ".env"
        env.write_text("API_TOKEN=" + _secret() + "\n", encoding="utf-8")
        env.chmod(0o600)
    return home


def _loop_at(home: Path, rel: str) -> None:
    """Make *rel* (a path under *home*) a symlink to itself, creating real parents."""
    target = home / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target.name, target)


def _loop_cases() -> list:
    """Every SKILL_DIRS entry replaced by a loop, plus every ancestor of a nested entry."""
    cases = []
    for rel in SKILL_DIRS:
        cases.append(rel)
        parts = Path(rel).parts
        for i in range(1, len(parts)):
            cases.append(str(Path(*parts[:i])))
    return sorted(set(cases))


@pytest.mark.parametrize("rel", _loop_cases())
def test_a_loop_at_a_skill_dir_is_not_a_crash_and_the_home_still_passes(tmp_path, rel):
    home = _home(tmp_path)
    _loop_at(home, rel)
    f = check_secrets_at_rest_home(collect(home))
    assert f.status == PASS, (f.status, f.detail, f.evidence)
    assert "Scanned 1 home file(s)" in f.detail, f.detail


@pytest.mark.parametrize("rel", _loop_cases())
def test_a_loop_at_a_skill_dir_does_not_degrade_the_engine(tmp_path, rel):
    """Through `run_all`, where a raised exception becomes an `ERR:` engine-degraded finding."""
    home = _home(tmp_path)
    _loop_at(home, rel)
    findings = run_all(collect(home))
    assert not [f for f in findings if f.id.startswith("ERR:")], [f.id for f in findings]
    c015 = [f for f in findings if f.id == "C015"]
    assert len(c015) == 1 and c015[0].status == PASS, [(f.id, f.status) for f in findings]


@pytest.mark.parametrize("rel", ["skills", "workspace/skills", ".agents/skills", ".agents"])
def test_a_loop_at_a_skill_dir_does_not_hide_a_secret_elsewhere_in_the_home(tmp_path, rel):
    """The scan continues around the loop: a plaintext secret in the home is still reported,
    by name and without its value."""
    home = _home(tmp_path, with_secret=True)
    _loop_at(home, rel)
    f = check_secrets_at_rest_home(collect(home))
    assert f.status == WARN, (f.status, f.detail, f.evidence)
    assert any(".env: secret-like value detected" in e for e in f.evidence), f.evidence
    assert _secret() not in f.detail and all(_secret() not in e for e in f.evidence)


def test_a_real_skill_dir_is_still_skipped_and_a_secret_in_it_is_not_scanned(tmp_path):
    """Control: an ordinary (non-loop) skills directory keeps its skip-root behaviour."""
    home = _home(tmp_path)
    (home / "skills").mkdir()
    sk = home / "skills" / "note.md"
    sk.write_text("token = " + _secret() + "\n", encoding="utf-8")
    sk.chmod(0o600)
    f = check_secrets_at_rest_home(collect(home))
    assert f.status == PASS, (f.status, f.detail, f.evidence)


# ------------------------------------------------ the --vet-plugin cell (owned by C-659)

_BENIGN = "---\nname: demo\ndescription: a demo skill\n---\nSummarise the text the user gives you.\n"


def _plugin(tmp_path: Path, skills: list) -> Path:
    d = tmp_path / "p"
    d.mkdir()
    (d / "openclaw.plugin.json").write_text(
        json.dumps({"id": "d", "configSchema": {}, "skills": skills}), encoding="utf-8"
    )
    return d


def test_a_manifest_skills_loop_is_a_warn_naming_the_entry_not_a_crash_or_install(tmp_path, capsys):
    d = _plugin(tmp_path, ["loopskill"])
    os.symlink("loopskill", d / "loopskill")
    f = vet_plugin(d)
    assert f.status == WARN, (f.status, f.detail, f.evidence)
    assert any("manifest skills entry" in e and "could not be examined" in e for e in f.evidence), f.evidence
    assert "loopskill" in "\n".join(f.evidence)
    rc = main(["--vet-plugin", str(d), "--no-color"])
    cap = capsys.readouterr()
    assert "unexpected internal error" not in cap.err, cap.err
    assert "CAUTION" in cap.out and "DO-NOT-INSTALL" not in cap.out, cap.out
    assert rc == 1


def test_a_missing_manifest_skills_entry_is_still_the_quiet_note(tmp_path):
    """Twin: a declared entry that is simply absent is not a coverage gap."""
    f = vet_plugin(_plugin(tmp_path, ["nothere"]))
    assert f.status == PASS, (f.status, f.evidence)
    assert any("manifest skills entry not present" in e for e in f.evidence), f.evidence


def test_a_present_manifest_skills_entry_is_vetted_as_before(tmp_path):
    d = _plugin(tmp_path, ["skills/ok"])
    (d / "skills" / "ok").mkdir(parents=True)
    (d / "skills" / "ok" / "SKILL.md").write_text(_BENIGN, encoding="utf-8")
    f = vet_plugin(d)
    assert f.status == PASS, (f.status, f.evidence)
    assert "(1 bundled skill(s)," in f.detail, f.detail
