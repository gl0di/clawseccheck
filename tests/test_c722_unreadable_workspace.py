"""C-722 item 2 -- an unreadable workspace directory is reported as unreadable, not as an
engine error (B22) and not as an absence (B7, C3).

With the workspace directory at mode 000, ``check_self_modification`` (B22) let a
``PermissionError`` out of ``pathprobe.is_file`` and the finding became
``ERR:check_self_modification`` (UNKNOWN, engine error); B7 said "No memory file found." and
C3 "No bootstrap/memory files found to back up." about files nobody could look for.

Status is UNKNOWN throughout (unchanged for B7/C3). Only the unreadable case gets new
wording: the sentences for a truly absent directory are pinned byte-identical below because
``baseline.fingerprint()`` hashes ``detail``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, UNKNOWN, WARN
from clawseccheck.checks import check_backups, check_memory_poisoning, check_self_modification
from clawseccheck.collector import collect

REPO_ROOT = Path(__file__).resolve().parent.parent
VULN = REPO_ROOT / "fixtures" / "home_vuln"

pytestmark = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="chmod 000 does not stop root, so the unreadable case cannot be built",
)

# The sentences a truly ABSENT workspace gets today (and must keep getting).
B7_ABSENT = "No memory file found."
C3_ABSENT = "No bootstrap/memory files found to back up."
B22_NO_TARGETS_PREFIX = "Dangerous tools present but no group/world-writable identity/skill targets found"


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    shutil.copytree(VULN, home)
    for root, _dirs, files in os.walk(home):
        for name in files:
            os.chmod(os.path.join(root, name), 0o600)
    return home


class _Unreadable:
    """chmod 000 a directory and ALWAYS give it back, so tmp cleanup works."""

    def __init__(self, path: Path):
        self.path = path
        self.mode = path.stat().st_mode & 0o7777

    def __enter__(self):
        self.path.chmod(0)
        return self

    def __exit__(self, *exc):
        self.path.chmod(self.mode)


def _audit_json(home: Path, scratch: Path) -> dict:
    fake_home = scratch / "hm"
    fake_home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("OPENCLAW_")}
    env["HOME"] = str(fake_home)
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", str(home), "--json", "--no-history",
         "--no-native", "--no-deptree", "--no-host", "--no-sockets"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=400, env=env)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    return json.loads(proc.stdout)


# ----------------------------------------------------------------------------- B22
def test_b22_returns_unknown_with_its_own_id_when_the_workspace_is_unreadable(tmp_path):
    home = _home(tmp_path)
    with _Unreadable(home / "workspace-home"):
        finding = check_self_modification(collect(home))
    assert finding.id == "B22"
    assert finding.status == UNKNOWN
    assert "could not be read" in finding.detail
    assert not finding.detail.startswith(B22_NO_TARGETS_PREFIX)
    assert finding.fix and finding.fix != "\u2014"


def test_b22_keeps_its_existing_sentence_for_a_truly_absent_workspace(tmp_path):
    home = _home(tmp_path)
    shutil.rmtree(home / "workspace-home")
    finding = check_self_modification(collect(home))
    assert finding.id == "B22" and finding.status == UNKNOWN
    assert finding.detail.startswith(B22_NO_TARGETS_PREFIX)
    assert "could not be read" not in finding.detail


def test_b22_keeps_its_existing_sentence_for_a_readable_workspace(tmp_path):
    """The control for the two tests above: the same home, nothing chmod'd."""
    finding = check_self_modification(collect(_home(tmp_path)))
    assert finding.id == "B22"
    assert "could not be read" not in finding.detail


def test_b22_still_convicts_a_writable_skills_dir_beside_an_unreadable_workspace(tmp_path):
    """Skipping the unreadable directory must not drop what the other legs found."""
    home = _home(tmp_path)
    skills = home / "skills"
    skills.mkdir()
    skills.chmod(0o777)
    with _Unreadable(home / "workspace-home"):
        finding = check_self_modification(collect(home))
    assert finding.id == "B22"
    assert finding.status in (FAIL, WARN), finding.detail
    assert "skills/" in finding.detail


# ------------------------------------------------------------------------ B7 and C3
def test_b7_says_the_workspace_could_not_be_read(tmp_path):
    home = _home(tmp_path)
    with _Unreadable(home / "workspace-home"):
        finding = check_memory_poisoning(collect(home))
    assert finding.id == "B7" and finding.status == UNKNOWN
    assert finding.detail != B7_ABSENT
    assert "could not be read" in finding.detail


def test_c3_says_the_workspace_could_not_be_read(tmp_path):
    home = _home(tmp_path)
    with _Unreadable(home / "workspace-home"):
        finding = check_backups(collect(home))
    assert finding.id == "C3" and finding.status == UNKNOWN
    assert finding.detail != C3_ABSENT
    assert "could not be read" in finding.detail


def test_b7_and_c3_keep_their_sentences_for_a_truly_absent_workspace(tmp_path):
    home = _home(tmp_path)
    shutil.rmtree(home / "workspace-home")
    ctx = collect(home)
    assert check_memory_poisoning(ctx).detail == B7_ABSENT
    assert check_backups(ctx).detail == C3_ABSENT


def test_b7_and_c3_are_unchanged_for_a_readable_workspace(tmp_path):
    ctx = collect(_home(tmp_path))
    assert "could not be read" not in check_memory_poisoning(ctx).detail
    assert "could not be read" not in check_backups(ctx).detail


def test_an_oversized_but_readable_file_is_not_called_unreadable(tmp_path):
    """The size-cap limit hit is a different fact from an unreadable directory: with no
    memory file and a capped SOUL.md, B7 keeps the absence sentence."""
    home = _home(tmp_path)
    (home / "workspace-home" / "MEMORY.md").unlink()
    (home / "workspace-home" / "SOUL.md").write_bytes(b"x" * 1_100_000)
    (home / "workspace-home" / "SOUL.md").chmod(0o600)
    ctx = collect(home)
    assert any("exceeded" in str(h) for h in ctx.limit_hits), "the control must hit the cap"
    assert check_memory_poisoning(ctx).detail == B7_ABSENT


# ----------------------------------------------------------- the whole audit, real CLI
def test_the_audit_has_no_engine_error_when_the_workspace_is_unreadable(tmp_path):
    home = _home(tmp_path)
    with _Unreadable(home / "workspace-home"):
        payload = _audit_json(home, tmp_path)
    ids = {f["id"]: f for f in payload["findings"]}
    assert [i for i in ids if i.startswith("ERR:")] == []
    assert ids["B22"]["status"] == UNKNOWN
    assert not ids["B22"].get("engine_degraded")


def test_the_audit_with_nothing_chmodded_has_no_engine_error(tmp_path):
    """Control for the test above."""
    payload = _audit_json(_home(tmp_path), tmp_path)
    assert [f["id"] for f in payload["findings"] if f["id"].startswith("ERR:")] == []


# ------------------------------------------------- one unreadable FILE is not an unreadable DIRECTORY
SAFE = REPO_ROOT / "fixtures" / "home_safe"


def _bare_home(tmp_path: Path, files: dict) -> Path:
    home = tmp_path / "home"
    ws = home / "workspace-home"
    ws.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    os.chmod(home / "openclaw.json", 0o600)
    for name, data in files.items():
        (ws / name).write_bytes(data)
        os.chmod(ws / name, 0o600)
    return home


def _b7_c3(home: Path):
    ctx = collect(home)
    b7, c3 = check_memory_poisoning(ctx), check_backups(ctx)
    return (b7.status, b7.detail, b7.fix), (c3.status, c3.detail, c3.fix)


@pytest.mark.parametrize("files", [
    {"USER.md": b"u"},
    {"SOUL.md": b"s", "USER.md": b"u"},
], ids=["only_the_sibling", "identity_file_beside_it"])
def test_an_unreadable_sibling_file_changes_nothing_for_b7_and_c3(tmp_path, files):
    """The directory listing proves the memory/identity file is absent: B7 and C3 say what
    they say for a readable workspace, byte for byte (status, detail and fix)."""
    readable = _b7_c3(_bare_home(tmp_path / "r", files))
    home = _bare_home(tmp_path / "u", files)
    with _Unreadable(home / "workspace-home" / "USER.md"):
        unreadable = _b7_c3(home)
    assert unreadable == readable
    assert unreadable[0][1] == B7_ABSENT or "memory" in unreadable[0][1].lower()


def test_an_unreadable_sibling_in_the_home_safe_fixture_leaves_b7_at_its_base_sentence(tmp_path):
    home = tmp_path / "home"
    shutil.copytree(SAFE, home)
    for root, _dirs, names in os.walk(home):
        for name in names:
            os.chmod(os.path.join(root, name), 0o600)
    (home / "workspace-home" / "USER.md").write_bytes(b"u")
    with _Unreadable(home / "workspace-home" / "USER.md"):
        finding = check_memory_poisoning(collect(home))
    assert finding.id == "B7" and finding.detail == B7_ABSENT


def test_the_memory_file_itself_unreadable_is_called_unreadable(tmp_path):
    """The specific file B7 looks for exists but cannot be opened: that is not 'no memory
    file found'."""
    home = _bare_home(tmp_path, {"SOUL.md": b"s", "MEMORY.md": b"m"})
    with _Unreadable(home / "workspace-home" / "MEMORY.md"):
        finding = check_memory_poisoning(collect(home))
    assert finding.id == "B7" and finding.status == UNKNOWN
    assert finding.detail != B7_ABSENT and "could not be read" in finding.detail


def test_an_identity_file_unreadable_is_called_unreadable_by_c3_but_not_by_b7(tmp_path):
    home = _bare_home(tmp_path, {"SOUL.md": b"s"})
    with _Unreadable(home / "workspace-home" / "SOUL.md"):
        ctx = collect(home)
        b7, c3 = check_memory_poisoning(ctx), check_backups(ctx)
    assert b7.detail == B7_ABSENT, "B7 looks for a memory file; the unreadable one is SOUL.md"
    assert c3.status == UNKNOWN and c3.detail != C3_ABSENT
    assert "could not be read" in c3.detail
