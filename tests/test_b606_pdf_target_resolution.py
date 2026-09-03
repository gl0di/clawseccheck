"""B-606: where a bare ``--pdf`` writes, and that the choice reaches the emitted directive.

OpenClaw parses a ``MEDIA:<path>`` line out of the assistant's reply and attaches the file.
The path has to be one its read tool may open, and by `toolpolicy.py`'s own measurement most
homes deny that outside the workspace -- so the report has to land in the runtime's managed
outbound area to have a real chance of arriving. When it cannot, the run must say so, because
a blocked attachment is dropped SILENTLY: the host logs it, appends a note, and sends the
reply anyway. The user gets a message and no file.

These tests pin BOTH halves. The helper's own answer is cheap to assert and cheap to get
right; what actually broke before is the wiring -- an instruction that named no mechanism at
all. So the CLI cases below drive the real binary and read the real stderr note, and the
explicit-path case exists to prove the auto-resolution cannot capture a path the user named.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from clawseccheck.cli import _default_pdf_target  # noqa: E402

FALLBACK = "~/.clawseccheck/report.pdf"


def _home_with_outbound(tmp_path: Path) -> Path:
    home = tmp_path / "oc_home"
    (home / "media" / "outbound").mkdir(parents=True)
    return home


# --------------------------------------------------------------------------- helper

def test_the_managed_outbound_dir_is_chosen_when_it_exists(tmp_path):
    home = _home_with_outbound(tmp_path)
    target, managed = _default_pdf_target(str(home))
    assert managed is True
    assert target == str(home / "media" / "outbound" / "clawseccheck-report.pdf")


def test_an_absent_managed_dir_falls_back_and_says_so(tmp_path):
    home = tmp_path / "oc_home"
    home.mkdir()
    target, managed = _default_pdf_target(str(home))
    assert managed is False
    assert target == FALLBACK


def test_a_present_but_unwritable_managed_dir_falls_back(tmp_path):
    home = _home_with_outbound(tmp_path)
    outbound = home / "media" / "outbound"
    outbound.chmod(0o500)
    try:
        if os.access(outbound, os.W_OK):
            pytest.skip("running with rights that ignore the mode (root?)")
        target, managed = _default_pdf_target(str(home))
        assert managed is False, "an unwritable dir must not be reported as the managed root"
        assert target == FALLBACK
    finally:
        outbound.chmod(0o700)


def test_resolution_never_creates_the_directory(tmp_path):
    """Auto-resolution must not manufacture the precondition it is testing for.

    CLAUDE.md allows the PDF write because the user asked for it with ``--pdf``. Creating
    OpenClaw's managed directory as a side effect of *deciding where to write* would be a
    second, unasked-for write into the audited home.
    """
    home = tmp_path / "oc_home"
    home.mkdir()
    _default_pdf_target(str(home))
    assert not (home / "media").exists(), "resolution created a directory it only meant to test"


# ----------------------------------------------------------------------------- wiring
#
# The helper being right is not the thing that failed. Assert the resolved path reaches the
# directive the agent is told to emit -- deleting the call site must redden something here.

def _stderr_note(tmp_path: Path, home: Path, pdf_args: list) -> str:
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir(exist_ok=True)
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", str(home), "--no-history",
         "--data-dir", str(tmp_path / "store"), "--dashboard", *pdf_args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})
    return proc.stderr


def _media_lines(note: str) -> list:
    return [ln.strip() for ln in note.splitlines() if ln.strip().startswith("MEDIA:")]


def test_a_bare_pdf_flag_points_the_directive_at_the_managed_root(tmp_path):
    home = _home_with_outbound(tmp_path)
    note = _stderr_note(tmp_path, home, ["--pdf"])
    media = _media_lines(note)
    assert media, f"no MEDIA: directive was emitted; stderr was:\n{note}"
    assert media[0].endswith("media/outbound/clawseccheck-report.pdf"), media


def test_a_bare_pdf_flag_without_the_managed_root_warns_the_attachment_may_vanish(tmp_path):
    home = tmp_path / "oc_home"
    home.mkdir()
    note = _stderr_note(tmp_path, home, ["--pdf"])
    media = _media_lines(note)
    assert media, f"no MEDIA: directive was emitted; stderr was:\n{note}"
    assert media[0].endswith(".clawseccheck/report.pdf"), media
    assert "silently dropped" in note, (
        "the fallback must disclose that the attachment may never arrive -- a blocked "
        f"MEDIA line is dropped without an error. stderr was:\n{note}")


def test_an_explicit_path_is_never_replaced_by_the_managed_root(tmp_path):
    """The user naming a path is a decision, not a hint."""
    home = _home_with_outbound(tmp_path)
    chosen = tmp_path / "mine.pdf"
    note = _stderr_note(tmp_path, home, ["--pdf", str(chosen)])
    media = _media_lines(note)
    assert media, f"no MEDIA: directive was emitted; stderr was:\n{note}"
    assert media[0].endswith("mine.pdf"), media
    assert "media/outbound" not in media[0], (
        "auto-resolution captured a path the user named explicitly")
    assert "silently dropped" not in note, (
        "the fallback caveat fired on a path the user chose, where it does not apply")


def test_the_directive_carries_no_operating_system_username(tmp_path):
    """B-381: a pasted report must not name its author's account.

    The home-relative form is also the one OpenClaw's expandPath accepts, so the privacy
    requirement and the working input format are the same string.
    """
    home = _home_with_outbound(tmp_path)
    note = _stderr_note(tmp_path, home, ["--pdf"])
    for line in _media_lines(note):
        assert "/home/" not in line and "/Users/" not in line, (
            f"the directive carries an absolute home path: {line}")
