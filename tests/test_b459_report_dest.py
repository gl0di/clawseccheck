"""B-459 — writing a report artifact must never destroy the audit, and a report path whose
directory does not exist yet must be created rather than fatal.

The defect this pins: SKILL.md's guided flow hardcodes ``--pdf ~/.clawseccheck/report.pdf``
while none of the commands that precede it create ``~/.clawseccheck``. On a first run
``mkstemp`` died with ENOENT, and because ``--dashboard --full --pdf`` had already collapsed
the card in anticipation of the attachment, the entire audit was discarded — 118 bytes of
stdout, exit 1, no grade, no findings. The documented flow's own first run was the failing
case, so every new user hit it.

Two independent guarantees are pinned here:
  1. a missing parent directory is created (0700 — a report carries audit detail);
  2. a genuinely impossible write degrades to the FULL inline report, never to nothing.

Offline; every write is confined to pytest's tmp_path.
"""
from __future__ import annotations

import stat
from pathlib import Path

import pytest

from clawseccheck import cli
from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")


def _run(capsys, *argv):
    code = main(list(argv))
    return code, capsys.readouterr().out


# ---- 1. the first-run break ----

def test_guided_first_run_writes_the_pdf_and_still_prints_the_card(tmp_path, capsys):
    """The exact shape of SKILL.md Step 3 on a machine where the state dir is absent."""
    dest = tmp_path / ".clawseccheck" / "report.pdf"
    assert not dest.parent.exists()

    code, out = _run(capsys, "--dashboard", "--full", "--pdf", str(dest), "--home", VULN)

    assert code == 0
    assert dest.is_file(), "the report directory must be created, not fatal"
    assert dest.read_bytes().startswith(b"%PDF")
    # The card itself must still reach the user. This first-guided-run home has no
    # --attest / --judged-bundle, so layers 4-5 never ran and the run is ungraded
    # (C-422/C-423): no "Grade X" letter anywhere, but the card still leads with the
    # most urgent finding and discloses exactly which layers did not run instead of
    # going quiet — the same "audit was swallowed" failure mode this test pins.
    assert "ClawSecCheck" in out
    assert "Grade" not in out
    assert "No grade yet" in out
    assert "layers did not run" in out
    assert len(out) > 300, f"the audit was swallowed again: {len(out)} bytes"


def test_created_report_dir_is_private(tmp_path, capsys):
    dest = tmp_path / "fresh" / "report.pdf"
    _run(capsys, "--dashboard", "--full", "--pdf", str(dest), "--home", VULN)
    mode = stat.S_IMODE(dest.parent.stat().st_mode)
    assert mode == 0o700, f"report dir should be 0700, got {mode:o}"


@pytest.mark.parametrize("flag,suffix", [("--html", ".html"), ("--sarif", ".sarif"), ("--save", ".txt")])
def test_other_artifacts_also_create_their_directory(tmp_path, capsys, flag, suffix):
    dest = tmp_path / "nested" / "deeper" / ("report" + suffix)
    _run(capsys, flag, str(dest), "--home", VULN)
    assert dest.is_file(), f"{flag} must create its missing parent directory"
    assert dest.stat().st_size > 0, f"{flag} wrote an empty artifact"


# ---- 2. an impossible write must not cost the audit ----

def _break_pdf_write(monkeypatch) -> None:
    """Make the PDF write fail for everyone, at any uid.

    A ``chmod 0500`` parent would be the obvious way to force this, but root ignores
    directory write permissions, so that test would pass for the wrong reason wherever the
    suite runs as root — and a conditional skip would hide the regression exactly there.
    """
    def boom(path, data):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(cli, "secure_write_bytes", boom)


def test_failed_pdf_write_falls_back_to_the_full_inline_report(tmp_path, capsys, monkeypatch):
    dest = tmp_path / "nope" / "report.pdf"
    _break_pdf_write(monkeypatch)

    code, out = _run(capsys, "--dashboard", "--full", "--pdf", str(dest), "--home", VULN)

    assert code == 0, "a delivery failure must not be reported as an audit failure"
    assert not dest.exists()
    # The user is told what happened...
    assert "could not write PDF report" in out
    assert "inline" in out
    # ...and gets the whole analysis anyway, not a card pointing at a file we never wrote.
    assert len(out) > 5000, f"expected the full inline report, got {len(out)} bytes"


def test_failed_pdf_write_keeps_every_pipeline_section(tmp_path, capsys, monkeypatch):
    """The collapse gate must not fire on a PDF that was never written."""
    dest = tmp_path / "nope" / "report.pdf"
    _break_pdf_write(monkeypatch)
    _, out = _run(capsys, "--dashboard", "--full", "--pdf", str(dest), "--home", VULN)

    inline = out.split("could not write PDF report", 1)[1]
    for section in ("Skills", "Coverage"):
        assert section in inline, f"{section!r} missing — the card collapsed with no attachment"


# ---- 3. an existing parent must be left exactly alone ----

def test_existing_parent_directory_permissions_are_not_touched(tmp_path, capsys):
    """`--pdf /tmp/report.pdf` must never chmod /tmp."""
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o755)
    before = stat.S_IMODE(parent.stat().st_mode)

    _run(capsys, "--dashboard", "--full", "--pdf", str(parent / "report.pdf"), "--home", VULN)

    after = stat.S_IMODE(parent.stat().st_mode)
    assert after == before == 0o755, "an existing report parent must not be re-permissioned"
