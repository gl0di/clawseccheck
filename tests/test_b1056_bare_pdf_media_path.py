"""B-1056: a bare ``--pdf`` with no ``--data-dir`` and no ``<home>/media/outbound`` must name
the file it actually wrote.

``_default_pdf_target`` used to return the literal string ``~/.clawseccheck/report.pdf``.
The write expanded ``~`` and landed in ``$HOME/.clawseccheck/report.pdf``, but the attach
note and the ``MEDIA:`` line went through the delivery renderer, which resolves a path that
does not start with ``/`` against the CURRENT DIRECTORY - so a run started anywhere other
than ``$HOME`` printed ``<cwd>/~/.clawseccheck/report.pdf``, a file that does not exist, and
OpenClaw's attachment of it failed. The existing tests ran from the repo root and only
checked a suffix (``.endswith('.clawseccheck/report.pdf')`` and ``"~/.clawseccheck/report.pdf"
in out``), which the broken path also satisfies.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = REPO_ROOT / "fixtures" / "home_safe"


def _run_bare_pdf(tmp_path: Path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    work = tmp_path / "work"  # a cwd that is NOT the home and not under it
    work.mkdir()
    env = {**os.environ, "HOME": str(fake_home), "PYTHONPATH": str(REPO_ROOT)}
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", str(SAFE), "--no-history",
         "--no-deptree", "--no-host", "--no-dist", "--no-native", "--pdf"],
        cwd=work, capture_output=True, text=True, env=env, timeout=400)
    return proc, fake_home, work


def _media_target(text: str, home: Path) -> Path:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("MEDIA:")]
    assert lines, f"no MEDIA: directive was emitted; output was:\n{text}"
    raw = lines[0][len("MEDIA:"):]
    # Host rendering collapses $HOME to "~/" + a shell-quoted rest; undo exactly that.
    if raw.startswith("~/"):
        return home / shlex.split(raw[2:])[0]
    return Path(shlex.split(raw)[0])


def test_the_media_line_names_the_file_that_was_written(tmp_path):
    proc, home, work = _run_bare_pdf(tmp_path)
    out = proc.stdout + proc.stderr  # the plain-report path prints its note on stdout
    assert proc.returncode in (0, 1), out
    written = home / ".clawseccheck" / "report.pdf"
    assert written.read_bytes().startswith(b"%PDF")
    target = _media_target(out, home)
    assert target == written, (target, out)
    assert target.is_file()


def test_no_literal_tilde_directory_appears_under_the_cwd(tmp_path):
    proc, _home, work = _run_bare_pdf(tmp_path)
    assert "/~/" not in proc.stdout + proc.stderr, proc.stdout + proc.stderr
    assert not (work / "~").exists(), "nothing may be created under <cwd>/~"
