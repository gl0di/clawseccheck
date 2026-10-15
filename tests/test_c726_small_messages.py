"""C-726 item 6: four small messages that disagreed with the documentation.

(a) ``--help`` for ``--exit-code`` read as if a bare ``--monitor`` always exits 0; it exits 1
    when the store cannot be written, with or without the flag.
(b) ``--verify-baseline ""`` printed the vet family's "needs a target ... path, slug, or URL".
(c) a bare ``--pdf`` printed an absolute path where the documentation promises ``MEDIA:~/...``.
(d) the chain verifiers count entries from 0 and never said so.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import re
import shutil
from pathlib import Path

import pytest

from clawseccheck.cli import _chain_verdict, main

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = REPO_ROOT / "fixtures" / "home_safe"


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:                      # --help exits through argparse
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def test_exit_code_help_names_the_store_write_failure_without_the_flag(monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    _rc, out, _err = _cli(["--help"])
    text = re.sub(r"\s+", " ", out)
    assert "exit 1 whenever the monitor's local store could not be written" in text
    assert "with or without this flag" in text


def test_a_bare_monitor_with_an_unwritable_store_exits_1(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a directory is needed", encoding="utf-8")
    home = tmp_path / "home"
    shutil.copytree(SAFE, home)
    rc, _out, err = _cli(["--monitor", "--home", str(home), "--state",
                          str(blocker / "state.json"), "--events", str(tmp_path / "e.jsonl"),
                          "--history", str(tmp_path / "h.jsonl"), "--no-deptree", "--no-host"])
    assert rc == 1
    assert "MONITORING NOT ESTABLISHED" in err


def test_an_empty_verify_baseline_has_its_own_message(tmp_path):
    rc, _out, err = _cli(["--verify-baseline", "", "--data-dir", str(tmp_path)])
    assert rc == 2
    assert "--verify-baseline needs a baseline reference" in err
    assert "path, slug, or URL" not in err


@pytest.mark.parametrize("msg", ["broken at entry 0", "broken at entry 7"])
def test_chain_verdict_says_entries_are_counted_from_zero(msg):
    for ok in (False, None):
        text, rc = _chain_verdict("History", "p.jsonl", ok, msg, explicit=False)
        assert rc == 1
        assert msg in text
        assert "counted from 0" in text


def test_chain_verdict_leaves_other_messages_alone():
    text, rc = _chain_verdict("History", "p.jsonl", True, "12 entries", explicit=False)
    assert rc == 0 and "counted from 0" not in text


def test_bare_pdf_prints_the_home_relative_media_line(tmp_path, monkeypatch):
    fakehome = tmp_path / "fakehome"
    home = fakehome / ".openclaw"
    shutil.copytree(SAFE, home)
    (home / "media" / "outbound").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fakehome))
    rc, out, _err = _cli(["--pdf", "--home", str(home), "--data-dir", str(tmp_path / "store"),
                          "--no-history", "--no-deptree", "--no-host"])
    assert rc == 0
    assert (home / "media" / "outbound" / "clawseccheck-report.pdf").is_file()
    assert re.search(r"^MEDIA:~/\.openclaw/media/outbound/clawseccheck-report\.pdf$", out, re.M), out
    assert str(fakehome) not in out
