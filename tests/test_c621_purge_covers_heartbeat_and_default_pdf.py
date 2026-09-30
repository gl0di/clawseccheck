"""C-621: ``--purge`` must reach every file the tool writes into its own store.

Two writers were missing from ``_PURGE_FILENAMES`` (clawseccheck/cli.py): ``--watch``'s
liveness heartbeat (``watch_heartbeat.json`` - a pid, the absolute home path and
timestamps) and the file a bare ``--pdf`` falls back to (``report.pdf``). ``--purge``
therefore left both behind, printed "Nothing to purge" when nothing else was there, and
``--watch-status`` kept reporting a stale STOPPED watcher after the user had "purged".

A second half of the same defect: with ``--data-dir D`` a bare ``--pdf`` still wrote the REAL
``~/.clawseccheck/report.pdf`` (``_default_pdf_target`` hardcoded the literal path), so a
``--purge --data-dir D`` could not have reached it even with the name whitelisted. The store
moves together (B-599); the PDF fallback now follows it.

The name pins are anchored on the producers (``_watch_heartbeat_path``,
``_default_pdf_target``), not on literals copied into this file, so they stay honest if a
producer is ever renamed.

Offline; every write is confined to pytest's tmp_path (HOME is redirected into it).
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from clawseccheck import cli, watch
from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")

# The flags that keep a full in-process audit inside tmp_path and off the host.
_QUIET = ["--no-native", "--no-history", "--no-deptree", "--no-host", "--no-sockets"]


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


def _write_heartbeat(store: Path) -> Path:
    ns = SimpleNamespace(history=str(store / "history.jsonl"))
    path = cli._watch_heartbeat_path(ns)
    watch._write_heartbeat(
        path, pid=999999, status="stopped", mode="watch", home="/home/someone/.openclaw",
        started_at="2026-09-30T00:00:00Z", updated_at="2026-09-30T00:00:05Z")
    assert path.is_file(), "the real heartbeat writer did not produce the file"
    return path


# ------------------------------------------------- producer-anchored name pins

def test_the_watch_heartbeat_name_is_on_the_purge_list(tmp_path):
    ns = SimpleNamespace(history=str(tmp_path / "store" / "history.jsonl"))
    assert cli._watch_heartbeat_path(ns).name in cli._PURGE_FILENAMES


def test_the_bare_pdf_fallback_name_is_on_the_purge_list(tmp_path, fake_home):
    # A nonexistent home forces the fallback branch (no managed attachment directory).
    target, managed = cli._default_pdf_target(str(tmp_path / "no-such-home"))
    assert managed is False
    assert Path(target).name in cli._PURGE_FILENAMES
    # ... and so does the --data-dir-relative form of the same fallback.
    target, managed = cli._default_pdf_target(
        str(tmp_path / "no-such-home"), tmp_path / "store")
    assert Path(target).name in cli._PURGE_FILENAMES


def test_the_managed_attachment_name_is_not_on_the_purge_list():
    """Boundary pin: clawseccheck-report.pdf lives in <openclaw home>/media/outbound,
    inside the audited home and outside the store. --purge must never reach into it."""
    assert "clawseccheck-report.pdf" not in cli._PURGE_FILENAMES


def test_purge_leaves_the_managed_attachment_alone(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    (store / "history.jsonl").write_text("{}\n")
    home = tmp_path / "oc_home"
    outbound = home / "media" / "outbound"
    outbound.mkdir(parents=True)
    managed_pdf = outbound / "clawseccheck-report.pdf"
    managed_pdf.write_bytes(b"%PDF-1.4 managed")

    rc = main(["--purge", "--yes", "--home", str(home), "--data-dir", str(store)])

    assert rc == 0
    assert managed_pdf.is_file(), "--purge reached into the audited OpenClaw home"


# ----------------------------------------------- the reported bug, end to end

def test_purge_deletes_the_watch_heartbeat_and_watch_status_forgets_it(tmp_path, capsys):
    store = tmp_path / "store"
    hb = _write_heartbeat(store)
    capsys.readouterr()
    assert main(["--watch-status", "--data-dir", str(store)]) == 1
    assert "STOPPED" in capsys.readouterr().out  # the stale watcher is visible before

    rc = main(["--purge", "--yes", "--data-dir", str(store)])
    out = capsys.readouterr().out

    assert rc == 0
    assert not hb.exists(), "--purge left the heartbeat behind"
    assert "watch_heartbeat.json" in out, out
    assert "Purged 1 file(s)" in out, out
    assert main(["--watch-status", "--data-dir", str(store)]) == 1
    assert "NOT RUNNING" in capsys.readouterr().out


def test_purge_deletes_an_unreadable_heartbeat_too(tmp_path, capsys):
    """Purge deletes by name and never parses, so a corrupt heartbeat is no obstacle."""
    store = tmp_path / "store"
    store.mkdir()
    hb = store / "watch_heartbeat.json"
    hb.write_bytes(b"\xff not json")

    rc = main(["--purge", "--yes", "--data-dir", str(store)])

    assert rc == 0
    assert not hb.exists()
    assert "Purged 1 file(s)" in capsys.readouterr().out


def test_purge_deletes_report_pdf_and_only_report_pdf(tmp_path, capsys):
    store = tmp_path / "store"
    store.mkdir()
    pdf = store / "report.pdf"
    pdf.write_bytes(b"%PDF-1.4 audit")
    notes = store / "notes.txt"
    notes.write_text("mine")

    rc = main(["--purge", "--yes", "--history", str(store / "history.jsonl")])
    out = capsys.readouterr().out

    assert rc == 0
    assert not pdf.exists(), "--purge left the default report.pdf behind"
    assert notes.read_text() == "mine", "--purge deleted a file that is not on the list"
    assert "Purged 1 file(s)" in out, out


@pytest.mark.parametrize("name", ["report.pdf", "watch_heartbeat.json"])
def test_a_store_holding_only_the_new_names_is_not_nothing_to_purge(tmp_path, capsys, name):
    store = tmp_path / "store"
    store.mkdir()
    (store / name).write_bytes(b"x")

    rc = main(["--purge", "--yes", "--data-dir", str(store)])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Nothing to purge" not in out, out
    assert name in out, out


def test_an_empty_store_still_says_nothing_to_purge(tmp_path, capsys):
    store = tmp_path / "store"
    store.mkdir()
    (store / "notes.txt").write_text("mine")

    rc = main(["--purge", "--yes", "--data-dir", str(store)])

    assert rc == 0
    assert "Nothing to purge" in capsys.readouterr().out
    assert (store / "notes.txt").exists()


def test_the_confirmation_prompt_lists_report_pdf_before_deleting(tmp_path, monkeypatch, capsys):
    store = tmp_path / "store"
    store.mkdir()
    pdf = store / "report.pdf"
    pdf.write_bytes(b"%PDF-1.4 audit")
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "n")

    rc = main(["--purge", "--data-dir", str(store)])

    assert rc == 0
    assert str(pdf) in capsys.readouterr().out, "the prompt did not name the file it would delete"
    assert pdf.exists()


# -------------------------------------------------------- blast radius (delete path)

def test_a_symlinked_report_pdf_removes_the_link_not_its_target(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    target = tmp_path / "important.pdf"
    target.write_bytes(b"%PDF-1.4 mine")
    link = store / "report.pdf"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    rc = main(["--purge", "--yes", "--data-dir", str(store)])

    assert rc == 0
    assert not link.is_symlink()
    assert target.read_bytes() == b"%PDF-1.4 mine", "--purge followed the link"


def test_a_directory_named_report_pdf_is_reported_not_a_crash(tmp_path, capsys):
    store = tmp_path / "store"
    (store / "report.pdf").mkdir(parents=True)

    rc = main(["--purge", "--yes", "--data-dir", str(store)])
    out = capsys.readouterr().out

    assert rc == 0
    assert "could not delete" in out, out
    assert (store / "report.pdf").is_dir()


# ------------------- bare --pdf follows the store (the half-redirect this task fixes)

def test_the_pdf_fallback_follows_the_store_dir_argument(tmp_path):
    home = tmp_path / "oc_home"
    home.mkdir()
    store = tmp_path / "store"

    target, managed = cli._default_pdf_target(str(home), store)

    assert managed is False
    assert target == str(store / "report.pdf")


def test_the_managed_root_still_beats_the_store(tmp_path):
    home = tmp_path / "oc_home"
    (home / "media" / "outbound").mkdir(parents=True)

    target, managed = cli._default_pdf_target(str(home), tmp_path / "store")

    assert managed is True
    assert target == str(home / "media" / "outbound" / "clawseccheck-report.pdf")


def test_bare_pdf_with_data_dir_writes_into_that_dir_and_purge_reaches_it(
        tmp_path, fake_home, capsys):
    store = tmp_path / "scratch"

    rc = main(["--home", SAFE, "--data-dir", str(store), "--pdf", *_QUIET])
    capsys.readouterr()

    assert rc == 0
    assert (store / "report.pdf").read_bytes().startswith(b"%PDF"), (
        "a bare --pdf under --data-dir did not write <data-dir>/report.pdf")
    assert not (fake_home / ".clawseccheck" / "report.pdf").exists(), (
        "a --data-dir run wrote its report into the real store")

    rc = main(["--purge", "--yes", "--data-dir", str(store)])
    out = capsys.readouterr().out

    assert rc == 0
    assert not (store / "report.pdf").exists(), "--purge --data-dir D cannot reach D/report.pdf"
    assert "report.pdf" in out and "Nothing to purge" not in out


def test_bare_pdf_without_data_dir_still_writes_the_default_store_and_purge_reaches_it(
        tmp_path, fake_home, capsys):
    default_pdf = fake_home / ".clawseccheck" / "report.pdf"

    rc = main(["--home", SAFE, "--pdf", *_QUIET])
    captured = capsys.readouterr()

    assert rc == 0
    assert default_pdf.read_bytes().startswith(b"%PDF")
    assert "~/.clawseccheck/report.pdf" in captured.out  # the note keeps its spelling

    rc = main(["--purge", "--yes"])

    assert rc == 0
    assert not default_pdf.exists()
    assert "Purged" in capsys.readouterr().out
