"""A read-only local store (``~/.clawseccheck``) never crashes an audit and is never silent.

The shape that found it: an agent running under a sandbox that only lets a run write
inside its workspace (the Codex harness's ``codex-linux-sandbox``). The audit finished,
but history, coverage dates, saved runs and the default PDF all went nowhere - three of
the four silently - and the one visible failure named no way out.

The store is made read-only the way such a sandbox does it: every create/write under the
store directory fails with EROFS (``chmod 0500`` would not do - ``secure_dir`` chmods an
owned store back to 0700, and root-run CI ignores mode bits). Offline; writes only
inside ``tmp_path``.
"""
from __future__ import annotations

import errno
import json
import os
import tempfile
from pathlib import Path

import pytest

from clawseccheck import ledger, runstore, sbom_runs
from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HOME = str(FIXTURES / "home_vuln")

NOTE = "NOT SAVED"


def _erofs(path) -> OSError:
    return OSError(errno.EROFS, os.strerror(errno.EROFS), str(path))


def _patch_readonly(mp, store: Path) -> None:
    root = str(store)

    def under(p) -> bool:
        return str(p) == root or str(p).startswith(root + os.sep)

    real_mkdir, real_mkstemp, real_open = Path.mkdir, tempfile.mkstemp, os.open

    def mkdir(self, *a, **kw):
        if under(self):
            raise _erofs(self)
        return real_mkdir(self, *a, **kw)

    def mkstemp(*a, **kw):
        if kw.get("dir") is not None and under(kw["dir"]):
            raise _erofs(kw["dir"])
        return real_mkstemp(*a, **kw)

    def opener(path, flags, *a, **kw):
        if under(path) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND):
            raise _erofs(path)
        return real_open(path, flags, *a, **kw)

    mp.setattr(Path, "mkdir", mkdir)
    mp.setattr(tempfile, "mkstemp", mkstemp)
    mp.setattr(os, "open", opener)


@pytest.fixture
def readonly_store(tmp_path, monkeypatch):
    """Make everything under ``tmp_path/store`` unwritable (EROFS), as a read-only mount."""
    store = tmp_path / "store"
    store.mkdir()
    _patch_readonly(monkeypatch, store)
    return store


def _run(capsys, *argv):
    rc = main(["--home", HOME, "--no-native", "--ascii", *argv])
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def _fresh_store(tmp_path):
    """A writable store, for the clean (control) runs."""
    store = tmp_path / "store"
    store.mkdir(exist_ok=True)
    return store


# ---------------------------------------------------------------------------
# Control: a writable store saves everything and says nothing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flags", [
    [], ["--save-run"], ["--dashboard", "--pdf"], ["--sbom", "--save-sbom-run"],
    ["--self-test"],
])
def test_writable_store_saves_and_says_nothing(tmp_path, capsys, flags):
    store = _fresh_store(tmp_path)
    rc, _out, err = _run(capsys, "--data-dir", str(store), *flags)
    assert rc == 0
    assert NOTE not in err
    expected = {
        "--save-run": "runs.jsonl", "--save-sbom-run": "sbom_runs.jsonl",
        "--pdf": "report.pdf", "--self-test": "coverage.json",
    }
    for flag, name in expected.items():
        if flag in flags:
            assert (store / name).exists(), f"{flag} wrote no {name}"
    if not any(f in flags for f in ("--sbom", "--self-test")):
        assert (store / "history.jsonl").exists()


# ---------------------------------------------------------------------------
# A read-only store: no crash, verdict and exit code unchanged, ONE note
# ---------------------------------------------------------------------------

def test_default_audit_reports_the_unsaved_history_once(tmp_path, capsys, readonly_store):
    rc, out, err = _run(capsys, "--data-dir", str(readonly_store))
    assert rc == 0
    assert err.count(NOTE) == 1
    assert "score history" in err
    assert "Read-only file system" in err
    assert "--data-dir <a writable directory>" in err
    assert "Traceback" not in err
    assert NOTE not in out
    assert not any(readonly_store.iterdir())


def test_verdict_and_exit_code_are_the_same_as_on_a_writable_store(tmp_path, capsys):
    ro_store = tmp_path / "ro"
    ok_store = tmp_path / "ok"
    ok_store.mkdir()
    # Writable control first (the fixture below patches globally for its test only).
    rc_ok, out_ok, err_ok = _run(capsys, "--json", "--exit-code", "--data-dir", str(ok_store))
    assert NOTE not in err_ok
    ro_store.mkdir()
    mp = pytest.MonkeyPatch()
    try:
        _patch_readonly(mp, ro_store)
        rc_ro, out_ro, err_ro = _run(capsys, "--json", "--exit-code", "--data-dir", str(ro_store))
    finally:
        mp.undo()
    assert rc_ro == rc_ok
    assert NOTE in err_ro
    ok, ro = json.loads(out_ok), json.loads(out_ro)
    assert ro["score"] == ok["score"]
    assert ro["findings"] == ok["findings"]


def test_no_history_leaves_nothing_to_report(tmp_path, capsys, readonly_store):
    rc, _out, err = _run(capsys, "--no-history", "--data-dir", str(readonly_store))
    assert rc == 0
    assert NOTE not in err


def test_save_run_and_history_share_one_note(tmp_path, capsys, readonly_store):
    rc, out, err = _run(capsys, "--save-run", "--data-dir", str(readonly_store))
    assert rc == 0
    assert err.count(NOTE) == 1
    assert "saved run (--save-run)" in err and "score history" in err
    assert "run saved as" not in out


def test_save_sbom_run_is_reported(tmp_path, capsys, readonly_store):
    rc, _out, err = _run(capsys, "--sbom", "--save-sbom-run", "--data-dir", str(readonly_store))
    assert rc == 0
    assert err.count(NOTE) == 1
    assert "saved SBOM run" in err


def test_coverage_ledger_write_is_reported(tmp_path, capsys, readonly_store):
    rc, _out, err = _run(capsys, "--self-test", "--data-dir", str(readonly_store))
    assert rc == 0
    assert err.count(NOTE) == 1
    assert "coverage dates" in err


def test_dashboard_pdf_keeps_the_audit_and_names_the_fix(tmp_path, capsys, readonly_store):
    rc, out, err = _run(capsys, "--dashboard", "--pdf", "--data-dir", str(readonly_store))
    assert rc == 0
    assert "could not write PDF report" in out
    assert "showing the full report inline" in out
    assert "--pdf <path>" in out and "writable" in out
    assert "Read-only file system" in out
    assert ".tmp" not in out, "named the atomic-write temp file, not the requested path"
    assert err.count(NOTE) == 1
    assert len(out) > 800


def test_bare_pdf_still_exits_1_and_names_the_fix(tmp_path, capsys, readonly_store):
    rc, out, err = _run(capsys, "--pdf", "--data-dir", str(readonly_store))
    assert rc == 1
    assert out == ""
    assert "could not write PDF report" in err
    assert "--pdf <path>" in err and "nothing was written" in err
    assert ".tmp" not in err


def test_explicit_writable_pdf_path_works_while_the_store_is_read_only(
        tmp_path, capsys, readonly_store):
    dest = tmp_path / "workspace" / "report.pdf"
    rc, out, err = _run(capsys, "--dashboard", "--pdf", str(dest),
                        "--data-dir", str(readonly_store))
    assert rc == 0
    assert dest.exists() and dest.stat().st_size > 0
    assert "could not write PDF report" not in out
    # History still could not be saved, and that is still said (once).
    assert err.count(NOTE) == 1


def test_monitor_still_fails_loudly_and_says_how_to_fix_it(tmp_path, capsys, readonly_store):
    rc, _out, err = _run(capsys, "--monitor", "--data-dir", str(readonly_store))
    assert rc == 1
    assert "MONITORING NOT ESTABLISHED" in err
    assert "Read-only file system" in err
    assert "--data-dir <a writable directory>" in err
    assert ".tmp" not in err


# ---------------------------------------------------------------------------
# The writers themselves: never raise, and hand back why
# ---------------------------------------------------------------------------

def test_ledger_record_run_returns_the_error_instead_of_dropping_it(tmp_path, readonly_store):
    err = ledger.record_run("self_test", path=str(readonly_store / "coverage.json"))
    assert err is not None and "Read-only file system" in err


def test_ledger_record_run_returns_none_on_success(tmp_path):
    assert ledger.record_run("self_test", path=str(tmp_path / "ok" / "coverage.json")) is None


def test_run_stores_hand_back_the_reason(tmp_path, readonly_store):
    sink: list[str] = []
    assert runstore.save_run([], str(readonly_store / "runs.jsonl"), error_sink=sink) is None
    assert sink and "Read-only file system" in sink[0]
    sink2: list[str] = []
    assert sbom_runs.save_sbom_run({}, str(readonly_store / "s.jsonl"), error_sink=sink2) is None
    assert sink2 and "Read-only file system" in sink2[0]


def test_run_stores_without_a_sink_still_just_return_none(tmp_path, readonly_store):
    assert runstore.save_run([], str(readonly_store / "runs.jsonl")) is None
