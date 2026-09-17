"""H4 hardening — non-zero exit code from openclaw security audit is surfaced."""
import json
import subprocess

from clawseccheck import native
from clawseccheck.native import run_native_audit


def _mock_run(monkeypatch, stdout, stderr="", returncode=0):
    monkeypatch.setattr(native.shutil, "which", lambda *_a, **_k: "/usr/bin/openclaw")
    # B-774: the exec-trust guard now fails CLOSED on a stat it cannot perform, and
    # this fixed path need not exist on the machine running the suite.
    monkeypatch.setattr(native, "_untrusted_exec_reason", lambda _exe: None)

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(native.subprocess, "run", fake_run)


# (a) returncode != 0 + parseable JSON stdout
def test_nonzero_exit_with_parseable_json_status_ok(monkeypatch):
    payload = json.dumps({"findings": [
        {"severity": "high", "title": "Exposed port", "message": "port 9000 open"},
    ]})
    _mock_run(monkeypatch, stdout=payload, returncode=1)
    res = run_native_audit()
    assert res.status == "ok"
    assert len(res.findings) == 1
    assert "exited 1" in res.note


def test_nonzero_exit_with_parseable_json_note_mentions_code(monkeypatch):
    payload = json.dumps({"findings": []})
    _mock_run(monkeypatch, stdout=payload, returncode=2)
    res = run_native_audit()
    assert res.status == "ok"
    assert "exited 2" in res.note


# (b) returncode != 0 + empty stdout
def test_nonzero_exit_with_empty_stdout_is_error(monkeypatch):
    _mock_run(monkeypatch, stdout="", returncode=1)
    res = run_native_audit()
    assert res.status == "error"
    assert "exited 1" in res.note


# (b) returncode != 0 + garbage stdout
def test_nonzero_exit_with_garbage_stdout_is_error(monkeypatch):
    _mock_run(monkeypatch, stdout="fatal: unknown command", returncode=127)
    res = run_native_audit()
    assert res.status == "error"
    assert "exited 127" in res.note


def test_nonzero_exit_with_garbage_stdout_includes_stderr(monkeypatch):
    _mock_run(monkeypatch, stdout="", stderr="command not found: openclaw", returncode=127)
    res = run_native_audit()
    assert res.status == "error"
    assert "exited 127" in res.note
    assert "command not found" in res.note


def test_nonzero_exit_stderr_truncated_to_300_chars(monkeypatch):
    long_stderr = "x" * 500
    _mock_run(monkeypatch, stdout="", stderr=long_stderr, returncode=1)
    res = run_native_audit()
    assert res.status == "error"
    # note = "openclaw security audit exited 1: " + 300 chars of stderr
    assert len(res.note) <= len("openclaw security audit exited 1: ") + 300


# zero exit + garbage output keeps existing behavior (no exit-code mention)
def test_zero_exit_with_garbage_stdout_is_error_no_exit_mention(monkeypatch):
    _mock_run(monkeypatch, stdout="not json at all", returncode=0)
    res = run_native_audit()
    assert res.status == "error"
    assert "exited" not in res.note


# zero exit + parseable JSON keeps existing behavior (no exit-code mention)
def test_zero_exit_with_parseable_json_note_has_no_exit_code(monkeypatch):
    payload = json.dumps({"findings": [{"severity": "low", "title": "Minor issue"}]})
    _mock_run(monkeypatch, stdout=payload, returncode=0)
    res = run_native_audit()
    assert res.status == "ok"
    assert "exited" not in res.note
