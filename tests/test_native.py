"""Native `openclaw security audit` integration — fully mocked (offline)."""
import json
import subprocess

from clawseccheck import native
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM
from clawseccheck.native import NativeResult, run_native_audit
from clawseccheck.report import render_report
from clawseccheck.scoring import compute


def _mock(monkeypatch, stdout, exe="/usr/bin/openclaw", recorder=None):
    monkeypatch.setattr(native.shutil, "which", lambda *_a, **_k: exe)

    def fake_run(args, **kwargs):
        if recorder is not None:
            recorder["args"] = args
            recorder["kwargs"] = kwargs
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
    monkeypatch.setattr(native.subprocess, "run", fake_run)


def test_native_parses_and_normalizes_findings(monkeypatch):
    payload = json.dumps({"findings": [
        {"severity": "critical", "title": "Gateway exposed", "message": "0.0.0.0",
         "remediation": "bind loopback", "id": "GW01"},
        {"level": "warning", "name": "Verbose logs", "description": "logs not redacted"},
        {"risk": "info", "check": "model", "detail": "cloud model"},
    ]})
    _mock(monkeypatch, payload)
    res = run_native_audit()
    assert res.status == "ok"
    assert [f.severity for f in res.findings] == [CRITICAL, MEDIUM, LOW]
    assert all(f.status == FAIL and not f.scored for f in res.findings)
    assert res.findings[0].framework == "OpenClaw built-in audit"
    assert res.findings[0].title == "Gateway exposed"


def test_native_uses_fixed_safe_args_no_shell(monkeypatch):
    rec = {}
    _mock(monkeypatch, "[]", recorder=rec)
    run_native_audit()
    assert rec["args"] == ["/usr/bin/openclaw", "security", "audit", "--json"]
    assert rec["kwargs"].get("shell", False) is False


def test_native_not_found_degrades(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda *_a, **_k: None)
    res = run_native_audit()
    assert res.status == "not_found"
    assert res.findings == []
    assert "PATH" in res.note


def test_native_timeout(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda *_a, **_k: "/usr/bin/openclaw")

    def boom(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="openclaw", timeout=60)
    monkeypatch.setattr(native.subprocess, "run", boom)
    assert run_native_audit().status == "timeout"


def test_native_logs_before_json_are_tolerated(monkeypatch):
    _mock(monkeypatch, 'INFO booting audit...\n{"issues": [{"severity":"high","title":"X"}]}')
    res = run_native_audit()
    assert res.status == "ok"
    assert res.findings[0].severity == HIGH


def test_native_unparseable_is_error(monkeypatch):
    _mock(monkeypatch, "not json at all")
    assert run_native_audit().status == "error"


def test_native_skipped_when_disabled():
    assert run_native_audit(enabled=False).status == "skipped"


def test_report_includes_native_section():
    nr = NativeResult("ok", findings=[
        native._to_finding({"severity": "high", "title": "Open Telegram group", "message": "m"}),
    ])
    out = render_report([], compute([]), native=nr)
    assert "built-in" in out
    assert "Open Telegram group" in out


def test_native_findings_never_affect_score():
    # native findings are scored=False -> a critical native FAIL must not cap
    native_fail = native._to_finding({"severity": "critical", "title": "boom"})
    assert compute([native_fail]).score == 0  # no scored findings -> 0 baseline, not a cap artifact
    assert compute([native_fail]).capped is False


# ---------------------------------------------------------------------------
# B-014 — refuse to exec an openclaw binary on an untrusted (writable) path
# ---------------------------------------------------------------------------

def test_native_skips_group_writable_install_path(tmp_path, monkeypatch):
    import os

    if os.name != "posix":
        import pytest
        pytest.skip("POSIX permission bits only")

    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "openclaw"
    exe.write_text("#!/bin/sh\necho '[]'\n")
    exe.chmod(0o755)
    # Make the install dir group- and world-writable -> a local user could swap it.
    bindir.chmod(0o777)

    monkeypatch.setattr(native.shutil, "which", lambda *_a, **_k: str(exe))

    def _boom(*_a, **_k):  # exec must NOT happen
        raise AssertionError("subprocess.run should not be called for an untrusted path")

    monkeypatch.setattr(native.subprocess, "run", _boom)

    res = run_native_audit()
    assert res.status == "skipped"
    assert "writable" in res.note
