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
    # B-774: the exec-trust guard now fails CLOSED on a stat it can't perform, and
    # `exe` here is a fixed path that need not exist on the machine running this
    # test — so without this, every test below would exercise the guard's "could
    # not check" branch instead of the parsing/args/error-handling it means to.
    monkeypatch.setattr(native, "_untrusted_exec_reason", lambda _exe: None)

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
    monkeypatch.setattr(native, "_untrusted_exec_reason", lambda _exe: None)

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


# ---------------------------------------------------------------------------
# B-774 — the guard must not fail OPEN on non-POSIX or on a stat it cannot
# perform; those two "learned nothing" answers must stay distinguishable from
# each other AND from a genuine "checked, clean" verdict.
# ---------------------------------------------------------------------------

def test_untrusted_exec_reason_fails_closed_on_stat_error(monkeypatch, tmp_path):
    """A path that cannot even be stat()ed is not a trusted one. Before the fix this
    returned bare `None` — identical to a real, verified-clean path."""
    monkeypatch.setattr(native.os, "name", "posix")

    def boom(_path):
        raise OSError("permission denied")
    monkeypatch.setattr(native.os, "stat", boom)

    result = native._untrusted_exec_reason(str(tmp_path / "nonexistent" / "openclaw"))
    assert result is not None, "OSError must not read as 'checked, clean'"
    must_skip, reason = result
    assert must_skip is True
    assert reason


def test_untrusted_exec_reason_non_posix_is_distinguishable_from_clean(monkeypatch):
    """Windows `os.stat().st_mode`'s group/other bits carry no meaning — the guard
    must say so distinctly (must_skip=False), never collapse into the SAME bare
    `None` a real POSIX clean pass returns."""
    monkeypatch.setattr(native.os, "name", "nt")

    result = native._untrusted_exec_reason(r"C:\Program Files\openclaw\openclaw.exe")
    assert result is not None, "non-POSIX must not read as 'checked, clean'"
    must_skip, reason = result
    assert must_skip is False
    assert reason


def test_untrusted_exec_reason_non_posix_is_distinguishable_from_stat_error(monkeypatch):
    """The two no-information paths must not collapse into EACH OTHER either — a
    caller (run_native_audit) treats them differently (always skip vs. proceed and
    disclose), so they need different `must_skip` values, not just both being
    non-None."""
    monkeypatch.setattr(native.os, "name", "nt")
    _must_skip, non_posix_reason = native._untrusted_exec_reason("C:\\openclaw.exe")

    monkeypatch.setattr(native.os, "name", "posix")
    monkeypatch.setattr(native.os, "stat", lambda _p: (_ for _ in ()).throw(OSError("x")))
    stat_error_must_skip, stat_error_reason = native._untrusted_exec_reason("/opt/openclaw")

    assert stat_error_must_skip is True
    assert non_posix_reason != stat_error_reason


def test_untrusted_exec_reason_still_none_on_a_genuinely_clean_posix_path(tmp_path):
    """Positive control: the fix must not turn EVERY path into a caveat — a real,
    owner-only install still reads as clean."""
    import os
    if os.name != "posix":
        import pytest
        pytest.skip("POSIX permission bits only")

    bindir = tmp_path / "bin"
    bindir.mkdir(mode=0o755)
    exe = bindir / "openclaw"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    assert native._untrusted_exec_reason(str(exe)) is None


def test_run_native_audit_skips_on_stat_error(monkeypatch):
    """The CALL SITE, not just the helper: a stat failure must behave exactly like a
    confirmed-unsafe verdict — skip, never silently exec."""
    monkeypatch.setattr(native.shutil, "which", lambda *_a, **_k: "/usr/bin/openclaw")
    monkeypatch.setattr(
        native, "_untrusted_exec_reason",
        lambda _exe: (True, "could not check install-path permissions (boom)"))

    def _boom(*_a, **_k):
        raise AssertionError("subprocess.run should not be called")
    monkeypatch.setattr(native.subprocess, "run", _boom)

    res = run_native_audit()
    assert res.status == "skipped"
    assert "could not check" in res.note


def test_run_native_audit_proceeds_and_discloses_when_unverifiable(monkeypatch):
    """The CALL SITE's other new branch: non-POSIX may still run the built-in audit
    (dropping the feature entirely on a declared-supported platform would be its own
    regression), but the result must carry an honest disclosure — never render the
    same as a silent, fully-verified 'ok'."""
    monkeypatch.setattr(native.shutil, "which", lambda *_a, **_k: "/usr/bin/openclaw")
    monkeypatch.setattr(
        native, "_untrusted_exec_reason",
        lambda _exe: (False, "this platform's file permissions can't be read as POSIX mode bits"))

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout="[]", stderr="")
    monkeypatch.setattr(native.subprocess, "run", fake_run)

    res = run_native_audit()
    assert res.status == "ok", "non-POSIX must not silently disable the feature"
    assert "trust check not performed" in res.note
