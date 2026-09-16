"""CLAWSECCHECK-C-510 item 2: a plain audit gives progress feedback instead of running
silently for up to ~3 minutes on hostile content (indistinguishable from a hang).

`checks.run_all`'s `on_check_done` hook (threaded through `audit(progress_cb=...)`) is
called after every check -- normal, budget-exceeded, or crashed -- with
`(done_count, total_count)`, so the count never under-reports a degraded run. Default
None everywhere except the CLI's interactive default-audit path
(`cli._default_audit_progress_cb`), which stays quiet for `--quiet`, `--json`, and
non-interactive stderr.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import clawseccheck.checks as checks
from clawseccheck.catalog import PASS
from clawseccheck.cli import _default_audit_progress_cb
from clawseccheck.collector import Context


def _ctx() -> Context:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {}
    return ctx


def _ok(ctx):
    from clawseccheck.catalog import Finding, HIGH
    return Finding(id="X1", status=PASS, detail="d", fix="f", title="t", severity=HIGH,
                   framework="F")


def _boom(ctx):
    raise KeyError("boom")


def test_run_all_default_has_no_progress_hook_and_is_unaffected():
    """No `on_check_done` -> run_all behaves exactly as before (every existing
    caller/test in this suite relies on this)."""
    findings = checks.run_all(_ctx())
    assert len(findings) == len(checks.CHECKS)


def test_on_check_done_fires_once_per_check_including_crashes(monkeypatch):
    monkeypatch.setattr(checks, "CHECKS", [_ok, _boom, _ok])
    calls = []
    findings = checks.run_all(_ctx(), on_check_done=lambda d, t: calls.append((d, t)))
    assert len(findings) == 3
    assert calls == [(1, 3), (2, 3), (3, 3)]


def test_on_check_done_final_call_always_reports_full_total(monkeypatch):
    """Even a check the audit-wide budget skipped still counts -- the last call must
    equal (total, total), never a lower number that reads as fewer checks than the
    catalog."""
    monkeypatch.setattr(checks, "CHECKS", [_ok, _ok, _ok, _ok])
    monkeypatch.setattr(checks, "audit_budget_exceeded", lambda deadline: True)
    calls = []
    findings = checks.run_all(
        _ctx(), on_check_done=lambda d, t: calls.append((d, t))
    )
    assert len(findings) == 4
    assert all(f.id.startswith("ERR:") for f in findings)
    assert calls[-1] == (4, 4)


def test_audit_progress_cb_reaches_run_all(monkeypatch):
    """`audit(progress_cb=...)` threads straight through to run_all's hook."""
    from clawseccheck import audit

    calls = []
    ctx, findings, score = audit(
        Path("fixtures/home_safe"), include_native=False,
        progress_cb=lambda d, t: calls.append((d, t)),
    )
    assert calls, "progress_cb was never called"
    assert calls[-1] == (len(checks.CHECKS), len(checks.CHECKS))


def _args(**overrides):
    base = {"quiet": False, "json": False}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_cli_progress_cb_none_when_quiet():
    assert _default_audit_progress_cb(_args(quiet=True)) is None


def test_cli_progress_cb_none_when_json():
    assert _default_audit_progress_cb(_args(json=True)) is None


def test_cli_progress_cb_none_when_stderr_not_a_tty(monkeypatch, capsys):
    import clawseccheck.cli as cli_mod

    class _NotATty:
        def isatty(self):
            return False

    monkeypatch.setattr(cli_mod.sys, "stderr", _NotATty())
    assert _default_audit_progress_cb(_args()) is None


def test_cli_progress_cb_writes_to_stderr_when_interactive(monkeypatch, capsys):
    import io

    import clawseccheck.cli as cli_mod

    class _Tty(io.StringIO):
        def isatty(self):
            return True

    fake_stderr = _Tty()
    monkeypatch.setattr(cli_mod.sys, "stderr", fake_stderr)
    cb = _default_audit_progress_cb(_args())
    assert cb is not None
    cb(1, 5)  # first call always prints (no prior throttle timestamp)
    cb(5, 5)  # final call always prints regardless of throttling
    out = fake_stderr.getvalue()
    assert "1/5" in out
    assert "5/5" in out
