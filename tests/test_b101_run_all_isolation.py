"""B-101: run_all must isolate a single crashing check.

A check that raises a non-OSError (KeyError/TypeError/re.error/RecursionError, …)
must NOT sink the whole audit — that is both an availability failure and an
evasion primitive (a malicious skill/config crafted to crash one check would
otherwise suppress the entire report). run_all degrades a crashing check to one
UNKNOWN finding; every other check still runs. The exception *message* is never
surfaced (it may carry a path / config value) — only its type name.
"""
from __future__ import annotations

import logging
from pathlib import Path

import clawseccheck.checks as checks
from clawseccheck.catalog import UNKNOWN
from clawseccheck.collector import Context


def _ctx() -> Context:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {}
    return ctx


def _boom(ctx):
    # message deliberately carries secret-shaped text that must never leak
    raise KeyError("leaky detail /home/user/.openclaw/creds.json api_key=sk-live")


def test_one_crashing_check_does_not_sink_the_audit(monkeypatch):
    original = list(checks.CHECKS)
    monkeypatch.setattr(checks, "CHECKS", original + [_boom])

    findings = checks.run_all(_ctx())  # must NOT raise

    # every real check still produced a finding, plus exactly one for the crash
    assert len(findings) == len(original) + 1

    errs = [f for f in findings if f.id.startswith("ERR:")]
    assert len(errs) == 1
    err = errs[0]
    assert err.status == UNKNOWN
    assert err.scored is False
    assert "_boom" in err.id
    # the exception *type* is useful and safe; the message must never leak
    assert "KeyError" in " ".join(err.evidence)
    blob = f"{err.title}\n{err.detail}\n{err.fix}\n{' '.join(err.evidence)}"
    assert "creds.json" not in blob
    assert "/home/user" not in blob
    assert "sk-live" not in blob


def test_clean_run_has_no_error_findings():
    # a normal run over an empty config must never synthesize an ERR finding
    findings = checks.run_all(_ctx())
    assert not [f for f in findings if f.id.startswith("ERR:")]


# ── B-767: the traceback the finding promises must actually reach --debug ─────


def test_crash_traceback_reaches_the_debug_log(monkeypatch, caplog):
    """The ERR finding tells the user to re-run with --debug for the traceback --
    something has to actually write one for that to be true."""
    original = list(checks.CHECKS)
    monkeypatch.setattr(checks, "CHECKS", original + [_boom])
    # logsafe.get_logger() sets propagate=False on this SAME process-global logger --
    # deliberately, in production, so records never double up on the root logger. But
    # caplog's handler is attached to the root logger and relies on propagation, so any
    # earlier test in this pytest session that ran the real CLI (cli.main(), which calls
    # get_logger()) leaves this logger unable to be captured for the rest of the run.
    # Not a source bug -- restore propagation for the duration of this test only.
    monkeypatch.setattr(logging.getLogger("clawseccheck"), "propagate", True)

    with caplog.at_level("DEBUG", logger="clawseccheck"):
        checks.run_all(_ctx())

    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "_boom" in text
    assert "KeyError" in text
    assert "Traceback (most recent call last)" in text, "format_exc() must have rendered a real traceback"
    # exc_info must NOT be set: logsafe._RedactingFilter redacts getMessage(), but a
    # Formatter renders exc_info separately, after the filter runs — exc_info=True
    # would ship a traceback the redaction filter never saw.
    assert all(r.exc_info is None for r in caplog.records)


def test_crash_traceback_is_silent_below_debug_level(monkeypatch, caplog):
    """No --debug -> the logger stays at its default (WARNING+) level -> silent,
    same as every real CLI invocation that does not pass --debug."""
    original = list(checks.CHECKS)
    monkeypatch.setattr(checks, "CHECKS", original + [_boom])
    monkeypatch.setattr(logging.getLogger("clawseccheck"), "propagate", True)

    with caplog.at_level("WARNING", logger="clawseccheck"):
        checks.run_all(_ctx())

    assert not caplog.records


# ── Part 2: main() top-level guard ────────────────────────────────────────────

import clawseccheck.cli as cli  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_SAFE_HOME = str(FIXTURES / "home_safe")


def _explode(*a, **k):
    raise ValueError("leaky boom /home/user/.openclaw/creds.json token=sk-live")


def test_main_degrades_unexpected_error_to_clean_exit(monkeypatch, capsys):
    monkeypatch.setattr(cli, "audit", _explode)

    rc = cli.main(["--home", _SAFE_HOME])  # must NOT raise

    assert rc == 1
    out = capsys.readouterr()
    # clean one-liner on stderr; stdout stays clean (matters for --json/--sarif)
    assert "unexpected internal error" in out.err
    assert "ValueError" in out.err
    assert "Traceback" not in out.err and "Traceback" not in out.out
    # CLAWSECCHECK-C-314: somewhere to go when the tool itself is the problem —
    # cosmetic, unlike the leak check below, which is load-bearing
    assert cli._ISSUES_URL in out.err
    # the exception message (path/token) must never leak — this is the part that
    # actually matters; the URL above must never be an excuse to relax it
    for secret in ("creds.json", "/home/user", "sk-live"):
        assert secret not in out.err and secret not in out.out


def test_main_debug_reraises_for_developers(monkeypatch):
    monkeypatch.setattr(cli, "audit", _explode)
    import pytest  # noqa: PLC0415
    with pytest.raises(ValueError):
        cli.main(["--home", _SAFE_HOME, "--debug"])


def _budget_boom(*a, **k):
    from clawseccheck.scanbudget import ScanBudgetExceeded  # noqa: PLC0415
    raise ScanBudgetExceeded("leaky detail /home/user/.openclaw/creds.json api_key=sk-live")


def test_main_degrades_scan_budget_exceeded_to_clean_exit(monkeypatch, capsys):
    """CLAWSECCHECK-C-314: the ScanBudgetExceeded arm gets the same issues-URL
    treatment as the generic-crash arm, and the same no-leak contract."""
    monkeypatch.setattr(cli, "audit", _budget_boom)

    rc = cli.main(["--home", _SAFE_HOME])  # must NOT raise

    assert rc == 1
    out = capsys.readouterr()
    assert "cut short by its own time budget" in out.err
    assert cli._ISSUES_URL in out.err
    assert "Traceback" not in out.err and "Traceback" not in out.out
    for secret in ("creds.json", "/home/user", "sk-live"):
        assert secret not in out.err and secret not in out.out


def test_main_debug_reraises_scan_budget_exceeded(monkeypatch):
    monkeypatch.setattr(cli, "audit", _budget_boom)
    import pytest  # noqa: PLC0415
    from clawseccheck.scanbudget import ScanBudgetExceeded  # noqa: PLC0415
    with pytest.raises(ScanBudgetExceeded):
        cli.main(["--home", _SAFE_HOME, "--debug"])


def _ctrl_c(*a, **k):
    raise KeyboardInterrupt


def test_main_degrades_keyboard_interrupt_to_clean_exit(monkeypatch, capsys):
    """CLAWSECCHECK-C-509: Ctrl+C mid-scan is a normal, expected user action, not a
    bug — but KeyboardInterrupt derives from BaseException, so it was never caught
    by the generic `except Exception` arm at all and used to dump a raw traceback,
    breaking this module's own "never dump a raw traceback at users" promise."""
    monkeypatch.setattr(cli, "audit", _ctrl_c)

    rc = cli.main(["--home", _SAFE_HOME])  # must NOT raise, must NOT print a traceback

    assert rc == 1
    out = capsys.readouterr()
    assert "interrupted" in out.err
    # Not the "unexpected internal error" / bug-report framing — a user-initiated
    # interrupt is not a defect in this tool.
    assert "unexpected internal error" not in out.err
    assert "Traceback" not in out.err and "Traceback" not in out.out


def test_main_debug_reraises_keyboard_interrupt(monkeypatch):
    monkeypatch.setattr(cli, "audit", _ctrl_c)
    import pytest  # noqa: PLC0415
    with pytest.raises(KeyboardInterrupt):
        cli.main(["--home", _SAFE_HOME, "--debug"])


# ── Part 3: Python-version guard (CLAWSECCHECK-C-314) ─────────────────────────


def test_main_rejects_old_python_before_doing_any_other_work(monkeypatch, capsys):
    """The version guard is the very first thing main() does — it must fire even
    when the rest of the pipeline (here, ``audit``) would blow up, proving nothing
    else ran first."""
    monkeypatch.setattr(cli, "audit", _explode)
    monkeypatch.setattr(cli.sys, "version_info", (3, 8, 0, "final", 0))

    rc = cli.main(["--home", _SAFE_HOME])

    assert rc == 1
    out = capsys.readouterr()
    assert "Python 3.9+" in out.err
    assert "3.8" in out.err
    assert "unexpected internal error" not in out.err  # _explode never ran


def test_main_accepts_current_python():
    """On a supported interpreter the guard is a no-op (sanity check against a
    guard that accidentally always fires)."""
    rc = cli.main(["--home", _SAFE_HOME, "--card", "--no-native", "--no-history"])
    assert rc == 0
