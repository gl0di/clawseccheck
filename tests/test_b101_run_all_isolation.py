"""B-101: run_all must isolate a single crashing check.

A check that raises a non-OSError (KeyError/TypeError/re.error/RecursionError, …)
must NOT sink the whole audit — that is both an availability failure and an
evasion primitive (a malicious skill/config crafted to crash one check would
otherwise suppress the entire report). run_all degrades a crashing check to one
UNKNOWN finding; every other check still runs. The exception *message* is never
surfaced (it may carry a path / config value) — only its type name.
"""
from __future__ import annotations

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
    # the exception message (path/token) must never leak
    for secret in ("creds.json", "/home/user", "sk-live"):
        assert secret not in out.err and secret not in out.out


def test_main_debug_reraises_for_developers(monkeypatch):
    monkeypatch.setattr(cli, "audit", _explode)
    import pytest  # noqa: PLC0415
    with pytest.raises(ValueError):
        cli.main(["--home", _SAFE_HOME, "--debug"])
