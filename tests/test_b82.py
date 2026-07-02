"""B82 — cacheTrace transcripts persisted without tool-output redaction.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_cachetrace_redaction
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_b82_no_cachetrace_is_pass():
    assert check_cachetrace_redaction(_ctx({"logging": {"redactSensitive": "off"}})).status == PASS


def test_b82_cachetrace_with_redaction_is_pass():
    cfg = {"logging": {"redactSensitive": "tools",
                       "cacheTrace": {"filePath": "~/.openclaw/t.jsonl"}}}
    assert check_cachetrace_redaction(_ctx(cfg)).status == PASS


def test_b82_cachetrace_without_redaction_is_warn():
    cfg = {"logging": {"redactSensitive": "off",
                       "cacheTrace": {"filePath": "~/.openclaw/t.jsonl"}}}
    assert check_cachetrace_redaction(_ctx(cfg)).status == WARN


def test_b82_cachetrace_unset_redaction_is_warn():
    cfg = {"logging": {"cacheTrace": {"filePath": "~/.openclaw/t.jsonl"}}}
    assert check_cachetrace_redaction(_ctx(cfg)).status == WARN


def test_b82_clean_fixture_pass():
    assert check_cachetrace_redaction(collect(FIXTURES / "clean_b82_cachetrace_redaction")).status == PASS


def test_b82_bad_fixture_warn():
    assert check_cachetrace_redaction(collect(FIXTURES / "bad_b82_cachetrace_redaction")).status == WARN


def test_b82_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b82_cachetrace_redaction", include_native=False)
    assert "B82" in {f.id for f in findings}
