"""B-017 — honest output on non-OpenClaw / custom setups.

When there is no openclaw.json the config-driven checks return UNKNOWN. UNKNOWN is
neutral (never counted against the score), but the report must say so explicitly so a
hardened custom setup does not read as "half-broken".
"""
from pathlib import Path

from clawseccheck import audit
from clawseccheck.collector import collect
from clawseccheck.report import render_report

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------- collector flag
def test_config_found_false_when_no_openclaw_json(tmp_path):
    assert collect(tmp_path).config_found is False


def test_config_found_true_with_openclaw_json(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    assert collect(tmp_path).config_found is True


# ---------------------------------------------------------------- banner present
def test_nonstandard_banner_shown_without_openclaw_json(tmp_path):
    ctx, findings, score = audit(tmp_path)
    assert ctx.config_found is False
    out = render_report(findings, score, openclaw_detected=ctx.config_found)
    assert "No openclaw.json found" in out
    assert "only fully-supported target" in out
    assert "NOT counted against your score" in out


def test_banner_reports_unknown_count(tmp_path):
    ctx, findings, score = audit(tmp_path)
    n_unknown = sum(1 for f in findings if f.status == "UNKNOWN")
    out = render_report(findings, score, openclaw_detected=ctx.config_found)
    assert n_unknown > 0
    assert f"{n_unknown} check(s) were not assessed" in out


# ---------------------------------------------------------------- banner absent
def test_no_banner_on_real_openclaw_config():
    _, findings, score = audit(FIXTURES / "home_safe")
    out = render_report(findings, score, openclaw_detected=True)
    assert "No openclaw.json found" not in out
    assert "non-standard" not in out


def test_default_assumes_openclaw_detected():
    """Omitting the flag must not spuriously show the banner (back-compat)."""
    _, findings, score = audit(FIXTURES / "home_safe")
    out = render_report(findings, score)
    assert "No openclaw.json found" not in out
