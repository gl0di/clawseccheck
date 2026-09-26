"""B-869 — a build-identity line so a dev install is distinguishable from the release.

``__version__``/``__released__`` are strings a human edits by hand; a local dev
checkout can print the exact same version as the release it diverged from while the
files underneath differ (the real incident: an agent quoted the release version back
as reassurance while unreleased fixes sat uninstalled). ``render_menu()`` and
``render_report()`` now accept an optional ``build_digest`` — a short self-computed
content fingerprint from ``integrity.build_fingerprint()`` — that says so. Offline,
read-only, no fixtures needed beyond a bare tmp_path.
"""
from __future__ import annotations

from clawseccheck.cli import main
from clawseccheck.integrity import build_fingerprint
from clawseccheck.menu import render_menu
from clawseccheck.report import render_report
from clawseccheck.scoring import compute

BASE = ["--no-native", "--no-history"]


# ── render_menu() ──────────────────────────────────────────────────────────────

def test_menu_build_line_carries_the_digest_verbatim():
    out = render_menu(version="1.0.0", build_digest="0123456789ab")
    assert "🔧 Build: 0123456789ab" in out


def test_menu_omits_build_line_when_not_given():
    """Optional and additive — every pre-existing render_menu() caller/test that
    omits build_digest must reproduce the prior output unchanged."""
    assert "Build:" not in render_menu(version="1.0.0")


# ── render_report() ────────────────────────────────────────────────────────────

def _report(tmp_path, build_digest=None):
    findings = []
    score = compute(findings, ctx=None)
    return render_report(findings, score, build_digest=build_digest)


def test_report_build_line_carries_the_digest_verbatim(tmp_path):
    out = _report(tmp_path, build_digest="0123456789ab")
    assert "Build: 0123456789ab" in out


def test_report_omits_build_line_when_not_given(tmp_path):
    """Optional and additive — every pre-existing render_report() caller/test that
    omits build_digest must reproduce the prior output unchanged."""
    assert "Build:" not in _report(tmp_path, build_digest=None)


def test_report_build_line_sits_right_under_the_header(tmp_path):
    out = _report(tmp_path, build_digest="0123456789ab")
    lines = out.splitlines()
    assert lines[1] == "Build: 0123456789ab"
    assert lines[2] == "=" * 44


# ── CLI wiring: the real fingerprint reaches both surfaces ────────────────────

def test_cli_menu_prints_the_real_build_fingerprint(tmp_path, capsys):
    rc = main(["--menu", "--history", str(tmp_path / "history.jsonl")])
    assert rc == 0
    assert f"Build: {build_fingerprint()}" in capsys.readouterr().out


def test_cli_default_report_prints_the_real_build_fingerprint(tmp_path, capsys):
    # A bare empty tmp_path hits the onboarding screen (render_onboarding), not the
    # audit report — a minimal openclaw.json routes this through render_report instead.
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    main(["--home", str(tmp_path)] + BASE)
    assert f"Build: {build_fingerprint()}" in capsys.readouterr().out
