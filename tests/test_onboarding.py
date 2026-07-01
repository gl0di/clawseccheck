"""Screen 13 — first-run / no-config onboarding (F-046).

Offline, deterministic; all filesystem work stays inside pytest's tmp_path.
"""
from __future__ import annotations

import json

from clawseccheck.cli import _onboarding_reason, main
from clawseccheck.menu import render_onboarding


# ── Detection: _onboarding_reason ────────────────────────────────────────────

class TestReason:
    def test_missing_home(self, tmp_path):
        assert _onboarding_reason(tmp_path / "nope") == "missing"

    def test_empty_home(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        assert _onboarding_reason(d) == "empty"

    def test_dir_with_any_entry_is_not_onboarding(self, tmp_path):
        # A populated dir hands off to the audit path — this is also how the
        # "config present but unreadable" case is kept OUT of onboarding: the
        # openclaw.json entry makes the dir non-empty, so we never hide it.
        d = tmp_path / "home"
        d.mkdir()
        (d / "openclaw.json").write_text("{}", encoding="utf-8")
        assert _onboarding_reason(d) is None

    def test_junk_only_home_is_not_onboarding(self, tmp_path):
        d = tmp_path / "home"
        d.mkdir()
        (d / "readme.txt").write_text("hi", encoding="utf-8")
        assert _onboarding_reason(d) is None


# ── Rendering ─────────────────────────────────────────────────────────────────

class TestRender:
    def test_missing_variant(self):
        out = render_onboarding(reason="missing", home="/x/.openclaw", n_checks=81)
        assert "/x/.openclaw" in out
        assert "nothing there" in out
        assert "81 security checks" in out
        assert '"check"' in out  # the call to action

    def test_empty_variant(self):
        out = render_onboarding(reason="empty", home="/x/.openclaw", n_checks=81)
        assert "empty" in out

    def test_count_fallback(self):
        out = render_onboarding(reason="missing", home="/x", n_checks=None)
        assert "the full set of security checks" in out

    def test_ascii_is_pure(self):
        out = render_onboarding(reason="missing", home="/x", n_checks=81, ascii_only=True)
        assert out.isascii()
        assert "🦞" not in out and "•" not in out


# ── CLI integration ───────────────────────────────────────────────────────────

class TestCliIntegration:
    def test_missing_home_shows_welcome_rc0(self, tmp_path, capsys):
        rc = main(["--home", str(tmp_path / "nope"), "--no-history"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "welcome" in out
        assert "Security Audit" not in out  # NOT the dashboard

    def test_missing_home_json_stays_machine(self, tmp_path, capsys):
        # --json keeps its contract: a valid JSON document, never the welcome screen.
        rc = main(["--home", str(tmp_path / "nope"), "--json", "--no-history"])
        out = capsys.readouterr().out
        assert rc == 0
        json.loads(out)  # raises if the welcome text leaked in
        assert "welcome" not in out
