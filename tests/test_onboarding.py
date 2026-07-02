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


class TestBareRunOnly:
    """B-075: onboarding fires only on a BARE human run. Any CI / artifact / work flag
    takes the normal audit path, so nothing is silently dropped and CI gates fail loud."""

    def test_fail_under_still_fails_on_missing_home(self, tmp_path, capsys):
        # The CI guard-rail: a missing home must not turn a --fail-under gate green.
        rc = main(["--home", str(tmp_path / "nope"), "--fail-under", "90", "--no-history"])
        out = capsys.readouterr().out
        assert rc != 0
        assert "welcome" not in out
        assert "Score:" in out  # the real audit ran

    def test_exit_code_path_skips_onboarding(self, tmp_path, capsys):
        main(["--home", str(tmp_path / "nope"), "--exit-code", "--no-history"])
        assert "welcome" not in capsys.readouterr().out

    def test_save_is_honored_on_missing_home(self, tmp_path, capsys):
        target = tmp_path / "report.txt"
        rc = main(["--home", str(tmp_path / "nope"), "--save", str(target), "--no-history"])
        out = capsys.readouterr().out
        assert rc == 0
        assert target.exists() and target.stat().st_size > 0
        assert "welcome" not in out

    def test_full_still_runs_selftest_on_missing_home(self, tmp_path, capsys):
        rc = main(["--home", str(tmp_path / "nope"), "--full", "--no-history",
                   "--seed", "1", "--no-freshness-notice"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "SELF-TEST" in out
        assert "welcome" not in out

    def test_bare_run_still_gets_onboarding(self, tmp_path, capsys):
        # The welcome itself must survive the gate tightening.
        rc = main(["--home", str(tmp_path / "nope"), "--no-history"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "welcome" in out


class TestUnreadableHome:
    """B-076: an unreadable home is a controlled, plain-language outcome — no traceback."""

    def test_perm_denied_home_is_controlled(self, tmp_path, capsys):
        import os
        locked = tmp_path / "locked"
        locked.mkdir()
        (locked / "openclaw.json").write_text("{}", encoding="utf-8")
        os.chmod(locked, 0o000)
        try:
            rc = main(["--home", str(locked), "--no-history"])
        finally:
            os.chmod(locked, 0o755)  # let pytest clean tmp_path up
        out = capsys.readouterr().out
        assert rc == 1
        assert "Cannot read the OpenClaw home" in out
        assert "Traceback" not in out
