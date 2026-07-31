"""CLAWSECCHECK-B-363 — a wholly ABSENT openclaw.json must never score better than a
present-but-unreadable one.

Pre-fix repro: ``clawseccheck --home /nonexistent/path --json`` scored 89/B,
``capped: false``, exit code 0 for ``--exit-code`` — the tool silently lied about a
target it never read. Meanwhile a present-but-unparseable config already correctly
scored 49/F, ``capped: true`` (scoring.CONFIG_BLIND_CAP, B-306). Absence is strictly
LESS information than a corrupt file (the collector never even opened anything), yet it
scored 40 points HIGHER — the exact "hiding evidence improves the grade" defect
CONFIG_BLIND_CAP exists to prevent, one state further back.

Fix: `scoring._config_blind_signal` now also fires (reason ``"absent"``) when
``ctx.config_found`` is False, at the SAME ceiling as the existing "unreadable"
case (reason ``"unreadable"``) — this EXTENDS the existing B-306 signal/field rather
than adding a fourth, parallel cap. `report.py` distinguishes the two cases in its
cap-reason text and stops printing "Audited config: <path>" when nothing was actually
read. `cli.py`'s ``--exit-code`` gate trips on an absent config exactly like it already
trips on an unreadable one.

Offline, deterministic, real fixtures + the shipped ``audit()``/``main()`` entry points
(per project doctrine: verify end-to-end, not traces).
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.cli import main
from clawseccheck.scoring import CONFIG_BLIND_CAP, compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CLEAN_HOME = FIXTURES / "home_safe"


def _truncate_config(tmp_path: Path) -> Path:
    """A present-but-unparseable openclaw.json (the pre-existing B-306 shape)."""
    (tmp_path / "openclaw.json").write_text('{"mcp": {"servers": ')
    (tmp_path / "openclaw.json").chmod(0o600)
    return tmp_path


# ── Unit level: scoring.compute() in isolation ────────────────────────────────────────

class TestConfigBlindSignalUnit:
    def test_absent_config_caps_same_ceiling_as_unreadable(self, tmp_path):
        from clawseccheck.catalog import LOW, PASS, Finding

        def _f():
            return Finding("X", "t", LOW, PASS, "d", "fix", "fw", True)

        from clawseccheck.collector import Context
        absent_ctx = Context(home=tmp_path)  # config_found defaults False: never scanned
        r = compute([_f() for _ in range(20)], absent_ctx)
        assert r.score <= CONFIG_BLIND_CAP
        assert r.grade == "F"
        assert r.capped is True
        assert r.config_blind_capped is True
        assert r.config_blind_reason == "absent"

    def test_unreadable_reason_still_reported_distinctly(self, tmp_path):
        from clawseccheck.catalog import LOW, PASS, Finding
        from clawseccheck.collector import Context

        ctx = Context(home=tmp_path)
        ctx.config_found = True
        ctx.config_parse_error = True
        r = compute([Finding("X", "t", LOW, PASS, "d", "fix", "fw", True) for _ in range(20)], ctx)
        assert r.config_blind_capped is True
        assert r.config_blind_reason == "unreadable"

    def test_readable_config_gets_no_reason(self, tmp_path):
        from clawseccheck.catalog import LOW, PASS, Finding
        from clawseccheck.collector import Context

        ctx = Context(home=tmp_path)
        ctx.config_found = True
        ctx.config_parse_error = False
        r = compute([Finding("X", "t", LOW, PASS, "d", "fix", "fw", True) for _ in range(20)], ctx)
        assert r.config_blind_capped is False
        assert r.config_blind_reason is None

    def test_ctx_none_stays_inert(self):
        from clawseccheck.catalog import LOW, PASS, Finding
        r = compute([Finding("X", "t", LOW, PASS, "d", "fix", "fw", True)], None)
        assert r.config_blind_capped is False
        assert r.config_blind_reason is None


# ── Three-way contract via the real audit()/main() entry points ───────────────────────

class TestThreeWayContract:
    """absent home / unreadable home / clean fixture home — score, capped, cap-reason
    substring, and exit code (with and without --exit-code) for each."""

    def test_absent_home(self, tmp_path, capsys):
        missing = tmp_path / "does-not-exist"
        ctx, findings, score = audit(missing)
        assert ctx.config_found is False
        assert score.score <= CONFIG_BLIND_CAP
        assert score.grade == "F"
        assert score.capped is True
        assert score.config_blind_capped is True
        assert score.config_blind_reason == "absent"

        # --json: no "Audited config" line equivalent leak, and machine-visible reason.
        rc_json = main(["--home", str(missing), "--json", "--no-native", "--no-history"])
        out = capsys.readouterr().out
        assert '"config_blind_reason": "absent"' in out
        assert rc_json == 0  # --json alone never sets a nonzero exit by itself

        # --exit-code: must now be non-zero (the bug this task fixes).
        rc = main(["--home", str(missing), "--exit-code", "--no-native", "--no-history"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "no OpenClaw config found" in out
        assert "Audited config:" not in out

        # No --exit-code at all: still 0 (only --exit-code/--fail-under/--save force a
        # nonzero return; the ordinary text-report path never does on its own).
        rc_plain = main(["--home", str(missing), "--no-native", "--no-history"])
        assert rc_plain == 0

    def test_unreadable_home(self, tmp_path, capsys):
        home = _truncate_config(tmp_path)
        ctx, findings, score = audit(home)
        assert ctx.config_found is True
        assert ctx.config_parse_error is True
        assert score.score <= CONFIG_BLIND_CAP
        assert score.grade == "F"
        assert score.capped is True
        assert score.config_blind_capped is True
        assert score.config_blind_reason == "unreadable"

        rc = main(["--home", str(home), "--exit-code", "--no-native", "--no-history"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "openclaw.json unreadable/unparseable this run" in out
        # The file WAS found (just unparseable) -- unlike the absent case, naming it is
        # still honest and still prints.
        assert "Audited config:" in out

    def test_clean_home_unaffected(self, capsys):
        ctx, findings, score = audit(CLEAN_HOME)
        assert ctx.config_found is True
        assert ctx.config_parse_error is False
        assert score.config_blind_capped is False
        assert score.config_blind_reason is None
        assert score.score > CONFIG_BLIND_CAP

        # Runs under DEFAULT flags (sockets scanning included): B-374 fixed the
        # underlying F-156/B340 attribution bug that used to make this
        # nondeterministic -- a non-loopback listener sharing this fixture's declared
        # gateway.bind (127.0.0.1:8080) port number can no longer FAIL this check
        # unless it is POSITIVELY confirmed (via /proc identity) to be the gateway
        # process itself; an unrelated listener now degrades to UNKNOWN, which
        # --exit-code ignores.
        rc = main(["--home", str(CLEAN_HOME), "--exit-code", "--no-native", "--no-history"])
        capsys.readouterr()
        assert rc == 0

        rc_plain = main(["--home", str(CLEAN_HOME), "--no-native", "--no-history"])
        capsys.readouterr()
        assert rc_plain == 0


# ── Monotonicity: hiding the config must never score better ───────────────────────────

class TestAbsentNeverScoresBetterThanClean:
    def test_score_absent_le_score_clean(self, tmp_path):
        _, _, score_absent = audit(tmp_path / "nowhere")
        _, _, score_clean = audit(CLEAN_HOME)
        assert score_absent.score <= score_clean.score, (
            f"an absent config must never outscore a clean one: absent="
            f"{score_absent.score}/{score_absent.grade}, clean="
            f"{score_clean.score}/{score_clean.grade}"
        )

    def test_score_absent_le_score_unreadable_is_equal_at_the_same_ceiling(self, tmp_path):
        # Both states are capped at the identical CRITICAL ceiling -- absence is not
        # WORSE than corruption (there's nothing sound to rank them by), just never
        # BETTER. Pins that the two paths land on the same cap, not two different ones.
        absent_home = tmp_path / "absent"
        unreadable_home = tmp_path / "unreadable"
        unreadable_home.mkdir()
        _truncate_config(unreadable_home)

        _, _, score_absent = audit(absent_home)
        _, _, score_unreadable = audit(unreadable_home)
        assert score_absent.score <= CONFIG_BLIND_CAP
        assert score_unreadable.score <= CONFIG_BLIND_CAP


# ── Regression guard: bare onboarding path must still exit 0 ──────────────────────────

class TestBareOnboardingRegression:
    """The bug fix must NOT touch _bare_run (cli.py ~line 1660): a BARE interactive run
    (no --json/--card/--save/--full/--fail-under/--exit-code/--attest/primary-mode flag)
    against a missing home shows the onboarding screen and returns 0, unconditionally."""

    def test_bare_run_missing_home_still_exits_zero(self, tmp_path, capsys):
        missing = tmp_path / "still-does-not-exist"
        rc = main(["--home", str(missing)])
        out = capsys.readouterr().out
        assert rc == 0
        # Onboarding screen, not a normal audit report.
        assert "Audited config:" not in out
