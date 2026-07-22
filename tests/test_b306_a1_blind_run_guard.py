"""B-306 — A1 (check_trifecta) computed a real-looking verdict during a blind run.

`check_trifecta` never called the opt-in `_config_unreadable()` guard (B-228). With
openclaw.json present but unparseable/unreadable, the collector falls back to
`ctx.config == {}` (B-166) — an empty dict that looks like a valid, clean config — and
A1 read that as "0/3 legs, cannot determine two of them from config" and reported WARN
instead of its true FAIL. Measured on the real ~/.openclaw: true grade F/49, blind-run
grade C/79 — a two-grade improvement from a run that could not even read the config,
on the flagship CRITICAL check (Lethal Trifecta).

This pins:
  1. A1 degrades to UNKNOWN (not WARN/PASS/FAIL) whenever openclaw.json is present but
     unparseable (truncated JSON) or unreadable (permission-denied) — both shapes the
     collector folds into `ctx.config_parse_error` (B-166).
  2. The guard is completely inert on a genuinely readable config — byte-identical A1
     verdicts on fixtures/home_safe and fixtures/home_vuln, whether or not the fix is
     applied (asserted directly against those two real-shaped fixtures below).
  3. The same "real-config-shape" property using home_vuln's own openclaw.json content:
     truncating it must turn A1's true FAIL into UNKNOWN, never leave it at a
     confidently-worded WARN that a scorer would credit.
  4. check_credential_blast_radius (B41) has the identical mixed-evidence bug — its
     credential inventory can be established by a config-INDEPENDENT persistent-dotenv
     signal alone, while its "reachable" assessment is 100% ctx.config-derived — and gets
     the same guard.

Offline, read-only of the tmp_path sandbox, stdlib only.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_credential_blast_radius, check_trifecta
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _by_id(findings):
    return {f.id: f for f in findings}


class TestA1TruncatedJson:
    """Case 1 — openclaw.json present but invalid JSON (mirrors test_b228's shape)."""

    @pytest.fixture
    def home(self, tmp_path) -> Path:
        (tmp_path / "openclaw.json").write_text(
            '{ "channels": { "telegram": { "dmPolicy": "open" } }, "tools": { "exec":  '
        )  # truncated -> invalid JSON; would be a real 3/3 FAIL if it parsed
        return tmp_path

    def test_collector_flags_parse_error(self, home):
        ctx = collect(home)
        assert ctx.config_found is True
        assert ctx.config_parse_error is True
        assert ctx.config == {}

    def test_a1_is_unknown_not_warn(self, home):
        ctx = collect(home)
        finding = check_trifecta(ctx)
        assert finding.status == UNKNOWN, (
            f"A1 returned {finding.status!r} on an unparseable config — must degrade to "
            f"UNKNOWN, not compute a real-looking verdict (detail: {finding.detail!r})"
        )
        assert "unparseable/unreadable" in finding.detail


class TestA1PermissionDenied:
    """Case 2 — valid JSON with a real 3-leg trifecta, but the file is owner-unreadable."""

    @pytest.fixture
    def home(self, tmp_path) -> Path:
        cfg = tmp_path / "openclaw.json"
        cfg.write_text(
            '{"channels": {"telegram": {"dmPolicy": "open"}}, '
            '"tools": {"allow": ["exec", "email_send"], "elevated": {"allowFrom": {"telegram": ["*"]}}}}'
        )
        os.chmod(cfg, 0o000)
        yield tmp_path
        os.chmod(cfg, 0o600)  # restore so pytest can clean tmp_path up

    def test_collector_flags_parse_error(self, home):
        ctx = collect(home)
        assert ctx.config_found is True
        assert ctx.config_parse_error is True
        assert ctx.config == {}

    def test_a1_is_unknown_not_warn(self, home):
        ctx = collect(home)
        finding = check_trifecta(ctx)
        assert finding.status == UNKNOWN, (
            f"A1 returned {finding.status!r} on a permission-denied config — must degrade "
            f"to UNKNOWN, not compute a real-looking verdict (detail: {finding.detail!r})"
        )


class TestA1RegressionGuardIsInert:
    """A normally-readable config (config_parse_error is False) must be completely
    unaffected — the guard only fires on an actual parse/read failure."""

    def test_readable_thin_config_still_warns_as_before(self, tmp_path):
        # Pre-existing B-033 thin-surface behavior: A1 legitimately WARNs (not PASS) on a
        # readable-but-undeclared tool surface. The B-306 guard must not change this.
        (tmp_path / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}')
        os.chmod(tmp_path / "openclaw.json", 0o600)
        ctx = collect(tmp_path)
        assert ctx.config_parse_error is False
        finding = check_trifecta(ctx)
        assert finding.status == WARN
        assert "unparseable/unreadable" not in finding.detail

    def test_readable_3of3_config_still_fails(self, tmp_path):
        (tmp_path / "openclaw.json").write_text(
            '{"channels": {"telegram": {"dmPolicy": "open"}}, '
            '"tools": {"allow": ["exec", "email_send"]}}'
        )
        os.chmod(tmp_path / "openclaw.json", 0o600)
        ctx = collect(tmp_path)
        assert ctx.config_parse_error is False
        finding = check_trifecta(ctx)
        assert finding.status == FAIL
        assert len(finding.evidence) == 3

    def test_home_safe_and_home_vuln_a1_unchanged(self):
        """Byte-identical assertion the task's test plan asks for directly, on the two
        real-shaped fixtures used throughout the suite."""
        _, safe_findings, _ = audit(FIXTURES / "home_safe")
        _, vuln_findings, _ = audit(FIXTURES / "home_vuln")
        assert _by_id(safe_findings)["A1"].status == PASS
        assert _by_id(vuln_findings)["A1"].status == FAIL
        assert len(_by_id(vuln_findings)["A1"].evidence) == 3


class TestA1RealConfigShapeBlindRun:
    """The exact 'hiding evidence never improves the grade' shape from the bug report:
    take a REAL vulnerable config (home_vuln's own openclaw.json, a genuine 3/3 FAIL) and
    make it unreadable. A1 must never report anything softer than UNKNOWN — in
    particular it must never re-derive the old WARN/PASS that credited a clean-looking
    but actually-blind run."""

    def test_truncated_home_vuln_config_a1_is_unknown(self, tmp_path):
        real_vuln_cfg = (FIXTURES / "home_vuln" / "openclaw.json").read_text()
        # Confirm the untouched config really is a true 3/3 FAIL before blinding it.
        (tmp_path / "openclaw.json").write_text(real_vuln_cfg)
        os.chmod(tmp_path / "openclaw.json", 0o600)
        ctx_readable = collect(tmp_path)
        assert check_trifecta(ctx_readable).status == FAIL

        # Now blind it (truncate mid-object) and confirm A1 degrades honestly.
        (tmp_path / "openclaw.json").write_text(real_vuln_cfg[: len(real_vuln_cfg) // 2])
        ctx_blind = collect(tmp_path)
        assert ctx_blind.config_parse_error is True
        finding = check_trifecta(ctx_blind)
        assert finding.status == UNKNOWN, (
            "A1 must report UNKNOWN on a blinded real-vulnerable config, not silently "
            f"soften the true FAIL into {finding.status!r}"
        )


# ── B41 (check_credential_blast_radius) shares the identical mixed-evidence bug: its
# credential inventory can be established from a config-INDEPENDENT persistent dotenv
# artifact alone, while the "reachable" claim is 100% ctx.config-derived. ─────────────

class TestB41EnvTokenBlindConfig:
    """A persistent (on-disk) OPENCLAW_GATEWAY_TOKEN makes `has_credentials` True
    without any openclaw.json content at all — so before this fix, an unparseable
    config still reached the "not broadly reachable" PASS purely because the
    (unreadable) config could not show an ingress+outbound path either."""

    @pytest.fixture
    def home(self, tmp_path) -> Path:
        (tmp_path / "openclaw.json").write_text('{ "tools": { "exec":  ')  # truncated
        # global runtime dotenv slot read by collector._collect_global_dotenv
        (tmp_path / ".env").write_text(
            "OPENCLAW_GATEWAY_TOKEN=abcdefghijklmnopqrstuvwx\n"
        )
        return tmp_path

    def test_collector_sees_env_token_but_not_config(self, home):
        ctx = collect(home)
        assert ctx.config_parse_error is True
        assert ctx.dotenv_values.get("OPENCLAW_GATEWAY_TOKEN")

    def test_b41_is_unknown_not_false_pass(self, home):
        ctx = collect(home)
        finding = check_credential_blast_radius(ctx)
        assert finding.status == UNKNOWN, (
            "B41 returned a confident verdict from a config it never actually read — "
            f"got {finding.status!r} (detail: {finding.detail!r})"
        )

    def test_readable_config_env_token_regression_unaffected(self, tmp_path):
        # Same env token, but this time openclaw.json is present, valid, and genuinely
        # has no untrusted-ingress/outbound path — B41's own PASS logic must still fire.
        (tmp_path / "openclaw.json").write_text("{}")
        os.chmod(tmp_path / "openclaw.json", 0o600)
        (tmp_path / ".env").write_text(
            "OPENCLAW_GATEWAY_TOKEN=abcdefghijklmnopqrstuvwx\n"
        )
        ctx = collect(tmp_path)
        assert ctx.config_parse_error is False
        finding = check_credential_blast_radius(ctx)
        assert finding.status == PASS
        assert "unparseable/unreadable" not in finding.detail
