"""C-135 (independent, post-commit) — B-803's fix for A1 (check_trifecta) left the
identical root-cause bug unpatched in its sibling check, B3 (check_least_privilege).

Both checks let ``_capabilities_attested(ctx)`` alone clear an "undeclared surface"
hedge to a confident PASS, even on a run that never found ``openclaw.json`` at all.
B-803 fixed A1 with a ``config_blind`` guard; this pins the same guard on B3.

Same reasoning as ``test_b803_config_blind_attested_roster.py``: an attestation only
speaks to the agent's own declared tools, not the rest of the config surface (tool
profile, plugins, elevated-tool allowlists) a config-blind run never read.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import check_least_privilege
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class TestConfigBlindWithAttestedRoster:
    def test_blind_run_with_attested_roster_is_not_pass(self, tmp_path):
        # No openclaw.json anywhere under tmp_path -> a real, collector-produced
        # config_found=False, not a hand-built stand-in.
        ctx = collect(tmp_path)
        assert ctx.config_found is False
        ctx.attestation = {"agents": [{"name": "main", "tools": ["exec", "write"]}]}
        finding = check_least_privilege(ctx)
        assert finding.status != PASS, (
            "B3 returned PASS on a run that never found openclaw.json, just because an "
            f"attested roster was supplied (detail: {finding.detail!r})"
        )
        assert finding.status == UNKNOWN
        assert "no OpenClaw config was found to read at all" in finding.detail

    def test_blind_run_without_attestation_is_unaffected(self, tmp_path):
        """Regression guard: the plain blind-run UNKNOWN (no attestation at all) already
        existed via the ordinary surface_undeclared gate — the fix must not change its
        wording."""
        ctx = collect(tmp_path)
        assert ctx.config_found is False
        finding = check_least_privilege(ctx)
        assert finding.status == UNKNOWN
        assert "no OpenClaw config was found to read at all" in finding.detail


class TestPositiveControlUnaffected:
    def test_home_safe_with_attested_roster_unchanged(self):
        """A genuinely-found config's B3 verdict must not move just because an
        attestation is also supplied."""
        ctx = collect(FIXTURES / "home_safe")
        assert ctx.config_found is True
        baseline = check_least_privilege(ctx).status
        ctx.attestation = {"agents": [{"name": "bot", "tools": ["chat"]}]}
        attested = check_least_privilege(ctx)
        assert attested.status == baseline

    def test_found_but_undeclared_surface_attestation_still_clears_the_hedge(self, tmp_path):
        """The config-blind guard must stay completely inert once config was genuinely
        read, even when the config declares no privilege surface at all — attestation
        must still be able to clear the pre-existing surface_undeclared hedge."""
        (tmp_path / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}')
        (tmp_path / "openclaw.json").chmod(0o600)
        ctx = collect(tmp_path)
        assert ctx.config_found is True
        thin = check_least_privilege(ctx)
        assert thin.status == UNKNOWN

        ctx.attestation = {"agents": [{"name": "bot", "tools": ["chat"]}]}
        attested = check_least_privilege(ctx)
        assert attested.status == PASS
