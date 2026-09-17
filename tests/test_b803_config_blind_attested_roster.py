"""B-803 — A1 (check_trifecta) reported PASS on a run that never found openclaw.json,
once the attestation carried an agents roster.

``_capabilities_attested(ctx)`` (and ``_meaningful_tool_surface``, which folds it in)
let an attested roster silence every thin-surface hedge that would otherwise flag an OFF
trifecta leg as merely undetermined. But an attestation only speaks to the AGENT's own
declared tools — it says nothing about channels/dmPolicy or the rest of the config
surface a genuinely config-blind run never read at all. That let an attested roster turn
the honest "Cannot determine" WARN a blind run gets into a confident PASS on the
flagship CRITICAL check — worse than the run's own default, unattested behavior.

This pins:
  1. A config-blind run (``ctx.config_found is False``) with an attested roster is never
     PASS — it keeps the WARN hedge instead.
  2. The plain config-blind WARN (no attestation at all) is unaffected — its wording is
     unchanged, so this fix only widens an already-hedged branch.
  3. The task's own positive control: ``fixtures/home_safe`` (a genuinely found config)
     plus a roster naming only recognised, trifecta-free tools keeps today's PASS.
  4. A found-but-thin config (B-033/D3) still lets an attestation clear the hedge exactly
     as before — the config-blind guard must stay completely inert once config was
     genuinely read.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_trifecta
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class TestConfigBlindWithAttestedRoster:
    def test_blind_run_with_attested_roster_is_not_pass(self, tmp_path):
        # No openclaw.json anywhere under tmp_path -> a real, collector-produced
        # config_found=False, not a hand-built stand-in.
        ctx = collect(tmp_path)
        assert ctx.config_found is False
        ctx.attestation = {"agents": [{"name": "main", "tools": ["exec", "write"]}]}
        finding = check_trifecta(ctx)
        assert finding.status != PASS, (
            "A1 returned PASS on a run that never found openclaw.json, just because an "
            f"attested roster was supplied (detail: {finding.detail!r})"
        )
        assert finding.status == WARN
        assert "Cannot determine" in finding.detail

    def test_blind_run_without_attestation_is_unaffected(self, tmp_path):
        """Regression guard: the plain blind-run WARN (no attestation at all) must keep
        its existing wording — the fix only widens an already-hedged branch, it must not
        change behavior when there is nothing to widen."""
        ctx = collect(tmp_path)
        assert ctx.config_found is False
        finding = check_trifecta(ctx)
        assert finding.status == WARN
        assert (
            "Cannot determine from config: untrusted input, outbound actions."
            in finding.detail
        )


class TestPositiveControlUnaffected:
    def test_home_safe_with_recognised_trifecta_free_roster_unchanged(self):
        """The task's own positive control: a genuinely-found config plus a roster
        naming only non-leg tools must keep today's result."""
        ctx = collect(FIXTURES / "home_safe")
        assert ctx.config_found is True
        baseline = check_trifecta(ctx).status
        assert baseline == PASS
        ctx.attestation = {"agents": [{"name": "bot", "tools": ["chat"]}]}
        attested = check_trifecta(ctx)
        assert attested.status == baseline

    def test_found_thin_config_attestation_still_clears_the_hedge(self, tmp_path):
        """B-033/D3 regression guard: the config-blind guard must stay inert once
        config was genuinely read, even when the config declares nothing at all."""
        (tmp_path / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}')
        (tmp_path / "openclaw.json").chmod(0o600)
        ctx = collect(tmp_path)
        assert ctx.config_found is True
        thin = check_trifecta(ctx)
        assert thin.status == WARN
        assert "Cannot determine" in thin.detail

        ctx.attestation = {"agents": [{"name": "bot", "tools": ["chat"]}]}
        attested = check_trifecta(ctx)
        assert attested.status == PASS
        assert "Cannot determine" not in attested.detail
