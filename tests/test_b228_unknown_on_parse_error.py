"""B-228 — an unreadable/unparseable openclaw.json must not fake a clean PASS.

When openclaw.json exists but can't be parsed (truncated JSON) or can't be read
(permission-denied), the collector sets ctx.config_parse_error = True and falls back to
ctx.config = {} (B-166). Before this fix, every config-content check that reads
ctx.config/dig(ctx.config, ...) with no other guard saw that empty-but-valid-looking
config and emitted an affirmative "clean" PASS it never earned — most sharply B1
(check_secrets), which reported "No exposed plaintext secrets." on a file that (in the
repro) literally contains a plaintext AWS-shaped key. This violates Golden Rule #4:
report UNKNOWN, not a fake PASS/FAIL, when a check genuinely can't determine state.

This test pins the fix for every guarded config-dependent check across BOTH failure
shapes (truncated/invalid JSON, and a valid-JSON-but-permission-denied file), plus the
regression: a normally-readable config still gets a real B1 FAIL (secret present) or a
real B1 PASS (clean config) — the guard must be inert when config_parse_error is False.

Offline, read-only of the tmp_path sandbox, stdlib only. The AWS-key-shaped secret is
assembled from fragments at runtime (no contiguous literal in source — see
tests/test_logsafe.py for the same pattern).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import (
    check_cachetrace_redaction,       # B82
    check_cron_scheduler,             # C048
    check_dangerous_overrides,        # B48
    check_declared_skill_reconciliation,  # B158
    check_discovery_mdns_mode,        # B73
    check_exec_applypatch_workspace,  # B68
    check_gateway_rate_limit,         # B80
    check_hook_policy_bypass,         # C6
    check_mcp_external_endpoint,      # C047
    check_proxy_header_forging,       # C032
    check_secrets,                    # B1
    check_subagent_spawn_limits,      # B81
    check_tls,                        # B11
    check_webfetch_redirects,         # B83
)
from clawseccheck.collector import collect

# Every config-dependent check guarded by checks/_shared._config_unreadable (B-228).
# Keep in sync with the checks wired in clawseccheck/checks/_config.py, _capability.py,
# _agents.py, _egress.py, _mcp.py, _lifecycle.py.
GUARDED_CHECKS = [
    check_secrets,                    # B1
    check_tls,                        # B11
    check_dangerous_overrides,        # B48
    check_proxy_header_forging,       # C032
    check_gateway_rate_limit,         # B80
    check_exec_applypatch_workspace,  # B68
    check_subagent_spawn_limits,      # B81
    check_cachetrace_redaction,       # B82
    check_discovery_mdns_mode,        # B73
    check_webfetch_redirects,         # B83
    check_mcp_external_endpoint,      # C047
    check_cron_scheduler,             # C048
    check_hook_policy_bypass,         # C6
    check_declared_skill_reconciliation,  # B158
]

# Assembled at runtime so no contiguous secret-shaped literal exists in source.
_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def test_guarded_checks_are_config_dependent_sanity():
    # Guard against a future rename silently dropping a check from the manifest above.
    assert len(GUARDED_CHECKS) == 14


class TestTruncatedJson:
    """Case 1 — present but invalid JSON (a secret sits in the file, but it never parses)."""

    @pytest.fixture
    def home(self, tmp_path) -> Path:
        (tmp_path / "openclaw.json").write_text(
            '{ "apiKey": "' + _AWS_KEY + '", "tools": { "exec":  '
        )  # truncated -> invalid JSON
        return tmp_path

    def test_collector_flags_parse_error(self, home):
        ctx = collect(home)
        assert ctx.config_found is True
        assert ctx.config_parse_error is True
        assert ctx.config == {}

    @pytest.mark.parametrize("check_fn", GUARDED_CHECKS, ids=lambda f: f.__name__)
    def test_every_guarded_check_is_unknown(self, home, check_fn):
        ctx = collect(home)
        finding = check_fn(ctx)
        assert finding.status == UNKNOWN, (
            f"{check_fn.__name__} returned {finding.status!r} on an unparseable config "
            f"— must degrade to UNKNOWN, not fake a clean verdict (detail: {finding.detail!r})"
        )


class TestPermissionDenied:
    """Case 2 — valid JSON with a secret, but the file itself is owner-unreadable."""

    @pytest.fixture
    def home(self, tmp_path) -> Path:
        cfg = tmp_path / "openclaw.json"
        cfg.write_text('{"apiKey": "' + _AWS_KEY + '"}')
        os.chmod(cfg, 0o000)
        yield tmp_path
        os.chmod(cfg, 0o600)  # restore so pytest can clean tmp_path up

    def test_collector_flags_parse_error(self, home):
        ctx = collect(home)
        assert ctx.config_found is True
        assert ctx.config_parse_error is True
        assert ctx.config == {}

    @pytest.mark.parametrize("check_fn", GUARDED_CHECKS, ids=lambda f: f.__name__)
    def test_every_guarded_check_is_unknown(self, home, check_fn):
        ctx = collect(home)
        finding = check_fn(ctx)
        assert finding.status == UNKNOWN, (
            f"{check_fn.__name__} returned {finding.status!r} on a permission-denied "
            f"config — must degrade to UNKNOWN, not fake a clean verdict "
            f"(detail: {finding.detail!r})"
        )


class TestRegressionGuardIsInert:
    """A normally-readable config (config_parse_error is False) must be byte-identically
    unaffected — the guard only fires on an actual parse/read failure."""

    def test_readable_config_with_secret_still_fails(self, tmp_path):
        (tmp_path / "openclaw.json").write_text('{"apiKey": "' + _AWS_KEY + '"}')
        os.chmod(tmp_path / "openclaw.json", 0o644)  # group/world-readable -> B1 evidence
        ctx = collect(tmp_path)
        assert ctx.config_parse_error is False
        assert check_secrets(ctx).status == FAIL

    def test_readable_clean_config_still_passes(self, tmp_path):
        (tmp_path / "openclaw.json").write_text("{}")
        ctx = collect(tmp_path)
        assert ctx.config_parse_error is False
        assert check_secrets(ctx).status == PASS

    def test_readable_config_other_guarded_checks_still_pass(self, tmp_path):
        # A valid, fully-parsed "{}" config declares nothing dangerous, so every guarded
        # check's own (pre-existing, unchanged) logic legitimately PASSes — the guard
        # must stay completely inert (never fire) once config_parse_error is False.
        # (chmod 600: B11 also WARNs on a group/world-readable config file, independent
        # of config content — pin tight perms here so that signal doesn't fire either.)
        cfg = tmp_path / "openclaw.json"
        cfg.write_text("{}")
        os.chmod(cfg, 0o600)
        ctx = collect(tmp_path)
        assert ctx.config_parse_error is False
        for check_fn in GUARDED_CHECKS:
            finding = check_fn(ctx)
            assert finding.status == PASS, (
                f"{check_fn.__name__} returned {finding.status!r} (expected PASS) on a "
                f"valid, parsed empty config — the B-228 guard must be inert here"
            )


class TestBootstrapSecretStillDetectedUnderParseError:
    """B1 mixes config-derived evidence with an independent bootstrap-file secret scan;
    the guard is placed before the terminal PASS only, so a real bootstrap-file secret
    still legitimately FAILs even when openclaw.json itself is unparseable."""

    def test_bootstrap_secret_fails_even_with_broken_config(self, tmp_path):
        (tmp_path / "openclaw.json").write_text('{ "tools": { "exec":  ')  # truncated
        (tmp_path / "AGENTS.md").write_text("api_key: " + _AWS_KEY)
        ctx = collect(tmp_path)
        assert ctx.config_parse_error is True
        finding = check_secrets(ctx)
        assert finding.status == FAIL
        assert any("AGENTS.md" in e for e in finding.evidence)
