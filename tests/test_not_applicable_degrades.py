"""F-139 (B2) degradation matrix — the migrated MCP-cluster checks (B15/B24/B166)
must fall back to ordinary ``not_applicable=False`` UNKNOWN (never a claim of
proven surface absence) whenever the config read was NOT provably complete:

(a) a domain-tagged LimitHit for LIMIT_DOMAIN_CONFIG (the scan hit a cap while
    reading the config itself);
(b) ``config_parse_error=True`` (openclaw.json present but unparseable);
(c) ``config_found=False`` (no openclaw.json at all -- absence of evidence is
    not evidence of absence).

In all three cases status stays UNKNOWN (unaffected -- not_applicable is
orthogonal to status). Mirrors tests/test_not_applicable_field.py's own
``test_surface_absent_*`` cases, applied through the real check functions
rather than the bare ``_surface_absent`` predicate.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import (
    check_mcp,
    check_mcp_hardening,
    check_mcp_server_exfil_host_in_args,
)
from clawseccheck.collector import LIMIT_DOMAIN_CONFIG, Context, note_limit

_CHECKS = pytest.mark.parametrize(
    "check_fn",
    [check_mcp, check_mcp_hardening, check_mcp_server_exfil_host_in_args],
    ids=["B15", "B24", "B166"],
)


def _complete_ctx() -> Context:
    """A config read that WOULD otherwise prove absence -- the control case."""
    return Context(home=Path("/nonexistent"), config_found=True, config_parse_error=False)


@_CHECKS
def test_control_complete_read_sets_not_applicable(check_fn):
    ctx = _complete_ctx()
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is True, (
        "control case: a fully-read, empty config should set not_applicable=True -- "
        "if this fails the (a)/(b)/(c) cases below aren't testing a real degradation"
    )


@_CHECKS
def test_domain_tagged_limit_hit_keeps_flag_false(check_fn):
    ctx = _complete_ctx()
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


@_CHECKS
def test_config_parse_error_keeps_flag_false(check_fn):
    ctx = Context(home=Path("/nonexistent"), config_found=True, config_parse_error=True)
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


@_CHECKS
def test_config_not_found_keeps_flag_false(check_fn):
    ctx = Context(home=Path("/nonexistent"), config_found=False, config_parse_error=False)
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False
