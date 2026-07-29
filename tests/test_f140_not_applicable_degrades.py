"""F-140 degradation matrix — the second wave of ``Finding.not_applicable`` migrations
must fall back to ordinary ``not_applicable=False`` UNKNOWN (never a claim of proven
surface absence) whenever the locus read was NOT provably complete.

Same three config-locus degradations F-139 pinned for the MCP cluster, applied to the
newly-migrated sites (ten checks, eleven call sites -- B194 has two):

(a) a domain-tagged LimitHit for LIMIT_DOMAIN_CONFIG (the scan hit a cap while reading
    the config itself);
(b) ``config_parse_error=True`` (openclaw.json present but unparseable);
(c) ``config_found=False`` (no openclaw.json at all -- absence of evidence is not
    evidence of absence, and this is the case that would otherwise mark ~25 checks
    "not applicable" on a plain non-OpenClaw machine).

In all three cases status stays UNKNOWN -- ``not_applicable`` is orthogonal to status,
so a degradation must be visible in the flag alone, never as a status change.

B18 additionally carries a DISK locus (B-296's ``subagent_runs`` disclosure), so it gets
its own section: config-locus completeness alone must not be enough for it.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import (
    check_control_plane_mutation,
    check_multiagent_exposure,
    check_outbound_proxy,
    check_path_safety,
    check_plugin_app_server_command,
    check_plugin_permission_mode,
    check_secrets_provider_exec,
    check_sender_identity,
    check_session_visibility,
    check_subagents,
)
from clawseccheck.collector import (
    LIMIT_DOMAIN_AGENTS,
    LIMIT_DOMAIN_CONFIG,
    Context,
    note_limit,
)

# The nine config-locus checks migrated by F-140. C5 is deliberately absent: its locus
# is the host PLATFORM, not openclaw.json, so none of the three config degradations
# below can move its flag -- it gets its own discrimination test in
# tests/test_f140_not_applicable_adversarial.py instead.
_CONFIG_LOCUS_CHECKS = pytest.mark.parametrize(
    "check_fn",
    [
        check_multiagent_exposure,
        check_sender_identity,
        check_session_visibility,
        check_subagents,
        check_control_plane_mutation,
        check_plugin_permission_mode,
        check_plugin_app_server_command,
        check_secrets_provider_exec,
        check_outbound_proxy,
    ],
    ids=["B46", "B30", "B39", "B18", "B32", "B57", "B167", "B194", "B155"],
)


def _complete_ctx() -> Context:
    """A config read that WOULD otherwise prove absence -- the control case."""
    return Context(home=Path("/nonexistent"), config_found=True, config_parse_error=False)


@_CONFIG_LOCUS_CHECKS
def test_control_complete_read_sets_not_applicable(check_fn):
    """Anti-vacuity control: without this, the three degradation tests below could all
    pass simply because the flag is never set to True by anything."""
    f = check_fn(_complete_ctx())
    assert f.status == UNKNOWN
    assert f.not_applicable is True, (
        "control case: a fully-read, empty config should set not_applicable=True -- "
        "if this fails the (a)/(b)/(c) cases below aren't testing a real degradation"
    )


@_CONFIG_LOCUS_CHECKS
def test_domain_tagged_limit_hit_keeps_flag_false(check_fn):
    ctx = _complete_ctx()
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_CONFIG, "hit the config scan cap")
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


@_CONFIG_LOCUS_CHECKS
def test_untagged_limit_hit_keeps_flag_false(check_fn):
    """``limit_hits_for`` includes UNTAGGED entries deliberately (Golden Rule #4): a
    bare string carries no evidence about which scan it truncated, so it must not be
    resolved into a convenient "your config was complete"."""
    ctx = _complete_ctx()
    ctx.limit_hits.append("some untagged truncation")
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


@_CONFIG_LOCUS_CHECKS
def test_config_parse_error_keeps_flag_false(check_fn):
    ctx = Context(home=Path("/nonexistent"), config_found=True, config_parse_error=True)
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


@_CONFIG_LOCUS_CHECKS
def test_config_not_found_keeps_flag_false(check_fn):
    ctx = Context(home=Path("/nonexistent"), config_found=False, config_parse_error=False)
    f = check_fn(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


# ---------------------------------------------------------------------------
# B18's second locus: the subagent_runs disk registry (B-296).
#
# B18 is the only F-140 site with a disk corroborator, so "no subagent delegation" is a
# claim about ctx.config AND about the state DB. Config-locus completeness alone must
# not be enough.
# ---------------------------------------------------------------------------

def test_b18_agents_domain_limit_hit_keeps_flag_false():
    """LIMIT_DOMAIN_AGENTS is the domain collector.py reserves for exactly this
    disclosure; a truncated registry read means spawns may exist that we never saw."""
    ctx = _complete_ctx()
    note_limit(ctx.limit_hits, LIMIT_DOMAIN_AGENTS, "subagent_runs row cap")
    f = check_subagents(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_b18_subagent_runs_parse_error_keeps_flag_false():
    """The registry EXISTS but not one row could be parsed -- the precise case where
    delegation may have happened and we cannot see it."""
    ctx = _complete_ctx()
    ctx.subagent_runs_found = True
    ctx.subagent_runs_parse_error = True
    f = check_subagents(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is False


def test_b18_subagent_runs_absent_still_sets_flag():
    """Deliberate asymmetry, pinned so a later "tighten it" refactor has to argue with
    this test rather than silently flip it: ``subagent_runs_found=False`` means the state
    DB or the table is absent, which is the ORDINARY shape on a host that has never run a
    subagent. Treating it as unknown would make the flag unreachable on exactly the clean
    single-agent configs it exists to describe. What must never be swallowed is a
    registry that exists and could not be read (the test above)."""
    ctx = _complete_ctx()
    ctx.subagent_runs_found = False
    ctx.subagent_runs_parse_error = False
    f = check_subagents(ctx)
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b18_config_locus_still_required_alongside_the_disk_locus():
    """Both loci, not either: a clean registry does not rescue an unread config."""
    ctx = Context(home=Path("/nonexistent"), config_found=False, config_parse_error=False)
    ctx.subagent_runs_found = False
    assert check_subagents(ctx).not_applicable is False


# ---------------------------------------------------------------------------
# P3 — every migrated check must JUSTIFY its flag in its own docstring.
#
# The flag is a positive security claim ("this surface does not exist on your host"),
# and the reasoning for why absence is provable at that branch is exactly the thing a
# reviewer needs and a diff hides. This guard is mechanical so the justification cannot
# quietly rot away from the code it explains.
# ---------------------------------------------------------------------------

_MIGRATED = {
    "B46": check_multiagent_exposure,
    "B30": check_sender_identity,
    "B39": check_session_visibility,
    "B18": check_subagents,
    "B32": check_control_plane_mutation,
    "B57": check_plugin_permission_mode,
    "B167": check_plugin_app_server_command,
    "B194": check_secrets_provider_exec,
    "B155": check_outbound_proxy,
    # C5 is here (unlike the degradation matrix above) because the docstring obligation
    # is universal: its justification is the one that most needs writing down, since it
    # is the only site whose locus is NOT the config.
    "C5": check_path_safety,
}


@pytest.mark.parametrize("cid", sorted(_MIGRATED))
def test_migrated_check_docstring_justifies_the_flag(cid):
    doc = _MIGRATED[cid].__doc__ or ""
    assert "F-140" in doc, (
        f"{cid}: the not_applicable migration must be marked in the check's own "
        "docstring so a reader knows the UNKNOWN branch carries a positive "
        "surface-absence claim"
    )
    assert "not_applicable" in doc or "not-applicable" in doc, (
        f"{cid}: docstring must name the flag it now sets"
    )
    assert "COMPLETELY" in doc or "complete" in doc.lower(), (
        f"{cid}: docstring must state the completeness precondition -- the flag is only "
        "ever a claim that the locus was read completely, never that the check applies"
    )
