"""B48 / B-231: wildcard-authority overrides.

commands.ownerAllowFrom containing a literal "*" gets a severity ABOVE the plain
scoped-list FAIL/WARN case B48 already covers (FAIL/CRITICAL). Grounded against the
OpenClaw dist RUNTIME, not just the schema doc string: command-auth-*.js
resolveOwnerAuthorizationState() sets ownerAllowAll = hasWildcardAllowFrom(
configOwnerAllowFromList); isWildcardAllowFromEntry is a literal `entry.trim() === "*"`
check — a bare "*" flips owner authority open to ANY sender. (The schema doc string
"'*' is ignored" describes a narrower filter that drops "*" from the *explicit owner ID
candidate* list built from the same array — not the ownerAllowAll authorization gate
itself.)

gateway.nodes.pairing.autoApproveCidrs containing a world-open CIDR (0.0.0.0/0, ::/0, or
"*") stays a plain WARN, NOT escalated to FAIL: although message-handler-*.js feeds the
raw CIDR list straight into isTrustedProxyAddress() (a literal 0.0.0.0/0 genuinely
matches every source IP for first-time, zero-scope node pairing), the internal schema
recon (NC-11) records that OpenClaw's own docs name "reports treating configured
gateway.nodes.pairing.autoApproveCidrs as vulnerability by itself" on their "not a
vulnerability by design" list, with an explicit "do NOT FAIL on ... pairing.
autoApproveCidrs" verdict. Escalating this field to FAIL/CRITICAL would contradict that
grounded guidance, so it is surfaced as a WARN only.

gateway.nodes.allowCommands is deliberately NOT given the same escalation: grounded
against node-command-policy-*.js, a literal "*" there is folded into a plain Set of exact
command-name strings (`allow.has(command)`) with no wildcard special-case — inert, not a
broader grant than a scoped list.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, PASS, WARN
from clawseccheck.checks import check_dangerous_overrides
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# commands.ownerAllowFrom
# ---------------------------------------------------------------------------

def test_owner_allow_from_wildcard_fails_critical():
    r = check_dangerous_overrides(_ctx({"commands": {"ownerAllowFrom": ["*"]}}))
    assert r.status == FAIL
    assert r.severity == CRITICAL
    assert any("commands.ownerAllowFrom" in e for e in r.evidence)


def test_owner_allow_from_scoped_id_passes():
    r = check_dangerous_overrides(_ctx({"commands": {"ownerAllowFrom": ["telegram:307615315"]}}))
    assert r.status == PASS


def test_owner_allow_from_scoped_at_handle_passes():
    """A single scoped owner handle (@dave) must never be treated as a wildcard."""
    r = check_dangerous_overrides(_ctx({"commands": {"ownerAllowFrom": ["@dave"]}}))
    assert r.status == PASS


def test_owner_allow_from_absent_passes():
    r = check_dangerous_overrides(_ctx({"commands": {}}))
    assert r.status == PASS


def test_owner_allow_from_wildcard_amongst_scoped_still_fails():
    # A mixed list containing "*" anywhere still trips the wildcard gate (matches the
    # dist's hasWildcardAllowFrom -- any() semantics, not exact-match-only).
    r = check_dangerous_overrides(
        _ctx({"commands": {"ownerAllowFrom": ["telegram:1", "*"]}}))
    assert r.status == FAIL
    assert r.severity == CRITICAL


def test_owner_allow_from_star_substring_not_flagged():
    # "*" must be an exact (trimmed) entry, not a substring -- a real ID never contains
    # a bare asterisk, but this guards the trim()==\"*\" semantics precisely.
    r = check_dangerous_overrides(_ctx({"commands": {"ownerAllowFrom": ["chat*bot"]}}))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# gateway.nodes.pairing.autoApproveCidrs — WARN only, never FAIL (NC-11: OpenClaw's own
# "not a vulnerability by design" list names this exact field).
# ---------------------------------------------------------------------------

def test_auto_approve_cidrs_world_open_ipv4_warns_not_fails():
    cfg = {"gateway": {"nodes": {"pairing": {"autoApproveCidrs": ["0.0.0.0/0"]}}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == WARN
    assert r.severity != CRITICAL
    assert any("autoApproveCidrs" in e for e in r.evidence)


def test_auto_approve_cidrs_world_open_ipv6_warns_not_fails():
    cfg = {"gateway": {"nodes": {"pairing": {"autoApproveCidrs": ["::/0"]}}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == WARN
    assert r.severity != CRITICAL


def test_auto_approve_cidrs_scoped_private_range_passes():
    cfg = {"gateway": {"nodes": {"pairing": {"autoApproveCidrs": ["10.0.0.0/24"]}}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == PASS


def test_auto_approve_cidrs_single_host_passes():
    cfg = {"gateway": {"nodes": {"pairing": {"autoApproveCidrs": ["192.168.1.42/32"]}}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == PASS


def test_auto_approve_cidrs_absent_passes():
    r = check_dangerous_overrides(_ctx({"gateway": {"nodes": {"pairing": {}}}}))
    assert r.status == PASS


def test_auto_approve_cidrs_empty_list_passes():
    cfg = {"gateway": {"nodes": {"pairing": {"autoApproveCidrs": []}}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# gateway.nodes.allowCommands wildcard is DELIBERATELY inert (not escalated) — a
# literal "*" there does not match any real node command name (grounded: plain Set
# membership, `allow.has(command)`, no wildcard special-case).
# ---------------------------------------------------------------------------

def test_allow_commands_wildcard_stays_plain_warn_not_escalated():
    cfg = {"gateway": {"nodes": {"allowCommands": ["*"]}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == WARN
    assert r.severity != CRITICAL


def test_allow_commands_scoped_list_still_warns():
    cfg = {"gateway": {"nodes": {"allowCommands": ["file.fetch"]}}}
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# Priority: wildcard-authority FAIL/CRITICAL outranks the plain sandbox-escape FAIL
# ---------------------------------------------------------------------------

def test_wildcard_priority_over_plain_fail():
    cfg = {
        "commands": {"ownerAllowFrom": ["*"]},
        "agents": {"defaults": {"sandbox": {"docker": {
            "dangerouslyAllowContainerNamespaceJoin": True}}}},
    }
    r = check_dangerous_overrides(_ctx(cfg))
    assert r.status == FAIL
    assert r.severity == CRITICAL
    joined = " ".join(r.evidence)
    assert "ownerAllowFrom" in joined and "ContainerNamespaceJoin" in joined


# ---------------------------------------------------------------------------
# Fixtures on disk
# ---------------------------------------------------------------------------

def test_bad_fixture_wildcard_authority_fails_critical():
    r = check_dangerous_overrides(collect(FIXTURES / "bad_b48_wildcard_authority"))
    assert r.status == FAIL
    assert r.severity == CRITICAL
    joined = " ".join(r.evidence)
    assert "ownerAllowFrom" in joined and "autoApproveCidrs" in joined


def test_clean_fixture_wildcard_authority_passes():
    r = check_dangerous_overrides(collect(FIXTURES / "clean_b48_wildcard_authority"))
    assert r.status == PASS
