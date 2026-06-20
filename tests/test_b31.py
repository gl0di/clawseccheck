"""B31 — Effective-tools bypass (illusory deny) tests.

Grounded on docs.openclaw.ai (config-tools, exec, apply-patch pages).

Philosophy: WARN when a deny list blocks 'write'/'edit' but leaves
apply_patch/exec/process un-denied (and no 'group:fs'); PASS when every
deny list is safe; UNKNOWN when no deny lists exist at all.

B31 never produces FAIL — WARN/PASS/UNKNOWN only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_effective_tools
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# WARN — global tools.deny blocks write/edit but not apply_patch/exec/process
# ---------------------------------------------------------------------------

def test_b31_global_deny_write_only_warns():
    """tools.deny blocks 'write' but apply_patch/exec/process are still open."""
    cfg = {"tools": {"deny": ["write"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN


def test_b31_global_deny_edit_only_warns():
    """tools.deny blocks 'edit' but apply_patch/exec/process are still open."""
    cfg = {"tools": {"deny": ["edit"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN


def test_b31_global_deny_write_and_edit_still_warns_when_apply_patch_missing():
    """Blocking both write and edit is still bypassable via apply_patch/exec/process."""
    cfg = {"tools": {"deny": ["write", "edit"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN


def test_b31_warn_detail_mentions_bypass_tools():
    """The WARN detail names the tools that remain un-denied."""
    cfg = {"tools": {"deny": ["write"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN
    # At least one of the bypass tools must be named in the detail
    assert any(t in f.detail for t in ("apply_patch", "exec", "process"))


def test_b31_warn_evidence_populated():
    """Evidence list must be non-empty and name the bypassable scope."""
    cfg = {"tools": {"deny": ["write"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN
    assert len(f.evidence) >= 1
    assert any("tools.deny" in e for e in f.evidence)


def test_b31_warn_fix_mentions_group_fs_or_full_list():
    """The fix text must guide the user to 'group:fs' or the full mutating set."""
    cfg = {"tools": {"deny": ["write"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN
    assert "group:fs" in f.fix or "apply_patch" in f.fix


# ---------------------------------------------------------------------------
# WARN — via toolsBySender (global per-sender deny)
# ---------------------------------------------------------------------------

def test_b31_tools_by_sender_wildcard_deny_write_edit_warns():
    """toolsBySender['*'].deny blocks write+edit but apply_patch/exec slip through."""
    cfg = {"toolsBySender": {"*": {"deny": ["write", "edit"]}}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN


def test_b31_tools_by_sender_named_key_warns():
    """A named sender key with a partial deny triggers WARN."""
    cfg = {"toolsBySender": {"channel:slack:U123": {"deny": ["edit"]}}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN


def test_b31_tools_by_sender_evidence_mentions_key():
    """Evidence must reference the specific toolsBySender key that is bypassable."""
    cfg = {"toolsBySender": {"*": {"deny": ["write", "edit"]}}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN
    assert any("toolsBySender" in e for e in f.evidence)


# ---------------------------------------------------------------------------
# WARN — via per-agent toolsBySender deny
# ---------------------------------------------------------------------------

def test_b31_per_agent_tools_by_sender_deny_edit_warns():
    """agents.list[0].tools.toolsBySender['*'].deny blocks edit but not apply_patch."""
    cfg = {"agents": {"list": [
        {"tools": {"toolsBySender": {"*": {"deny": ["edit"]}}}}
    ]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN


def test_b31_per_agent_evidence_references_agent_scope():
    """Evidence must reference the per-agent scope path."""
    cfg = {"agents": {"list": [
        {"tools": {"toolsBySender": {"*": {"deny": ["write"]}}}}
    ]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN
    assert any("agents.list[0]" in e for e in f.evidence)


def test_b31_per_agent_multiple_agents_any_bypassable_warns():
    """If any per-agent deny list is bypassable, result is WARN."""
    cfg = {"agents": {"list": [
        {"tools": {"toolsBySender": {"*": {"deny": ["write", "edit",
                                                     "apply_patch", "exec", "process"]}}}},
        {"tools": {"toolsBySender": {"*": {"deny": ["write"]}}}},  # bypassable
    ]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == WARN


# ---------------------------------------------------------------------------
# PASS — group:fs blocks all file mutation
# ---------------------------------------------------------------------------

def test_b31_global_deny_group_fs_passes():
    """'group:fs' in tools.deny covers all fs mutation — PASS."""
    cfg = {"tools": {"deny": ["group:fs"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == PASS


def test_b31_global_deny_group_fs_with_extras_passes():
    """'group:fs' alongside other tokens is still PASS."""
    cfg = {"tools": {"deny": ["group:fs", "exec", "write"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == PASS


def test_b31_tools_by_sender_group_fs_passes():
    """group:fs in a toolsBySender deny is safe."""
    cfg = {"toolsBySender": {"*": {"deny": ["group:fs"]}}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# PASS — full mutating set explicitly listed
# ---------------------------------------------------------------------------

def test_b31_full_mutating_set_in_global_deny_passes():
    """Denying write+edit+apply_patch+exec+process leaves no bypass."""
    cfg = {"tools": {"deny": ["write", "edit", "apply_patch", "exec", "process"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == PASS


def test_b31_full_set_plus_extra_tools_passes():
    """Extra entries in a complete deny list do not break PASS."""
    cfg = {"tools": {"deny": [
        "write", "edit", "apply_patch", "exec", "process", "read", "list_dir"
    ]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == PASS


def test_b31_tools_by_sender_full_set_passes():
    """toolsBySender deny with full mutating set is PASS."""
    cfg = {"toolsBySender": {"*": {
        "deny": ["write", "edit", "apply_patch", "exec", "process"]
    }}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# PASS — deny list exists but does NOT contain write/edit (no bypass trigger)
# ---------------------------------------------------------------------------

def test_b31_deny_only_apply_patch_no_write_class_passes():
    """A deny list that blocks apply_patch (but not write/edit) is not a bypass pattern."""
    cfg = {"tools": {"deny": ["apply_patch", "exec"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == PASS


def test_b31_deny_unrelated_tools_passes():
    """Denying only non-mutating tools is not a bypass — PASS."""
    cfg = {"tools": {"deny": ["read", "list_dir", "search"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# UNKNOWN — no deny lists anywhere
# ---------------------------------------------------------------------------

def test_b31_empty_config_unknown():
    """Empty config has no deny lists — UNKNOWN."""
    f = check_effective_tools(_ctx({}))
    assert f.status == UNKNOWN


def test_b31_only_allow_lists_no_deny_unknown():
    """Config with only allow lists (no deny) yields UNKNOWN."""
    cfg = {
        "tools": {"allow": ["read", "write", "exec"]},
        "toolsBySender": {"*": {"allow": ["read"]}},
    }
    f = check_effective_tools(_ctx(cfg))
    assert f.status == UNKNOWN


def test_b31_empty_deny_lists_treated_as_no_deny_unknown():
    """Empty deny arrays (no effective entries) count as no deny list — UNKNOWN."""
    cfg = {"tools": {"deny": []}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == UNKNOWN


def test_b31_tools_section_missing_deny_key_unknown():
    """tools section without a 'deny' key has no deny list — UNKNOWN."""
    cfg = {"tools": {"exec": {"mode": "ask"}}}
    f = check_effective_tools(_ctx(cfg))
    assert f.status == UNKNOWN


# ---------------------------------------------------------------------------
# B31 must never produce FAIL
# ---------------------------------------------------------------------------

def test_b31_never_fails_worst_case():
    """Even the worst bypassable config cannot produce FAIL."""
    cfg = {
        "tools": {"deny": ["write"]},
        "toolsBySender": {"*": {"deny": ["edit"]}},
        "agents": {"list": [
            {"tools": {"toolsBySender": {"*": {"deny": ["write", "edit"]}}}}
        ]},
    }
    f = check_effective_tools(_ctx(cfg))
    assert f.status != "FAIL"


# ---------------------------------------------------------------------------
# Finding metadata
# ---------------------------------------------------------------------------

def test_b31_finding_id_is_b31():
    cfg = {"tools": {"deny": ["write"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.id == "B31"


def test_b31_finding_severity_is_medium():
    cfg = {"tools": {"deny": ["write"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.severity == "MEDIUM"


def test_b31_finding_is_scored():
    cfg = {"tools": {"deny": ["write"]}}
    f = check_effective_tools(_ctx(cfg))
    assert f.scored is True
