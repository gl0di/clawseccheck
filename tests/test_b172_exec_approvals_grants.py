"""B172 (B-236, re-scoped): inventory of standing exec-approvals.json "allow-always"
grants.

Grounded: ~/.openclaw/exec-approvals.json is OpenClaw's persisted per-agent
exec-approval store (confirmed against exec-approvals-BIKWP8_V.js in the installed
dist -- DEFAULT_EXEC_APPROVALS_STATE_DIR="~/.openclaw", EXEC_APPROVALS_FILE=
"exec-approvals.json"). No check previously read it (grep for "exec-approvals" across
clawseccheck/ was zero hits). collector._collect_exec_approvals now reads it read-only,
symlink-safe, and size/entry-capped, mirroring the B168 cron-store precedent.

B-236 was originally filed on the premise that a standing "allow-always" grant
SILENTLY OVERRIDES the openclaw.json tools.exec gate, making B8/B22/B23/B48 lying-PASS.
That premise was adversarially REFUTED during the task's own review: OpenClaw computes
the effective exec policy as minSecurity(tools.exec.security, execApprovals.security) +
maxAsk(tools.exec.ask, execApprovals.ask) (bash-tools*.js:581-582;
exec-approvals-BIKWP8_V.js:1126-1140) -- a standing grant can only TIGHTEN the gate,
never loosen it. So B172 is a pure visibility/inventory advisory (WARN-only, never
FAIL, unscored) -- it must never contradict B8/B22/B23/B48's PASS, and a bare
security="full"/ask="off" policy with NO actual allow-always allowlist entry must not
trigger it either (that would resurrect the refuted "override" framing under a
different name).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_exec_approvals_grants
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixtures on disk
# ---------------------------------------------------------------------------

def test_bad_fixture_warns():
    r = check_exec_approvals_grants(collect(FIXTURES / "bad_b172_exec_approvals_allow_always"))
    assert r.status == WARN
    assert any("main" in e and "allow-always" in e for e in r.evidence)


def test_clean_fixture_passes():
    """Matches the real machine's shape: defaults={} and agents={} (no grant ever
    persisted) -- must stay a clean PASS, never a spurious WARN."""
    r = check_exec_approvals_grants(collect(FIXTURES / "clean_b172_exec_approvals_empty"))
    assert r.status == PASS


def test_absent_store_is_unknown():
    r = check_exec_approvals_grants(collect(FIXTURES / "unknown_b172_exec_approvals_absent"))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# Check metadata / never-FAIL contract
# ---------------------------------------------------------------------------

def test_check_id_is_b172():
    r = check_exec_approvals_grants(collect(FIXTURES / "bad_b172_exec_approvals_allow_always"))
    assert r.id == "B172"


def test_check_is_unscored_advisory():
    """B172 never moves the A-F grade -- it is a visibility advisory, not a
    correctness verdict on any other check."""
    assert BY_ID["B172"].scored is False


@pytest.mark.parametrize("fixture_name", [
    "bad_b172_exec_approvals_allow_always",
    "clean_b172_exec_approvals_empty",
    "unknown_b172_exec_approvals_absent",
])
def test_never_fails(fixture_name):
    r = check_exec_approvals_grants(collect(FIXTURES / fixture_name))
    assert r.status != FAIL


# ---------------------------------------------------------------------------
# Dynamic (tmp_path) coverage: malformed store, symlinked store, and the two
# C-135 anti-false-positive shapes.
# ---------------------------------------------------------------------------

def _home_with_config(tmp_path) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "openclaw.json").write_text("{}")
    return home


def test_malformed_store_is_unknown(tmp_path):
    home = _home_with_config(tmp_path)
    (home / "exec-approvals.json").write_text("{not valid json")
    r = check_exec_approvals_grants(collect(home))
    assert r.status == UNKNOWN


def test_non_object_store_root_is_unknown(tmp_path):
    home = _home_with_config(tmp_path)
    (home / "exec-approvals.json").write_text(json.dumps(["not", "an", "object"]))
    r = check_exec_approvals_grants(collect(home))
    assert r.status == UNKNOWN


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
def test_symlinked_store_is_treated_as_absent(tmp_path):
    home = _home_with_config(tmp_path)
    real = tmp_path / "elsewhere-exec-approvals.json"
    real.write_text(json.dumps({
        "version": 1, "defaults": {},
        "agents": {"main": {"security": "full", "ask": "off",
                             "allowlist": [{"pattern": "*", "source": "allow-always"}]}},
    }))
    (home / "exec-approvals.json").symlink_to(real)
    r = check_exec_approvals_grants(collect(home))
    # The symlink is never followed -- treated the same as "no store found", never a
    # false PASS/WARN derived from a target outside the audited home.
    assert r.status == UNKNOWN


def test_manual_allowlist_entry_without_allow_always_source_does_not_warn(tmp_path):
    """C-135: `openclaw approvals allowlist add` writes an entry with NO `source` key
    at all (see registerAllowlistMutationCommand's `mutate` in
    exec-approvals-cli-CGVXnUMS.js -- it pushes {pattern, lastUsedAt}, never `source`).
    Only a `source: "allow-always"` entry (written by the exec-confirmation "always
    allow" click) is the uninventoried standing-grant surface this check targets, so a
    manually-curated allowlist entry must not trigger a WARN."""
    home = _home_with_config(tmp_path)
    (home / "exec-approvals.json").write_text(json.dumps({
        "version": 1,
        "defaults": {},
        "agents": {
            "main": {
                "allowlist": [
                    {"pattern": "/usr/bin/uptime", "lastUsedAt": 1700000000000},
                ],
            },
        },
    }))
    r = check_exec_approvals_grants(collect(home))
    assert r.status == PASS


def test_bare_security_policy_without_allow_always_does_not_warn(tmp_path):
    """C-135 (the refuted-override angle, re-tested directly): an agent-level
    security="full"/ask="off" policy with NO allow-always allowlist entry must not
    WARN. Per the adversarial correction, this alone does not defeat the
    openclaw.json gate (OpenClaw takes the stricter of the two) and is not itself the
    uninventoried surface -- only a persisted allow-always PATTERN is."""
    home = _home_with_config(tmp_path)
    (home / "exec-approvals.json").write_text(json.dumps({
        "version": 1,
        "defaults": {},
        "agents": {
            "main": {"security": "full", "ask": "off"},
        },
    }))
    r = check_exec_approvals_grants(collect(home))
    assert r.status == PASS


def test_multiple_agents_evidence_names_each():
    r = check_exec_approvals_grants(collect(FIXTURES / "bad_b172_exec_approvals_allow_always"))
    assert r.status == WARN
    # Two allow-always patterns for the same agent -> a single evidence line naming
    # both the agent and the count, not one line per pattern.
    assert any("2 allow-always pattern" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# Collector-level shape check
# ---------------------------------------------------------------------------

def test_collector_populates_grants_shape():
    ctx = collect(FIXTURES / "bad_b172_exec_approvals_allow_always")
    assert ctx.exec_approvals_found is True
    assert ctx.exec_approvals_parse_error is False
    assert len(ctx.exec_approvals_grants) == 1
    grant = ctx.exec_approvals_grants[0]
    assert grant["agent_id"] == "main"
    assert grant["security"] == "full"
    assert grant["ask"] == "off"
    assert grant["allow_always_count"] == 2


def test_collector_absent_store_leaves_found_false():
    ctx = collect(FIXTURES / "unknown_b172_exec_approvals_absent")
    assert ctx.exec_approvals_found is False
    assert ctx.exec_approvals_grants == []
