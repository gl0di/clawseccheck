"""B378 — agents.defaults.cwd / agents.entries.<id>.cwd relocation.

Verdicts (check_agent_cwd_relocation, checks/_capability.py):
  UNKNOWN : config unreadable, OR no cwd declared anywhere (not_applicable=True)
  PASS    : every configured cwd is textually equal (after ~-expansion) to that same
            scope's own EXPLICITLY declared workspace — a proven no-op
  WARN    : at least one scope configures cwd with no proof it matches its workspace
  (no FAIL — the check cannot prove relocation against OpenClaw's full implicit
  workspace-derivation chain, only against an explicitly declared workspace)

Grounded against the installed 2026.9.4 dist: AgentDefaultsSchema / AgentEntryBaseSchema
both carry `cwd: string().optional()` as a plain sibling of `workspace`
(zod-schema-*.mjs), resolved by resolveAgentRunCwd = entry.cwd ?? agents.defaults.cwd
(agent-scope-config-*.mjs), and resolveAttemptWorkspaceSandbox
(workspace-sandbox-*.mjs) throws when a sandboxed run's cwd differs from its resolved
workspace.
"""
import json
import os
import tempfile
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict, home: str = "/home/testuser") -> Context:
    c = Context(home=Path(home))
    c.config = cfg
    c.config_found = True
    return c


def _finding_direct(cfg: dict, home: str = "/home/testuser"):
    return C.check_agent_cwd_relocation(_ctx(cfg, home))


def _finding_via_home(cfg: dict):
    """Round-trip through collect()/run_all(), matching how the real audit invokes it."""
    home = Path(tempfile.mkdtemp(prefix="b378-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    return next(f for f in C.run_all(ctx) if f.id == "B378")


# ---- catalog sanity ----

def test_b378_is_catalogued_hardening_scored():
    meta = BY_ID["B378"]
    assert meta.block == "hardening"
    assert meta.scored is True
    assert meta.surface == "agents"


# ---- UNKNOWN / not_applicable: nothing configured ----

def test_empty_config_not_applicable():
    f = _finding_direct({})
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_agents_defaults_present_but_no_cwd_not_applicable():
    f = _finding_direct({"agents": {"defaults": {"workspace": "/home/testuser/ws"}}})
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_roster_declared_but_no_agent_configures_cwd_not_applicable():
    cfg = {"agents": {"entries": {"web": {"workspace": "/home/testuser/ws-web"}}}}
    f = _finding_direct(cfg)
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# ---- PASS: proven no-op (cwd == that scope's own declared workspace) ----

def test_default_cwd_equals_default_workspace_passes():
    cfg = {"agents": {"defaults": {
        "cwd": "/home/testuser/ws", "workspace": "/home/testuser/ws",
    }}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_tilde_expansion_treated_as_equal():
    cfg = {"agents": {"defaults": {"cwd": "~/ws", "workspace": "~/ws"}}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_roster_entry_own_cwd_equals_own_workspace_passes():
    cfg = {"agents": {"entries": {"web": {
        "workspace": "/home/testuser/ws-web", "cwd": "/home/testuser/ws-web",
    }}}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_roster_entry_with_no_own_workspace_proves_against_default_workspace():
    # A roster entry declaring neither cwd nor workspace of its own still inherits
    # BOTH from agents.defaults — and when those two agree, that is a real no-op,
    # not merely an unproven one. This is the common "converted an implicit default
    # agent into an explicit (near-empty) roster entry" shape.
    cfg = {
        "agents": {
            "defaults": {"cwd": "/home/testuser/ws", "workspace": "/home/testuser/ws"},
            "entries": {"main": {}},
        }
    }
    f = _finding_direct(cfg)
    assert f.status == PASS


# ---- WARN: relocation, or no proof of equality ----

def test_default_cwd_with_no_workspace_at_all_warns():
    cfg = {"agents": {"defaults": {"cwd": "/opt/other"}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "agents.defaults.cwd" in " ".join(f.evidence)
    assert "no explicit workspace declared" in " ".join(f.evidence)


def test_roster_entry_own_cwd_differs_from_own_workspace_warns():
    cfg = {"agents": {"entries": {"web": {
        "workspace": "/home/testuser/ws-web", "cwd": "/srv/checkout/repo",
    }}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    joined = " ".join(f.evidence)
    assert "agents.entries.web.cwd" in joined
    assert "/srv/checkout/repo" in joined
    assert "/home/testuser/ws-web" in joined


def test_roster_entry_inherits_default_cwd_and_warns():
    cfg = {
        "agents": {
            "defaults": {"cwd": "/opt/shared"},
            "entries": {"web": {"workspace": "/home/testuser/ws-web"}},
        }
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "agents.entries.web.cwd" in " ".join(f.evidence)


def test_roster_entry_inherits_both_cwd_and_workspace_but_they_disagree_warns():
    # The default_workspace fallback must not over-suppress: when the entry has no
    # workspace of its own AND agents.defaults.cwd/workspace genuinely disagree, this
    # is a real relocation and must still WARN.
    cfg = {
        "agents": {
            "defaults": {"cwd": "/opt/shared", "workspace": "/home/testuser/ws"},
            "entries": {"web": {}},
        }
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "agents.entries.web.cwd" in " ".join(f.evidence)


def test_legacy_agents_list_shape_warns():
    cfg = {"agents": {"list": [
        {"id": "main", "workspace": "/w", "cwd": "/other"},
    ]}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "agents.list[main].cwd" in " ".join(f.evidence)


def test_warn_detail_mentions_sandbox_implication():
    cfg = {"agents": {"defaults": {"cwd": "/opt/other"}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "sandbox" in f.detail.lower() or "unsandboxed" in f.detail.lower()


# ---- correctness guard: dead default cwd must not be flagged when every declared
#      agent overrides it with its own (provably equal) cwd ----

def test_default_cwd_never_inherited_by_any_agent_is_not_flagged():
    cfg = {
        "agents": {
            "defaults": {"cwd": "/somewhere/dead"},
            "entries": {"web": {"workspace": "/w", "cwd": "/w"}},
        }
    }
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert "agents.defaults.cwd" not in " ".join(f.evidence)


# ---- config-unreadable engine-side UNKNOWN ----

def test_unparseable_config_is_engine_degraded_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    f = C.check_agent_cwd_relocation(c)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


# ---- never FAIL ----

def test_never_fail():
    for cfg in (
        {},
        {"agents": {"defaults": {"cwd": "/opt/other"}}},
        {"agents": {"entries": {"web": {"workspace": "/w", "cwd": "/elsewhere"}}}},
        {"agents": {"list": [{"id": "main", "cwd": "/x"}]}},
    ):
        assert _finding_direct(cfg).status != FAIL, f"B378 must never return FAIL; got FAIL for {cfg}"


# ---- fixtures, round-tripped through the real audit pipeline ----

def test_the_bad_fixture_fires_and_the_clean_one_does_not():
    for name, expected in (
        ("bad_b378_cwd_relocated", WARN),
        ("clean_b378_cwd_matches_workspace", PASS),
    ):
        ctx = collect(FIXTURES / name)
        f = next(fi for fi in C.run_all(ctx) if fi.id == "B378")
        assert f.status == expected, name


def test_full_pipeline_round_trip_matches_direct_call():
    cfg = {"agents": {"defaults": {"cwd": "/opt/other"}}}
    assert _finding_via_home(cfg).status == _finding_direct(cfg).status == WARN
