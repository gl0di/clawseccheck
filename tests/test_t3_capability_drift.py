"""T3 (F-123) — runtime capability drift: a HIGH-BLAST verb PROVEN in the trajectory log
that is NOT in the declared (tools.allow / gateway.tools.allow) ∪ attested grant.

Complements B84 (proven-high-blast + UNGATED posture); T3 fires on proven-high-blast +
UNDECLARED, gated or not. WARN-only, scored=False, --behavioral only — never part of
audit()/CHECKS/A-F. The high-blast gate is load-bearing: built-ins and MCP tools are
auto-available beyond tools.allow, so reversible / unknown verbs never reach the alert.

Offline, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.behavioral import (
    _t3_declared,
    analyze,
    check_capability_drift,
)
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.collector import Context

_TRACE_SCHEMA = "openclaw-trajectory"
_SCHEMA_VERSION = 1


def _write_traj(home: Path, verbs, *, schema_version: int = _SCHEMA_VERSION) -> None:
    """Write a minimal tool.call trajectory sidecar with the given proven verb names."""
    d = home / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    lines = []
    for seq, name in enumerate(verbs, start=1):
        rec = {
            "traceSchema": _TRACE_SCHEMA,
            "schemaVersion": schema_version,
            "type": "tool.call",
            "ts": str(seq),
            "seq": seq,
            "sessionId": "s1",
            "data": {"name": name, "threadId": "th1"},
        }
        lines.append(json.dumps(rec))
    (d / "s1.trajectory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _ctx(home: Path, *, allow=None, also_allow=None, profile=None, gateway_allow=None,
         attested=None) -> Context:
    ctx = Context(home=home)
    cfg: dict = {}
    if allow is not None:
        cfg.setdefault("tools", {})["allow"] = allow
    if also_allow is not None:
        cfg.setdefault("tools", {})["alsoAllow"] = also_allow
    if profile is not None:
        cfg.setdefault("tools", {})["profile"] = profile
    if gateway_allow is not None:
        cfg.setdefault("gateway", {}).setdefault("tools", {})["allow"] = gateway_allow
    ctx.config = cfg
    if attested is not None:
        ctx.attestation = {"tools": attested}
    return ctx


# ---------------------------------------------------------------------------
# _t3_declared — merged tools.allow + tools.alsoAllow + gateway.tools.allow ∪ attested,
# returning (literal_verbs, unbounded) where unbounded flags class-grant tokens.
# ---------------------------------------------------------------------------

def test_declared_union_config_gateway_attestation():
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {
        "tools": {"allow": ["bash"], "alsoAllow": ["read_file"]},
        "gateway": {"tools": {"allow": ["mcp__x__send_message"]}},
    }
    ctx.attestation = {"tools": ["delete_forever"]}
    verbs, unbounded, has_allow_bound = _t3_declared(ctx)
    assert unbounded is False
    assert has_allow_bound is True  # top-level tools.allow is present + non-empty
    # bash folds to its canonical id "exec" (dist TOOL_NAME_ALIASES); the rest pass through.
    assert {"exec", "read_file", "send_message", "delete_forever"} <= verbs


def test_declared_empty_when_nothing_declared():
    verbs, unbounded, has_allow_bound = _t3_declared(Context(home=Path("/nonexistent")))
    assert verbs == set() and unbounded is False and has_allow_bound is False


def test_declared_has_no_bound_when_only_also_allow_or_profile():
    """C-135: alsoAllow / gateway.allow / attestation ADD to the declared set but never BOUND
    it — only a top-level tools.allow does. The schema-recommended 'profile + alsoAllow' shape
    (no allow) must report has_allow_bound=False so the profile-granted core tools don't drift."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {"tools": {"profile": "coding", "alsoAllow": ["notion__search_pages"]}}
    verbs, unbounded, has_allow_bound = _t3_declared(ctx)
    assert has_allow_bound is False
    assert "search_pages" in verbs  # still collected, just not treated as a bound


def test_declared_marks_unbounded_on_class_grant_tokens():
    # Grounded token forms: bare glob, server glob, every core group is group:<id>,
    # plugin group/bundle, and the default-plugin-tools sentinel (expands to "*").
    for token in (
        "*",
        "slack__*",
        "group:plugins",
        "group:openclaw",
        "group:core",
        "bundle-mcp",
        "__openclaw_default_plugin_tools__",
    ):
        ctx = Context(home=Path("/nonexistent"))
        ctx.config = {"tools": {"allow": ["bash", token]}}
        verbs, unbounded, has_allow_bound = _t3_declared(ctx)
        assert unbounded is True, token
        assert has_allow_bound is True, token
        assert "exec" in verbs  # literals still collected alongside (bash folds to exec)


# ---------------------------------------------------------------------------
# WARN — proven high-blast verb, undeclared
# ---------------------------------------------------------------------------

def test_warn_on_undeclared_destructive_verb(tmp_path):
    _write_traj(tmp_path, ["mcp__admin__delete_forever"])  # DESTRUCTIVE, high-blast
    ctx = _ctx(tmp_path, allow=["web_search", "read_file"])  # explicit list, no delete
    f = check_capability_drift(ctx)
    assert f.id == "T3"
    assert f.status == WARN, f.detail
    assert any("delete_forever" in e for e in f.evidence)


def test_warn_on_undeclared_exec_verb(tmp_path):
    _write_traj(tmp_path, ["bash"])  # EXEC, high-blast
    ctx = _ctx(tmp_path, allow=["web_search"])
    assert check_capability_drift(ctx).status == WARN


# ---------------------------------------------------------------------------
# PASS — proven high-blast verb that IS within the declared / attested grant
# ---------------------------------------------------------------------------

def test_pass_when_high_blast_verb_declared(tmp_path):
    _write_traj(tmp_path, ["bash"])
    ctx = _ctx(tmp_path, allow=["bash", "web_search"])
    assert check_capability_drift(ctx).status == PASS


def test_pass_when_gateway_allow_supplements_a_bounded_allow(tmp_path):
    """gateway.tools.allow entries are folded into the declared set (additive), so a proven
    verb they cover is not drift — PROVIDED a top-level tools.allow bound exists."""
    _write_traj(tmp_path, ["send_message"])  # EGRESS, high-blast
    ctx = _ctx(tmp_path, allow=["read_file"], gateway_allow=["send_message"])
    assert check_capability_drift(ctx).status == PASS


def test_pass_when_covered_by_attestation(tmp_path):
    _write_traj(tmp_path, ["bash"])
    ctx = _ctx(tmp_path, allow=["web_search"], attested=["bash"])
    assert check_capability_drift(ctx).status == PASS


def test_pass_when_declared_via_also_allow(tmp_path):
    """C-135: tools.alsoAllow is merged with tools.allow (real OpenClaw semantics) — a verb
    declared there must NOT read as drift."""
    _write_traj(tmp_path, ["bash"])
    ctx = _ctx(tmp_path, allow=["web_search"], also_allow=["bash"])
    assert check_capability_drift(ctx).status == PASS


def test_pass_bash_proven_when_exec_declared(tmp_path):
    """C-135: OpenClaw folds 'bash' -> 'exec' before allow-matching (dist TOOL_NAME_ALIASES),
    so tools.allow=['exec'] genuinely permits a proven 'bash' — T3 must apply the same fold
    and NOT read it as drift."""
    _write_traj(tmp_path, ["bash"])
    ctx = _ctx(tmp_path, allow=["exec"])
    assert check_capability_drift(ctx).status == PASS


def test_pass_exec_proven_when_bash_declared(tmp_path):
    """The alias fold is symmetric: tools.allow=['bash'] permits a proven 'exec'."""
    _write_traj(tmp_path, ["exec"])
    ctx = _ctx(tmp_path, allow=["bash"])
    assert check_capability_drift(ctx).status == PASS


def test_pass_low_blast_verb_undeclared_is_spared(tmp_path):
    """A reversible/unknown verb (web_fetch) beyond the allow-list is NOT drift — the
    high-blast gate spares it (built-ins/MCP tools are auto-available)."""
    _write_traj(tmp_path, ["web_fetch"])  # REVERSIBLE, not high-blast
    ctx = _ctx(tmp_path, allow=["read_file"])
    assert check_capability_drift(ctx).status == PASS


# ---------------------------------------------------------------------------
# UNKNOWN branches
# ---------------------------------------------------------------------------

def test_unknown_when_no_declared_grant(tmp_path):
    """No explicit allow-list AND no attestation -> drift can't be measured -> UNKNOWN,
    not a false WARN flood (real configs commonly omit tools.allow)."""
    _write_traj(tmp_path, ["bash"])  # high-blast proven, but nothing declared
    assert check_capability_drift(_ctx(tmp_path)).status == UNKNOWN


def test_unknown_when_profile_grants_without_toplevel_allow(tmp_path):
    """C-135 (architect-confirmed): OpenClaw's schema forbids allow+alsoAllow and recommends
    'profile + alsoAllow'. In that shape the profile ('coding') grants high-blast core tools
    (exec/code_execution/sessions_send) and there is NO tools.allow layer. T3 must report
    UNKNOWN (profile grant is unenumerable), never WARN on a profile-granted verb."""
    _write_traj(tmp_path, ["exec", "code_execution", "sessions_send"])
    ctx = _ctx(tmp_path, profile="coding", also_allow=["notion__search_pages"])
    assert check_capability_drift(ctx).status == UNKNOWN


def test_unknown_when_only_gateway_allow_no_toplevel_allow(tmp_path):
    """C-135 gateway variant: gateway.tools.allow governs gateway tools, it is NOT the
    top-level core-tool upper bound — with a profile granting exec and no tools.allow, T3 is
    UNKNOWN, not WARN."""
    _write_traj(tmp_path, ["exec"])
    ctx = _ctx(tmp_path, profile="coding", gateway_allow=["web_fetch"])
    assert check_capability_drift(ctx).status == UNKNOWN


def test_unknown_when_allow_list_uses_class_grant_token(tmp_path):
    """C-135: an allow-list that bundles MCP tools via a glob / group / bundle token can't be
    enumerated — flagging a proven MCP verb as 'undeclared' would false-WARN. UNKNOWN, not
    WARN, even with a high-blast verb proven and no literal grant for it."""
    _write_traj(tmp_path, ["mcp__slack__send_message"])  # EGRESS, high-blast
    for token in ("bundle-mcp", "slack__*", "group:plugins", "*", "__openclaw_default_plugin_tools__"):
        ctx = _ctx(tmp_path, allow=["read_file", token])
        assert check_capability_drift(ctx).status == UNKNOWN, token


def test_unknown_when_no_sidecar(tmp_path):
    ctx = _ctx(tmp_path, allow=["bash"])  # declared, but no trajectory at all
    assert check_capability_drift(ctx).status == UNKNOWN


def test_unknown_when_home_not_path():
    ctx = Context(home=None)
    ctx.config = {"tools": {"allow": ["bash"]}}
    assert check_capability_drift(ctx).status == UNKNOWN


def test_unknown_on_unrecognised_schema_version(tmp_path):
    _write_traj(tmp_path, ["bash"], schema_version=999)
    ctx = _ctx(tmp_path, allow=["web_search"])
    assert check_capability_drift(ctx).status == UNKNOWN


# ---------------------------------------------------------------------------
# Integration through analyze()
# ---------------------------------------------------------------------------

def test_analyze_surfaces_t3_warn(tmp_path):
    _write_traj(tmp_path, ["web_search", "bash"])  # bash = undeclared high-blast
    ctx = _ctx(tmp_path, allow=["web_search"])
    r = analyze(ctx)
    t3 = next(f for f in r["findings"] if f.id == "T3")
    assert t3.status == WARN


def test_analyze_t3_pass_when_declared(tmp_path):
    _write_traj(tmp_path, ["bash"])
    ctx = _ctx(tmp_path, allow=["bash"])
    r = analyze(ctx)
    t3 = next(f for f in r["findings"] if f.id == "T3")
    assert t3.status == PASS


def test_render_marks_unknown_t3_not_as_pass(tmp_path):
    """An UNKNOWN T3 must render with the '?' marker, never the '✓' pass check."""
    from clawseccheck.behavioral import render_behavioral_analysis

    _write_traj(tmp_path, ["bash"])  # proven high-blast, but no declared grant -> UNKNOWN
    out = render_behavioral_analysis(_ctx(tmp_path), ascii_only=True)
    assert "[?] T3" in out
    assert "[ok] T3" not in out
