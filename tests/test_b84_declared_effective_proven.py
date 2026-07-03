"""B84 — declared vs. effective vs. proven tool use (E-014 S1 / Pulse C-090).

B44 already cross-checks declared (config 'tools.allow') vs. effective (attested
self-reported inventory). B84 adds a THIRD column: PROVEN — verbs the agent has
LOG/TRACE evidence it ACTUALLY invoked, via the new 'proven_tools' attestation
field. Still an agent self-report end to end, so ATTESTED confidence and advisory
(scored=False) — silent (UNKNOWN) by default when no proven-tool-use evidence is
cited. Offline, deterministic, no network.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import attest, audit
from clawseccheck.catalog import ATTESTED, BY_ID, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_declared_effective_proven, run_all
from clawseccheck.collector import Context


def _ctx(config=None, attestation=None):
    c = Context(home=Path("/nonexistent"), config=config or {}, attestation=attestation or {})
    return c


# --------------------------------------------------------------- catalog wiring
def test_b84_is_in_catalog_with_expected_meta():
    meta = BY_ID["B84"]
    assert meta.scored is False
    assert meta.confidence == ATTESTED
    assert meta.surface == "tools"


def test_b84_registered_in_audit():
    ctx = Context(home=Path("/nonexistent"), config={})
    run_ids = {f.id for f in run_all(ctx)}
    assert "B84" in run_ids


# --------------------------------------------------------------- attest.py plumbing
def test_template_has_proven_tools_key_and_question():
    t = attest.template()
    assert "proven_tools" in t
    assert t["proven_tools"] == []
    assert "proven_tools" in t["_questions"]


def test_attested_proven_normalizes_and_tolerates_junk():
    assert attest.attested_proven({"proven_tools": ["Bash", "mcp__Gmail__send_email"]}) == {
        "bash", "send_email",
    }
    assert attest.attested_proven({}) == set()
    assert attest.attested_proven({"proven_tools": "not-a-list"}) == set()
    assert attest.attested_proven({"proven_tools": [1, None, "  ", "search"]}) == {"search"}


# --------------------------------------------------------------- B84 verdicts
def test_b84_unknown_without_attestation():
    f = check_declared_effective_proven(_ctx())
    assert f.status == UNKNOWN
    assert f.confidence == ATTESTED


def test_b84_unknown_when_attestation_present_but_proven_tools_empty():
    # Attestation exists (e.g. tools/approval_gates filled in) but no proven-use
    # evidence was cited — must stay UNKNOWN, not silently PASS.
    att = {"tools": ["search", "send_email"], "proven_tools": []}
    f = check_declared_effective_proven(_ctx(attestation=att))
    assert f.status == UNKNOWN


def test_b84_unknown_when_proven_tools_absent_key():
    att = {"tools": ["search", "send_email"], "untrusted_to_action": "gated"}
    f = check_declared_effective_proven(_ctx(attestation=att))
    assert f.status == UNKNOWN


def test_b84_pass_proven_within_effective_and_gated():
    cfg = {"tools": {"allow": ["search_threads", "send_email"]}}
    att = {
        "tools": ["search_threads", "send_email"],
        "proven_tools": ["search_threads"],
        "untrusted_to_action": "gated",
    }
    f = check_declared_effective_proven(_ctx(config=cfg, attestation=att))
    assert f.status == PASS


def test_b84_pass_notes_dead_grant_informationally_never_warns():
    # send_email is declared+effective but never proven — informational only.
    cfg = {"tools": {"allow": ["search_threads", "send_email"]}}
    att = {
        "tools": ["search_threads", "send_email"],
        "proven_tools": ["search_threads"],
        "untrusted_to_action": "gated",
    }
    f = check_declared_effective_proven(_ctx(config=cfg, attestation=att))
    assert f.status == PASS
    assert any("send_email" in e for e in f.evidence)


def test_b84_warn_proven_high_blast_verb_with_ungated_posture():
    att = {
        "tools": ["search", "send_email"],
        "proven_tools": ["send_email"],
        "untrusted_to_action": "ungated",
    }
    f = check_declared_effective_proven(_ctx(attestation=att))
    assert f.status == WARN
    assert any("send_email" in e for e in f.evidence)
    assert any("ungated" in e for e in f.evidence)


def test_b84_warn_proven_high_blast_verb_with_runtime_bypass_actor():
    att = {
        "tools": ["Bash"],
        "proven_tools": ["Bash"],
        "approval_bypass_actors": ["sleeper"],
    }
    f = check_declared_effective_proven(_ctx(attestation=att))
    assert f.status == WARN
    assert any("bash" in e.lower() for e in f.evidence)
    assert any("approval bypass actor(s):" in e for e in f.evidence)


def test_b84_pass_proven_high_blast_verb_but_gated():
    # A dangerous verb was proven invoked, but the posture is gated — no WARN.
    att = {
        "tools": ["send_email"],
        "proven_tools": ["send_email"],
        "untrusted_to_action": "gated",
    }
    f = check_declared_effective_proven(_ctx(attestation=att))
    assert f.status == PASS


def test_b84_evidence_and_namespace_normalization_match_declared_config():
    # Config lists the MCP-namespaced grant; proven cites the bare verb — same verb.
    cfg = {"tools": {"allow": ["mcp__claude_ai_Gmail__send_email"]}}
    att = {
        "tools": ["send_email"],
        "proven_tools": ["send_email"],
        "untrusted_to_action": "ungated",
    }
    f = check_declared_effective_proven(_ctx(config=cfg, attestation=att))
    assert f.status == WARN
    assert any("send_email" in e for e in f.evidence)


# --------------------------------------------------------------- regression guard
def test_b84_scored_false_never_moves_score(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _, f_plain, s_plain = audit(tmp_path)
    _, f_att, s_att = audit(tmp_path, attestation={
        "tools": ["send_email"],
        "proven_tools": ["send_email"],
        "untrusted_to_action": "ungated",
    })
    assert s_plain.score == s_att.score
    assert s_plain.grade == s_att.grade
    plain = {f.id: f.status for f in f_plain}
    assert plain["B84"] == UNKNOWN
    att_findings = {f.id: f.status for f in f_att}
    assert att_findings["B84"] == WARN


# ------------------------------------------------- log-observed (trajectory sidecar) leg
def _home_with_traj(tmp_path: Path, call_names: list[str]) -> Path:
    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    recs = [{"traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.call",
             "data": {"name": n, "arguments": {"x": "y"}, "toolCallId": f"c{i}"}}
            for i, n in enumerate(call_names)]
    (d / "s.trajectory.jsonl").write_text(
        "\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
    return tmp_path


def test_b84_log_observed_prefers_trajectory_over_attestation(tmp_path):
    """A trajectory sidecar exists -> proven comes from the LOG (HIGH confidence), not the
    self-report. The log shows only a low-blast verb, so an attested high-blast 'proven' +
    ungated posture does NOT WARN — the log is authoritative over the self-report."""
    home = _home_with_traj(tmp_path, ["memory_search"])
    att = {"tools": ["send_email"], "proven_tools": ["send_email"],
           "untrusted_to_action": "ungated"}
    f = check_declared_effective_proven(Context(home=home, config={}, attestation=att))
    assert f.status == PASS
    assert f.confidence == "HIGH"
    assert any("log-observed" in e for e in f.evidence)


def test_b84_log_observed_high_blast_ungated_warns_at_high_confidence(tmp_path):
    """Log proves a high-blast verb (bash) actually ran AND the attested posture is
    ungated -> WARN at HIGH confidence (log-observed, not a self-report)."""
    home = _home_with_traj(tmp_path, ["bash"])
    att = {"untrusted_to_action": "ungated"}
    f = check_declared_effective_proven(Context(home=home, config={}, attestation=att))
    assert f.status == WARN
    assert f.confidence == "HIGH"
    assert any("log-observed" in e for e in f.evidence)


def test_b84_log_observed_without_posture_passes_high_confidence(tmp_path):
    """Log proves a high-blast verb ran but no ungated-posture evidence -> PASS
    (informational), still HIGH confidence and sourced from the log."""
    home = _home_with_traj(tmp_path, ["bash"])
    f = check_declared_effective_proven(Context(home=home, config={}, attestation={}))
    assert f.status == PASS
    assert f.confidence == "HIGH"
    assert any("log-observed" in e for e in f.evidence)
