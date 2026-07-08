"""Behavioral trajectory audit (E-032 v1) — T1 behavioral trifecta, T2 outcome anomaly.

Metadata-only (§8): read_events() never surfaces arguments/output/result/contentItems;
these detectors classify verb ROLE by name only. WARN-only, scored=False (Golden Rule
#5) — never part of the main audit()/CHECKS list or the A-F score, only --behavioral.

Offline, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.behavioral import (
    _classify_verb_role,
    analyze,
    check_behavioral_trifecta,
    check_outcome_anomaly,
    group_events_by_thread,
    render_behavioral_analysis,
)
from clawseccheck.catalog import PASS, WARN
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home: Path) -> Context:
    return Context(home=home)


# ---------------------------------------------------------------------------
# Unit: _classify_verb_role
# ---------------------------------------------------------------------------

def test_classify_ingress_verb():
    assert _classify_verb_role("web_fetch") == "ingress"


def test_classify_sensitive_verb():
    assert _classify_verb_role("read_credential_file") == "sensitive"


def test_classify_egress_verb():
    assert _classify_verb_role("send_message") == "egress"


def test_classify_unrelated_verb_is_none():
    assert _classify_verb_role("list_calendars") is None


def test_classify_none_name_is_none():
    assert _classify_verb_role(None) is None


# ---------------------------------------------------------------------------
# Unit: group_events_by_thread
# ---------------------------------------------------------------------------

def test_group_by_thread_id():
    events = [
        {"threadId": "a", "turnId": "t1", "seq": 2, "ts": "2"},
        {"threadId": "a", "turnId": "t1", "seq": 1, "ts": "1"},
        {"threadId": "b", "turnId": "t2", "seq": 1, "ts": "1"},
    ]
    groups = group_events_by_thread(events)
    assert set(groups) == {"a", "b"}
    assert [e["seq"] for e in groups["a"]] == [1, 2]  # sorted


def test_group_falls_back_to_turn_id_when_no_thread_id():
    events = [{"threadId": None, "turnId": "t1", "seq": 1, "ts": "1"}]
    groups = group_events_by_thread(events)
    assert set(groups) == {"t1"}


def test_group_no_ids_falls_into_shared_bucket():
    events = [{"threadId": None, "turnId": None, "seq": 1, "ts": "1"}]
    groups = group_events_by_thread(events)
    assert set(groups) == {""}


# ---------------------------------------------------------------------------
# T1 — behavioral trifecta
# ---------------------------------------------------------------------------

def test_t1_warns_on_ordered_trifecta():
    groups = {
        "th1": [
            {"type": "tool.call", "name": "web_fetch", "seq": 1},
            {"type": "tool.call", "name": "read_credential_file", "seq": 2},
            {"type": "tool.call", "name": "send_message", "seq": 3},
        ]
    }
    f = check_behavioral_trifecta(groups)
    assert f.id == "T1"
    assert f.status == WARN
    assert "th1" in f.evidence


def test_t1_pass_when_egress_before_sensitive():
    """Order matters — egress before the sensitive leg is not a trifecta."""
    groups = {
        "th1": [
            {"type": "tool.call", "name": "web_fetch", "seq": 1},
            {"type": "tool.call", "name": "send_message", "seq": 2},
            {"type": "tool.call", "name": "read_credential_file", "seq": 3},
        ]
    }
    f = check_behavioral_trifecta(groups)
    assert f.status == PASS


def test_t1_pass_when_sensitive_leg_missing():
    groups = {
        "th1": [
            {"type": "tool.call", "name": "web_fetch", "seq": 1},
            {"type": "tool.call", "name": "send_message", "seq": 2},
        ]
    }
    f = check_behavioral_trifecta(groups)
    assert f.status == PASS


def test_t1_pass_when_no_groups():
    assert check_behavioral_trifecta({}).status == PASS


def test_t1_does_not_fire_across_separate_threads():
    """Ingress in one thread and sensitive+egress in a totally different thread must
    NOT combine into a false trifecta — each thread is evaluated independently."""
    groups = {
        "th1": [{"type": "tool.call", "name": "web_fetch", "seq": 1}],
        "th2": [
            {"type": "tool.call", "name": "read_credential_file", "seq": 1},
            {"type": "tool.call", "name": "send_message", "seq": 2},
        ],
    }
    f = check_behavioral_trifecta(groups)
    assert f.status == PASS


# ---------------------------------------------------------------------------
# T2 — outcome anomaly
# ---------------------------------------------------------------------------

def test_t2_warns_on_fail_fail_success():
    groups = {
        "th1": [
            {"type": "tool.result", "name": "read_credential_file", "outcome": "failed"},
            {"type": "tool.result", "name": "read_credential_file", "outcome": "failed"},
            {"type": "tool.result", "name": "read_credential_file", "outcome": "success"},
        ]
    }
    f = check_outcome_anomaly(groups)
    assert f.id == "T2"
    assert f.status == WARN


def test_t2_pass_on_single_failure_then_success():
    """A single failure is the overwhelming common case — must NOT warn."""
    groups = {
        "th1": [
            {"type": "tool.result", "name": "read_credential_file", "outcome": "failed"},
            {"type": "tool.result", "name": "read_credential_file", "outcome": "success"},
        ]
    }
    f = check_outcome_anomaly(groups)
    assert f.status == PASS


def test_t2_pass_on_non_sensitive_verb_failures():
    groups = {
        "th1": [
            {"type": "tool.result", "name": "web_fetch", "outcome": "failed"},
            {"type": "tool.result", "name": "web_fetch", "outcome": "failed"},
            {"type": "tool.result", "name": "web_fetch", "outcome": "success"},
        ]
    }
    f = check_outcome_anomaly(groups)
    assert f.status == PASS


def test_t2_pass_on_tool_call_events_ignored():
    """tool.call events have no outcome — only tool.result counts."""
    groups = {
        "th1": [
            {"type": "tool.call", "name": "read_credential_file", "outcome": None},
            {"type": "tool.call", "name": "read_credential_file", "outcome": None},
        ]
    }
    f = check_outcome_anomaly(groups)
    assert f.status == PASS


def test_t2_different_verbs_do_not_combine_streaks():
    """Two failures on verb A and a success on verb B must not combine into a false
    anomaly — the streak is tracked per verb name."""
    groups = {
        "th1": [
            {"type": "tool.result", "name": "read_credential_file", "outcome": "failed"},
            {"type": "tool.result", "name": "read_credential_file", "outcome": "failed"},
            {"type": "tool.result", "name": "vault_get_secret", "outcome": "success"},
        ]
    }
    f = check_outcome_anomaly(groups)
    assert f.status == PASS


# ---------------------------------------------------------------------------
# Fixture-based integration tests
# ---------------------------------------------------------------------------

def test_traj_behavioral_trifecta_fixture_warns():
    r = analyze(_ctx(FIXTURES / "traj_behavioral_trifecta"))
    t1 = next(f for f in r["findings"] if f.id == "T1")
    assert t1.status == WARN


def test_traj_behavioral_clean_fixture_silent():
    r = analyze(_ctx(FIXTURES / "traj_behavioral_clean"))
    assert all(f.status == PASS for f in r["findings"])


def test_traj_outcome_anomaly_fixture_warns():
    r = analyze(_ctx(FIXTURES / "traj_outcome_anomaly"))
    t2 = next(f for f in r["findings"] if f.id == "T2")
    assert t2.status == WARN


def test_traj_no_sidecar_fixture_present_false():
    """No trajectory sidecar at all — UNKNOWN-shaped (present=False), not a false PASS
    dressed up as a real assessment."""
    r = analyze(_ctx(FIXTURES / "traj_no_sidecar"))
    assert r["present"] is False
    assert r["findings"] == []


def test_render_behavioral_analysis_no_sidecar_message():
    out = render_behavioral_analysis(_ctx(FIXTURES / "traj_no_sidecar"), ascii_only=True)
    assert "No trajectory sidecars found" in out


def test_render_behavioral_analysis_warns_visible():
    out = render_behavioral_analysis(_ctx(FIXTURES / "traj_behavioral_trifecta"), ascii_only=True)
    assert "T1" in out and "[!]" in out


def test_render_behavioral_analysis_unicode_by_default():
    out = render_behavioral_analysis(_ctx(FIXTURES / "traj_behavioral_trifecta"))
    assert "⚠" in out


def test_analyze_unknown_schema_version_marked(tmp_path):
    import json
    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True)
    rec = {
        "traceSchema": "openclaw-trajectory", "schemaVersion": 2, "type": "tool.call",
        "ts": "t", "seq": 1, "data": {"name": "bash", "turnId": "t1"},
    }
    (d / "s.trajectory.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    r = analyze(_ctx(tmp_path))
    assert r["unknown_version"] is True
    assert r["event_count"] == 0
