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
    _group_label,
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


def test_classify_egress_verb_not_shadowed_by_ingress_product_name():
    """C-170 adversarial finding: 'gmail_send'/'send_email' contain 'gmail'/'email'
    (INPUT_TOOL_HINTS, meant for the ingress leg) but are egress ACTIONS — they must
    classify as egress, not ingress, or the canonical email-exfil trifecta becomes
    invisible to T1."""
    assert _classify_verb_role("gmail_send") == "egress"
    assert _classify_verb_role("send_email") == "egress"
    assert _classify_verb_role("email_send") == "egress"
    assert _classify_verb_role("webhook") == "egress"


def test_classify_routine_filesystem_verb_is_not_sensitive():
    """C-170 adversarial finding: a bare filesystem-listing verb ('list_files') must
    NOT classify as 'sensitive' — that reading was broad enough to turn an ordinary
    web-search-then-list-files-then-slack-post workflow into a false trifecta."""
    assert _classify_verb_role("list_files") is None
    assert _classify_verb_role("read_files") is None


# ---------------------------------------------------------------------------
# Unit: group_events_by_thread
# ---------------------------------------------------------------------------

def test_group_by_thread_id():
    events = [
        {"sessionId": "s1", "threadId": "a", "turnId": "t1", "seq": 2, "ts": "2"},
        {"sessionId": "s1", "threadId": "a", "turnId": "t1", "seq": 1, "ts": "1"},
        {"sessionId": "s1", "threadId": "b", "turnId": "t2", "seq": 1, "ts": "1"},
    ]
    groups = group_events_by_thread(events)
    assert {_group_label(k) for k in groups} == {"a", "b"}
    a_key = next(k for k in groups if _group_label(k) == "a")
    assert [e["seq"] for e in groups[a_key]] == [1, 2]  # sorted


def test_group_falls_back_to_turn_id_when_no_thread_id():
    events = [{"sessionId": "s1", "threadId": None, "turnId": "t1", "seq": 1, "ts": "1"}]
    groups = group_events_by_thread(events)
    assert {_group_label(k) for k in groups} == {"t1"}


def test_group_no_ids_falls_into_shared_bucket():
    events = [{"sessionId": "s1", "threadId": None, "turnId": None, "seq": 1, "ts": "1"}]
    groups = group_events_by_thread(events)
    assert len(groups) == 1
    assert {_group_label(k) for k in groups} == {"(no thread/turn id)"}


def test_group_scoped_by_session_never_merges_unrelated_sessions():
    """C-170 adversarial finding: seq is a per-SESSION counter — two different
    sessions that happen to share a threadId (or both lack one, landing in the
    shared "" bucket) must NOT be pooled into one group; that could manufacture a
    trifecta out of three unrelated single-verb sessions."""
    events = [
        {"sessionId": "session-A", "threadId": "shared", "turnId": None, "seq": 1, "ts": "1",
         "type": "tool.call", "name": "web_fetch"},
        {"sessionId": "session-B", "threadId": "shared", "turnId": None, "seq": 1, "ts": "1",
         "type": "tool.call", "name": "read_credential_file"},
        {"sessionId": "session-C", "threadId": "shared", "turnId": None, "seq": 1, "ts": "1",
         "type": "tool.call", "name": "send_message"},
    ]
    groups = group_events_by_thread(events)
    assert len(groups) == 3  # NOT pooled into one "shared" group
    f = check_behavioral_trifecta(groups)
    assert f.status == PASS


def test_t1_disambiguates_label_when_two_sessions_share_a_thread_id():
    """C-180: two different sessions both using OpenClaw's own default threadId
    ("th1") and both independently firing a real trifecta must not render as
    two identical, indistinguishable "th1" labels — the reviewer needs to know
    which session's sidecar to actually go inspect."""
    events = []
    for session in ("sessA", "sessB"):
        for seq, name in enumerate(
            ("web_fetch", "read_credential_file", "send_message"), start=1
        ):
            events.append({
                "sessionId": session, "threadId": "th1", "seq": seq, "ts": str(seq),
                "type": "tool.call", "name": name,
            })
    groups = group_events_by_thread(events)
    f = check_behavioral_trifecta(groups)
    assert f.status == WARN
    assert "th1 (session sessA)" in f.detail
    assert "th1 (session sessB)" in f.detail
    # the two labels must be distinct, not both just "th1"
    assert len(set(f.evidence)) == 2


def test_t1_label_stays_plain_when_no_collision():
    """Regression guard: the disambiguation must not fire (and pollute the
    label) for the overwhelming common case of a single firing thread."""
    groups = {
        "th1": [
            {"type": "tool.call", "name": "web_fetch", "seq": 1},
            {"type": "tool.call", "name": "read_credential_file", "seq": 2},
            {"type": "tool.call", "name": "send_message", "seq": 3},
        ]
    }
    f = check_behavioral_trifecta(groups)
    assert f.status == WARN
    assert f.evidence == ["th1"]


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


def test_t1_warns_on_canonical_email_exfil_pattern():
    """C-170 regression: fetch inbox -> read a credential -> send it out over email
    must WARN — this is the textbook exfil path the check exists to catch, and an
    earlier draft missed it entirely (the egress-verb 'gmail_send' was shadowed by
    the ingress hint 'gmail' since ingress was checked first)."""
    groups = {
        "th1": [
            {"type": "tool.call", "name": "gmail_fetch_inbox", "seq": 1},
            {"type": "tool.call", "name": "read_credential_file", "seq": 2},
            {"type": "tool.call", "name": "gmail_send", "seq": 3},
        ]
    }
    f = check_behavioral_trifecta(groups)
    assert f.status == WARN


def test_t1_pass_on_base64_get_exfil_via_web_fetch_accepted_limitation():
    """B-249, documented/accepted limitation, NOT a regression to "fix" here: a full
    ingress -> sensitive -> (disguised egress) sequence is observed, yet T1 stays
    silent. The third leg is a GET-based exfil beacon carrying stolen data as a
    base64 URL param on an ordinary web_fetch call — but 'web_fetch' classifies as
    ingress (INPUT_TOOL_HINTS), same as the first leg, regardless of what its
    (unread) arguments actually contain: T1 is metadata-only by contract (§8,
    structurally enforced by trajectory.read_events() never exposing
    data.arguments), so it can never tell this fetch apart from an ordinary
    ingress fetch. This exact sequence (cred-read then a beacon-shaped fetch) is
    instead caught by B164/logscan.py's cross-line corroboration (see
    tests/test_check_b164.py's B-249 tests) — the layer that already has a sound,
    bounded precedent for reading raw argument text. See the in-source note above
    _classify_verb_role for the full reasoning."""
    groups = {
        "th1": [
            {"type": "tool.call", "name": "browse_page", "seq": 1},  # ingress leg
            {"type": "tool.call", "name": "read_credential_file", "seq": 2},  # sensitive leg
            # web_fetch's arguments (destination host + base64 param) are exactly what
            # make THIS call an exfil beacon, but T1 never reads them — only the verb
            # NAME, which reads identically to an ordinary ingress fetch.
            {"type": "tool.call", "name": "web_fetch", "seq": 3},
        ]
    }
    f = check_behavioral_trifecta(groups)
    assert f.status == PASS


def test_t1_pass_on_ordinary_web_files_chat_workflow():
    """C-170 regression: 'search the web, look at repo files, post a summary to
    Slack' is an entirely mundane combo, not a lethal-trifecta pattern — an earlier
    draft's overly-broad 'files' sensitive-hint made this a false WARN."""
    groups = {
        "th1": [
            {"type": "tool.call", "name": "web_search", "seq": 1},
            {"type": "tool.call", "name": "list_files", "seq": 2},
            {"type": "tool.call", "name": "slack_send_message", "seq": 3},
        ]
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
    # "Silent" = no WARN fires. T1/T2 PASS on the clean fixture; T3 (F-123) reports
    # UNKNOWN here because the bare Context has no declared tools.allow to measure drift
    # against — an advisory non-state, not an alert.
    r = analyze(_ctx(FIXTURES / "traj_behavioral_clean"))
    assert all(f.status != WARN for f in r["findings"])


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


def test_analyze_truncation_marked_and_a_signal_past_the_cap_is_missed(tmp_path):
    """C-180: a real trifecta placed entirely past the 8MB per-file scan cap must
    not silently produce a clean PASS with no indication anything was cut off."""
    import json

    from clawseccheck.trajectory import _MAX_BYTES_PER_FILE

    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True)

    def line(seq, name):
        rec = {
            "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.call",
            "ts": str(seq), "seq": seq, "sessionId": "s1",
            "data": {"name": name, "threadId": "th1"},
        }
        return json.dumps(rec) + "\n"

    path = d / "s.trajectory.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        seq = 1
        written = 0
        while written < _MAX_BYTES_PER_FILE + 100_000:
            row = line(seq, "list_files")
            fh.write(row)
            written += len(row)
            seq += 1
        # the real signal, placed entirely past the byte cap
        for name in ("web_fetch", "read_credential_file", "send_message"):
            fh.write(line(seq, name))
            seq += 1

    r = analyze(_ctx(tmp_path))
    assert r["truncated"] is True
    # confirms the signal really was missed (the bug this caveat discloses) —
    # not a claim this is desirable, just the honest current behavior. No WARN fires
    # (T1/T2 PASS; T3 is UNKNOWN on this config-less Context — an advisory non-state).
    assert all(f.status != WARN for f in r["findings"])

    out = render_behavioral_analysis(_ctx(tmp_path))
    assert "INCOMPLETE" in out and "scan cap" in out


def test_analyze_no_truncation_on_small_file(tmp_path):
    """Regression guard: the cap-hit caveat must not fire on ordinary small files."""
    import json
    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True)
    rec = {
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.call",
        "ts": "1", "seq": 1, "sessionId": "s1", "data": {"name": "bash", "threadId": "t1"},
    }
    (d / "s.trajectory.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    r = analyze(_ctx(tmp_path))
    assert r["truncated"] is False
