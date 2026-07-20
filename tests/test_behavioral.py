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


# ---------------------------------------------------------------------------
# B-245 — per-FILE cap (_MAX_FILES) disclosure: unlike the per-byte cap above
# (C-180, disclosed via `truncated`), the per-file cap used to silently drop the
# oldest sessions with no signal anywhere in the output. These pin the fix:
# `analyze()`'s `files_total`/`files_capped` and the matching summary caveat.
# ---------------------------------------------------------------------------

def _write_capped_home(tmp_path, extra_files: int):
    """Write _MAX_FILES + extra_files synthetic sessions with distinct mtimes, the
    OLDEST one (dropped when capped) carrying a real T1 trifecta so a silent drop
    would otherwise hide a genuine finding."""
    import json
    import os

    from clawseccheck.trajectory import _MAX_FILES

    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True)
    base = 1_700_000_000

    def write(i: int, events: list[tuple[str, str]]):
        p = d / f"s{i}.trajectory.jsonl"
        lines = []
        for seq, (name, thread) in enumerate(events, start=1):
            lines.append(json.dumps({
                "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.call",
                "ts": str(seq), "seq": seq, "sessionId": f"s{i}",
                "data": {"name": name, "threadId": thread},
            }))
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.utime(p, (base + i, base + i))

    total = _MAX_FILES + extra_files
    # oldest session (i=0) — a real ingress -> sensitive -> egress trifecta, only
    # visible if this file is actually scanned.
    write(0, [("web_fetch", "th0"), ("read_credential_file", "th0"), ("send_message", "th0")])
    for i in range(1, total):
        write(i, [("list_files", f"th{i}")])
    return total


def test_analyze_files_capped_marked_and_oldest_session_missed(tmp_path):
    total = _write_capped_home(tmp_path, extra_files=1)
    from clawseccheck.trajectory import _MAX_FILES

    r = analyze(_ctx(tmp_path))
    assert r["files_total"] == total
    assert r["files_capped"] is True
    assert r["files_scanned"] == _MAX_FILES
    # the oldest session's trifecta (in the dropped file) is genuinely missed —
    # confirms the disclosure is needed, not a claim this is desirable.
    assert all(f.status != WARN for f in r["findings"])

    out = render_behavioral_analysis(_ctx(tmp_path))
    assert "INCOMPLETE" in out
    assert f"{_MAX_FILES} most recent of {total}" in out
    assert "oldest session" in out


def test_analyze_not_capped_at_max_files_no_disclosure(tmp_path):
    """Regression guard: sitting exactly AT the cap (not over it) must not read as
    capped — that's a complete scan, not a truncated one."""
    from clawseccheck.trajectory import _MAX_FILES

    _write_capped_home(tmp_path, extra_files=0)
    r = analyze(_ctx(tmp_path))
    assert r["files_total"] == _MAX_FILES
    assert r["files_capped"] is False

    out = render_behavioral_analysis(_ctx(tmp_path))
    assert "most recent" not in out


# ---------------------------------------------------------------------------
# B-298 — the CHANNEL ingress leg.
#
# Before this, T1's ingress leg was VERB-NAME-ONLY. A message delivered over a
# configured channel — the most common real injection vector — arrives as a
# `prompt.submitted` event carrying no `data.name`, so `_classify_verb_role(None)`
# was None and the trifecta could never START: a poisoned group message -> read a
# credential -> send it out showed only sensitive->egress and T1 stayed a hollow PASS.
#
# The leg is now armed off the record's `sessionKey` ORIGIN KIND, and ONLY for a
# group/channel peer kind. The rejected alternative — "a thread that begins with
# prompt.submitted" — was measured on a real host to flag 74 of 85 threads, 46 of them
# owner-origin sessions where the "untrusted input" is the owner typing at his own
# dashboard. The tests below pin both halves of that: the group case fires, and every
# owner-origin bucket stays silent on the identical sensitive+egress pair.
# ---------------------------------------------------------------------------

def _prompt(seq, origin, channel=None, thread="th1"):
    return {"type": "prompt.submitted", "name": None, "seq": seq, "ts": str(seq),
            "sessionId": "s1", "threadId": thread, "origin": origin,
            "originChannel": channel}


def _tool(seq, name, thread="th1", origin="group", channel="telegram"):
    return {"type": "tool.call", "name": name, "seq": seq, "ts": str(seq),
            "sessionId": "s1", "threadId": thread, "origin": origin,
            "originChannel": channel}


def test_t1_warns_on_channel_delivered_message_then_sensitive_then_egress():
    """The defect, directly: no ingress VERB runs anywhere in this thread, yet the
    canonical poisoned-message -> read-secret -> exfil sequence is present."""
    groups = {"th1": [
        _prompt(1, "group", "telegram"),
        _tool(2, "read_credential_file"),
        _tool(3, "send_message"),
    ]}
    f = check_behavioral_trifecta(groups)
    assert f.status == WARN
    # the finding must say the ingress leg was a channel message, not "an ingress verb"
    assert "external group message" in f.evidence[0]


def test_t1_warns_on_broadcast_channel_origin():
    groups = {"th1": [
        _prompt(1, "channel", "discord"),
        _tool(2, "vault_get_secret", origin="channel", channel="discord"),
        _tool(3, "send_message", origin="channel", channel="discord"),
    ]}
    assert check_behavioral_trifecta(groups).status == WARN


def test_t1_does_not_arm_on_owner_or_unknown_origins():
    """THE decisive false-positive guard. Every non-external origin bucket, given the
    IDENTICAL sensitive+egress pair that fires for a group origin, must stay PASS —
    including None (no sessionKey / unparseable), which is the honest UNKNOWN.

    "direct" is in this list on purpose: a 1:1 DM is overwhelmingly the owner talking
    to his own bot (measured: 1,774 of one real host's 3,896 records are a single
    telegram:direct owner session), and the session key alone cannot tell that apart
    from a stranger's DM. Arming it would reproduce exactly the 74-of-85-threads false
    positive this design exists to avoid. See the residual note in behavioral.py.
    """
    for origin in ("direct", "dashboard", "main", "global", "cron", "subagent", "acp",
                   "explicit", "voice", "boot", "other", None):
        groups = {"th1": [
            _prompt(1, origin, "telegram"),
            _tool(2, "read_credential_file", origin=origin),
            _tool(3, "send_message", origin=origin),
        ]}
        assert check_behavioral_trifecta(groups).status == PASS, origin


def test_t1_channel_ingress_still_requires_the_order():
    """A channel message arriving AFTER the sensitive read must not retro-arm the leg —
    the ordering invariant the whole check rests on is unchanged."""
    groups = {"th1": [
        _tool(1, "read_credential_file"),
        _prompt(2, "group", "telegram"),
        _tool(3, "send_message"),
    ]}
    assert check_behavioral_trifecta(groups).status == PASS


def test_t1_channel_origin_alone_is_not_a_trifecta():
    """A group-origin thread with no sensitive leg must stay silent — otherwise every
    group message becomes a finding, which is noise, not detection."""
    groups = {"th1": [
        _prompt(1, "group", "telegram"),
        _tool(2, "list_calendars"),
        _tool(3, "send_message"),
    ]}
    assert check_behavioral_trifecta(groups).status == PASS


def test_t1_non_prompt_events_do_not_arm_ingress_by_origin_alone():
    """Only the `prompt.submitted` event — the message delivery itself — arms the leg.
    If any group-origin event did, the leg would be armed at position 0 for the whole
    session and the ordering requirement would collapse."""
    groups = {"th1": [
        _tool(1, "list_calendars"),           # group origin, but not a prompt
        _tool(2, "read_credential_file"),
        _tool(3, "send_message"),
    ]}
    assert check_behavioral_trifecta(groups).status == PASS


def test_t1_verb_armed_firing_keeps_its_plain_label():
    """No annotation regression: a firing opened by a real ingress VERB must not be
    mislabelled as an external message."""
    groups = {"th1": [
        {"type": "tool.call", "name": "web_fetch", "seq": 1},
        {"type": "tool.call", "name": "read_credential_file", "seq": 2},
        {"type": "tool.call", "name": "send_message", "seq": 3},
    ]}
    f = check_behavioral_trifecta(groups)
    assert f.status == WARN
    assert f.evidence == ["th1"]


def test_t1_verb_role_wins_over_channel_origin():
    """An event that DOES carry a verb role keeps it — the origin fallback only applies
    where the verb-name classifier had nothing to say."""
    groups = {"th1": [
        _tool(1, "web_fetch"),                # ingress by verb, in a group session
        _tool(2, "read_credential_file"),
        _tool(3, "send_message"),
    ]}
    f = check_behavioral_trifecta(groups)
    assert f.status == WARN
    assert f.evidence == ["th1"]  # armed by the verb, so no external-message annotation


def test_t1_channel_finding_never_emits_a_peer_id(tmp_path):
    """§8 end-to-end through the real reader: a group session key embedding a peer id
    fires T1, and neither the id nor the raw key appears anywhere in the output."""
    import json

    peer = "3076" + "15315"
    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True)
    key = f"agent:main:telegram:group:{peer}"

    def line(seq, rec_type, name):
        rec = {"traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": rec_type,
               "ts": str(seq), "seq": seq, "sessionId": "s1", "sessionKey": key,
               "data": {"threadId": "th1", "turnId": "th1",
                        **({"name": name} if name else {})}}
        return json.dumps(rec) + "\n"

    (d / "s.trajectory.jsonl").write_text(
        line(1, "prompt.submitted", None)
        + line(2, "tool.call", "read_credential_file")
        + line(3, "tool.call", "send_message"),
        encoding="utf-8",
    )
    r = analyze(_ctx(tmp_path))
    t1 = next(f for f in r["findings"] if f.id == "T1")
    assert t1.status == WARN
    blob = " ".join([t1.detail, t1.fix, *t1.evidence,
                     render_behavioral_analysis(_ctx(tmp_path), ascii_only=True)])
    assert peer not in blob
    assert key not in blob
    assert "external group message" in blob


def test_traj_channel_group_ingress_fixture_warns():
    """Bad fixture: a group-origin channel message opens the chain, with NO ingress verb
    anywhere in the thread."""
    r = analyze(_ctx(FIXTURES / "traj_channel_group_ingress"))
    t1 = next(f for f in r["findings"] if f.id == "T1")
    assert t1.status == WARN


def test_traj_channel_owner_clean_fixture_silent():
    """Clean fixture: dashboard-origin and telegram:direct-origin threads carrying the
    SAME sensitive+egress pair as the bad fixture. Owner traffic must not manufacture a
    trifecta — this is the pair that makes the bad fixture's WARN meaningful."""
    r = analyze(_ctx(FIXTURES / "traj_channel_owner_clean"))
    assert all(f.status != WARN for f in r["findings"])


def test_behavioral_checks_stay_unscored():
    """Owner decision (2026-07-20): T1/T2/T3 are advisory and stay scored=False
    permanently. B-298 improves T1's recall; it must not move the A-F grade."""
    from clawseccheck.behavioral import BEHAVIORAL_CHECK_IDS
    from clawseccheck.catalog import BY_ID
    from clawseccheck.checks import CHECKS

    for cid in BEHAVIORAL_CHECK_IDS:
        assert BY_ID[cid].scored is False, cid
    catalogued = {getattr(fn, "__name__", "") for fn in CHECKS}
    assert "check_behavioral_trifecta" not in catalogued
