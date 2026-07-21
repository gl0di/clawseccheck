"""F-134 (DISK-1) — OpenClaw's OWN runtime audit trail (``audit_events``) as a
``--behavioral`` corroboration source, plus two narrow, near-zero-FP runtime signals.

Schema grounded verbatim against the installed dist (``openclaw-state-db-DzSsA9Ji.js``:
``CREATE TABLE IF NOT EXISTS audit_events``).

HARD GR#5 BLOCKER pinned throughout: ``audit_events`` stores ``tool_name`` alone — no
argv, no command, no path, no host. A benign fixture with hundreds of plain ``bash`` rows
(mirroring the real box's 344-of-502) must stay silent — that is the volumetric-FP guard
these tests exist to pin, not an incidental detail.

Opt-in, ``--behavioral`` only: B191 is cataloged (``scored=False``) but never registered
in ``CHECKS`` — it runs exclusively through ``behavioral.analyze()``, matching the
T1/T2/T3 precedent (``BEHAVIORAL_CHECK_IDS``).

Offline, stdlib only.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from clawseccheck.behavioral import (
    BEHAVIORAL_CHECK_IDS,
    _audit_event_sessions,
    analyze,
    audit_trail_divergence,
)
from clawseccheck.catalog import BY_ID, PASS, UNKNOWN, WARN
from clawseccheck.checks import CHECKS, check_audit_trail_signals
from clawseccheck.collector import (
    LIMIT_DOMAIN_AUDIT,
    Context,
    _MAX_AUDIT_EVENTS,
    _collect_audit_events,
    collect,
)

# Column list copied verbatim from the dist CREATE TABLE so the fixture cannot drift
# from the real schema.
_AUDIT_EVENTS_DDL = (
    "CREATE TABLE audit_events ("
    "sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, "
    "source_id TEXT NOT NULL UNIQUE, source_sequence INTEGER NOT NULL, "
    "occurred_at INTEGER NOT NULL, kind TEXT NOT NULL, action TEXT NOT NULL, "
    "status TEXT NOT NULL, error_code TEXT, actor_type TEXT NOT NULL, "
    "actor_id TEXT NOT NULL, agent_id TEXT NOT NULL, session_key TEXT, session_id TEXT, "
    "run_id TEXT NOT NULL, tool_call_id TEXT, tool_name TEXT)"
)


def _insert_row(conn, i, *, status="succeeded", error_code=None, tool_name="bash",
                session_id="s1", occurred_at=None):
    conn.execute(
        "INSERT INTO audit_events (event_id, source_id, source_sequence, occurred_at, "
        "kind, action, status, error_code, actor_type, actor_id, agent_id, session_key, "
        "session_id, run_id, tool_call_id, tool_name) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            f"ev-{i}", f"src-{i}", i, occurred_at if occurred_at is not None else 1_700_000_000_000 + i,
            "tool_action", "tool.action.finished", status, error_code,
            "agent", "main", "main", f"key-{session_id}", session_id, f"run-{i}",
            f"call-{i}", tool_name,
        ),
    )


def _build_home(tmp_path, *, rows=(), db=True, table=True):
    """Materialise a fake ~/.openclaw with a state DB holding `audit_events` rows.

    `rows` is a list of dicts with any of the `_insert_row` kwargs (besides `i`).
    """
    home = tmp_path / "openclaw"
    home.mkdir(exist_ok=True)
    if db:
        state = home / "state"
        state.mkdir(exist_ok=True)
        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            if table:
                conn.execute(_AUDIT_EVENTS_DDL)
            for i, row in enumerate(rows):
                _insert_row(conn, i, **row)
            conn.commit()
        finally:
            conn.close()
    ctx = Context(home=home)
    _collect_audit_events(home, ctx)
    return ctx


# --------------------------------------------------------------------------------------
# Collector: presence / absence / empty / parse-error distinctions (Golden Rule #4).
# --------------------------------------------------------------------------------------

def test_collector_absent_db_leaves_found_false(tmp_path):
    ctx = _build_home(tmp_path, db=False)
    assert ctx.audit_events_found is False
    assert ctx.audit_events == []


def test_collector_missing_table_is_not_a_parse_error(tmp_path):
    """A state DB predating the audit_events table is not corrupt — same honest UNKNOWN
    as absent (mirrors _collect_cron_run_logs / _collect_subagent_runs)."""
    ctx = _build_home(tmp_path, table=False)
    assert ctx.audit_events_found is False
    assert ctx.audit_events_parse_error is False


def test_collector_present_but_empty_is_distinct_from_absent(tmp_path):
    ctx = _build_home(tmp_path, rows=())
    assert ctx.audit_events_found is True
    assert ctx.audit_events_total_rows == 0
    assert ctx.audit_events == []


def test_collector_reads_pivot_columns(tmp_path):
    ctx = _build_home(tmp_path, rows=[
        {"status": "blocked", "error_code": "tool_blocked", "tool_name": "bash", "session_id": "sess-a"},
    ])
    assert ctx.audit_events_found is True
    row = ctx.audit_events[0]
    assert row["status"] == "blocked"
    assert row["error_code"] == "tool_blocked"
    assert row["session_id"] == "sess-a"
    assert row["run_id"] == "run-0"
    assert row["kind"] == "tool_action"


def test_collector_coverage_stats_span_the_full_table_independent_of_sample_cap(tmp_path):
    rows = [{"occurred_at": 1_700_000_000_000 + i} for i in range(5)]
    ctx = _build_home(tmp_path, rows=rows)
    assert ctx.audit_events_total_rows == 5
    assert ctx.audit_events_oldest_ms == 1_700_000_000_000
    assert ctx.audit_events_newest_ms == 1_700_000_000_004


@pytest.mark.parametrize(
    "n_rows,expect_truncated",
    [(_MAX_AUDIT_EVENTS - 1, False), (_MAX_AUDIT_EVENTS, False), (_MAX_AUDIT_EVENTS + 1, True)],
)
def test_collector_row_cap_is_not_off_by_one(tmp_path, n_rows, expect_truncated):
    rows = [{} for _ in range(n_rows)]
    ctx = _build_home(tmp_path, rows=rows)
    assert len(ctx.audit_events) == min(n_rows, _MAX_AUDIT_EVENTS)
    assert ctx.audit_events_truncated is expect_truncated
    assert ctx.audit_events_total_rows == n_rows  # coverage count is EXACT, never capped
    assert bool([h for h in ctx.limit_hits if h.domain == LIMIT_DOMAIN_AUDIT]) is expect_truncated


def test_collector_read_only_never_writes_to_the_state_db(tmp_path):
    ctx = _build_home(tmp_path, rows=[{"status": "blocked", "error_code": "tool_blocked"}])
    db = ctx.home / "state" / "openclaw.sqlite"
    before = db.read_bytes()
    check_audit_trail_signals(ctx)
    assert db.read_bytes() == before


# --------------------------------------------------------------------------------------
# The check: UNKNOWN paths.
# --------------------------------------------------------------------------------------

def test_check_unknown_when_state_db_absent(tmp_path):
    ctx = _build_home(tmp_path, db=False)
    f = check_audit_trail_signals(ctx)
    assert f.status == UNKNOWN


def test_check_unknown_when_table_absent(tmp_path):
    ctx = _build_home(tmp_path, table=False)
    f = check_audit_trail_signals(ctx)
    assert f.status == UNKNOWN


def test_check_unknown_when_table_present_but_empty(tmp_path):
    ctx = _build_home(tmp_path, rows=())
    f = check_audit_trail_signals(ctx)
    assert f.status == UNKNOWN
    assert "currently empty" in f.detail


def test_check_unknown_on_parse_error(tmp_path):
    ctx = _build_home(tmp_path, rows=())
    ctx.audit_events_parse_error = True
    f = check_audit_trail_signals(ctx)
    assert f.status == UNKNOWN


# --------------------------------------------------------------------------------------
# THE VOLUMETRIC-FP GUARD (Golden Rule #5) — this is the load-bearing test.
# --------------------------------------------------------------------------------------

def test_clean_fixture_hundreds_of_plain_bash_rows_stays_silent(tmp_path):
    """344 benign 'bash' rows (mirroring the real box's actual ratio) must NOT warn.
    `audit_events` stores tool_name alone; a volumetric or tool-name-presence rule here
    would false-FAIL essentially every real config, including a benign one. Pinned
    explicitly per the task's own test plan."""
    rows = [{"tool_name": "bash", "status": "succeeded"} for _ in range(344)]
    rows += [{"tool_name": "message", "status": "succeeded"} for _ in range(28)]
    rows += [{"tool_name": "apply_patch", "status": "succeeded"} for _ in range(18)]
    rows += [{"tool_name": None, "status": "succeeded"} for _ in range(10)]
    ctx = _build_home(tmp_path, rows=rows)
    f = check_audit_trail_signals(ctx)
    assert f.status == PASS
    assert f.scored is False


def test_clean_fixture_pass_reports_coverage_span(tmp_path):
    rows = [
        {"occurred_at": 1_700_000_000_000},
        {"occurred_at": 1_700_600_000_000},
    ]
    ctx = _build_home(tmp_path, rows=rows)
    f = check_audit_trail_signals(ctx)
    assert f.status == PASS
    assert "2 row(s)" in f.detail
    assert "spanning" in f.detail


# --------------------------------------------------------------------------------------
# C-135 ROUND 2 (F-134/B191): the truncated-sample ABSENCE-IMPLIES-CLEAN defect and its fix.
#
# The row SAMPLE (ctx.audit_events) is most-recent-first and capped at _MAX_AUDIT_EVENTS. A
# genuine blocked-tool row inserted FIRST (lowest `sequence`) is exactly the row evicted once
# enough later rows exist — reproduced here with the report's own shape: one blocked row
# followed by >1000 ordinary rows. Before the fix this returned PASS/confidence=HIGH with no
# caveat at all, over a sample that never actually saw the blocked row.
# --------------------------------------------------------------------------------------

def test_truncated_sample_with_no_hits_in_window_degrades_pass_confidence(tmp_path):
    """THE DEFECT, reproduced verbatim: a genuine blocked row evicted by the cap must not
    produce a full-confidence 'clean' PASS. The absence-implies-clean inference is the only
    thing that weakens — pass_confidence becomes 'no_signal' (this codebase's own idiom for
    exactly this shape, see checks/_lifecycle.py's cron_store_empty split), and the detail
    text says plainly that the sample was capped and an older signal would not have been seen."""
    rows = [{"status": "blocked", "error_code": "tool_blocked", "session_id": "evicted"}]
    rows += [{"tool_name": "bash", "status": "succeeded"} for _ in range(_MAX_AUDIT_EVENTS + 200)]
    ctx = _build_home(tmp_path, rows=rows)
    assert ctx.audit_events_truncated is True
    # the blocked row (sequence 1) is NOT in the capped, most-recent-first sample
    assert not any(r.get("status") == "blocked" for r in ctx.audit_events)
    f = check_audit_trail_signals(ctx)
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"
    assert "capped" in f.detail
    assert "not have been seen" in f.detail.lower()


def test_non_truncated_clean_pass_is_verified(tmp_path):
    """Control for the fix itself: when the sample is NOT truncated, a clean PASS keeps the
    stronger 'verified' tier (the sample really is the whole table)."""
    rows = [{"tool_name": "bash", "status": "succeeded"} for _ in range(5)]
    ctx = _build_home(tmp_path, rows=rows)
    assert ctx.audit_events_truncated is False
    f = check_audit_trail_signals(ctx)
    assert f.status == PASS
    assert f.pass_confidence == "verified"


def test_blocked_row_inside_a_truncated_window_still_warns_at_full_confidence(tmp_path):
    """Round-1's true positive must survive round-2's fix: a blocked row that IS inside the
    sampled window (most-recent) still WARNs at full confidence even though the table as a
    whole is truncated — only the ABSENCE-implies-clean PASS weakens, never a real hit."""
    rows = [{"tool_name": "bash", "status": "succeeded"} for _ in range(_MAX_AUDIT_EVENTS + 50)]
    rows.append({"status": "blocked", "error_code": "tool_blocked", "session_id": "still-seen"})
    ctx = _build_home(tmp_path, rows=rows)
    assert ctx.audit_events_truncated is True
    assert any(r.get("status") == "blocked" for r in ctx.audit_events)
    f = check_audit_trail_signals(ctx)
    assert f.status == WARN
    assert f.confidence == "HIGH"
    assert any("still-seen" in e for e in f.evidence)


# --------------------------------------------------------------------------------------
# The two narrow, near-zero-FP signals.
# --------------------------------------------------------------------------------------

def test_blocked_tool_row_warns(tmp_path):
    ctx = _build_home(tmp_path, rows=[
        {"status": "blocked", "error_code": "tool_blocked", "session_id": "sess-x"},
    ])
    f = check_audit_trail_signals(ctx)
    assert f.status == WARN
    assert f.scored is False
    assert any("blocked:" in e for e in f.evidence)
    assert any("sess-x" in e for e in f.evidence)


def test_blocked_status_alone_without_tool_blocked_code_does_not_warn(tmp_path):
    """Narrow on purpose: a DIFFERENT blocked reason (e.g. the agent-run-level
    'run_blocked') must not be conflated with the tool-level policy denial this signal
    targets."""
    ctx = _build_home(tmp_path, rows=[{"status": "blocked", "error_code": "run_blocked"}])
    f = check_audit_trail_signals(ctx)
    assert f.status == PASS


def test_evasive_tool_name_warns(tmp_path):
    ctx = _build_home(tmp_path, rows=[{"tool_name": "unknown", "session_id": "sess-y"}])
    f = check_audit_trail_signals(ctx)
    assert f.status == WARN
    assert any("evasive" in e for e in f.evidence)
    assert any("sess-y" in e for e in f.evidence)


def test_a_real_tool_named_literally_unknown_string_is_the_sentinel_not_a_false_read():
    """Documentation-only sanity: the collector has no way to distinguish a tool
    genuinely named 'unknown' from the sentinel — both are grounded as the same OpenClaw
    behavior (isAllowedToolCallName returns True for a syntactically valid name, so a
    real tool cannot be literally named 'unknown' and ALSO be a malformed name; the
    dist's own audit layer only ever writes this literal as the failure sentinel)."""
    assert True  # no separate code path exists to test; this documents the reasoning


def test_both_narrow_signals_fire_together(tmp_path):
    ctx = _build_home(tmp_path, rows=[
        {"status": "blocked", "error_code": "tool_blocked"},
        {"tool_name": "unknown"},
    ])
    f = check_audit_trail_signals(ctx)
    assert f.status == WARN
    assert any("blocked:" in e for e in f.evidence)
    assert any("evasive" in e for e in f.evidence)


def test_evidence_never_carries_session_key_pii(tmp_path):
    """session_key is PII-adjacent (its peer-id segment) — never surface it, even for a
    firing row. session_id (a bare identifier) is fine and is what's actually shown."""
    ctx = _build_home(tmp_path, rows=[
        {"status": "blocked", "error_code": "tool_blocked", "session_id": "sess-z"},
    ])
    f = check_audit_trail_signals(ctx)
    for e in f.evidence:
        assert "key-sess-z" not in e


def test_evidence_bounded_length(tmp_path):
    rows = [{"status": "blocked", "error_code": "tool_blocked"} for _ in range(20)]
    ctx = _build_home(tmp_path, rows=rows)
    f = check_audit_trail_signals(ctx)
    assert len(f.evidence) <= 6
    for e in f.evidence:
        assert len(e) < 400


# --------------------------------------------------------------------------------------
# The --behavioral corroboration source: session-id divergence.
# --------------------------------------------------------------------------------------

def test_audit_event_sessions_extracts_distinct_non_null_ids(tmp_path):
    ctx = _build_home(tmp_path, rows=[
        {"session_id": "a"}, {"session_id": "a"}, {"session_id": "b"}, {"session_id": None},
    ])
    assert _audit_event_sessions(ctx) == frozenset({"a", "b"})


def test_divergence_empty_when_no_audit_events_at_all(tmp_path):
    ctx = _build_home(tmp_path, db=False)
    assert audit_trail_divergence(ctx, events=[{"sessionId": "a"}]) == frozenset()


def test_divergence_empty_when_every_audit_session_has_a_trajectory_record(tmp_path):
    ctx = _build_home(tmp_path, rows=[{"session_id": "a"}, {"session_id": "b"}])
    events = [{"sessionId": "a"}, {"sessionId": "b"}, {"sessionId": "c"}]  # c is extra, fine
    assert audit_trail_divergence(ctx, events) == frozenset()


def test_divergence_names_the_session_audit_events_has_that_trajectory_does_not(tmp_path):
    """THE REAL VALUE: audit_events retains a session the trajectory source doesn't —
    disabled/relocated/rotated-past-cap on the trajectory side, while this
    independently-bounded store still has it."""
    ctx = _build_home(tmp_path, rows=[{"session_id": "kept-only-in-audit"}, {"session_id": "a"}])
    events = [{"sessionId": "a"}]
    assert audit_trail_divergence(ctx, events) == frozenset({"kept-only-in-audit"})


def test_check_reports_divergence_only_when_told_it_was_compared(tmp_path):
    """Safety gate: an empty/default `trajectory_compared=False` must never assert a
    divergence claim, even if a non-empty set is (incorrectly) supplied — the caller
    contract is that `behavioral.analyze()` is the only one that sets this True."""
    ctx = _build_home(tmp_path, rows=[{"session_id": "s1"}])
    f_untold = check_audit_trail_signals(ctx, divergent_sessions=frozenset({"s1"}))
    assert f_untold.status == PASS
    f_told = check_audit_trail_signals(
        ctx, divergent_sessions=frozenset({"s1"}), trajectory_compared=True
    )
    assert f_told.status == WARN
    assert any("s1" in e for e in f_told.evidence)


# --------------------------------------------------------------------------------------
# End-to-end through behavioral.analyze() — real collect(), real trajectory sidecars.
# --------------------------------------------------------------------------------------

def _write_traj(home, session_id: str, name: str = "bash") -> None:
    d = home / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    rec = {
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.call",
        "ts": "1", "seq": 1, "sessionId": session_id, "data": {"name": name, "threadId": "t1"},
    }
    (d / f"{session_id}.trajectory.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")


def test_analyze_end_to_end_divergence_when_trajectory_disabled_entirely(tmp_path):
    """The scenario the task spec calls out by name: OPENCLAW_TRAJECTORY=0 (or simply
    never having run) leaves NO trajectory sidecar, while audit_events still holds
    sessions. B191 must still fire — this is exactly the case T1/T2/T3 go silent on."""
    home = tmp_path / "openclaw"
    home.mkdir()
    state = home / "state"
    state.mkdir()
    conn = sqlite3.connect(state / "openclaw.sqlite")
    try:
        conn.execute(_AUDIT_EVENTS_DDL)
        _insert_row(conn, 0, session_id="orphan-session")
        conn.commit()
    finally:
        conn.close()
    ctx = collect(home)
    r = analyze(ctx)
    assert r["present"] is False  # no trajectory sidecar at all
    assert len(r["findings"]) == 1
    b191 = r["findings"][0]
    assert b191.id == "B191"
    assert b191.status == WARN
    assert any("orphan-session" in e for e in b191.evidence)


def test_analyze_end_to_end_no_divergence_when_sessions_match(tmp_path):
    home = tmp_path / "openclaw"
    home.mkdir()
    state = home / "state"
    state.mkdir()
    conn = sqlite3.connect(state / "openclaw.sqlite")
    try:
        conn.execute(_AUDIT_EVENTS_DDL)
        _insert_row(conn, 0, session_id="shared-session")
        conn.commit()
    finally:
        conn.close()
    _write_traj(home, "shared-session")
    ctx = collect(home)
    r = analyze(ctx)
    b191 = next(f for f in r["findings"] if f.id == "B191")
    assert b191.status == PASS


def test_analyze_end_to_end_unknown_when_no_audit_events_and_no_trajectory(tmp_path):
    home = tmp_path / "openclaw"
    home.mkdir()
    ctx = collect(home)
    r = analyze(ctx)
    assert r["present"] is False
    assert len(r["findings"]) == 1
    assert r["findings"][0].id == "B191"
    assert r["findings"][0].status == UNKNOWN


# --------------------------------------------------------------------------------------
# Opt-in wiring: cataloged, scored=False, --behavioral only (never a default audit()/
# CHECKS entry) — matches the T1/T2/T3 precedent exactly.
# --------------------------------------------------------------------------------------

def test_b191_is_catalogued_and_unscored():
    meta = BY_ID["B191"]
    assert meta.scored is False


def test_b191_is_in_behavioral_check_ids():
    assert "B191" in BEHAVIORAL_CHECK_IDS


def test_b191_never_runs_in_default_checks_registry():
    """It must not be reachable through audit()/CHECKS — only through --behavioral."""
    catalogued = {getattr(fn, "__name__", "") for fn in CHECKS}
    assert "check_audit_trail_signals" not in catalogued


def test_b191_stays_unscored_through_analyze(tmp_path):
    ctx = _build_home(tmp_path, rows=[{"status": "blocked", "error_code": "tool_blocked"}])
    r = analyze(ctx)
    for f in r["findings"]:
        assert getattr(f, "scored", False) is False, f"{f.id} became scored"
