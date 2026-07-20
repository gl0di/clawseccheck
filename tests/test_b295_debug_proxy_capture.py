"""B-295 (DISK-4) — the OPENCLAW_DEBUG_PROXY_* env cluster and on-disk traffic capture (B190).

FILED NARROWED. The original DISK-4 claim double-counted B164 and mis-stated the enablement
gate; these tests pin the corrected scope.

ALREADY COVERED BY B164 (not re-filed, not re-scanned here): the ``cache-trace.jsonl`` FILE
sink. ``logdiscovery`` finds it from ``diagnostics.cacheTrace.filePath`` AND from the
conventional ``logs/cache-trace.jsonl`` (not gated on ``enabled``), and ``logscan``
content-scans it with the vetted detectors.

GENUINELY UNCOVERED, and what B190 adds: debug-proxy capture is a different subsystem with
NO config field — enablement is env-only (``env-DNgUBPBb.js``: ``isTruthy(env
.OPENCLAW_DEBUG_PROXY_ENABLED)`` where ``isTruthy(v) === v === "1" || "true" || "yes" ||
"on"``) — and its rows live in SQLite tables that logdiscovery's file-path sink model
structurally cannot reach.

STILL NOT DONE, asserted below: B190 does not mine captured traffic. Counts only.
"""
from __future__ import annotations

import sqlite3

import pytest

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_debug_proxy_capture
from clawseccheck.collector import Context, _collect_capture_state, _collect_global_dotenv

# Column list copied verbatim from the dist CREATE TABLE so the fixture cannot drift.
_CAPTURE_EVENTS_DDL = (
    "CREATE TABLE capture_events (id INTEGER NOT NULL PRIMARY KEY, session_id TEXT NOT NULL, "
    "ts INTEGER NOT NULL, source_scope TEXT NOT NULL, source_process TEXT NOT NULL, "
    "protocol TEXT NOT NULL, direction TEXT NOT NULL, kind TEXT NOT NULL, "
    "flow_id TEXT NOT NULL, method TEXT, host TEXT, path TEXT, status INTEGER, "
    "close_code INTEGER, content_type TEXT, headers_json TEXT, data_text TEXT, "
    "data_blob_id TEXT, data_sha256 TEXT, error_text TEXT, meta_json TEXT)"
)
_CAPTURE_BLOBS_DDL = (
    "CREATE TABLE capture_blobs (blob_id TEXT NOT NULL PRIMARY KEY, content_type TEXT, "
    "encoding TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, "
    "data BLOB NOT NULL, created_at INTEGER NOT NULL)"
)

# Secret-shaped test values are assembled from fragments so no contiguous literal exists in
# source (CLAUDE.md §2 rule 3 / tests/test_logsafe.py precedent).
_FAKE_BEARER = "Bearer " + "sk-" + "live" + "9" * 20
_FAKE_HEADERS = '{"authorization": "' + _FAKE_BEARER + '"}'
_FAKE_BODY = "password=" + "hunter" + "2" * 8


def _ctx(tmp_path, *, events=0, blobs=0, tables=True, db=True, env=None):
    home = tmp_path / "openclaw"
    home.mkdir(parents=True, exist_ok=True)
    if db:
        state = home / "state"
        state.mkdir(exist_ok=True)
        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            if tables:
                conn.execute(_CAPTURE_EVENTS_DDL)
                conn.execute(_CAPTURE_BLOBS_DDL)
                for i in range(events):
                    conn.execute(
                        "INSERT INTO capture_events (id, session_id, ts, source_scope, "
                        "source_process, protocol, direction, kind, flow_id, host, "
                        "headers_json, data_text) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (i, "s1", 1, "openclaw", "openclaw", "https", "out", "req",
                         f"f{i}", "api.example.test", _FAKE_HEADERS, _FAKE_BODY),
                    )
                for i in range(blobs):
                    conn.execute(
                        "INSERT INTO capture_blobs VALUES (?,?,?,?,?,?,?)",
                        (f"b{i}", "application/json", "utf8", 10, "deadbeef", b"x", 1),
                    )
            else:
                conn.execute("CREATE TABLE unrelated (x INTEGER)")
            conn.commit()
        finally:
            conn.close()
    if env:
        (home / ".env").write_text(
            "\n".join(f"{k}={v}" for k, v in env.items()) + "\n", encoding="utf-8"
        )
    ctx = Context(home=home)
    # Read ~/.openclaw/.env through the REAL global-dotenv collector, so these tests exercise
    # the same persistent-delivery path the audit uses rather than a hand-stuffed dict.
    _collect_global_dotenv(home, ctx)
    _collect_capture_state(home, ctx)
    return ctx


# --------------------------------------------------------------------------------------
# Scope: the narrowing is explicit and asserted, not just claimed in prose.
# --------------------------------------------------------------------------------------

def test_b190_is_advisory_and_never_fail_capable():
    """A developer legitimately running the debug proxy captures benign traffic (provider
    APIs, ClawHub). Flagging those hosts as 'exfil' would be a false FAIL, so B190 is
    WARN-only and scored=False — it can never move the A-F grade."""
    meta = BY_ID["B190"]
    assert meta.scored is False


def test_b190_does_not_rescan_the_cache_trace_file(tmp_path):
    """B164 already discovers and content-scans logs/cache-trace.jsonl. B190 must not
    re-file that work: a cache-trace file alone is not a B190 signal."""
    ctx = _ctx(tmp_path)
    logs = ctx.home / "logs"
    logs.mkdir()
    (logs / "cache-trace.jsonl").write_text('{"host": "evil.test"}\n', encoding="utf-8")
    assert check_debug_proxy_capture(ctx).status == UNKNOWN


# --------------------------------------------------------------------------------------
# The env cluster — the only static evidence of enablement, since no config field exists.
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE", "On"])
def test_enablement_truthy_values_fire(tmp_path, value):
    """isTruthy(v) === v === "1" || "true" || "yes" || "on" (env-DNgUBPBb.js), matched
    case-insensitively by collector.is_truthy_env_value."""
    ctx = _ctx(tmp_path, env={"OPENCLAW_DEBUG_PROXY_ENABLED": value})
    f = check_debug_proxy_capture(ctx)
    assert f.status == WARN
    assert "OPENCLAW_DEBUG_PROXY_ENABLED" in " ".join(f.evidence)


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_enablement_falsy_values_do_not_fire(tmp_path, value):
    ctx = _ctx(tmp_path, env={"OPENCLAW_DEBUG_PROXY_ENABLED": value})
    assert check_debug_proxy_capture(ctx).status == UNKNOWN


def test_proxy_url_is_flagged_as_a_mitm_surface(tmp_path):
    """The secondary, arguably higher-value finding: OPENCLAW_DEBUG_PROXY_URL routes all
    agent traffic through an arbitrary proxy."""
    ctx = _ctx(tmp_path, env={"OPENCLAW_DEBUG_PROXY_URL": "http://127.0.0.1:8888"})
    f = check_debug_proxy_capture(ctx)
    assert f.status == WARN
    assert "man-in-the-middle" in f.detail


def test_proxy_url_value_is_never_echoed(tmp_path):
    """A proxy URL can embed credentials (http://user:pass@host), so the VALUE must never
    reach the report — naming the variable and its source is enough (§8)."""
    secret = "pa" + "ssw0rd" + "XYZ"
    ctx = _ctx(tmp_path, env={"OPENCLAW_DEBUG_PROXY_URL": f"http://user:{secret}@evil.test"})
    f = check_debug_proxy_capture(ctx)
    blob = f.detail + f.fix + " ".join(f.evidence)
    assert secret not in blob
    assert "evil.test" not in blob


def test_db_path_redirect_is_flagged(tmp_path):
    ctx = _ctx(tmp_path, env={"OPENCLAW_DEBUG_PROXY_DB_PATH": "/tmp/elsewhere.sqlite"})
    f = check_debug_proxy_capture(ctx)
    assert f.status == WARN
    assert "OPENCLAW_DEBUG_PROXY_DB_PATH" in " ".join(f.evidence)


def test_require_toggle_is_flagged(tmp_path):
    ctx = _ctx(tmp_path, env={"OPENCLAW_DEBUG_PROXY_REQUIRE": "1"})
    assert check_debug_proxy_capture(ctx).status == WARN


# --------------------------------------------------------------------------------------
# The sqlite half — counts only.
# --------------------------------------------------------------------------------------

def test_populated_capture_tables_warn(tmp_path):
    ctx = _ctx(tmp_path, events=3, blobs=2)
    assert ctx.capture_event_rows == 3
    assert ctx.capture_blob_rows == 2
    f = check_debug_proxy_capture(ctx)
    assert f.status == WARN
    assert "3 captured request/response flow" in " ".join(f.evidence)


def test_captured_content_never_reaches_the_report(tmp_path):
    """§8 is load-bearing: headers_json carries bearer tokens and data_text carries request
    bodies. The collector reads COUNT(*) and nothing else, so no captured byte — not even a
    redacted excerpt — can appear in the finding or on the Context."""
    ctx = _ctx(tmp_path, events=2)
    f = check_debug_proxy_capture(ctx)
    blob = f.detail + f.fix + " ".join(f.evidence)
    for leaked in (_FAKE_BEARER, _FAKE_HEADERS, _FAKE_BODY, "api.example.test"):
        assert leaked not in blob
    # And nothing content-bearing was even collected onto the Context.
    assert not hasattr(ctx, "capture_hosts")
    assert not hasattr(ctx, "capture_samples")


def test_collector_reads_counts_only(tmp_path):
    ctx = _ctx(tmp_path, events=5, blobs=1)
    assert (ctx.capture_event_rows, ctx.capture_blob_rows) == (5, 1)
    assert ctx.capture_tables_found is True
    assert ctx.capture_parse_error is False


def test_collector_never_writes_to_the_state_db(tmp_path):
    ctx = _ctx(tmp_path, events=2)
    db = ctx.home / "state" / "openclaw.sqlite"
    before = db.read_bytes()
    check_debug_proxy_capture(ctx)
    assert db.read_bytes() == before


# --------------------------------------------------------------------------------------
# UNKNOWN — and the explicit refusal to ever emit an all-clear.
# --------------------------------------------------------------------------------------

def test_empty_capture_tables_are_unknown_never_pass(tmp_path):
    """The real-box state (tables live, rows=0). Zero rows is NOT proof capture is off:
    enablement is env-only, a shell export leaves no on-disk trace, and
    OPENCLAW_DEBUG_PROXY_DB_PATH can point capture at a database never counted here."""
    f = check_debug_proxy_capture(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert "NOT an all-clear" in f.detail


def test_no_capture_tables_is_unknown(tmp_path):
    f = check_debug_proxy_capture(_ctx(tmp_path, tables=False))
    assert f.status == UNKNOWN
    assert "NO config field" in f.detail


def test_no_state_db_at_all_is_unknown(tmp_path):
    f = check_debug_proxy_capture(_ctx(tmp_path, db=False))
    assert f.status == UNKNOWN


def test_b190_never_returns_pass_on_any_input(tmp_path):
    """Pinned invariant: B190 has NO pass branch by design. There is no static evidence that
    could affirm capture is off, so an affirmative all-clear would be a lie."""
    for kwargs in (
        {}, {"tables": False}, {"db": False}, {"events": 1},
        {"env": {"OPENCLAW_DEBUG_PROXY_ENABLED": "1"}},
        {"env": {"OPENCLAW_DEBUG_PROXY_ENABLED": "0"}},
    ):
        f = check_debug_proxy_capture(_ctx(tmp_path / str(abs(hash(str(kwargs)))), **kwargs))
        assert f.status in (WARN, UNKNOWN)
        assert f.status not in (PASS, FAIL)
