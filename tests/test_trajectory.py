"""Trajectory-sidecar reader (log-observed proven tool use) — read-only, name-only.

Grounded schema: docs/research/openclaw-schema-recon.md §9.1. The reader extracts the
set of tool verbs from tool.call records' data.name, gated on
traceSchema=openclaw-trajectory / schemaVersion=1, and NEVER reads call/return payloads.

Offline, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.trajectory import find_trajectory_files, read_events, read_proven_tools


def _write_traj(home: Path, session: str, records: list[dict]) -> None:
    d = home / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(json.dumps(r) for r in records) + "\n"
    (d / f"{session}.trajectory.jsonl").write_text(lines, encoding="utf-8")


def _call(name: str, arguments: dict) -> dict:
    return {
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.call",
        "ts": "2026-07-03T00:00:00Z", "seq": 1, "sessionId": "s",
        "data": {"name": name, "arguments": arguments, "toolCallId": "c1"},
    }


def _write_many(home: Path, agent: str, n: int) -> list[Path]:
    """Write *n* minimal, distinctly-timestamped trajectory sidecars — one per
    synthetic session — so find_trajectory_files' newest-first mtime sort has a
    deterministic order to cap against (B-245)."""
    d = home / "agents" / agent / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    base = 1_700_000_000
    paths = []
    for i in range(n):
        rec = _call(f"tool_{i}", {})
        p = d / f"s{i}.trajectory.jsonl"
        p.write_text(json.dumps(rec) + "\n", encoding="utf-8")
        os.utime(p, (base + i, base + i))
        paths.append(p)
    return paths


def test_reader_missing_home_is_empty(tmp_path):
    verbs, meta = read_proven_tools(tmp_path / "nope")
    assert verbs == set()
    assert meta["present"] is False


def test_reader_extracts_tool_call_names(tmp_path):
    _write_traj(tmp_path, "sess1", [
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1,
         "type": "session.started", "data": {}},
        _call("bash", {"command": "ls"}),
        _call("web_search", {"q": "x"}),
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1,
         "type": "tool.result", "data": {"name": "bash", "status": "completed"}},
    ])
    verbs, meta = read_proven_tools(tmp_path)
    assert verbs == {"bash", "web_search"}
    assert meta["present"] is True and meta["files_scanned"] == 1
    assert meta["unknown_version"] is False


def test_reader_never_returns_argument_payloads(tmp_path):
    # A secret-shaped value assembled from fragments so no contiguous literal exists (§2.3).
    secret = "sk-" + "live" + "".join(["A"] * 20)
    _write_traj(tmp_path, "sess1", [_call("bash", {"command": "curl -H " + secret})])
    verbs, _ = read_proven_tools(tmp_path)
    assert verbs == {"bash"}
    # The reader returns tool identities only — no payload text ever leaves data.arguments.
    assert all(secret not in v for v in verbs)


def test_reader_version_gate_rejects_unknown_schema(tmp_path):
    rec = _call("bash", {"command": "ls"})
    rec["schemaVersion"] = 2  # unrecognised format — must NOT be trusted
    _write_traj(tmp_path, "sess1", [rec])
    verbs, meta = read_proven_tools(tmp_path)
    assert verbs == set()
    assert meta["unknown_version"] is True


def test_reader_ignores_wrong_trace_schema(tmp_path):
    rec = _call("bash", {"command": "ls"})
    rec["traceSchema"] = "something-else"
    _write_traj(tmp_path, "sess1", [rec])
    verbs, _ = read_proven_tools(tmp_path)
    assert verbs == set()


def test_reader_skips_malformed_lines(tmp_path):
    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True)
    good = json.dumps(_call("bash", {"command": "ls"}))
    (d / "s.trajectory.jsonl").write_text(
        'not json but mentions "tool.call"\n' + good + "\n", encoding="utf-8"
    )
    verbs, _ = read_proven_tools(tmp_path)
    assert verbs == {"bash"}


# ---------------------------------------------------------------------------
# read_events (F-107) — §8-safe event metadata for the behavioral engine
# ---------------------------------------------------------------------------

def _result(name: str, *, status=None, is_error=None, success=None, thread=None, turn=None):
    data = {"name": name, "toolCallId": "c1"}
    if status is not None:
        data["status"] = status
    if is_error is not None:
        data["isError"] = is_error
    if success is not None:
        data["success"] = success
    if thread is not None:
        data["threadId"] = thread
    if turn is not None:
        data["turnId"] = turn
    return {
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.result",
        "ts": "2026-07-03T00:00:01Z", "seq": 2, "data": data,
    }


def test_read_events_missing_home_is_empty(tmp_path):
    events, meta = read_events(tmp_path / "nope")
    assert events == []
    assert meta["present"] is False


def test_read_events_tool_call_and_result(tmp_path):
    _write_traj(tmp_path, "sess1", [
        {**_call("bash", {"command": "ls"}), "data": {
            "name": "bash", "arguments": {"command": "ls"}, "turnId": "t1", "threadId": "th1",
        }},
        _result("bash", status="completed", thread="th1", turn="t1"),
    ])
    events, meta = read_events(tmp_path)
    assert meta["present"] is True and meta["files_scanned"] == 1
    assert len(events) == 2
    call, result = events
    assert call["type"] == "tool.call" and call["name"] == "bash"
    assert call["turnId"] == "t1" and call["threadId"] == "th1"
    assert call["outcome"] is None  # only tool.result carries an outcome
    assert result["type"] == "tool.result" and result["outcome"] == "success"


def test_read_events_outcome_classification():
    from clawseccheck.trajectory import _event_outcome
    assert _event_outcome("tool.result", {"status": "failed"}) == "failed"
    assert _event_outcome("tool.result", {"isError": True}) == "failed"
    assert _event_outcome("tool.result", {"success": False}) == "failed"
    assert _event_outcome("tool.result", {"status": "completed"}) == "success"
    assert _event_outcome("tool.result", {"success": True}) == "success"
    assert _event_outcome("tool.result", {}) is None  # ambiguous — never guessed
    assert _event_outcome("tool.call", {"status": "failed"}) is None  # wrong type


def test_read_events_never_returns_argument_or_result_payloads(tmp_path):
    secret = "sk-" + "live" + "".join(["A"] * 20)
    _write_traj(tmp_path, "sess1", [
        _call("bash", {"command": "curl -H " + secret}),
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.result",
         "ts": "t", "seq": 2, "data": {"name": "bash", "status": "completed", "output": secret}},
    ])
    events, _ = read_events(tmp_path)
    blob = json.dumps(events)
    assert secret not in blob


def test_read_events_version_gate_rejects_unknown_schema(tmp_path):
    rec = _call("bash", {"command": "ls"})
    rec["schemaVersion"] = 2
    _write_traj(tmp_path, "sess1", [rec])
    events, meta = read_events(tmp_path)
    assert events == []
    assert meta["unknown_version"] is True


def test_read_events_prompt_submitted_has_no_name(tmp_path):
    _write_traj(tmp_path, "sess1", [
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1,
         "type": "prompt.submitted", "ts": "t", "seq": 1, "data": {"turnId": "t1"}},
    ])
    events, _ = read_events(tmp_path)
    assert len(events) == 1
    assert events[0]["type"] == "prompt.submitted"
    assert events[0]["name"] is None


def test_read_events_ignores_unrecognised_event_types(tmp_path):
    _write_traj(tmp_path, "sess1", [
        {"traceSchema": "openclaw-trajectory", "schemaVersion": 1,
         "type": "model.completed", "ts": "t", "seq": 1, "data": {}},
        _call("bash", {"command": "ls"}),
    ])
    events, _ = read_events(tmp_path)
    assert len(events) == 1
    assert events[0]["type"] == "tool.call"


def test_read_events_explicit_path(tmp_path):
    _write_traj(tmp_path, "sess1", [_call("bash", {"command": "ls"})])
    path = tmp_path / "agents" / "main" / "sessions" / "sess1.trajectory.jsonl"
    events, meta = read_events(tmp_path / "unused", explicit_path=str(path))
    assert meta["present"] is True
    assert len(events) == 1


def test_read_events_explicit_path_missing_file_is_empty(tmp_path):
    events, meta = read_events(tmp_path, explicit_path=str(tmp_path / "nope.jsonl"))
    assert events == []
    assert meta["present"] is False


# ---------------------------------------------------------------------------
# B-245 — per-FILE cap (_MAX_FILES) disclosure: the per-byte cap has been
# disclosed (`truncated`, C-180) since it was added, but the per-file cap
# silently dropped the oldest sessions with no signal at all. find_trajectory_files'
# `stats` out-param and read_proven_tools/read_events' `files_total`/`files_capped`
# meta fields close that gap — mirrors safeio.walk_dir_safely's `capped` (B-244).
# ---------------------------------------------------------------------------

def test_find_trajectory_files_stats_missing_home(tmp_path):
    stats: dict = {}
    files = find_trajectory_files(tmp_path / "nope", stats=stats)
    assert files == []
    assert stats == {"files_total": 0, "files_capped": False}


def test_find_trajectory_files_stats_not_capped_at_max(tmp_path):
    _write_many(tmp_path, "main", 60)
    stats: dict = {}
    files = find_trajectory_files(tmp_path, max_files=60, stats=stats)
    assert len(files) == 60
    assert stats["files_total"] == 60
    assert stats["files_capped"] is False


def test_find_trajectory_files_stats_capped_over_max(tmp_path):
    _write_many(tmp_path, "main", 61)
    stats: dict = {}
    files = find_trajectory_files(tmp_path, max_files=60, stats=stats)
    assert len(files) == 60
    assert stats["files_total"] == 61
    assert stats["files_capped"] is True
    # newest-first: the 61 mtimes are base..base+60, so the dropped file is the
    # very oldest one (s0) — the returned set must be the 60 newest, not it.
    assert (tmp_path / "agents" / "main" / "sessions" / "s0.trajectory.jsonl") not in files


def test_find_trajectory_files_no_stats_arg_unaffected(tmp_path):
    # Default (no `stats`) must keep the original return-type/behaviour for every
    # existing caller (incident.py, logdiscovery.py, trajaudit.py, checks/_host.py).
    _write_many(tmp_path, "main", 3)
    files = find_trajectory_files(tmp_path)
    assert len(files) == 3


def test_find_trajectory_files_broken_symlink_does_not_corrupt_order(tmp_path):
    # B-245 false-positive fix: a single unreadable path (here, a dangling
    # symlink — e.g. a session archived to cold storage and left dangling) used
    # to abort list.sort()'s single try/except entirely, leaving `files` in
    # arbitrary glob order. `files[:max_files]` then dropped an arbitrary subset
    # while the caller-facing message claims only the OLDEST sessions were
    # skipped. The per-path mtime lookup must isolate that one failure so every
    # real session still sorts by its true mtime and the newest N are the ones
    # actually returned.
    paths = _write_many(tmp_path, "main", 65)
    sessions_dir = tmp_path / "agents" / "main" / "sessions"
    (sessions_dir / "zz_archived.trajectory.jsonl").symlink_to(
        "sessions/moved_to_nas.trajectory.jsonl"
    )
    stats: dict = {}
    files = find_trajectory_files(tmp_path, max_files=60, stats=stats)
    assert stats["files_total"] == 66
    assert stats["files_capped"] is True
    assert len(files) == 60
    # The 5 newest real sessions must all be present...
    for p in paths[-5:]:
        assert p in files
    # ...and the 5 oldest real sessions must all be absent — not an arbitrary
    # subset that happens to include a recent one instead.
    for p in paths[:5]:
        assert p not in files


def test_find_trajectory_files_disappearing_file_does_not_corrupt_order(tmp_path):
    # Same failure mode, second real-world trigger: a live agent rotates/prunes a
    # session file between the glob() and the sort() (the normal state during an
    # in-agent audit run, not an edge case).
    paths = _write_many(tmp_path, "main", 65)
    victim = paths[30]

    real_stat = Path.stat

    def flaky_stat(self, *a, **kw):
        if self == victim:
            victim.unlink()
            raise FileNotFoundError(victim)
        return real_stat(self, *a, **kw)

    Path.stat = flaky_stat
    try:
        stats: dict = {}
        files = find_trajectory_files(tmp_path, max_files=60, stats=stats)
    finally:
        Path.stat = real_stat

    assert stats["files_capped"] is True
    assert len(files) == 60
    assert victim not in files
    # The 5 newest real sessions must still be intact and returned — not
    # silently swapped out for an arbitrary older file.
    for p in paths[-5:]:
        assert p in files


def test_read_proven_tools_meta_capped_over_max_files(tmp_path):
    _write_many(tmp_path, "main", 61)
    verbs, meta = read_proven_tools(tmp_path, max_files=60)
    assert meta["files_total"] == 61
    assert meta["files_capped"] is True
    assert meta["files_scanned"] == 60


def test_read_proven_tools_meta_not_capped_at_max_files(tmp_path):
    _write_many(tmp_path, "main", 60)
    verbs, meta = read_proven_tools(tmp_path, max_files=60)
    assert meta["files_total"] == 60
    assert meta["files_capped"] is False
    assert meta["files_scanned"] == 60


def test_read_proven_tools_meta_no_sidecar_is_uncapped(tmp_path):
    verbs, meta = read_proven_tools(tmp_path / "nope")
    assert meta["files_total"] == 0
    assert meta["files_capped"] is False


def test_read_events_meta_capped_over_max_files(tmp_path):
    _write_many(tmp_path, "main", 61)
    events, meta = read_events(tmp_path, max_files=60)
    assert meta["files_total"] == 61
    assert meta["files_capped"] is True
    assert meta["files_scanned"] == 60


def test_read_events_meta_not_capped_at_max_files(tmp_path):
    _write_many(tmp_path, "main", 60)
    events, meta = read_events(tmp_path, max_files=60)
    assert meta["files_total"] == 60
    assert meta["files_capped"] is False


def test_read_events_explicit_path_files_total_and_not_capped(tmp_path):
    _write_traj(tmp_path, "sess1", [_call("bash", {"command": "ls"})])
    path = tmp_path / "agents" / "main" / "sessions" / "sess1.trajectory.jsonl"
    events, meta = read_events(tmp_path / "unused", explicit_path=str(path))
    assert meta["files_total"] == 1
    assert meta["files_capped"] is False


# ---------------------------------------------------------------------------
# B-298 — session ORIGIN bucketing. `sessionKey` is on 100% of real trajectory
# records and was never read by anything in the package; it is the only field that
# says WHERE a session came from, which no tool verb name can express.
#
# Shapes are grounded in the installed dist, not invented: `parseAgentSessionKey`
# (`agent:<agentId>:<rest>`), `buildAgentPeerSessionKey`
# (`<channel>:<peerKind>:<peerId>`, `<channel>:<accountId>:direct:<peerId>`,
# `direct:<peerId>`), `buildDashboardSessionKey` (`dashboard:<uuid>`),
# `buildAgentMainSessionKey` (`main`), and the `cron:`/`subagent:`/`acp:`/
# `explicit:`/`voice:`/`boot` prefixes.
# ---------------------------------------------------------------------------

# (session_key, expected_kind, expected_channel) — one row per grounded shape, so this
# asserts the INVARIANT across the whole shape matrix rather than one spelling.
_ORIGIN_MATRIX = [
    # external, multi-party peer kinds — the only ones a detector may arm ingress on
    ("agent:main:telegram:group:g-1", "group", "telegram"),
    ("agent:main:discord:channel:c-1", "channel", "discord"),
    ("agent:main:unknown:group:legacy-1", "group", "unknown"),   # legacy remap shape
    ("agent:main:matrix:GROUP:g-1", "group", "matrix"),          # case-insensitive kind
    # 1:1 DM shapes — all three dmScope spellings fold to "direct"
    ("agent:main:telegram:direct:p-1", "direct", "telegram"),
    ("agent:main:telegram:acct7:direct:p-1", "direct", "telegram"),
    ("agent:main:slack:dm:p-1", "direct", "slack"),
    ("agent:main:direct:p-1", "direct", None),
    # non-peer surfaces
    ("agent:main:dashboard:0000-uuid", "dashboard", None),
    ("agent:main:main", "main", None),
    ("agent:main:global", "global", None),
    ("agent:main:cron:job1:run:r1", "cron", None),
    ("agent:main:subagent:abc", "subagent", None),
    ("agent:main:acp:abc", "acp", None),
    ("agent:main:explicit:sess-1", "explicit", None),
    ("agent:main:voice:call:1", "voice", None),
    ("agent:main:boot", "boot", None),
    # a parseable key of an unrecognised shape (e.g. a custom session.mainKey)
    ("agent:main:my-custom-main-key", "other", None),
]


def test_parse_session_origin_matrix():
    from clawseccheck.trajectory import parse_session_origin

    for key, kind, channel in _ORIGIN_MATRIX:
        assert parse_session_origin(key) == (kind, channel), key


def test_parse_session_origin_unparseable_is_unknown_not_a_guess():
    """§4: an absent / malformed / non-agent-scoped key reports UNKNOWN (None), never a
    fabricated origin. A detector must then leave its leg unarmed."""
    from clawseccheck.trajectory import parse_session_origin

    for key in (None, "", "   ", 12, ["agent", "main", "x"], "agent:main", "agent:main:",
                "agent::telegram:group:g-1", "telegram:group:g-1", "notagent:a:b"):
        assert parse_session_origin(key) == (None, None), repr(key)


def test_parse_session_origin_never_returns_the_peer_id():
    """§8: the peer-id segment of a real session key is PII (a live host's key embeds a
    Telegram user id). Only the bucketed KIND and the channel id may escape."""
    from clawseccheck.trajectory import parse_session_origin

    peer = "3076" + "15315"
    for key in (
        f"agent:main:telegram:direct:{peer}",
        f"agent:main:telegram:acct7:direct:{peer}",
        f"agent:main:telegram:group:{peer}",
        f"agent:main:direct:{peer}",
        f"agent:main:dashboard:{peer}",
    ):
        assert peer not in "|".join(str(v) for v in parse_session_origin(key)), key


def test_read_events_surfaces_origin_kind_and_channel(tmp_path):
    rec = _call("bash", {"command": "ls"})
    rec["sessionKey"] = "agent:main:telegram:group:g-1"
    _write_traj(tmp_path, "sess1", [rec])
    events, _ = read_events(tmp_path)
    assert events[0]["origin"] == "group"
    assert events[0]["originChannel"] == "telegram"


def test_read_events_origin_is_none_when_session_key_absent(tmp_path):
    """UNKNOWN path: pre-B-298 fixtures (and any record without a sessionKey) report
    origin None — no affirmative claim either way."""
    _write_traj(tmp_path, "sess1", [_call("bash", {"command": "ls"})])
    events, _ = read_events(tmp_path)
    assert events[0]["origin"] is None
    assert events[0]["originChannel"] is None


def test_read_events_never_leaks_the_session_key_peer_id(tmp_path):
    """§8 end-to-end: the raw sessionKey (peer id included) must not reach the event
    dicts the behavioral engine and its findings are built from."""
    peer = "3076" + "15315"
    rec = _call("bash", {"command": "ls"})
    rec["sessionKey"] = f"agent:main:telegram:direct:{peer}"
    _write_traj(tmp_path, "sess1", [rec])
    events, _ = read_events(tmp_path)
    blob = json.dumps(events)
    assert peer not in blob
    assert "sessionKey" not in blob
    assert events[0]["origin"] == "direct"


def test_parse_session_origin_c135_near_misses_do_not_bucket_as_external():
    """C-135 adversarial pass (B-298): the ONLY thing allowed to bucket as an external
    group/channel origin is the literal peer-kind token followed by a peer id. These are
    the near-misses probed while trying to make the ingress leg fire wrongly — a bare
    kind token with no peer id, a substring, a plural, and every real non-peer key
    observed on a live host. Each must bucket as something T1 never arms."""
    from clawseccheck.trajectory import EXTERNAL_ORIGIN_KINDS, parse_session_origin

    near_misses = [
        "agent:main:telegram:group",          # kind token, but NO peer id after it
        "agent:main:group",                   # bare token in the surface slot
        "agent:main:channel",
        "agent:main:grouping:x:y",            # substring, not the token
        "agent:main:x:groups:y",              # plural, not the token
        "agent:main:verification-model-picker",   # real custom key seen on a live host
        "agent:main:workboard-default-card",
        "agent:main:heartbeat-recovered-20260720",
        "agent:main:dashboard:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "agent:main:cron:nightly:run:r1",
    ]
    for key in near_misses:
        kind, _ = parse_session_origin(key)
        assert kind not in EXTERNAL_ORIGIN_KINDS, key
