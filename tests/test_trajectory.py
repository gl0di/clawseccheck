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
    assert stats == {
        "files_total": 0, "files_capped": False,
        "pointer_targets_missing": 0, "pointer_out_of_home": 0, "pointer_invalid": 0,
        "pointer_scan_capped": False,
    }


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


# ---------------------------------------------------------------------------
# B-732: OpenClaw locates a trajectory sidecar through a POINTER file
# (<session>.trajectory-path.json), not only by the agents/*/sessions/*.trajectory.jsonl
# glob above. find_trajectory_files must union the two, confine a pointer's runtimeFile
# to the audited home (refuse+disclose an escape, never follow it), and disclose a
# pointer whose target is missing or invalid rather than silently reading as "no
# sidecars".
# ---------------------------------------------------------------------------

def _write_pointer(
    home: Path, agent: str, session: str, runtime_file, *, session_id=None,
    trace_schema="openclaw-trajectory-pointer", schema_version=1,
) -> Path:
    """Write one *.trajectory-path.json pointer, matching the vendor's own shape.
    ``session_id`` defaults to *session* (the common real-world case: the pointer's
    filename stem IS the sessionId, verified against a real pointer on this machine)."""
    d = home / "agents" / agent / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    rec = {
        "traceSchema": trace_schema,
        "schemaVersion": schema_version,
        "sessionId": session_id if session_id is not None else session,
        "runtimeFile": str(runtime_file),
    }
    p = d / f"{session}.trajectory-path.json"
    p.write_text(json.dumps(rec), encoding="utf-8")
    return p


def test_pointer_naming_a_globbed_file_is_found_once_not_twice(tmp_path):
    """Dedup: a session with BOTH a runtime file the glob already found AND a pointer
    naming that same file must not be counted twice."""
    paths = _write_many(tmp_path, "main", 1)
    _write_pointer(tmp_path, "main", "s0", paths[0])
    stats: dict = {}
    files = find_trajectory_files(tmp_path, stats=stats)
    assert len(files) == 1
    assert files[0] in (paths[0], paths[0].resolve())
    assert stats["files_total"] == 1
    assert stats["pointer_targets_missing"] == 0
    assert stats["pointer_out_of_home"] == 0
    assert stats["pointer_invalid"] == 0


def test_pointer_naming_an_unglobbed_file_is_found_via_the_pointer_alone(tmp_path):
    """The additive case the glob alone misses: a real trajectory sidecar (correctly
    suffixed) sitting in a NESTED location the flat agents/*/sessions/*.trajectory.jsonl
    glob pattern does not reach, findable only by following the pointer. Must still end
    in .trajectory.jsonl (C-135: an arbitrary in-home filename is refused -- see
    test_pointer_target_not_shaped_like_a_trajectory_file_is_rejected)."""
    d = tmp_path / "agents" / "main" / "sessions" / "archive"
    d.mkdir(parents=True, exist_ok=True)
    nested = d / "s0.trajectory.jsonl"
    nested.write_text(json.dumps(_call("bash", {})) + "\n", encoding="utf-8")
    _write_pointer(tmp_path, "main", "s0", nested)
    stats: dict = {}
    files = find_trajectory_files(tmp_path, stats=stats)
    assert nested.resolve() in files
    assert stats["pointer_invalid"] == 0


def test_pointer_target_not_shaped_like_a_trajectory_file_is_rejected(tmp_path):
    """C-135: confinement to home is not enough on its own -- a pointer naming an
    arbitrary in-home file (not ending in .trajectory.jsonl) must be refused, not
    followed, even though it is genuinely inside home and genuinely exists."""
    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    decoy = tmp_path / "credentials" / "store.json"
    decoy.parent.mkdir(parents=True, exist_ok=True)
    decoy.write_text('{"secret": "not-a-trajectory-file"}', encoding="utf-8")
    _write_pointer(tmp_path, "main", "s0", decoy)
    stats: dict = {}
    files = find_trajectory_files(tmp_path, stats=stats)
    assert files == []
    assert decoy.resolve() not in files
    assert stats["pointer_invalid"] == 1
    assert stats["files_total"] == 0


def test_a_fifo_named_as_a_pointer_is_never_opened(tmp_path):
    """C-135: the B-549 precedent (collector.py) -- a FIFO glob-matched as a pointer
    file must never be read_bytes()'d, since a FIFO with no writer blocks forever.
    is_file() (a stat, not an open) must reject it before any read is attempted. This
    test itself would hang the whole suite if the fix regressed."""
    import os

    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    fifo_path = d / "s0.trajectory-path.json"
    os.mkfifo(fifo_path)  # POSIX-only, matching this project's POSIX-only scope
    stats: dict = {}
    files = find_trajectory_files(tmp_path, stats=stats)  # must return promptly
    assert files == []
    assert stats["pointer_invalid"] == 1


def test_out_of_home_pointer_target_is_refused_not_followed(tmp_path):
    """The core security property: a pointer's runtimeFile resolving OUTSIDE the
    audited home must never be opened, and the refusal must be disclosed, not silent."""
    outside = tmp_path.parent / f"outside-{tmp_path.name}.trajectory.jsonl"
    outside.write_text(json.dumps(_call("bash", {})) + "\n", encoding="utf-8")
    try:
        _write_pointer(tmp_path, "main", "s0", outside)
        stats: dict = {}
        files = find_trajectory_files(tmp_path, stats=stats)
        assert outside.resolve() not in files
        assert files == []
        assert stats["pointer_out_of_home"] == 1
        assert stats["pointer_targets_missing"] == 0
        assert stats["pointer_invalid"] == 0
    finally:
        outside.unlink(missing_ok=True)


def test_pointer_failing_vendor_validation_is_ignored_and_disclosed(tmp_path):
    """schemaVersion/traceSchema/sessionId mismatches are exactly the vendor's own
    validation -- a pointer failing any of them is not ours to follow, but the fact
    that an unreadable/invalid pointer exists must still be counted, not silenced."""
    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    target = d / "real.trajectory.jsonl"
    target.write_text(json.dumps(_call("bash", {})) + "\n", encoding="utf-8")

    _write_pointer(tmp_path, "main", "bad-schema", target, trace_schema="something-else")
    _write_pointer(tmp_path, "main", "bad-version", target, schema_version=2)
    _write_pointer(tmp_path, "main", "bad-sessionid", target, session_id="a-different-session")
    (d / "not-json.trajectory-path.json").write_text("{not valid json", encoding="utf-8")

    stats: dict = {}
    files = find_trajectory_files(tmp_path, stats=stats)
    # `target` is real and glob-matched regardless (it ends in .trajectory.jsonl); the
    # point of this test is that NONE of the four bad pointers contributes anything,
    # and each is counted as invalid rather than silently dropped.
    assert files == [target.resolve()] or files == [target]
    assert stats["pointer_invalid"] == 4
    assert stats["pointer_targets_missing"] == 0
    assert stats["pointer_out_of_home"] == 0


def test_pointer_with_missing_target_is_disclosed_not_folded_into_no_sidecars(tmp_path):
    """The exact asymmetry measured live on a real machine (135 pointers, 0 runtime
    files -- since explained by trajectorystore.corroborate() as the 8.1-era SQLite
    migration archiving the JSONL away): a valid, in-home pointer whose target does not
    exist must surface as pointer_targets_missing, never read as "no trajectory
    sidecars" the way an empty glob alone would."""
    missing_target = tmp_path / "agents" / "main" / "sessions" / "gone.trajectory.jsonl"
    _write_pointer(tmp_path, "main", "s0", missing_target)
    stats: dict = {}
    files = find_trajectory_files(tmp_path, stats=stats)
    assert files == []
    assert stats["pointer_targets_missing"] == 1
    assert stats["pointer_out_of_home"] == 0
    assert stats["pointer_invalid"] == 0


def test_runtime_file_with_no_pointer_is_still_found(tmp_path):
    """Regression guard: the glob path must not regress when a session has a runtime
    file and genuinely no pointer at all (still the common case on most installs)."""
    paths = _write_many(tmp_path, "main", 3)
    stats: dict = {}
    files = find_trajectory_files(tmp_path, stats=stats)
    assert len(files) == 3
    for p in paths:
        assert p in files or p.resolve() in files
    assert stats["files_total"] == 3
    assert stats["pointer_targets_missing"] == 0


def test_meta_dicts_carry_the_new_pointer_keys(tmp_path):
    """read_proven_tools/read_events/read_compiled_tool_descriptions all delegate to
    find_trajectory_files and must surface its new stats, not just files_total/
    files_capped, so a downstream consumer can eventually report them."""
    from clawseccheck.trajectory import read_compiled_tool_descriptions

    missing_target = tmp_path / "agents" / "main" / "sessions" / "gone.trajectory.jsonl"
    _write_pointer(tmp_path, "main", "s0", missing_target)
    for reader in (read_proven_tools, read_events, read_compiled_tool_descriptions):
        _, meta = reader(tmp_path)
        assert meta["pointer_targets_missing"] == 1, reader.__name__
        assert meta["pointer_out_of_home"] == 0, reader.__name__
        assert meta["pointer_invalid"] == 0, reader.__name__
        assert meta["pointer_scan_capped"] is False, reader.__name__


def test_pointer_scan_is_capped_and_disclosed(tmp_path):
    """C-135: an unbounded pointer count is a DoS surface (real I/O per pointer before
    max_files ever trims the union) -- mirrors trajectorystore.py's own independent
    _MAX_POINTER_SCAN=500 cap. Uses a small monkeypatched cap so the test itself stays
    fast rather than actually writing 501 files."""
    import clawseccheck.trajectory as trajectory_mod

    d = tmp_path / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    old_cap = trajectory_mod._MAX_POINTER_SCAN
    trajectory_mod._MAX_POINTER_SCAN = 3
    try:
        for i in range(5):
            missing = d / f"gone{i}.trajectory.jsonl"
            _write_pointer(tmp_path, "main", f"s{i}", missing)
        stats: dict = {}
        find_trajectory_files(tmp_path, stats=stats)
        assert stats["pointer_scan_capped"] is True
        # Only the first 3 (the cap) were ever opened/counted -- not all 5.
        assert stats["pointer_targets_missing"] == 3
    finally:
        trajectory_mod._MAX_POINTER_SCAN = old_cap


def test_pointer_scan_interrupted_by_oserror_is_also_disclosed(tmp_path):
    """C-135: a directory going unreadable MID-enumeration (permission change,
    concurrent removal) must be disclosed the same way hitting the count cap is --
    not silently treated as 'the scan was clean and found nothing more'."""
    missing = tmp_path / "agents" / "main" / "sessions" / "gone.trajectory.jsonl"
    _write_pointer(tmp_path, "main", "s0", missing)

    real_glob = Path.glob

    def _raising_glob(self, pattern):
        if pattern.endswith(".trajectory-path.json"):
            def _gen():
                yield from real_glob(self, pattern)
                raise OSError("simulated mid-scan failure")
            return _gen()
        return real_glob(self, pattern)

    import unittest.mock

    with unittest.mock.patch.object(Path, "glob", _raising_glob):
        stats: dict = {}
        files = find_trajectory_files(tmp_path, stats=stats)
    assert files == []
    assert stats["pointer_scan_capped"] is True
    assert stats["pointer_targets_missing"] == 1  # the one pointer seen before the raise


def test_safe_trajectory_session_file_name_matches_the_installed_dist():
    """Local-only differential: executes the REAL vendor function (paths-*.mjs,
    safeTrajectorySessionFileName) if OpenClaw is installed, over the same 8 cases the
    in-source port was verified against, so the port cannot silently drift from a future
    dist without this test noticing."""
    import shutil
    import subprocess

    import pytest

    from clawseccheck.trajectory import _safe_trajectory_session_file_name

    exe = shutil.which("openclaw")
    if not exe:
        pytest.skip("no installed OpenClaw — differential is local-only")
    here = Path(os.path.realpath(exe)).parent
    root = None
    for candidate in (here, *here.parents):
        if (candidate / "dist").is_dir():
            root = candidate
            break
    if root is None:
        pytest.skip("could not locate the OpenClaw dist root")
    bundles = list((root / "dist").glob("paths-*.mjs")) + list((root / "dist").glob("paths-*.js"))
    matches = [p for p in bundles if "TRAJECTORY_POINTER_FILE_MAX_BYTES" in
               p.read_text(encoding="utf-8", errors="replace")]
    if not matches:
        pytest.skip("no paths-*.mjs bundle declares TRAJECTORY_POINTER_FILE_MAX_BYTES "
                     "— renamed, re-locate before trusting this citation")
    cases = [
        "02258d00-eaa3-4586-b23b-885df1e714ba", "", "!!!", "a" * 200,
        "héllo wörld", "../../etc/passwd", "session with spaces", "UPPER_lower-123",
    ]
    script = """
const mod = await import(process.env.OC_MOD);
const fn = mod.s ?? mod.safeTrajectorySessionFileName;
const cases = JSON.parse(process.env.OC_CASES);
console.log(JSON.stringify(cases.map(fn)));
"""
    env = dict(os.environ, OC_MOD=str(matches[0]), OC_CASES=json.dumps(cases))
    proc = subprocess.run(["node", "--input-type=module", "-e", script],
                           capture_output=True, text=True, timeout=60, env=env)
    if proc.returncode != 0:
        pytest.skip(f"could not execute the dist module: {proc.stderr.strip()[:200]}")
    expected = json.loads(proc.stdout)
    actual = [_safe_trajectory_session_file_name(c) for c in cases]
    assert actual == expected, list(zip(cases, actual, expected, strict=True))
