"""CLAWSECCHECK-C-643 -- B172 reads the exec-approvals store OpenClaw actually uses.

Current OpenClaw builds keep exec approvals in ONE row of the shared state database
(``state/openclaw.sqlite``, table ``exec_approvals_config``, ``config_key = 'current'``,
``raw_json`` holding the same ``{version, socket, defaults, agents}`` document the legacy
``~/.openclaw/exec-approvals.json`` held). B172 read only the file, so on a current build it
answered UNKNOWN ("No exec-approvals.json store found ...") about a store that exists and
may hold standing "allow-always" grants.

Grounded against the installed dist (2026.9.7, state schema v19) by SYMBOL in
``src/infra/exec-approvals-sqlite.ts`` (``EXEC_APPROVALS_CONFIG_KEY``,
``readExecApprovalsConfigRow``, ``snapshotFromExecApprovalsRow``, ``projectionValues``) and
``src/infra/exec-approvals-config.ts`` (``persistedExecApprovalsSchema``: ``version`` is
``literal(1)``; ``normalizePersistedAllowlistSource`` keeps ONLY the exact literal
``"allow-always"``). The count columns of the table cannot answer B172's question (they tally
every allowlist entry, and a manual entry has no ``source``), so ``raw_json`` is parsed in
memory for its counts only; these tests pin that nothing else about it is retained.

The test that must fail if the fix is reverted is
``test_sqlite_only_home_with_an_allow_always_grant_warns``: on the old code that home is
reported UNKNOWN.

Read-only fixtures use a rollback-journal database on purpose: ``mode=ro`` on a WAL-mode
database may create/rewrite the ``-shm``/``-wal`` sidecars (B-909, module-wide, not specific
to this reader), so the byte-for-byte "nothing changed" assertion is only meaningful for a
rollback-journal file. The WAL case has its own test (uncheckpointed rows must be visible).

Offline, stdlib only, everything under ``tmp_path``.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck import collector
from clawseccheck.catalog import BY_ID, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_exec_approvals_grants
from clawseccheck.collector import (
    LIMIT_DOMAIN_APPROVALS,
    Context,
    _collect_exec_approvals_sqlite,
    collect,
    limit_hits_for,
)

# The detail the check gave before a state-database reader existed, for the neither-store
# case. baseline.fingerprint() hashes `detail`, so it must stay byte-identical.
_NO_STORE_DETAIL = (
    "No exec-approvals.json store found at ~/.openclaw/exec-approvals.json \u2014 "
    "cannot determine whether any standing 'always allow' exec grants are persisted."
)

# Secret-shaped sentinels, assembled at runtime so no contiguous literal exists.
_TOKEN_SENTINEL = "-".join(["sentinel", "token", "".join(["c9", "e1", "7b"])])
_PATTERN_SENTINEL = "/opt/" + "-".join(["sentinel", "pattern", "".join(["4d", "2a"])]) + "/bin/tool"

MODERN = "2026.8.1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "openclaw.json").write_text("{}")
    return home


def _doc(agents=None, defaults=None, *, token=None, version=1) -> dict:
    doc: dict = {"version": version}
    if token is not None:
        doc["socket"] = {"path": "/tmp/exec-approvals.sock", "token": token}
    if defaults is not None:
        doc["defaults"] = defaults
    if agents is not None:
        doc["agents"] = agents
    return doc


def _grant(pattern="/usr/bin/git", *, arg_pattern=None, source="allow-always") -> dict:
    entry: dict = {"pattern": pattern}
    if source is not None:
        entry["source"] = source
    if arg_pattern is not None:
        entry["argPattern"] = arg_pattern
    return entry


def _projection(doc) -> tuple:
    """(socket_path, has_socket_token, default_security, default_ask, default_ask_fallback,
    auto_allow_skills, agent_count, allowlist_count) the way the vendor's `projectionValues`
    derives them -- so the fixture row is shaped like a real one."""
    if not isinstance(doc, dict):
        return (None, 0, None, None, None, None, 0, 0)
    socket = doc.get("socket") if isinstance(doc.get("socket"), dict) else {}
    defaults = doc.get("defaults") if isinstance(doc.get("defaults"), dict) else {}
    agents = doc.get("agents") if isinstance(doc.get("agents"), dict) else {}
    allowlist_count = sum(
        len(a.get("allowlist") or []) for a in agents.values() if isinstance(a, dict)
    )
    return (
        socket.get("path"), 1 if socket.get("token") else 0,
        defaults.get("security"), defaults.get("ask"), defaults.get("askFallback"),
        None, len(agents), allowlist_count,
    )


def _insert_row(conn: sqlite3.Connection, config_key: str, raw: str, doc) -> None:
    conn.execute(
        "INSERT INTO exec_approvals_config (config_key, raw_json, socket_path, "
        "has_socket_token, default_security, default_ask, default_ask_fallback, "
        "auto_allow_skills, agent_count, allowlist_count, updated_at_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (config_key, raw) + _projection(doc) + (1_700_000_000_000,),
    )


def _write_state_db(home: Path, doc=None, *, raw=None, row=True, config_key="current") -> Path:
    """`state/openclaw.sqlite` holding the real (vendor-shaped) `exec_approvals_config`
    table and, unless *row* is False, one row. *raw* overrides the stored text verbatim."""
    state = home / "state"
    state.mkdir(parents=True, exist_ok=True)
    db = state / "openclaw.sqlite"
    conn = sqlite3.connect(db)
    try:
        conn.executescript(_EXEC_APPROVALS_CONFIG_DDL)
        if row:
            text = raw if raw is not None else json.dumps(doc, indent=2) + "\n"
            _insert_row(conn, config_key, text, doc)
        conn.commit()
    finally:
        conn.close()
    return db


def _write_legacy_json(home: Path, doc) -> Path:
    path = home / "exec-approvals.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _audit(home: Path):
    ctx = collect(home)
    return ctx, check_exec_approvals_grants(ctx)


def _tree_state(root: Path) -> dict:
    """path -> sha256 of every file under *root* (and the directory names), for a
    before/after 'nothing was written' comparison."""
    out: dict = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_file():
            out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            out[rel] = "<dir>"
    return out


def _collect_bounded(fn, *args, timeout: float = 10.0) -> None:
    """Bounded daemon-thread call: a regressed guard fails in seconds instead of hanging
    the suite (same shape as tests/test_b908_collector_sqlite_fifo_guard.py)."""
    result: dict = {}

    def _run():
        fn(*args)
        result["done"] = True

    thread = threading.Thread(target=_run, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(timeout=timeout)
    assert not thread.is_alive(), (
        f"{getattr(fn, '__name__', fn)} did not return within {timeout:.0f}s -- a hang"
    )
    assert result.get("done") is True
    assert time.monotonic() - started < timeout


# ---------------------------------------------------------------------------
# BAD: a standing grant in the state database is a WARN
# ---------------------------------------------------------------------------

def test_sqlite_only_home_with_an_allow_always_grant_warns(tmp_path):
    """MUST FAIL IF THE FIX IS REVERTED: a home with ONLY the state database (no
    exec-approvals.json) and one standing grant was reported UNKNOWN before."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({"main": {"allowlist": [_grant()]}}))
    ctx, f = _audit(home)
    assert f.status == WARN
    assert ctx.exec_approvals_sqlite_read is True
    assert any(
        "agent 'main'" in e and "binary-wide" in e and "[state database]" in e
        for e in f.evidence
    ), f.evidence
    assert "No exec-approvals.json store found" not in (f.detail or "")
    # the advice must not send anyone to a file that (on this build) does not exist
    assert "exec-approvals.json" not in (f.fix or "")
    assert "openclaw approvals get" in (f.fix or "")


def test_mixed_arg_pattern_shapes_are_split_like_the_legacy_store(tmp_path):
    """C-430 parity: the binary-wide vs argument-restricted split survives the move."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({"main": {"allowlist": [
        _grant("/usr/bin/git", arg_pattern="^status$"),
        _grant("/usr/bin/tar"),
    ]}}))
    _, f = _audit(home)
    assert f.status == WARN
    line = next(e for e in f.evidence if "agent 'main'" in e)
    assert "2 allow-always pattern(s)" in line
    assert "1 binary-wide: any arguments" in line
    assert "1 argument-restricted" in line


def test_per_agent_tiers_are_carried_onto_the_evidence(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({"ops": {
        "security": "allowlist", "ask": "on-miss", "allowlist": [_grant()]}}))
    _, f = _audit(home)
    assert f.status == WARN
    line = next(e for e in f.evidence if "agent 'ops'" in e)
    assert "security=allowlist" in line and "ask=on-miss" in line


# ---------------------------------------------------------------------------
# CLEAN: a readable store with no allow-always entry is a verified PASS
# ---------------------------------------------------------------------------

def test_empty_agents_row_is_a_verified_pass(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({}, defaults={}))
    ctx, f = _audit(home)
    assert f.status == PASS
    assert f.pass_confidence == "verified"
    assert ctx.exec_approvals_sqlite_read is True
    assert "state database" in (f.detail or "")


def test_table_present_with_no_row_is_a_verified_pass(tmp_path):
    """The vendor reads an absent row as EMPTY approvals (`snapshotFromExecApprovalsRow`)."""
    home = _home(tmp_path)
    _write_state_db(home, row=False)
    ctx, f = _audit(home)
    assert f.status == PASS
    assert f.pass_confidence == "verified"
    assert ctx.exec_approvals_sqlite_read is True
    assert ctx.exec_approvals_grants == []


def test_manual_and_bare_string_allowlist_entries_are_not_grants(tmp_path):
    """Regression guard against using the `allowlist_count` column: a manual entry (no
    `source`) and a bare-string entry are both allowlist entries, neither is allow-always."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({"main": {"allowlist": [
        _grant("/usr/bin/git", source=None), "/usr/bin/ls",
    ]}}))
    ctx, f = _audit(home)
    assert f.status == PASS
    assert ctx.exec_approvals_grants[0]["allow_always_count"] == 0


@pytest.mark.parametrize("source", ["Allow-Always", "allow_always", "ALLOW-ALWAYS", " allow-always", ""])
def test_only_the_exact_vendor_literal_counts_as_allow_always(tmp_path, source):
    """`normalizePersistedAllowlistSource` keeps only the exact literal `"allow-always"`;
    any other spelling is dropped by the vendor, so it is not a standing grant there."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({"main": {"allowlist": [_grant(source=source)]}}))
    _, f = _audit(home)
    assert f.status == PASS


def test_mcp_tool_grants_are_not_exec_allowlist_grants(tmp_path):
    """`agents.<id>.mcpTools[].source == "allow-always"` lives in the same document but is
    a different grant kind; B172's contract is the exec allowlist."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({"main": {"mcpTools": [
        {"server": "docs", "tool": "search", "source": "allow-always", "addedAt": 1}]}}))
    _, f = _audit(home)
    assert f.status == PASS


def test_a_row_under_another_config_key_is_never_consulted(tmp_path):
    """The vendor reads `config_key = 'current'` only; a grant filed under any other key
    is not a grant OpenClaw acts on, and is not a place this reader looks either."""
    home = _home(tmp_path)
    db = _write_state_db(home, _doc({"main": {}}))
    conn = sqlite3.connect(db)
    try:
        other = _doc({"main": {"allowlist": [_grant()]}})
        _insert_row(conn, "shadow", json.dumps(other), other)
        conn.commit()
    finally:
        conn.close()
    _, f = _audit(home)
    assert f.status == PASS


def test_the_legacy_default_agent_alias_is_reported_as_its_own_entry(tmp_path):
    """The vendor folds `agents.default` into `agents.main`; the collector does not merge,
    it lists what the document holds. One grant under `default` is one grant, not two."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({"default": {"allowlist": [_grant()]}, "main": {}}))
    ctx, f = _audit(home)
    assert f.status == WARN
    assert sum(g["allow_always_count"] for g in ctx.exec_approvals_grants) == 1


# ---------------------------------------------------------------------------
# UNKNOWN: never a PASS about a store that was not read in full
# ---------------------------------------------------------------------------

def test_neither_store_keeps_the_old_unknown_byte_for_byte(tmp_path):
    home = _home(tmp_path)
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    assert f.detail == _NO_STORE_DETAIL
    assert ctx.exec_approvals_found is False
    assert ctx.exec_approvals_sqlite_read is False
    # never advises creating the deprecated file because it is missing
    assert "create" not in (f.fix or "").lower()


def test_a_state_db_without_the_table_is_the_old_unknown(tmp_path):
    """An older build's state database predates the table: same UNKNOWN as before, and
    not the 'could not be read' one -- nothing was present and unread."""
    home = _home(tmp_path)
    (home / "state").mkdir()
    conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
    conn.execute("PRAGMA user_version = 1")
    conn.close()
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    assert f.detail == _NO_STORE_DETAIL
    assert ctx.exec_approvals_sqlite_read is False
    assert ctx.exec_approvals_sqlite_unreadable is False


def test_invalid_json_row_is_unknown_and_degraded(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, raw="{not valid json")
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True
    assert ctx.exec_approvals_sqlite_unreadable is True
    assert ctx.exec_approvals_sqlite_read is False
    assert "No exec-approvals.json store found" not in (f.detail or "")


@pytest.mark.parametrize("column", ["raw_json", "config_key"])
def test_a_table_without_the_expected_columns_is_unknown(tmp_path, column):
    home = _home(tmp_path)
    db = _write_state_db(home, _doc({}))
    conn = sqlite3.connect(db)
    try:
        conn.execute(f"ALTER TABLE exec_approvals_config RENAME COLUMN {column} TO renamed_col")
        conn.commit()
    finally:
        conn.close()
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True
    assert ctx.exec_approvals_sqlite_read is False


@pytest.mark.parametrize("raw", [
    json.dumps({"version": 2, "agents": {}}),
    json.dumps({"version": True, "agents": {}}),
    json.dumps({"version": "1", "agents": {}}),
    json.dumps({"version": 1, "agents": []}),
    json.dumps({"version": 1, "agents": "main"}),
    json.dumps({"version": 1, "agents": None}),
    json.dumps([]),
    json.dumps("a string"),
    "\ufeff" + json.dumps({"version": 1, "agents": {}}),
], ids=["version-2", "version-true", "version-string", "agents-list", "agents-string",
        "agents-null", "root-list", "root-string", "bom-prefix"])
def test_an_unknown_document_shape_is_unknown_not_no_agents(tmp_path, raw):
    """`agents` of the wrong type read as 'no agents' would be a false all-clear; a
    `version` the vendor schema (`literal(1)`) does not accept is a document we do not
    know how to read."""
    home = _home(tmp_path)
    _write_state_db(home, raw=raw)
    ctx, f = _audit(home)
    assert f.status == UNKNOWN, f.detail
    assert f.engine_degraded is True
    assert ctx.exec_approvals_grants == []


def test_a_view_standing_in_for_the_table_is_refused_and_never_executed(tmp_path):
    """Name resolution is a property of the FILE's schema: a crafted VIEW named
    `exec_approvals_config` must not be queried. Its body carries a full allow-always
    document -- if the reader trusted the name this would be a WARN built from
    attacker-chosen data."""
    home = _home(tmp_path)
    (home / "state").mkdir()
    planted = json.dumps(_doc({"main": {"allowlist": [_grant()]}}))
    conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
    try:
        conn.execute(
            "CREATE VIEW exec_approvals_config AS SELECT 'current' AS config_key, '"
            + planted.replace("'", "''") + "' AS raw_json"
        )
        conn.commit()
    finally:
        conn.close()
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True
    assert ctx.exec_approvals_grants == []
    assert any("exec_approvals_config" in e and "real table" in e for e in ctx.errors)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs only")
def test_a_fifo_at_the_state_db_path_is_refused_without_hanging(tmp_path):
    home = _home(tmp_path)
    (home / "state").mkdir()
    os.mkfifo(home / "state" / "openclaw.sqlite")
    ctx = Context(home=home)
    _collect_bounded(_collect_exec_approvals_sqlite, home, ctx)
    assert ctx.exec_approvals_found is True
    assert ctx.exec_approvals_parse_error is True
    assert ctx.exec_approvals_sqlite_unreadable is True
    assert any("not a regular file" in e for e in ctx.errors), ctx.errors
    assert check_exec_approvals_grants(ctx).status == UNKNOWN


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs only")
@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_a_fifo_at_a_sidecar_path_is_refused_without_hanging(tmp_path, suffix):
    home = _home(tmp_path)
    db = _write_state_db(home, _doc({}))
    os.mkfifo(str(db) + suffix)
    ctx = Context(home=home)
    _collect_bounded(_collect_exec_approvals_sqlite, home, ctx)
    assert ctx.exec_approvals_sqlite_unreadable is True
    assert ctx.exec_approvals_sqlite_read is False
    assert check_exec_approvals_grants(ctx).status == UNKNOWN


def test_a_document_over_the_byte_cap_is_unknown_never_a_pass(tmp_path, monkeypatch):
    """A grant sitting past the cap must not be hidden by padding: the over-cap document
    is not parsed at all, and the outcome is a disclosed limit + UNKNOWN."""
    monkeypatch.setattr(collector, "_MAX_EXEC_APPROVALS_BYTES", 400)
    home = _home(tmp_path)
    body = json.dumps(_doc({"main": {"allowlist": [_grant()]}}), separators=(",", ":"))
    pad = " " * (401 - len(body) + 1)
    _write_state_db(home, raw=pad + body)  # leading whitespace: the grant starts past the cap
    ctx, f = _audit(home)
    assert limit_hits_for(ctx, LIMIT_DOMAIN_APPROVALS)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


def test_a_document_of_exactly_the_cap_is_still_read(tmp_path, monkeypatch):
    """Boundary control for the test above: at the cap it parses; one byte over it does not."""
    monkeypatch.setattr(collector, "_MAX_EXEC_APPROVALS_BYTES", 400)
    body = json.dumps(_doc({"main": {"allowlist": [_grant()]}}), separators=(",", ":"))
    assert len(body) < 400
    at_cap = body + " " * (400 - len(body))
    over_cap = at_cap + " "
    home_a, home_b = _home(tmp_path / "a"), _home(tmp_path / "b")
    _write_state_db(home_a, raw=at_cap)
    _write_state_db(home_b, raw=over_cap)
    ctx_a, f_a = _audit(home_a)
    ctx_b, f_b = _audit(home_b)
    assert f_a.status == WARN and not limit_hits_for(ctx_a, LIMIT_DOMAIN_APPROVALS)
    assert f_b.status == UNKNOWN and limit_hits_for(ctx_b, LIMIT_DOMAIN_APPROVALS)


def test_agents_past_the_count_cap_make_a_clean_scan_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_EXEC_APPROVALS_AGENTS", 3)
    agents = {f"a{i}": {} for i in range(5)}
    agents["a4"] = {"allowlist": [_grant()]}  # the only grant sits past the cap
    home = _home(tmp_path)
    _write_state_db(home, _doc(agents))
    ctx, f = _audit(home)
    assert limit_hits_for(ctx, LIMIT_DOMAIN_APPROVALS)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


def test_a_grant_among_the_scanned_agents_still_warns_past_the_count_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_EXEC_APPROVALS_AGENTS", 3)
    agents = {f"a{i}": {} for i in range(5)}
    agents["a0"] = {"allowlist": [_grant()]}
    home = _home(tmp_path)
    _write_state_db(home, _doc(agents))
    _, f = _audit(home)
    assert f.status == WARN


# ---------------------------------------------------------------------------
# Both stores: the verdict is the UNION, and an unread store is never turned into a PASS
# ---------------------------------------------------------------------------

def test_clean_state_db_plus_a_legacy_file_with_a_grant_warns(tmp_path):
    """A leftover file beside the canonical row is a pending grant Doctor would import."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({}))
    _write_legacy_json(home, _doc({"main": {"allowlist": [_grant()]}}))
    ctx, f = _audit(home)
    assert f.status == WARN
    line = next(e for e in f.evidence if "agent 'main'" in e)
    assert "[state database]" not in line
    assert "exec-approvals.json" in (f.fix or "")
    assert "store" not in ctx.exec_approvals_grants[0]  # legacy grant dicts are unchanged


def test_unreadable_state_db_plus_a_legacy_grant_still_warns_and_says_incomplete(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, raw="{broken")
    _write_legacy_json(home, _doc({"main": {"allowlist": [_grant()]}}))
    ctx, f = _audit(home)
    assert f.status == WARN
    assert "incomplete" in (f.fix or "")
    assert ctx.exec_approvals_sqlite_unreadable is True


def test_unreadable_state_db_plus_a_clean_legacy_file_is_unknown_never_pass(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, raw="{broken")
    _write_legacy_json(home, _doc({}))
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


def test_clean_state_db_plus_a_malformed_legacy_file_is_unknown_never_pass(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({}))
    (home / "exec-approvals.json").write_text("{not valid json")
    ctx, f = _audit(home)
    assert ctx.exec_approvals_sqlite_read is True
    assert f.status == UNKNOWN
    assert "exec-approvals.json" in (f.detail or "")


def test_state_db_grant_plus_clean_legacy_file_warns(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({"main": {"allowlist": [_grant()]}}))
    _write_legacy_json(home, _doc({}))
    _, f = _audit(home)
    assert f.status == WARN
    assert all("[state database]" in e for e in f.evidence)


def test_the_same_grant_in_both_stores_warns_without_crashing(tmp_path):
    home = _home(tmp_path)
    doc = _doc({"main": {"allowlist": [_grant()]}})
    _write_state_db(home, doc)
    _write_legacy_json(home, doc)
    ctx, f = _audit(home)
    assert f.status == WARN
    assert len(f.evidence) == 2
    assert sum("[state database]" in e for e in f.evidence) == 1


def test_state_db_defaults_win_over_the_legacy_file(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({}, defaults={"security": "deny", "ask": "always"}))
    _write_legacy_json(home, _doc({}, defaults={"security": "full", "ask": "off"}))
    ctx = collect(home)
    assert ctx.exec_approvals_defaults == {"security": "deny", "ask": "always"}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
def test_a_symlinked_legacy_file_beside_a_clean_state_db_is_unknown_never_pass(tmp_path):
    """The runtime refuses exec approvals while the legacy path exists, and Doctor would
    import whatever it points at. A path that is never followed is a present-but-unread
    store, so the state database's 'no grant' cannot stand alone as a verified PASS."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({}))
    real = tmp_path / "elsewhere-exec-approvals.json"
    real.write_text(json.dumps(_doc({"main": {"allowlist": [_grant()]}})))
    (home / "exec-approvals.json").symlink_to(real)
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    assert ctx.exec_approvals_parse_error is True
    assert any("not a regular file" in e for e in ctx.errors), ctx.errors


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
def test_a_symlinked_legacy_file_with_no_state_db_keeps_its_historical_meaning(tmp_path):
    """Control: with no state-database store the skipped path is still 'treated as absent'
    (tests/test_b172_exec_approvals_grants.py), byte-for-byte the old UNKNOWN."""
    home = _home(tmp_path)
    real = tmp_path / "elsewhere-exec-approvals.json"
    real.write_text(json.dumps(_doc({})))
    (home / "exec-approvals.json").symlink_to(real)
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    assert f.detail == _NO_STORE_DETAIL
    assert ctx.exec_approvals_found is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
def test_a_state_db_grant_beside_a_symlinked_legacy_file_still_warns_as_incomplete(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({"main": {"allowlist": [_grant()]}}))
    real = tmp_path / "elsewhere-exec-approvals.json"
    real.write_text(json.dumps(_doc({})))
    (home / "exec-approvals.json").symlink_to(real)
    _, f = _audit(home)
    assert f.status == WARN
    assert "incomplete" in (f.fix or "")


def test_legacy_only_home_is_byte_stable(tmp_path):
    """No state database at all: today's behaviour, dict shapes and texts included."""
    home = _home(tmp_path)
    _write_legacy_json(home, _doc({"main": {"allowlist": [_grant()]}}, defaults={}))
    ctx, f = _audit(home)
    assert f.status == WARN
    assert ctx.exec_approvals_sqlite_read is False
    assert ctx.exec_approvals_grants == [{
        "agent_id": "main", "security": None, "ask": None,
        "allow_always_count": 1, "binary_wide_count": 1, "arg_restricted_count": 0,
    }]
    assert all("[state database]" not in e for e in f.evidence)
    assert "(or inspect ~/.openclaw/exec-approvals.json directly)" in (f.fix or "")


# ---------------------------------------------------------------------------
# WAL visibility and read-only behaviour
# ---------------------------------------------------------------------------

def test_a_row_still_resident_in_the_wal_is_seen(tmp_path):
    """The opener is plain `mode=ro` (B-909), never `immutable=1`, precisely so that rows a
    live OpenClaw has committed but not yet checkpointed are visible. The fixture proves
    its own premise: the main database file alone holds the table but NOT the row."""
    home = _home(tmp_path)
    db = _write_state_db(home, row=False)
    writer = sqlite3.connect(db)
    try:
        assert writer.execute("PRAGMA journal_mode = WAL").fetchone()[0].lower() == "wal"
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        doc = _doc({"main": {"allowlist": [_grant()]}})
        _insert_row(writer, "current", json.dumps(doc), doc)
        writer.commit()

        frozen = sqlite3.connect(f"file:{db.as_posix()}?mode=ro&immutable=1", uri=True)
        try:
            in_main_file = frozen.execute("SELECT COUNT(*) FROM exec_approvals_config").fetchone()[0]
        finally:
            frozen.close()
        assert in_main_file == 0, "premise broken: the row reached the main file"

        _, f = _audit(home)
        assert f.status == WARN
    finally:
        writer.close()


def test_collect_writes_nothing_to_a_rollback_journal_state_db(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({"main": {"allowlist": [_grant()]}}))
    before = _tree_state(home)
    collect(home)
    assert _tree_state(home) == before


# ---------------------------------------------------------------------------
# Secrecy: only counts, tier strings and agent ids leave the reader
# ---------------------------------------------------------------------------

def test_document_content_never_reaches_ctx_errors_or_the_finding(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc(
        {"main": {"allowlist": [_grant(_PATTERN_SENTINEL, arg_pattern=_PATTERN_SENTINEL)]}},
        token=_TOKEN_SENTINEL,
    ))
    ctx, f = _audit(home)
    assert f.status == WARN
    seen = "\n".join([
        repr(ctx), "\n".join(ctx.errors), f.detail or "", f.fix or "",
        "\n".join(f.evidence or []),
    ])
    assert _TOKEN_SENTINEL not in seen
    assert _PATTERN_SENTINEL not in seen


@pytest.mark.parametrize("raw", [
    # truncated: invalid JSON with the secret inside it
    '{"version": 1, "socket": {"token": "' + _TOKEN_SENTINEL + '"',
    # well-formed but an unknown version
    json.dumps({"version": 2, "socket": {"token": _TOKEN_SENTINEL}, "agents": {}}),
], ids=["invalid-json", "unknown-version"])
def test_unreadable_document_content_never_reaches_the_error_text(tmp_path, raw):
    home = _home(tmp_path)
    _write_state_db(home, raw=raw)
    ctx, f = _audit(home)
    assert f.status == UNKNOWN
    seen = "\n".join([repr(ctx), "\n".join(ctx.errors), f.detail or "", f.fix or ""])
    assert _TOKEN_SENTINEL not in seen


def test_the_reader_selects_one_column_of_one_row(tmp_path, monkeypatch):
    """No `SELECT *`, no other column, no other table: the socket path and the projection
    columns are never asked for, so they cannot be retained even by accident."""
    home = _home(tmp_path)
    _write_state_db(home, _doc({}))
    seen: list = []
    real_connect = sqlite3.connect

    class _Spy(sqlite3.Connection):
        def execute(self, sql, *args):
            seen.append(sql)
            return super().execute(sql, *args)

    monkeypatch.setattr(
        collector.sqlite3, "connect",
        lambda *a, **kw: real_connect(*a, factory=_Spy, **kw),
    )
    ctx = Context(home=home)
    _collect_exec_approvals_sqlite(home, ctx)
    selects = [s for s in seen if s.lstrip().upper().startswith("SELECT")]
    reads = [s for s in selects if "exec_approvals_config" in s]
    assert len(reads) == 1, selects
    assert "raw_json" in reads[0] and "*" not in reads[0]
    for banned in ("socket_path", "has_socket_token", "auth_profile", "config_health"):
        assert all(banned not in s for s in seen), (banned, seen)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_b172_title_no_longer_names_only_the_legacy_file():
    assert ".json" not in BY_ID["B172"].title
    assert BY_ID["B172"].scored is False


# ---------------------------------------------------------------------------
# B353 / B831: the caveat and the floor wording follow what was actually read
# ---------------------------------------------------------------------------

def _b353(home: Path):
    cfg = {
        "mcp": {"servers": {"ops-mcp": {"command": "c"}}},
        "plugins": {"entries": {"codex": {
            "enabled": True, "config": {"appServer": {"mode": "yolo"}}}}},
    }
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = MODERN
    finding = next(f for f in C.run_all(ctx) if f.id == "B353")
    return finding, C._codex_appserver_yolo_reach(ctx)[0]


def test_b353_a_state_db_floor_hedges_a_yes_and_names_the_store(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({}, defaults={"security": "deny"}))
    f, answer = _b353(home)
    assert (f.status, answer) == (WARN, "unknown")
    detail = f.detail or ""
    assert "the exec-approvals store defaults sets security='deny'" in detail
    assert "exec-approvals.json" not in detail


def test_b353_a_per_agent_state_db_floor_hedges_a_yes(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({"work": {"ask": "always"}}))
    f, answer = _b353(home)
    assert (f.status, answer) == (WARN, "unknown")
    assert "the exec-approvals store agents.work sets ask='always'" in (f.detail or "")


@pytest.mark.parametrize("defaults", [
    {"security": "full", "ask": "off"}, {}, None,
], ids=["neutral-defaults", "empty-defaults", "no-defaults"])
def test_b353_control_a_state_db_without_a_tightening_floor_leaves_yes(tmp_path, defaults):
    home = _home(tmp_path)
    _write_state_db(home, _doc({}, defaults=defaults))
    f, answer = _b353(home)
    assert (f.status, answer) == (WARN, "yes")


def test_b353_the_runtime_caveat_drops_the_store_clause_once_the_store_was_read(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, _doc({}))
    f, _ = _b353(home)
    assert C._CODEX_APPSERVER_RUNTIME_CAVEAT_STORE_READ in (f.detail or "")
    assert C._CODEX_APPSERVER_RUNTIME_CAVEAT not in (f.detail or "")


def test_b353_the_original_caveat_stands_when_no_store_was_read(tmp_path):
    home = _home(tmp_path)
    f, answer = _b353(home)
    assert (f.status, answer) == (WARN, "yes")
    assert C._CODEX_APPSERVER_RUNTIME_CAVEAT in (f.detail or "")
    assert C._CODEX_APPSERVER_RUNTIME_CAVEAT_STORE_READ not in (f.detail or "")


def test_b353_an_unreadable_state_db_keeps_the_original_caveat_and_hedges(tmp_path):
    home = _home(tmp_path)
    _write_state_db(home, raw="{broken")
    f, answer = _b353(home)
    assert (f.status, answer) == (WARN, "unknown")
    detail = f.detail or ""
    assert "the exec-approvals store is present but could not be read in full" in detail
    assert "exec-approvals.json" not in detail.replace(C._CODEX_APPSERVER_RUNTIME_CAVEAT, "")
    assert C._CODEX_APPSERVER_RUNTIME_CAVEAT in detail


def test_b353_the_two_caveats_differ_exactly_by_the_store_clause():
    old, new = C._CODEX_APPSERVER_RUNTIME_CAVEAT, C._CODEX_APPSERVER_RUNTIME_CAVEAT_STORE_READ
    assert "state database" in old and "state database" not in new
    assert "exec-approvals.json" in old and "exec-approvals.json" not in new
    assert "OPENCLAW_CODEX_APP_SERVER_" in old and "OPENCLAW_CODEX_APP_SERVER_" in new


# ---------------------------------------------------------------------------
# Vendor DDL -- keep at the END of the file. tests/test_state_schema_grounding.py keys its
# registry by `<file>:<line>` of this literal; anything added below shifts the key.
# ---------------------------------------------------------------------------

# Copied verbatim from `sqlite3 ~/.openclaw/state/openclaw.sqlite ".schema
# exec_approvals_config"` against a real, installed OpenClaw 2026.9.7 (state schema v19);
# it equals OPENCLAW_STATE_SCHEMA_SQL's declaration column for column.
_EXEC_APPROVALS_CONFIG_DDL = """
CREATE TABLE IF NOT EXISTS exec_approvals_config (
  config_key TEXT NOT NULL PRIMARY KEY,
  raw_json TEXT NOT NULL,
  socket_path TEXT,
  has_socket_token INTEGER NOT NULL,
  default_security TEXT,
  default_ask TEXT,
  default_ask_fallback TEXT,
  auto_allow_skills INTEGER,
  agent_count INTEGER NOT NULL,
  allowlist_count INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
) STRICT;
"""
