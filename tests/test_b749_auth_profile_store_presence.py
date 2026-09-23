"""CLAWSECCHECK-B-749 — the sensitive-data leg reads a clean OFF on a machine whose
credentials live in the state DB (`config_machine_state["authProfiles.store"]`), not in
`<home>/credentials`.

Measured on the real fleet machine, 2026-09-06 (this task's own filing): the on-disk
credential-store scan (B-666) read a confident "looked, nothing there" --
``secret_files=[]``, ``incomplete=False`` -- while the state DB held a non-trivial
``authProfiles.store`` row. A1 (check_trifecta) reported a clean, unhedged sensitive-data
leg is OFF over a home that really does hold auth material.

The fix is deliberately a HEDGE (WARN), not a leg-raising signal, following the direction
the prior investigation on this task settled on and this file's own comments explain:
whether a non-empty ``authProfiles.store`` row always means a USABLE credential (vs. an
expired/revoked profile) was not settled, so asserting the sensitive-data leg is ON would
risk a NEW false-positive FAIL on A1 -- the CRITICAL check that grade-caps the whole
audit. A hedge trivially satisfies "no credential value reaches any output" (the reader
`_collect_auth_profile_store_presence` only ever asks SQLite for ``LENGTH(value_json)``,
never the value) and cannot re-open the false-positive HIGH B-730 closed, because it never
touches the boolean `_trifecta_legs()["sensitive data"]` that RISK-02 and the capability
graph read -- the SAME "hedge in A1, stay silent in the chain" asymmetry
``test_b730_sensitive_data_model_agreement.py::test_an_unreadable_store_hedges_in_a1_and_stays_silent_in_the_chain``
already pins for an unreadable on-disk store, not a new one.

The empty-store byte threshold (27) is grounded by READING the installed OpenClaw dist
(2026.9.4), not inferred from one machine: ``buildPersistedAuthProfileSecretsStore``
(``legacy-source-diagnostic-D-_lsE4x.mjs``) returns ``{version: 1, profiles: {}}``
whenever ``store.profiles`` is empty, and ``saveAuthProfileStoreInTransaction``
(``store-BxRoDWvl.mjs``) writes that shape on the very FIRST save even with zero
configured profiles (``existingRaw`` starts ``null``, so ``credentialsChanged`` is always
true the first time). ``json.dumps({"version": 1, "profiles": {}}, separators=(",", ":"))``
reproduces the same 27 bytes Node's ``JSON.stringify`` writes -- pinned below so a value AT
that length (freshly-initialized, still empty) does not hedge, only a value ABOVE it does.

No independent C-135 pass was performed on the ORIGINAL B-749 change (the shared-store
hedge above) -- flagged explicitly in the Pulse comment landing it, and this file was, at
that point, the implementer's own test suite, not adversarial review. CLAWSECCHECK-B-845
(the ``TestPerAgentAuthProfileStore*`` classes below) extends the SAME hedge to a second,
per-agent auth-material source and is, for the same reason, likewise NOT independently
C-135-reviewed yet -- this is a security-relevant verdict-adjacent change (A1's
sensitive-data leg) and needs that pass before merge, same as the change it extends.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import _trifecta_legs, check_trifecta
from clawseccheck.collector import (
    _AUTH_PROFILE_STORE_EMPTY_BYTES,
    _collect_auth_profile_store_presence,
    collect,
)
from clawseccheck.report import _capability_graph
from clawseccheck.risk import risk_paths
from clawseccheck.trajectorystore import _MAX_SQLITE_DBS, sqlite_db_paths_capped

# Isolates the sensitive-data leg exactly like test_b730_sensitive_data_model_agreement's
# own CFG: untrusted-input and outbound are both held ON by construction so ONLY the
# sensitive-data leg's own True/False can move `len(active)`, and exec is gated / fs is
# confined so neither raises the leg on its own (verified by construction there; reused
# verbatim rather than re-derived).
CFG = {
    "channels": {"telegram": {"dmPolicy": "open"}},
    "tools": {
        "profile": "coding",
        "exec": {"mode": "ask"},
        "fs": {"workspaceOnly": True},
        "web": {"fetch": {"enabled": True}},
    },
}

_EMPTY_STORE_JSON = json.dumps({"version": 1, "profiles": {}}, separators=(",", ":"))


def _token(seed: str) -> str:
    """Assembled at runtime from fragments — Golden Rule #3 forbids a contiguous
    secret-shaped literal in source, so secret scanners stay quiet on this repo."""
    return "sk-" + "ant-" + "api03-" + (seed * 40)


def _home(
    tmp_path: Path,
    name: str,
    *,
    cfg: dict = CFG,
    credentials: bool = True,
    auth_store_json: str | None = None,
    table: str = "config_machine_state",
    make_db: bool | None = None,
) -> Path:
    """A real, on-disk home: `collect()` runs over it end-to-end, not a hand-built ctx.

    `credentials`: create an EMPTY `credentials/` directory (the real fleet shape --
    B-666's pairing state, no secret) when True; no directory at all when False.
    `auth_store_json`: if given, a `state/openclaw.sqlite` is created with exactly one
    `config_machine_state` row for `authProfiles.store` holding this raw JSON text.
    `make_db`: force-create an empty (rowless) state DB even with no auth_store_json,
    to exercise "table exists, key absent" separately from "no DB at all".
    """
    home = tmp_path / name
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text(json.dumps(cfg))
    os.chmod(home / "openclaw.json", 0o600)
    if credentials:
        store = home / "credentials"
        store.mkdir()
        # The real fleet home's own shape (B-730): pairing state, never a secret.
        (store / "telegram-allow.json").write_text('{"allow": []}')
    if auth_store_json is not None or make_db:
        state = home / "state"
        state.mkdir()
        con = sqlite3.connect(state / "openclaw.sqlite")
        try:
            con.execute(
                f"CREATE TABLE {table} "
                "(state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)"
            )
            if auth_store_json is not None:
                con.execute(
                    f"INSERT INTO {table} VALUES (?,?,?)",
                    ("authProfiles.store", auth_store_json, 0),
                )
            con.commit()
        finally:
            con.close()
    return home


def _a1_leg(ctx) -> bool:
    return bool(_trifecta_legs(ctx)["sensitive data"])


def _risk02_present(ctx) -> bool:
    return any(p.id == "RISK-02" for p in risk_paths(ctx, []))


def _graph_main_secrets(ctx) -> bool:
    main = next(n for n in _capability_graph(ctx)["nodes"] if n["id"] == "main")
    return bool(main["secrets_visible"])


# --------------------------------------------------------------- the raw collector reader


class TestAuthProfileStorePresenceReader:
    """`_collect_auth_profile_store_presence` in isolation: the three-state disclosure,
    and that it NEVER lands the parsed value anywhere in `ctx` — only a byte count."""

    def test_no_state_dir_at_all_is_undetermined(self, tmp_path):
        home = _home(tmp_path, "h", credentials=False)
        ctx = collect(home)
        assert ctx.auth_profile_store_read is False
        assert ctx.auth_profile_store_length is None

    def test_db_predating_the_table_is_undetermined_not_absent(self, tmp_path):
        home = _home(tmp_path, "h", table="something_else", make_db=True)
        ctx = collect(home)
        assert ctx.auth_profile_store_read is False
        assert ctx.auth_profile_store_length is None

    def test_table_present_key_absent_reads_as_absent_not_undetermined(self, tmp_path):
        """"Looked, nothing there" (a real answer) vs "could not look" (no answer) —
        collapsing them is the lying-clean Golden Rule #4 forbids."""
        home = _home(tmp_path, "h", make_db=True)
        ctx = collect(home)
        assert ctx.auth_profile_store_read is True
        assert ctx.auth_profile_store_length is None

    def test_a_present_row_is_measured_by_length_only(self, tmp_path):
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("A")}
        }})
        home = _home(tmp_path, "h", auth_store_json=payload)
        ctx = collect(home)
        assert ctx.auth_profile_store_read is True
        assert ctx.auth_profile_store_length == len(payload)

    def test_the_empty_store_shape_is_exactly_27_bytes(self, tmp_path):
        """Pins the grounded constant itself — if a future OpenClaw release changes how
        it serializes an empty store, this is the test that should redden first."""
        assert len(_EMPTY_STORE_JSON) == _AUTH_PROFILE_STORE_EMPTY_BYTES == 27

    def test_the_secret_value_never_reaches_config_machine_state(self, tmp_path):
        """§8: `authProfiles.store` must stay OUT of the allowlisted
        `ctx.config_machine_state` dict no matter what this new reader does — the F-183
        allowlist is the thing that stops a generic reader from becoming a credential
        leak, and this feature must not quietly widen it."""
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("B")}
        }})
        home = _home(tmp_path, "h", auth_store_json=payload)
        ctx = collect(home)
        assert "authProfiles.store" not in ctx.config_machine_state
        assert ctx.auth_profile_store_length == len(payload)

    def test_called_directly_matches_collect(self, tmp_path):
        """Regression guard on the function itself, not just through the full pipeline."""
        home = _home(tmp_path, "h", auth_store_json=_EMPTY_STORE_JSON)
        from clawseccheck.collector import Context

        ctx = Context(home=home)
        _collect_auth_profile_store_presence(home, ctx)
        assert ctx.auth_profile_store_read is True
        assert ctx.auth_profile_store_length == 27


# --------------------------------------------------------------------- A1's hedge (check_trifecta)


class TestA1HedgesOnStateDbAuthMaterial:
    def test_the_exact_reported_defect_now_hedges(self, tmp_path):
        """The task's own reproduction: empty credentials/, real material in the state
        DB. Before the fix this was a confident, unhedged PASS."""
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("C")}
        }})
        home = _home(tmp_path, "h", auth_store_json=payload)
        ctx = collect(home)
        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail
        assert "Cannot determine from config: sensitive data" in finding.detail
        assert "authProfiles.store" in finding.detail
        assert "config_machine_state" in finding.fix

    def test_no_state_db_at_all_stays_a_clean_pass(self, tmp_path):
        """The B-730 regression control, re-verified with this reader wired in: a home
        with no state DB (or none reachable) must not start hedging just because the new
        signal exists — `auth_profile_store_read` is False, so `auth_store_present` is
        False by construction."""
        home = _home(tmp_path, "h", credentials=True)
        ctx = collect(home)
        assert ctx.auth_profile_store_read is False
        finding = check_trifecta(ctx)
        assert finding.status == PASS, finding.detail

    def test_an_empty_initialized_store_does_not_hedge(self, tmp_path):
        """The B-730 control in its sharpest form: a row EXISTS (OpenClaw saved once)
        but holds exactly the vendor's own empty shape. Must stay a clean PASS, or this
        fix reopens the false-positive HIGH B-730 closed — every freshly-onboarded
        machine writes this row on its first run with zero profiles configured."""
        home = _home(tmp_path, "h", auth_store_json=_EMPTY_STORE_JSON)
        ctx = collect(home)
        assert ctx.auth_profile_store_length == _AUTH_PROFILE_STORE_EMPTY_BYTES
        finding = check_trifecta(ctx)
        assert finding.status == PASS, finding.detail

    def test_one_byte_over_the_empty_shape_hedges(self, tmp_path):
        """Pins the threshold boundary itself, not just a realistic-sized payload."""
        home = _home(tmp_path, "h", auth_store_json=_EMPTY_STORE_JSON + " ")
        ctx = collect(home)
        assert ctx.auth_profile_store_length == _AUTH_PROFILE_STORE_EMPTY_BYTES + 1
        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail

    def test_a_real_on_disk_credential_still_raises_the_leg_directly(self, tmp_path):
        """Regression: the ORIGINAL B-666 content scan is untouched by this change. A
        real on-disk secret must still raise the leg outright (not merely hedge), same
        as before this task."""
        home = _home(tmp_path, "h", credentials=True)
        (home / "credentials" / "oauth.json").write_text(
            json.dumps({"access_token": _token("D")})
        )
        ctx = collect(home)
        finding = check_trifecta(ctx)
        assert "sensitive data" in finding.detail
        assert _a1_leg(ctx) is True

    def test_an_attested_roster_still_silences_this_hedge_too(self, tmp_path):
        """The SAME asymmetry B-803 already pins for the other thin-surface hedges: an
        attested roster speaks to the agent's own tool grants, so it can silence the
        "cannot determine" hedge even though it says nothing about the state DB. Not a
        new decision — this new hedge sits in the same gated block as the existing ones
        and must follow the same rule or it becomes the one hedge attestation cannot
        clear, for no stated reason."""
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("E")}
        }})
        home = _home(tmp_path, "h", auth_store_json=payload)
        ctx = collect(home)
        ctx.attestation = {"agents": [{"name": "main", "tools": ["exec", "write"]}]}
        finding = check_trifecta(ctx)
        assert finding.status == PASS, finding.detail


# --------------------------------------------------------- consumer agreement (risk/report)


class TestConsumersStayConsistent:
    """RISK-02 and the capability graph must not move just because A1 started hedging —
    a hedge is disclosure, not a leg raise, so the boolean `_trifecta_legs()["sensitive
    data"]` these two read is UNCHANGED by this task. This is the identical asymmetry
    `test_b730_sensitive_data_model_agreement.py::
    test_an_unreadable_store_hedges_in_a1_and_stays_silent_in_the_chain` already pins for
    an unreadable on-disk store; this test pins the same shape for the new signal so a
    future attempt to "finish the job" by wiring RISK-02/report.py off of
    `auth_profile_store_length` does so as a deliberate, reviewed decision — not by
    accident."""

    def test_state_db_auth_material_hedges_a1_but_leaves_the_chain_and_graph_off(
        self, tmp_path
    ):
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("F")}
        }})
        home = _home(tmp_path, "h", auth_store_json=payload)
        ctx = collect(home)
        assert check_trifecta(ctx).status == WARN
        assert _a1_leg(ctx) is False
        assert _risk02_present(ctx) is False
        assert _graph_main_secrets(ctx) is False


# ------------------------------------------------------------- CLAWSECCHECK-B-845
# per-agent auth material (agents/<agent-id>/agent/openclaw-agent.sqlite,
# table auth_profile_store) -- a THIRD source, distinct from both the on-disk
# credentials/ scan (B-666) and the shared-state-DB authProfiles.store row (B-749)
# above. The task's own reproduction: empty credentials/, no shared-DB row, but a
# real row in an agent's OWN database -- before this fix, a confident, unhedged PASS.


def _agent_home(
    tmp_path: Path,
    name: str,
    agent: str = "main",
    *,
    cfg: dict = CFG,
    credentials: bool = False,
    agent_auth_store_json: str | None = None,
) -> Path:
    """A home whose only auth-adjacent material (if any) sits in one agent's own
    database — no shared `state/openclaw.sqlite` at all, so `auth_profile_store_read`
    stays False by construction and only the NEW per-agent fields can move.
    `agent_auth_store_json`, if given, seeds exactly one row
    (`store_key='primary'`, matching the real runtime's own `PRIMARY_ROW_KEY`,
    grounded against the installed dist, 2026.9.5: sqlite-Cp6HSWY4.mjs) in
    `agents/<agent>/agent/openclaw-agent.sqlite`.
    """
    home = tmp_path / name
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text(json.dumps(cfg))
    os.chmod(home / "openclaw.json", 0o600)
    if credentials:
        store = home / "credentials"
        store.mkdir()
        (store / "telegram-allow.json").write_text('{"allow": []}')
    if agent_auth_store_json is not None:
        agent_dir = home / "agents" / agent / "agent"
        agent_dir.mkdir(parents=True)
        con = sqlite3.connect(agent_dir / "openclaw-agent.sqlite")
        try:
            con.execute(
                "CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, "
                "store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)"
            )
            con.execute(
                "INSERT INTO auth_profile_store VALUES (?,?,?)",
                ("primary", agent_auth_store_json, 0),
            )
            con.commit()
        finally:
            con.close()
    return home


class TestPerAgentAuthProfileStoreReader:
    """`_collect_agent_auth_profile_store_presence` in isolation: same three-state
    disclosure and length-only discipline as the shared-store reader, on a completely
    separate database file."""

    def test_no_agent_db_at_all_is_undetermined(self, tmp_path):
        home = _agent_home(tmp_path, "h")
        ctx = collect(home)
        assert ctx.agent_auth_profile_store_read is False
        assert ctx.agent_auth_profile_store_length is None

    def test_a_present_per_agent_row_is_measured_by_length_only(self, tmp_path):
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("G")}
        }})
        home = _agent_home(tmp_path, "h", agent_auth_store_json=payload)
        ctx = collect(home)
        assert ctx.agent_auth_profile_store_read is True
        assert ctx.agent_auth_profile_store_length == len(payload)
        # No shared state DB exists in this fixture at all -- the shared-store fields
        # must stay at their undetermined default, not be accidentally set by the new
        # per-agent reader.
        assert ctx.auth_profile_store_read is False
        assert ctx.auth_profile_store_length is None

    def test_the_secret_value_never_reaches_ctx_errors_or_config_machine_state(self, tmp_path):
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("J")}
        }})
        home = _agent_home(tmp_path, "h", agent_auth_store_json=payload)
        ctx = collect(home)
        assert "authProfiles.store" not in ctx.config_machine_state
        assert payload not in " ".join(ctx.errors)
        assert ctx.agent_auth_profile_store_length == len(payload)


class TestA1HedgesOnPerAgentAuthMaterial:
    def test_the_b845_reported_defect_now_hedges(self, tmp_path):
        """The task's own reproduction: empty credentials/, no shared-DB row, real
        material ONLY in an agent's own database. Before this fix, `check_trifecta`
        reported a clean, unhedged PASS over a home that really does hold auth
        material — the false PASS CLAWSECCHECK-B-845 exists to close."""
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("K")}
        }})
        home = _agent_home(
            tmp_path, "h", credentials=True, agent_auth_store_json=payload
        )
        ctx = collect(home)
        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail
        assert "Cannot determine from config: sensitive data" in finding.detail
        assert "auth_profile_store" in finding.detail
        assert "auth_profile_store" in finding.fix

    def test_no_agent_db_at_all_stays_a_clean_pass(self, tmp_path):
        """The B-730 regression control, re-verified with this second reader wired
        in: a home with no per-agent database (or none reachable) must not start
        hedging just because the new signal exists."""
        home = _agent_home(tmp_path, "h", credentials=True)
        ctx = collect(home)
        assert ctx.agent_auth_profile_store_read is False
        finding = check_trifecta(ctx)
        assert finding.status == PASS, finding.detail

    def test_an_empty_initialized_per_agent_store_does_not_hedge(self, tmp_path):
        """Same B-730 control in its sharpest form, for the per-agent source: a row
        EXISTS but holds exactly the vendor's own empty shape (grounded: the per-agent
        write path reuses the SAME `buildPersistedAuthProfileSecretsStore` the shared
        path does) — must stay a clean PASS."""
        home = _agent_home(
            tmp_path, "h", credentials=True, agent_auth_store_json=_EMPTY_STORE_JSON
        )
        ctx = collect(home)
        assert ctx.agent_auth_profile_store_length == _AUTH_PROFILE_STORE_EMPTY_BYTES
        finding = check_trifecta(ctx)
        assert finding.status == PASS, finding.detail

    def test_a_second_agent_with_real_material_is_not_hidden_by_the_first(self, tmp_path):
        """Two agents, only the SECOND holds real material — the aggregation must not
        let the first agent's empty row win."""
        home = _agent_home(
            tmp_path, "h", agent="main", agent_auth_store_json=_EMPTY_STORE_JSON
        )
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("L")}
        }})
        agent_dir = home / "agents" / "second" / "agent"
        agent_dir.mkdir(parents=True)
        con = sqlite3.connect(agent_dir / "openclaw-agent.sqlite")
        try:
            con.execute(
                "CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, "
                "store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)"
            )
            con.execute(
                "INSERT INTO auth_profile_store VALUES (?,?,?)",
                ("primary", payload, 0),
            )
            con.commit()
        finally:
            con.close()
        ctx = collect(home)
        assert ctx.agent_auth_profile_store_length == len(payload)
        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail


class TestPerAgentConsumersStayConsistent:
    """Same asymmetry as `TestConsumersStayConsistent` above, for the new per-agent
    signal: it hedges A1 but must never move the boolean leg RISK-02/the capability
    graph read."""

    def test_agent_auth_material_hedges_a1_but_leaves_the_chain_and_graph_off(
        self, tmp_path
    ):
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("M")}
        }})
        home = _agent_home(
            tmp_path, "h", credentials=True, agent_auth_store_json=payload
        )
        ctx = collect(home)
        assert check_trifecta(ctx).status == WARN
        assert _a1_leg(ctx) is False
        assert _risk02_present(ctx) is False
        assert _graph_main_secrets(ctx) is False


# --------------------------------------------------------- CLAWSECCHECK-B-845 follow-up
# (2026-09-23) — the two blocking defects an independent C-135 review found in the
# per-agent reader above: an unbounded hang, and a silent scan-coverage gap. Recorded as
# a Pulse comment on the task, dated 2026-09-23T06:12. That review round's own fixes
# reused existing machinery (`trajectorystore._open_and_verify_table`/`_table_kind`,
# `trajectorystore.sqlite_db_paths_capped`), which is WHY the earlier version of this
# comment claimed no fresh C-135 pass was needed -- but round 2's own review turned up a
# SECOND, structurally different hang (a planted FIFO, at both the main DB path and a
# `-journal` sidecar path -- see `TestAgentAuthProfileStoreFifoGuard` below) plus a
# never-wired disclosure gap in the cap hedge, in that SAME "reuses existing machinery"
# code. So "reuses existing machinery" is not, on its own, evidence a change needs no
# adversarial pass -- every round on this bug has needed one, including this one.


def _plant_recursive_view_auth_profile_store(tmp_path: Path, name: str = "h") -> Path:
    """A home whose ONLY per-agent database has `auth_profile_store` defined as a
    recursive VIEW — the exact pathological object the C-135 rejection reproduced: a
    plain `SELECT ... FROM auth_profile_store` against this file never terminates on its
    own, because the view body is an infinite `WITH RECURSIVE` generator with no LIMIT.
    Real OpenClaw never writes a VIEW here (grounded: every write path this table's own
    row-key comment cites goes through a `CREATE TABLE`), so this is a hostile/corrupt
    object, not a real shape — the fix must refuse to query it, not hedge it away.

    `store_key` is `'k' || x` (`'k1'`, `'k2'`, `'k3'`, ...), NOT the constant
    `'primary'` an earlier version of this fixture used. That earlier version returned
    instantly even against the ORIGINAL, unfixed reader (round 1): the real query this
    module runs is `SELECT LENGTH(store_json) FROM auth_profile_store WHERE store_key =
    'primary'`, and SQLite evaluates a recursive CTE lazily, row at a time -- with a
    constant `store_key`, the WHERE clause is satisfied by the FIRST row the view ever
    emits, so `.fetchone()` returns after one step regardless of whether the reader does
    any schema verification at all. That made the fixture unable to tell a fixed reader
    from a vulnerable one -- it passed either way. With `store_key` genuinely varying
    per row, `store_key = 'primary'` never matches ANY row the view can ever produce,
    so an unfixed reader must keep pulling rows forever looking for a match that does
    not exist -- a real, reproduced hang (verified against a pre-fix build of this
    reader before this fixture was accepted), not just an infinite view definition that
    happens not to be exercised.
    """
    home = tmp_path / name
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text(json.dumps(CFG))
    os.chmod(home / "openclaw.json", 0o600)
    agent_dir = home / "agents" / "main" / "agent"
    agent_dir.mkdir(parents=True)
    conn = sqlite3.connect(agent_dir / "openclaw-agent.sqlite")
    try:
        conn.execute(
            "CREATE VIEW auth_profile_store AS "
            "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt) "
            "SELECT 'k' || x AS store_key, CAST(x AS TEXT) AS store_json FROM cnt"
        )
        conn.commit()
    finally:
        conn.close()
    return home


class TestAgentAuthProfileStoreHangGuard:
    """A hostile per-agent database whose `auth_profile_store` is actually a recursive
    VIEW hung `collect()` forever before this fix — the C-135 reviewer measured it
    killed at both 25s and 90s timeouts, because the reader opened the connection
    directly and issued an unbounded `SELECT ... FROM auth_profile_store` against a view
    body with no row bound. Reusing `trajectorystore._open_and_verify_table`/
    `_table_kind` refuses the VIEW from its `sqlite_master.type` alone, before the view
    body is ever evaluated — so this closes the hang without weakening detection
    (OpenClaw's own runtime never reads through a VIEW here either).

    Run in a daemon thread with a bounded `join()`, not a bare call: if this ever
    regresses, THIS test fails in a few seconds instead of hanging the whole suite the
    way the reviewer's own run did.
    """

    def test_a_recursive_view_does_not_hang_collect(self, tmp_path):
        home = _plant_recursive_view_auth_profile_store(tmp_path)
        result: dict = {}

        def _run():
            result["ctx"] = collect(home)

        thread = threading.Thread(target=_run, daemon=True)
        started = time.monotonic()
        thread.start()
        thread.join(timeout=10)
        elapsed = time.monotonic() - started

        assert not thread.is_alive(), (
            "collect() did not return within 10s against a recursive-VIEW "
            "auth_profile_store -- the exact hang this fix closes"
        )
        assert elapsed < 10, f"collect() took {elapsed:.1f}s -- expected a few seconds"

        ctx = result["ctx"]
        # Behaves like "could not read this store", not like a partial/successful read:
        # the same honest UNDETERMINED every other unreadable-table case in this reader
        # already reports (see `_collect_agent_auth_profile_store_presence`).
        assert ctx.agent_auth_profile_store_read is False
        assert ctx.agent_auth_profile_store_length is None


# ------------------------------------------------------------------- cap disclosure


def _make_agent_auth_db(agent_dir: Path, payload: str) -> None:
    agent_dir.mkdir(parents=True)
    con = sqlite3.connect(agent_dir / "openclaw-agent.sqlite")
    try:
        con.execute(
            "CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, "
            "store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)"
        )
        con.execute(
            "INSERT INTO auth_profile_store VALUES (?,?,?)",
            ("primary", payload, 0),
        )
        con.commit()
    finally:
        con.close()


class TestAgentDatabaseCapDisclosure:
    """The per-agent DB discovery (`trajectorystore.sqlite_db_paths`) silently caps at
    `_MAX_SQLITE_DBS` -- before this fix, a home with more agents than that read as an
    exhaustive sweep with nothing saying otherwise. `_MAX_SQLITE_DBS + 1` agents (all
    holding the SAME real material, so which ones the cap keeps is irrelevant to whether
    the hedge fires) reproduces the gap deterministically.
    """

    def _many_agent_home(self, tmp_path: Path, count: int) -> tuple[Path, str]:
        home = tmp_path / "h"
        home.mkdir(parents=True)
        (home / "openclaw.json").write_text(json.dumps(CFG))
        os.chmod(home / "openclaw.json", 0o600)
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("N")}
        }})
        for i in range(count):
            agent_dir = home / "agents" / f"agent-{i:03d}" / "agent"
            _make_agent_auth_db(agent_dir, payload)
        return home, payload

    def test_sqlite_db_paths_capped_reports_the_overflow(self, tmp_path):
        """Unit-level check of the new trajectorystore helper on its own, independent
        of the collector/check wiring below."""
        home, _payload = self._many_agent_home(tmp_path, _MAX_SQLITE_DBS + 1)
        assert sqlite_db_paths_capped(home) is True

    def test_sqlite_db_paths_capped_is_false_under_the_cap(self, tmp_path):
        home, _payload = self._many_agent_home(tmp_path, _MAX_SQLITE_DBS)
        assert sqlite_db_paths_capped(home) is False

    def test_the_finding_discloses_not_every_agent_was_checked(self, tmp_path):
        home, _payload = self._many_agent_home(tmp_path, _MAX_SQLITE_DBS + 1)
        ctx = collect(home)
        assert ctx.agent_auth_profile_store_capped is True
        assert ctx.agent_auth_profile_store_read is True
        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail
        assert "not every agent" in finding.detail

    def test_no_disclosure_when_every_agent_fits_under_the_cap(self, tmp_path):
        """Regression control: the disclosure clause must not fire when nothing was
        actually capped."""
        home, _payload = self._many_agent_home(tmp_path, _MAX_SQLITE_DBS)
        ctx = collect(home)
        assert ctx.agent_auth_profile_store_capped is False
        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail
        assert "not every agent" not in finding.detail

    def test_the_finding_discloses_capped_even_when_nothing_found_among_checked_agents(
        self, tmp_path
    ):
        """B-845 round 3 BLOCKING fix. A C-135 review found the ORIGINAL wiring only
        ever read `agent_auth_profile_store_capped` from INSIDE the
        `agent_auth_store_present` branch -- so a home with real material ONLY in the
        one agent database past the cap (every database the sweep actually checks
        holds nothing but the empty-store shell) read as a clean, unhedged PASS: since
        nothing was FOUND among the checked agents, the whole disclosure branch never
        ran, silently dropping the fact that 51 agent databases existed and only 50
        were ever looked at.

        `_MAX_SQLITE_DBS` (50) agents sorted first (`agent-000`..`agent-049`) each get
        only the empty-store shape; the 51st (`agent-050`), sorting LAST and excluded
        by the cap, is the ONLY one holding real material -- reproducing the exact gap
        the review reported, deterministically (`sqlite_db_paths` sorts and truncates,
        so which agent the cap drops is not left to chance here).
        """
        home = tmp_path / "h"
        home.mkdir(parents=True)
        (home / "openclaw.json").write_text(json.dumps(CFG))
        os.chmod(home / "openclaw.json", 0o600)
        empty_payload = json.dumps({"version": 1, "profiles": {}}, separators=(",", ":"))
        real_payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("P")}
        }})
        for i in range(_MAX_SQLITE_DBS):
            agent_dir = home / "agents" / f"agent-{i:03d}" / "agent"
            _make_agent_auth_db(agent_dir, empty_payload)
        agent_dir = home / "agents" / f"agent-{_MAX_SQLITE_DBS:03d}" / "agent"
        _make_agent_auth_db(agent_dir, real_payload)

        ctx = collect(home)
        assert ctx.agent_auth_profile_store_capped is True
        # Nothing FOUND among the 50 agents the sweep actually checked -- each of
        # those only ever holds the empty-store shell, so the largest length observed
        # across them is exactly that shell's own length.
        assert ctx.agent_auth_profile_store_length == len(empty_payload)

        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail
        assert "not every agent" in finding.detail
        # The "at least one agent's own ... holds more than an empty shell" sentence
        # must NOT fire here -- nothing was found among the checked agents, only the
        # capped sweep itself is the reason this WARNs.
        assert "holds more than an empty shell" not in finding.detail


# --------------------------------------------------------------- FIFO / sidecar guard


class TestAgentAuthProfileStoreFifoGuard:
    """B-845 round 3 BLOCKING fix: a second, structurally different hang from the
    recursive-VIEW one above, found in the SAME code path by the SAME C-135 review.

    A database path -- or one of the sidecar paths SQLite itself consults before this
    module's own schema verification ever runs (`-journal`, `-wal`, `-shm`) -- that is
    a FIFO, not a regular file, blocks in `sqlite3.connect`/the very first
    `sqlite_master` read: SQLite blocks reading (or checking for) a FIFO with no
    writer on the other end. This closed the SAME `_open_and_verify_table` path the
    recursive-VIEW fix reuses, but earlier: `_table_kind`'s own `sqlite_master` read
    never gets a chance to refuse anything, because SQLite checks for a hot journal
    sidecar BEFORE that read even starts.

    Reused the SAME bounded daemon-thread pattern as
    `TestAgentAuthProfileStoreHangGuard` above, for the same reason: if this ever
    regresses, these tests fail in a few seconds, not by hanging the whole suite.
    """

    def _collect_bounded(self, home: Path, timeout: float = 10.0) -> "tuple[object, float]":
        result: dict = {}

        def _run():
            result["ctx"] = collect(home)

        thread = threading.Thread(target=_run, daemon=True)
        started = time.monotonic()
        thread.start()
        thread.join(timeout=timeout)
        elapsed = time.monotonic() - started
        assert not thread.is_alive(), (
            f"collect() did not return within {timeout:.0f}s -- the exact hang "
            "this fix closes"
        )
        return result["ctx"], elapsed

    def test_main_path_fifo_does_not_hang_collect(self, tmp_path):
        """`mkfifo` at the main database path itself -- the DB path IS the FIFO."""
        home = tmp_path / "h"
        home.mkdir(parents=True)
        (home / "openclaw.json").write_text(json.dumps(CFG))
        os.chmod(home / "openclaw.json", 0o600)
        agent_dir = home / "agents" / "main" / "agent"
        agent_dir.mkdir(parents=True)
        os.mkfifo(agent_dir / "openclaw-agent.sqlite")

        ctx, elapsed = self._collect_bounded(home)
        assert elapsed < 10, f"collect() took {elapsed:.1f}s -- expected a few seconds"
        # Behaves like "could not read this store" -- same honest UNDETERMINED every
        # other unreadable-table case in this reader already reports.
        assert ctx.agent_auth_profile_store_read is False
        assert ctx.agent_auth_profile_store_length is None

    def test_journal_sidecar_fifo_does_not_hang_collect(self, tmp_path):
        """A genuine, regular database (with a real, readable `auth_profile_store`
        table) plus a FIFO at its `-journal` SIDECAR path -- SQLite checks for a hot
        journal at the very FIRST `sqlite_master` read, before `_table_kind`'s own
        schema verification runs at all, so this hangs even earlier than the
        main-path case above.
        """
        home = tmp_path / "h"
        home.mkdir(parents=True)
        (home / "openclaw.json").write_text(json.dumps(CFG))
        os.chmod(home / "openclaw.json", 0o600)
        agent_dir = home / "agents" / "main" / "agent"
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("Q")}
        }})
        _make_agent_auth_db(agent_dir, payload)
        os.mkfifo(str(agent_dir / "openclaw-agent.sqlite") + "-journal")

        ctx, elapsed = self._collect_bounded(home)
        assert elapsed < 10, f"collect() took {elapsed:.1f}s -- expected a few seconds"
        assert ctx.agent_auth_profile_store_read is False
        assert ctx.agent_auth_profile_store_length is None

    def test_symlinked_main_db_with_target_journal_fifo_does_not_hang_collect(
        self, tmp_path
    ):
        """Round 4 BLOCKING fix. The main DB path is a RELATIVE SYMLINK to a real,
        regular database (`x.db`) in the SAME directory; the FIFO is planted at the
        TARGET's own `-journal` sidecar name (`x.db-journal`), never the symlink's own
        (`openclaw-agent.sqlite-journal`). SQLite resolves the symlink to its target
        before it ever looks for a hot journal, so this is the sidecar name that
        actually matters -- the round-3 guard, which only ever built sidecar names
        from the path AS GIVEN, never looked here, and hung the same way the round-3
        repros did.
        """
        home = tmp_path / "h"
        home.mkdir(parents=True)
        (home / "openclaw.json").write_text(json.dumps(CFG))
        os.chmod(home / "openclaw.json", 0o600)
        agent_dir = home / "agents" / "main" / "agent"
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("R")}
        }})
        _make_agent_auth_db(agent_dir, payload)
        symlink_path = agent_dir / "openclaw-agent.sqlite"
        target_path = agent_dir / "x.db"
        symlink_path.rename(target_path)
        os.symlink("x.db", symlink_path)  # relative symlink, same directory
        os.mkfifo(str(target_path) + "-journal")

        ctx, elapsed = self._collect_bounded(home)
        assert elapsed < 10, f"collect() took {elapsed:.1f}s -- expected a few seconds"
        assert ctx.agent_auth_profile_store_read is False
        assert ctx.agent_auth_profile_store_length is None

    def test_symlinked_main_db_without_fifo_reads_successfully(self, tmp_path):
        """Positive control for the round-4 fix: a symlink to a genuine regular DB
        with NO FIFO anywhere (neither at the symlink's own sidecar names nor the
        target's) must still read successfully and produce a WARN -- the new
        realpath-based check must not itself become a new false refusal.
        """
        home = tmp_path / "h"
        home.mkdir(parents=True)
        (home / "openclaw.json").write_text(json.dumps(CFG))
        os.chmod(home / "openclaw.json", 0o600)
        agent_dir = home / "agents" / "main" / "agent"
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("S")}
        }})
        _make_agent_auth_db(agent_dir, payload)
        symlink_path = agent_dir / "openclaw-agent.sqlite"
        target_path = agent_dir / "x.db"
        symlink_path.rename(target_path)
        os.symlink("x.db", symlink_path)

        ctx, elapsed = self._collect_bounded(home)
        assert elapsed < 10, f"collect() took {elapsed:.1f}s -- expected a few seconds"
        assert ctx.agent_auth_profile_store_read is True
        assert ctx.agent_auth_profile_store_length == len(payload)
        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail
