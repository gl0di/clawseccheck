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

No independent C-135 pass was performed on this change -- flagged explicitly in the Pulse
comment landing it. This file is the implementer's own test suite, not adversarial review.
"""
from __future__ import annotations

import json
import os
import sqlite3
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


# --------------------------------------------------------- B-889: view-masquerade hardening


class TestB889ViewMasqueradeHardening:
    """CLAWSECCHECK-B-889 — `_collect_auth_profile_store_presence` ran ``SELECT
    LENGTH(value_json) FROM config_machine_state ...`` directly against
    `state/openclaw.sqlite` without first checking the name resolves to a real TABLE,
    not a VIEW — the identical attack shape `trajectorystore._table_kind` was hardened
    against for `trajectory_runtime_events` (adversarial review, B-811, 2026-09-15;
    see `test_f187_trajectory_sqlite_corroborator.py
    ::test_corroborate_refuses_a_view_masquerading_as_the_trajectory_table` for the
    sibling reader's own pin of the same shape). This reader now reuses
    `trajectorystore._table_kind` verbatim (imported into `collector.py` as
    `_sqlite_table_kind`) rather than re-deriving the check.

    Impact stays bounded either way — only `LENGTH(value_json)` is ever selected, never
    the value — so the attack surface this closes is spoofing the presence/length
    signal itself (a false WARN, or suppressing a real one), not a credential leak."""

    def test_view_masquerading_as_config_machine_state_is_refused(self, tmp_path):
        """The bug's own reproduction: a decoy table plus a VIEW named
        `config_machine_state` that projects a spoofed `state_key`/`value_json` row.
        Before the fix this landed `ctx.auth_profile_store_read = True` with a length
        sourced from a table the code never named, and no disclosure at all. After the
        fix the row must be refused outright — not silently trusted, and not silently
        merged into the quieter "table predates this feature" UNDETERMINED case."""
        home = _home(tmp_path, "h", credentials=True)
        state = home / "state"
        state.mkdir()
        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            conn.execute(
                "CREATE TABLE decoy_secrets "
                "(store_key TEXT, store_json TEXT, updated_at INTEGER)"
            )
            spoofed = json.dumps({"version": 1, "profiles": {
                "anthropic:default": {"type": "api_key", "key": _token("V")}
            }})
            conn.execute(
                "INSERT INTO decoy_secrets VALUES (?, ?, ?)",
                ("authProfiles.store", spoofed, 0),
            )
            conn.execute(
                "CREATE VIEW config_machine_state AS "
                "SELECT store_key AS state_key, store_json AS value_json "
                "FROM decoy_secrets"
            )
            conn.commit()
        finally:
            conn.close()

        ctx = collect(home)
        assert ctx.auth_profile_store_read is False
        assert ctx.auth_profile_store_length is None
        assert any(
            "config_machine_state" in e and "did not resolve to a real table" in e
            for e in ctx.errors
        ), ctx.errors
        # The downstream hedge must never fire off a signal that was never really read.
        finding = check_trifecta(ctx)
        assert finding.status == PASS, finding.detail

    def test_a_genuine_table_still_reads_correctly_after_the_hardening(self, tmp_path):
        """Clean-fixture control: an ordinary, honest `config_machine_state` TABLE (the
        real shape every fleet machine has) must still be read exactly as before — the
        hardening must not turn every legitimate read into a refusal."""
        payload = json.dumps({"version": 1, "profiles": {
            "anthropic:default": {"type": "api_key", "key": _token("W")}
        }})
        home = _home(tmp_path, "h", auth_store_json=payload)
        ctx = collect(home)
        assert ctx.auth_profile_store_read is True
        assert ctx.auth_profile_store_length == len(payload)
        assert not any(
            "config_machine_state" in e or "auth-profile" in e for e in ctx.errors
        ), ctx.errors

    def test_an_embedded_nul_byte_does_not_truncate_the_measured_length(self, tmp_path):
        """Round 2 of B-889 (reviewer-found, reproduced independently here): a bare
        `LENGTH(value_json)` on a TEXT column stops counting at the first embedded NUL
        byte (SQLite computes it as if by C's `strlen()`) -- the IDENTICAL bug class
        B-811 round 2 already fixed for `trajectorystore.py`'s own `session_id`/
        `event_json` queries (see that module's `_SELECT_TRAJECTORY_ROWS`/
        `_SELECT_TRAJECTORY_EVENT_JSON` comments). This is a genuine, honestly-stored
        `config_machine_state` TABLE -- it passes `_table_kind` cleanly, no VIEW trick
        needed -- so round 1's hardening does not touch this route at all. A real
        >500KB payload starting with one NUL byte must still measure as its true byte
        length, not silently truncate to (near) zero and suppress the hedge below the
        27-byte empty-store threshold."""
        payload = "\x00" + ("A" * 500_000)
        home = tmp_path / "h"
        home.mkdir()
        (home / "openclaw.json").write_text(json.dumps(CFG))
        os.chmod(home / "openclaw.json", 0o600)
        state = home / "state"
        state.mkdir()
        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            conn.execute(
                "CREATE TABLE config_machine_state "
                "(state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)"
            )
            conn.execute(
                "INSERT INTO config_machine_state VALUES (?, ?, ?)",
                ("authProfiles.store", payload, 0),
            )
            conn.commit()
        finally:
            conn.close()

        ctx = collect(home)
        assert ctx.auth_profile_store_read is True
        assert ctx.auth_profile_store_length == len(payload) == 500_001
        finding = check_trifecta(ctx)
        assert finding.status == WARN, finding.detail
