"""B-1014: A1 no longer reads PASS when an auth-profile store exists but cannot be read.

Measured 2026-11-04 (OpenClaw 2026.10.10): A1 WARNed on a copy of the real home and turned
into a clean PASS once ``state/openclaw.sqlite`` was 4 KB of random bytes, or an anchor-only
PostgreSQL engine file (refused since B-1010). The presence reader left
``auth_profile_store_read`` False -- the same value as "no state DB at all" -- so the
sensitive-data hedge never fired: a PASS on missing evidence (Golden Rule #4).

Now an unread store hedges A1 to WARN, the same way an unreadable ``credentials/`` does.
It is a hedge, never a leg: the trifecta leg, RISK-02 and the capability graph stay where
they were (``risk.py::_has_sensitive_data`` asserts legs and ignores unread stores, B-730).
"No DB" and "DB predating the table" keep today's PASS.

Offline, stdlib only, writes only under ``tmp_path``.
"""
from __future__ import annotations

import sqlite3

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_trifecta
from clawseccheck.collector import collect
from test_b749_auth_profile_store_presence import (
    _EMPTY_STORE_JSON,
    _a1_leg,
    _graph_main_secrets,
    _home,
    _risk02_present,
    _token,
)

_ANCHOR_DDL = (
    "CREATE TABLE openclaw_engine_anchor (store_id TEXT NOT NULL, engine TEXT NOT NULL, "
    "schema TEXT NOT NULL)"
)


def _garbage_state_db(home):
    state = home / "state"
    state.mkdir()
    (state / "openclaw.sqlite").write_bytes(bytes(range(256)) * 16)


def _anchor_state_db(home):
    state = home / "state"
    state.mkdir()
    con = sqlite3.connect(state / "openclaw.sqlite")
    try:
        con.execute(_ANCHOR_DDL)
        con.commit()
    finally:
        con.close()


def test_garbage_state_db_hedges_a1_instead_of_pass(tmp_path):
    home = _home(tmp_path, "h")
    _garbage_state_db(home)
    ctx = collect(home)
    assert ctx.auth_profile_store_read is False
    assert ctx.auth_profile_store_unreadable is True
    f = check_trifecta(ctx)
    assert f.status == WARN, f.detail
    assert "Cannot determine from config: sensitive data" in f.detail
    assert "shared auth-profile store (state/openclaw.sqlite) exists but could not be read" in f.detail
    assert "could not read OpenClaw's auth-profile store" in f.fix


def test_engine_anchor_state_db_hedges_a1(tmp_path):
    home = _home(tmp_path, "h")
    _anchor_state_db(home)
    ctx = collect(home)
    assert ctx.auth_profile_store_unreadable is True
    assert check_trifecta(ctx).status == WARN


def test_state_db_without_the_table_keeps_pass(tmp_path):
    home = _home(tmp_path, "h", table="something_else", make_db=True)
    ctx = collect(home)
    assert ctx.auth_profile_store_unreadable is False
    assert check_trifecta(ctx).status == PASS


def test_no_state_db_keeps_pass(tmp_path):
    ctx = collect(_home(tmp_path, "h"))
    assert ctx.auth_profile_store_unreadable is False
    assert ctx.agent_auth_profile_store_unreadable is False
    assert check_trifecta(ctx).status == PASS


def test_readable_empty_store_keeps_pass(tmp_path):
    ctx = collect(_home(tmp_path, "h", auth_store_json=_EMPTY_STORE_JSON))
    assert ctx.auth_profile_store_read is True
    assert ctx.auth_profile_store_unreadable is False
    assert check_trifecta(ctx).status == PASS


def test_readable_store_with_material_keeps_its_own_warn(tmp_path):
    payload = '{"version":1,"profiles":{"a":{"key":"%s"}}}' % _token("D")
    ctx = collect(_home(tmp_path, "h", auth_store_json=payload))
    f = check_trifecta(ctx)
    assert f.status == WARN
    assert "could not be read" not in f.detail
    assert "config_machine_state" in f.fix


def test_non_table_config_machine_state_hedges(tmp_path):
    home = _home(tmp_path, "h", table="real_rows", make_db=True)
    con = sqlite3.connect(home / "state" / "openclaw.sqlite")
    try:
        con.execute("CREATE VIEW config_machine_state AS SELECT * FROM real_rows")
        con.commit()
    finally:
        con.close()
    ctx = collect(home)
    assert ctx.auth_profile_store_unreadable is True
    assert check_trifecta(ctx).status == WARN


def test_unreadable_per_agent_store_hedges(tmp_path):
    home = _home(tmp_path, "h")
    d = home / "agents" / "main" / "agent"
    d.mkdir(parents=True)
    (d / "openclaw-agent.sqlite").write_bytes(b"not a database" * 300)
    ctx = collect(home)
    assert ctx.agent_auth_profile_store_unreadable is True
    f = check_trifecta(ctx)
    assert f.status == WARN
    assert "per-agent auth-profile store" in f.detail


def test_hedge_never_raises_the_leg_or_a_risk_chain(tmp_path):
    home = _home(tmp_path, "h")
    _garbage_state_db(home)
    ctx = collect(home)
    assert _a1_leg(ctx) is False
    assert _risk02_present(ctx) is False
    assert _graph_main_secrets(ctx) is False


def test_unlistable_agent_directory_hedges(tmp_path, monkeypatch):
    """C-135 round 1: an ``agents/`` tree the walk could not list returned no paths --
    the same empty list as "no agents" -- and A1 read PASS. Simulated through the walk's
    own ``dbs_unlistable`` stat (a real chmod 000 is root-dependent)."""
    from clawseccheck import trajectorystore

    real = trajectorystore._sqlite_dbs

    def fake(home, *a, stats=None, **k):
        out = real(home, *a, stats=stats, **k)
        if stats is not None:
            stats["dbs_unlistable"] = 1
        return out

    monkeypatch.setattr(trajectorystore, "_sqlite_dbs", fake)
    ctx = collect(_home(tmp_path, "h"))
    assert ctx.agent_auth_profile_store_unreadable is True
    assert any("could not list every per-agent directory" in e for e in ctx.errors)
    assert check_trifecta(ctx).status == WARN


def test_unread_and_capped_fix_names_both(tmp_path, monkeypatch):
    from clawseccheck import trajectorystore

    monkeypatch.setattr(trajectorystore, "sqlite_db_paths_capped", lambda home: True)
    home = _home(tmp_path, "h")
    _garbage_state_db(home)
    f = check_trifecta(collect(home))
    assert f.status == WARN
    assert "could not read OpenClaw's auth-profile store" in f.fix
    assert "check the remaining agents' stores too" in f.fix
