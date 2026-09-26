"""CLAWSECCHECK-B-908 — wire `trajectorystore._refuse_non_regular_sqlite_paths` into
every direct `sqlite3.connect()` call site in `collector.py`.

`collector.py` has eleven direct `sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro",
uri=True)` call sites, none of which guarded against *db_path* (or one of SQLite's own
sidecar paths it consults BEFORE any schema check in this module ever runs — `-journal`
/ `-wal` / `-shm`) being a FIFO, device node, directory, or socket instead of a regular
file. `sqlite3.connect`'s very first read blocks forever on a FIFO with no writer — a
real hang, reachable through a full audit, `--retest`, `--vet-all`, and the plugin
sweep. `trajectorystore._refuse_non_regular_sqlite_paths` already closes this for
trajectorystore.py's own connections (B-845, rounds 3-5); this fix calls it, unchanged,
immediately before each of collector.py's own eleven `sqlite3.connect()` calls, inside
the same `try` block each call site already has — so a refusal is caught and disclosed
exactly the way that call site already discloses any other `sqlite3.Error`.

Two verification tiers, matching the eleven call sites' actual traffic/shape:

1. FULL hang-reproduction (`TestFullHangReproduction` below) — a real `mkfifo` at the
   state DB path, a bounded daemon thread (mirrors
   `TestAgentAuthProfileStoreFifoGuard._collect_bounded` in
   tests/test_b749_auth_profile_store_presence.py), for three representative sites that
   between them cover both wiring shapes in collector.py:
   - `_collect_cron_run_logs` — runs unconditionally at the top of every `_collect_cron`
     call (both store branches) as well as standalone; the highest-traffic of the eleven.
   - `_collect_audit_events` — the largest table this module reads (up to
     `_MAX_AUDIT_EVENTS` rows plus an aggregate query), and security-relevant (feeds
     `check_audit_trail_signals`).
   - `_collect_plugin_trust` — the ONE call site whose `try` around `sqlite3.connect`
     is split from the read logic (a second, nested `try` handles the PRAGMA/SELECTs),
     structurally different from the other ten single-`try` sites, so it is verified
     independently rather than assumed to share their shape's proof.

2. Lighter, spy-based wiring verification (`TestGuardIsInvoked` below) — a call-through
   spy on the real `_refuse_non_regular_sqlite_paths` confirms it is actually invoked,
   with the correct `db_path`, for each of the remaining eight call sites, run against a
   genuine (if often empty) regular SQLite file — this doubles as the "no accidental
   refusal of a legitimate database" sanity check for those sites, since the spy calls
   through to the real guard rather than mocking it away.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from clawseccheck import trajectorystore
from clawseccheck.collector import (
    Context,
    _collect_audit_events,
    _collect_auth_profile_store_presence,
    _collect_capture_state,
    _collect_config_machine_state,
    _collect_cron,
    _collect_cron_run_logs,
    _collect_plugin_trust,
    _collect_skill_library_state,
    _collect_subagent_runs,
    _collect_update_runs,
    _flag_shadowed_cron_store,
)


def _fifo_state_db(tmp_path) -> tuple[Path, Path]:
    """A fake ~/.openclaw whose `state/openclaw.sqlite` is a FIFO, not a database."""
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    db_path = state / "openclaw.sqlite"
    os.mkfifo(db_path)
    return home, db_path


def _empty_regular_db(tmp_path) -> tuple[Path, Path]:
    """A fake ~/.openclaw whose `state/openclaw.sqlite` is a genuine, if table-less,
    regular SQLite file — the ordinary shape most real homes have for most of these
    tables most of the time (a state DB that predates a given feature's own tables)."""
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    db_path = state / "openclaw.sqlite"
    conn = sqlite3.connect(db_path)
    conn.close()
    return home, db_path


def _collect_bounded(fn, *args, timeout: float = 10.0) -> float:
    """Bounded daemon-thread call — mirrors
    `TestAgentAuthProfileStoreFifoGuard._collect_bounded`
    (tests/test_b749_auth_profile_store_presence.py). If a guard ever regresses, this
    fails in a few seconds instead of hanging the whole suite."""
    result: dict = {}

    def _run():
        fn(*args)
        result["done"] = True

    thread = threading.Thread(target=_run, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(timeout=timeout)
    elapsed = time.monotonic() - started
    assert not thread.is_alive(), (
        f"{getattr(fn, '__name__', fn)} did not return within {timeout:.0f}s -- "
        "the exact hang this fix closes"
    )
    assert result.get("done") is True
    return elapsed


# --------------------------------------------------------------------------------
# Tier 1: full hang-reproduction, three representative call sites.
# --------------------------------------------------------------------------------


class TestFullHangReproduction:
    def test_collect_cron_run_logs_fifo_does_not_hang(self, tmp_path):
        home, db_path = _fifo_state_db(tmp_path)
        ctx = Context(home=home)
        elapsed = _collect_bounded(_collect_cron_run_logs, home, ctx)
        assert elapsed < 10, f"took {elapsed:.1f}s -- expected a few seconds"
        # Refused, not silently "absent": same "found but unreadable" disclosure every
        # other unreadable-table case in this reader already gets.
        assert ctx.cron_run_logs_found is True
        assert ctx.cron_run_logs_parse_error is True
        assert any(str(db_path) in e and "not a regular file" in e for e in ctx.errors), \
            ctx.errors

    def test_collect_audit_events_fifo_does_not_hang(self, tmp_path):
        home, db_path = _fifo_state_db(tmp_path)
        ctx = Context(home=home)
        elapsed = _collect_bounded(_collect_audit_events, home, ctx)
        assert elapsed < 10, f"took {elapsed:.1f}s -- expected a few seconds"
        assert ctx.audit_events_found is True
        assert ctx.audit_events_parse_error is True
        assert any(str(db_path) in e and "not a regular file" in e for e in ctx.errors), \
            ctx.errors

    def test_collect_plugin_trust_fifo_does_not_hang(self, tmp_path):
        """This call site's `try` wraps ONLY `sqlite3.connect` (the read logic below it
        is a separate, nested `try`) -- a structurally different wiring shape from the
        other ten sites, verified independently rather than assumed."""
        home, db_path = _fifo_state_db(tmp_path)
        ctx = Context(home=home)
        elapsed = _collect_bounded(_collect_plugin_trust, home, ctx)
        assert elapsed < 10, f"took {elapsed:.1f}s -- expected a few seconds"
        assert ctx.plugin_trust_found is True
        assert ctx.plugin_trust_parse_error is True
        assert ctx.plugin_index_found is True
        assert ctx.plugin_index_parse_error is True
        assert any(str(db_path) in e and "not a regular file" in e for e in ctx.errors), \
            ctx.errors

    def test_collect_cron_sqlite_fallback_fifo_does_not_hang(self, tmp_path):
        """End-to-end through the public entry point `_collect_cron` itself (no legacy
        JSON store, so it falls to the SQLite `cron_jobs` table) -- confirms the whole
        call chain (`_collect_cron` -> `_collect_cron_run_logs` -> back into
        `_collect_cron`'s own SQLite branch), not just one reader in isolation, never
        hangs on the shared state DB."""
        home, db_path = _fifo_state_db(tmp_path)
        ctx = Context(home=home)
        elapsed = _collect_bounded(_collect_cron, home, ctx)
        assert elapsed < 10, f"took {elapsed:.1f}s -- expected a few seconds"
        assert ctx.cron_found is True
        assert ctx.cron_parse_error is True


# --------------------------------------------------------------------------------
# Tier 2: spy-based wiring verification, the remaining eight call sites.
# --------------------------------------------------------------------------------


class _Spy:
    """Call-through wrapper around the real guard: records every `db_path` it was
    invoked with while still enforcing the real refusal logic, so a spied run against a
    genuine database still behaves exactly as it would unpatched."""

    def __init__(self, real):
        self._real = real
        self.calls: list = []

    def __call__(self, db_path):
        self.calls.append(db_path)
        return self._real(db_path)


@pytest.fixture
def guard_spy(monkeypatch):
    real = trajectorystore._refuse_non_regular_sqlite_paths
    spy = _Spy(real)
    # Patched on the module object itself -- collector.py calls it as
    # `_trajectorystore._refuse_non_regular_sqlite_paths(...)` (an attribute lookup at
    # call time via its own `from . import trajectorystore as _trajectorystore`), so
    # patching the shared module attribute reaches every one of collector.py's call
    # sites regardless of which private alias each uses.
    monkeypatch.setattr(trajectorystore, "_refuse_non_regular_sqlite_paths", spy)
    return spy


class TestGuardIsInvoked:
    """Each test plants a genuine (if table-less) regular SQLite file — never a mock —
    at `state/openclaw.sqlite`, calls the ONE collector function owning that call site
    directly, and asserts the real guard was reached with the right `db_path`. Because
    the spy calls through to the real implementation, a false refusal of this ordinary,
    non-malicious database would make these tests fail too, doubling as the "no
    accidental refusal of a legitimate database" sanity check for these eight sites.
    """

    def test_flag_shadowed_cron_store(self, tmp_path, guard_spy):
        home, db_path = _empty_regular_db(tmp_path)
        ctx = Context(home=home)
        jobs_json = home / "cron" / "jobs.json"
        _flag_shadowed_cron_store(home, ctx, jobs_json)
        assert guard_spy.calls == [db_path]
        # No cron_jobs table on this empty DB -> silently unreadable, same as always.
        assert ctx.cron_store_shadowed is False

    def test_collect_auth_profile_store_presence(self, tmp_path, guard_spy):
        home, db_path = _empty_regular_db(tmp_path)
        ctx = Context(home=home)
        _collect_auth_profile_store_presence(home, ctx)
        assert guard_spy.calls == [db_path]
        # config_machine_state absent on this empty DB -> genuinely-absent branch, not
        # a refusal or a parse error.
        assert ctx.auth_profile_store_read is False
        assert ctx.auth_profile_store_length is None

    def test_collect_config_machine_state(self, tmp_path, guard_spy):
        home, db_path = _empty_regular_db(tmp_path)
        ctx = Context(home=home)
        _collect_config_machine_state(home, ctx)
        assert guard_spy.calls == [db_path]
        assert ctx.config_machine_state_read is False

    def test_collect_update_runs(self, tmp_path, guard_spy):
        home, db_path = _empty_regular_db(tmp_path)
        ctx = Context(home=home)
        _collect_update_runs(home, ctx)
        assert guard_spy.calls == [db_path]
        assert ctx.update_runs_read is False

    def test_collect_capture_state(self, tmp_path, guard_spy):
        home, db_path = _empty_regular_db(tmp_path)
        ctx = Context(home=home)
        _collect_capture_state(home, ctx)
        assert guard_spy.calls == [db_path]
        assert ctx.capture_tables_found is False

    def test_collect_skill_library_state(self, tmp_path, guard_spy):
        home, db_path = _empty_regular_db(tmp_path)
        ctx = Context(home=home)
        _collect_skill_library_state(home, ctx)
        assert guard_spy.calls == [db_path]
        assert ctx.skill_library_entries_read is False
        assert ctx.skill_uploads_read is False

    def test_collect_subagent_runs(self, tmp_path, guard_spy):
        home, db_path = _empty_regular_db(tmp_path)
        ctx = Context(home=home)
        _collect_subagent_runs(home, ctx)
        assert guard_spy.calls == [db_path]
        assert ctx.subagent_runs_found is False

    def test_collect_cron_own_sqlite_branch(self, tmp_path, guard_spy):
        """`_collect_cron` itself calls `_collect_cron_run_logs` first (its own,
        separate call site), then falls to its own SQLite `cron_jobs` read when no
        legacy JSON store exists -- two of the eleven call sites, both against the
        same `db_path`, exercised together the way `collect()` actually calls them."""
        home, db_path = _empty_regular_db(tmp_path)
        ctx = Context(home=home)
        _collect_cron(home, ctx)
        assert guard_spy.calls == [db_path, db_path]
        assert ctx.cron_found is False
