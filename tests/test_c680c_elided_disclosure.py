"""CLAWSECCHECK-C-680 item 2: a state document padded past the shallow reader's depth is visible.

Since C-664 the collector reads plugin trust, the plugin index, subagent rows and the machine
state with the shallow reader. A document padded past 64 levels was recorded only in the run's
notes (`ctx.limit_hits` / `ctx.errors`); no finding showed it. These tests pin the rule each
consuming check now follows:

* a clean PASS over a padded document is UNKNOWN (the unread part could change the answer);
* a FAIL/WARN found in the part that WAS read stands, and its `fix` names the cut-off;
* an unpadded document gives exactly the finding it gave before (no new text anywhere).

The `detail` of a finding that existed before is never changed; the new sentence is in `fix`.
"""

from __future__ import annotations

import json
import os
import sqlite3

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from test_b294_cron_run_logs import _CRON_RUN_LOGS_DDL
from test_c664_deep_state_audit import (
    HOSTILE_MESSAGE,
    PADS,
    _build,
    _build_cron_json,
    _insert_machine_state,
    _nest,
    _plugin_home,
)

NOTE = "nests deeper than the audit reads"


def _finding(home, ident):
    ctx, findings, _score = audit(home)
    assert [f.id for f in findings if f.id.startswith("ERR:")] == []
    return ctx, {f.id: f for f in findings}[ident]


# ---------------------------------------------------------------------------------------
# plugin trust (B177) and plugin index (B187)
# ---------------------------------------------------------------------------------------

TRUST_SITES = ["plugin_state_row", "install_records_json"]


@pytest.mark.parametrize("site", TRUST_SITES)
def test_b177_unpadded_clean_is_pass_without_the_note(tmp_path, site):
    ctx, f = _finding(_build(site, tmp_path, "clean", None), "B177")
    assert f.status == PASS
    assert not getattr(ctx, "plugin_trust_elided", False)  # also runs on a tree without it
    assert NOTE not in f.detail + f.fix


@pytest.mark.parametrize("pad", PADS)
@pytest.mark.parametrize("site", TRUST_SITES)
def test_b177_padded_clean_is_unknown_not_pass(tmp_path, site, pad):
    ctx, f = _finding(_build(site, tmp_path, "clean", pad), "B177")
    assert ctx.plugin_trust_elided
    assert f.status == UNKNOWN
    assert NOTE in f.detail
    assert f.engine_degraded


@pytest.mark.parametrize("site", TRUST_SITES)
def test_b177_unpadded_fail_has_no_note(tmp_path, site):
    _ctx, f = _finding(_build(site, tmp_path, "hostile", None), "B177")
    assert f.status == FAIL
    assert NOTE not in f.detail + f.fix


@pytest.mark.parametrize("pad", PADS)
@pytest.mark.parametrize("site", TRUST_SITES)
def test_b177_fail_found_in_the_read_part_stands_and_says_so_in_fix(tmp_path, site, pad):
    _ctx, f = _finding(_build(site, tmp_path, "hostile", pad), "B177")
    assert f.status == FAIL
    assert NOTE not in f.detail  # the detail of an existing finding is not changed
    assert NOTE in f.fix


def test_b177_detail_is_byte_identical_with_and_without_padding(tmp_path):
    _c, plain = _finding(_build("install_records_json", tmp_path / "a", "hostile", None), "B177")
    _c, padded = _finding(_build("install_records_json", tmp_path / "b", "hostile", 201), "B177")
    assert plain.detail == padded.detail


def test_b187_unpadded_clean_is_pass_without_the_note(tmp_path):
    ctx, f = _finding(_build("plugins_json", tmp_path, "clean", None), "B187")
    assert f.status == PASS
    assert not getattr(ctx, "plugin_index_elided", False)
    assert NOTE not in f.detail + f.fix


@pytest.mark.parametrize("pad", PADS)
@pytest.mark.parametrize("site", ["plugins_json", "plugin_state_row"])
def test_b187_padded_clean_is_unknown_not_pass(tmp_path, site, pad):
    ctx, f = _finding(_build(site, tmp_path, "clean", pad), "B187")
    assert ctx.plugin_index_elided
    assert f.status == UNKNOWN
    assert NOTE in f.detail
    assert f.engine_degraded


def test_b187_unpadded_warn_has_no_note(tmp_path):
    _ctx, f = _finding(_build("plugins_json", tmp_path, "hostile", None), "B187")
    assert f.status == WARN
    assert NOTE not in f.detail + f.fix


@pytest.mark.parametrize("pad", PADS)
def test_b187_warn_found_in_the_read_part_stands_and_says_so_in_fix(tmp_path, pad):
    _ctx, f = _finding(_build("plugins_json", tmp_path, "hostile", pad), "B187")
    assert f.status == WARN
    assert NOTE not in f.detail
    assert NOTE in f.fix


def test_a_padded_index_does_not_touch_the_trust_verdict(tmp_path):
    """plugins_json padded, install_records_json clean: B177 keeps answering about the trust
    document it read in full."""
    ctx, f = _finding(_build("plugins_json", tmp_path, "clean", 201), "B187")
    assert ctx.plugin_index_elided and not ctx.plugin_trust_elided
    assert f.status == UNKNOWN


# ---------------------------------------------------------------------------------------
# subagent rows (B18)
# ---------------------------------------------------------------------------------------

SUB_SITES = ["subagent_outcome_json", "subagent_payload_json"]


@pytest.mark.parametrize("site", SUB_SITES)
def test_b18_unpadded_rows_carry_no_note(tmp_path, site):
    ctx, f = _finding(_build(site, tmp_path, "clean", None), "B18")
    assert f.status == WARN
    assert getattr(ctx, "subagent_runs_elided", 0) == 0
    assert NOTE not in f.detail + f.fix


@pytest.mark.parametrize("pad", PADS)
@pytest.mark.parametrize("site", SUB_SITES)
def test_b18_padded_rows_are_still_counted_and_the_fix_names_the_cut_off(tmp_path, site, pad):
    ctx, f = _finding(_build(site, tmp_path, "hostile", pad), "B18")
    assert f.status == WARN
    assert "records 2 spawn(s)" in f.detail  # the padded row is read and counted
    assert ctx.subagent_runs_elided == 1
    assert "deeper than the audit reads" not in f.detail
    assert "1 of these row(s)" in f.fix and "deeper than the audit reads" in f.fix


# ---------------------------------------------------------------------------------------
# machine state: the cron.store key names the live cron store (B168, B189)
# ---------------------------------------------------------------------------------------

def _home_with_cron_store_key(tmp_path, value_json, run_log_jobs=()):
    home = _build_cron_json(tmp_path, "clean", None)  # jobs.json holds one job, "ok"
    (home / "state").mkdir()
    db = home / "state" / "openclaw.sqlite"
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "CREATE TABLE config_machine_state "
            "(state_key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at INTEGER)")
        conn.execute("INSERT INTO config_machine_state VALUES (?,?,0)",
                     ("cron.store", value_json))
        conn.execute(_CRON_RUN_LOGS_DDL)
        for i, job_id in enumerate(run_log_jobs):
            conn.execute(
                "INSERT INTO cron_run_logs (store_key, job_id, seq, ts, status, session_id, "
                "session_key, run_id, entry_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("default", job_id, i, 1_700_000_000 + i, "ok", f"s{i}", f"k{i}", f"r{i}",
                 "{}", 1_700_000_000 + i))
        conn.commit()
    finally:
        conn.close()
    os.chmod(db, 0o600)
    return home


def _scanned_store_value(tmp_path_factory_home_parent) -> str:
    """The value_json that names the jobs.json the audit scans (a plain JSON string)."""
    return json.dumps(str(tmp_path_factory_home_parent / "openclaw" / "cron" / "jobs.json"))


def _padded_cron_store(pad):
    return '{"path": ' + _nest(pad) + "}"


def test_cron_store_key_naming_the_scanned_store_is_a_clean_pass(tmp_path):
    home = _home_with_cron_store_key(tmp_path, _scanned_store_value(tmp_path))
    ctx, f = _finding(home, "B168")
    # getattr: this control must also run on a tree that lacks the C-680 fields
    assert not getattr(ctx, "config_machine_state_elided", set())
    assert not getattr(ctx, "cron_store_key_elided", False)
    assert not ctx.cron_store_shadowed
    assert f.status == PASS
    assert "cron.store" not in f.detail


@pytest.mark.parametrize("pad", PADS)
def test_a_padded_cron_store_key_cannot_answer_a_clean_pass(tmp_path, pad):
    home = _home_with_cron_store_key(tmp_path, _padded_cron_store(pad))
    ctx, f = _finding(home, "B168")
    assert "cron.store" in ctx.config_machine_state_elided
    assert ctx.cron_store_key_elided
    assert f.status == UNKNOWN
    assert f.engine_degraded
    assert any("config_machine_state['cron.store']" in str(h) for h in ctx.limit_hits)


@pytest.mark.parametrize("pad", PADS)
def test_a_padded_cron_store_key_is_not_reported_as_a_shadowed_store(tmp_path, pad):
    """The shadow state is proven and has its own texts (a SQLite cron_jobs table that also
    holds rows); a padded key is a different fact and gets its own detail and fix."""
    home = _home_with_cron_store_key(tmp_path, _padded_cron_store(pad))
    ctx, f = _finding(home, "B168")
    assert not ctx.cron_store_shadowed
    assert "cron.store" in f.detail and NOTE in f.detail
    assert "cron.store" in f.fix
    for shadow_text in ("cron_jobs table also holds rows", "move it aside", "legacy"):
        assert shadow_text not in f.detail + f.fix


@pytest.mark.parametrize("pad", PADS)
def test_a_padded_cron_store_key_keeps_a_real_b189_orphan_warn(tmp_path, pad):
    """The padding hides neither the jobs nor the run log: a run of a job that no longer
    exists is reported, exactly as it is without the padded key."""
    (tmp_path / "plain").mkdir()
    (tmp_path / "padded").mkdir()
    plain = _home_with_cron_store_key(
        tmp_path / "plain", _scanned_store_value(tmp_path / "plain"), run_log_jobs=["ghost"])
    padded = _home_with_cron_store_key(
        tmp_path / "padded", _padded_cron_store(pad), run_log_jobs=["ghost"])
    _c, base = _finding(plain, "B189")
    ctx, f = _finding(padded, "B189")
    assert base.status == WARN and NOTE not in base.fix
    assert not ctx.cron_store_shadowed
    assert f.status == WARN
    assert f.detail == base.detail
    assert NOTE in f.fix  # the orphan comparison used a store that may not be the live one
    assert "ghost" in " ".join(f.evidence or [])


def test_b189_pass_is_unchanged_by_a_padded_cron_store_key(tmp_path):
    padded = _home_with_cron_store_key(tmp_path, _padded_cron_store(201), run_log_jobs=["ok"])
    _ctx, f = _finding(padded, "B189")
    assert f.status == PASS


def test_a_padded_cron_store_key_keeps_a_hostile_job_it_did_read(tmp_path):
    home = _home_with_cron_store_key(tmp_path, _padded_cron_store(201))
    (home / "cron" / "jobs.json").write_text(
        '{"version": 1, "jobs": [{"id": "evil", "payload": {"kind": "agentTurn", '
        f'"message": "{HOSTILE_MESSAGE}"}}}}]}}',
        encoding="utf-8")
    ctx, f = _finding(home, "B168")
    assert f.status == FAIL
    assert ctx.cron_store_key_elided


# ---------------------------------------------------------------------------------------
# machine state: hooks.internal.installs (B179)
# ---------------------------------------------------------------------------------------

def _hooks_home(tmp_path, installs_json=None):
    home = _plugin_home(tmp_path, modern_row=("raw", "{}")).home
    cfg = home / "openclaw.json"
    if not cfg.exists():
        cfg.write_text("{}", encoding="utf-8")
        os.chmod(cfg, 0o600)
    if installs_json is not None:
        _insert_machine_state(home, "hooks.internal.installs", installs_json)
    return home


def test_b179_without_the_key_is_a_clean_pass_without_the_note(tmp_path):
    ctx, f = _finding(_hooks_home(tmp_path), "B179")
    assert f.status == PASS
    assert not getattr(ctx, "config_machine_state_elided", set())
    assert NOTE not in f.detail + f.fix


def test_b179_unpadded_installs_warn_has_no_note(tmp_path):
    _ctx, f = _finding(_hooks_home(tmp_path, '{"h1": {"source": "npm"}}'), "B179")
    assert f.status == WARN
    assert NOTE not in f.detail + f.fix


@pytest.mark.parametrize("pad", PADS)
def test_b179_a_padded_top_level_list_is_not_a_clean_pass(tmp_path, pad):
    ctx, f = _finding(_hooks_home(tmp_path, _nest(pad)), "B179")
    assert "hooks.internal.installs" in ctx.config_machine_state_elided
    assert f.status == UNKNOWN
    assert f.engine_degraded
    assert NOTE in f.detail and "hooks.internal.installs" in f.fix


@pytest.mark.parametrize("pad", PADS)
def test_b179_a_warn_found_in_the_read_part_stands_and_says_so_in_fix(tmp_path, pad):
    installs = '{"h1": {"source": "npm"}, "pad": ' + _nest(pad) + "}"
    _ctx, f = _finding(_hooks_home(tmp_path, installs), "B179")
    assert f.status == WARN
    assert NOTE not in f.detail
    assert NOTE in f.fix


def test_b179_an_explicitly_disabled_block_is_not_degraded_by_padded_installs(tmp_path):
    """hooks.internal.enabled: false disables loading outright, so installs left under it are
    not a live surface and an unread part of them cannot change the answer."""
    home = _hooks_home(tmp_path, _nest(201))
    (home / "openclaw.json").write_text('{"hooks": {"internal": {"enabled": false}}}',
                                        encoding="utf-8")
    _ctx, f = _finding(home, "B179")
    assert f.status == PASS
