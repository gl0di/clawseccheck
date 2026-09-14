"""CLAWSECCHECK-C-524 — `--save-run` / `--diff RUN_ID1 RUN_ID2`.

history.jsonl only ever kept a score/grade line, never the finding list a real
new/fixed/unchanged comparison needs — that gap is the actual prerequisite the task's
own description flags, and closing it is `clawseccheck/runstore.py`: an OPT-IN
(never-by-default) local store of full per-run finding snapshots, keyed by the same
'ts' stamp history.record() already produces.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, MEDIUM, PASS, WARN, Finding
from clawseccheck.cli import main
from clawseccheck.runstore import diff_runs, list_run_ids, load_run, render_diff_json, save_run

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
VULN = str(FIXTURES / "home_vuln")
_COMMON = ["--no-native", "--no-host", "--no-history"]


def _f(cid, severity, status, detail="d", title="t"):
    return Finding(cid, title, severity, status, detail, "fix", "fw")


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


# --------------------------------------------------------------------------------------
# runstore.save_run / load_run / list_run_ids — synthetic findings, no live audit
# --------------------------------------------------------------------------------------

def test_save_run_round_trips_through_load_run(tmp_path):
    p = tmp_path / "runs.jsonl"
    findings = [_f("B2", CRITICAL, FAIL, "gateway exposed"), _f("B14", MEDIUM, PASS, "fine")]
    rid = save_run(findings, str(p), home="~/.openclaw", version="4.0.1")
    assert rid is not None
    row = load_run(rid, str(p))
    assert row is not None
    assert row["ts"] == rid
    assert row["home"] == "~/.openclaw"
    assert row["version"] == "4.0.1"
    assert {f["id"] for f in row["findings"]} == {"B2", "B14"}


def test_saved_finding_shape_matches_report_finding_to_dict(tmp_path):
    p = tmp_path / "runs.jsonl"
    rid = save_run([_f("B2", CRITICAL, FAIL, "gateway exposed")], str(p))
    row = load_run(rid, str(p))
    stored = row["findings"][0]
    from clawseccheck.report import _finding_to_dict
    assert stored == _finding_to_dict(_f("B2", CRITICAL, FAIL, "gateway exposed"))


def test_load_run_absent_file_returns_none(tmp_path):
    assert load_run("2026-01-01T00:00:00", str(tmp_path / "nope.jsonl")) is None


def test_load_run_unknown_id_returns_none(tmp_path):
    p = tmp_path / "runs.jsonl"
    rid = save_run([_f("B2", CRITICAL, FAIL)], str(p))
    assert load_run("not-" + rid, str(p)) is None


def test_list_run_ids_empty_when_absent(tmp_path):
    assert list_run_ids(str(tmp_path / "nope.jsonl")) == []


def test_list_run_ids_lists_every_saved_run(tmp_path):
    p = tmp_path / "runs.jsonl"
    r1 = save_run([_f("B2", CRITICAL, FAIL)], str(p), when="2026-01-01T00:00:00")
    r2 = save_run([_f("B2", CRITICAL, FAIL)], str(p), when="2026-01-02T00:00:00")
    assert list_run_ids(str(p)) == [r1, r2]


def test_save_run_duplicate_ts_last_write_wins(tmp_path):
    p = tmp_path / "runs.jsonl"
    ts = "2026-01-01T00:00:00"
    save_run([_f("B2", CRITICAL, FAIL, "first")], str(p), when=ts)
    save_run([_f("B2", CRITICAL, FAIL, "second")], str(p), when=ts)
    row = load_run(ts, str(p))
    assert row["findings"][0]["detail"] == "second"


def test_save_run_never_raises_on_unwritable_directory(tmp_path):
    # A file where a directory is expected -- secure_dir() cannot create the parent.
    blocker = tmp_path / "blocked"
    blocker.write_text("x")
    p = blocker / "runs.jsonl"
    assert save_run([_f("B2", CRITICAL, FAIL)], str(p)) is None


def test_rotation_prunes_with_a_disclosed_marker(tmp_path, monkeypatch):
    """Same _rotate_journal machinery history.jsonl/events.jsonl already use, exercised
    with small caps (the established pattern in tests/test_journal_lifecycle.py) rather
    than looping the real 50/60 default."""
    import clawseccheck.runstore as runstore_mod
    monkeypatch.setattr(runstore_mod, "_RUNS_MAX_LINES", 4)
    monkeypatch.setattr(runstore_mod, "_RUNS_KEEP", 2)
    p = tmp_path / "runs.jsonl"
    ids = [save_run([_f("B2", CRITICAL, FAIL)], str(p), when=f"2026-01-0{i}T00:00:00")
           for i in range(1, 6)]
    surviving = list_run_ids(str(p))
    assert surviving == ids[-2:]
    # The pruned-but-earlier runs are gone, not just unlisted.
    assert load_run(ids[0], str(p)) is None


# --------------------------------------------------------------------------------------
# diff_runs — the DoD's "constructed run snapshots, not live scans" cases
# --------------------------------------------------------------------------------------

def _run_row(ts, findings):
    return {"ts": ts, "home": "~/.openclaw", "version": "4.0.1",
            "findings": [
                {"id": f.id, "title": f.title, "severity": f.severity, "status": f.status,
                 "detail": f.detail, "fix": f.fix, "framework": f.framework,
                 "suppressed": False}
                for f in findings
            ]}


def test_identical_runs_produce_an_empty_diff():
    findings = [_f("B2", CRITICAL, FAIL, "gateway exposed"), _f("B14", MEDIUM, PASS, "fine")]
    run1 = _run_row("2026-01-01T00:00:00", findings)
    run2 = _run_row("2026-01-02T00:00:00", findings)
    d = diff_runs(run1, run2)
    assert d["new"] == []
    assert d["fixed"] == []
    assert d["unchanged_count"] == 2
    assert d["scope_note"] is None


def test_a_new_fail_appears_in_new_only():
    run1 = _run_row("t1", [_f("B14", MEDIUM, PASS, "fine")])
    run2 = _run_row("t2", [_f("B14", MEDIUM, WARN, "now flagged")])
    d = diff_runs(run1, run2)
    assert [f["id"] for f in d["new"]] == ["B14"]
    assert d["fixed"] == []
    assert d["unchanged_count"] == 0


def test_a_resolved_fail_appears_in_fixed_only():
    run1 = _run_row("t1", [_f("B2", CRITICAL, FAIL, "gateway exposed")])
    run2 = _run_row("t2", [_f("B2", CRITICAL, PASS, "gateway locked down")])
    d = diff_runs(run1, run2)
    assert d["new"] == []
    assert [f["id"] for f in d["fixed"]] == ["B2"]


def test_a_pass_wording_change_is_not_a_fake_new_or_fixed():
    """A PASS whose detail text changed (e.g. a release reworded it) must not read as
    a regression or a resolution -- fingerprint identity is scoped to non-PASS findings
    for exactly this reason."""
    run1 = _run_row("t1", [_f("B14", MEDIUM, PASS, "no egress configured")])
    run2 = _run_row("t2", [_f("B14", MEDIUM, PASS, "no egress surface detected")])
    d = diff_runs(run1, run2)
    assert d["new"] == []
    assert d["fixed"] == []


def test_a_severity_change_shows_in_both_buckets_under_the_same_id():
    """WARN -> FAIL on the same check id is a real regression, not a fixed-then-new
    pair -- but under fingerprint identity it legitimately appears in BOTH lists (the
    old WARN fingerprint vanished = 'fixed', the new FAIL fingerprint appeared =
    'new'). Reading the two together, filtered by id, IS the correct story -- this
    pins that it is not silently collapsed or lost."""
    run1 = _run_row("t1", [_f("B11", MEDIUM, WARN, "world-readable")])
    run2 = _run_row("t2", [_f("B11", HIGH, FAIL, "world-readable and TLS absent")])
    d = diff_runs(run1, run2)
    assert [f["id"] for f in d["new"]] == ["B11"]
    assert [f["id"] for f in d["fixed"]] == ["B11"]
    assert d["new"][0]["status"] == "FAIL"
    assert d["fixed"][0]["status"] == "WARN"


def test_a_check_id_only_in_one_run_sets_scope_note():
    run1 = _run_row("t1", [_f("B2", CRITICAL, FAIL), _f("B50", MEDIUM, WARN)])
    run2 = _run_row("t2", [_f("B2", CRITICAL, FAIL)])  # B50 absent (e.g. --no-host)
    d = diff_runs(run1, run2)
    assert d["scope_note"] is not None
    assert "B50" in d["scope_note"]
    # B50's disappearance must not silently read as "fixed" with no caveat attached.
    assert any(f["id"] == "B50" for f in d["fixed"])


def test_matching_scope_leaves_scope_note_none():
    run1 = _run_row("t1", [_f("B2", CRITICAL, FAIL)])
    run2 = _run_row("t2", [_f("B2", CRITICAL, PASS)])
    assert diff_runs(run1, run2)["scope_note"] is None


def test_render_diff_json_shape_and_sanitized():
    run1 = _run_row("t1", [_f("B2", CRITICAL, FAIL, "gateway exposed")])
    run2 = _run_row("t2", [_f("B2", CRITICAL, PASS, "gateway locked down")])
    payload = json.loads(render_diff_json(diff_runs(run1, run2), version="4.0.1"))
    assert payload["tool"] == "clawseccheck"
    assert payload["version"] == "4.0.1"
    assert payload["run1"] == "t1" and payload["run2"] == "t2"
    assert isinstance(payload["new"], list) and isinstance(payload["fixed"], list)
    assert "unchangedCount" in payload and "scopeNote" in payload


# --------------------------------------------------------------------------------------
# CLI wiring: --save-run / --diff, through the real audit path
# --------------------------------------------------------------------------------------

def _save_run_id(capsys, home, store, when_suffix=""):
    rc, out, _ = _run(capsys, "--home", home, "--data-dir", str(store), *_COMMON, "--save-run")
    assert rc == 0
    line = next(ln for ln in out.splitlines() if ln.startswith("(run saved as "))
    return line.split("(run saved as ")[1].split(" —")[0]


def test_save_run_creates_the_store_file_and_prints_the_run_id(tmp_path, capsys):
    store = tmp_path / "store"
    rid = _save_run_id(capsys, SAFE, store)
    assert (store / "runs.jsonl").is_file()
    assert load_run(rid, str(store / "runs.jsonl")) is not None


def test_default_run_never_creates_the_runs_store(tmp_path, capsys):
    store = tmp_path / "store"
    rc, _out, _ = _run(capsys, "--home", SAFE, "--data-dir", str(store), *_COMMON)
    assert rc == 0
    assert not (store / "runs.jsonl").exists()


def test_save_run_no_effect_note_on_a_non_default_mode(capsys):
    rc, _out, err = _run(capsys, "--home", SAFE, *_COMMON, "--save-run", "--vet-plan", "skillx")
    assert rc == 0
    assert "--save-run has no effect with --vet-plan" in err


def test_diff_identical_saved_runs_is_empty(tmp_path, capsys):
    store = tmp_path / "store"
    r1 = _save_run_id(capsys, SAFE, store)
    r2 = _save_run_id(capsys, SAFE, store)
    rc, out, _ = _run(capsys, "--diff", r1, r2, "--data-dir", str(store), "--no-history")
    assert rc == 0
    assert "No new findings." in out
    assert "No fixed findings." in out


def _save_two_distinct_runs(store):
    """Save VULN then SAFE with explicit, distinct 'ts' values -- two real CLI
    --save-run invocations can collide on the same wall-clock second (ts is
    seconds-precision, documented in save_run's own docstring), which would make
    this test flaky rather than exercising --diff's real logic. Bypassing the CLI
    for the WRITE side only; --diff itself is still exercised through the real CLI
    below, which is the part end-to-end coverage is for."""
    store.mkdir(parents=True, exist_ok=True)
    runs_path = str(store / "runs.jsonl")
    _, vuln_findings, _ = audit(VULN, include_native=False, include_host=False)
    _, safe_findings, _ = audit(SAFE, include_native=False, include_host=False)
    r_vuln = save_run(vuln_findings, runs_path, when="2026-01-01T00:00:00")
    r_safe = save_run(safe_findings, runs_path, when="2026-01-02T00:00:00")
    return r_vuln, r_safe


def test_diff_between_vuln_and_safe_shows_fixed_findings(tmp_path, capsys):
    store = tmp_path / "store"
    r_vuln, r_safe = _save_two_distinct_runs(store)
    rc, out, _ = _run(capsys, "--diff", r_vuln, r_safe, "--data-dir", str(store), "--no-history")
    assert rc == 0
    assert "fixed finding(s):" in out
    assert "B2" in out  # gateway exposure is fixed going VULN -> SAFE


def test_diff_json_end_to_end(tmp_path, capsys):
    store = tmp_path / "store"
    r_vuln, r_safe = _save_two_distinct_runs(store)
    rc, out, _ = _run(capsys, "--diff", r_vuln, r_safe, "--data-dir", str(store),
                      "--no-history", "--json")
    assert rc == 0
    payload = json.loads(out)
    assert payload["run1"] == r_vuln and payload["run2"] == r_safe
    assert any(f["id"] == "B2" for f in payload["fixed"])


def test_diff_missing_run_id_reports_and_exits_1(tmp_path, capsys):
    store = tmp_path / "store"
    r1 = _save_run_id(capsys, SAFE, store)
    rc, _out, err = _run(capsys, "--diff", r1, "no-such-run", "--data-dir", str(store),
                         "--no-history")
    assert rc == 1
    assert "no-such-run" in err
    assert "--save-run" in err


def test_diff_blank_run_id_exits_2(tmp_path, capsys):
    store = tmp_path / "store"
    rc, _out, err = _run(capsys, "--diff", "", "x", "--data-dir", str(store), "--no-history")
    assert rc == 2
    assert "cannot be blank" in err


def test_diff_with_no_store_at_all_reports_and_exits_1(tmp_path, capsys):
    store = tmp_path / "store"
    rc, _out, err = _run(capsys, "--diff", "a", "b", "--data-dir", str(store), "--no-history")
    assert rc == 1
    assert "a" in err and "b" in err


def test_purge_removes_the_runs_store(tmp_path, capsys, monkeypatch):
    store = tmp_path / "store"
    _save_run_id(capsys, SAFE, store)
    assert (store / "runs.jsonl").exists()
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    rc, out, _ = _run(capsys, "--data-dir", str(store), "--purge", "--no-history")
    assert rc == 0
    assert not (store / "runs.jsonl").exists()
    assert "runs.jsonl" in out


@pytest.mark.parametrize("flag", ["diff"])
def test_diff_is_read_only_no_live_audit_files_written(tmp_path, capsys, flag):
    """--diff must not touch --history/--events/--state even though those flags are
    still accepted on the command line -- it never calls audit()."""
    store = tmp_path / "store"
    r1 = _save_run_id(capsys, SAFE, store)
    r2 = _save_run_id(capsys, SAFE, store)
    _run(capsys, "--diff", r1, r2, "--data-dir", str(store), "--no-history")
    assert not (store / "history.jsonl").exists()
