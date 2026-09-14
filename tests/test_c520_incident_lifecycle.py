"""Tests for the persistent incident lifecycle (C-520): --incident-open/--incident-mark/
--incident-show, and the underlying clawseccheck/incidentstore.py store.

Separate from tests/test_incident.py, which covers the pre-existing, stateless, one-shot
--incident evidence pack (never touched by this task).

Offline, read-only against the audited home; local-only opt-in writes under a scratch
--data-dir. stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import Finding
from clawseccheck.cli import main
from clawseccheck.incident import _pid_from_findings, incident_timeline, open_incident_from_audit
from clawseccheck.incidentstore import (
    INCIDENT_STATUSES,
    STATUS_CLOSED,
    STATUS_INVESTIGATING,
    STATUS_MITIGATED,
    STATUS_OPEN,
    _incident_to_dict,
    _is_valid_transition,
    create_incident,
    list_incident_ids,
    load_incident,
    mark_incident,
)
from clawseccheck.monitorstore import _last_chain_hash, record_events

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
VULN = str(FIXTURES / "home_vuln")


def _f(id_="B1", status="FAIL", evidence=None) -> Finding:
    return Finding(id=id_, title="t", severity="HIGH", status=status, detail="d", fix="f",
                   framework="fr", evidence=evidence or [])


# --------------------------------------------------------------------------- state machine

def test_status_vocabulary_is_a_closed_set_of_four():
    assert INCIDENT_STATUSES == {STATUS_OPEN, STATUS_INVESTIGATING, STATUS_MITIGATED,
                                 STATUS_CLOSED}


def test_forward_transitions_are_valid_one_step_at_a_time():
    assert _is_valid_transition(STATUS_OPEN, STATUS_INVESTIGATING)
    assert _is_valid_transition(STATUS_INVESTIGATING, STATUS_MITIGATED)
    assert _is_valid_transition(STATUS_MITIGATED, STATUS_CLOSED)


def test_forward_skip_is_rejected():
    assert not _is_valid_transition(STATUS_OPEN, STATUS_MITIGATED)
    assert not _is_valid_transition(STATUS_OPEN, STATUS_CLOSED)
    assert not _is_valid_transition(STATUS_INVESTIGATING, STATUS_CLOSED)


def test_backward_transitions_are_always_valid():
    assert _is_valid_transition(STATUS_CLOSED, STATUS_MITIGATED)
    assert _is_valid_transition(STATUS_CLOSED, STATUS_INVESTIGATING)
    assert _is_valid_transition(STATUS_CLOSED, STATUS_OPEN)
    assert _is_valid_transition(STATUS_MITIGATED, STATUS_OPEN)


def test_same_status_transition_is_rejected():
    for s in INCIDENT_STATUSES:
        assert not _is_valid_transition(s, s)


def test_unknown_status_is_never_valid_on_either_side():
    assert not _is_valid_transition(STATUS_OPEN, "bogus")
    assert not _is_valid_transition("bogus", STATUS_OPEN)


# --------------------------------------------------------------------------- store round-trip

def test_create_and_load_round_trip(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    inc = create_incident(["B1", "B2"], pid="123", process_name="node",
                          monitor_watermark="abc", path=store, when="2026-09-10T10:00:00")
    assert inc is not None
    assert inc.id == "2026-09-10T10:00:00"
    assert inc.status == STATUS_OPEN
    assert inc.finding_ids == ("B1", "B2")
    assert inc.pid == "123"
    assert inc.history == ({"status": STATUS_OPEN, "ts": "2026-09-10T10:00:00"},)

    loaded = load_incident(inc.id, path=store)
    assert loaded == inc


def test_load_nonexistent_incident_returns_none(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    assert load_incident("nope", path=store) is None


def test_load_from_missing_file_returns_none(tmp_path):
    assert load_incident("anything", path=str(tmp_path / "absent.jsonl")) is None


def test_list_incident_ids_in_creation_order(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    create_incident(["B1"], path=store, when="2026-09-10T10:00:00")
    create_incident(["B2"], path=store, when="2026-09-10T11:00:00")
    assert list_incident_ids(store) == ["2026-09-10T10:00:00", "2026-09-10T11:00:00"]


def test_list_incident_ids_empty_when_no_store(tmp_path):
    assert list_incident_ids(str(tmp_path / "absent.jsonl")) == []


def test_incident_to_dict_shape(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    inc = create_incident(["B1"], pid=None, process_name=None, monitor_watermark=None,
                          path=store, when="2026-09-10T10:00:00")
    d = _incident_to_dict(inc)
    assert set(d.keys()) == {"id", "status", "created_at", "finding_ids", "pid",
                             "process_name", "monitor_watermark", "history"}
    assert d["finding_ids"] == ["B1"]
    json.dumps(d)  # must be JSON-serializable as-is


# --------------------------------------------------------------------------- the DoD test:
# full open -> investigating -> mitigated -> closed path, plus rejection of an invalid one.

def test_full_open_to_closed_lifecycle_path(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    inc = create_incident(["B1"], path=store, when="2026-09-10T10:00:00")
    assert inc.status == STATUS_OPEN

    updated, err = mark_incident(inc.id, STATUS_INVESTIGATING, path=store,
                                 when="2026-09-10T11:00:00")
    assert err is None
    assert updated.status == STATUS_INVESTIGATING

    updated, err = mark_incident(inc.id, STATUS_MITIGATED, path=store,
                                 when="2026-09-10T12:00:00")
    assert err is None
    assert updated.status == STATUS_MITIGATED

    updated, err = mark_incident(inc.id, STATUS_CLOSED, path=store,
                                 when="2026-09-10T13:00:00")
    assert err is None
    assert updated.status == STATUS_CLOSED

    assert updated.history == (
        {"status": STATUS_OPEN, "ts": "2026-09-10T10:00:00"},
        {"status": STATUS_INVESTIGATING, "ts": "2026-09-10T11:00:00"},
        {"status": STATUS_MITIGATED, "ts": "2026-09-10T12:00:00"},
        {"status": STATUS_CLOSED, "ts": "2026-09-10T13:00:00"},
    )


def test_mark_rejects_a_forward_skip(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    inc = create_incident(["B1"], path=store, when="2026-09-10T10:00:00")
    updated, err = mark_incident(inc.id, STATUS_CLOSED, path=store)
    assert updated is None
    assert err == "invalid_transition"
    # And the record itself is untouched by the rejected attempt.
    assert load_incident(inc.id, path=store).status == STATUS_OPEN


def test_mark_rejects_an_unrecognized_status(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    inc = create_incident(["B1"], path=store)
    updated, err = mark_incident(inc.id, "resolved", path=store)
    assert updated is None
    assert err == "invalid_status"


def test_mark_rejects_a_nonexistent_incident(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    updated, err = mark_incident("nope", STATUS_INVESTIGATING, path=store)
    assert updated is None
    assert err == "not_found"


def test_concurrent_marks_never_double_commit_a_transition(tmp_path):
    """C-135: the read-current-status-then-validate step must be inside the SAME lock
    acquisition as the append, or two racing --incident-mark calls could both read the
    pre-transition status and both pass validation, leaving two identical transition
    rows in the history. Stress-tested with real threads, not just reasoned about."""
    import threading

    store = str(tmp_path / "incidents.jsonl")
    inc = create_incident(["B1"], path=store, when="t0")

    results = []

    def worker():
        updated, err = mark_incident(inc.id, STATUS_INVESTIGATING, path=store)
        results.append((updated.status if updated else None, err))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = load_incident(inc.id, path=store)
    assert final.status == STATUS_INVESTIGATING
    committed = [h for h in final.history if h["status"] == STATUS_INVESTIGATING]
    assert len(committed) == 1, f"race: {len(committed)} duplicate transition rows"
    successes = [r for r in results if r[1] is None]
    assert len(successes) == 1


def test_mark_allows_reopening_a_closed_incident(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    inc = create_incident(["B1"], path=store, when="t0")
    mark_incident(inc.id, STATUS_INVESTIGATING, path=store, when="t1")
    mark_incident(inc.id, STATUS_MITIGATED, path=store, when="t2")
    mark_incident(inc.id, STATUS_CLOSED, path=store, when="t3")
    updated, err = mark_incident(inc.id, STATUS_OPEN, path=store, when="t4")
    assert err is None
    assert updated.status == STATUS_OPEN
    assert len(updated.history) == 5


# --------------------------------------------------------------------------- rotation fail-safe

def test_a_transition_row_with_no_created_row_folds_to_none(tmp_path):
    """C-135-style defensive check: if journal rotation ever separates an incident's
    "created" row from its later "transition" rows, the fold must fail SAFE (treat the
    incident as not found) rather than fabricate a status/finding-id list it cannot
    ground."""
    store = tmp_path / "incidents.jsonl"
    orphan_transition = {
        "ts": "2026-09-10T11:00:00", "event": "transition", "id": "orphan-id",
        "from_status": STATUS_OPEN, "to_status": STATUS_INVESTIGATING, "_schema": 1,
        "chain_hash": "irrelevant-for-this-test",
    }
    store.write_text(json.dumps(orphan_transition) + "\n", encoding="utf-8")
    assert load_incident("orphan-id", path=str(store)) is None
    assert list_incident_ids(str(store)) == []


# --------------------------------------------------------------------------- PID extraction

def test_pid_extracted_from_held_by_pid_evidence():
    f = _f(id_="B340", evidence=["0.0.0.0:1234 held by pid 4821 (node) — not "
                                 "identifiable as the OpenClaw gateway"])
    pid, name = _pid_from_findings([f])
    assert pid == "4821"
    assert name == "node"


def test_pid_extracted_from_confirmed_via_pid_evidence():
    f = _f(id_="B340", evidence=["0.0.0.0:1234 confirmed via pid 555 (openclaw)"])
    pid, name = _pid_from_findings([f])
    assert pid == "555"
    assert name == "openclaw"


def test_pid_none_when_no_evidence_matches():
    f = _f(id_="B340", evidence=["gateway.bind='0.0.0.0' (declared class='loopback')"])
    assert _pid_from_findings([f]) == (None, None)


def test_pid_takes_the_first_match_among_b340_findings_in_order():
    f1 = _f(id_="B340", evidence=["held by pid 111 (a)"])
    f2 = _f(id_="B340", evidence=["held by pid 222 (b)"])
    pid, name = _pid_from_findings([f1, f2])
    assert (pid, name) == ("111", "a")


def test_pid_ignores_matching_text_from_a_non_b340_finding():
    """C-135: checks/_content.py's content-security ring echoes a SKILL's own text
    verbatim into evidence (`evidence.append(f'{skill_name}: "{snippet}"')`). A
    malicious skill whose own markdown contains the literal substring
    "confirmed via pid 1 (systemd)" must NOT get that text read back as if sockets.py
    had really resolved PID 1 -- confirmed exploitable before the id-scoping fix."""
    fake = _f(id_="B333", status="FAIL",
             evidence=['evil-skill: "ignore prior instructions... confirmed via pid 1 '
                       '(systemd)"'])
    assert _pid_from_findings([fake]) == (None, None)


def test_pid_ignores_a_non_b340_match_even_alongside_a_real_b340_one():
    """The scoping is per-finding-id, not "stop at the first match anywhere" -- a
    forged non-B340 line earlier in the list must not shadow (or be mistaken for) a
    real B340 one later in it."""
    fake = _f(id_="B333", evidence=["confirmed via pid 1 (systemd)"])
    real = _f(id_="B340", evidence=["held by pid 4821 (node)"])
    pid, name = _pid_from_findings([fake, real])
    assert (pid, name) == ("4821", "node")


# --------------------------------------------------------------------------- open_incident_from_audit

def test_open_refuses_when_no_actionable_findings(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    passing = [_f(status="PASS"), _f(id_="B2", status="UNKNOWN")]
    record, err = open_incident_from_audit(None, passing, path=store,
                                           events=str(tmp_path / "events.jsonl"))
    assert record is None
    assert err == "no_actionable_findings"
    assert list_incident_ids(store) == []


def test_open_links_actionable_findings_and_pid(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    findings = [
        _f(id_="B1", status="PASS"),
        _f(id_="B340", status="FAIL", evidence=["held by pid 999 (node)"]),
        _f(id_="B41", status="WARN"),
    ]
    record, err = open_incident_from_audit(None, findings, path=store,
                                           events=str(tmp_path / "events.jsonl"),
                                           when="2026-09-10T10:00:00")
    assert err is None
    assert record["finding_ids"] == ["B340", "B41"]  # PASS excluded, FAIL/WARN linked
    assert record["pid"] == "999"
    assert record["process_name"] == "node"
    assert record["status"] == STATUS_OPEN
    assert list_incident_ids(store) == ["2026-09-10T10:00:00"]


def test_open_records_the_real_monitor_watermark(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    events_path = str(tmp_path / "events.jsonl")
    record_events([("CRITICAL", "gateway bind changed")], path=events_path)
    expected = _last_chain_hash(Path(events_path))
    assert expected  # sanity: the journal really has a chain hash now

    findings = [_f(status="FAIL")]
    record, err = open_incident_from_audit(None, findings, path=store, events=events_path)
    assert err is None
    assert record["monitor_watermark"] == expected


def test_open_watermark_is_none_when_journal_absent(tmp_path):
    store = str(tmp_path / "incidents.jsonl")
    record, err = open_incident_from_audit(
        None, [_f(status="FAIL")], path=store, events=str(tmp_path / "absent.jsonl"))
    assert err is None
    assert record["monitor_watermark"] is None


# --------------------------------------------------------------------------- incident_timeline

def test_timeline_returns_events_after_the_watermark(tmp_path):
    events_path = str(tmp_path / "events.jsonl")
    record_events([("CRITICAL", "first")], path=events_path)
    watermark = _last_chain_hash(Path(events_path))
    record_events([("HIGH", "second")], path=events_path)
    record_events([("MEDIUM", "third")], path=events_path)

    events, complete = incident_timeline(watermark, events=events_path)
    assert complete is True
    assert [e["message"] for e in events] == ["second", "third"]


def test_timeline_with_no_watermark_returns_everything(tmp_path):
    events_path = str(tmp_path / "events.jsonl")
    record_events([("CRITICAL", "only")], path=events_path)
    events, complete = incident_timeline(None, events=events_path)
    assert complete is True
    assert [e["message"] for e in events] == ["only"]


def test_timeline_discloses_when_watermark_is_not_found():
    """The watermark rotated away (or is simply wrong) — every currently-available
    event is still returned, but the caller must be told not to trust completeness."""
    events, complete = incident_timeline("does-not-exist-in-the-journal",
                                         events="/nonexistent/events.jsonl")
    assert events == []
    assert complete is False


# --------------------------------------------------------------------------- CLI end-to-end

def test_cli_incident_open_refuses_on_a_clean_target(tmp_path, capsys, monkeypatch):
    """The real audit engine's own checks are exercised at the open_incident_from_audit
    unit level above (test_open_refuses_when_no_actionable_findings) with a controlled,
    deterministic all-PASS/UNKNOWN finding list — no real fixture reliably produces zero
    actionable findings across the whole check suite (even home_safe carries a few WARNs
    by design). This proves the CLI's OWN handling of that outcome."""
    import clawseccheck.cli as cli_mod

    monkeypatch.setattr(cli_mod, "open_incident_from_audit",
                        lambda *a, **k: (None, "no_actionable_findings"))
    rc = main(["--incident-open", "--home", SAFE, "--data-dir", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "no actionable" in err.lower()
    assert not (tmp_path / "incidents.jsonl").is_file()


def test_cli_incident_open_creates_a_record_on_a_vulnerable_target(tmp_path, capsys):
    rc = main(["--incident-open", "--home", VULN, "--data-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "status: open" in out
    assert (tmp_path / "incidents.jsonl").is_file()


def test_cli_incident_open_json_shape(tmp_path, capsys):
    rc = main(["--incident-open", "--home", VULN, "--data-dir", str(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "clawseccheck"
    assert payload["status"] == "open"
    assert payload["finding_ids"]


def _open_one(tmp_path, capsys) -> str:
    main(["--incident-open", "--home", VULN, "--data-dir", str(tmp_path), "--json"])
    return json.loads(capsys.readouterr().out)["id"]


def test_cli_incident_mark_full_lifecycle(tmp_path, capsys):
    inc_id = _open_one(tmp_path, capsys)

    rc = main(["--incident-mark", inc_id, "investigating", "--data-dir", str(tmp_path)])
    assert rc == 0
    assert "investigating" in capsys.readouterr().out

    rc = main(["--incident-mark", inc_id, "mitigated", "--data-dir", str(tmp_path)])
    assert rc == 0
    assert "mitigated" in capsys.readouterr().out

    rc = main(["--incident-mark", inc_id, "closed", "--data-dir", str(tmp_path)])
    assert rc == 0
    assert "closed" in capsys.readouterr().out

    rc = main(["--incident-show", inc_id, "--data-dir", str(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "closed"
    assert [h["status"] for h in payload["history"]] == [
        "open", "investigating", "mitigated", "closed"]


def test_cli_incident_mark_rejects_forward_skip(tmp_path, capsys):
    inc_id = _open_one(tmp_path, capsys)
    rc = main(["--incident-mark", inc_id, "closed", "--data-dir", str(tmp_path)])
    assert rc == 1
    assert "not a valid transition" in capsys.readouterr().err


def test_cli_incident_mark_bad_status_is_rc2(tmp_path, capsys):
    inc_id = _open_one(tmp_path, capsys)
    rc = main(["--incident-mark", inc_id, "resolved", "--data-dir", str(tmp_path)])
    assert rc == 2
    assert "resolved" in capsys.readouterr().err


def test_cli_incident_mark_blank_id_is_rc2(tmp_path, capsys):
    rc = main(["--incident-mark", "", "open", "--data-dir", str(tmp_path)])
    assert rc == 2


def test_cli_incident_mark_unknown_id_is_rc1(tmp_path, capsys):
    rc = main(["--incident-mark", "nope", "investigating", "--data-dir", str(tmp_path)])
    assert rc == 1
    assert "no incident" in capsys.readouterr().err.lower()


def test_cli_incident_show_unknown_id_is_rc1(tmp_path, capsys):
    rc = main(["--incident-show", "nope", "--data-dir", str(tmp_path)])
    assert rc == 1


def test_cli_incident_show_includes_timeline(tmp_path, capsys):
    events_path = tmp_path / "events.jsonl"
    inc_id = _open_one(tmp_path, capsys)
    record_events([("HIGH", "after the incident opened")], path=str(events_path))

    rc = main(["--incident-show", inc_id, "--data-dir", str(tmp_path),
              "--events", str(events_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["monitor_timeline_complete"] is True
    assert [e["message"] for e in payload["monitor_timeline"]] == [
        "after the incident opened"]


def test_cli_incident_open_never_writes_under_home(tmp_path, capsys):
    """Golden Rule #2: the audited home is never mutated, only --data-dir."""
    home = tmp_path / "home"
    home.mkdir()
    data_dir = tmp_path / "store"
    before = set(home.rglob("*"))
    main(["--incident-open", "--home", str(home), "--data-dir", str(data_dir)])
    after = set(home.rglob("*"))
    assert before == after


def test_cli_purge_removes_incidents_store(tmp_path, capsys):
    _open_one(tmp_path, capsys)
    assert (tmp_path / "incidents.jsonl").is_file()
    main(["--purge", "--yes", "--data-dir", str(tmp_path)])
    assert not (tmp_path / "incidents.jsonl").is_file()


def test_cli_incident_flags_appear_in_functions_screen(capsys):
    rc = main(["--functions"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "--incident-open" in out
    assert "--incident-mark" in out
    assert "--incident-show" in out
