"""C-718 - the monitor run right after a recorded change raised a false "could not make a
comparison it made at the last check".

The coverage arm (B-676) compares what a run could not compare against what the previous
run could not compare. A member that appears for the first time (a new tool server, a new
skill) is an ADDITION on that run, so nothing about it is "not compared" yet; on the next
run it is present on both sides, its not-comparable state (no transcript for the server, no
declared version for the skill) shows up for the first time, and the arm called it lost
coverage. The sentence was false: the previous run never made that comparison.

Two halves are pinned here, through the real CLI: the run after a recorded change is quiet
(and writes nothing to the journal), and a REAL loss of coverage - plus a real second
change - still alerts. Offline, stdlib only, nothing outside pytest's tmp_path.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"
LOST = "could not make a comparison it made at the last check"
OPENS = "A new blind spot opens with this check"


def _mon(home, store, *extra, as_json=True):
    args = [sys.executable, "-m", "clawseccheck.cli", "--monitor",
            "--home", str(home), "--data-dir", str(store),
            "--no-native", "--no-host", "--no-sockets", "--no-deptree", "--no-dist", *extra]
    if as_json:
        args.insert(4, "--json")
    return subprocess.run(args, cwd=REPO, capture_output=True, text=True)


def _alerts(res):
    return json.loads(res.stdout)["alerts"]


def _messages(res):
    return [a["message"] for a in _alerts(res)]


@pytest.fixture()
def home(tmp_path):
    h = tmp_path / "home"
    shutil.copytree(FIXTURES / "home_safe", h)
    os.chmod(h / "openclaw.json", 0o600)
    return h


def _skill(home, name, version=None, extra=""):
    d = home / "workspace" / "skills" / name
    d.mkdir(parents=True, exist_ok=True)
    ver = f"version: {version}\n" if version else ""
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\n{ver}description: helper {name}\n---\n\nHelper.\n{extra}",
        encoding="utf-8")


def _add_server(home, name="evilsrv"):
    p = home / "openclaw.json"
    cfg = json.loads(p.read_text(encoding="utf-8"))
    cfg.setdefault("mcp", {}).setdefault("servers", {})[name] = {
        "command": "npx", "args": ["-y", "evil-mcp-pkg"]}
    p.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(p, 0o600)


def _steady(home, store):
    """Baseline plus two compared runs, and prove the home is quiet before any change."""
    _mon(home, store)
    _mon(home, store)
    assert _alerts(_mon(home, store)) == []


def _events_size(store):
    p = store / "events.jsonl"
    return p.stat().st_size if p.exists() else 0


def _assert_recorded_change_then_quiet(home, store, token, blind_spot):
    """Run N names the change AND says, in its own words, that a blind spot opens with it;
    runs N+1 and N+2 are quiet and write nothing."""
    n = _mon(home, store)
    assert any(token in m for m in _messages(n)), n.stdout
    assert not [m for m in _messages(n) if LOST in m], _messages(n)
    opened = [m for m in _messages(n) if OPENS in m]
    assert len(opened) == 1 and blind_spot in opened[0], _messages(n)
    size = _events_size(store)
    for _ in range(2):
        again = _mon(home, store)
        assert _alerts(again) == [], again.stdout
        assert _events_size(store) == size, "an unchanged run must not write an event"


# ---------------------------------------------------------------- the false alarm


def test_run_after_a_new_mcp_server_is_quiet(home, tmp_path):
    store = tmp_path / "store"
    _steady(home, store)
    _add_server(home)
    _assert_recorded_change_then_quiet(home, store, "evilsrv", "tools actually offered")


def test_run_after_a_new_unversioned_skill_is_quiet(home, tmp_path):
    store = tmp_path / "store"
    _steady(home, store)
    _skill(home, "newskill")
    _assert_recorded_change_then_quiet(home, store, "newskill", "Version numbers were not compared")


def test_the_record_a_change_leaves_names_its_uncomparable_members(home, tmp_path):
    """White-box on the cause: the run that records a new unversioned skill also records,
    BY NAME (as a digest), that its version cannot be compared - and does not record the
    bare key early, because a key carries no names and would hide a real loss for another
    skill on the next run."""
    from clawseccheck.monitor import (
        _COVERAGE_MEMBERS_MARK, _coverage_member_digest, _coverage_recorded_members,
        _coverage_standing,
    )

    store = tmp_path / "store"
    _steady(home, store)
    _skill(home, "newskill")
    _mon(home, store)
    record = json.loads((store / "state.json").read_text(encoding="utf-8"))["not_compared"]
    assert _COVERAGE_MEMBERS_MARK in record
    assert not any("Version numbers" in k for k in _coverage_standing(record)), record
    members = _coverage_recorded_members(record)
    key = next(k for k in members if "Version numbers were not compared" in k)
    assert members[key] == {_coverage_member_digest("newskill")}
    assert "newskill" not in json.dumps(record), "names are stored as digests only"


def test_a_state_file_without_the_key_stays_quiet(home, tmp_path):
    """A baseline written before the key existed has nothing to compare against."""
    store = tmp_path / "store"
    _steady(home, store)
    _skill(home, "newskill")
    _mon(home, store)
    state = json.loads((store / "state.json").read_text(encoding="utf-8"))
    state.pop("not_compared")
    (store / "state.json").write_text(json.dumps(state), encoding="utf-8")
    res = _mon(home, store)
    assert res.returncode == 0 and _alerts(res) == [], res.stdout


# ---------------------------------------------------------------- controls: still loud


def test_a_version_that_was_compared_and_is_gone_still_alerts(home, tmp_path):
    """A REAL loss: the skill declared a version at the last check and does not now."""
    store = tmp_path / "store"
    _skill(home, "base", version="1.0.0")
    _steady(home, store)
    _skill(home, "base")  # same skill, version line removed
    n = _mon(home, store)
    lost = [m for m in _messages(n) if LOST in m]
    assert len(lost) == 1 and "Version numbers were not compared" in lost[0], _messages(n)
    assert [m for m in _messages(n) if "'base'" in m], "the skill change itself is reported"
    assert _alerts(_mon(home, store)) == [], "and it is reported once"


def test_a_second_real_change_after_a_recorded_change_still_alerts(home, tmp_path):
    store = tmp_path / "store"
    _steady(home, store)
    _skill(home, "newskill")
    _mon(home, store)
    _add_server(home)  # the second, unrelated, real change
    n = _mon(home, store)
    msgs = _messages(n)
    assert any("evilsrv" in m for m in msgs), msgs
    assert not [m for m in msgs if LOST in m], msgs
    # and a real edit of the skill that was recorded unversioned is still caught
    _skill(home, "newskill", extra="Run the installer first.\n")
    again = _messages(_mon(home, store))
    assert any("newskill" in m for m in again), again


def test_a_loss_of_a_different_comparison_is_not_hidden_by_the_recorded_one(home, tmp_path):
    """The new record must only cover what this snapshot cannot compare itself. A version
    lost on a skill that declared one is a different key from a missing tool transcript."""
    store = tmp_path / "store"
    _add_server(home)
    _steady(home, store)  # the server is on both sides: its transcript gap is standing
    _skill(home, "base", version="2.0.0")
    _mon(home, store)
    _mon(home, store)
    _skill(home, "base")
    lost = [m for m in _messages(_mon(home, store)) if LOST in m]
    assert len(lost) == 1 and "Version numbers" in lost[0], lost


def _servers_with_evidence(home, with_evidence):
    """Give the named servers an observed tool surface (one trajectory sidecar)."""
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    rec = {"traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "context.compiled",
           "data": {"tools": [{"name": f"mcp__{n}__search", "description": n}
                              for n in with_evidence]}}
    (sessions / "session-1.trajectory.jsonl").write_text(json.dumps(rec) + "\n",
                                                         encoding="utf-8")


def test_a_server_that_loses_its_observed_tools_alerts_on_the_run_after_another_was_added(
        home, tmp_path):
    """The blocker an independent review found in the first version of this fix, through
    the real CLI. Servers A and C have observed tools; B is added (run N); then only C
    keeps its evidence (run N+1). Recording B's blind spot under a bare key one run early
    silenced A's loss, which the old code reported."""
    store = tmp_path / "store"
    _add_server(home, "A")
    _add_server(home, "C")
    _servers_with_evidence(home, ["A", "C"])
    _steady(home, store)

    _add_server(home, "B")
    n = _messages(_mon(home, store))
    assert any("'B'" in m for m in n), n
    assert len([m for m in n if OPENS in m]) == 1 and not [m for m in n if LOST in m], n

    _servers_with_evidence(home, ["C"])                      # A's evidence is gone
    n1 = _messages(_mon(home, store))
    lost = [m for m in n1 if LOST in m]
    assert len(lost) == 1 and "tools actually offered" in lost[0], n1
    assert _alerts(_mon(home, store)) == [], "and it is reported once"


# ---------------------------------------------------------------- unit: the coverage arm


_GAIN = "2 check(s) began reporting a problem they could not determine last time \u2014 " \
        "it may be new, or it may have been there unseen."
_DARK = "2 check(s) that previously reported a problem can no longer determine their " \
        "state, so the score no longer counts them against you."


def _arm(recorded, notes, members_now=None, ahead_notes=None, members_ahead=None):
    from clawseccheck.monitor import _diff_coverage

    out = []
    _diff_coverage({"not_compared": recorded, "watched": ["x"]}, {"watched": ["x"]},
                   notes, out, lambda *_: None, members_now=members_now,
                   ahead_notes=ahead_notes, members_ahead=members_ahead)
    return out


def _tools_note(n):
    from clawseccheck.monitordims._shared import NOTE_UNDETERMINED

    return (NOTE_UNDETERMINED,
            f"The tools actually offered to your model by {n} server(s) were not compared "
            "\u2014 no session transcript was available for one of the two runs, so a server "
            "that started offering new tools would not show.")


def _record(live_notes, ahead_members):
    from clawseccheck.monitor import _coverage_record, _coverage_signature

    return _coverage_record(_coverage_signature(live_notes), ahead_members)


def _digests(*names):
    from clawseccheck.monitor import _coverage_member_digest

    return [_coverage_member_digest(n) for n in names]


def _key(note):
    from clawseccheck.monitor import _coverage_key

    return _coverage_key(*note)


class TestPerNameComparisonsAreJudgedByName:
    """The arm keyed a per-name comparison on its sentence with the digits removed. One
    key, any names: that is what produced the false alarm AND hid real losses."""

    def test_a_name_that_was_new_last_run_is_not_a_lost_comparison(self):
        key = _key(_tools_note(1))
        # Run N: server B appeared. Nothing is skipped for it yet, but an unchanged next
        # run will skip it - so its name goes on record.
        record = _record([], {key: _digests("B")})
        # Run N+1, unchanged.
        out = _arm(record, [_tools_note(1)], members_now={key: _digests("B")},
                   ahead_notes=[_tools_note(1)], members_ahead={key: _digests("B")})
        assert out == []

    def test_a_real_loss_for_another_name_is_reported_on_the_run_after_an_addition(self):
        """The review's blocker against the first version of this fix: A and C had observed
        tools, B was added at run N, and at run N+1 only C still had evidence. A key
        recorded early for B silenced A's loss; the baseline tree reported it."""
        key = _key(_tools_note(1))
        record = _record([], {key: _digests("B")})
        out = _arm(record, [_tools_note(2)], members_now={key: _digests("A", "B")},
                   ahead_notes=[_tools_note(2)], members_ahead={key: _digests("A", "B")})
        assert len(out) == 1 and LOST in out[0][1] and "by 2 server(s)" in out[0][1]

    def test_a_real_loss_is_reported_even_when_another_name_has_stood_for_long(self):
        """Steady state, which was blind before this change too: B has been uncomparable
        for many runs, so its key is in the record; A now loses its evidence."""
        key = _key(_tools_note(1))
        record = _record([_tools_note(1)], {key: _digests("B")})
        assert key in record                                   # the key IS on record
        out = _arm(record, [_tools_note(2)], members_now={key: _digests("A", "B")})
        assert len(out) == 1 and LOST in out[0][1]
        # and the control: nothing new is skipped, so nothing is said
        assert _arm(record, [_tools_note(1)], members_now={key: _digests("B")}) == []

    def test_a_blind_spot_is_announced_on_the_run_that_opens_it(self):
        key = _key(_tools_note(1))
        record = _record([], {})
        out = _arm(record, [], members_now={}, ahead_notes=[_tools_note(1)],
                   members_ahead={key: _digests("B")})
        assert len(out) == 1 and out[0][0] == "MEDIUM"
        assert OPENS in out[0][1] and "tools actually offered" in out[0][1]
        assert LOST not in out[0][1]

    def test_a_lost_comparison_is_not_also_called_a_new_blind_spot(self):
        key = _key(_tools_note(1))
        record = _record([], {})
        out = _arm(record, [_tools_note(1)], members_now={key: _digests("A")},
                   ahead_notes=[_tools_note(1)], members_ahead={key: _digests("A")})
        assert len(out) == 1 and LOST in out[0][1]

    def test_a_record_written_before_members_existed_is_judged_by_key_as_before(self):
        key = _key(_tools_note(1))
        # key not on record: lost, exactly as the old arm said
        out = _arm([], [_tools_note(1)], members_now={key: _digests("B")},
                   ahead_notes=[_tools_note(1)], members_ahead={key: _digests("B")})
        assert len(out) == 1 and LOST in out[0][1]
        # key on record: quiet, and no blind-spot line is invented on an upgrade run
        out = _arm([key], [_tools_note(2)], members_now={key: _digests("A", "B")},
                   ahead_notes=[_tools_note(2)], members_ahead={key: _digests("A", "B")})
        assert out == []

    def test_a_key_over_the_member_cap_falls_back_to_key_judgement(self):
        from clawseccheck.monitor import _coverage_recorded_members
        from clawseccheck.monitordims import _coverage as cov

        key = _key(_tools_note(1))
        many = _digests(*(f"s{i}" for i in range(cov._COVERAGE_MAX_MEMBERS + 1)))
        record = _record([_tools_note(1)], {key: many})
        assert _coverage_recorded_members(record) == {key: None}
        # judged by key: the key is on record, so a standing gap this large stays quiet
        assert _arm(record, [_tools_note(9)], members_now={key: many},
                    ahead_notes=[_tools_note(9)], members_ahead={key: many}) == []

    def test_a_note_that_is_not_per_name_is_still_judged_by_key(self):
        from clawseccheck.monitordims._shared import NOTE_UNDETERMINED

        other = (NOTE_UNDETERMINED, "5 security tool(s) could not be confirmed.")
        record = _record([], {})
        assert len(_arm(record, [other], members_now={})) == 1
        record = _record([other], {})
        grown = (NOTE_UNDETERMINED, "6 security tool(s) could not be confirmed.")
        assert _arm(record, [grown], members_now={}) == []

    def test_the_blind_spot_line_counts_the_names_that_are_new(self):
        """The quoted sentence carries the total for its comparison; the alert must say how
        many of those are first seen now, and must not say anything was ADDED - a name can
        come into view because the inspection window moved, with nothing added."""
        key = _key(_tools_note(1))
        standing = [f"s{i}" for i in range(30)]
        record = _record([_tools_note(30)], {key: _digests(*standing)})
        out = _arm(record, [_tools_note(30)], members_now={key: _digests(*standing)},
                   ahead_notes=[_tools_note(31)],
                   members_ahead={key: _digests(*standing, "newcomer")})
        assert len(out) == 1 and OPENS in out[0][1]
        assert "by 31 server(s)" in out[0][1]
        assert "1 of them is seen by this check for the first time" in out[0][1]
        assert "added" not in out[0][1]
        out = _arm(_record([], {}), [], members_now={}, ahead_notes=[_tools_note(2)],
                   members_ahead={key: _digests("x", "y")})
        assert "2 of them are seen by this check for the first time" in out[0][1]

    def test_a_failed_self_diff_leaves_a_record_that_is_judged_by_key(self, monkeypatch):
        """`None` from the self-diff is not "no names". A marker with no names behind it
        would make every standing name read as lost on every later run."""
        from clawseccheck import monitor
        from clawseccheck.monitor import (
            _COVERAGE_MEMBERS_MARK, _coverage_ahead, _coverage_record,
            _coverage_recorded_members, _coverage_signature,
        )

        def boom(*_a, **_k):
            raise RuntimeError("self-diff failed")

        monkeypatch.setattr(monitor, "diff_with_notes", boom)
        assert _coverage_ahead({"watched": ["x"]}) == ([], None)

        key = _key(_tools_note(1))
        record = _coverage_record(_coverage_signature([_tools_note(1)]), None)
        assert record == [key] and _COVERAGE_MEMBERS_MARK not in record
        assert _coverage_recorded_members(record) is None
        # next run, the name still standing: judged by key, so quiet - not "lost" forever
        assert _arm(record, [_tools_note(1)], members_now={key: _digests("B")},
                    ahead_notes=[], members_ahead=None) == []

    def test_an_older_version_reads_the_new_record_as_keys_it_never_matches(self):
        """Downgrade safety: the old arm did `key not in set(recorded)` over this list."""
        key = _key(_tools_note(1))
        record = _record([_tools_note(1)], {key: _digests("B")})
        assert all(isinstance(e, str) for e in record)
        assert [e for e in record if not e.startswith("@")] == [key]


def test_a_check_that_begins_reporting_still_alerts_but_not_as_a_lost_comparison():
    """This arm is the only place an UNKNOWN -> WARN/FAIL transition reaches the user, so
    it must keep alerting. What changes is the sentence: last time the check could not
    report at all, so "a comparison it made at the last check" was false."""
    from clawseccheck.monitordims._shared import NOTE_UNDETERMINED

    out = _arm([], [(NOTE_UNDETERMINED, _GAIN)])
    assert len(out) == 1 and out[0][0] == "MEDIUM"
    assert "began reporting a problem" in out[0][1]
    assert LOST not in out[0][1] and "looking at less" not in out[0][1]

    out = _arm([], [(NOTE_UNDETERMINED, _DARK)])
    assert len(out) == 1 and LOST in out[0][1]
    assert "no longer determine their state" in out[0][1]


def test_an_event_note_is_never_stored_so_the_next_transition_alerts_too():
    """Both sentences describe something that happened between two runs. Stored under
    their number-normalised key, a second transition on the very next run (another check
    going dark, or starting to report) read as already known and raised nothing."""
    from clawseccheck.monitor import (
        _coverage_record, _coverage_signature, _coverage_standing,
    )
    from clawseccheck.monitordims._shared import NOTE_NO_PRIOR_RECORD, NOTE_UNDETERMINED

    standing = (NOTE_NO_PRIOR_RECORD, "Version numbers were not compared for 1 skill(s) "
                                      "\u2014 they do not declare one on both sides.")
    notes = [(NOTE_UNDETERMINED, _GAIN), (NOTE_UNDETERMINED, _DARK), standing]
    live = _coverage_signature(notes)
    assert len(live) == 3
    assert len(_coverage_standing(live)) == 1
    record = _coverage_record(live, {})
    assert len(_coverage_standing(record)) == 1 and "Version numbers" in record[0]

    # Run N+1: the same two events happen again (other checks). Both alert; the standing
    # blind spot, already on record, does not.
    out = _arm(record, notes)
    assert len(out) == 2
    assert sum(LOST in text for _sev, text in out) == 1
    assert not any("Version numbers" in text for _sev, text in out)

    # A record written before this change may hold the event keys. It must not silence
    # anything: recorded event keys are ignored on read as well.
    out = _arm(live, notes)
    assert len(out) == 2


def test_the_two_sentences_the_arm_tells_apart_still_exist_in_the_producer():
    src = (REPO / "clawseccheck" / "monitor.py").read_text(encoding="utf-8")
    assert "began reporting a problem they could not" in src
    assert "that previously reported a problem can no longer" in src


# ---------------------------------------------------------------- item 2: the probe line


def test_an_unchanged_probe_says_nothing_changed(home, tmp_path):
    store = tmp_path / "store"
    _steady(home, store)
    res = _mon(home, store, "--probe", as_json=False)
    assert res.returncode == 0
    assert "No new threats" in res.stdout, res.stdout
    assert "This was a probe: nothing was recorded" in res.stdout
    # The claim is scoped the way the ordinary run scopes it: same all-clear sentence and
    # the same "could not be compared" line (or its absence).
    ordinary = _mon(home, store, as_json=False).stdout

    def scope_lines(text):
        return [ln for ln in text.splitlines()
                if "No new threats" in ln or "could not be compared" in ln]

    assert scope_lines(res.stdout) == scope_lines(ordinary), (res.stdout, ordinary)


def test_a_probe_with_drift_does_not_claim_nothing_changed(home, tmp_path):
    store = tmp_path / "store"
    _steady(home, store)
    _add_server(home)
    res = _mon(home, store, "--probe", as_json=False)
    assert "No new threats" not in res.stdout
    assert "evilsrv" in res.stdout
    assert "This was a probe: nothing was recorded" in res.stdout
