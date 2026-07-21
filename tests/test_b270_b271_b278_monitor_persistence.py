"""--monitor must not claim to have persisted what it did not (B-271 / B-270 / B-278).

Three defects that all lived in the same ~10-line ``if args.monitor:`` block, and all
produced the same class of harm: an affirmative statement the tool could not back.

* **B-271** — "Baseline saved." was rendered BEFORE ``save_state`` was attempted, the
  failure went to stdout as a footnote, and the run returned 0. ``--badge`` / ``--html`` /
  ``--sarif`` / ``--save`` all return 1 on the same failure; ``--monitor`` was the sole
  outlier, so a cron job persisting nothing forever looked healthy.
* **B-270** — ``load_state`` returned raw ``json.loads`` output with no shape validation
  and collapsed absent / corrupt / unreadable into one ``None``, which three call sites
  then interpreted differently. A state file holding ``{}`` rendered "No new threats since
  last check" over a genuinely changed config; ``[1,2,3]`` crashed ``diff()`` with an
  AttributeError *before* ``save_state``, so the poison was never replaced and the crash
  repeated forever.
* **B-278** — a failed events-journal append was swallowed by ``except OSError: pass``
  while the baseline had already advanced, so the drift was consumed and lost. For a
  tamper-evident journal that is the worst failure mode: the record looks intact.

Every test writes only under ``tmp_path`` and passes ``--state`` / ``--events`` /
``--history`` explicitly, so no test touches the real ``~/.clawseccheck`` store.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import diff, record_events
from clawseccheck.catalog import FAIL, PASS
from clawseccheck.cli import main
from clawseccheck.monitor import (
    BASELINE_ABSENT, BASELINE_CORRUPT, BASELINE_OK, load_state, read_baseline,
)
from clawseccheck.report import render_monitor
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")


def _run(tmp_path: Path, *extra: str, home: str = SAFE, state=None, events=None):
    """Run --monitor with every local-store path confined to tmp_path.

    --monitor deliberately records a history point even under --no-history, so --history
    must be redirected too or the test would append to the user's real store.
    """
    state = state if state is not None else tmp_path / "state.json"
    events = events if events is not None else tmp_path / "events.jsonl"
    return main(["--home", home, "--no-native", "--monitor", "--ascii",
                 "--state", str(state), "--events", str(events),
                 "--history", str(tmp_path / "history.jsonl"), *extra])


# The payloads that parse as JSON but are not a usable snapshot. Split by the harm each
# one used to cause so a regression names which arm broke.
_FALSY_JSON = ["{}", "[]", "0", '""', "false", "null"]          # -> "No new threats" lie
_TRUTHY_NON_DICT = ['"abc"', "[1,2,3]", "42", "3.5", "true"]     # -> AttributeError crash
_UNPARSEABLE = ['{"a":', "", "   ", "not json at all", "\x00\x01"]  # -> "Baseline saved" lie
_ALL_UNUSABLE = _FALSY_JSON + _TRUTHY_NON_DICT + _UNPARSEABLE


# ---------------------------------------------------------------------------
# B-270 — one shared definition of "no usable baseline"
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", _ALL_UNUSABLE)
def test_unusable_baseline_is_corrupt_not_absent(tmp_path, payload):
    """The whole point: present-but-unusable must be distinguishable from a first run."""
    state = tmp_path / "state.json"
    state.write_text(payload, encoding="utf-8")
    status, snap = read_baseline(state)
    assert status == BASELINE_CORRUPT
    assert snap is None


@pytest.mark.parametrize("payload", _ALL_UNUSABLE)
def test_load_state_returns_none_for_unusable_payloads(tmp_path, payload):
    """load_state's narrowed contract: a usable non-empty dict, or None."""
    state = tmp_path / "state.json"
    state.write_text(payload, encoding="utf-8")
    assert load_state(state) is None


def test_absent_state_is_absent_not_corrupt(tmp_path):
    status, snap = read_baseline(tmp_path / "nope.json")
    assert status == BASELINE_ABSENT
    assert snap is None


def test_valid_state_is_ok_and_round_trips(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"version": 2, "score": 90}), encoding="utf-8")
    status, snap = read_baseline(state)
    assert status == BASELINE_OK
    assert snap == {"version": 2, "score": 90}
    assert load_state(state) == snap


def test_unreadable_state_file_is_corrupt(tmp_path):
    """chmod 000: present, so it must NOT read as a first run."""
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"version": 2}), encoding="utf-8")
    state.chmod(0o000)
    try:
        assert read_baseline(state)[0] == BASELINE_CORRUPT
    finally:
        state.chmod(0o600)


def test_directory_at_state_path_is_corrupt(tmp_path):
    (tmp_path / "state.json").mkdir()
    assert read_baseline(tmp_path / "state.json")[0] == BASELINE_CORRUPT


def test_dangling_symlink_at_state_path_is_corrupt(tmp_path):
    """`exists()` follows symlinks and reports False for a broken one — a planted
    dangling symlink must not be mistaken for "no baseline yet"."""
    link = tmp_path / "state.json"
    link.symlink_to(tmp_path / "nowhere.json")
    assert read_baseline(link)[0] == BASELINE_CORRUPT


@pytest.mark.parametrize("payload", _ALL_UNUSABLE)
def test_unusable_baseline_never_renders_an_all_clear(tmp_path, payload, capsys):
    """The affirmative falsehood, end to end through the real CLI."""
    state = tmp_path / "state.json"
    state.write_text(payload, encoding="utf-8")
    rc = _run(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "No new threats" not in out
    assert "Baseline saved." not in out          # not a first run — one existed and is gone
    assert "previous monitor baseline could not be read" in out


@pytest.mark.parametrize("payload", _ALL_UNUSABLE)
def test_unusable_baseline_is_journaled(tmp_path, payload):
    """B-270 asks for an events.jsonl entry so a scheduled run notices."""
    (tmp_path / "state.json").write_text(payload, encoding="utf-8")
    _run(tmp_path)
    lines = [json.loads(ln) for ln in
             (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines() if ln]
    assert any("baseline could not be read" in e["message"] for e in lines)


@pytest.mark.parametrize("payload", _TRUTHY_NON_DICT)
def test_poison_payload_no_longer_crashes_or_persists(tmp_path, payload):
    """The crash preceded save_state, so the bad file was never replaced and every
    subsequent run failed identically. Two runs prove it now self-heals."""
    state = tmp_path / "state.json"
    state.write_text(payload, encoding="utf-8")
    assert _run(tmp_path) == 0
    assert read_baseline(state)[0] == BASELINE_OK      # replaced, not left poisoned
    assert _run(tmp_path) == 0                          # and the next run is a clean diff


def test_absent_baseline_still_says_baseline_saved(tmp_path, capsys):
    """The clean case must be untouched: a genuine first run keeps its wording."""
    rc = _run(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "Baseline saved." in out
    assert "could not be read" not in out


def test_valid_baseline_unchanged_still_says_no_new_threats(tmp_path, capsys):
    """The other clean case: a real baseline with no drift keeps its all-clear."""
    _run(tmp_path)
    capsys.readouterr()
    rc = _run(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert "No new threats" in out
    assert "could not be read" not in out


def test_empty_dict_baseline_earns_no_tamper_credit(tmp_path, capsys):
    """A `{}` state file used to satisfy the tamper sub-grade's own `is not None` rule and
    earn full HIGH-weight credit for a baseline that cannot detect anything."""
    def _tamper(state_payload):
        d = tmp_path / ("t" + str(abs(hash(state_payload))))
        d.mkdir()
        if state_payload is not None:
            (d / "state.json").write_text(state_payload, encoding="utf-8")
        main(["--home", SAFE, "--no-native", "--no-history", "--ascii",
              "--state", str(d / "state.json"), "--events", str(d / "events.jsonl"),
              "--history", str(d / "history.jsonl")])
        for line in capsys.readouterr().out.splitlines():
            if "Tamper posture:" in line:
                return line
        raise AssertionError("no tamper line rendered")

    assert _tamper("{}") == _tamper(None)


# ---------------------------------------------------------------------------
# B-270 — diff() defensively skips a dimension of the wrong type
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("prev", [None, {}, [], 0, "", False, "abc", [1, 2, 3], 42, True])
def test_diff_returns_empty_for_an_unusable_prev(prev):
    """No caller of diff() — public API included — may crash it with a non-dict."""
    curr = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}}
    assert diff(prev, curr) == []


_DICT_DIMENSIONS = ["skills", "bootstrap", "checks", "mcp", "mcp_detail",
                    "channels", "host", "memory"]


@pytest.mark.parametrize("dimension", _DICT_DIMENSIONS)
@pytest.mark.parametrize("junk", [[1, 2], "str", 42, None, True])
def test_diff_skips_a_wrong_typed_dimension_instead_of_crashing(dimension, junk):
    """A hand-edited or partially-corrupted snapshot must cost that ONE dimension, not
    the whole run."""
    good = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "mcp": {}, "mcp_detail": {}, "channels": {}, "host": {}, "memory": {}}
    prev = {**good, dimension: junk}
    curr = {**good, "version": 2}
    diff(prev, curr)                     # must not raise
    diff(curr, prev)                     # nor in the other direction


@pytest.mark.parametrize("field", ["score", "native_count"])
@pytest.mark.parametrize("junk", ["ninety", [1], {}, None])
def test_diff_survives_a_wrong_typed_numeric_field(field, junk):
    good = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}}
    diff({**good, field: junk}, {**good, field: 90})
    diff({**good, field: 90}, {**good, field: junk})


@pytest.mark.parametrize("junk", [["a"], {"a": 1}, 42, None])
def test_diff_survives_a_wrong_typed_gateway_bind(junk):
    """`cb in EXPOSED_BINDS` raises TypeError on an unhashable value."""
    good = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "gateway_bind": "127.0.0.1"}
    diff({**good, "gateway_bind": junk}, good)
    diff(good, {**good, "gateway_bind": junk})


@pytest.mark.parametrize("key", ["skills_capped", "memory_capped"])
@pytest.mark.parametrize("junk", [42, "abc", {"a": 1}, True])
def test_diff_survives_a_wrong_typed_truncation_frontier(key, junk):
    """`set(... or ())` raises TypeError on an int and silently yields dict KEYS."""
    good = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "memory": {}}
    diff({**good, key: junk}, good)
    diff(good, {**good, key: junk})


def test_diff_still_detects_real_drift_after_the_type_guards():
    """Capability retained — proven with a hand-built case through the real function,
    not inferred from the fixtures still passing."""
    prev = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "mcp": {"good": "x"}, "channels": {}, "gateway_bind": "127.0.0.1", "host": {}}
    curr = {**prev, "mcp": {"good": "x", "evil": "y"}, "gateway_bind": "0.0.0.0"}
    msgs = " ".join(m for _, m in diff(prev, curr))
    assert "NEW MCP server connected" in msgs and "evil" in msgs
    assert "Gateway bind changed" in msgs and "exposed to the network" in msgs


def test_a_wrong_typed_dimension_costs_only_itself():
    """Corrupting `skills` must not suppress the gateway alert."""
    prev = {"score": 90, "grade": "A", "skills": [1, 2], "bootstrap": {}, "checks": {},
            "gateway_bind": "127.0.0.1"}
    curr = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "gateway_bind": "0.0.0.0"}
    assert any("Gateway bind changed" in m for _, m in diff(prev, curr))


# ---------------------------------------------------------------------------
# B-304 — a corrupted dimension must not fabricate drift against a REAL other side
#
# `test_diff_skips_a_wrong_typed_dimension_instead_of_crashing` above proves no crash,
# but its `curr` is always the shared `good` dict, which carries an EMPTY "skills" /
# "bootstrap" / "checks" too — so `cs.keys() - ps.keys()` was always `{} - {}` and the
# tests could never observe what happens when the *other* side is genuinely populated.
# That is exactly the realistic shape: `curr` is always freshly computed by this run's
# own `snapshot()` and is never hand-edited — only a saved, previously-written `prev`
# can be corrupted. These tests use a real, non-empty `curr` to close that gap.
# ---------------------------------------------------------------------------

_FABRICATION_MARKERS_B304 = (
    "NEW skill installed", "New bootstrap file appeared", "Now FAILING",
    "was removed", "no longer being read",
)


@pytest.mark.parametrize("junk", [[1, 2], "a string", None, 42, True])
def test_corrupted_skills_does_not_fabricate_new_skill_installed(junk):
    """Measured before this fix: `"skills": ["not", "a", "dict"]` on prev reported the
    one real, unchanged, already-installed skill as `NEW skill installed ... this is
    when malware lands` — a CRITICAL false alarm on every run against an untouched
    fleet, for as long as the corrupted field was never overwritten."""
    prev = {"score": 90, "grade": "A", "skills": junk, "bootstrap": {}, "checks": {}}
    curr = {"score": 90, "grade": "A",
            "skills": {"my-skill": {"hash": "abc", "caps": ["net"], "tree": "t1"}},
            "bootstrap": {}, "checks": {}}
    alerts = diff(prev, curr)
    assert not any(m for _, m in alerts if any(mk in m for mk in _FABRICATION_MARKERS_B304)), alerts


@pytest.mark.parametrize("junk", [[1, 2], "a string", None, 42, True])
def test_corrupted_bootstrap_does_not_fabricate_new_file_appeared(junk):
    """Measured before this fix: a corrupted `bootstrap` on prev reported every REAL
    current bootstrap file as `New bootstrap file appeared`, even though none of them
    had actually just appeared."""
    prev = {"score": 90, "grade": "A", "skills": {}, "bootstrap": junk, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"workspace-home/SOUL.md": "hash1"}, "checks": {}}
    alerts = diff(prev, curr)
    assert not any(m for _, m in alerts if any(mk in m for mk in _FABRICATION_MARKERS_B304)), alerts


@pytest.mark.parametrize("junk", [[1, 2], "a string", None, 42, True])
def test_corrupted_checks_does_not_fabricate_now_failing(junk):
    """Measured before this fix: a corrupted `checks` on prev reported every check that
    is CURRENTLY failing as `Now FAILING`, including catalog-CRITICAL ids, as if the
    failure were a fresh transition this run actually witnessed."""
    prev = {"score": 49, "grade": "F", "skills": {}, "bootstrap": {}, "checks": junk}
    curr = {"score": 49, "grade": "F", "skills": {}, "bootstrap": {},
            "checks": {"A1": FAIL}}
    alerts = diff(prev, curr)
    assert not any(m for _, m in alerts if any(mk in m for mk in _FABRICATION_MARKERS_B304)), alerts


def test_real_skill_bootstrap_checks_drift_still_detected_when_both_sides_valid():
    """The B-304 guard must cost nothing when neither side is corrupted — real drift in
    all three dimensions at once is still reported, through the same real function."""
    prev = {"score": 90, "grade": "A",
            "skills": {"old-skill": {"hash": "h1", "tree": "t1"}},
            "bootstrap": {"workspace-home/SOUL.md": "hash1"},
            "checks": {"A1": PASS}}
    curr = {"score": 49, "grade": "F",
            "skills": {"old-skill": {"hash": "h1", "tree": "t1"},
                       "new-skill": {"hash": "h2", "tree": "t2"}},
            "bootstrap": {"workspace-home/SOUL.md": "hash2"},
            "checks": {"A1": FAIL}}
    msgs = " ".join(m for _, m in diff(prev, curr))
    assert "NEW skill installed" in msgs and "new-skill" in msgs
    assert "SOUL.md changed" in msgs
    assert "Now FAILING" in msgs


def test_monitor_cli_self_heals_a_corrupted_bootstrap_field(tmp_path, capsys):
    """End to end through the real CLI, not just diff(): a state.json that is a
    well-formed JSON *object* (so `read_baseline` reports it BASELINE_OK, not
    BASELINE_CORRUPT — this is the one-field corruption B-304 is actually about, not a
    wholly unusable snapshot) whose 'bootstrap' field is corrupted must not crash, must
    not fabricate a 'New bootstrap file appeared' claim, and the corruption must not be
    laundered forward silently: the next saved baseline carries a real dict, so the run
    right after this one is a normal, unremarkable comparison."""
    state = tmp_path / "state.json"
    state.write_text(json.dumps({
        "version": 2, "score": 90, "grade": "A",
        "skills": {}, "bootstrap": ["not", "a", "dict"], "checks": {},
    }), encoding="utf-8")
    rc = _run(tmp_path, state=state)
    out = capsys.readouterr().out
    assert rc == 0
    assert "New bootstrap file appeared" not in out
    # Not reported as a corrupt/unusable BASELINE either — this is a narrower, one-field
    # gap than the whole-snapshot BASELINE_CORRUPT case tested above, and diff() already
    # self-heals it silently, the same idiom every other dimension guard in this module
    # uses (see _dim / _both_dims docstrings).
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert isinstance(saved["bootstrap"], dict)          # self-healed, not carried forward
    rc2 = _run(tmp_path, state=state)                    # the following run is unremarkable
    assert rc2 == 0
    assert "New bootstrap file appeared" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# B-271 — save first; a failed save is the verdict, not a footnote
# ---------------------------------------------------------------------------

def _unwritable_state(tmp_path: Path) -> Path:
    """A state path whose write must fail. A directory is used rather than a 0500 parent:
    save_state calls secure_dir(), which chmods a parent we own back to 0700, so the
    obvious "read-only parent" repro silently succeeds for the owning user."""
    p = tmp_path / "state.json"
    p.mkdir()
    return p


def test_monitor_returns_nonzero_when_state_cannot_be_saved(tmp_path, capsys):
    assert _run(tmp_path, state=_unwritable_state(tmp_path)) != 0


def _absent_baseline_unwritable_state(tmp_path: Path) -> Path:
    """No baseline exists AND the save must fail — the exact shape of B-271's headline.

    Deliberately not a directory/symlink at the state path: both of those read as a
    *corrupt* baseline, which suppresses "Baseline saved." on its own and would let this
    test pass without the fix. Here the file genuinely does not exist (so the run really is
    a first run), and the write fails because secure_dir() cannot mkdir under a 0500
    grandparent — a permission secure_dir does not chmod away, since it never touches the
    parent's parent.
    """
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    return ro / "sub" / "state.json"


def test_first_run_that_cannot_save_does_not_say_baseline_saved(tmp_path, capsys):
    """The headline lie: told the baseline exists when nothing was written."""
    state = _absent_baseline_unwritable_state(tmp_path)
    try:
        assert read_baseline(state)[0] == BASELINE_ABSENT   # a genuine first run
        rc = _run(tmp_path, state=state)
    finally:
        (tmp_path / "ro").chmod(0o700)
    cap = capsys.readouterr()
    assert rc != 0
    assert "Baseline saved." not in cap.out
    assert not state.exists()
    assert "MONITORING NOT ESTABLISHED" in cap.err


def test_clean_run_that_cannot_save_does_not_say_no_new_threats(tmp_path, capsys,
                                                                monkeypatch):
    """The other affirmation: an all-clear implies monitoring continues, and it does not."""
    import clawseccheck.cli as cli

    _run(tmp_path)                                  # establish a real baseline
    capsys.readouterr()
    monkeypatch.setattr(cli, "save_state",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    rc = _run(tmp_path)                             # same config -> zero alerts
    cap = capsys.readouterr()
    assert rc != 0
    assert "No new threats" not in cap.out
    assert "MONITORING NOT ESTABLISHED" in cap.err


def test_monitor_state_failure_prints_no_success_wording(tmp_path, capsys):
    _run(tmp_path, state=_unwritable_state(tmp_path))
    out = capsys.readouterr().out
    assert "Baseline saved." not in out
    assert "No new threats" not in out
    # A corrupt baseline whose replacement could not be written must not claim one exists.
    assert "replacement baseline has been saved" not in out


def test_monitor_state_failure_verdict_goes_to_stderr(tmp_path, capsys):
    """The failure line used to go to stdout, so `--monitor 2>&1 1>/dev/null` was empty."""
    _run(tmp_path, state=_unwritable_state(tmp_path))
    err = capsys.readouterr().err
    assert "MONITORING NOT ESTABLISHED" in err
    assert "cannot detect future changes" in err


def test_monitor_state_failure_names_the_state_path(tmp_path, capsys):
    state = _unwritable_state(tmp_path)
    _run(tmp_path, state=state)
    assert str(state) in capsys.readouterr().err


def test_monitor_symlinked_state_target_returns_nonzero(tmp_path, capsys):
    link = tmp_path / "state.json"
    link.symlink_to(tmp_path / "nowhere.json")
    assert _run(tmp_path, state=link) != 0


def test_monitor_happy_path_returns_zero_and_actually_writes(tmp_path, capsys):
    state = tmp_path / "state.json"
    rc = _run(tmp_path, state=state)
    assert rc == 0
    assert "Baseline saved." in capsys.readouterr().out
    assert read_baseline(state)[0] == BASELINE_OK      # the claim is now backed


def test_success_wording_is_withheld_when_the_save_raises(tmp_path, capsys, monkeypatch):
    """Ordering, pinned directly: the render must not precede the write's outcome."""
    import clawseccheck.cli as cli

    monkeypatch.setattr(cli, "save_state",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    rc = _run(tmp_path)
    cap = capsys.readouterr()
    assert rc != 0
    assert "Baseline saved." not in cap.out
    assert "boom" in cap.err


def test_real_drift_is_still_shown_when_the_save_fails(tmp_path, capsys, monkeypatch):
    """A failed save must not swallow alerts that were genuinely computed — they are not
    lost (the baseline did not advance), and the user needs to see them now."""
    import clawseccheck.cli as cli

    _run(tmp_path)                                  # establish a real baseline
    capsys.readouterr()
    monkeypatch.setattr(cli, "save_state",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    _run(tmp_path, home=str(FIXTURES / "home_vuln"))
    out = capsys.readouterr().out
    assert "change(s) detected since last check" in out


# ---------------------------------------------------------------------------
# B-278 — a failed journal write is loud, and does not consume the event
# ---------------------------------------------------------------------------

def test_record_events_returns_none_on_success(tmp_path):
    assert record_events([("HIGH", "x")], tmp_path / "e.jsonl") is None


def test_record_events_returns_none_when_there_is_nothing_to_record(tmp_path):
    assert record_events([], tmp_path / "e.jsonl") is None


def test_record_events_returns_the_error_and_does_not_raise(tmp_path):
    """The contract change is "report", not "raise": a journal problem must still never
    take a monitor run down (see tests/test_symlink_safety.py)."""
    journal = tmp_path / "e.jsonl"
    journal.write_text("", encoding="utf-8")
    journal.chmod(0o444)
    try:
        err = record_events([("HIGH", "x")], journal)
    finally:
        journal.chmod(0o600)
    assert isinstance(err, str) and err


def test_record_events_reports_a_symlinked_target(tmp_path):
    link = tmp_path / "e.jsonl"
    link.symlink_to(tmp_path / "real.jsonl")
    err = record_events([("HIGH", "x")], link)
    assert isinstance(err, str) and err


def _readonly_journal(tmp_path: Path) -> Path:
    j = tmp_path / "events.jsonl"
    j.write_text("", encoding="utf-8")
    j.chmod(0o444)
    return j


def test_broken_journal_does_not_fail_a_run_with_nothing_to_record(tmp_path, capsys):
    """The false-failure risk this fix could have introduced, pinned in the other
    direction: record_events() returns early when there are no alerts, so an unwritable
    journal must NOT turn every quiet run into a non-zero exit. Without this, any user
    whose journal became root-owned would see their cron job fail daily over nothing."""
    _run(tmp_path)                                  # baseline
    capsys.readouterr()
    journal = _readonly_journal(tmp_path)
    try:
        rc = _run(tmp_path, events=journal)         # same config -> zero alerts
    finally:
        journal.chmod(0o600)
    cap = capsys.readouterr()
    assert rc == 0
    assert "No new threats" in cap.out
    assert "could not record drift events" not in cap.err


def test_first_run_with_a_broken_journal_still_establishes_a_baseline(tmp_path, capsys):
    """A first run has nothing to journal, so a broken journal must not block the
    baseline it exists to create."""
    journal = _readonly_journal(tmp_path)
    state = tmp_path / "state.json"
    try:
        rc = _run(tmp_path, state=state, events=journal)
    finally:
        journal.chmod(0o600)
    assert rc == 0
    assert read_baseline(state)[0] == BASELINE_OK


def test_monitor_journal_failure_returns_nonzero(tmp_path, capsys):
    _run(tmp_path)                                  # baseline
    capsys.readouterr()
    journal = _readonly_journal(tmp_path)
    try:
        rc = _run(tmp_path, home=str(FIXTURES / "home_vuln"), events=journal)
    finally:
        journal.chmod(0o600)
    assert rc != 0


def test_monitor_journal_failure_warns_on_stderr(tmp_path, capsys):
    """The identical failure on state.json already warned; the durable artifact did not."""
    _run(tmp_path)
    capsys.readouterr()
    journal = _readonly_journal(tmp_path)
    try:
        _run(tmp_path, home=str(FIXTURES / "home_vuln"), events=journal)
    finally:
        journal.chmod(0o600)
    err = capsys.readouterr().err
    assert "could not record drift events" in err
    assert str(journal) in err


def test_monitor_journal_failure_does_not_consume_the_event(tmp_path, capsys):
    """The chosen tradeoff, pinned: the baseline is NOT advanced when the journal write
    fails, so the drift is re-detected and gets another chance to be recorded."""
    state = tmp_path / "state.json"
    _run(tmp_path, state=state)
    capsys.readouterr()
    before = state.read_text(encoding="utf-8")

    journal = _readonly_journal(tmp_path)
    try:
        _run(tmp_path, home=str(FIXTURES / "home_vuln"), state=state, events=journal)
        assert state.read_text(encoding="utf-8") == before      # unconsumed
    finally:
        journal.chmod(0o600)

    # Journal repaired: the SAME drift is re-reported and now recorded.
    capsys.readouterr()
    rc = _run(tmp_path, home=str(FIXTURES / "home_vuln"), state=state, events=journal)
    out = capsys.readouterr().out
    assert rc == 0
    assert "change(s) detected since last check" in out
    assert journal.read_text(encoding="utf-8").strip()
    assert state.read_text(encoding="utf-8") != before           # now advanced


def test_journal_ok_but_state_failure_double_records_next_run(tmp_path, capsys,
                                                              monkeypatch):
    """The accepted cost of journal-before-advance, measured rather than asserted: when
    the journal lands and the state write then fails, the next run re-detects the same
    drift and journals it a second time. A duplicated timeline line is recoverable; a
    missing one is not."""
    import clawseccheck.cli as cli

    state, journal = tmp_path / "state.json", tmp_path / "events.jsonl"
    _run(tmp_path, state=state, events=journal)
    capsys.readouterr()

    monkeypatch.setattr(cli, "save_state",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    assert _run(tmp_path, home=str(FIXTURES / "home_vuln"),
                state=state, events=journal) != 0
    first = [json.loads(ln) for ln in
             journal.read_text(encoding="utf-8").splitlines() if ln]
    assert first                                    # the journal DID land

    monkeypatch.undo()
    capsys.readouterr()
    _run(tmp_path, home=str(FIXTURES / "home_vuln"), state=state, events=journal)
    second = [json.loads(ln) for ln in
              journal.read_text(encoding="utf-8").splitlines() if ln]
    assert len(second) > len(first)
    msgs = [e["message"] for e in second]
    assert any(msgs.count(m) > 1 for m in msgs), "expected the documented double-record"


# ---------------------------------------------------------------------------
# render_monitor — the renderer's own contract
# ---------------------------------------------------------------------------

def test_render_monitor_defaults_are_unchanged():
    """Every pre-existing caller must render exactly as before."""
    assert "Baseline saved." in render_monitor([], compute([]), baseline=True)
    assert "No new threats" in render_monitor([], compute([]))
    assert "1 change(s)" in render_monitor([("HIGH", "x")], compute([]))


def test_render_monitor_withholds_both_affirmations_when_not_persisted():
    out = render_monitor([], compute([]), baseline=True, persisted=False)
    assert "Baseline saved." not in out
    assert "No new threats" not in out


def test_render_monitor_still_shows_alerts_when_not_persisted():
    out = render_monitor([("CRITICAL", "gateway opened")], compute([]), ascii_only=True,
                         persisted=False)
    assert "gateway opened" in out
    assert "No new threats" not in out


def test_render_monitor_corrupt_claims_a_replacement_only_when_persisted():
    saved = render_monitor([("HIGH", "lost")], compute([]), ascii_only=True,
                           baseline_corrupt=True, persisted=True)
    assert "replacement baseline has been saved" in saved
    unsaved = render_monitor([("HIGH", "lost")], compute([]), ascii_only=True,
                             baseline_corrupt=True, persisted=False)
    assert "replacement baseline has been saved" not in unsaved


def test_render_monitor_corrupt_is_not_a_first_run():
    """The wording that made a destroyed baseline look like a healthy new one."""
    out = render_monitor([("HIGH", "lost")], compute([]), ascii_only=True,
                         baseline_corrupt=True)
    assert "Baseline saved. Future runs" not in out
