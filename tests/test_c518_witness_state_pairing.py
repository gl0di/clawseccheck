"""CLAWSECCHECK-C-518: the baseline's local-journal witness must describe the exact
state file it is being cross-checked against.

`--monitor`'s "Baseline reference is now X" journal entry (F-173) records that the
baseline MOVED, but until now said nothing about WHICH state file moved. CLAWSECCHECK-
C-464 built a reader that compared the journal's last witnessed reference against
whatever state.json happened to be on disk, ran it against a real machine, and got a
false "reference moved" report on a HEALTHY, untampered machine — because --state and
--events are independent flags with no guaranteed pairing, and that box's state.json
and its witness entries simply described different runs (measured: state.json from
2026-08-03, witness entries from 2026-08-24). C-464 was retracted rather than shipped,
and named the fix without building it: "Record the store's identity in the witness
line itself... so a reader can tell whether a given witness line describes the
baseline it is holding."

The fix: `baseline_witness_event()` now embeds a short digest of the resolved --state
path in its message (same `sha256(str(Path(...).resolve()))` identity pattern
monitor.py's own `_home_identity` uses for --home, B-781), and
`witnessed_reference_for_state()` reads the journal back filtered to that exact
digest, so an unrelated/unpaired events file reads as "no witness on record" rather
than a false disagreement — `test_the_c464_false_positive_is_closed_*` below
reproduces the measured scenario directly.

Wired into `--verify-baseline` as an additional, separately-worded paragraph (never
folded into the primary user-supplied-reference verdict, and never presented as
proof of tampering on its own — matching the "three outcomes, never two" idiom this
codebase already uses for --verify-events/configjournal.py). Deliberately NOT a new
scored catalog Finding: C-464's own retraction comment already rejected both a silent
NOTE ("no consumer, on a signal we already know is unreliable") and an implicit FAIL
(that is what got measured false on a healthy real machine) for this exact signal.
`--verify-baseline`'s own exit code is a real, already-wired consumer that is not
scored into the audit's letter grade, so a witness-recording hiccup elsewhere cannot
turn into a spurious FAIL the way Golden Rule #5 would block.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawseccheck.cli import main
from clawseccheck.monitor import (
    BASELINE_DIGEST_CHARS,
    DEFAULT_STATE,
    baseline_witness_event,
    record_events,
    snapshot_reference,
    witnessed_reference_for_state,
)
from clawseccheck.monitorstore import _state_path_digest

_SAFE = '{"gateway": {"bind": "127.0.0.1"}}'
_EXPOSED = '{"gateway": {"bind": "0.0.0.0"}}'


def _home(tmp_path: Path, body: str = _SAFE, name: str = "home") -> Path:
    home = tmp_path / name
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(body, encoding="utf-8")
    os.chmod(cfg, 0o600)
    return home


def _run(home: Path, store: Path, *extra) -> int:
    return main(["--monitor", "--home", str(home), "--data-dir", str(store), *extra])


def _capture_ref(store: Path) -> str:
    snap = json.loads((store / "state.json").read_text(encoding="utf-8"))
    return snapshot_reference(snap)


# --------------------------------------------------------------- _state_path_digest


def test_same_state_path_absolute_vs_relative_spelling_is_one_identity(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    a = _state_path_digest(tmp_path / "state.json")
    b = _state_path_digest(Path("state.json"))
    assert a == b


def test_same_state_path_with_a_trailing_slash_on_its_parent_is_one_identity(tmp_path):
    d = tmp_path / "store"
    d.mkdir()
    a = _state_path_digest(str(d) + "/state.json")
    b = _state_path_digest(str(d) + "//state.json")
    assert a == b


def test_same_state_path_reached_through_a_symlinked_parent_is_one_identity(tmp_path):
    real = tmp_path / "real_store"
    real.mkdir()
    link = tmp_path / "link_store"
    link.symlink_to(real)
    a = _state_path_digest(real / "state.json")
    b = _state_path_digest(link / "state.json")
    assert a == b


def test_two_different_state_paths_have_different_identity(tmp_path):
    a = _state_path_digest(tmp_path / "a" / "state.json")
    b = _state_path_digest(tmp_path / "b" / "state.json")
    assert a != b


def test_state_path_digest_does_not_require_the_file_to_exist(tmp_path):
    # Path.resolve() must not raise on a --state that was never saved yet.
    _state_path_digest(tmp_path / "never" / "written" / "state.json")


# --------------------------------------------------------------- baseline_witness_event


def test_witness_event_embeds_the_state_path_digest(tmp_path):
    state = tmp_path / "state.json"
    events = baseline_witness_event("a" * 64, state)
    assert len(events) == 1
    level, msg = events[0]
    assert level == "INFO"
    assert "Baseline reference is now" in msg  # pre-existing substring contract
    digest = _state_path_digest(state)[:8]
    assert f"(state {digest})" in msg


def test_witness_event_for_an_empty_reference_still_records_nothing():
    assert baseline_witness_event("", "/tmp/whatever/state.json") == []


def test_witness_event_defaults_to_DEFAULT_STATE_when_no_path_given():
    # Backward-compatible call shape: a caller that never learned about the new
    # parameter still gets a valid (if generically-keyed) witness line.
    events = baseline_witness_event("a" * 64)
    assert events and "Baseline reference is now" in events[0][1]
    digest = _state_path_digest(DEFAULT_STATE)[:8]
    assert f"(state {digest})" in events[0][1]


# --------------------------------------------------------------- witnessed_reference_for_state


def test_no_events_file_at_all_is_no_witness_not_unreadable(tmp_path):
    ref, why = witnessed_reference_for_state(tmp_path / "state.json", tmp_path / "nope.jsonl")
    assert ref is None
    assert why == "no_witness"


def test_empty_events_file_is_no_witness(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text("", encoding="utf-8")
    ref, why = witnessed_reference_for_state(tmp_path / "state.json", events)
    assert ref is None
    assert why == "no_witness"


def test_events_file_with_only_unrelated_entries_is_no_witness(tmp_path):
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    record_events([("CRITICAL", "Gateway bind changed: something")], events)
    ref, why = witnessed_reference_for_state(state, events)
    assert ref is None
    assert why == "no_witness"


def test_the_c464_false_positive_is_closed_unpaired_events_file(tmp_path):
    """The exact scenario CLAWSECCHECK-C-464 measured on a real machine: a witness
    entry recorded FOR A DIFFERENT state file must not read as describing THIS one,
    even though it is the most recent (or only) witness line in the journal."""
    state_a = tmp_path / "a" / "state.json"
    state_b = tmp_path / "b" / "state.json"
    events = tmp_path / "events.jsonl"
    record_events(baseline_witness_event("a" * 64, state_a), events)
    ref, why = witnessed_reference_for_state(state_b, events)
    assert ref is None
    assert why == "no_witness", "an unrelated state file's witness must never look like a match"


def test_a_matching_witness_entry_is_found(tmp_path):
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    reference = "abc123def456" + "0" * 52
    record_events(baseline_witness_event(reference, state), events)
    ref, why = witnessed_reference_for_state(state, events)
    assert why == "ok"
    assert ref == reference[:BASELINE_DIGEST_CHARS]


def test_only_the_last_matching_witness_is_returned(tmp_path):
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    record_events(baseline_witness_event("1" * 64, state), events)
    record_events(baseline_witness_event("2" * 64, state), events)
    ref, why = witnessed_reference_for_state(state, events)
    assert why == "ok"
    assert ref == "2" * BASELINE_DIGEST_CHARS


def test_interleaved_witnesses_for_different_states_pick_only_the_matching_one(tmp_path):
    state_a = tmp_path / "a" / "state.json"
    state_b = tmp_path / "b" / "state.json"
    events = tmp_path / "events.jsonl"
    record_events(baseline_witness_event("1" * 64, state_a), events)
    record_events(baseline_witness_event("2" * 64, state_b), events)
    record_events(baseline_witness_event("3" * 64, state_a), events)
    ref_a, why_a = witnessed_reference_for_state(state_a, events)
    ref_b, why_b = witnessed_reference_for_state(state_b, events)
    assert (ref_a, why_a) == ("3" * BASELINE_DIGEST_CHARS, "ok")
    assert (ref_b, why_b) == ("2" * BASELINE_DIGEST_CHARS, "ok")


def test_a_redaction_collision_degrades_to_no_witness_never_a_wrong_value(tmp_path):
    """C-135: `record_events` pipes every message through `logsafe.redact()` (defence
    in depth, C-465). Measured over 50,000 realistic references, about 1 in 2,000
    happens to contain a contiguous digit-only run that passes Luhn and gets partially
    replaced with the literal `<redacted>` by the credit-card-number redactor — a
    coincidental collision, not a real card number. `914302698973596f` is one such
    reference, found by that sweep and pinned here so the fix cannot silently regress
    into producing a WRONG reference on a collision instead of gracefully reporting
    "no_witness" (verified: this can only ever suppress the confirmation, never
    fabricate a mismatched one, because the substitution always breaks the literal
    " (state " boundary _WITNESS_REF_RE requires right after the hex run)."""
    reference = "914302698973596f" + "0" * 48
    from clawseccheck.logsafe import redact
    assert "<redacted>" in redact(f"Baseline reference is now {reference[:16]} (state x)"), (
        "precondition: this reference must actually collide, or the test proves nothing")

    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    record_events(baseline_witness_event(reference, state), events)
    ref, why = witnessed_reference_for_state(state, events)
    assert (ref, why) == (None, "no_witness"), (
        "a redaction collision must degrade to no_witness, never surface a corrupted "
        "or mismatched reference")


@pytest.mark.skipif(os.name != "posix", reason="permission bits are POSIX-only")
def test_an_unreadable_events_file_is_its_own_outcome(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can read through mode 000")
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    record_events(baseline_witness_event("a" * 64, state), events)
    os.chmod(events, 0o000)
    try:
        ref, why = witnessed_reference_for_state(state, events)
        assert ref is None
        assert why == "unreadable"
    finally:
        os.chmod(events, 0o600)


# --------------------------------------------------------------- --verify-baseline CLI


def test_matching_state_and_events_show_the_reassuring_cross_check(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    _home(tmp_path, _EXPOSED)
    assert _run(home, store) == 0
    ref = _capture_ref(store)
    capsys.readouterr()

    rc = main(["--verify-baseline", ref, "--state", str(store / "state.json"),
               "--events", str(store / "events.jsonl")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Local journal cross-check" in out
    assert "agrees with what is on disk now" in out


def test_c464_repro_unpaired_events_file_gives_no_cross_check_not_a_false_mismatch(
    tmp_path, capsys
):
    """The regression this whole task exists to close: pairing state.json from one
    store against events.jsonl from an unrelated one must never read as tampering."""
    home_a = _home(tmp_path, name="home_a")
    store_a, store_b = tmp_path / "store_a", tmp_path / "store_b"
    _run(home_a, store_a)
    _home(tmp_path, _EXPOSED, name="home_a")
    assert _run(home_a, store_a) == 0
    ref_a = _capture_ref(store_a)

    # store_b: a completely unrelated baseline/journal pair, also with witness activity,
    # so events.jsonl is non-empty and DOES contain "Baseline reference is now" lines —
    # just none of them about store_a's state file.
    home_b = _home(tmp_path, _SAFE, name="home_b")
    _run(home_b, store_b)
    _home(tmp_path, _EXPOSED, name="home_b")
    _run(home_b, store_b)

    capsys.readouterr()
    rc = main(["--verify-baseline", ref_a, "--state", str(store_a / "state.json"),
               "--events", str(store_b / "events.jsonl")])
    out = capsys.readouterr().out
    assert rc == 0, "the primary check must still pass on its own merit"
    assert "Local journal cross-check" not in out, (
        "an unrelated journal must not manufacture a cross-check paragraph at all — "
        "this is the exact false positive CLAWSECCHECK-C-464 measured and retracted")


def test_stale_offbox_reference_with_agreeing_journal_is_reassuring(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    stale_ref = _capture_ref(store)
    _home(tmp_path, _EXPOSED)
    assert _run(home, store) == 0

    capsys.readouterr()
    rc = main(["--verify-baseline", stale_ref, "--state", str(store / "state.json"),
               "--events", str(store / "events.jsonl")])
    out = capsys.readouterr().out
    assert rc == 1, "the primary check correctly reports the stale off-box copy as a mismatch"
    assert "does NOT match" in out
    assert "agrees with what is on disk now" in out, (
        "the journal cross-check should reassure that nothing beyond the ordinary "
        "baseline move happened")


def test_journal_disagreement_flips_an_otherwise_clean_verdict_to_exit_1(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    ref = _capture_ref(store)
    # Forge a witness entry for this exact state path recording a DIFFERENT reference,
    # simulating a change that bypassed --monitor's own witness-recording path. Not
    # all-zeros: logsafe.redact() treats a run of one repeated hex digit as secret-shaped
    # (harmless for a real, naturally-varied sha256-derived reference, but it would mask
    # this test's own forged value).
    events = store / "events.jsonl"
    record_events(baseline_witness_event("0123456789abcdef" * 4, store / "state.json"),
                  events)

    capsys.readouterr()
    rc = main(["--verify-baseline", ref, "--state", str(store / "state.json"),
               "--events", str(events)])
    out = capsys.readouterr().out
    assert rc == 1, "a disagreeing journal must flip an otherwise-passing verdict"
    assert "Baseline still matches your reference" in out, "the primary check is unaffected"
    assert "Local journal cross-check" in out
    assert "not proof of tampering" in out


@pytest.mark.skipif(os.name != "posix", reason="permission bits are POSIX-only")
def test_unreadable_events_path_is_disclosed_not_silently_dropped(tmp_path, capsys):
    if os.geteuid() == 0:
        pytest.skip("root can read through mode 000")
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    ref = _capture_ref(store)
    events = store / "events.jsonl"
    # A single first run journals no witness (nothing to move FROM yet) — create the
    # file directly so there is something to make unreadable.
    record_events([("INFO", "filler")], events)
    os.chmod(events, 0o000)
    try:
        capsys.readouterr()
        rc = main(["--verify-baseline", ref, "--state", str(store / "state.json"),
                   "--events", str(events)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "could not be read" in out
    finally:
        os.chmod(events, 0o600)


def test_early_return_absent_baseline_is_unaffected(tmp_path, capsys):
    capsys.readouterr()
    rc = main(["--verify-baseline", "a" * 16, "--state", str(tmp_path / "nope.json"),
               "--events", str(tmp_path / "events.jsonl")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Cannot check" in out
    assert "Local journal cross-check" not in out


def test_early_return_reference_too_short_is_unaffected(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    capsys.readouterr()
    rc = main(["--verify-baseline", "abcd", "--state", str(store / "state.json"),
               "--events", str(store / "events.jsonl")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Cannot check" in out
    assert "Local journal cross-check" not in out


def test_verify_baseline_still_writes_nothing(tmp_path):
    """The read-only contract this mode has always had must survive the new cross-check
    (which reads events.jsonl but must never rotate, append to, or otherwise touch it)."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    _home(tmp_path, _EXPOSED)
    assert _run(home, store) == 0
    ref = _capture_ref(store)
    before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in store.iterdir()}

    main(["--verify-baseline", ref, "--state", str(store / "state.json"),
          "--events", str(store / "events.jsonl")])

    after = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in store.iterdir()}
    assert before == after
