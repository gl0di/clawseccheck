"""C-441 — the first run after an upgrade names what it could not compare.

C-418 made `--monitor` disclose comparisons it skipped instead of printing a bare all-clear
over them. On the one path that disclosure exists to serve — a baseline written before this
build's coverage manifest — it said only:

    Your saved record predates coverage tracking, so this run cannot say which comparisons
    it was able to make. The next run will.

which names nothing the reader can act on, and was the least informative sentence the monitor
emitted. The names were derivable the whole time: a pre-manifest baseline still carries its
own keys, and a dimension this build watches that is absent from them is exactly a comparison
that had nothing to compare against.

Four branches, all pinned here:

* pre-manifest baseline missing dimensions -> named, counted, capped;
* pre-manifest baseline that happens to carry everything -> says so, and must NOT imply a gap;
* a short recorded manifest -> named too, via the manifest rather than the key set;
* a current baseline -> silent, because nothing was skipped.

The last one is the control. Without it every assertion here is satisfied by a note that
fires unconditionally, which is a different defect wearing this fix's clothes.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck import monitor
from clawseccheck.cli import main
from clawseccheck.monitor import (
    _DIMENSION_LABELS,
    _DIMENSION_NAME_CAP,
    NOTE_CATEGORY_ORDER,
    WATCHED_DIMENSIONS,
    diff_with_notes,
)

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _current() -> dict:
    return {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {},
        "graded": True,
        "score": 50,
        "raw_score": 50,
        "grade": "F",
        "scope": ["host"],
        "watched": list(WATCHED_DIMENSIONS),
    }


def _v3_era() -> dict:
    """A baseline from before the manifest existed, with the keys such a build really wrote.

    Not `_current()` minus `watched`: that carries every modern dimension and so exercises
    the "nothing was skipped" branch instead of the one this task is about. The degenerate
    fixture is exactly why the pre-existing C-418 test kept passing over the generic
    sentence.
    """
    return {"version": 3, "checks": {}, "mcp": {}, "channels": {},
            "gateway_bind": "127.0.0.1", "skills": {}, "bootstrap": {}, "memory": {},
            "score": 50, "grade": "F"}


def _coverage_note(prev: dict, curr: dict | None = None) -> str | None:
    _alerts, notes = diff_with_notes(prev, curr or _current())
    hits = [s for _c, s in notes
            if "coverage tracking" in s or "this version watches" in s]
    assert len(hits) <= 1, f"the coverage note fired more than once: {hits}"
    return hits[0] if hits else None


# ------------------------------------------------------------------ the defect

def test_a_pre_manifest_baseline_names_what_it_could_not_compare():
    note = _coverage_note(_v3_era())
    assert note, "a pre-manifest baseline produced no coverage note at all"
    assert "cannot say which" not in note, (
        "the generic sentence is back — the whole point of this task is that the names are "
        f"derivable:\n{note}")
    # Names, not snapshot keys: a user-facing sentence must not read as internals.
    assert "the settings file's contents" in note, note
    assert "config_file_sha256" not in note, f"a raw snapshot key leaked into prose:\n{note}"


def test_the_count_accounts_for_every_skipped_dimension():
    """Named + hidden-behind-the-cap + unnamed bookkeeping must add up to the count the
    sentence claims. A cap that quietly drops entries would understate the gap, which is the
    failure mode the disclosure exists to prevent."""
    prev = _v3_era()
    missing = [k for k in WATCHED_DIMENSIONS if k not in prev and k != "watched"]
    note = _coverage_note(prev)
    assert f"{len(missing)} thing(s)" in note, (missing, note)

    named = [k for k in missing if k in _DIMENSION_LABELS]
    unnamed = len(missing) - len(named)
    shown = min(len(named), _DIMENSION_NAME_CAP)
    hidden = len(named) - shown
    assert shown + hidden + unnamed == len(missing)
    if hidden:
        assert f"and {hidden} more" in note, note
    if unnamed:
        assert f"plus {unnamed} internal bookkeeping field(s)" in note, note


def test_the_cap_is_stated_rather_than_applied_silently():
    """A truncation the reader cannot see reads as 'that was all of them'."""
    prev = _v3_era()
    named = [k for k in WATCHED_DIMENSIONS
             if k not in prev and k != "watched" and k in _DIMENSION_LABELS]
    assert len(named) > _DIMENSION_NAME_CAP, (
        "this fixture no longer exceeds the cap, so it cannot test that the cap is "
        "disclosed — pick a sparser baseline")
    assert "more" in _coverage_note(prev)


def test_a_short_recorded_manifest_names_them_too():
    prev = dict(_current(),
                watched=[d for d in WATCHED_DIMENSIONS
                         if d not in ("openclaw_install", "skill_provenance")])
    note = _coverage_note(prev)
    assert "2 thing(s) this version watches" in note, note
    assert "the OpenClaw installation itself" in note, note
    assert "where each installed skill came from" in note, note


# ------------------------------------------------------------------ the controls

def test_a_current_baseline_says_nothing():
    """The control. Every other assertion in this file is satisfied by a note that fires
    unconditionally; this is what rules that out."""
    assert _coverage_note(_current()) is None


def test_a_pre_manifest_baseline_that_missed_nothing_does_not_imply_a_gap():
    """Honest in the other direction: the reader is owed the reason this run had to derive
    the answer, but not a coverage gap that does not exist."""
    prev = {k: {} for k in WATCHED_DIMENSIONS if k != "watched"}
    note = _coverage_note(prev)
    assert note and "nothing was skipped" in note, note
    assert "had nothing to compare against" not in note, note


def test_the_manifest_key_is_not_counted_against_itself():
    """`watched`'s absence is the precondition of the derived branch, not a separate skipped
    comparison. Counting it double-counts the thing the sentence is already explaining."""
    prev = {k: {} for k in WATCHED_DIMENSIONS if k not in ("watched", "mcp")}
    note = _coverage_note(prev)
    assert "1 thing(s)" in note, note


def test_the_disclosure_is_a_note_and_never_an_alert():
    """A note must not reach the event journal by looking close enough to an alert."""
    alerts, notes = diff_with_notes(_v3_era(), _current())
    assert not any("coverage tracking" in m for _lvl, m in alerts), alerts
    for category, _sentence in notes:
        assert category in NOTE_CATEGORY_ORDER
        assert category not in _SEVERITIES


def test_every_label_names_a_dimension_this_build_actually_watches():
    """A label for a key that is not watched would be a name for a comparison that never
    happens — the reverse of the defect, and just as misleading."""
    stray = sorted(set(_DIMENSION_LABELS) - set(WATCHED_DIMENSIONS))
    assert not stray, f"labels for unwatched dimensions: {stray}"


# ------------------------------------------------------------------ end to end

def test_the_names_reach_a_real_verbose_run(tmp_path, capsys):
    """Through the CLI, not through diff_with_notes — the note has to survive the renderer,
    which collapses the notes block to a bare count unless --verbose is passed."""
    home, store = tmp_path / "home", tmp_path / "store"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({"gateway": {"bind": "127.0.0.1"}}), encoding="utf-8")
    os.chmod(cfg, 0o600)

    store.mkdir()
    Path(store / "state.json").write_text(json.dumps(_v3_era()), encoding="utf-8")
    os.chmod(store / "state.json", 0o600)

    main(["--monitor", "--home", str(home), "--data-dir", str(store), "--verbose"])
    out = capsys.readouterr().out
    assert "cannot say which" not in out, out
    assert "had nothing to compare against this once" in out, out
    assert "the settings file's contents" in out, out
