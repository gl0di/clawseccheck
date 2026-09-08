"""C-418 — "No new threats since last check" must stop covering ground nobody looked at.

`diff()` is full of deliberate silences, each individually correct: a blind config makes
every disappearance untrustworthy, a truncated collection cannot tell "gone" from "never
inspected", a baseline written by an older build simply lacks the key a newer comparison
needs. Every one of them used to fall through into an unconditional all-clear — a sentence
about the whole setup, printed over the parts of it that were never examined.

The fix records those silences as *notes* and scopes the verdict to them. A note is not an
alert: it describes no change, reaches no journal, moves no score. The load-bearing
invariant, and the first test below, is that the ✅ now appears only on a run that compared
everything it knows how to compare.

Measured before the render was designed, because the task named the UX risk and a guess
would not have settled it: on a real, healthy, unchanged home the notes count is 2 — not
the eight that would have made the screen read as a malfunction. The default therefore
collapses to a count and only --verbose enumerates. (The first measurement said 1, and one
of those was a FALSE note — a watcher confidently absent on both sides being counted as
uncompared. An independent pass found it; the count went up when the false one was removed
and the genuinely missed ones were added.)

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.monitor import (
    NOTE_CATEGORY_ORDER,
    NOTE_CONFIG_BLIND,
    NOTE_NO_PRIOR_RECORD,
    NOTE_RECORD_DAMAGED,
    NOTE_UNDETERMINED,
    WATCHED_DIMENSIONS,
    diff,
    diff_with_notes,
)
from clawseccheck.report import render_monitor
from clawseccheck.scoring import compute


def _complete(**over) -> dict:
    """A snapshot that leaves nothing uncompared — the only shape that earns the tick.

    **Populated, not empty.** The first version of this helper left `mcp_detail`, `skills`,
    `channels` and `host` empty, which made every per-item note site unreachable: it earned
    the tick by having nothing to compare rather than by comparing everything, and an
    independent pass showed the "invariant" test below passed for that reason. Each
    collection here carries a fully-comparable entry, so the sites are reached and must
    stay silent on their own merits.
    """
    snap = {
        "version": 4,
        "watched": list(WATCHED_DIMENSIONS),
        "score": 90, "raw_score": 90, "raw_score_scope": "abc", "grade": "A",
        # B-511: a snapshot that "leaves nothing uncompared" must include having
        # earned its grade — without this the score comparison stands down and the
        # helper stops describing the shape it is named for.
        "graded": True,
        "checks": {"B1": PASS},
        "checks_not_applicable": [], "checks_degraded": [],
        "skills": {"helper": {"hash": "h", "tree": "t", "caps": ["fs"], "version": "1.0"}},
        "bootstrap": {"SOUL.md": "b"},
        "memory": {"memory/note.md": {"hash": "m"}},
        "memory_capped": [], "skills_capped": [], "skills_capped_count": 0,
        "skills_frontier_partial": False,
        "mcp": {"srv": "sig"},
        "mcp_detail": {"srv": {
            "command": "npx", "args0": "@x/srv", "args_pkg": "@x/srv", "transport": "stdio",
            "url": "", "env_keys": [], "oauth_scope": "read",
            "tool_sigs": {"read_file": "a"}, "surface_tool_sigs": {"read_file": "a"},
        }},
        "channels": {"tg": {"allowlist": "x", "requireMention": "y"}},
        # `absent` on both sides is a confident verdict, not a gap — the note must not fire.
        "host": {"edr_av": "absent", "firewall": "present"},
        "gateway_bind": "127.0.0.1",
        "ignore_hash": "", "native_count": 0, "config_ever_seen": True,
        # F-173: the behavioural layer ran, found nothing, and read everything. Anything
        # less than all three is a gap, so a "complete" snapshot has to state them —
        # leaving them out is exactly the run this helper exists to distinguish itself
        # from, and it correctly reddened this file the moment the arm landed.
        "behavioral_fired": [], "behavioral_undetermined": [], "behavioral_capped": False,
    }
    snap.update(over)
    return snap


def _score():
    return compute([])


def _render(alerts, notes, **kw):
    return render_monitor(alerts, _score(), ascii_only=True, notes=notes, **kw)


# ---------------------------------------------------------------- the invariant

def test_the_tick_appears_only_when_everything_was_compared():
    """The whole point of the task, stated as one property."""
    alerts, notes = diff_with_notes(_complete(), _complete())
    assert alerts == [] and notes == []
    assert "No new threats since last check." in _render(alerts, notes)


def test_an_uncompared_run_never_claims_a_clean_sweep():
    """The same empty alert list, a different sentence — because it means something else."""
    prev = _complete()
    del prev["gateway_bind"]                       # one comparison becomes impossible
    alerts, notes = diff_with_notes(prev, _complete())
    assert alerts == [], "precondition: still no drift"
    assert notes, "precondition: something was not compared"
    out = _render(alerts, notes)
    assert "No new threats among what was compared." in out
    assert "No new threats since last check." not in out


def test_the_scoped_line_also_appears_when_there_are_alerts():
    """A run that found three changes and skipped four comparisons is still partial. The
    alerts it did produce must not read as the complete answer."""
    out = _render([("HIGH", "something moved")],
                  [(NOTE_CONFIG_BLIND, "settings unreadable")])
    assert "could not be compared this run" in out
    assert "something moved" in out


# ---------------------------------------------------------------- notes are not alerts

def test_the_shim_returns_exactly_the_alert_half():
    """A shape check only — `diff` IS `diff_with_notes(...)[0]`, so this can never fail and
    is not evidence that alerts are unmoved. That property is pinned by the corpus below,
    against expected values rather than against the implementation."""
    for prev, curr in [(_complete(), _complete()), ({}, _complete()), (None, _complete())]:
        assert diff(prev, curr) == diff_with_notes(prev, curr)[0]


def test_the_alerts_a_known_corpus_produces_are_unchanged():
    """The real regression gate for "zero new alerts".

    Comparing `diff` against `diff_with_notes` proves nothing: one calls the other, so the
    assertion is `x == x`. What has to hold is that these pairs still produce THESE alerts —
    values recorded from the behaviour before notes existed, so a note site that
    accidentally appends to `alerts`, or a refactored guard that drops one, fails here.
    """
    cases = [
        ((_complete(), _complete()), []),
        ((_complete(), _complete(checks={"B1": FAIL})), ["CRITICAL"]),
        ((_complete(), _complete(gateway_bind="0.0.0.0")), ["CRITICAL"]),
        ((_complete(), _complete(skills={**_complete()["skills"],
                                         "evil": {"hash": "h"}})), ["CRITICAL"]),
        ((_complete(), _complete(score=40, raw_score=40, grade="F")), ["HIGH"]),
        ((_complete(), _complete(config_parse_error=True)), ["HIGH"]),
        ((_complete(), _complete(native_count=3)), ["INFO"]),
        ((None, _complete()), []),
        (({}, _complete()), []),
    ]
    for (prev, curr), expected_levels in cases:
        alerts, _ = diff_with_notes(prev, curr)
        assert [lvl for lvl, _ in alerts] == expected_levels, (prev.get("score") if prev
                                                              else None, alerts)


def test_notes_carry_no_severity_and_cannot_be_mistaken_for_alerts():
    """An alert is (level, message) with a catalog severity; a note is (category, sentence).
    Keeping the vocabularies disjoint is what stops a note reaching the event journal by
    looking close enough to an alert."""
    _, notes = diff_with_notes(_complete(watched=[]), _complete())
    assert notes
    levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    for category, _sentence in notes:
        assert category in NOTE_CATEGORY_ORDER
        assert category not in levels


# ---------------------------------------------------------------- the four reasons

def test_an_unreadable_config_says_what_the_blindness_cost():
    prev = _complete()
    curr = _complete(config_parse_error=True)
    _, notes = diff_with_notes(prev, curr)
    blind = [m for c, m in notes if c == NOTE_CONFIG_BLIND]
    assert len(blind) >= 3, blind
    assert any("disappeared" in m for m in blind)
    assert any("connections" in m for m in blind)


def test_an_older_baseline_reads_as_nothing_to_compare_not_as_damage():
    """The two states call for opposite actions — one heals itself, the other needs the
    state file deleted — so they must not share a sentence."""
    prev = _complete()
    del prev["channels"]
    _, notes = diff_with_notes(prev, _complete())
    cats = {c for c, _ in notes}
    assert NOTE_NO_PRIOR_RECORD in cats
    assert NOTE_RECORD_DAMAGED not in cats


def test_a_corrupted_dimension_reads_as_damage():
    _, notes = diff_with_notes(_complete(channels="not-a-dict"), _complete())
    assert any(c == NOTE_RECORD_DAMAGED and "damaged" in m for c, m in notes)


def test_a_surface_absent_from_both_sides_is_not_reported_as_a_gap():
    """`host` is absent on an unsupported platform. Never recorded on either side is not a
    gap — it is a surface that does not exist here, and calling it uncompared would invent
    a problem the user cannot act on."""
    prev, curr = _complete(), _complete()
    del prev["host"], curr["host"]
    _, notes = diff_with_notes(prev, curr)
    assert not any("machine" in m for _, m in notes)


def test_a_damaged_side_is_not_mistaken_for_an_absent_surface():
    """The carve-out above must test ABSENCE, not "not a dict".

    Damaged-on-one-side plus absent-on-the-other is precisely the state whose note tells
    the user to delete the state file, and a looser carve-out swallowed it — returning the
    unqualified all-clear over a baseline it had just failed to read."""
    prev = _complete(skills="junk-string")
    curr = _complete()
    del curr["skills"]
    _, notes = diff_with_notes(prev, curr)
    assert any(c == NOTE_RECORD_DAMAGED for c, _ in notes), notes


def test_a_confidently_absent_watcher_is_not_called_uncompared():
    """`absent` on both sides is a verdict, not a gap: nothing can have stopped, and the
    comparison did happen. Counting it would make the tick unreachable forever on a machine
    that simply has no EDR — a note that can never be cleared teaches the reader to ignore
    the whole block."""
    both_absent = _complete(host={"edr_av": "absent", "firewall": "absent"})
    _, notes = diff_with_notes(both_absent, both_absent)
    assert not any("security tool" in m for _, m in notes)


def test_an_undetermined_watcher_is_reported_and_not_as_a_missing_record():
    """`unknown` last time genuinely means a stop cannot be detected — but a full record
    exists, so filing it under "nothing to compare against yet" would misdescribe it."""
    prev = _complete(host={"edr_av": "unknown", "firewall": "present"})
    curr = _complete(host={"edr_av": "absent", "firewall": "present"})
    _, notes = diff_with_notes(prev, curr)
    hits = [c for c, m in notes if "security tool" in m]
    assert hits == [NOTE_UNDETERMINED], notes


def test_a_baseline_predating_the_coverage_manifest_says_so_once():
    """The generic form: rather than a new note site per release, the recorded manifest is
    compared against what this build reads."""
    prev = _complete()
    del prev["watched"]
    _, notes = diff_with_notes(prev, _complete())
    assert any("predates coverage tracking" in m for _, m in notes)


def test_a_manifest_missing_entries_counts_them():
    prev = _complete(watched=[w for w in WATCHED_DIMENSIONS if w != "channels"])
    _, notes = diff_with_notes(prev, _complete())
    assert any("1 thing(s) this version watches" in m for _, m in notes)


# ---------------------------------------------------------------- the render

def test_the_default_collapses_and_verbose_enumerates():
    """Eight lines on a healthy run reads as a malfunction; that is the risk this shape
    exists to avoid."""
    notes = [(NOTE_CONFIG_BLIND, "alpha not compared"),
             (NOTE_NO_PRIOR_RECORD, "beta not compared")]
    terse = _render([], notes)
    assert "2 things could not be compared" in terse
    assert "alpha not compared" not in terse
    assert "--verbose" in terse

    loud = _render([], notes, verbose=True)
    assert "alpha not compared" in loud and "beta not compared" in loud


def test_one_note_is_not_pluralised():
    assert "1 thing could not be compared" in _render([], [(NOTE_CONFIG_BLIND, "x")])


def test_every_category_has_its_own_heading():
    """A category with no heading falls back to a bare "Not compared:", which throws away
    the reason — the whole point of grouping. Caught on a real run when a fifth category
    was added and its heading was not."""
    from clawseccheck.report import _NOTE_HEADINGS
    for category in NOTE_CATEGORY_ORDER:
        assert category in _NOTE_HEADINGS, f"{category} would render without a reason"
        out = _render([], [(category, "sentence")], verbose=True)
        assert _NOTE_HEADINGS[category] in out


def test_verbose_groups_by_reason_in_severity_order():
    notes = [(NOTE_NO_PRIOR_RECORD, "quiet one"), (NOTE_CONFIG_BLIND, "loud one")]
    out = _render([], notes, verbose=True)
    assert out.index("loud one") < out.index("quiet one"), (
        "the reason that should worry the reader most comes first"
    )


def test_a_run_with_nothing_uncompared_prints_no_block_at_all():
    """Absence of the block is itself the statement that everything was compared."""
    out = _render([], [])
    assert "could not be compared" not in out


def test_no_block_on_a_branch_that_makes_no_claim():
    """Nothing was compared on the first two, and nothing was affirmed on the third. A
    qualifier needs a claim to qualify; without one it is a caveat attached to nothing."""
    notes = [(NOTE_CONFIG_BLIND, "x")]
    assert "could not be compared" not in _render([], notes, baseline=True)
    assert "could not be compared" not in _render([], notes, baseline_corrupt=True)
    assert "could not be compared" not in _render([], notes, persisted=False)


def test_the_block_survives_ascii_mode():
    out = render_monitor([], _score(), ascii_only=True,
                         notes=[(NOTE_CONFIG_BLIND, "x")], verbose=True)
    assert "[i]" in out and "ℹ" not in out
