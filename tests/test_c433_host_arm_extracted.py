"""C-433 — the first per-dimension extraction, pinned.

`_diff_host_monitors` was lifted out of `diff_with_notes`. This is the shape the task asks
for and NOT the by-function shape it rejected three times: the arm travels with its own
dimension rather than with "all the diff code".

**Why this arm went first, measured rather than guessed.** Its entire free-variable set
inside `diff_with_notes` was `_host_pair`, `alerts`, `note` and module constants — three
parameters. The task's blocking analysis said a per-dimension cut meant threading 61 shared
locals; that figure is an aggregate over the whole 1,635-line function and does not describe
the arms, which read three or four names each. The 61 live in the blind-run preamble, which
is why the preamble moves last.

**The verification harness for the move was blind at first, and that is the lesson worth
carrying into the next extraction.** The initial contract check compared `diff_with_notes`
output across the two fixture homes and reported "identical" — but disabling the arm
entirely *also* produced identical output, because neither fixture home carries a `host`
dimension at all. A negative measured without a positive control is worthless. The cases
below are the ones that actually exercise the arm.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import pytest

from clawseccheck import monitor
from clawseccheck.monitor import diff_with_notes

_PRESENT = {"network_ids": "present", "edr_av": "present", "file_integrity": "unknown"}
_GONE = {"network_ids": "absent", "edr_av": "present", "file_integrity": "unknown"}
_ALL_UNKNOWN = {"network_ids": "unknown", "edr_av": "unknown", "file_integrity": "unknown"}


def _snap(host=None, **kw) -> dict:
    base = {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {}, "graded": True, "score": 50, "raw_score": 50, "grade": "F",
        "scope": ["host"], "watched": list(monitor.WATCHED_DIMENSIONS),
        "config_ever_seen": True, "config_file_sha256": "a" * 64,
    }
    if host is not None:
        base["host"] = host
    base.update(kw)
    return base


def _host_alerts(prev, curr):
    alerts, _notes = diff_with_notes(prev, curr)
    return [(lvl, m) for lvl, m in alerts if "Host monitor" in m]


def _host_notes(prev, curr):
    _alerts, notes = diff_with_notes(prev, curr)
    return [(c, s) for c, s in notes if "security tool" in s]


def test_the_arm_is_a_module_level_function_now():
    """The structural claim. If a later change inlines it back, the extraction has been
    undone and the per-dimension pattern this establishes is gone with it."""
    assert callable(getattr(monitor, "_diff_host_monitors", None))


def test_a_watcher_that_disappears_still_alerts():
    """The positive control, and the case the first harness could not see. Without this,
    every 'output is unchanged' claim about the move is satisfied by an arm that never
    runs."""
    hits = _host_alerts(_snap(_PRESENT), _snap(_GONE))
    assert len(hits) == 1, hits
    assert hits[0][0] == "HIGH", hits
    assert "network_ids" in hits[0][1], hits


def test_an_unchanged_host_says_nothing():
    assert not _host_alerts(_snap(_PRESENT), _snap(_PRESENT))


def test_a_watcher_that_was_never_confirmed_is_disclosed_not_alerted():
    """C-418's rule, preserved across the move: only present -> absent alerts, and a class
    that was already `unknown` gets a note instead of silence."""
    assert not _host_alerts(_snap(_ALL_UNKNOWN), _snap(_ALL_UNKNOWN))
    assert _host_notes(_snap(_ALL_UNKNOWN), _snap(_ALL_UNKNOWN))


def test_absent_on_one_side_is_neither_alert_nor_note():
    """The dimension simply was not recorded. Reporting it would put a permanent entry in
    the un-compared list on every machine that never enables host detection."""
    assert not _host_alerts(_snap(), _snap(_PRESENT))
    assert not _host_notes(_snap(), _snap(_PRESENT))


@pytest.mark.parametrize("pair", [None])
def test_the_function_tolerates_no_pair(pair):
    """It is called unconditionally now; the None guard moved inside. A caller that stops
    checking must not get an exception."""
    monitor._diff_host_monitors(pair, [], lambda *_a, **_k: None)


# ------------------------------------------------ the second and third extractions

def test_the_channels_and_plugins_arms_are_module_level_too():
    """Three dimensions now travel as their own functions. Each is the shape C-433 asks for
    — an arm with its dimension — rather than the by-function shape it rejected."""
    for name in ("_diff_host_monitors", "_diff_channels", "_diff_plugins"):
        assert callable(getattr(monitor, name, None)), name


def test_the_extracted_arms_take_only_what_they_measured_to_need():
    """The parameter counts are the measurement, not a preference: 3, 4 and 3. The task's
    blocking analysis said a per-dimension cut meant threading 61 shared locals; that
    figure describes the whole function, and the arms read three or four names each."""
    import inspect
    assert len(inspect.signature(monitor._diff_host_monitors).parameters) == 3
    assert len(inspect.signature(monitor._diff_channels).parameters) == 4
    assert len(inspect.signature(monitor._diff_plugins).parameters) == 3


def test_a_plugin_newly_allowed_still_alerts_after_the_move():
    """A positive control per extracted arm. Without one, 'the output did not change' is
    satisfied by an arm that no longer runs — which is exactly how the first harness for
    this refactor passed with the host arm deleted."""
    base = _snap()
    before = dict(base, plugins={"allow": ["a"], "deny": ["evil"], "entries": {},
                                 "bundled_discovery": "strict"})
    after = dict(base, plugins={"allow": ["a", "new"], "deny": ["evil"], "entries": {},
                                "bundled_discovery": "strict"})
    alerts, _notes = diff_with_notes(before, after)
    assert [m for _lvl, m in alerts if "newly allowed" in m], alerts


def test_an_unchanged_plugin_surface_is_silent_after_the_move():
    base = _snap()
    same = dict(base, plugins={"allow": ["a"], "deny": ["evil"], "entries": {},
                               "bundled_discovery": "strict"})
    alerts, _notes = diff_with_notes(same, dict(same))
    assert not [m for _lvl, m in alerts if "Plugin" in m], alerts


def test_the_provenance_arm_moved_too_and_the_claim_that_blocked_it_was_wrong():
    """**This replaces a test that pinned a wrong claim of mine.**

    The previous version asserted the provenance arm had been "deliberately left in place"
    because `trust_removals` is a shared accumulator, and it asserted
    `not hasattr(monitor, "_diff_skill_provenance")` to keep it there. That was a test
    enforcing my own mistake.

    `trust_removals = not curr_blind` is a **boolean flag**, computed once and never
    mutated. My scan looked for assignments by name, which would not have seen a `.append`;
    re-checked for method calls, augmented assignment and item stores, there are none. A
    read-only flag is a parameter, and the arm extracts with six of them.

    Twice on this task I called a per-dimension cut infeasible on a measurement that was
    true of the wrong thing — first the 61-shared-locals figure, which describes the whole
    function rather than its arms, then this. The pattern is worth more than either fix:
    **a claim that blocks work deserves the same adversarial pass as the work.**
    """
    assert callable(getattr(monitor, "_diff_skill_provenance", None))
    import inspect
    assert len(inspect.signature(monitor._diff_skill_provenance).parameters) == 6
    src = inspect.getsource(monitor.diff_with_notes)
    assert "trust_removals = not curr_blind" in src, (
        "if this stops being a plain flag, the parameter passed to the provenance arm "
        "needs re-deriving before anything else moves")


def test_all_four_dimension_arms_are_module_level():
    """The state C-433 has reached: four dimensions travel as their own functions, and
    what remains in `diff_with_notes` converges on the preamble plus a list of calls."""
    for name in ("_diff_host_monitors", "_diff_channels", "_diff_plugins",
                 "_diff_skill_provenance"):
        assert callable(getattr(monitor, name, None)), name


def test_a_provenance_record_that_moved_still_alerts():
    """Positive control for the fourth arm, so 'the output did not change' is not satisfied
    by an arm that stopped running."""
    def rec(**kw):
        base = {"version": "1.0.0", "installed_at": 1, "registry": "",
                "artifact_sha256": "a" * 64, "skill_file_sha256": "c" * 64,
                "corroborated": True}
        base.update(kw)
        return base

    base = _snap()
    before = dict(base, skill_provenance={"demo-skill": rec()})
    after = dict(base, skill_provenance={
        "demo-skill": rec(version="2.0.0", artifact_sha256="b" * 64, installed_at=2)})
    alerts, _notes = diff_with_notes(before, after)
    assert alerts, "a moved install record must still be reported"


def test_the_extracted_arms_keep_the_blind_run_guard():
    """**The regression this refactor actually shipped, before the full suite caught it.**

    The original conditions were `if compare_config and _pair is not None:`. The extraction
    script rebuilt only the None half, so on a run recovering from an unknown baseline —
    where `compare_config` is False — the channels arm ran anyway and fabricated

        HIGH  NEW channel 'telegram' appeared since last check

    about a channel the baseline had simply never recorded. That is precisely the
    fabrication class B-269 exists to prevent, reintroduced by a mechanical move.

    Two things are worth carrying from it. A compound guard is not one guard: an AST-driven
    extraction that reconstructs an `if` must reconstruct the whole test, and mine took one
    clause. And the 19-case equivalence harness did not see it — the case that did is in
    `tests/test_b269_monitor_config_parse_error.py`, which builds the unknown-baseline state
    the harness never constructed. An equivalence harness covers the states you thought of.
    """
    pair = ({"telegram": {"dm": "closed"}}, {"telegram": {"dm": "closed"},
                                             "slack": {"dm": "open"}})
    for fn, args in ((monitor._diff_channels, (pair, False, [], False)),
                     (monitor._diff_plugins, (pair, [], False))):
        alerts: list = []
        call = list(args)
        call[-2 if fn is monitor._diff_channels else 1] = alerts
        fn(*call)
        assert alerts == [], (
            f"{fn.__name__} fired with compare_config False — the blind-run guard is gone "
            f"and this is the B-269 fabrication shape\n{alerts}")
