"""``clawseccheck/harnessruntime.py`` re-grounded against the INSTALLED OpenClaw, live.

Local-only: skipped wherever the dist (or node) is absent -- CI, a machine without OpenClaw.
That is the only stand-down; a present dist whose anchors moved FAILS, naming the symbol
(B-728, ``tests/_distgrounding.py``). The offline replay of the same battery, which is what
CI runs, is ``test_harnessruntime_battery.py``.

Three jobs, in order of how much they would cost to lose:

1. **Soundness, live.** Re-execute the vendor over every battery case and require the port to
   be sound against the FRESH answer -- so a vendor release that moves the chain turns this
   red on the developer's machine, before the pinned battery goes quietly stale.
2. **Drift.** On the build the battery was generated for, the fresh oracle must equal the
   pinned one row for row. A mismatch means the battery (or the case tables) changed without
   a regeneration: ``python3.12 tests/_harnessoracle.py --write``.
3. **Anchors.** The four functions the oracle binds are exported by their real names.
"""
from __future__ import annotations

import copy
import json

import pytest
from _distgrounding import require_dist

import _harnessoracle as oracle
from clawseccheck import harnessruntime as hr

pytestmark = pytest.mark.skipif(not oracle.has_node(), reason="no node on this machine")


@pytest.fixture(scope="module")
def live():
    require_dist()
    cases = oracle.all_cases()
    return cases, oracle.run_oracle(copy.deepcopy(cases))


def _version():
    ver = oracle.dist_version()
    assert ver, "could not read the installed OpenClaw version"
    return ver, tuple(int(x) for x in ver.split(".")[:3])


def test_port_is_sound_against_the_live_vendor(live):
    cases, results = live
    _, numeric = _version()
    # clamp INTO the window: on a build newer than the validated one the port would answer
    # `unknown` to everything, which is trivially sound and would hide the drift this test is for
    version = min(max(numeric, hr.ORACLE_MIN), hr.ORACLE_MAX)
    bad = []
    counts = {hr.YES: 0, hr.NO: 0, hr.UNKNOWN: 0}
    for case, res in zip(cases, results):
        got = hr.codex_harness_reach(case["cfg"], version, environ=case["env"]).answer
        counts[got] += 1
        if "error" in res:
            if got != hr.UNKNOWN:
                bad.append((case["label"], got, res["error"]))
            continue
        has = "codex" in res["runtimes"]
        if (got == hr.YES and not has) or (got == hr.NO and has):
            bad.append((case["label"], got, res["runtimes"]))
    assert not bad, bad[:10]
    assert counts[hr.YES] and counts[hr.NO] and counts[hr.UNKNOWN], counts


def test_the_installed_build_is_inside_the_validated_window():
    """The drift ALARM. Outside ``ORACLE_MIN..ORACLE_MAX`` the runtime answers `unknown` and
    the B353 / B333 gate silently goes back to the old WARN -- safe, but a feature that has
    quietly stopped working. This turns that into a red test on the developer's machine, so
    the upgrade protocol re-runs the battery and raises ``ORACLE_MAX`` deliberately."""
    require_dist()
    ver, numeric = _version()
    assert hr.ORACLE_MIN <= numeric <= hr.ORACLE_MAX, (
        f"installed OpenClaw {ver} is outside the window the Codex-harness determination was "
        f"validated on {hr.ORACLE_MIN}..{hr.ORACLE_MAX}: re-run the live soundness test, "
        f"regenerate the battery (`python3.12 tests/_harnessoracle.py --write`) and raise "
        f"ORACLE_MAX -- until then B353/B333 fall back to the pre-gate WARN")


def test_pinned_battery_has_not_drifted_from_the_vendor(live):
    ver, _ = _version()
    if ver != oracle.ORACLE_BUILD:
        pytest.skip(f"installed OpenClaw {ver} is not the build the battery is pinned to "
                    f"({oracle.ORACLE_BUILD}); the live soundness test above is the check "
                    f"for this build, and re-baselining is a deliberate step")
    cases, results = live
    pinned = json.loads(oracle.BATTERY_PATH.read_text(encoding="utf-8"))
    assert pinned["build"] == ver
    fresh = [{"label": c["label"], "cfg": c["cfg"], "env": c["env"], "oracle": r}
             for c, r in zip(cases, results)]
    assert pinned["rows"] == fresh, (
        "tests/data/harnessruntime_battery.json is stale against the case tables or the "
        "vendor -- regenerate with `python3.12 tests/_harnessoracle.py --write` and review "
        "the diff")


def test_model_refs_equal_the_live_vendor_enumeration(live):
    cases, results = live
    for case, res in zip(cases, results):
        if "error" in res:
            continue
        assert [v for _, v in hr.model_refs(case["cfg"])] == res["refs"], case["label"]


def test_the_bound_symbols_are_still_exported_by_name():
    """`run_oracle` asserts each export by real name and raises with the moved symbol; this
    just makes that a named, greppable test rather than a side effect of the others."""
    require_dist()
    assert oracle.run_oracle([{"cfg": {}, "env": {}}]) == [
        {"collect": [], "refs": [], "runtimes": []}]
