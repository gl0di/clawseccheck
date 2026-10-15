"""``clawseccheck/retiredformats.py`` re-grounded against the INSTALLED OpenClaw, live.

Local-only: skipped wherever the dist (or node) is absent. That is the only stand-down; a
present dist whose anchors moved FAILS, naming the symbol (``tests/_distgrounding.py``). The
offline replay of the same battery, which is what CI runs, is
``test_retiredformats_battery.py``.

Jobs, in order of what losing them would cost:

1. **Every path the installed finder names is covered.** The finder's whole source (region
   plus its traversal helpers) is hashed, and its vocabulary (every key name and retired
   value it mentions) is compared with the pinned one. A vendor release that adds, removes
   or recombines a retired path turns this red, naming the new word, BEFORE B382 goes quietly
   stale. The explicit ledger is ``_retiredformatsoracle.FINDER_PATHS``: the fresh vendor must
   answer exactly each ledger path, and every vocabulary word must appear in the ledger or be
   excluded here by name.
2. **Soundness, live.** Re-execute the vendor over every battery case and the whole fixture
   corpus; the port must agree with the FRESH answer.
3. **Drift.** On the build the battery was generated for, the fresh oracle must equal the
   pinned one row for row (regenerate: ``python3.12 tests/_retiredformatsoracle.py --write``).
4. **The window.** The installed build must be inside ``ORACLE_MIN..ORACLE_MAX``; outside it
   B382 silently falls back to its hand table, so this turns that into a red test.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from _distgrounding import require_dist

import _retiredformatsoracle as oracle
from clawseccheck import retiredformats as rf

pytestmark = pytest.mark.skipif(not oracle.has_node(), reason="no node on this machine")

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

#: Words the finder mentions that are not a key a config can hold (a typeof test, the empty
#: root path, the two bridge releases), or joined prefixes covered through their segments.
_EXCLUDED_VOCABULARY = {"", "boolean", "string", "2026.9.5", "2026.9.7", "agents.defaults",
                        "browser.ssrfPolicy", "channels.feishu", "channels.telegram",
                        "messages.queue.mode", "session.threadBindings"}


@pytest.fixture(scope="module")
def live():
    require_dist()
    cases = oracle.all_cases()
    return cases, oracle.run_oracle(copy.deepcopy(cases))


def _same(got, vendor) -> bool:
    if vendor is None:
        return got is None
    return (got is not None and oracle.reassemble_message(got.paths) == vendor["message"]
            and got.bridge_version == oracle.bridge_of(vendor["nextAction"]))


def test_the_installed_build_is_inside_the_validated_window():
    require_dist()
    ver = oracle.dist_version()
    assert ver, "could not read the installed OpenClaw version"
    numeric = tuple(int(x) for x in ver.split(".")[:3])
    assert rf.ORACLE_MIN <= numeric <= rf.ORACLE_MAX, (
        f"installed OpenClaw {ver} is outside the window the retired-format finder was "
        f"validated on {rf.ORACLE_MIN}..{rf.ORACLE_MAX}: B382 falls back to its hand table "
        f"there. Re-run this module, regenerate the battery "
        f"(`python3.12 tests/_retiredformatsoracle.py --write`) and raise ORACLE_MAX.")


def test_the_finder_source_has_not_changed():
    require_dist()
    pinned = json.loads(oracle.BATTERY_PATH.read_text(encoding="utf-8"))
    assert oracle.finder_digest() == pinned["finder_sha256"], (
        "the installed finder (or a helper it imports) differs from the one the battery was "
        "generated from -- a retired path may have been added or moved. Diff the vocabulary "
        "(next test), extend FINDER_PATHS, regenerate the battery and re-baseline B382.")


def test_every_path_the_installed_finder_names_is_covered_or_excluded():
    require_dist()
    pinned = json.loads(oracle.BATTERY_PATH.read_text(encoding="utf-8"))
    fresh = set(oracle.vendor_vocabulary())
    assert fresh == set(pinned["vocabulary"]), (
        f"new in the installed finder: {sorted(fresh - set(pinned['vocabulary']))}; gone: "
        f"{sorted(set(pinned['vocabulary']) - fresh)}")
    covered = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                covered.add(key)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            covered.add(node)

    for _label, cfg, _path in oracle.FINDER_PATHS:
        walk(cfg)
    uncovered = sorted(fresh - _EXCLUDED_VOCABULARY - covered)
    assert not uncovered, (
        f"the installed finder mentions {uncovered}, which no FINDER_PATHS config holds: add "
        f"a ledger row for each (or exclude it here with the reason)")


def test_the_fresh_vendor_answers_exactly_each_ledger_path(live):
    cases, results = live
    for case, res in zip(cases, results):
        if case["expect"] is None:
            continue
        assert res is not None and res["message"] == oracle.reassemble_message(case["expect"]), (
            case["label"], res)


def test_port_equals_the_live_vendor(live):
    cases, results = live
    bad = [(c["label"], res) for c, res in zip(cases, results)
           if not _same(rf.find_retired(c["cfg"]), res)]
    assert not bad, bad[:5]


def test_port_equals_the_live_vendor_over_every_fixture_config():
    require_dist()
    cases = []
    for path in sorted(FIXTURES.glob("*/openclaw.json")):
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(cfg, dict):
            cases.append({"label": path.parent.name, "cfg": cfg})
    assert len(cases) > 100, len(cases)
    results = oracle.run_oracle(cases)
    bad = [(c["label"], res) for c, res in zip(cases, results)
           if not _same(rf.find_retired(c["cfg"]), res)]
    assert not bad, bad[:5]


def test_pinned_battery_has_not_drifted_from_the_vendor(live):
    ver = oracle.dist_version()
    if ver != oracle.ORACLE_BUILD:
        pytest.skip(f"installed OpenClaw {ver} is not the build the battery is pinned to "
                    f"({oracle.ORACLE_BUILD}); the live equality test above is the check for "
                    f"this build, and re-baselining is a deliberate step")
    cases, results = live
    pinned = json.loads(oracle.BATTERY_PATH.read_text(encoding="utf-8"))
    fresh = [{"label": c["label"], "cfg": c["cfg"], "vendor": r}
             for c, r in zip(cases, results)]
    assert pinned["build"] == ver
    assert pinned["rows"] == fresh, (
        "tests/data/retiredformats_battery.json is stale against the case tables or the "
        "vendor -- regenerate with `python3.12 tests/_retiredformatsoracle.py --write`")


def test_the_bound_symbol_is_still_exported_by_name():
    require_dist()
    assert oracle.run_oracle([{"cfg": {}}]) == [None]
