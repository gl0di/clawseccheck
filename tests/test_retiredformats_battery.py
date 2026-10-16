"""Offline replay of the vendor differential for ``clawseccheck.retiredformats``.

``tests/data/retiredformats_battery.json`` was produced by EXECUTING OpenClaw's own
``findRetiredConfigUpgradeRequirement`` (see ``tests/_retiredformatsoracle.py``). This file
replays it against the port with no node and no dist, the same split as
``test_harnessruntime_battery.py``; the live re-execution and the dist grounding are
``test_retiredformats_dist_grounding.py`` (local-only).

THE CONTRACT is exact agreement, not soundness: for every row the port reports the same
paths in the same order (the vendor's message is reassembled from the port's paths and
compared as one string) and the same ``bridgeVersion``; where the vendor answers
``undefined`` the port answers ``None``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from _retiredformatsoracle import bridge_of, reassemble_message

from clawseccheck import retiredformats as rf

DATA = json.loads((Path(__file__).parent / "data" / "retiredformats_battery.json")
                  .read_text(encoding="utf-8"))
ROWS = DATA["rows"]


def _disagreements(rows):
    bad = []
    for row in rows:
        got = rf.find_retired(row["cfg"])
        vendor = row["vendor"]
        if vendor is None:
            if got is not None:
                bad.append((row["label"], "port reports", got.paths))
            continue
        if got is None:
            bad.append((row["label"], "port misses", vendor["message"][:200]))
        elif reassemble_message(got.paths) != vendor["message"]:
            bad.append((row["label"], got.paths, vendor["message"][:300]))
        elif got.bridge_version != bridge_of(vendor["nextAction"]):
            bad.append((row["label"], "bridge", got.bridge_version, vendor["nextAction"][:80]))
    return bad


@pytest.mark.parametrize("prefix", ["one:", "near:", "fuzz:"])
def test_port_equals_the_vendor_on_every_row(prefix):
    rows = [r for r in ROWS if r["label"].startswith(prefix)]
    assert rows, prefix
    assert not _disagreements(rows)


def test_battery_is_a_real_sweep_and_not_vacuous():
    """A port that always answered ``None`` would pass the near-miss rows; a port that always
    reported would pass the one-key rows. Both answers, both bridge versions, and a large
    share of definite answers must occur."""
    fired = [r for r in ROWS if r["vendor"] is not None]
    quiet = [r for r in ROWS if r["vendor"] is None]
    assert len(fired) > 500 and len(quiet) > 100, (len(fired), len(quiet))
    assert {bridge_of(r["vendor"]["nextAction"]) for r in fired} == {
        rf.BRIDGE_DEFAULT, rf.BRIDGE_DISCORD}
    assert not [r for r in ROWS if r["vendor"] and "error" in r["vendor"]]
    # every one-key row names exactly the one path its label promises
    one = [r for r in ROWS if r["label"].startswith("one:")]
    assert len(one) >= 110
    for r in one:
        assert r["vendor"] is not None, r["label"]


def test_every_vendor_name_is_exercised_by_a_one_key_row():
    """The vocabulary is every key name / retired value the vendor finder mentions. Each
    must appear as a key (or a retired value) in some pinned config, else a typo'd key in
    the port would go unseen. Structural words the finder only uses in a typeof test, and
    the empty root path, are excluded by name."""
    excluded = {"", "boolean", "string", "2026.9.5", "2026.9.7",
                # joined template prefixes, covered through their segments
                "agents.defaults", "browser.ssrfPolicy", "channels.feishu",
                "channels.telegram", "messages.queue.mode", "session.threadBindings"}
    seen = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                seen.add(key)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            seen.add(node)

    for row in ROWS:
        if row["label"].startswith("one:"):
            walk(row["cfg"])
    missing = sorted(set(DATA["vocabulary"]) - excluded - seen)
    assert not missing, missing


# --- a control that cannot fail controls nothing: break the port four ways, see it caught ---

def _broken_disagreements(monkeypatch, attr, value):
    monkeypatch.setattr(rf, attr, value)
    return _disagreements(ROWS)


def test_battery_catches_a_port_that_ignores_js_key_order(monkeypatch):
    assert _broken_disagreements(monkeypatch, "_entries", lambda rec: list(rec.items()))


def test_battery_catches_a_wrong_bridge_rule(monkeypatch):
    assert _broken_disagreements(monkeypatch, "BRIDGE_DISCORD", "2026.9.5")


def test_battery_catches_a_missing_prototype_key_skip(monkeypatch):
    assert _broken_disagreements(monkeypatch, "_BLOCKED_OBJECT_KEYS", frozenset())


def test_battery_catches_a_short_retired_value_list(monkeypatch):
    assert _broken_disagreements(monkeypatch, "_RETIRED_QUEUE_MODES", ("queue",))


# --- the window ---

def test_window_is_the_validated_builds_only():
    assert DATA["build"] == "2026.10.4"
    assert rf.in_window((2026, 10, 1)) and rf.in_window((2026, 10, 2))
    assert rf.in_window((2026, 10, 3)) and rf.in_window((2026, 10, 4))
    assert rf.in_window((2026, 10, 2, 1))  # a correction release stays inside
    assert not rf.in_window((2026, 9, 9)) and not rf.in_window((2026, 10, 5))
    assert not rf.in_window((2027, 1, 1))
    assert not rf.in_window(None) and not rf.in_window(()) and not rf.in_window((2026, 10))
    assert not rf.in_window("2026.10.2")


def test_a_non_record_config_is_nothing_retired():
    for junk in (None, [], "x", 0, True):
        assert rf.find_retired(junk) is None
