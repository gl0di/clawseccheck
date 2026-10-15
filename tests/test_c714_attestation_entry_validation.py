"""C-714 - unusable parts of an attestation must not make any check cleaner or dirtier.

`attested_agents()` used to accept ANY dict entry (a blank/missing name became a positional
label, a non-list `tools` became `[]`), so `{"agents": [{"name": 5, "tools": "y"}]}` produced
a roster of one agent that holds nothing - and "no agent holds all three legs" PASSed with
no warning. The same class sat in the neighbouring lists: `tools: ["", null]` read as a
classified toolset (B43 PASS) and `host_monitors: [<zero-width char>]` as a named monitor
(B16 PASS).

The rule now: every part is vetted on its own. An unusable agent roster, or an unusable
`tools` / `proven_tools` / `host_monitors` list, is dropped and then reads EXACTLY as if the
key had not been written; the rest of the attestation is read as written. The invariant
tested through the real CLI: the (id, status) set of an attestation with a garbage part
equals the set of the same attestation without that key.
"""
from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

from clawseccheck import attest
from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.cli import main
from clawseccheck.collector import Context

SC = attest.SCHEMA_ID
ZW = "\u200b"
BOM = "\ufeff"

# Agent rosters that are unusable in whole or in part. Each used to leave an entry behind.
GARBAGE_ROSTERS = [
    [1],
    ["x"],
    [{}],
    [{"name": 5}],
    [{"name": "a", "tools": "y"}],
    [{"name": "a", "tools": [1, 2]}],
    [{"name": "a"}],
    [{"tools": ["web_fetch"]}],
    [{"name": "  ", "tools": ["web_fetch"]}],
    [{"name": ZW, "tools": []}],
    [{"name": BOM, "tools": []}],
    [{"name": "\x01", "tools": []}],
    [{"name": "\x00", "tools": []}],
    [{"name": "a", "tools": ["", " "]}],
    [{"name": "a", "tools": [ZW]}],
    [1, "x", {"name": 5, "tools": "y"}],
]
# `agents` that is not a list at all.
NON_LIST_ROSTERS = ["x", {}, {"name": "a", "tools": ["web_fetch"]}, 5, True]
_RIDS = [json.dumps(r) for r in GARBAGE_ROSTERS + NON_LIST_ROSTERS]

# Member garbage for the name lists. None of these is a name.
GARBAGE_MEMBERS = {
    "tools": [["", " "], ["", None, 5], [ZW], [BOM], ["\x01"], ["\x00"], [5], [None]],
    "proven_tools": [["", None], [ZW], [5]],
    "host_monitors": [[ZW], [BOM], ["\x01"], ["\x00"], [""], [" "], [5], ["", None]],
}

# A realistic attestation in which EVERY section moves a verdict, so "equal to the run
# without the key" cannot hold by accident (checked in test_the_base_attestation_is_not_inert).
BASE = {
    "schema": SC,
    "tools": ["bash", "send_email", "search_threads"],
    "proven_tools": ["send_email"],
    "approval_gates": {"exec": "auto", "send": "auto", "write": "auto"},
    "untrusted_to_action": "ungated",
    "host_monitors": ["Falcon EDR"],
}


def _ctx(att) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = {"mcp": {"servers": {"files": {"command": "mcp-files"}}}}
    c.bootstrap = {}
    c.installed_skills = {}
    c.attestation = att
    return c


# ------------------------------------------------------------------------------ units
def test_is_blank_text_follows_the_category_definition():
    from clawseccheck.attest import is_blank_text
    for blank in ("", " ", "\t\n", ZW, BOM, "\x01", "\x00", "\u2028", "\u2029", "\u00a0",
                  ZW + " " + BOM):
        assert is_blank_text(blank), repr(blank)
    for visible in ("a", ZW + "a", "0", "\ud800"):
        assert not is_blank_text(visible), repr(visible)


@pytest.mark.parametrize("roster", GARBAGE_ROSTERS, ids=_RIDS[:len(GARBAGE_ROSTERS)])
def test_unusable_entries_leave_no_roster(roster):
    from clawseccheck.attest import attested_agents
    assert attested_agents({"agents": roster}) == []


@pytest.mark.parametrize("roster", GARBAGE_ROSTERS, ids=_RIDS[:len(GARBAGE_ROSTERS)])
def test_unusable_roster_keeps_b45_b75_b76_unknown(roster):
    from clawseccheck.checks import (
        check_agent_separation,
        check_mcp_bypass_highblast,
        check_mcp_tool_inheritance,
    )
    att = {"schema": SC, "agents": roster}
    for fn, cid in ((check_agent_separation, "B45"),
                    (check_mcp_tool_inheritance, "B75"),
                    (check_mcp_bypass_highblast, "B76")):
        f = fn(_ctx(att))
        assert f.id == cid
        assert f.status == UNKNOWN, (cid, roster)


def test_unusable_roster_is_not_a_declared_capability_roster():
    from clawseccheck.checks import _config
    assert _config._capabilities_attested(_ctx({"agents": [{"name": 5, "tools": "y"}]})) is False


def test_one_unusable_entry_makes_the_whole_roster_unusable():
    """All or nothing: the entry that fails to validate can be the one that declared the
    risk, so the rest is not a smaller valid roster."""
    from clawseccheck.attest import attested_agents
    att = {"agents": [1, {"name": "reader", "tools": ["web_fetch"]}, {"name": "b"}]}
    assert attested_agents(att) == []


def test_valid_roster_is_unchanged_and_an_empty_toolset_is_valid():
    from clawseccheck.attest import attested_agents
    att = {"agents": [{"name": " reader ", "tools": ["web_fetch", "read_file"]},
                      {"name": "idle", "tools": []}]}
    assert attested_agents(att) == [
        {"name": "reader", "tools": ["web_fetch", "read_file"]},
        {"name": "idle", "tools": []},
    ]


def test_blank_tool_names_in_the_helpers_are_not_a_toolset():
    from clawseccheck.attest import attested_proven, classify_tools
    from clawseccheck.checks import _host
    assert classify_tools(["", ZW, None, 5, " "]) == {}
    assert attested_proven({"proven_tools": ["", ZW, "\x00"]}) == set()
    assert _host._attested_monitors_any(_ctx({"host_monitors": [ZW, "", "\x01"]})) == []
    assert _host._attested_monitors_any(_ctx({"host_monitors": ["zzz"]})) == ["zzz"]


def test_vet_attestation_returns_a_valid_attestation_untouched():
    from clawseccheck.attest import vet_attestation
    att = dict(BASE, agents=[{"name": "a", "tools": ["x"]}, {"name": "idle", "tools": []}],
               delegation=[{"from": "a", "to": "idle", "returns": "raw"}])
    out, notes = vet_attestation(att)
    assert out is att and notes == []
    for empty in ({}, {"schema": SC, "agents": [], "tools": [], "host_monitors": []},
                  {"agents": None}):
        assert vet_attestation(empty) == (empty, [])


def test_vet_attestation_notes_hold_counts_and_reasons_never_content():
    from clawseccheck.attest import vet_attestation
    marker = "".join(["ZZ", "MARK", "ER"])
    att = {"agents": [{"name": "ok", "tools": ["x"]}, 7, marker, {"name": 5, "tools": marker},
                      {"name": "a", "tools": [marker, 3]}],
           "tools": [marker, 5, "fine"], "host_monitors": [5, ""]}
    out, notes = vet_attestation(att)
    # every part with anything unusable in it is removed whole, never trimmed
    assert "agents" not in out and "tools" not in out and "host_monitors" not in out
    assert len(notes) == 3 and all(isinstance(n, str) for n in notes)
    # a note may name the KEY but never repeat an entry's content
    assert marker not in " ".join(notes)
    assert "4 of 5 entries are unusable" in notes[0]
    assert "1 of 3 members are not" not in notes[1] and "1 of 3 member is not" in notes[1]


def test_vet_attestation_removes_a_non_list_roster_only():
    from clawseccheck.attest import vet_attestation
    out, notes = vet_attestation(dict(BASE, agents="x"))
    assert out == BASE and len(notes) == 1 and "str" in notes[0]
    out, notes = vet_attestation(dict(BASE, agents={"name": "x"}))
    assert out == BASE and "dict" in notes[0]


# ------------------------------------------------------------------ through the real CLI
def _run(tmp_path, capsys, monkeypatch, payload, *, via_stdin=False, extra=()):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    argv = ["--home", str(tmp_path), "--no-native", "--no-host", "--no-deptree",
            "--no-history", "--json", *extra]
    if payload is None:
        pass
    elif via_stdin:
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(raw)))
        argv += ["--attest", "-"]
    else:
        f = tmp_path / "att.json"
        f.write_bytes(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
        argv += ["--attest", str(f)]
    rc = main(argv)
    cap = capsys.readouterr()
    statuses = {f["id"]: f["status"] for f in json.loads(cap.out)["findings"]}
    return rc, statuses, cap.err


def _minus(att, key):
    return {k: v for k, v in att.items() if k != key}


def test_the_base_attestation_is_not_inert(tmp_path, capsys, monkeypatch):
    # positive control: each section the invariant tests drop really moves a verdict,
    # so "equal to the run without the key" is a statement about something.
    none = _run(tmp_path, capsys, monkeypatch, None)[1]
    full = _run(tmp_path, capsys, monkeypatch, BASE)[1]
    assert none["B43"] == UNKNOWN and full["B43"] != UNKNOWN
    assert none["B16"] != PASS and full["B16"] == PASS
    no_tools = _run(tmp_path, capsys, monkeypatch, _minus(BASE, "tools"))[1]
    assert no_tools["B43"] == UNKNOWN
    no_mon = _run(tmp_path, capsys, monkeypatch, _minus(BASE, "host_monitors"))[1]
    assert no_mon["B16"] != PASS


@pytest.mark.parametrize("via_stdin", [False, True], ids=["file", "stdin"])
def test_cli_garbage_roster_equals_the_run_without_the_agents_key(tmp_path, capsys,
                                                                  monkeypatch, via_stdin):
    expect = _run(tmp_path, capsys, monkeypatch, BASE, via_stdin=via_stdin)[1]
    for roster in GARBAGE_ROSTERS + NON_LIST_ROSTERS:
        rc, got, err = _run(tmp_path, capsys, monkeypatch, dict(BASE, agents=roster),
                            via_stdin=via_stdin)
        assert rc == 0
        assert got == expect, (roster, {k: (expect[k], got[k]) for k in got if got[k] != expect[k]})
        assert err.count("\u26a0") == 1
        assert "agent roster" in err or "agent entries" in err
        assert "rest of the attestation was read" in err


@pytest.mark.parametrize("key", sorted(GARBAGE_MEMBERS))
def test_cli_garbage_name_list_equals_the_run_without_that_key(tmp_path, capsys,
                                                               monkeypatch, key):
    expect = _run(tmp_path, capsys, monkeypatch, _minus(BASE, key))[1]
    for members in GARBAGE_MEMBERS[key]:
        rc, got, err = _run(tmp_path, capsys, monkeypatch, dict(BASE, **{key: members}))
        assert rc == 0
        assert got == expect, (key, members,
                               {k: (expect[k], got[k]) for k in got if got[k] != expect[k]})
        assert err.count("\u26a0") == 1 and f"'{key}'" in err
        assert "rest of the attestation was read" in err


@pytest.mark.parametrize("key,value", [
    ("tools", ["web_fetch", "exec", "", None, ZW]),
    ("tools", ["exec", 5]),
    ("proven_tools", ["exec", {}]),
    ("host_monitors", ["Falcon EDR", 5]),
])
def test_cli_partly_garbage_name_list_is_ignored_whole(tmp_path, capsys, monkeypatch, key, value):
    """A list with one bad member reads exactly as if its key were absent: nothing is
    trimmed, so no check can PASS on the part that happened to validate."""
    minus_key = {k: v for k, v in BASE.items() if k != key}
    expect = _run(tmp_path, capsys, monkeypatch, minus_key)[1]
    rc, got, err = _run(tmp_path, capsys, monkeypatch, dict(BASE, **{key: value}))
    assert rc == 0 and got == expect
    assert err.count("\u26a0") == 1 and f"the '{key}' list" in err


def test_cli_a_valid_host_monitor_name_still_counts(tmp_path, capsys, monkeypatch):
    got = _run(tmp_path, capsys, monkeypatch, dict(BASE, host_monitors=["zzz"]))[1]
    assert got["B16"] == PASS


_TRIFECTA = ["web_fetch", "db_query", "send_email"]
_BENIGN = {"name": "reader", "tools": ["read_file"]}


@pytest.mark.parametrize("bad_entry", [
    3,
    {"name": "b", "tools": "y"},
    {"name": "risky", "tools": _TRIFECTA + [7]},      # the risk rides the entry that fails
    {"name": "risky", "tools": _TRIFECTA + [""]},
    {"tools": _TRIFECTA},                               # no name
    {"id": "risky", "tools": _TRIFECTA},                # wrong key
    {"name": ZW, "tools": _TRIFECTA},
], ids=["int", "tools-str", "trifecta+junk", "trifecta+blank", "no-name", "id-not-name",
        "zero-width-name"])
def test_cli_a_mixed_roster_never_reads_cleaner_than_no_roster(tmp_path, capsys, monkeypatch,
                                                               bad_entry):
    """One valid entry beside one unusable entry. Trimming to the valid entry made B45
    PASS while the dropped entry declared all three trifecta legs; the roster is now
    ignored whole, so every status equals the run without the ``agents`` key."""
    expect = _run(tmp_path, capsys, monkeypatch, BASE)[1]
    rc, got, err = _run(tmp_path, capsys, monkeypatch, dict(BASE, agents=[_BENIGN, bad_entry]))
    assert rc == 0 and got == expect, {k: (expect[k], got[k]) for k in got if got[k] != expect[k]}
    assert got["B45"] != PASS
    assert "1 of 2 entry is unusable" in err


def test_cli_the_valid_roster_alone_is_the_control(tmp_path, capsys, monkeypatch):
    """Without the bad entry the same roster IS used: the test above is not vacuous."""
    rc, got, err = _run(tmp_path, capsys, monkeypatch, dict(BASE, agents=[_BENIGN]))
    assert rc == 0 and err == "" and got["B45"] == PASS
    risky = {"name": "risky", "tools": _TRIFECTA}
    rc, got, err = _run(tmp_path, capsys, monkeypatch, dict(BASE, agents=[_BENIGN, risky]))
    assert rc == 0 and err == "" and got["B45"] not in (PASS, UNKNOWN)


def test_cli_warning_never_prints_the_rejected_content(tmp_path, capsys, monkeypatch):
    marker = "".join(["ZZ", "MARK", "ER"])
    att = dict(BASE, agents=[{"name": 5, "tools": marker}, marker, {marker: marker}],
               tools=[marker, 5], proven_tools=[5, ZW + marker.lower()],
               host_monitors=[{marker: 1}])
    _rc, _got, err = _run(tmp_path, capsys, monkeypatch, att)
    assert err and marker not in err and marker.lower() not in err


def test_cli_valid_attestation_prints_no_warning(tmp_path, capsys, monkeypatch):
    att = dict(BASE, agents=[{"name": "a", "tools": ["web_fetch"]}, {"name": "idle", "tools": []}])
    rc, _got, err = _run(tmp_path, capsys, monkeypatch, att)
    assert rc == 0 and err == ""
    rc, _got, err = _run(tmp_path, capsys, monkeypatch, dict(BASE, agents=[]))
    assert rc == 0 and err == ""


def test_cli_judged_bundle_attestation_is_vetted_the_same_way(tmp_path, capsys, monkeypatch):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"attestation": dict(BASE, agents=[1])}), encoding="utf-8")
    rc, got, err = _run(tmp_path, capsys, monkeypatch, None,
                        extra=("--full", "--judged-bundle", str(bundle)))
    assert rc == 0 and got["B43"] != UNKNOWN and got["B16"] == PASS
    assert "agent roster" in err and "rest of the attestation was read" in err


def test_cli_ten_thousand_garbage_entries_are_bounded(tmp_path, capsys, monkeypatch):
    att = dict(BASE, agents=[{"name": i, "tools": "y"} for i in range(10000)])
    expect = _run(tmp_path, capsys, monkeypatch, BASE)[1]
    t0 = time.monotonic()
    rc, got, err = _run(tmp_path, capsys, monkeypatch, att)
    assert rc == 0 and time.monotonic() - t0 < 60
    assert got == expect and "10000 of 10000 entries are unusable" in err


@pytest.mark.parametrize("depth", [200, 2000])
def test_cli_deep_nesting_is_the_unreadable_attestation_warning(tmp_path, capsys,
                                                                monkeypatch, depth):
    deep = (b'{"schema": "' + SC.encode() + b'", "agents": ' + b"[" * depth + b"]" * depth + b"}")
    rc, got, err = _run(tmp_path, capsys, monkeypatch, deep, via_stdin=True)
    assert rc == 0 and got["B45"] == UNKNOWN
    assert "could not read a valid attestation" in err and "Traceback" not in err


@pytest.mark.parametrize("raw", [
    b'{"schema": "' + SC.encode() + b'", "agents": [{"name": "\\u0000", "tools": []}]}',
    b'{"schema": "' + SC.encode() + b'", "agents": [{"name": "\\ud800", "tools": ["web_fetch"]}]}',
    b'{"schema": "' + SC.encode() + b'", "tools": ["\\ud800", "\\u0000"], "host_monitors": ["\\ud800"]}',
    b'{"schema": "' + SC.encode() + b'", "agents": [\x00]}',
], ids=["nul-name", "lone-surrogate-name", "surrogate-and-nul-lists", "raw-nul-byte"])
def test_cli_odd_characters_never_crash(tmp_path, capsys, monkeypatch, raw):
    rc, got, err = _run(tmp_path, capsys, monkeypatch, raw, via_stdin=True)
    assert rc == 0 and "B45" in got and "Traceback" not in err
