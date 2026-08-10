"""F-170 — what OpenClaw's own config journal lets the monitor say that a diff cannot.

A snapshot comparison answers "what is different now". Two things it structurally cannot
do: name who made a change, and notice a change that was made and put back between runs.
OpenClaw records both, and the file was being ignored.

Three arms, and the design decision behind all of them is that the evidence is captured in
`snapshot()` and compared as HASHES:

* `diff()` stays a pure function of two stored snapshots, so every conclusion it reaches is
  reproducible from the state file alone.
* No clock comparison anywhere. Our `ts` is local time with second resolution; the
  journal's is UTC with a trailing `Z`. Comparing those as strings — the obvious way to ask
  "did anything get written since the last check?" — is a silent timezone bug for every
  user east of Greenwich. The journal HEAD hash answers the same question exactly.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import os

_D_OLD = "a" * 64
_D_NEW = "b" * 64
_H_OLD = "1" * 64
_H_NEW = "2" * 64

# `previous_hash` is what makes attribution provable: the journaled write started from
# the bytes the previous snapshot recorded, so it is the write that produced the change.
_WRITE = {"ts": "2026-08-03T08:39:10.769Z", "pid": 149054, "argv0": "node",
          "previous_hash": _D_OLD}

from clawseccheck.monitor import diff_with_notes  # noqa: E402


def _snap(digest, head, written_by=None, **over):
    snap = {
        "checks": {}, "checks_not_applicable": [], "checks_degraded": [], "scope": [],
        "mcp": {}, "mcp_detail": {}, "channels": {}, "gateway_bind": "127.0.0.1",
        "config_file_sha256": digest,
    }
    if head is not None:
        snap["config_journal_head"] = head
    if written_by is not None:
        snap["config_written_by"] = written_by
    snap.update(over)
    return snap


def _msgs(alerts):
    return [m for _, m in alerts]


# ---------------------------------------------------------------- arm 1: attribution

def test_a_journaled_edit_annotates_the_drift_alert_rather_than_adding_one():
    """One edit, one message. `diff()` already collapses three other double-reporting
    cases; a separate "your config changed" line beside "gateway bind changed" would be
    the same event told twice."""
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, gateway_bind="127.0.0.1"),
        _snap(_D_NEW, _H_NEW, written_by=_WRITE, gateway_bind="0.0.0.0"))
    assert len(alerts) == 1, alerts
    only = alerts[0][1]
    assert "Gateway bind changed" in only
    assert "pid 149054" in only and "node" in only


def test_attribution_reaches_every_config_derived_alert():
    """Each alert becomes its own entry in the tamper-evident journal and is sorted away
    from its neighbours in the report, so each has to carry its own provenance."""
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, gateway_bind="127.0.0.1", mcp={}),
        _snap(_D_NEW, _H_NEW, written_by=_WRITE, gateway_bind="0.0.0.0",
              mcp={"evil": "sig"}))
    assert len(alerts) == 2
    assert all("pid 149054" in m for m in _msgs(alerts)), alerts


def test_attribution_does_not_reach_alerts_the_config_edit_did_not_cause():
    """Skill and memory drift have nothing to do with a config write; stamping them with
    its provenance would be a fabricated causal claim."""
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, skills={}),
        _snap(_D_NEW, _H_NEW, written_by=_WRITE, skills={"newthing": "h"}))
    skill_alerts = [m for m in _msgs(alerts) if "newthing" in m]
    assert skill_alerts and not any("pid 149054" in m for m in skill_alerts)


def test_a_missing_program_name_does_not_render_as_an_empty_bracket():
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, gateway_bind="127.0.0.1"),
        _snap(_D_NEW, _H_NEW,
              written_by={"ts": "t", "pid": 1, "argv0": "", "previous_hash": _D_OLD},
              gateway_bind="0.0.0.0"))
    assert "unknown program" in alerts[0][1]


# ---------------------------------------------------------------- arm 2: unjournalled

def test_an_edit_openclaw_did_not_write_is_an_observation_not_an_accusation():
    """MEDIUM is a ceiling, not a judgement. `vim`, `jq ... > tmp && mv`, a dotfile manager
    swapping a symlink and a restored backup all produce exactly this shape."""
    alerts, _ = diff_with_notes(_snap(_D_OLD, _H_OLD), _snap(_D_NEW, _H_OLD))
    assert [lvl for lvl, _ in alerts] == ["MEDIUM"]
    assert "Confirm you made this change" in alerts[0][1]
    assert "normal for a hand edit" in alerts[0][1]


def test_the_unjournalled_observation_fires_once_not_on_every_run():
    """It is gated on the digest having CHANGED. Firing whenever the live bytes merely
    disagree with the journal head would nag forever after one hand edit, and a warning
    that cannot be cleared is one the reader learns to skip."""
    after = _snap(_D_NEW, _H_OLD)
    assert diff_with_notes(after, after)[0] == []


def test_a_journaled_edit_is_never_also_reported_as_unjournalled():
    alerts, _ = diff_with_notes(_snap(_D_OLD, _H_OLD),
                                _snap(_D_NEW, _D_NEW, written_by=_WRITE))
    assert not any("not recorded by OpenClaw" in m for m in _msgs(alerts))


# ---------------------------------------------------------------- arm 3: the revert

def test_a_change_made_and_put_back_between_checks_is_reported():
    """The whole reason this task exists: the file matches last time's, so no snapshot
    comparison could ever see it, but the journal advanced."""
    alerts, _ = diff_with_notes(_snap(_D_OLD, _H_OLD), _snap(_D_OLD, _H_NEW))
    assert [lvl for lvl, _ in alerts] == ["INFO"]
    assert "changed back" in alerts[0][1]


def test_a_quiet_journal_over_an_unchanged_config_says_nothing():
    assert diff_with_notes(_snap(_D_OLD, _H_OLD), _snap(_D_OLD, _H_OLD))[0] == []


def test_the_revert_arm_is_not_confused_by_a_real_change():
    """Head advanced AND the digest moved is an ordinary journaled edit, not a revert."""
    alerts, _ = diff_with_notes(_snap(_D_OLD, _H_OLD),
                                _snap(_D_NEW, _H_NEW, written_by=_WRITE))
    assert not any("changed back" in m for m in _msgs(alerts))


# ---------------------------------------------------------------- standing down

def test_an_install_with_no_journal_produces_none_of_the_three_arms():
    """Absence of the journal is not evidence of anything. Every arm needs it present."""
    alerts, _ = diff_with_notes(_snap(_D_OLD, None), _snap(_D_NEW, None))
    for phrase in ("not recorded by OpenClaw", "changed back", "pid "):
        assert not any(phrase in m for m in _msgs(alerts)), phrase


def test_a_blind_run_produces_none_of_the_three_arms():
    """No digest means no evidence to compare — the config could not be read at all."""
    alerts, _ = diff_with_notes(_snap(None, _H_OLD), _snap(None, _H_NEW))
    for phrase in ("not recorded by OpenClaw", "changed back"):
        assert not any(phrase in m for m in _msgs(alerts)), phrase


def test_the_migration_from_a_pre_journal_baseline_is_silent_both_ways():
    """The regression that matters on any snapshot-schema change."""
    from clawseccheck.monitor import diff
    new = _snap(_D_OLD, _H_OLD, written_by=_WRITE)
    old = {k: v for k, v in new.items()
           if k not in ("config_journal_head", "config_written_by")}
    assert diff(old, new) == []
    assert diff(new, old) == []


def test_no_path_or_working_directory_can_reach_an_alert():
    """`config_written_by` is built from `configjournal`, which keeps the argv basename
    only. Pinned here too because this is the surface that renders to the user."""
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, gateway_bind="127.0.0.1"),
        _snap(_D_NEW, _H_NEW, gateway_bind="0.0.0.0",
              written_by={"ts": "t", "pid": 1, "argv0": "node"}))
    blob = " ".join(_msgs(alerts))
    assert "/" not in blob.split("[written")[-1]


def test_a_truncated_journal_does_not_manufacture_a_revert():
    """The first version of this test was VACUOUS — it compared two identical snapshots, so
    the arm could not fire whatever the code did, and its docstring asserted an invariant
    that was false. An independent pass disproved it end to end.

    The real shape: `copytruncate` rotation (or any moment the window holds no usable
    record) drives the head from a hash to nothing. A vanished cursor is not an advanced
    one — the evidence was LOST, not moved — so the arm must stand down, not report a
    revert on a config nobody touched."""
    before = _snap(_D_OLD, _H_OLD)
    after = _snap(_D_OLD, None)          # journal truncated: no cursor at all
    assert diff_with_notes(before, after)[0] == []


def test_an_empty_head_is_never_stored_in_the_first_place(tmp_path):
    """Belt and braces at the capture site: `newest_hash` returns "" for an empty window,
    and "" is still a str — which is exactly how a lost cursor became a moved one."""
    from clawseccheck import audit
    from clawseccheck.monitor import snapshot
    (tmp_path / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}',
                                            encoding="utf-8")
    os.chmod(tmp_path / "openclaw.json", 0o600)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "config-audit.jsonl").write_text("", encoding="utf-8")
    snap = snapshot(*audit(tmp_path))
    assert "config_journal_head" not in snap


def test_a_second_openclaw_write_between_runs_is_an_ordinary_change_not_a_revert():
    """Two journaled writes between checks leave the digest changed and the head moved —
    the plain attributed-edit case, not the revert."""
    alerts, _ = diff_with_notes(_snap(_D_OLD, _D_OLD),
                                _snap(_D_NEW, _D_NEW, written_by=_WRITE))
    assert not any("changed back" in m for m in _msgs(alerts))


# ------------------------------------------------ provenance may not outrun the evidence

def test_a_trajectory_derived_alert_is_never_stamped_with_a_config_write():
    """RP6/RP7 read the tool surface OBSERVED IN TRAJECTORY SIDECARS, not the config file.
    They sit inside the config-derived index span, so stamping by range alone claimed that
    a config write put a tool description into a session transcript."""
    detail = {"srv": {"command": "npx", "args0": "@x/srv", "args_pkg": "@x/srv",
                      "transport": "stdio", "url": "", "env_keys": [], "oauth_scope": "r",
                      "tool_sigs": {}, "surface_tool_sigs": {"read_file": "a"}}}
    after = {"srv": dict(detail["srv"],
                         surface_tool_sigs={"read_file": "a", "exfil": "b"})}
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, mcp_detail=detail),
        _snap(_D_NEW, _H_NEW, written_by=_WRITE, mcp_detail=after))
    rp6 = [m for m in _msgs(alerts) if "RP6" in m]
    assert rp6, "precondition: the trajectory-derived alert fired"
    assert not any("pid 149054" in m for m in rp6), rp6


def test_attribution_stands_down_unless_one_write_explains_the_change():
    """A hand edit followed by any OpenClaw write used to hand the resulting CRITICAL alert
    OpenClaw's own provenance — a false exoneration, written into a tamper-evident journal.
    The journaled write must have STARTED from the bytes the previous snapshot recorded."""
    someone_else = dict(_WRITE, previous_hash="f" * 64)   # started from other bytes
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, mcp={}),
        _snap(_D_NEW, _H_NEW, written_by=someone_else, mcp={"evil": "sig"}))
    assert any("evil" in m for m in _msgs(alerts)), "precondition: the drift alert fired"
    assert not any("pid 149054" in m for m in _msgs(alerts)), alerts


def test_a_baseline_predating_the_origin_field_is_not_attributed():
    """An older snapshot carries no `previous_hash`, so nothing can be proven and nothing
    is claimed."""
    legacy = {"ts": "t", "pid": 7, "argv0": "node"}
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, gateway_bind="127.0.0.1"),
        _snap(_D_NEW, _H_NEW, written_by=legacy, gateway_bind="0.0.0.0"))
    assert not any("pid 7" in m for m in _msgs(alerts))


def test_a_write_with_no_timestamp_does_not_render_the_word_none():
    alerts, _ = diff_with_notes(
        _snap(_D_OLD, _H_OLD, gateway_bind="127.0.0.1"),
        _snap(_D_NEW, _H_NEW, gateway_bind="0.0.0.0",
              written_by={"pid": 7, "argv0": "node", "previous_hash": _D_OLD}))
    assert "None" not in alerts[0][1], alerts[0][1]
    assert "pid 7" in alerts[0][1]
