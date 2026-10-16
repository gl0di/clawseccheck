"""C-689 -- B382 also answers from OpenClaw's own retired-format finder.

Before this change B382 answered from a hand table of 20 measured keys and said PASS about a
file the installed build's Doctor and ``openclaw update`` refuse (``agentRuntime``,
``messages.queue.mode: "queue"``, ``plugins.installs``, every channel-level retired key...).
The finder is now ported (``clawseccheck/retiredformats.py``) and unioned in on builds inside
its validated window. These tests pin the verdicts; the port itself is graded against the
vendor by ``test_retiredformats_battery.py``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from _retiredformatsoracle import FINDER_PATHS

from clawseccheck import retiredformats as rf
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks._config import check_retired_config_keys_invalid
from clawseccheck.collector import Context

IN = "2026.10.2"
BATTERY = json.loads((Path(__file__).parent / "data" / "retiredformats_battery.json")
                     .read_text(encoding="utf-8"))


def _run(cfg, installed=IN):
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    c.installed_dist_version = installed
    return check_retired_config_keys_invalid(c)


@pytest.mark.parametrize("installed", ["2026.10.1", "2026.10.2", "2026.10.2-1", "2026.10.3", "2026.10.4"])
def test_every_ledger_path_warns_inside_the_window(installed):
    """For every path the finder names, alone in its config, B382 is WARN and names it."""
    bad = []
    for label, cfg, path in FINDER_PATHS:
        f = _run(cfg, installed)
        # the legacy roster shape is itself a table row (`agents.list`), reported beside it
        want = ["agents.list", path] if path.startswith("agents.list[") else [path]
        if f.status != WARN or f.evidence != want:
            bad.append((label, f.status, f.evidence))
    assert not bad, bad[:5]


def test_the_failures_the_task_reproduced_are_no_longer_pass():
    for cfg in ({"agents": {"entries": {"main": {"agentRuntime": {"id": "codex"}}}}},
                {"messages": {"queue": {"mode": "queue"}}}):
        assert _run(cfg).status == WARN


def test_a_finder_row_says_what_it_is_and_who_refuses():
    f = _run({"agents": {"defaults": {"agentRuntime": {"id": "codex"}}}})
    assert f.status == WARN
    assert "agents.defaults.agentRuntime (retired on the installed build)" in f.detail
    assert "bridge release 2026.9.5" in f.detail
    assert "contains 1 key that OpenClaw" in f.detail and "1 is named by" in f.detail
    assert "Doctor and `openclaw update` refuse this config until it is removed" in f.detail
    assert "install OpenClaw 2026.9.5" in f.fix and "upgrade to latest" in f.fix
    assert "removed)" not in f.detail  # a finder row is not claimed to be a measured removal


def test_a_channel_level_key_the_root_schema_accepts_is_warn_like_the_root_rows():
    f = _run({"channels": {"telegram": {"streamMode": "partial"}}})
    assert f.status == WARN
    assert f.evidence == ["channels.telegram.streamMode"]
    assert "Doctor and `openclaw update` refuse" in f.detail


def test_the_bridge_release_is_the_vendors_own_per_config_value():
    discord = {"channels": {"discord": {"voice": {"tts": {"edge": {}}}}}}
    f = _run(discord)
    assert "bridge release 2026.9.7" in f.detail and "install OpenClaw 2026.9.7" in f.fix
    f = _run({"channels": {"discord": {"threadBindings": {"ttlHours": 1}}}})
    assert "bridge release 2026.9.5" in f.detail


def test_a_table_only_finding_keeps_its_exact_detail():
    """The detail hashes into users' ignore fingerprints: a config only the table names must
    produce the wording it always did, on a build outside the finder window as well as
    inside it."""
    expected = (
        "The file audited still contains 1 key(s) that OpenClaw {v} removed, so its strict "
        "config schema rejects the file: `openclaw config validate` and CLI commands that "
        "load it report it invalid until the keys are migrated. "
        "audit.enabled (replaced by logging.audit.enabled)")
    for v in (IN, "2026.9.9", "2026.10.4"):
        f = _run({"audit": {"enabled": True}}, v)
        assert f.status == WARN and f.detail == expected.format(v=v), (v, f.detail)


def test_a_table_row_the_finder_also_names_is_reported_once_with_its_old_detail():
    cfg = {"agents": {"defaults": {"silentReplyRewrite": True}}}
    f = _run(cfg)
    assert f.evidence == ["agents.defaults.silentReplyRewrite"]
    assert f.detail.endswith("agents.defaults.silentReplyRewrite (removed)")
    assert "retired on the installed build" not in f.detail
    # ...but Doctor refuses on the finder's say-so, so the old `doctor --fix` advice is gone
    assert "cannot migrate it" in f.fix


def test_table_and_finder_rows_are_unioned():
    f = _run({"audit": {"enabled": True}, "heartbeat": {"every": "5m"}})
    assert f.status == WARN
    assert f.evidence == ["audit.enabled", "heartbeat"]
    assert "contains 2 keys that" in f.detail and "1 of them left the strict config schema" in f.detail
    assert "audit.enabled (replaced by logging.audit.enabled)" in f.detail
    assert "heartbeat (retired on the installed build)" in f.detail
    assert "cannot migrate it" in f.fix


def test_many_hits_are_all_in_evidence_and_the_detail_is_capped():
    cfg = {"talk": {k: 1 for k in ("mode", "transport", "brain", "model", "voice")},
           "session": {"parentForkMaxTokens": 1}, "heartbeat": 1}
    f = _run(cfg)
    assert len(f.evidence) == 7 and "(+1 more)" in f.detail


@pytest.mark.parametrize("cfg", [
    {},
    {"channels": {"feishu": {"botName": "x"}}},                      # root feishu is exempt
    {"messages": {"queue": {"mode": "collect", "byChannel": {"slack": "followup"}}}},
    {"channels": {"matrix": {"dm": {"policy": "allowlist"}}}},
    {"channels": {"telegram": {"streaming": {"mode": "partial"}}}},
    {"talk": {"realtime": {"model": "m"}}},
    {"agents": {"entries": {"__proto__": {"agentRuntime": 1}}}},
    {"agentRuntime": {"id": "codex"}},                                # wrong scope: the root
])
def test_benign_near_misses_stay_pass_and_say_what_was_checked(cfg):
    f = _run(cfg)
    assert f.status == PASS
    assert "retired-format finder names nothing in it" in f.detail
    assert "none of the 20 retired config keys this check tracks" in f.detail


_FINDER_ONLY = {"agents": {"entries": {"main": {"agentRuntime": {"id": "codex"}}}}}


@pytest.mark.parametrize("build", ["2026.10.5", "2026.10.0", "2026.9.9", "2027.1.1"])
def test_outside_the_window_the_pass_carries_the_caveat_in_detail(build):
    """The vendor's list was not consulted: the PASS must not read like the in-window one,
    and the caveat is in `detail` because the list renderer never shows `fix`."""
    f = _run(_FINDER_ONLY, build)
    assert f.status == PASS and f.pass_confidence == "no_signal"
    assert f.detail == (
        "The file audited holds none of the 20 retired config keys this check tracks. "
        "OpenClaw's own retired-format list was NOT checked: it is ported only for "
        f"2026.10.1-2026.10.4 and this build is {build}.")
    assert "retired-format finder names nothing" not in f.detail
    assert "not applied" not in f.fix


@pytest.mark.parametrize("build", ["2026.10.1", "2026.10.2", "2026.10.3", "2026.10.4"])
def test_inside_the_window_the_same_config_warns(build):
    assert _run(_FINDER_ONLY, build).status == WARN


def test_the_fix_offers_the_bridge_route_only_for_the_keys_the_vendor_names():
    f = _run({"audit": {"enabled": True}, "heartbeat": 1})
    assert f.fix.startswith("Delete the retired keys listed above by hand. For the keys the "
                            "vendor's list names, the vendor's own route is to install "
                            "OpenClaw 2026.9.5")
    assert "the retired keys listed above" not in f.fix.split("For the keys")[1]


def test_an_unknown_or_prerelease_build_is_still_the_no_signal_pass():
    for v in (None, "", "2026.10.2-beta.1"):
        f = _run({"heartbeat": 1}, v)
        assert f.status == PASS and f.pass_confidence == "no_signal"
        assert f.detail.startswith("Installed OpenClaw version not determined")


def test_the_pinned_battery_never_makes_b382_pass_or_fail_wrongly():
    """Every battery config the vendor flags is WARN, every one it does not is PASS or a
    table-only WARN, and no row is ever FAIL."""
    flagged = quiet = 0
    for row in BATTERY["rows"]:
        f = _run(row["cfg"])
        assert f.status != FAIL, row["label"]
        if row["vendor"] is not None:
            flagged += 1
            assert f.status == WARN, row["label"]
            assert set(rf.find_retired(row["cfg"]).paths) <= set(f.evidence), row["label"]
        else:
            quiet += 1
            if f.status == WARN:  # only a hand-table key can be the reason
                assert "retired on the installed build" not in f.detail, row["label"]
    assert flagged > 500 and quiet > 100
