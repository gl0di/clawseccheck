"""B-1053: a channel whose DM ingress is opened through the NESTED ``dm.policy`` (matrix -
the only channel whose schema declares the nested form and no flat ``dmPolicy``, B-619)
must read as open everywhere a flat ``dmPolicy: "open"`` does.

``_open_channels`` (B2's predicate, also consumed by B55's "open ingress proves reach"
branch), B171's open-channel helper, ``_external_input_channels`` and risk.py's
open-channel labels all read the raw flat key. On the shipped fixture
``bad_b619_nested_dm_open`` (loopback + token gateway, matrix ``dm.policy: "open"``) B2
printed "channels are not open" - a clean PASS on a CRITICAL check - while A1 already
counted the open leg through ``_declared_dm_policy``.
"""
from __future__ import annotations

import copy
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import (
    _external_input_channels,
    _open_channels,
    check_gateway,
)
from clawseccheck.checks._config import _b171_open_channels
from clawseccheck.collector import collect
from clawseccheck.risk import _open_channel_labels

REPO = Path(__file__).resolve().parents[1]
BAD = REPO / "fixtures" / "bad_b619_nested_dm_open"
CLEAN = REPO / "fixtures" / "clean_b619_nested_dm_closed"


def _cfg(channels: dict) -> dict:
    return {
        "gateway": {"bind": "loopback", "auth": {"mode": "token", "token": "${OC_TOKEN}"}},
        "channels": channels,
    }


def test_the_shipped_nested_open_fixture_fails_b2():
    f = check_gateway(collect(str(BAD)))
    assert f.status == FAIL, f
    assert "matrix" in f.detail


def test_the_shipped_nested_closed_fixture_still_passes_b2():
    f = check_gateway(collect(str(CLEAN)))
    assert f.status == PASS, f


def test_nested_open_matrix_is_an_open_channel_for_every_helper():
    cfg = _cfg({"matrix": {"dm": {"policy": "open"}}})
    assert _open_channels(cfg) == ["matrix"]
    assert "matrix" in _external_input_channels(cfg)
    assert _b171_open_channels(cfg) == ["matrix"]
    assert any(label.startswith("matrix") for label in _open_channel_labels(cfg))


def test_a_flat_dmpolicy_on_matrix_still_counts_as_before():
    # The fix only ADDS the nested form; a flat key the old predicate counted is never
    # dropped (no finding may be cleared by this change).
    cfg = _cfg({"matrix": {"dmPolicy": "open"}})
    assert _open_channels(cfg) == ["matrix"]


def test_flat_open_on_a_flat_channel_is_unchanged():
    cfg = _cfg({"telegram": {"dmPolicy": "open"}})
    assert _open_channels(cfg) == ["telegram"]
    assert _b171_open_channels(cfg) == ["telegram"]


def test_nested_closures_stay_closed():
    for node in ({"dm": {"policy": "pairing"}}, {"dm": {"policy": "disabled"}},
                 {"dm": {"policy": "allowlist"}}, {}):
        cfg = _cfg({"matrix": copy.deepcopy(node)})
        assert _open_channels(cfg) == [], node
        assert _b171_open_channels(cfg) == [], node


def test_nothing_the_flat_read_reported_is_cleared():
    # dm.enabled:false is a grounded closure for discord (B-619), but clearing a previously
    # reported open channel is out of this fix's scope - the union keeps the old answer.
    assert _open_channels(_cfg({"discord": {"dmPolicy": "open",
                                             "dm": {"enabled": False}}})) == ["discord"]


def test_a_nested_open_policy_on_a_live_account_counts():
    cfg = _cfg({"matrix": {"accounts": {"main": {"dm": {"policy": "open"}}}}})
    assert _open_channels(cfg) == ["matrix"]


def test_matrix_dm_enabled_false_keeps_a_stale_nested_open_closed():
    # C-135 FP on the first version of this fix: matrix ignores all DMs when dm.enabled is
    # false (vendor docs), so a leftover dm.policy "open" beside it must not open B2.
    cfg = _cfg({"matrix": {"dm": {"enabled": False, "policy": "open"},
                           "groupPolicy": "allowlist",
                           "groupAllowFrom": ["@admin:example.org"]}})
    assert _open_channels(cfg) == []
    assert _b171_open_channels(cfg) == []
    assert not any(label.startswith("matrix") for label in _open_channel_labels(cfg))


def test_b171_honours_matrix_nested_dm_allowfrom_scoping():
    scoped = _cfg({"matrix": {"dm": {"policy": "open", "allowFrom": ["@owner:example.org"]}}})
    assert _b171_open_channels(scoped) == []
    wildcard = _cfg({"matrix": {"dm": {"policy": "open", "allowFrom": ["*"]}}})
    assert _b171_open_channels(wildcard) == ["matrix"]
