"""B-390 / B-391: the rest of the `_resolved_channel_nodes` family.

B-389 fixed `_open_channels` (B2/B55) to read the RESOLVED per-account channel node
instead of the raw ``[c] + accounts.values()`` union. Three siblings were left behind and
are closed here:

* **B-390** — `_b171_open_channels` (`checks/_config.py`, feeds B171) still walked the raw
  union, so a vestigial base-level ``dmPolicy: "open"`` (template scaffolding) counted as
  open even when every real account overrode it to something restrictive.
* **B-391 gap 1** — neither `_open_channels` nor `_open_wildcard_group_channels` honored a
  RESOLVED node's own ``enabled: false``. A retired account left in place with its old
  wide-open policy still on record was scored as live ingress. This is the same class
  B-041 already fixed at the CHANNEL level, never extended to the per-account level.
* **B-391 gap 2** — `_resolved_channel_nodes` silently dropped non-dict entries from a
  MIXED ``accounts`` dict: the well-formed entries made ``merged`` non-empty so the
  ``[c]`` schema-drift fallback never fired, and the malformed entry (plus the base node)
  vanished from the walk with no trace.

The gap-1 skip carries its own hazard, and a C-135 pass on this very change found it live:
silencing a disabled node must NOT also silence the BASE node's policy. A channel-level
credential (telegram ``botToken``) keeps running once ``accounts`` is added — OpenClaw
synthesizes an implicit default account carrying the base policy — so a single
``accounts: {retired: {enabled: false}}`` entry made the whole channel's open wildcard
group invisible. `_open_wildcard_group_channels` feeds the behavioral arming and the RISK
chains, so that was a multi-detector false NEGATIVE, the dangerous direction for any change
that makes a check fire less often. `_channel_has_implicit_default_account` restores the
base node exactly when the credential is genuinely present — the same guard `_open_channels`
and `_b171_open_channels` already apply. The "implicit default account" group below pins it.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import (
    _channel_has_implicit_default_account,
    _open_channels,
    _open_wildcard_group_channels,
    _resolved_channel_nodes,
)
# `_b171_open_channels` is private to the _config topic module and deliberately not part
# of the `clawseccheck.checks` aggregator surface (see tests/checks_public_api.txt), so it
# is imported from its owning module rather than widening that surface for a test.
from clawseccheck.checks._config import _b171_open_channels
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# --------------------------------------------------------------- B-390: _b171_open_channels

def test_b171_vestigial_open_base_is_not_flagged_when_accounts_override_it():
    """The B-390 repro: base dmPolicy=='open' is leftover scaffolding with no credential
    behind it; the one real account overrides it to pairing."""
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "open",
                                     "accounts": {"main": {"dmPolicy": "pairing"}}}}}
    assert _b171_open_channels(cfg) == []


def test_b171_account_that_is_actually_open_still_flagged():
    """The narrowing must not swallow a genuinely open account."""
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "pairing",
                                     "accounts": {"main": {"dmPolicy": "open"}}}}}
    assert _b171_open_channels(cfg) == ["telegram"]


def test_b171_open_base_with_no_accounts_is_unchanged():
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "open"}}}
    assert _b171_open_channels(cfg) == ["telegram"]


def test_b171_disabled_account_does_not_make_a_channel_open():
    """B-391 gap 1 through B171: a retired account keeps its old wide-open policy on
    record but ingests nothing."""
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "pairing",
                                     "accounts": {"retired": {"enabled": False,
                                                              "dmPolicy": "open"}}}}}
    assert _b171_open_channels(cfg) == []


def test_b171_live_base_credential_survives_a_disabled_account():
    """The false-NEGATIVE guard: the implicit default account still ingests, so an open
    base policy must remain visible even though the one explicit account is disabled."""
    cfg = {"channels": {"telegram": {"enabled": True, "botToken": "t", "dmPolicy": "open",
                                     "accounts": {"retired": {"enabled": False}}}}}
    assert _channel_has_implicit_default_account("telegram", cfg["channels"]["telegram"])
    assert _b171_open_channels(cfg) == ["telegram"]


def test_b171_allow_from_scoping_still_applies_after_the_resolve():
    """`_b171_open_channels` layers allowFrom scoping on top of the node walk; swapping in
    the resolved node must not defeat it."""
    scoped = {"channels": {"telegram": {"enabled": True,
                                        "accounts": {"main": {"dmPolicy": "open",
                                                              "allowFrom": ["user:42"]}}}}}
    assert _b171_open_channels(scoped) == []
    wildcard = {"channels": {"telegram": {"enabled": True,
                                          "accounts": {"main": {"dmPolicy": "open",
                                                                "allowFrom": ["*"]}}}}}
    assert _b171_open_channels(wildcard) == ["telegram"]


def test_b171_disabled_channel_is_skipped():
    cfg = {"channels": {"telegram": {"enabled": False, "dmPolicy": "open"}}}
    assert _b171_open_channels(cfg) == []


# ------------------------------------------------- B-391 gap 1: per-account enabled: false

def test_open_channels_skips_a_disabled_account():
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "pairing",
                                     "accounts": {"retired": {"enabled": False,
                                                              "dmPolicy": "open"}}}}}
    assert _open_channels(cfg) == []


def test_open_channels_still_flags_an_enabled_open_account():
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "pairing",
                                     "accounts": {"live": {"enabled": True,
                                                           "dmPolicy": "open"}}}}}
    assert _open_channels(cfg) == ["telegram"]


# --------------------------------------- B-391 gap 1 + the C-135 FN guard, wildcard variant

def test_wildcard_group_live_base_survives_a_disabled_account():
    """The regression this change nearly shipped: `_open_wildcard_group_channels` gained
    the disabled-node skip WITHOUT the implicit-default-account add-back, so one retired
    account silenced a genuinely open wildcard group. This helper feeds the behavioral
    arming and the RISK chains, so the miss propagated well beyond B140."""
    cfg = {"channels": {"telegram": {"enabled": True, "botToken": "t",
                                     "groups": {"*": {}},
                                     "accounts": {"retired": {"enabled": False}}}}}
    assert _open_wildcard_group_channels(cfg) == {"telegram": "no allowFrom configured"}


def test_wildcard_group_open_only_on_a_disabled_account_is_silent():
    """The other direction: when the open wildcard group lives ONLY on the disabled
    account and the base declares none of its own, nothing ingests."""
    cfg = {"channels": {"telegram": {"enabled": True, "botToken": "t",
                                     "accounts": {"retired": {"enabled": False,
                                                              "groups": {"*": {}}}}}}}
    assert _open_wildcard_group_channels(cfg) == {}


def test_wildcard_group_enabled_account_still_flagged():
    cfg = {"channels": {"telegram": {"enabled": True, "botToken": "t",
                                     "accounts": {"live": {"enabled": True,
                                                           "groups": {"*": {}}}}}}}
    assert _open_wildcard_group_channels(cfg) == {"telegram": "no allowFrom configured"}


def test_wildcard_group_no_accounts_is_unchanged():
    cfg = {"channels": {"telegram": {"enabled": True, "botToken": "t",
                                     "groups": {"*": {}}}}}
    assert _open_wildcard_group_channels(cfg) == {"telegram": "no allowFrom configured"}


# ------------------------------------------------ B-391 gap 2: mixed / drifted accounts dict

def test_mixed_accounts_dict_falls_back_to_the_base_node():
    """A non-dict entry means we cannot read that account's policy at all. We cannot tell
    whether it is a live account with a wide-open policy, so the whole block degrades to
    the base node rather than silently proceeding on the well-formed subset."""
    c = {"dmPolicy": "open", "accounts": {"a": {"dmPolicy": "pairing"}, "b": "not-a-dict"}}
    assert _resolved_channel_nodes(c) == [c]


def test_all_dict_accounts_still_merge_normally():
    c = {"dmPolicy": "open", "accounts": {"a": {"dmPolicy": "pairing"}}}
    assert _resolved_channel_nodes(c) == [{"dmPolicy": "pairing"}]


def test_schema_drifted_accounts_shapes_degrade_to_the_base_node():
    for accounts in ([], "nope", {}, 7, None):
        c = {"dmPolicy": "open", "accounts": accounts}
        assert _resolved_channel_nodes(c) == [c], accounts


# ----------------------------------------------------------------- malformed shapes: no raise

def test_malformed_channel_shapes_do_not_raise():
    for cfg in (
        {"channels": {"t": {"enabled": True, "accounts": []}}},
        {"channels": {"t": {"enabled": True, "accounts": "nope"}}},
        {"channels": {"t": {"enabled": True, "accounts": {"a": "str"}}}},
        {"channels": {"t": None}},
        {"channels": {}},
        {},
    ):
        _b171_open_channels(cfg)
        _open_channels(cfg)
        _open_wildcard_group_channels(cfg)
