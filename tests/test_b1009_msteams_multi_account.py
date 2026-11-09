"""msteams became multi-account in @openclaw/msteams 2026.10.10.

Up to 2026.10.9 the Teams plugin ran one account built from the channel node, and its
strict config schema rejected ``accounts`` / ``defaultAccount`` outright. From 2026.10.10 it
lists configured accounts plus an implicit ``default`` account that exists only when the
base node carries a Teams identity (``hasConfiguredMSTeamsCredentials``), and it resolves
each account as the base merged under that account's entry. Before this change the base
node was always treated as a live account of its own, so a base the configured accounts
fully replace still FAILed B2.

The expectations below are written from the plugin's own code, not imported from the code
under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.checks import (
    _BASE_IS_THE_DEFAULT_ACCOUNT,
    _MSTEAMS_IDENTITY_KEYS,
    _SINGLE_ACCOUNT_CHANNELS,
    _channel_has_implicit_default_account,
    _live_channel_nodes,
    check_gateway,
)
from clawseccheck.collector import Context

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"
FAIL, PASS = "FAIL", "PASS"

APP = "11111111-1111-1111-1111-111111111111"
TENANT = "00000000-0000-0000-0000-000000000000"
REF = {"source": "env", "provider": "default", "id": "MSTEAMS_WORK_APP_PASSWORD"}
OPEN = {"dmPolicy": "open", "allowFrom": ["*"]}
CLOSED = {"dmPolicy": "pairing", "allowFrom": []}
WORK = {"work": {"appId": APP, "tenantId": TENANT, "appPassword": REF, **CLOSED}}


def _b2(msteams: dict) -> str:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {"channels": {"msteams": msteams}}
    return check_gateway(ctx).status


def _fixture(name: str) -> str:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = json.loads((FIX / name / "openclaw.json").read_text())
    return check_gateway(ctx).status


# ------------------------------------------------------------------ fixtures

def test_an_open_named_account_fails():
    assert _fixture("bad_b2_msteams_account_open") == FAIL


def test_a_default_entry_that_closes_the_open_base_passes():
    assert _fixture("clean_b2_msteams_default_entry_closes_base") == PASS


def test_named_accounts_under_a_base_with_no_identity_pass():
    assert _fixture("clean_b2_msteams_named_accounts_only") == PASS


# ------------------------------------------------------------------ base-only: every build

def test_a_base_only_node_reads_the_same_as_before():
    """No ``accounts``: the only shape a 2026.10.9 plugin accepts. The base is the account."""
    assert _live_channel_nodes("msteams", {**OPEN}) == [OPEN]
    assert _b2({**OPEN}) == FAIL
    assert _b2({**CLOSED}) == PASS
    assert _b2({**OPEN, "accounts": {}}) == FAIL


# ------------------------------------------------------------------ the implicit default

def test_msteams_is_no_longer_single_account():
    assert "msteams" not in _SINGLE_ACCOUNT_CHANNELS
    assert "msteams" not in _BASE_IS_THE_DEFAULT_ACCOUNT


@pytest.mark.parametrize("key", _MSTEAMS_IDENTITY_KEYS)
def test_any_identity_key_on_the_base_keeps_it_live(key):
    """Every identity value can come from an MSTEAMS_* env var, so a base that sets only
    part of one (the app id in the file, the password in the environment) may run: kept."""
    value = True if key == "useManagedIdentity" else "v"
    assert _channel_has_implicit_default_account("msteams", {key: value}) is True
    assert _b2({key: value, **OPEN, "accounts": WORK}) == FAIL


def test_a_base_without_identity_is_not_an_account():
    for base in ({}, {"appId": "   "}, {"tenantId": ""}, {"appId": None}, OPEN):
        assert _channel_has_implicit_default_account("msteams", base, {}) is False, base


def test_without_the_whole_config_the_base_is_kept():
    """The env block is unknown, so the identity may come from it: fail closed."""
    assert _channel_has_implicit_default_account("msteams", {}) is True


def test_an_env_block_identity_keeps_the_base_live():
    """applyConfigEnvVars feeds env.vars into the process before channels start, and the
    default account falls back to MSTEAMS_* variables."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {"env": {"vars": {"MSTEAMS_APP_ID": APP}},
                  "channels": {"msteams": {**OPEN, "accounts": WORK}}}
    assert check_gateway(ctx).status == FAIL


def test_a_full_base_identity_beside_named_accounts_still_fails_when_open():
    base = {"appId": APP, "tenantId": TENANT, "appPassword": REF, **OPEN}
    assert _b2({**base, "accounts": WORK}) == FAIL


# ------------------------------------------------------------------ the default entry

@pytest.mark.parametrize("key", ["default", "Default", " default ", "DEFAULT", "default!"])
def test_an_entry_that_normalizes_to_default_replaces_the_base(key):
    """resolveMSTeamsAccountEntryKey matches with normalizeAccountId."""
    base = {"tenantId": TENANT, **OPEN}
    entry = {"appId": APP, "appPassword": REF, **CLOSED}
    assert _b2({**base, "accounts": {key: entry}}) == PASS


def test_an_entry_that_does_not_normalize_to_default_leaves_the_base_live():
    base = {"tenantId": TENANT, **OPEN}
    entry = {"appId": APP, "appPassword": REF, **CLOSED}
    assert _b2({**base, "accounts": {"defaults": entry}}) == FAIL


def test_a_named_account_inherits_an_open_base_policy():
    """resolveMergedAccountConfig: base first, the account wins key by key."""
    accounts = {"work": {"appId": APP, "tenantId": TENANT, "appPassword": REF}}
    assert _b2({**OPEN, "accounts": accounts}) == FAIL


# ------------------------------------------------------------------ undecidable shapes

def test_a_malformed_accounts_block_keeps_the_base():
    assert _b2({**OPEN, "accounts": {"work": "not-an-object"}}) == FAIL
