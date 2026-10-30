"""B-1006: a sibling account inherits the default account's entry.

Grounded on OpenClaw v2026.10.9 (see ``_DEFAULT_ENTRY_SHARED_TO_SIBLINGS``):

* whatsapp (``whatsapp/src/account-config.ts:9-42``): ``{...root, ...accounts.default
  (minus enabled/name/authDir/selfChatMode), ...account}`` - the default entry beats the root.
  Executed against the installed dist's ``mergeAccountConfig``: root ``dmPolicy: open`` +
  ``accounts.default.dmPolicy: pairing`` + ``accounts.work: {}`` resolves BOTH accounts to
  ``pairing``, so the open root policy runs for no account.
* googlechat (``googlechat/src/accounts.ts:62-90``): ``{...defaultShared, ...root, ...account}``
  - the root still wins, so the open root policy stays live in every sibling.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_gateway
from clawseccheck.checks._shared import _live_channel_nodes, _resolved_account_nodes
from clawseccheck.collector import Context

OPEN = {"dmPolicy": "open", "allowFrom": ["*"]}


def _b2(channel: str, node: dict) -> str:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {"channels": {channel: node}}
    return check_gateway(ctx).status


def _wa(**kw) -> dict:
    return {"authDir": "/x", **OPEN, **kw}


def test_whatsapp_default_entry_closes_the_open_root_for_every_account():
    node = _wa(accounts={"default": {"dmPolicy": "pairing"}, "work": {}})
    assert _b2("whatsapp", node) == PASS
    assert [n["dmPolicy"] for n in _live_channel_nodes("whatsapp", node)] == ["pairing"] * 2


def test_whatsapp_sibling_that_reopens_itself_still_fails():
    node = _wa(accounts={"default": {"dmPolicy": "pairing"}, "work": {"dmPolicy": "open"}})
    assert _b2("whatsapp", node) == FAIL


def test_whatsapp_open_default_entry_fails_and_spreads_to_siblings():
    node = {"authDir": "/x", "accounts": {"default": dict(OPEN), "work": {}}}
    assert _b2("whatsapp", node) == FAIL
    assert all(n["dmPolicy"] == "open" for n in _resolved_account_nodes("whatsapp", node))


def test_whatsapp_unshared_keys_do_not_leak_to_siblings():
    node = _wa(accounts={"default": {"enabled": False, "name": "d", "authDir": "/d"}, "work": {}})
    work = _resolved_account_nodes("whatsapp", node)[1]
    assert work["authDir"] == "/x" and "name" not in work and "enabled" not in work


def test_whatsapp_no_default_entry_is_the_pre_existing_walk():
    node = _wa(accounts={"work": {"dmPolicy": "pairing"}})
    assert _resolved_account_nodes("whatsapp", node) == [{**_wa(), "dmPolicy": "pairing"}]
    assert _b2("whatsapp", node) == FAIL  # live implicit base account stays open


def test_whatsapp_unclear_default_pick_never_hides_an_open_policy():
    # Two candidate default entries, neither the exact key: the pick is unclear, so the
    # resolver must keep every reading - one of them (the empty candidate) leaves the open
    # root policy standing, and hiding it would be a fail-open false PASS.
    node = _wa(accounts={" default": {"dmPolicy": "pairing"}, "DEFAULT": {}, "work": {}})
    nodes = _resolved_account_nodes("whatsapp", node)
    assert any(n.get("dmPolicy") == "open" for n in nodes)
    assert any(n.get("dmPolicy") == "pairing" for n in nodes)
    assert _b2("whatsapp", node) == FAIL


def test_googlechat_root_still_wins_over_the_default_entry():
    node = {"serviceAccountFile": "/s.json", **OPEN,
            "accounts": {"default": {"dmPolicy": "pairing"}, "work": {}}}
    work = _resolved_account_nodes("googlechat", node)[1]
    assert work["dmPolicy"] == "open"


def test_googlechat_default_entry_fills_keys_the_root_leaves_unset():
    node = {"accounts": {"default": {"groupPolicy": "open", "serviceAccount": "x"}, "work": {}}}
    work = _resolved_account_nodes("googlechat", node)[1]
    assert work["groupPolicy"] == "open" and "serviceAccount" not in work


def test_other_channels_do_not_inherit_the_default_entry():
    node = {"botToken": "p", **OPEN, "accounts": {"default": {"dmPolicy": "pairing"}, "work": {}}}
    nodes = _resolved_account_nodes("telegram", node)
    assert nodes[1]["dmPolicy"] == "open"
