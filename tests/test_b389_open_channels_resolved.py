"""B-389: `_open_channels` must read the RESOLVED per-account channel node, not the raw
``[c] + accounts.values()`` idiom it used before this fix — see
`clawseccheck/checks/_shared.py`'s `_open_channels` and `_resolved_channel_nodes`
docstrings for the full grounding.

Found by the 2026-07-31 C-135 adversarial review of B-376/B-369 (B55's WARN->FAIL
escalation): a vestigial base-level `dmPolicy`/`groupPolicy == "open"` — leftover
template scaffolding — was still counted as "open" even when every real running account
overrode it to something restrictive (`pairing`/`allowlist`), because the raw walk
evaluated the unmerged base node IN ADDITION TO each account's own raw node. Once
`accounts` is configured, that base node is never itself what actually runs — OpenClaw
merges it as defaults UNDER each account's overrides (`mergeAccountConfig`).
`_open_wildcard_group_channels` already used `_resolved_channel_nodes` for the identical
class of shape; `_open_channels` (shared by B2 and B55) did not, until this fix.

Both consumers are FAIL-capable through this helper: B2's own `open_ch` evidence line
alone drives `sev = FAIL` in `check_gateway` (`checks/_config.py`), and B55's B-376
escalation made its `open_ch`-driven FAIL branch `scored=True`
(`check_fs_write_exposure`, `checks/_capability.py`). So this was a genuine, scored
false-positive FAIL on both checks for a real, correctly-scoped config shape.

A same-day C-135 adversarial review of the fix itself (independent architect pass) found
that blindly dropping the base node whenever `accounts` exists introduces a WORSE false
NEGATIVE: a channel-level credential (e.g. telegram `botToken`) does not stop running
once `accounts` is added — OpenClaw synthesizes an extra IMPLICIT default account that
keeps the base node's own (possibly still-open) policy live, alongside the explicitly
configured accounts. `_channel_has_implicit_default_account` (`checks/_shared.py`,
grounded per-channel against the installed dist) restores the base node to the walk only
when that credential is genuinely present, which the same review proved analytically
(and by 200k-trial fuzz) cannot reintroduce the original false-positive — a merged
account node can only ever be a strict subset of what the raw union tested. See the
"implicit default account" test group below for the exact reviewer-found repro.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import (
    _channel_has_implicit_default_account,
    _open_channels,
    check_fs_write_exposure,
    check_gateway,
)
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# --------------------------------------------------------------------------- helper level

def test_accounts_override_narrows_vestigial_open_telegram_base():
    """Exact repro from the task: base dmPolicy/groupPolicy=='open' is template
    scaffolding (no credential at the base — see the implicit-default-account group
    below for the case where the base DOES carry a live credential); the one real
    account overrides both to pairing/allowlist."""
    cfg = {
        "channels": {
            "telegram": {
                "dmPolicy": "open", "groupPolicy": "open",
                "accounts": {
                    "main": {"botToken": "x", "dmPolicy": "pairing", "groupPolicy": "allowlist"}
                },
            }
        }
    }
    assert _open_channels(cfg) == []


def test_accounts_override_narrows_vestigial_open_discord_base():
    """Same shape, second channel — confirms this isn't Telegram-specific."""
    cfg = {
        "channels": {
            "discord": {
                "dmPolicy": "open", "groupPolicy": "open",
                "accounts": {
                    "main": {"token": "x", "dmPolicy": "pairing", "groupPolicy": "allowlist"}
                },
            }
        }
    }
    assert _open_channels(cfg) == []


def test_account_that_does_not_override_still_inherits_open_base():
    """NOT a blind narrowing: an account that leaves dmPolicy unset genuinely inherits
    the open base (mergeAccountConfig is a shallow spread) and must still count as open."""
    cfg = {
        "channels": {
            "telegram": {"dmPolicy": "open", "accounts": {"main": {"botToken": "x"}}}
        }
    }
    assert _open_channels(cfg) == ["telegram"]


def test_one_of_several_accounts_still_open_is_still_flagged():
    """A mixed fleet: one account scoped, one left open — still open overall."""
    cfg = {
        "channels": {
            "telegram": {
                "dmPolicy": "open",
                "accounts": {
                    "scoped": {"token": "a", "dmPolicy": "pairing"},
                    "unscoped": {"token": "b"},
                },
            }
        }
    }
    assert _open_channels(cfg) == ["telegram"]


def test_no_accounts_key_unaffected():
    """The common case (no `accounts` at all) must not regress."""
    cfg = {"channels": {"telegram": {"dmPolicy": "open"}}}
    assert _open_channels(cfg) == ["telegram"]


def test_schema_drifted_accounts_still_degrades_gracefully():
    """B-378: a schema-drifted `accounts` (list instead of dict) degrades to 'no
    accounts', never raises — must still hold now that this routes through
    `_resolved_channel_nodes`."""
    cfg = {"channels": {"telegram": {"dmPolicy": "open", "accounts": ["not-a-dict"]}}}
    assert _open_channels(cfg) == ["telegram"]


# --------------------------------------------------------------------------- implicit default account
# C-135 review of the fix above (2026-07-31): a channel-level credential still spawns a
# live implicit default account once `accounts` is added — it joins, not replaces.

def test_implicit_default_via_telegram_bot_token_still_flagged():
    """Reviewer's exact repro: the base node keeps a real botToken (a still-running
    bot), so it is NOT vestigial scaffolding even though `accounts` also exists."""
    cfg = {
        "channels": {
            "telegram": {
                "botToken": "the-original-bots-token",
                "dmPolicy": "open", "groupPolicy": "open",
                "accounts": {
                    "second": {
                        "botToken": "second-bots-token",
                        "dmPolicy": "pairing", "groupPolicy": "allowlist",
                    }
                },
            }
        }
    }
    assert _open_channels(cfg) == ["telegram"]


def test_implicit_default_via_telegram_token_file_still_flagged():
    cfg = {
        "channels": {
            "telegram": {
                "tokenFile": "/run/secrets/telegram-token",
                "dmPolicy": "open",
                "accounts": {"second": {"botToken": "x", "dmPolicy": "pairing"}},
            }
        }
    }
    assert _open_channels(cfg) == ["telegram"]


def test_implicit_default_via_discord_token_still_flagged():
    cfg = {
        "channels": {
            "discord": {
                "token": "the-original-bots-token",
                "dmPolicy": "open",
                "accounts": {"second": {"token": "y", "dmPolicy": "pairing"}},
            }
        }
    }
    assert _open_channels(cfg) == ["discord"]


def test_no_implicit_default_without_credential_key_stays_narrowed():
    """Control: the base node has no credential-bearing key at all (the original B-389
    repro) — must stay narrowed, i.e. the implicit-default carve-out must not silently
    regress the main fix."""
    cfg = {
        "channels": {
            "telegram": {
                "dmPolicy": "open", "groupPolicy": "open",
                "accounts": {
                    "main": {"botToken": "x", "dmPolicy": "pairing", "groupPolicy": "allowlist"}
                },
            }
        }
    }
    assert _open_channels(cfg) == []


def test_blank_credential_string_does_not_trigger_implicit_default():
    """Mirrors the dist's own hasConfiguredAccountValue: an empty/whitespace-only
    string does not count as a configured credential."""
    cfg = {
        "channels": {
            "telegram": {
                "botToken": "   ",
                "dmPolicy": "open",
                "accounts": {"second": {"botToken": "x", "dmPolicy": "pairing"}},
            }
        }
    }
    assert _open_channels(cfg) == []


def test_feishu_implicit_default_requires_both_appid_and_appsecret():
    """Feishu uses a bespoke AND'd predicate, not a single-key check."""
    both = {
        "channels": {
            "feishu": {
                "appId": "a", "appSecret": "s", "dmPolicy": "open",
                "accounts": {"second": {"appId": "a2", "appSecret": "s2", "dmPolicy": "pairing"}},
            }
        }
    }
    assert _open_channels(both) == ["feishu"]

    only_one = {
        "channels": {
            "feishu": {
                "appId": "a", "dmPolicy": "open",
                "accounts": {"second": {"appId": "a2", "appSecret": "s2", "dmPolicy": "pairing"}},
            }
        }
    }
    assert _open_channels(only_one) == []


def test_channel_has_implicit_default_account_helper_directly():
    assert _channel_has_implicit_default_account("telegram", {"botToken": "x"}) is True
    assert _channel_has_implicit_default_account("telegram", {}) is False
    assert _channel_has_implicit_default_account("telegram", {"botToken": ""}) is False
    assert _channel_has_implicit_default_account("slack", {"botToken": "x"}) is False
    assert not _channel_has_implicit_default_account("telegram", None)


def test_b55_implicit_default_via_telegram_bot_token_still_fails():
    """Same repro through the real B55 check — this is the config shape the review
    flagged as a genuine worse-false-negative if left unfixed."""
    cfg = {
        "channels": {
            "telegram": {
                "botToken": "the-original-bots-token",
                "dmPolicy": "open", "groupPolicy": "open",
                "accounts": {
                    "second": {
                        "botToken": "second-bots-token",
                        "dmPolicy": "pairing", "groupPolicy": "allowlist",
                    }
                },
            }
        },
        "tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}},
    }
    f = check_fs_write_exposure(_ctx(cfg))
    assert f.status == FAIL, f.detail
    assert f.scored is True


# --------------------------------------------------------------------------- B2 (check_gateway)

def test_b2_accounts_override_no_longer_fails():
    cfg = {
        "gateway": {
            "bind": "127.0.0.1:8080",
            "auth": {"mode": "token", "token": "a-very-long-token-1234567890"},
        },
        "channels": {
            "telegram": {
                "dmPolicy": "open", "groupPolicy": "open",
                "accounts": {
                    "main": {"botToken": "x", "dmPolicy": "pairing", "groupPolicy": "allowlist"}
                },
            }
        },
    }
    f = check_gateway(_ctx(cfg))
    assert f.status == PASS, f.detail


def test_b2_still_fails_when_no_accounts_override_exists():
    """Control: without the accounts-override shape, B2's own open-channel FAIL fires."""
    cfg = {
        "gateway": {
            "bind": "127.0.0.1:8080",
            "auth": {"mode": "token", "token": "a-very-long-token-1234567890"},
        },
        "channels": {"telegram": {"dmPolicy": "open"}},
    }
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL


# --------------------------------------------------------------------------- B55 (check_fs_write_exposure)

def test_b55_accounts_override_no_longer_fails():
    """B-389's exact repro from the task description (Telegram + fs_write + exec-only gate)."""
    cfg = {
        "channels": {
            "telegram": {
                "dmPolicy": "open", "groupPolicy": "open",
                "accounts": {
                    "main": {"botToken": "x", "dmPolicy": "pairing", "groupPolicy": "allowlist"}
                },
            }
        },
        "tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}},
    }
    f = check_fs_write_exposure(_ctx(cfg))
    assert f.status != FAIL, f.detail


def test_b55_still_fails_when_no_accounts_override_exists():
    """Control: without the accounts-override shape, B55's own B-376 FAIL still fires."""
    cfg = {
        "channels": {"telegram": {"dmPolicy": "open"}},
        "tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}},
    }
    f = check_fs_write_exposure(_ctx(cfg))
    assert f.status == FAIL
    assert f.scored is True
