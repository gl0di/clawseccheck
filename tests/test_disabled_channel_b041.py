"""B-041 regression: a channel with `enabled: false` ingests nothing, so it must not
drive any "reachable by untrusted senders" verdict. Before the fix, the two
enabled-unaware channel helpers (`_open_channels`, `_external_input_channels`) counted
disabled channels, producing §5 hard-FAIL false positives (B2/B39/B55/B30) and spurious
WARNs (B41/B46). Zero fixtures use `enabled:false`, so this class was latent against the
suite but fired on real configs — hence these explicit cases.

Each test pairs a DISABLED untrusted/open channel (asserts the §5-correct verdict) with
an ENABLED control (asserts detection still fires — the fix only narrows, never blinds).
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import run_all
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import _external_input_channels, _open_channels
from clawseccheck.collector import Context


def _run(cfg: dict, home: str = "/nonexistent") -> dict:
    ctx = Context(home=Path(home))
    ctx.config = cfg
    return {f.id: f for f in run_all(ctx)}


# ── helper level: disabled channel contributes no ingress ────────────────────────

def test_open_channels_skips_disabled():
    cfg = {"channels": {"telegram": {"enabled": False, "dmPolicy": "open"}}}
    assert _open_channels(cfg) == []
    # enabled control still matches
    cfg2 = {"channels": {"telegram": {"dmPolicy": "open"}}}
    assert _open_channels(cfg2) == ["telegram"]


def test_external_input_channels_skips_disabled():
    cfg = {"channels": {"slack": {"enabled": False, "dmPolicy": "allowlist"}}}
    assert _external_input_channels(cfg) == []
    cfg2 = {"channels": {"slack": {"dmPolicy": "allowlist"}}}
    assert _external_input_channels(cfg2) == ["slack"]


# ── B2: disabled open channel must not FAIL a loopback+auth gateway ──────────────

def test_b2_disabled_open_channel_not_failed():
    cfg = {
        "gateway": {"bind": "127.0.0.1:8080",
                    "auth": {"mode": "token", "token": "a-very-long-token-1234567890"}},
        "channels": {"telegram": {"enabled": False, "dmPolicy": "open"}},
    }
    assert _run(cfg)["B2"].status != FAIL
    # enabled control: an open channel on the gateway IS flagged
    cfg["channels"]["telegram"].pop("enabled")
    assert _run(cfg)["B2"].status == FAIL


# ── B39: disabled allowlist channel must not FAIL session visibility ─────────────

def test_b39_disabled_channel_not_cross_user_failed():
    cfg = {"session": {"dmScope": "main"},
           "channels": {"telegram": {"enabled": False, "dmPolicy": "allowlist"}}}
    assert _run(cfg)["B39"].status != FAIL
    # enabled control: a live allowlist DM channel with shared session IS flagged
    cfg["channels"]["telegram"].pop("enabled")
    assert _run(cfg)["B39"].status == FAIL


# ── B55: disabled open channel must not make fs_write "reachable" (FAIL) ─────────

def test_b55_disabled_channel_not_broad_reach_fail():
    cfg = {"tools": {"allow": ["fs_write"]},
           "channels": {"telegram": {"enabled": False, "dmPolicy": "open"}}}
    assert _run(cfg)["B55"].status != FAIL
    # enabled control: fs_write reachable via an open channel IS a FAIL
    cfg["channels"]["telegram"].pop("enabled")
    assert _run(cfg)["B55"].status == FAIL


# ── B41: disabled allowlist channel must not WARN credential blast radius ────────

def test_b41_disabled_channel_no_untrusted_ingress_warn():
    # NB: outbound tool is "deploy", NOT "webhook" — "webhook" contains the substring
    # "web", which independently trips INPUT_TOOL_HINTS and would mask the channel fix.
    cfg = {"channels": {"slack": {"enabled": False, "dmPolicy": "allowlist"}},
           "tools": {"allow": ["deploy"]},
           "auth": {"profiles": {"google:me@x.com": {}, "github:bot": {}}}}
    assert _run(cfg)["B41"].status != WARN
    # enabled control: live untrusted ingress + creds + outbound IS a WARN
    cfg["channels"]["slack"].pop("enabled")
    assert _run(cfg)["B41"].status == WARN


# ── B46: disabled allowlist channel must not WARN multi-agent exposure ───────────

def test_b46_disabled_channel_no_multiagent_warn():
    cfg = {"agents": {"list": [{"name": "a"}, {"name": "b"}]},
           "channels": {"telegram": {"enabled": False, "dmPolicy": "allowlist"}},
           "tools": {"elevated": {"allowFrom": {"telegram": ["uid1"]}}}}
    assert _run(cfg)["B46"].status != WARN
    # enabled control: live untrusted ingress + multi-agent + elevated IS a WARN
    cfg["channels"]["telegram"].pop("enabled")
    assert _run(cfg)["B46"].status == WARN


# ── B30: a disabled channel's name-matching flag is not a live bypass ────────────

def test_b30_disabled_channel_namematch_not_failed():
    cfg = {"channels": {"discord": {"enabled": False,
                                    "dangerouslyAllowNameMatching": True}}}
    # all channels disabled → nothing live to assess → UNKNOWN, not FAIL
    assert _run(cfg)["B30"].status == UNKNOWN
    # enabled control: a live channel with the flag IS a FAIL
    cfg["channels"]["discord"].pop("enabled")
    assert _run(cfg)["B30"].status == FAIL


# ── B3 (B-042): PASS message must not overclaim runtime reachability ─────────────

def test_b3_pass_does_not_claim_runtime_reachability():
    cfg = {"gateway": {"bind": "loopback"}}
    b3 = _run(cfg)["B3"]
    assert b3.status == PASS
    assert "tool reachability is constrained" not in b3.detail
    assert "runtime-granted tools are not visible" in b3.detail
