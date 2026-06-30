from __future__ import annotations

from pathlib import Path

from clawseccheck import audit, run_all
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _by_id(findings):
    return {f.id: f for f in findings}


def _a1(cfg: dict, attestation: dict | None = None, home: str = "/nonexistent"):
    """Run all checks against an in-memory config and return the A1 finding.

    home defaults to a nonexistent path so the `credentials/` dir does not
    silently raise the sensitive-data leg in leg-isolation tests.
    """
    ctx = Context(home=Path(home))
    ctx.config = cfg
    if attestation:
        ctx.attestation = attestation
    return {x.id: x for x in run_all(ctx)}["A1"]


def test_vulnerable_setup_scores_low_and_fails_criticals():
    _, findings, score = audit(FIXTURES / "home_vuln")
    f = _by_id(findings)
    # critical holes open -> hard cap to <=49 -> grade F
    assert score.score <= 49
    assert score.grade == "F"
    assert score.failed_critical >= 1
    # the headline trifecta is fully active
    assert f["A1"].status == FAIL
    assert len(f["A1"].evidence) == 3
    # core criticals/highs flagged
    # B5 (supply chain) uses no real config fields to FAIL — it delegates to B24/B25
    # for pinning detail; with only config present and no phantom fields it returns PASS.
    for cid in ("B1", "B2", "B3", "B4", "B6"):
        assert f[cid].status == FAIL, f"{cid} should FAIL on vulnerable fixture"


def test_hardened_setup_scores_high_and_clean():
    _, findings, score = audit(FIXTURES / "home_safe")
    f = _by_id(findings)
    assert score.grade == "A"
    assert score.score >= 90
    assert score.capped is False
    # no failures on a hardened setup
    assert not [x for x in findings if x.status == FAIL]
    # trifecta broken (<=2 of 3)
    assert len(f["A1"].evidence) <= 2
    assert f["A1"].status == PASS


def test_bootstrap_injection_is_the_wedge():
    # FAIL on vulnerable SOUL.md (blanket-obedience), PASS on the careful one.
    _, vuln, _ = audit(FIXTURES / "home_vuln")
    _, safe, _ = audit(FIXTURES / "home_safe")
    assert _by_id(vuln)["B6"].status == FAIL
    assert _by_id(safe)["B6"].status == PASS


def test_missing_config_is_unknown_not_false_positive():
    ctx, findings, _ = audit(FIXTURES / "does_not_exist")
    assert ctx.errors  # collector reported the missing file
    assert _by_id(findings)["B2"].status == UNKNOWN


def test_secret_in_config_flagged_only_when_perms_loose(tmp_path):
    # tokens in config are normal; the risk is a world-readable config file
    cfg = tmp_path / "openclaw.json"
    cfg.write_text(
        '{"gateway":{"auth":{"mode":"token","token":"a-very-long-token-1234567890"}},'
        '"channels":{"telegram":{"accounts":{"main":'
        '{"botToken":"1234567890abcdef1234567890"}}}}}'
    )
    cfg.chmod(0o644)
    assert _by_id(audit(tmp_path)[1])["B1"].status == FAIL   # secrets + world-readable
    cfg.chmod(0o600)
    assert _by_id(audit(tmp_path)[1])["B1"].status == PASS   # same secrets, tight perms


def test_loopback_keyword_bind_is_not_flagged():
    # real OpenClaw uses bind keyword "loopback", not an IP
    import json

    from clawseccheck import run_all
    from clawseccheck.collector import Context
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = json.loads('{"gateway":{"bind":"loopback","auth":{"mode":"token",'
                            '"token":"a-very-long-token-1234567890"}}}')
    f = {x.id: x for x in run_all(ctx)}
    assert f["B2"].status == PASS
    assert f["B11"].status == PASS


def test_read_only_no_writes(tmp_path):
    # audit must not create/modify anything in the target dir
    (tmp_path / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}')
    before = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    audit(tmp_path)
    after = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    assert before == after


# ── B-032: _open_channels() must count paired/allowlist as untrusted input ─────

def test_a1_paired_channel_counts_as_untrusted_input(tmp_path):
    """paired Telegram raises the untrusted-input leg (B-032)."""
    (tmp_path / "openclaw.json").write_text(
        '{"channels": {"telegram": {"dmPolicy": "paired"}}}'
    )
    (tmp_path / "openclaw.json").chmod(0o600)
    f = _by_id(audit(tmp_path)[1])["A1"]
    assert "untrusted input" in (f.evidence or [])


def test_a1_allowlist_channel_counts_as_untrusted_input(tmp_path):
    """allowlist Telegram raises the untrusted-input leg (B-032)."""
    (tmp_path / "openclaw.json").write_text(
        '{"channels": {"telegram": {"dmPolicy": "allowlist"}}}'
    )
    (tmp_path / "openclaw.json").chmod(0o600)
    f = _by_id(audit(tmp_path)[1])["A1"]
    assert "untrusted input" in (f.evidence or [])


def test_a1_owner_only_channel_not_untrusted_input(tmp_path):
    """owner-only channel must NOT raise the untrusted-input leg."""
    (tmp_path / "openclaw.json").write_text(
        '{"channels": {"telegram": {"dmPolicy": "owner-only"}}}'
    )
    (tmp_path / "openclaw.json").chmod(0o600)
    f = _by_id(audit(tmp_path)[1])["A1"]
    assert "untrusted input" not in (f.evidence or [])


# ── B-033: check_trifecta() thin-surface guard ──────────────────────────────────

def test_a1_thin_surface_warns_not_passes(tmp_path):
    """No tool config + no channels → WARN for undetectable runtime capabilities (B-033)."""
    (tmp_path / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}')
    (tmp_path / "openclaw.json").chmod(0o600)
    f = _by_id(audit(tmp_path)[1])["A1"]
    assert f.status == WARN
    assert "Runtime tools" in f.detail


def test_a1_no_warn_when_runtime_legs_already_active(tmp_path):
    """Both runtime legs already active (untrusted via allowlist, outbound via send
    tool) → nothing is 'cannot determine', so no thin-surface WARN. Uses a non-exec
    outbound tool deliberately: post-B-061 an ungated `exec` tool would add the
    sensitive leg and make this a 3/3 FAIL, changing the scenario under test (the
    no-WARN path on a determinable 2/3 config)."""
    (tmp_path / "openclaw.json").write_text(
        '{"tools": {"allow": ["send"]}, '
        '"channels": {"telegram": {"dmPolicy": "allowlist"}}}'
    )
    (tmp_path / "openclaw.json").chmod(0o600)
    f = _by_id(audit(tmp_path)[1])["A1"]
    assert "Cannot determine" not in f.detail


# ── A1 leg-detection fixes: web.fetch, group bots, enabled flag, no-op guard,
#    attestation resolution ─────────────────────────────────────────────────────

def test_a1_web_fetch_enabled_is_untrusted_input():
    """D1: an enabled web-fetch tool pulls untrusted remote content into the agent."""
    a1 = _a1({"tools": {"web": {"fetch": {"enabled": True}}}})
    assert "untrusted input" in (a1.evidence or [])


def test_a1_gateway_password_alone_is_not_sensitive_data():
    """§5 false-positive guard: gateway.auth.password is the gateway's own auth secret,
    NOT agent-readable private data, so it must not constitute the sensitive-data leg.
    web_fetch fills input + outbound, so counting the gateway password as sensitive would
    let "web browsing + a gateway password" reach a spurious 3/3 FAIL. B1 still flags the
    password as a plaintext secret — that is its proper home."""
    a1 = _a1({"tools": {"web": {"fetch": {"enabled": True}}},
              "gateway": {"auth": {"password": "x"}}})
    assert "sensitive data" not in (a1.evidence or [])
    assert a1.status != FAIL
    # contrast: web_fetch + a REAL data tool (fs_read) IS a genuine 3/3 lethal trifecta
    real = _a1({"tools": {"web": {"fetch": {"enabled": True}}, "allow": ["fs_read"]}})
    assert real.status == FAIL
    assert "sensitive data" in (real.evidence or [])


def test_a1_open_group_bot_is_untrusted_input():
    """D4: a group bot whose groupPolicy admits non-owner senders (open/allowlist/paired)
    is untrusted input — the same allowlist the rest of the engine uses
    (_UNTRUSTED_INPUT_POLICIES), not a groups-present denylist."""
    a1 = _a1({"channels": {"telegram": {"groups": {"*": {"requireMention": True}},
                                        "groupPolicy": "open"}}})
    assert "untrusted input" in (a1.evidence or [])


def test_a1_approval_gated_group_bot_not_untrusted_input():
    """§5 false-positive guard: an owner-approved group bot (groupPolicy="ask",
    per-message approval) is NOT an untrusted-input surface — the untrusted group
    sender cannot autonomously drive the agent. An earlier groups-present denylist
    FAILed this safe config; "ask"/absent/owner group policies are excluded, matching
    DM behaviour and the leg doctrine at _UNTRUSTED_INPUT_POLICIES."""
    a1 = _a1({"channels": {"telegram": {"groups": {"*": {}}, "groupPolicy": "ask"}}})
    assert "untrusted input" not in (a1.evidence or [])
    # full vector: approval-gated group bot + a sensitive/db tool must NOT reach 3/3 FAIL
    full = _a1({"channels": {"telegram": {"enabled": True, "groups": {"*": {}},
                                          "groupPolicy": "ask"}},
                "tools": {"allow": ["db_query"]}})
    assert full.status != FAIL


def test_a1_owner_only_group_bot_not_untrusted_input():
    """Guard against over-broadening: a group bot locked to owner-only is NOT untrusted."""
    a1 = _a1({"channels": {"telegram": {"groups": {"*": {}}, "groupPolicy": "owner-only"}}})
    assert "untrusted input" not in (a1.evidence or [])


def test_a1_disabled_channel_contributes_no_legs():
    """enabled:false → the channel ingests/sends nothing (untrusted and outbound off)."""
    a1 = _a1({"channels": {"telegram": {"enabled": False, "dmPolicy": "open"}}})
    assert "untrusted input" not in (a1.evidence or [])
    assert "outbound actions" not in (a1.evidence or [])


def test_a1_noop_tool_does_not_suppress_warn():
    """D7: a no-op tools.allow entry must NOT flip the 'cannot determine' WARN to PASS."""
    a1 = _a1({"tools": {"allow": ["noop"]},
              "channels": {"telegram": {"dmPolicy": "owner-only"}}})
    assert a1.status == WARN
    assert "Cannot determine" in a1.detail


def test_a1_attestation_clears_thin_surface_warn():
    """D3: a real attestation roster clears the 'cannot determine' WARN that a thin
    config raises — unlike a no-op tools.allow entry (which must not)."""
    thin = _a1({"gateway": {"bind": "x"}})
    assert thin.status == WARN
    assert "Cannot determine" in thin.detail
    attested = _a1({"gateway": {"bind": "x"}},
                   attestation={"agents": [{"name": "a", "tools": ["chat"]}]})
    assert attested.status != WARN
    assert "Cannot determine" not in attested.detail


def test_a1_attestation_clears_warn_without_adding_leg():
    """D3/D7: a real attestation declaring no input/outbound tools positively resolves
    the leg as off and clears the WARN — unlike a no-op tools.allow entry."""
    a1 = _a1(
        {"channels": {"telegram": {"dmPolicy": "owner-only"}}},
        attestation={"agents": [{"name": "chatbot", "tools": ["chat"]}]},
    )
    assert a1.status == PASS
    assert "Cannot determine" not in a1.detail


# ── B-061: ungated exec raises BOTH sensitive + outbound legs ────────────────────

def test_a1_exec_alone_is_lethal_capable():
    """Ungated exec (no channels/web) = exactly 2 legs: sensitive + outbound.
    No untrusted-input channel, so it is NOT a 3/3 FAIL (an owner-only local CLI
    agent with exec stays non-FAIL — the §5 case the B-061 decision protects)."""
    a1 = _a1({"tools": {"exec": {"mode": "full"}}})
    assert set(a1.evidence or []) == {"sensitive data", "outbound actions"}
    assert a1.status != FAIL


def test_a1_exec_plus_open_channel_is_trifecta():
    """Ungated exec + an open (untrusted) channel = full 3/3 lethal trifecta FAIL."""
    a1 = _a1({"tools": {"exec": {"mode": "full"}},
              "channels": {"telegram": {"dmPolicy": "open"}}})
    assert a1.status == FAIL
    assert len(a1.evidence) == 3


def test_a1_gated_exec_plus_channel_is_not_sensitive():
    """§5 guard: approval-gated exec (mode='ask') does NOT raise the sensitive leg,
    so an untrusted channel + gated exec stays 2/3 (not FAIL). Protects home_safe and
    clean_b55/b68/b69/c014/c6, which all share this shape."""
    a1 = _a1({"tools": {"exec": {"mode": "ask"}},
              "channels": {"telegram": {"dmPolicy": "open"}}})
    assert "sensitive data" not in (a1.evidence or [])
    assert a1.status != FAIL


def test_a1_sandbox_without_exec_not_lethal():
    """B-064 §5 regression: a Docker SANDBOX (a hardening control) plus an open channel,
    with NO declared exec tool, must NOT be read as ungated exec. The sandbox-inferred
    'exec' (from agents.defaults.sandbox.mode != 'off') must not raise the sensitive leg,
    so this stays 2/3, not a spurious 3/3 FAIL."""
    a1 = _a1({"agents": {"defaults": {"sandbox": {"mode": "docker"}}},
              "channels": {"telegram": {"dmPolicy": "open"}}})
    assert a1.status != FAIL
    assert "sensitive data" not in (a1.evidence or [])
    assert set(a1.evidence or []) == {"untrusted input", "outbound actions"}


# ── F-036: distance-to-trifecta note for 2/3 configs ─────────────────────────────

def test_a1_distance_note_names_missing_sensitive_leg():
    """2/3 (untrusted channel + outbound) names 'sensitive data' as the missing leg."""
    a1 = _a1({"channels": {"telegram": {"dmPolicy": "open"}}})
    assert "the missing leg is 'sensitive data'" in a1.detail
    assert "2 of 3 lethal-trifecta legs present" in a1.detail


def test_a1_distance_note_names_missing_outbound_leg():
    """2/3 (input tool + sensitive tool, no outbound) names 'outbound actions'."""
    a1 = _a1({"tools": {"allow": ["imap", "fs_read"]}})
    assert "the missing leg is 'outbound actions'" in a1.detail


def test_a1_distance_note_names_missing_untrusted_leg():
    """2/3 (sensitive + outbound, no untrusted input) names 'untrusted input'."""
    a1 = _a1({"tools": {"allow": ["fs_read", "deploy"]}})
    assert "the missing leg is 'untrusted input'" in a1.detail


def test_a1_distance_note_absent_when_not_two_legs():
    """No distance note for 3/3 (FAIL) or <2/3 — additive only at exactly 2/3."""
    full = _a1({"tools": {"allow": ["imap", "fs_read", "webhook"]}})
    assert full.status == FAIL
    assert "missing leg" not in full.detail
    empty = _a1({"gateway": {"bind": "loopback"}})
    assert "missing leg" not in empty.detail
