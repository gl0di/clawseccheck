from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _by_id(findings):
    return {f.id: f for f in findings}


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


def test_a1_explicit_tools_suppress_thin_surface_warn(tmp_path):
    """Explicit tools.allow present → thin-surface branch does not fire."""
    (tmp_path / "openclaw.json").write_text(
        '{"tools": {"allow": ["exec_command"]}, '
        '"channels": {"telegram": {"dmPolicy": "allowlist"}}}'
    )
    (tmp_path / "openclaw.json").chmod(0o600)
    f = _by_id(audit(tmp_path)[1])["A1"]
    assert "Runtime tools" not in f.detail
