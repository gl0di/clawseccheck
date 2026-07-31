"""B55 / C-013 — filesystem-write tool exposure check + RISK-12 chain.

B55's CheckMeta is advisory (scored=False): the WARN/PASS/UNKNOWN branches name a
broad/ungated fs-write grant and feed RISK-12 (write + untrusted ingress =
tamper/persistence), while the general write/least-privilege dimension stays with the
SCORED checks B3/B22/B31. It must never WARN/FAIL on a genuinely scoped config (§5
zero-false-positive).

B-315 originally downgraded the broad-reach case FAIL->WARN (an unscored check must
never FAIL — Dave's ruling: scored=False caps at WARN). B-376/B-369 (2026-07-31)
re-escalated it: ClawRange's false-negative hunter found real misses on two grounded,
PROVEN-broad-reach mutations, so this branch now follows the B186 narrow-FAIL-override
precedent instead — CheckMeta stays scored=False, and only this one Finding carries
scored=True (see tests/test_b315_unscored_never_fails.py for the cross-check
invariant). Everything short of proven broad reach (an allowlist/paired channel, or no
broad-reach signal at all) is unaffected and still stays WARN.
"""
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.collector import collect
from clawseccheck.checks import check_fs_write_exposure
from clawseccheck.risk import risk_paths

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _by_id(findings):
    return {f.id: f for f in findings}


def _b55(home: Path):
    return check_fs_write_exposure(collect(home))


def _write_config(tmp_path: Path, body: str) -> Path:
    (tmp_path / "openclaw.json").write_text(body, encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------- FAIL (B-376/B-369)
def test_broad_fs_write_fails_on_bad_fixture():
    f = _b55(FIXTURES / "bad_b55_fs_write_broad")
    assert f.id == "B55"
    assert f.status == FAIL
    assert f.scored is True  # per-finding override — this specific Finding participates
    assert any("fs_write" in e for e in f.evidence)
    assert any("no approval gate" in e for e in f.evidence)


def test_bad_fixture_b55_is_scored_in_audit_but_checkmeta_is_not():
    """The whole audit must run; this FAIL must be visible to scoring.compute() even
    though CheckMeta.scored stays False for B55's other branches."""
    from clawseccheck.catalog import BY_ID

    assert BY_ID["B55"].scored is False
    _, findings, _ = audit(FIXTURES / "bad_b55_fs_write_broad")
    b55 = _by_id(findings)["B55"]
    assert b55.status == FAIL and b55.scored is True


# --------------------------------------------------------------------------- PASS
def test_scoped_fs_write_passes_on_clean_fixture():
    f = _b55(FIXTURES / "clean_b55_fs_write_scoped")
    assert f.status == PASS, f.detail


def test_no_write_tool_passes(tmp_path):
    home = _write_config(tmp_path, '{"tools": {"allow": ["web_fetch", "fs_read"]}}')
    assert _b55(home).status == PASS


def test_tight_sender_allowlist_passes(tmp_path):
    home = _write_config(
        tmp_path,
        '{"tools": {"allow": ["fs_write"], "elevated": {"allowFrom": ["owner@example.com"]}}}',
    )
    assert _b55(home).status == PASS


# C-135 (2026-07-31): the real tools.elevated.allowFrom shape is a dict keyed by
# provider (see B3's check_least_privilege), not the flat list/bare "*" form. An
# adversarial review of the FAIL escalation found this dict shape fell through to the
# open_ch-only FAIL branch unrecognized — the textbook-recommended way to scope
# elevated tools was itself a false-positive FAIL trigger.
def test_dict_shaped_tight_allowlist_passes_even_with_open_channel(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "elevated": '
        '{"allowFrom": {"telegram": ["987654321"]}}}}',
    )
    f = _b55(home)
    assert f.status == PASS, f.detail


def test_dict_shaped_wildcard_allowlist_still_fails(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "elevated": '
        '{"allowFrom": {"telegram": ["*"]}}}}',
    )
    f = _b55(home)
    assert f.status == FAIL, f.detail
    assert f.scored is True


def test_open_channel_not_scoped_by_exec_gate_fails(tmp_path):
    """B-369's exact mutation: an exec-only approval gate does not scope write tools,
    so it cannot clear an otherwise-broad-reach fs_write grant."""
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}}}',
    )
    f = _b55(home)
    assert f.status == FAIL, f.detail
    assert f.scored is True
    assert any("open-ingress bypasses exec-style approval" in e for e in f.evidence)


# C-135 (2026-07-31): B68 (check_exec_applypatch_workspace, same file) already treats
# tools.fs.workspaceOnly=true / agents.defaults.sandbox.mode="all" as sufficient
# confinement for this identical tool family. An adversarial review of the FAIL
# escalation found B55 never consulted either field, so a workspace-confined or fully
# sandboxed write grant still hard-FAILed as "arbitrary" — downgraded to WARN instead:
# still reachable, but not arbitrary, so not scored=True.
def test_workspace_confined_write_downgrades_to_warn_not_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "fs": {"workspaceOnly": true}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.scored is False
    assert any("confined to the workspace" in e for e in f.evidence)


def test_fully_sandboxed_write_downgrades_to_warn_not_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"discord": {"dmPolicy": "open", "groupPolicy": "open"}},'
        ' "tools": {"allow": ["apply_patch"]},'
        ' "agents": {"defaults": {"sandbox": {"mode": "all"}}}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.scored is False


# --------------------------------------------------------------------------- WARN
def test_ungated_write_without_broad_reach_warns(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "allowlist"}},'
        ' "tools": {"allow": ["apply_patch"]}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert any("apply_patch" in e for e in f.evidence)


# B-057 invariant: the FAIL gate uses _open_channels (open-only) BY DESIGN. An allowlist
# or paired channel is untrusted *content* but not proven-broad reach, so a write tool
# behind one stays WARN — never FAIL. Widening the gate to _external_input_channels would
# flip these to FAIL: a §5 false-positive. These lock that boundary explicitly.
def test_b55_allowlist_channel_does_not_escalate_to_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "allowlist"}},'
        ' "tools": {"allow": ["fs_write"]}}',
    )
    f = _b55(home)
    assert f.status == WARN, f.detail
    assert f.status != FAIL


def test_b55_paired_channel_does_not_escalate_to_fail(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "pairing"}},'
        ' "tools": {"allow": ["fs_write"]}}',
    )
    assert _b55(home).status == WARN


# --------------------------------------------------------------------------- UNKNOWN
def test_no_tool_allowlist_is_unknown(tmp_path):
    home = _write_config(tmp_path, '{"gateway": {"bind": "127.0.0.1:8080"}}')
    f = _b55(home)
    assert f.status == UNKNOWN
    assert "not determinable" not in f.detail  # uses "cannot be enumerated" phrasing
    assert "enumerated" in f.detail


# --------------------------------------------------------------------------- RISK-12
def test_risk12_fires_on_broad_write_plus_untrusted_ingress():
    ctx, findings, _ = audit(FIXTURES / "bad_b55_fs_write_broad")
    ids = {p.id for p in risk_paths(ctx, findings)}
    assert "RISK-12" in ids


def test_risk12_silent_on_scoped_config():
    ctx, findings, _ = audit(FIXTURES / "clean_b55_fs_write_scoped")
    ids = {p.id for p in risk_paths(ctx, findings)}
    assert "RISK-12" not in ids
