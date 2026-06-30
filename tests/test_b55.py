"""B55 / C-013 — filesystem-write tool exposure check + RISK-12 chain.

B55 is advisory (scored=False): it names a broad/ungated fs-write grant and feeds
RISK-12 (write + untrusted ingress = tamper/persistence). It must never FAIL/WARN on
a scoped config (§5 zero-false-positive).
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


# --------------------------------------------------------------------------- FAIL
def test_broad_fs_write_fails_on_bad_fixture():
    f = _b55(FIXTURES / "bad_b55_fs_write_broad")
    assert f.id == "B55"
    assert f.status == FAIL
    assert f.scored is False  # advisory — never moves the grade
    assert any("fs_write" in e for e in f.evidence)
    assert any("no approval gate" in e for e in f.evidence)


def test_bad_fixture_b55_is_not_scored_in_audit():
    """The whole audit must run and B55 must be present but advisory."""
    _, findings, _ = audit(FIXTURES / "bad_b55_fs_write_broad")
    b55 = _by_id(findings)["B55"]
    assert b55.status == FAIL and b55.scored is False


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


def test_open_channel_not_scoped_by_exec_gate_fails(tmp_path):
    home = _write_config(
        tmp_path,
        '{"channels": {"telegram": {"dmPolicy": "open"}},'
        ' "tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}}}',
    )
    f = _b55(home)
    assert f.status == FAIL, f.detail
    assert any("open-ingress channel(s)" in e for e in f.evidence)


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
        '{"channels": {"telegram": {"dmPolicy": "paired"}},'
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
