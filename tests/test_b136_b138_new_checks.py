"""B136 — Codex CLI project trust_level="trusted" (codex-home/config.toml).
B138 — dangling high-scope pending device pairing (devices/pending.json).
"""
from pathlib import Path

from clawseccheck.catalog import CATALOG, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_codex_project_trust, check_pending_device_pairing_scope
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home):
    return Context(home=Path(home))


# ---------------------------------------------------------------------------
# B136 — Codex CLI project trust_level="trusted"
# ---------------------------------------------------------------------------

def test_b136_warn_trusted_project():
    f = check_codex_project_trust(_ctx(FIXTURES / "bad_b136_codex_trusted_project"))
    assert f.id == "B136"
    assert f.status == WARN
    assert any("demo-project" in e for e in f.evidence)


def test_b136_pass_no_trusted_project():
    f = check_codex_project_trust(_ctx(FIXTURES / "clean_b136_codex_no_trust"))
    assert f.id == "B136"
    assert f.status == PASS


def test_b136_unknown_no_codex_home():
    f = check_codex_project_trust(_ctx(FIXTURES / "unknown_b136_no_codex_home"))
    assert f.id == "B136"
    assert f.status == UNKNOWN


def test_b136_unknown_when_no_agents_dir_at_all(tmp_path):
    f = check_codex_project_trust(_ctx(tmp_path))
    assert f.status == UNKNOWN


def test_b136_warn_multiple_agents_one_trusted(tmp_path):
    """Only one of several agents has a trusted project — must still WARN."""
    safe = tmp_path / "agents" / "main" / "agent" / "codex-home" / "config.toml"
    safe.parent.mkdir(parents=True)
    safe.write_text('[projects."/ws/safe"]\ntrust_level = "workspace-write"\n', encoding="utf-8")

    trusted = tmp_path / "agents" / "analyst" / "agent" / "codex-home" / "config.toml"
    trusted.parent.mkdir(parents=True)
    trusted.write_text('[projects."/ws/risky"]\ntrust_level = "trusted"\n', encoding="utf-8")

    f = check_codex_project_trust(_ctx(tmp_path))
    assert f.status == WARN
    assert any("/ws/risky" in e for e in f.evidence)


def test_b136_meta_advisory_tools():
    m = next(c for c in CATALOG if c.id == "B136")
    assert m.scored is False
    assert m.surface == "tools"


# ---------------------------------------------------------------------------
# B138 — dangling high-scope pending device pairing
# ---------------------------------------------------------------------------

def test_b138_warn_admin_scope_pending():
    f = check_pending_device_pairing_scope(_ctx(FIXTURES / "bad_b138_pending_admin_scope"))
    assert f.id == "B138"
    assert f.status == WARN
    assert any("device-repair-01" in e for e in f.evidence)
    assert any("isRepair=True" in e for e in f.evidence)


def test_b138_pass_no_highscope_pending():
    f = check_pending_device_pairing_scope(_ctx(FIXTURES / "clean_b138_pending_no_highscope"))
    assert f.id == "B138"
    assert f.status == PASS


def test_b138_pass_when_file_absent(tmp_path):
    """Absence of devices/pending.json is informative (no pending pairings at all) —
    PASS, not UNKNOWN, matching the common/expected case."""
    f = check_pending_device_pairing_scope(_ctx(tmp_path))
    assert f.status == PASS


def test_b138_pass_when_file_empty(tmp_path):
    d = tmp_path / "devices"
    d.mkdir()
    (d / "pending.json").write_text("{}", encoding="utf-8")
    f = check_pending_device_pairing_scope(_ctx(tmp_path))
    assert f.status == PASS


def test_b138_unknown_when_malformed_json(tmp_path):
    d = tmp_path / "devices"
    d.mkdir()
    (d / "pending.json").write_text("{not valid json", encoding="utf-8")
    f = check_pending_device_pairing_scope(_ctx(tmp_path))
    assert f.status == UNKNOWN


def test_b138_warn_operator_write_scope(tmp_path):
    d = tmp_path / "devices"
    d.mkdir()
    (d / "pending.json").write_text(
        '{"r1": {"deviceId": "d1", "platform": "linux", "isRepair": false, '
        '"scopes": ["operator.write"]}}',
        encoding="utf-8",
    )
    f = check_pending_device_pairing_scope(_ctx(tmp_path))
    assert f.status == WARN


def test_b138_meta_advisory_agents():
    m = next(c for c in CATALOG if c.id == "B138")
    assert m.scored is False
    assert m.surface == "agents"
