"""B22 Self-modification risk tests.

Approval gating uses the REAL OpenClaw field `tools.exec.mode` (deny/allowlist/
ask/auto/full) via `_has_approval_gate`. The phantom fields tools.confirm /
tools.requireApproval / tools.elevated.requireApproval do NOT exist and must not
influence the result (regression for BLK-01).
"""
import json
from pathlib import Path

from clawseccheck.checks import check_self_modification
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg=None, home="/x"):
    c = Context(home=Path(home))
    c.config = cfg or {}
    c.bootstrap = {}
    return c


def json_load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name / "openclaw.json").read_text())


def _make_workspace(tmp_path, soul_mode=0o644, ws_mode=0o755, skills_mode=None):
    """Create a minimal workspace with SOUL.md and optionally a skills dir."""
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    ws.chmod(ws_mode)
    soul = ws / "SOUL.md"
    soul.write_text("I am the agent.")
    soul.chmod(soul_mode)
    if skills_mode is not None:
        sk = ws / "skills"
        sk.mkdir(exist_ok=True)
        sk.chmod(skills_mode)
    return ws


def _cfg_with_tools(exec_mode=None, exec_security=None):
    """Config with fs_write tool present; optional REAL approval gate fields."""
    cfg = {"tools": {"allow": ["fs_write", "shell"]}}
    exec_cfg = {}
    if exec_mode is not None:
        exec_cfg["mode"] = exec_mode
    if exec_security is not None:
        exec_cfg["security"] = exec_security
    if exec_cfg:
        cfg["tools"]["exec"] = exec_cfg
    return cfg


# ---- condition (a): no tools -> UNKNOWN ----
def test_b22_no_tools_is_unknown(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    c = _ctx({}, home=str(tmp_path))
    assert check_self_modification(c).status == "UNKNOWN"


# ---- condition (b): tools present but no writable targets -> UNKNOWN ----
def test_b22_tools_but_tight_perms_is_unknown(tmp_path):
    _make_workspace(tmp_path, soul_mode=0o600, ws_mode=0o700)
    c = _ctx(_cfg_with_tools(), home=str(tmp_path))
    assert check_self_modification(c).status == "UNKNOWN"


# ---- FAIL: tools + writable workspace dir + no approval ----
def test_b22_world_writable_ws_dir_no_approval_fails(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    c = _ctx(_cfg_with_tools(), home=str(tmp_path))
    result = check_self_modification(c)
    assert result.status == "FAIL"
    assert result.id == "B22"


# ---- FAIL: tools + group-writable SOUL.md + no approval ----
def test_b22_group_writable_soul_no_approval_fails(tmp_path):
    _make_workspace(tmp_path, soul_mode=0o664, ws_mode=0o700)
    c = _ctx(_cfg_with_tools(), home=str(tmp_path))
    assert check_self_modification(c).status == "FAIL"


# ---- FAIL: tools + world-writable skills dir + no approval ----
def test_b22_world_writable_skills_dir_no_approval_fails(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o700, skills_mode=0o777)
    # Also need a top-level skills dir (outside workspace)
    sk = tmp_path / "skills"
    sk.mkdir(exist_ok=True)
    sk.chmod(0o777)
    c = _ctx(_cfg_with_tools(), home=str(tmp_path))
    assert check_self_modification(c).status == "FAIL"


# ---- WARN: tools + writable target + real approval gate (tools.exec.mode=ask) ----
def test_b22_writable_with_approval_warns(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    c = _ctx(_cfg_with_tools(exec_mode="ask"), home=str(tmp_path))
    assert check_self_modification(c).status == "WARN"


# ---- WARN: tools.exec.security='ask' also counts as a real approval gate ----
def test_b22_exec_security_ask_counts_as_approval(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    c = _ctx(_cfg_with_tools(exec_security="ask"), home=str(tmp_path))
    assert check_self_modification(c).status == "WARN"


# ---- tools.exec.mode='full' is NO gate -> FAIL ----
def test_b22_exec_mode_full_no_gate_fails(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    c = _ctx(_cfg_with_tools(exec_mode="full"), home=str(tmp_path))
    assert check_self_modification(c).status == "FAIL"


# ---- BLK-01 regression: phantom tools.requireApproval must NOT be read as a gate ----
def test_b22_phantom_require_approval_field_is_ignored(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    # A config that ONLY sets the non-existent field (no real exec.mode gate)
    cfg = {"tools": {"allow": ["fs_write"], "requireApproval": True,
                     "confirm": True, "elevated": {"requireApproval": True}}}
    c = _ctx(cfg, home=str(tmp_path))
    # Phantom fields confer no real gate -> must still FAIL
    assert check_self_modification(c).status == "FAIL"


# ---- BLK-01 regression: real tools.exec.mode='ask' is honored (no false FAIL) ----
def test_b22_uses_real_exec_approval_mode_ask(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    cfg = {"tools": {"allow": ["fs_write"], "exec": {"mode": "ask"}}}
    c = _ctx(cfg, home=str(tmp_path))
    assert check_self_modification(c).status == "WARN"  # gate detected, NOT FAIL


# ---- BLK-01 regression: no real gate + self-modification path still FAILs ----
def test_b22_no_approval_self_modification_fails(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    cfg = {"tools": {"allow": ["fs_write"], "exec": {"mode": "full"}}}
    c = _ctx(cfg, home=str(tmp_path))
    assert check_self_modification(c).status == "FAIL"


# ---- BLK-01 regression: remediation text names REAL fields, not phantom ones ----
def test_b22_remediation_mentions_real_fields(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    c = _ctx(_cfg_with_tools(exec_mode="full"), home=str(tmp_path))
    result = check_self_modification(c)
    assert result.status == "FAIL"
    assert "tools.exec" in result.fix
    assert "requireApproval" not in result.fix
    assert "tools.confirm" not in result.fix


# ---- elevated tools trigger condition (a) ----
def test_b22_elevated_tools_count(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    cfg = {"tools": {"elevated": {"allowFrom": ["owner@example.com"]}}}
    c = _ctx(cfg, home=str(tmp_path))
    assert check_self_modification(c).status == "FAIL"


# ---- B-130: powerful tools.profile (e.g. "coding") counts as condition (a), ----
# ---- even with no explicit tools.exec.*/elevated fields set ----
def test_b22_coding_profile_no_exec_fields_counts_as_dangerous_tools(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    cfg = {"tools": {"profile": "coding"}}
    c = _ctx(cfg, home=str(tmp_path))
    # No approval gate configured -> FAIL (condition (a) now true via profile).
    assert check_self_modification(c).status == "FAIL"


def test_b22_minimal_profile_stays_unknown(tmp_path):
    # Regression: a genuinely minimal profile must NOT be treated as dangerous tools.
    _make_workspace(tmp_path, ws_mode=0o777)
    cfg = {"tools": {"profile": "minimal"}}
    c = _ctx(cfg, home=str(tmp_path))
    assert check_self_modification(c).status == "UNKNOWN"


def test_b22_bad_fixture_coding_profile_fails(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    cfg = json_load_fixture("bad_b130_coding_profile_no_exec_fields")
    c = _ctx(cfg, home=str(tmp_path))
    result = check_self_modification(c)
    assert result.status == "FAIL", f"Expected FAIL, got {result.status}: {result.detail}"


def test_b22_clean_fixture_minimal_unknown(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    cfg = json_load_fixture("clean_b130_minimal_no_capability")
    c = _ctx(cfg, home=str(tmp_path))
    result = check_self_modification(c)
    assert result.status == "UNKNOWN", f"Expected UNKNOWN, got {result.status}: {result.detail}"


# ---- no workspace at all -> UNKNOWN (no writable targets found) ----
def test_b22_no_workspace_is_unknown(tmp_path):
    c = _ctx(_cfg_with_tools(), home=str(tmp_path))
    assert check_self_modification(c).status == "UNKNOWN"


# ---- Windows (non-POSIX) -> UNKNOWN ----
def test_b22_windows_is_unknown(monkeypatch, tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    from clawseccheck import checks
    monkeypatch.setattr(checks._shared, "_is_posix", lambda: False)
    c = _ctx(_cfg_with_tools(), home=str(tmp_path))
    assert check_self_modification(c).status == "UNKNOWN"


# ---- finding metadata ----
def test_b22_finding_has_correct_severity(tmp_path):
    _make_workspace(tmp_path, ws_mode=0o777)
    c = _ctx(_cfg_with_tools(), home=str(tmp_path))
    result = check_self_modification(c)
    assert result.severity == "HIGH"
    assert result.scored is True
