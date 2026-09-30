"""C-641: B4 must not say "Execution is sandboxed." for `sandbox.mode: non-main`.

`non-main` sandboxes only an agent's NON-main sessions; its own main session (where an
operator usually works) runs exec tooling on the host (vendor `shouldSandboxSession`:
`sessionKey !== mainSessionKey`). So B4 WARNs for it, PASSes only for `all`, and every
branch that sits ahead of the final fall-through (FAIL evidence, per-agent FAIL, unset,
`off`) is unchanged.

Offline, read-only, stdlib only; builds configs in-test.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_sandbox
from clawseccheck.collector import Context
from clawseccheck.toolpolicy import _sandbox_confines

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_PASS_DETAIL = "Execution is sandboxed."
_PASS_FIX = "Keep sandbox mode enabled."


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _cfg(mode, **extra_sandbox) -> dict:
    """An otherwise-safe sandbox (bridge network, read-only workspace); only *mode* varies."""
    sandbox = {
        "mode": mode,
        "workspaceAccess": "ro",
        "docker": {"network": "bridge"},
    }
    sandbox.update(extra_sandbox)
    return {"agents": {"defaults": {"sandbox": sandbox}}}


# ---------------------------------------------------------------------------
# Clean: mode "all" is unchanged (text is hashed by baseline.fingerprint())
# ---------------------------------------------------------------------------

def test_mode_all_still_passes_with_byte_identical_text():
    f = check_sandbox(_ctx(_cfg("all")))
    assert f.status == PASS
    assert f.detail == _PASS_DETAIL
    assert f.fix == _PASS_FIX


# ---------------------------------------------------------------------------
# Bad: mode "non-main" WARNs and never claims execution is sandboxed
# ---------------------------------------------------------------------------

def test_mode_non_main_warns_with_a_qualified_message():
    f = check_sandbox(_ctx(_cfg("non-main")))
    assert f.status == WARN
    assert "Execution is sandboxed" not in f.detail
    assert "main session" in f.detail
    assert "allowing" in f.detail  # docs/CHECK_AUTHORING.md: name the consequence
    assert "'all'" in f.fix
    # B-738 retired this offer: 'non-main' does not contain the agent's own main session.
    assert "'non-main' or 'all'" not in f.fix
    assert f.evidence == ["agents.defaults.sandbox.mode=non-main"]


def test_non_main_wording_is_one_byte_safe():
    """CI publish guard: no character above U+00FF in shipped text."""
    f = check_sandbox(_ctx(_cfg("non-main")))
    assert all(ord(ch) <= 0xFF for ch in f.detail + f.fix)


def test_non_main_wording_does_not_claim_the_running_session_is_unsandboxed():
    """B-712: which session is running has no static answer. B4 states the CONFIG property
    (an unsandboxed main session exists), never "this session is unsandboxed"."""
    f = check_sandbox(_ctx(_cfg("non-main")))
    for banned in ("this session", "current session", "running session"):
        assert banned not in f.detail.lower()


def _copy_home_safe_with_mode(tmp_path: Path, mode: str) -> Path:
    home = tmp_path / f"home_{mode.replace('-', '_')}"
    shutil.copytree(FIXTURES / "home_safe", home)
    cfg_file = home / "openclaw.json"
    text = cfg_file.read_text(encoding="utf-8")
    assert text.count('"mode": "non-main"') == 1
    cfg_file.write_text(text.replace('"mode": "non-main"', f'"mode": "{mode}"'), encoding="utf-8")
    cfg_file.chmod(0o600)
    return home


def test_home_safe_fixture_b4_warns_and_costs_one_step_versus_mode_all(tmp_path):
    _, findings_nm, score_nm = audit(FIXTURES / "home_safe", include_native=False)
    home_all = _copy_home_safe_with_mode(tmp_path, "all")
    _, findings_all, score_all = audit(home_all, include_native=False)

    b4_nm = next(f for f in findings_nm if f.id == "B4")
    b4_all = next(f for f in findings_all if f.id == "B4")
    assert b4_nm.status == WARN
    assert b4_all.status == PASS
    assert b4_all.detail == _PASS_DETAIL

    assert score_all.score > score_nm.score
    assert score_all.grade == score_nm.grade  # a WARN, never a cap

    # Positive control for the score claim: B4 is the ONLY verdict that moved.
    moved = {
        f.id for f in findings_nm
        if {g.id: g.status for g in findings_all}.get(f.id) != f.status
    }
    assert moved == {"B4"}, moved


# ---------------------------------------------------------------------------
# Precedence / unchanged branches: only the final fall-through moved
# ---------------------------------------------------------------------------

def test_mode_off_still_fails_with_the_off_evidence():
    f = check_sandbox(_ctx(_cfg("off")))
    assert f.status == FAIL
    assert any("sandbox.mode is off" in line for line in f.evidence)


def test_mode_unset_with_exec_still_warns_not_set():
    cfg = {"tools": {"exec": {"mode": "ask"}}}
    f = check_sandbox(_ctx(cfg))
    assert f.status == WARN
    assert "not set" in f.detail
    assert "non-main" not in f.detail  # the new branch must not leak into this one


def test_mode_unset_without_exec_still_unknown_not_applicable():
    f = check_sandbox(_ctx({"agents": {"defaults": {}}}))
    assert f.status == UNKNOWN
    assert "not applicable" in f.detail


def test_non_main_with_docker_sock_bind_still_fails():
    cfg = _cfg("non-main", docker={"binds": ["/var/run/docker.sock:/var/run/docker.sock"]})
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    assert any("docker.sock" in line for line in f.evidence)


def test_non_main_with_malformed_binds_still_fails_closed():
    cfg = _cfg("non-main", docker={"binds": {"not": "a bind spec"}})
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL


def test_non_main_with_host_network_still_fails():
    cfg = _cfg("non-main", docker={"network": "host"})
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    assert any("network=host" in line for line in f.evidence)


def test_non_main_with_writable_workspace_still_fails():
    f = check_sandbox(_ctx(_cfg("non-main", workspaceAccess="rw")))
    assert f.status == FAIL
    assert any("workspaceAccess=rw" in line for line in f.evidence)


def test_non_main_with_a_per_agent_off_override_still_fails_in_the_list_shape():
    cfg = _cfg("non-main")
    cfg["agents"]["list"] = [{"id": "helper", "sandbox": {"mode": "off"}}]
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    assert any("sandbox.mode=off" in line for line in f.evidence)


def test_non_main_with_a_per_agent_off_override_still_fails_in_the_entries_shape():
    cfg = _cfg("non-main")
    cfg["agents"]["entries"] = {"helper": {"sandbox": {"mode": "off"}}}
    f = check_sandbox(_ctx(cfg))
    assert f.status == FAIL
    assert any("sandbox.mode=off" in line for line in f.evidence)


# ---------------------------------------------------------------------------
# Consistency with B-712
# ---------------------------------------------------------------------------

def test_b4_warn_agrees_with_sandbox_confines_having_no_static_answer():
    """`_sandbox_confines` is None for `non-main` (no static answer for the RUNNING session)
    while B4 WARNs: B4 states a config property - an unsandboxed main session EXISTS - not
    which session is running. The two are consistent, and neither says "confined"."""
    cfg = _cfg("non-main")
    assert _sandbox_confines(cfg, "main", None) is None
    assert check_sandbox(_ctx(cfg)).status == WARN
