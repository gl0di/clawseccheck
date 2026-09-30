"""C-641b: B4 WARNs when a NAMED agent sets its own `sandbox.mode: non-main`.

`non-main` sandboxes only an agent's NON-main sessions; its own main session runs exec tooling
on the host (vendor `shouldSandboxSession`: `sessionKey !== mainSessionKey`). C-641 fixed B4's
verdict for `agents.defaults.sandbox.mode: non-main`. This closes the same reading one level
down: a named agent that sets `sandbox.mode: non-main` under `agents.defaults.sandbox.mode: all`
must not read PASS for B4, because that agent's own main session is on the host. B4 WARNs.

`off` and unset stay exactly as they were, and so does `all`. Offline, read-only, stdlib only;
configs are built in-test.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def _defaults_all(**agents_extra) -> dict:
    """An otherwise-safe `all` sandbox (bridge network, read-only workspace)."""
    agents = {
        "defaults": {
            "sandbox": {"mode": "all", "workspaceAccess": "ro", "docker": {"network": "bridge"}}
        }
    }
    agents.update(agents_extra)
    return {"agents": agents}


def _b4(cfg: dict):
    return check_sandbox(_ctx(cfg))


# ---------------------------------------------------------------------------
# B4: a named agent on non-main under defaults `all`
# ---------------------------------------------------------------------------

def _list_shape(*entries) -> dict:
    return _defaults_all(list=list(entries))


def _entries_shape(**entries) -> dict:
    return _defaults_all(entries=entries)


def test_clean_defaults_all_without_agents_still_passes_byte_identical():
    f = _b4(_defaults_all())
    assert f.status == PASS
    assert f.detail == _PASS_DETAIL
    assert f.fix == _PASS_FIX


def test_clean_agents_that_inherit_or_say_all_still_pass():
    cfg = _list_shape(
        {"id": "plain"},                                   # no sandbox key: inherits `all`
        {"id": "explicit", "sandbox": {"mode": "all"}},    # says `all` itself
        {"id": "tuned", "sandbox": {"workspaceAccess": "ro"}},  # no mode key: inherits
    )
    f = _b4(cfg)
    assert f.status == PASS
    assert f.detail == _PASS_DETAIL and f.fix == _PASS_FIX
    f = _b4(_entries_shape(plain={}, explicit={"sandbox": {"mode": "all"}}))
    assert f.status == PASS
    assert f.detail == _PASS_DETAIL and f.fix == _PASS_FIX


def test_clean_malformed_peragent_sandbox_shapes_do_not_warn_or_crash():
    for bad in (None, "non-main", ["non-main"], 7):
        f = _b4(_list_shape({"id": "x", "sandbox": bad}))
        assert f.status == PASS, (bad, f.status, f.detail)
    # a non-string mode value is not the literal 'non-main'
    f = _b4(_list_shape({"id": "x", "sandbox": {"mode": ["non-main"]}}))
    assert f.status == PASS


@pytest.mark.parametrize(
    "cfg",
    [
        _list_shape({"id": "helper", "sandbox": {"mode": "non-main"}}),
        _entries_shape(helper={"sandbox": {"mode": "non-main"}}),
    ],
    ids=["agents.list", "agents.entries"],
)
def test_bad_peragent_non_main_under_defaults_all_warns(cfg):
    f = _b4(cfg)
    assert f.status == WARN
    assert "Execution is sandboxed" not in f.detail
    assert "main session" in f.detail
    assert "allowing" in f.detail  # docs/CHECK_AUTHORING.md: name the consequence
    assert "'all'" in f.fix
    assert "'non-main' or 'all'" not in f.fix  # the retired B-738 offer
    assert len(f.evidence) == 1
    assert "agent 'helper'" in f.evidence[0]
    assert "sandbox.mode=non-main" in f.evidence[0]


def test_bad_peragent_non_main_names_every_offender_and_prefers_the_name():
    cfg = _list_shape(
        {"id": "a1", "name": "Alpha", "sandbox": {"mode": "non-main"}},
        {"id": "ok", "sandbox": {"mode": "all"}},
        {"id": "a2", "sandbox": {"mode": "non-main"}},
    )
    f = _b4(cfg)
    assert f.status == WARN
    assert [line.split(":")[0] for line in f.evidence] == ["agent 'Alpha'", "agent 'a2'"]


def test_peragent_non_main_wording_is_one_byte_safe_and_config_scoped():
    f = _b4(_list_shape({"id": "helper", "sandbox": {"mode": "non-main"}}))
    assert all(ord(ch) <= 0xFF for ch in f.detail + f.fix + " ".join(f.evidence))
    # B-712: a config property (an unsandboxed main session EXISTS), never "this session".
    for banned in ("this session", "current session", "running session"):
        assert banned not in f.detail.lower()


def test_defaults_non_main_keeps_its_own_text_when_an_agent_also_says_non_main():
    """The defaults-level C-641 branch wins and its text (hashed by fingerprint()) is stable."""
    cfg = _list_shape({"id": "helper", "sandbox": {"mode": "non-main"}})
    cfg["agents"]["defaults"]["sandbox"]["mode"] = "non-main"
    f = _b4(cfg)
    assert f.status == WARN
    assert f.detail.startswith("agents.defaults.sandbox.mode is 'non-main'")
    assert f.evidence == ["agents.defaults.sandbox.mode=non-main"]


# ---------------------------------------------------------------------------
# Precedence: the new WARN never downgrades a FAIL
# ---------------------------------------------------------------------------

def test_peragent_non_main_never_masks_a_fail():
    non_main = {"id": "helper", "sandbox": {"mode": "non-main"}}
    # another agent turned the sandbox off
    f = _b4(_list_shape(non_main, {"id": "bad", "sandbox": {"mode": "off"}}))
    assert f.status == FAIL
    # the same agent also asks for a writable workspace
    f = _b4(_list_shape({"id": "helper", "sandbox": {"mode": "non-main", "workspaceAccess": "rw"}}))
    assert f.status == FAIL
    # defaults carry a docker.sock bind
    cfg = _list_shape(non_main)
    cfg["agents"]["defaults"]["sandbox"]["docker"]["binds"] = [
        "/var/run/docker.sock:/var/run/docker.sock"
    ]
    assert _b4(cfg).status == FAIL
    # defaults carry a malformed binds value (fails closed, as before)
    cfg = _list_shape(non_main)
    cfg["agents"]["defaults"]["sandbox"]["docker"]["binds"] = {"not": "a bind spec"}
    assert _b4(cfg).status == FAIL


# ---------------------------------------------------------------------------
# Unchanged: off / unset (explicit UNKNOWN path included)
# ---------------------------------------------------------------------------

def test_defaults_off_still_fails_and_unset_branches_are_unchanged():
    off = _b4({"agents": {"defaults": {"sandbox": {"mode": "off"}}}})
    assert off.status == FAIL
    assert any("sandbox.mode is off" in line for line in off.evidence)

    # unset + exec tooling: the "not set" WARN, untouched by the per-agent branch
    unset_exec = _b4({"tools": {"exec": {"mode": "ask"}}})
    assert unset_exec.status == WARN and "not set" in unset_exec.detail

    # unset + no exec tooling: UNKNOWN "not applicable", even with a per-agent non-main
    # (documented as unchanged: Dave's ruling was 'keep off/unset unchanged')
    unknown = _b4({"agents": {"list": [{"id": "helper", "sandbox": {"mode": "non-main"}}]}})
    assert unknown.status == UNKNOWN
    assert "not applicable" in unknown.detail


# ---------------------------------------------------------------------------
# Shipped fixtures and the real audit() path (not only check_sandbox in isolation)
# ---------------------------------------------------------------------------

_PERAGENT_FIXTURES = ("clean_b4_peragent_sandbox", "clean_b4_peragent_sandbox_shared_scope")


def _fixture_home_with_agent_mode(tmp_path: Path, name: str, mode: str) -> Path:
    """A tmp copy of a shipped per-agent fixture with the agent's own sandbox mode swapped."""
    cfg = json.loads((FIXTURES / name / "openclaw.json").read_text(encoding="utf-8"))
    cfg["agents"]["list"][0]["sandbox"]["mode"] = mode
    home = tmp_path / f"{name}-{mode}"
    home.mkdir()
    target = home / "openclaw.json"
    target.write_text(json.dumps(cfg), encoding="utf-8")
    target.chmod(0o600)
    return home


@pytest.mark.parametrize("name", _PERAGENT_FIXTURES)
def test_shipped_clean_peragent_fixtures_use_all_and_still_pass(name):
    """These fixtures are the corpus's 'safe per-agent override' examples. They used to say
    `non-main`, which is no longer safe, so they say `all` - and the value is asserted, so a
    later edit cannot quietly turn a clean fixture into a warning one."""
    cfg = json.loads((FIXTURES / name / "openclaw.json").read_text(encoding="utf-8"))
    assert cfg["agents"]["defaults"]["sandbox"]["mode"] == "all"
    assert cfg["agents"]["list"][0]["sandbox"]["mode"] == "all"
    c = Context(home=FIXTURES / name)
    c.config = cfg
    f = check_sandbox(c)
    assert f.status == PASS
    assert f.detail == _PASS_DETAIL and f.fix == _PASS_FIX


@pytest.mark.parametrize("name", _PERAGENT_FIXTURES)
def test_real_audit_warns_on_a_peragent_non_main_and_costs_score(tmp_path, name):
    """Both directions through the real `audit()`: the same fixture with only the agent's
    own mode flipped `all` -> `non-main` goes B4 PASS -> WARN, B4 is the ONLY verdict that
    moves, the score drops, and a WARN never caps the grade."""
    _, f_all, s_all = audit(_fixture_home_with_agent_mode(tmp_path, name, "all"), include_native=False)
    _, f_nm, s_nm = audit(_fixture_home_with_agent_mode(tmp_path, name, "non-main"), include_native=False)
    b4_all = next(f for f in f_all if f.id == "B4")
    b4_nm = next(f for f in f_nm if f.id == "B4")
    assert b4_all.status == PASS and b4_all.detail == _PASS_DETAIL
    assert b4_nm.status == WARN
    assert "Execution is sandboxed" not in b4_nm.detail
    assert s_all.score > s_nm.score
    assert s_all.grade == s_nm.grade
    by_status = {f.id: f.status for f in f_all}
    assert {f.id for f in f_nm if by_status.get(f.id) != f.status} == {"B4"}


# ---------------------------------------------------------------------------
# Consistency with B-712: a config property, not which session is running
# ---------------------------------------------------------------------------

def test_peragent_warn_agrees_with_sandbox_confines_being_undecidable():
    """`_sandbox_confines` is None for a `non-main` agent entry (no static answer for the
    RUNNING session), True for `all`. B4 WARNs for the first - an unsandboxed main session
    EXISTS - and passes the second. Neither side says "this session is unsandboxed"."""
    non_main = {"id": "helper", "sandbox": {"mode": "non-main"}}
    all_ = {"id": "helper", "sandbox": {"mode": "all"}}
    assert _sandbox_confines(_list_shape(non_main), "helper", non_main) is None
    assert _b4(_list_shape(non_main)).status == WARN
    assert _sandbox_confines(_list_shape(all_), "helper", all_) is True
    assert _b4(_list_shape(all_)).status == PASS
