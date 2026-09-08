"""B-497 — RISK-12 must respect VERIFIED sandbox containment of filesystem writes.

RISK-12 ("Untrusted input + broad filesystem-write = tamper / persistence") used to
fire on B55 FAIL/WARN + untrusted ingress regardless of the sandbox, so it kept
reporting a tamper/persistence path even after the operator closed it with
`agents.defaults.sandbox.mode: "all"` + `agents.defaults.sandbox.workspaceAccess: "ro"`.

Field paths/values grounded against the installed OpenClaw dist
(~/.npm-global/lib/node_modules/openclaw), see `_fs_writes_contained`'s docstring in
clawseccheck/risk.py for the exact grep citations. This suite pins:

  1. suppressed only when BOTH mode='all' AND workspaceAccess in ('ro','none')
  2. negative controls -- mode='off', mode='non-main' (main session stays on host per
     dist/launch-BmPwk1y9.js), and workspaceAccess='rw' -- must all still fire
  3. an absent/unparseable containment key is NOT treated as containment (ambiguity
     must not silently suppress a real chain)
  4. C-135 ROUND 2: a per-agent `agents.list[].sandbox` override that re-exposes the
     host must NOT be suppressed even when `agents.defaults.sandbox` is safe -- this
     is the exact C-058 gap already fixed for B4 (checks/_config.py's
     `_peragent_sandbox_evidence`), reintroduced here in round 1 and closed in round 2.
     Includes the `??`-semantics case: a per-agent override that sets only
     `workspaceAccess` (no `mode`) still inherits `mode` from the default per-field,
     not per-object.
  5. C-135 ROUND 3: `docker.binds` (custom binds are host-writable with no read-only
     flag, dist/docker-Hq4HIYYD.js:977, and defaults/per-agent binds are CONCATENATED
     not replaced, dist/config-Dy4vED5-.js:57) and `backend` (only "docker" is a
     backend the ro/none semantics are grounded against; "ssh" or any unmodelled
     value must not be certified as contained) -- both checked at BOTH levels
     independently, mirroring `_peragent_sandbox_evidence` rather than a third reader.
  6. C-135 ROUND 4 -- two false positives (round 3's blanket bind check was too
     blunt) and one false negative (a fourth axis round 3 never read), each
     reproduced against the real engine before being fixed, each FP fix carrying a
     positive control proving the uncontained case still fires:
       * FP1: a verifiably `:ro`-suffixed bind IS genuinely contained (Docker's own
         native bind-mode enforcement) -- narrowed via `_bind_mode_is_ro`; a bind
         with no mode suffix, an explicit `:rw`, or a mix, must still fire.
       * FP2: `scope: "shared"` (or legacy `perSession: false`) makes OpenClaw
         discard a per-agent's OWN `docker.binds` entirely -- must not defeat
         containment; any OTHER scope (or none declared) must still fire.
       * FN: `tools.exec.host` ("gateway"/"node") routes exec OFF the sandboxed
         container regardless of mode/workspaceAccess -- a fourth, co-equal axis at
         BOTH the top-level `tools.exec.host` and per-agent
         `agents.list[N].tools.exec.host`.
     Mutation-proven: `test_mutants_are_caught_by_the_positive_controls` monkeypatches
     the exact predicates each FP fix introduced and asserts the positive-control
     configs above flip to a wrongly-silent result under the mutant -- proving those
     tests are load-bearing, not vacuous.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.collector import Context
from clawseccheck.checks import run_all
from clawseccheck.risk import risk_paths

_UNTRUSTED_INGRESS_WRITE_CFG = {
    "channels": {"telegram": {"dmPolicy": "open"}},
    "tools": {"allow": ["fs_write"]},
}


def _fires(sandbox_extra: dict | None) -> bool:
    cfg = dict(_UNTRUSTED_INGRESS_WRITE_CFG)
    if sandbox_extra is not None:
        cfg = {**cfg, "agents": {"defaults": {"sandbox": sandbox_extra}}}
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    findings = run_all(ctx)
    ids = {p.id for p in risk_paths(ctx, findings)}
    return "RISK-12" in ids


def test_risk12_fires_with_no_sandbox_configured_at_all():
    # Sanity: the base shape (no containment declared) still fires -- this is the
    # pre-existing behavior the suppression must not disturb.
    assert _fires(None) is True


@pytest.mark.parametrize(
    "sandbox_extra",
    [
        {"mode": "all", "workspaceAccess": "ro"},
        {"mode": "all", "workspaceAccess": "none"},
    ],
)
def test_risk12_suppressed_when_genuinely_contained(sandbox_extra):
    assert _fires(sandbox_extra) is False


@pytest.mark.parametrize(
    "sandbox_extra",
    [
        {"mode": "off", "workspaceAccess": "ro"},
        {"mode": "non-main", "workspaceAccess": "ro"},
        {"mode": "non-main", "workspaceAccess": "none"},
        {"mode": "all", "workspaceAccess": "rw"},
        {"mode": "all"},  # workspaceAccess absent -- ambiguous, must NOT suppress
        {"workspaceAccess": "ro"},  # mode absent -- ambiguous, must NOT suppress
        {},  # both absent
    ],
)
def test_risk12_negative_control_still_fires_when_not_genuinely_contained(sandbox_extra):
    """The required negative control: containment is NOT properly set -> warning stays."""
    assert _fires(sandbox_extra) is True


# ── C-135 round 2: per-agent override (C-058 reintroduction) ──────────────────────

def _fires_with_agent_list(default_sandbox: dict, agent_list: list) -> bool:
    cfg = {
        **_UNTRUSTED_INGRESS_WRITE_CFG,
        "agents": {"defaults": {"sandbox": default_sandbox}, "list": agent_list},
    }
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    findings = run_all(ctx)
    ids = {p.id for p in risk_paths(ctx, findings)}
    return "RISK-12" in ids


_SAFE_DEFAULT = {"mode": "all", "workspaceAccess": "ro"}


@pytest.mark.parametrize(
    "agent_sandbox",
    [
        {"mode": "off"},
        {"mode": "non-main"},
        {"workspaceAccess": "rw"},  # mode omitted -> inherits "all" from default per-field
        {"mode": "off", "workspaceAccess": "rw"},
    ],
)
def test_risk12_fires_when_per_agent_override_re_exposes_host(agent_sandbox):
    """The coordinator's exact repro shape: safe default, unsafe NAMED agent override."""
    agent_list = [{"id": "main", "name": "main", "sandbox": agent_sandbox}]
    assert _fires_with_agent_list(_SAFE_DEFAULT, agent_list) is True


@pytest.mark.parametrize(
    "agent_list",
    [
        [{"id": "main", "name": "main"}],  # no sandbox override -> fully inherits safe default
        [{"id": "main", "name": "main", "sandbox": {"mode": "all", "workspaceAccess": "none"}}],
        [{"id": "main", "name": "main"}, {"id": "aux", "name": "aux", "sandbox": {"mode": "all"}}],
    ],
)
def test_risk12_still_suppressed_when_every_agent_stays_contained(agent_list):
    assert _fires_with_agent_list(_SAFE_DEFAULT, agent_list) is False


# ── C-135 round 3: docker.binds + backend (one field deeper than round 2) ─────────

def _fires_with_default_sandbox(default_sandbox: dict, agent_list: list | None = None) -> bool:
    agents = {"defaults": {"sandbox": default_sandbox}}
    if agent_list is not None:
        agents["list"] = agent_list
    cfg = {**_UNTRUSTED_INGRESS_WRITE_CFG, "agents": agents}
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    findings = run_all(ctx)
    ids = {p.id for p in risk_paths(ctx, findings)}
    return "RISK-12" in ids


def test_risk12_fires_when_defaults_declare_docker_binds():
    # Coordinator's exact repro: mode=all + workspaceAccess=ro + docker.binds.
    sandbox = {"mode": "all", "workspaceAccess": "ro", "docker": {"binds": ["/home:/home"]}}
    assert _fires_with_default_sandbox(sandbox) is True


def test_risk12_fires_when_only_per_agent_declares_docker_binds():
    # Safe default, but the agent's OWN docker.binds is concatenated onto it
    # (dist/config-Dy4vED5-.js:57), not replaced.
    agent_list = [
        {"id": "main", "name": "main", "sandbox": {"docker": {"binds": ["/data:/data"]}}},
    ]
    assert _fires_with_default_sandbox(_SAFE_DEFAULT, agent_list) is True


def test_risk12_stays_suppressed_with_empty_binds_list():
    sandbox = {"mode": "all", "workspaceAccess": "ro", "docker": {"binds": []}}
    assert _fires_with_default_sandbox(sandbox) is False


@pytest.mark.parametrize("backend", ["ssh", "some-plugin-backend"])
def test_risk12_fires_when_defaults_backend_is_not_docker(backend):
    sandbox = {"mode": "all", "workspaceAccess": "ro", "backend": backend}
    assert _fires_with_default_sandbox(sandbox) is True


def test_risk12_fires_when_only_per_agent_backend_is_not_docker():
    agent_list = [{"id": "main", "name": "main", "sandbox": {"backend": "ssh"}}]
    assert _fires_with_default_sandbox(_SAFE_DEFAULT, agent_list) is True


def test_risk12_stays_suppressed_when_backend_is_explicitly_docker():
    sandbox = {"mode": "all", "workspaceAccess": "ro", "backend": "docker"}
    assert _fires_with_default_sandbox(sandbox) is False


def test_risk12_stays_suppressed_when_backend_is_implicit_default():
    # backend absent -> resolves to "docker" (dist/config-Dy4vED5-.js:154).
    sandbox = {"mode": "all", "workspaceAccess": "ro"}
    assert _fires_with_default_sandbox(sandbox) is False


# ── C-135 round 4: FP1 (bind mode), FP2 (scope=shared), FN (tools.exec.host) ──────

def _fires_full(agents: dict, tools: dict | None = None) -> bool:
    cfg = {**_UNTRUSTED_INGRESS_WRITE_CFG, "agents": agents}
    if tools is not None:
        cfg = {**cfg, "tools": {**cfg["tools"], **tools}}
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    findings = run_all(ctx)
    ids = {p.id for p in risk_paths(ctx, findings)}
    return "RISK-12" in ids


# -- FP1: a verifiably ':ro' bind is genuinely contained (Docker's own bind-mode
# enforcement) -- narrower than round 3's blanket "any declared bind defeats it".

def test_risk12_stays_suppressed_for_a_readonly_ro_bind_at_defaults():
    sandbox = {"mode": "all", "workspaceAccess": "ro", "docker": {"binds": ["/srv/data:/data:ro"]}}
    assert _fires_full({"defaults": {"sandbox": sandbox}}) is False


def test_risk12_stays_suppressed_for_a_readonly_ro_bind_per_agent():
    agents = {
        "defaults": {"sandbox": _SAFE_DEFAULT},
        "list": [{"id": "main", "name": "main", "sandbox": {"docker": {"binds": ["/srv/data:/data:ro"]}}}],
    }
    assert _fires_full(agents) is False


@pytest.mark.parametrize(
    "binds",
    [
        ["/srv/data:/data"],           # no mode suffix -> Docker's rw default
        ["/srv/data:/data:rw"],        # explicit rw
        ["/srv/data:/data:ro", "/other:/x"],  # ANY non-ro bind still defeats it
        [{"not": "a string"}],         # unparseable entry -> fail closed
    ],
)
def test_risk12_fp1_positive_control_non_ro_bind_still_fires(binds):
    """Required positive control: a bind that is NOT verifiably ':ro' must still fire."""
    sandbox = {"mode": "all", "workspaceAccess": "ro", "docker": {"binds": binds}}
    assert _fires_full({"defaults": {"sandbox": sandbox}}) is True


def test_risk12_fires_when_defaults_docker_field_is_malformed_shape():
    # Consistency fix: a PRESENT-but-malformed `docker` key fails closed, unlike an
    # absent one.
    sandbox = {"mode": "all", "workspaceAccess": "ro", "docker": "not-a-dict"}
    assert _fires_full({"defaults": {"sandbox": sandbox}}) is True


# -- FP1 follow-up (C-135 round 4, second pass): Docker's mode is a COMMA-SEPARATED
# option list, not a single token -- ":ro,z" is the standard SELinux-host form
# (Fedora/RHEL). The equality-against-whole-segment check wrongly called this
# writable; the suite previously had no multi-option mode case at all.

@pytest.mark.parametrize("mode", ["ro,z", "z,ro", "ro,rshared", "ro,Z,rshared"])
def test_risk12_stays_suppressed_for_a_multi_option_ro_bind(mode):
    sandbox = {
        "mode": "all", "workspaceAccess": "ro",
        "docker": {"binds": [f"/srv/data:/data:{mode}"]},
    }
    assert _fires_full({"defaults": {"sandbox": sandbox}}) is False


def test_risk12_fp1_followup_positive_control_rw_ro_still_fires():
    """Required control: 'rw,ro' -- a spec Docker itself rejects outright -- must
    stay on the fail-closed side, not be credited as read-only."""
    sandbox = {
        "mode": "all", "workspaceAccess": "ro",
        "docker": {"binds": ["/srv/data:/data:rw,ro"]},
    }
    assert _fires_full({"defaults": {"sandbox": sandbox}}) is True


# -- FP2: scope:"shared" (or legacy perSession:false) discards a per-agent's OWN
# docker.binds entirely -- must not defeat containment.

@pytest.mark.parametrize("agent_sandbox_extra", [{"scope": "shared"}, {"perSession": False}])
def test_risk12_stays_suppressed_when_shared_scope_discards_the_binds(agent_sandbox_extra):
    agents = {
        "defaults": {"sandbox": _SAFE_DEFAULT},
        "list": [{
            "id": "main", "name": "main",
            "sandbox": {**agent_sandbox_extra, "docker": {"binds": ["/data:/data"]}},
        }],
    }
    assert _fires_full(agents) is False


@pytest.mark.parametrize(
    "agent_sandbox_extra",
    [{"scope": "session"}, {"scope": "agent"}, {}],  # anything but scope=="shared"
)
def test_risk12_fp2_positive_control_non_shared_scope_still_fires(agent_sandbox_extra):
    """Required positive control: a NON-shared scope's own bind must still fire."""
    agents = {
        "defaults": {"sandbox": _SAFE_DEFAULT},
        "list": [{
            "id": "main", "name": "main",
            "sandbox": {**agent_sandbox_extra, "docker": {"binds": ["/data:/data"]}},
        }],
    }
    assert _fires_full(agents) is True


def test_risk12_shared_scope_does_not_excuse_defaults_level_binds():
    # scope only gates the PER-AGENT leg; defaults-level binds are never discarded.
    sandbox = {"mode": "all", "workspaceAccess": "ro", "docker": {"binds": ["/data:/data"]}}
    agents = {
        "defaults": {"sandbox": sandbox},
        "list": [{"id": "main", "name": "main", "sandbox": {"scope": "shared"}}],
    }
    assert _fires_full(agents) is True


# -- FN: tools.exec.host is a co-equal fourth axis, not a sandbox sub-field.

@pytest.mark.parametrize("host", ["gateway", "node"])
def test_risk12_fires_when_defaults_exec_host_escapes_the_sandbox(host):
    assert _fires_full(
        {"defaults": {"sandbox": _SAFE_DEFAULT}}, tools={"exec": {"host": host}}
    ) is True


def test_risk12_fires_when_only_per_agent_exec_host_escapes_the_sandbox():
    agents = {
        "defaults": {"sandbox": _SAFE_DEFAULT},
        "list": [{"id": "main", "name": "main", "tools": {"exec": {"host": "gateway"}}}],
    }
    assert _fires_full(agents) is True


@pytest.mark.parametrize("host", ["auto", "sandbox"])
def test_risk12_stays_suppressed_for_safe_exec_host_values(host):
    assert _fires_full(
        {"defaults": {"sandbox": _SAFE_DEFAULT}}, tools={"exec": {"host": host}}
    ) is False


def test_risk12_stays_suppressed_when_exec_host_is_absent():
    assert _fires_full({"defaults": {"sandbox": _SAFE_DEFAULT}}) is False


# -- Mutation proof: the positive controls above are load-bearing, not vacuous.

def test_mutants_are_caught_by_the_positive_controls(monkeypatch):
    import clawseccheck.risk as risk_mod

    # Mutant A: pretend every bind is read-only -- must flip FP1's positive control
    # (a real :rw bind) from "fires" to "wrongly silent".
    #
    # Patched at `checks._shared`, not at `risk`: B-673 moved `_bind_mode_is_ro` and
    # `_sandbox_has_writable_bind` DOWN into the Layer-2 leaf so `checks/_config.py` could
    # stop keeping a cruder copy. The caller moved with it, so the name now resolves in
    # `_shared`'s namespace and patching risk's re-export would no longer reach it -- a
    # mutation that silently stops mutating is worse than no mutation test at all.
    from clawseccheck.checks import _shared as shared_mod

    monkeypatch.setattr(shared_mod, "_bind_mode_is_ro", lambda bind: True)
    sandbox = {"mode": "all", "workspaceAccess": "ro", "docker": {"binds": ["/srv/data:/data:rw"]}}
    assert _fires_full({"defaults": {"sandbox": sandbox}}) is False, (
        "mutant did not flip the FP1 positive control -- that control is vacuous"
    )
    monkeypatch.undo()

    # Mutant B: pretend scope always resolves "shared" -- must flip FP2's positive
    # control (scope="session") from "fires" to "wrongly silent".
    monkeypatch.setattr(risk_mod, "_resolve_sandbox_scope", lambda a, d: "shared")
    agents = {
        "defaults": {"sandbox": _SAFE_DEFAULT},
        "list": [{"id": "main", "name": "main",
                   "sandbox": {"scope": "session", "docker": {"binds": ["/data:/data"]}}}],
    }
    assert _fires_full(agents) is False, (
        "mutant did not flip the FP2 positive control -- that control is vacuous"
    )
    monkeypatch.undo()

    # Mutant C: pretend exec host is always "auto" -- must flip the PER-AGENT FN test
    # (agent tools.exec.host="gateway") from "fires" to "wrongly silent". Targets the
    # per-agent case specifically because the DEFAULTS-level exec.host check reads
    # `tools.exec.host` inline (never calling `_resolve_exec_host`) -- an earlier
    # version of this mutant targeted the defaults-level case and did NOT flip,
    # which is how this distinction was caught.
    monkeypatch.setattr(risk_mod, "_resolve_exec_host", lambda tools, fallback: "auto")
    agents = {
        "defaults": {"sandbox": _SAFE_DEFAULT},
        "list": [{"id": "main", "name": "main", "tools": {"exec": {"host": "gateway"}}}],
    }
    assert _fires_full(agents) is False, "mutant did not flip the FN test -- that test is vacuous"
