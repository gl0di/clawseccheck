"""B-673 — B4 convicted a per-agent docker bind that the runtime throws away.

`_peragent_sandbox_evidence` reported every `sandbox.docker.binds` entry it found, and
`check_sandbox` turns any entry from that list into a hard FAIL. Two false FAILs lived in
those three lines, and both are Golden Rule #5 violations:

1. **No scope gate.** Under `sandbox.scope: "shared"` — at either level, or the legacy
   `perSession: false` — OpenClaw discards this agent's entire `sandbox.docker`, so the
   binds never reach a container. We were accusing a user of mounting docker.sock on a
   config where the mount does not happen.
The first version of this fix ALSO excused a verifiably read-only bind, borrowing
`_bind_mode_is_ro` from `risk.py`. The C-135 pass killed that half and was right — see
`test_a_read_only_bind_is_still_reported` for the measurement. Only the scope gate survives.

GROUNDED BY EXECUTION against the installed openclaw@2026.8.2, not read:

    resolveSandboxConfigForAgent, dist/config-*.js
      scope=shared at GLOBAL   -> binds ["/g:/g"]              (the agent's are gone)
      scope=shared at AGENT    -> binds null
      default (scope=agent)    -> binds ["/g:/g", "/a:/a"]     (a UNION, not an override)

A note on how that measurement was almost got wrong: the first probe put `scope` under
`sandbox.docker.scope` and saw no discarding at all. The schema says `sandbox.scope`
(`agents.entries.<key>.sandbox.scope`), so the probe was exercising an unrecognised key and
its clean result meant nothing. Corrected before any of this was written.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck.catalog import FAIL
from clawseccheck.checks import _resolve_sandbox_scope
from clawseccheck.collector import collect

SOCK = "/var/run/docker.sock:/var/run/docker.sock"


def _b4(cfg):
    home = Path(tempfile.mkdtemp(prefix="b673-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = "2026.8.2"
    return next(f for f in C.run_all(ctx) if f.id == "B4")


def _bind_evidence(finding):
    return [e for e in (finding.evidence or []) if "binds" in e]


def _network_evidence(finding):
    return [e for e in (finding.evidence or []) if "network" in e]


def _agent(sandbox, defaults=None):
    cfg = {"agents": {"entries": {"worker": {"sandbox": sandbox}}}}
    if defaults is not None:
        cfg["agents"]["defaults"] = {"sandbox": defaults}
    return cfg


# ======================================================================================
# 1. The false FAILs this fixes
# ======================================================================================

@pytest.mark.parametrize("cfg,why", [
    (_agent({"scope": "shared", "docker": {"binds": [SOCK]}}),
     "scope=shared on the agent — the runtime drops the agent's whole sandbox.docker"),
    (_agent({"docker": {"binds": [SOCK]}}, defaults={"scope": "shared"}),
     "scope=shared inherited from defaults — resolveSandboxScope reads defaults second"),
    (_agent({"perSession": False, "docker": {"binds": [SOCK]}}),
     "the legacy boolean folds to 'shared' and must be honoured the same way"),
], ids=["shared-agent", "shared-defaults", "legacy-perSession"])
def test_a_bind_that_cannot_bite_is_not_reported(cfg, why):
    f = _b4(cfg)
    assert not _bind_evidence(f), f"{why}\n  got: {_bind_evidence(f)}"
    assert f.status != FAIL, why


@pytest.mark.parametrize("cfg,why", [
    (_agent({"scope": "shared", "docker": {"network": "host"}}),
     "scope=shared on the agent — the runtime drops the agent's whole sandbox.docker, "
     "network included, before resolveSandboxDockerConfig ever reads it"),
    (_agent({"docker": {"network": "host"}}, defaults={"scope": "shared"}),
     "scope=shared inherited from defaults — same discard, same object"),
], ids=["shared-agent", "shared-defaults"])
def test_a_network_leg_that_cannot_bite_is_not_reported(cfg, why):
    """The sibling of `test_a_bind_that_cannot_bite_is_not_reported`: `docker.network` sits
    in the SAME `sandbox.docker` object as `docker.binds` and is discarded by the vendor
    under the identical condition, so it needs the identical gate. Left ungated, this is a
    HIGH FAIL asserting "no network isolation" about a config the runtime isolates
    completely (shared scope with no global docker resolves network to "none")."""
    f = _b4(cfg)
    assert not _network_evidence(f), f"{why}\n  got: {_network_evidence(f)}"
    assert f.status != FAIL, why


# ======================================================================================
# 2. The controls — without these, "never report a bind" passes everything above
# ======================================================================================

@pytest.mark.parametrize("sandbox,expect_sock", [
    ({"docker": {"binds": [SOCK]}}, True),
    ({"docker": {"binds": ["/srv:/srv:rw"]}}, False),
    ({"docker": {"binds": ["/srv:/srv"]}}, False),
    ({"scope": "agent", "docker": {"binds": [SOCK]}}, True),
    ({"scope": "session", "docker": {"binds": [SOCK]}}, True),
], ids=["default-scope-sock", "explicit-rw", "no-mode-suffix", "scope-agent", "scope-session"])
def test_a_bind_that_really_mounts_is_still_a_fail(sandbox, expect_sock):
    """`scope: "session"` is the sharpest of these: it is not `"agent"`, so a gate written as
    `== "agent"` rather than `!= "shared"` would wrongly silence it — and `session` is a
    per-session container that really does get the bind."""
    f = _b4(_agent(sandbox))
    assert f.status == FAIL
    ev = _bind_evidence(f)
    assert ev, "a bind that mounts must still be reported"
    assert any("docker.sock" in e for e in ev) is expect_sock


@pytest.mark.parametrize("sandbox", [
    {"docker": {"network": "host"}},
    {"scope": "agent", "docker": {"network": "host"}},
    {"scope": "session", "docker": {"network": "host"}},
], ids=["default-scope", "scope-agent", "scope-session"])
def test_a_network_leg_that_really_applies_is_still_a_fail(sandbox):
    """Sibling control for the network leg: outside shared scope this agent's own
    `docker.network` really does apply, so gating it must not silence a real "host"
    network."""
    f = _b4(_agent(sandbox))
    assert f.status == FAIL
    assert _network_evidence(f), "a network=host that applies must still be reported"


def test_a_writable_bind_beside_a_read_only_one_is_still_reported():
    """The narrowing is per-ENTRY, not per-server: one `:ro` entry must not excuse the
    writable one sitting next to it."""
    f = _b4(_agent({"docker": {"binds": ["/etc:/etc:ro", "/srv:/srv:rw"]}}))
    assert f.status == FAIL
    assert _bind_evidence(f)


def test_a_read_only_docker_sock_is_reported_like_any_other():
    """Written the other way round in the first version of this fix, which expected `:ro` to
    suppress the container-escape line. It must not: OpenClaw's validator blocks every
    docker.sock spelling identically, mode included, so `:ro` says nothing about whether the
    operator meant to grant host control. Reporting both spellings the same way is the
    consistent answer, and it is also the pre-existing one."""
    f = _b4(_agent({"docker": {"binds": ["/var/run/docker.sock:/var/run/docker.sock:ro"]}}))
    assert f.status == FAIL
    assert any("container escape" in e for e in (f.evidence or []))


# ======================================================================================
# 3. The helpers, and the fact that they are SHARED rather than a fourth copy
# ======================================================================================

def test_the_scope_resolver_mirrors_the_vendor():
    """Agent first, defaults second, then the legacy boolean, then "agent"."""
    assert _resolve_sandbox_scope({"scope": "shared"}, {}) == "shared"
    assert _resolve_sandbox_scope({}, {"scope": "shared"}) == "shared"
    assert _resolve_sandbox_scope({"scope": "agent"}, {"scope": "shared"}) == "agent"
    assert _resolve_sandbox_scope({"perSession": False}, {}) == "shared"
    assert _resolve_sandbox_scope({"perSession": True}, {}) == "session"
    assert _resolve_sandbox_scope({}, {}) == "agent"


def test_the_helpers_live_in_one_place_only():
    """B-673's root cause was FOUR independently-drifting copies of this model — the correct
    one in `risk.py` (Layer 3, unreachable from checks), a partial one in `toolpolicy.py`, a
    crude one here, and a one-liner in `report.py`. The fix moved the vetted pair DOWN into
    the Layer-2 leaf so there is one implementation.

    Asserted structurally, because a fifth copy would be invisible to every behavioural test
    above: the definitions must exist in `_shared.py` and NOT be redefined in `risk.py` or in
    the check module that consumes them.
    """
    root = Path(__file__).resolve().parent.parent / "clawseccheck"
    shared = (root / "checks" / "_shared.py").read_text(encoding="utf-8")
    for name in ("_bind_mode_is_ro", "_resolve_sandbox_scope", "_sandbox_has_writable_bind"):
        assert f"def {name}(" in shared, f"{name} should be defined in the leaf"
    for other in (root / "risk.py", root / "checks" / "_config.py"):
        text = other.read_text(encoding="utf-8")
        for name in ("_bind_mode_is_ro", "_resolve_sandbox_scope"):
            assert f"def {name}(" not in text, (
                f"{other.name} redefines {name} — that is the fourth-copy problem this "
                f"task exists to remove")


# ======================================================================================
# 4. What the C-135 pass found: `:ro` is NOT a discriminator, and must not become one
# ======================================================================================

@pytest.mark.parametrize("bind", [
    "/etc:/etc:ro",
    "/home/glodi/.openclaw:/oc:ro",
    "/var/run/docker.sock:/var/run/docker.sock:ro",
    "/srv:/srv:ro,z",
], ids=["etc", "openclaw-home", "docker-sock", "ro-with-label"])
def test_a_read_only_bind_is_still_reported(bind):
    """The first version of this fix excused `:ro` binds. That was a FALSE NEGATIVE and the
    adversarial pass proved it by executing OpenClaw's own validator:

      * `getBlockedBindReason` (dist/validate-sandbox-security-*.js) parses ONLY the source
        path and never reads the mode segment. `/var/run/docker.sock:...:ro` and the same
        bind without `:ro` return an IDENTICAL blocked verdict — the vendor assigns `:ro`
        zero security value here.
      * And the vendor's blocklist has a hole `:ro` walks through. `~/.ssh`, `/etc`, `/` and
        the docker.sock spellings are blocked; **`~/.openclaw` is not** — it is a sibling of
        the blocked `~/.config`/`~/.ssh` entries and matches none of them. Measured:
        `/home/<user>/.openclaw:/oc:ro` is ALLOWED and mounts. That directory holds
        `credentials/` and the state DB with live OAuth tokens, so a read-only mount of it
        is a total credential read.

    `risk.py`'s "a `:ro` bind is information disclosure, a different risk class" is true for
    RISK-12, a write/tamper chain. It is false for B4, whose remediation says "drop host and
    docker.sock binds" with no mode qualifier.
    """
    f = _b4(_agent({"docker": {"binds": [bind]}}))
    assert f.status == FAIL, f"a read-only bind still mounts: {bind}"
    assert _bind_evidence(f)


def test_the_ro_helper_is_not_wired_into_this_check():
    """Structural, because the behavioural tests above would pass again the moment someone
    re-adds the narrowing for a bind the vendor happens to block anyway. `_bind_mode_is_ro`
    still exists — RISK-12 needs it — it just must not gate B4."""
    src = (Path(__file__).resolve().parent.parent
           / "clawseccheck" / "checks" / "_config.py").read_text(encoding="utf-8")
    # The CALL, not the name. The comment above the fix explains why the narrowing was
    # removed and necessarily says `_bind_mode_is_ro` to do so; a scan that reads its own
    # explanation as the violation can only be satisfied by deleting the explanation.
    # (Third time this trap has come up — F-183's `SELECT *`, B-703's "subprocess".)
    assert "_bind_mode_is_ro(" not in src, (
        "B4 must not narrow on the bind mode: OpenClaw's own validator is mode-blind, and "
        "the paths it does NOT block (notably ~/.openclaw) are exactly where a read-only "
        "mount is still a full credential read")


def test_the_defaults_branch_and_the_per_agent_branch_agree_on_a_read_only_bind():
    """The C-135 pass also caught an internal inconsistency in the first version: the same
    `~/.openclaw:...:ro` bind FAILed at `agents.defaults` and went silent per-agent. Whatever
    the rule is, the two branches have to share it — a finding that depends on which half of
    the config you wrote it in is not a finding about the setup."""
    bind = "/home/glodi/.openclaw:/oc:ro"
    per_agent = _b4(_agent({"docker": {"binds": [bind]}}))
    defaults = _b4({"agents": {"defaults": {"sandbox": {"docker": {"binds": [bind]}}}}})
    assert per_agent.status == defaults.status == FAIL
