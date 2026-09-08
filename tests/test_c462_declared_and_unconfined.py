"""C-462 — the sensitive-data leg means DECLARED and UNCONFINED, and every source obeys it.

The engine used to hold two answers at once. A file `read` named in `tools.allow` raised
the leg no matter what confined it, while the same tool granted by `tools.profile` — or by
OpenClaw's permissive default, which grants every core tool when no profile is set — only
produced B-666's "cannot determine" WARN. One of those had to give.

The answer is not a matter of taste: OpenClaw's own audit already resolves it. The
predicate behind `security.exposure.open_groups_with_runtime_or_fs` is

    fsUnguarded = fsTools.length > 0 && sandboxMode !== "all" && fsWorkspaceOnly !== true

and the finding it feeds is `critical` only when RUNTIME tools are unguarded — filesystem
exposure alone is `warn`. So the platform says: `workspaceOnly: true` and a full sandbox
are real guards, and an unguarded file read is a warning rather than a headline. That is
exactly where this engine now puts each case.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.checks import _shared, run_all
from clawseccheck.checks._shared import _trifecta_leg_sources
from clawseccheck.collector import Context
from clawseccheck.toolpolicy import confined_scopes

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _sensitive(cfg, attestation=None):
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    if attestation is not None:
        ctx.attestation = attestation
    return _trifecta_leg_sources(ctx)["sensitive data"]


def _a1(cfg):
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    return {f.id: f for f in run_all(ctx)}["A1"]


# ------------------------------------------------------------------ confined ⇒ no leg

@pytest.mark.parametrize(
    "guard",
    [
        {"tools": {"fs": {"workspaceOnly": True}}},
        {"agents": {"defaults": {"sandbox": {"mode": "all"}}}},
    ],
    ids=["workspaceOnly", "sandbox-all"],
)
def test_a_confined_file_read_is_not_a_leg(guard):
    cfg = {"tools": {"allow": ["read"]}}
    for key, value in guard.items():
        cfg[key] = {**cfg.get(key, {}), **value} if isinstance(value, dict) else value
    assert _sensitive(cfg) == []


def test_an_unconfined_file_read_is_still_a_leg():
    assert _sensitive({"tools": {"allow": ["read"]}}) == ["tools.allow entry 'read'"]
    assert _sensitive({"tools": {"allow": ["read"], "fs": {"workspaceOnly": False}}}) != []


def test_one_unconfined_scope_is_enough():
    """The answer is the conjunction over scopes: a global confinement one agent opts out
    of does not confine that agent, and the leg stays up for the whole config."""
    cfg = {
        "tools": {"allow": ["read"], "fs": {"workspaceOnly": True}},
        "agents": {"list": [{"id": "main", "default": True},
                            {"id": "helper", "tools": {"fs": {"workspaceOnly": False}}}]},
    }
    assert confined_scopes(cfg) == [True, False]
    assert _sensitive(cfg) != []


def test_a_lone_declared_agent_is_the_only_scope():
    """`resolveDefaultAgentId` picks the entry marked `default`, else the first one — so a
    config whose only agent opts out has ONE scope, that agent's, and the global surface
    it overrode is not a second opinion to average in."""
    cfg = {
        "tools": {"allow": ["read"], "fs": {"workspaceOnly": True}},
        "agents": {"list": [{"id": "helper", "tools": {"fs": {"workspaceOnly": False}}}]},
    }
    assert confined_scopes(cfg) == [False]
    assert _sensitive(cfg) != []


def test_the_fixture_that_exposed_the_inconsistency():
    from clawseccheck.collector import collect

    ctx = collect(str(FIXTURES / "clean_b283_fs_workspace_confined"))
    assert _trifecta_leg_sources(ctx)["sensitive data"] == []


# ------------------------------------------------- the guard reaches only what it governs

def test_the_guard_does_not_touch_tools_no_filesystem_setting_governs():
    """`tools.fs.workspaceOnly` governs OpenClaw's core fs tools. It does not reach a
    memory tool, a database tool, or a generic name like `fs_read` — which is not even an
    id OpenClaw defines. Filtering those on it would suppress a leg over a control that
    never applied to them."""
    confined = {"fs": {"workspaceOnly": True}}
    for name in ("memory_get", "memory_search"):
        assert _sensitive({"tools": {"allow": [name], **confined}}) != [], name
    for name in ("fs_read", "vault", "db_query"):
        assert _sensitive({"tools": {"allow": [name], **confined}}) != [], name


def test_only_read_is_filesystem_governed():
    assert _shared._FS_GOVERNED_TOOL_IDS == {"read"}
    assert _shared._FS_GOVERNED_TOOL_IDS <= _shared.SENSITIVE_TOOL_IDS


def test_an_attested_read_is_filtered_by_the_same_guard():
    """A declaration is a declaration wherever it comes from, and so is a guard."""
    att = {"agents": [{"name": "bot", "tools": ["read"]}]}
    assert _sensitive({}, att) != []
    assert _sensitive({"tools": {"fs": {"workspaceOnly": True}}}, att) == []


# ------------------------------------------- the default is a WARN, never a CRITICAL leg

def test_a_capability_that_exists_only_by_default_is_not_a_leg():
    """No profile and no allowlist grants every core tool including `read`. Making that a
    leg would fire CRITICAL on any config that never mentioned tools — measured at 21 new
    corpus FAILs, seven of them on `clean_*` fixtures."""
    cfg = {"channels": {"telegram": {"dmPolicy": "open"}},
           "tools": {"web": {"fetch": {"enabled": True}}}}
    assert _sensitive(cfg) == []
    a1 = _a1(cfg)
    assert a1.status == "WARN"
    assert "Cannot determine from config: sensitive data." in a1.detail
    assert sorted(a1.evidence) == ["outbound actions", "untrusted input"]


def test_declaring_the_tool_turns_the_warning_into_a_leg():
    """The same config, with the capability declared, is determined rather than hedged."""
    cfg = {"channels": {"telegram": {"dmPolicy": "open"}},
           "tools": {"allow": ["read"], "web": {"fetch": {"enabled": True}}}}
    a1 = _a1(cfg)
    assert "sensitive data" in (a1.evidence or [])
    assert "Cannot determine from config: sensitive data." not in a1.detail


def test_confining_it_removes_the_leg_without_claiming_safety():
    """Confinement drops the leg — and hands the config back to the hedge only if the
    capability is still reachable some other way, never to a silent PASS that skipped it."""
    cfg = {"channels": {"telegram": {"dmPolicy": "open"}},
           "tools": {"allow": ["read"], "fs": {"workspaceOnly": True},
                     "web": {"fetch": {"enabled": True}}}}
    a1 = _a1(cfg)
    assert "sensitive data" not in (a1.evidence or [])
    assert a1.status in ("PASS", "WARN")


# ------------------------------------------------------------------------- the wiring

def test_a1_consults_the_confinement_predicate(monkeypatch):
    """Mutate the CALL SITE: with every scope reported confined, a declared read stops
    being a leg; with none confined, it is one."""
    cfg = {"tools": {"allow": ["read"]}}
    monkeypatch.setattr(_shared._toolpolicy, "confined_scopes", lambda c: [True])
    assert _sensitive(cfg) == []
    monkeypatch.setattr(_shared._toolpolicy, "confined_scopes", lambda c: [False])
    assert _sensitive(cfg) != []


def test_a_blind_config_does_not_read_as_confined():
    """`confined_scopes` returns None when there is no config to read, and None must not
    be mistaken for "everything is confined" — that would silence a declared tool on the
    strength of a file we never saw."""
    assert confined_scopes({}) is None
    assert _shared._fs_reads_are_confined({}) is False
