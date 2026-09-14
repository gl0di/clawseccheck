"""CLAWSECCHECK-B-671 -- `_capability_graph`'s `can_write_memory` for the `main` node used
to read `agents.defaults.sandbox.workspaceAccess` at DEFAULTS scope only. The runtime
(`resolveSandboxConfigForAgent`) resolves it PER AGENT with
`agentSandbox?.workspaceAccess ?? agent?.workspaceAccess ?? "none"` -- per FIELD, not per
object -- so the defaults-only read was wrong in BOTH directions whenever the agent that
resolves to the "main" id carries its own `sandbox.workspaceAccess`:

* over-reports `can_write_memory=True` when the default is "rw" but the main agent's own
  override narrows to "none"/"ro";
* under-reports `can_write_memory=False` (the dangerous direction -- this graph is what a
  reader uses to reason about reachability) when there is no permissive default at all but
  the main agent's own override widens to "rw".

The fix mirrors the per-field `?? default` loop already vetted in
`risk.py::_agents_are_docker_sandboxed_ro_or_none` (:560-570), and resolves the "main" agent
id through `checks._capability._b351_resolvable_agents` -- the same dist-verified,
first-match-wins normaliser B351 already uses elsewhere, under which an agent entry with no
`id` normalises to "main" and COLLIDES with one explicitly named "main" rather than being
skipped.

All tests call `_capability_graph` directly (the real call site inside `report.py`), not a
standalone helper -- there is no extracted helper to accidentally bypass, so a regression to
the old defaults-only read fails these tests directly. Offline, no fixtures on disk: every
config below is a plain dict, matching the inline-`Context` style `test_b503_capability_
graph_invariant.py` already uses for its non-corpus cases.
"""
from __future__ import annotations

from clawseccheck.catalog import FAIL
from clawseccheck.checks import check_fs_write_exposure
from clawseccheck.collector import Context
from clawseccheck.report import _capability_graph

# tools.profile: "minimal" grants no write-family tool, so `write_tools` is empty and the
# `workspaceAccess` leg of the `main_write` OR is the only thing that can make it True --
# isolating exactly the leg this bug is about, the same isolation the task's own measured
# table uses.
_MINIMAL_PROFILE = {"tools": {"profile": "minimal"}}


def _ctx(cfg: dict) -> Context:
    ctx = Context(home=None)
    ctx.config = cfg
    return ctx


def _cfg(agents: dict | None = None) -> dict:
    cfg = dict(_MINIMAL_PROFILE)
    if agents is not None:
        cfg["agents"] = agents
    return cfg


def _main_node(ctx) -> dict:
    graph = _capability_graph(ctx)
    for node in graph["nodes"]:
        if node["id"] == "main":
            return node
    raise AssertionError("capability graph has no 'main' node")


class TestFourRowMatrix:
    """The exact G0-G3 matrix measured in CLAWSECCHECK-B-671 against the real
    `_capability_graph`. G0 and G3 are positive/negative CONTROLS -- kept in the suite
    deliberately: without them a fix that hardcodes either answer for `can_write_memory`
    still passes."""

    def test_g0_nothing_set_is_false(self):
        """Control: no agents, no sandbox config at all -> no write edge."""
        assert _main_node(_ctx(_cfg()))["can_write_memory"] is False

    def test_g3_default_rw_agent_silent_is_true(self):
        """Control: a permissive default with a roster entry declaring no sandbox
        override of its own must still inherit "rw"."""
        cfg = _cfg({
            "defaults": {"sandbox": {"workspaceAccess": "rw"}},
            "list": [{"id": "main"}],
        })
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_g3_default_rw_no_roster_declared_is_true(self):
        """Same control, but with no `agents.list`/`agents.entries` at all -- the
        defaults leg must not be gated on a roster existing."""
        cfg = _cfg({"defaults": {"sandbox": {"workspaceAccess": "rw"}}})
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_g1_default_rw_main_agent_none_is_false(self):
        """Defect direction 1 (over-report): the main agent's own override narrows a
        permissive default to "none" -- must win over the default."""
        cfg = _cfg({
            "defaults": {"sandbox": {"workspaceAccess": "rw"}},
            "list": [{"id": "main", "sandbox": {"workspaceAccess": "none"}}],
        })
        assert _main_node(_ctx(cfg))["can_write_memory"] is False

    def test_g2_no_default_main_agent_rw_is_true(self):
        """Defect direction 2 (under-report, the dangerous one): no permissive default
        anywhere, but the main agent's own override widens to "rw" -- must surface the
        write edge."""
        cfg = _cfg({"list": [{"id": "main", "sandbox": {"workspaceAccess": "rw"}}]})
        assert _main_node(_ctx(cfg))["can_write_memory"] is True


class TestAgentIdResolution:
    """B351's ported, dist-verified agent-id normalisation: first-match-wins, and a
    nameless entry collides with one explicitly named "main"."""

    def test_nameless_entry_resolves_to_main(self):
        """An `agents.list` entry with no `id` field at all IS the main agent's config."""
        cfg = _cfg({"list": [{"sandbox": {"workspaceAccess": "rw"}}]})
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_id_normalisation_is_case_insensitive(self):
        cfg = _cfg({"list": [{"id": "MAIN", "sandbox": {"workspaceAccess": "rw"}}]})
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_nameless_and_explicit_main_collide_first_wins(self):
        """A nameless entry (normalises to "main") followed by one explicitly named
        "main" -- the vendor's resolver is first-match-wins, so the nameless entry's
        "rw" governs and the later explicit "none" entry is unreachable."""
        cfg = _cfg({
            "list": [
                {"sandbox": {"workspaceAccess": "rw"}},
                {"id": "main", "sandbox": {"workspaceAccess": "none"}},
            ]
        })
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_agents_entries_record_shape_is_read(self):
        """B-699: the 2026.8.1+ `agents.entries` record shape, not just legacy
        `agents.list`."""
        cfg = _cfg({"entries": {"main": {"sandbox": {"workspaceAccess": "rw"}}}})
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_agents_entries_agent_none_overrides_permissive_default(self):
        cfg = _cfg({
            "defaults": {"sandbox": {"workspaceAccess": "rw"}},
            "entries": {"main": {"sandbox": {"workspaceAccess": "none"}}},
        })
        assert _main_node(_ctx(cfg))["can_write_memory"] is False


class TestAdversarial:
    """C-135 pass: try to construct a config shape that makes the fix produce a FALSE
    `can_write_memory: True` -- a spurious grant the old code did not have and the fix
    must not introduce."""

    def test_agent_with_no_sandbox_key_falls_through_to_defaults_not_rw(self):
        """An agent entry that declares no `sandbox` key at all must inherit the
        default, never be treated as an implicit "rw" grant of its own."""
        cfg = _cfg({"list": [{"id": "main"}]})  # no defaults, no per-agent sandbox
        assert _main_node(_ctx(cfg))["can_write_memory"] is False

    def test_agent_with_sandbox_but_no_workspace_access_key_falls_through(self):
        """A `sandbox` object present but silent on `workspaceAccess` (e.g. it only sets
        `mode`) must fall through to the default for THIS field -- resolution is per
        field, not per object."""
        cfg = _cfg({
            "defaults": {"sandbox": {"workspaceAccess": "rw"}},
            "list": [{"id": "main", "sandbox": {"mode": "all"}}],
        })
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_malformed_agent_sandbox_is_not_a_dict_falls_through(self):
        """A hand-edited / schema-invalid `sandbox` value (a bare string) must not be
        treated as an override -- fail closed to the default, not to a crash or a
        spurious grant."""
        cfg = _cfg({
            "defaults": {"sandbox": {"workspaceAccess": "rw"}},
            "list": [{"id": "main", "sandbox": "not-a-dict"}],
        })
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_malformed_default_sandbox_is_not_a_dict_stays_false(self):
        cfg = _cfg({"defaults": {"sandbox": "not-a-dict"}, "list": [{"id": "main"}]})
        assert _main_node(_ctx(cfg))["can_write_memory"] is False

    def test_unrelated_agent_id_does_not_spuriously_grant_main(self):
        """An agent whose id matches nothing (not "main") granting itself "rw" must
        never leak onto the main node -- it is a different agent's capability."""
        cfg = _cfg({"list": [{"id": "worker", "sandbox": {"workspaceAccess": "rw"}}]})
        assert _main_node(_ctx(cfg))["can_write_memory"] is False

    def test_unrelated_agent_none_does_not_suppress_a_permissive_default(self):
        """The mirror case: an unrelated agent narrowing itself to "none" must not
        suppress the DEFAULT'S "rw" grant to main."""
        cfg = _cfg({
            "defaults": {"sandbox": {"workspaceAccess": "rw"}},
            "list": [{"id": "worker", "sandbox": {"workspaceAccess": "none"}}],
        })
        assert _main_node(_ctx(cfg))["can_write_memory"] is True

    def test_no_agents_key_at_all_stays_false(self):
        assert _main_node(_ctx(_cfg(agents=None)))["can_write_memory"] is False

    def test_agents_not_a_dict_does_not_crash_and_stays_false(self):
        cfg = _cfg()
        cfg["agents"] = "not-a-dict"
        assert _main_node(_ctx(cfg))["can_write_memory"] is False

    def test_entries_present_but_null_yields_empty_roster_not_a_crash(self):
        """B-699 semantics: `agents.entries: null` yields an EMPTY roster, and the
        `list` beside it (if any) is NOT consulted -- so an accompanying `list` entry
        must not leak through here either."""
        cfg = _cfg({
            "entries": None,
            "list": [{"id": "main", "sandbox": {"workspaceAccess": "rw"}}],
        })
        assert _main_node(_ctx(cfg))["can_write_memory"] is False


class TestB55Invariant:
    """The `3ab332c` invariant: the graph must never say `can_write_memory=False` while
    B55 FAILs for broad fs-write. The write-tools leg of the `main_write` OR is untouched
    by this fix, so a real write-tool grant must still win regardless of `workspaceAccess`.
    """

    # Same open-channel + powerful-profile shape as `bad_b503_capgraph_profile_no_allow`
    # (the real B55/graph repro that motivated the `3ab332c` invariant) -- a broad-reach
    # channel is required for B55 to actually FAIL rather than WARN; `fs_confined`
    # downgrades an otherwise-unconfined grant to WARN when nothing proves broad reach.
    _OPEN_CHANNEL = {"telegram": {"dmPolicy": "open", "groupPolicy": "allowlist"}}

    def test_granted_write_tool_wins_over_a_restrictive_workspace_access(self):
        cfg = {
            "tools": {"profile": "coding"},
            "channels": self._OPEN_CHANNEL,
            "agents": {
                "defaults": {"sandbox": {"workspaceAccess": "none"}},
            },
        }
        ctx = _ctx(cfg)
        assert check_fs_write_exposure(ctx).status == FAIL
        assert _main_node(ctx)["can_write_memory"] is True

    def test_granted_write_tool_wins_even_with_a_restrictive_per_agent_override(self):
        cfg = {
            "tools": {"profile": "coding"},
            "channels": self._OPEN_CHANNEL,
            "agents": {
                "list": [{"id": "main", "sandbox": {"workspaceAccess": "none"}}],
            },
        }
        ctx = _ctx(cfg)
        assert check_fs_write_exposure(ctx).status == FAIL
        assert _main_node(ctx)["can_write_memory"] is True
