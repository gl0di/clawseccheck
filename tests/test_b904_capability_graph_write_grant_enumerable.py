"""CLAWSECCHECK-B-904 -- the capability graph must not assert a confident
`can_write_memory=False` when the underlying grant could not actually be resolved.

The bug: on a config with no `tools` policy declared anywhere (e.g.
``{"channels": {"telegram": {"enabled": true, "dmPolicy": "pairing"}}}``), B55
(`check_fs_write_exposure`) reports `UNKNOWN` -- "cannot be assessed" -- because
`tools.allow`/`tools.alsoAllow`/`tools.profile` are all absent, so the write-tool grant
is not enumerable from static config at all. The capability graph, however, printed a
flat `can_write_memory=False` for the same `main` node: a confident "no" the check
itself never claimed. A reader comparing the two sees B55 explicitly decline to answer
right next to a graph line that looks like a settled answer.

This is the same *class* of bug B-503 fixed (`test_b503_capability_graph_invariant.py`)
one level down: B-503 was a FAIL-vs-False disagreement (two grant resolvers, only one
profile-aware); B-904 is an UNKNOWN-vs-False one (one resolver, but the graph discarded
its own "not enumerable" bit).

No new grant-resolution model is introduced here. `write_grant_enumerable` on the `main`
node is exactly the `enumerable` flag `_b55_write_tools_granted` already returns and
`check_fs_write_exposure` already branches its own UNKNOWN verdict on
(checks/_capability.py) -- surfaced, not re-derived. `can_write_memory`'s own value and
the logic that computes it are completely untouched by this fix; this file's control
tests exist to prove that (a real, explicit restrictive policy must still read as a
confident, enumerable "no").

`write_grant_enumerable` is an additive field (docs/OUTPUT_SCHEMA.md 17, "Stable
additions") -- `can_write_memory` keeps its documented `bool` type and every existing
`is True`/`is False` assertion on it elsewhere in the suite is unaffected.

Offline, no fixtures on disk -- every config below is a plain dict, matching the inline-
`Context` style `test_b503_capability_graph_invariant.py` and
`test_b671_capability_graph_per_agent_workspace_access.py` already use.
"""
from __future__ import annotations

from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import check_fs_write_exposure
from clawseccheck.collector import Context
from clawseccheck.report import _capability_graph


def _ctx(cfg: dict) -> Context:
    ctx = Context(home=None)
    ctx.config = cfg
    return ctx


def _main_node(ctx) -> dict:
    graph = _capability_graph(ctx)
    for node in graph["nodes"]:
        if node["id"] == "main":
            return node
    raise AssertionError("capability graph has no 'main' node")


class TestReproNoPolicyDeclared:
    """The exact repro from the bug report: a channel declared, no `tools` block at
    all anywhere in config."""

    _CFG = {"channels": {"telegram": {"enabled": True, "dmPolicy": "pairing"}}}

    def test_b55_reports_unknown(self):
        assert check_fs_write_exposure(_ctx(self._CFG)).status == UNKNOWN

    def test_graph_flags_the_same_uncertainty_b55_has(self):
        node = _main_node(_ctx(self._CFG))
        assert node["can_write_memory"] is False
        assert node["write_grant_enumerable"] is False

    def test_text_render_surfaces_the_uncertainty(self):
        from clawseccheck.report import _capability_graph_lines

        lines = _capability_graph_lines(_ctx(self._CFG))
        main_line = next(line for line in lines if line.startswith("- main "))
        assert "write_grant_enumerable=no" in main_line


class TestControlExplicitRestrictivePolicy:
    """A config with a REAL, explicit, restrictive tools policy must still read as a
    confident "no" -- the fix must not blur every `can_write_memory=False` into
    "unknown", only the genuinely non-enumerable ones."""

    def test_explicit_allow_without_write_is_confidently_no(self):
        cfg = {"tools": {"allow": ["read"]}}
        assert check_fs_write_exposure(_ctx(cfg)).status != UNKNOWN
        node = _main_node(_ctx(cfg))
        assert node["can_write_memory"] is False
        assert node["write_grant_enumerable"] is True

    def test_explicit_deny_of_every_write_tool_is_confidently_no(self):
        cfg = {
            "tools": {
                "allow": ["read", "write", "edit", "apply_patch"],
                "deny": ["write", "edit", "apply_patch"],
            }
        }
        assert check_fs_write_exposure(_ctx(cfg)).status != UNKNOWN
        node = _main_node(_ctx(cfg))
        assert node["can_write_memory"] is False
        assert node["write_grant_enumerable"] is True

    def test_explicit_grant_is_still_true_and_enumerable(self):
        """A real, explicit write grant must stay a confident "yes" -- untouched by
        this fix (B-503's own invariant, re-asserted here for this file's config
        shapes)."""
        cfg = {"tools": {"allow": ["write"]}}
        assert check_fs_write_exposure(_ctx(cfg)).status != UNKNOWN
        node = _main_node(_ctx(cfg))
        assert node["can_write_memory"] is True
        assert node["write_grant_enumerable"] is True


class TestAdversarial:
    """C-135-lite pass (per this task's reduced scope): a couple more shapes tried
    against the fix, confirming graph and B55 never newly contradict."""

    def test_non_write_tools_granted_explicitly_stays_confidently_no(self):
        """Some tools ARE explicitly granted, but none of them write-capable --
        must resolve as a confident "no", not "unknown"."""
        cfg = {"tools": {"allow": ["read", "web_search"]}}
        assert check_fs_write_exposure(_ctx(cfg)).status != UNKNOWN
        node = _main_node(_ctx(cfg))
        assert node["can_write_memory"] is False
        assert node["write_grant_enumerable"] is True

    def test_explicit_empty_allow_list_matches_b55s_own_unknown(self):
        """`tools.allow: []` is schema-edge-case territory. Whatever B55 itself
        decides for it (UNKNOWN here, same as no tools block at all), the graph must
        agree -- not invent its own reading of an edge case B55 already resolved."""
        cfg = {"tools": {"allow": []}}
        finding = check_fs_write_exposure(_ctx(cfg))
        node = _main_node(_ctx(cfg))
        assert node["write_grant_enumerable"] == (finding.status != UNKNOWN)

    def test_field_is_absent_on_non_main_nodes(self):
        """`write_grant_enumerable` is only meaningful for `main` -- every other node
        kind derives `can_write_memory` from fully-known data, so the field must not
        appear there (an always-True filler would be noise, not signal)."""
        cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "pairing"}}}
        graph = _capability_graph(_ctx(cfg))
        for node in graph["nodes"]:
            if node["id"] == "main":
                continue
            assert "write_grant_enumerable" not in node, node["id"]
