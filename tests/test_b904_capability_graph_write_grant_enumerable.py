"""CLAWSECCHECK-B-904 -- the capability graph must not assert a confident
`can_write_memory=False` when the underlying grant could not actually be resolved.

The original bug: on a config with no `tools` policy declared anywhere (e.g.
``{"channels": {"telegram": {"enabled": true, "dmPolicy": "pairing"}}}``), the
capability graph called `_b55_write_tools_granted` alone and never applied the B-737
not-enumerable-scope fallback (`_fs_scope_grants`, OpenClaw's own per-scope tool-policy
resolution) that `check_fs_write_exposure` (B55) itself falls back to -- so the graph
printed a flat `can_write_memory=False, write_grant_enumerable=False` right next to a
B55 finding that, once B-737 landed, no longer agreed with that reading at all. This is
the same *class* of bug B-503 fixed (`test_b503_capability_graph_invariant.py`) one
level down: two grant resolvers, only one of them (the check's own) applying the full
model.

Fixed by `_b55_resolved_write_grant` (checks/_capability.py): the SAME resolution B55
performs -- `_b55_write_tools_granted` PLUS its B-737 not-enumerable fallback -- shared
between B55 and the graph, so the two can no longer disagree. On the repro config above,
OpenClaw's own permissive default now resolves the grant, so B55 reports WARN (not
UNKNOWN) and the graph agrees: `can_write_memory=True, write_grant_enumerable=True`.

A genuine B55 UNKNOWN still exists -- a config with at least one opaque scope
(`tools.byProvider` only, no other resolvable scope) that the shared resolver truly
cannot resolve either way -- and the graph must still show `write_grant_enumerable=False`
there, not invent a confident answer B55 itself declined to give.

The three-way outcome (config resolves to a real "granted", a real "resolved to
nothing", or "cannot resolve") is exercised here in all three shapes, plus the
agreement invariant `write_grant_enumerable == (B55.status != UNKNOWN)` on the
adversarial edge case B55 itself decides.

`write_grant_enumerable` is an additive field (docs/OUTPUT_SCHEMA.md, "Stable
additions") -- `can_write_memory` keeps its documented `bool` type and every existing
`is True`/`is False` assertion on it elsewhere in the suite is unaffected.

Offline, no fixtures on disk -- every config below is a plain dict, matching the inline-
`Context` style `test_b503_capability_graph_invariant.py` and
`test_b671_capability_graph_per_agent_workspace_access.py` already use.
"""
from __future__ import annotations

from clawseccheck.catalog import PASS, UNKNOWN, WARN
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
    """The original bug report's repro: a channel declared, no `tools` block at all
    anywhere in config. OpenClaw's own permissive default resolves a write grant here
    (B-737), so B55 now reports WARN, not UNKNOWN -- the graph must agree with THAT,
    not with the pre-B-737 UNKNOWN this class used to pin."""

    _CFG = {"channels": {"telegram": {"enabled": True, "dmPolicy": "pairing"}}}

    def test_b55_reports_warn_on_the_permissive_default(self):
        assert check_fs_write_exposure(_ctx(self._CFG)).status == WARN

    def test_graph_agrees_with_b55s_resolved_grant(self):
        node = _main_node(_ctx(self._CFG))
        assert node["can_write_memory"] is True
        assert node["write_grant_enumerable"] is True

    def test_text_render_no_longer_flags_uncertainty(self):
        """The text render only annotates `write_grant_enumerable` when it is False
        (report.py's own "flag it exactly when it is False" comment) -- now that the
        grant resolves, the resolved-uncertainty annotation must not appear."""
        from clawseccheck.report import _capability_graph_lines

        lines = _capability_graph_lines(_ctx(self._CFG))
        main_line = next(line for line in lines if line.startswith("- main "))
        assert "write_grant_enumerable=no" not in main_line


class TestGenuineUnknownRemainsUnknown:
    """Not every config resolves. A global `tools.byProvider`-only policy is opaque to
    both `_b55_write_tools_granted` and the B-737 per-scope residual (no other scope to
    fall back to) -- a real "cannot tell", and the graph must still show that as
    `write_grant_enumerable=False` rather than manufacturing a confident answer neither
    resolver actually has."""

    _CFG = {"tools": {"byProvider": {"openai": {"profile": "minimal"}}}}

    def test_b55_stays_unknown(self):
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


class TestResolvedToNothing:
    """The B-737 residual's third outcome: every scope it could examine WAS examined
    (none opaque) and none of them grants a write-capable tool -- a real, positive
    "resolved, and resolved to nothing" answer. B55 reports PASS (naming the scope
    checked), and the graph must read this as a confident "no", not "unknown": grant
    resolution genuinely completed, it just found nothing."""

    _CFG = {
        "agents": {"list": [{"id": "main", "tools": {"profile": "minimal"}}]},
        "channels": {"telegram": {"enabled": True, "dmPolicy": "pairing"}},
    }

    def test_b55_passes_naming_the_checked_scope(self):
        assert check_fs_write_exposure(_ctx(self._CFG)).status == PASS

    def test_graph_reads_it_as_a_confident_no(self):
        node = _main_node(_ctx(self._CFG))
        assert node["can_write_memory"] is False
        assert node["write_grant_enumerable"] is True


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

    def test_explicit_empty_allow_list_matches_b55s_own_reading(self):
        """`tools.allow: []` is schema-edge-case territory: OpenClaw's own permissive
        default resolves it via the same B-737 residual as the no-policy-declared
        shape above, so B55 reports WARN here too, not UNKNOWN. Whatever B55 itself
        decides for it, the graph must agree -- not invent its own reading of an edge
        case B55 already resolved. Kept as an invariant assertion (not a hardcoded
        status) so it stays meaningful regardless of which status B55 lands on."""
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
