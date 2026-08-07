"""B-503 — the capability graph must not contradict B55 in the same run.

The bug: on the commonest real-world shape (`tools.profile: "coding"` with no
`tools.allow`), the report printed a HIGH B55 FAIL saying "filesystem-write tool granted:
apply_patch, edit, write" and, 340 lines later, `can_write_memory=no` about the same
agent. Two grant resolvers coexisted and only one understood `tools.profile`.

The specific repro is pinned below, but the test that actually earns its place is
`TestCorpusInvariant`: it asserts the two can never disagree on ANY fixture, so it
catches the next divergence rather than only this one.

All tests are offline and deterministic — no network, no writes outside pytest's tmp.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL
from clawseccheck.checks import (
    _B55_FS_WRITE_TOOLS,
    _FS_WRITE_TOOL_HINTS,
    check_fs_write_exposure,
)
from clawseccheck.collector import Context, collect
from clawseccheck.report import _capability_graph

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _main_node(ctx) -> dict:
    graph = _capability_graph(ctx)
    nodes = graph["nodes"] if isinstance(graph, dict) else graph
    for node in nodes:
        if node.get("id") == "main":
            return node
    raise AssertionError("capability graph has no 'main' node")


def _fixture_homes():
    """Every fixture dir that carries a top-level openclaw.json."""
    return sorted(p.parent for p in FIXTURES.glob("*/openclaw.json"))


class TestCorpusInvariant:
    """The assertion that would have caught B-503, and will catch its successor."""

    def test_no_fixture_fails_b55_while_the_graph_denies_write(self):
        offenders = []
        for home in _fixture_homes():
            ctx = collect(home)
            if check_fs_write_exposure(ctx).status != FAIL:
                continue
            if not _main_node(ctx)["can_write_memory"]:
                offenders.append(home.name)
        assert not offenders, (
            "capability graph says can_write_memory=no while B55 FAILs for broad "
            f"fs-write on: {offenders}. The two read the same config and must agree."
        )

    def test_graph_write_flag_matches_its_own_tool_list(self):
        """can_write_memory must be derivable from the tools the graph itself prints.

        The recognised set is taken from B55's own constants rather than hand-written
        here, so this test cannot drift from the model it is checking. It deliberately
        includes the legacy aliases (`fs_write` and friends): B55 still honours them for
        old-style configs, several fixtures use them, and a graph that ignored them would
        be wrong in the opposite direction.
        """
        for home in _fixture_homes():
            node = _main_node(collect(home))
            listed = {str(t).lower() for t in node["tools"]}
            canonical = bool(listed & {t.lower() for t in _B55_FS_WRITE_TOOLS})
            legacy = any(hint in t for t in listed for hint in _FS_WRITE_TOOL_HINTS)
            assert node["can_write_memory"] == (canonical or legacy), (
                f"{home.name}: graph prints tools={sorted(listed)} but "
                f"can_write_memory={node['can_write_memory']}"
            )


class TestProfileOnlyGrant:
    """`tools.profile: coding` with no tools.allow — the real-world repro."""

    def test_b55_fails_and_the_graph_agrees(self):
        ctx = collect(FIXTURES / "bad_b503_capgraph_profile_no_allow")
        assert check_fs_write_exposure(ctx).status == FAIL
        node = _main_node(ctx)
        assert node["can_write_memory"] is True
        assert {"write", "edit", "apply_patch"} & {str(t).lower() for t in node["tools"]}

    def test_minimal_profile_grants_no_write_and_b55_does_not_fail(self):
        ctx = collect(FIXTURES / "clean_b503_capgraph_profile_minimal")
        assert check_fs_write_exposure(ctx).status != FAIL
        assert _main_node(ctx)["can_write_memory"] is False


class TestNoSubstringFalsePositive:
    """The old code matched write tools by substring, so any name containing "write" won.

    Keeping this pinned because the fix replaced `_hint` substring matching with an exact
    match against B55's canonical set, and a future refactor could quietly reintroduce it.
    """

    def test_a_tool_merely_containing_write_does_not_grant_write(self):
        ctx = Context(home=None)
        ctx.config = {"tools": {"allow": ["underwriter_lookup", "rewriter"]}}
        node = _main_node(ctx)
        assert node["can_write_memory"] is False

    def test_the_real_write_tool_still_counts(self):
        ctx = Context(home=None)
        ctx.config = {"tools": {"allow": ["write"]}}
        assert _main_node(ctx)["can_write_memory"] is True
