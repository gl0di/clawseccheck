"""Tests for B-041: capability graph / A1 trifecta verdict consistency.

The capability graph (emitted in --json output) and A1's Lethal-Trifecta verdict
must agree on which channels supply untrusted external input.  Before the B-041
fix, ``_capability_graph()`` used ``_open_channels()`` (dmPolicy="open" only)
while ``check_trifecta`` (A1) used ``_external_input_channels()``
(dmPolicy in {"open","allowlist","paired"}).  That mismatch produced an
internally-contradictory output: "trifecta 3/3 active" alongside the capability
graph input node showing ``tools=[]`` / ``can_egress=false``.

All tests are offline and write nothing outside ``tmp_path``.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.report import render_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_cfg(tmp_path: Path, cfg: dict) -> None:
    """Write openclaw.json to tmp_path at 0o600 (deterministic perm check)."""
    p = tmp_path / "openclaw.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)


def _run(tmp_path: Path) -> dict:
    """Run the full audit and return the parsed --json document."""
    ctx, findings, score = audit(tmp_path)
    return json.loads(render_json(findings, score, ctx=ctx))


def _input_node(doc: dict) -> dict:
    """Return the 'input' (ingress) node from the capability graph."""
    node = next(
        (n for n in doc["capability_graph"]["nodes"] if n["id"] == "input"),
        None,
    )
    assert node is not None, "capability_graph must always contain an 'input' node"
    return node


def _a1(doc: dict) -> dict:
    """Return the A1 finding dict from the findings list."""
    a1 = next((f for f in doc["findings"] if f["id"] == "A1"), None)
    assert a1 is not None, "A1 (trifecta) must always be present in findings"
    return a1


# ---------------------------------------------------------------------------
# Fixture configs
#
# _ALLOWLIST_CFG / _PAIRED_CFG: channels with dmPolicy ∈ {"allowlist","paired"}
#   — not "open", so _open_channels() returns [] while
#     _external_input_channels() returns ["slack"] / ["teams"].
#   Tools: db_query (matches SENSITIVE_TOOL_HINTS via "db"),
#          http_post (matches OUTBOUND_TOOL_HINTS exactly).
#   Neither tool matches INPUT_TOOL_HINTS, so the ONLY source of an external
#   input surface is the channel itself — this isolates the bug precisely.
#
# _OWNER_CFG: owner-only channel and a tool ("search") that matches none of the
#   three hint categories.  _external_input_channels() returns []; A1 does NOT
#   flag "untrusted input"; graph must show no external input surface.
# ---------------------------------------------------------------------------

_ALLOWLIST_CFG = {
    "channels": {"slack": {"dmPolicy": "allowlist"}},
    "tools": {"allow": ["db_query", "http_post"]},
}

_PAIRED_CFG = {
    "channels": {"teams": {"dmPolicy": "paired"}},
    "tools": {"allow": ["db_query", "http_post"]},
}

_OWNER_CFG = {
    "channels": {"personal": {"dmPolicy": "owner"}},
    "tools": {"allow": ["search"]},
}


# ---------------------------------------------------------------------------
# Dirty case — allowlist channel
# ---------------------------------------------------------------------------

class TestAllowlistChannelConsistency:
    def test_a1_flags_untrusted_input_for_allowlist_channel(self, tmp_path):
        """A1 must classify an allowlist channel as 'untrusted input'."""
        _write_cfg(tmp_path, _ALLOWLIST_CFG)
        doc = _run(tmp_path)
        a1 = _a1(doc)
        assert "untrusted input" in a1["evidence"], (
            f"A1 must list 'untrusted input' for dmPolicy='allowlist'; "
            f"evidence={a1['evidence']}"
        )

    def test_input_node_lists_allowlist_channel_in_tools(self, tmp_path):
        """Capability graph input node must include the allowlist channel by name."""
        _write_cfg(tmp_path, _ALLOWLIST_CFG)
        doc = _run(tmp_path)
        node = _input_node(doc)
        assert "slack" in node["tools"], (
            f"input node must list 'slack' (allowlist channel) in tools; "
            f"got {node['tools']!r}"
        )

    def test_input_node_can_egress_true_for_allowlist(self, tmp_path):
        """Capability graph input node must show can_egress=true for allowlist channel."""
        _write_cfg(tmp_path, _ALLOWLIST_CFG)
        doc = _run(tmp_path)
        node = _input_node(doc)
        assert node["can_egress"] is True, (
            "input node can_egress must be True when an allowlist channel is present; "
            f"got {node['can_egress']!r}"
        )

    def test_no_contradiction_untrusted_input_active_but_graph_empty(self, tmp_path):
        """Core B-041 check: if A1 says 'untrusted input', graph must not show tools=[].

        The bug: _capability_graph used _open_channels() (open-only) while A1 used
        _external_input_channels() (open+allowlist+paired).  For an allowlist-only
        channel the old code produced A1 3/3 + input node tools=[]/can_egress=false.
        """
        _write_cfg(tmp_path, _ALLOWLIST_CFG)
        doc = _run(tmp_path)
        a1 = _a1(doc)
        node = _input_node(doc)
        if "untrusted input" in a1["evidence"]:
            assert node["tools"] != [], (
                "CONTRADICTION (B-041): A1 says 'untrusted input' active but "
                "capability graph input node shows tools=[]"
            )
            assert node["can_egress"] is True, (
                "CONTRADICTION (B-041): A1 says 'untrusted input' active but "
                "capability graph input node shows can_egress=false"
            )


# ---------------------------------------------------------------------------
# Dirty case — paired channel
# ---------------------------------------------------------------------------

class TestPairedChannelConsistency:
    def test_a1_flags_untrusted_input_for_paired_channel(self, tmp_path):
        """A1 must classify a paired channel as 'untrusted input'."""
        _write_cfg(tmp_path, _PAIRED_CFG)
        doc = _run(tmp_path)
        a1 = _a1(doc)
        assert "untrusted input" in a1["evidence"], (
            f"A1 must list 'untrusted input' for dmPolicy='paired'; "
            f"evidence={a1['evidence']}"
        )

    def test_input_node_lists_paired_channel_in_tools(self, tmp_path):
        """Capability graph input node must include the paired channel by name."""
        _write_cfg(tmp_path, _PAIRED_CFG)
        doc = _run(tmp_path)
        node = _input_node(doc)
        assert "teams" in node["tools"], (
            f"input node must list 'teams' (paired channel) in tools; "
            f"got {node['tools']!r}"
        )

    def test_input_node_can_egress_true_for_paired(self, tmp_path):
        _write_cfg(tmp_path, _PAIRED_CFG)
        doc = _run(tmp_path)
        node = _input_node(doc)
        assert node["can_egress"] is True, (
            "input node can_egress must be True when a paired channel is present; "
            f"got {node['can_egress']!r}"
        )

    def test_no_contradiction_for_paired_channel(self, tmp_path):
        """Paired channel must not produce the B-041 contradiction."""
        _write_cfg(tmp_path, _PAIRED_CFG)
        doc = _run(tmp_path)
        a1 = _a1(doc)
        node = _input_node(doc)
        if "untrusted input" in a1["evidence"]:
            assert node["tools"] != [], (
                "CONTRADICTION (B-041): A1 says 'untrusted input' active (paired) "
                "but capability graph input node shows tools=[]"
            )
            assert node["can_egress"] is True, (
                "CONTRADICTION (B-041): A1 says 'untrusted input' active (paired) "
                "but capability graph input node shows can_egress=false"
            )


# ---------------------------------------------------------------------------
# Clean case — owner-only channel → no external input in graph
# ---------------------------------------------------------------------------

class TestOwnerChannelClean:
    def test_owner_channel_not_flagged_as_untrusted_input_by_a1(self, tmp_path):
        """A1 must NOT list 'untrusted input' for an owner-only channel."""
        _write_cfg(tmp_path, _OWNER_CFG)
        doc = _run(tmp_path)
        a1 = _a1(doc)
        assert "untrusted input" not in a1["evidence"], (
            f"A1 must not flag 'untrusted input' for dmPolicy='owner'; "
            f"evidence={a1['evidence']}"
        )

    def test_owner_channel_not_in_input_surface(self, tmp_path):
        """Owner-only channel must not appear in the capability graph input surface."""
        _write_cfg(tmp_path, _OWNER_CFG)
        doc = _run(tmp_path)
        node = _input_node(doc)
        assert "personal" not in node["tools"], (
            f"owner-only channel 'personal' must not appear in input surface; "
            f"got {node['tools']!r}"
        )

    def test_owner_only_input_node_can_egress_false(self, tmp_path):
        """With no external channels and no INPUT_TOOL_HINTS match, can_egress must be False."""
        _write_cfg(tmp_path, _OWNER_CFG)
        doc = _run(tmp_path)
        node = _input_node(doc)
        # "search" matches none of INPUT_TOOL_HINTS; "personal" (owner) is not
        # in _external_input_channels → input_surfaces = [] → can_egress=False
        assert node["can_egress"] is False, (
            "input node can_egress must be False with only an owner-only channel "
            f"and no input-hinted tools; got {node['can_egress']!r}"
        )

    def test_owner_only_input_surface_empty(self, tmp_path):
        """Input surface must be empty when the only channel is owner-only."""
        _write_cfg(tmp_path, _OWNER_CFG)
        doc = _run(tmp_path)
        node = _input_node(doc)
        assert node["tools"] == [], (
            f"input surface must be [] with owner-only channel; got {node['tools']!r}"
        )
