"""CLAWSECCHECK-B-1089 - an unversioned SCOPED npm package (`npx -y @scope/pkg`) is unpinned.

`_VET_MCP_UNPINNED_PKG_RE` treated any "@" as a version separator, so the leading "@" of an
npm scope made every unversioned scoped package read as pinned and --vet-mcp said INSTALL on
the most common real MCP launch shape. Only an "@" AFTER the package name is a version.
"""
from __future__ import annotations

import pytest

from clawseccheck.checks import _VET_MCP_UNPINNED_PKG_RE, _vet_mcp_server


@pytest.mark.parametrize("arg", [
    "@modelcontextprotocol/server-filesystem",
    "@scope/pkg",
    "@scope/pkg@latest",
    "some-mcp",
    "some-mcp@latest",
])
def test_unpinned_specs_match(arg):
    assert _VET_MCP_UNPINNED_PKG_RE.search(arg)


@pytest.mark.parametrize("arg", [
    "@scope/pkg@1.2.3",
    "@modelcontextprotocol/server-filesystem@2025.8.21",
    "some-mcp@1.0.0",
    "-y",
    "@",
])
def test_pinned_specs_and_flags_do_not_match(arg):
    assert not _VET_MCP_UNPINNED_PKG_RE.search(arg)


@pytest.mark.parametrize("args", [
    ["-y", "@modelcontextprotocol/server-filesystem"],
    ["@scope/pkg"],
    ["-y", "some-mcp"],  # control: the unscoped shape was already caught
])
def test_vet_mcp_server_flags_unpinned_scoped_package(args):
    _dangerous, suspicious = _vet_mcp_server("s", {"command": "npx", "args": args})
    assert any("unpinned" in r for r in suspicious), suspicious


def test_vet_mcp_server_pinned_scoped_package_is_quiet():
    _dangerous, suspicious = _vet_mcp_server(
        "s", {"command": "npx", "args": ["-y", "@scope/pkg@1.2.3"]})
    assert not any("unpinned" in r for r in suspicious), suspicious
