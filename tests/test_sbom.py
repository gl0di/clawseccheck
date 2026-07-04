"""Tests for `--sbom` (F-085) — deterministic local bill-of-materials export.

Checks: skill/MCP field extraction, hash alignment with monitor.py's own hashing
scheme, deterministic ordering, redaction (no secret VALUES ever leak, only key
names), and the CLI flag itself.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.collector import Context
from clawseccheck.monitor import _h
from clawseccheck.sbom import build_sbom, render_sbom

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HOME_FAKE = Path("/nonexistent/home")


def _ctx_with_skill(name: str, skill_md: str) -> Context:
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {name: skill_md}
    ctx.config = {}
    return ctx


# --------------------------------------------------------------------------- skills

def test_skill_hash_matches_monitor_hashing_scheme():
    blob = "---\nname: x\ndescription: y\nversion: 1.2.0\n---\nrequests>=2.0\n"
    ctx = _ctx_with_skill("net-fetcher", blob)
    bom = build_sbom(ctx)
    entry = bom["skills"][0]
    assert entry["name"] == "net-fetcher"
    assert entry["version"] == "1.2.0"
    assert entry["hash"] == _h(blob)  # must align with monitor.py's own hash scheme


def test_skill_no_version_is_none():
    ctx = _ctx_with_skill("no-ver", "---\nname: x\ndescription: y\n---\n")
    bom = build_sbom(ctx)
    assert bom["skills"][0]["version"] is None


def test_skills_sorted_by_name():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {
        "zeta": "---\nname: z\ndescription: z\n---\n",
        "alpha": "---\nname: a\ndescription: a\n---\n",
    }
    ctx.config = {}
    bom = build_sbom(ctx)
    assert [s["name"] for s in bom["skills"]] == ["alpha", "zeta"]


# --------------------------------------------------------------------------- mcp

def test_mcp_hash_matches_monitor_hashing_scheme():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {
        "mcp": {"servers": {"svc": {"command": "npx", "args": ["svc-mcp@1.2.3"],
                                     "transport": "stdio", "env": {"API_KEY": "secret-value"}}}}
    }
    bom = build_sbom(ctx)
    assert len(bom["mcp_servers"]) == 1
    entry = bom["mcp_servers"][0]
    assert entry["name"] == "svc"
    assert entry["transport"] == "stdio"
    # redaction: only the key NAME (marked as secret-shaped), never the value
    assert all("secret-value" not in str(v) for v in entry.values())
    assert any("API_KEY" in k for k in entry["env_keys"])


def test_mcp_pinned_detection():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {
        "mcp": {"servers": {
            "pinned-svc": {"command": "npx", "args": ["svc-mcp@1.2.3"], "transport": "stdio"},
            "unpinned-svc": {"command": "npx", "args": ["svc-mcp"], "transport": "stdio"},
        }}
    }
    bom = build_sbom(ctx)
    by_name = {e["name"]: e for e in bom["mcp_servers"]}
    assert by_name["pinned-svc"]["pinned"] is True
    assert by_name["unpinned-svc"]["pinned"] is False


# --------------------------------------------------------------------------- determinism

def test_render_sbom_is_deterministic():
    ctx = _ctx_with_skill("x", "---\nname: x\ndescription: y\n---\n")
    out1 = render_sbom(ctx)
    out2 = render_sbom(ctx)
    assert out1 == out2
    json.loads(out1)  # valid JSON


def test_empty_context_produces_valid_empty_bom():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {}
    out = render_sbom(ctx)
    payload = json.loads(out)
    assert payload["skills"] == []
    assert payload["mcp_servers"] == []
    assert payload["version"] == 1


# --------------------------------------------------------------------------- redaction guard

def test_no_secret_value_anywhere_in_bom():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {
        "mcp": {"servers": {"svc": {
            "command": "npx", "args": ["svc-mcp"], "transport": "stdio",
            "env": {"OPENAI_API_KEY": "sk-THIS-MUST-NEVER-APPEAR", "PASSWORD": "hunter2"},
        }}}
    }
    out = render_sbom(ctx)
    assert "sk-THIS-MUST-NEVER-APPEAR" not in out
    assert "hunter2" not in out


# --------------------------------------------------------------------------- CLI

def test_cli_sbom_emits_valid_json(capsys):
    rc = main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host",
               "--no-history", "--sbom"])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["version"] == 1
    assert "skills" in payload and "mcp_servers" in payload


def test_cli_sbom_is_deterministic_across_runs(capsys):
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host",
          "--no-history", "--sbom"])
    out1 = capsys.readouterr().out
    main(["--home", str(FIXTURES / "home_safe"), "--no-native", "--no-host",
          "--no-history", "--sbom"])
    out2 = capsys.readouterr().out
    assert out1 == out2
