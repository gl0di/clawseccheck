"""B-073 — MCP command/URL strings must not leak embedded credentials into evidence.

A remote MCP endpoint or stdio launcher can hide a token in a URL's userinfo, path,
or query (``https://user:TOKEN@host/mcp/<TOKEN>?key=<TOKEN>``). ``check_mcp_hardening``
(B24) and ``check_mcp_external_endpoint`` (C047) echo those strings into Finding
evidence/detail, so both must reduce any URL to ``scheme://host`` first (§8: never echo
raw secrets). Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import check_mcp_external_endpoint, check_mcp_hardening
from clawseccheck.collector import Context

# Assemble the secret at runtime so no contiguous secret literal exists in source
# (§2.3 / the tests/test_logsafe.py pattern) — secret scanners must stay quiet.
_TOKEN = "gh" + "p_" + "A1b2C3d4" + "E5f6G7h8" + "I9j0K1l2"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _rendered(f) -> str:
    """Everything a reader could see for this finding — evidence + detail + fix."""
    return " ".join(f.evidence or []) + " " + (f.detail or "") + " " + (f.fix or "")


def test_c047_external_url_credential_not_in_evidence():
    url = f"https://user:{_TOKEN}@mcp.evil.example.com/mcp/{_TOKEN}?api_key={_TOKEN}"
    f = check_mcp_external_endpoint(_ctx({"mcp": {"servers": {"corp": {"url": url}}}}))
    assert f.status == UNKNOWN
    blob = _rendered(f)
    assert _TOKEN not in blob, "credential leaked into C047 finding"
    assert "mcp.evil.example.com" in blob, "host signal must survive sanitization"


def test_b24_stdio_url_credential_not_in_evidence():
    cfg = {"mcpServers": {"tool": {
        "command": "npx",
        "args": ["--registry", f"https://{_TOKEN}@reg.example.com/", "pkg@latest"],
    }}}
    f = check_mcp_hardening(_ctx(cfg))
    assert f.status == "WARN"
    blob = _rendered(f)
    assert _TOKEN not in blob, "credential leaked into B24 finding"
    assert "reg.example.com" in blob, "host signal must survive sanitization"
