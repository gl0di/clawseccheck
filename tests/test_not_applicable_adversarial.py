"""F-139 (B2) adversarial matrix — every MCP-surface form ``_mcp_servers()``
recognizes must NOT be misread as "no MCP surface" by the migrated checks
(B15/B24/B166) or by the standalone ``vet_mcp`` "MCP-VET" path.

``_mcp_servers()`` (``clawseccheck/checks/_shared.py``) reads seven shapes:
``mcp.servers``, legacy top-level ``mcp`` (a direct ``{name: spec}`` map),
``mcpServers``, ``mcp_servers``, ``tools.mcp``, ``plugins.mcp``, and a
fallback that treats any INSTALLED PLUGIN whose name merely contains "mcp"
as an (empty-spec) server. Presence in ANY of these forms means real MCP
surface exists — the `not servers` branch must never fire, so status can
never be UNKNOWN and (by ``Finding.__post_init__``) ``not_applicable`` can
never be True.

Offline, read-only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import (
    check_mcp,
    check_mcp_hardening,
    check_mcp_server_exfil_host_in_args,
    vet_mcp,
)
from clawseccheck.collector import Context

_CLEAN_SPEC = {"command": "node", "args": ["index.js"]}

# name -> full config dict, one server named "tool" (or an equivalent single
# surface) present via that specific form.
_MCP_SURFACE_FORMS = {
    "mcp.servers": {"mcp": {"servers": {"tool": _CLEAN_SPEC}}},
    "legacy_top_level_mcp": {"mcp": {"tool": _CLEAN_SPEC}},
    "mcpServers": {"mcpServers": {"tool": _CLEAN_SPEC}},
    "mcp_servers": {"mcp_servers": {"tool": _CLEAN_SPEC}},
    "tools.mcp": {"tools": {"mcp": {"tool": _CLEAN_SPEC}}},
    "plugins.mcp": {"plugins": {"mcp": {"tool": _CLEAN_SPEC}}},
    "plugin_name_contains_mcp": {"plugins": {"entries": {"my-mcp-plugin": {}}}},
}


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"), config_found=True, config_parse_error=False)
    c.config = cfg
    return c


@pytest.mark.parametrize("form", sorted(_MCP_SURFACE_FORMS))
def test_b15_surface_present_in_every_form_stays_applicable(form):
    ctx = _ctx(_MCP_SURFACE_FORMS[form])
    f = check_mcp(ctx)
    assert f.status != UNKNOWN, f"form={form}: B15 wrongly saw no MCP surface"
    assert f.not_applicable is False, form


@pytest.mark.parametrize("form", sorted(_MCP_SURFACE_FORMS))
def test_b24_surface_present_in_every_form_stays_applicable(form):
    ctx = _ctx(_MCP_SURFACE_FORMS[form])
    f = check_mcp_hardening(ctx)
    assert f.status != UNKNOWN, f"form={form}: B24 wrongly saw no MCP surface"
    assert f.not_applicable is False, form


@pytest.mark.parametrize("form", sorted(_MCP_SURFACE_FORMS))
def test_b166_surface_present_in_every_form_stays_applicable(form):
    ctx = _ctx(_MCP_SURFACE_FORMS[form])
    f = check_mcp_server_exfil_host_in_args(ctx)
    assert f.status != UNKNOWN, f"form={form}: B166 wrongly saw no MCP surface"
    assert f.not_applicable is False, form


# ---------------------------------------------------------------------------
# The genuinely-empty case: every form absent -> the surface really IS absent,
# and (with config_found/config_parse_error set) not_applicable goes True.
# ---------------------------------------------------------------------------

def test_b15_genuinely_empty_config_sets_not_applicable():
    f = check_mcp(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b24_genuinely_empty_config_sets_not_applicable():
    f = check_mcp_hardening(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_b166_genuinely_empty_config_sets_not_applicable():
    f = check_mcp_server_exfil_host_in_args(_ctx({}))
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# ---------------------------------------------------------------------------
# vet_mcp() standalone "MCP-VET" path — no Context/LimitHit machinery of its
# own; mirrors _surface_absent's config_found/config_parse_error reasoning by
# reading the on-disk openclaw.json directly.
# ---------------------------------------------------------------------------

def test_vet_mcp_readable_config_with_no_servers_is_not_applicable(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    findings = vet_mcp(target=None, home=tmp_path)
    assert len(findings) == 1
    assert findings[0].status == UNKNOWN
    assert findings[0].not_applicable is True


def test_vet_mcp_missing_config_is_not_not_applicable(tmp_path):
    """No openclaw.json at all -- config_found is False, so this must NOT be
    misread as a positive assertion of MCP-surface absence."""
    findings = vet_mcp(target=None, home=tmp_path / "does-not-exist")
    assert len(findings) == 1
    assert findings[0].status == UNKNOWN
    assert findings[0].not_applicable is False


def test_vet_mcp_unparseable_config_is_not_not_applicable(tmp_path):
    (tmp_path / "openclaw.json").write_text("{not valid json", encoding="utf-8")
    findings = vet_mcp(target=None, home=tmp_path)
    assert len(findings) == 1
    assert findings[0].status == UNKNOWN
    assert findings[0].not_applicable is False


def test_vet_mcp_surface_present_stays_applicable(tmp_path):
    import json
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"mcp": {"servers": {"tool": _CLEAN_SPEC}}}), encoding="utf-8"
    )
    findings = vet_mcp(target=None, home=tmp_path)
    assert len(findings) == 1
    assert findings[0].status != UNKNOWN
    assert findings[0].not_applicable is False
