"""An empty config is OpenClaw's grant-all default; a config never read is not evidence.

The vendor resolver (``resolveConfiguredToolPolicies`` + ``isToolAllowedByPolicies``) has no
special case for ``{}``: with no policy layer every tool is allowed, exactly as for a
non-empty config without a ``tools`` block (executed; ``{}`` is a synthetic row of
``tests/data/toolgrant_battery.json``). ``toolgrant`` now answers the same. The collector
also leaves ``ctx.config == {}`` when no openclaw.json was found or it could not be parsed,
so B55/B68 keep their UNKNOWN for that case through ``_config_was_read``.
"""

from __future__ import annotations

from pathlib import Path

from clawseccheck import toolgrant
from clawseccheck.checks import (
    _config_was_read,
    check_exec_applypatch_workspace,
    check_fs_write_exposure,
)
from clawseccheck.collector import Context

UNKNOWN, WARN = "UNKNOWN", "WARN"


def _ctx(cfg, *, found: bool, parse_error: bool = False) -> Context:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    ctx.config_found = found
    ctx.config_parse_error = parse_error
    return ctx


def _b55_b68(ctx: Context) -> tuple:
    return check_fs_write_exposure(ctx).status, check_exec_applypatch_workspace(ctx).status


# ------------------------------------------------------------------ the leaf

def test_an_empty_config_grants_every_tool_like_the_vendor():
    for tool in ("read", "write", "exec", "gateway", "apply_patch"):
        assert toolgrant.granted({}, tool) is True, tool
        assert toolgrant.granted({}, tool) is toolgrant.granted({"meta": {}}, tool), tool


def test_an_empty_config_resolves_one_global_default_scope():
    scopes = toolgrant.resolved_scopes({})
    assert [(s.scope, s.provenance, s.opaque) for s in scopes] == [
        (toolgrant.GLOBAL_SCOPE, "default", False)
    ]
    assert toolgrant.policy_layers({}) == []


def test_a_non_dict_config_still_grants_nothing():
    for bad in (None, [], "x", 0):
        assert toolgrant.granted(bad, "read") is False
        assert toolgrant.policy_layers(bad) == []
        assert toolgrant.resolved_scopes(bad) is None


# ------------------------------------------------------------------ the callers

def test_no_config_found_stays_unknown():
    ctx = _ctx({}, found=False)
    assert _config_was_read(ctx) is False
    assert _b55_b68(ctx) == (UNKNOWN, UNKNOWN)


def test_an_unparseable_config_stays_unknown():
    ctx = _ctx({}, found=True, parse_error=True)
    assert _config_was_read(ctx) is False
    assert _b55_b68(ctx) == (UNKNOWN, UNKNOWN)


def test_a_real_empty_config_warns_like_any_config_without_tools():
    empty = _ctx({}, found=True)
    assert _config_was_read(empty) is True
    assert _b55_b68(empty) == (WARN, WARN)
    assert _b55_b68(_ctx({"meta": {}}, found=True)) == (WARN, WARN)


def test_a_non_empty_config_counts_as_read_without_the_flags():
    """In-memory callers build a Context without config_found; a non-empty config was read."""
    assert _config_was_read(_ctx({"meta": {}}, found=False)) is True
