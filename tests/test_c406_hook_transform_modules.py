"""CLAWSECCHECK-C-406 — B380: hooks.mappings[].transform.module inventory/writability.

Grounded against the installed OpenClaw dist (2026.9.4), by symbol (see
check_hook_transform_modules's own docstring for the full citation) --
loadTransform/resolveContainedPath/resolveOptionalContainedPath confine BOTH the
transform module path and hooks.transformsDir itself, so this check is disclosure
only (WARN, never FAIL) even when a transform module is configured.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_hook_transform_modules
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# --------------------------------------------------------------------------- fixtures

def test_bad_fixture_warns_with_module_evidence():
    ctx = collect(FIXTURES / "bad_b380_hook_transform_module")
    r = check_hook_transform_modules(ctx)
    assert r.status == WARN, r.detail
    assert any("sanitize.mjs" in e for e in r.evidence)


def test_clean_fixture_passes():
    ctx = collect(FIXTURES / "clean_b380_no_transform")
    r = check_hook_transform_modules(ctx)
    assert r.status == PASS, r.detail


def _ctx(cfg: dict, home=None) -> Context:
    c = Context(home=Path(home) if home is not None else Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    return c


def _cfg_with_module(module: str = "sanitize.mjs") -> dict:
    return {"hooks": {"mappings": [
        {"id": "incoming", "event": "message", "transform": {"module": module}},
    ]}}


# --------------------------------------------------------------------------- UNKNOWN

def test_unknown_when_no_config_read():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_found = False
    assert check_hook_transform_modules(c).status == UNKNOWN


def test_unknown_when_config_unparseable():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_found = True
    c.config_parse_error = True
    assert check_hook_transform_modules(c).status == UNKNOWN


# --------------------------------------------------------------------------- PASS

def test_pass_when_no_hooks_configured():
    assert check_hook_transform_modules(_ctx({})).status == PASS


def test_pass_when_hooks_mappings_has_no_transform():
    cfg = {"hooks": {"mappings": [{"id": "x", "event": "message"}]}}
    assert check_hook_transform_modules(_ctx(cfg)).status == PASS


def test_pass_when_transform_has_no_module_key():
    cfg = {"hooks": {"mappings": [{"id": "x", "transform": {"other": "field"}}]}}
    assert check_hook_transform_modules(_ctx(cfg)).status == PASS


def test_pass_when_module_is_blank_string():
    assert check_hook_transform_modules(_ctx(_cfg_with_module("   "))).status == PASS


def test_pass_when_mappings_entries_are_malformed():
    """Non-dict list entries must not raise."""
    cfg = {"hooks": {"mappings": ["not-a-dict", 42, None]}}
    assert check_hook_transform_modules(_ctx(cfg)).status == PASS


# --------------------------------------------------------------------------- WARN (disclosure)

def test_warn_when_transform_module_configured():
    r = check_hook_transform_modules(_ctx(_cfg_with_module("sanitize.mjs")))
    assert r.status == WARN
    assert any("sanitize.mjs" in e for e in r.evidence)
    # Never FAIL: the field is path-confined at both levels (see docstring).
    assert r.severity != "CRITICAL"


def test_warn_evidence_names_the_mapping_index():
    r = check_hook_transform_modules(_ctx(_cfg_with_module("x.mjs")))
    assert any("hooks.mappings[0].transform.module" in e for e in r.evidence)


def test_warn_multiple_modules_counted():
    cfg = {"hooks": {"mappings": [
        {"transform": {"module": "a.mjs"}},
        {"transform": {"module": "b.mjs"}},
    ]}}
    r = check_hook_transform_modules(_ctx(cfg))
    assert r.status == WARN
    assert len(r.evidence) == 2


def test_never_fails():
    for cfg in (
        _cfg_with_module("a.mjs"),
        _cfg_with_module("../../../etc/passwd"),  # confined by the vendor regardless
        {"hooks": {"mappings": [{"transform": {"module": "x"}}] * 20}},
    ):
        assert check_hook_transform_modules(_ctx(cfg)).status != "FAIL"


# --------------------------------------------------------------------------- WARN (writability escalation)

def test_warn_escalates_when_transforms_dir_world_writable(tmp_path):
    transforms_dir = tmp_path / "hooks" / "transforms"
    transforms_dir.mkdir(parents=True)
    transforms_dir.chmod(0o777)
    r = check_hook_transform_modules(_ctx(_cfg_with_module("a.mjs"), home=tmp_path))
    assert r.status == WARN
    assert r.severity == "MEDIUM"
    assert "writable" in r.detail


def test_warn_does_not_escalate_when_transforms_dir_owner_only(tmp_path):
    transforms_dir = tmp_path / "hooks" / "transforms"
    transforms_dir.mkdir(parents=True)
    transforms_dir.chmod(0o700)
    r = check_hook_transform_modules(_ctx(_cfg_with_module("a.mjs"), home=tmp_path))
    assert r.status == WARN
    assert r.severity != "MEDIUM"


def test_warn_does_not_escalate_when_transforms_dir_absent(tmp_path):
    """No crash, no false escalation, when the directory doesn't exist on disk yet."""
    r = check_hook_transform_modules(_ctx(_cfg_with_module("a.mjs"), home=tmp_path))
    assert r.status == WARN
    assert r.severity != "MEDIUM"


def test_custom_transforms_dir_resolved_as_subdirectory(tmp_path):
    """hooks.transformsDir resolves as a SUBDIRECTORY of <home>/hooks/transforms
    (matching resolveOptionalContainedPath's own base), not of <home> directly."""
    custom_dir = tmp_path / "hooks" / "transforms" / "prod"
    custom_dir.mkdir(parents=True)
    custom_dir.chmod(0o777)
    cfg = _cfg_with_module("a.mjs")
    cfg["hooks"]["transformsDir"] = "prod"
    r = check_hook_transform_modules(_ctx(cfg, home=tmp_path))
    assert r.status == WARN
    assert r.severity == "MEDIUM"
