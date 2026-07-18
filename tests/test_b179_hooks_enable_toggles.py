"""B179 (CLAWSECCHECK-B-250): hooks.enabled / hooks.internal(.load.extraDirs)
enable-toggle attack-surface inventory.

Grounded against the installed dist (2026.7.1, see
docs/research/openclaw-schema-recon.md §20): the originating bug report's title
"hooks.webhooks" is NOT a real config field -- the native audit's own inventory line
(audit.nondeep.runtime-C3y1Q5Fi.js:205-212) computes its "hooks.webhooks: enabled/
disabled" DISPLAY LABEL from the real field `hooks.enabled`
(`cfg.hooks?.enabled === true`). The real internal-hooks fields are
`hooks.internal.enabled`, `.entries`, `.installs`, and `.load.extraDirs`
(schema-DRyO1XBt.js:1063-1068). Before this check, clawseccheck had zero references to
any of these five fields -- only `hooks.mappings` and `hooks.token` had a dig() path.

LOW severity, WARN-only (never FAIL), scored=False (advisory attack-surface inventory,
not a misconfiguration verdict) -- the real fleet config has no `hooks` key at all, and
the native audit itself treats this as info, not WARN/FAIL.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_hooks_enable_toggles
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# PASS: no hooks configured at all (the real fleet's shape)
# ---------------------------------------------------------------------------

def test_no_hooks_key_passes():
    r = check_hooks_enable_toggles(_ctx({}))
    assert r.status == PASS


def test_empty_hooks_object_passes():
    r = check_hooks_enable_toggles(_ctx({"hooks": {}}))
    assert r.status == PASS


def test_hooks_enabled_false_passes():
    r = check_hooks_enable_toggles(_ctx({"hooks": {"enabled": False}}))
    assert r.status == PASS


def test_hooks_mappings_alone_without_enable_toggles_passes():
    """B169/B48 already cover hooks.mappings[] content -- B179 only inventories the
    enable-toggles and must not double-fire just because mappings exist."""
    r = check_hooks_enable_toggles(_ctx({
        "hooks": {"mappings": [{"id": "x", "messageTemplate": "hi {{name}}"}]},
    }))
    assert r.status == PASS


def test_internal_enabled_false_passes():
    r = check_hooks_enable_toggles(_ctx({
        "hooks": {"internal": {"enabled": False, "entries": {"onSessionStart": {}}}},
    }))
    assert r.status == PASS


def test_clean_fixture_passes():
    r = check_hooks_enable_toggles(collect(FIXTURES / "clean_b179_hooks_absent"))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# WARN: real positive evidence of an enabled hooks surface
# ---------------------------------------------------------------------------

def test_hooks_enabled_true_warns():
    r = check_hooks_enable_toggles(_ctx({"hooks": {"enabled": True}}))
    assert r.status == WARN
    assert any("hooks.enabled" in e for e in r.evidence)


def test_internal_enabled_true_warns():
    r = check_hooks_enable_toggles(_ctx({"hooks": {"internal": {"enabled": True}}}))
    assert r.status == WARN
    assert any("hooks.internal.enabled" in e for e in r.evidence)


def test_internal_enabled_entry_warns():
    r = check_hooks_enable_toggles(_ctx({
        "hooks": {"internal": {"entries": {"onSessionStart": {"module": "./x.js"}}}},
    }))
    assert r.status == WARN
    assert any("hooks.internal.entries" in e and "onSessionStart" in e for e in r.evidence)


def test_internal_entry_explicitly_disabled_does_not_warn_alone():
    """A single entries[] item with enabled: false is not a live load surface -- must
    not by itself trigger WARN."""
    r = check_hooks_enable_toggles(_ctx({
        "hooks": {"internal": {"entries": {"onSessionStart": {"enabled": False}}}},
    }))
    assert r.status == PASS


def test_internal_installs_warns():
    r = check_hooks_enable_toggles(_ctx({
        "hooks": {"internal": {"installs": {"my-pack": {"source": "npm:my-pack@1.0.0"}}}},
    }))
    assert r.status == WARN
    assert any("hooks.internal.installs" in e for e in r.evidence)


def test_extra_dirs_warns_with_codeexec_wording():
    r = check_hooks_enable_toggles(_ctx({
        "hooks": {"internal": {"load": {"extraDirs": ["./custom-hooks"]}}},
    }))
    assert r.status == WARN
    assert any("hooks.internal.load.extraDirs" in e and "custom-hooks" in e for e in r.evidence)
    assert "code-exec" in r.detail or "persistence" in r.detail


def test_blank_extra_dirs_entries_do_not_warn():
    """A blank/whitespace-only extraDirs string is not a real configured directory."""
    r = check_hooks_enable_toggles(_ctx({
        "hooks": {"internal": {"load": {"extraDirs": ["", "   "]}}},
    }))
    assert r.status == PASS


def test_bad_fixture_repro_from_task_warns():
    """The task's own repro payload: hooks.enabled + hooks.internal.enabled +
    load.extraDirs + an entries[] item -- all four evidence lines must appear."""
    r = check_hooks_enable_toggles(
        collect(FIXTURES / "bad_b179_hooks_internal_extradirs")
    )
    assert r.status == WARN
    assert any("hooks.enabled" in e for e in r.evidence)
    assert any("hooks.internal.enabled" in e for e in r.evidence)
    assert any("hooks.internal.entries" in e for e in r.evidence)
    assert any("hooks.internal.load.extraDirs" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# UNKNOWN: config present but unparseable
# ---------------------------------------------------------------------------

def test_unreadable_config_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = "boom"
    r = check_hooks_enable_toggles(c)
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# Check metadata / never-FAIL contract
# ---------------------------------------------------------------------------

def test_check_id_is_b179():
    r = check_hooks_enable_toggles(_ctx({"hooks": {"enabled": True}}))
    assert r.id == "B179"


def test_check_is_unscored_advisory():
    assert BY_ID["B179"].scored is False


def test_check_severity_is_low():
    assert BY_ID["B179"].severity == "LOW"


def test_hooks_webhooks_is_not_a_real_field_no_dig_path():
    """Spec correction guard: the originating bug title says 'hooks.webhooks', but that
    key does not exist in the schema -- it must never appear as a dig() literal."""
    import ast
    import inspect

    from clawseccheck.checks import _config

    src = inspect.getsource(_config.check_hooks_enable_toggles)
    tree = ast.parse(src)
    dig_paths = set()

    class V(ast.NodeVisitor):
        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == "dig" and len(node.args) >= 2:
                arg = node.args[1]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    dig_paths.add(arg.value)
            self.generic_visit(node)

    V().visit(tree)
    assert "hooks.webhooks" not in dig_paths
    assert dig_paths == {
        "hooks.enabled",
        "hooks.internal.enabled",
        "hooks.internal.entries",
        "hooks.internal.installs",
        "hooks.internal.load.extraDirs",
    }


@pytest.mark.parametrize("cfg", [
    {},
    {"hooks": {"enabled": True}},
    {"hooks": {"internal": {"enabled": True}}},
    {"hooks": {"internal": {"load": {"extraDirs": ["./x"]}}}},
])
def test_never_fails(cfg):
    r = check_hooks_enable_toggles(_ctx(cfg))
    assert r.status != FAIL
