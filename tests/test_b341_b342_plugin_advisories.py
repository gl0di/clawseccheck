"""B341 / B342 — two unscored disclosure advisories over the plugin block.

Before these, only `plugins.allow` / `plugins.entries` / `plugins.mcp` / `plugins.load.paths`
were read anywhere in the package. Both new checks are WARN-only and `scored=False`: they
surface a grant an operator should be able to see named in an audit, they do not adjudicate
it. Config alone cannot tell an intentional grant from an abusive one, so a FAIL here would
be a verdict the tool has no basis for.

Grounding (installed openclaw npm dist, `zod-schema-O9ml_nmo.js`):

* B341 — `PluginEntrySchema.hooks.{allowPromptInjection, allowConversationAccess}` at
  :788-806. Note the per-entry `hooks` object is NOT the root-level `hooks` block
  (a separate `.strict()` schema with no such fields).
* B342 — `plugins.slots` at :1521-1529 is a `.strict()` object with exactly two optional
  string fields, `memory` and `contextEngine` — not a record of arbitrary slot names.
  `plugins.deny` blocks an id "even if allowlists or paths include them"
  (`schema-DRyO1XBt.js:809`), so deny wins over allow and an id in both is silently blocked.

The `"none"` case is the sharp edge worth pinning: `plugins.slots.memory: "none"` is the
documented value for DISABLING memory plugins, i.e. the opposite of a slot capture. Reporting
it would be a false positive on a config that is strictly safer than the default.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_plugin_hook_grants, check_plugin_slots_and_deny
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# --------------------------------------------------------------------- contract: never FAIL

def test_both_advisories_are_unscored():
    for cid in ("B341", "B342"):
        assert BY_ID[cid].scored is False, cid


def test_neither_check_can_ever_fail():
    """Every reachable branch, driven through the real check functions."""
    configs = [
        {},
        {"plugins": {}},
        {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": True}}}}},
        {"plugins": {"entries": {"p": {"enabled": True}}}},
        {"plugins": {"slots": {"memory": "m", "contextEngine": "c"}}},
        {"plugins": {"allow": ["x"], "deny": ["x"]}},
    ]
    for cfg in configs:
        for fn in (check_plugin_hook_grants, check_plugin_slots_and_deny):
            assert fn(_ctx(cfg)).status != FAIL, (fn.__name__, cfg)


# ------------------------------------------------------------------------ B341: fixtures

def test_b341_bad_fixture_warns():
    f = check_plugin_hook_grants(collect(home=str(FIXTURES / "bad_b341_plugin_hook_grants")))
    assert f.status == WARN
    joined = " ".join(f.evidence or [])
    assert "notes" in joined and "allowPromptInjection" in joined
    assert "recall" in joined and "allowConversationAccess" in joined


def test_b341_clean_fixture_passes():
    f = check_plugin_hook_grants(collect(home=str(FIXTURES / "clean_b341_plugin_hook_grants")))
    assert f.status == PASS


# ------------------------------------------------------------------------- B341: semantics

def test_b341_false_is_not_a_grant():
    """Only `is True` counts — an explicitly-disabled grant is not a grant."""
    cfg = {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": False}}}}}
    assert check_plugin_hook_grants(_ctx(cfg)).status == PASS


def test_b341_truthy_non_true_is_not_a_grant():
    """A schema-invalid truthy value is not read as an enabled boolean grant."""
    for value in ("yes", 1, ["x"], {}):
        cfg = {"plugins": {"entries": {"p": {"hooks": {"allowConversationAccess": value}}}}}
        assert check_plugin_hook_grants(_ctx(cfg)).status == PASS, value


def test_b341_unknown_when_no_plugins():
    assert check_plugin_hook_grants(_ctx({})).status == UNKNOWN


def test_b341_root_level_hooks_are_not_the_plugin_entry_hooks():
    """The root `hooks` block is a different schema; it must not drive this check."""
    cfg = {"hooks": {"allowPromptInjection": True}, "plugins": {"entries": {"p": {}}}}
    assert check_plugin_hook_grants(_ctx(cfg)).status == PASS


def test_b341_malformed_shapes_do_not_raise():
    for cfg in (
        {"plugins": {"entries": {"p": "not-a-dict"}}},
        {"plugins": {"entries": {"p": {"hooks": "not-a-dict"}}}},
        {"plugins": {"entries": {"p": {"hooks": None}}}},
        {"plugins": {"entries": []}},
        {"plugins": "not-a-dict"},
        {"plugins": None},
    ):
        assert check_plugin_hook_grants(_ctx(cfg)).status != FAIL, cfg


# ------------------------------------------------------------------------ B342: fixtures

def test_b342_bad_fixture_warns():
    f = check_plugin_slots_and_deny(collect(home=str(FIXTURES / "bad_b342_plugin_slots_deny")))
    assert f.status == WARN
    joined = " ".join(f.evidence or [])
    assert "plugins.slots.memory=memkeeper" in joined
    assert "rolled-back" in joined


def test_b342_clean_fixture_passes():
    """That fixture sets slots.memory to "none" and keeps allow/deny disjoint."""
    f = check_plugin_slots_and_deny(collect(home=str(FIXTURES / "clean_b342_plugin_slots_deny")))
    assert f.status == PASS


# ------------------------------------------------------------------------- B342: semantics

def test_b342_none_disables_the_slot_and_is_never_reported():
    """`"none"` is the documented way to DISABLE memory plugins — reporting it would be a
    false positive on a config that is strictly safer than the default."""
    for value in ("none", "NONE", " none "):
        cfg = {"plugins": {"slots": {"memory": value}}}
        assert check_plugin_slots_and_deny(_ctx(cfg)).status == PASS, value


def test_b342_context_engine_slot_is_reported_too():
    cfg = {"plugins": {"slots": {"contextEngine": "ctxplug"}}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any("contextEngine=ctxplug" in e for e in f.evidence or [])


def test_b342_allow_deny_overlap_is_reported():
    cfg = {"plugins": {"allow": ["a", "b"], "deny": ["b"]}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any(e.startswith("b:") for e in f.evidence or [])


def test_b342_disjoint_allow_and_deny_is_clean():
    cfg = {"plugins": {"allow": ["a"], "deny": ["b"]}}
    assert check_plugin_slots_and_deny(_ctx(cfg)).status == PASS


def test_b342_unknown_when_no_plugins_block():
    assert check_plugin_slots_and_deny(_ctx({})).status == UNKNOWN
    assert check_plugin_slots_and_deny(_ctx({"plugins": {}})).status == UNKNOWN


def test_b342_malformed_shapes_do_not_raise():
    for cfg in (
        {"plugins": {"slots": "not-a-dict"}},
        {"plugins": {"slots": {"memory": None}}},
        {"plugins": {"slots": {"memory": 7}}},
        {"plugins": {"slots": {"memory": "   "}}},
        {"plugins": {"allow": "not-a-list", "deny": ["b"]}},
        {"plugins": {"allow": ["a"], "deny": "not-a-list"}},
        {"plugins": {"allow": [None, 3], "deny": [None, 3]}},
        {"plugins": "not-a-dict"},
    ):
        assert check_plugin_slots_and_deny(_ctx(cfg)).status != FAIL, cfg
