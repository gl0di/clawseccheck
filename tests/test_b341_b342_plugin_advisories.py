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

B-401 (polarity fix). Both checks originally read "field absent" as "not granted" for
`hooks.allowPromptInjection` (B341) and `plugins.slots.memory` (B342). Grounded against the
runtime ENFORCEMENT / normalization sites (not just the schema shape):

* `registry-B8eQDFB4.js:1390` — `...hooks?.allowPromptInjection !== false` — the grant is
  held UNLESS explicitly withdrawn with `false`; absent is the same granted state as `true`.
* `config-normalization-shared-w2iz0aeC.js:314-323` — an unset `plugins.slots.memory`
  normalizes to `defaultSlotIdForKey("memory")` = the bundled `"memory-core"` plugin, not to
  "no owner". Only the literal `"none"` disables the slot.

`hooks.allowConversationAccess` (B341) and `plugins.slots.contextEngine` (B342) do **not**
share this polarity (grounded separately, see the two check docstrings) and are unchanged:
absent still reads as "not granted" / "no owner" for those two fields specifically.
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
    """Only an explicit `False` withholds the grant -- the safe, corrected state."""
    cfg = {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": False}}}}}
    assert check_plugin_hook_grants(_ctx(cfg)).status == PASS


# -------------------------------------------------------------- B-401: the four-case matrix


def test_b341_absent_prompt_injection_field_is_a_grant():
    """B-401: an omitted `allowPromptInjection` -- with a `hooks` object present for an
    unrelated field -- is the SAME granted state as an explicit `true` (grounded
    `!== false` semantics), so it must WARN, not PASS silently."""
    cfg = {"plugins": {"entries": {"p": {"hooks": {"timeoutMs": 1000}}}}}
    f = check_plugin_hook_grants(_ctx(cfg))
    assert f.status == WARN
    assert any("allowPromptInjection" in e for e in f.evidence or [])


def test_b341_entirely_absent_hooks_block_is_also_a_grant():
    """B-401: the field can be absent because the WHOLE `hooks` object is absent -- the
    real enforcement site reads `entry?.hooks?.allowPromptInjection`, so an entry with no
    `hooks` key at all is just the field being maximally absent, still granted."""
    cfg = {"plugins": {"entries": {"p": {"enabled": True}}}}
    f = check_plugin_hook_grants(_ctx(cfg))
    assert f.status == WARN
    assert any("allowPromptInjection" in e for e in f.evidence or [])


def test_b341_explicit_true_is_a_grant():
    cfg = {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": True}}}}}
    f = check_plugin_hook_grants(_ctx(cfg))
    assert f.status == WARN
    assert any("allowPromptInjection" in e for e in f.evidence or [])


def test_b341_malformed_prompt_injection_value_is_unknown():
    """B-401 / Golden Rule #4: a non-boolean value doesn't match the schema
    (`boolean().optional()`) and must never be read confidently either way."""
    for value in ("yes", 1, ["x"], {}):
        cfg = {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": value}}}}}
        f = check_plugin_hook_grants(_ctx(cfg))
        assert f.status == UNKNOWN, (value, f.status)
        assert any("allowPromptInjection" in e for e in f.evidence or [])


def test_b341_malformed_conversation_access_value_is_unknown():
    """Same Golden Rule #4 treatment for the OTHER field -- previously silently folded
    into PASS as "not `is True`", which is itself an unjustified confident guess.
    `allowPromptInjection` is pinned explicitly to `False` in the same entry so its own
    (correct, post-B-401) default-grant reading can't also fire and mask the result."""
    for value in ("yes", 1, ["x"], {}):
        cfg = {
            "plugins": {
                "entries": {
                    "p": {
                        "hooks": {
                            "allowPromptInjection": False,
                            "allowConversationAccess": value,
                        }
                    }
                }
            }
        }
        f = check_plugin_hook_grants(_ctx(cfg))
        assert f.status == UNKNOWN, (value, f.status)
        assert any("allowConversationAccess" in e for e in f.evidence or [])


def test_b341_conversation_access_absent_is_still_not_a_grant():
    """`allowConversationAccess` does NOT share allowPromptInjection's polarity (see
    module docstring) -- absent stays the safe reading, unchanged by B-401."""
    cfg = {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": False}}}}}
    assert check_plugin_hook_grants(_ctx(cfg)).status == PASS


def test_b341_fix_text_never_recommends_the_permissive_default():
    """B-401 general guard: whenever a PASS/WARN/UNKNOWN fix string names
    `allowPromptInjection`, it must pair it with the real safe action (`false`) -- never
    tell the operator that leaving it unset is fine, which is the exact defect this
    ticket fixed (the old PASS fix text was 'Keep per-plugin hook grants unset...')."""
    configs = [
        {},
        {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": True}}}}},
        {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": False}}}}},
        {"plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": "yes"}}}}},
    ]
    for cfg in configs:
        f = check_plugin_hook_grants(_ctx(cfg))
        fix = f.fix or ""
        if "allowPromptInjection" in fix:
            assert "false" in fix, (cfg, f.status, fix)
        # Regression pin: the exact old, wrong PASS fix text must never come back.
        assert "unset unless a plugin genuinely needs them" not in fix, (cfg, f.status, fix)


def test_b341_unknown_when_no_plugins():
    assert check_plugin_hook_grants(_ctx({})).status == UNKNOWN


def test_b341_root_level_hooks_are_not_the_plugin_entry_hooks():
    """The root `hooks` block is a different schema; it must not drive this check. The
    entry itself explicitly withholds the grant so the assertion isolates the root-vs-
    entry separation from the (correct, post-B-401) absent-is-granted behavior."""
    cfg = {
        "hooks": {"allowPromptInjection": True},
        "plugins": {"entries": {"p": {"hooks": {"allowPromptInjection": False}}}},
    }
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
    cfg = {"plugins": {"slots": {"memory": "none", "contextEngine": "ctxplug"}}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any("contextEngine=ctxplug" in e for e in f.evidence or [])


def test_b342_allow_deny_overlap_is_reported():
    cfg = {"plugins": {"slots": {"memory": "none"}, "allow": ["a", "b"], "deny": ["b"]}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any(e.startswith("b:") for e in f.evidence or [])


def test_b342_disjoint_allow_and_deny_is_clean():
    cfg = {"plugins": {"slots": {"memory": "none"}, "allow": ["a"], "deny": ["b"]}}
    assert check_plugin_slots_and_deny(_ctx(cfg)).status == PASS


def test_b342_unknown_when_no_plugins_block():
    assert check_plugin_slots_and_deny(_ctx({})).status == UNKNOWN
    assert check_plugin_slots_and_deny(_ctx({"plugins": {}})).status == UNKNOWN


# -------------------------------------------------------------- B-401: the four-case matrix
# (mirrors the B341 matrix above, but for `plugins.slots.memory`'s implicit "memory-core"
# default -- `plugins.slots.contextEngine` has no such default and is covered by the
# unchanged `test_b342_context_engine_slot_is_reported_too` above.)


def test_b342_absent_slots_block_is_the_memory_core_default():
    """B-401: no `plugins.slots` key at all still resolves to the bundled `memory-core`
    default owner (config-normalization-shared-w2iz0aeC.js:314-323), not "no owner"."""
    cfg = {"plugins": {"entries": {"p": {"enabled": True}}}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any("plugins.slots.memory=memory-core" in e for e in f.evidence or [])


def test_b342_absent_memory_field_is_the_memory_core_default():
    """Same default, but with an explicit (empty) `plugins.slots` object -- isolates
    "memory key omitted" from "slots block omitted entirely"."""
    cfg = {"plugins": {"slots": {}}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any("plugins.slots.memory=memory-core" in e for e in f.evidence or [])


def test_b342_explicit_memory_owner_is_reported():
    cfg = {"plugins": {"slots": {"memory": "custom-memory-plugin"}}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any("plugins.slots.memory=custom-memory-plugin" in e for e in f.evidence or [])


def test_b342_explicit_none_is_the_clean_case():
    cfg = {"plugins": {"slots": {"memory": "none"}}}
    assert check_plugin_slots_and_deny(_ctx(cfg)).status == PASS


def test_b342_malformed_memory_value_is_unknown():
    """Golden Rule #4: a non-string `plugins.slots.memory` is schema-invalid
    (`string().optional()`) and must never be folded into either "owned" or "disabled"."""
    for value in (7, ["x"], {"a": 1}, True):
        cfg = {"plugins": {"slots": {"memory": value}}}
        f = check_plugin_slots_and_deny(_ctx(cfg))
        assert f.status == UNKNOWN, (value, f.status)
        assert any("plugins.slots.memory" in e for e in f.evidence or [])


def test_b342_malformed_slots_block_is_unknown():
    cfg = {"plugins": {"slots": "not-a-dict"}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == UNKNOWN
    assert any("plugins.slots" in e for e in f.evidence or [])


def test_b342_fix_text_never_recommends_the_permissive_default():
    """B-401 general guard: whenever a fix string names `plugins.slots.memory`, it must
    pair it with the real safe action (explicit `"none"`) -- never imply that leaving it
    unset is the safe/no-owner state."""
    configs = [
        {},
        {"plugins": {"slots": {"memory": "custom"}}},
        {"plugins": {"slots": {"memory": "none"}}},
        {"plugins": {"slots": {"memory": 7}}},
    ]
    for cfg in configs:
        f = check_plugin_slots_and_deny(_ctx(cfg))
        fix = f.fix or ""
        if "plugins.slots.memory" in fix:
            assert "none" in fix, (cfg, f.status, fix)


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


# ---------------------------------------------------- B-421: implicit-default owner gating
# The unset `plugins.slots.memory` default only takes effect when OpenClaw's own activation
# precedence actually lets it -- config-normalization-shared-w2iz0aeC.js:70-100
# (`resolvePluginActivationDecisionShared`) and gateway-startup-plugin-ids-COmsQTCi.js
# :603-614 (`resolveMemorySlotStartupPluginId`, which resolves who actually backs the
# memory slot when the field is left unset). Before B-421 the implicit default was
# disclosed unconditionally, which WARNed on this project's own fixtures/home_safe.


def test_b342_implicit_default_not_disclosed_when_plugins_disabled():
    """Gate 1 -- config-normalization-shared-w2iz0aeC.js:70, `!config.enabled`."""
    cfg = {"plugins": {"enabled": False}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == PASS, f.evidence


def test_b342_implicit_default_not_disclosed_when_denied():
    """Gate 2 -- :77, `deny.includes(id)` -- deny wins even over the implicit default."""
    cfg = {"plugins": {"deny": ["memory-core"]}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == PASS, f.evidence


def test_b342_implicit_default_not_disclosed_when_entry_disabled():
    """Gate 3 -- :85, `entry?.enabled === false`."""
    cfg = {"plugins": {"entries": {"memory-core": {"enabled": False}}}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == PASS, f.evidence


def test_b342_implicit_default_not_disclosed_when_excluded_by_allowlist():
    """Gate 4 -- gateway-startup-plugin-ids-COmsQTCi.js:610: a non-empty `plugins.allow`
    that omits the bundled default id means the implicit default is never even selected
    as a candidate. This is fixtures/home_safe's own shape."""
    cfg = {"plugins": {"allow": ["trentclaw"]}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == PASS, f.evidence


def test_b342_implicit_default_still_disclosed_when_no_gate_applies():
    """Regression pin: the B-401 default-owner disclosure itself must still fire when
    none of the four B-421 gates block it (an unrelated entry "p" does not touch
    memory-core's own gates)."""
    cfg = {"plugins": {"entries": {"p": {"enabled": True}}}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any("plugins.slots.memory=memory-core" in e for e in f.evidence or [])


def test_b342_gates_do_not_affect_an_explicitly_named_owner():
    """B-421 scope: only the UNSET/blank implicit-default path is gated -- an explicitly
    named plugins.slots.memory owner is still disclosed regardless (it is a direct
    statement in the config, not an inferred default; unchanged from B-401)."""
    cfg = {"plugins": {"enabled": False, "slots": {"memory": "custom-memory-plugin"}}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any("plugins.slots.memory=custom-memory-plugin" in e for e in f.evidence or [])


def test_b342_home_safe_fixture_no_longer_warns():
    """The exact repro from CLAWSECCHECK-B-421: fixtures/home_safe
    (plugins.allow: ["trentclaw"], nothing else in the plugin block) used to WARN B342
    unconditionally on this project's own canonical clean baseline config."""
    f = check_plugin_slots_and_deny(collect(home=str(FIXTURES / "home_safe")))
    assert f.status == PASS, f.evidence


# --------------------------------------------------- B-421: allow/deny alias normalization


def test_b342_allow_deny_alias_collision_is_reported():
    """OpenClaw's own `normalizePluginId` (config-state-CtMlHVRM.js:6-9) folds a built-in
    alias to its canonical id before activation, so an id pair that LOOKS disjoint can
    still collide. `google-gemini-cli` -> `google` is a real, grounded alias (contrast
    with the case-difference test below, which is NOT folded by the real normalizer)."""
    cfg = {
        "plugins": {
            "slots": {"memory": "none"},
            "allow": ["google-gemini-cli"],
            "deny": ["google"],
        }
    }
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    joined = " ".join(f.evidence or [])
    assert "google-gemini-cli" in joined and "google" in joined


def test_b342_allow_deny_canonical_id_case_difference_is_a_collision():
    """Post-B-421 correction: the real BUILT_IN_PLUGIN_ALIAS_LOOKUP (config-state-
    CtMlHVRM.js:11) is built as `new Map([...FALLBACKS, ...FALLBACKS.map(([, id]) =>
    [id, id])])` -- it self-maps the two canonical alias TARGETS ("google", "minimax")
    in addition to the 3 alias -> canonical entries, and the lookup itself is
    case-insensitive (normalizeOptionalLowercaseString runs before the map .get()). So,
    unlike an arbitrary non-alias id (see the case-difference-is-not-a-collision test
    below), a bare case difference on "google" IS folded together by the real
    normalizer and must be reported as a contradiction."""
    cfg = {
        "plugins": {
            "slots": {"memory": "none"},
            "allow": ["Google"],
            "deny": ["google"],
        }
    }
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    joined = " ".join(f.evidence or [])
    assert "Google" in joined and "google" in joined


def test_b342_allow_deny_case_difference_alone_is_not_a_collision():
    """Grounding correction: the real `normalizePluginId` (config-state-CtMlHVRM.js
    :17-23) does NOT lowercase arbitrary ids OUTSIDE the built-in alias table -- it only
    trims them and falls back to the case-preserved original on an alias-lookup miss. So
    a bare case difference on an id that is NOT in that table (like `memory-core`, which
    is never a built-in alias target -- confirmed separately) is not treated as a
    collision. Contrast the alias-table self-entry case above (`google`/`Google`), where
    the lookup IS case-insensitive because the id is a member of the table."""
    cfg = {
        "plugins": {
            "slots": {"memory": "none"},
            "allow": ["Memory-Core"],
            "deny": ["memory-core"],
        }
    }
    assert check_plugin_slots_and_deny(_ctx(cfg)).status == PASS


def test_b342_allow_deny_literal_match_still_uses_the_plain_evidence_format():
    """Regression pin: a literal (non-alias) match keeps the original, simpler evidence
    string -- only an alias-obscured collision gets the two-sided phrasing."""
    cfg = {"plugins": {"slots": {"memory": "none"}, "allow": ["a", "b"], "deny": ["b"]}}
    f = check_plugin_slots_and_deny(_ctx(cfg))
    assert f.status == WARN
    assert any(e == "b: in both plugins.allow and plugins.deny (deny wins)" for e in f.evidence or [])
