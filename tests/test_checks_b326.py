"""B326: agents.defaults.elevatedDefault="full" bypasses human approval by default.

Grounded against the installed OpenClaw dist (2026-07-28, v2026.7.1-2) — see
docs/research/openclaw-schema-recon.md section 39 (workspace root, not shipped) and
clawseccheck/checks/_capability.py's check_elevated_default_full docstring/grounding
comment for the full trail.

Round-2 (independent C-135 review): the original WARN condition only covered
tools.elevated.enabled==False. The reviewer traced resolveElevatedPermissions() and
found a SECOND, independent unconditional block on the same {enabled, allowed} object
every consumer (get-reply.js AND bash-tools.js) shares: the GLOBAL
tools.elevated.allowFrom having no entry that could ever match a sender. A per-agent
allowFrom can only ever further RESTRICT after the global check already passed, never
grant access on its own -- so only the global leg needs checking. The WARN condition
now covers EITHER dormancy gate.

Severity shape:
  - no config file at all                                                -> UNKNOWN
  - config present but unparseable                                       -> UNKNOWN
  - elevatedDefault absent                                                -> PASS
  - elevatedDefault == "off"                                              -> PASS
  - elevatedDefault == "on"  (the stock runtime default, TRAP case)       -> PASS
  - elevatedDefault == "ask"                                              -> PASS
  - elevatedDefault == "full", enabled != False, allowFrom has an entry   -> FAIL
  - elevatedDefault == "full", enabled == False                          -> WARN
  - elevatedDefault == "full", allowFrom has no entry anywhere            -> WARN
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_elevated_default_full
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


def test_clean_fixture_absent_passes():
    r = check_elevated_default_full(
        collect(FIXTURES / "clean_b326_elevated_default_absent")
    )
    assert r.status == PASS


def test_clean_fixture_on_passes_the_trap_case():
    """"on" is the stock runtime default and behaviorally identical to "ask" (both
    approval-gated) -- must NOT fire, or this would be a mass false FAIL restating
    existing B43/B48/B55 coverage for no new signal."""
    r = check_elevated_default_full(
        collect(FIXTURES / "clean_b326_elevated_default_on")
    )
    assert r.status == PASS
    assert r.status != FAIL
    assert r.status != WARN


def test_bad_fixture_full_reachable_fails():
    """The bad fixture must configure a real tools.elevated.allowFrom entry -- without
    one, per the round-2 fix, "full" is dormant (WARN), not reachable (FAIL). This is
    the exact coverage gap an independent C-135 pass caught in round 1."""
    r = check_elevated_default_full(
        collect(FIXTURES / "bad_b326_elevated_default_full")
    )
    assert r.status == FAIL
    assert "full" in r.detail


def test_warn_fixture_full_dormant_enabled_false_warns():
    """WARN via the tools.elevated.enabled=false gate -- allowFrom is configured on
    this fixture too, isolating this as the dormancy reason under test."""
    r = check_elevated_default_full(
        collect(FIXTURES / "warn_b326_elevated_default_full_dormant")
    )
    assert r.status == WARN
    assert "tools.elevated.enabled=false" in r.detail


def test_warn_fixture_full_no_allowfrom_warns():
    """WARN via the missing-allowFrom gate -- tools.elevated.enabled is explicitly
    true on this fixture, isolating this as the dormancy reason under test."""
    r = check_elevated_default_full(
        collect(FIXTURES / "warn_b326_elevated_default_full_no_allowfrom")
    )
    assert r.status == WARN
    assert "allowFrom" in r.detail


def test_unknown_fixture_unparseable_is_unknown():
    r = check_elevated_default_full(
        collect(FIXTURES / "unknown_b326_elevated_default_unparseable")
    )
    assert r.status == UNKNOWN


def test_no_config_file_is_unknown(tmp_path):
    home = _home(tmp_path, config=None)
    r = check_elevated_default_full(collect(home))
    assert r.status == UNKNOWN


def test_elevated_default_off_is_pass(tmp_path):
    home = _home(tmp_path, config={"agents": {"defaults": {"elevatedDefault": "off"}}})
    r = check_elevated_default_full(collect(home))
    assert r.status == PASS


def test_elevated_default_ask_is_pass(tmp_path):
    home = _home(tmp_path, config={"agents": {"defaults": {"elevatedDefault": "ask"}}})
    r = check_elevated_default_full(collect(home))
    assert r.status == PASS


def test_elevated_default_full_no_tools_block_is_warn_not_fail(tmp_path):
    """Adversarial edge case (the exact gap round-1's C-135 self-check missed): with
    no tools.elevated block at all, enabled defaults true (not the WARN trigger), but
    allowFrom is also absent -- which alone makes the bypass unreachable today. Must
    be WARN, not FAIL."""
    home = _home(tmp_path, config={"agents": {"defaults": {"elevatedDefault": "full"}}})
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_enabled_true_no_allowfrom_is_warn(tmp_path):
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_enabled_true_with_allowfrom_is_fail(tmp_path):
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True, "allowFrom": {"telegram": ["*"]}}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == FAIL


def test_elevated_default_full_enabled_false_with_allowfrom_is_warn(tmp_path):
    """tools.elevated.enabled=false alone is enough to WARN, even with a configured
    allowFrom -- either dormancy gate is sufficient on its own."""
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {
                "elevated": {"enabled": False, "allowFrom": {"telegram": ["*"]}}
            },
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_empty_allowfrom_dict_is_warn(tmp_path):
    """An explicitly-declared but empty tools.elevated.allowFrom dict is the same as
    absent -- no provider has a matching entry."""
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True, "allowFrom": {}}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_allowfrom_empty_list_for_provider_is_warn(tmp_path):
    """A provider entry present but holding an empty list matches no sender either."""
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True, "allowFrom": {"telegram": []}}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_allowfrom_bare_string_value_is_warn(tmp_path):
    """Round-2 C-135 correction: resolveElevatedAllowList() only honors a per-provider
    value when Array.isArray(value) is true -- a bare string like "*" is never read
    (falls through to the always-undefined fallback in this dist), so it must count
    as absent, not present."""
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True, "allowFrom": {"telegram": "*"}}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_allowfrom_blank_entries_is_warn(tmp_path):
    """Round-2 C-135 correction: normalizeStringEntries() trims each element and drops
    empty results before length is checked -- an array of only empty/whitespace-only
    strings normalizes to [] and is never reachable."""
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {
                "elevated": {"enabled": True, "allowFrom": {"telegram": ["", "   "]}}
            },
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_allowfrom_single_whitespace_entry_is_warn(tmp_path):
    """Same as above with a single whitespace-only entry."""
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True, "allowFrom": {"telegram": ["   "]}}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_allowfrom_bom_entry_is_warn(tmp_path):
    """Round-3 C-135 correction: JS String.prototype.trim() (what
    normalizeStringEntries() actually uses) strips U+FEFF (BOM/ZWNBSP) to empty, but
    Python's str.strip()/isspace() does NOT treat U+FEFF as whitespace -- an entry that
    is only a BOM character normalizes to "" in the real resolver and must stay WARN,
    not FAIL."""
    bom = "\ufeff"
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {
                "elevated": {"enabled": True, "allowFrom": {"telegram": [bom]}}
            },
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_allowfrom_nbsp_entry_is_warn(tmp_path):
    """Round-3 C-135 correction, companion case: U+00A0 (NBSP) is also part of the
    ECMA-262 WhiteSpace production JS's .trim() strips, so an NBSP-only entry must
    also normalize away and stay WARN."""
    nbsp = "\xa0"
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True, "allowFrom": {"telegram": [nbsp]}}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_elevated_default_full_allowfrom_zero_width_space_entry_is_fail(tmp_path):
    """Adversarial edge case pinning the OTHER direction: U+200B (zero-width space) is
    NOT part of what JS .trim() strips (verified empirically in Node v22), so an entry
    that is only a zero-width space is genuinely non-empty to the real resolver and
    must count as reachable -- FAIL, not WARN. Guards against over-broadening the
    JS-whitespace charset beyond what .trim() actually strips."""
    zwsp = "\u200b"
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True, "allowFrom": {"telegram": [zwsp]}}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == FAIL


def test_agents_list_per_agent_allowfrom_does_not_rescue_missing_global(tmp_path):
    """Grounding correction pinned by the round-2 fix: a per-agent
    tools.elevated.allowFrom can only further RESTRICT after the GLOBAL check already
    passed (resolveElevatedPermissions returns early on a failed globalAllowed, before
    agentAllowed is even computed) -- it can never grant reachability the global gate
    denies. A per-agent allowFrom with no global allowFrom must stay WARN, not FAIL."""
    home = _home(
        tmp_path,
        config={
            "agents": {
                "defaults": {"elevatedDefault": "full"},
                "list": [
                    {
                        "name": "Gary",
                        "tools": {"elevated": {"allowFrom": {"telegram": ["*"]}}},
                    }
                ],
            },
            "tools": {"elevated": {"enabled": True}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == WARN


def test_agents_defaults_block_entirely_absent_is_pass(tmp_path):
    home = _home(tmp_path, config={"tools": {"profile": "minimal"}})
    r = check_elevated_default_full(collect(home))
    assert r.status == PASS


def test_unrecognized_value_is_pass_not_warn(tmp_path):
    """Adversarial edge case: a garbage/typo'd value is not the dangerous "full"
    literal and must not be treated as if it were -- this is a strict-equality check,
    not a substring/keyword match."""
    home = _home(
        tmp_path, config={"agents": {"defaults": {"elevatedDefault": "full-access"}}}
    )
    r = check_elevated_default_full(collect(home))
    assert r.status == PASS


def test_fix_text_names_the_field(tmp_path):
    home = _home(
        tmp_path,
        config={
            "agents": {"defaults": {"elevatedDefault": "full"}},
            "tools": {"elevated": {"enabled": True, "allowFrom": {"telegram": ["*"]}}},
        },
    )
    r = check_elevated_default_full(collect(home))
    assert "elevatedDefault" in r.fix
    assert "ask" in r.fix
