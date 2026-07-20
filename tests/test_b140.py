"""B140 — Wildcard group ingress with no allowFrom restriction (B-139) tests.

Logic under test (check_wildcard_group_ingress):
- UNKNOWN  when no channels block is present (or it only holds non-provider entries,
           e.g. only 'defaults').
- PASS     when channels are configured but no provider has a groups["*"] wildcard
           entry, or every wildcard entry is restricted by an effective allowFrom
           (channel-level or on the "*" group itself).
- WARN     when a provider has a groups["*"] wildcard entry with no allowFrom
           anywhere (neither channel-level nor per-group) — never FAIL, since a
           public/community bot may accept this deliberately.

Design notes:
- The 'defaults' key inside channels is a config block, not a provider; it must not
  be treated as a channel itself (same pattern as B26 / check_untrusted_context).
- allowFrom can restrict the wildcard group either on the "*" group's own dict, or
  as a sibling of "groups" at the channel level — either is sufficient to PASS.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_wildcard_group_ingress
from clawseccheck.collector import Context

RELIABILITY = Path(__file__).resolve().parent.parent / "fixtures" / "reliability"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# UNKNOWN cases
# ---------------------------------------------------------------------------

def test_b140_no_channels_key_unknown():
    """No channels block at all -> UNKNOWN."""
    assert check_wildcard_group_ingress(_ctx({})).status == UNKNOWN


def test_b140_empty_channels_dict_unknown():
    """channels present but empty -> UNKNOWN."""
    assert check_wildcard_group_ingress(_ctx({"channels": {}})).status == UNKNOWN


def test_b140_channels_only_defaults_block_unknown():
    """channels contains only a 'defaults' block with no real providers -> UNKNOWN."""
    cfg = {"channels": {"defaults": {"contextVisibility": "allowlist"}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS cases
# ---------------------------------------------------------------------------

def test_b140_no_groups_field_passes():
    """Provider with no 'groups' field at all -> PASS."""
    cfg = {"channels": {"telegram": {"dmPolicy": "allowlist"}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_named_groups_only_passes():
    """groups present but only named (non-wildcard) entries -> PASS."""
    cfg = {
        "channels": {
            "telegram": {"groups": {"engineering": {"requireMention": True}}}
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_wildcard_with_channel_level_allowfrom_passes():
    """Wildcard group present, but channel-level allowFrom restricts it -> PASS."""
    cfg = {
        "channels": {
            "telegram": {
                "groups": {"*": {"requireMention": True}},
                "allowFrom": ["123456789"],
            }
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_wildcard_with_per_group_allowfrom_passes():
    """Wildcard group present, restricted by allowFrom on the '*' entry itself -> PASS."""
    cfg = {
        "channels": {
            "telegram": {
                "groups": {"*": {"requireMention": True, "allowFrom": ["123456789"]}}
            }
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_groups_not_a_dict_passes():
    """A malformed/non-dict 'groups' field is ignored, not treated as wildcard -> PASS."""
    cfg = {"channels": {"telegram": {"groups": "oops-not-a-dict"}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_defaults_block_not_treated_as_provider():
    """The 'defaults' key inside channels is config metadata, not a provider channel."""
    cfg = {
        "channels": {
            "defaults": {"contextVisibility": "all"},
            "telegram": {"groups": {"*": {"allowFrom": ["1"]}}},
        }
    }
    result = check_wildcard_group_ingress(_ctx(cfg))
    assert result.status == PASS
    assert "defaults" not in (result.evidence or [])


# ---------------------------------------------------------------------------
# WARN cases
# ---------------------------------------------------------------------------

def test_b140_wildcard_no_allowfrom_anywhere_warns():
    """Wildcard group, no allowFrom (channel or per-group) -> WARN."""
    cfg = {"channels": {"telegram": {"groups": {"*": {"requireMention": True}}}}}
    result = check_wildcard_group_ingress(_ctx(cfg))
    assert result.status == WARN
    assert "telegram" in result.evidence


def test_b140_wildcard_empty_allowfrom_still_warns():
    """An empty/falsy allowFrom (e.g. []) does not effectively restrict -> WARN."""
    cfg = {
        "channels": {
            "telegram": {"groups": {"*": {"requireMention": True}}, "allowFrom": []}
        }
    }
    result = check_wildcard_group_ingress(_ctx(cfg))
    assert result.status == WARN
    assert "telegram" in result.evidence


def test_b140_mixed_channels_only_offender_in_evidence():
    """One channel restricted, one wide open -> only the open one is in evidence."""
    cfg = {
        "channels": {
            "slack": {"groups": {"*": {"allowFrom": ["team-x"]}}},
            "telegram": {"groups": {"*": {"requireMention": True}}},
        }
    }
    result = check_wildcard_group_ingress(_ctx(cfg))
    assert result.status == WARN
    assert "telegram" in result.evidence
    assert "slack" not in result.evidence


def test_b140_never_fails():
    """This check is WARN-only advisory — it must never emit FAIL."""
    cfg = {"channels": {"telegram": {"groups": {"*": {"requireMention": True}}}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status != FAIL


# ---------------------------------------------------------------------------
# Fixture-backed integration cases (real config files through the full audit()).
# ---------------------------------------------------------------------------

def test_b140_fixture_wildcard_no_allowfrom_warns():
    _, findings, _ = audit(RELIABILITY / "bad_b140_wildcard_group_no_allowfrom")
    by_id = {f.id: f for f in findings}
    assert by_id["B140"].status == WARN


def test_b140_fixture_wildcard_with_allowfrom_passes():
    _, findings, _ = audit(RELIABILITY / "clean_b140_wildcard_group_with_allowfrom")
    by_id = {f.id: f for f in findings}
    assert by_id["B140"].status == PASS


def test_b140_fixture_no_wildcard_group_passes():
    _, findings, _ = audit(RELIABILITY / "clean_b140_no_wildcard_group")
    by_id = {f.id: f for f in findings}
    assert by_id["B140"].status == PASS


def test_b140_fixture_no_channels_unknown():
    _, findings, _ = audit(RELIABILITY / "clean_b140_no_channels")
    by_id = {f.id: f for f in findings}
    assert by_id["B140"].status == UNKNOWN


# ---------------------------------------------------------------------------
# B-266 — a wildcard allowlist is NOT a restriction (was a lying PASS).
#
# OpenClaw's isSenderIdAllowed() (dist/allow-from-*.js) short-circuits
# `if (allow.hasWildcard) return true;` BEFORE consulting senderId, so an
# allowFrom containing the literal "*" admits every sender. Until B-266 the
# check tested the list for bare truthiness, so `allowFrom: ["*"]` — the most
# open config expressible — reported PASS "No configured channel has an
# unrestricted wildcard ('*') group entry."
# ---------------------------------------------------------------------------

def test_b140_channel_allowfrom_wildcard_warns():
    """allowFrom: ["*"] is truthy but admits everyone -> WARN, not PASS (B-266)."""
    cfg = {
        "channels": {
            "telegram": {"groups": {"*": {"requireMention": True}}, "allowFrom": ["*"]}
        }
    }
    result = check_wildcard_group_ingress(_ctx(cfg))
    assert result.status == WARN
    assert "telegram" in result.evidence
    assert "*" in result.detail


def test_b140_per_group_allowfrom_wildcard_warns():
    """The wildcard is equally open when it sits on the '*' group entry itself."""
    cfg = {"channels": {"telegram": {"groups": {"*": {"allowFrom": ["*"]}}}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b140_wildcard_among_narrow_entries_still_warns():
    """A "*" beside real sender IDs still short-circuits the allowlist open."""
    cfg = {
        "channels": {
            "telegram": {"groups": {"*": {}}, "allowFrom": ["123456789", "*"]}
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b140_bare_string_wildcard_allowfrom_warns():
    """A bare "*" string (not a list) is schema-invalid but must not buy a PASS."""
    cfg = {"channels": {"telegram": {"groups": {"*": {}}, "allowFrom": "*"}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b140_padded_wildcard_entry_warns():
    """Entries are trimmed before comparison, mirroring the dist's isWildcardEntry."""
    cfg = {"channels": {"telegram": {"groups": {"*": {}}, "allowFrom": [" * "]}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b140_numeric_entry_is_not_a_wildcard():
    """Numeric sender IDs are a genuine restriction -> PASS (no over-firing)."""
    cfg = {"channels": {"telegram": {"groups": {"*": {}}, "allowFrom": [123456789]}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_narrow_allowlist_still_passes():
    """The genuinely-restricted case is unchanged by B-266 -> PASS."""
    cfg = {"channels": {"telegram": {"groups": {"*": {}}, "allowFrom": ["owner"]}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_wildcard_allowfrom_never_fails():
    """Still advisory: the wildcard case escalates PASS->WARN, never to FAIL."""
    cfg = {"channels": {"telegram": {"groups": {"*": {}}, "allowFrom": ["*"]}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status != FAIL


def test_b140_wildcard_detail_distinguishes_from_absent_allowfrom():
    """The two ways to be open must not read identically (the B-266 complaint)."""
    wildcard = check_wildcard_group_ingress(
        _ctx({"channels": {"tg": {"groups": {"*": {}}, "allowFrom": ["*"]}}})
    )
    absent = check_wildcard_group_ingress(
        _ctx({"channels": {"tg": {"groups": {"*": {}}}}})
    )
    assert wildcard.status == absent.status == WARN
    assert wildcard.detail != absent.detail


# ---------------------------------------------------------------------------
# B-266 — channels.<provider>.groupAllowFrom is a real restriction source.
#
# A channel-level array sibling of `groups` in the bundled schema (telegram,
# line, feishu, zalo, matrix, imessage, msteams, googlechat, nextcloud). It was
# never read before B-266, so scoping a wildcard group with groupAllowFrom
# alone drew a false WARN.
# ---------------------------------------------------------------------------

def test_b140_group_allow_from_is_an_effective_restriction():
    """groupAllowFrom alone restricts the wildcard group -> PASS (was a false WARN)."""
    cfg = {
        "channels": {
            "telegram": {"groups": {"*": {}}, "groupAllowFrom": ["123456789"]}
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_group_allow_from_wildcard_warns():
    """...but a wildcard groupAllowFrom is no more a restriction than allowFrom."""
    cfg = {"channels": {"telegram": {"groups": {"*": {}}, "groupAllowFrom": ["*"]}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b140_empty_group_allow_from_falls_through_to_allowfrom():
    """An empty groupAllowFrom is 'no entries' and falls through to allowFrom."""
    cfg = {
        "channels": {
            "telegram": {
                "groups": {"*": {}},
                "groupAllowFrom": [],
                "allowFrom": ["123456789"],
            }
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


# --- precedence: the first CONFIGURED source wins outright, it is not a union ---
#
# Grounded on the dist's group-allowlist resolution order (LINE monitor-*.js):
#   firstDefined(groupConfig?.allowFrom, config.groupAllowFrom, config.allowFrom)
# An "any source restricts it" test would re-introduce the lying PASS.

def test_b140_per_group_wildcard_beats_narrow_channel_allowfrom():
    """Per-group ["*"] wins over a narrow channel allowFrom -> WARN, not PASS."""
    cfg = {
        "channels": {
            "telegram": {
                "groups": {"*": {"allowFrom": ["*"]}},
                "allowFrom": ["123456789"],
            }
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b140_group_allow_from_wildcard_beats_narrow_allowfrom():
    """groupAllowFrom ["*"] takes precedence over a narrow allowFrom -> WARN."""
    cfg = {
        "channels": {
            "telegram": {
                "groups": {"*": {}},
                "groupAllowFrom": ["*"],
                "allowFrom": ["123456789"],
            }
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b140_empty_per_group_allowfrom_falls_through_to_channel():
    """An empty per-group list defers to the next source rather than winning."""
    cfg = {
        "channels": {
            "telegram": {
                "groups": {"*": {"allowFrom": []}},
                "allowFrom": ["123456789"],
            }
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


# --- fixture-backed (full audit()) ---

def test_b140_fixture_wildcard_allowfrom_warns():
    """BAD fixture: allowFrom ["*"] beside a wildcard group -> WARN."""
    _, findings, _ = audit(RELIABILITY / "bad_b140_wildcard_allowfrom")
    by_id = {f.id: f for f in findings}
    assert by_id["B140"].status == WARN


def test_b140_fixture_wildcard_with_groupallowfrom_passes():
    """CLEAN fixture: a narrow groupAllowFrom is a genuine restriction -> PASS."""
    _, findings, _ = audit(RELIABILITY / "clean_b140_wildcard_group_with_groupallowfrom")
    by_id = {f.id: f for f in findings}
    assert by_id["B140"].status == PASS


def test_b140_wildcard_dm_allowfrom_beside_narrow_groupallowfrom_passes():
    """A wildcard DM allowFrom does NOT open the GROUP surface -> PASS is correct.

    Flagged by the B-266 adversarial pass as a suspected lying PASS; investigated and
    confirmed correct, so it is pinned here rather than "fixed". OpenClaw resolves the
    group allowlist as `explicitGroupAllowFrom ? explicitGroupAllowFrom : allowFrom`
    (resolveGroupAllowFromSources), so a non-empty groupAllowFrom wins outright and
    `allowFrom: ["*"]` only widens DMs. B140's claim is scoped to group ingress and
    stays true here; the open-DM exposure is B171/B2's question, not this check's.
    Do not "tighten" this into a WARN — it would be a false positive.
    """
    cfg = {
        "channels": {
            "telegram": {
                "groups": {"*": {}},
                "allowFrom": ["*"],
                "groupAllowFrom": ["123456789"],
            }
        }
    }
    assert check_wildcard_group_ingress(_ctx(cfg)).status == PASS


def test_b140_malformed_shapes_do_not_crash():
    """Schema-invalid allowFrom shapes must degrade, never raise."""
    for allow_from in ({"a": 1}, 5, False, [None, "123"], "", 0):
        cfg = {"channels": {"tg": {"groups": {"*": {}}, "allowFrom": allow_from}}}
        assert check_wildcard_group_ingress(_ctx(cfg)).status in (PASS, WARN)
    for group in (None, "not-a-dict", 7):
        cfg = {"channels": {"tg": {"groups": {"*": group}}}}
        assert check_wildcard_group_ingress(_ctx(cfg)).status == WARN


def test_b140_unknown_path_unaffected_by_wildcard_logic():
    """The UNKNOWN branch is reached before any allowFrom is inspected."""
    cfg = {"channels": {"defaults": {"allowFrom": ["*"]}}}
    assert check_wildcard_group_ingress(_ctx(cfg)).status == UNKNOWN
