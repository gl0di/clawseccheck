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
