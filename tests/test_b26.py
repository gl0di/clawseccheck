"""B26 — Untrusted-context exposure (channels.contextVisibility) tests.

Logic under test (check_untrusted_context):
- UNKNOWN  when no channels block is present or it is empty.
- PASS     when every provider's effective contextVisibility is in
           {'allowlist', 'allowlist_quote'}.
- WARN     when any channel's effective value is 'all' (explicit or by
           missing-field default), listing the affected provider names
           in evidence.

Design notes:
- The 'defaults' key inside channels is a config block, not a provider;
  it must not be treated as a channel itself.
- Per-channel contextVisibility takes priority over channels.defaults.contextVisibility.
- The documented insecure default (absent field, absent global default) is "all".
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_untrusted_context
from clawseccheck.collector import Context


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# UNKNOWN cases
# ---------------------------------------------------------------------------

def test_b26_no_channels_key_unknown():
    """No channels block at all -> UNKNOWN."""
    assert check_untrusted_context(_ctx({})).status == UNKNOWN


def test_b26_empty_channels_dict_unknown():
    """channels present but empty -> UNKNOWN."""
    assert check_untrusted_context(_ctx({"channels": {}})).status == UNKNOWN


def test_b26_channels_only_defaults_block_unknown():
    """channels contains only a 'defaults' block with no real providers -> UNKNOWN."""
    cfg = {"channels": {"defaults": {"contextVisibility": "allowlist"}}}
    assert check_untrusted_context(_ctx(cfg)).status == UNKNOWN


# ---------------------------------------------------------------------------
# PASS cases
# ---------------------------------------------------------------------------

def test_b26_single_channel_explicit_allowlist_passes():
    """One channel with contextVisibility='allowlist' -> PASS."""
    cfg = {"channels": {"slack": {"contextVisibility": "allowlist"}}}
    assert check_untrusted_context(_ctx(cfg)).status == PASS


def test_b26_single_channel_allowlist_quote_passes():
    """One channel with contextVisibility='allowlist_quote' -> PASS."""
    cfg = {"channels": {"telegram": {"contextVisibility": "allowlist_quote"}}}
    assert check_untrusted_context(_ctx(cfg)).status == PASS


def test_b26_multiple_channels_all_allowlist_passes():
    """Multiple channels all explicitly set to allowlist values -> PASS."""
    cfg = {
        "channels": {
            "slack": {"contextVisibility": "allowlist"},
            "discord": {"contextVisibility": "allowlist_quote"},
            "telegram": {"contextVisibility": "allowlist"},
        }
    }
    assert check_untrusted_context(_ctx(cfg)).status == PASS


def test_b26_global_default_allowlist_no_per_channel_override_passes():
    """channels.defaults.contextVisibility='allowlist' with no per-channel override
    -> all channels inherit the safe default -> PASS."""
    cfg = {
        "channels": {
            "defaults": {"contextVisibility": "allowlist"},
            "slack": {"dmPolicy": "allowlist"},
            "telegram": {"dmPolicy": "allowlist"},
        }
    }
    assert check_untrusted_context(_ctx(cfg)).status == PASS


def test_b26_per_channel_overrides_global_insecure_default_passes():
    """Per-channel contextVisibility overrides an insecure global default -> PASS."""
    cfg = {
        "channels": {
            "defaults": {"contextVisibility": "all"},
            "slack": {"contextVisibility": "allowlist"},
        }
    }
    # 'slack' has 'allowlist', which overrides the 'all' global default.
    assert check_untrusted_context(_ctx(cfg)).status == PASS


# ---------------------------------------------------------------------------
# WARN cases
# ---------------------------------------------------------------------------

def test_b26_single_channel_explicit_all_warns():
    """One channel with contextVisibility='all' explicitly -> WARN."""
    cfg = {"channels": {"slack": {"contextVisibility": "all"}}}
    result = check_untrusted_context(_ctx(cfg))
    assert result.status == WARN
    assert "slack" in result.evidence


def test_b26_channel_missing_field_uses_insecure_default_warns():
    """Channel with no contextVisibility and no global default -> effective 'all' -> WARN."""
    cfg = {"channels": {"telegram": {"dmPolicy": "allowlist"}}}
    result = check_untrusted_context(_ctx(cfg))
    assert result.status == WARN
    assert "telegram" in result.evidence


def test_b26_mixed_channels_one_uses_all_default_warns():
    """One channel explicit allowlist, one missing field (defaults to 'all') -> WARN."""
    cfg = {
        "channels": {
            "slack": {"contextVisibility": "allowlist"},
            "discord": {"dmPolicy": "allowlist"},  # no contextVisibility -> effective "all"
        }
    }
    result = check_untrusted_context(_ctx(cfg))
    assert result.status == WARN
    assert "discord" in result.evidence
    assert "slack" not in result.evidence


def test_b26_global_default_all_no_per_channel_override_warns():
    """channels.defaults.contextVisibility='all' and no per-channel override -> WARN."""
    cfg = {
        "channels": {
            "defaults": {"contextVisibility": "all"},
            "slack": {"dmPolicy": "allowlist"},
        }
    }
    result = check_untrusted_context(_ctx(cfg))
    assert result.status == WARN
    assert "slack" in result.evidence


def test_b26_warn_evidence_lists_affected_channels():
    """WARN evidence must list all affected channel names, not others."""
    cfg = {
        "channels": {
            "good": {"contextVisibility": "allowlist"},
            "bad1": {"contextVisibility": "all"},
            "bad2": {},  # no field -> effective "all"
        }
    }
    result = check_untrusted_context(_ctx(cfg))
    assert result.status == WARN
    assert "bad1" in result.evidence
    assert "bad2" in result.evidence
    assert "good" not in result.evidence


def test_b26_defaults_block_not_treated_as_provider():
    """The 'defaults' key inside channels is config metadata, not a provider channel."""
    cfg = {
        "channels": {
            "defaults": {"contextVisibility": "all"},
            "slack": {"contextVisibility": "allowlist"},
        }
    }
    result = check_untrusted_context(_ctx(cfg))
    # slack is safe; defaults is not a provider -> PASS (no channel triggers WARN)
    assert result.status == PASS
    assert "defaults" not in (result.evidence or [])
