"""B390 (CLAWSECCHECK-F-201) — attachments.ttlHours unset means no media-retention sweep.

Verdicts (check_attachments_ttl, checks/_egress.py):
  PASS    : a live channel is configured AND attachments.ttlHours is a real number
            (any int/float) — OpenClaw's general mtime sweep for staged incoming
            media is live.
  WARN    : a live channel is configured AND ttlHours is absent, null, or any other
            non-number shape — the vendor's own runtime sweep gate
            (`params.ttlHours !== void 0 && ...`) never runs the expiry check at all
            without a real number, so staged incoming media (screenshots, voice
            notes, forwarded files) accumulates on disk indefinitely.
  UNKNOWN : (a) config unreadable, (b) never read at all (B-661), or (c) F-201 —
            the config WAS read completely but configures no live channel provider
            at all, so nothing can ever stage inbound media in the first place
            (not_applicable=True in this third case only).
  (no FAIL — an unswept disk is a data-hygiene gap the operator can act on any time,
  not a proven compromise; see the check's own docstring for the full grounding
  against the installed 2026.9.5 dist.)

Re-grounds the filed task's own recon gap: the internal schema-recon doc's
descriptions map omits the `attachments` namespace entirely, so this check is
grounded directly against the installed dist's schema/type declarations and the
general, channel-agnostic media sweep (`cleanOldMedia` / `pruneNonPlaybackMedia`,
`store-SPnAoW3B.mjs`, invoked from `server-maintenance-Cl2cKcaI.mjs`'s maintenance
tick) instead — see tests/dist_verified_paths.txt (attachments.ttlHours, regenerated
against the installed 2026.9.5 dist) for the machine-checked layer.

F-201 integration follow-up: the WARN branch originally fired even with ZERO
channels configured (a config of exactly `{}`), where no ingress path exists that
could ever stage an inbound attachment — a false WARN about a risk that cannot
exist on that host, and one that broke
tests/test_b472_b477_self_contradiction.py's Channels-row self-contradiction guard
(a WARN sharing the "channels" inventory bucket with B26's own not_applicable+UNKNOWN
turned "not applicable" into a spurious "1 issue(s)"). Fixed by adding a third
UNKNOWN+not_applicable branch, gated on the SAME "no live channel provider" test
B25/B26/B30 already use — see this file's ``test_no_channels_configured_is_not_applicable*``
tests below, and the fixtures/bad_b390_*/clean_b390_* configs, which now each carry a
channel so the WARN/PASS tests keep exercising the real "channel configured, ttl
unset/set" scenario rather than the no-channels one.
"""
import json
import os
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import BY_ID, FAIL, MEDIUM, PASS, UNKNOWN, WARN
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# A minimal, realistic live channel — mirrors the idiom already used across the
# fixture corpus (e.g. fixtures/bad_b72_subagents_wildcard/openclaw.json).
_A_CHANNEL = {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}}


def _ctx(cfg: dict, *, config_found: bool = True, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    c.config_found = config_found
    return c


def _finding_direct(cfg: dict):
    return C.check_attachments_ttl(_ctx(cfg))


def _finding_via_home(cfg: dict, tmp_path):
    """Round-trip through collect()/run_all(), matching how the real audit invokes it."""
    home = tmp_path
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    return next(f for f in C.run_all(ctx) if f.id == "B390")


# ---- catalog sanity ----

def test_b390_is_catalogued_scored_hardening_medium():
    meta = BY_ID["B390"]
    assert meta.block == "hardening"
    assert meta.scored is True
    assert meta.severity == MEDIUM


# ---- PASS: a live channel is configured and a real number is set ----

def test_finite_hours_passes():
    f = _finding_direct({"channels": _A_CHANNEL, "attachments": {"ttlHours": 168}})
    assert f.status == PASS
    assert "168" in " ".join(f.evidence)


def test_zero_hours_passes():
    # No documented floor in the schema (a plain ZodOptional<ZodNumber>) — 0 is still a
    # real, present number, so the runtime's `!== void 0` gate is live either way.
    f = _finding_direct({"channels": _A_CHANNEL, "attachments": {"ttlHours": 0}})
    assert f.status == PASS


def test_float_hours_passes():
    f = _finding_direct({"channels": _A_CHANNEL, "attachments": {"ttlHours": 1.5}})
    assert f.status == PASS


# ---- WARN: a live channel is configured, but unset / non-number shapes ----

def test_absent_attachments_block_warns():
    f = _finding_direct({"channels": _A_CHANNEL})
    assert f.status == WARN
    assert "accumulate" in f.detail


def test_attachments_block_present_but_ttlhours_absent_warns():
    f = _finding_direct({"channels": _A_CHANNEL, "attachments": {}})
    assert f.status == WARN


def test_null_ttlhours_warns():
    f = _finding_direct({"channels": _A_CHANNEL, "attachments": {"ttlHours": None}})
    assert f.status == WARN


def test_non_numeric_ttlhours_warns():
    # Not a shape the real ZodOptional<ZodNumber> schema would accept either, so it
    # never enacts a sweep — treated the same as absent, not as a false PASS.
    f = _finding_direct({"channels": _A_CHANNEL, "attachments": {"ttlHours": "168"}})
    assert f.status == WARN


def test_bool_ttlhours_warns():
    # isinstance(True, int) is True in Python — must not be read as a real number.
    f = _finding_direct({"channels": _A_CHANNEL, "attachments": {"ttlHours": True}})
    assert f.status == WARN


# ---- UNKNOWN + not_applicable: no live channel configured at all (F-201) ----

def test_no_channels_configured_is_not_applicable_even_with_ttl_unset():
    """The live repro: an empty config (`{}`) has no ingress path at all, so nothing
    can ever stage inbound media — the WARN below is not a real risk on this host."""
    f = _finding_direct({})
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_no_channels_configured_is_not_applicable_even_with_ttl_set():
    """not_applicable is about whether ANY channel exists, not about ttlHours itself
    — must fire the same way regardless of what attachments.ttlHours holds."""
    f = _finding_direct({"attachments": {"ttlHours": 168}})
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_channels_defaults_only_is_not_applicable():
    """`channels.defaults` is a policy block, not a real provider (same exclusion as
    B25/B26/B30) — its presence alone must not count as "a channel is configured"."""
    f = _finding_direct({"channels": {"defaults": {"groupPolicy": "allowlist"}}})
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_a_real_channel_provider_makes_it_applicable_again():
    f = _finding_direct({"channels": _A_CHANNEL})
    assert f.status == WARN
    assert f.not_applicable is False


# ---- UNKNOWN: config truly unreadable / never read (B-661) — distinct from the
# "no channels" case above: these must NOT set not_applicable. ----

def test_unparseable_config_is_engine_degraded_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    f = C.check_attachments_ttl(c)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True
    assert f.not_applicable is False


def test_unread_config_is_unknown_not_a_false_warn():
    """B-661: config={}, config_found=False (a real host that was simply never
    scanned, or a plain non-OpenClaw box) must not silently read as 'unset' and WARN —
    that would assert a fact about a host nobody actually looked at. This is also NOT
    the same thing as "no channels configured": the config was never read, so it stays
    plain UNKNOWN, not not_applicable."""
    f = C.check_attachments_ttl(_ctx({}, config_found=False))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


# ---- never FAIL ----

def test_never_fail():
    for cfg in (
        {},
        {"channels": _A_CHANNEL},
        {"channels": _A_CHANNEL, "attachments": {}},
        {"channels": _A_CHANNEL, "attachments": {"ttlHours": None}},
        {"channels": _A_CHANNEL, "attachments": {"ttlHours": 0}},
        {"channels": _A_CHANNEL, "attachments": {"ttlHours": 168}},
        {"channels": _A_CHANNEL, "attachments": {"ttlHours": "not-a-number"}},
    ):
        assert _finding_direct(cfg).status != FAIL, f"B390 must never return FAIL; got FAIL for {cfg}"


# ---- fixtures, round-tripped through the real audit pipeline ----

def test_the_bad_fixture_fires_and_the_clean_one_does_not():
    for name, expected in (
        ("bad_b390_attachments_ttl_unset", WARN),
        ("clean_b390_attachments_ttl_set", PASS),
    ):
        ctx = collect(FIXTURES / name)
        f = next(fi for fi in C.run_all(ctx) if fi.id == "B390")
        assert f.status == expected, name


def test_the_no_channels_fixture_is_not_applicable():
    ctx = collect(FIXTURES / "unknown_b390_no_channels")
    f = next(fi for fi in C.run_all(ctx) if fi.id == "B390")
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_full_pipeline_round_trip_matches_direct_call(tmp_path):
    cfg = {"channels": _A_CHANNEL, "attachments": {"ttlHours": 24}}
    assert _finding_via_home(cfg, tmp_path).status == _finding_direct(cfg).status == PASS
