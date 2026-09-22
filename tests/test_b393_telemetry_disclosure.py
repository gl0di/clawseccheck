"""B393 (CLAWSECCHECK-F-202) — telemetry.enabled disclosure (INFO, not FAIL).

Re-grounded directly against the installed 2026.9.5 dist — the internal schema-recon
doc's descriptions map has no `telemetry` entry at all (same documented gap class as
B389/B390/B391). See checks/_config.py::check_telemetry_enabled for the full grounding
(dist/zod-schema-DN2u5FdA.mjs:1487-1499 `TelemetryConfigShape`,
dist/schema-CwAIqZVE.mjs:410 top-level description,
dist/telemetry-CwSEtSer.mjs:147-195 `resolveTelemetryStatus`/`prepareTelemetryPayload`)
and tests/dist_verified_paths.txt (`telemetry.enabled`, regenerated against the
installed 2026.9.5 dist) for the machine-checked layer.

Verdicts:
  PASS    : `telemetry.enabled` is not `True` (absent, `False`, or any other
            non-`True` shape — the vendor default), so nothing leaves the machine via
            this channel; OR `telemetry.enabled` IS `True`, in which case the PASS
            detail instead names what the vendor's own schema says this shares — a
            transparency line, not a verdict.
  UNKNOWN : (a) config unreadable/unparseable (engine-side), or (b) no config was
            read at all — not_applicable=True in that second case only, mirroring
            B4/B351/B391's own "nothing to look at" idiom.
  (no FAIL, no WARN — settled by CLAWSECCHECK-C-473's shortlist item 8: telemetry is
  disabled by default, always suppressed under DO_NOT_TRACK, and the vendor's own
  description of the payload is already the benign one this check quotes. There is no
  weakening for a static audit to judge, so this never escalates past PASS and needed
  no C-135 pass — there is no FAIL/WARN branch for one to adversarially test.)
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import BY_ID, FAIL, LOW, PASS, UNKNOWN, WARN
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# A minimal, realistic baseline — mirrors the idiom already used across the fixture
# corpus (e.g. fixtures/clean_b391_workerruns_disabled/openclaw.json).
_BASELINE = {
    "gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
    },
    "agents": {"defaults": {"sandbox": {"mode": "all"}}},
}


def _ctx(cfg: dict, *, config_found: bool = True, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    c.config_found = config_found
    return c


def _finding_direct(cfg: dict):
    return C.check_telemetry_enabled(_ctx(cfg))


def _finding_via_home(cfg: dict):
    """Round-trip through collect()/run_all(), matching how the real audit invokes it."""
    home = Path(tempfile.mkdtemp(prefix="b393-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    return next(f for f in C.run_all(ctx) if f.id == "B393")


# ---- catalog sanity ----

def test_b393_is_catalogued_advisory_unscored_low():
    meta = BY_ID["B393"]
    assert meta.block == "advisory"
    assert meta.scored is False
    assert meta.severity == LOW


# ---- PASS: telemetry.enabled absent or falsy (the vendor default) ----

def test_no_telemetry_key_at_all_passes():
    f = _finding_direct({**_BASELINE})
    assert f.status == PASS
    assert "not set to true" in f.detail


def test_enabled_false_passes():
    cfg = {**_BASELINE, "telemetry": {"enabled": False}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_telemetry_object_present_but_enabled_absent_passes():
    cfg = {**_BASELINE, "telemetry": {"consentedAt": "2026-01-01T00:00:00Z"}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_enabled_non_bool_truthy_does_not_count_as_true():
    # Only a real `True` counts as opted-in — a stray string/number must not be read
    # as enabling the feature (mirrors B390/B391's bool-vs-other isinstance discipline).
    cfg = {**_BASELINE, "telemetry": {"enabled": "true"}}
    f = _finding_direct(cfg)
    assert f.status == PASS


# ---- PASS: telemetry.enabled is True — disclosure of what the vendor shares ----

def test_enabled_true_passes_and_names_the_payload():
    cfg = {**_BASELINE, "telemetry": {"enabled": True}}
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert "telemetry.enabled is true" in f.detail
    assert "enabled channels and provider families" in f.detail
    assert "sessions in the last 24 hours" in f.detail
    # The vendor's help text says "plugin count"; the payload builder also sends the
    # plugin ids (telemetry-CwSEtSer.mjs:181). Pin the part the help text leaves out,
    # so a regression to quoting the help text instead of the payload fails here.
    assert "ids of enabled plugins" in f.detail
    assert "publicly-known ones only" in f.detail
    for sent in ("OpenClaw version", "platform and architecture", "Node version"):
        assert sent in f.detail, sent
    assert "DO_NOT_TRACK" in f.detail
    # Never claims to have observed the gateway's own env for the suppression.
    assert "cannot observe" in f.detail


def test_enabled_true_with_consented_at_still_passes():
    cfg = {
        **_BASELINE,
        "telemetry": {"enabled": True, "consentedAt": "2026-01-01T00:00:00Z"},
    }
    f = _finding_direct(cfg)
    assert f.status == PASS


# ---- UNKNOWN: no config read at all — not_applicable ----

def test_empty_config_is_unknown_and_not_applicable():
    f = _finding_direct({})
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# ---- UNKNOWN: config truly unreadable — distinct from the "no config" case above ----

def test_unparseable_config_is_engine_degraded_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    f = C.check_telemetry_enabled(c)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True
    assert f.not_applicable is False


def test_unread_config_is_unknown_not_a_false_pass():
    """A real host that was simply never scanned (config_found=False) must not
    silently read as 'unset' and PASS — that would assert a fact about a host nobody
    actually looked at. Also distinct from the 'no config' UNKNOWN above: config was
    never read, so this stays plain UNKNOWN, not not_applicable."""
    f = C.check_telemetry_enabled(_ctx({}, config_found=False))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


# ---- never FAIL, never WARN ----

def test_never_fail_or_warn():
    for cfg in (
        {},
        {**_BASELINE},
        {**_BASELINE, "telemetry": {"enabled": False}},
        {**_BASELINE, "telemetry": {"enabled": True}},
        {**_BASELINE, "telemetry": {"enabled": True, "consentedAt": "x"}},
    ):
        f = _finding_direct(cfg)
        assert f.status != FAIL, f"B393 must never return FAIL; got FAIL for {cfg}"
        assert f.status != WARN, f"B393 must never return WARN; got WARN for {cfg}"


# ---- fixtures, round-tripped through the real audit pipeline ----

def test_the_on_fixture_and_the_off_fixture_both_pass():
    for name in ("clean_b393_telemetry_on", "clean_b393_telemetry_off"):
        ctx = collect(FIXTURES / name)
        f = next(fi for fi in C.run_all(ctx) if fi.id == "B393")
        assert f.status == PASS, name


def test_the_on_fixture_names_the_payload_and_the_off_fixture_does_not():
    ctx_on = collect(FIXTURES / "clean_b393_telemetry_on")
    f_on = next(fi for fi in C.run_all(ctx_on) if fi.id == "B393")
    assert "ids of enabled plugins" in f_on.detail

    ctx_off = collect(FIXTURES / "clean_b393_telemetry_off")
    f_off = next(fi for fi in C.run_all(ctx_off) if fi.id == "B393")
    assert "not set to true" in f_off.detail


def test_the_no_config_fixture_is_not_applicable():
    ctx = collect(FIXTURES / "unknown_b393_no_config")
    f = next(fi for fi in C.run_all(ctx) if fi.id == "B393")
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_full_pipeline_round_trip_matches_direct_call():
    cfg = {**_BASELINE, "telemetry": {"enabled": True}}
    assert _finding_via_home(cfg).status == _finding_direct(cfg).status == PASS
