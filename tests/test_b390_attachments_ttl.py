"""B390 (CLAWSECCHECK-F-201) — attachments.ttlHours unset means no media-retention sweep.

Verdicts (check_attachments_ttl, checks/_egress.py):
  PASS    : attachments.ttlHours is a real number (any int/float) — OpenClaw's general
            mtime sweep for staged incoming media is live.
  WARN    : absent, null, or any other non-number shape — the vendor's own runtime
            sweep gate (`params.ttlHours !== void 0 && ...`) never runs the expiry
            check at all without a real number, so staged incoming media (screenshots,
            voice notes, forwarded files) accumulates on disk indefinitely.
  UNKNOWN : config unreadable, or never read at all (B-661).
  (no FAIL — an unswept disk is a data-hygiene gap the operator can act on any time,
  not a proven compromise; see the check's own docstring for the full grounding
  against the installed 2026.9.5 dist.)

Re-grounds the filed task's own recon gap: the internal schema-recon doc's
descriptions map omits the `attachments` namespace entirely, so this check is
grounded directly against the installed dist's schema/type declarations and the
`telegram-ingress-drain-factory` runtime sweep gate instead — see
tests/dist_verified_paths.txt (attachments.ttlHours, regenerated against the
installed 2026.9.5 dist) for the machine-checked layer.
"""
import json
import os
import tempfile
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import BY_ID, FAIL, MEDIUM, PASS, UNKNOWN, WARN
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict, *, config_found: bool = True, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    c.config_found = config_found
    return c


def _finding_direct(cfg: dict):
    return C.check_attachments_ttl(_ctx(cfg))


def _finding_via_home(cfg: dict):
    """Round-trip through collect()/run_all(), matching how the real audit invokes it."""
    home = Path(tempfile.mkdtemp(prefix="b390-"))
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


# ---- PASS: a real number is set ----

def test_finite_hours_passes():
    f = _finding_direct({"attachments": {"ttlHours": 168}})
    assert f.status == PASS
    assert "168" in " ".join(f.evidence)


def test_zero_hours_passes():
    # No documented floor in the schema (a plain ZodOptional<ZodNumber>) — 0 is still a
    # real, present number, so the runtime's `!== void 0` gate is live either way.
    f = _finding_direct({"attachments": {"ttlHours": 0}})
    assert f.status == PASS


def test_float_hours_passes():
    f = _finding_direct({"attachments": {"ttlHours": 1.5}})
    assert f.status == PASS


# ---- WARN: unset / non-number shapes ----

def test_absent_attachments_block_warns():
    f = _finding_direct({})
    assert f.status == WARN
    assert "accumulate" in f.detail


def test_attachments_block_present_but_ttlhours_absent_warns():
    f = _finding_direct({"attachments": {}})
    assert f.status == WARN


def test_null_ttlhours_warns():
    f = _finding_direct({"attachments": {"ttlHours": None}})
    assert f.status == WARN


def test_non_numeric_ttlhours_warns():
    # Not a shape the real ZodOptional<ZodNumber> schema would accept either, so it
    # never enacts a sweep — treated the same as absent, not as a false PASS.
    f = _finding_direct({"attachments": {"ttlHours": "168"}})
    assert f.status == WARN


def test_bool_ttlhours_warns():
    # isinstance(True, int) is True in Python — must not be read as a real number.
    f = _finding_direct({"attachments": {"ttlHours": True}})
    assert f.status == WARN


# ---- UNKNOWN: config truly unreadable / never read (B-661) ----

def test_unparseable_config_is_engine_degraded_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    f = C.check_attachments_ttl(c)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


def test_unread_config_is_unknown_not_a_false_warn():
    """B-661: config={}, config_found=False (a real host that was simply never
    scanned, or a plain non-OpenClaw box) must not silently read as 'unset' and WARN —
    that would assert a fact about a host nobody actually looked at."""
    f = C.check_attachments_ttl(_ctx({}, config_found=False))
    assert f.status == UNKNOWN


# ---- never FAIL ----

def test_never_fail():
    for cfg in (
        {},
        {"attachments": {}},
        {"attachments": {"ttlHours": None}},
        {"attachments": {"ttlHours": 0}},
        {"attachments": {"ttlHours": 168}},
        {"attachments": {"ttlHours": "not-a-number"}},
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


def test_full_pipeline_round_trip_matches_direct_call():
    cfg = {"attachments": {"ttlHours": 24}}
    assert _finding_via_home(cfg).status == _finding_direct(cfg).status == PASS
