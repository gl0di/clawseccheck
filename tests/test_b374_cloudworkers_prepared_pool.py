"""B374 (CLAWSECCHECK-C-526) — cloudWorkers 9.4 prepared-pool default-on warm reserve.

Verdicts (check_cloudworkers_prepared_pool, checks/_config.py):
  UNKNOWN : cloudWorkers.profiles absent/empty/all-malformed — no provider configured,
            so the pool can never target a nonzero reserve (the runtime's own gate:
            `configured: Boolean(profile && ...)`)
  PASS    : cloudWorkers.preparedPool.maxTotal == 0 (gateway-wide kill switch), OR every
            configured profile has readyWorkers explicitly 0
  WARN    : at least one profile has an effective readyWorkers > 0 (explicit, or unset —
            which defaults to 1) and the gateway-wide cap is not 0
  (no FAIL — CLAWSECCHECK-C-526's DoD: a reserve existing is not itself a hole)

Defaults grounded against the installed 2026.9.4 dist (dist/service-DTQsk1L5.mjs):
DEFAULT_READY_WORKERS = 1, DEFAULT_MAX_TOTAL = 4.
"""
import json
import os
import tempfile
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import PASS, UNKNOWN, WARN, FAIL, BY_ID
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _finding_direct(cfg: dict):
    return C.check_cloudworkers_prepared_pool(_ctx(cfg))


def _finding_via_home(cfg: dict):
    """Round-trip through collect()/run_all(), matching how the real audit invokes it."""
    home = Path(tempfile.mkdtemp(prefix="b374-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    return next(f for f in C.run_all(ctx) if f.id == "B374")


# ---- catalog sanity ----

def test_b374_is_catalogued_unscored_advisory():
    meta = BY_ID["B374"]
    assert meta.block == "advisory"
    assert meta.scored is False


# ---- UNKNOWN: no cloud worker provider configured ----

def test_empty_config_unknown():
    f = _finding_direct({})
    assert f.status == UNKNOWN


def test_cloudworkers_present_but_no_profiles_key_unknown():
    f = _finding_direct({"cloudWorkers": {"desktop": True}})
    assert f.status == UNKNOWN


def test_empty_profiles_dict_unknown():
    f = _finding_direct({"cloudWorkers": {"profiles": {}}})
    assert f.status == UNKNOWN


def test_all_malformed_profile_entries_unknown():
    # A profile value that isn't an object is not a usable profile.
    f = _finding_direct({"cloudWorkers": {"profiles": {"x": "not-an-object", "y": None}}})
    assert f.status == UNKNOWN


# ---- PASS: reserve explicitly disabled ----

def test_gateway_wide_maxtotal_zero_passes_even_with_active_profile():
    cfg = {
        "cloudWorkers": {
            "profiles": {"default": {"provider": "acme", "readyWorkers": 5}},
            "preparedPool": {"maxTotal": 0},
        }
    }
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert "maxTotal is 0" in f.detail


def test_every_profile_readyworkers_zero_passes():
    cfg = {
        "cloudWorkers": {
            "profiles": {
                "a": {"provider": "acme", "readyWorkers": 0},
                "b": {"provider": "acme", "readyWorkers": 0},
            }
        }
    }
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert "readyWorkers: 0" in f.detail


# ---- WARN: the default-on posture ----

def test_unset_readyworkers_defaults_on_and_warns():
    cfg = {"cloudWorkers": {"profiles": {"default": {"provider": "acme"}}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "defaults to 1" in " ".join(f.evidence)
    assert "default" in f.detail.lower()


def test_explicit_positive_readyworkers_warns():
    cfg = {"cloudWorkers": {"profiles": {"default": {"provider": "acme", "readyWorkers": 3}}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "readyWorkers=3" in " ".join(f.evidence)


def test_mixed_active_and_disabled_profiles_warns_and_lists_both():
    cfg = {
        "cloudWorkers": {
            "profiles": {
                "on": {"provider": "acme", "readyWorkers": 1},
                "off": {"provider": "acme", "readyWorkers": 0},
            }
        }
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "on" in f.detail
    joined = " ".join(f.evidence)
    assert "reserve active" in joined
    assert "reserve disabled" in joined


def test_explicit_maxtotal_is_reflected_in_the_warn_detail():
    cfg = {
        "cloudWorkers": {
            "profiles": {"default": {"provider": "acme", "readyWorkers": 1}},
            "preparedPool": {"maxTotal": 2},
        }
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "cap 2" in f.detail


# ---- edge cases: values the schema wouldn't actually accept ----

def test_negative_maxtotal_is_treated_as_unset_default_four():
    cfg = {
        "cloudWorkers": {
            "profiles": {"default": {"provider": "acme", "readyWorkers": 1}},
            "preparedPool": {"maxTotal": -1},
        }
    }
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "cap 4" in f.detail  # falls back to DEFAULT_MAX_TOTAL


def test_bool_readyworkers_is_not_treated_as_explicit_numeric():
    # JSON `true`/`false` decode to Python bool, a subclass of int — must not be read as 1/0.
    cfg = {"cloudWorkers": {"profiles": {"default": {"provider": "acme", "readyWorkers": True}}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "unset (defaults to 1)" in " ".join(f.evidence)


def test_string_readyworkers_is_treated_as_unset():
    cfg = {"cloudWorkers": {"profiles": {"default": {"provider": "acme", "readyWorkers": "1"}}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "unset (defaults to 1)" in " ".join(f.evidence)


# ---- config-unreadable engine-side UNKNOWN ----

def test_unparseable_config_is_engine_degraded_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    f = C.check_cloudworkers_prepared_pool(c)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


# ---- never FAIL ----

def test_never_fail():
    for cfg in (
        {},
        {"cloudWorkers": {"profiles": {"default": {"provider": "acme"}}}},
        {"cloudWorkers": {"profiles": {"default": {"provider": "acme", "readyWorkers": 0}}}},
        {"cloudWorkers": {"preparedPool": {"maxTotal": 0},
                          "profiles": {"default": {"provider": "acme", "readyWorkers": 9}}}},
    ):
        assert _finding_direct(cfg).status != FAIL, f"B374 must never return FAIL; got FAIL for {cfg}"


# ---- fixtures, round-tripped through the real audit pipeline ----

def test_the_bad_fixture_fires_and_the_clean_one_does_not():
    for name, expected in (
        ("bad_b374_cloudworkers_prepared_pool_default_on", WARN),
        ("clean_b374_cloudworkers_prepared_pool_disabled", PASS),
    ):
        ctx = collect(FIXTURES / name)
        f = next(fi for fi in C.run_all(ctx) if fi.id == "B374")
        assert f.status == expected, name


def test_full_pipeline_round_trip_matches_direct_call():
    cfg = {"cloudWorkers": {"profiles": {"default": {"provider": "acme"}}}}
    assert _finding_via_home(cfg).status == _finding_direct(cfg).status == WARN
