"""CLAWSECCHECK-C-405 — B381: secret-shaped value at an OpenClaw-redactor-blind
config path.

MEASURED FIRST (this task's own instruction): B1's `_secret_paths` and C015's
`_c015_has_secret` were run directly against Authorization/bearer/bare-key/plural-
tokens-as-a-list shapes before any code was written here -- all four missed, a bare
`apiKey` control was caught. See `_redactor_blind_secret_paths`'s own docstring in
checks/_config.py for the full measurement and the two distinct root causes.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _secret_paths,
    check_redactor_blind_secret_paths,
)
from clawseccheck.checks._config import _redactor_blind_secret_paths
from clawseccheck.checks._shared import _c015_has_secret
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

TOKEN = "sometoken1234567890abcdefgh"  # 16+ chars, no known vendor-prefix format


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    return c


# ---------------------------------------------------------------------------
# The measurement itself: existing B1/C015 detection misses all four shapes.
# ---------------------------------------------------------------------------

def test_measurement_b1_secret_paths_misses_all_four_shapes():
    configs = [
        {"headers": {"Authorization": f"Bearer {TOKEN}"}},
        {"auth": {"bearer": TOKEN}},
        {"auth": {"tokens": [TOKEN, TOKEN + "2"]}},
        {"encryption": {"key": TOKEN}},
    ]
    for cfg in configs:
        assert _secret_paths(cfg) == [], f"{cfg}: B1's detector unexpectedly caught this"


def test_measurement_b1_secret_paths_catches_the_positive_control():
    assert _secret_paths({"tools": {"apiKey": TOKEN}}) == ["tools.apiKey"]


def test_measurement_c015_has_secret_misses_all_four_shapes():
    import json
    configs = [
        {"headers": {"Authorization": f"Bearer {TOKEN}"}},
        {"auth": {"bearer": TOKEN}},
        {"auth": {"tokens": [TOKEN, TOKEN + "2"]}},
        {"encryption": {"key": TOKEN}},
    ]
    for cfg in configs:
        text = json.dumps(cfg)
        assert _c015_has_secret(text) is False, f"{cfg}: C015's detector unexpectedly caught this"


def test_measurement_c015_has_secret_catches_the_positive_control():
    import json
    assert _c015_has_secret(json.dumps({"tools": {"apiKey": TOKEN}})) is True


# ---------------------------------------------------------------------------
# The new check itself: positive controls
# ---------------------------------------------------------------------------

def test_authorization_header_warns():
    r = check_redactor_blind_secret_paths(_ctx({"headers": {"Authorization": f"Bearer {TOKEN}"}}))
    assert r.status == WARN
    assert any("headers.Authorization" in e for e in r.evidence)


def test_bare_bearer_key_warns():
    r = check_redactor_blind_secret_paths(_ctx({"auth": {"bearer": TOKEN}}))
    assert r.status == WARN
    assert any("auth.bearer" in e for e in r.evidence)


def test_bare_key_field_warns():
    r = check_redactor_blind_secret_paths(_ctx({"encryption": {"key": TOKEN}}))
    assert r.status == WARN
    assert any("encryption.key" in e for e in r.evidence)


def test_plural_tokens_array_warns():
    r = check_redactor_blind_secret_paths(_ctx({"auth": {"tokens": [TOKEN, TOKEN + "2"]}}))
    assert r.status == WARN
    assert any("auth.tokens[0]" in e for e in r.evidence)
    assert any("auth.tokens[1]" in e for e in r.evidence)


def test_never_fails():
    for cfg in (
        {"headers": {"Authorization": f"Bearer {TOKEN}"}},
        {"auth": {"tokens": [TOKEN] * 20}},
    ):
        assert check_redactor_blind_secret_paths(_ctx(cfg)).status != "FAIL"


# ---------------------------------------------------------------------------
# Negative controls -- the anchored key match must not collide with ordinary
# field names that merely CONTAIN "key" as a substring.
# ---------------------------------------------------------------------------

def test_primary_key_field_name_does_not_warn():
    r = check_redactor_blind_secret_paths(_ctx({"sort": {"primaryKey": TOKEN}}))
    assert r.status == PASS


def test_sort_key_field_name_does_not_warn():
    r = check_redactor_blind_secret_paths(_ctx({"db": {"sortKey": TOKEN}}))
    assert r.status == PASS


def test_keyword_field_name_does_not_warn():
    r = check_redactor_blind_secret_paths(_ctx({"ui": {"keyword": TOKEN}}))
    assert r.status == PASS


def test_foreign_key_field_name_does_not_warn():
    r = check_redactor_blind_secret_paths(_ctx({"nav": {"foreignKey": TOKEN}}))
    assert r.status == PASS


def test_ordinary_api_key_field_is_not_double_reported():
    """apiKey is already B1's own territory (SECRET_KEY_RE matches "key" via the
    "api[_-]?key" alternative) -- this check's own anchored regex requires the WHOLE
    key segment to be exactly "key", so "apiKey" must not also fire here."""
    r = check_redactor_blind_secret_paths(_ctx({"tools": {"apiKey": TOKEN}}))
    assert r.status == PASS


def test_secret_reference_indirection_does_not_warn():
    r = check_redactor_blind_secret_paths(_ctx({"auth": {"bearer": "${MY_TOKEN}"}}))
    assert r.status == PASS


def test_short_value_does_not_warn():
    r = check_redactor_blind_secret_paths(_ctx({"headers": {"Authorization": "short"}}))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# UNKNOWN / PASS
# ---------------------------------------------------------------------------

def test_unknown_when_no_config_read():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_found = False
    assert check_redactor_blind_secret_paths(c).status == UNKNOWN


def test_pass_when_config_empty():
    assert check_redactor_blind_secret_paths(_ctx({})).status == PASS


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def test_bad_fixture_warns():
    ctx = collect(FIXTURES / "bad_b381_redactor_blind_secret")
    r = check_redactor_blind_secret_paths(ctx)
    assert r.status == WARN, r.detail
    assert any("headers.Authorization" in e for e in r.evidence)


def test_clean_fixture_passes():
    ctx = collect(FIXTURES / "clean_b381_no_redactor_blind_secret")
    r = check_redactor_blind_secret_paths(ctx)
    assert r.status == PASS, r.detail


# ---------------------------------------------------------------------------
# direct helper regression
# ---------------------------------------------------------------------------

def test_helper_depth_bound_does_not_crash_on_deep_nesting():
    obj = {}
    cur = obj
    for _ in range(150):
        cur["a"] = {}
        cur = cur["a"]
    cur["bearer"] = TOKEN
    # Should not raise; whether it finds the deeply-nested value depends on the depth
    # bound, but it must terminate cleanly either way.
    _redactor_blind_secret_paths(obj)
