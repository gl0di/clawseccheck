"""B178 — cleartext http:// baseUrl on a model provider (check_provider_baseurl).

Extends B155's coverage: B155 already dig()s the sibling `request.tls.*` /
`request.proxy.*` / `request.allowPrivateNetwork` fields on a provider object under
`models.providers.<id>` but never reads `baseUrl` itself (grounded: ModelProviderSchema
.baseUrl, zod-schema.core-DviqqtPj.js — a real, optional, per-provider field).

Dual-use caveat (explicit in the originating task, CLAWSECCHECK-B-241): a custom
baseUrl with valid TLS (https://) is indistinguishable from a legitimate private/
self-hosted proxy or corporate gateway, so it must NEVER FAIL here. Only a cleartext
http:// scheme to a non-loopback host is sound, unambiguous positive evidence: the
provider API key (Authorization header) and the full outbound model stream then
travel in plaintext.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import check_provider_baseurl
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    return c


def _blob(f) -> str:
    return " ".join(f.evidence or []) + " " + (f.detail or "") + " " + (f.fix or "")


# ---------------------------------------------------------------------------
# FAIL: cleartext http:// to a non-loopback host
# ---------------------------------------------------------------------------

def test_cleartext_http_to_remote_host_fails():
    cfg = {"models": {"providers": {"corp-gateway": {"baseUrl": "http://models.internal.example.com:8080/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == FAIL
    blob = _blob(f)
    assert "models.internal.example.com" in blob
    assert "cleartext" in blob


def test_bad_fixture_fails():
    f = check_provider_baseurl(collect(FIXTURES / "bad_b178_cleartext_baseurl"))
    assert f.status == FAIL


def test_cleartext_http_to_public_ip_fails():
    cfg = {"models": {"providers": {"custom": {"baseUrl": "http://203.0.113.7:8080/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == FAIL


def test_multiple_providers_only_flagged_one_named_in_evidence():
    cfg = {
        "models": {
            "providers": {
                "safe-one": {"baseUrl": "https://safe.example.com/v1"},
                "bad-one": {"baseUrl": "http://leaky.example.com/v1"},
            }
        }
    }
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == FAIL
    blob = _blob(f)
    assert "bad-one" in blob
    assert "leaky.example.com" in blob


# ---------------------------------------------------------------------------
# PASS: dual-use https:// custom baseUrl — NEVER flagged (the epic's explicit caveat)
# ---------------------------------------------------------------------------

def test_https_custom_baseurl_passes():
    cfg = {"models": {"providers": {"corp-gateway": {"baseUrl": "https://models.internal.example.com/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == PASS


def test_clean_fixture_https_custom_baseurl_passes():
    f = check_provider_baseurl(collect(FIXTURES / "clean_b178_https_custom_baseurl"))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# PASS: no baseUrl override at all (bundled provider default, which is https)
# ---------------------------------------------------------------------------

def test_default_provider_no_baseurl_passes():
    cfg = {"models": {"providers": {"openai": {"auth": "api-key"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == PASS


def test_clean_fixture_no_baseurl_override_passes():
    f = check_provider_baseurl(collect(FIXTURES / "clean_b178_no_baseurl_override")).status
    assert f == PASS


def test_no_models_key_at_all_passes():
    f = check_provider_baseurl(_ctx({}))
    assert f.status == PASS


def test_non_dict_providers_value_passes():
    """A malformed/legacy `models.providers` shape (not a dict) must not crash or
    manufacture a FAIL out of a value this check cannot interpret."""
    f = check_provider_baseurl(_ctx({"models": {"providers": "not-a-dict"}}))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# PASS: cleartext http:// to a loopback host — a local model runtime, not a leak
# ---------------------------------------------------------------------------

def test_http_to_localhost_hostname_passes():
    cfg = {"models": {"providers": {"ollama": {"baseUrl": "http://localhost:11434/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == PASS


def test_http_to_loopback_ip_passes():
    cfg = {"models": {"providers": {"ollama": {"baseUrl": "http://127.0.0.1:11434/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == PASS


def test_http_to_ipv6_loopback_passes():
    cfg = {"models": {"providers": {"ollama": {"baseUrl": "http://[::1]:11434/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# UNKNOWN: config genuinely unreadable (never a fake PASS/FAIL, Golden Rule #5)
# ---------------------------------------------------------------------------

def test_unparseable_config_is_unknown():
    f = check_provider_baseurl(_ctx({}, parse_error=True))
    assert f.status == UNKNOWN
