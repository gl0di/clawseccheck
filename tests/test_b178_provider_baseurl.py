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

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
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


# ---------------------------------------------------------------------------
# PASS: cleartext http:// to a hostname OpenClaw's own runtime treats as "the
# local machine" for a model-provider baseUrl (CLAWSECCHECK-B-241 — confirmed FP:
# these are FIRST-PARTY OpenClaw constants/hostnames, not attacker values).
# Grounded: selection-JInn13lc.js isExplicitLocalHostnameBaseUrl / isLoopbackOllamaBaseUrl,
# discovery-shared-XxlmIfaG.js LOCAL_OLLAMA_HOSTNAMES,
# runtime-C40mDMdO.d.ts LMSTUDIO_DOCKER_HOST_BASE_URL.
# ---------------------------------------------------------------------------

def test_http_to_docker_host_internal_passes():
    """The exact value of OpenClaw's own LMSTUDIO_DOCKER_HOST_BASE_URL constant."""
    cfg = {"models": {"providers": {"lmstudio": {"baseUrl": "http://host.docker.internal:1234/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == PASS


def test_http_to_orb_internal_hostnames_pass():
    for host in ("docker.orb.internal", "host.orb.internal"):
        cfg = {"models": {"providers": {"p": {"baseUrl": f"http://{host}:11434/v1"}}}}
        assert check_provider_baseurl(_ctx(cfg)).status == PASS


def test_http_to_unspecified_ipv4_passes():
    """0.0.0.0 as a baseUrl target is in OpenClaw's own LOCAL_OLLAMA_HOSTNAMES."""
    cfg = {"models": {"providers": {"ollama": {"baseUrl": "http://0.0.0.0:11434/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == PASS


def test_http_to_unspecified_ipv6_passes():
    cfg = {"models": {"providers": {"ollama": {"baseUrl": "http://[::]:11434/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == PASS


def test_clean_fixture_local_model_baseurl_passes():
    f = check_provider_baseurl(collect(FIXTURES / "clean_b178_local_model_baseurl"))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# WARN (not FAIL): cleartext http:// to a private/CGNAT-range host, or a bare
# single-label hostname — an on-LAN-only exposure, ambiguous with a benign
# homelab/Docker-Compose setup (CLAWSECCHECK-B-241 confirmed FP direction).
# Grounded: selection-JInn13lc.js isLoopbackOllamaBaseUrl (10/8, 172.16/12,
# 192.168/16, 100.64.0.0/10 CGNAT) and isBareProviderHostnameBaseUrl (no dot/colon).
# ---------------------------------------------------------------------------

def test_http_to_lan_ip_warns_not_fails():
    cfg = {"models": {"providers": {"ollama-lan": {"baseUrl": "http://192.168.1.50:11434/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == WARN
    blob = _blob(f)
    assert "192.168.1.50" in blob
    # the false API-key claim from the original FP report must not reappear
    assert "the provider API key and the full outbound model stream travel in cleartext" not in blob


def test_http_to_docker_compose_bare_hostname_warns():
    cfg = {"models": {"providers": {"p": {"baseUrl": "http://ollama:11434/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == WARN


def test_http_to_tailscale_cgnat_warns():
    cfg = {"models": {"providers": {"p": {"baseUrl": "http://100.100.5.9:4000/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == WARN


def test_http_to_10_range_warns():
    cfg = {"models": {"providers": {"p": {"baseUrl": "http://10.0.12.4:4000/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == WARN


def test_bad_fixture_private_network_baseurl_warns():
    f = check_provider_baseurl(collect(FIXTURES / "bad_b178_private_network_baseurl"))
    assert f.status == WARN


# ---------------------------------------------------------------------------
# Regression: the genuinely dangerous case must still FAIL — private/local
# exemptions must not open a false negative on real public cleartext egress.
# ---------------------------------------------------------------------------

def test_http_to_public_fqdn_still_fails():
    """A dotted hostname is not on the private/CGNAT list and not a bare
    single-label name — this check cannot rule out that it resolves publicly,
    so it must stay FAIL (same shape as the pre-existing corp-gateway test)."""
    cfg = {"models": {"providers": {"p": {"baseUrl": "http://litellm.ai.svc.cluster.local:4000/v1"}}}}
    f = check_provider_baseurl(_ctx(cfg))
    assert f.status == FAIL
