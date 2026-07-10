"""B155 — outbound proxy hardening (check_outbound_proxy).

Audits OpenClaw's OUTBOUND proxy surface: the top-level managed forward proxy (`proxy.*`),
per-provider request proxy/TLS options, and web_fetch's env-proxy trust. Absence of a proxy
is the default and must be a non-scoring advisory (UNKNOWN), never a FAIL (§5). A credential
embedded in proxy.proxyUrl is a secret leak (FAIL) and must never round-trip into evidence.
Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_outbound_proxy
from clawseccheck.collector import Context

# Assemble the secret at runtime so no contiguous secret literal exists in source (§2.3).
_SECRET = "prox" + "yUsr" + ":" + "s3cr" + "etPw0rd"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _blob(f) -> str:
    return " ".join(f.evidence or []) + " " + (f.detail or "") + " " + (f.fix or "")


def test_no_proxy_is_unknown_advisory():
    f = check_outbound_proxy(_ctx({}))
    assert f.status == UNKNOWN  # absence is never a FAIL (§5)
    assert "not required" in f.detail.lower() or "informational" in f.detail.lower()


def test_credential_in_proxy_url_fails_and_is_redacted():
    url = f"http://{_SECRET}@proxy.corp.example.com:8080"
    f = check_outbound_proxy(_ctx({"proxy": {"enabled": True, "proxyUrl": url}}))
    assert f.status == FAIL
    blob = _blob(f)
    assert _SECRET not in blob, "proxy credential leaked into the finding"
    assert "proxy.corp.example.com" in blob, "host signal must survive redaction"


def test_clean_managed_proxy_passes():
    f = check_outbound_proxy(_ctx({"proxy": {"enabled": True, "proxyUrl": "https://proxy.corp.example.com:8080"}}))
    assert f.status == PASS


def test_provider_proxy_tls_insecure_skip_verify_warns():
    cfg = {"models": {"providers": {"openai": {"request": {"proxy": {"tls": {"insecureSkipVerify": True}}}}}}}
    f = check_outbound_proxy(_ctx(cfg))
    assert f.status == WARN
    assert "proxy.tls.insecureSkipVerify" in _blob(f)


def test_provider_endpoint_tls_insecure_skip_verify_warns():
    cfg = {"models": {"providers": {"anthropic": {"request": {"tls": {"insecureSkipVerify": True}}}}}}
    f = check_outbound_proxy(_ctx(cfg))
    assert f.status == WARN
    assert "request.tls.insecureSkipVerify" in _blob(f)


def test_provider_allow_private_network_warns():
    cfg = {"models": {"providers": {"local": {"request": {"allowPrivateNetwork": True}}}}}
    f = check_outbound_proxy(_ctx(cfg))
    assert f.status == WARN
    assert "allowPrivateNetwork" in _blob(f)


def test_webfetch_trusted_env_proxy_warns():
    cfg = {"tools": {"web": {"fetch": {"useTrustedEnvProxy": True}}}}
    f = check_outbound_proxy(_ctx(cfg))
    assert f.status == WARN
    assert "useTrustedEnvProxy" in _blob(f)


def test_proxy_enabled_without_config_url_is_not_flagged():
    # OpenClaw's resolveProxyUrl falls back to the OPENCLAW_PROXY_URL env var, which this
    # static check cannot see — so proxy.enabled with no config URL is a valid running
    # config, not a WARN (§4/§5; C-135 defect 1 — the check must not assert "refuses to start").
    f = check_outbound_proxy(_ctx({"proxy": {"enabled": True}}))
    assert f.status == PASS
    assert "refuses to start" not in _blob(f)


def test_provider_explicit_proxy_url_credential_fails_and_is_redacted():
    # C-135 defect 2: a credential in an explicit-proxy url is the same secret-leak class as
    # the top-level proxy.proxyUrl and must FAIL, echoing host-only.
    url = f"http://{_SECRET}@corp-proxy.example.com:3128"
    cfg = {"models": {"providers": {"openai": {"request": {"proxy": {"mode": "explicit-proxy", "url": url}}}}}}
    f = check_outbound_proxy(_ctx(cfg))
    assert f.status == FAIL
    blob = _blob(f)
    assert _SECRET not in blob, "explicit-proxy credential leaked"
    assert "corp-proxy.example.com" in blob


def test_plain_http_proxy_to_remote_is_note_not_fail():
    # §5: a plain http:// CONNECT proxy is documented-normal — PASS with an advisory note,
    # NOT a WARN/FAIL.
    f = check_outbound_proxy(_ctx({"proxy": {"enabled": True, "proxyUrl": "http://proxy.corp.example.com:8080"}}))
    assert f.status == PASS
    assert "http://" in _blob(f) and "cleartext" in _blob(f)


def test_plain_http_proxy_to_loopback_no_note():
    f = check_outbound_proxy(_ctx({"proxy": {"enabled": True, "proxyUrl": "http://127.0.0.1:8080"}}))
    assert f.status == PASS
    assert "cleartext" not in _blob(f)  # loopback proxy is not flagged
