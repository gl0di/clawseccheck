"""C-688 (behaviour) - a plaintext value at a path OpenClaw's own schema marks sensitive was
invisible to B1 and C015 whenever the LEAF name was not one `SECRET_KEY_RE` knows
(`passphrase`, `key`, `value`, `identityData`, an env/header map entry, a proxy password).

Imports ONLY names that exist on the unfixed tree (`audit`, `check_secrets`, `_secret_paths`,
`_c015_has_secret`), so every test here fails on it for the stated reason and not at
collection. Helper-level unit tests live in test_c688_vendor_slot_helpers.py.

Before the fix (value at the path, config mode 0644): B1 PASS and C015 PASS for every class
in `_FLAGGED` (a PEM block was already a C015 WARN). After: B1 FAIL at 0644 (PASS with the
tight-perms note at 0600), C015 WARN. A SecretRef object, a `${NAME}` template and an embedded
`Bearer ${NAME}` stay PASS; public material (`cert`, `ca`, `certificateData`,
`knownHostsData`) and a session key stay PASS by explicit exclusion.

Env and header MAPS add NO key-name reach for env entries (the older SECRET_KEY_RE rule in
`_secret_paths` is unchanged). A map entry is reported for a concrete value shape (sk-, ghp_,
AKIA, JWT, PEM), for a URL with an inline password (at any length), or - header maps only - for a
vendor credential header name (Authorization, Proxy-Authorization, X-Api-Key, ...) holding a
literal. A random literal under a neutral or credential-sounding env key is a DISCLOSED CEILING
(docs/THREAT_COVERAGE.md, Non-static coverage; `test_a_random_literal_under_a_neutral_key_is_
the_documented_ceiling`).

Direction: PASS -> FAIL/WARN only for a plaintext literal at a vendor-sensitive slot; nothing
that was flagged before stops being flagged. Secret-shaped values are derived at runtime.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import _c015_has_secret, _secret_paths, check_secrets
from clawseccheck.collector import Context

_REF = {"source": "env", "provider": "default", "id": "SOME_SECRET_ENV"}


def _secret(n: int = 30, seed: bytes = b"c688") -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(seed).digest()).decode()[:n]


def _alnum(n: int, seed: bytes) -> str:
    raw = base64.b64encode(hashlib.sha256(seed).digest() * 2).decode()
    return "".join(c for c in raw if c.isalnum())[:n]


def _ghp() -> str:
    return "ghp" + "_" + _alnum(36, b"gh")


def _sk() -> str:
    return "sk" + "-" + _alnum(32, b"sk")


def _akia() -> str:
    return "AK" + "IA" + _alnum(16, b"aws").upper()


def _jwt() -> str:
    return ".".join(["eyJ" + _alnum(20, b"h"), "eyJ" + _alnum(20, b"p"), _alnum(20, b"s")])


def _pem() -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\n" + _alnum(60, b"pem") + "\n-----END " + "PRIVATE KEY-----"


def _nest(path: str, value) -> dict:
    cfg: dict = {}
    parts = path.replace("[]", ".0").split(".")
    cur = cfg
    for i, p in enumerate(parts[:-1]):
        nxt = parts[i + 1]
        if p.isdigit():
            continue
        cur[p] = [{}] if nxt.isdigit() else {}
        cur = cur[p][0] if nxt.isdigit() else cur[p]
    cur[parts[-1]] = value
    return cfg


# One representative per leaf class: a credential slot, or a header-map entry with a vendor credential name
_FLAGGED = [
    ("passphrase storage", "storage.locations.s3.encryption.passphrase"),
    ("passphrase tls", "models.providers.p1.request.tls.passphrase"),
    ("passphrase proxy tls", "tools.media.audio.request.proxy.tls.passphrase"),
    ("tls key", "models.providers.p1.request.tls.key"),
    ("proxy tls key", "models.providers.p1.request.proxy.tls.key"),
    ("auth value", "models.providers.p1.request.auth.value"),
    ("array-scoped auth value", "tools.media.models[].request.auth.value"),
    ("edge auth header", "gateway.remote.edgeAuth.X-Edge"),
    ("ssh identity", "agents.defaults.sandbox.ssh.identityData"),
    ("per-agent ssh identity", "agents.entries.main.sandbox.ssh.identityData"),
    ("mcp Authorization", "mcp.servers.s1.headers.Authorization"),
    ("provider Proxy-Authorization", "models.providers.p1.headers.Proxy-Authorization"),
    ("request Cookie", "models.providers.p1.request.headers.Cookie"),
    ("web fetch x-access-token", "tools.web.fetch.headers.x-access-token"),
]


@pytest.mark.parametrize("label,path", _FLAGGED, ids=[p[0] for p in _FLAGGED])
def test_literal_at_a_vendor_sensitive_slot_is_reported(label, path):
    assert _secret_paths(_nest(path, _secret())), f"{label}: a literal at {path} was not reported"


@pytest.mark.parametrize("label,path", _FLAGGED, ids=[p[0] for p in _FLAGGED])
@pytest.mark.parametrize(
    "ref",
    [_REF, "${SOME_SECRET_ENV}", "$SOME_SECRET_ENV", "${SOME_SECRET_ENV:-}"],
    ids=["secretref-object", "template", "shorthand", "empty-fallback-template"],
)
def test_a_reference_at_a_vendor_sensitive_slot_is_never_reported(label, path, ref):
    assert _secret_paths(_nest(path, ref)) == []
    assert _secret_paths(_nest(path, ref), min_len=1) == []


@pytest.mark.parametrize(
    "path",
    ["models.providers.p1.request.auth.value", "models.providers.p1.headers.Authorization",
     "mcp.servers.s1.headers.Authorization"],
)
def test_an_embedded_reference_in_an_auth_header_is_the_safe_form(path):
    assert _secret_paths(_nest(path, "Bearer ${MY_API_CREDENTIAL}")) == []
    assert _secret_paths(_nest(path, "Bearer ${MY_API_CREDENTIAL}"), min_len=1) == []
    assert _secret_paths(_nest(path, "Bearer " + _secret()))  # a literal after the scheme word
    assert _secret_paths(_nest(path, "${MY_API_CREDENTIAL:-" + _secret() + "}"))  # a literal default


@pytest.mark.parametrize(
    "path",
    ["models.providers.p1.request.tls.cert", "models.providers.p1.request.tls.ca",
     "tools.media.image.request.proxy.tls.cert", "tools.media.image.request.proxy.tls.ca",
     "agents.defaults.sandbox.ssh.certificateData", "agents.defaults.sandbox.ssh.knownHostsData",
     "hooks.mappings[].sessionKey"],
)
def test_public_material_and_a_session_key_are_excluded(path):
    pem = "-----BEGIN " + "CERTIFICATE-----\n" + _secret(60) + "\n-----END " + "CERTIFICATE-----"
    assert _secret_paths(_nest(path, pem)) == []
    assert _secret_paths(_nest(path, _secret())) == []


@pytest.mark.parametrize(
    "path",
    ["some.unrelated.key", "some.unrelated.value", "request.auth.key", "tls.key",
     "foo.env.SSH_PASSPHRASE", "foo.headers.Authorization",
     "storage.locations.s3.encryption.passphraseFile", "models.providers.p1.request.tls.keyFile"],
)
def test_an_unrelated_path_with_an_ambiguous_leaf_does_not_start_to_flag(path):
    assert _secret_paths(_nest(path, _secret())) == []


def test_the_exact_leaf_name_is_matched_anywhere_but_only_exactly():
    assert _secret_paths({"anything": {"passphrase": _secret()}})
    assert _secret_paths({"anything": {"identityData": _secret()}})
    assert _secret_paths({"anything": {"Passphrase": _secret()}})
    assert _secret_paths({"anything": {"passphraseFile": "/home/user/.secrets/passphrase.txt"}}) == []
    assert _secret_paths({"passphrase": "hunter2"}) == []  # B1's placeholder floor is unchanged
    assert _secret_paths({"passphrase": "hunter2"}, min_len=1) == ["passphrase"]  # --incident


# --- env / header maps: key name + concrete value shapes, nothing else -------------------

_BENIGN_ENV = {  # every value here is an ordinary env value (C-135 review matrix)
    "OLLAMA_MODEL": "llama3.1-8b-instruct-q4_K_M",
    "MODEL_FILE": "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
    "EMBED_MODEL": "nomic-embed-text-v1.5",
    "ANTHROPIC_MODEL": "claude-3-5-sonnet-20241022",
    "GIT_COMMIT": hashlib.sha1(b"c688").hexdigest(),
    "REQUEST_UUID": "123e4567-e89b-12d3-a456-426614174000",
    "NVIDIA_VISIBLE_DEVICES": "GPU-" + "6c1a3f2e-5b8d-4e7a-9c20-1f3b5a7d9e02",
    "NODE_HOST": "gpu-node-01.cluster.local",
    "NODE_OPTIONS": "--max-old-space-size=4096",
    "IMAGE_DIGEST": "sha256:" + hashlib.sha256(b"c688").hexdigest(),
    "CACHE_KEY_B64": base64.b64encode(hashlib.sha256(b"c688b").digest()).decode(),
    "API_BASE_URL": "https://api.example.com/v1/items",
}
_BENIGN_HEADERS = {
    "User-Agent": "openclaw/2026.10.2",
    "anthropic-beta": "prompt-caching-2024-07-31",
    "X-Goog-User-Project": "my-gcp-project-123456",
    "X-Tenant-Id": "tenant-4f8a2c1e-acme-prod",
    "x-request-id": "req_01HZX3K9Q8W7E5R2T4Y6U8I0OP",
    "Accept": "application/json;charset=utf-8",
}
_ENV_PATHS = ["mcp.servers.s.env", "nodeHost.mcp.servers.s.env", "models.providers.p.localService.env",
              "security.installPolicy.exec.env"]
_HEADER_PATHS = ["mcp.servers.s.headers", "models.providers.p.headers", "models.providers.p.request.headers",
                 "tools.web.fetch.headers"]


@pytest.mark.parametrize("base", _ENV_PATHS)
@pytest.mark.parametrize("key,value", sorted(_BENIGN_ENV.items()))
def test_benign_env_values_are_not_reported(base, key, value):
    assert _secret_paths(_nest(f"{base}.{key}", value)) == []


@pytest.mark.parametrize("base", _HEADER_PATHS)
@pytest.mark.parametrize("key,value", sorted(_BENIGN_HEADERS.items()))
def test_benign_header_values_are_not_reported(base, key, value):
    assert _secret_paths(_nest(f"{base}.{key}", value)) == []


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_a_config_full_of_benign_map_values_stays_clean_end_to_end(tmp_path, mode):
    env = dict(_BENIGN_ENV)
    cfg = {"mcp": {"servers": {"s": {"env": env, "headers": _BENIGN_HEADERS}}},
           "models": {"providers": {"p": {"headers": _BENIGN_HEADERS, "localService": {"env": env},
                                          "request": {"headers": _BENIGN_HEADERS}}}}}
    b1, c015 = _status(tmp_path, cfg, mode)
    assert b1.status == PASS and "No exposed plaintext secrets." in b1.detail
    assert c015.status == PASS


_INDIRECTIONS = {  # credential-NAMED keys that hold a path or a bare URL (the B248 benign fixture)
    "DB_PASSWORD_FILE": "/run/secrets/db_password_file",
    "GITHUB_TOKEN_PATH": "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "OAUTH_TOKEN_ENDPOINT": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    "SSH_PASSPHRASE_FILE": "~/.secrets/ssh_passphrase",
}
_INDIRECT_HEADERS = {
    "X-Vault-Token-Path": "/var/run/secrets/vault/token",
    "X-Token-Endpoint": "https://auth.example.com/oauth/token",
}


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_credential_named_keys_holding_a_path_or_url_never_warn_c015(tmp_path, mode):
    """A path or bare URL is an indirection to a secret, not the secret (B248). The older
    key-name rule still counts it for B1; C015 must not start to WARN on it."""
    cfg = {"mcp": {"servers": {"s": {"env": _INDIRECTIONS, "headers": _INDIRECT_HEADERS}}},
           "models": {"providers": {"p": {"localService": {"env": _INDIRECTIONS},
                                          "headers": _INDIRECT_HEADERS}}}}
    _, c015 = _status(tmp_path, cfg, mode)
    assert c015.status == PASS


@pytest.mark.parametrize("make", [_ghp, _sk, _akia, _jwt, _pem], ids=["ghp", "sk", "aws", "jwt", "pem"])
def test_a_concrete_credential_shape_is_reported_whatever_the_key_is_called(make):
    assert _secret_paths(_nest("mcp.servers.s.env.FOO", make()))
    assert _secret_paths(_nest("models.providers.p.headers.X-Org", make()))
    assert _secret_paths(_nest("models.providers.p.headers.X-Org", "Bearer " + make()))


def test_a_random_literal_under_a_neutral_key_is_the_documented_ceiling():
    """No recognisable shape: nothing in the text says 'secret'. Stays unflagged, and the limit
    is declared in docs/THREAT_COVERAGE.md (Non-static coverage, CEILING)."""
    for path in ("mcp.servers.s.env.FOO", "mcp.servers.s.env.SSH_PASSPHRASE",
                 "models.providers.p.localService.env.APP_CREDENTIAL",
                 "security.installPolicy.exec.env.REGISTRY_CREDENTIAL",
                 "models.providers.p.headers.X-Org", "tools.web.fetch.headers.X-Tenant"):
        assert _secret_paths(_nest(path, _secret())) == [], path
    doc = (Path(__file__).resolve().parent.parent / "docs" / "THREAT_COVERAGE.md").read_text(encoding="utf-8")
    assert "A secret in an env or header map entry that has no recognisable shape" in doc


# C-135 review: credential-NAMED env keys whose values point AT a secret or are settings
_REVIEW_ENV = {
    "GOOGLE_APPLICATION_CREDENTIALS": "credentials.json",
    "NPM_TOKEN_FILE": ".npmrc.d/token.txt",
    "SECRET_KEY_BASE_FILE": "secrets/key_base",
    "DB_PASSWORD_FILE": "secrets/db_password.txt",
    "VAULT_SECRET_PATH": "secret/data/myapp/prod/openai",
    "SECRET_NAME": "prod-openai-api-credentials-v2",
    "API_KEY_NAME": "primary-service-account-key-01",
    "PASSWORD_POLICY": "min-length-16-rotate-90d-no-reuse",
}
_REVIEW_HEADERS = {"X-Token-Expiry": "2026-12-31T23:59:59Z-extended-window"}


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_credential_named_env_and_header_entries_add_no_new_warn_or_fail(tmp_path, mode):
    """No new reach beyond the older key-name rule: B1 reports exactly what that rule reported
    on the unfixed tree, and C015 stays clean."""
    cfg = {"mcp": {"servers": {"s": {"env": _REVIEW_ENV, "headers": _REVIEW_HEADERS}}},
           "models": {"providers": {"p": {"localService": {"env": _REVIEW_ENV},
                                          "headers": _REVIEW_HEADERS}}}}
    import re

    old_rule = re.compile(r"(password|secret|token|api[_-]?key|apikey|bottoken)", re.I)
    expected = [
        f"{base}.{k}"
        for base, entries in (("mcp.servers.s.env", _REVIEW_ENV), ("mcp.servers.s.headers", _REVIEW_HEADERS),
                              ("models.providers.p.localService.env", _REVIEW_ENV),
                              ("models.providers.p.headers", _REVIEW_HEADERS))
        for k, v in entries.items() if old_rule.search(k) and len(v) >= 16
    ]
    assert sorted(_secret_paths(cfg)) == sorted(expected)
    b1, c015 = _status(tmp_path, cfg, mode)
    assert c015.status == PASS
    assert (b1.status == FAIL) == (bool(expected) and mode == 0o644)


# --- URLs: a real parse, the password lives in the AUTHORITY only ------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://proxy.corp.example:3128/?next=a@b",
        "http://proxy.corp.example:3128/pac@v2.pac",
        "http://proxy.corp.example:3128/?user=a@corp.example",
        "http://127.0.0.1:3128/path:a@b",
        "http://proxy.corp.example:3128",
        "http://user@proxy.corp.example:3128",
        "http://proxy.corp.example:3128/#frag:a@b",
        "http://[::1",  # unparseable: not flagged
        "http://svc:${PROXY_PASSWORD}@proxy.corp.example:3128",
    ],
)
def test_a_url_without_an_inline_password_is_clean(url):
    assert _secret_paths(_nest("proxy.proxyUrl", url)) == []
    assert _secret_paths(_nest("mcp.servers.s.env.UPSTREAM", url)) == []


def test_a_url_with_an_inline_password_is_reported_where_the_vendor_says_credentials_may_sit():
    assert _secret_paths(_nest("proxy.proxyUrl", "http://user:pw@proxy:3128"))
    # a URL password is a credential at ANY length: the 16-character floor does not apply to it
    assert _secret_paths(_nest("proxy.proxyUrl", "socks5://u:p@h"))
    assert _secret_paths(_nest("proxy.proxyUrl", "http://u:p@h"))
    assert _secret_paths(_nest("mcp.servers.db.env.UPSTREAM", "http://u:p@h"))
    assert _secret_paths(_nest("proxy.proxyUrl", "http://svc:" + _secret(16) + "@proxy.corp.example:3128"))
    assert _secret_paths(_nest("mcp.servers.db.env.DB_DSN", "postgres://app:" + _secret(16) + "@db/x"))
    assert _secret_paths(_nest("mcp.servers.db.env.DB_DSN", "redis://:" + _secret(16) + "@cache:6379"))


def test_the_old_key_name_rule_is_unchanged():
    assert _secret_paths({"gateway": {"auth": {"password": _secret()}}}) == ["gateway.auth.password"]
    assert _secret_paths({"mcp": {"servers": {"s": {"env": {"GH_TOKEN": _secret()}}}}}) == [
        "mcp.servers.s.env.GH_TOKEN"
    ]


# ----------------------------------------------------------------- B1 / C015 end to end

def _home(tmp_path: Path, cfg: dict, mode: int) -> Path:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    p = home / "openclaw.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(mode)
    return home


def _status(tmp_path: Path, cfg: dict, mode: int) -> tuple:
    _, findings, _ = audit(_home(tmp_path, cfg, mode))
    by = {f.id: f for f in findings}
    return by["B1"], by["C015"]


@pytest.mark.parametrize(
    "path",
    ["storage.locations.s3.encryption.passphrase", "models.providers.p1.request.tls.key",
     "models.providers.p1.request.auth.value",
     "mcp.servers.s1.headers.Authorization", "agents.defaults.sandbox.ssh.identityData"],
)
def test_b1_fails_a_readable_config_and_c015_warns(tmp_path, path):
    b1, c015 = _status(tmp_path, _nest(path, _secret()), 0o644)
    assert b1.status == FAIL, b1.detail
    assert c015.status == WARN
    assert _secret() not in json.dumps([b1.detail, b1.evidence, c015.detail, c015.evidence])


def test_b1_passes_with_the_tight_perms_note_when_the_config_is_private(tmp_path):
    b1, c015 = _status(tmp_path, _nest("storage.locations.s3.encryption.passphrase", _secret()), 0o600)
    assert b1.status == PASS and "file perms are tight" in b1.detail
    assert c015.status == WARN  # C015 does not depend on the file mode


@pytest.mark.parametrize("value", [_REF, "${SOME_SECRET_ENV}"], ids=["secretref-object", "template"])
def test_references_keep_b1_and_c015_clean(tmp_path, value):
    b1, c015 = _status(tmp_path, _nest("storage.locations.s3.encryption.passphrase", value), 0o644)
    assert b1.status == PASS and "No exposed plaintext secrets." in b1.detail
    assert c015.status == PASS


@pytest.mark.parametrize(
    "url", ["http://proxy.corp.example:3128/?next=a@b", "http://127.0.0.1:3128/path:a@b"]
)
def test_a_proxy_url_with_an_at_sign_in_the_path_is_clean_end_to_end(tmp_path, url):
    b1, c015 = _status(tmp_path, _nest("proxy.proxyUrl", url), 0o644)
    assert b1.status == PASS and c015.status == PASS


@pytest.mark.parametrize("url", ["http://user:pw@proxy:3128", "socks5://u:p@h", "http://u:p@h"])
def test_a_proxy_url_with_a_password_fails_end_to_end(tmp_path, url):
    b1, c015 = _status(tmp_path, _nest("proxy.proxyUrl", url), 0o644)
    assert b1.status == FAIL and c015.status == WARN


def test_c015_json_copy_of_the_config_is_caught_by_the_quoted_key_pattern():
    assert _c015_has_secret('{"passphrase": "' + _secret() + '"}')
    assert _c015_has_secret('{"identityData": "' + _secret() + '"}')
    assert not _c015_has_secret('{"passphrase": "${SOME_SECRET_ENV}"}')
    assert not _c015_has_secret('{"passphrase": {"source": "env", "provider": "default", "id": "X"}}')
    assert not _c015_has_secret('{"passphraseFile": "/etc/secrets/passphrase.txt"}')


def test_check_secrets_counts_the_new_paths_on_a_context():
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = _nest("storage.locations.s3.encryption.passphrase", _secret())
    ctx.config_found = True
    ctx.config_mode = 0o644
    assert check_secrets(ctx).status == FAIL
