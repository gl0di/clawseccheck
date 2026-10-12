"""C-688 helper-level unit tests (names that exist only on the fixed tree). The behaviour
tests that also fail on the unfixed tree are in test_c688_plaintext_at_vendor_sensitive_paths.py."""
from __future__ import annotations

import pytest

from clawseccheck.checks import (
    _concrete_secret_literal,
    _header_name_is_credential,
    _map_entry_is_indirection,
    _secret_paths,
    _url_inline_password,
    _vendor_secret_slot_paths,
)


def test_slots_only_view_never_repeats_the_old_key_name_rule():
    assert _vendor_secret_slot_paths({"gateway": {"auth": {"password": "x" * 30}}}) == []
    assert _vendor_secret_slot_paths({"storage": {"locations": {"s": {"encryption": {"passphrase": "x" * 30}}}}})
    assert _secret_paths({"gateway": {"auth": {"password": "x" * 30}}}, slots_only=True) == []


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://user:pw@proxy:3128", "pw"),
        ("redis://:secret123@cache:6379", "secret123"),
        ("http://u:p@w@host:1/x", "p@w"),
        ("http://proxy.corp.example:3128/?next=a@b", None),
        ("http://proxy.corp.example:3128/pac@v2.pac", None),
        ("http://127.0.0.1:3128/path:a@b", None),
        ("http://user@host", None),
        ("socks5://u:p@h", "p"),
        ("http://user:@host", None),
        ("http://user:${PW}@host", None),
        ("http://[::1", None),
        ("no-scheme:pw@host", None),
        ("", None),
        (None, None),
    ],
)
def test_url_inline_password_is_a_real_authority_parse(url, expected):
    assert _url_inline_password(url) == expected


@pytest.mark.parametrize(
    "key,expected",
    [
        ("Authorization", True), ("Proxy-Authorization", True), ("Cookie", True), ("X-Api-Key", True),
        ("x-auth-token", True), ("X_Secret_Key", True), ("x-access-token", True),
        ("User-Agent", False), ("anthropic-beta", False), ("X-Tenant-Id", False),
        ("x-request-id", False), ("X-Goog-User-Project", False),
        ("X-Token-Expiry", False), ("X-Credential-Id", False),  # fragments are NOT a signal
    ],
)
def test_header_names(key, expected):
    assert _header_name_is_credential(key) is expected


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("GOOGLE_APPLICATION_CREDENTIALS", "credentials.json", True),
        ("X", ".npmrc.d/token.txt", True), ("X", "secrets/key_base", True),
        ("X", "secret/data/myapp/prod/openai", True), ("X", "/run/secrets/db", True),
        ("X", "~/.secrets/pass", True), ("X", "https://example.com/token", True),
        ("X", "id_rsa.pem", True), ("X", ".env", True),
        ("DB_PASSWORD_FILE", "whatever", True), ("VAULT_SECRET_PATH", "x", True),
        ("SECRET_NAME", "x", True), ("PASSWORD_POLICY", "x", True), ("X-Token-Expiry", "x", True),
        ("CERT_DIR", "x", True), ("SESSION_TTL", "x", True), ("TOKEN_EXPIRES", "x", True),
        ("Authorization", "Zm9vOmJhcg" + "x" * 12, False),
        ("X", "gAAAAAB" + "a" * 20, False),
    ],
)
def test_indirection_exemption(key, value, expected):
    assert _map_entry_is_indirection(key, value) is expected


def test_concrete_literal_detector_uses_only_the_groupless_global_patterns():
    assert _concrete_secret_literal("ghp" + "_" + "A" * 36)
    assert _concrete_secret_literal("-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END " + "PRIVATE KEY-----")
    assert not _concrete_secret_literal("llama3.1-8b-instruct-q4_K_M")
    assert not _concrete_secret_literal("password=hunter2hunter2")  # a text-shaped keyword pattern
