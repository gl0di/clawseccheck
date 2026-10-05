"""C-646 - a SecretRef is the remedy B1 recommends, so it must not FAIL B1; a templated
enum value must not be read as a literal by B2.

Three linked changes, each with a clean / bad / UNKNOWN case and a look-alike sweep:

1. B1 (``check_secrets``) named-credential test: ``gateway.auth.password`` and
   ``hooks.token`` no longer FAIL "set in config" on a SecretRef, but still FAIL on any
   non-empty value that is not a WHOLE-value reference, at any length.
2. ``_is_secret_reference`` accepts the ``${ID:-}`` EMPTY-fallback template (OpenClaw
   2026.9.7 env substitution) and nothing else new; ``${ID:-x}`` stays a literal.
3. B2 (``check_gateway``): a ``${...}`` template in ``gateway.bind`` /
   ``gateway.auth.mode`` / ``gateway.tailscale.mode`` is UNKNOWN when it would decide the
   verdict, never a literal (no spurious FAIL, no fabricated PASS).
4. B1: a whole-value PLAIN ``${NAME}`` at ``hooks.token`` is UNKNOWN, always (section 7) -
   the gateway reads that string verbatim and, with NAME unset or empty, uses the text as
   the bearer token; the empty-fallback ``${NAME:-}`` form is a reference on 2026.9.7+.
5. B1 build gate (section 9): a whole-value ``${NAME:-}`` at those two paths is a
   reference only where the audited OpenClaw understands the ``:-`` operator (2026.9.7+).
   Earlier builds use the text itself as the credential, so B1 FAILs it with the plaintext
   finding's own ``detail`` and a one-sentence note in ``fix``; an undeterminable build is
   UNKNOWN. Everything else stays build-independent.

Secret-shaped values are assembled at runtime (Golden Rule 3). Every "must stay flagged"
row is a false-negative guard on a CRITICAL check: if a row starts passing as a
reference, a plaintext credential has learned to hide behind a look-alike.
"""
from __future__ import annotations

from pathlib import Path

import json
import re

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _c015_has_secret,
    _credential_is_plaintext,
    _has_env_template,
    _is_secret_ref_object,
    _is_secret_reference,
    _secret_paths,
    check_gateway,
    check_secrets,
)
from clawseccheck.collector import Context, persistent_env_evidence


def _ctx(cfg: dict, config_mode: int | None = None, found: bool = True,
         build: "str | None" = None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = found
    if config_mode is not None:
        c.config_mode = config_mode
    if build is not None:
        # The installed OpenClaw build. The empty-fallback `${NAME:-}` is a reference only
        # where the build understands the `:-` operator (2026.9.7+), so a test that treats
        # that form as a reference must say which build it ran against (section 9).
        c.installed_dist_version = build
    return c


def _runtime_secret() -> str:
    """Assembled at runtime so no contiguous secret-shaped literal exists in source."""
    return "ghp" + "_" + "A" * 36


_OBJ = {"source": "env", "provider": "default", "id": "GW_PW"}
_B97 = "2026.9.7"  # first build that reads `${NAME:-}` as an environment reference


# --------------------------------------------------------------------------------------
# 1. _is_secret_reference: the ${ID:-} EMPTY fallback is new, everything else is unchanged
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    [
        "${GW_PW}",
        "$GW_PW",
        "secretref-env:GW_PW",
        "__env__:GW_PW",
        "${GW_PW:-}",  # C-646: empty fallback
        "  ${GW_PW:-}  ",  # outer whitespace, same as the other shapes
        "${A:-}",
        "${" + "A" * 128 + ":-}",  # the SecretRef id ceiling (1 + 127 chars)
    ],
)
def test_reference_shapes_are_references(value):
    assert _is_secret_reference(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "${GW_PW:-x}",  # non-empty fallback is a LITERAL wrapped in a reference costume
        "${GW_PW:- }",  # a whitespace fallback is still a literal (vendor keeps it verbatim)
        "${GW_PW:-changeme}",
        "${GW_PW:-}suffix",  # something follows the closing brace
        "prefix${GW_PW:-}",  # something precedes the opening brace
        "${GW_PW:-}${OTHER:-}",  # two tokens: not a single whole-value reference
        "${GW_PW:-${OTHER}}",  # nested (the vendor leaves this literal too)
        "$${GW_PW:-}",  # escaped: the vendor emits the literal text ${GW_PW:-}
        "${gw_pw:-}",  # lowercase name: not an env id, the vendor does not substitute it
        "${GW_PW::-}",  # doubled operator
        "${GW_PW:=}",  # a different bash operator the vendor does not implement
        "${GW_PW-}",  # `-` without the colon: not implemented by the vendor
        "${GW_PW:-",  # unclosed
        "${:-}",  # no name
        "${1PW:-}",  # name must start with a letter as a SecretRef id
        "${" + "A" * 129 + ":-}",  # one over the id ceiling
        "",
        "   ",
        "hunter2xx",
    ],
)
def test_lookalikes_are_not_references(value):
    """The exclusion must stay narrow (C-226 adversarial requirement, extended)."""
    assert _is_secret_reference(value) is False


def test_non_string_is_never_a_reference():
    for v in (None, 0, True, ["${A:-}"], {"a": "${A:-}"}):
        assert _is_secret_reference(v) is False


# --------------------------------------------------------------------------------------
# 2. Structured SecretRef object: only a WELL-FORMED pointer is a reference
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "obj",
    [
        {"source": "env", "provider": "default", "id": "GW_PW"},
        {"source": "store", "provider": "vault", "id": "GW_PW"},
        {"source": "file", "provider": "secrets-file", "id": "/providers/gw/password"},
        {"source": "file", "provider": "one", "id": "value"},
        {"source": "exec", "provider": "op", "id": "vault/openai/api-key"},
        {"source": "exec", "provider": "aws", "id": "aws/secret#json_key"},
        {"source": "env", "id": "GW_PW"},  # legacy two-key form the runtime still coerces
    ],
)
def test_wellformed_secretref_objects_are_references(obj):
    assert _is_secret_ref_object(obj) is True


@pytest.mark.parametrize(
    "obj",
    [
        dict(_OBJ, value="x"),  # a plaintext value smuggled next to the pointer
        dict(_OBJ, token=_runtime_secret()),
        {"source": "env", "provider": "default"},  # no id
        {"source": "env", "provider": "default", "id": ""},
        {"source": "env", "provider": "default", "id": "lower_case"},
        {"source": "env", "provider": "default", "id": 5},
        {"source": "vault", "provider": "default", "id": "GW_PW"},  # unknown source
        {"source": "env", "provider": "Default", "id": "GW_PW"},  # bad provider alias
        {"source": "env", "provider": "", "id": "GW_PW"},
        {"source": "env", "provider": 7, "id": "GW_PW"},
        {"source": "file", "provider": "p", "id": "relative/path"},  # not a JSON pointer
        {"source": "file", "provider": "p", "id": "/bad~2escape"},
        {"source": "exec", "provider": "p", "id": "../etc/passwd"},  # traversal segment
        {"source": "exec", "provider": "p", "id": "a/./b"},
        {"source": "exec", "provider": "p", "id": "has space"},
        {"provider": "default", "id": "GW_PW"},  # no source
        {},
        "${GW_PW}",  # a string is not an object
        None,
        ["env", "default", "GW_PW"],
    ],
)
def test_malformed_or_overkeyed_objects_are_not_references(obj):
    assert _is_secret_ref_object(obj) is False


# --------------------------------------------------------------------------------------
# 3. _credential_is_plaintext: B1's per-path predicate, incl. the two vendor types
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("value", [None, "", 0, False, {}, []])
@pytest.mark.parametrize("secret_input", [True, False])
def test_falsy_means_nothing_is_set(value, secret_input):
    assert _credential_is_plaintext(value, secret_input=secret_input) is False


@pytest.mark.parametrize("secret_input", [True, False])
def test_any_nonempty_literal_is_plaintext_at_any_length(secret_input):
    for v in ("x", "1234567", "a" * 15, "a" * 16, "a" * 64, "  ", "${GW_PW:-x}", "12345678"):
        assert _credential_is_plaintext(v, secret_input=secret_input) is True, v
    # Non-string truthy scalars / containers keep B1's old "set" verdict.
    for v in (12345678, True, ["${GW_PW}"], {"nested": "${GW_PW}"}):
        assert _credential_is_plaintext(v, secret_input=secret_input) is True, v


@pytest.mark.parametrize("secret_input", [True, False])
def test_env_template_and_object_are_references_on_both_paths(secret_input):
    for v in ("${GW_PW}", "${GW_PW:-}", " ${GW_PW} ", dict(_OBJ)):
        assert _credential_is_plaintext(v, secret_input=secret_input) is False, v


def test_dollar_shorthand_depends_on_the_vendor_type():
    """``gateway.auth.password`` is a SecretInput: the runtime coerces ``$NAME``
    (``parseEnvTemplateSecretRef``). ``hooks.token`` is a PLAIN string (zod-schema
    ``string()``, read verbatim by resolveHooksConfig), so on it ``$HOOK_TOKEN`` is the
    literal bearer token - a guessable one - and must keep reading as "set"."""
    assert _credential_is_plaintext("$HOOK_TOKEN", secret_input=True) is False
    assert _credential_is_plaintext("$HOOK_TOKEN", secret_input=False) is True


@pytest.mark.parametrize("secret_input", [True, False])
@pytest.mark.parametrize("marker", ["secretref-env:GW_PW", "__env__:GW_PW"])
def test_retired_markers_are_the_literal_credential_on_both_paths(secret_input, marker):
    """C-135 round 2: ``types.secrets-*.mjs`` says the retired string markers are "parsed
    only by doctor migration"; ``coerceSecretRef`` / ``resolveSecretInputRef`` accept only a
    SecretRef object, ``${NAME}`` and ``$NAME``. ``auth-resolve`` then uses the marker text
    itself as the gateway password, so it is a public, guessable credential - not a pointer.
    (C-226's generic secret scan still reads them as references; that is a different
    question and is deliberately unchanged - see ``_is_secret_reference``.)"""
    for v in (marker, "  " + marker + "  ", marker.upper(), "x" + marker):
        assert _credential_is_plaintext(v, secret_input=secret_input) is True, v
    assert _credential_is_plaintext(marker, secret_input=secret_input, cfg={}) is True


def test_secret_input_string_references_are_exactly_what_the_vendor_coerces():
    """``coerceSecretRef`` -> ``parseEnvTemplateSecretRef``: ``${NAME}`` and ``$NAME`` with
    NAME = ``[A-Z][A-Z0-9_]{0,127}`` after ``trim()``, plus this project's ``${NAME:-}``."""
    for v in ("${GW_PW}", "${GW_PW:-}", "$GW_PW", " $GW_PW ", "$" + "A" * 128):
        assert _credential_is_plaintext(v, secret_input=True) is False, v
    for v in ("$" + "A" * 129, "$gw_pw", "$", "$1PW", "$GW-PW", "$GW_PW x", "$$GW_PW"):
        assert _credential_is_plaintext(v, secret_input=True) is True, v


@pytest.mark.parametrize("secret_input", [True, False])
def test_whitespace_is_trimmed_the_way_javascript_does(secret_input):
    """The vendor ``trim()``s before matching ``$NAME``. Python ``str.strip()`` also strips
    U+001C..U+001F and U+0085, which JS does not, so U+001F followed by ``$GW_PW`` would
    read as a reference here while being a literal there; and it does not strip U+FEFF,
    which JS does.
    Only the JS whitespace set may be stripped, so a look-alike never reads as a pointer."""
    for pad in ("\x1c", "\x1d", "\x1e", "\x1f", "\x85"):
        assert _credential_is_plaintext(pad + "${GW_PW}", secret_input=secret_input) is True, repr(pad)
        assert _credential_is_plaintext("${GW_PW}" + pad, secret_input=secret_input) is True, repr(pad)
    for pad in ("\t", "\n", "\r", "\x0b", "\x0c", " ", "\xa0", "\u2028", "\u2029", "\u3000", "\ufeff"):
        assert _credential_is_plaintext(pad + "${GW_PW}" + pad, secret_input=secret_input) is False, repr(pad)
    assert _credential_is_plaintext("\x1f$GW_PW", secret_input=True) is True
    assert _credential_is_plaintext("\ufeff$GW_PW", secret_input=True) is False


def test_over_keyed_object_is_still_set():
    smuggled = dict(_OBJ, value=_runtime_secret())
    assert _credential_is_plaintext(smuggled, secret_input=True) is True
    assert _credential_is_plaintext(smuggled, secret_input=False) is True


# --------------------------------------------------------------------------------------
# 4. B1 end to end - clean (reference) / bad (plaintext) / look-alikes / UNKNOWN
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "password",
    ["${GW_PW}", "${GW_PW:-}", "$GW_PW", dict(_OBJ)],
)
def test_b1_secretref_gateway_password_does_not_fail(password):
    """The regression: B1 used to FAIL 'gateway.auth.password set in config' on every one
    of these (bare truthiness). Reverting the fix makes this red."""
    f = check_secrets(_ctx({"gateway": {"auth": {"password": password}}}, build=_B97))
    assert f.status == PASS, (f.status, f.detail)
    assert "gateway.auth.password" not in f.detail


@pytest.mark.parametrize("token", ["${HOOK_TOKEN:-}", dict(_OBJ)])
def test_b1_secretref_hooks_token_does_not_fail(token):
    # The plain `${HOOK_TOKEN}` string is NOT in this list: it is UNKNOWN, never PASS
    # (section 7). The empty-fallback form and the structured object stay references.
    f = check_secrets(_ctx({"hooks": {"token": token}}, build=_B97))
    assert f.status == PASS, (f.status, f.detail)


def test_b1_secretref_stays_pass_even_with_loose_perms():
    cfg = {
        "gateway": {"auth": {"password": "${GW_PW:-}"}},
        "hooks": {"token": "${HOOK_TOKEN:-}"},
    }
    assert check_secrets(_ctx(cfg, config_mode=0o644, build=_B97)).status == PASS


@pytest.mark.parametrize("plain", ["x", "hunter2", "a" * 15, "a" * 16, "a" * 40])
def test_b1_plaintext_gateway_password_still_fails_at_any_length(plain):
    f = check_secrets(_ctx({"gateway": {"auth": {"password": plain}}}))
    assert f.status == FAIL
    assert "gateway.auth.password set in config" in f.detail
    assert plain not in f.detail  # the value never reaches the report


@pytest.mark.parametrize("plain", ["x", "hunter2", "a" * 15, "a" * 40])
def test_b1_plaintext_hooks_token_still_fails_at_any_length(plain):
    f = check_secrets(_ctx({"hooks": {"token": plain}}))
    assert f.status == FAIL
    assert "hooks.token set in config" in f.detail


@pytest.mark.parametrize(
    "password",
    [
        "${GW_PW:-x}",  # non-empty fallback: a literal (owner decision 2026-09-30)
        "${GW_PW:-changeme}",
        "${GW_PW}" + "a" * 16,  # reference with real material appended
        "a" * 16 + "${GW_PW}",
        "${GW_PW:-}${OTHER}",
        "$${GW_PW}",  # escaped: the literal text, not a reference
        "$$GW_PW",
        "$gw_pw",  # lowercase: not an env id
        "secretref-env:not-an-env-id",
        "secretref-env:GW_PW",  # C-135 round 2: retired markers are the literal credential
        "__env__:GW_PW",
        "  secretref-env:GW_PW  ",
        "\x1f$GW_PW",  # JS trim() does not strip U+001F, so the vendor reads a literal
        dict(_OBJ, value="x"),  # over-keyed object hides a value
        {"source": "vault", "provider": "default", "id": "GW_PW"},
        12345678,
        ["${GW_PW}"],
    ],
)
def test_b1_lookalike_gateway_password_still_fails(password):
    f = check_secrets(_ctx({"gateway": {"auth": {"password": password}}}))
    assert f.status == FAIL, (password, f.status, f.detail)
    assert "gateway.auth.password set in config" in f.detail


@pytest.mark.parametrize(
    "token",
    [
        "${HOOK_TOKEN:-x}",
        "$HOOK_TOKEN",  # plain-string path: the literal token, not a pointer
        "secretref-env:HOOK_TOKEN",
        "__env__:HOOK_TOKEN",
        "${HOOK_TOKEN}" + "a" * 16,
        "$${HOOK_TOKEN}",
        dict(_OBJ, value="x"),
        ["${HOOK_TOKEN}"],
    ],
)
def test_b1_lookalike_hooks_token_still_fails(token):
    f = check_secrets(_ctx({"hooks": {"token": token}}))
    assert f.status == FAIL, (token, f.status, f.detail)
    assert "hooks.token set in config" in f.detail


@pytest.mark.parametrize("marker", ["secretref-env:OPENCLAW_GATEWAY_PASSWORD", "__env__:OPENCLAW_GATEWAY_PASSWORD"])
def test_b1_retired_marker_gateway_password_is_the_literal_credential(marker):
    """C-135 round 2 blocking finding. On OpenClaw 2026.9.7 the retired string markers are
    NOT SecretRefs (``coerceSecretRef`` accepts only an object, ``${NAME}`` and ``$NAME``;
    ``auth-resolve`` then uses the marker text as the password), so a non-loopback gateway
    whose password is ``secretref-env:...`` is protected by a public, guessable string. B1
    must keep the base FAIL - the first C-646 cut flipped it to a clean PASS."""
    f = check_secrets(_ctx({"gateway": {"auth": {"password": marker}}}))
    assert f.status == FAIL, (f.status, f.detail)
    assert f.detail == "gateway.auth.password set in config"  # fingerprint-stable
    assert "retired marker" in f.fix  # the reader who wrote one thinks it is a SecretRef
    assert marker not in f.detail and marker not in f.fix  # nothing echoed
    # ... with a bind that makes it matter, and with loose perms (the other B1 clause)
    cfg = {"gateway": {"bind": "lan", "auth": {"mode": "password", "password": marker}}}
    assert check_secrets(_ctx(cfg, config_mode=0o644)).status == FAIL


def test_b1_retired_marker_hint_is_absent_for_a_plain_or_reference_fail():
    f = check_secrets(_ctx({"gateway": {"auth": {"password": "hunter2"}}}))
    assert f.status == FAIL and "retired marker" not in f.fix
    cfg = _with_env({"gateway": {"auth": {"password": "${GW_PW}"}}}, {"vars": {"GW_PW": "x"}})
    f = check_secrets(_ctx(cfg))
    assert f.status == FAIL and "retired marker" not in f.fix


def test_b1_retired_marker_does_not_mask_a_reference_sibling_or_vice_versa():
    cfg = {
        "gateway": {"auth": {"password": "secretref-env:GW_PW"}},
        "hooks": {"token": "${HOOK_TOKEN:-}"},
    }
    f = check_secrets(_ctx(cfg, build=_B97))
    assert f.status == FAIL and f.detail == "gateway.auth.password set in config"
    cfg = {
        "gateway": {"auth": {"password": "${GW_PW:-}"}},
        "hooks": {"token": "secretref-env:HOOK_TOKEN"},
    }
    f = check_secrets(_ctx(cfg, build=_B97))
    assert f.status == FAIL and f.detail == "hooks.token set in config"


def test_b1_reference_does_not_mask_a_plaintext_sibling():
    """A reference on one named path must not stop the other from firing."""
    cfg = {"gateway": {"auth": {"password": "${GW_PW:-}"}}, "hooks": {"token": "hook-value"}}
    f = check_secrets(_ctx(cfg, build=_B97))
    assert f.status == FAIL
    assert "hooks.token set in config" in f.detail
    assert "gateway.auth.password" not in f.detail
    cfg = {"gateway": {"auth": {"password": "gw-value"}}, "hooks": {"token": "${HOOK_TOKEN}"}}
    f = check_secrets(_ctx(cfg))
    assert f.status == FAIL
    assert "gateway.auth.password set in config" in f.detail
    assert "hooks.token" not in f.detail


def test_b1_empty_fallback_reference_does_not_hide_a_bootstrap_secret():
    """A decoy empty-fallback reference earlier in the same file must not stop the scan
    from finding a real secret later in it (the finditer-not-search property, C-226)."""
    text = 'password: "${GW_PW:-}"\napi token: ' + _runtime_secret() + "\n"
    ctx = _ctx({})
    ctx.bootstrap = {"SOUL.md": text}
    f = check_secrets(ctx)
    assert f.status == FAIL
    assert any("SOUL.md" in e for e in f.evidence)


def test_b1_empty_fallback_alone_in_bootstrap_passes():
    ctx = _ctx({})
    ctx.bootstrap = {"SOUL.md": 'Use token: "${OPENCLAW_GATEWAY_TOKEN:-}" from the env.'}
    assert check_secrets(ctx).status == PASS


def test_b1_nonempty_fallback_holding_a_real_key_is_still_caught_in_bootstrap():
    ctx = _ctx({})
    ctx.bootstrap = {"SOUL.md": "token: ${OPENCLAW_GATEWAY_TOKEN:-" + _runtime_secret() + "}"}
    f = check_secrets(ctx)
    assert f.status == FAIL


def test_b1_unknown_paths_are_untouched():
    """The UNKNOWN branches must not have turned into a reference-shaped PASS."""
    # (a) no config was read at all: still UNKNOWN, not a clean PASS.
    f = check_secrets(_ctx({}, found=False))
    assert f.status == UNKNOWN
    # (b) a plaintext secret under a generic key, perms unreadable: UNKNOWN, as before.
    cfg = {"channels": {"telegram": {"botToken": _runtime_secret()}}}
    c = _ctx(cfg)
    c.config_mode = None
    assert check_secrets(c).status == UNKNOWN
    # (c) ... and the same key holding an empty-fallback reference has no secret to protect.
    cfg = {"channels": {"telegram": {"botToken": "${TG_BOT_TOKEN:-}"}}}
    c = _ctx(cfg)
    c.config_mode = None
    assert check_secrets(c).status == PASS


def test_empty_fallback_reference_is_not_counted_as_a_secret_path():
    cfg = {"channels": {"telegram": {"botToken": "${TELEGRAM_BOT_TOKEN_FROM_ENV:-}"}}}
    assert _secret_paths(cfg) == []
    # ... but a non-empty fallback long enough to matter still is (unchanged design).
    cfg = {"channels": {"telegram": {"botToken": "${TELEGRAM_BOT_TOKEN:-" + "z" * 16 + "}"}}}
    assert _secret_paths(cfg) == ["channels.telegram.botToken"]
    assert check_secrets(_ctx(cfg, config_mode=0o644)).status == FAIL


def test_c015_pattern_layer_treats_only_the_empty_fallback_as_a_reference():
    assert _c015_has_secret('{"token": "${OPENCLAW_GATEWAY_TOKEN:-}"}') is False
    assert _c015_has_secret('{"token": "${OPENCLAW_GATEWAY_TOKEN}"}') is False
    assert _c015_has_secret('{"token": "${OPENCLAW_GATEWAY_TOKEN:-' + _runtime_secret() + '}"}')
    # a decoy empty-fallback reference must not mask a real secret in the same text
    assert _c015_has_secret(
        '{"a": {"token": "${X_TOKEN:-}"}, "b": {"token": "' + _runtime_secret() + '"}}'
    )


# --------------------------------------------------------------------------------------
# 4b. C-135 round 2: a reference to a variable the SAME config defines in plaintext
#     (env.vars.NAME / flat env.NAME) is a plaintext credential in a reference costume
# --------------------------------------------------------------------------------------

_PLAIN = "plain" + "text-value-1234"  # assembled at runtime; not a real secret


def _with_env(cfg: dict, env: dict) -> dict:
    cfg = dict(cfg)
    cfg["env"] = env
    return cfg


_GW_REFS = ["${GW_PW}", "${GW_PW:-}", "$GW_PW", dict(_OBJ)]
_ENV_SHAPES = [
    {"vars": {"GW_PW": _PLAIN}},  # env.vars.<NAME>
    {"GW_PW": _PLAIN},  # flat env.<NAME> catch-all
    {"vars": {"gw_pw": _PLAIN}},  # case-insensitive on Windows: compared upper-cased
    {"vars": {" GW_PW ": _PLAIN}},  # the vendor trims the key
    {"vars": {"GW_PW": "x"}},  # any length
]


@pytest.mark.parametrize("password", _GW_REFS)
@pytest.mark.parametrize("env", _ENV_SHAPES)
def test_b1_reference_to_a_plaintext_env_block_entry_fails(password, env):
    """The regression: base FAILed this shape, the first C-646 cut PASSed it ('No exposed
    plaintext secrets'). Reverting the cfg wiring makes this red."""
    cfg = _with_env({"gateway": {"auth": {"password": password}}}, env)
    f = check_secrets(_ctx(cfg, build=_B97))
    assert f.status == FAIL, (password, env, f.status, f.detail)
    assert f.detail == "gateway.auth.password set in config"  # detail text is fingerprint-stable
    assert "env block" in f.fix
    assert _PLAIN not in f.detail and _PLAIN not in f.fix  # the value never reaches the report


@pytest.mark.parametrize("token", ["${HOOK_TOKEN}", "${HOOK_TOKEN:-}", dict(_OBJ, id="HOOK_TOKEN")])
@pytest.mark.parametrize("env", [{"vars": {"HOOK_TOKEN": _PLAIN}}, {"HOOK_TOKEN": _PLAIN}])
def test_b1_hooks_token_reference_to_a_plaintext_env_block_entry_fails(token, env):
    f = check_secrets(_ctx(_with_env({"hooks": {"token": token}}, env), build=_B97))
    assert f.status == FAIL, (token, env, f.status, f.detail)
    assert f.detail == "hooks.token set in config"
    assert "env block" in f.fix


def test_b1_plain_plaintext_fail_does_not_claim_an_env_block():
    f = check_secrets(_ctx({"gateway": {"auth": {"password": _PLAIN}}}))
    assert f.status == FAIL
    assert "env block" not in f.fix


@pytest.mark.parametrize(
    "env",
    [
        {"vars": {"OTHER_VAR": _PLAIN}},  # a different variable
        {"OTHER_VAR": _PLAIN},
        {"vars": {"GW_PW": ""}},  # blank: the vendor skips it
        {"vars": {"GW_PW": "   "}},
        {"vars": {"GW_PW": 12345678}},  # non-string: the vendor skips it
        {"vars": {"GW_PW": ["x"]}},
        {"vars": {"GW_PW": "${UNDEFINED_ELSEWHERE}"}},  # a pointer to nothing in this file
        {"vars": {"GW_PW": "${UNDEFINED_ELSEWHERE:-}"}},
        {"shellEnv": {"GW_PW": _PLAIN}},  # excluded key: not an env entry
        {"vars": {"bad key": _PLAIN, "GW-PW": _PLAIN}},  # not portable names: skipped
        {},
        {"vars": "not-a-dict"},
        "not-a-dict",
        None,
    ],
)
def test_b1_reference_stays_clean_when_the_env_block_holds_no_plaintext_for_it(env):
    """The other direction: the extra rule must not turn every reference into a FAIL."""
    cfg = _with_env({"gateway": {"auth": {"password": "${GW_PW}"}}}, env)
    f = check_secrets(_ctx(cfg))
    assert f.status == PASS, (env, f.status, f.detail)


def test_b1_env_block_definition_only_matters_for_env_backed_references():
    """A file / exec SecretRef resolves outside the env block, so a same-named env entry is
    not what it points at."""
    env = {"vars": {"GW_PW": _PLAIN}}
    for obj in (
        {"source": "file", "provider": "secrets-file", "id": "/providers/gw/password"},
        {"source": "exec", "provider": "op", "id": "GW_PW"},
    ):
        cfg = _with_env({"gateway": {"auth": {"password": obj}}}, env)
        assert check_secrets(_ctx(cfg)).status == PASS, obj


def test_b1_env_block_chain_is_followed_and_cycles_terminate():
    # GW_PW -> OTHER_PW -> plaintext: the block chains to a plaintext entry.
    env = {"vars": {"GW_PW": "${OTHER_PW}", "OTHER_PW": _PLAIN}}
    cfg = _with_env({"gateway": {"auth": {"password": "${GW_PW}"}}}, env)
    assert check_secrets(_ctx(cfg)).status == FAIL
    # a chain that never reaches plaintext is clean
    env = {"vars": {"GW_PW": "${OTHER_PW}", "OTHER_PW": "${THIRD_PW:-}"}}
    cfg = _with_env({"gateway": {"auth": {"password": "${GW_PW}"}}}, env)
    assert check_secrets(_ctx(cfg)).status == PASS
    # cycles (incl. self-reference) terminate and are clean
    for env in (
        {"vars": {"GW_PW": "${GW_PW}"}},
        {"vars": {"GW_PW": "${OTHER_PW}", "OTHER_PW": "${GW_PW}"}},
    ):
        cfg = _with_env({"gateway": {"auth": {"password": "${GW_PW}"}}}, env)
        assert check_secrets(_ctx(cfg)).status == PASS, env
    # a non-empty fallback or text around a template is a literal: plaintext
    for value in ("${OTHER_PW:-x}", "prefix-${OTHER_PW}", "${OTHER_PW}-suffix", "$OTHER_PW"):
        cfg = _with_env(
            {"gateway": {"auth": {"password": "${GW_PW}"}}}, {"vars": {"GW_PW": value}}
        )
        assert check_secrets(_ctx(cfg)).status == FAIL, value


def test_b1_env_block_zai_alias_group_is_one_variable():
    """The vendor treats Z_AI_API_KEY and ZAI_API_KEY as one variable (env normalization)."""
    cfg = _with_env(
        {"gateway": {"auth": {"password": "${ZAI_API_KEY}"}}}, {"vars": {"Z_AI_API_KEY": _PLAIN}}
    )
    assert check_secrets(_ctx(cfg)).status == FAIL


def test_b1_env_block_chain_deeper_than_the_bound_fails_closed():
    """C-135 round 2 (non-blocking, fixed): exhausting the depth bound used to return
    'no plaintext', i.e. a chain of >= 10 hops to a plaintext entry read PASS. The
    bound being spent is not evidence of absence."""
    for hops in (3, 8, 9, 10, 11, 13, 40):
        vars_ = {"V%d" % i: "${V%d}" % (i + 1) for i in range(hops)}
        vars_["V%d" % hops] = _PLAIN
        cfg = _with_env({"gateway": {"auth": {"password": "${V0}"}}}, {"vars": vars_})
        assert check_secrets(_ctx(cfg)).status == FAIL, hops
    # ... and a chain that genuinely ends in a pointer to nothing is still clean when short
    vars_ = {"V%d" % i: "${V%d}" % (i + 1) for i in range(3)}
    cfg = _with_env({"gateway": {"auth": {"password": "${V0}"}}}, {"vars": vars_})
    assert check_secrets(_ctx(cfg)).status == PASS


def test_b1_env_block_blank_and_key_trim_follow_javascript_whitespace():
    """The vendor skips a value whose JS ``trim()`` is empty and trims the KEY with the
    same function. U+001F is not JS whitespace, so a value made of it is a real (if odd)
    entry and a reference to it is not clean; U+FEFF and U+00A0 are, so those are blank."""
    for blank in ("\ufeff", "\xa0 \t", "\u2028"):
        cfg = _with_env({"gateway": {"auth": {"password": "${GW_PW}"}}}, {"vars": {"GW_PW": blank}})
        assert check_secrets(_ctx(cfg)).status == PASS, repr(blank)
    cfg = _with_env({"gateway": {"auth": {"password": "${GW_PW}"}}}, {"vars": {"GW_PW": "\x1f"}})
    assert check_secrets(_ctx(cfg)).status == FAIL
    cfg = _with_env(
        {"gateway": {"auth": {"password": "${GW_PW}"}}}, {"vars": {"\ufeffGW_PW\xa0": _PLAIN}}
    )
    assert check_secrets(_ctx(cfg)).status == FAIL


def test_credential_is_plaintext_cfg_parameter_is_the_only_new_input():
    cfg = _with_env({}, {"vars": {"GW_PW": _PLAIN}})
    assert _credential_is_plaintext("${GW_PW}") is False  # bare pointer reading unchanged
    assert _credential_is_plaintext("${GW_PW}", cfg=cfg) is True
    assert _credential_is_plaintext("${GW_PW}", cfg={}) is False
    assert _credential_is_plaintext("${GW_PW}", cfg=None) is False
    assert _credential_is_plaintext("${GW_PW}", cfg="not-a-dict") is False
    assert _credential_is_plaintext(None, cfg=cfg) is False  # nothing set stays nothing set
    assert _credential_is_plaintext("literal-value", cfg={}) is True


def test_audit_reference_to_a_plaintext_env_block_entry_fails_b1_from_disk(tmp_path):
    """The reviewer's repro, end to end through audit() from openclaw.json on disk."""
    by_id = _audit_by_id(
        tmp_path,
        '{"env": {"vars": {"GW_PW": "' + _PLAIN + '"}},'
        ' "gateway": {"bind": "loopback", "auth": {"mode": "password", "password": "${GW_PW}"}}}',
    )
    assert by_id["B1"].status == FAIL, by_id["B1"].detail
    assert "gateway.auth.password set in config" in by_id["B1"].detail


@pytest.mark.parametrize("marker", ["secretref-env:OPENCLAW_GATEWAY_PASSWORD", "__env__:OPENCLAW_GATEWAY_PASSWORD"])
def test_audit_retired_marker_password_on_a_lan_bind_fails_b1_from_disk(tmp_path, marker):
    """The round-2 reviewer's repro, end to end through audit(): the base FAIL survives."""
    by_id = _audit_by_id(
        tmp_path,
        '{"gateway": {"bind": "lan", "auth": {"mode": "password", "password": "' + marker + '"}}}',
    )
    assert by_id["B1"].status == FAIL, by_id["B1"].detail
    assert "gateway.auth.password set in config" in by_id["B1"].detail


# --------------------------------------------------------------------------------------
# 5. B2 - a templated enum value is UNKNOWN, never a literal
# --------------------------------------------------------------------------------------

def _gw(bind=None, mode=None, token=None, **extra):
    gw: dict = {}
    if bind is not None:
        gw["bind"] = bind
    auth: dict = {}
    if mode is not None:
        auth["mode"] = mode
    if token is not None:
        auth["token"] = token
    if auth:
        gw["auth"] = auth
    gw.update(extra)
    return {"gateway": gw}


_STRONG_TOKEN = "t" * 32


def test_has_env_template_only_matches_a_dollar_brace_token():
    for v in ("${X:-loopback}", "${X}", "lan${X}", "$${X}"):
        assert _has_env_template(v) is True, v
    for v in ("loopback", "lan", "127.0.0.1:8080", "$X", "{X}", "", None, 5, ["${X}"]):
        assert _has_env_template(v) is False, v


def test_b2_templated_loopback_bind_with_auth_none_is_unknown_not_fail():
    """The regression: 'gateway.bind=${x exposed with auth.mode=none' FAIL on a config
    whose template defaults to loopback. Reverting the fix makes this red."""
    f = check_gateway(_ctx(_gw(bind="${GATEWAY_BIND:-loopback}", mode="none"), config_mode=0o600))
    assert f.status == UNKNOWN, (f.status, f.detail)
    assert "gateway.bind" in f.detail
    assert "${" in f.detail
    assert "exposed with auth.mode" not in f.detail


def test_b2_templated_bind_with_absent_auth_mode_is_unknown():
    f = check_gateway(_ctx(_gw(bind="${GATEWAY_BIND:-lan}"), config_mode=0o600))
    assert f.status == UNKNOWN


def test_b2_templated_bind_default_is_not_taken_as_the_value_even_when_it_is_exposed():
    """No fabricated verdict in either direction: the template defaulting to `lan` is not a
    FAIL either, because whether the default applies depends on the gateway environment."""
    f = check_gateway(_ctx(_gw(bind="${GATEWAY_BIND:-0.0.0.0}", mode="none")))
    assert f.status == UNKNOWN


def test_b2_literal_control_cases_are_unchanged():
    assert check_gateway(_ctx(_gw(bind="loopback", mode="none"))).status == PASS
    f = check_gateway(_ctx(_gw(bind="lan", mode="none")))
    assert f.status == FAIL
    assert "gateway.bind=lan exposed with auth.mode=none" in f.detail
    f = check_gateway(_ctx(_gw(bind="lan", mode="token", token=_STRONG_TOKEN)))
    assert f.status == PASS


def test_b2_templated_bind_with_a_self_authenticating_mode_does_not_branch_on_it():
    """token / password auth authenticate whatever the bind resolves to, so the templated
    bind does not change the verdict and there is nothing to be UNKNOWN about."""
    f = check_gateway(_ctx(_gw(bind="${GATEWAY_BIND:-loopback}", mode="token", token=_STRONG_TOKEN)))
    assert f.status == PASS
    f = check_gateway(_ctx(_gw(bind="${GATEWAY_BIND:-lan}", mode="password")))
    assert f.status == PASS


def test_b2_templated_auth_mode_on_an_exposed_bind_is_unknown_not_pass():
    """``${M:-none}`` on a `lan` bind used to read as some other mode and PASS as
    'authenticated'. It must not."""
    f = check_gateway(_ctx(_gw(bind="lan", mode="${AUTH_MODE:-none}")))
    assert f.status == UNKNOWN, (f.status, f.detail)
    assert "gateway.auth.mode" in f.detail


def test_b2_templated_auth_mode_on_a_loopback_bind_does_not_matter():
    f = check_gateway(_ctx(_gw(bind="loopback", mode="${AUTH_MODE:-none}")))
    assert f.status == PASS
    f = check_gateway(_ctx(_gw(mode="${AUTH_MODE:-none}")))  # bind absent
    assert f.status == PASS


def test_b2_both_templated_names_both_in_the_unknown():
    f = check_gateway(_ctx(_gw(bind="${B:-lan}", mode="${M:-none}")))
    assert f.status == UNKNOWN
    assert "gateway.bind" in f.detail and "gateway.auth.mode" in f.detail


def test_b2_templated_tailscale_mode_is_unknown_not_pass():
    """`${TS:-funnel}` would expose the gateway publicly; a config-only audit cannot tell."""
    cfg = _gw(bind="loopback", mode="token", token=_STRONG_TOKEN)
    cfg["gateway"]["tailscale"] = {"mode": "${TS_MODE:-funnel}"}
    f = check_gateway(_ctx(cfg))
    assert f.status == UNKNOWN
    assert "gateway.tailscale.mode" in f.detail
    # literal controls
    cfg["gateway"]["tailscale"] = {"mode": "funnel"}
    assert check_gateway(_ctx(cfg)).status == FAIL
    cfg["gateway"]["tailscale"] = {"mode": "serve"}
    assert check_gateway(_ctx(cfg)).status == PASS


def test_b2_independent_evidence_still_wins_over_a_templated_read():
    """A templated bind must not swallow a FAIL that has nothing to do with the bind."""
    # weak (sub-24) config token
    f = check_gateway(_ctx(_gw(bind="${B:-loopback}", mode="none", token="short-token")))
    assert f.status == FAIL
    assert "gateway auth token shorter than 24 chars" in f.detail
    assert "gateway.bind" in f.detail  # ... and the report says the bind was not evaluated
    # funnel is exposure on its own
    cfg = _gw(bind="${B:-loopback}", mode="none")
    cfg["gateway"]["tailscale"] = {"mode": "funnel"}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    assert "gateway.tailscale.mode=funnel" in f.detail
    # an open channel
    cfg = _gw(bind="${B:-loopback}", mode="none")
    cfg["channels"] = {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    assert "open dm/group policy" in f.detail


def test_b2_templated_read_is_not_the_message_text_of_the_old_garbled_host():
    f = check_gateway(_ctx(_gw(bind="${GATEWAY_BIND:-loopback}", mode="none")))
    assert "${gateway_bind" not in f.detail
    assert "gateway.bind=${" not in f.detail


def test_b2_unknown_carries_a_fix():
    f = check_gateway(_ctx(_gw(bind="${GATEWAY_BIND:-loopback}", mode="none")))
    assert f.fix
    assert "literally" in f.fix


# --------------------------------------------------------------------------------------
# 6. Wiring: the real audit() path, from openclaw.json on disk
# --------------------------------------------------------------------------------------

def _audit_by_id(tmp_path, cfg_text: str):
    from clawseccheck import audit

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(cfg_text, encoding="utf-8")
    cfg.chmod(0o600)
    _, findings, _ = audit(tmp_path, include_native=False)
    return {f.id: f for f in findings}


def test_audit_secretref_config_from_disk_is_clean_on_b1_and_c015(tmp_path):
    by_id = _audit_by_id(
        tmp_path,
        '{"gateway": {"bind": "loopback", "auth": {"mode": "password",'
        ' "password": "${OPENCLAW_GATEWAY_PASSWORD:-}"}},'
        ' "hooks": {"enabled": false, "token": "${HOOKS_TOKEN_REF:-}"},'
        ' "meta": {"lastTouchedVersion": "2026.9.7"}}',
    )
    assert by_id["B1"].status == PASS, by_id["B1"].detail
    assert by_id["C015"].status != WARN, by_id["C015"].detail


def test_audit_plaintext_config_from_disk_still_fails_b1(tmp_path):
    by_id = _audit_by_id(
        tmp_path,
        '{"gateway": {"bind": "loopback", "auth": {"mode": "password", "password": "pw-12345"}},'
        ' "hooks": {"token": "hook-12345"}}',
    )
    assert by_id["B1"].status == FAIL
    assert "gateway.auth.password set in config" in by_id["B1"].detail
    assert "hooks.token set in config" in by_id["B1"].detail


def test_audit_templated_bind_from_disk_is_unknown_on_b2(tmp_path):
    by_id = _audit_by_id(
        tmp_path,
        '{"gateway": {"bind": "${GATEWAY_BIND:-loopback}", "auth": {"mode": "none"}}}',
    )
    assert by_id["B2"].status == UNKNOWN, by_id["B2"].detail


# --------------------------------------------------------------------------------------
# 7. C-135 rounds 3-4, final rule: a whole-value PLAIN ${NAME} at hooks.token is UNKNOWN
# --------------------------------------------------------------------------------------
# hooks.token is a PLAIN string read verbatim. On OpenClaw 2026.9.7 a ${NAME} whose variable
# is unset or empty in the gateway process only logs a warning, and the config text
# `${NAME}` itself becomes the hooks bearer token - a public, guessable literal. B1 used to
# FAIL it; the round-1/2 change turned that into a clean PASS (a false negative). Round 3
# answered UNKNOWN unless a unit / dotenv file showed the variable defined; round 4 broke
# that evidence rule six ways (each a PASS where the literal was the live token), and the
# model was RETRACTED: a static scan cannot see the gateway process environment. The rule
# now: the plain form is UNKNOWN always, with no environment lookup of any kind and whether
# hooks.enabled is true, false or absent; the empty-fallback form `${NAME:-}` stays a
# reference (unset, it substitutes to "" and 2026.9.7 refuses to enable hooks).

_VISIBLE = "x" * 40
_LONG_NAME = "T" + "O" * 127  # the longest name the reference grammar accepts (128 chars)
_ENABLED = [True, False, None]  # None: the `hooks.enabled` key is absent


def _hk_ctx(token="${HK}", *, enabled=True, dotenv=None, unit=None, extra=None, build=None):
    hooks = {"token": token}
    if enabled is not None:
        hooks["enabled"] = enabled
    cfg = {"hooks": hooks}
    if extra:
        cfg.update(extra)
    c = _ctx(cfg, build=build)
    c.dotenv_values.update(dotenv or {})
    c.unit_env_values.update(unit or {})
    return c


# The three disclosure statements, each as written in `fix` for NAME = HK.
_FIX_A = "Confirm HK is set to a non-empty value in the environment the gateway process runs with."
_FIX_B = (
    "On OpenClaw 2026.9.7, when hooks are enabled and the variable is unset or empty, the "
    "gateway logs a warning and uses the reference text itself as the hooks bearer token."
)
_FIX_C = (
    "Writing the empty-fallback form ${HK:-} instead makes OpenClaw 2026.9.7 refuse to "
    "enable hooks when the variable is unset, rather than fall back to the literal text."
)


@pytest.mark.parametrize("token", ["${HK}", "  ${HK}  ", "${" + _LONG_NAME + "}"])
@pytest.mark.parametrize("enabled", _ENABLED)
def test_plain_reference_at_hooks_token_is_unknown_with_no_definition(token, enabled):
    """The regression. Reverting to the round-1/2 behaviour makes this PASS."""
    f = check_secrets(_hk_ctx(token, enabled=enabled))
    assert f.status == UNKNOWN, (f.status, f.detail)
    assert f.id == "B1"
    assert f.fix


@pytest.mark.parametrize("enabled", _ENABLED)
@pytest.mark.parametrize(
    "kw",
    [
        {"dotenv": {"HK": _VISIBLE}},
        {"unit": {"HK": _VISIBLE}},
        {"dotenv": {"HK": _VISIBLE}, "unit": {"HK": _VISIBLE}},
    ],
)
def test_a_visible_definition_never_upgrades_the_plain_reference(kw, enabled):
    c = _hk_ctx("${HK}", enabled=enabled, **kw)
    # positive control: the evidence reader DOES see the definition, so UNKNOWN is the rule
    # and not an artefact of the evidence being invisible.
    assert persistent_env_evidence(c, "HK")[0] == _VISIBLE
    f = check_secrets(c)
    assert f.status == UNKNOWN, (kw, f.status, f.detail)


def test_the_environment_is_never_consulted(monkeypatch):
    """No evidence lookup of any kind: B1 must not call `persistent_env_evidence`, and the
    auditing process's own environment does not matter either."""
    import clawseccheck.checks._config as cfgmod

    calls = []
    real = cfgmod.persistent_env_evidence
    monkeypatch.setattr(
        cfgmod, "persistent_env_evidence", lambda *a, **k: calls.append(a) or real(*a, **k)
    )
    monkeypatch.setenv("HK", _VISIBLE)
    f = check_secrets(_hk_ctx("${HK}", dotenv={"HK": _VISIBLE}))
    assert f.status == UNKNOWN
    assert calls == []
    # control: the wrapper is live - the same wrapped function does record a call
    cfgmod.persistent_env_evidence(_hk_ctx(), "HK")
    assert len(calls) == 1


@pytest.mark.parametrize("enabled", _ENABLED)
@pytest.mark.parametrize("token", ["${HK:-}", "  ${HK:-}  "])
@pytest.mark.parametrize("kw", [{}, {"dotenv": {"HK": _VISIBLE}}, {"unit": {"HK": _VISIBLE}}])
def test_empty_fallback_form_is_a_reference_with_and_without_a_definition(token, enabled, kw):
    """Unset, `${NAME:-}` substitutes to "" and 2026.9.7 throws "hooks.enabled requires
    hooks.token": no literal token ever exists, so it is a reference (PASS)."""
    f = check_secrets(_hk_ctx(token, enabled=enabled, build=_B97, **kw))
    assert f.status == PASS, (f.status, f.detail)


def test_fail_elsewhere_in_b1_wins_over_the_unknown():
    f = check_secrets(
        _hk_ctx("${HK}", extra={"gateway": {"auth": {"password": "pw-12345"}}})
    )
    assert f.status == FAIL
    assert "gateway.auth.password set in config" in f.detail
    assert "hooks.token" not in f.detail
    # a reference to a variable the same config defines in plaintext is a FAIL too
    c = _hk_ctx("${HK}", extra={"env": {"vars": {"HK": _VISIBLE}}})
    assert check_secrets(c).status == FAIL


@pytest.mark.parametrize(
    "token",
    [
        "$HK",  # the shorthand is a literal at a plain-string field
        "abc${HK}",  # an embedded reference carries literal text
        "${HK}abc",
        "${HK:-changeme}",  # a non-empty fallback is a literal in a reference costume
        "secretref-env:HK",  # the retired markers are the literal credential on 2026.9.7
        "__env__:HK",
    ],
)
@pytest.mark.parametrize("enabled", _ENABLED)
def test_lookalikes_and_retired_markers_still_fail_at_hooks_token(token, enabled):
    f = check_secrets(_hk_ctx(token, enabled=enabled, dotenv={"HK": _VISIBLE}))
    assert f.status == FAIL, (token, f.status, f.detail)
    assert "hooks.token set in config" in f.detail


def test_a_plain_reference_at_gateway_password_is_still_pass():
    """gateway.auth.password is a SecretInput: a whole-value reference is parsed as a
    SecretRef and fails closed when unresolved (no literal is ever used)."""
    for pw in ("${GW_PW}", "${GW_PW:-}", "$GW_PW", dict(_OBJ)):
        f = check_secrets(_ctx({"gateway": {"auth": {"password": pw}}}, build=_B97))
        assert f.status == PASS, (pw, f.status, f.detail)


def test_a_structured_object_at_hooks_token_is_not_a_plain_reference():
    """Not a valid hooks.token in the vendor schema, but it carries no plaintext and no
    `${NAME}` text that could become a literal token, so B1's question has no hit here."""
    assert check_secrets(_ctx({"hooks": {"token": dict(_OBJ)}})).status == PASS


@pytest.mark.parametrize("name", ["HK", "HOOK_TOKEN", _LONG_NAME])
def test_detail_prints_the_reference_exactly_as_configured(name):
    ref = "${" + name + "}"
    f = check_secrets(_hk_ctx(ref))
    assert f.status == UNKNOWN
    assert f.detail == (
        "hooks.token is the reference " + ref + ", and this audit cannot see the "
        "environment the gateway runs with, so it cannot confirm that the variable is set."
    )
    # the fix names the same variable and its empty-fallback spelling
    assert "Confirm " + name + " is set" in f.fix
    assert "${" + name + ":-}" in f.fix


def test_the_three_disclosure_statements_are_in_fix_and_absent_from_detail():
    f = check_secrets(_hk_ctx("${HK}"))
    for statement in (_FIX_A, _FIX_B, _FIX_C):
        assert statement in f.fix, statement
    for marker in ("2026.9.7", "OpenClaw", "bearer", "empty-fallback", "Confirm", "logs a warning"):
        assert marker not in f.detail, marker
    # nothing about other OpenClaw versions, and ASCII only
    assert set(re.findall(r"\d{4}\.\d+\.\d+", f.fix)) == {"2026.9.7"}
    assert f.fix.isascii() and f.detail.isascii()


# -- on-disk shapes: a real audit() over a real home, evidence files included ----------------

_SVC = "[Service]\nExecStart=/usr/bin/openclaw gateway run\n"
_SVC_NAME = "openclaw-gateway.service"
_REAL = "realvalue" + "123"


def _disk(tmp_path, token="${HOOK_TOKEN}", *, enabled=True, home_name=".openclaw", dotenv=None,
          units=None, extra_files=None, gwenv=None, build=None):
    base = tmp_path / "fx"
    home = base / home_name
    home.mkdir(parents=True)
    home.chmod(0o700)
    hooks = {"path": "/hooks", "token": token}
    if enabled is not None:
        hooks["enabled"] = enabled
    cfg = {
        "gateway": {"mode": "local", "bind": "loopback",
                    "auth": {"mode": "token", "token": "${GW_TOK}"}},
        "hooks": hooks,
    }
    if build is not None:
        cfg["meta"] = {"lastTouchedVersion": build}  # the build, stated the way a real config does
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    (home / "openclaw.json").chmod(0o600)
    if dotenv is not None:
        (home / ".env").write_text(dotenv, encoding="utf-8")
        (home / ".env").chmod(0o600)
    if gwenv is not None:
        g = base / ".config" / "openclaw"
        g.mkdir(parents=True, exist_ok=True)
        (g / "gateway.env").write_text(gwenv, encoding="utf-8")
    ud = base / ".config" / "systemd" / "user"
    for name, body in (units or {}).items():
        ud.mkdir(parents=True, exist_ok=True)
        (ud / name).write_text(body, encoding="utf-8")
    for rel, body in (extra_files or {}).items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return home


def _audit_home(home):
    from clawseccheck import audit

    ctx, findings, _ = audit(home, include_native=False)
    return ctx, {f.id: f for f in findings}


@pytest.mark.parametrize("enabled", _ENABLED)
@pytest.mark.parametrize("where", ["dotenv", "unit"])
def test_a_real_definition_on_disk_leaves_the_plain_reference_unknown(tmp_path, where, enabled):
    if where == "dotenv":
        home = _disk(tmp_path, enabled=enabled, dotenv="HOOK_TOKEN=" + _REAL + "\n")
    else:
        home = _disk(
            tmp_path, enabled=enabled,
            units={_SVC_NAME: _SVC + "Environment=HOOK_TOKEN=" + _REAL + "\n"},
        )
    ctx, by_id = _audit_home(home)
    # positive control: the collector read the definition, so UNKNOWN is the rule
    assert persistent_env_evidence(ctx, "HOOK_TOKEN")[0] == _REAL
    assert by_id["B1"].status == UNKNOWN, by_id["B1"].detail


_R4_SHAPES = {
    # each of these made the round-3 evidence rule answer PASS where the literal text is the
    # live token; the retracted rule has no evidence to get wrong
    "dotenv_quoted_empty_value_with_a_trailing_comment":
        dict(dotenv='HOOK_TOKEN="" # fill me in\n'),
    "dotenv_value_is_itself_a_template":
        dict(dotenv="HOOK_TOKEN=${HOOK_TOKEN}\n"),
    "blank_unit_value_masks_a_real_dotenv_value":
        dict(units={_SVC_NAME: _SVC + "Environment=HOOK_TOKEN=\n"},
             dotenv="HOOK_TOKEN=" + _REAL + "\n"),
    "defined_only_in_another_services_unit":
        dict(units={_SVC_NAME: _SVC,
                    "openclaw-backup.service":
                        "[Service]\nExecStart=/usr/bin/rsync -a x y\nEnvironment=HOOK_TOKEN="
                        + _REAL + "\n"}),
    "unit_unset_environment":
        dict(units={_SVC_NAME: _SVC + "Environment=HOOK_TOKEN=" + _REAL
                    + "\nUnsetEnvironment=HOOK_TOKEN\n"}),
    "unit_empty_environment_reset":
        dict(units={_SVC_NAME: _SVC + "Environment=HOOK_TOKEN=" + _REAL + "\nEnvironment=\n"}),
    "unit_dropin_reset":
        dict(units={_SVC_NAME: _SVC + "Environment=HOOK_TOKEN=" + _REAL + "\n"},
             extra_files={".config/systemd/user/openclaw-gateway.service.d/override.conf":
                          "[Service]\nEnvironment=\n"}),
    "unit_definition_in_the_wrong_section":
        dict(units={_SVC_NAME: "[Unit]\nDescription=x\nEnvironment=HOOK_TOKEN=" + _REAL
                    + "\n" + _SVC}),
    "profile_gateway_never_loads_the_default_gateway_env":
        dict(home_name=".openclaw-dev", gwenv="HOOK_TOKEN=" + _REAL + "\n",
             units={"openclaw-gateway-dev.service":
                    _SVC + "Environment=OPENCLAW_STATE_DIR=%h/.openclaw-dev\n"}),
}


@pytest.mark.parametrize("enabled", _ENABLED)
@pytest.mark.parametrize("shape", sorted(_R4_SHAPES))
def test_round_four_shapes_never_read_as_pass(tmp_path, shape, enabled):
    _, by_id = _audit_home(_disk(tmp_path, enabled=enabled, **_R4_SHAPES[shape]))
    assert by_id["B1"].status == UNKNOWN, (shape, by_id["B1"].status, by_id["B1"].detail)


@pytest.mark.parametrize("shape", ["none", "dotenv", "unit"])
def test_empty_fallback_on_disk_is_pass_with_and_without_a_definition(tmp_path, shape):
    kw = {
        "none": {},
        "dotenv": dict(dotenv="HOOK_TOKEN=" + _REAL + "\n"),
        "unit": dict(units={_SVC_NAME: _SVC + "Environment=HOOK_TOKEN=" + _REAL + "\n"}),
    }[shape]
    _, by_id = _audit_home(_disk(tmp_path, "${HOOK_TOKEN:-}", build=_B97, **kw))
    assert by_id["B1"].status == PASS, by_id["B1"].detail


def test_audit_from_disk_plain_reference_is_unknown_and_a_dotenv_does_not_change_it(tmp_path):
    cfg_text = '{"hooks": {"enabled": true, "token": "${HOOKS_TOKEN_REF}"}}'
    first = _audit_by_id(tmp_path, cfg_text)["B1"]
    assert first.status == UNKNOWN, first.detail
    assert "${HOOKS_TOKEN_REF}" in first.detail
    (tmp_path / ".env").write_text("HOOKS_TOKEN_REF=" + _VISIBLE + "\n", encoding="utf-8")
    (tmp_path / ".env").chmod(0o600)
    second = _audit_by_id(tmp_path, cfg_text)["B1"]
    assert second.status == UNKNOWN, second.detail
    assert second.detail == first.detail


# --------------------------------------------------------------------------------------
# 9. Build gate (C-646): a whole-value `${NAME:-}` is a reference only where the audited
#    OpenClaw understands the `:-` operator (2026.9.7+). Measured in the vendor code:
#    2026.9.7 parses the body with `parseEnvTokenBody` and a default operator; 2026.9.6 and
#    earlier test the whole body `NAME:-` against the name pattern, do not recognise the
#    token and pass the string through verbatim - so there the TEXT is the credential.
#    Only B1's two credential paths decide by build; the shape predicates, C015 and the
#    generic scan stay build-independent (they ask "is a secret held in the file").
# --------------------------------------------------------------------------------------

from clawseccheck.checks import _ENV_DEFAULT_OPERATOR_MIN, _env_default_operator  # noqa: E402

_GW_PATH = "gateway.auth.password"
_HK_PATH = "hooks.token"
_BOTH_PATHS = [_GW_PATH, _HK_PATH]

_NO_SENTENCE = (
    " This OpenClaw build does not understand the ${NAME:-} fallback form, which OpenClaw "
    "2026.9.7 introduced, so it uses the text itself as the credential."
)
_UNKNOWN_FIX = (
    "OpenClaw 2026.9.7 and later read the ${NAME:-} form as an environment reference; "
    "earlier builds do not understand it and use the text itself as the credential. Run "
    "the audit where the installed openclaw can be found, so the build is known."
)


def _at(path: str, value) -> dict:
    if path == _GW_PATH:
        return {"gateway": {"auth": {"password": value}}}
    return {"hooks": {"token": value}}


def _built(cfg: dict, installed=None, stamp=None, **kw) -> Context:
    cfg = dict(cfg)
    if stamp is not None:
        cfg["meta"] = {"lastTouchedVersion": stamp}
    return _ctx(cfg, build=installed, **kw)


# (id, installed build, meta.lastTouchedVersion stamp, what the helper must answer)
_BUILDS = [
    pytest.param("2026.9.6", None, "no", id="9.6"),
    pytest.param("2026.9.7", None, "yes", id="9.7"),
    pytest.param("2026.10.0", None, "yes", id="10.0"),
    pytest.param("2026.7.33", None, "no", id="extended-stable-7.33"),
    pytest.param("2026.9.7-beta.1", None, "unknown", id="prerelease"),
    pytest.param(None, "2026.9.7", "yes", id="none+stamp-9.7"),
    pytest.param(None, "2026.9.6", "unknown", id="none+stamp-9.6"),
    pytest.param(None, None, "unknown", id="none+no-stamp"),
    # the installed build decides outright: a stamp never overrules it, either way
    pytest.param("2026.9.6", "2026.9.7", "no", id="9.6-over-a-newer-stamp"),
    pytest.param("2026.9.7", "2026.9.6", "yes", id="9.7-over-an-older-stamp"),
    # what cannot be placed on the calendar-release timeline is unknown, not no
    pytest.param("0.0.0", None, "unknown", id="zero-version"),
    pytest.param("1.2.3", None, "unknown", id="not-a-calendar-release"),
    pytest.param("2026.9", None, "unknown", id="two-part"),
    pytest.param("2027.1", None, "unknown", id="two-part-after-the-threshold"),
    pytest.param("not-a-version", None, "unknown", id="no-digits"),
    pytest.param(None, "2026.9.7-rc.1", "unknown", id="prerelease-stamp"),
    pytest.param(None, "2027.1", "unknown", id="two-part-stamp"),
]
_STATUS_FOR = {"yes": PASS, "no": FAIL, "unknown": UNKNOWN}


def test_the_threshold_is_the_release_that_introduced_the_operator():
    assert _ENV_DEFAULT_OPERATOR_MIN == (2026, 9, 7)


@pytest.mark.parametrize(("installed", "stamp", "answer"), _BUILDS)
def test_env_default_operator_matrix(installed, stamp, answer):
    assert _env_default_operator(_built({}, installed, stamp)) == answer


def test_env_default_operator_without_a_context_is_unknown():
    assert _env_default_operator(object()) == "unknown"
    assert _env_default_operator(None) == "unknown"


@pytest.mark.parametrize("path", _BOTH_PATHS)
@pytest.mark.parametrize(("installed", "stamp", "answer"), _BUILDS)
def test_empty_fallback_status_follows_the_build_at_both_paths(path, installed, stamp, answer):
    f = check_secrets(_built(_at(path, "${HK:-}"), installed, stamp))
    assert f.id == "B1"
    assert f.status == _STATUS_FOR[answer], (installed, stamp, f.status, f.detail)


@pytest.mark.parametrize("path", _BOTH_PATHS)
@pytest.mark.parametrize(("installed", "stamp", "answer"), [b.values for b in _BUILDS if b.values[2] == "no"])
def test_no_is_the_plaintext_fail_byte_for_byte_with_one_added_fix_sentence(
        path, installed, stamp, answer):
    plain = check_secrets(_built(_at(path, "hunter2"), installed, stamp))
    f = check_secrets(_built(_at(path, "${HK:-}"), installed, stamp))
    assert plain.status == FAIL and f.status == FAIL
    # `detail` is what `.clawseccheckignore` fingerprints hash: a user who suppressed the
    # plaintext finding on dev keeps the suppression
    assert f.detail == plain.detail == path + " set in config"
    assert f.id == plain.id == "B1"
    # the disclosure is `fix` only, as exactly one added sentence
    assert f.fix == plain.fix + _NO_SENTENCE
    assert f.fix.isascii()
    for marker in ("2026.9.7", "fallback", "OpenClaw", "${"):
        assert marker not in f.detail, marker
    assert "fallback" not in plain.fix  # control: the added sentence is what carries it
    # the value never reaches the report
    assert "HK" not in f.detail


@pytest.mark.parametrize("path", _BOTH_PATHS)
@pytest.mark.parametrize(("installed", "stamp", "answer"), [b.values for b in _BUILDS if b.values[2] == "unknown"])
def test_unknown_names_the_path_and_the_reference_and_says_the_build_is_unknown(
        path, installed, stamp, answer):
    f = check_secrets(_built(_at(path, "  ${HK:-}  "), installed, stamp))
    assert f.status == UNKNOWN
    assert f.detail == (
        path + " is the reference ${HK:-}, and the installed OpenClaw build could not be "
        "determined, so this audit cannot tell whether that form is read as an environment "
        "reference."
    )
    assert f.fix == _UNKNOWN_FIX
    # nothing about versions or remedies leaks into the fingerprinted text
    assert "2026.9.7" not in f.detail and "earlier" not in f.detail and "Run the audit" not in f.detail
    assert f.detail.isascii() and f.fix.isascii()


@pytest.mark.parametrize("path", _BOTH_PATHS)
@pytest.mark.parametrize(("installed", "stamp", "answer"), [b.values for b in _BUILDS if b.values[2] == "yes"])
def test_yes_is_todays_reference_behaviour(path, installed, stamp, answer):
    f = check_secrets(_built(_at(path, "${HK:-}"), installed, stamp))
    assert f.status == PASS and f.detail.startswith("No exposed plaintext secrets")
    assert path not in f.detail


@pytest.mark.parametrize(("installed", "stamp", "answer"), _BUILDS)
def test_plain_reference_at_hooks_token_is_unknown_on_every_build(installed, stamp, answer):
    base = check_secrets(_hk_ctx("${HK}"))
    f = check_secrets(_built(_at(_HK_PATH, "${HK}"), installed, stamp))
    assert f.status == UNKNOWN, (installed, stamp, f.status, f.detail)
    # the build changes nothing about the plain form: same finding as with no build stated
    assert (f.detail, f.fix) == (base.detail, base.fix)


@pytest.mark.parametrize(("installed", "stamp", "answer"), _BUILDS)
def test_plain_reference_at_gateway_password_is_pass_on_every_build(installed, stamp, answer):
    for pw in ("${GW_PW}", "$GW_PW", dict(_OBJ)):
        f = check_secrets(_built(_at(_GW_PATH, pw), installed, stamp))
        assert f.status == PASS, (installed, stamp, pw, f.status, f.detail)


# the shapes the gate must NOT touch: the same verdict on every build
_BUILD_INDEPENDENT = [
    (_GW_PATH, "${GW_PW:-x}", FAIL),  # a non-empty fallback is a literal
    (_HK_PATH, "${HK:-x}", FAIL),
    (_GW_PATH, "${GW_PW:-}${OTHER}", FAIL),  # embedded / two tokens
    (_HK_PATH, "abc${HK:-}", FAIL),
    (_GW_PATH, "secretref-env:GW_PW", FAIL),  # the retired markers
    (_HK_PATH, "__env__:HK", FAIL),
    (_HK_PATH, "$HK", FAIL),  # shorthand is a literal at a plain-string field
    (_GW_PATH, "$GW_PW", PASS),  # shorthand IS a SecretInput reference
    (_GW_PATH, "${GW_PW}", PASS),
    (_GW_PATH, dict(_OBJ), PASS),
    (_HK_PATH, dict(_OBJ), PASS),
    (_GW_PATH, "hunter2", FAIL),
    (_HK_PATH, "hunter2", FAIL),
]


@pytest.mark.parametrize(("path", "value", "status"), _BUILD_INDEPENDENT)
@pytest.mark.parametrize(("installed", "stamp", "answer"), _BUILDS)
def test_everything_but_the_whole_value_empty_fallback_is_build_independent(
        path, value, status, installed, stamp, answer):
    f = check_secrets(_built(_at(path, value), installed, stamp))
    assert f.status == status, (path, value, installed, stamp, f.status, f.detail)
    if status == FAIL:
        assert "fallback form" not in f.fix  # the build sentence belongs to the gated shape only


def test_the_shape_predicates_and_the_generic_scans_read_no_build():
    from clawseccheck.checks import _c015_has_secret

    # no ctx parameter exists on any of these: they cannot depend on the build
    assert _is_secret_reference("${GW_PW:-}") is True
    assert _credential_is_plaintext("${GW_PW:-}", secret_input=True) is False
    assert _credential_is_plaintext("${GW_PW:-}", secret_input=False) is False
    assert _secret_paths({"gateway": {"auth": {"password": "${GW_PW:-}"}}}) == []
    assert _c015_has_secret('{"token": "${OPENCLAW_GATEWAY_TOKEN:-}"}') is False


@pytest.mark.parametrize(("installed", "stamp", "answer"), _BUILDS)
def test_a_fail_elsewhere_always_wins(installed, stamp, answer):
    # a plaintext sibling: the finding is the plaintext FAIL only, never an UNKNOWN
    cfg = dict(_at(_GW_PATH, "hunter2"), hooks={"token": "${HK:-}"})
    f = check_secrets(_built(cfg, installed, stamp))
    assert f.status == FAIL
    if answer == "no":  # both paths are the same finding: one label each
        assert f.detail == "gateway.auth.password set in config; hooks.token set in config"
    else:
        assert f.detail == "gateway.auth.password set in config"
    assert "could not be determined" not in f.detail
    # the plain hooks.token UNKNOWN loses to a FAIL too
    cfg = dict(_at(_GW_PATH, "hunter2"), hooks={"token": "${HK}"})
    assert check_secrets(_built(cfg, installed, stamp)).status == FAIL
    # a bootstrap secret FAILs regardless of the build, ahead of the UNKNOWN
    c = _built(_at(_HK_PATH, "${HK:-}"), installed, stamp)
    c.bootstrap = {"SOUL.md": "api token: " + _runtime_secret() + "\n"}
    f = check_secrets(c)
    assert f.status == FAIL and "SOUL.md" in f.detail and "could not be determined" not in f.detail


@pytest.mark.parametrize(("installed", "stamp", "answer"), [b.values for b in _BUILDS if b.values[2] == "unknown"])
def test_both_unknowns_are_one_finding_naming_both(installed, stamp, answer):
    # plain hooks.token + an empty-fallback password: ONE UNKNOWN, both causes named,
    # each cause's own text unchanged
    cfg = dict(_at(_GW_PATH, "${GW_PW:-}"), hooks={"token": "${HK}"})
    f = check_secrets(_built(cfg, installed, stamp))
    plain = check_secrets(_built(_at(_HK_PATH, "${HK}"), installed, stamp))
    fallback = check_secrets(_built(_at(_GW_PATH, "${GW_PW:-}"), installed, stamp))
    assert f.status == UNKNOWN and f.id == "B1"
    assert f.detail == plain.detail + " " + fallback.detail
    assert f.fix == plain.fix + " " + fallback.fix
    # both empty-fallback paths: one finding, both paths and both references printed
    cfg = dict(_at(_GW_PATH, "${GW_PW:-}"), hooks={"token": "${HK:-}"})
    f = check_secrets(_built(cfg, installed, stamp))
    assert f.status == UNKNOWN
    assert "gateway.auth.password is the reference ${GW_PW:-}" in f.detail
    assert "hooks.token is the reference ${HK:-}" in f.detail
    assert f.detail.count("could not be determined") == 1
    assert f.fix == _UNKNOWN_FIX


def test_the_no_sentence_is_added_once_even_when_both_paths_are_the_fallback():
    cfg = dict(_at(_GW_PATH, "${GW_PW:-}"), hooks={"token": "${HK:-}"})
    f = check_secrets(_built(cfg, "2026.9.6"))
    assert f.status == FAIL
    assert f.detail == "gateway.auth.password set in config; hooks.token set in config"
    assert f.fix.count("does not understand the ${NAME:-} fallback form") == 1


def test_the_env_block_note_and_the_build_sentence_are_independent():
    env = {"vars": {"GW_PW": _PLAIN}}
    cfg = _with_env(_at(_GW_PATH, "${GW_PW:-}"), env)
    yes = check_secrets(_built(cfg, _B97))
    no = check_secrets(_built(cfg, "2026.9.6"))
    assert yes.status == no.status == FAIL
    assert yes.detail == no.detail == "gateway.auth.password set in config"
    assert "env block" in yes.fix and "fallback form" not in yes.fix
    assert no.fix == yes.fix + _NO_SENTENCE


def test_the_environment_the_audit_runs_in_never_decides_the_build(monkeypatch):
    # only the installed dist (or the stamp) decides; the auditing process's own variables
    # and a same-named variable in the config's env block do not
    monkeypatch.setenv("HK", "x" * 40)
    f = check_secrets(_built(_at(_HK_PATH, "${HK:-}")))
    assert f.status == UNKNOWN


# -- the real seam: audit(include_dist=True) fills the installed build, B1 reads it ----------

@pytest.mark.parametrize(
    ("installed", "expected"),
    [("2026.9.6", FAIL), ("2026.9.7", PASS), ("2026.10.0", PASS), (None, UNKNOWN)],
)
def test_audit_from_disk_decides_by_the_installed_build(tmp_path, monkeypatch, installed, expected):
    import clawseccheck

    monkeypatch.setattr(clawseccheck, "_installed_dist_version", lambda *a, **k: installed)
    home = _disk(tmp_path, "${HOOK_TOKEN:-}")
    from clawseccheck import audit

    ctx, findings, _ = audit(home, include_native=False, include_dist=True)
    assert ctx.installed_dist_version == installed
    b1 = {f.id: f for f in findings}["B1"]
    assert b1.status == expected, (installed, b1.status, b1.detail)
    if expected == FAIL:
        assert b1.detail == "hooks.token set in config"
        assert b1.fix.endswith(_NO_SENTENCE)
