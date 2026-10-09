"""C-667: a SecretRef OBJECT at ``gateway.auth.token`` is a token set by reference.

OpenClaw types ``gateway.auth.token`` as ``SecretInput = string | SecretRef{source, provider,
id}``. Its resolver gives an unset ``gateway.auth.mode`` the value ``"token"`` whenever any
token is configured, and it recognises the reference in either spelling. B2 (`check_gateway`)
and B80 (`check_gateway_rate_limit`) already understood the string spelling (``"${ID}"``, C-653)
but read the object as "no token", so a non-loopback bind with no ``auth.mode`` was a false
FAIL (B2) / UNKNOWN (B80).

What this file pins, through the one pair of helpers (`_gateway_token_form`,
`_gateway_config_token`) that B2 and B80 share, plus B2's own strength lookup:

* a WELL-FORMED object (`_is_secret_ref_object`, no second parser) is a token set by
  reference, as a whole-value ``${ID}`` string is: the same authenticated-by-reference
  disclosure in B2, the same WARN in B80, no length read off the object itself, and nothing of
  the object (provider, id) echoed except the NAME of an ``env`` variable in a FAIL;
* B2 then looks up how strong the secret behind an ``env`` object is where the audit can see
  it: the env block of openclaw.json first (as for a string reference), then the gateway's
  persistent environment (a systemd unit, a dotenv file). A value under 24 characters is a
  FAIL, 24 or more is the plain disclosure, nothing found is the disclosure plus the caveat
  that the strength was not evaluated. A ``store`` / ``file`` / ``exec`` object is resolved by
  its own provider, never from the environment, so neither lookup is made for it;
* ``source: "exec"`` is a reference like env / file / store: OpenClaw 2026.9.8 resolves an
  exec reference for this key at gateway start through the same path, with no carve-out;
* an unresolvable reference makes the gateway REFUSE to start (the key is registered
  fail-closed), it never starts unauthenticated - which is why softening the FAIL for a
  reference is sound at all;
* everything else keeps today's verdict: an absent token, a literal, a retired marker, every
  malformed object, an explicit ``mode: none``, and an object at the legacy ``gateway.token``
  key (not in the OpenClaw schema, so it must never clear a "no auth" finding);
* NO token that is not an object changes: a differential table pins B2 and B80 on dev's output
  for about fifty non-object values (see `_DIFF_EXPECTED`).

Offline, read-only, stdlib only. Nothing here is a secret; ids are variable NAMES.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_gateway, check_gateway_rate_limit
from clawseccheck.checks._config import _gateway_config_token, _gateway_token_form
from clawseccheck.collector import Context

_NO_AUTH_DETAIL = "gateway.bind=lan exposed with auth.mode=None"
_DISCLOSURE = "gateway.auth.token is set"
_STRING_REF = "${OPENCLAW_GATEWAY_TOKEN}"
# The caveat B2 adds when the strength of a reference object's secret could not be found.
_CAVEAT = "cannot be read from the config and were not evaluated"
_CAVEAT_FIX = "Check, where the reference is resolved"

# One well-formed object per source. Ids are grammar-valid variable NAMES / paths.
_OBJECTS = {
    "env": {"source": "env", "provider": "default", "id": "OPENCLAW_GATEWAY_TOKEN"},
    "file": {"source": "file", "provider": "default", "id": "/gateway/token"},
    "store": {
        "source": "store",
        "provider": "default",
        "id": "OPENCLAW_GATEWAY_TOKEN_0123456789ABCDEF",
    },
    "exec": {"source": "exec", "provider": "vault", "id": "gateway/token"},
    "env-legacy-two-key": {"source": "env", "id": "OPENCLAW_GATEWAY_TOKEN"},
}


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    return c


def _gw(bind=None, mode=None, token=None, **extra) -> dict:
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


def _both(cfg: dict):
    ctx = _ctx(cfg)
    return check_gateway(ctx), check_gateway_rate_limit(_ctx(cfg))


def _same(a, b) -> bool:
    return (a.status, a.detail, a.fix) == (b.status, b.detail, b.fix)


# --------------------------------------------------------------------------------------
# the bug: no mode, non-loopback bind
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("source", sorted(_OBJECTS))
def test_object_token_with_no_mode_on_lan_is_the_reference_disclosure_not_a_fail(source):
    b2, b80 = _both(_gw(bind="lan", token=_OBJECTS[source]))
    assert b2.status == WARN, b2.detail
    assert _DISCLOSURE in b2.detail and "authenticated" in b2.detail
    assert "exposed" not in b2.detail
    assert b80.status == WARN, b80.detail


@pytest.mark.parametrize("source", sorted(_OBJECTS))
def test_object_token_with_no_evidence_reads_like_the_long_named_string_reference_plus_a_caveat(
    source,
):
    """With nothing in the env block and no persistent environment evidence, the object is
    the same configuration to OpenClaw as the ``${ID}`` string, so B2 gives the string's
    status, detail, fix and evidence - and then ONE addition: the string says "authenticated"
    and stops because its own (long) text carries no strength note, while an object is opaque
    by construction, so B2 says that its strength was not evaluated. B80 is identical."""
    obj_b2, obj_b80 = _both(_gw(bind="lan", token=_OBJECTS[source]))
    str_b2, str_b80 = _both(_gw(bind="lan", token=_STRING_REF))
    assert obj_b2.status == str_b2.status == WARN
    assert obj_b2.detail.startswith(str_b2.detail + "; ")
    assert obj_b2.fix.startswith(str_b2.fix + "; ")
    assert obj_b2.evidence[: len(str_b2.evidence)] == str_b2.evidence
    assert len(obj_b2.evidence) == len(str_b2.evidence) + 1
    assert _CAVEAT in obj_b2.detail[len(str_b2.detail):]
    assert _CAVEAT_FIX in obj_b2.fix[len(str_b2.fix):]
    assert _same(obj_b80, str_b80)
    assert obj_b80.evidence == str_b80.evidence


def test_the_issue_repro_row():
    """The literal repro from the report: lan bind, object token, no auth.mode."""
    for source, obj in sorted(_OBJECTS.items()):
        c = _ctx({"gateway": {"bind": "lan", "auth": {"token": obj}}})
        assert (check_gateway(c).status, check_gateway_rate_limit(c).status) == (WARN, WARN), source


def test_rate_limit_set_clears_b80_for_an_object_token_like_for_a_string_reference():
    for source, obj in sorted(_OBJECTS.items()):
        cfg = _gw(bind="lan", token=obj)
        cfg["gateway"]["auth"]["rateLimit"] = {"maxAttempts": 5}
        assert check_gateway_rate_limit(_ctx(cfg)).status == PASS, source


# --------------------------------------------------------------------------------------
# the matrix: object x bind x mode (what changes, and what must not)
# --------------------------------------------------------------------------------------

# (bind, mode) -> (B2, B80). Only (lan, no mode) moved; every other cell is today's verdict.
_MATRIX = {
    ("lan", None): (WARN, WARN),
    ("lan", "token"): (PASS, WARN),
    ("lan", "password"): (PASS, WARN),
    ("loopback", None): (PASS, PASS),
    ("loopback", "token"): (PASS, PASS),
    ("loopback", "password"): (PASS, PASS),
}


def test_object_token_matrix():
    for source, obj in sorted(_OBJECTS.items()):
        for (bind, mode), expected in sorted(_MATRIX.items(), key=str):
            cfg = _gw(bind=bind, mode=mode, token=obj)
            if mode == "password":
                cfg["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
            b2, b80 = _both(cfg)
            assert (b2.status, b80.status) == expected, (source, bind, mode, b2.detail, b80.detail)


def test_under_mode_token_an_object_with_no_evidence_gets_the_verdict_of_a_long_reference():
    """No extra note, no UNKNOWN: with an explicit mode and nothing found for the secret the
    object gets what the long-named string reference and a long literal get. (A short-named
    string reference such as ``${X}`` is not that: its text length triggers an UNKNOWN note
    of its own, which an object does not have.)"""
    ref = check_gateway(_ctx(_gw(bind="lan", mode="token", token=_STRING_REF)))
    lit = check_gateway(_ctx(_gw(bind="lan", mode="token", token="t" * 32)))
    for source, tok in sorted(_OBJECTS.items()):
        obj = check_gateway(_ctx(_gw(bind="lan", mode="token", token=tok)))
        assert _same(obj, ref) and _same(obj, lit), source
        assert obj.status == PASS, source


def test_under_password_mode_the_object_is_not_the_credential_in_effect():
    """Verdict unchanged: the token key is a leftover, so it is neither softened nor
    escalated. (A short STRING token there still FAILs; an object has no length.)"""
    base = _gw(bind="lan", mode="password")
    base["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
    for source, tok in sorted(_OBJECTS.items()):
        cfg = _gw(bind="lan", mode="password", token=tok)
        cfg["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
        assert _same(check_gateway(_ctx(cfg)), check_gateway(_ctx(base))), source
        assert _same(check_gateway_rate_limit(_ctx(cfg)), check_gateway_rate_limit(_ctx(base))), source


def test_explicit_mode_none_is_still_a_fail_with_an_object_token():
    """``mode: none`` is a decision, not an omission; a token beside it clears nothing."""
    without = check_gateway(_ctx(_gw(bind="lan", mode="none")))
    assert without.status == FAIL
    for source, tok in sorted(_OBJECTS.items()):
        with_obj = check_gateway(_ctx(_gw(bind="lan", mode="none", token=tok)))
        assert _same(with_obj, without), source


def test_a_templated_mode_is_not_cleared_by_an_object_token():
    ref = check_gateway(_ctx(_gw(bind="lan", mode="${M}", token=_STRING_REF)))
    assert ref.status == UNKNOWN
    for source, tok in sorted(_OBJECTS.items()):
        obj = check_gateway(_ctx(_gw(bind="lan", mode="${M}", token=tok)))
        assert _same(obj, ref), source


def test_an_independent_fail_still_wins_beside_an_object_token():
    cfg = _gw(bind="lan", token=_OBJECTS["env"])
    cfg["channels"] = {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    assert "open dm/group policy" in f.detail
    assert _DISCLOSURE in f.detail


def test_tailscale_funnel_still_fails_beside_an_object_token():
    cfg = _gw(bind="lan", token=_OBJECTS["env"], tailscale={"mode": "funnel"})
    assert check_gateway(_ctx(cfg)).status == FAIL


# --------------------------------------------------------------------------------------
# fail closed: nothing that is not a well-formed reference clears anything
# --------------------------------------------------------------------------------------

_MALFORMED = {
    "no-id": {"source": "env"},
    "no-id-with-provider": {"source": "env", "provider": "default"},
    "unknown-source": {"source": "nope", "provider": "p", "id": "X"},
    "source-case": {"source": "ENV", "provider": "default", "id": "GW_TOKEN"},
    "empty-id": {"source": "env", "provider": "default", "id": ""},
    "non-string-id": {"source": "env", "provider": "default", "id": 5},
    "lowercase-env-id": {"source": "env", "provider": "default", "id": "gw_token"},
    "store-id-with-dash": {"source": "store", "provider": "default", "id": "GW-TOKEN"},
    "file-id-not-absolute": {"source": "file", "provider": "default", "id": "gateway/token"},
    "exec-id-dotdot": {"source": "exec", "provider": "vault", "id": "gw/../token"},
    "empty-provider": {"source": "env", "provider": "", "id": "GW_TOKEN"},
    "uppercase-provider": {"source": "env", "provider": "Default", "id": "GW_TOKEN"},
    "non-string-provider": {"source": "env", "provider": 1, "id": "GW_TOKEN"},
    "plaintext-smuggled-next-to-the-pointer": {
        "source": "env",
        "provider": "default",
        "id": "GW_TOKEN",
        "value": "x" * 30,
    },
    "extra-key-only": {"source": "env", "provider": "default", "id": "GW_TOKEN", "x": 1},
    "empty-object": {},
    "only-a-value": {"value": "x" * 30},
    "list-instead-of-object": [_OBJECTS["env"]],
    "list-of-one-string": ["${OPENCLAW_GATEWAY_TOKEN}"],
    "object-nested-one-level-deeper": {"token": _OBJECTS["env"]},
    "reference-nested-under-value": {"value": _OBJECTS["env"]},
    "number": 12345,
    "true": True,
}


def test_a_malformed_object_keeps_the_no_token_fail():
    none_b2, none_b80 = _both(_gw(bind="lan"))
    assert none_b2.status == FAIL and _NO_AUTH_DETAIL in none_b2.detail
    assert none_b80.status == UNKNOWN
    for name, tok in sorted(_MALFORMED.items()):
        b2, b80 = _both(_gw(bind="lan", token=tok))
        # byte-for-byte what a config with no token at all says
        assert _same(b2, none_b2), (name, b2.detail)
        assert _same(b80, none_b80), (name, b80.detail)


def test_a_malformed_object_is_never_a_reference_and_never_cleaner_than_no_token():
    """Every malformed shape x the exposed bind spellings x the modes that do not
    authenticate by themselves: the helpers see no credential and the verdicts never move
    off the no-token ones."""
    cells = 0
    for name, tok in sorted(_MALFORMED.items()):
        assert _gateway_token_form(tok) != "reference", name
        assert _gateway_config_token(_gw(bind="lan", token=tok), None) == (None, False), name
        for bind in ("lan", "0.0.0.0"):
            for mode in ("none", None):
                cfg, base = _gw(bind=bind, mode=mode, token=tok), _gw(bind=bind, mode=mode)
                assert _same(check_gateway(_ctx(cfg)), check_gateway(_ctx(base))), (name, bind, mode)
                assert _same(
                    check_gateway_rate_limit(_ctx(cfg)), check_gateway_rate_limit(_ctx(base))
                ), (name, bind, mode)
                cells += 1
    assert cells == len(_MALFORMED) * 4


def test_a_malformed_object_at_the_auth_key_hides_nothing_behind_a_legacy_string():
    """`gateway.auth.token` wins over `gateway.token` (B-312's order). A truthy malformed
    object at the first key must not be skipped in favour of the second."""
    cfg = _gw(bind="lan", token=_MALFORMED["no-id"])
    cfg["gateway"]["token"] = _OBJECTS["env"]
    assert check_gateway(_ctx(cfg)).status == FAIL


# --- the legacy root key: not in the OpenClaw schema, so never auth --------------------


def test_an_object_at_the_legacy_root_key_clears_nothing():
    """OpenClaw 2026.9.8's GatewayConfigSchema is a strictObject with no root ``token``, and
    it logs that the key "is ignored"; a reference there must keep the no-auth FAIL."""
    base_b2, base_b80 = _both(_gw(bind="lan"))
    for source, obj in sorted(_OBJECTS.items()):
        cfg = {"gateway": {"bind": "lan", "token": obj}}
        b2, b80 = _both(cfg)
        assert b2.status == FAIL and _NO_AUTH_DETAIL in b2.detail, source
        assert _same(b2, base_b2), source
        assert b80.status == UNKNOWN and _same(b80, base_b80), source
        assert _gateway_config_token(cfg, None) == (None, False), source


def test_an_object_at_the_legacy_key_beside_an_empty_auth_token_clears_nothing():
    cfg = {"gateway": {"bind": "lan", "auth": {"token": ""}, "token": _OBJECTS["env"]}}
    assert check_gateway(_ctx(cfg)).status == FAIL


def test_a_string_at_the_legacy_root_key_keeps_its_old_reading():
    """Control: this change does not touch the string reading of the legacy key."""
    cfg = {"gateway": {"bind": "lan", "token": "t" * 32}}
    assert check_gateway(_ctx(cfg)).status == WARN
    assert _gateway_config_token(cfg, None) == ("t" * 32, True)


# --------------------------------------------------------------------------------------
# controls: other token forms keep their verdicts
# --------------------------------------------------------------------------------------


def test_absent_token_is_unchanged():
    b2, b80 = _both(_gw(bind="lan"))
    assert b2.status == FAIL and _NO_AUTH_DETAIL in b2.detail
    assert b80.status == UNKNOWN


def test_literal_token_is_unchanged():
    b2, b80 = _both(_gw(bind="lan", token="t" * 32))
    assert (b2.status, b80.status) == (WARN, WARN)
    assert _DISCLOSURE in b2.detail


def test_short_literal_token_is_unchanged():
    b2, _ = _both(_gw(bind="lan", token="short-token"))
    assert b2.status == FAIL
    assert "gateway auth token shorter than 24 chars" in b2.detail
    assert "world-reachable behind a guessable secret" in b2.detail
    mode_token = check_gateway(_ctx(_gw(bind="lan", mode="token", token="short-token")))
    assert mode_token.status == FAIL
    assert mode_token.detail == "gateway auth token shorter than 24 chars"


@pytest.mark.parametrize(
    "marker", ["secretref-env:OPENCLAW_GATEWAY_TOKEN", "__env__:OPENCLAW_GATEWAY_TOKEN"]
)
def test_retired_marker_is_unchanged(marker):
    b2, b80 = _both(_gw(bind="lan", token=marker))
    assert b2.status == WARN and "retired" in b2.detail and "authenticated" not in b2.detail
    assert b80.status == WARN
    assert _gateway_token_form(marker) == "marker"


def test_string_reference_is_unchanged():
    b2, b80 = _both(_gw(bind="lan", token=_STRING_REF))
    assert (b2.status, b80.status) == (WARN, WARN)
    assert _DISCLOSURE in b2.detail
    assert _gateway_token_form(_STRING_REF) == "reference"


# --------------------------------------------------------------------------------------
# B2 and B80 read the input one way, through the shared helper
# --------------------------------------------------------------------------------------


def test_the_helpers_answer_reference_for_every_well_formed_object():
    for source, obj in sorted(_OBJECTS.items()):
        assert _gateway_token_form(obj) == "reference", source
        token, strong = _gateway_config_token(_gw(bind="lan", token=obj), None)
        assert token is not None and strong is True, source


def test_the_helper_returns_nothing_of_the_object():
    """The first item is documented as "the credential" and the whole point of a reference
    is that there is none in the file; no id, provider or source may ride along."""
    for source, obj in sorted(_OBJECTS.items()):
        token, _ = _gateway_config_token(_gw(bind="lan", token=obj), None)
        assert isinstance(token, str), source
        for part in (obj["source"], obj["id"], obj.get("provider", "\0")):
            assert part not in token, (source, part)


def test_an_explicit_mode_means_the_helper_derives_nothing_from_an_object():
    for source, obj in sorted(_OBJECTS.items()):
        for mode in ("token", "password", "none", "trusted-proxy", "${M}"):
            cfg = _gw(bind="lan", mode=mode, token=obj)
            assert _gateway_config_token(cfg, mode) == (None, False), (source, mode)


def test_b2_and_b80_agree_on_every_object_x_bind_x_mode():
    """B80 reads the token as credential exactly where B2 does: a (lan, no mode) object is
    authenticated-by-reference in both, never FAIL in one and UNKNOWN in the other."""
    for source, obj in sorted(_OBJECTS.items()):
        for bind in ("lan", "loopback"):
            for mode in (None, "token"):
                b2, b80 = _both(_gw(bind=bind, mode=mode, token=obj))
                ref_b2, ref_b80 = _both(_gw(bind=bind, mode=mode, token=_STRING_REF))
                assert (b2.status, b80.status) == (ref_b2.status, ref_b80.status), (
                    source, bind, mode)
                assert b2.status != FAIL and b80.status != UNKNOWN, (source, bind, mode)


# --------------------------------------------------------------------------------------
# nothing of the object reaches a message
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("bind,mode", [("lan", None), ("lan", "token"), ("loopback", None)])
def test_the_object_is_never_echoed(bind, mode):
    obj = {"source": "env", "provider": "uniqueprovider", "id": "UNIQUE_ID_PROBE_NAME"}
    for f in _both(_gw(bind=bind, mode=mode, token=obj)):
        blob = " ".join([f.detail, f.fix, *f.evidence])
        for needle in ("uniqueprovider", "UNIQUE_ID_PROBE_NAME", "SecretRef object"):
            assert needle not in blob, (f.id, needle)


# --------------------------------------------------------------------------------------
# an env-source reference whose variable the config's OWN env block defines
# --------------------------------------------------------------------------------------
# The string reference is not cleared by a short value defined in openclaw.json's env block
# (the secret sits in the file); an ENV-source object points at the same variable and gets the
# same reading of that block. (A store / file / exec object does not: see the section below.)


def _with_env_block(cfg: dict, name: str, value) -> dict:
    cfg["env"] = {"vars": {name: value}}
    return cfg


def test_env_object_whose_variable_the_env_block_defines_short_keeps_the_fail():
    """The env block is read for an ``env`` object exactly as for the string reference: same
    status, detail, fix and evidence."""
    obj = _OBJECTS["env"]
    cfg = _with_env_block(_gw(bind="lan", token=obj), obj["id"], "abc")
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL, f.detail
    assert "gateway auth token shorter than 24 chars" in f.detail
    ref = check_gateway(
        _ctx(_with_env_block(_gw(bind="lan", token="${" + obj["id"] + "}"), obj["id"], "abc"))
    )
    assert _same(f, ref)


def test_the_env_block_value_never_reaches_the_message():
    value = "v" * 7 + "qzx"
    obj = _OBJECTS["env"]
    f = check_gateway(_ctx(_with_env_block(_gw(bind="lan", token=obj), obj["id"], value)))
    assert f.status == FAIL
    assert value not in f.detail and value not in f.fix and all(value not in e for e in f.evidence)


def test_env_object_whose_variable_the_env_block_defines_long_is_never_a_pass():
    obj = _OBJECTS["env"]
    cfg = _with_env_block(_gw(bind="lan", token=obj), obj["id"], "v" * 40)
    f = check_gateway(_ctx(cfg))
    ref = check_gateway(
        _ctx(_with_env_block(_gw(bind="lan", token="${" + obj["id"] + "}"), obj["id"], "v" * 40))
    )
    assert f.status == WARN and "process environment" in f.detail
    assert _same(f, ref)


@pytest.mark.parametrize("mode", [None, "token"])
def test_object_env_block_reading_is_the_string_reference_reading_in_both_modes(mode):
    """Where the token is the credential in effect (no mode, or mode exactly "token") the
    object follows the string reference through the env block, so under mode "token" a short
    value the config itself defines is a FAIL for both spellings - the same input, read the
    same way - while an undefined variable (no env block entry) stays the plain PASS."""
    obj = _OBJECTS["env"]
    short = "abc"
    for value, expect in ((short, FAIL), ("v" * 40, WARN if mode is None else UNKNOWN)):
        o = check_gateway(_ctx(_with_env_block(_gw(bind="lan", mode=mode, token=obj), obj["id"], value)))
        s = check_gateway(
            _ctx(_with_env_block(_gw(bind="lan", mode=mode, token="${" + obj["id"] + "}"), obj["id"], value))
        )
        assert o.status == expect, (mode, len(value), o.detail)
        assert _same(o, s), (mode, len(value))
    undefined = check_gateway(_ctx(_gw(bind="lan", mode=mode, token=obj)))
    assert undefined.status == (WARN if mode is None else PASS)


@pytest.mark.parametrize("mode", ["password", "none", "trusted-proxy"])
def test_object_env_block_is_not_consulted_where_the_token_is_not_in_effect(mode):
    obj = _OBJECTS["env"]
    cfg = _with_env_block(_gw(bind="lan", mode=mode, token=obj), obj["id"], "abc")
    plain = _gw(bind="lan", mode=mode, token=obj)
    for c in (cfg, plain):
        if mode == "password":
            c["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
    assert _same(check_gateway(_ctx(cfg)), check_gateway(_ctx(plain)))


# --------------------------------------------------------------------------------------
# store / file / exec: resolved by their own provider, so neither lookup is made
# --------------------------------------------------------------------------------------
# A store reference is resolved from OpenClaw's secret store, a file one from the file, an
# exec one by the command - never from the process environment and never from the env block
# of openclaw.json. A value either holds under the same NAME says nothing about them.


def _store_obj(var: str = "OPENCLAW_GATEWAY_TOKEN") -> dict:
    return {"source": "store", "provider": "default", "id": var}


@pytest.mark.parametrize("env_value", ["abc", "v" * 40])
def test_store_object_ignores_the_env_block_whatever_it_holds(env_value):
    """The two configs a reviewer built for the store source. On dev both are PASS (the
    object read as no token, and mode "token" asks nothing more); the round-one branch read
    the store id through the env block and turned them into a FAIL and an UNKNOWN."""
    cfg = {
        "gateway": {"bind": "lan", "auth": {"mode": "token", "token": _store_obj()}},
        "env": {"vars": {"OPENCLAW_GATEWAY_TOKEN": env_value}},
    }
    assert check_gateway(_ctx(cfg)).status == PASS


_PROVIDER_RESOLVED = {
    "store": _store_obj(),  # the id is a variable NAME, so the block could define it
    "store-long-id": _OBJECTS["store"],
    "file": _OBJECTS["file"],
    "exec": _OBJECTS["exec"],
}


@pytest.mark.parametrize("env_value", ["abc", "v" * 40])
@pytest.mark.parametrize("name", sorted(_PROVIDER_RESOLVED))
def test_store_file_exec_object_ignores_the_env_block_and_reads_as_unevaluated(name, env_value):
    """No mode: the same verdict as with no env block at all - the disclosure plus the
    caveat that the strength was not evaluated - whatever the block holds under the object's
    own id (when that is a variable name) or under the gateway token's usual name."""
    obj = dict(_PROVIDER_RESOLVED[name])
    plain = check_gateway(_ctx(_gw(bind="lan", token=obj)))
    assert plain.status == WARN and _CAVEAT in plain.detail
    cfg = _gw(bind="lan", token=obj)
    cfg["env"] = {"vars": {obj["id"]: env_value, "OPENCLAW_GATEWAY_TOKEN": env_value}}
    assert _same(check_gateway(_ctx(cfg)), plain)


@pytest.mark.parametrize("unit_value", ["abc", "v" * 40])
@pytest.mark.parametrize("name", sorted(_PROVIDER_RESOLVED))
def test_store_file_exec_object_ignores_the_unit_environment(name, unit_value):
    """Even when a unit sets a variable that has the object's own id as its name, a store /
    file / exec reference does not read it: no FAIL, the caveat in the no-mode disclosure,
    and PASS under mode "token"."""
    obj = dict(_PROVIDER_RESOLVED[name])
    unit = {obj["id"]: unit_value, "OPENCLAW_GATEWAY_TOKEN": unit_value}
    plain = check_gateway(_ctx(_gw(bind="lan", token=obj)))
    nomode = check_gateway(_with_unit_env(_gw(bind="lan", token=obj), unit))
    assert _same(nomode, plain)
    token_mode = check_gateway(_with_unit_env(_gw(bind="lan", mode="token", token=obj), unit))
    assert token_mode.status == PASS, token_mode.detail


# --------------------------------------------------------------------------------------
# an env-source object: the strength of its secret, looked up where the audit can see it
# --------------------------------------------------------------------------------------
# The gateway resolves an env reference from its own process environment, which a service
# unit or a global dotenv file supplies. B2 reads that evidence (persistent artifacts only;
# the auditing shell's os.environ is never consulted), measures only the LENGTH, and keeps
# the value, the provider and the source's absolute path out of every message.

_UNIT_VAR = "OPENCLAW_GATEWAY_TOKEN"
_SHORT = "q7z"  # three characters: never a plausible secret, and easy to look for
_LONG = "w" * 40
_PROVIDER = "uniqprov"
_ENV_OBJ = {"source": "env", "provider": _PROVIDER, "id": _UNIT_VAR}


def _with_unit_env(cfg: dict, unit_env: dict, source: str = "gateway.service") -> Context:
    c = _ctx(cfg)
    c.unit_env_values = dict(unit_env)
    c.unit_env_sources = {k: source for k in unit_env}
    c.unit_env_found = True
    return c


def _blob(f) -> str:
    return " ".join([f.detail, f.fix, *f.evidence])


def _lan(bind="lan", mode=None, token=None):
    return _gw(bind=bind, mode=mode, token=_ENV_OBJ if token is None else token)


@pytest.mark.parametrize("obj_key", ["env", "env-legacy-two-key"])
@pytest.mark.parametrize("bind", ["lan", "custom"])
def test_env_object_whose_variable_a_unit_sets_short_is_a_fail(bind, obj_key):
    """The true positive the first round lost: dev FAILs this (the environment leg, with the
    object read as no token); the object is a reference to that very variable, and the
    gateway resolves it to the 3-character value."""
    obj = dict(_OBJECTS[obj_key])
    obj["id"] = _UNIT_VAR
    f = check_gateway(_with_unit_env(_gw(bind=bind, token=obj), {_UNIT_VAR: _SHORT}))
    assert f.status == FAIL, f.detail
    assert "environment-supplied secret shorter than 24 chars (gateway.service)" in f.detail
    assert "gateway auth token shorter than 24 chars" in f.detail
    assert _UNIT_VAR in f.detail  # the variable NAME may be said
    for part in (_SHORT, _PROVIDER):
        assert part not in _blob(f), part
    # B80 keeps the behaviour of a well-formed object: a credential, unthrottled
    b80 = check_gateway_rate_limit(_with_unit_env(_gw(bind=bind, token=obj), {_UNIT_VAR: _SHORT}))
    assert b80.status == WARN


def test_env_object_short_value_is_found_through_a_dotenv_file_too(tmp_path):
    c = _ctx(_lan())
    c.home = tmp_path / ".openclaw"
    c.dotenv_values = {_UNIT_VAR: _SHORT}
    c.dotenv_sources = {_UNIT_VAR: str(c.home / ".env")}
    c.dotenv_found = True
    f = check_gateway(c)
    assert f.status == FAIL
    assert _SHORT not in _blob(f) and str(tmp_path) not in _blob(f)
    assert ".env" in f.detail


def test_env_object_variable_name_is_the_one_looked_up():
    """The object names its variable; a short OPENCLAW_GATEWAY_TOKEN that the object does not
    point at is not its secret (the config token wins, config-first), so it is not a FAIL."""
    obj = {"source": "env", "provider": _PROVIDER, "id": "MY_GW_SECRET"}
    other = check_gateway(_with_unit_env(_gw(bind="lan", token=obj), {_UNIT_VAR: _SHORT}))
    assert other.status == WARN and _CAVEAT in other.detail
    named = check_gateway(_with_unit_env(_gw(bind="lan", token=obj), {"MY_GW_SECRET": _SHORT}))
    assert named.status == FAIL and "MY_GW_SECRET" in named.detail


def test_env_object_value_that_is_long_enough_is_the_plain_disclosure():
    f = check_gateway(_with_unit_env(_lan(), {_UNIT_VAR: _LONG}))
    assert f.status == WARN
    assert _DISCLOSURE in f.detail and "authenticated" in f.detail
    assert _CAVEAT not in f.detail and _CAVEAT_FIX not in f.fix
    assert _LONG not in _blob(f)


def test_a_value_is_measured_after_strip():
    f = check_gateway(_with_unit_env(_lan(), {_UNIT_VAR: "  " + "x" * 23 + "  "}))
    assert f.status == FAIL
    f = check_gateway(_with_unit_env(_lan(), {_UNIT_VAR: "  " + "x" * 24 + "  "}))
    assert f.status == WARN


@pytest.mark.parametrize("bind", ["lan", "custom"])
def test_env_object_with_no_evidence_is_the_disclosure_with_the_caveat(bind):
    f = check_gateway(_ctx(_lan(bind=bind)))
    assert f.status == WARN
    assert _DISCLOSURE in f.detail and "authenticated" in f.detail
    assert _CAVEAT in f.detail and _CAVEAT_FIX in f.fix
    assert "exposed" not in f.detail
    for part in (_PROVIDER, _UNIT_VAR):  # nothing of the object rides along in the caveat
        assert part not in _blob(f), part
    # a unit that was read but does not carry the variable is the same "nothing found"
    other = check_gateway(_with_unit_env(_lan(bind=bind), {"UNRELATED_VAR": _SHORT}))
    assert _same(other, f)


@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_under_mode_token_a_short_env_value_is_the_token_length_clause(bind):
    f = check_gateway(_with_unit_env(_lan(bind=bind, mode="token"), {_UNIT_VAR: _SHORT}))
    assert f.status == FAIL
    assert f.detail == "gateway auth token shorter than 24 chars"
    assert "Use a gateway auth token of at least 24 characters" in f.fix
    assert _UNIT_VAR in f.fix
    for part in (_SHORT, _PROVIDER):
        assert part not in _blob(f), part


@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_under_mode_token_a_long_or_unseen_env_value_is_a_pass(bind):
    long_ = check_gateway(_with_unit_env(_lan(bind=bind, mode="token"), {_UNIT_VAR: _LONG}))
    none = check_gateway(_ctx(_lan(bind=bind, mode="token")))
    assert long_.status == PASS and none.status == PASS
    assert _same(long_, none)


def test_a_loopback_bind_with_no_mode_and_a_short_env_value_gets_the_clause_of_a_short_literal():
    """A short literal token FAILs on loopback too (the clause is bind-independent); a
    reference to a variable that holds a short value is the same weakness."""
    lit = check_gateway(_ctx(_gw(bind="loopback", token="short-token")))
    obj = check_gateway(_with_unit_env(_lan(bind="loopback"), {_UNIT_VAR: _SHORT}))
    assert lit.status == obj.status == FAIL
    assert obj.detail == lit.detail == "gateway auth token shorter than 24 chars"
    # and nothing seen, or a long value: unchanged, PASS
    assert check_gateway(_ctx(_lan(bind="loopback"))).status == PASS
    assert check_gateway(_with_unit_env(_lan(bind="loopback"), {_UNIT_VAR: _LONG})).status == PASS


@pytest.mark.parametrize("mode", ["password", "none", "trusted-proxy"])
def test_env_evidence_is_not_consulted_where_the_token_is_not_in_effect(mode):
    cfg = _lan(mode=mode)
    if mode == "password":
        cfg["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
    plain = check_gateway(_ctx(cfg))
    with_unit = check_gateway(_with_unit_env(cfg, {_UNIT_VAR: _SHORT}))
    assert _same(plain, with_unit)


def test_the_environment_of_the_auditing_shell_is_not_evidence(monkeypatch):
    monkeypatch.setenv(_UNIT_VAR, _SHORT)
    f = check_gateway(_ctx(_lan()))
    assert f.status == WARN and _CAVEAT in f.detail


def test_the_env_block_is_read_first_and_a_weak_entry_there_is_final():
    """Order: the env block (as for a string reference), then the persistent environment.
    A short block entry is the FAIL the string reference gets, whatever a unit holds."""
    cfg = _with_env_block(_lan(), _UNIT_VAR, _SHORT)
    f = check_gateway(_with_unit_env(cfg, {_UNIT_VAR: _LONG}))
    ref_cfg = _with_env_block(_gw(bind="lan", token="${" + _UNIT_VAR + "}"), _UNIT_VAR, _SHORT)
    ref = check_gateway(_with_unit_env(ref_cfg, {_UNIT_VAR: _LONG}))
    assert f.status == FAIL and _same(f, ref)


def test_a_long_env_block_entry_does_not_hide_a_short_value_in_the_unit():
    """The process environment wins over a config env value (the existing "long" note says
    so), so a short unit value is what the gateway uses: still a FAIL."""
    cfg = _with_env_block(_lan(), _UNIT_VAR, _LONG)
    f = check_gateway(_with_unit_env(cfg, {_UNIT_VAR: _SHORT}))
    assert f.status == FAIL and "shorter than 24 chars" in f.detail
    for part in (_SHORT, _LONG, _PROVIDER):
        assert part not in _blob(f), part


def test_a_long_env_block_entry_with_a_long_unit_value_keeps_the_no_pass_note():
    cfg = _with_env_block(_lan(), _UNIT_VAR, _LONG)
    f = check_gateway(_with_unit_env(cfg, {_UNIT_VAR: _LONG}))
    assert f.status == WARN and "process environment" in f.detail


def test_a_malformed_env_object_is_not_looked_up():
    """A malformed object keeps the no-token verdict, with the same evidence in the unit as
    a config with no token at all would see."""
    unit = {"GW_TOKEN": _SHORT, _UNIT_VAR: _SHORT}
    base = check_gateway(_with_unit_env(_gw(bind="lan"), unit))
    for name, tok in sorted(_MALFORMED.items()):
        f = check_gateway(_with_unit_env(_gw(bind="lan", token=tok), unit))
        assert _same(f, base), name


def test_wiring_collect_reads_the_unit_and_the_message_hides_the_path(tmp_path):
    from clawseccheck.collector import collect

    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = {"gateway": {"bind": "lan", "auth": {"token": _ENV_OBJ}}}
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "openclaw-gateway.service").write_text(
        "[Service]\nExecStart=/usr/bin/openclaw gateway run\n"
        f"Environment={_UNIT_VAR}={_SHORT}\n",
        encoding="utf-8",
    )
    f = check_gateway(collect(home))
    assert f.status == FAIL, f.detail
    assert "Environment=" in f.detail
    assert str(tmp_path) not in _blob(f)
    assert _SHORT not in _blob(f)


# --------------------------------------------------------------------------------------
# a token that is not an object: B2 and B80 give exactly what dev gives (differential)
# --------------------------------------------------------------------------------------
# The rule of this change: only a SecretRef OBJECT reads differently. This table runs B2 and
# B80 over about fifty values that are NOT objects (absent, empty, literals of every length
# class, whole-value and look-alike references, retired markers, numbers, lists, booleans, and
# the same at the legacy gateway.token key) across the bind spellings, the auth modes, four
# kinds of environment evidence (unreadable, read and empty, a short value, a long value) and
# three kinds of env block (none, short, long), and compares status, detail, fix and evidence
# with a frozen expectation.
#
# HOW `_DIFF_EXPECTED` WAS GENERATED: by this file's own `_diff_cells()`, run on the tree the
# change is based on (dev), not on the branch, with
#     cd <dev checkout> && PYTHONPATH=. /usr/bin/python3 <branch>/tests/test_c667_gateway_token_secretref_object.py
# which prints the literal below (`--cells LABEL` prints one value cell by cell). Per value and
# per check it stores the cell statuses run-length encoded (F fail, W warn, P pass, U unknown;
# cell order: bind, mode, unit evidence, env block) and a digest of every cell's
# status, detail, fix and evidence. Regenerate it the same way, from the commit before a
# deliberate change to how B2 or B80 read a non-object token, never from the tree under test.

_DIFF_VAR_LONG = "OPENCLAW_GATEWAY_TOKEN"
_DIFF_VAR_SHORT = "GW_T"
_DIFF_BINDS = (None, "loopback", "lan", "custom")
_DIFF_MODES = (None, "token", "password", "none")
_DIFF_UNIT = (("unreadable", None), ("empty", {}), ("short", "abc"), ("long", "v" * 40))
_DIFF_BLOCK = (("none", None), ("short", "abc"), ("long", "v" * 40))
_NOKEY = object()  # the key is not in the config at all

_DIFF_VALUES = [
    # (label, value at gateway.auth.token, value at the legacy gateway.token)
    ("absent", _NOKEY, _NOKEY),
    ("null", None, _NOKEY),
    ("empty", "", _NOKEY),
    ("blank", "   ", _NOKEY),
    ("lit-3", "abc", _NOKEY),
    ("lit-11", "short-token", _NOKEY),
    ("lit-23", "t" * 23, _NOKEY),
    ("lit-24", "t" * 24, _NOKEY),
    ("lit-24-padded", "  " + "t" * 24 + "  ", _NOKEY),
    ("lit-23-padded", "  " + "t" * 23 + "  ", _NOKEY),
    ("lit-32", "t" * 32, _NOKEY),
    ("lit-bearer", "Bearer abc", _NOKEY),
    ("lit-null-word", "null", _NOKEY),
    ("lit-none-word", "none", _NOKEY),
    ("ref-long-name", "${" + _DIFF_VAR_LONG + "}", _NOKEY),
    ("ref-short-name", "${" + _DIFF_VAR_SHORT + "}", _NOKEY),
    ("ref-shorthand-long", "$" + _DIFF_VAR_LONG, _NOKEY),
    ("ref-shorthand-short", "$" + _DIFF_VAR_SHORT, _NOKEY),
    ("ref-fallback-empty-long", "${" + _DIFF_VAR_LONG + ":-}", _NOKEY),
    ("ref-fallback-empty-short", "${" + _DIFF_VAR_SHORT + ":-}", _NOKEY),
    ("ref-fallback-value", "${" + _DIFF_VAR_SHORT + ":-fallback-value}", _NOKEY),
    ("ref-padded", "  ${" + _DIFF_VAR_LONG + "}  ", _NOKEY),
    ("ref-trailing-newline", "${" + _DIFF_VAR_SHORT + "}\n", _NOKEY),
    ("ref-prefixed", "prefix-${" + _DIFF_VAR_SHORT + "}", _NOKEY),
    ("ref-suffixed", "${" + _DIFF_VAR_SHORT + "}-suffix", _NOKEY),
    ("ref-two", "${A}${B}", _NOKEY),
    ("ref-lowercase-name", "${gw_t}", _NOKEY),
    ("ref-bad-name", "${1BAD}", _NOKEY),
    ("ref-unclosed", "${" + _DIFF_VAR_SHORT, _NOKEY),
    ("marker-secretref-long", "secretref-env:" + _DIFF_VAR_LONG, _NOKEY),
    ("marker-secretref-short", "secretref-env:" + _DIFF_VAR_SHORT, _NOKEY),
    ("marker-env-long", "__env__:" + _DIFF_VAR_LONG, _NOKEY),
    ("marker-env-short", "__env__:" + _DIFF_VAR_SHORT, _NOKEY),
    ("int-zero", 0, _NOKEY),
    ("int", 12345, _NOKEY),
    ("float", 1.5, _NOKEY),
    ("true", True, _NOKEY),
    ("false", False, _NOKEY),
    ("list-empty", [], _NOKEY),
    ("list-literal", ["abc"], _NOKEY),
    ("list-reference", ["${" + _DIFF_VAR_SHORT + "}"], _NOKEY),
    ("list-of-dict", [{"source": "env", "provider": "default", "id": _DIFF_VAR_LONG}], _NOKEY),
    ("legacy-lit-3", _NOKEY, "abc"),
    ("legacy-lit-32", _NOKEY, "t" * 32),
    ("legacy-ref-long", _NOKEY, "${" + _DIFF_VAR_LONG + "}"),
    ("legacy-ref-short", _NOKEY, "${" + _DIFF_VAR_SHORT + "}"),
    ("legacy-int", _NOKEY, 12345),
    ("legacy-true", _NOKEY, True),
    ("legacy-list", _NOKEY, ["x"]),
    ("both-empty-and-legacy-literal", "", "abc"),
    ("both-reference-and-legacy-long", "${" + _DIFF_VAR_SHORT + "}", "t" * 32),
    ("both-literal-and-legacy-reference", "t" * 32, "${" + _DIFF_VAR_SHORT + "}"),
]


def _diff_config(auth_tok, legacy_tok, bind, mode, block) -> dict:
    gw: dict = {}
    if bind is not None:
        gw["bind"] = bind
    auth: dict = {}
    if mode is not None:
        auth["mode"] = mode
    if auth_tok is not _NOKEY:
        auth["token"] = auth_tok
    if auth:
        gw["auth"] = auth
    if legacy_tok is not _NOKEY:
        gw["token"] = legacy_tok
    cfg: dict = {"gateway": gw}
    if block is not None:
        cfg["env"] = {"vars": {_DIFF_VAR_LONG: block, _DIFF_VAR_SHORT: block}}
    return cfg


def _diff_context(cfg: dict, unit) -> Context:
    c = _ctx(cfg)
    if unit is not None:
        c.unit_env_found = True
        c.unit_env_values = {_DIFF_VAR_LONG: unit, _DIFF_VAR_SHORT: unit} if unit else {}
        c.unit_env_sources = {k: "gateway.service" for k in c.unit_env_values}
    return c


def _rle(letters: str) -> str:
    out, i = [], 0
    while i < len(letters):
        j = i
        while j < len(letters) and letters[j] == letters[i]:
            j += 1
        out.append(f"{letters[i]}{j - i}")
        i = j
    return "".join(out)


def _diff_cells(only: "str | None" = None, verbose: bool = False) -> dict:
    """label -> (B2 statuses RLE, B2 digest, B80 statuses RLE, B80 digest)."""
    out = {}
    for label, auth_tok, legacy_tok in _DIFF_VALUES:
        if only is not None and label != only:
            continue
        letters = {"B2": "", "B80": ""}
        digests = {"B2": hashlib.sha256(), "B80": hashlib.sha256()}
        for bind in _DIFF_BINDS:
            for mode in _DIFF_MODES:
                for unit_name, unit in _DIFF_UNIT:
                    for block_name, block in _DIFF_BLOCK:
                        cfg = _diff_config(auth_tok, legacy_tok, bind, mode, block)
                        found = {
                            "B2": check_gateway(_diff_context(cfg, unit)),
                            "B80": check_gateway_rate_limit(_diff_context(cfg, unit)),
                        }
                        for cid, f in found.items():
                            letters[cid] += f.status[0]
                            digests[cid].update(
                                "\x1f".join([f.status, f.detail, f.fix, "\x1e".join(f.evidence)])
                                .encode("utf-8")
                                + b"\x00"
                            )
                            if verbose:
                                print(cid, bind, mode, unit_name, block_name, f.status, f.detail)
        out[label] = (
            _rle(letters["B2"]),
            digests["B2"].hexdigest()[:16],
            _rle(letters["B80"]),
            digests["B80"].hexdigest()[:16],
        )
    return out


_DIFF_EXPECTED: dict = {
    'absent': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'null': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'empty': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'blank': ('F192', 'c3ee74b5ec44a438', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'lit-3': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'lit-11': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'lit-23': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'lit-24': ('P96W12P24F12W12P24F12', '27aa7dc74ac4278d', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'lit-24-padded': ('P96W12P24F12W12P24F12', '27aa7dc74ac4278d', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'lit-23-padded': ('P96F12P24F24P24F12', '539841c77b97d0e4', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'lit-32': ('P96W12P24F12W12P24F12', '27aa7dc74ac4278d', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'lit-bearer': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'lit-null-word': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'lit-none-word': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'ref-long-name': ('P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P25F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P24W1F1W2F1W2F1W2F1W1P1F1U1P1F1U1P1F1U1P1F1U1P12F12W1F1W2F1W2F1W2F1W1P1F1U1P1F1U1P1F1U1P1F1U1P12F12', '63e734bd24f5053f', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'ref-short-name': ('U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24', 'b814970b2a4c0baf', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'ref-shorthand-long': ('U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24', 'b814970b2a4c0baf', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'ref-shorthand-short': ('U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24', 'b814970b2a4c0baf', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'ref-fallback-empty-long': ('P96W12P24F12W12P24F12', '27aa7dc74ac4278d', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'ref-fallback-empty-short': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'ref-fallback-value': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'ref-padded': ('P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P25F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P24W1F1W2F1W2F1W2F1W1P1F1U1P1F1U1P1F1U1P1F1U1P12F12W1F1W2F1W2F1W2F1W1P1F1U1P1F1U1P1F1U1P1F1U1P12F12', '63e734bd24f5053f', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'ref-trailing-newline': ('U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24', 'b814970b2a4c0baf', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'ref-prefixed': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'ref-suffixed': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'ref-two': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'ref-lowercase-name': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'ref-bad-name': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'ref-unclosed': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'marker-secretref-long': ('W24P24W24P24W24P12F12W24P12F12', '7d7714c28547a26b', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'marker-secretref-short': ('F192', '31bc9ab2e920411b', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'marker-env-long': ('W24P24W24P24W24P12F12W24P12F12', '7d7714c28547a26b', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'marker-env-short': ('F192', '31bc9ab2e920411b', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'int-zero': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'int': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'float': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'true': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'false': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'list-empty': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'list-literal': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'list-reference': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'list-of-dict': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'legacy-lit-3': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'legacy-lit-32': ('P96W12P24F12W12P24F12', '27aa7dc74ac4278d', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'legacy-ref-long': ('P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P25F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P1F1U1P24W1F1W2F1W2F1W2F1W1P1F1U1P1F1U1P1F1U1P1F1U1P12F12W1F1W2F1W2F1W2F1W1P1F1U1P1F1U1P1F1U1P1F1U1P12F12', '63e734bd24f5053f', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'legacy-ref-short': ('U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24', 'b814970b2a4c0baf', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'legacy-int': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'legacy-true': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'legacy-list': ('P96F9W3P24F21W3P24F12', '4ba4b6a70fdde3cc', 'P96U3P6W27P12U3P6W27P12', '8d0777d28b540908'),
    'both-empty-and-legacy-literal': ('F192', '1fa80a8c9804507d', 'P108W24P24W24P12', '2dc6757070110c2c'),
    'both-reference-and-legacy-long': ('U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24U1F1U2F1U2F1U2F1U2F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24W1F1W2F1W2F1W2F1W1U1F1U2F1U2F1U2F1U1F24', 'b814970b2a4c0baf', 'P96W36P12W36P12', 'b25325a6e4d86091'),
    'both-literal-and-legacy-reference': ('P96W12P24F12W12P24F12', '27aa7dc74ac4278d', 'P96W36P12W36P12', 'b25325a6e4d86091'),
}


def test_the_differential_table_covers_enough_values():
    labels = [v[0] for v in _DIFF_VALUES]
    assert len(labels) == len(set(labels)) >= 40
    assert not any(isinstance(v[1], dict) or isinstance(v[2], dict) for v in _DIFF_VALUES)
    assert set(_DIFF_EXPECTED) == set(labels)


def test_a_token_that_is_not_an_object_reads_exactly_as_it_does_on_dev():
    """One test for the whole table (about 10,000 check runs, two seconds): a value whose cells
    moved is named in the message, and `--cells LABEL` on the dev checkout shows which cell."""
    moved = []
    for label, _, _ in _DIFF_VALUES:
        if _diff_cells(only=label)[label] != _DIFF_EXPECTED[label]:
            moved.append(label)
    assert not moved, (
        "B2/B80 changed for a token that is not a SecretRef object: " + ", ".join(moved)
        + " - compare with dev via `--cells LABEL`"
    )


if __name__ == "__main__":  # pragma: no cover - the generator, see the comment above
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "--cells":
        _diff_cells(only=sys.argv[2], verbose=True)
    else:
        print("_DIFF_EXPECTED = {")
        for _label, _row in _diff_cells().items():
            print(f"    {_label!r}: {_row!r},")
        print("}")


# --------------------------------------------------------------------------------------
# wiring: the real audit() path, from openclaw.json on disk
# --------------------------------------------------------------------------------------


def _audit(tmp_path, body: str):
    from clawseccheck import audit

    cfg = tmp_path / "openclaw.json"
    cfg.write_text(body, encoding="utf-8")
    cfg.chmod(0o600)
    _, findings, _ = audit(tmp_path, include_native=False)
    return {f.id: f for f in findings}


@pytest.mark.parametrize("source", ["env", "exec"])
def test_audit_object_token_from_disk_is_not_a_b2_fail(tmp_path, source):
    body = json.dumps({"gateway": {"bind": "lan", "auth": {"token": _OBJECTS[source]}}})
    by_id = _audit(tmp_path, body)
    assert by_id["B2"].status == WARN, by_id["B2"].detail
    assert by_id["B80"].status == WARN, by_id["B80"].detail


def test_audit_malformed_object_from_disk_keeps_the_fail(tmp_path):
    body = json.dumps(
        {"gateway": {"bind": "lan", "auth": {"token": {"source": "env", "provider": "default"}}}}
    )
    by_id = _audit(tmp_path, body)
    assert by_id["B2"].status == FAIL
    assert by_id["B80"].status == UNKNOWN


def test_audit_a_mode_none_supplied_by_an_include_is_still_a_fail(tmp_path):
    """The loader merges a confined ``$include`` before any check runs, so a mode that lives
    in a fragment is the mode in effect - an object token beside it must clear nothing."""
    (tmp_path / "auth-mode.json").write_text('{"mode": "none"}', encoding="utf-8")
    body = json.dumps(
        {
            "gateway": {
                "bind": "lan",
                "auth": {"$include": "./auth-mode.json", "token": _OBJECTS["env"]},
            }
        }
    )
    by_id = _audit(tmp_path, body)
    assert by_id["B2"].status == FAIL, by_id["B2"].detail
    assert "auth.mode=none" in by_id["B2"].detail


def test_audit_an_object_token_supplied_by_an_include_is_read_like_an_inline_one(tmp_path):
    (tmp_path / "auth-token.json").write_text(
        json.dumps({"token": _OBJECTS["env"]}), encoding="utf-8"
    )
    body = json.dumps(
        {"gateway": {"bind": "lan", "auth": {"$include": "./auth-token.json"}}}
    )
    by_id = _audit(tmp_path, body)
    assert by_id["B2"].status == WARN, by_id["B2"].detail
    assert by_id["B80"].status == WARN
