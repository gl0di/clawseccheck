"""C-667: a SecretRef OBJECT at ``gateway.auth.token`` is a token set by reference.

OpenClaw types ``gateway.auth.token`` as ``SecretInput = string | SecretRef{source, provider,
id}``. Its resolver gives an unset ``gateway.auth.mode`` the value ``"token"`` whenever any
token is configured, and it recognises the reference in either spelling. B2 (`check_gateway`)
and B80 (`check_gateway_rate_limit`) already understood the string spelling (``"${ID}"``, C-653)
but read the object as "no token", so a non-loopback bind with no ``auth.mode`` was a false
FAIL (B2) / UNKNOWN (B80).

What this file pins, all through the one pair of helpers (`_gateway_token_form`,
`_gateway_config_token`) that B2 and B80 share:

* a WELL-FORMED object (`_is_secret_ref_object`, no second parser) is read exactly like a
  whole-value ``${ID}`` string reference - the same disclosure in B2, the same WARN in B80,
  no length verdict, and nothing of the object (id, provider) echoed anywhere;
* ``source: "exec"`` is read like env / file / store: OpenClaw 2026.9.8 resolves an exec
  reference for this key at gateway start through the same path, with no carve-out;
* an unresolvable reference makes the gateway REFUSE to start (the key is registered
  fail-closed), it never starts unauthenticated - which is why softening the FAIL for a
  reference is sound at all;
* everything else keeps today's verdict: an absent token, a literal, a retired marker, every
  malformed object, an explicit ``mode: none``, and an object at the legacy ``gateway.token``
  key (not in the OpenClaw schema, so it must never clear a "no auth" finding).

Offline, read-only, stdlib only. Nothing here is a secret; ids are variable NAMES.
"""
from __future__ import annotations

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
def test_object_token_reads_byte_for_byte_like_the_string_reference(source):
    """The object and the ``${ID}`` string are the same configuration to OpenClaw, so the
    two checks answer them identically - status, detail, fix and evidence."""
    obj_b2, obj_b80 = _both(_gw(bind="lan", token=_OBJECTS[source]))
    str_b2, str_b80 = _both(_gw(bind="lan", token=_STRING_REF))
    assert _same(obj_b2, str_b2)
    assert obj_b2.evidence == str_b2.evidence
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


def test_under_mode_token_the_object_gets_the_same_verdict_as_any_other_token_form():
    """No extra note, no UNKNOWN: with an explicit mode nothing about the token form is
    consulted for the object, exactly as for the long-named string reference."""
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
# (the secret sits in the file); the object form points at the same variable and reads the same.


def _with_env_block(cfg: dict, name: str, value) -> dict:
    cfg["env"] = {"vars": {name: value}}
    return cfg


@pytest.mark.parametrize("source", ["env", "store"])
def test_object_whose_variable_the_env_block_defines_short_keeps_the_fail(source):
    obj = _OBJECTS[source]
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


@pytest.mark.parametrize("source", ["env", "store"])
def test_object_whose_variable_the_env_block_defines_long_is_never_a_pass(source):
    obj = _OBJECTS[source]
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


@pytest.mark.parametrize("source", ["file", "exec"])
def test_file_and_exec_objects_do_not_read_the_env_block(source):
    """A file or exec reference resolves outside the environment, so an env block entry
    cannot be its value; the verdict is the plain by-reference one."""
    obj = _OBJECTS[source]
    plain = check_gateway(_ctx(_gw(bind="lan", token=obj)))
    cfg = _with_env_block(_gw(bind="lan", token=obj), "GW_TOKEN", "abc")
    assert _same(check_gateway(_ctx(cfg)), plain)
    assert plain.status == WARN


# --------------------------------------------------------------------------------------
# parity with the string reference where neither looks at the gateway's own environment
# --------------------------------------------------------------------------------------


def _with_unit_env(cfg: dict, unit_env: dict) -> Context:
    c = _ctx(cfg)
    c.unit_env_values = dict(unit_env)
    c.unit_env_sources = {k: "gateway.service" for k in unit_env}
    c.unit_env_found = True
    return c


@pytest.mark.parametrize("value", ["abc", "v" * 40])
def test_object_and_string_reference_agree_when_a_unit_supplies_the_variable_they_name(value):
    """Pins PARITY, not a correct verdict. A reference's target is read from the gateway's
    own environment, which this audit sees only through persistent artifacts (a systemd
    unit, a dotenv file), and a config-supplied token is read config-FIRST (B-312) - so
    neither spelling consults the unit's value, short or long. That is a limit the string
    reference already had (C-653); the object joins it rather than getting a reading of its
    own. If a later change makes the unit's value count, it must move both spellings."""
    unit = {"OPENCLAW_GATEWAY_TOKEN": value}
    obj_cfg = _gw(bind="lan", token=_OBJECTS["env"])
    str_cfg = _gw(bind="lan", token=_STRING_REF)
    assert _same(
        check_gateway(_with_unit_env(obj_cfg, unit)), check_gateway(_with_unit_env(str_cfg, unit))
    )
    assert _same(
        check_gateway_rate_limit(_with_unit_env(obj_cfg, unit)),
        check_gateway_rate_limit(_with_unit_env(str_cfg, unit)),
    )


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
