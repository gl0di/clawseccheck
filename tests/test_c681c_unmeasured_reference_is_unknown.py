"""C-681 (owner question): ONE answer for a gateway token that is a reference nothing visible
resolves.

Owner ruling (Dave, 2026-10-11): a ``gateway.auth.token`` that is a reference - the string
``${VAR}`` / ``$VAR`` (long or short variable name), a SecretRef object of any source, the
``${VAR:-}`` empty fallback on a build that understands ``:-`` - and for which the audit can
see NO evidence of the secret behind it (no config env-block value, no systemd / dotenv
value) is UNKNOWN with the existing "not evaluated" caveat, never PASS. Before this, the
common ``"${OPENCLAW_GATEWAY_TOKEN}"`` (25 characters, so it passed by TEXT length) and the
object forms PASSed under mode "token" while ``"${GW_TOKEN}"`` was already UNKNOWN.

Where evidence IS visible and usable nothing moves: a visible short value is a FAIL, a visible
long one passes as before, an env-block value is an UNKNOWN as before (a visible empty or
template-shaped value is UNKNOWN too, and one test pins it). Where the token is not the
credential in effect (any mode but "token" / no mode) nothing moves either. The `detail` of
every finding that existed before is byte-identical (a fingerprint hashes it): the new
wording rides in `fix` there.

Offline, read-only, stdlib only. Secret-shaped values are assembled at runtime.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_gateway, check_gateway_rate_limit
from clawseccheck.collector import Context

_LONG = "v" * 40
_LONG_REF = "${OPENCLAW_GATEWAY_TOKEN}"
_STR_NOTE = (
    "gateway.auth.token is an environment reference, so its length and strength cannot be "
    "read from the config and were not evaluated"
)
_STR_FIX = (
    "Check in the gateway's environment that the variable gateway.auth.token points at "
    "holds a secret of at least 24 characters"
)
_OBJ_NOTE = (
    "gateway.auth.token is a secret reference, so the length and strength of the secret "
    "behind it cannot be read from the config and were not evaluated"
)
_OBJ_FIX = (
    "Check, where the reference is resolved (the gateway's environment, the secret store, "
    "a file or a command), that the secret gateway.auth.token points at holds at least 24 "
    "characters"
)
_UNKNOWN_PREFIX = "Cannot assess the gateway: "

_OBJECTS = {
    "env": {"source": "env", "provider": "default", "id": "OPENCLAW_GATEWAY_TOKEN"},
    "env-short-id": {"source": "env", "provider": "default", "id": "GW_TOKEN"},
    "env-legacy-two-key": {"source": "env", "id": "OPENCLAW_GATEWAY_TOKEN"},
    "file": {"source": "file", "provider": "default", "id": "/gateway/token"},
    "store": {
        "source": "store",
        "provider": "default",
        "id": "OPENCLAW_GATEWAY_TOKEN_0123456789ABCDEF",
    },
    "exec": {"source": "exec", "provider": "vault", "id": "gateway/token"},
}
# string references, all with nothing visible behind them
_STRINGS = {
    "long-name": "${OPENCLAW_GATEWAY_TOKEN}",
    "long-name-dollar": "$OPENCLAW_GATEWAY_AUTH_TOKEN",
    "short-name": "${GW_TOKEN}",
    "short-name-dollar": "$GW_TOKEN",
    "long-name-padded": "  ${OPENCLAW_GATEWAY_TOKEN}\n",
}


def _ctx(cfg: dict, build=None, unit=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    c.installed_dist_version = build
    if unit is not None:
        c.unit_env_values = dict(unit)
        c.unit_env_sources = {k: "gateway.service" for k in unit}
        c.unit_env_found = True
    return c


def _gw(bind="lan", mode=None, token=None, **extra) -> dict:
    gw: dict = {"bind": bind}
    auth: dict = {}
    if mode is not None:
        auth["mode"] = mode
    if token is not None:
        auth["token"] = token
    if auth:
        gw["auth"] = auth
    gw.update(extra)
    return {"gateway": gw}


_NOTHING_VISIBLE_CELLS = [("lan", "token"), ("loopback", "token"), ("loopback", None)]


# --------------------------------------------------------------------------------------
# the ruling: nothing visible -> UNKNOWN with the caveat, in every cell that was a PASS
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("bind,mode", _NOTHING_VISIBLE_CELLS)
@pytest.mark.parametrize("name", sorted(_STRINGS))
def test_a_string_reference_with_nothing_visible_is_unknown_with_the_caveat(name, bind, mode):
    f = check_gateway(_ctx(_gw(bind, mode, _STRINGS[name])))
    assert f.status == UNKNOWN, (name, bind, mode, f.detail)
    assert f.detail == _UNKNOWN_PREFIX + _STR_NOTE
    assert f.fix == _STR_FIX
    assert "shorter than 24" not in f.detail
    assert _STRINGS[name].strip() not in f.detail and _STRINGS[name].strip() not in f.fix


@pytest.mark.parametrize("bind,mode", _NOTHING_VISIBLE_CELLS)
@pytest.mark.parametrize("source", sorted(_OBJECTS))
def test_an_object_reference_with_nothing_visible_is_unknown_with_the_caveat(source, bind, mode):
    f = check_gateway(_ctx(_gw(bind, mode, _OBJECTS[source])))
    assert f.status == UNKNOWN, (source, bind, mode, f.detail)
    assert f.detail == _UNKNOWN_PREFIX + _OBJ_NOTE
    assert f.fix == _OBJ_FIX
    # nothing of the object (id, provider, source) rides along
    for needle in ("OPENCLAW_GATEWAY_TOKEN", "default", "vault", "/gateway/token"):
        assert needle not in f.detail and needle not in f.fix, needle


@pytest.mark.parametrize("bind,mode", _NOTHING_VISIBLE_CELLS)
def test_the_long_and_the_short_named_string_reference_get_one_identical_answer(bind, mode):
    """The point of the ruling: the length of the variable NAME no longer decides."""
    a = check_gateway(_ctx(_gw(bind, mode, "${OPENCLAW_GATEWAY_TOKEN}")))
    b = check_gateway(_ctx(_gw(bind, mode, "${GW_TOKEN}")))
    c = check_gateway(_ctx(_gw(bind, mode, "$GW_TOKEN")))
    assert (a.status, a.detail, a.fix) == (b.status, b.detail, b.fix) == (c.status, c.detail, c.fix)
    assert a.status == UNKNOWN


@pytest.mark.parametrize("build", ["2026.9.7", "2026.9.8", "2026.10.1"])
@pytest.mark.parametrize("bind,mode", _NOTHING_VISIBLE_CELLS)
def test_the_long_named_empty_fallback_is_a_reference_where_the_build_knows_the_operator(
    build, bind, mode
):
    f = check_gateway(_ctx(_gw(bind, mode, "${OPENCLAW_GATEWAY_TOKEN:-}"), build=build))
    assert f.status == UNKNOWN, f.detail
    assert f.detail == _UNKNOWN_PREFIX + _STR_NOTE


@pytest.mark.parametrize("build", [None, "2026.9.6", "unknown-build"])
def test_the_long_named_empty_fallback_stays_a_literal_where_the_operator_is_not_known(build):
    """Not a reference there (the text is the token), so this change does not touch it - the
    known C-653 (d) gap, left exactly as it was."""
    f = check_gateway(_ctx(_gw("lan", "token", "${OPENCLAW_GATEWAY_TOKEN:-}"), build=build))
    assert f.status == PASS, f.detail


@pytest.mark.parametrize("name", sorted(_STRINGS))
def test_no_mode_on_a_lan_bind_stays_the_warn_it_was_with_its_detail_unchanged(name):
    """Already not a PASS: the "authenticated" disclosure. The detail of this existing finding
    must not change; a long-named reference gains the caveat in `fix` only."""
    f = check_gateway(_ctx(_gw("lan", None, _STRINGS[name])))
    assert f.status == WARN
    assert f.detail.startswith(
        "gateway.bind=lan is non-loopback and the config sets no gateway.auth.mode, but "
        "gateway.auth.token is set \u2014 OpenClaw derives auth.mode from it, so the gateway "
        "is authenticated. Reported as disclosure, not exposure"
    )
    assert _STR_FIX in f.fix
    if name.startswith("long"):
        assert f.detail == (
            "gateway.bind=lan is non-loopback and the config sets no gateway.auth.mode, but "
            "gateway.auth.token is set \u2014 OpenClaw derives auth.mode from it, so the "
            "gateway is authenticated. Reported as disclosure, not exposure"
        )
        assert f.evidence == [f.detail]


@pytest.mark.parametrize("source", sorted(_OBJECTS))
def test_an_object_with_no_mode_on_a_lan_bind_keeps_its_warn_detail_and_fix(source):
    """The object already carried the caveat in both fields here; it is not said twice."""
    f = check_gateway(_ctx(_gw("lan", None, _OBJECTS[source])))
    assert f.status == WARN
    assert f.detail.count(_OBJ_NOTE) == 1
    assert f.fix.count(_OBJ_FIX) == 1
    assert len(f.evidence) == 2


# --------------------------------------------------------------------------------------
# visible evidence: behaviour unchanged
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("bind,mode", _NOTHING_VISIBLE_CELLS)
def test_a_visible_long_environment_value_still_passes(bind, mode):
    for token in (_LONG_REF, "${GW_TOKEN}", _OBJECTS["env"], _OBJECTS["env-short-id"]):
        name = token["id"] if isinstance(token, dict) else token.strip("${}")
        f = check_gateway(_ctx(_gw(bind, mode, token), unit={name: _LONG}))
        assert f.status == PASS, (token, bind, mode, f.detail)


@pytest.mark.parametrize("bind,mode", _NOTHING_VISIBLE_CELLS)
def test_a_visible_short_environment_value_is_still_a_fail(bind, mode):
    for token in (_LONG_REF, "${GW_TOKEN}", _OBJECTS["env"], _OBJECTS["env-short-id"]):
        name = token["id"] if isinstance(token, dict) else token.strip("${}")
        f = check_gateway(_ctx(_gw(bind, mode, token), unit={name: "abc"}))
        assert f.status == FAIL, (token, bind, mode, f.detail)
        assert f.detail.startswith("gateway auth token shorter than 24 chars") or (
            "shorter than 24" in f.detail
        )
        assert "abc" not in f.detail and "abc" not in f.fix


def test_a_visible_env_block_value_keeps_its_verdicts():
    short = _gw("lan", "token", _LONG_REF)
    short["env"] = {"vars": {"OPENCLAW_GATEWAY_TOKEN": "abc"}}
    assert check_gateway(_ctx(short)).status == FAIL
    long_ = _gw("lan", "token", _LONG_REF)
    long_["env"] = {"vars": {"OPENCLAW_GATEWAY_TOKEN": _LONG}}
    f = check_gateway(_ctx(long_))
    assert f.status == UNKNOWN and "process environment" in f.detail  # as before, never PASS


@pytest.mark.parametrize("value", ["${OTHER_LONG_NAME_FOR_A_TOKEN}", "secretref-env:SOME_LONG_TOKEN_NAME"])
def test_a_template_or_marker_shaped_environment_value_is_no_evidence(value):
    """A long value that is itself a pointer's text is not a credential: the cell keeps the
    verdict it has with nothing found - now UNKNOWN, no longer PASS (string and object)."""
    assert len(value) >= 24
    for token in (_LONG_REF, _OBJECTS["env"]):
        f = check_gateway(_ctx(_gw("lan", "token", token), unit={"OPENCLAW_GATEWAY_TOKEN": value}))
        assert f.status == UNKNOWN, (token, f.detail)


@pytest.mark.parametrize("source", ["file", "store", "exec"])
def test_a_non_env_object_is_never_judged_by_an_environment_value_of_the_same_name(source):
    obj = _OBJECTS[source]
    f = check_gateway(
        _ctx(_gw("lan", "token", obj), unit={"OPENCLAW_GATEWAY_TOKEN": _LONG, "gateway/token": _LONG})
    )
    assert f.status == UNKNOWN, f.detail


# --------------------------------------------------------------------------------------
# scope: only where the token is the credential in effect
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["password", "none", "trusted-proxy", "TOKEN", "${M}"])
@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_a_reference_token_outside_the_modes_where_it_is_in_effect_is_untouched(mode, bind):
    """The verdict equals the one a 32-character literal token gets in the same cell: the
    reference reading is for the credential in effect only."""
    for token in (_LONG_REF, _OBJECTS["env"], _OBJECTS["store"]):
        ref_cfg = _gw(bind, mode, token)
        lit_cfg = _gw(bind, mode, "t" * 32)
        for cfg in (ref_cfg, lit_cfg):
            if mode == "password":
                cfg["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
        a, b = check_gateway(_ctx(ref_cfg)), check_gateway(_ctx(lit_cfg))
        assert (a.status, a.detail) == (b.status, b.detail), (mode, bind, token)


def test_no_token_and_a_literal_token_are_unchanged():
    assert check_gateway(_ctx(_gw("lan", "token", "t" * 32))).status == PASS
    assert check_gateway(_ctx(_gw("loopback", "token", "t" * 32))).status == PASS
    assert check_gateway(_ctx(_gw("loopback"))).status == PASS
    assert check_gateway(_ctx(_gw("lan", "none"))).status == FAIL


def test_a_malformed_object_is_still_no_token_not_a_reference():
    bad = {"source": "env", "provider": "default", "id": "lower case id"}
    assert check_gateway(_ctx(_gw("loopback", "token", bad))).status == PASS
    assert check_gateway(_ctx(_gw("lan", None, bad))).status == FAIL


# --------------------------------------------------------------------------------------
# existing findings keep their `detail` (fingerprint); the caveat rides in `fix`
# --------------------------------------------------------------------------------------


def test_an_independent_fail_keeps_its_detail_and_gains_the_caveat_in_fix():
    cfg = _gw("lan", "token", _LONG_REF)
    cfg["channels"] = {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    assert f.detail == "channel 'telegram' has an open dm/group policy (anyone can command it)"
    assert f.evidence == [f.detail]
    assert f.fix == "Set every open channel's dmPolicy/groupPolicy to 'allowlist'; " + _STR_FIX
    # the object form: same
    cfg["gateway"]["auth"]["token"] = _OBJECTS["env"]
    g = check_gateway(_ctx(cfg))
    assert g.status == FAIL and g.detail == f.detail
    assert g.fix == "Set every open channel's dmPolicy/groupPolicy to 'allowlist'; " + _OBJ_FIX


def test_the_already_unknown_template_finding_keeps_its_detail_and_gains_the_caveat_in_fix():
    cfg = _gw("loopback", "token", _LONG_REF, tailscale={"mode": "${TS:-off}"})
    base = _gw("loopback", "token", "t" * 32, tailscale={"mode": "${TS:-off}"})
    f, b = check_gateway(_ctx(cfg)), check_gateway(_ctx(base))
    assert f.status == b.status == UNKNOWN
    assert f.detail == b.detail and "gateway.tailscale.mode" in f.detail
    assert _STR_NOTE not in f.detail
    assert f.fix == b.fix + "; " + _STR_FIX


def test_the_short_named_reference_findings_are_byte_identical_to_before():
    """These existed before and carry the caveat in `detail` already: not said twice."""
    cfg = _gw("lan", "token", "${GW_TOKEN}")
    cfg["channels"] = {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}
    f = check_gateway(_ctx(cfg))
    assert f.detail == (
        "channel 'telegram' has an open dm/group policy (anyone can command it); " + _STR_NOTE
    )
    assert f.fix == "Set every open channel's dmPolicy/groupPolicy to 'allowlist'; " + _STR_FIX


# --------------------------------------------------------------------------------------
# B80 is a different question and does not move; the audit path; the score
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("token", [_LONG_REF, "${GW_TOKEN}", _OBJECTS["env"], _OBJECTS["store"]])
def test_b80_is_unchanged(token):
    assert check_gateway_rate_limit(_ctx(_gw("lan", "token", token))).status == WARN
    assert check_gateway_rate_limit(_ctx(_gw("loopback", "token", token))).status == PASS


def _audit_b2(tmp_path, auth_json: str, bind: str = "loopback"):
    from clawseccheck import audit

    cfg = tmp_path / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "%s", "auth": %s}}' % (bind, auth_json), encoding="utf-8")
    cfg.chmod(0o600)
    _, findings, _ = audit(tmp_path, include_native=False)
    return {f.id: f for f in findings}["B2"]


def test_audit_from_disk_the_common_config_is_unknown_not_pass(tmp_path):
    f = _audit_b2(tmp_path, '{"mode": "token", "token": "${OPENCLAW_GATEWAY_TOKEN}"}')
    assert f.status == UNKNOWN, f.detail
    assert _STR_NOTE in f.detail
    # a plain UNKNOWN: not an engine-side degradation, so no grade cap rides on it
    assert not getattr(f, "engine_degraded", False)
    assert not getattr(f, "not_applicable", False)


def test_audit_from_disk_the_object_form_is_unknown_not_pass(tmp_path):
    obj = '{"source": "env", "provider": "default", "id": "OPENCLAW_GATEWAY_TOKEN"}'
    f = _audit_b2(tmp_path, '{"mode": "token", "token": %s}' % obj, bind="lan")
    assert f.status == UNKNOWN, f.detail
    assert _OBJ_NOTE in f.detail
