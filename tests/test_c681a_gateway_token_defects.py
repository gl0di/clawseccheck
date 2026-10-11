"""C-681 defects 1, 2, 5 and 6: four small gaps left by C-653 / C-667 / C-672.

1. A unit / dotenv value that is long but template- or marker-shaped (``${OTHER_LONG_NAME}``,
   ``secretref-env:...``) is no credential: the string reference already refuses it (C-672);
   the ``env`` SecretRef object and the fixed-name ``OPENCLAW_GATEWAY_TOKEN`` /
   ``OPENCLAW_GATEWAY_PASSWORD`` leg now refuse it too.
2. B1 judged a ``store`` SecretRef at ``gateway.auth.password`` by the config's env block. A
   store reference is resolved from OpenClaw's secret store, never from the environment.
3. ``${GW_BIND:- lan}`` carries whitespace in its default; the default is trimmed.
4. ``${ID:-fallback}`` at the gateway token: the visible value of ``ID`` when there is one
   (measured like any reference), else the default as a literal token - on a build that
   understands ``:-`` (2026.9.7+). Anywhere else the text stays the literal it always was.

Offline, read-only, stdlib only. Values are fillers, ids are variable NAMES.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import check_gateway, check_gateway_rate_limit, check_secrets
from clawseccheck.checks._shared import _effective_gateway_bind
from clawseccheck.collector import Context

_LONG = "w" * 40
_SHORT = "q7z"
_VAR = "OPENCLAW_GATEWAY_TOKEN"
_CAVEAT = "cannot be read from the config and were not evaluated"
_WEAK_SHAPED = {
    "template": "${SOME_OTHER_LONG_VARIABLE_NAME}",
    "marker-secretref": "secretref-env:SOME_LONG_VAR_NAME_X",
    "marker-env": "__env__:SOME_LONG_VAR_NAME_XYZ",
}


def _ctx(cfg: dict, unit=None, dotenv=None, build=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    if build is not None:
        c.installed_dist_version = build
    if unit is not None:
        c.unit_env_found = True
        c.unit_env_values = dict(unit)
        c.unit_env_sources = {k: "gateway.service" for k in unit}
    if dotenv is not None:
        c.dotenv_found = True
        c.dotenv_values = dict(dotenv)
        c.dotenv_sources = {k: "/nonexistent/.env" for k in dotenv}
    return c


def _cfg(token=None, bind="lan", mode=None, block=None) -> dict:
    gw: dict = {"bind": bind}
    auth: dict = {}
    if mode is not None:
        auth["mode"] = mode
    if token is not None:
        auth["token"] = token
    if auth:
        gw["auth"] = auth
    cfg: dict = {"gateway": gw}
    if block is not None:
        cfg["env"] = {"vars": block}
    return cfg


def _key(f) -> tuple:
    return (f.status, f.detail, f.fix, tuple(f.evidence))


# --------------------------------------------------------------------------------------
# defect 1a: the env-source OBJECT
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(_WEAK_SHAPED))
@pytest.mark.parametrize("mode", [None, "token"])
@pytest.mark.parametrize("where", ["unit", "dotenv"])
def test_object_a_long_template_or_marker_shaped_value_is_no_evidence_of_strength(
    shape, mode, where
):
    value = _WEAK_SHAPED[shape]
    assert len(value) >= 24
    obj = {"source": "env", "provider": "default", "id": _VAR}
    cfg = _cfg(obj, mode=mode)
    seen = _ctx(cfg, **{where: {_VAR: value}})
    assert _key(check_gateway(seen)) == _key(check_gateway(_ctx(cfg)))  # nothing found
    if mode is None:
        assert _CAVEAT in check_gateway(seen).detail  # said, not silently authenticated


def test_object_a_long_real_value_is_still_the_strength_evidence():
    obj = {"source": "env", "provider": "default", "id": _VAR}
    cfg = _cfg(obj)
    got = check_gateway(_ctx(cfg, unit={_VAR: _LONG}))
    assert _CAVEAT not in got.detail  # measured, so no "not evaluated" caveat
    assert _key(got) != _key(check_gateway(_ctx(cfg)))


def test_object_a_short_template_shaped_value_is_still_a_short_value():
    obj = {"source": "env", "provider": "default", "id": _VAR}
    got = check_gateway(_ctx(_cfg(obj), unit={_VAR: "${GW_T}"}))
    assert got.status == FAIL, got.detail


# --------------------------------------------------------------------------------------
# defect 1b: the fixed-name environment leg
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(_WEAK_SHAPED))
@pytest.mark.parametrize("var", ["OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_PASSWORD"])
def test_fixed_name_env_credential_that_is_template_or_marker_shaped_is_not_strong(shape, var):
    cfg = _cfg(bind="lan")
    got = check_gateway(_ctx(cfg, unit={var: _WEAK_SHAPED[shape]}))
    assert got.status == FAIL, got.detail
    assert "exposed" in got.detail
    assert "authenticated" not in got.detail
    assert _WEAK_SHAPED[shape] not in " ".join([got.detail, got.fix, *got.evidence])
    # the verdict it had with nothing found
    assert _key(got) == _key(check_gateway(_ctx(cfg)))


def test_fixed_name_env_credential_real_long_value_is_still_strong():
    got = check_gateway(_ctx(_cfg(bind="lan"), unit={_VAR: _LONG}))
    assert got.status == WARN
    assert "authenticated" in got.detail


def test_fixed_name_env_credential_skips_a_shaped_token_for_a_real_password():
    unit = {"OPENCLAW_GATEWAY_TOKEN": _WEAK_SHAPED["template"], "OPENCLAW_GATEWAY_PASSWORD": _LONG}
    got = check_gateway(_ctx(_cfg(bind="lan"), unit=unit))
    assert got.status == WARN
    assert "authenticated" in got.detail


def test_fixed_name_env_credential_short_shaped_value_keeps_the_short_verdict():
    got = check_gateway(_ctx(_cfg(bind="lan"), unit={_VAR: "${GW_T}"}))
    assert got.status == FAIL
    assert "shorter than 24 chars" in got.detail


# --------------------------------------------------------------------------------------
# defect 2: B1 and a store SecretRef
# --------------------------------------------------------------------------------------


def _ref(source: str, rid: str) -> dict:
    return {"source": source, "provider": "default", "id": rid}


def _b1(password, block=None):
    cfg: dict = {"gateway": {"auth": {"password": password}}}
    if block is not None:
        cfg["env"] = {"vars": block}
    ctx = _ctx(cfg)
    ctx.config_mode = 0o600
    return check_secrets(ctx)


def test_b1_a_store_reference_is_not_judged_by_an_unrelated_env_block_value():
    got = _b1(_ref("store", "GW_PW"), block={"GW_PW": "hunter-two-plain"})
    assert "gateway.auth.password set in config" not in got.evidence, got.detail
    assert got.status != FAIL, got.detail


def test_b1_an_env_reference_is_still_judged_by_the_env_block():
    got = _b1(_ref("env", "GW_PW"), block={"GW_PW": "hunter-two-plain"})
    assert got.status == FAIL
    assert "gateway.auth.password set in config" in got.evidence


@pytest.mark.parametrize("source,rid", [("file", "/gateway/pw"), ("exec", "gateway/pw")])
def test_b1_file_and_exec_references_ignore_the_env_block(source, rid):
    got = _b1(_ref(source, rid), block={"GW_PW": "hunter-two-plain", rid: "hunter-two-plain"})
    assert got.status != FAIL, got.detail


def test_b1_a_plaintext_password_still_fails():
    assert _b1("hunter-two-plain").status == FAIL


# --------------------------------------------------------------------------------------
# defect 5: whitespace in a bind default
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["${GW_BIND:- lan}", "${GW_BIND:-lan }", "${GW_BIND:-\t lan \t}"])
def test_bind_default_is_trimmed(raw):
    cfg = _cfg(bind=raw)
    value, note = _effective_gateway_bind(_ctx(cfg), cfg, raw)
    assert (value, note) == ("lan", None)


@pytest.mark.parametrize("raw", ["${GW_BIND:- loopback}", "${GW_BIND:- }", "${GW_BIND:-   }"])
def test_bind_default_that_trims_to_loopback_or_nothing_is_unresolved(raw):
    cfg = _cfg(bind=raw)
    value, note = _effective_gateway_bind(_ctx(cfg), cfg, raw)
    assert value is None and note


# --------------------------------------------------------------------------------------
# defect 6: ${ID:-fallback} at the gateway token
# --------------------------------------------------------------------------------------

_BUILD = "2026.9.9"
_FALLBACK = "changeme"  # eight characters: the TEXT of the template is 35


def _tpl(name: str, default: str) -> str:
    return "${" + name + ":-" + default + "}"


@pytest.mark.parametrize("bind", ["lan", "loopback"])
@pytest.mark.parametrize("mode", [None, "token"])
def test_default_template_with_a_short_default_and_nothing_visible_is_a_disclosed_warn(
    bind, mode
):
    """The default applies only while the gateway's own environment leaves the variable unset
    or empty, which the audit cannot read: a WARN that says so, never the short-literal FAIL
    and never a silent pass (base: a PASS under mode token, the 'authenticated' note otherwise
    on a lan bind)."""
    tpl = _tpl(_VAR, _FALLBACK)
    assert len(tpl) >= 24 and len(_FALLBACK) < 24
    got = check_gateway(_ctx(_cfg(tpl, bind=bind, mode=mode), build=_BUILD))
    assert got.status == WARN, got.detail
    blob = " ".join([got.detail, got.fix, *got.evidence])
    assert "shorter than 24 chars" not in blob
    assert f"short ({len(_FALLBACK)} chars) fallback" in got.detail
    assert f"whenever {_VAR} is unset or empty" in got.detail
    assert "cannot see the gateway's environment" in got.detail
    assert _VAR in got.fix and "24 characters" in got.fix
    assert _FALLBACK not in blob  # the default text itself is never echoed


def test_default_template_short_default_is_said_once_on_a_lan_bind_with_no_mode():
    got = check_gateway(_ctx(_cfg(_tpl(_VAR, _FALLBACK)), build=_BUILD))
    assert got.detail.count("fallback OpenClaw uses") == 1
    assert got.fix.count("Set " + _VAR) == 1


def test_default_template_with_a_visible_short_value_is_still_a_fail():
    got = check_gateway(_ctx(_cfg(_tpl(_VAR, _FALLBACK), mode="token"), unit={_VAR: _SHORT}, build=_BUILD))
    assert got.status == FAIL, got.detail


def test_default_template_with_a_visible_long_value_makes_the_default_irrelevant():
    cfg = _cfg(_tpl(_VAR, _FALLBACK), mode="token")
    got = check_gateway(_ctx(cfg, unit={_VAR: _LONG}, build=_BUILD))
    assert got.status == PASS, got.detail
    assert "fallback" not in got.detail


@pytest.mark.parametrize("mode", ["password", "none", "trusted-proxy"])
def test_default_template_is_unchanged_under_a_mode_where_the_token_is_not_in_effect(mode):
    cfg = _cfg(_tpl(_VAR, _FALLBACK), mode=mode)
    assert _key(check_gateway(_ctx(cfg, build=_BUILD))) == _key(
        check_gateway(_ctx(cfg, build=None))
    )


def test_default_template_with_a_long_default_and_nothing_visible_is_a_long_literal():
    default = "d" * 30
    cfg = _cfg(_tpl("GW_T", default))
    got = check_gateway(_ctx(cfg, build=_BUILD))
    assert _key(got) == _key(check_gateway(_ctx(_cfg(default), build=_BUILD)))


@pytest.mark.parametrize("mode", [None, "token"])
@pytest.mark.parametrize("name", [_VAR, "GW_T"])
@pytest.mark.parametrize("visible", [_SHORT, _LONG, "x" * 23, "x" * 24])
@pytest.mark.parametrize("where", ["unit", "dotenv"])
def test_default_template_with_a_visible_value_is_measured_like_the_plain_reference(
    mode, name, visible, where
):
    plain = _cfg("${" + name + "}", mode=mode)
    withdef = _cfg(_tpl(name, _FALLBACK), mode=mode)
    seen = {name: visible}
    a = check_gateway(_ctx(withdef, build=_BUILD, **{where: seen}))
    b = check_gateway(_ctx(plain, build=_BUILD, **{where: seen}))
    assert _key(a) == _key(b)


@pytest.mark.parametrize("value", [_SHORT, _LONG])
def test_default_template_with_a_value_in_the_env_block_is_measured_like_the_plain_reference(
    value,
):
    block = {"GW_T": value}
    a = check_gateway(_ctx(_cfg(_tpl("GW_T", _FALLBACK), mode="token", block=block), build=_BUILD))
    b = check_gateway(_ctx(_cfg("${GW_T}", mode="token", block=block), build=_BUILD))
    assert _key(a) == _key(b)


@pytest.mark.parametrize("build", [None, "2026.9.6", "0.0.0"])
def test_default_template_keeps_the_literal_reading_on_a_build_that_is_not_known_to_have_it(
    build,
):
    tpl = _tpl(_VAR, _FALLBACK)
    cfg = _cfg(tpl)
    got = check_gateway(_ctx(cfg, unit={_VAR: _SHORT}, build=build))
    # the text itself (35 characters) is the token there: no lookup, no short-default FAIL
    assert "shorter than 24 chars" not in got.detail
    assert _key(got) == _key(check_gateway(_ctx(cfg, build=build)))


def test_default_template_with_a_blank_default_is_unchanged():
    """``${ID:- }`` is not a default template: the text keeps its dev reading on every build."""
    cfg = _cfg("${GW_TOKEN_VARIABLE_NAME:- }")
    assert _key(check_gateway(_ctx(cfg, build=_BUILD))) == _key(
        check_gateway(_ctx(cfg, build="2026.9.6"))
    )


def test_b80_reads_an_unseen_short_default_as_a_credential_of_unknown_strength():
    """B80 is never made cleaner: the unseen variable may hold a strong secret, so the
    reading is the one the plain reference gets - the same output as before this change."""
    cfg = _cfg(_tpl(_VAR, _FALLBACK))
    got = check_gateway_rate_limit(_ctx(cfg, build=_BUILD))
    assert got.status == WARN, got.detail
    assert _key(got) == _key(check_gateway_rate_limit(_ctx(cfg, build=None)))
