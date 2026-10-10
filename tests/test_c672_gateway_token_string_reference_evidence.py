"""C-672: a whole-value ``"${ID}"`` / ``"$ID"`` STRING at ``gateway.auth.token`` is measured
against the environment the audit can see, as the ``env`` SecretRef object has been since C-667.

On dev, ``{"gateway": {"bind": "lan", "auth": {"token": "${OPENCLAW_GATEWAY_TOKEN}"}}}`` with a
systemd unit that sets that variable to three characters was a WARN ("gateway.auth.token is
set"), while the same reference written as ``{"source": "env", "id": ...}`` and a literal
three-character token were both a FAIL. What this file pins:

* the variable a string reference names is looked up the way the env object's is: the config's
  own env block first (never a PASS), then the gateway's persistent environment (a systemd
  unit, then the global dotenv files); a visible value under 24 characters is the FAIL the
  object gets, a visible long one is the verdict the object gets, and B2 says the same about
  the string as about the object in every cell where the token is the credential in effect
  (mode absent or "token") and a value is visible (asserted by running both). With nothing
  visible, or under another mode, the two spellings differ and this file does not say they
  agree;
* B80 is unchanged: it measures nothing about a reference, the object's behaviour today;
* a long persistent value that is itself a ``${NAME}`` template or a retired marker is no
  evidence of strength (the env-block leg's own weak-shape rule): the cell keeps its verdict
  from before the lookup. The object form does not make this test;
* nothing visible leaves the string form exactly as it was (the long-named / short-named
  verdicts and caveats are pinned by ``tests/test_c653_gateway_token_reference.py``);
* the value, the unit path and the auditing shell's own environment never reach a message.

Offline, read-only, stdlib only. Values are three-character and forty-character fillers.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_gateway, check_gateway_rate_limit
from clawseccheck.collector import Context

_LONG_NAME = "OPENCLAW_GATEWAY_TOKEN"
_SHORT_NAME = "GW_TOKEN"
_SHORT = "q7z"  # three characters
_LONG = "w" * 40
_CAVEAT = "cannot be read from the config and were not evaluated"
_SHORT_CLAUSE = "gateway auth token shorter than 24 chars"

# (label, string spelling, the object spelling of the same reference)
_REFS = [
    ("braces-long-name", "${" + _LONG_NAME + "}", _LONG_NAME),
    ("shorthand-long-name", "$" + _LONG_NAME, _LONG_NAME),
    ("braces-short-name", "${" + _SHORT_NAME + "}", _SHORT_NAME),
    ("shorthand-short-name", "$" + _SHORT_NAME, _SHORT_NAME),
]
_REF_IDS = [r[0] for r in _REFS]


def _obj(name: str) -> dict:
    return {"source": "env", "provider": "default", "id": name}


def _cfg(token, bind="lan", mode=None, legacy=None, block=None) -> dict:
    gw: dict = {"bind": bind}
    auth: dict = {}
    if mode is not None:
        auth["mode"] = mode
    if token is not None:
        auth["token"] = token
    if auth:
        gw["auth"] = auth
    if legacy is not None:
        gw["token"] = legacy
    cfg: dict = {"gateway": gw}
    if block is not None:
        cfg["env"] = {"vars": block}
    return cfg


def _ctx(cfg: dict, unit=None, dotenv=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    if unit is not None:
        c.unit_env_found = True
        c.unit_env_values = dict(unit)
        c.unit_env_sources = {k: "gateway.service" for k in unit}
    if dotenv is not None:
        c.dotenv_found = True
        c.dotenv_values = dict(dotenv)
        c.dotenv_sources = {k: "/nonexistent/.env" for k in dotenv}
    return c


def _both(cfg: dict, unit=None, dotenv=None):
    return (
        check_gateway(_ctx(cfg, unit, dotenv)),
        check_gateway_rate_limit(_ctx(cfg, unit, dotenv)),
    )


def _key(f) -> tuple:
    return (f.status, f.detail, f.fix, tuple(f.evidence))


def _blob(f) -> str:
    return " ".join([f.detail, f.fix, *f.evidence])


# --------------------------------------------------------------------------------------
# the false negative, and its neighbours
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_the_issue_repro_a_short_unit_value_behind_a_string_reference_is_a_fail(label, ref, name):
    f = check_gateway(_ctx(_cfg(ref), unit={name: _SHORT}))
    assert f.status == FAIL, f.detail
    assert _SHORT_CLAUSE in f.detail
    assert "environment-supplied secret shorter than 24 chars (gateway.service)" in f.detail
    assert name in f.detail  # the variable NAME may be said; the value never is
    assert "gateway.auth.token is set" not in f.detail
    assert _SHORT not in _blob(f)


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_a_short_value_in_a_dotenv_file_is_found_too(label, ref, name):
    f = check_gateway(_ctx(_cfg(ref), dotenv={name: _SHORT}))
    assert f.status == FAIL, f.detail
    assert _SHORT not in _blob(f)


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_under_mode_token_a_short_value_is_the_token_length_clause(label, ref, name, bind):
    f = check_gateway(_ctx(_cfg(ref, bind=bind, mode="token"), unit={name: _SHORT}))
    assert f.status == FAIL
    assert f.detail == _SHORT_CLAUSE
    assert name in f.fix and _SHORT not in _blob(f)


def test_a_loopback_bind_with_no_mode_gets_the_clause_a_short_literal_gets():
    lit = check_gateway(_ctx(_cfg("short-token", bind="loopback")))
    ref = check_gateway(_ctx(_cfg("${" + _LONG_NAME + "}", bind="loopback"), unit={_LONG_NAME: _SHORT}))
    assert lit.status == ref.status == FAIL
    assert ref.detail == lit.detail == _SHORT_CLAUSE


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_only_the_variable_the_reference_names_is_looked_up(label, ref, name):
    other = "SOME_OTHER_VAR"
    f = check_gateway(_ctx(_cfg(ref), unit={other: _SHORT}))
    assert f.status == WARN and _SHORT_CLAUSE not in f.detail


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_a_value_is_measured_after_strip(label, ref, name):
    short = check_gateway(_ctx(_cfg(ref), unit={name: "  " + "x" * 23 + "  "}))
    long_ = check_gateway(_ctx(_cfg(ref), unit={name: "  " + "x" * 24 + "  "}))
    assert short.status == FAIL and long_.status == WARN


# --------------------------------------------------------------------------------------
# the string reads exactly as the env object, wherever the audit can see the variable
# --------------------------------------------------------------------------------------

_BINDS = ["lan", "loopback"]
_MODES = [None, "token", "password", "none"]
# The modes under which gateway.auth.token is the credential in effect. Under any other mode
# the key is a leftover and the string is judged by the length of its own TEXT, as on dev,
# where an object has none - so the two spellings are compared only here.
_IN_EFFECT = [None, "token"]
_BLOCKS = [None, "short", "long"]
_UNITS = ["short", "long"]
_BLOCK_VALUE = {"short": "abc", "long": "v" * 40}


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
@pytest.mark.parametrize("bind", _BINDS)
@pytest.mark.parametrize("mode", _IN_EFFECT)
@pytest.mark.parametrize("block", _BLOCKS)
@pytest.mark.parametrize("unit", _UNITS)
def test_string_and_object_give_one_result_when_the_unit_supplies_a_value(
    label, ref, name, bind, mode, block, unit
):
    value = _SHORT if unit == "short" else _LONG
    env_block = None if block is None else {name: _BLOCK_VALUE[block]}
    s_b2, s_b80 = _both(_cfg(ref, bind, mode, block=env_block), unit={name: value})
    o_b2, o_b80 = _both(_cfg(_obj(name), bind, mode, block=env_block), unit={name: value})
    assert _key(s_b2) == _key(o_b2), (s_b2.detail, o_b2.detail)
    assert _key(s_b80) == _key(o_b80)
    assert value not in _blob(s_b2)


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
@pytest.mark.parametrize("bind", _BINDS)
@pytest.mark.parametrize("mode", _IN_EFFECT)
@pytest.mark.parametrize("block", ["short", "long"])
def test_string_and_object_give_one_result_when_only_the_env_block_supplies_a_value(
    label, ref, name, bind, mode, block
):
    env_block = {name: _BLOCK_VALUE[block]}
    s_b2, s_b80 = _both(_cfg(ref, bind, mode, block=env_block))
    o_b2, o_b80 = _both(_cfg(_obj(name), bind, mode, block=env_block))
    assert _key(s_b2) == _key(o_b2)
    assert _key(s_b80) == _key(o_b80)


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
@pytest.mark.parametrize("bind", _BINDS)
@pytest.mark.parametrize("mode", ["password", "none"])
def test_where_the_token_is_not_in_effect_the_evidence_changes_nothing(
    label, ref, name, bind, mode
):
    cfg = _cfg(ref, bind, mode)
    plain = check_gateway(_ctx(cfg))
    assert _key(check_gateway(_ctx(cfg, unit={name: _SHORT}))) == _key(plain)
    assert _key(check_gateway(_ctx(cfg, unit={name: _LONG}))) == _key(plain)


# --------------------------------------------------------------------------------------
# a visible long value, and a value nobody can see
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_a_long_unit_value_is_the_plain_disclosure_with_no_caveat(label, ref, name):
    f = check_gateway(_ctx(_cfg(ref), unit={name: _LONG}))
    assert f.status == WARN
    assert "gateway.auth.token is set" in f.detail and "authenticated" in f.detail
    assert _CAVEAT not in f.detail and _LONG not in _blob(f)


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_under_mode_token_a_long_unit_value_is_a_pass_like_the_object(label, ref, name):
    f = check_gateway(_ctx(_cfg(ref, mode="token"), unit={name: _LONG}))
    assert f.status == PASS, f.detail
    assert _key(f) == _key(check_gateway(_ctx(_cfg(_obj(name), mode="token"), unit={name: _LONG})))


def test_nothing_visible_keeps_the_verdicts_the_name_length_gave_on_dev():
    """The open question (owner not asked): with no evidence the long-named reference is a
    PASS under mode token and the short-named one an UNKNOWN. Not changed here."""
    long_ = check_gateway(_ctx(_cfg("${" + _LONG_NAME + "}", mode="token")))
    short = check_gateway(_ctx(_cfg("${" + _SHORT_NAME + "}", mode="token")))
    assert long_.status == PASS
    assert short.status == UNKNOWN and _CAVEAT in short.detail
    no_mode = check_gateway(_ctx(_cfg("${" + _SHORT_NAME + "}")))
    assert no_mode.status == WARN and _CAVEAT in no_mode.detail
    assert _CAVEAT not in check_gateway(_ctx(_cfg("${" + _LONG_NAME + "}"))).detail


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
@pytest.mark.parametrize("mode", _MODES)
def test_a_unit_that_does_not_carry_the_variable_is_the_same_as_no_unit(label, ref, name, mode):
    cfg = _cfg(ref, mode=mode)
    base = _key(check_gateway(_ctx(cfg)))
    assert _key(check_gateway(_ctx(cfg, unit={}))) == base
    assert _key(check_gateway(_ctx(cfg, unit={"UNRELATED_VAR": _SHORT}))) == base


def test_the_environment_of_the_auditing_shell_is_not_evidence(monkeypatch):
    monkeypatch.setenv(_LONG_NAME, _SHORT)
    f = check_gateway(_ctx(_cfg("${" + _LONG_NAME + "}")))
    assert f.status == WARN and _SHORT_CLAUSE not in f.detail


# --------------------------------------------------------------------------------------
# the env block is read first, and is never a PASS
# --------------------------------------------------------------------------------------


def test_a_short_env_block_entry_is_final_whatever_the_unit_holds():
    ref = "${" + _LONG_NAME + "}"
    f = check_gateway(_ctx(_cfg(ref, block={_LONG_NAME: _SHORT}), unit={_LONG_NAME: _LONG}))
    assert f.status == FAIL and _SHORT_CLAUSE in f.detail


def test_a_long_env_block_entry_does_not_hide_a_short_unit_value():
    ref = "${" + _LONG_NAME + "}"
    f = check_gateway(_ctx(_cfg(ref, block={_LONG_NAME: _LONG}), unit={_LONG_NAME: _SHORT}))
    assert f.status == FAIL and _SHORT_CLAUSE in f.detail
    assert _SHORT not in _blob(f) and _LONG not in _blob(f)


def test_a_long_env_block_entry_with_a_long_unit_value_keeps_the_no_pass_note():
    ref = "${" + _LONG_NAME + "}"
    f = check_gateway(_ctx(_cfg(ref, block={_LONG_NAME: _LONG}), unit={_LONG_NAME: _LONG}))
    assert f.status == WARN and "process environment" in f.detail


# --------------------------------------------------------------------------------------
# B80, the legacy key, forms that are not references
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_b80_still_reads_the_string_reference_as_an_unthrottled_credential(label, ref, name):
    for unit in (None, {name: _SHORT}, {name: _LONG}):
        assert check_gateway_rate_limit(_ctx(_cfg(ref), unit=unit)).status == WARN


def test_a_string_reference_at_the_legacy_key_is_measured_as_the_env_block_already_is():
    ref = "${" + _LONG_NAME + "}"
    f = check_gateway(_ctx(_cfg(None, legacy=ref), unit={_LONG_NAME: _SHORT}))
    assert f.status == FAIL and _SHORT_CLAUSE in f.detail


@pytest.mark.parametrize(
    "token",
    [
        "prefix-${" + _LONG_NAME + "}",
        "${" + _LONG_NAME + "}-suffix",
        "${" + _LONG_NAME + ":-fallback-value}",
        "secretref-env:" + _LONG_NAME,
        "__env__:" + _LONG_NAME,
    ],
)
def test_a_look_alike_is_not_a_reference_and_the_evidence_is_not_consulted(token):
    cfg = _cfg(token)
    assert _key(check_gateway(_ctx(cfg, unit={_LONG_NAME: _SHORT}))) == _key(
        check_gateway(_ctx(cfg))
    )


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_the_value_and_the_path_never_reach_a_message(label, ref, name):
    unit = {name: _SHORT}
    for mode in _MODES:
        for bind in _BINDS:
            f = check_gateway(_ctx(_cfg(ref, bind, mode), unit=unit))
            assert _SHORT not in _blob(f)
            assert "/nonexistent" not in _blob(f)


# --------------------------------------------------------------------------------------
# what counts as a strong persistent value
# --------------------------------------------------------------------------------------

_WEAK_SHAPED = {
    "template": "${SOME_OTHER_LONG_VARIABLE_NAME}",
    "marker-secretref": "secretref-env:SOME_LONG_VAR_NAME_X",
    "marker-env": "__env__:SOME_LONG_VAR_NAME_XYZ",
}


@pytest.mark.parametrize("shape", sorted(_WEAK_SHAPED))
@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
@pytest.mark.parametrize("mode", _IN_EFFECT)
@pytest.mark.parametrize("bind", _BINDS)
def test_a_long_template_or_marker_shaped_value_is_no_evidence_of_strength(
    shape, label, ref, name, mode, bind
):
    value = _WEAK_SHAPED[shape]
    assert len(value) >= 24
    cfg = _cfg(ref, bind, mode)
    f = check_gateway(_ctx(cfg, unit={name: value}))
    assert _key(f) == _key(check_gateway(_ctx(cfg)))  # the verdict with nothing found
    assert _key(f) == _key(check_gateway(_ctx(cfg, dotenv={name: value})))
    if mode == "token" and name == _SHORT_NAME:
        assert f.status == UNKNOWN, f.detail  # not a PASS


@pytest.mark.parametrize("label,ref,name", _REFS, ids=_REF_IDS)
def test_the_24_character_bar_under_mode_token(label, ref, name):
    cfg = _cfg(ref, mode="token")
    assert check_gateway(_ctx(cfg, unit={name: "x" * 23})).status == FAIL
    assert check_gateway(_ctx(cfg, unit={name: "x" * 24})).status == PASS
    assert check_gateway(_ctx(cfg, unit={name: _LONG})).status == PASS
