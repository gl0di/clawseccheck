"""C-653 (a) and (c): how B2 (`check_gateway`) and B80 (`check_gateway_rate_limit`) read the
text of ``gateway.auth.token`` when it is not a plain secret.

(a) A whole-value ``secretref-env:ID`` / ``__env__:ID`` string is a RETIRED marker. OpenClaw
    2026.9.7 reads a ``gateway.auth.token`` that is not a reference as the token itself, so the
    marker text is the live gateway token - public and guessable, not a secret read from the
    environment. B2 used to count its 30+ characters as a strong token and say "Gateway is
    authenticated". It is a WARN now, never a PASS and never the "authenticated" disclosure.
    WARN rather than FAIL because B2 already passes other long guessable literal tokens, so a
    FAIL would be stricter than the existing rule.

(c) A whole-value ``${ID}`` reference (`_SECRET_INPUT_STRING_REF_RE`, the same string shapes
    the ``gateway.auth.password`` path counts; ``${ID:-}`` only on a build that understands the
    ``:-`` operator, the same `_env_default_operator` gate B1 uses) is not a literal either,
    and the length of the variable NAME says nothing about the secret behind it. B2 used to
    FAIL ``${GW_TOKEN}`` "shorter than 24 chars". Where the token is the credential in effect
    (mode exactly "token", or no mode) the length leg is skipped for a reference and B2 says
    so. Under every other mode a reference keeps the verdict it always had.

Offline, read-only, stdlib only. Secret-shaped values are assembled at runtime.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_gateway, check_gateway_rate_limit
from clawseccheck.checks._config import _gateway_config_token
from clawseccheck.collector import Context

_LITERAL_32 = "t" * 32
_MARKERS = (
    "secretref-env:OPENCLAW_GATEWAY_TOKEN",
    "__env__:OPENCLAW_GATEWAY_TOKEN",
)
_SHORT_REFS = ("${GW_TOKEN}", "${GATEWAY_TOKEN}")
_SHORT_TOKEN_DETAIL = "gateway auth token shorter than 24 chars"


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


# --------------------------------------------------------------------------------------
# (a) retired marker at gateway.auth.token
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("marker", _MARKERS)
@pytest.mark.parametrize("mode", ["token", None])
def test_marker_token_on_a_lan_bind_is_a_warn_not_a_pass(marker, mode):
    f = check_gateway(_ctx(_gw(bind="lan", mode=mode, token=marker)))
    assert f.status == WARN, f.detail
    assert "authenticated" not in f.detail
    assert "retired" in f.detail and "marker" in f.detail


@pytest.mark.parametrize("marker", _MARKERS)
def test_marker_warn_fix_names_the_reference_form_and_never_echoes_the_value(marker):
    f = check_gateway(_ctx(_gw(bind="lan", mode="token", token=marker)))
    assert "${ID}" in f.fix
    assert marker not in f.detail and marker not in f.fix
    assert all(marker not in e for e in f.evidence)


@pytest.mark.parametrize("marker", _MARKERS)
def test_marker_token_on_loopback_is_also_a_warn(marker):
    """The marker is a public literal wherever the gateway listens; the short-literal clause
    this sits beside is not bind-gated either."""
    for mode in ("token", None):
        f = check_gateway(_ctx(_gw(bind="loopback", mode=mode, token=marker)))
        assert f.status == WARN, (mode, f.detail)


def test_marker_with_surrounding_whitespace_is_still_the_marker():
    f = check_gateway(_ctx(_gw(bind="lan", mode="token", token="  " + _MARKERS[0] + "\n")))
    assert f.status == WARN


def test_marker_in_the_legacy_gateway_token_key_is_read_the_same_way():
    cfg = {"gateway": {"bind": "lan", "auth": {"mode": "token"}, "token": _MARKERS[0]}}
    assert check_gateway(_ctx(cfg)).status == WARN


def test_a_marker_only_counts_as_a_whole_value():
    """A marker with anything appended is ordinary literal text (a >=24-char literal PASSes
    exactly as before); a lower-case id is not a marker shape either."""
    for tok in (_MARKERS[0] + " and more text", "secretref-env:lower_case_name_here_x"):
        assert len(tok) >= 24
        assert check_gateway(_ctx(_gw(bind="lan", mode="token", token=tok))).status == PASS, tok


def test_marker_does_not_warn_when_the_token_is_not_the_credential_in_effect():
    """mode=password: the stray token is not what OpenClaw authenticates with."""
    cfg = _gw(bind="lan", mode="password", token=_MARKERS[0])
    cfg["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
    assert check_gateway(_ctx(cfg)).status == PASS


@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_marker_under_a_templated_mode_is_a_conditional_warn_with_the_template_note(bind):
    """`${M}` may resolve to "token", so a marker there is not waved through - but it may
    also resolve to "password", so the wording must not claim the marker IS the token."""
    f = check_gateway(_ctx(_gw(bind=bind, mode="${M}", token=_MARKERS[0])))
    assert f.status == WARN, f.detail
    assert "if gateway.auth.mode resolves to 'token'" in f.detail
    assert "gateway.auth.mode carries a ${...} environment template" in f.detail
    assert "authenticated" not in f.detail


@pytest.mark.parametrize("mode", ["token", None])
def test_marker_wording_is_unconditional_only_where_the_mode_is_token_or_unset(mode):
    f = check_gateway(_ctx(_gw(bind="lan", mode=mode, token=_MARKERS[0])))
    assert "the marker text itself is the gateway token" in f.detail
    assert "if gateway.auth.mode resolves" not in f.detail
    assert "environment template" not in f.detail


def test_short_marker_keeps_its_fail_and_its_detail_and_gains_the_reference_hint_in_fix():
    f = check_gateway(_ctx(_gw(bind="lan", mode="token", token="__env__:GW_T")))
    assert f.status == FAIL
    assert f.detail == _SHORT_TOKEN_DETAIL
    assert "${ID}" in f.fix


def test_marker_agrees_between_b2_and_b80():
    """B80 keeps treating a >=24-char marker as a token credential (it IS the token in
    effect), so a marker with no rateLimit is a WARN in both checks."""
    for mode in ("token", None):
        cfg = _gw(bind="lan", mode=mode, token=_MARKERS[0])
        assert check_gateway(_ctx(cfg)).status == WARN
        assert check_gateway_rate_limit(_ctx(cfg)).status == WARN


# --------------------------------------------------------------------------------------
# (c) short ${VAR} reference at gateway.auth.token
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("ref", _SHORT_REFS)
@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_short_reference_with_token_mode_gets_no_length_verdict(ref, bind):
    f = check_gateway(_ctx(_gw(bind=bind, mode="token", token=ref)))
    assert f.status == UNKNOWN, f.detail
    assert "shorter than 24" not in f.detail
    assert "gateway.auth.token" in f.detail


@pytest.mark.parametrize("ref", _SHORT_REFS)
def test_short_reference_fix_never_asks_for_a_literal_secret(ref):
    f = check_gateway(_ctx(_gw(bind="lan", mode="token", token=ref)))
    assert f.fix
    assert "shorter than 24" not in f.fix
    # the literal-token remedy (and B2's "write the value literally") would put the secret
    # in the file, which is what a reference exists to avoid
    assert "Use a gateway auth token" not in f.fix
    assert "literally" not in f.fix
    assert "environment" in f.fix
    assert ref not in f.detail


@pytest.mark.parametrize("ref", _SHORT_REFS)
def test_short_reference_with_no_auth_mode_on_loopback_is_unknown(ref):
    f = check_gateway(_ctx(_gw(bind="loopback", token=ref)))
    assert f.status == UNKNOWN, f.detail
    assert "shorter than 24" not in f.detail


@pytest.mark.parametrize("ref", _SHORT_REFS)
def test_short_reference_with_no_auth_mode_on_lan_is_a_disclosure_not_a_length_fail(ref):
    f = check_gateway(_ctx(_gw(bind="lan", token=ref)))
    assert f.status == WARN, f.detail
    assert "shorter than 24" not in f.detail
    assert "gateway.auth.token" in f.detail


@pytest.mark.parametrize("ref", ["$GW_TOKEN"])
def test_the_dollar_name_shorthand_is_a_reference_too(ref):
    f = check_gateway(_ctx(_gw(bind="lan", mode="token", token=ref)))
    assert f.status == UNKNOWN, f.detail


@pytest.mark.parametrize("ref", _SHORT_REFS)
def test_short_reference_agrees_between_b2_and_b80(ref):
    """The shared helper counts a reference as a credential of unknown strength: B80 reads
    it as token auth (it used to read the short text as no credential and PASS while B2
    FAILed the same input), so both checks treat it like the long reference."""
    assert _gateway_config_token(_gw(bind="lan", token=ref), None) == (ref, True)
    for bind, mode in (("lan", None), ("lan", "token")):
        cfg = _gw(bind=bind, mode=mode, token=ref)
        long_cfg = _gw(bind=bind, mode=mode, token="${OPENCLAW_GATEWAY_TOKEN}")
        assert (
            check_gateway_rate_limit(_ctx(cfg)).status
            == check_gateway_rate_limit(_ctx(long_cfg)).status
            == WARN
        )


@pytest.mark.parametrize("mode", ["password", "none", "trusted-proxy", "TOKEN", "${M}"])
@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_a_short_reference_keeps_its_old_verdict_where_the_token_is_not_in_effect(mode, bind):
    """The reference reading is for the credential in effect only. Under any other mode a
    short reference keeps exactly the verdict and detail a short literal of the same length
    gets - the change never makes a verdict cleaner outside the case it is about."""
    for ref in _SHORT_REFS:
        ref_cfg = _gw(bind=bind, mode=mode, token=ref)
        lit_cfg = _gw(bind=bind, mode=mode, token="x" * len(ref))
        for cfg in (ref_cfg, lit_cfg):
            if mode == "password":
                cfg["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
        a = check_gateway(_ctx(ref_cfg))
        b = check_gateway(_ctx(lit_cfg))
        assert (a.status, a.detail, a.fix) == (b.status, b.detail, b.fix), (mode, bind, ref)
        assert a.status == FAIL, (mode, bind, ref, a.detail)
        assert "shorter than 24" in a.detail


def test_password_mode_short_reference_token_still_fails_like_a_short_literal():
    cfg = _gw(bind="lan", mode="password", token="${GW_TOKEN}")
    cfg["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL and f.detail == _SHORT_TOKEN_DETAIL


# `${ID:-}` is a reference only on a build that understands the `:-` operator (2026.9.7+).
# Older builds pass it through verbatim, so the text is the token. The build comes from
# `installed_dist_version`, exactly as `_env_default_operator` reads it for B1's password path.


def _ctx_build(cfg: dict, build) -> Context:
    c = _ctx(cfg)
    c.installed_dist_version = build
    return c


@pytest.mark.parametrize("build", ["2026.9.6", "2026.9.0", "2026.8.1"])
@pytest.mark.parametrize("mode", ["token", None])
def test_empty_fallback_token_on_a_build_without_the_operator_keeps_the_literal_verdict(
    build, mode
):
    cfg = _gw(bind="lan", mode=mode, token="${GW_TOKEN:-}")
    f = check_gateway(_ctx_build(cfg, build))
    assert f.status == FAIL, f.detail
    assert _SHORT_TOKEN_DETAIL in f.detail
    assert "environment reference" not in f.detail
    # byte-identical to what a 13-character literal gets on the same build
    lit = check_gateway(_ctx_build(_gw(bind="lan", mode=mode, token="x" * 13), build))
    assert (f.status, f.detail, f.fix) == (lit.status, lit.detail, lit.fix)


@pytest.mark.parametrize("build", ["2026.9.7", "2026.9.8", "2026.10.1"])
@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_empty_fallback_token_on_a_build_with_the_operator_is_a_reference(build, bind):
    f = check_gateway(_ctx_build(_gw(bind=bind, mode="token", token="${GW_TOKEN:-}"), build))
    assert f.status == UNKNOWN, f.detail
    assert "shorter than 24" not in f.detail
    assert "gateway.auth.token" in f.detail


@pytest.mark.parametrize("build", [None, "unknown-build", "0.0.0", "2026.9"])
def test_empty_fallback_token_on_an_unseen_build_is_not_cleared(build):
    """Only a build seen to understand `:-` clears the text. An unseen one keeps the dev
    verdict (B1 answers UNKNOWN for the same build; here that would be CLEANER than the
    literal reading this check always gave)."""
    f = check_gateway(_ctx_build(_gw(bind="lan", mode="token", token="${GW_TOKEN:-}"), build))
    assert f.status == FAIL, f.detail
    assert f.detail == _SHORT_TOKEN_DETAIL


def test_a_config_stamp_alone_does_not_make_the_empty_fallback_a_reference():
    cfg = _gw(bind="lan", mode="token", token="${GW_TOKEN:-}")
    cfg["meta"] = {"lastTouchedVersion": "2026.9.8"}
    assert check_gateway(_ctx(cfg)).status == FAIL


def test_empty_fallback_build_gate_reaches_b80_through_the_shared_helper():
    cfg = _gw(bind="lan", token="${GW_TOKEN:-}")
    assert _gateway_config_token(cfg, None, _ctx_build(cfg, "2026.9.7")) == ("${GW_TOKEN:-}", True)
    assert _gateway_config_token(cfg, None, _ctx_build(cfg, "2026.9.6")) == ("${GW_TOKEN:-}", False)
    assert _gateway_config_token(cfg, None) == ("${GW_TOKEN:-}", False)
    # B2 and B80 agree on each build
    old, new = _ctx_build(cfg, "2026.9.6"), _ctx_build(cfg, "2026.9.7")
    assert check_gateway(old).status == FAIL
    assert check_gateway_rate_limit(old).status == PASS  # same as a short literal: weak, unrated
    assert check_gateway(new).status == WARN
    assert check_gateway_rate_limit(new).status == WARN


def test_pins_dev_behaviour_for_the_long_named_empty_fallback_which_is_a_known_gap():
    """Pins what dev already does, NOT a correct verdict. `${OPENCLAW_GATEWAY_TOKEN:-}` is
    27 characters, so B2 passes it by text length on every build. On a build before 2026.9.7
    (or an unseen one) that text is a public 27-character literal and the PASS is wrong; that
    is the known gap tracked as item (d) of the C-653 task, deliberately left as it was. This
    test only guards against this change moving the verdict by accident."""
    cfg = _gw(bind="lan", mode="token", token="${OPENCLAW_GATEWAY_TOKEN:-}")
    for build in (None, "2026.9.6", "2026.9.7"):
        assert check_gateway(_ctx_build(cfg, build)).status == PASS, build


def test_an_independent_fail_still_wins_and_the_reference_note_rides_along():
    cfg = _gw(bind="lan", mode="token", token="${GW_TOKEN}")
    cfg["channels"] = {"telegram": {"dmPolicy": "open", "groupPolicy": "open"}}
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL
    assert "open dm/group policy" in f.detail
    assert "gateway.auth.token" in f.detail
    assert "shorter than 24" not in f.detail


def test_a_templated_bind_and_a_short_reference_are_both_named_in_one_unknown():
    f = check_gateway(_ctx(_gw(bind="${B:-lan}", mode="token", token="${GW_TOKEN}")))
    assert f.status == UNKNOWN
    assert "gateway.auth.token" in f.detail


# --------------------------------------------------------------------------------------
# controls: nothing here moved
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("bind", ["lan", "loopback"])
def test_short_literal_token_still_fails_with_its_detail(bind):
    f = check_gateway(_ctx(_gw(bind=bind, mode="token", token="short-token")))
    assert f.status == FAIL
    assert f.detail == _SHORT_TOKEN_DETAIL
    assert f.fix == "Use a gateway auth token of at least 24 characters"


def test_short_literal_token_with_no_mode_on_lan_still_fails():
    f = check_gateway(_ctx(_gw(bind="lan", token="short-token")))
    assert f.status == FAIL
    assert _SHORT_TOKEN_DETAIL in f.detail


def test_a_partial_template_is_not_a_whole_value_reference():
    """`abc${X}` is not a reference shape, so it keeps the plain literal verdict."""
    f = check_gateway(_ctx(_gw(bind="lan", mode="token", token="ab${X}")))
    assert f.status == FAIL
    assert f.detail == _SHORT_TOKEN_DETAIL


def test_thirty_two_char_literal_token_still_passes():
    f = check_gateway(_ctx(_gw(bind="lan", mode="token", token=_LITERAL_32)))
    assert f.status == PASS
    assert "Gateway is authenticated (gateway.auth.mode=token)" in f.detail


def test_the_long_named_reference_keeps_its_verdicts():
    ref = "${OPENCLAW_GATEWAY_TOKEN}"
    assert check_gateway(_ctx(_gw(bind="lan", mode="token", token=ref))).status == PASS
    assert check_gateway(_ctx(_gw(bind="loopback", mode="token", token=ref))).status == PASS
    lan_no_mode = check_gateway(_ctx(_gw(bind="lan", token=ref)))
    assert lan_no_mode.status == WARN
    assert "authenticated" in lan_no_mode.detail


def test_a_literal_with_no_mode_on_lan_keeps_the_authenticated_disclosure():
    f = check_gateway(_ctx(_gw(bind="lan", token=_LITERAL_32)))
    assert f.status == WARN
    assert "authenticated" in f.detail


def test_no_token_at_all_is_unchanged():
    assert check_gateway(_ctx(_gw(bind="lan", mode="none"))).status == FAIL
    assert check_gateway(_ctx(_gw(bind="loopback"))).status == PASS


# --------------------------------------------------------------------------------------
# (c) a reference whose variable the config's OWN env block defines
# --------------------------------------------------------------------------------------
# B1 counts such a reference at gateway.auth.password as plaintext in the file
# (`_credential_is_plaintext(..., cfg=cfg)`, `_env_block_defines_plaintext`), and the same
# helpers find the definition here. But a value in the config's env block is NEVER taken as
# proof of a strong token (OpenClaw 2026.9.8 `config-env-vars`): the process environment
# wins over a config value, a config value that itself contains a `${...}` reference is
# dropped, and env keys are case-sensitive. So there are three outcomes for a whole-value
# reference when the token is in effect (mode exactly "token", or no mode):
#   (1) defined in the env block and some resolved value is short (<24) or a retired marker:
#       the dev FAIL, detail byte-for-byte;
#   (2) defined and every resolved value is 24+ characters: UNKNOWN (never PASS), saying why;
#   (3) not defined in the config (it comes from the process environment): UNKNOWN.
# No input moves from FAIL to PASS.

_SHORT_VALUE = "abc"
_LONG_VALUE = "v" * 40


def _envcfg(env, token="${GW_TOKEN}", mode="token", bind="lan") -> dict:
    cfg = _gw(bind=bind, mode=mode, token=token)
    cfg["env"] = env
    return cfg


_ENV_FORMS = {
    "vars": lambda name, value: {"vars": {name: value}},
    "flat": lambda name, value: {name: value},
}


def _with_unit_env(cfg: dict, unit_env: dict) -> Context:
    c = _ctx_build(cfg, "2026.9.8")
    c.unit_env_values = dict(unit_env)
    c.unit_env_sources = {k: "gateway.service" for k in unit_env}
    c.unit_env_found = True
    return c


# ---- outcome (1): defined, some resolved value short or a marker -> the dev FAIL ----------


@pytest.mark.parametrize("form", sorted(_ENV_FORMS))
@pytest.mark.parametrize("mode", ["token", None])
def test_env_block_short_value_keeps_the_dev_fail(form, mode):
    cfg = _envcfg(_ENV_FORMS[form]("GW_TOKEN", _SHORT_VALUE), mode=mode)
    f = check_gateway(_ctx_build(cfg, "2026.9.8"))
    dev = check_gateway(_ctx(_envcfg({}, mode=mode, token="x" * 11)))  # dev: short text
    assert f.status == FAIL, f.detail
    assert f.detail == dev.detail
    assert "cannot be read" not in f.detail
    assert _SHORT_VALUE not in f.detail and _SHORT_VALUE not in f.fix


def test_env_block_boundary_is_the_same_24_character_bar():
    assert check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": "x" * 23}}))).status == FAIL
    assert check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": "x" * 24}}))).status == UNKNOWN


@pytest.mark.parametrize(
    "value", ["abc" + " " * 30, " " * 30 + "abc", "abc" + "\x1f" * 30], ids=["tail", "head", "x1f"]
)
def test_env_block_padding_does_not_make_a_short_value_long(value):
    f = check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": value}})))
    assert f.status == FAIL and f.detail == _SHORT_TOKEN_DETAIL


def test_env_block_retired_marker_value_is_the_dev_fail_never_a_pass():
    """The same marker as a LITERAL token is a WARN; defined in the env block it must not be
    cleaner than that, and it is the dev FAIL for a short reference."""
    for marker in _MARKERS:
        f = check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": marker}})))
        assert f.status == FAIL and f.detail == _SHORT_TOKEN_DETAIL, marker
        long_ref = check_gateway(
            _ctx(_envcfg({"vars": {"OPENCLAW_GATEWAY_TOKEN": marker}}, token="${OPENCLAW_GATEWAY_TOKEN}"))
        )
        assert long_ref.status == FAIL, marker
    assert check_gateway(_ctx(_gw(bind="lan", mode="token", token=_MARKERS[0]))).status == WARN


def test_env_block_long_named_reference_with_a_short_value_is_no_longer_a_pass():
    """`${OPENCLAW_GATEWAY_TOKEN}` is 25 characters, which passed by text length while the
    config's own env block held a 3-character value."""
    cfg = _envcfg({"vars": {"OPENCLAW_GATEWAY_TOKEN": _SHORT_VALUE}}, token="${OPENCLAW_GATEWAY_TOKEN}")
    f = check_gateway(_ctx(cfg))
    assert f.status == FAIL and f.detail == _SHORT_TOKEN_DETAIL


def test_env_block_name_is_case_folded_here_because_that_only_finds_more_weak_values():
    f = check_gateway(_ctx(_envcfg({"vars": {"gw_token": _SHORT_VALUE}})))
    assert f.status == FAIL and f.detail == _SHORT_TOKEN_DETAIL


def test_env_block_short_value_anywhere_in_the_chain_or_the_two_forms_is_the_dev_fail():
    for env in (
        {"vars": {"GW_TOKEN": "${OTHER_TOKEN}", "OTHER_TOKEN": _SHORT_VALUE}},
        {"vars": {"GW_TOKEN": "${B}", "B": "${C}", "C": _SHORT_VALUE}},
        {"vars": {"GW_TOKEN": _LONG_VALUE}, "GW_TOKEN": _SHORT_VALUE},  # vars long, flat short
        {"vars": {"GW_TOKEN": _SHORT_VALUE}, "GW_TOKEN": _LONG_VALUE},  # vars short, flat long
    ):
        f = check_gateway(_ctx(_envcfg(env)))
        assert f.status == FAIL and f.detail == _SHORT_TOKEN_DETAIL, env


# ---- outcome (2): defined, every resolved value 24+ -> UNKNOWN, never PASS ------------------


@pytest.mark.parametrize("form", sorted(_ENV_FORMS))
@pytest.mark.parametrize("token", ["${GW_TOKEN}", "$GW_TOKEN"])
def test_env_block_long_value_is_unknown_and_says_why_no_pass_is_given(form, token):
    cfg = _envcfg(_ENV_FORMS[form]("GW_TOKEN", _LONG_VALUE), token=token)
    f = check_gateway(_ctx(cfg))
    assert f.status == UNKNOWN, f.detail
    for why in ("process environment", "not injected", "case-sensitive"):
        assert why in f.detail, why
    assert "shorter than 24" not in f.detail
    assert _LONG_VALUE not in f.detail and _LONG_VALUE not in f.fix
    assert f.fix and "Use a gateway auth token" not in f.fix


def test_env_block_long_value_with_no_mode_on_lan_is_a_warn_with_the_same_note():
    f = check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": _LONG_VALUE}}, mode=None)))
    assert f.status == WARN, f.detail
    assert "process environment" in f.detail


def test_env_block_long_value_behind_a_long_named_reference_is_unknown_not_pass():
    cfg = _envcfg({"vars": {"OPENCLAW_GATEWAY_TOKEN": _LONG_VALUE}}, token="${OPENCLAW_GATEWAY_TOKEN}")
    assert check_gateway(_ctx(cfg)).status == UNKNOWN


def test_env_block_repro_process_environment_wins_over_the_config_value():
    """A 40-character value in the config's env block, but the gateway unit sets
    GW_TOKEN=abc: the process environment wins, so a PASS would be false."""
    cfg = _envcfg({"vars": {"GW_TOKEN": _LONG_VALUE}})
    f = check_gateway(_with_unit_env(cfg, {"GW_TOKEN": "abc"}))
    assert f.status == UNKNOWN and f.status != PASS, f.detail


def test_env_block_repro_lowercase_key_is_never_a_pass():
    """Env keys are case-sensitive on the vendor side, so `gw_token` may not be what
    `${GW_TOKEN}` reads; a long value there must not clear it."""
    f = check_gateway(_ctx(_envcfg({"vars": {"gw_token": _LONG_VALUE}})))
    assert f.status == UNKNOWN, f.detail


def test_env_block_repro_chain_to_a_long_value_is_never_a_pass():
    """A config value that itself holds a `${...}` reference is not injected."""
    f = check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": "${B}", "B": _LONG_VALUE}})))
    assert f.status == UNKNOWN, f.detail
    deep = {"vars": {"GW_TOKEN": "${B}", "B": "${C}", "C": _LONG_VALUE}}
    assert check_gateway(_ctx(_envcfg(deep))).status == UNKNOWN


def test_env_block_repro_long_value_ending_in_a_reference_is_never_a_pass():
    f = check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": "t" * 30 + "${X}"}})))
    assert f.status == UNKNOWN, f.detail


# ---- outcome (3): not defined in the config -> UNKNOWN as before -------------------------------


def test_env_block_chain_to_a_variable_the_config_does_not_define_stays_unknown():
    f = check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": "${OTHER_TOKEN}"}})))
    assert f.status == UNKNOWN, f.detail
    assert "gateway.auth.token" in f.detail and "shorter than 24" not in f.detail


def test_env_block_chain_cycle_adds_no_value_and_stays_unknown():
    cyc = {"vars": {"GW_TOKEN": "${A_TOKEN}", "A_TOKEN": "${GW_TOKEN}"}}
    assert check_gateway(_ctx(_envcfg(cyc))).status == UNKNOWN


def test_env_block_empty_string_value_is_not_a_definition():
    for env in ({"vars": {"GW_TOKEN": ""}}, {"GW_TOKEN": "   "}):
        f = check_gateway(_ctx(_envcfg(env)))
        assert f.status == UNKNOWN, (env, f.detail)
        assert "process environment" not in f.detail  # the opaque-reference note, not outcome 2


def test_reference_to_an_undefined_variable_stays_unknown_beside_other_definitions():
    f = check_gateway(_ctx(_envcfg({"vars": {"SOMETHING_ELSE": _SHORT_VALUE}})))
    assert f.status == UNKNOWN, f.detail
    assert check_gateway(_ctx(_envcfg({}))).status == UNKNOWN


def test_env_block_non_string_values_are_not_definitions():
    f = check_gateway(_ctx(_envcfg({"vars": {"GW_TOKEN": 12345}})))
    assert f.status == UNKNOWN, f.detail


# ---- scope: only where the token is the credential in effect; builds; B80 -------------------


@pytest.mark.parametrize("mode", ["password", "none", "trusted-proxy", "TOKEN"])
def test_env_block_is_not_consulted_where_the_token_is_not_in_effect(mode):
    """Outside mode exactly "token" / no mode the verdict stays what it always was: the
    reference text's length, whatever the env block holds."""
    for value in (_SHORT_VALUE, _LONG_VALUE):
        cfg = _envcfg({"vars": {"GW_TOKEN": value}}, mode=mode)
        plain = _envcfg({}, mode=mode)
        for c in (cfg, plain):
            if mode == "password":
                c["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
        a, b = check_gateway(_ctx(cfg)), check_gateway(_ctx(plain))
        assert (a.status, a.detail) == (b.status, b.detail), (mode, len(value))


def test_env_block_and_the_empty_fallback_build_gate():
    """`${GW_TOKEN:-}` is a reference (so its env-block value is consulted) only on a build
    with the `:-` operator; on an older or unseen build the 13-character text is the token."""
    for build in ("2026.9.6", None):
        for value in (_SHORT_VALUE, _LONG_VALUE):
            cfg = _envcfg({"vars": {"GW_TOKEN": value}}, token="${GW_TOKEN:-}")
            f = check_gateway(_ctx_build(cfg, build))
            assert f.status == FAIL and f.detail == _SHORT_TOKEN_DETAIL, (build, len(value))
    short = _envcfg({"vars": {"GW_TOKEN": _SHORT_VALUE}}, token="${GW_TOKEN:-}")
    long_ = _envcfg({"vars": {"GW_TOKEN": _LONG_VALUE}}, token="${GW_TOKEN:-}")
    assert check_gateway(_ctx_build(short, "2026.9.8")).status == FAIL
    assert check_gateway(_ctx_build(long_, "2026.9.8")).status == UNKNOWN


@pytest.mark.parametrize("value", [_SHORT_VALUE, "x" * 23, "x" * 24, _LONG_VALUE])
def test_b80_counts_an_env_block_defined_reference_as_a_credential_and_is_never_cleaner(value):
    """B80 never reads a reference as weaker than its text length did before (dev: a
    reference under 24 characters was no credential, so PASS; 24+ was WARN). Every reference
    is a credential here whatever the env block holds; B2 is the check that reports a short
    env value."""
    for token in ("${GW_TOKEN}", "${OPENCLAW_GATEWAY_TOKEN}"):
        name = token[2:-1]
        cfg = _envcfg({"vars": {name: value}}, token=token, mode=None)
        assert _gateway_config_token(cfg, None)[1] is True
        assert check_gateway_rate_limit(_ctx(cfg)).status == WARN


def test_b80_keeps_an_undefined_reference_as_a_credential_of_unknown_strength():
    cfg = _envcfg({"vars": {"OTHER": _SHORT_VALUE}}, mode=None)
    assert _gateway_config_token(cfg, None) == ("${GW_TOKEN}", True)
    assert check_gateway_rate_limit(_ctx(cfg)).status == WARN


# ---- no FAIL -> PASS anywhere ------------------------------------------------------------------


def test_no_cell_goes_from_a_dev_fail_to_a_pass_in_a_matrix_of_references_and_env_blocks():
    """Dev FAILs every reference at gateway.auth.token whose TEXT is under 24 characters, in
    every mode. Over references x env definitions x modes x binds, no such cell may be a PASS,
    and outside the modes where the token is in effect the env block must not be consulted at
    all (the verdict equals the same config without it)."""
    tokens = ["${GW_TOKEN}", "$GW_TOKEN", "${GW_TOKEN:-}", "${OPENCLAW_GATEWAY_TOKEN}"]
    values = [
        _SHORT_VALUE, "x" * 23, "x" * 24, _LONG_VALUE, "t" * 30 + "${X}", "${B}", "${GW_TOKEN}",
        "", 12345, _MARKERS[0], _MARKERS[1],
    ]
    modes = [None, "token", "password", "none", "trusted-proxy", "TOKEN"]
    cells = 0
    for token in tokens:
        for form in sorted(_ENV_FORMS):
            for name in ("GW_TOKEN", "gw_token", "OPENCLAW_GATEWAY_TOKEN"):
                for value in values:
                    env = _ENV_FORMS[form](name, value)
                    if value in ("${B}",):
                        env = {"vars": {name: value, "B": _LONG_VALUE}}
                    for mode in modes:
                        for bind in ("lan", "loopback"):
                            for build in (None, "2026.9.6", "2026.9.8"):
                                cfg = _envcfg(env, token=token, mode=mode, bind=bind)
                                bare = _envcfg({}, token=token, mode=mode, bind=bind)
                                for c in (cfg, bare):
                                    if mode == "password":
                                        c["gateway"]["auth"]["password"] = "${GW_PASSWORD}"
                                f = check_gateway(_ctx_build(cfg, build))
                                cells += 1
                                if len(token) < 24 and not (token == "${GW_TOKEN:-}" and build == "2026.9.8"):
                                    assert f.status != PASS, (token, env, mode, bind, build, f.detail)
                                if mode not in (None, "token"):
                                    g = check_gateway(_ctx_build(bare, build))
                                    assert (f.status, f.detail) == (g.status, g.detail), (
                                        token, env, mode, bind, build)
    assert cells > 5000


# --------------------------------------------------------------------------------------
# wiring: the real audit() path, from openclaw.json on disk
# --------------------------------------------------------------------------------------


def _audit_b2(tmp_path, token: str, mode: bool = True):
    from clawseccheck import audit

    auth = '{"mode": "token", "token": "%s"}' % token if mode else '{"token": "%s"}' % token
    cfg = tmp_path / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "lan", "auth": %s}}' % auth, encoding="utf-8")
    cfg.chmod(0o600)
    _, findings, _ = audit(tmp_path, include_native=False)
    return {f.id: f for f in findings}["B2"]


def test_audit_marker_from_disk_is_not_a_b2_pass(tmp_path):
    f = _audit_b2(tmp_path, _MARKERS[0])
    assert f.status == WARN, f.detail
    assert "authenticated" not in f.detail


def test_audit_short_reference_from_disk_is_not_a_length_fail(tmp_path):
    f = _audit_b2(tmp_path, "${GW_TOKEN}")
    assert f.status == UNKNOWN, f.detail
    assert "shorter than 24" not in f.detail
