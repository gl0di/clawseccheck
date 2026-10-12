"""C-693: a non-loopback gateway with NO credential is REFUSED at start-up by the installed
OpenClaw, so B2 must not call it "exposed" - and the two configs that are refused the same way
must get the same answer.

Owner ruling (Dave, 2026-10-12), option (a) for BOTH cells:

* ``gateway.bind`` non-loopback with no ``gateway.auth.mode`` and no credential, and
* ``gateway.auth.mode: "token"`` with no token,

answer WARN - not FAIL, not PASS - on a build whose ``gateway run`` pre-flight was read
(``_B2_BIND_PREFLIGHT_READ_MIN``, 2026.9.6 and later), with a sentence that says the build
refuses to start the gateway with this configuration (a non-loopback bind needs a configured
token or password), so it is a configuration error rather than an exposure, and that a token or
password should be configured. An explicit ``mode: "none"`` stays the FAIL it always was,
byte-identical detail. On a build that is NOT read (older, unknown, a pre-release, no version)
both cells keep today's verdict - FAIL and PASS - and the FAIL is reworded (no "exposed", no
Python literal "None").

CORRECTION of the first version of this ticket, which claimed the gateway "starts behind a token
it generates". It did not: ``gateway run`` computes ``hasSharedSecret`` and exits 78 with
"Refusing to bind gateway to lan without auth." BEFORE ``ensureGatewayStartupAuth`` can generate a
runtime token, so the generated token only exists on a loopback bind. Calling the vendor's
start-up functions directly skipped that pre-flight and measured a path no real start takes. The
local-only half below therefore RUNS THE REAL CLI.

The WARN is a WHITELIST of the exact shapes the CLI was run on (a "lan" bind, an auth block that
is absent or holds only the mode, no token or password anywhere, no Tailscale serve/funnel, no
gateway.remote content): every other shape keeps its old status and says nothing about a refused
start. The INSTALLED build alone decides; the config's own version stamp is never read for this.

Two halves. The always-on half pins the matrix (shape x build). The local-only half starts
``openclaw gateway run`` from the installed package in a throwaway HOME with a clean environment
and asserts the exit status of each shape, then that the package claims a refusal only where the
real CLI refused. It is skipped, never weakened, where node or the installed package is absent.

Offline, read-only, stdlib only. Secret-shaped values are assembled at runtime.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_gateway, check_gateway_rate_limit
from clawseccheck.checks._config import (
    _B2_BIND_PREFLIGHT_READ_MIN,
    _gateway_bind_preflight,
)
from clawseccheck.collector import Context

_LONG = "t" * 40
_MEASURED = ["2026.9.6", "2026.9.7", "2026.9.9", "2026.10.1", "2026.10.2"]
# Not measured: older, unknown, no version, a version that is not a calendar release, a pre-release.
_UNMEASURED = [None, "2026.9.5", "2026.8.1", "2026.7.1", "0.0.0", "2026.10", "2026.10.2-beta.1"]

_REFUSES = "refuse to start the gateway with this configuration"
_FAIL_DETAIL = (
    "gateway.bind=lan is non-loopback, no gateway.auth.mode is set and no usable gateway token "
    "is configured"
)
_NONE_DETAIL = "gateway.bind=lan exposed with auth.mode=none"  # byte-identical to before C-693


def _ctx(cfg: dict, build=None, unit=None, dotenv=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    c.installed_dist_version = build
    if unit is not None:
        c.unit_env_values = dict(unit)
        c.unit_env_sources = {k: "gateway.service" for k in unit}
        c.unit_env_found = True
    if dotenv is not None:
        c.dotenv_values = dict(dotenv)
        c.dotenv_sources = {k: ".env" for k in dotenv}
        c.dotenv_found = True
    return c


def _gw(bind="lan", **auth) -> dict:
    gw: dict = {"bind": bind}
    if auth:
        gw["auth"] = dict(auth)
    return {"gateway": gw}


# The task's three configs and two controls.
NO_CREDENTIAL = _gw()                                      # cell A: no mode, nothing
TOKEN_NO_TOKEN = _gw(mode="token")                         # cell B: mode token, no token
LITERAL_TOKEN = _gw(mode="token", token=_LONG)             # control: a configured token
EXPLICIT_NONE = _gw(mode="none")                           # control: the vendor refuses to bind it


def _unconfirmed(f) -> str:
    return " ".join([f.detail, f.fix, *f.evidence])


# ----------------------------------------------------------------------------- matrix: measured


@pytest.mark.parametrize("build", _MEASURED)
@pytest.mark.parametrize("cfg", [NO_CREDENTIAL, TOKEN_NO_TOKEN], ids=["no-mode", "token-no-token"])
def test_read_build_no_credential_cells_are_a_warn_about_a_refused_start(cfg, build):
    f = check_gateway(_ctx(cfg, build))
    assert f.status == WARN, f.detail
    assert _REFUSES in f.detail
    assert "a non-loopback bind needs a configured token or password" in f.detail
    assert "configuration error rather than an exposure" in f.detail
    assert "unless an environment or start-up flag this audit cannot see supplies a token or " in f.detail
    # no claim that the gateway starts, runs, or is served behind a token of its own
    for text in (f.detail, f.fix, *f.evidence):
        for word in ("generates", "generated", "starts a gateway", "unauthenticated",
                     "authenticates the gateway"):
            assert word not in text.replace("generates a runtime token at each start", ""), word
    # the advice rides in fix
    assert "gateway.auth.token" in f.fix and "SecretRef" in f.fix
    assert "bind the gateway to loopback" in f.fix
    for text in (f.detail, f.fix):
        assert "exposed" not in text
        assert "None" not in text


def test_the_exit_message_is_quoted_only_when_gateway_mode_is_local():
    # with gateway.mode unset the real refusal is "missing gateway.mode", not the bind message
    quote = "Refusing to bind gateway to lan without auth"
    unset = check_gateway(_ctx(NO_CREDENTIAL, "2026.10.2"))
    assert unset.status == WARN and _REFUSES in unset.detail and quote not in unset.detail
    local = dict(NO_CREDENTIAL)
    local["gateway"] = dict(local["gateway"], mode="local")
    for cfg in (local, dict(TOKEN_NO_TOKEN, gateway=dict(TOKEN_NO_TOKEN["gateway"], mode="local"))):
        f = check_gateway(_ctx(cfg, "2026.10.2"))
        assert f.status == WARN and quote in f.detail
    # and the mode-unset text never names a missing gateway.mode as THE reason
    assert "gateway.mode" not in unset.detail


@pytest.mark.parametrize("build", _MEASURED + _UNMEASURED)
def test_the_two_equivalent_configs_get_the_same_answer_on_every_build(build):
    a = check_gateway(_ctx(NO_CREDENTIAL, build))
    b = check_gateway(_ctx(TOKEN_NO_TOKEN, build))
    if build in _MEASURED:
        assert a.status == b.status == WARN
        # one shared sentence: only the clause that names the mode differs
        assert a.detail.split(". ", 1)[1] == b.detail.split(". ", 1)[1]
        assert a.fix == b.fix
    else:
        # unmeasured: today's answers, unchanged (FAIL for the no-mode cell, PASS for the other)
        assert (a.status, b.status) == (FAIL, PASS)


@pytest.mark.parametrize("build", _MEASURED + _UNMEASURED)
def test_explicit_mode_none_stays_the_fail_with_its_old_detail(build):
    f = check_gateway(_ctx(EXPLICIT_NONE, build))
    assert f.status == FAIL
    assert f.detail == _NONE_DETAIL


@pytest.mark.parametrize("build", _MEASURED + _UNMEASURED)
def test_a_configured_token_is_unaffected_by_the_build(build):
    f = check_gateway(_ctx(LITERAL_TOKEN, build))
    assert f.status == PASS
    assert "authenticated" in f.detail


@pytest.mark.parametrize("build", _MEASURED + _UNMEASURED)
@pytest.mark.parametrize("cfg", [_gw("loopback"), _gw("loopback", mode="token")])
def test_loopback_binds_are_unaffected_by_the_build(cfg, build):
    assert check_gateway(_ctx(cfg, build)).status == PASS


# --------------------------------------------------------------------------- matrix: unmeasured


@pytest.mark.parametrize("build", _UNMEASURED)
def test_unmeasured_build_keeps_the_fail_with_reworded_text(build):
    f = check_gateway(_ctx(NO_CREDENTIAL, build))
    assert f.status == FAIL
    assert f.detail == _FAIL_DETAIL
    for text in (f.detail, f.fix):
        assert "exposed" not in text
        assert "None" not in text
    # only the sentence is reworded: the advice is what it always was
    assert f.fix == (
        "Bind the gateway to loopback or require auth (gateway.auth.mode=token, token >=24 chars)"
    )


@pytest.mark.parametrize("build", _UNMEASURED)
def test_unmeasured_build_keeps_the_pass_for_mode_token_without_a_token(build):
    f = check_gateway(_ctx(TOKEN_NO_TOKEN, build))
    assert f.status == PASS
    assert "authenticated" in f.detail


# ------------------------------------------------------------------------------ the build gate


def test_the_threshold_is_the_oldest_executed_build():
    assert _B2_BIND_PREFLIGHT_READ_MIN == (2026, 9, 6)


@pytest.mark.parametrize("build", _MEASURED)
def test_installed_build_in_the_read_range_refuses(build):
    assert _gateway_bind_preflight(_ctx({}, build)) == "refuses"


@pytest.mark.parametrize("build", _UNMEASURED)
def test_installed_build_outside_the_read_range_is_unknown(build):
    assert _gateway_bind_preflight(_ctx({}, build)) == "unknown"


_STAMPS = ["2026.10.2", "2026.9.6", "2099.1.1"]


@pytest.mark.parametrize("stamp", _STAMPS)
def test_the_config_stamp_never_selects_the_refusal_reading(stamp):
    meta = {"meta": {"lastTouchedVersion": stamp}}
    for build in (None, "garbage", "2026.10.2-beta.1", "2026.9.5", "2026.10"):
        assert _gateway_bind_preflight(_ctx(meta, build)) == "unknown", (stamp, build)
        a = check_gateway(_ctx(dict(NO_CREDENTIAL, **meta), build))
        b = check_gateway(_ctx(dict(TOKEN_NO_TOKEN, **meta), build))
        # exactly the answers a stamp-less config gets on that build: FAIL (reworded) and PASS
        assert (a.status, a.detail) == (FAIL, _FAIL_DETAIL), (stamp, build)
        assert (b.status, b.detail) == (PASS, check_gateway(_ctx(TOKEN_NO_TOKEN, build)).detail)
        assert check_gateway_rate_limit(_ctx(dict(NO_CREDENTIAL, **meta), build)).status == UNKNOWN


@pytest.mark.parametrize("stamp", [None, "2026.7.1", "2099.1.1"])
def test_an_installed_measured_build_decides_whatever_the_stamp_says(stamp):
    cfg = dict(NO_CREDENTIAL, meta={"lastTouchedVersion": stamp}) if stamp else NO_CREDENTIAL
    assert _gateway_bind_preflight(_ctx(cfg, "2026.10.2")) == "refuses"
    assert check_gateway(_ctx(cfg, "2026.10.2")).status == WARN


# --------------------------------- cases where "the start is refused" is NOT established


@pytest.mark.parametrize("build", _MEASURED)
def test_a_credential_anywhere_means_the_refused_start_claim_is_not_made(build):
    shapes = {
        "blank token (the vendor refuses to start)": _gw(token=""),
        "whitespace token": _gw(token="   "),
        "password without a mode (the vendor derives mode password)": _gw(password=_LONG),
        "a token reference object": _gw(token={"source": "env", "id": "GW_TOKEN"}),
        "a token reference string": _gw(token="${OPENCLAW_GATEWAY_TOKEN}"),
        "auth block that is not an object": {"gateway": {"bind": "lan", "auth": "token"}},
    }
    for name, cfg in shapes.items():
        f = check_gateway(_ctx(cfg, build))
        assert _REFUSES not in _unconfirmed(f), name


@pytest.mark.parametrize("build", _MEASURED)
def test_the_two_shapes_that_stay_a_fail_keep_failing_on_a_measured_build(build):
    # no usable token / a password with no mode: these are the verdicts they had before
    for cfg in (_gw(token=""), _gw(password=_LONG)):
        f = check_gateway(_ctx(cfg, build))
        assert f.status == FAIL
        assert f.detail == _FAIL_DETAIL


@pytest.mark.parametrize("var", ["OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_PASSWORD"])
def test_an_environment_credential_in_a_persistent_artifact_clears_the_refusal_reading(var):
    for src in ({"unit": {var: _LONG}}, {"dotenv": {var: _LONG}}):
        # no mode: the environment authenticates (the older, softer WARN) - never the new note
        f = check_gateway(_ctx(NO_CREDENTIAL, "2026.10.2", **src))
        assert f.status == WARN
        assert _REFUSES not in f.detail
        assert "authenticated" in f.detail
        # mode token with no config token: stays the PASS it was
        g = check_gateway(_ctx(TOKEN_NO_TOKEN, "2026.10.2", **src))
        assert g.status == PASS, g.detail


def test_a_legacy_root_token_string_keeps_the_pass_for_mode_token():
    cfg = {"gateway": {"bind": "lan", "auth": {"mode": "token"}, "token": _LONG}}
    assert check_gateway(_ctx(cfg, "2026.10.2")).status == PASS


def test_an_open_channel_still_fails_beside_the_refused_start_note():
    # the channel leg decides the status; the refused-start note rides along in the detail
    cfg = dict(NO_CREDENTIAL, channels={"telegram": {"dmPolicy": "open"}})
    f = check_gateway(_ctx(cfg, "2026.10.2"))
    assert f.status == FAIL
    assert _REFUSES in f.detail
    assert "open dm/group policy" in f.detail


# Configs outside the run whitelist: the real CLI starts them, rejects them at config load, or
# they differ from the run shape in some way (see `_CLI_SHAPES` for what the CLI did).
_REMOTE_TOKEN = {"token": _LONG}
_NOT_THE_RUN_SHAPE = {
    "remote-token-no-auth": {"gateway": {"bind": "lan", "remote": _REMOTE_TOKEN}},
    "remote-password-no-auth": {"gateway": {"bind": "lan", "remote": {"password": _LONG}}},
    "remote-token-mode-token": {
        "gateway": {"bind": "lan", "auth": {"mode": "token"}, "remote": _REMOTE_TOKEN}},
    "tailscale-serve-no-auth": {"gateway": {"bind": "lan", "tailscale": {"mode": "serve"}}},
    "tailscale-funnel-no-auth": {"gateway": {"bind": "lan", "tailscale": {"mode": "funnel"}}},
    "tailscale-serve-mode-token": {
        "gateway": {"bind": "lan", "auth": {"mode": "token"}, "tailscale": {"mode": "serve"}}},
    "tailscale-funnel-mode-token": {
        "gateway": {"bind": "lan", "auth": {"mode": "token"}, "tailscale": {"mode": "funnel"}}},
    "tailscale-templated": {"gateway": {"bind": "lan", "tailscale": {"mode": "${TS_MODE}"}}},
    "gateway-mode-remote": {"gateway": {"bind": "lan", "mode": "remote"}},
    "remote-url-only": {"gateway": {"bind": "lan", "remote": {"url": "wss://h.example/ws"}}},
    "bind-0000": _gw("0.0.0.0"),
    "bind-0000-mode-token": _gw("0.0.0.0", mode="token"),
    "bind-custom": _gw("custom"),
    "bind-tailnet": _gw("tailnet"),
    "legacy-root-token": {"gateway": {"bind": "lan", "token": _LONG}},
    "password-no-mode": _gw(password=_LONG),
    "password-with-mode-token": _gw(mode="token", password=_LONG),
    "blank-token": _gw(token=""),
    "rate-limit-only": _gw(rateLimit={"maxAttempts": 3}),
    "allow-tailscale": _gw(allowTailscale=True),
    "trusted-proxy-block-no-mode": _gw(trustedProxy={"userHeader": "x-user"}),
    "mode-trusted-proxy": _gw(mode="trusted-proxy"),
    "mode-password": _gw(mode="password"),
    "mode-empty-string": _gw(mode=""),
    "auth-not-an-object": {"gateway": {"bind": "lan", "auth": "token"}},
}


@pytest.mark.parametrize("name", sorted(_NOT_THE_RUN_SHAPE))
@pytest.mark.parametrize("build", ["2026.9.6", "2026.10.2"])
def test_a_shape_outside_the_run_whitelist_never_gets_the_refused_start_reading(name, build):
    cfg = _NOT_THE_RUN_SHAPE[name]
    measured, unknown = check_gateway(_ctx(cfg, build)), check_gateway(_ctx(cfg, None))
    for f in (measured, unknown):
        assert _REFUSES not in _unconfirmed(f), name
        assert "refuse to start" not in _unconfirmed(f), name
        assert "generated" not in _unconfirmed(f), name
    # the measured build changes NOTHING for these shapes: status, detail, fix and evidence
    key = lambda f: (f.status, f.detail, f.fix, tuple(f.evidence))  # noqa: E731
    assert key(measured) == key(unknown), name
    b_measured, b_unknown = (check_gateway_rate_limit(_ctx(cfg, b)) for b in (build, None))
    assert key(b_measured) == key(b_unknown), name


def test_funnel_stays_a_fail_and_says_nothing_about_a_refused_start():
    for name in ("tailscale-funnel-no-auth", "tailscale-funnel-mode-token"):
        f = check_gateway(_ctx(_NOT_THE_RUN_SHAPE[name], "2026.10.2"))
        assert f.status == FAIL
        assert "gateway.tailscale.mode=funnel exposes the gateway publicly" in f.detail
        assert "refuse to start" not in f.detail


def test_a_remote_token_keeps_the_old_verdicts_and_gets_no_refusal_claim():
    # no auth block: the no-credential FAIL; with mode token: the PASS it always was
    f = check_gateway(_ctx(_NOT_THE_RUN_SHAPE["remote-token-no-auth"], "2026.10.2"))
    assert (f.status, f.detail) == (FAIL, _FAIL_DETAIL)
    assert "generated" not in f.fix
    g = check_gateway(_ctx(_NOT_THE_RUN_SHAPE["remote-token-mode-token"], "2026.10.2"))
    assert g.status == PASS


def test_the_whitelist_edges_that_do_stay_a_warn():
    ok = {
        "auth block absent": _gw(),
        "auth block empty": _gw(**{}),
        "mode null": {"gateway": {"bind": "lan", "auth": {"mode": None}}},
        "tailscale off": {"gateway": {"bind": "lan", "tailscale": {"mode": "off"}}},
        "tailscale block without a mode": {"gateway": {"bind": "lan", "tailscale": {}}},
        "gateway.mode local": {"gateway": {"bind": "lan", "mode": "local"}},
        "empty remote block": {"gateway": {"bind": "lan", "remote": {}}},
    }
    for name, cfg in ok.items():
        f = check_gateway(_ctx(cfg, "2026.10.2"))
        assert f.status == WARN and _REFUSES in f.detail, name


# ------------------------------------------------------------------------------------------ B80


@pytest.mark.parametrize("build", _MEASURED)
@pytest.mark.parametrize("cfg", [NO_CREDENTIAL, TOKEN_NO_TOKEN], ids=["no-mode", "token-no-token"])
def test_b80_reads_the_two_equivalent_configs_the_same_way(cfg, build):
    f = check_gateway_rate_limit(_ctx(cfg, build))
    assert f.status == WARN
    assert "rateLimit" in f.detail


def test_b80_hedges_the_refused_start_for_the_no_mode_cell():
    f = check_gateway_rate_limit(_ctx(NO_CREDENTIAL, "2026.10.2"))
    text = " ".join(f.evidence)
    assert "refuse to start this gateway" in text
    assert "a non-loopback bind needs a configured token or password" in text
    assert "unless an environment or start-up flag this audit cannot see supplies one" in text
    assert "authenticates the gateway" not in text and "generates" not in text


def test_b80_with_a_rate_limit_is_a_pass_on_a_measured_build():
    cfg = {"gateway": {"bind": "lan", "auth": {"mode": "token", "rateLimit": {"maxAttempts": 5}}}}
    assert check_gateway_rate_limit(_ctx(cfg, "2026.10.2")).status == PASS


def test_b80_rate_limit_without_a_mode_is_outside_the_executed_shape():
    # an auth block that holds more than the mode is not the executed shape: today's answer
    cfg = {"gateway": {"bind": "lan", "auth": {"rateLimit": {"maxAttempts": 5}}}}
    assert check_gateway_rate_limit(_ctx(cfg, "2026.10.2")).status == UNKNOWN


@pytest.mark.parametrize("build", _UNMEASURED)
def test_b80_on_an_unmeasured_build_is_what_it_was(build):
    # no environment evidence readable -> UNKNOWN, as before
    assert check_gateway_rate_limit(_ctx(NO_CREDENTIAL, build)).status == UNKNOWN
    assert check_gateway_rate_limit(_ctx(TOKEN_NO_TOKEN, build)).status == WARN


@pytest.mark.parametrize("build", _MEASURED + _UNMEASURED)
def test_b80_explicit_none_is_unchanged(build):
    assert check_gateway_rate_limit(_ctx(EXPLICIT_NONE, build)).status == PASS


# ------------------------------------------------------------ LOCAL-ONLY: run the real CLI

_BIND_REFUSAL = "Refusing to bind gateway to lan without auth"
_PAST_PREFLIGHT = "[gateway] starting..."   # logged right after the pre-flight passes
_RUNTIME_TOKEN = "Generated a runtime token"

#: label -> (config, extra environment, expected outcome). Every config gets ``mode: "local"``
#: unless the label says otherwise. Outcomes: ``("refused", fragment)`` - exit 78 and the
#: fragment on the output; ``("started", marker)`` - the process got past the pre-flight and
#: logged the marker, then was killed. The first group is the whitelist, the rest are the
#: controls that bound it.
_CLI_SHAPES = {
    "no-credential": ({"bind": "lan"}, {}, ("refused", _BIND_REFUSAL)),
    "token-no-token": ({"bind": "lan", "auth": {"mode": "token"}}, {}, ("refused", _BIND_REFUSAL)),
    "auth-empty": ({"bind": "lan", "auth": {}}, {}, ("refused", _BIND_REFUSAL)),
    "tailscale-off-remote-empty": (
        {"bind": "lan", "tailscale": {"mode": "off"}, "remote": {}}, {}, ("refused", _BIND_REFUSAL)),
    "no-gateway-mode": ({"bind": "lan", "mode": None}, {}, ("refused", "missing gateway.mode")),
    # explicit none and a blank token are refused too, and stay outside the whitelist
    "explicit-none": ({"bind": "lan", "auth": {"mode": "none"}}, {}, ("refused", _BIND_REFUSAL)),
    "blank-token": ({"bind": "lan", "auth": {"token": ""}}, {}, ("refused", _BIND_REFUSAL)),
    # rejected at config load: not the pre-flight at all
    "tailscale-serve": (
        {"bind": "lan", "tailscale": {"mode": "serve"}}, {}, ("refused", "must resolve to loopback")),
    "legacy-root-token": ({"bind": "lan", "token": _LONG}, {}, ("refused", "Unrecognized key")),
    # a configured credential, or a loopback bind, gets past the pre-flight
    "token-literal": (
        {"bind": "lan", "auth": {"mode": "token", "token": _LONG}}, {}, ("started", _PAST_PREFLIGHT)),
    "password": (
        {"bind": "lan", "auth": {"mode": "password", "password": _LONG}}, {},
        ("started", _PAST_PREFLIGHT)),
    "password-no-mode": (
        {"bind": "lan", "auth": {"password": _LONG}}, {}, ("started", _PAST_PREFLIGHT)),
    "remote-token-only": (
        {"bind": "lan", "remote": {"token": _LONG}}, {}, ("started", _PAST_PREFLIGHT)),
    "env-token": (
        {"bind": "lan"}, {"OPENCLAW_GATEWAY_TOKEN": _LONG}, ("started", _PAST_PREFLIGHT)),
    "loopback": ({"bind": "loopback"}, {}, ("started", _RUNTIME_TOKEN)),
}

#: Labels whose real outcome depends on an environment the audit cannot see: the package's
#: hedge ("unless an environment or start-up flag ... supplies a token") covers them.
_ENV_SUPPLIED = {"env-token"}


def _package_config(label: str) -> dict:
    gw, _env, _outcome = _CLI_SHAPES[label]
    gw = {k: v for k, v in gw.items() if not (k == "mode" and v is None)}
    if "mode" not in _CLI_SHAPES[label][0]:
        gw["mode"] = "local"
    return {"gateway": gw}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _gateway_cli(node: str, entry: str, scratch, label: str) -> dict:
    """``openclaw gateway run`` in a throwaway HOME with a clean environment. Stops as soon as the
    outcome is known (the process exited, or the success marker was logged) and kills the whole
    process group, so no gateway is ever left running."""
    gw, extra_env, (kind, marker) = _CLI_SHAPES[label]
    home = scratch / label
    (home / "state").mkdir(parents=True)
    cfg = {"gateway": {k: v for k, v in gw.items() if not (k == "mode" and v is None)}}
    if "mode" not in gw:
        cfg["gateway"]["mode"] = "local"
    config = home / "openclaw.json"
    config.write_text(json.dumps(cfg), encoding="utf-8")
    config.chmod(0o600)
    env = {
        "PATH": os.path.dirname(node), "HOME": str(home), "LANG": "C",
        "OPENCLAW_STATE_DIR": str(home / "state"), "OPENCLAW_CONFIG_PATH": str(config),
        **extra_env,
    }
    proc = subprocess.Popen(
        [node, entry, "gateway", "run", "--port", str(_free_port())],
        env=env, cwd=str(home), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,
    )
    lines: list = []
    seen = threading.Event()

    def pump() -> None:
        for line in proc.stdout:
            lines.append(line)
            if kind == "started" and marker in line:
                seen.set()

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline and proc.poll() is None and not seen.is_set():
            time.sleep(0.2)
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
        reader.join(timeout=5)
    text = "".join(lines)
    return {"exit": proc.returncode, "text": text, "marker_seen": seen.is_set()}


@pytest.fixture(scope="module")
def real_cli(tmp_path_factory) -> dict:
    """Run the installed OpenClaw's real ``gateway run`` for every shape in `_CLI_SHAPES`."""
    from _distgrounding import OPENCLAW_DIST, require_dist

    require_dist()
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed - the real-CLI test needs it")
    entry = OPENCLAW_DIST.parent / "openclaw.mjs"
    assert entry.is_file(), f"the installed package has no {entry.name} next to its dist"
    version = json.loads((OPENCLAW_DIST.parent / "package.json").read_text(encoding="utf-8")).get(
        "version", "")
    scratch = tmp_path_factory.mktemp("c693-real-cli")
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            label: pool.submit(_gateway_cli, node, str(entry), scratch, label) for label in _CLI_SHAPES
        }
        results = {label: fut.result() for label, fut in futures.items()}
    return {"version": version, "rows": results}


def _read_range(real_cli: dict) -> None:
    parts = tuple(int(p) for p in re.findall(r"\d+", real_cli["version"].split("-")[0]))
    if not (len(parts) >= 3 and parts >= _B2_BIND_PREFLIGHT_READ_MIN):
        pytest.skip(f"installed OpenClaw {real_cli['version']} predates the read pre-flight")


def test_the_real_cli_refuses_or_starts_each_shape_as_the_matrix_assumes(real_cli):
    _read_range(real_cli)
    for label, (_gw_cfg, _env, (kind, fragment)) in _CLI_SHAPES.items():
        row = real_cli["rows"][label]
        if kind == "refused":
            assert row["exit"] == 78, (label, row["exit"], row["text"][-400:])
            assert fragment in row["text"], (label, row["text"][-400:])
        else:
            assert row["marker_seen"], (label, row["exit"], row["text"][-400:])
            assert fragment in row["text"], (label, row["text"][-400:])
            assert row["exit"] != 78, (label, row["text"][-400:])


def test_the_whitelisted_shapes_are_exactly_the_ones_the_real_cli_refuses_for_want_of_a_credential(
    real_cli,
):
    _read_range(real_cli)
    for label in ("no-credential", "token-no-token", "auth-empty",
                  "tailscale-off-remote-empty", "no-gateway-mode"):
        f = check_gateway(_ctx(_package_config(label), real_cli["version"]))
        assert f.status == WARN and _REFUSES in f.detail, (label, f.detail)
        assert real_cli["rows"][label]["exit"] == 78, label


def test_the_package_claims_a_refused_start_only_where_the_real_cli_refused(real_cli):
    _read_range(real_cli)
    claimed = []
    for label in _CLI_SHAPES:
        cfg = _package_config(label)
        for f in (
            check_gateway(_ctx(cfg, real_cli["version"])),
            check_gateway_rate_limit(_ctx(cfg, real_cli["version"])),
        ):
            if "refuse to start" in _unconfirmed(f):
                claimed.append(label)
                if label in _ENV_SUPPLIED:
                    continue  # the claim is hedged on an environment the audit cannot see
                assert real_cli["rows"][label]["exit"] == 78, (label, f.detail)
    # a vacuous pass would not be one: the claim IS made for the cells the ruling is about
    assert {"no-credential", "token-no-token"} <= set(claimed)
    # and never for a shape the real CLI starts on its own configuration
    started = {k for k, v in _CLI_SHAPES.items() if v[2][0] == "started"} - _ENV_SUPPLIED
    assert not (set(claimed) & started), sorted(set(claimed) & started)
