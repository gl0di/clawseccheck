"""C-693: a non-loopback gateway with NO credential is served behind a token the vendor generates
at start-up, so B2 must not call it "exposed" - and the two configs the vendor resolves to the
same runtime state must get the same answer.

Owner ruling (Dave, 2026-10-12), option (a) for BOTH cells:

* ``gateway.bind`` non-loopback with no ``gateway.auth.mode`` and no credential, and
* ``gateway.auth.mode: "token"`` with no token,

answer WARN - not FAIL, not PASS - on a build whose start-up generation was MEASURED
(``_B2_STARTUP_TOKEN_MEASURED_MIN``, 2026.9.6 and later), with a sentence saying the gateway
starts with a token generated at each start (not persisted) and that an explicit credential
should be set. An explicit ``mode: "none"`` stays the FAIL it always was, byte-identical
detail (the vendor refuses to bind it). On a build that is NOT measured (older, unknown, a
pre-release, no version) both cells keep today's verdict - FAIL and PASS - and the FAIL is
reworded (no "exposed", no Python literal "None").

The WARN is a WHITELIST of the exact shapes the vendor was executed on (a "lan" bind, an auth
block that is absent or holds only the mode, no token or password anywhere, no Tailscale
serve/funnel, no gateway.remote content, no trusted-proxy mode): every other shape - including
the ones the vendor REFUSES to start (a remote token, Tailscale serve or funnel) - keeps its
old status and says nothing about a generated token. The INSTALLED build alone decides; the
config's own version stamp is never read for this.

Two halves. The always-on half pins the matrix (shape x build). The local-only half EXECUTES
the vendor's ``ensureGatewayStartupAuth`` and ``assertGatewayRuntimeSecurityConfig`` from the
installed OpenClaw dist in node with an empty environment, so a future change of the start-up
behaviour is a red test here, and then asserts the package's answer for the very same configs:
a grep never proves behaviour (see ``tests/_distgrounding.py``). It is skipped, never
weakened, where node or the dist is absent.

Offline, read-only, stdlib only. Secret-shaped values are assembled at runtime.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_gateway, check_gateway_rate_limit
from clawseccheck.checks._config import (
    _B2_STARTUP_TOKEN_MEASURED_MIN,
    _gateway_startup_token,
)
from clawseccheck.collector import Context

_LONG = "t" * 40
_MEASURED = ["2026.9.6", "2026.9.7", "2026.9.9", "2026.10.1", "2026.10.2"]
# Not measured: older, unknown, no version, a version that is not a calendar release, a pre-release.
_UNMEASURED = [None, "2026.9.5", "2026.8.1", "2026.7.1", "0.0.0", "2026.10", "2026.10.2-beta.1"]

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
def test_measured_build_no_credential_cells_are_a_warn_about_a_generated_token(cfg, build):
    f = check_gateway(_ctx(cfg, build))
    assert f.status == WARN, f.detail
    assert "generates at each start" in f.detail
    assert "not persisted, so no client knows it" in f.detail
    assert "unless an environment this audit cannot see supplies a credential" in f.detail
    assert "not unauthenticated" not in f.detail and "authenticates the gateway" not in f.detail
    # the advice rides in fix
    assert "explicit credential" in f.fix
    assert "gateway.auth.token" in f.fix
    for text in (f.detail, f.fix):
        assert "exposed" not in text
        assert "None" not in text


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
    assert _B2_STARTUP_TOKEN_MEASURED_MIN == (2026, 9, 6)


@pytest.mark.parametrize("build", _MEASURED)
def test_installed_build_in_the_measured_range_is_generated(build):
    assert _gateway_startup_token(_ctx({}, build)) == "generated"


@pytest.mark.parametrize("build", _UNMEASURED)
def test_installed_build_outside_the_measured_range_is_unknown(build):
    assert _gateway_startup_token(_ctx({}, build)) == "unknown"


_STAMPS = ["2026.10.2", "2026.9.6", "2099.1.1"]


@pytest.mark.parametrize("stamp", _STAMPS)
def test_the_config_stamp_never_selects_the_generated_token_reading(stamp):
    meta = {"meta": {"lastTouchedVersion": stamp}}
    for build in (None, "garbage", "2026.10.2-beta.1", "2026.9.5", "2026.10"):
        assert _gateway_startup_token(_ctx(meta, build)) == "unknown", (stamp, build)
        a = check_gateway(_ctx(dict(NO_CREDENTIAL, **meta), build))
        b = check_gateway(_ctx(dict(TOKEN_NO_TOKEN, **meta), build))
        # exactly the answers a stamp-less config gets on that build: FAIL (reworded) and PASS
        assert (a.status, a.detail) == (FAIL, _FAIL_DETAIL), (stamp, build)
        assert (b.status, b.detail) == (PASS, check_gateway(_ctx(TOKEN_NO_TOKEN, build)).detail)
        assert check_gateway_rate_limit(_ctx(dict(NO_CREDENTIAL, **meta), build)).status == UNKNOWN


@pytest.mark.parametrize("stamp", [None, "2026.7.1", "2099.1.1"])
def test_an_installed_measured_build_decides_whatever_the_stamp_says(stamp):
    cfg = dict(NO_CREDENTIAL, meta={"lastTouchedVersion": stamp}) if stamp else NO_CREDENTIAL
    assert _gateway_startup_token(_ctx(cfg, "2026.10.2")) == "generated"
    assert check_gateway(_ctx(cfg, "2026.10.2")).status == WARN


# ----------------------------------------------- cases where "a token is generated" is NOT true


@pytest.mark.parametrize("build", _MEASURED)
def test_a_credential_anywhere_means_the_generated_token_claim_is_not_made(build):
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
        assert "generates at each start" not in _unconfirmed(f), name


@pytest.mark.parametrize("build", _MEASURED)
def test_the_two_shapes_that_stay_a_fail_keep_failing_on_a_measured_build(build):
    # no usable token / a password with no mode: these are the verdicts they had before
    for cfg in (_gw(token=""), _gw(password=_LONG)):
        f = check_gateway(_ctx(cfg, build))
        assert f.status == FAIL
        assert f.detail == _FAIL_DETAIL


@pytest.mark.parametrize("var", ["OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_PASSWORD"])
def test_an_environment_credential_in_a_persistent_artifact_clears_the_generated_reading(var):
    for src in ({"unit": {var: _LONG}}, {"dotenv": {var: _LONG}}):
        # no mode: the environment authenticates (the older, softer WARN) - never the new note
        f = check_gateway(_ctx(NO_CREDENTIAL, "2026.10.2", **src))
        assert f.status == WARN
        assert "generates at each start" not in f.detail
        assert "authenticated" in f.detail
        # mode token with no config token: stays the PASS it was
        g = check_gateway(_ctx(TOKEN_NO_TOKEN, "2026.10.2", **src))
        assert g.status == PASS, g.detail


def test_a_legacy_root_token_string_keeps_the_pass_for_mode_token():
    cfg = {"gateway": {"bind": "lan", "auth": {"mode": "token"}, "token": _LONG}}
    assert check_gateway(_ctx(cfg, "2026.10.2")).status == PASS


def test_an_open_channel_still_fails_beside_the_generated_token_note():
    # the channel leg decides the status; the generated-token note rides along in the detail
    cfg = dict(NO_CREDENTIAL, channels={"telegram": {"dmPolicy": "open"}})
    f = check_gateway(_ctx(cfg, "2026.10.2"))
    assert f.status == FAIL
    assert "generates at each start" in f.detail
    assert "open dm/group policy" in f.detail


# Configs the VENDOR REFUSES to start, or resolves to another mode, or that fall outside the
# executed shape (see `_REFUSED_BY_VENDOR` for what the executed start-up said about each).
_REMOTE_TOKEN = {"token": _LONG}
_NOT_THE_EXECUTED_SHAPE = {
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


@pytest.mark.parametrize("name", sorted(_NOT_THE_EXECUTED_SHAPE))
@pytest.mark.parametrize("build", ["2026.9.6", "2026.10.2"])
def test_a_shape_outside_the_executed_whitelist_never_gets_the_generated_token_reading(name, build):
    cfg = _NOT_THE_EXECUTED_SHAPE[name]
    measured, unknown = check_gateway(_ctx(cfg, build)), check_gateway(_ctx(cfg, None))
    for f in (measured, unknown):
        assert "generates at each start" not in _unconfirmed(f), name
        assert "generated" not in _unconfirmed(f), name
    # the measured build changes NOTHING for these shapes: status, detail, fix and evidence
    key = lambda f: (f.status, f.detail, f.fix, tuple(f.evidence))  # noqa: E731
    assert key(measured) == key(unknown), name
    b_measured, b_unknown = (check_gateway_rate_limit(_ctx(cfg, b)) for b in (build, None))
    assert key(b_measured) == key(b_unknown), name


def test_funnel_stays_a_fail_and_says_nothing_about_a_generated_token():
    for name in ("tailscale-funnel-no-auth", "tailscale-funnel-mode-token"):
        f = check_gateway(_ctx(_NOT_THE_EXECUTED_SHAPE[name], "2026.10.2"))
        assert f.status == FAIL
        assert "gateway.tailscale.mode=funnel exposes the gateway publicly" in f.detail
        assert "unauthenticated" not in f.detail and "token it generates" not in f.detail


def test_a_remote_token_keeps_the_old_verdicts_and_gets_no_generated_claim():
    # no auth block: the no-credential FAIL; with mode token: the PASS it always was
    f = check_gateway(_ctx(_NOT_THE_EXECUTED_SHAPE["remote-token-no-auth"], "2026.10.2"))
    assert (f.status, f.detail) == (FAIL, _FAIL_DETAIL)
    assert "generated" not in f.fix
    g = check_gateway(_ctx(_NOT_THE_EXECUTED_SHAPE["remote-token-mode-token"], "2026.10.2"))
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
        assert f.status == WARN and "generates at each start" in f.detail, name


# ------------------------------------------------------------------------------------------ B80


@pytest.mark.parametrize("build", _MEASURED)
@pytest.mark.parametrize("cfg", [NO_CREDENTIAL, TOKEN_NO_TOKEN], ids=["no-mode", "token-no-token"])
def test_b80_reads_the_two_equivalent_configs_the_same_way(cfg, build):
    f = check_gateway_rate_limit(_ctx(cfg, build))
    assert f.status == WARN
    assert "rateLimit" in f.detail


def test_b80_hedges_the_generated_token_for_the_no_mode_cell():
    f = check_gateway_rate_limit(_ctx(NO_CREDENTIAL, "2026.10.2"))
    text = " ".join(f.evidence)
    assert "generates at each start" in text
    assert "unless an environment this audit cannot see supplies a credential" in text
    assert "authenticates the gateway" not in text


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


# ------------------------------------------------------- LOCAL-ONLY: execute the vendor function

# The real start-up order (server-start): seed the Control-UI origins for a non-loopback bind
# mode, `ensureGatewayStartupAuth`, then `resolveGatewayRuntimeConfig` on the resulting config.
_HARNESS = r"""
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const payload = JSON.parse(readFileSync(0, "utf8"));
function bind(file, name) {
  const src = readFileSync(file, "utf8");
  const m = src.match(/export\s*\{([^}]*)\}/);
  for (const part of m[1].split(",")) {
    const mm = part.trim().match(/^(\w+)(?:\s+as\s+(\w+))?$/);
    if (mm && mm[1] === name) return mm[2] || mm[1];
  }
  throw new Error("no export " + name + " in " + file);
}
async function load(file, name) {
  return (await import(pathToFileURL(file).href))[bind(file, name)];
}
const seed = await load(payload.origins, "ensureControlUiAllowedOriginsForNonLoopbackBind");
const ensure = await load(payload.startup, "ensureGatewayStartupAuth");
const resolveRuntime = await load(payload.runtime, "resolveGatewayRuntimeConfig");
const out = {};
for (const [label, cfg] of Object.entries(payload.rows)) {
  const r = {};
  let ensured;
  try {
    const seeded = seed(cfg, { isContainerEnvironment: () => false, runtimePort: 18789 }).config;
    ensured = await ensure({ cfg: seeded, env: {} });
  } catch (e) {
    r.ensureThrows = String(e.message).slice(0, 200);
    r.started = false;
    out[label] = r;
    continue;
  }
  const token = ensured.auth.token || "";
  r.mode = ensured.auth.mode;
  r.tokenLen = token.length;
  r.tokenHex = /^[0-9a-f]{48}$/.test(token);
  r.generated = ensured.generatedToken !== undefined;
  r.persisted = ensured.persistedGeneratedToken;
  try {
    const rc = await resolveRuntime({ cfg: ensured.cfg, port: 18789 });
    r.started = true;
    r.bindHost = rc.bindHost;
  } catch (e) {
    r.started = false;
    r.startError = String(e.message).slice(0, 160);
  }
  out[label] = r;
}
process.stdout.write(JSON.stringify(out));
"""

# label -> (config, what the executed start-up said). The first six are the task's cells and
# controls; the rest are the shapes the independent review found the vendor REFUSES or reads
# as another mode - the WARN must never be claimed for them.
_LABELS = {
    "no-credential": NO_CREDENTIAL,
    "token-no-token": TOKEN_NO_TOKEN,
    "literal-token": LITERAL_TOKEN,
    "explicit-none": EXPLICIT_NONE,
    "password-no-mode": _gw(password=_LONG),
    "blank-token": _gw(token=""),
    **_NOT_THE_EXECUTED_SHAPE,
}

#: What the vendor does with each non-whitelisted shape on 2026.10.2 (a substring of the error,
#: or None when it STARTS). A change here is the upgrade signal this test exists to give.
_REFUSED_BY_VENDOR = {
    "remote-token-no-auth": "no token was configured",
    "remote-password-no-auth": "no token was configured",
    "remote-token-mode-token": "no token was configured",
    "tailscale-serve-no-auth": "requires gateway bind=loopback",
    "tailscale-funnel-no-auth": "funnel requires gateway auth mode=password",
    "tailscale-serve-mode-token": "requires gateway bind=loopback",
    "tailscale-funnel-mode-token": "funnel requires gateway auth mode=password",
    "bind-0000": "non-loopback Control UI requires gateway.controlUi.allowedOrigins",
    "bind-0000-mode-token": "non-loopback Control UI requires gateway.controlUi.allowedOrigins",
    "bind-custom": "requires gateway.customBindHost",
    "blank-token": "blank",
    "mode-trusted-proxy": "no trustedProxy config was provided",
    "mode-password": "no password was configured",
    "explicit-none": "refusing to bind gateway",
}


@pytest.fixture(scope="module")
def vendor(tmp_path_factory) -> dict:
    """Execute the installed dist's real start-up sequence on the configs above; ONE node run."""
    from _distgrounding import OPENCLAW_DIST, dist_declaring, dist_file, require_dist

    require_dist()
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed - the executing grounding test needs it")
    startup = dist_file(
        "startup-auth-*", symbol="ensureGatewayStartupAuth",
        contains="async function ensureGatewayStartupAuth(",
    )
    runtime = dist_declaring(
        "async function resolveGatewayRuntimeConfig(", symbol="resolveGatewayRuntimeConfig"
    )
    origins = dist_declaring(
        "function ensureControlUiAllowedOriginsForNonLoopbackBind(",
        symbol="ensureControlUiAllowedOriginsForNonLoopbackBind",
    )
    pkg = OPENCLAW_DIST.parent / "package.json"
    version = json.loads(pkg.read_text(encoding="utf-8")).get("version", "")
    scratch = tmp_path_factory.mktemp("c693-startup-auth")
    harness = scratch / "harness.mjs"
    harness.write_text(_HARNESS, encoding="utf-8")
    payload = json.dumps({
        "startup": str(startup), "runtime": str(runtime), "origins": str(origins),
        "rows": _LABELS,
    })
    proc = subprocess.run(
        [node, str(harness)], input=payload, capture_output=True, text=True,
        env={"HOME": str(scratch), "PATH": "", "LANG": "C"}, cwd=str(scratch), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-600:]
    return {"version": version, "rows": json.loads(proc.stdout)}


def _installed_is_measured(vendor: dict) -> bool:
    parts = tuple(int(p) for p in re.findall(r"\d+", vendor["version"].split("-")[0]))
    return len(parts) >= 3 and parts >= _B2_STARTUP_TOKEN_MEASURED_MIN


def _skip_unless_measured(vendor: dict) -> None:
    if not _installed_is_measured(vendor):
        pytest.skip(f"installed OpenClaw {vendor['version']} predates the measured threshold")


def test_vendor_generates_a_token_and_starts_for_both_no_credential_cells(vendor):
    _skip_unless_measured(vendor)
    for label in ("no-credential", "token-no-token"):
        row = vendor["rows"][label]
        assert row["mode"] == "token", (label, row)
        assert row["generated"] is True and row["persisted"] is False, (label, row)
        assert row["tokenLen"] == 48 and row["tokenHex"] is True, (label, row)
        assert row["started"] is True and row["bindHost"] == "0.0.0.0", (label, row)


def test_vendor_controls_behave_as_the_matrix_assumes(vendor):
    _skip_unless_measured(vendor)
    rows = vendor["rows"]
    # a configured token is used as given, never replaced
    assert rows["literal-token"]["generated"] is False
    assert rows["literal-token"]["tokenLen"] == len(_LONG)
    assert rows["literal-token"]["started"] is True
    # explicit mode none: no token, and the start-up REFUSES the non-loopback bind
    assert rows["explicit-none"]["mode"] == "none" and rows["explicit-none"]["generated"] is False
    # a password with no mode is its own mode: it starts, and NOT on a generated token
    assert rows["password-no-mode"]["mode"] == "password"
    assert rows["password-no-mode"]["generated"] is False


def test_vendor_refuses_or_reads_otherwise_each_shape_the_whitelist_excludes(vendor):
    _skip_unless_measured(vendor)
    rows = vendor["rows"]
    for label, fragment in _REFUSED_BY_VENDOR.items():
        row = rows[label]
        assert row["started"] is False, (label, row)
        assert fragment in (row.get("ensureThrows") or row.get("startError") or ""), (label, row)


def test_the_package_claims_a_generated_token_only_where_the_vendor_generates_and_starts(vendor):
    _skip_unless_measured(vendor)
    build = vendor["version"]
    claimed = []
    for label, cfg in _LABELS.items():
        row = vendor["rows"][label]
        for f in (check_gateway(_ctx(cfg, build)), check_gateway_rate_limit(_ctx(cfg, build))):
            if "generates at each start" in _unconfirmed(f):
                claimed.append(label)
                # soundness: every claim is backed by an executed generate-and-start
                assert row.get("generated") is True and row["started"] is True, (label, row)
    # and the claim IS made for the two cells the ruling is about (a vacuous pass would not be)
    assert {"no-credential", "token-no-token"} <= set(claimed)
    assert set(claimed) == {"no-credential", "token-no-token"}, claimed
    assert check_gateway(_ctx(NO_CREDENTIAL, build)).status == WARN
    assert check_gateway(_ctx(TOKEN_NO_TOKEN, build)).status == WARN
    assert check_gateway(_ctx(LITERAL_TOKEN, build)).status == PASS
    assert check_gateway(_ctx(EXPLICIT_NONE, build)).status == FAIL
