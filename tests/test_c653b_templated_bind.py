"""C-653 (b) - a templated ``gateway.bind`` (``${VAR}`` / ``${VAR:-default}``) is not a host.

B11, B32, B80, B340 and B397 used to read the template text as a literal host:
``parse_bind_host`` lowercased it and split it at the first colon, so
``${GW_BIND:-loopback}`` became the host ``${gw_bind`` and the port ``-loopback}``. The five
checks now share ONE decision (``_effective_gateway_bind``): the variable's value when the
audit can see it (the gateway's persistent environment; the config's own env block only when
it is non-loopback, because the process environment overrides that block), else a
NON-loopback ``:-default``, else UNKNOWN naming the template verbatim. A visible LOOPBACK
value never clears the bind (the unit view is partial and the process environment decides).

Every resolved cell must be byte-identical to the same check on the equivalent LITERAL bind
(the property that proves no new reading was invented); every unresolved cell is UNKNOWN,
EXCEPT where the bind cannot matter and the verdict is what it is on dev: B11 with
``gateway.tls.enabled`` and B80 with ``gateway.auth.rateLimit`` stay PASS, B32 with the
control-plane tools denied stays PASS and with ``auth.mode=none`` stays WARN. Those cells
are pinned at the end of the file.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _B32_CONTROL_PLANE_TOOLS,
    check_control_plane_mutation,
    check_effective_bind,
    check_gateway_portal_reach,
    check_gateway_rate_limit,
    check_tls,
)
from clawseccheck.collector import Context
from clawseccheck.sockets import ListenSocket, SocketScanResult

_CHECKS = {
    "B11": check_tls,
    "B32": check_control_plane_mutation,
    "B80": check_gateway_rate_limit,
    "B340": check_effective_bind,
    "B397": check_gateway_portal_reach,
}

_BINDS = [
    "${GW_BIND}",
    "${GW_BIND:-loopback}",
    "${GW_BIND:-lan}",
    "${GW_BIND:-0.0.0.0:8080}",
    "$GW_BIND",
    "${GW_BIND:-}",
]
_EVIDENCE = ["none", "block_lan", "block_loopback", "unit_lan", "unit_loopback"]


def _ctx(bind, evidence="none", tmp=Path("/nonexistent")) -> Context:
    cfg = {
        "meta": {"lastTouchedVersion": "2026.9.6"},
        "gateway": {
            "mode": "local",
            "port": 18789,
            "bind": bind,
            "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
            "tailscale": {"mode": "off"},
        },
        "tools": {"profile": "coding"},
    }
    if evidence == "block_lan":
        cfg["env"] = {"vars": {"GW_BIND": "lan"}}
    elif evidence == "block_loopback":
        cfg["env"] = {"vars": {"GW_BIND": "loopback"}}
    ctx = Context(home=tmp, config=cfg, config_found=True, config_mode=0o600)
    unit_value = {"unit_lan": "lan", "unit_loopback": "loopback"}.get(evidence)
    if unit_value:
        ctx.unit_env_values = {"GW_BIND": unit_value}
        ctx.unit_env_sources = {"GW_BIND": "openclaw-gateway.service"}
        ctx.unit_env_found = True
    # B340 reads injected sockets: a wildcard listener on the default gateway port.
    ctx.sockets = SocketScanResult(
        available=True, listeners=(ListenSocket(host="0.0.0.0", port=18789, family="inet"),)
    )
    return ctx


def _expected(bind, evidence):
    """The literal bind the shared rule must resolve *bind* to, or None for UNKNOWN."""
    if bind == "$GW_BIND":  # OpenClaw substitutes only ${...}: no host, no reference
        return None
    default = bind[len("${GW_BIND:-"):-1] if ":-" in bind else ""
    if evidence in ("block_lan", "unit_lan"):
        return "lan"
    if default and default != "loopback":
        return default
    return None


@pytest.mark.parametrize("evidence", _EVIDENCE)
@pytest.mark.parametrize("bind", _BINDS)
@pytest.mark.parametrize("cid", sorted(_CHECKS))
def test_templated_bind_matches_its_literal_or_is_unknown(cid, bind, evidence):
    got = _CHECKS[cid](_ctx(bind, evidence))
    want = _expected(bind, evidence)
    if want is None:
        assert got.status == UNKNOWN, (got.status, got.detail)
        assert bind in got.detail or any(bind in e for e in got.evidence)
    else:
        # Evidence for an unresolved cell is gone; a resolved cell is the literal's finding.
        control = _CHECKS[cid](_ctx(want))
        assert (got.status, got.detail) == (control.status, control.detail)
    blob = " ".join([got.detail, got.fix, *got.evidence])
    assert "not a valid TCP port" not in blob
    assert "${gw_bind" not in blob
    assert bind.lower() not in blob


@pytest.mark.parametrize("cid", sorted(_CHECKS))
def test_literal_controls_unchanged(cid):
    lan, loop, hostport = (_CHECKS[cid](_ctx(b)) for b in ("lan", "loopback", "127.0.0.1:8080"))
    assert lan.status == (WARN if cid != "B340" else lan.status)
    if cid != "B340":
        assert loop.status == PASS and hostport.status == PASS
    assert "${" not in lan.detail + loop.detail + hostport.detail


def test_a_visible_loopback_value_never_clears_the_bind():
    # Unit, dotenv-less: the persistent view is partial, so loopback there is "not seen".
    for evidence in ("unit_loopback", "block_loopback"):
        for cid in sorted(_CHECKS):
            got = _CHECKS[cid](_ctx("${GW_BIND}", evidence))
            assert got.status == UNKNOWN, (cid, evidence, got.status)
            assert "${GW_BIND}" in got.detail or any("${GW_BIND}" in e for e in got.evidence)
    got = check_tls(_ctx("${GW_BIND}", "unit_loopback"))
    assert "partial" in got.detail
    # A non-loopback default still applies when only a loopback value is visible.
    for cid in sorted(_CHECKS):
        control = _CHECKS[cid](_ctx("lan"))
        got = _CHECKS[cid](_ctx("${GW_BIND:-lan}", "unit_loopback"))
        assert (got.status, got.detail) == (control.status, control.detail), cid


def test_an_env_value_that_is_itself_a_template_is_unresolved():
    ctx = _ctx("${GW_BIND}", "none")
    ctx.unit_env_values = {"GW_BIND": "${OTHER}"}
    from clawseccheck.checks._shared import _effective_gateway_bind

    assert _effective_gateway_bind(ctx, ctx.config, "${GW_BIND}")[0] is None


@pytest.mark.parametrize("raw", ["x${GW_BIND}", "${gw_bind}", "${GW_BIND:-${X}}", "${GW_BIND"])
def test_embedded_or_malformed_template_is_unresolved(raw):
    from clawseccheck.checks._shared import _effective_gateway_bind

    ctx = _ctx(raw)
    value, note = _effective_gateway_bind(ctx, ctx.config, raw)
    assert value is None and raw in note
    for cid in _CHECKS:
        assert _CHECKS[cid](ctx).status == UNKNOWN, cid


def test_b11_unresolved_bind_still_reports_loose_permissions():
    ctx = _ctx("${GW_BIND}")
    ctx.config_mode = 0o644
    got = check_tls(ctx)
    assert got.status == WARN and "group/world-readable" in got.detail
    assert "${GW_BIND}" in got.detail


def test_exposure_that_does_not_depend_on_the_bind_is_still_reported():
    # B32: auth.mode=none exposes the gateway whatever the bind is.
    ctx = _ctx("${GW_BIND}")
    ctx.config["gateway"]["auth"] = {"mode": "none"}
    assert check_control_plane_mutation(ctx).status == WARN
    # B80: rate limiting configured clears the finding whatever the bind is.
    ctx = _ctx("${GW_BIND}")
    ctx.config["gateway"]["auth"]["rateLimit"] = {"maxAttempts": 5}
    assert check_gateway_rate_limit(ctx).status == PASS
    # B32: control-plane tools denied clears it whatever the bind is.
    ctx = _ctx("${GW_BIND}")
    ctx.config["gateway"]["tools"] = {
        "deny": sorted(_B32_CONTROL_PLANE_TOOLS)
    }
    assert check_control_plane_mutation(ctx).status == PASS


def test_exposure_that_does_not_depend_on_the_bind_b11_tls_stays_pass():
    ctx = _ctx("${GW_BIND}")
    ctx.config["gateway"]["tls"] = {"enabled": True}
    assert check_tls(ctx).status == PASS


# --- collected homes: the unit view is partial (C-135), so loopback never clears ----------

def _collected(tmp_path, units, bind="${GW_BIND}"):
    """A real collected home: ~/.openclaw/openclaw.json plus ~/.config/systemd/user units."""
    import json
    import os

    from clawseccheck.collector import collect

    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = _ctx(bind).config
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(home / "openclaw.json", 0o600)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    for name, body in units.items():
        if name.endswith(".conf"):  # a drop-in directory the collector does not read
            d = unit_dir / name.rsplit("/", 1)[0]
            d.mkdir()
            (unit_dir / name).write_text(body, encoding="utf-8")
        else:
            (unit_dir / name).write_text(
                "[Unit]\nDescription=OpenClaw\n\n[Service]\n"
                "ExecStart=/usr/bin/openclaw gateway run\n" + body + "\n", encoding="utf-8"
            )
    ctx = collect(home)
    ctx.sockets = _ctx("lan").sockets
    return ctx


_S4 = {
    "openclaw-gateway.service": "Environment=GW_BIND=loopback",
    "openclaw-gateway.service.d/override.conf": "[Service]\nEnvironment=GW_BIND=lan\n",
}
_S5 = {
    "openclaw-gateway.service": "Environment=GW_BIND=lan",
    "openclaw-helper.service": "Environment=GW_BIND=loopback",
}
_S6 = {"openclaw-gateway.service": "Environment=GW_BIND=lan"}


@pytest.mark.parametrize("cid", sorted(_CHECKS))
@pytest.mark.parametrize("units", [_S4, _S5], ids=["s4_dropin_invisible", "s5_units_overwrite"])
def test_partial_unit_view_with_loopback_is_unknown_never_pass(cid, units, tmp_path):
    ctx = _collected(tmp_path, units)
    assert ctx.unit_env_values.get("GW_BIND") == "loopback"  # the view the audit really has
    got = _CHECKS[cid](ctx)
    assert got.status == UNKNOWN, (cid, got.status, got.detail)
    assert "${GW_BIND}" in " ".join([got.detail, *got.evidence])


@pytest.mark.parametrize("cid", sorted(_CHECKS))
def test_unit_that_sets_lan_is_the_literal_lan(cid, tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "l").mkdir()
    got = _CHECKS[cid](_collected(tmp_path / "t", _S6))
    control = _CHECKS[cid](_collected(tmp_path / "l", {}, bind="lan"))
    assert (got.status, got.detail) == (control.status, control.detail)
    if cid != "B340":
        assert got.status == WARN


# --- the other readers of gateway.bind use the same rule ----------------------------------

def _mdns_ctx(bind, evidence="none"):
    ctx = _ctx(bind, evidence)
    ctx.config["discovery"] = {"mdns": {"mode": "full"}}
    return ctx


def _blob(f):
    return " ".join([f.detail, f.fix, *f.evidence])


def test_b73_templated_bind():
    from clawseccheck.checks import check_discovery_mdns_mode  # noqa: PLC0415

    unres = check_discovery_mdns_mode(_mdns_ctx("${GW_BIND}"))
    assert unres.status == UNKNOWN and "${GW_BIND}" in unres.detail
    assert "${gw_bind" not in _blob(unres)
    lan = check_discovery_mdns_mode(_mdns_ctx("${GW_BIND:-lan}"))
    assert lan.status == WARN and "gateway.bind host='lan'" in _blob(lan)
    assert check_discovery_mdns_mode(_mdns_ctx("${GW_BIND}", "unit_lan")).status == WARN
    assert check_discovery_mdns_mode(_mdns_ctx("${GW_BIND}", "unit_loopback")).status == UNKNOWN
    assert check_discovery_mdns_mode(_mdns_ctx("loopback")).status == PASS


def test_b70_templated_bind():
    from clawseccheck.checks import check_trustedproxy_loopback  # noqa: PLC0415

    def ctx_for(bind, evidence="none"):
        ctx = _ctx(bind, evidence)
        ctx.config["gateway"]["auth"] = {"mode": "trusted-proxy"}
        return ctx

    unres = check_trustedproxy_loopback(ctx_for("${GW_BIND}"))
    assert unres.status == UNKNOWN and "${GW_BIND}" in unres.detail
    assert "${gw_bind" not in _blob(unres)
    assert check_trustedproxy_loopback(ctx_for("${GW_BIND:-lan}")).status == WARN
    assert check_trustedproxy_loopback(ctx_for("${GW_BIND}", "unit_lan")).status == WARN
    assert check_trustedproxy_loopback(ctx_for("lan")).status == WARN
    assert check_trustedproxy_loopback(ctx_for("loopback")).status == PASS


def test_b350_and_http_reach_templated_bind():
    from clawseccheck.checks import check_gateway_operator_terminal  # noqa: PLC0415
    from clawseccheck.checks._config import _gateway_http_reach  # noqa: PLC0415

    for bind, evidence in [("${GW_BIND}", "none"), ("${GW_BIND}", "unit_loopback"), ("$GW_BIND", "none")]:
        ctx = _ctx(bind, evidence)
        ctx.config["gateway"]["terminal"] = {"enabled": True}
        got = check_gateway_operator_terminal(ctx)
        assert bind in got.detail and "${gw_bind" not in _blob(got) and "$gw_bind" not in _blob(got)
        reach = _gateway_http_reach(ctx.config, "this endpoint", ctx)
        assert bind in reach and "not established" in reach
    # resolved: byte-identical to the literal it stands for
    ctx = _ctx("${GW_BIND}", "unit_lan")
    ctx.config["gateway"]["terminal"] = {"enabled": True}
    lit = _ctx("lan")
    lit.config["gateway"]["terminal"] = {"enabled": True}
    assert check_gateway_operator_terminal(ctx).detail == check_gateway_operator_terminal(lit).detail
    assert _gateway_http_reach(ctx.config, "x", ctx) == _gateway_http_reach(lit.config, "x", lit)


def test_remote_exposure_reason_names_the_template_verbatim():
    from clawseccheck.checks import _gateway_remote_exposure_reason  # noqa: PLC0415

    got = _gateway_remote_exposure_reason({"gateway": {"bind": "${GW_BIND:-loopback}"}})
    assert got == "gateway.bind=${GW_BIND:-loopback}"
