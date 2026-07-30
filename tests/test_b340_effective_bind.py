"""B340 (F-156): corroborate declared gateway.bind against the actual listening socket.

check_effective_bind (checks/_config.py) reads ctx.sockets (a sockets.SocketScanResult,
populated by audit(include_sockets=True) via sockets.scan_listening_sockets — see
tests/test_sockets.py for the parser itself). In hermetic/test mode ctx.sockets is None
-> UNKNOWN, exactly like ctx.host is None for B50-B54 (see tests/test_host_checks.py).

Offline, read-only: every socket state here is INJECTED via Context.sockets, never a
real /proc read or a real listening socket.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_effective_bind
from clawseccheck.collector import Context, collect
from clawseccheck.sockets import ListenSocket, SocketScanResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict, sockets=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.sockets = sockets
    return c


def _scan(*listeners: ListenSocket) -> SocketScanResult:
    return SocketScanResult(available=True, listeners=tuple(listeners))


_BASE = {
    "gateway": {"bind": "127.0.0.1:8765", "auth": {"mode": "token", "token": "x" * 32}},
}


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_declared_loopback_effective_loopback_passes():
    ctx = collect(FIXTURES / "clean_b340_effective_bind_loopback")
    ctx.sockets = _scan(ListenSocket(host="127.0.0.1", port=8765, family="inet"))
    r = check_effective_bind(ctx)
    assert r.status == PASS
    assert "corroborates B2" in r.detail


def test_bad_fixture_declared_loopback_effective_wildcard_fails():
    ctx = collect(FIXTURES / "bad_b340_effective_bind_wildcard")
    ctx.sockets = _scan(ListenSocket(host="0.0.0.0", port=8765, family="inet"))
    r = check_effective_bind(ctx)
    assert r.status == FAIL
    assert "the config lies" in r.detail
    assert any("gateway.bind" in e for e in r.evidence)


# ---------------------------------------------------------------------------
# Fully enumerated verdict matrix (inline configs)
# ---------------------------------------------------------------------------

def test_declared_loopback_effective_loopback_is_pass():
    ctx = _ctx(_BASE, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status == PASS


def test_declared_loopback_effective_wildcard_is_fail():
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == FAIL


def test_declared_loopback_effective_specific_lan_ip_is_fail():
    # The motivating false-PASS scenario from the task: config says loopback but an env
    # override/wrapper actually binds a real LAN interface, not just 0.0.0.0.
    ctx = _ctx(_BASE, _scan(ListenSocket("192.168.1.5", 8765, "inet")))
    assert check_effective_bind(ctx).status == FAIL


def test_declared_wildcard_effective_loopback_is_warn():
    cfg = {"gateway": {"bind": "0.0.0.0:8765", "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == WARN
    assert "not currently exposed" in r.detail or "nothing is exposed" in r.detail


def test_declared_wildcard_effective_wildcard_is_pass():
    # Declared exposure is real -- B2/B70 already assess it; this check just confirms
    # reality matches the declaration, so it must not double-report the same exposure.
    cfg = {"gateway": {"bind": "0.0.0.0:8765", "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == PASS
    assert "already assessed by B2/B70" in r.detail


def test_dual_stack_loopback_is_one_pass_not_two_findings():
    # F-156's explicit requirement: 127.0.0.1 + [::1] on the same port is the benign
    # dual-stack shape and must read as ONE corroborated PASS.
    ctx = _ctx(
        _BASE,
        _scan(
            ListenSocket("127.0.0.1", 8765, "inet"),
            ListenSocket("::1", 8765, "inet6"),
        ),
    )
    r = check_effective_bind(ctx)
    assert r.status == PASS


def test_mixed_loopback_and_wildcard_listeners_is_fail():
    # Declared loopback, but ONE of the matched listeners on the port is exposed -- any
    # non-loopback listener on the declared port is real exposure, must not average out.
    ctx = _ctx(
        _BASE,
        _scan(
            ListenSocket("127.0.0.1", 8765, "inet"),
            ListenSocket("0.0.0.0", 8765, "inet6"),
        ),
    )
    assert check_effective_bind(ctx).status == FAIL


# ---------------------------------------------------------------------------
# gateway.port fallback (C-135 finding): the CURRENT OpenClaw schema makes
# gateway.bind a bare mode enum (auto/lan/loopback/custom/tailnet) with the real
# port living in the sibling gateway.port field -- confirmed against a live
# ~/.openclaw/openclaw.json ("bind": "loopback", "port": 18789). Only the
# host:port-embedded shape (_BASE, above) is exercised by the tests before this.
# ---------------------------------------------------------------------------

_MODE_ENUM_CFG = {
    "gateway": {
        "bind": "loopback",
        "port": 18789,
        "auth": {"mode": "token", "token": "x" * 32},
    },
}


def test_mode_enum_bind_with_gateway_port_declared_loopback_effective_loopback_passes():
    ctx = _ctx(_MODE_ENUM_CFG, _scan(ListenSocket("127.0.0.1", 18789, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == PASS


def test_mode_enum_bind_with_gateway_port_declared_loopback_effective_wildcard_fails():
    ctx = _ctx(_MODE_ENUM_CFG, _scan(ListenSocket("0.0.0.0", 18789, "inet")))
    assert check_effective_bind(ctx).status == FAIL


def test_mode_enum_bind_lan_is_declared_non_loopback():
    cfg = {"gateway": {"bind": "lan", "port": 18789, "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 18789, "inet")))
    # declared="lan" (not in LOOPBACK) + effective=loopback -> WARN, never FAIL/PASS-silent.
    assert check_effective_bind(ctx).status == WARN


# ---------------------------------------------------------------------------
# C-135 finding: gateway.bind="auto" must NEVER false-FAIL. It resolves to
# loopback on bare metal but to 0.0.0.0 inside a container -- unknowable from the
# config alone -- so a naive LOOPBACK-membership test would misread a container's
# (correct) wildcard effective bind as "the config lied". Must degrade to UNKNOWN.
# ---------------------------------------------------------------------------

def test_bind_auto_with_wildcard_effective_is_unknown_never_fail():
    cfg = {"gateway": {"bind": "auto", "port": 18789, "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 18789, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status != FAIL


def test_bind_auto_with_loopback_effective_is_unknown_not_pass():
    # Also must not silently claim PASS -- the declared state genuinely isn't provable.
    cfg = {"gateway": {"bind": "auto", "port": 18789, "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 18789, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


def test_bind_custom_with_loopback_customBindHost_is_declared_loopback():
    cfg = {
        "gateway": {
            "bind": "custom",
            "customBindHost": "127.0.0.1",
            "port": 8765,
            "auth": {"mode": "token", "token": "x" * 32},
        }
    }
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status == PASS


def test_bind_custom_with_remote_customBindHost_is_declared_remote():
    cfg = {
        "gateway": {
            "bind": "custom",
            "customBindHost": "10.0.0.5",
            "port": 8765,
            "auth": {"mode": "token", "token": "x" * 32},
        }
    }
    ctx = _ctx(cfg, _scan(ListenSocket("10.0.0.5", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == PASS  # declared remote, effective matches -- already assessed by B2/B70


def test_bind_custom_with_invalid_customBindHost_is_ambiguous_unknown():
    cfg = {
        "gateway": {"bind": "custom", "port": 8765, "auth": {"mode": "token", "token": "x" * 32}}
    }
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 8765, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


def test_embedded_port_in_bind_is_preferred_over_gateway_port():
    # When gateway.bind DOES embed a port, that takes precedence over a (possibly
    # stale/unrelated) sibling gateway.port -- never silently prefer the other source.
    cfg = {
        "gateway": {
            "bind": "127.0.0.1:8765",
            "port": 9999,
            "auth": {"mode": "token", "token": "x" * 32},
        }
    }
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status == PASS


def test_gateway_port_zero_is_not_a_valid_fallback():
    cfg = {"gateway": {"bind": "loopback", "port": 0}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


def test_gateway_port_non_int_is_not_a_valid_fallback():
    cfg = {"gateway": {"bind": "loopback", "port": "not-a-number"}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


# ---------------------------------------------------------------------------
# UNKNOWN branches
# ---------------------------------------------------------------------------

def test_no_config_is_unknown():
    ctx = _ctx({}, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


def test_malformed_gateway_value_is_unknown():
    ctx = _ctx({"gateway": "not-an-object"}, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


def test_no_port_declared_is_unknown():
    cfg = {"gateway": {"bind": "127.0.0.1", "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


def test_sockets_not_scanned_is_unknown():
    # ctx.sockets is None by default (hermetic mode / include_sockets=False) -- must
    # never be silently treated as "nothing listening".
    ctx = _ctx(_BASE, sockets=None)
    assert check_effective_bind(ctx).status == UNKNOWN


def test_proc_unavailable_is_unknown():
    ctx = _ctx(_BASE, SocketScanResult(available=False, reason="neither table readable"))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert "neither table readable" in r.detail


def test_no_listener_on_declared_port_is_unknown():
    # Gateway not running (or listening on a different port): nothing to corroborate.
    ctx = _ctx(_BASE, _scan(ListenSocket("127.0.0.1", 9999, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


def test_empty_listener_table_is_unknown():
    ctx = _ctx(_BASE, _scan())
    assert check_effective_bind(ctx).status == UNKNOWN


# ---------------------------------------------------------------------------
# Regression: the competitor's peer-column bug must never surface here either
# ---------------------------------------------------------------------------

def test_loopback_listener_never_produces_fail():
    """A /proc-derived loopback listener corroborating a declared loopback bind must
    NEVER produce FAIL — pins the same guarantee sockets.py's own regression test
    makes, one layer up at the check level."""
    ctx = _ctx(_BASE, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    assert check_effective_bind(ctx).status != FAIL
