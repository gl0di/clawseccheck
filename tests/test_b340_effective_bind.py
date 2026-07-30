"""B340 (F-156): corroborate declared gateway.bind against the actual listening socket.

check_effective_bind (checks/_config.py) reads ctx.sockets (a sockets.SocketScanResult,
populated by audit(include_sockets=True) via sockets.scan_listening_sockets — see
tests/test_sockets.py for the parser itself). In hermetic/test mode ctx.sockets is None
-> UNKNOWN, exactly like ctx.host is None for B50-B54 (see tests/test_host_checks.py).

Offline, read-only: every socket state here is INJECTED via Context.sockets, never a
real /proc read or a real listening socket.
"""
from __future__ import annotations

import os
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_effective_bind
from clawseccheck.collector import Context, collect
from clawseccheck.sockets import ListenSocket, SocketScanResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _make_pid(root, pid: str, fd_targets: dict, comm: "str | None" = None):
    """Build a fake /proc/<pid>/fd + comm under *root*, for the C-135 bug-1 PID
    correlation tests below -- same shape tests/test_sockets.py's own helper uses."""
    fd_dir = root / pid / "fd"
    fd_dir.mkdir(parents=True, exist_ok=True)
    for fd_num, target in fd_targets.items():
        os.symlink(target, fd_dir / str(fd_num))
    if comm is not None:
        (root / pid / "comm").write_text(comm, encoding="utf-8")


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
# C-135 bug 1 (independent review, 2026-07-30 -- live-reproduced on
# fixtures/home_safe by an unrelated Docker userland-proxy listener sharing the
# declared gateway port): declared-loopback / effective-non-loopback must downgrade
# to WARN, never FAIL, when the non-loopback listener positively, confidently
# resolves to a process that is NOT the gateway. Every OTHER FAIL test above/below
# injects a ListenSocket with no inode (the default "") -- PID correlation is a
# no-op for all of them (see test_sockets.py), so none of those FAILs are affected.
# ---------------------------------------------------------------------------

def test_unrelated_process_on_same_port_downgrades_fail_to_warn(tmp_path):
    # The exact real-world repro: fixtures/home_safe declares gateway.bind loopback
    # on port 8080; Docker's userland proxy happens to also listen on 0.0.0.0:8080,
    # unrelated to the gateway. Positive process-identity evidence must downgrade
    # this to WARN, not silently FAIL a correctly-hardened host.
    _make_pid(tmp_path, "4242", {7: "socket:[8080001]"}, comm="docker-proxy\n")
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="8080001")))
    ctx.proc_root = str(tmp_path)
    r = check_effective_bind(ctx)
    assert r.status == WARN
    assert r.status != FAIL
    assert "docker-proxy" in r.detail
    assert "not the gateway" in r.detail or "NOT the gateway" in r.detail


def test_bad_fixture_with_no_pid_info_still_fails():
    # The pre-existing bad fixture/test must be completely unaffected: no inode was
    # ever recorded for its synthetic listener, so PID correlation is a no-op and
    # the original FAIL behavior must survive this change exactly as before.
    ctx = collect(FIXTURES / "bad_b340_effective_bind_wildcard")
    ctx.sockets = _scan(ListenSocket(host="0.0.0.0", port=8765, family="inet"))
    r = check_effective_bind(ctx)
    assert r.status == FAIL


def test_unresolvable_pid_correlation_keeps_the_fail(tmp_path):
    # An inode is recorded, but nothing in the (fake) process table owns it -- PID
    # correlation is unavailable, so the conservative default (keep FAIL) applies.
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="999999")))
    ctx.proc_root = str(tmp_path)  # empty fake /proc -- no matching inode anywhere
    assert check_effective_bind(ctx).status == FAIL


def test_process_that_could_plausibly_be_the_gateway_keeps_the_fail(tmp_path):
    # PID correlation succeeds, but the resolved process is a Node.js process -- which
    # could plausibly BE the gateway itself (comm alone can't distinguish OpenClaw's
    # own node process from any other). Must never guess this away.
    _make_pid(tmp_path, "1111", {3: "socket:[555]"}, comm="node\n")
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="555")))
    ctx.proc_root = str(tmp_path)
    assert check_effective_bind(ctx).status == FAIL


def test_ambiguous_pid_correlation_keeps_the_fail(tmp_path):
    # Two different PIDs disagree on the name for the same inode -- genuinely
    # ambiguous, never resolved by guessing; must keep the FAIL.
    _make_pid(tmp_path, "111", {5: "socket:[555]"}, comm="docker-proxy\n")
    _make_pid(tmp_path, "222", {5: "socket:[555]"}, comm="nginx\n")
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="555")))
    ctx.proc_root = str(tmp_path)
    assert check_effective_bind(ctx).status == FAIL


def test_one_unresolved_listener_among_several_keeps_the_fail(tmp_path):
    # Two non-loopback listeners match the port; only ONE resolves to a confirmed
    # unrelated process. The other is unresolved, so the FAIL must be kept overall --
    # downgrading requires EVERY non-loopback listener to be positively cleared.
    _make_pid(tmp_path, "4242", {7: "socket:[111]"}, comm="docker-proxy\n")
    ctx = _ctx(
        _BASE,
        _scan(
            ListenSocket("0.0.0.0", 8765, "inet", inode="111"),
            ListenSocket("192.168.1.5", 8765, "inet", inode="222"),  # no PID info at all
        ),
    )
    ctx.proc_root = str(tmp_path)
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


# ---------------------------------------------------------------------------
# C-135 bug 2 (independent review, 2026-07-30): an ABSENT gateway.bind must resolve
# the SAME way as an explicit "auto" -- ambiguous/UNKNOWN -- because the vendor's own
# effective default for an absent bind resolves through the identical
# container-dependent path (grounded against net-BOKtNTf8.js's defaultGatewayBindMode).
# Must never silently fall through to "loopback" and then FAIL a container's correct
# 0.0.0.0 default.
# ---------------------------------------------------------------------------

def test_absent_bind_with_wildcard_effective_is_unknown_never_fail():
    # This exact shape (gateway.port set, no "bind" key at all) already exists in
    # fixtures/bad_c015_config_backup, fixtures/bad_c032_proxy_headers, and
    # fixtures/clean_c032_proxy_headers -- a real, non-hypothetical config shape.
    cfg = {"gateway": {"port": 18443, "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 18443, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status != FAIL


def test_absent_bind_with_loopback_effective_is_unknown_not_pass():
    # Also must not silently claim PASS -- same reasoning as bind="auto" above.
    cfg = {"gateway": {"port": 18443, "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 18443, "inet")))
    assert check_effective_bind(ctx).status == UNKNOWN


def test_empty_string_bind_is_ambiguous_like_absent():
    cfg = {"gateway": {"bind": "", "port": 18443, "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 18443, "inet")))
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
