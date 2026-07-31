"""B340 (F-156): corroborate declared gateway.bind against the actual listening socket.

check_effective_bind (checks/_config.py) reads ctx.sockets (a sockets.SocketScanResult,
populated by audit(include_sockets=True) via sockets.scan_listening_sockets — see
tests/test_sockets.py for the parser itself). In hermetic/test mode ctx.sockets is None
-> UNKNOWN, exactly like ctx.host is None for B50-B54 (see tests/test_host_checks.py).

Offline, read-only: every socket state here is INJECTED via Context.sockets, never a
real /proc read or a real listening socket.

B-374 + B-387 (C-135 round 2, independent review, 2026-07-31) rewrote the attribution
and scoring semantics of the declared-loopback / effective-non-loopback branch:

* B-374 (attribution): the original C-135 bug-1 fix could only ever DOWNGRADE FAIL to
  WARN, and only on POSITIVE evidence a listener was something else -- any UNRESOLVED
  identity (no inode, permission denied, disagreeing names) kept the FAIL, which is
  itself an unproven guess in the FAIL direction (Golden Rule #5 forbids exactly
  this). Now the verdict stays FAIL only when at least one non-loopback listener is
  POSITIVELY confirmed to be the gateway itself (comm/cmdline actually names
  OpenClaw); everything else in that branch -- a positively-foreign process OR an
  unresolvable identity -- degrades to UNKNOWN, never WARN, never FAIL. This is a
  deliberate accepted false-negative trade: a real lying gateway whose /proc this
  reader cannot read now also reads UNKNOWN, not FAIL. Every existing FAIL test below
  that injects a ListenSocket with NO inode (or an inode nothing in the fake /proc
  owns, or a positively-non-OpenClaw process) therefore changes from FAIL to UNKNOWN
  -- that is this fix working as designed, not a regression.
* B-387 (scoring inversion): every PASS/WARN branch below now passes ``scored=False``
  explicitly -- B340 can only ever COST a scored point (the single FAIL branch,
  HIGH-capped), never EARN one. See test_widening_the_bind_never_improves_the_score
  below for the direct regression test.
"""
from __future__ import annotations

import os
from pathlib import Path

from clawseccheck.catalog import FAIL, HIGH, LOW, PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks import _config as _config_mod
from clawseccheck.checks import check_effective_bind
from clawseccheck.collector import Context, collect
from clawseccheck.scoring import compute
from clawseccheck.sockets import ListenSocket, SocketScanResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _make_pid(root, pid: str, fd_targets: dict, comm: "str | None" = None, cmdline: "bytes | None" = None):
    """Build a fake /proc/<pid>/fd + comm/cmdline under *root* -- same shape
    tests/test_sockets.py's own helper uses."""
    fd_dir = root / pid / "fd"
    fd_dir.mkdir(parents=True, exist_ok=True)
    for fd_num, target in fd_targets.items():
        os.symlink(target, fd_dir / str(fd_num))
    if comm is not None:
        (root / pid / "comm").write_text(comm, encoding="utf-8")
    if cmdline is not None:
        (root / pid / "cmdline").write_bytes(cmdline)


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
    assert r.scored is False


def test_bad_fixture_declared_loopback_effective_wildcard_is_unknown_without_attribution():
    # B-374: no inode was ever recorded for this synthetic listener, so the wildcard
    # listener can never be positively tied to the gateway process -- UNKNOWN, not
    # FAIL. See test_bad_fixture_with_positively_confirmed_gateway_still_fails below
    # for the shape that DOES still FAIL.
    ctx = collect(FIXTURES / "bad_b340_effective_bind_wildcard")
    ctx.sockets = _scan(ListenSocket(host="0.0.0.0", port=8765, family="inet"))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status != FAIL
    assert any("gateway.bind" in e for e in r.evidence)


def test_bad_fixture_with_positively_confirmed_gateway_still_fails(tmp_path):
    # Same fixture/socket shape as above, but this time the non-loopback listener's
    # inode resolves to a process whose cmdline names OpenClaw itself -- positive
    # confirmation, so the FAIL is preserved.
    _make_pid(
        tmp_path,
        "9999",
        {3: "socket:[42]"},
        comm="node\n",
        cmdline=b"/usr/bin/node\x00/home/user/.openclaw/dist/cli.js\x00",
    )
    ctx = collect(FIXTURES / "bad_b340_effective_bind_wildcard")
    ctx.sockets = _scan(ListenSocket(host="0.0.0.0", port=8765, family="inet", inode="42"))
    ctx.proc_root = str(tmp_path)
    r = check_effective_bind(ctx)
    assert r.status == FAIL
    assert "the config lies" in r.detail
    assert any("gateway.bind" in e for e in r.evidence)
    assert r.scored is True


# ---------------------------------------------------------------------------
# Fully enumerated verdict matrix (inline configs)
# ---------------------------------------------------------------------------

def test_declared_loopback_effective_loopback_is_pass():
    ctx = _ctx(_BASE, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == PASS
    assert r.scored is False


def test_declared_loopback_effective_wildcard_without_attribution_is_unknown():
    # B-374: no inode recorded at all -- attribution is impossible, so this can no
    # longer FAIL. See test_declared_loopback_effective_wildcard_confirmed_gateway_is_fail.
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status != FAIL


def test_declared_loopback_effective_wildcard_confirmed_gateway_is_fail(tmp_path):
    # B-374 acceptance test (b): a resolved process whose cmdline names OpenClaw is
    # POSITIVE evidence the gateway itself is lying -- the verdict table applies and
    # FAIL is preserved.
    _make_pid(
        tmp_path,
        "42",
        {3: "socket:[7]"},
        cmdline=b"/usr/bin/node\x00/opt/openclaw/dist/cli.js\x00",
    )
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="7")))
    ctx.proc_root = str(tmp_path)
    r = check_effective_bind(ctx)
    assert r.status == FAIL
    assert r.scored is True


def test_declared_loopback_effective_specific_lan_ip_without_attribution_is_unknown():
    # The motivating false-PASS scenario from the original task: config says loopback
    # but an env override/wrapper actually binds a real LAN interface, not just
    # 0.0.0.0. Without positive attribution this is now UNKNOWN, not FAIL (B-374).
    ctx = _ctx(_BASE, _scan(ListenSocket("192.168.1.5", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status != FAIL


def test_declared_wildcard_effective_loopback_is_warn():
    cfg = {"gateway": {"bind": "0.0.0.0:8765", "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == WARN
    assert "not currently exposed" in r.detail or "nothing is exposed" in r.detail
    assert r.scored is False


def test_declared_wildcard_effective_wildcard_is_pass():
    # Declared exposure is real -- B2/B70 already assess it; this check just confirms
    # reality matches the declaration, so it must not double-report the same exposure.
    cfg = {"gateway": {"bind": "0.0.0.0:8765", "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == PASS
    assert "already assessed by B2/B70" in r.detail
    assert r.scored is False


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


def test_mixed_loopback_and_wildcard_listeners_without_attribution_is_unknown():
    # Declared loopback, one of the matched listeners on the port is exposed -- but
    # with no attribution evidence at all, this is UNKNOWN (B-374), not an average.
    ctx = _ctx(
        _BASE,
        _scan(
            ListenSocket("127.0.0.1", 8765, "inet"),
            ListenSocket("0.0.0.0", 8765, "inet6"),
        ),
    )
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status != FAIL


# ---------------------------------------------------------------------------
# B-374 (C-135 round 2, independent review, 2026-07-31 -- live-reproduced on
# fixtures/home_safe by an unrelated Docker userland-proxy listener sharing the
# declared gateway port): declared-loopback / effective-non-loopback now degrades to
# UNKNOWN -- never WARN, never a kept FAIL -- unless at least one non-loopback
# listener is POSITIVELY confirmed to be the gateway process itself. Every OTHER FAIL
# test above/below injects a ListenSocket with no inode (the default "") -- attribution
# is a no-op ("unknown") for all of them, so they all now read UNKNOWN too.
# ---------------------------------------------------------------------------

def test_unrelated_process_on_same_port_is_unknown_not_warn_not_fail(tmp_path):
    # B-374 acceptance test (a): the exact real-world repro -- fixtures/home_safe
    # declares gateway.bind loopback on port 8080; Docker's userland proxy happens to
    # also listen on 0.0.0.0:8080, unrelated to the gateway. A POSITIVELY foreign
    # process is not evidence the gateway lied -- but it is also not proof it didn't,
    # so this is UNKNOWN, not WARN (the old downgrade) and not FAIL.
    _make_pid(tmp_path, "4242", {7: "socket:[8080001]"}, comm="docker-proxy\n")
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="8080001")))
    ctx.proc_root = str(tmp_path)
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status not in (FAIL, WARN)
    assert "docker-proxy" in r.detail


def test_bad_fixture_with_no_pid_info_is_now_unknown_not_fail():
    # B-374: the pre-existing bad fixture/test now reads UNKNOWN, not FAIL -- no
    # inode was ever recorded, so attribution cannot positively tie this listener to
    # the gateway, and "unattributable" is no longer treated as "keep the FAIL".
    ctx = collect(FIXTURES / "bad_b340_effective_bind_wildcard")
    ctx.sockets = _scan(ListenSocket(host="0.0.0.0", port=8765, family="inet"))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN


def test_unresolvable_pid_correlation_is_unknown_not_fail(tmp_path):
    # An inode is recorded, but nothing in the (fake) process table owns it -- PID
    # correlation is unavailable, so this is now UNKNOWN (B-374), not a kept FAIL.
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="999999")))
    ctx.proc_root = str(tmp_path)  # empty fake /proc -- no matching inode anywhere
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN


def test_bare_node_process_is_not_positive_gateway_evidence_so_unknown(tmp_path):
    # PID correlation succeeds, and the resolved process IS a Node.js process -- but
    # "node" alone (comm, no cmdline) cannot distinguish OpenClaw's own gateway
    # process from any other Node process on the box, so this is no longer treated
    # as positive gateway evidence (the retired _GATEWAY_PROCESS_MARKERS approach).
    # It is "foreign" (a specific, nameable, non-OpenClaw-named identity) -> UNKNOWN.
    _make_pid(tmp_path, "1111", {3: "socket:[555]"}, comm="node\n")
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="555")))
    ctx.proc_root = str(tmp_path)
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status != FAIL


def test_ambiguous_pid_correlation_is_unknown_not_fail(tmp_path):
    # Two different PIDs disagree on the name for the same inode -- genuinely
    # ambiguous, never resolved by guessing; this is UNKNOWN (B-374), not a kept FAIL.
    _make_pid(tmp_path, "111", {5: "socket:[555]"}, comm="docker-proxy\n")
    _make_pid(tmp_path, "222", {5: "socket:[555]"}, comm="nginx\n")
    ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="555")))
    ctx.proc_root = str(tmp_path)
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN


def test_one_unresolved_listener_among_several_is_unknown_not_fail(tmp_path):
    # Two non-loopback listeners match the port; one resolves to a confirmed foreign
    # process, the other is unresolved. NEITHER is positively confirmed as the
    # gateway, so this is UNKNOWN -- confirming FAIL requires at least one listener
    # positively tied to OpenClaw itself, not merely "not cleared as foreign".
    _make_pid(tmp_path, "4242", {7: "socket:[111]"}, comm="docker-proxy\n")
    ctx = _ctx(
        _BASE,
        _scan(
            ListenSocket("0.0.0.0", 8765, "inet", inode="111"),
            ListenSocket("192.168.1.5", 8765, "inet", inode="222"),  # no PID info at all
        ),
    )
    ctx.proc_root = str(tmp_path)
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN


def test_one_confirmed_gateway_listener_among_several_still_fails(tmp_path):
    # Mirror of the above: as soon as ONE non-loopback listener is positively
    # confirmed as the gateway itself, the FAIL fires regardless of what the other,
    # unrelated listener on the same port resolves to.
    _make_pid(tmp_path, "4242", {7: "socket:[111]"}, comm="docker-proxy\n")
    _make_pid(
        tmp_path,
        "9000",
        {3: "socket:[222]"},
        cmdline=b"/usr/bin/node\x00/home/user/.openclaw/dist/cli.js\x00",
    )
    ctx = _ctx(
        _BASE,
        _scan(
            ListenSocket("0.0.0.0", 8765, "inet", inode="111"),
            ListenSocket("192.168.1.5", 8765, "inet", inode="222"),
        ),
    )
    ctx.proc_root = str(tmp_path)
    r = check_effective_bind(ctx)
    assert r.status == FAIL
    assert r.scored is True


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


def test_mode_enum_bind_with_gateway_port_declared_loopback_effective_wildcard_is_unknown():
    # B-374: no attribution evidence -> UNKNOWN, not FAIL.
    ctx = _ctx(_MODE_ENUM_CFG, _scan(ListenSocket("0.0.0.0", 18789, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert r.status != FAIL


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
    assert r.scored is False


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


def test_gateway_port_out_of_range_high_is_not_a_valid_fallback():
    # B-374 follow-up (item 6): 65536 is one past the valid TCP port range -- the old
    # code accepted any positive int with no upper bound.
    cfg = {"gateway": {"bind": "loopback", "port": 70000}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert "not a valid TCP port" in r.detail


def test_embedded_bind_port_out_of_range_is_a_distinct_unknown():
    # gateway.bind NAMES a port substring, but it is out of range -- distinct message
    # from "no explicit port declared at all".
    cfg = {"gateway": {"bind": "127.0.0.1:70000", "auth": {"mode": "token", "token": "x" * 32}}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == UNKNOWN
    assert "not a valid TCP port" in r.detail
    assert "70000" in r.detail


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


# ---------------------------------------------------------------------------
# B-374 follow-up: Tailscale serve/funnel names the actual exposure reason in the
# declared-remote/effective-loopback WARN, instead of telling the owner to "set
# gateway.bind to loopback" when it plausibly already is (item 4/S7).
# ---------------------------------------------------------------------------

def test_tailscale_funnel_warn_names_tailscale_not_generic_bind_advice():
    cfg = {
        "gateway": {
            "bind": "loopback",
            "port": 18789,
            "tailscale": {"mode": "funnel"},
            "auth": {"mode": "token", "token": "x" * 32},
        }
    }
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 18789, "inet")))
    r = check_effective_bind(ctx)
    assert r.status == WARN
    assert "tailscale" in r.detail.lower()
    assert "funnel" in r.detail.lower()
    assert r.scored is False


# ---------------------------------------------------------------------------
# _parse_bind_port / _parse_bind_port_raw edge cases (B-374 follow-up, item 6):
# isdecimal() + try/except, and a validated 1-65535 range, so a malformed or
# out-of-range port substring degrades to None instead of raising or silently
# accepting an invalid port number.
# ---------------------------------------------------------------------------

def test_parse_bind_port_rejects_unicode_digit_that_isdigit_but_not_isdecimal():
    # "8080²" -- the superscript satisfies str.isdigit() but int() raises ValueError
    # on it; must degrade to None, never raise.
    assert _config_mod._parse_bind_port("127.0.0.1:8080²") is None


def test_parse_bind_port_rejects_zero():
    assert _config_mod._parse_bind_port("127.0.0.1:0") is None


def test_parse_bind_port_rejects_out_of_range_high():
    assert _config_mod._parse_bind_port("127.0.0.1:70000") is None


def test_parse_bind_port_accepts_max_valid_port():
    assert _config_mod._parse_bind_port("127.0.0.1:65535") == 65535


def test_parse_bind_port_raw_distinguishes_no_port_from_invalid_port():
    assert _config_mod._parse_bind_port_raw("127.0.0.1") is None
    assert _config_mod._parse_bind_port_raw("127.0.0.1:70000") == "70000"


# ---------------------------------------------------------------------------
# B-387 (C-135 round 2): scoring monotonicity -- widening the declared/effective
# bind must never IMPROVE the overall score. This is the direct regression test for
# the diagnosed inversion (a declared-remote config whose effective bind also read
# non-loopback used to score a full-weight PASS).
# ---------------------------------------------------------------------------

def _anchor() -> Finding:
    """A fixed, always-scored LOW PASS so compute()'s denominator is never zero --
    lets the two scenarios below be compared as plain numeric scores instead of both
    collapsing into the "nothing scorable" not-assessable sentinel."""
    return Finding("ZZZTEST", "anchor", LOW, PASS, "anchor", "anchor", "test", True)


def test_widening_the_bind_never_improves_the_score_declared_remote_effective_remote():
    # THE diagnosed inversion: a config that DECLARES a remote bind, whose effective
    # socket also reads non-loopback, used to score a full-weight PASS (widening the
    # bind swapped a capped FAIL for a full-weight PASS). Now it is scored=False --
    # it contributes nothing, so it can never outscore a tight, unattributable config.
    wide_cfg = {"gateway": {"bind": "0.0.0.0:8765", "auth": {"mode": "token", "token": "x" * 32}}}
    wide_ctx = _ctx(wide_cfg, _scan(ListenSocket("0.0.0.0", 8765, "inet")))
    wide_finding = check_effective_bind(wide_ctx)
    assert wide_finding.status == PASS
    assert wide_finding.scored is False

    tight_ctx = _ctx(_BASE, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    tight_finding = check_effective_bind(tight_ctx)
    assert tight_finding.status == PASS
    assert tight_finding.scored is False

    score_wide = compute([_anchor(), wide_finding]).score
    score_tight = compute([_anchor(), tight_finding]).score
    assert score_wide <= score_tight


def test_widening_the_effective_bind_never_improves_the_score_with_confirmed_attribution(tmp_path):
    # 127.0.0.1:8080 (tight, PASS/unscored) vs. 0.0.0.0:8080 with the listener
    # POSITIVELY confirmed as the gateway (wide, FAIL/scored, HIGH-capped): the wide
    # scenario must never score better than the tight one.
    _make_pid(
        tmp_path,
        "42",
        {3: "socket:[7]"},
        cmdline=b"/usr/bin/node\x00/opt/openclaw/dist/cli.js\x00",
    )
    tight_ctx = _ctx(_BASE, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    tight_finding = check_effective_bind(tight_ctx)
    assert tight_finding.status == PASS

    wide_ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet", inode="7")))
    wide_ctx.proc_root = str(tmp_path)
    wide_finding = check_effective_bind(wide_ctx)
    assert wide_finding.status == FAIL
    assert wide_finding.severity == HIGH

    score_wide = compute([_anchor(), wide_finding]).score
    score_tight = compute([_anchor(), tight_finding]).score
    assert score_wide <= score_tight
    assert score_wide < score_tight  # the confirmed-FAIL case must strictly cost something


def test_widening_the_effective_bind_without_attribution_never_improves_the_score(tmp_path):
    # Same comparison, but the wide listener's identity is unresolvable -- UNKNOWN,
    # not FAIL (B-374). Both scenarios are unscored, so the scores are equal --
    # equal still satisfies "never improves".
    tight_ctx = _ctx(_BASE, _scan(ListenSocket("127.0.0.1", 8765, "inet")))
    tight_finding = check_effective_bind(tight_ctx)
    assert tight_finding.status == PASS

    wide_ctx = _ctx(_BASE, _scan(ListenSocket("0.0.0.0", 8765, "inet")))
    wide_finding = check_effective_bind(wide_ctx)
    assert wide_finding.status == UNKNOWN

    score_wide = compute([_anchor(), wide_finding]).score
    score_tight = compute([_anchor(), tight_finding]).score
    assert score_wide <= score_tight
