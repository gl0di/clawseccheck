"""B384 (F-197): corroborate desktop.host's always-loopback design assumption against the
actual listening socket on its resolved port.

Same offline/injected-state approach as tests/test_b340_effective_bind.py: ctx.sockets is
a sockets.SocketScanResult INJECTED via Context, never a real /proc read. ctx.proc_root
points at a synthetic tree built by `_make_pid` (identical helper shape to test_b340's)
when a test needs /proc/<pid>/exe correlation.

Re-grounding note the check's own module comment (clawseccheck/checks/_config.py, right
above `_DESKTOP_DEFAULT_VNC_PORT`) explains in full: unlike gateway.bind, the real
desktop.host schema has no host-restriction field at all, so there is no "declared
non-loopback" case to test here -- only whether the actual listener matches the always
-loopback design.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CATALOG, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_desktop_host_exposure
from clawseccheck.collector import Context
from clawseccheck.sockets import ListenSocket, SocketScanResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _make_pid(root, pid: str, fd_targets: dict, exe: "str | None" = None):
    fd_dir = root / pid / "fd"
    fd_dir.mkdir(parents=True, exist_ok=True)
    import os

    for fd_num, target in fd_targets.items():
        os.symlink(target, fd_dir / str(fd_num))
    (root / pid / "comm").write_text("Xtigervnc", encoding="utf-8")
    (root / pid / "cmdline").write_bytes(b"Xtigervnc\x00:99\x00")
    if exe is not None:
        os.symlink(exe, root / pid / "exe")


def _ctx(cfg: dict, sockets=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.sockets = sockets
    return c


def _scan(*listeners: ListenSocket) -> SocketScanResult:
    return SocketScanResult(available=True, listeners=tuple(listeners))


# ---------------------------------------------------------------------------
# Absent / disabled / malformed
# ---------------------------------------------------------------------------


def test_no_config_is_unknown():
    ctx = _ctx({})
    ctx.config = None
    assert check_desktop_host_exposure(ctx).status == UNKNOWN


def test_desktop_host_absent_is_pass():
    # A non-empty config that simply has no `desktop` section -- an empty dict `{}` is
    # falsy and would hit the (distinct) "no config loaded at all" UNKNOWN branch instead.
    r = check_desktop_host_exposure(_ctx({"gateway": {}}))
    assert r.status == PASS
    assert "not configured" in r.detail


def test_desktop_host_malformed_is_unknown():
    r = check_desktop_host_exposure(_ctx({"desktop": {"host": "nope"}}))
    assert r.status == UNKNOWN


def test_desktop_host_not_enabled_is_pass():
    r = check_desktop_host_exposure(_ctx({"desktop": {"host": {"enabled": False}}}))
    assert r.status == PASS
    r2 = check_desktop_host_exposure(_ctx({"desktop": {"host": {}}}))
    assert r2.status == PASS


def test_invalid_port_is_unknown():
    cfg = {"desktop": {"host": {"enabled": True, "port": 0}}}
    r = check_desktop_host_exposure(_ctx(cfg))
    assert r.status == UNKNOWN
    cfg2 = {"desktop": {"host": {"enabled": True, "port": "5900"}}}
    r2 = check_desktop_host_exposure(_ctx(cfg2))
    assert r2.status == UNKNOWN


# ---------------------------------------------------------------------------
# Socket-scan availability
# ---------------------------------------------------------------------------

_ENABLED = {"desktop": {"host": {"enabled": True}}}


def test_no_sockets_scan_is_unknown():
    ctx = _ctx(_ENABLED, sockets=None)
    assert check_desktop_host_exposure(ctx).status == UNKNOWN


def test_sockets_unavailable_is_unknown():
    ctx = _ctx(_ENABLED, sockets=SocketScanResult(available=False, reason="no /proc"))
    assert check_desktop_host_exposure(ctx).status == UNKNOWN


def test_nothing_listening_is_unknown():
    ctx = _ctx(_ENABLED, _scan())
    r = check_desktop_host_exposure(ctx)
    assert r.status == UNKNOWN
    assert "5900" in r.detail  # default port used in the message


# ---------------------------------------------------------------------------
# Clean: loopback-only listener
# ---------------------------------------------------------------------------


def test_loopback_listener_on_default_port_is_pass():
    ctx = _ctx(_ENABLED, _scan(ListenSocket("127.0.0.1", 5900, "inet")))
    r = check_desktop_host_exposure(ctx)
    assert r.status == PASS
    assert "loopback-only" in r.detail


def test_loopback_listener_on_explicit_port_is_pass():
    cfg = {"desktop": {"host": {"enabled": True, "port": 5901, "managed": True}}}
    ctx = _ctx(cfg, _scan(ListenSocket("127.0.0.1", 5901, "inet")))
    r = check_desktop_host_exposure(ctx)
    assert r.status == PASS


# ---------------------------------------------------------------------------
# Bad: non-loopback listener
# ---------------------------------------------------------------------------


def test_non_loopback_listener_without_attribution_is_warn_not_fail():
    ctx = _ctx(_ENABLED, _scan(ListenSocket("0.0.0.0", 5900, "inet")))
    r = check_desktop_host_exposure(ctx)
    assert r.status == WARN
    assert r.status != FAIL
    assert r.scored is False


def test_non_loopback_listener_confirmed_xtigervnc_and_managed_is_fail(tmp_path):
    # The real attack: OpenClaw is supposed to be supervising this desktop
    # (managed=True) and its own `-localhost yes` enforcement did not hold.
    _make_pid(tmp_path, "42", {3: "socket:[9]"}, exe="/usr/bin/Xtigervnc")
    cfg = {"desktop": {"host": {"enabled": True, "managed": True}}}
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 5900, "inet", inode="9")))
    ctx.proc_root = str(tmp_path)
    r = check_desktop_host_exposure(ctx)
    assert r.status == FAIL
    assert r.scored is True
    assert any("Xtigervnc" in e or "pid 42" in e for e in r.evidence)


def test_non_loopback_listener_confirmed_other_process_is_warn_not_fail(tmp_path):
    # A different, positively-resolved binary sharing the port -- never a guessed FAIL.
    _make_pid(tmp_path, "42", {3: "socket:[9]"}, exe="/usr/bin/some-other-daemon")
    cfg = {"desktop": {"host": {"enabled": True, "managed": True}}}
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 5900, "inet", inode="9")))
    ctx.proc_root = str(tmp_path)
    r = check_desktop_host_exposure(ctx)
    assert r.status == WARN
    assert r.status != FAIL
    assert r.scored is False


# ---------------------------------------------------------------------------
# C-135 false positive (found + fixed): confirmed Xtigervnc binary is NOT
# sufficient on its own -- desktop.host.managed must also be true. Xtigervnc is
# the stock Debian/Ubuntu tigervnc-standalone-server binary, so an operator's own,
# separately-run, unmanaged VNC server matches the exact same identity check.
# ---------------------------------------------------------------------------


def test_non_loopback_confirmed_xtigervnc_but_unmanaged_absent_is_warn_not_fail(tmp_path):
    # Reviewer's exact offending input: managed absent entirely (falls back to falsy).
    _make_pid(tmp_path, "42", {3: "socket:[9]"}, exe="/usr/bin/Xtigervnc")
    ctx = _ctx(_ENABLED, _scan(ListenSocket("0.0.0.0", 5900, "inet", inode="9")))
    ctx.proc_root = str(tmp_path)
    r = check_desktop_host_exposure(ctx)
    assert r.status == WARN
    assert r.status != FAIL
    assert r.scored is False
    assert "managed" in r.detail


def test_non_loopback_confirmed_xtigervnc_but_managed_explicitly_false_is_warn(tmp_path):
    # Near-neighbour of the reviewer's input: managed explicitly False, not just absent.
    _make_pid(tmp_path, "42", {3: "socket:[9]"}, exe="/usr/bin/Xtigervnc")
    cfg = {
        "desktop": {
            "host": {
                "enabled": True,
                "managed": False,
                "passwordFile": "/home/user/.vnc/passwd",
            }
        }
    }
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 5900, "inet", inode="9")))
    ctx.proc_root = str(tmp_path)
    r = check_desktop_host_exposure(ctx)
    assert r.status == WARN
    assert r.status != FAIL
    assert r.scored is False


def test_non_loopback_confirmed_xtigervnc_unmanaged_nondefault_port_is_warn(tmp_path):
    # Near-neighbour: same shape, non-default port, still no false FAIL.
    _make_pid(tmp_path, "42", {3: "socket:[9]"}, exe="/usr/bin/Xtigervnc")
    cfg = {"desktop": {"host": {"enabled": True, "managed": False, "port": 5901}}}
    ctx = _ctx(cfg, _scan(ListenSocket("0.0.0.0", 5901, "inet", inode="9")))
    ctx.proc_root = str(tmp_path)
    r = check_desktop_host_exposure(ctx)
    assert r.status == WARN
    assert r.status != FAIL
    assert r.scored is False


# ---------------------------------------------------------------------------
# Catalog wiring
# ---------------------------------------------------------------------------


def test_catalog_entry():
    m = next(c for c in CATALOG if c.id == "B384")
    assert m.surface == "gateway"
    assert m.block == "hardening"
