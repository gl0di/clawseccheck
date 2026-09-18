"""§5 gate: zero false-positive FAILs across the clean-config corpus.

CLAUDE.md §5 forbids spurious FAILs on real/clean OpenClaw configs. Until now
that law was held only by manual pre-release checking. This test operationalizes
it: every fixture home designated *clean* must yield zero FAIL findings from a
full audit. Drop in a clean fixture named ``clean_*`` (or rely on the canonical
``home_safe``) and it is automatically enrolled in the gate — no edit here.

Read-only and offline: it runs the real ``audit()`` over the pinned fixtures
(``conftest.py`` chmods every ``openclaw.json`` to 0o600 so at-rest checks are
deterministic).

Two legs. The *hermetic* leg (``audit(home)``) sees only the config. The *host*
leg adds ``include_host`` and ``include_sockets`` against a pinned hostwatch seam
(Linux, no PATH resolver) and a host root and ``/proc`` built at runtime under
``tmp_path``, so it never depends on the machine running the tests. Without it the
host- and socket-dependent FAIL branches (B321, B328, B340) are unreachable here.
Permanent positive controls prove the host leg can actually see each of them.

Neither leg sees: C5 and B379 read the real host regardless of the roots (both
are WARN-capped, so they cannot FAIL), and RISK chains are not part of the
``audit()`` finding list.
"""
import dataclasses
import functools
import json
import os
from pathlib import Path

import pytest

import clawseccheck
from clawseccheck import audit, hostwatch
from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import _config, _host

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _clean_homes():
    """Discover the clean-config corpus by convention.

    Members: the canonical ``home_safe`` plus every ``fixtures/clean_*`` dir.
    ``bad_*`` / ``home_vuln`` / partial non-home fixtures are excluded — only
    configs that are *meant* to be clean belong in a zero-FAIL gate.
    """
    homes = []
    safe = FIXTURES / "home_safe"
    if safe.is_dir():
        homes.append(safe)
    homes += sorted(p for p in FIXTURES.glob("clean_*") if p.is_dir())
    return homes


CLEAN_HOMES = _clean_homes()


def test_clean_corpus_is_non_empty():
    # A renamed/emptied corpus must fail loudly, not let the gate pass vacuously.
    assert CLEAN_HOMES, (
        "no clean-config fixtures found — the §5 FP gate would be vacuous; "
        "expected home_safe and/or fixtures/clean_*"
    )


@pytest.mark.parametrize("home", CLEAN_HOMES, ids=lambda p: p.name)
def test_no_false_positive_fail_on_clean_config(home):
    _, findings, _ = audit(home)
    fails = [f.id for f in findings if f.status == FAIL]
    assert not fails, (
        f"§5 violation: clean fixture {home.name!r} produced FAIL(s): {fails}. "
        "Either the fixture isn't actually clean, or a check has a false positive — "
        "fix the check, don't whitelist the FAIL."
    )


# ---------------------------------------------------------------------------
# Host + sockets leg
# ---------------------------------------------------------------------------

_DEFAULT_PORT = _config._DEFAULT_GATEWAY_PORT


def _pin_linux_host(monkeypatch):
    """Make the host probe independent of the real machine (OS and PATH)."""
    monkeypatch.setattr(
        clawseccheck, "_host_detect",
        functools.partial(hostwatch.detect, system="Linux", which=lambda _n: None),
    )


def _host_root(tmp_path, kind):
    root = tmp_path / "hostroot"
    root.mkdir()
    if kind == "hardened":
        for rel, body in {
            "etc/suricata/suricata.yaml": "",
            "etc/audit/auditd.conf": "",
            "etc/aide/aide.conf": "",
            "etc/ufw/ufw.conf": "ENABLED=yes\n",
            "etc/default/ufw": 'DEFAULT_OUTPUT_POLICY="DROP"\n',
        }.items():
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body, encoding="utf-8")
    return root


def _synthetic_proc(tmp_path, ports, host_hex="0100007F"):
    """A /proc with listeners on *ports*, all owned by one node gateway process."""
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    hdr = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
           "retrnsmt   uid  timeout inode\n")
    rows = "".join(
        f"  {i}: {host_hex}:{port:04X} 00000000:0000 0A 00000000:00000000 "
        f"00:00000000 00000000  1000        0 {1000 + i} 1 0000000000000000 100 0 0 10 0\n"
        for i, port in enumerate(sorted(ports))
    )
    (proc / "net" / "tcp").write_text(hdr + rows, encoding="utf-8")
    (proc / "net" / "tcp6").write_text(hdr, encoding="utf-8")
    pid = proc / "4242"
    (pid / "fd").mkdir(parents=True)
    for i in range(len(ports)):
        os.symlink(f"socket:[{1000 + i}]", pid / "fd" / str(3 + i))
    (pid / "comm").write_text("node\n", encoding="utf-8")
    (pid / "cmdline").write_bytes(b"/usr/bin/node\0/opt/openclaw/dist/cli.js\0")
    os.symlink("/usr/bin/node", pid / "exe")
    return proc


def _gateway_ports(home):
    """The ports B340 will look for, mirroring its own resolution."""
    cfg = clawseccheck.collect(home).config or {}
    gw = cfg.get("gateway") if isinstance(cfg.get("gateway"), dict) else {}
    ports = {_DEFAULT_PORT}
    bp = _config._parse_bind_port(gw.get("bind", ""))
    if isinstance(bp, int):
        ports.add(bp)
    gp = gw.get("port")
    if isinstance(gp, int) and not isinstance(gp, bool) and 1 <= gp <= 65535:
        ports.add(gp)
    return ports


def _fail_ids(findings):
    return {f.id for f in findings if f.status == FAIL}


def _host_audit(home, tmp_path, kind="bare", ports=None, host_hex="0100007F"):
    proc = _synthetic_proc(tmp_path, _gateway_ports(home) if ports is None else ports,
                           host_hex)
    return audit(home, include_host=True, host_root=str(_host_root(tmp_path, kind)),
                 include_sockets=True, proc_root=str(proc))[1]


@pytest.mark.parametrize("home", CLEAN_HOMES, ids=lambda p: p.name)
def test_no_false_positive_fail_on_clean_config_host_mode(home, tmp_path, monkeypatch):
    _pin_linux_host(monkeypatch)
    hermetic = _fail_ids(audit(home)[1])
    host = _fail_ids(_host_audit(home, tmp_path))
    assert not host, (
        f"§5 violation (host+sockets leg): clean fixture {home.name!r} produced "
        f"FAIL(s): {sorted(host)}. Fix the check, don't whitelist the FAIL."
    )
    assert host <= hermetic


def test_no_false_positive_fail_on_hardened_host_root(tmp_path, monkeypatch):
    _pin_linux_host(monkeypatch)
    home = FIXTURES / "home_safe"
    assert not _fail_ids(_host_audit(home, tmp_path, kind="hardened"))


# -- positive controls: the host leg must be able to go red -----------------

def test_control_generic_host_fail_is_visible(tmp_path, monkeypatch):
    """A FAIL planted in a host-reading check is invisible hermetically, seen here."""
    _pin_linux_host(monkeypatch)
    orig = _host._host_finding

    def planted(cid, cls, ctx):
        f = orig(cid, cls, ctx)
        return dataclasses.replace(f, status=FAIL) if ctx.host else f

    monkeypatch.setattr(_host, "_host_finding", planted)
    home = FIXTURES / "home_safe"
    assert not _fail_ids(audit(home)[1])
    assert {"B50", "B51", "B52", "B53", "B54"} <= _fail_ids(_host_audit(home, tmp_path))


def _status(findings, cid):
    return next(f.status for f in findings if f.id == cid)


def test_control_b340_wildcard_listener_fails_loopback_passes(tmp_path, monkeypatch):
    _pin_linux_host(monkeypatch)
    home = FIXTURES / "clean_b340_effective_bind_loopback"
    ok = tmp_path / "ok"
    ok.mkdir()
    bad = tmp_path / "bad"
    bad.mkdir()
    assert _status(_host_audit(home, ok, ports={8765}), "B340") == PASS
    assert _status(_host_audit(home, bad, ports={8765}, host_hex="00000000"),
                   "B340") == FAIL


def _exec_home(tmp_path, bindir_mode):
    """A runtime-built home whose safeBinTrustedDirs and browser path are on the host."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    chrome = bindir / "chrome"
    chrome.write_text("#!/bin/sh\n", encoding="utf-8")
    chrome.chmod(0o755)
    bindir.chmod(bindir_mode)
    cfg = json.loads((FIXTURES / "clean_b328_exec_safebin_trusted_dirs"
                      / "openclaw.json").read_text(encoding="utf-8"))
    cfg["tools"]["exec"] = {"safeBinTrustedDirs": [str(bindir)]}
    cfg["browser"] = {"executablePath": str(chrome)}
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    (home / "openclaw.json").chmod(0o600)
    home.chmod(0o700)
    return home


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_control_b321_b328_absolute_host_paths(tmp_path, monkeypatch):
    _pin_linux_host(monkeypatch)
    safe = tmp_path / "safe"
    safe.mkdir()
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    ok = _host_audit(_exec_home(safe, 0o755), safe, ports=set())
    assert (_status(ok, "B321"), _status(ok, "B328")) == (PASS, PASS)
    bad_home = _exec_home(unsafe, 0o777)
    bad = _host_audit(bad_home, unsafe, ports=set())
    assert (_status(bad, "B321"), _status(bad, "B328")) == (FAIL, FAIL)
    hermetic = audit(bad_home)[1]
    assert (_status(hermetic, "B321"), _status(hermetic, "B328")) == (UNKNOWN, UNKNOWN)
