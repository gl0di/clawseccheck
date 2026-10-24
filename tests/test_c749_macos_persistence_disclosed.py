"""C-749: a macOS-shaped HOME must never read as "no host persistence".

hostpersist.py has no launchd coverage by design. What it owes the consumer is the
disclosure: the launchd directories exist, are not read, so B379 may not PASS and may not
say "does not apply". Platform is decided by the audited HOME's shape (a ``Library``
directory), never by the machine running the tests.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import hostpersist
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_host_scheduled_persistence
from clawseccheck.collector import Context


def _ctx(home: Path) -> Context:
    c = Context(home=home / ".openclaw")
    c.config = {}
    c.include_host = True
    return c


def _hermetic(monkeypatch, tmp_path):
    """No real /etc, spool, or /Library paths: only the fixture HOME is seen."""
    monkeypatch.setattr(hostpersist, "SYSTEM_CRON_PATHS", ())
    monkeypatch.setattr(hostpersist, "USER_CRON_SPOOLS", ())
    monkeypatch.setattr(hostpersist, "LAUNCHD_SYSTEM_DIRS", ())


def _mac_home(tmp_path, *, rc=False):
    agents = tmp_path / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    (agents / "evil.plist").write_text("<plist/>", encoding="utf-8")
    if rc:
        (tmp_path / ".zshrc").write_text("# rc\n", encoding="utf-8")


def test_scan_reports_launchd_dir_unread_on_mac_shaped_home(monkeypatch, tmp_path):
    _hermetic(monkeypatch, tmp_path)
    _mac_home(tmp_path)
    s = hostpersist.scan(tmp_path)
    assert s.launchd_unread == ("~/Library/LaunchAgents",)
    assert s.entries == ()  # not enumerated - disclosure only
    assert "launchd_unread" not in hostpersist.to_snapshot(s)


def test_system_launchd_dirs_reported_via_explicit_input(monkeypatch, tmp_path):
    _hermetic(monkeypatch, tmp_path)
    (tmp_path / "Library").mkdir()
    sysdir = tmp_path / "sys" / "LaunchDaemons"
    sysdir.mkdir(parents=True)
    s = hostpersist.scan(tmp_path, launchd_system_dirs=(str(sysdir),))
    assert s.launchd_unread == (str(sysdir),)


def test_linux_shaped_home_has_no_launchd_disclosure(monkeypatch, tmp_path):
    _hermetic(monkeypatch, tmp_path)
    (tmp_path / ".bashrc").write_text("# rc\n", encoding="utf-8")
    # Even if the machine running the test has /Library dirs, a Linux-shaped HOME says nothing.
    monkeypatch.setattr(hostpersist, "LAUNCHD_SYSTEM_DIRS", (str(tmp_path),))
    assert hostpersist.scan(tmp_path).launchd_unread == ()


def test_b379_mac_home_with_only_launchd_is_not_not_applicable(monkeypatch, tmp_path):
    _hermetic(monkeypatch, tmp_path)
    _mac_home(tmp_path)
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert not f.not_applicable
    assert "does not apply" not in f.detail
    assert "~/Library/LaunchAgents" in f.evidence
    assert "launchctl" in f.fix


def test_b379_mac_home_with_shell_rc_is_not_pass(monkeypatch, tmp_path):
    # The pre-fix behaviour: .zshrc made families_seen non-empty -> PASS "nothing found".
    _hermetic(monkeypatch, tmp_path)
    _mac_home(tmp_path, rc=True)
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert "~/Library/LaunchAgents" in f.evidence


def test_b379_linux_clean_home_still_passes(monkeypatch, tmp_path):
    _hermetic(monkeypatch, tmp_path)
    (tmp_path / ".bashrc").write_text("# rc\n", encoding="utf-8")
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == PASS


def test_b379_warn_on_mac_discloses_launchd_in_fix(monkeypatch, tmp_path):
    _hermetic(monkeypatch, tmp_path)
    _mac_home(tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "openclaw-x.timer").write_text("[Timer]\n", encoding="utf-8")
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == WARN
    assert "does not read them" in f.fix
