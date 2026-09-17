"""B379 (F-178) — host-level scheduled persistence (systemd user *.timer / system
cron) that names OpenClaw, outside openclaw.json's own `cron` block (C048's scope).

Deliberately narrow (see check_host_scheduled_persistence's own docstring): systemd
*.service is B150's territory, shell_rc is B324's, and the signal is a name/content
match on "openclaw" — never bare existence, since /etc/cron.* is near-universal on a
real Linux box.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck import hostpersist
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_host_scheduled_persistence
from clawseccheck.collector import Context


def _ctx(home: Path, *, include_host: bool = True) -> Context:
    c = Context(home=home / ".openclaw")
    c.config = {}
    c.include_host = include_host
    return c


def _no_spool(monkeypatch, tmp_path):
    """Point the (never-read) crontab-spool probe at a path that genuinely does not
    exist, so `scan.unreadable` is empty and a clean PASS is actually reachable in a
    test — on a real Linux box the spool always exists and this branch is UNKNOWN."""
    monkeypatch.setattr(hostpersist, "USER_CRON_SPOOLS", (str(tmp_path / "no-such-spool"),))




# ---------------------------------------------------------------- positive controls

def test_openclaw_named_systemd_timer_warns(monkeypatch, tmp_path):
    _no_spool(monkeypatch, tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "openclaw-healthcheck.timer").write_text(
        "[Timer]\nOnCalendar=hourly\n", encoding="utf-8"
    )
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == WARN, f.detail
    assert f.id == "B379"
    assert any("openclaw-healthcheck.timer" in e for e in f.evidence)


def test_timer_content_mentioning_openclaw_warns_even_with_unrelated_name(monkeypatch, tmp_path):
    _no_spool(monkeypatch, tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "nightly-sync.timer").write_text(
        "[Timer]\n# runs /home/x/.npm-global/lib/node_modules/openclaw/dist/index.js\n",
        encoding="utf-8",
    )
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == WARN, f.detail


def test_openclaw_named_system_cron_entry_warns(monkeypatch, tmp_path):
    _no_spool(monkeypatch, tmp_path)
    cron_d = tmp_path / "etc-cron.d"
    cron_d.mkdir()
    (cron_d / "openclaw-keepalive").write_text(
        "*/5 * * * * root /usr/bin/true\n", encoding="utf-8"
    )
    monkeypatch.setattr(hostpersist, "SYSTEM_CRON_PATHS", (str(cron_d),))
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == WARN, f.detail
    assert any("openclaw-keepalive" in e for e in f.evidence)


# ---------------------------------------------------------------- negative controls

def test_ordinary_system_cron_entries_do_not_warn(monkeypatch, tmp_path):
    """An 'ordinary user crontab'-shaped surface — real distro package cron jobs with
    no OpenClaw mention at all — must not fire. Mirrors the real-machine measurement
    in check_host_scheduled_persistence's own docstring (anacron/logrotate/sysstat/...)."""
    _no_spool(monkeypatch, tmp_path)
    cron_d = tmp_path / "etc-cron.d"
    cron_d.mkdir()
    (cron_d / "logrotate").write_text("0 3 * * * root /usr/sbin/logrotate\n", encoding="utf-8")
    (cron_d / "sysstat").write_text("*/10 * * * * root /usr/lib/sysstat/debian-sa1\n",
                                     encoding="utf-8")
    monkeypatch.setattr(hostpersist, "SYSTEM_CRON_PATHS", (str(cron_d),))
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == PASS, f.detail


def test_generic_timer_with_openclaw_in_paired_service_warns(monkeypatch, tmp_path):
    """C-135 (independent, post-commit): the real systemd idiom — an unremarkable
    `.timer` file with no command in it at all, and the actual ExecStart= living in a
    same-basename `.service` unit that the timer implicitly triggers. Neither the
    timer's own name/content (checked here) nor B150 (Restart=always-only; a
    timer-triggered service is normally Type=oneshot) used to see this."""
    _no_spool(monkeypatch, tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "backup-sync.timer").write_text(
        "[Timer]\nOnCalendar=hourly\n[Install]\nWantedBy=timers.target\n", encoding="utf-8"
    )
    (unit_dir / "backup-sync.service").write_text(
        "[Service]\nType=oneshot\nExecStart=/home/x/.npm-global/bin/openclaw run "
        "--agent exfil-task\n",
        encoding="utf-8",
    )
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == WARN, f.detail
    assert any("backup-sync.timer" in e and "paired" in e for e in f.evidence)


def test_timer_inside_wants_only_still_finds_its_top_level_paired_service(monkeypatch, tmp_path):
    """C-135 round 2 (independent, post-commit): a first attempt at the pairing lookup
    matched by full PATH, not basename — `~/…/timers.target.wants/x.timer` looked for a
    paired `~/…/timers.target.wants/x.service`, which does not exist, while the real
    paired unit sits at the top level (`~/…/x.service`, normal systemd layout). A
    `.timer` unit that exists ONLY inside `.wants/` (systemd loads a real file dropped
    there directly, not only a symlink) evaded the path-keyed lookup entirely — this
    pins the fix (basename-keyed, not path-keyed)."""
    _no_spool(monkeypatch, tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    wants_dir = unit_dir / "timers.target.wants"
    wants_dir.mkdir(parents=True)
    (wants_dir / "backup-sync.timer").write_text(
        "[Timer]\nOnCalendar=hourly\n", encoding="utf-8"
    )
    (unit_dir / "backup-sync.service").write_text(
        "[Service]\nType=oneshot\nExecStart=/home/x/.npm-global/bin/openclaw run "
        "--agent exfil-task\n",
        encoding="utf-8",
    )
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == WARN, f.detail
    assert any("backup-sync.timer" in e and "paired" in e for e in f.evidence)


def test_generic_timer_with_unrelated_paired_service_does_not_warn(monkeypatch, tmp_path):
    """Inverse control: a real timer+service pair with no OpenClaw mention anywhere in
    either file must stay clean — the paired-service check must not become an
    existence-only match."""
    _no_spool(monkeypatch, tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "logrotate.timer").write_text("[Timer]\nOnCalendar=daily\n", encoding="utf-8")
    (unit_dir / "logrotate.service").write_text(
        "[Service]\nType=oneshot\nExecStart=/usr/sbin/logrotate /etc/logrotate.conf\n",
        encoding="utf-8",
    )
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == PASS, f.detail


def test_openclaw_service_unit_does_not_warn_here(monkeypatch, tmp_path):
    """.service is B150's territory (Restart=always persistence) — double-reporting the
    exact same unit under a second id would be redundant, not additive."""
    _no_spool(monkeypatch, tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "openclaw-gateway.service").write_text(
        "[Service]\nExecStart=/usr/bin/openclaw gateway\nRestart=always\n", encoding="utf-8"
    )
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == PASS, f.detail
    assert not f.evidence


def test_shell_rc_mentioning_openclaw_does_not_warn_here(monkeypatch, tmp_path):
    """Shell startup files are B324's concern (env.shellEnv.enabled), not this check's —
    and ~/.bashrc existing (and mentioning an openclaw PATH entry) is close to universal,
    so counting it here would flood every real machine."""
    _no_spool(monkeypatch, tmp_path)
    (tmp_path / ".bashrc").write_text(
        'export PATH="$PATH:/home/x/.npm-global/bin"  # openclaw\n', encoding="utf-8"
    )
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == PASS, f.detail


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores the read bit, so chmod 000 proves nothing",
)
def test_unreadable_crontab_spool_is_unknown_not_pass(monkeypatch, tmp_path):
    """The 'ordinary user crontab' case the task exists for: the personal spool is
    NEVER read (mode 1730 on a real box) — must read as UNKNOWN, distinct from a WARN,
    and must not be silently swallowed into a false-clean PASS either."""
    spool = tmp_path / "spool"
    spool.mkdir()
    spool.chmod(0o000)
    monkeypatch.setattr(hostpersist, "USER_CRON_SPOOLS", (str(spool),))
    try:
        f = check_host_scheduled_persistence(_ctx(tmp_path))
    finally:
        spool.chmod(0o755)  # let pytest's tmp_path cleanup traverse back in
    assert f.status == UNKNOWN, f.detail
    assert f.not_applicable is not True


def test_nothing_present_is_unknown_not_applicable(monkeypatch, tmp_path):
    _no_spool(monkeypatch, tmp_path)
    monkeypatch.setattr(hostpersist, "SYSTEM_CRON_PATHS", ())
    f = check_host_scheduled_persistence(_ctx(tmp_path))
    assert f.status == UNKNOWN, f.detail
    assert f.not_applicable is True


def test_never_fails(monkeypatch, tmp_path):
    _no_spool(monkeypatch, tmp_path)
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "openclaw-healthcheck.timer").write_text("[Timer]\n", encoding="utf-8")
    assert check_host_scheduled_persistence(_ctx(tmp_path)).status != FAIL


def test_disabled_host_scanning_is_unknown_not_a_hermetic_pass(tmp_path):
    """2026-09-17: `hostpersist.scan()`'s system-cron leg reads hardcoded absolute
    paths (`/etc/crontab`, `/etc/cron.d`, ...) regardless of the `home` passed to it —
    unlike the systemd-user leg, it is NOT scoped to the audited home at all. Without
    this gate, every hermetic `audit()` call (the default; every fixture-based test,
    including `test_finding_fingerprint_manifest.py`) read the REAL host's own
    `/etc/cron.*` inventory, which differs by machine and by platform — a bare macOS
    runner has none of these paths at all — and made this check's finding text (and so
    its fingerprint) a function of whatever machine happened to run the audit rather
    than of the fixture/config under test. Caught by a macOS-only CI failure on a
    fixture unrelated to this check. `include_host` defaults to False specifically to
    keep the engine hermetic for tests (see `audit()`'s own docstring); this check must
    honor that the same way B328/the B-capability and B-egress `include_host` gates
    already do."""
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "openclaw-healthcheck.timer").write_text("[Timer]\n", encoding="utf-8")
    f = check_host_scheduled_persistence(_ctx(tmp_path, include_host=False))
    assert f.status == UNKNOWN, f.detail
    assert f.not_applicable is not True
