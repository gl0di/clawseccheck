"""C-756: the --monitor host-persistence dimension must not be silent about macOS launchd.

The fact rides in the snapshot as a separate ``launchd_unread`` key that the drift
comparison never reads; a Linux home is byte-identical to before. Offline, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import json
import os

from clawseccheck import hostpersist, monitor
from clawseccheck.cli import main
from clawseccheck.monitor import diff_with_notes

_UNIT = "~/.config/systemd/user/a.service"
_ENT = {_UNIT: {"family": hostpersist.FAMILY_SYSTEMD, "digest": "a" * 8}}


def _snap(**kw) -> dict:
    base = {
        "version": monitor.SNAPSHOT_VERSION, "checks": {}, "graded": True, "score": 50,
        "raw_score": 50, "grade": "F", "scope": ["host"],
        "watched": list(monitor.WATCHED_DIMENSIONS), "config_ever_seen": True,
        "host_persist": {"entries": dict(_ENT), "unreadable": [], "capped": False,
                         "families_seen": list(hostpersist.FAMILIES)},
    }
    base["host_persist"].update(kw)
    return base


def _notes(prev, curr):
    return [s for _c, s in diff_with_notes(prev, curr)[1] if "launchd" in s]


def test_mac_snapshot_discloses_unread_launchd():
    mac = _snap(launchd_unread=["~/Library/LaunchAgents"])
    notes = _notes(_snap(), mac)
    assert len(notes) == 1 and "~/Library/LaunchAgents" in notes[0]
    assert "launchctl list" in notes[0]


def test_disclosure_survives_a_missing_prior_record():
    mac = _snap(launchd_unread=["/Library/LaunchDaemons"])
    prev = _snap()
    del prev["host_persist"]
    assert any("/Library/LaunchDaemons" in n for n in _notes(prev, mac))


def test_linux_snapshot_is_silent_about_launchd():
    assert _notes(_snap(), _snap()) == []


def test_launchd_key_never_causes_drift():
    alerts, _ = diff_with_notes(_snap(), _snap(launchd_unread=["~/Library/LaunchAgents"]))
    assert not [a for a in alerts if "Startup/scheduling" in a[1]]


def test_unknown_malformed_launchd_value_is_ignored():
    assert _notes(_snap(), _snap(launchd_unread="nope")) == []


def test_crontab_advice_is_platform_correct():
    unread = {"unreadable": ["/var/at/tabs"]}
    linux = [s for _c, s in diff_with_notes(_snap(), _snap(**unread))[1] if "crontab" in s]
    mac = [s for _c, s in diff_with_notes(
        _snap(), _snap(launchd_unread=["~/Library/LaunchAgents"], **unread))[1] if "crontab" in s]
    assert linux and "launchctl" not in linux[0]
    assert mac and "launchctl list" in mac[0]


def _run(user_home, oc, store):
    buf = io.StringIO()
    prev = os.environ.get("HOME")
    os.environ["HOME"] = str(user_home)
    try:
        with contextlib.redirect_stdout(buf):
            main(["--monitor", "--home", str(oc), "--data-dir", str(store), "--verbose"])
    finally:
        if prev is not None:
            os.environ["HOME"] = prev
    return buf.getvalue()


def test_end_to_end_mac_home_gets_disclosure_linux_home_does_not(tmp_path, monkeypatch):
    monkeypatch.setattr(hostpersist, "SYSTEM_CRON_PATHS", ())
    monkeypatch.setattr(hostpersist, "USER_CRON_SPOOLS", ())
    monkeypatch.setattr(hostpersist, "LAUNCHD_SYSTEM_DIRS", ())
    oc = tmp_path / "oc"
    oc.mkdir()
    cfg = oc / "openclaw.json"
    cfg.write_text(json.dumps({"gateway": {"bind": "127.0.0.1:8080"}}), encoding="utf-8")
    os.chmod(cfg, 0o600)
    out = {}
    for name, mac in (("linux", False), ("mac", True)):
        home = tmp_path / name
        home.mkdir()
        if mac:
            (home / "Library" / "LaunchAgents").mkdir(parents=True)
        store = tmp_path / ("store-" + name)
        _run(home, oc, store)           # baseline
        out[name] = _run(home, oc, store)
    assert "launchd" in out["mac"] and "Library/LaunchAgents" in out["mac"]
    assert "launchd" not in out["linux"]
