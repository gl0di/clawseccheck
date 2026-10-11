"""C-676 - the OpenClaw updater's `.bak` leftovers in the systemd user directory.

Every OpenClaw update leaves `openclaw-gateway.service.reconcile-<id>.bak` and
`...reconcile-<id>.receipt.bak` beside the gateway unit. `hostpersist.scan` filed every
non-directory child of `~/.config/systemd/user` under "systemd user service", so `--monitor`
called those inert files new startup items after every update.

systemd loads a unit only from a name ending in a unit suffix (systemd.unit(5)) or from a
drop-in / `.wants/` directory. The fix is a RELABEL, not a suppression: a child without a
unit suffix is still reported - a staged unit can be renamed into place later - but as a
file systemd does not load, at INFO (the lowest level the dimension has).

The other half of the contract is pinned just as hard: every shape that really does arm
code keeps its family and its MEDIUM alert. The derivation is from the suffix list, never
from the string `reconcile` or the OpenClaw unit name, so another tool's backups are
treated the same way.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from clawseccheck import hostpersist, monitor
from clawseccheck.monitor import diff_with_notes

_MARK = "Startup/scheduling file(s)"
_NOT_LOADED_MARK = "systemd user unit directory that systemd does not load"
_ROOT = "~/.config/systemd/user/"


def _unit_dir(home: Path) -> Path:
    d = home / ".config" / "systemd" / "user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _build(home: Path) -> Path:
    """Every shape the issue and its C-135 note name, in one tree."""
    d = _unit_dir(home)
    (d / "x.service").write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    (d / "x.service.bak").write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    (d / "x.service.reconcile-1.bak").write_text("old\n", encoding="utf-8")
    (d / "x.service.reconcile-1.receipt.bak").write_text("receipt\n", encoding="utf-8")
    (d / "x@.service").write_text("[Service]\nExecStart=/bin/true %i\n", encoding="utf-8")
    (d / "x.timer").write_text("[Timer]\nOnCalendar=daily\n", encoding="utf-8")
    (d / "linked.service").symlink_to(d / "x.service")           # a symlinked unit
    (d / "linked.bak").symlink_to(d / "x.service")               # a symlink with no suffix
    (d / "default.target.wants").mkdir()
    (d / "default.target.wants" / "x.service").symlink_to(d / "x.service")
    (d / "x.service.d").mkdir()
    (d / "x.service.d" / "override.conf").write_text(
        "[Service]\nExecStartPre=/bin/true\n", encoding="utf-8")
    return home


def _scan(home: Path) -> "dict[str, str]":
    result = hostpersist.scan(home, system_cron_paths=(), user_cron_spools=())
    return {e.path: e.family for e in result.entries}


# ------------------------------------------------------------------------- the leaf

def test_the_updater_leftovers_are_not_called_services(tmp_path):
    fam = _scan(_build(tmp_path))
    for name in ("x.service.bak", "x.service.reconcile-1.bak",
                 "x.service.reconcile-1.receipt.bak"):
        assert fam[_ROOT + name] == hostpersist.FAMILY_SYSTEMD_NOT_LOADED, name
    # recorded, not suppressed
    assert _ROOT + "x.service.reconcile-1.receipt.bak" in fam
    label = hostpersist.FAMILY_LABELS_NOT_LOADED[hostpersist.FAMILY_SYSTEMD_NOT_LOADED]
    assert "service" not in label.replace("systemd user unit directory", "")
    assert label != hostpersist.FAMILY_LABELS[hostpersist.FAMILY_SYSTEMD]


def test_a_symlink_without_a_unit_suffix_is_not_loaded_either(tmp_path):
    """systemd matches on the NAME, so a link called `linked.bak` is not a unit however
    real its target is."""
    assert _scan(_build(tmp_path))[_ROOT + "linked.bak"] == \
        hostpersist.FAMILY_SYSTEMD_NOT_LOADED


@pytest.mark.parametrize("name", [
    "x.service", "x@.service", "x@inst.service", "x.socket", "x.timer", "x.target",
    "x.path", "x.mount", "x.automount", "x.swap", "x.slice", "x.scope", "x.device",
    "linked.service",
])
def test_real_unit_names_keep_the_service_family(tmp_path, name):
    d = _unit_dir(tmp_path)
    (d / name).write_text("[Unit]\n", encoding="utf-8")
    assert _scan(tmp_path)[_ROOT + name] == hostpersist.FAMILY_SYSTEMD


def test_a_symlinked_unit_template_and_dropin_keep_the_service_family(tmp_path):
    fam = _scan(_build(tmp_path))
    assert fam[_ROOT + "linked.service"] == hostpersist.FAMILY_SYSTEMD
    assert fam[_ROOT + "x@.service"] == hostpersist.FAMILY_SYSTEMD
    assert fam[_ROOT + "x.service.d/override.conf"] == hostpersist.FAMILY_SYSTEMD
    assert fam[_ROOT + "default.target.wants/x.service"] == hostpersist.FAMILY_SYSTEMD
    assert fam[_ROOT + "x.service"] == hostpersist.FAMILY_SYSTEMD
    assert fam[_ROOT + "x.timer"] == hostpersist.FAMILY_SYSTEMD


def test_a_dropin_file_with_a_non_unit_name_inside_a_directory_is_still_a_service(tmp_path):
    """Only DIRECT children are reclassified. A `.conf` inside `x.service.d/` is exactly
    what arms a drop-in, and it has no unit suffix of its own."""
    fam = _scan(_build(tmp_path))
    assert not fam[_ROOT + "x.service.d/override.conf"].endswith("not_loaded")


def test_the_suffix_match_is_systemds_not_a_substring(tmp_path):
    """`.service` in the middle of a name is not a suffix; `.SERVICE` is not systemd's."""
    d = _unit_dir(tmp_path)
    for name in ("x.service.old", "x.servicebak", "x.SERVICE", "x.service~", ".x.service.swp"):
        (d / name).write_text("x\n", encoding="utf-8")
    fam = _scan(tmp_path)
    for name in ("x.service.old", "x.servicebak", "x.SERVICE", "x.service~", ".x.service.swp"):
        assert fam[_ROOT + name] == hostpersist.FAMILY_SYSTEMD_NOT_LOADED, name


def test_a_different_tools_backup_is_treated_the_same_way(tmp_path):
    """No special-casing of `reconcile` or of the OpenClaw unit name."""
    d = _unit_dir(tmp_path)
    (d / "syncthing.service.dpkg-old").write_text("x\n", encoding="utf-8")
    (d / "pipewire.socket.bak").write_text("x\n", encoding="utf-8")
    fam = _scan(tmp_path)
    assert fam[_ROOT + "syncthing.service.dpkg-old"] == hostpersist.FAMILY_SYSTEMD_NOT_LOADED
    assert fam[_ROOT + "pipewire.socket.bak"] == hostpersist.FAMILY_SYSTEMD_NOT_LOADED


def test_the_not_loaded_family_is_classified_on_the_info_side():
    """The existing guard pins FAMILIES == FAMILY_LABELS and requires every family to be
    placed on one side of the MEDIUM/INFO line. This family sits outside FAMILIES because
    its appearance is not an execution entry point; this test is its own placement guard."""
    fam = hostpersist.FAMILY_SYSTEMD_NOT_LOADED
    assert fam not in hostpersist.FAMILIES
    assert fam not in monitor._HOST_PERSIST_INFRA
    assert fam in hostpersist.FAMILY_LABELS_NOT_LOADED
    assert not set(hostpersist.FAMILY_LABELS_NOT_LOADED) & set(hostpersist.FAMILY_LABELS)
    assert fam in monitor._HOST_PERSIST_LABELS


# ----------------------------------------------------------------- the diff arm

def _snap(home: Path) -> dict:
    return {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {}, "graded": True, "score": 50, "raw_score": 50, "grade": "F",
        "scope": ["host"], "watched": list(monitor.WATCHED_DIMENSIONS),
        "config_ever_seen": True,
        "host_persist": hostpersist.to_snapshot(
            hostpersist.scan(home, system_cron_paths=(), user_cron_spools=())),
    }


def _alerts(prev: dict, curr: dict) -> "list[tuple[str, str]]":
    alerts, _notes = diff_with_notes(prev, curr)
    return [(lvl, m) for lvl, m in alerts if _MARK in m or _NOT_LOADED_MARK in m]


def _homes(tmp_path: Path) -> "tuple[Path, Path]":
    a, b = tmp_path / "before", tmp_path / "after"
    a.mkdir()
    b.mkdir()
    return _build(a), _build(b)


def test_an_unchanged_tree_says_nothing(tmp_path):
    """The floor: every assertion below is satisfied by an arm that always fires without it."""
    before, after = _homes(tmp_path)
    assert not _alerts(_snap(before), _snap(after))


def test_an_updater_leftover_appearing_is_info_and_not_a_service(tmp_path):
    before, after = _homes(tmp_path)
    d = _unit_dir(after)
    (d / "x.service.reconcile-2.bak").write_text("old\n", encoding="utf-8")
    (d / "x.service.reconcile-2.receipt.bak").write_text("receipt\n", encoding="utf-8")
    hits = _alerts(_snap(before), _snap(after))
    assert hits, "the file must still be reported (relabelled, not suppressed)"
    assert {lvl for lvl, _m in hits} == {"INFO"}, hits
    text = " ".join(m for _l, m in hits)
    assert "x.service.reconcile-2.receipt.bak" in text
    assert "systemd user service" not in text
    assert "These run code" not in text      # false for a file nothing loads
    assert "does not load" in text and "renamed into place" in text


@pytest.mark.parametrize("name", [
    "new.service", "new@.service", "new.timer", "new.socket", "new.path",
])
def test_a_real_unit_appearing_is_still_medium(tmp_path, name):
    before, after = _homes(tmp_path)
    (_unit_dir(after) / name).write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    hits = _alerts(_snap(before), _snap(after))
    assert any(lvl == "MEDIUM" and name in m and "systemd user service" in m
               for lvl, m in hits), hits


def test_a_new_enable_link_is_still_medium(tmp_path):
    before, after = _homes(tmp_path)
    d = _unit_dir(after)
    (d / "default.target.wants" / "new.service").symlink_to(d / "x.service")
    hits = _alerts(_snap(before), _snap(after))
    assert any(lvl == "MEDIUM" and "default.target.wants/new.service" in m
               for lvl, m in hits), hits


def test_a_new_dropin_is_still_medium(tmp_path):
    before, after = _homes(tmp_path)
    (_unit_dir(after) / "x.service.d" / "evil.conf").write_text(
        "[Service]\nExecStartPre=/bin/false\n", encoding="utf-8")
    hits = _alerts(_snap(before), _snap(after))
    assert any(lvl == "MEDIUM" and "x.service.d/evil.conf" in m for lvl, m in hits), hits


def test_a_new_symlinked_unit_is_still_medium(tmp_path):
    before, after = _homes(tmp_path)
    d = _unit_dir(after)
    (d / "alias.service").symlink_to(d / "x.service")
    hits = _alerts(_snap(before), _snap(after))
    assert any(lvl == "MEDIUM" and "alias.service" in m for lvl, m in hits), hits


def test_a_modified_unit_is_still_medium_and_a_modified_leftover_is_info(tmp_path):
    before, after = _homes(tmp_path)
    d = _unit_dir(after)
    (d / "x.service").write_text("[Service]\nExecStart=/bin/false\n", encoding="utf-8")
    (d / "x.service.bak").write_text("tampered\n", encoding="utf-8")
    hits = _alerts(_snap(before), _snap(after))
    assert any(lvl == "MEDIUM" and "x.service (systemd user service)" in m
               for lvl, m in hits), hits
    leftover = [(lvl, m) for lvl, m in hits if "x.service.bak" in m]
    assert leftover and {lvl for lvl, _m in leftover} == {"INFO"}, hits
    assert "changed in the systemd user unit directory that systemd does not load" \
        in leftover[0][1]
    assert "These run code" not in leftover[0][1]


def test_a_leftover_renamed_into_place_shows_as_a_new_service(tmp_path):
    """The reason the file is worth one line at all."""
    before, after = _homes(tmp_path)
    d = _unit_dir(after)
    (d / "x.service.bak").rename(d / "staged.service")
    hits = _alerts(_snap(before), _snap(after))
    assert any(lvl == "MEDIUM" and "staged.service (systemd user service)" in m
               for lvl, m in hits), hits


# ---------------------------------------------- baselines recorded by older versions

def _as_recorded_by_an_older_version(snap: dict) -> dict:
    """Rewrite the snapshot the way a pre-C-676 build stored it: the not-loaded files under
    the one systemd family, and no other difference."""
    old = copy.deepcopy(snap)
    for entry in old["host_persist"]["entries"].values():
        if entry["family"] == hostpersist.FAMILY_SYSTEMD_NOT_LOADED:
            entry["family"] = hostpersist.FAMILY_SYSTEMD
    return old


def test_an_old_baseline_does_not_report_the_leftovers_as_removed_and_added(tmp_path):
    before, after = _homes(tmp_path)
    old = _as_recorded_by_an_older_version(_snap(before))
    # the old record really does file them under the service family
    assert old["host_persist"]["entries"][_ROOT + "x.service.bak"]["family"] == \
        hostpersist.FAMILY_SYSTEMD
    assert not _alerts(old, _snap(after))
    alerts, notes = diff_with_notes(old, _snap(after))
    assert not [m for _l, m in alerts if "x.service.bak" in m]
    assert not [m for _l, m in notes if "x.service.bak" in m]


def test_an_old_baseline_still_catches_real_changes_in_the_first_run(tmp_path):
    before, after = _homes(tmp_path)
    old = _as_recorded_by_an_older_version(_snap(before))
    d = _unit_dir(after)
    (d / "new.service").write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    (d / "x.service.reconcile-3.bak").write_text("n\n", encoding="utf-8")
    hits = _alerts(old, _snap(after))
    assert any(lvl == "MEDIUM" and "new.service" in m for lvl, m in hits), hits
    assert any(lvl == "INFO" and "x.service.reconcile-3.bak" in m for lvl, m in hits), hits


def test_removing_a_leftover_recorded_by_an_older_version_is_not_called_a_service(tmp_path):
    before, after = _homes(tmp_path)
    old = _as_recorded_by_an_older_version(_snap(before))
    (_unit_dir(after) / "x.service.bak").unlink()
    hits = _alerts(old, _snap(after))
    removed = [(lvl, m) for lvl, m in hits if "x.service.bak" in m]
    assert removed and {lvl for lvl, _m in removed} == {"INFO"}, hits
    assert "systemd user service" not in removed[0][1]
    assert "were removed in the systemd user unit directory that systemd does not load" \
        in removed[0][1]


def test_only_a_direct_child_of_the_unit_directory_is_reread_from_an_old_baseline(tmp_path):
    """`x.service.d/override.conf` was recorded as `systemd_user` and must stay one: if the
    old-baseline reclassification looked at the name alone it would demote a drop-in."""
    before, after = _homes(tmp_path)
    old = _as_recorded_by_an_older_version(_snap(before))
    (_unit_dir(after) / "x.service.d" / "override.conf").unlink()
    hits = _alerts(old, _snap(after))
    assert any("x.service.d/override.conf (systemd user service)" in m for _l, m in hits), hits
