"""F-174 — the two supply-chain dimensions, as the monitor compares them.

The leaf modules are tested next door (`test_f174_openclaw_install.py`,
`test_f174_skill_provenance.py`). This file is about the arms in `diff_with_notes`: what
they say, what they refuse to say, and the two false alarms they were built to avoid.

**False alarm 1 — the install vanishing.** The OpenClaw package is located from PATH, and a
cron job's PATH is minimal. Verified rather than assumed: `env -i PATH=/usr/bin:/bin` cannot
find the openclaw that the same machine resolves interactively. So the very schedule this
feature exists to serve would have reported "OpenClaw was uninstalled" on its first cron run
and "OpenClaw appeared" the first time someone ran the check by hand. Wholesale appearance
and disappearance are therefore notes, never alerts.

**False alarm 2 — a wrong version direction.** "Your agent runtime was rolled back" is the
loudest sentence these dimensions can produce, and a naive digit scan reads `1.0.0-rc1` as
newer than `1.0.0` — so upgrading to a release build would report as a downgrade. Anything
that cannot be ordered confidently gets a bare "changed", which is always true.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.monitor import (
    NOTE_INSPECTION_CAPPED,
    NOTE_UNDETERMINED,
    WATCHED_DIMENSIONS,
    _SHRINKABLE_DIMENSIONS,
    diff_with_notes,
)
from clawseccheck.openclawdist import compare_versions

_CODE_A, _CODE_B = "a" * 64, "b" * 64
_ART_A, _ART_B = "c" * 64, "d" * 64


def _inst(version="2026.7.1-2", code=_CODE_A, lock="l" * 64, capped=False) -> dict:
    return {"name": "openclaw", "version": version, "manifest_sha256": "m" * 64,
            "lock_sha256": lock, "lock_name": "npm-shrinkwrap.json",
            "code_sha256": code, "code_files": 7717, "code_capped": capped}


def _prov(version="3.61.0", artifact=_ART_A, corroborated=True) -> dict:
    return {"clawseccheck": {"version": version, "installed_at": 1786033098305,
                             "registry": "https://clawhub.ai",
                             "artifact_sha256": artifact,
                             "skill_file_sha256": "s" * 64,
                             "corroborated": corroborated}}


def _snap(**over) -> dict:
    base = {
        "version": 8, "watched": list(WATCHED_DIMENSIONS),
        "score": 90, "raw_score": 90, "raw_score_scope": "abc", "grade": "A",
        "checks": {"B1": "PASS"}, "checks_not_applicable": [], "checks_degraded": [],
        "behavioral_fired": [], "behavioral_undetermined": [], "behavioral_capped": False,
        "openclaw_install": _inst(), "skill_provenance": _prov(),
    }
    base.update(over)
    return base


def _msgs(alerts) -> str:
    return " | ".join(m for _, m in alerts)


def _cats(notes) -> list:
    return [c for c, _ in notes]


# ================================================================ version ordering

def test_a_prerelease_build_is_never_ordered():
    """The trap: a digit scan reads `1.0.0-rc1` as (1,0,0,1) and therefore as NEWER than
    `1.0.0`, so upgrading to the release build would report as a rollback."""
    assert compare_versions("1.0.0-rc1", "1.0.0") == "unknown"
    assert compare_versions("1.0.0", "1.0.0-rc1") == "unknown"
    assert compare_versions("2.0.0-beta", "1.0.0") == "unknown"


def test_the_real_installs_version_shape_orders_fine():
    """`2026.7.1-2` is npm's build revision, not a pre-release, and it is what is actually
    installed on the maintainer's machine — so the guard above must not swallow it too."""
    assert compare_versions("2026.7.1-1", "2026.7.1-2") == "up"
    assert compare_versions("2026.7.1-2", "2026.7.1-1") == "down"
    assert compare_versions("2026.6.9", "2026.7.1-2") == "up"


def test_equal_and_unparseable_versions_have_no_direction():
    assert compare_versions("1.2.3", "1.2.3") == "unknown"
    assert compare_versions("", "1.2.3") == "unknown"
    assert compare_versions("stable", "latest") == "unknown"
    assert compare_versions("1.2.3", "1.2.3+build7") == "unknown"


# ================================================================ the OpenClaw install

def test_an_ordinary_update_is_reported_quietly():
    alerts, _ = diff_with_notes(_snap(), _snap(openclaw_install=_inst(version="2026.8.0",
                                                                     code=_CODE_B)))
    assert [lvl for lvl, _ in alerts] == ["INFO"]
    assert "2026.7.1-2 to 2026.8.0" in _msgs(alerts)


def test_a_downgrade_is_the_loud_one():
    """The signal the task named as mattering most, and invisible in both the check and the
    monitor before this."""
    alerts, _ = diff_with_notes(_snap(), _snap(openclaw_install=_inst(version="2026.6.0",
                                                                     code=_CODE_B)))
    assert [lvl for lvl, _ in alerts] == ["HIGH"]
    assert "went BACKWARDS" in _msgs(alerts)


def test_an_unorderable_version_change_says_changed_and_not_a_direction():
    alerts, _ = diff_with_notes(
        _snap(openclaw_install=_inst(version="2026.8.0-rc1")),
        _snap(openclaw_install=_inst(version="2026.8.0", code=_CODE_B)))
    assert [lvl for lvl, _ in alerts] == ["INFO"]
    assert "BACKWARDS" not in _msgs(alerts)


def test_a_swapped_build_under_an_unchanged_version_is_high():
    """The attack a version number cannot show, and the reason a content digest is worth
    0.34 s of a scheduled run."""
    alerts, _ = diff_with_notes(_snap(), _snap(openclaw_install=_inst(code=_CODE_B)))
    assert [lvl for lvl, _ in alerts] == ["HIGH"]
    assert "program files changed while the version number stayed" in _msgs(alerts)


def test_a_dependency_set_change_alone_is_informational():
    alerts, _ = diff_with_notes(_snap(), _snap(openclaw_install=_inst(lock="z" * 64)))
    assert [lvl for lvl, _ in alerts] == ["INFO"]
    assert "packages OpenClaw depends on" in _msgs(alerts)


def test_a_capped_code_digest_cannot_raise_the_swapped_build_alert():
    """A partial digest differing from another partial digest is not evidence the program
    files changed — the two runs may simply have stopped at different points."""
    alerts, notes = diff_with_notes(
        _snap(openclaw_install=_inst(code=_CODE_A, capped=True)),
        _snap(openclaw_install=_inst(code=_CODE_B, capped=True)))
    assert not any("program files changed" in m for _, m in alerts)
    assert NOTE_INSPECTION_CAPPED in _cats(notes)


def test_an_install_that_could_not_be_located_is_a_note_and_never_an_alert():
    """False alarm 1, pinned. A cron job's minimal PATH really does produce this."""
    curr = _snap()
    del curr["openclaw_install"]
    alerts, notes = diff_with_notes(_snap(), curr)
    assert alerts == []
    assert NOTE_UNDETERMINED in _cats(notes)
    assert any("could not find it" in m for _, m in notes)


def test_an_install_appearing_for_the_first_time_is_silent():
    """The other half of the same flap: the interactive run after a cron run must not
    report OpenClaw as newly installed."""
    prev = _snap()
    del prev["openclaw_install"]
    alerts, _ = diff_with_notes(prev, _snap())
    assert alerts == []


def test_a_baseline_predating_the_dimension_produces_no_alert():
    prev = _snap()
    del prev["openclaw_install"]
    del prev["skill_provenance"]
    alerts, _ = diff_with_notes(prev, _snap())
    assert alerts == []


def test_nothing_moving_says_nothing():
    alerts, _ = diff_with_notes(_snap(), _snap())
    assert alerts == []


# ================================================================ skill provenance

def test_a_skill_update_is_reported_with_both_versions():
    alerts, _ = diff_with_notes(_snap(), _snap(skill_provenance=_prov(version="3.62.0",
                                                                     artifact=_ART_B)))
    assert [lvl for lvl, _ in alerts] == ["INFO"]
    assert "3.61.0 to 3.62.0" in _msgs(alerts)
    assert "--vet-skill" in _msgs(alerts)


def test_a_replaced_artifact_under_an_unchanged_version_is_high():
    """The version is the publisher's to choose and the digest is not, so this is the
    stronger signal even though it looks like the quieter one."""
    alerts, _ = diff_with_notes(_snap(), _snap(skill_provenance=_prov(artifact=_ART_B)))
    assert [lvl for lvl, _ in alerts] == ["HIGH"]
    assert "replaced with different content" in _msgs(alerts)


def test_the_two_install_records_falling_out_of_step_is_reported_once():
    """Reported on the TRANSITION only. A skill whose records already disagreed when the
    baseline was taken would otherwise re-alert forever, which is how a warning becomes
    something the reader learns to skip."""
    alerts, _ = diff_with_notes(_snap(), _snap(skill_provenance=_prov(corroborated=False)))
    assert [lvl for lvl, _ in alerts] == ["MEDIUM"]
    assert "no longer agree" in _msgs(alerts)
    already, _ = diff_with_notes(_snap(skill_provenance=_prov(corroborated=False)),
                                 _snap(skill_provenance=_prov(corroborated=False)))
    assert already == []


def test_losing_the_second_witness_is_not_reported_as_a_disagreement():
    """`corroborated` is bool|None for exactly this: a skill whose origin.json became
    unreadable has no second witness, which is a different fact from the witnesses
    conflicting."""
    alerts, _ = diff_with_notes(_snap(), _snap(skill_provenance=_prov(corroborated=None)))
    assert alerts == []


def test_a_newly_installed_skill_is_reported():
    both = dict(_prov())
    both["helper"] = dict(_prov()["clawseccheck"])
    alerts, _ = diff_with_notes(_snap(), _snap(skill_provenance=both))
    assert "1 skill(s) were installed" in _msgs(alerts)
    assert "helper" in _msgs(alerts)


def test_a_removed_skill_is_reported_on_a_sighted_run():
    alerts, _ = diff_with_notes(_snap(), _snap(skill_provenance={}))
    assert "no longer in your install records" in _msgs(alerts)


def test_a_removed_skill_is_NOT_reported_on_a_blind_run():
    """B-269's rule, carried to this dimension: the workspace roots are config-derived, so
    a run that could not read the config sees a subset and every disappearance is an
    artifact rather than an event."""
    alerts, _ = diff_with_notes(_snap(), _snap(skill_provenance={},
                                               config_parse_error=True))
    assert not any("no longer in your install records" in m for _, m in alerts)


def test_the_dimension_is_registered_as_shrinkable_not_config_derived():
    """The list it is in decides how a blind run repairs it: `_CONFIG_DIMENSIONS` are
    carried wholesale from the previous snapshot, shrinkable ones are union-merged so this
    run's real observations still win. Putting a shrink-only dimension in the wrong list
    would freeze it at whatever the last sighted run saw."""
    assert "skill_provenance" in _SHRINKABLE_DIMENSIONS
    assert "skill_provenance" in WATCHED_DIMENSIONS
    assert "openclaw_install" in WATCHED_DIMENSIONS


def test_an_absent_provenance_dimension_never_tells_the_user_to_delete_their_baseline():
    """D2, reproduced. The first version routed this through the generic `pair_or_note`
    helper, whose absent-from-curr branch says "the saved record for them is damaged.
    Delete the monitor state file to start a fresh baseline." Both halves are wrong: the
    saved record is fine — THIS run found no install records — and the remedy destroys the
    user's entire drift history.

    The key is absent whenever a run comes up empty: no lock file in any workspace it
    searched, an unreadable or oversized one, or a blind run whose only workspace came from
    the config. None of those is a damaged baseline.

    This test replaces one that asserted `assert notes` and therefore pinned nothing about
    what the note said."""
    curr = _snap()
    del curr["skill_provenance"]
    alerts, notes = diff_with_notes(_snap(), curr)
    assert alerts == []
    # Scoped to the note about THIS dimension. A blanket search over every note catches a
    # sibling dimension's own legitimate "damaged" wording — which is how the first version
    # of this assertion failed for a reason it did not name.
    mine = [m for _, m in notes if "skills came from" in m]
    assert len(mine) == 1, [m for _, m in notes]
    assert "found no install records" in mine[0]
    assert "Delete the monitor state file" not in mine[0]
    assert "damaged" not in mine[0]


def test_a_genuinely_damaged_record_still_gets_the_damaged_wording():
    """The other direction — without it, the fix above could have deleted the branch that
    IS correct rather than narrowing it."""
    _, notes = diff_with_notes(_snap(skill_provenance="not-a-dict"), _snap())
    # Scoped to this dimension's own note, for the same reason its sibling above is: a
    # blanket search would pass on any other dimension's "damaged" wording and prove
    # nothing about this branch. Verified at the time of writing that this IS the only
    # record_damaged note the fixture produces.
    mine = [m for _, m in notes if "skills came from" in m]
    assert len(mine) == 1, [m for _, m in notes]
    assert "damaged" in mine[0] and "Delete the monitor state file" in mine[0]


def test_adding_a_workspace_to_the_config_does_not_report_a_replaced_skill(tmp_path):
    """D1, the BLOCKER, reproduced end-to-end through the real reader.

    Two workspaces each hold a skill of the same NAME with different artifact digests.
    With last-wins merging, merely adding `agents.list[].workspace` to openclaw.json
    changed which record won and the diff read the swap as a content replacement — a false
    HIGH supply-chain alert from an ordinary config edit, and the same flip in reverse the
    moment a blind run dropped the config root again."""
    import json as _json

    from clawseccheck.skillprovenance import read_provenance

    def _ws(root, digest):
        (root / ".clawhub").mkdir(parents=True, exist_ok=True)
        (root / ".clawhub" / "lock.json").write_text(_json.dumps({
            "version": 1, "skills": {"clawseccheck": {
                "version": "3.61.0", "installedAt": 1, "registry": "r",
                "artifact": {"sha256": digest}, "skillFile": {"sha256": "s" * 64}}}}),
            encoding="utf-8")

    _ws(tmp_path / "workspace", _ART_A)
    other = tmp_path / "second"
    _ws(other, _ART_B)

    without = read_provenance(tmp_path, None).as_dimension()
    with_cfg = read_provenance(
        tmp_path, {"agents": {"list": [{"workspace": str(other)}]}}).as_dimension()
    assert without["clawseccheck"]["artifact_sha256"] == \
        with_cfg["clawseccheck"]["artifact_sha256"], \
        "the winning record must not depend on the config"
    # The one field that DOES move is `ambiguous`, and it should: a second, disagreeing
    # source really did appear. That is disclosed as a note, never as a supply-chain alert.
    assert with_cfg["clawseccheck"]["ambiguous"] is True

    alerts, notes = diff_with_notes(_snap(skill_provenance=without),
                                    _snap(skill_provenance=with_cfg))
    assert alerts == [], f"a config edit produced {alerts}"
    assert any("more than one of your workspaces" in m.lower() for _, m in notes)


def test_the_first_run_after_this_release_does_not_tell_users_to_delete_anything():
    """The regression I introduced WHILE fixing D2, and the worst of the lot: every
    existing user's first post-v8 run has the key in `curr` and not in `prev`, and the
    first version of the bespoke block had no branch for it — so it fell through to the
    damaged wording and told each of them to delete their drift history.

    Silent is correct here: the generic `watched` manifest arm already says the baseline
    predates this comparison."""
    prev = _snap()
    del prev["skill_provenance"]
    alerts, notes = diff_with_notes(prev, _snap())
    assert alerts == []
    text = " ".join(m for _, m in notes)
    assert "Delete the monitor state file" not in text
    assert "skills came from" not in text


def test_a_lock_only_change_is_only_reported_when_everything_else_is_evidenced():
    """D3, second location. Tightening the swapped-build branch pushed three cases into
    this one, whose sentence claims MORE — that both the version and the program files are
    unchanged. Each must be evidenced rather than merely un-contradicted."""
    lock_moved = _inst(lock="z" * 64)
    # version missing on one side
    alerts, _ = diff_with_notes(_snap(openclaw_install=_inst(version="")),
                                _snap(openclaw_install=lock_moved))
    assert not any("program files unchanged" in m for _, m in alerts)
    # code digest actually differs
    alerts, _ = diff_with_notes(_snap(),
                                _snap(openclaw_install=_inst(code=_CODE_B, lock="z" * 64)))
    assert not any("program files unchanged" in m for _, m in alerts)
    # code digest was capped, so "unchanged" is not something this run can say
    alerts, _ = diff_with_notes(
        _snap(openclaw_install=_inst(capped=True)),
        _snap(openclaw_install=_inst(lock="z" * 64, capped=True)))
    assert not any("program files unchanged" in m for _, m in alerts)


def test_a_skill_recorded_in_two_disagreeing_workspaces_is_not_compared():
    """The remaining half of D1. Sorting the config roots makes the winner stable but not
    correct: when two workspaces hold different records under one name, which one the agent
    loads is not something this tool can determine. So the conflict is disclosed and the
    digest comparison stands down, rather than a picked-at-random record being compared."""
    ambiguous = {"clawseccheck": {**_prov()["clawseccheck"], "ambiguous": True,
                                  "artifact_sha256": _ART_B}}
    alerts, notes = diff_with_notes(_snap(), _snap(skill_provenance=ambiguous))
    assert not any("replaced with different content" in m for _, m in alerts)
    assert any("more than one of your workspaces" in m.lower() for _, m in notes)


def test_a_swapped_build_needs_both_versions_recorded_and_equal():
    """D3. The `elif` chain was reached when one side's version was never recorded, and the
    sentence then asserted the number "stayed at" a value the other side did not have —
    a same-version swap claimed out of a missing field."""
    alerts, _ = diff_with_notes(_snap(openclaw_install=_inst(version="")),
                                _snap(openclaw_install=_inst(version="2026.8.0",
                                                             code=_CODE_B)))
    assert not any("stayed at" in m for _, m in alerts)


def test_a_replaced_skill_needs_both_versions_recorded_and_equal():
    before = _prov(version="")
    after = _prov(version="3.61.0", artifact=_ART_B)
    alerts, _ = diff_with_notes(_snap(skill_provenance=before),
                                _snap(skill_provenance=after))
    assert not any("stayed at" in m for _, m in alerts)


def test_a_run_that_found_no_install_records_writes_no_dimension_at_all(tmp_path, capsys):
    """A SURVIVING MUTANT. Dropping the `_scan.present` gate in `cli.py` — so a run that
    found no lock file records `{}` — broke nothing in this suite: `present` was pinned six
    times at the leaf and nothing tested the consumer that acts on it.

    Recording `{}` states "you have no skills installed" about a setup we never looked at
    the right place for, and the next run that DOES find the lock file reports every skill
    as newly installed. This drives the real CLI against a home with no ClawHub records at
    all, which is what a fixture home is."""
    import json as _json
    import os as _os

    from clawseccheck.cli import main

    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}',
                                        encoding="utf-8")
    _os.chmod(home / "openclaw.json", 0o600)
    store = tmp_path / "store"
    assert main(["--monitor", "--home", str(home), "--data-dir", str(store)]) == 0
    capsys.readouterr()
    saved = _json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert "skill_provenance" not in saved, (
        "an absent lock file must leave the key ABSENT — `{}` would claim we established "
        "there are no installed skills"
    )


def test_a_junk_record_on_either_side_is_skipped_rather_than_compared():
    alerts, _ = diff_with_notes(_snap(skill_provenance={"clawseccheck": "junk"}),
                                _snap())
    assert alerts == []
