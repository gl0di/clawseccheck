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

import json

from clawseccheck.monitor import (
    NOTE_INSPECTION_CAPPED,
    NOTE_UNDETERMINED,
    WATCHED_DIMENSIONS,
    _SHRINKABLE_DIMENSIONS,
    changed_skills,
    diff_with_notes,
)
from clawseccheck.openclawdist import compare_versions
from clawseccheck.skillprovenance import read_provenance

_CODE_A, _CODE_B = "a" * 64, "b" * 64
_ART_A, _ART_B = "c" * 64, "d" * 64
_ART_C = "e" * 64
_SKF = "s" * 64


def _ws(root, *, name="clawseccheck", version="3.61.0", artifact=_ART_A, skill_file=_SKF):
    """One workspace's ClawHub lock file, in the real on-disk shape."""
    (root / ".clawhub").mkdir(parents=True, exist_ok=True)
    (root / ".clawhub" / "lock.json").write_text(json.dumps({
        "version": 1, "skills": {name: {
            "version": version, "installedAt": 1, "registry": "https://clawhub.ai",
            "artifact": {"sha256": artifact}, "skillFile": {"sha256": skill_file}}}}),
        encoding="utf-8")
    return root


def _origin(root, *, name="clawseccheck", version="3.61.0", artifact=_ART_A,
            skill_file=_SKF):
    """The second witness the installer writes beside the skill itself."""
    d = root / "skills" / name / ".clawhub"
    d.mkdir(parents=True, exist_ok=True)
    (d / "origin.json").write_text(json.dumps({
        "slug": name, "installedVersion": version, "installedAt": 1,
        "artifact": {"sha256": artifact}, "skillFile": {"sha256": skill_file}}),
        encoding="utf-8")
    return root


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
    """D1, the BLOCKER, reproduced end-to-end through the real reader — and REPRO 1 of the
    follow-up, which is the same config edit reaching the arm one line above.

    Two workspaces each hold a skill of the same NAME with a different version AND a
    different artifact digest. With last-wins merging, merely adding
    `agents.list[].workspace` to openclaw.json changed which record won and the diff read
    the swap as a content replacement — a false HIGH supply-chain alert from an ordinary
    config edit, and the same flip in reverse the moment a blind run dropped the config
    root again.

    The version difference is what this test grew: `ambiguous` gated the HIGH arm only, so
    the very same edit still produced "The skill 'clawseccheck' was updated, from 3.61.0 to
    9.9.9" from the INFO arm — a claim about a record this run could not identify, printed
    beside the note saying so."""
    _ws(tmp_path / "workspace", version="3.61.0", artifact=_ART_A)
    other = tmp_path / "second"
    _ws(other, version="9.9.9", artifact=_ART_B)

    without = read_provenance(tmp_path, None).as_dimension()
    with_cfg = read_provenance(
        tmp_path, {"agents": {"list": [{"workspace": str(other)}]}}).as_dimension()
    assert without["clawseccheck"]["artifact_sha256"] == \
        with_cfg["clawseccheck"]["artifact_sha256"], \
        "the winning record must not depend on the config"
    assert without["clawseccheck"]["version"] == with_cfg["clawseccheck"]["version"]
    # The one field that DOES move is `ambiguous`, and it should: a second, disagreeing
    # source really did appear. That is disclosed as a note, never as a supply-chain alert.
    assert with_cfg["clawseccheck"]["ambiguous"] is True

    # The added root LOSES: `workspace` is one of OpenClaw's own default directories and
    # those are searched before any config-declared one. So the winner did not move, the
    # comparison is MADE rather than stood down, and it finds the winning record unchanged
    # — silence earned by looking, which is strictly stronger than the silence a
    # stand-down buys. (Keying the stand-down on the whole witness SET stood this down and
    # emitted a note instead; keying it on the winner compares and stays quiet.)
    assert without["clawseccheck"]["winner_root"] == \
        with_cfg["clawseccheck"]["winner_root"] == "workspace"
    alerts, notes = diff_with_notes(_snap(skill_provenance=without),
                                    _snap(skill_provenance=with_cfg))
    assert alerts == [], f"a config edit produced {alerts}"
    assert not any("was updated, from" in m for _, m in alerts)
    assert not any("clawseccheck" in m for _, m in notes), (
        f"nothing was declined here — the winning record was compared: {notes}")


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
    digest comparison stands down, rather than a picked-at-random record being compared.

    `corroborated` moves here too, which is what this test grew: the MEDIUM arm was outside
    the guard, so the same undeterminable record produced "The two install records for the
    skill 'clawseccheck' no longer agree with each other. They are written together by the
    installer, so one changing alone is not something an ordinary update produces" — an
    accusation, about a record this run could not identify."""
    ambiguous = {"clawseccheck": {**_prov()["clawseccheck"], "ambiguous": True,
                                  "artifact_sha256": _ART_B, "corroborated": False}}
    alerts, notes = diff_with_notes(_snap(), _snap(skill_provenance=ambiguous))
    assert not any("replaced with different content" in m for _, m in alerts)
    assert not any("no longer agree" in m for _, m in alerts)
    assert alerts == []
    assert any("more than one of your workspaces" in m.lower() for _, m in notes)
    # The accusation must not reappear in the note that replaces it.
    assert not any("ordinary update" in m for _, m in notes)


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


# ============================================ the stand-down: what it covers, and what it
# ============================================ must never buy an attacker

def test_repro_2_two_workspaces_agreeing_on_the_lock_and_not_on_origin(tmp_path):
    """REPRO 2, end-to-end through the real reader.

    Both workspaces hold a BYTE-IDENTICAL lock record; only the skills' own `origin.json`
    files disagree. The old conflict tuple was `(version, artifact, skillFile)`, so this
    came out `ambiguous: False` — an undeterminable winner passed off as a settled one —
    and the MEDIUM arm then accused the user's setup on the strength of whichever record
    first-wins happened to pick.

    The rule the widened tuple encodes: it must cover every field the guarded comparisons
    read. `corroborated` is one of them, so it belongs in the tuple.

    Built as the grounding built it — the added workspace WINS. Config roots are searched
    in sorted order, so declaring `alpha` in run 2 puts it ahead of the `zeta` that run 1
    compared, and the corroboration the MEDIUM arm reads is suddenly a different record's.
    That flip is invisible in the lock files, which are byte-identical, which is exactly
    why the tuple had to grow rather than the arm being told to look harder."""
    zeta, alpha = tmp_path / "zeta", tmp_path / "alpha"
    _ws(zeta), _origin(zeta)                             # agrees      -> corroborated True
    _ws(alpha), _origin(alpha, artifact=_ART_B)          # disagrees   -> corroborated False
    assert sorted((str(alpha), str(zeta)))[0] == str(alpha), "alpha must win the sort"

    def _read(*roots):
        return read_provenance(tmp_path, {"agents": {"list": [
            {"workspace": str(r)} for r in roots]}}).as_dimension()

    before, after = _read(zeta), _read(alpha, zeta)
    assert before["clawseccheck"]["corroborated"] is True
    assert after["clawseccheck"]["corroborated"] is False, (
        "the record the MEDIUM arm reads really did change under it — that is the repro")
    assert after["clawseccheck"]["artifact_sha256"] == \
        before["clawseccheck"]["artifact_sha256"], "the lock files are identical"
    assert after["clawseccheck"]["ambiguous"] is True, (
        "identical locks with disagreeing origin files are still two records this check "
        "cannot choose between — the pre-fix tuple said False here")

    alerts, notes = diff_with_notes(_snap(skill_provenance=before),
                                    _snap(skill_provenance=after))
    assert not any("no longer agree with each other" in m for _, m in alerts)
    assert alerts == []
    assert any("more than one of your workspaces" in m.lower() for _, m in notes)


def test_a_stable_winner_still_gets_its_content_compared(tmp_path):
    """THE FN GUARD, and the reason this change is not just a wider suppression.

    A skill that is ambiguous at the baseline and STILL ambiguous now, with the same root
    winning both times, has a provably stable subject: first-wins picks by root order, and
    the winning root did not move. So a genuine same-version content swap in that winning
    record is a real event and must still be reported at full severity.

    Suppressing on the `ambiguous` bool alone made this case silent — no alert, no note,
    not even queued for re-vet — which is a silence an attacker buys for the cost of one
    extra file in a second workspace. This test fails on the code before that change."""
    ws, other = tmp_path / "workspace", tmp_path / "second"
    _ws(ws, artifact=_ART_A)
    _ws(other, artifact=_ART_C)          # a standing disagreement, in both runs
    cfg = {"agents": {"list": [{"workspace": str(other)}]}}
    before = read_provenance(tmp_path, cfg).as_dimension()

    _ws(ws, artifact=_ART_B)             # the winner's content is swapped, version pinned
    after = read_provenance(tmp_path, cfg).as_dimension()

    assert before["clawseccheck"]["ambiguous"] is True
    assert after["clawseccheck"]["ambiguous"] is True
    assert before["clawseccheck"]["winner_root"] == \
        after["clawseccheck"]["winner_root"] == "workspace", "the winner did not move"

    alerts, _ = diff_with_notes(_snap(skill_provenance=before),
                                _snap(skill_provenance=after))
    assert [lvl for lvl, _ in alerts] == ["HIGH"], alerts
    assert "replaced with different content" in _msgs(alerts)
    # And it reaches the re-vet queue too: the tier that acts on the change, not just the
    # one that prints it.
    assert changed_skills({"skill_provenance": before},
                          {"skill_provenance": after}) == ["clawseccheck"]


def test_a_losing_root_leaving_does_not_stop_the_comparison(tmp_path):
    """THIS TEST USED TO PIN THE BUG, under the name "a witness set that moved stands down
    because the winner may have flipped". It does not flip. `workspace` is one of
    OpenClaw's own default directories and those are searched before any config-declared
    root, so `workspace` wins in BOTH runs — the config root it loses to nothing is simply
    gone in the second. The old assertion (`alerts == []` plus a note) therefore recorded a
    suppression over a record whose identity never moved, and it went green because the
    guard was keyed on the whole witness SET: any change to the set, including one an
    attacker makes, closed every arm.

    Corrected here to assert what is actually true of these two runs — the winning record's
    artifact digest was swapped under a pinned version, and that is a HIGH.

    Keep this test adversarial when it is edited: if a future change makes it pass by
    standing down again, the decoy attack below is the same shape."""
    ws, other = tmp_path / "workspace", tmp_path / "second"
    _ws(ws, artifact=_ART_A)
    _ws(other, artifact=_ART_C)
    before = read_provenance(
        tmp_path, {"agents": {"list": [{"workspace": str(other)}]}}).as_dimension()
    _ws(ws, artifact=_ART_B)
    after = read_provenance(tmp_path, None).as_dimension()

    assert before["clawseccheck"]["ambiguous"] is True
    assert after["clawseccheck"]["ambiguous"] is False
    assert before["clawseccheck"]["n_records"] == 2
    assert after["clawseccheck"]["n_records"] == 1, "the record set really did move"
    assert before["clawseccheck"]["winner_root"] == \
        after["clawseccheck"]["winner_root"] == "workspace", \
        "and the winner really did not — that is why this must still be compared"

    alerts, notes = diff_with_notes(_snap(skill_provenance=before),
                                    _snap(skill_provenance=after))
    assert [lvl for lvl, _ in alerts] == ["HIGH"], alerts
    assert "replaced with different content" in _msgs(alerts)
    assert not [m for c, m in notes if c == NOTE_UNDETERMINED and "clawseccheck" in m]
    assert changed_skills({"skill_provenance": before},
                          {"skill_provenance": after}) == ["clawseccheck"]


def test_the_winner_genuinely_flipping_is_what_stands_the_comparison_down(tmp_path):
    """The other half of the predicate, built so the winner really does move.

    No default workspace directory exists here, so the only roots are the config-declared
    ones and they are searched in sorted order. Declaring `alpha` in the second run puts it
    ahead of the `zeta` the first run compared, so the record under the name is a different
    workspace's — and the version and digest differences between them are differences
    between two records, not a change in one. Comparing them would manufacture "the skill
    was downgraded" out of an ordinary config edit, which is the false alarm the whole
    stand-down exists for."""
    zeta, alpha = tmp_path / "zeta", tmp_path / "alpha"
    _ws(zeta, version="2.0.0", artifact=_ART_A)
    _ws(alpha, version="1.0.0", artifact=_ART_B)

    def _read(*roots):
        return read_provenance(tmp_path, {"agents": {"list": [
            {"workspace": str(r)} for r in roots]}}).as_dimension()

    before, after = _read(zeta), _read(alpha, zeta)
    assert before["clawseccheck"]["winner_root"] != after["clawseccheck"]["winner_root"]
    assert after["clawseccheck"]["ambiguous"] is True

    alerts, notes = diff_with_notes(_snap(skill_provenance=before),
                                    _snap(skill_provenance=after))
    assert alerts == [], f"a config edit that flips the winner produced {alerts}"
    mine = [m for c, m in notes if c == NOTE_UNDETERMINED and "clawseccheck" in m]
    assert len(mine) == 1, notes
    assert "was not compared" in mine[0]
    assert "(2 records found)" in mine[0], "the count comes off whichever side saw them"


def test_a_baseline_written_before_the_winner_field_stands_an_ambiguous_record_down():
    """The upgrade path. An old baseline carries no `winner_root`, so it cannot show which
    record it recorded and an ambiguous comparison against it has nothing to anchor on.
    Stood down, and disclosed — the conservative direction, for exactly one run."""
    base = _prov()["clawseccheck"]
    before = {**base, "ambiguous": True, "n_records": 2}          # no winner_root
    after = {**base, "ambiguous": True, "n_records": 2, "winner_root": "workspace",
             "version": "9.9.9"}
    alerts, notes = diff_with_notes(_snap(skill_provenance={"clawseccheck": before}),
                                    _snap(skill_provenance={"clawseccheck": after}))
    assert alerts == []
    assert len([m for c, m in notes if c == NOTE_UNDETERMINED and "clawseccheck" in m]) == 1


def test_the_winner_is_the_first_root_searched_not_the_first_one_alphabetically(tmp_path):
    """A SURVIVING MUTATION, closed. The winner's identity is `ids[0]` — the root the
    first-wins merge actually took the record from. `sorted(ids)[0]` is a one-word edit
    that looks like tidying and would name a root that lost, so a swap in the record the
    agent loads would be compared against a record it never loaded.

    Undetectable while the field was a digest over the whole set: `sorted(identities)` there
    kept all 67 tests in this file green, which left the ordering claim in its docstring
    undefended. Pinned here on content, not just on the string: the identity named must be
    the identity of the record that won."""
    home_ws, config_ws = tmp_path / "workspace", tmp_path / "aaa-sorts-first"
    _ws(home_ws, version="2.0.0", artifact=_ART_A)
    _ws(config_ws, version="1.0.0", artifact=_ART_B)
    dim = read_provenance(tmp_path, {"agents": {"list": [
        {"workspace": str(config_ws)}]}}).as_dimension()["clawseccheck"]

    assert sorted(("workspace", "aaa-sorts-first"))[0] == "aaa-sorts-first", \
        "the losing root must sort first, or this pins nothing"
    assert dim["winner_root"] == "workspace"
    assert (dim["version"], dim["artifact_sha256"]) == ("2.0.0", _ART_A), \
        "the named winner must be the root the winning record came from"


def test_every_stand_down_is_disclosed_and_none_of_them_accuses():
    """B-269's rule, and the requirement this change was written under: a comparison that
    stands down must SAY SO. A silenced branch with no note is a bare all-clear printed
    over ground nobody looked at.

    The second half matters as much: the sentence states what was observed and stops. "Two
    of your workspaces hold different records for this skill, so its content was not
    compared" is a fact; "the records no longer agree, which an ordinary update does not
    produce" is a verdict, and printing it about an undeterminable record would accuse a
    user of an attack for editing their config."""
    base = _prov()["clawseccheck"]
    cases = {
        "newly ambiguous": ({**base}, {**base, "ambiguous": True,
                                       "artifact_sha256": _ART_B}),
        "ambiguity resolved": ({**base, "ambiguous": True}, {**base,
                                                             "artifact_sha256": _ART_B}),
        "winner moved": ({**base, "ambiguous": True, "n_records": 2,
                          "winner_root": "workspace"},
                         {**base, "ambiguous": True, "n_records": 3,
                          "winner_root": "workspace-home", "version": "9.9.9"}),
        "baseline predates the winner field": (
            {**base, "ambiguous": True},
            {**base, "ambiguous": True, "n_records": 2, "winner_root": "workspace",
             "corroborated": False}),
    }
    for label, (before, after) in cases.items():
        alerts, notes = diff_with_notes(_snap(skill_provenance={"clawseccheck": before}),
                                        _snap(skill_provenance={"clawseccheck": after}))
        assert alerts == [], f"{label}: stood down but still alerted with {alerts}"
        mine = [m for c, m in notes if c == NOTE_UNDETERMINED and "clawseccheck" in m]
        assert len(mine) == 1, f"{label}: silenced with notes {notes}"
        assert "was not compared" in mine[0], f"{label}: {mine[0]}"
        for accusation in ("no longer agree", "ordinary update", "replaced with",
                           "was updated, from"):
            assert accusation not in mine[0], f"{label} accuses: {mine[0]}"
    assert "(3 records found)" in " ".join(
        m for _, m in diff_with_notes(
            _snap(skill_provenance={"clawseccheck": cases["winner moved"][0]}),
            _snap(skill_provenance={"clawseccheck": cases["winner moved"][1]}))[1])


def test_a_real_change_on_an_unambiguous_skill_still_alerts_at_full_severity(tmp_path):
    """THE FN DIRECTION, for all three arms, end-to-end on the ordinary shape: ONE
    workspace, one install record, nothing undeterminable anywhere.

    Every line of this change makes an alert quieter somewhere, so the thing to prove is
    that the ordinary case — the one every real machine is in, and the one where 100% of
    the real fleet's skills sit — did not get quieter with it."""
    ws = tmp_path / "workspace"

    # (1) INFO — the version moved.
    _ws(ws, version="1.0.0", artifact=_ART_A)
    _origin(ws, version="1.0.0", artifact=_ART_A)
    before = read_provenance(tmp_path).as_dimension()
    assert before["clawseccheck"]["ambiguous"] is False
    assert before["clawseccheck"]["n_records"] == 1
    _ws(ws, version="2.0.0", artifact=_ART_B)
    _origin(ws, version="2.0.0", artifact=_ART_B)
    alerts, _ = diff_with_notes(_snap(skill_provenance=before),
                                _snap(skill_provenance=read_provenance(
                                    tmp_path).as_dimension()))
    assert [lvl for lvl, _ in alerts] == ["INFO"], alerts
    assert "was updated, from 1.0.0 to 2.0.0" in _msgs(alerts)

    # (2) HIGH — the content moved under a pinned version.
    _ws(ws, version="2.0.0", artifact=_ART_B)
    _origin(ws, version="2.0.0", artifact=_ART_B)
    before = read_provenance(tmp_path).as_dimension()
    _ws(ws, version="2.0.0", artifact=_ART_C)
    _origin(ws, version="2.0.0", artifact=_ART_C)
    alerts, _ = diff_with_notes(_snap(skill_provenance=before),
                                _snap(skill_provenance=read_provenance(
                                    tmp_path).as_dimension()))
    assert [lvl for lvl, _ in alerts] == ["HIGH"], alerts
    assert "replaced with different content" in _msgs(alerts)

    # (3) MEDIUM — the two witnesses fell out of step.
    before = read_provenance(tmp_path).as_dimension()
    assert before["clawseccheck"]["corroborated"] is True
    _origin(ws, version="2.0.0", artifact=_ART_A)      # origin.json alone moves
    after = read_provenance(tmp_path).as_dimension()
    assert after["clawseccheck"]["corroborated"] is False
    assert after["clawseccheck"]["ambiguous"] is False, "one workspace is never a conflict"
    alerts, _ = diff_with_notes(_snap(skill_provenance=before),
                                _snap(skill_provenance=after))
    assert [lvl for lvl, _ in alerts] == ["MEDIUM"], alerts
    assert "no longer agree with each other" in _msgs(alerts)


def test_the_conflict_tuple_covers_every_field_the_guarded_arms_read():
    """The invariant repro 2 is an instance of: a comparison gated on `ambiguous` must not
    read a field that `ambiguous` never looked at. Mechanized rather than remembered,
    because the next arm added here will be written by someone who never saw repro 2."""
    import inspect
    import re

    from clawseccheck.skillprovenance import CONFLICT_FIELDS

    src = inspect.getsource(diff_with_notes)
    block = src[src.index("# ---- F-174: where each installed skill came from"):
                src.index("# ---- F-170:")]
    read = set(re.findall(r'_[ab]\.get\("([a-z_0-9]+)"', block))
    assert read, "the field scan matched nothing — the arms or their names moved"
    # `ambiguous` / `n_records` / `witness_digest` are the stand-down machinery itself, not
    # subjects of a verdict.
    verdict_fields = read - {"ambiguous", "n_records", "winner_root"}
    assert verdict_fields <= set(CONFLICT_FIELDS), (
        f"{sorted(verdict_fields - set(CONFLICT_FIELDS))} is read by a guarded arm but is "
        f"not in CONFLICT_FIELDS, so two records differing only in it would be compared as "
        f"one subject — exactly repro 2")
    # The tuple may be WIDER than what is read today; that direction only ever stands more
    # comparisons down. Pinned so the slack stays deliberate and named.
    assert set(CONFLICT_FIELDS) - verdict_fields == {"skill_file_sha256"}


# ================================================ the decoy attack, end to end, and the
# ================================================ benign battery it must not re-open

def _lab(home, *, version, artifact, decoy=None):
    """A home the real CLI can audit: a config it can read, one default workspace holding
    the install record, and optionally ONE decoy lock file in a second default workspace.

    `workspace-home` is first in `WORKSPACE_DIRS`, so it wins; `workspace` is last, so the
    decoy loses. No config edit is involved anywhere — both are paths OpenClaw itself uses,
    which is what makes the decoy something an attacker can drop with a single write.
    """
    import os

    home.mkdir(parents=True, exist_ok=True)
    (home / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}',
                                        encoding="utf-8")
    os.chmod(home / "openclaw.json", 0o600)
    _ws(home / "workspace-home", name="demo", version=version, artifact=artifact)
    _origin(home / "workspace-home", name="demo", version=version, artifact=artifact)
    if decoy is not None:
        _ws(home / "workspace", name="demo", version=decoy[0], artifact=decoy[1])
    return home


def test_a_decoy_lock_file_cannot_silence_a_downgrade_in_the_winning_record(tmp_path,
                                                                            capsys):
    """THE ATTACK, reproduced end to end through the real `--monitor` CLI over four runs.

    Keying the stand-down on the whole witness SET made this silent. The set is every root
    holding a record, so the ATTACKER can move it: drop one `<workspace>/.clawhub/lock.json`
    — a path OpenClaw itself uses, needing no config edit and no privilege — and the digests
    differ, every arm stands down, and a skill downgraded 2.0.0 -> 1.0.0 with a swapped
    artifact digest passes with `No new threats among what was compared.` and exit 0.

    The measured pre-fix behaviour, which is why runs 3 and 4 are here: the alert was not
    deferred, it was LOST. By the third run the tampered record is what the baseline holds,
    so there is nothing left to differ and no later run ever raises it.

    The winner does not move in any of this — `workspace-home` is searched before
    `workspace` — so there is nothing undeterminable about the record being compared, and
    the downgrade must be reported on the run it happens."""
    from clawseccheck.cli import main

    home, store = tmp_path / "home", tmp_path / "store"
    _lab(home, version="2.0.0", artifact=_ART_A)
    argv = ["--monitor", "--home", str(home), "--data-dir", str(store)]
    main(argv)                                        # run 1 — baseline
    capsys.readouterr()

    # The whole attack: downgrade + swapped artifact in the winner, one decoy beside it.
    _lab(home, version="1.0.0", artifact=_ART_B, decoy=("2.0.0", _ART_C))
    dim = read_provenance(home).as_dimension()["demo"]
    assert dim["winner_root"] == "workspace-home", "the decoy must not become the winner"
    assert dim["n_records"] == 2 and dim["ambiguous"] is True, "the decoy must be seen"

    main(argv)                                        # run 2 — the run that must alert
    said = capsys.readouterr().out
    assert "was updated, from 2.0.0 to 1.0.0" in said, said
    assert "No new threats" not in said, said

    # Runs 3 and 4: the set is stable now and the tampered record is the baseline, so
    # silence here is correct. This is the window the set-keyed build gave away — it is
    # only harmless because run 2 spoke.
    for _ in range(2):
        main(argv)
        assert "No new threats" in capsys.readouterr().out


def test_the_benign_battery_stays_silent(tmp_path):
    """Every ordinary edit that has ever been suspected of moving this dimension, run
    through the real reader. Notes are fine and alerts are not: none of these changes what
    the agent loads, and the winning root is `workspace` throughout.

    The two original F-174 repros are tested above by name
    (`test_adding_a_workspace_to_the_config_does_not_report_a_replaced_skill`,
    `test_repro_2_two_workspaces_agreeing_on_the_lock_and_not_on_origin`); these are the
    rest of the config edits a user actually makes."""
    home = tmp_path
    _ws(home / "workspace", version="2.0.0", artifact=_ART_A)
    _origin(home / "workspace", version="2.0.0", artifact=_ART_A)
    # Losing roots that DISAGREE, so the ambiguity in these cases is real rather than a
    # technicality — a stand-down keyed on anything but the winner would close here.
    _ws(home / "second", version="9.9.9", artifact=_ART_B)
    _ws(home / "third", version="8.8.8", artifact=_ART_C)
    (home / "renamed").mkdir()
    _ws(home / "renamed", version="9.9.9", artifact=_ART_B)
    (home / "truncated" / ".clawhub").mkdir(parents=True)
    (home / "truncated" / ".clawhub" / "lock.json").write_text(
        '{"version": 1, "skills": {"clawsecc', encoding="utf-8")

    def _cfg(*workspaces):
        return {"agents": {"list": [{"workspace": w} for w in workspaces]}}

    one, two = str(home / "second"), str(home / "third")
    cases = {
        "an agent is added":            (_cfg(one), _cfg(one, two)),
        "agents.list is reordered":     (_cfg(one, two), _cfg(two, one)),
        "the path is written relative": (_cfg(one), _cfg("second")),
        "a workspace is renamed":       (_cfg(one), _cfg(str(home / "renamed"))),
        "two agents share one dir":     (_cfg(one), _cfg(one, one)),
        "a lock file is truncated":     (_cfg(one), _cfg(one, str(home / "truncated"))),
    }
    for label, (before_cfg, after_cfg) in cases.items():
        before = read_provenance(home, before_cfg).as_dimension()
        after = read_provenance(home, after_cfg).as_dimension()
        assert before["clawseccheck"]["winner_root"] == \
            after["clawseccheck"]["winner_root"] == "workspace", label
        alerts, _ = diff_with_notes(_snap(skill_provenance=before),
                                    _snap(skill_provenance=after))
        assert alerts == [], f"{label} produced {alerts}"
        assert changed_skills({"skill_provenance": before},
                              {"skill_provenance": after}) == [], label
