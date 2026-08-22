"""B-541 — a decoy install record in an earlier-sorting workspace silenced the real one.

`read_provenance` elected a winner across workspaces by first-wins over the search order, and
the consumer compared THAT record across runs. One `lock.json` in a directory that sorts first
made the decoy the permanent winner, so a downgrade or content swap in the user's own record
was never compared and never reported — on every build since the dimension existed.

Three previous repairs all kept the election and argued about *when* the elected record may be
compared: stand down on `ambiguous`, on the witness set, on the winner's identity. Each was
broken by the next adversarial pass, and the last left the filed defect fully open, because a
decoy that always wins is stable and a guard keyed on stability never closes.

**This removes the election from the verdict path instead.** Every record is compared with
ITSELF across runs, keyed `(root identity, skill name)`. Grounding the question against the
installed dist is what showed the framing was wrong: `resolveAgentWorkspaceDir` gives each
configured agent its OWN workspace, so two records under one skill name are two agents that
each have it installed, and both are live. There is no contest to resolve.

Offline, read-only, stdlib only; writes nothing outside ``tmp_path``.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.monitor import (
    WATCHED_DIMENSIONS,
    changed_skills,
    diff_with_notes,
)
from clawseccheck.skillprovenance import ROOT_MARK, read_provenance

_ART_A, _ART_B, _ART_DECOY = "a" * 64, "b" * 64, "c" * 64
_SKF = "s" * 64


def _lock(root: Path, *, name="clawseccheck", version="2.0.0", artifact=_ART_A):
    (root / ".clawhub").mkdir(parents=True, exist_ok=True)
    (root / ".clawhub" / "lock.json").write_text(json.dumps({
        "version": 1, "skills": {name: {
            "version": version, "installedAt": 1, "registry": "https://clawhub.ai",
            "artifact": {"sha256": artifact}, "skillFile": {"sha256": _SKF}}}}),
        encoding="utf-8")
    return root


def _snap(dim: dict) -> dict:
    return {
        "version": 8, "watched": list(WATCHED_DIMENSIONS),
        "score": 90, "raw_score": 90, "raw_score_scope": "abc", "grade": "A",
        "graded": True, "checks": {"B1": "PASS"}, "checks_not_applicable": [],
        "checks_degraded": [], "behavioral_fired": [], "behavioral_undetermined": [],
        "behavioral_capped": False, "skill_provenance": dim,
    }


def _alerts(before: dict, after: dict):
    return diff_with_notes(_snap(before), _snap(after))


# ---------------------------------------------------------------------------
# The filed defect
# ---------------------------------------------------------------------------

def test_a_decoy_in_an_earlier_sorting_workspace_cannot_silence_the_real_record(tmp_path):
    """The reproduction from the task, end to end through the real reader.

    `WORKSPACE_DIRS` is searched in the order `workspace-home`, `workspace-work`, `workspace`,
    so a decoy in the first wins the election permanently. Before this change the user's own
    record was compared against nothing and the run produced neither an alert nor a note — not
    a declined comparison, but a comparison made about the wrong subject.
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)      # the user's real install
    _lock(home / "workspace-home", version="9.9.9", artifact=_ART_DECOY)   # sorts first

    before = read_provenance(home).as_dimension()
    _lock(home / "workspace", version="1.0.0", artifact=_ART_B)      # downgrade + swap
    after = read_provenance(home).as_dimension()

    assert before["clawseccheck"]["winner_root"] == "workspace-home", (
        "fixture must actually reproduce the decoy winning, or this passes vacuously")
    alerts, _notes = _alerts(before, after)
    assert any("was updated, from 2.0.0 to 1.0.0" in m for _, m in alerts), alerts


def test_the_tampered_record_is_also_handed_to_the_re_vet_trigger(tmp_path):
    """The consumer an earlier draft of this fix missed.

    `changed_skills` is a second reader of this dimension — F-175's tier-3 re-vet trigger —
    and it elected a winner too. Fixing only the drift arm would have left the tampered skill
    reported but not re-vetted. It must return NAMES, deduplicated: the keys are
    `(root, skill)` now, and a naive port hands the caller `workspace::clawseccheck`.
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)
    _lock(home / "workspace-home", version="9.9.9", artifact=_ART_DECOY)
    before = read_provenance(home).as_dimension()
    _lock(home / "workspace", version="1.0.0", artifact=_ART_B)
    after = read_provenance(home).as_dimension()

    assert changed_skills(_snap(before), _snap(after)) == ["clawseccheck"]


# ---------------------------------------------------------------------------
# The three blockers the design review raised, each pinned
# ---------------------------------------------------------------------------

def test_a_decoy_planted_in_a_directory_that_did_not_exist_is_still_reported(tmp_path):
    """BLOCKER 1: the signal must not be bypassable with one `mkdir`.

    `workspace_roots` returns only roots that EXIST, so a decoy planted in a `workspace-home`
    that was absent last run would look like "a root we had not searched before" — benign —
    which is exactly the thing worth reporting. `roots_searched` therefore lists the three
    `WORKSPACE_DIRS` unconditionally: searched-and-absent is not the same fact as not-searched.
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)
    before = read_provenance(home).as_dimension()
    assert f"{ROOT_MARK}workspace-home" in before, (
        "a directory that does not exist must still count as searched")

    _lock(home / "workspace-home", version="9.9.9", artifact=_ART_DECOY)   # the plant
    after = read_provenance(home).as_dimension()

    alerts, _notes = _alerts(before, after)
    assert any("appeared in a workspace that held none" in m for _, m in alerts), alerts


def test_removing_an_agent_from_the_config_is_not_an_alert(tmp_path):
    """BLOCKER 2: an ordinary, fully sighted config edit must stay quiet.

    `trust_removals` is False only when the config could not be READ; deleting an
    `agents.list[]` entry is a sighted edit that simply drops a root. Reporting its records as
    removed would be the defect class this dimension has already shipped twice. A removal may
    only be claimed when this run actually looked in that root — "we looked and it is gone",
    never "we stopped looking".
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)
    extra = home / "second"
    _lock(extra, version="2.0.0", artifact=_ART_A)
    cfg = {"agents": {"list": [{"id": "main"}, {"id": "x", "workspace": str(extra)}]}}

    before = read_provenance(home, cfg).as_dimension()
    after = read_provenance(home, None).as_dimension()          # the agent is removed

    alerts, notes = _alerts(before, after)
    assert alerts == [], alerts
    assert any("did not look in the workspace that held them" in m for _, m in notes), notes


def test_a_single_record_setup_is_unchanged(tmp_path):
    """The overwhelmingly common case must read exactly as it did before.

    One workspace, one record: the wording carries no parenthetical about other workspaces,
    because there are none and saying so would be noise invented by a fix for a rarer shape.
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)
    before = read_provenance(home).as_dimension()
    _lock(home / "workspace", version="3.0.0", artifact=_ART_B)
    after = read_provenance(home).as_dimension()

    alerts, _notes = _alerts(before, after)
    assert len(alerts) == 1, alerts
    assert alerts[0][1] == (
        "The skill 'clawseccheck' was updated, from 2.0.0 to 3.0.0. Run --vet-skill on it "
        "if you did not expect that.")
    assert "agent workspaces" not in alerts[0][1]


# ---------------------------------------------------------------------------
# The new keys must not be mistaken for skills
# ---------------------------------------------------------------------------

def test_the_new_keys_are_never_reported_as_installed_or_removed_skills(tmp_path):
    """`(root, skill)` entries and `::roots` share the map with the skill names.

    Every arm that treated "a key of this dimension" as "a skill" had to be told which it
    means. The installed/removed arms did not, and reported the same skill once per workspace
    and a skill called `::roots`.
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", name="alpha")
    before = read_provenance(home).as_dimension()
    _lock(home / "workspace-home", name="alpha")     # same skill, a second workspace
    after = read_provenance(home).as_dimension()

    alerts, _notes = _alerts(before, after)
    installed = [m for _, m in alerts if "were installed since the last check" in m]
    assert not installed, installed
    # Pin the WHOLE set, not just the absence of one line: asserting only an absence is how a
    # false accusation about a brand-new skill slipped past this test. Here the second record
    # under a name already present, in a root already watched, IS the decoy shape — so the
    # MEDIUM is earned and is the only thing that may fire.
    assert [c for c, _ in alerts] == ["MEDIUM"], alerts
    assert "appeared in a workspace that held none" in alerts[0][1]
    assert not any(ROOT_MARK in m for _, m in alerts)


def test_the_first_run_after_this_release_falls_back_to_the_legacy_comparison(tmp_path):
    """A baseline written before this release carries no per-root keys.

    The per-root pass needs both sides; with only one it would see every record as new. The
    legacy name-keyed comparison still runs on that transition, so an upgrading user loses
    nothing and gains no spurious "N skills were installed" line. This dimension has already
    shipped one upgrade that told every user to delete their drift history; it does not get to
    ship another.
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", version="2.0.0", artifact=_ART_A)
    legacy = {k: v for k, v in read_provenance(home).as_dimension().items()
              if "::" not in k}
    _lock(home / "workspace", version="3.0.0", artifact=_ART_B)
    after = read_provenance(home).as_dimension()

    alerts, _notes = _alerts(legacy, after)
    assert any("was updated, from 2.0.0 to 3.0.0" in m for _, m in alerts), alerts
    assert not any("were installed since the last check" in m for _, m in alerts), alerts


# ---------------------------------------------------------------------------
# What the independent false-negative pass found, each pinned
# ---------------------------------------------------------------------------

def test_an_ordinary_first_install_is_not_accused_of_being_a_second_record(tmp_path):
    """The false alarm this change introduced and Golden Rule #5 calls a hard blocker.

    A `clawhub install` of a brand-new skill lands in a workspace already searched, which was
    the whole test for "a record appeared where we looked and found none" — so every ordinary
    install was told, in a MEDIUM, that its arrival "is how an install is made to look
    unchanged". The name must already have been present for that sentence to be true.
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", name="existing")
    before = read_provenance(home).as_dimension()
    (home / "workspace" / ".clawhub" / "lock.json").write_text(json.dumps({
        "version": 1, "skills": {
            "existing": {"version": "2.0.0", "installedAt": 1,
                         "artifact": {"sha256": _ART_A}, "skillFile": {"sha256": _SKF}},
            "brand-new": {"version": "1.0.0", "installedAt": 1,
                          "artifact": {"sha256": _ART_B}, "skillFile": {"sha256": _SKF}}}}),
        encoding="utf-8")
    after = read_provenance(home).as_dimension()

    alerts, _notes = _alerts(before, after)
    assert [m for _, m in alerts] == [
        "1 skill(s) were installed since the last check: brand-new."], alerts


def test_a_blind_run_cannot_erase_the_searched_root_set(tmp_path):
    """The searched set has to survive `_degrade_snapshot`'s merge, or the decoy alert dies.

    That merge carries a blind run's dimension forward with `{**prev, **curr}` over top-level
    keys. A single `::roots` LIST under one key is replaced wholesale by the blind run's
    shorter one, while the records it guards survive — so one blind run disabled the alert for
    every config-derived root. One key per root is unioned by the same merge instead.
    """
    from clawseccheck.monitor import _degrade_snapshot

    home = tmp_path / ".openclaw"
    extra = home / "second"
    _lock(home / "workspace")
    _lock(extra)
    cfg = {"agents": {"list": [{"id": "main"}, {"id": "x", "workspace": str(extra)}]}}
    sighted = read_provenance(home, cfg).as_dimension()
    blind = read_provenance(home, None).as_dimension()       # config unreadable

    sighted_roots = {k for k in sighted if k.startswith(ROOT_MARK)}
    blind_roots = {k for k in blind if k.startswith(ROOT_MARK)}
    assert sighted_roots - blind_roots, "fixture must actually shrink the set"

    snap = _snap(blind)
    _degrade_snapshot(snap, _snap(sighted))
    merged = {k for k in snap["skill_provenance"] if k.startswith(ROOT_MARK)}
    assert sighted_roots <= merged, "a blind run must not erase what a sighted run searched"

    # And the CONSEQUENCE, not just the keys. The first version of this test asserted the
    # merge and stopped — a pin that would have stayed green if the union survived and the
    # verdict still went silent. Tamper the config root's record on the run after the blind
    # one and require the alert: that is the thing the searched set exists to protect.
    _lock(extra, version="9.9.9", artifact=_ART_B)
    after = read_provenance(home, cfg).as_dimension()
    alerts, _notes = diff_with_notes(snap, _snap(after))
    assert any("was updated, from 2.0.0 to 9.9.9" in m for _, m in alerts), alerts


def test_a_skill_named_like_a_record_key_invents_no_phantom(tmp_path):
    """`workspace::evil` is a legal skill name and must not become a skill called `evil`.

    Partitioning the key produced a subject that exists nowhere — into `changed_skills` and
    into an alert's text, with the name attacker-chosen. A record key is only a record key if
    the part after the separator is a real skill name in the same snapshot.
    """
    home = tmp_path / ".openclaw"
    _lock(home / "workspace", name="workspace::evil", version="1.0.0")
    before = read_provenance(home).as_dimension()
    _lock(home / "workspace", name="workspace::evil", version="2.0.0")
    after = read_provenance(home).as_dimension()

    assert "evil" not in changed_skills(_snap(before), _snap(after))
    alerts, _notes = _alerts(before, after)
    assert not any("'evil'" in m for _, m in alerts), alerts
