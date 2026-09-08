"""F-174 (B) — skill install provenance as a time series.

B181 already reads these digests for a point-in-time verdict. What was missing is watching
them MOVE: `installedVersion`, `installedAt`, `artifact.sha256`. That is how an update is
detected, and it is the only tier of the pre-update story that works without the user's
cooperation, because it needs nothing but the next scheduled run.

**Grounded, not guessed.** Every field name below was read off the maintainer's real
machine before a line of this was written: `<workspace>/.clawhub/lock.json` (27 KB,
`{"version": 1, "skills": {...}}`) and `<skill>/.clawhub/origin.json`, which name the same
facts differently (`version` vs `installedVersion`, and no `verification` block in the
latter). Measured there: one installed skill, the two files agreeing exactly on version,
`installedAt` and both digests, `read_provenance` in 0.4 ms.

Hermetic: every test builds its own workspace in `tmp_path`. Offline, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.collector import WORKSPACE_DIRS as _COLLECTOR_WORKSPACE_DIRS
from clawseccheck.skillprovenance import (
    WORKSPACE_DIRS,
    read_provenance,
    workspace_roots,
)

_A = "e87e9a8be39c612fd572ffc56bce1623cd00aded13f71b67bf31e7c599816f7e"
_S = "17dc0cbda39c12dda19f39ec6ee0e0260edc235203957e99eda7df52071c0e26"


def _record(version: str = "3.61.0", at: int = 1786033098305,
            artifact: str = _A, skill_file: str = _S) -> dict:
    return {
        "version": version, "installedAt": at, "registry": "https://clawhub.ai",
        "artifact": {"kind": "tarball", "sha256": artifact, "integrity": "sha512-x"},
        "skillFile": {"path": "SKILL.md", "sha256": skill_file},
        "verification": {"schema": 1, "ok": True, "decision": "pass"},
    }


def _workspace(home: Path, *, skills: "dict | None" = None, ws: str = "workspace") -> Path:
    root = home / ws
    (root / ".clawhub").mkdir(parents=True, exist_ok=True)
    (root / ".clawhub" / "lock.json").write_text(
        json.dumps({"version": 1, "skills": skills if skills is not None
                    else {"clawseccheck": _record()}}), encoding="utf-8")
    return root


def _origin(root: Path, name: str, *, version: str = "3.61.0", artifact: str = _A,
            skill_file: str = _S) -> Path:
    d = root / "skills" / name / ".clawhub"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "origin.json"
    p.write_text(json.dumps({
        "version": 1, "registry": "https://clawhub.ai", "slug": name,
        "installedVersion": version, "installedAt": 1786033098305,
        "artifact": {"kind": "tarball", "sha256": artifact, "integrity": "sha512-x"},
        "skillFile": {"path": "SKILL.md", "sha256": skill_file},
    }), encoding="utf-8")
    return p


# ---------------------------------------------------------------- the happy path

def test_it_reads_the_install_record_off_the_lock_file(tmp_path):
    _workspace(tmp_path)
    scan = read_provenance(tmp_path)
    assert scan.present is True
    entry = scan.skills["clawseccheck"]
    assert entry.version == "3.61.0"
    assert entry.installed_at == 1786033098305
    assert entry.artifact_sha256 == _A
    assert entry.skill_file_sha256 == _S


def test_an_update_moves_the_fields_an_update_moves(tmp_path):
    """The whole point: three separate facts about the same skill, each of which an update
    changes, so a diff has something to compare rather than a bare name list."""
    _workspace(tmp_path)
    before = read_provenance(tmp_path).as_dimension()
    _workspace(tmp_path, skills={"clawseccheck": _record(
        version="3.62.0", at=1786099999999, artifact="f" * 64)})
    after = read_provenance(tmp_path).as_dimension()
    assert after["clawseccheck"]["version"] != before["clawseccheck"]["version"]
    assert after["clawseccheck"]["installed_at"] != before["clawseccheck"]["installed_at"]
    assert after["clawseccheck"]["artifact_sha256"] != before["clawseccheck"][
        "artifact_sha256"]


def test_a_silent_reinstall_of_the_same_version_still_moves_the_digest(tmp_path):
    """The version number is the attacker's to choose; the artifact digest is not."""
    _workspace(tmp_path)
    before = read_provenance(tmp_path).as_dimension()
    _workspace(tmp_path, skills={"clawseccheck": _record(artifact="a" * 64)})
    after = read_provenance(tmp_path).as_dimension()
    assert after["clawseccheck"]["version"] == before["clawseccheck"]["version"]
    assert after["clawseccheck"]["artifact_sha256"] != before["clawseccheck"][
        "artifact_sha256"]


def test_nothing_changing_produces_an_identical_dimension(tmp_path):
    """Without this, every test above passes for a function that returns something new
    each call — and the monitor would report drift on every scheduled run."""
    _workspace(tmp_path)
    assert read_provenance(tmp_path).as_dimension() == \
        read_provenance(tmp_path).as_dimension()


# ---------------------------------------------------------------- absent vs empty

def test_no_lock_file_at_all_is_not_the_same_as_an_empty_one(tmp_path):
    """"This install does not use ClawHub" and "it does and has nothing installed" are
    different facts. Conflating them makes every skill look removed the day a user moves to
    a workspace layout we did not look in."""
    absent = read_provenance(tmp_path)
    assert absent.present is False and absent.skills == {}
    _workspace(tmp_path, skills={})
    empty = read_provenance(tmp_path)
    assert empty.present is True and empty.skills == {}


def test_a_corrupt_lock_file_reads_as_absent_rather_than_as_empty(tmp_path):
    root = _workspace(tmp_path)
    (root / ".clawhub" / "lock.json").write_text("{not json", encoding="utf-8")
    assert read_provenance(tmp_path).present is False


def test_a_lock_file_with_no_skills_section_says_so(tmp_path):
    root = _workspace(tmp_path)
    (root / ".clawhub" / "lock.json").write_text(json.dumps({"version": 1}),
                                                 encoding="utf-8")
    scan = read_provenance(tmp_path)
    assert scan.present is True and scan.skills == {}
    assert any("no skills section" in n for n in scan.notes)


def test_an_oversized_lock_file_is_refused_rather_than_read(tmp_path):
    """It is written by the audited agent, so its size is not ours to trust. The ceiling is
    roughly 150x the real 27 KB file."""
    root = _workspace(tmp_path)
    (root / ".clawhub" / "lock.json").write_text(
        json.dumps({"version": 1, "skills": {"x": _record()},
                    "pad": "z" * (5 * 1024 * 1024)}), encoding="utf-8")
    assert read_provenance(tmp_path).present is False


# ---------------------------------------------------------------- corroboration

def test_a_matching_origin_file_corroborates(tmp_path):
    root = _workspace(tmp_path)
    _origin(root, "clawseccheck")
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is True


def test_a_disagreeing_origin_file_is_recorded_as_a_disagreement(tmp_path):
    """The two files are written by the same installer at the same moment — measured, they
    agree exactly on the real machine — so one moving alone is not something an ordinary
    update produces."""
    root = _workspace(tmp_path)
    _origin(root, "clawseccheck", artifact="0" * 64)
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is False


def test_a_disagreeing_version_alone_is_enough(tmp_path):
    root = _workspace(tmp_path)
    _origin(root, "clawseccheck", version="9.9.9")
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is False


def test_a_missing_origin_file_is_no_second_witness_and_not_a_disagreement(tmp_path):
    """Three states, not two. A skill installed before origin.json existed, or installed by
    hand, must not be reported as though its records conflicted."""
    _workspace(tmp_path)
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is None


def test_a_corrupt_origin_file_is_also_no_second_witness(tmp_path):
    root = _workspace(tmp_path)
    p = _origin(root, "clawseccheck")
    p.write_text("{broken", encoding="utf-8")
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is None


def test_installed_at_is_deliberately_not_part_of_the_corroboration(tmp_path):
    """It is the same value in both files today, but it is a timestamp written by two
    separate writes. Building a mismatch signal on clock equality is how a benign
    millisecond becomes an accusation."""
    root = _workspace(tmp_path)
    p = _origin(root, "clawseccheck")
    data = json.loads(p.read_text(encoding="utf-8"))
    data["installedAt"] = 1786033098999
    p.write_text(json.dumps(data), encoding="utf-8")
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is True


# ---------------------------------------------------------------- roots and bounds

def test_the_workspace_names_stay_in_step_with_the_collector():
    """The three names are duplicated here rather than imported, because this is a leaf and
    importing the collector would invert the layering for three strings. That trade is only
    safe while something notices when they drift."""
    assert list(WORKSPACE_DIRS) == list(_COLLECTOR_WORKSPACE_DIRS)


def test_a_config_declared_workspace_is_also_searched(tmp_path):
    """`agents.defaults.workspace` can put the install records somewhere else entirely, and
    a scan that missed it would report every skill as absent."""
    elsewhere = tmp_path / "custom"
    (elsewhere / ".clawhub").mkdir(parents=True)
    (elsewhere / ".clawhub" / "lock.json").write_text(
        json.dumps({"version": 1, "skills": {"helper": _record()}}), encoding="utf-8")
    cfg = {"agents": {"defaults": {"workspace": str(elsewhere)}}}
    assert "helper" in read_provenance(tmp_path, cfg).skills


def test_a_per_agent_workspace_is_searched_too(tmp_path):
    elsewhere = tmp_path / "agent-one"
    (elsewhere / ".clawhub").mkdir(parents=True)
    (elsewhere / ".clawhub" / "lock.json").write_text(
        json.dumps({"version": 1, "skills": {"solo": _record()}}), encoding="utf-8")
    cfg = {"agents": {"list": [{"workspace": str(elsewhere)}]}}
    assert "solo" in read_provenance(tmp_path, cfg).skills


def test_the_config_can_only_ADD_roots_which_is_why_this_dimension_is_shrinkable(tmp_path):
    """The invariant `monitor._SHRINKABLE_DIMENSIONS` depends on: a run that could not read
    the config sees a SUBSET, never a superset. If a config key could ever REMOVE a root,
    a blind run could fabricate an appearance and the shrinkable treatment would be unsound.
    """
    _workspace(tmp_path)
    blind = set(read_provenance(tmp_path, None).skills)
    elsewhere = tmp_path / "extra"
    (elsewhere / ".clawhub").mkdir(parents=True)
    (elsewhere / ".clawhub" / "lock.json").write_text(
        json.dumps({"version": 1, "skills": {"extra": _record()}}), encoding="utf-8")
    sighted = set(read_provenance(
        tmp_path, {"agents": {"defaults": {"workspace": str(elsewhere)}}}).skills)
    assert blind and blind < sighted, "the config view must be a strict superset"


def test_a_workspace_root_is_never_listed_twice(tmp_path):
    """A config that names the default workspace explicitly must not make every skill in it
    appear twice, or get scanned twice on every run."""
    _workspace(tmp_path)
    cfg = {"agents": {"defaults": {"workspace": str(tmp_path / "workspace")},
                      "list": [{"workspace": str(tmp_path / "workspace")}]}}
    roots = workspace_roots(tmp_path, cfg)
    assert len(roots) == len(set(str(r) for r in roots)) == 1


def test_reordering_or_adding_an_agent_does_not_change_the_winning_record(tmp_path):
    """D1's surviving half. First-wins fixed default-vs-config; it did NOT fix ordering
    among CONFIG roots, and an independent pass flipped the winner by adding an agent to
    `agents.list` — not even reordering one. `workspace_roots` now sorts the config-derived
    roots, so an ordinary config edit cannot change what this reports."""
    a, b = tmp_path / "wsA", tmp_path / "wsB"
    for root, digest in ((a, _A), (b, "f" * 64)):
        (root / ".clawhub").mkdir(parents=True)
        (root / ".clawhub" / "lock.json").write_text(json.dumps(
            {"version": 1, "skills": {"dup": _record(artifact=digest)}}), encoding="utf-8")
    one = read_provenance(tmp_path, {"agents": {"list": [{"workspace": str(b)}]}})
    two = read_provenance(tmp_path, {"agents": {"list": [{"workspace": str(a)},
                                                         {"workspace": str(b)}]}})
    three = read_provenance(tmp_path, {"agents": {"list": [{"workspace": str(b)},
                                                           {"workspace": str(a)}]}})
    assert two.as_dimension()["dup"]["artifact_sha256"] == \
        three.as_dimension()["dup"]["artifact_sha256"], "order must not decide the winner"
    assert one.skills["dup"].ambiguous is False, "one source is not a conflict"
    assert two.skills["dup"].ambiguous is True, "two disagreeing sources must be disclosed"


def test_a_relative_workspace_is_resolved_against_home_not_the_working_directory(tmp_path,
                                                                                 monkeypatch):
    """The second D1 vector, and it needs no config edit at all: a bare `expanduser()` left
    a relative path CWD-relative, so running the same check from a different directory read
    a different workspace and produced the same false HIGH. `collector._config_workspace_
    dirs` (B-161) already resolves this key against *home*, and this now matches it."""
    (tmp_path / "rel" / ".clawhub").mkdir(parents=True)
    (tmp_path / "rel" / ".clawhub" / "lock.json").write_text(json.dumps(
        {"version": 1, "skills": {"here": _record()}}), encoding="utf-8")
    cfg = {"agents": {"defaults": {"workspace": "rel"}}}
    elsewhere = tmp_path / "cwd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert "here" in read_provenance(tmp_path, cfg).skills
    monkeypatch.chdir(tmp_path)
    assert "here" in read_provenance(tmp_path, cfg).skills


def test_a_config_workspace_symlinked_to_a_default_is_not_a_second_source(tmp_path):
    """De-duplication is on the RESOLVED path, matching the collector. Treating a symlink
    to the default workspace as a second source would manufacture the exact conflict the
    de-dup exists to avoid."""
    _workspace(tmp_path)
    link = tmp_path / "aliased"
    link.symlink_to(tmp_path / "workspace", target_is_directory=True)
    scan = read_provenance(tmp_path, {"agents": {"defaults": {"workspace": str(link)}}})
    assert scan.skills["clawseccheck"].ambiguous is False


def test_a_nonexistent_configured_workspace_is_skipped_quietly(tmp_path):
    _workspace(tmp_path)
    cfg = {"agents": {"defaults": {"workspace": str(tmp_path / "gone")}}}
    assert "clawseccheck" in read_provenance(tmp_path, cfg).skills


def test_a_malformed_config_does_not_take_the_scan_down(tmp_path):
    _workspace(tmp_path)
    for cfg in ({"agents": "nope"}, {"agents": {"list": "nope"}},
                {"agents": {"defaults": {"workspace": 42}}},
                {"agents": {"list": [None, 7, {"workspace": None}]}}):
        assert "clawseccheck" in read_provenance(tmp_path, cfg).skills


def test_more_skills_than_the_cap_is_disclosed_not_silently_truncated(tmp_path):
    _workspace(tmp_path, skills={f"s{i}": _record() for i in range(30)})
    scan = read_provenance(tmp_path, max_skills=10)
    assert scan.capped is True and len(scan.skills) == 10
    assert any("more installed skills" in n for n in scan.notes)


def test_an_uncapped_scan_does_not_claim_to_be_capped(tmp_path):
    _workspace(tmp_path)
    assert read_provenance(tmp_path).capped is False


def test_the_dimension_survives_a_json_round_trip(tmp_path):
    """It goes into the drift baseline, so a value that changes type on the way back would
    compare unequal against itself and report drift forever."""
    root = _workspace(tmp_path)
    _origin(root, "clawseccheck")
    dim = read_provenance(tmp_path).as_dimension()
    assert json.loads(json.dumps(dim)) == dim


def test_no_filesystem_path_reaches_the_dimension(tmp_path):
    """A drift baseline reaches the event journal and any report a user pastes into an
    issue."""
    root = _workspace(tmp_path)
    _origin(root, "clawseccheck")
    assert str(tmp_path) not in json.dumps(read_provenance(tmp_path).as_dimension())


def test_a_junk_record_is_skipped_rather_than_crashing_the_scan(tmp_path):
    _workspace(tmp_path, skills={"good": _record(), "bad": "not-a-dict"})
    scan = read_provenance(tmp_path)
    assert set(scan.skills) == {"good"}


def test_a_boolean_installed_at_does_not_pass_for_a_timestamp(tmp_path):
    """`True` is an int in Python, so a corrupted field would otherwise compare as 1
    against a real epoch and read as a reinstall."""
    rec = _record()
    rec["installedAt"] = True
    _workspace(tmp_path, skills={"x": rec})
    assert read_provenance(tmp_path).skills["x"].installed_at == 0
