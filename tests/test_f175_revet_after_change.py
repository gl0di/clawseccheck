"""F-175 tier 3 — when the watch sees a skill change, it re-checks that skill.

An update is the moment a vetted setup silently becomes an unvetted one, and this project
had a full vetting engine with no story for that moment. Of the three tiers the task
describes, this is the only one that needs no cooperation from the user: it happens on the
next scheduled run whether or not anyone remembered to ask.

**The other two tiers already ship, and building them again would have been the mistake.**
Measured before writing a line: `--advise` is described in its own source as "the same vet
engines/profile as --vet, reframed as an install decision" and renders INSTALL / CAUTION /
DO-NOT-INSTALL; run against `fixtures/bad_b100_clickfix_setup` it reaches the identical
CAUTION verdict `--vet-skill` does. SKILL.md already carries "Mode C · Before you install"
with that verdict. B25 already detects unpinned entries and auto-update, and its own fix
text already names `update.auto.enabled = false`. A `--preflight` mode would have been a
second name for `--advise`.

**What this cannot do, and never claims:** it does not block an install. OpenClaw's real
pre-install gate is the `before_install` PLUGIN hook — grounded in the installed dist at
`dist/hook-types-DQ9eTy2x.d.ts:1143`, returning `{findings?, block?, blockReason?}` — and
occupying it means shipping JavaScript into the agent runtime, which this project rejected.
So the honest posture is: warn early, check on demand, and catch afterwards. This file is
the third.

Cost measured, not assumed: `vet_skill` averages 0.010 s across the fixture corpus.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.monitor import changed_skills

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_CLEAN = "---\nname: helper\ndescription: does a thing\n---\n\nJust prose.\n"


def _dirty() -> str:
    """The real corpus fixture's body, not a payload written for this test.

    The first version of this file hand-wrote a ClickFix-shaped block and it verdicted
    PASS — the pattern lives in a check the hand-written shape did not trip. Reading the
    body the corpus already pins removes the question of whether the test's payload is
    representative, which was the actual defect."""
    return (FIXTURES / "bad_b100_clickfix_setup" / "skills" / "quick-tool"
            / "SKILL.md").read_text(encoding="utf-8")


def _record(version: str, artifact: str) -> dict:
    return {"version": version, "installedAt": 1786033098305,
            "registry": "https://clawhub.ai",
            "artifact": {"kind": "tarball", "sha256": artifact},
            "skillFile": {"path": "SKILL.md", "sha256": "s" * 64}}


def _home(tmp_path: Path, *, body: str, version: str, artifact: str) -> Path:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8")
    os.chmod(cfg, 0o600)
    ws = home / "workspace"
    (ws / ".clawhub").mkdir(parents=True, exist_ok=True)
    (ws / ".clawhub" / "lock.json").write_text(
        json.dumps({"version": 1, "skills": {"helper": _record(version, artifact)}}),
        encoding="utf-8")
    skill = ws / "skills" / "helper"
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text(body, encoding="utf-8")
    return home


def _run(home: Path, store: Path, *extra) -> int:
    return main(["--monitor", "--home", str(home), "--data-dir", str(store), *extra])


# ---------------------------------------------------------------- the selector

def test_a_moved_version_or_digest_selects_the_skill():
    before = {"skill_provenance": {"a": {"version": "1.0", "artifact_sha256": "x" * 64}}}
    assert changed_skills(before, {"skill_provenance": {
        "a": {"version": "1.1", "artifact_sha256": "x" * 64}}}) == ["a"]
    assert changed_skills(before, {"skill_provenance": {
        "a": {"version": "1.0", "artifact_sha256": "y" * 64}}}) == ["a"]


def test_an_unchanged_record_selects_nothing():
    same = {"skill_provenance": {"a": {"version": "1.0", "artifact_sha256": "x" * 64}}}
    assert changed_skills(same, same) == []


def test_a_newly_installed_skill_is_selected():
    assert changed_skills({"skill_provenance": {}},
                          {"skill_provenance": {"new": {"version": "1.0"}}}) == ["new"]


def test_a_removed_skill_is_not_selected():
    """It cannot be vetted, and its absence is already reported by the diff."""
    assert changed_skills({"skill_provenance": {"gone": {"version": "1.0"}}},
                          {"skill_provenance": {}}) == []


def test_an_ambiguous_record_is_not_selected():
    """Two workspaces disagreeing under one name means we cannot tell which the agent
    loads, so there is no single thing to re-check with confidence."""
    assert changed_skills(
        {"skill_provenance": {"a": {"version": "1.0", "artifact_sha256": "x" * 64}}},
        {"skill_provenance": {"a": {"version": "2.0", "artifact_sha256": "y" * 64,
                                    "ambiguous": True}}}) == []


def test_a_missing_dimension_on_either_side_selects_nothing():
    """A first run after this release, or a run that found no install records, must not
    re-vet the whole estate as though everything had just changed."""
    assert changed_skills({}, {"skill_provenance": {"a": {"version": "1"}}}) == []
    assert changed_skills({"skill_provenance": {"a": {"version": "1"}}}, {}) == []
    assert changed_skills(None, None) == []


# ---------------------------------------------------------------- end to end

def test_updating_a_skill_really_does_trigger_a_re_check(tmp_path, capsys):
    """The task's DoD, taken literally: verified by actually updating a fixture skill and
    running the monitor, not by reasoning about the code path.

    The skill goes from harmless prose to a ClickFix-shaped install instruction while its
    install record moves the way a real update moves it."""
    store = tmp_path / "store"
    home = _home(tmp_path, body=_CLEAN, version="1.0.0", artifact="a" * 64)
    assert _run(home, store) == 0
    capsys.readouterr()

    _home(tmp_path, body=_dirty(), version="1.1.0", artifact="b" * 64)
    assert _run(home, store) in (0, 3)
    out = capsys.readouterr().out
    assert "Re-checked 'helper' after it changed" in out, out
    assert "ClickFix" in out or "terminal" in out, out


def test_the_re_check_verdict_reaches_the_tamper_evident_journal(tmp_path, capsys):
    """It is a finding about the user's setup produced by a scheduled run, so it belongs in
    the timeline alongside the change that prompted it."""
    store = tmp_path / "store"
    home = _home(tmp_path, body=_CLEAN, version="1.0.0", artifact="a" * 64)
    _run(home, store)
    _home(tmp_path, body=_dirty(), version="1.1.0", artifact="b" * 64)
    _run(home, store)
    capsys.readouterr()
    assert "Re-checked 'helper'" in (store / "events.jsonl").read_text(encoding="utf-8")


def test_a_clean_skill_that_changed_gets_no_extra_line(tmp_path, capsys):
    """A skill that updated and still looks clean is not news — the CHANGE is already
    reported. A line per clean re-check would train the reader to skip the block that
    carries the real ones."""
    store = tmp_path / "store"
    home = _home(tmp_path, body=_CLEAN, version="1.0.0", artifact="a" * 64)
    _run(home, store)
    capsys.readouterr()
    _home(tmp_path, body=_CLEAN + "\nStill harmless.\n", version="1.1.0",
          artifact="b" * 64)
    _run(home, store)
    out = capsys.readouterr().out
    assert "was updated, from 1.0.0 to 1.1.0" in out, "precondition: the change IS reported"
    assert "Re-checked" not in out


def test_a_quiet_run_re_checks_nothing(tmp_path, capsys):
    """Gated on there being changes, so the scheduled cost is zero on a healthy machine."""
    store = tmp_path / "store"
    home = _home(tmp_path, body=_dirty(), version="1.0.0", artifact="a" * 64)
    _run(home, store)
    _run(home, store)
    out = capsys.readouterr().out
    assert "Re-checked" not in out


def test_a_skill_whose_files_are_gone_is_disclosed_and_not_accused(tmp_path, capsys):
    """The record moved but the directory is not where the records say — a workspace we
    cannot reach, or a removal caught mid-update. Neither is an accusation."""
    store = tmp_path / "store"
    home = _home(tmp_path, body=_CLEAN, version="1.0.0", artifact="a" * 64)
    _run(home, store)
    capsys.readouterr()
    _home(tmp_path, body=_CLEAN, version="1.1.0", artifact="b" * 64)
    import shutil
    shutil.rmtree(home / "workspace" / "skills" / "helper")
    _run(home, store, "--verbose")
    out = capsys.readouterr().out
    assert "could not be found to re-check" in out
    assert "Re-checked" not in out


def test_the_re_check_never_claims_to_block_an_install(tmp_path, capsys):
    """The one thing this must never say. OpenClaw's real pre-install gate is the
    `before_install` plugin hook, and occupying it means shipping JS into the agent
    runtime — which this project rejected."""
    store = tmp_path / "store"
    home = _home(tmp_path, body=_CLEAN, version="1.0.0", artifact="a" * 64)
    _run(home, store)
    _home(tmp_path, body=_dirty(), version="1.1.0", artifact="b" * 64)
    _run(home, store)
    out = capsys.readouterr().out.lower()
    for word in ("blocked", "prevented", "stopped the install", "quarantined"):
        assert word not in out, word
