"""B-557: the self-exclusion note may not claim more exclusion than there is.

One `--full` report used to say both of these about the same skill:

    ℹ️ clawseccheck not graded -- ClawSecCheck's own installed copy is excluded from
       its own audit
    🟠 HIGH  Installed skill modified after install (recorded ClawHub install hashes)
        why: ... clawseccheck: 'SKILL.md' does not match the digest recorded in
        .clawhub/lock.json at install time ... (+32 more)

The run had audited our own installed copy, named it and failed it, under a line promising
the opposite.

## What is and is not excluded

The collector's content-verified identity oracle (`collector._is_own_source`) drops our copy
from skill DISCOVERY, so `check_installed_skills`' content ring never sees it. Its own
docstring already scoped that honestly — "`check_installed_skills` [is] only one of the
surfaces that sees a skill" — and every check enumerating skills from elsewhere still does.

## The measured set

Four lock states over a home carrying a genuine own install, listing every check whose
finding NAMES it:

    lock state                          names our own copy
    everything agrees                   -
    post-install tamper                 B181 FAIL
    accepted despite failed verify      B135 WARN
    installed from a foreign registry   B184 WARN

All three read the workspace `.clawhub/lock.json`, which lists our skill by slug, so the
content oracle never gets a say. B177 is the family's fourth member and is deliberately
absent: its subject is an installed plugin's trust disposition, not a skill.

`test_the_note_names_exactly_the_checks_that_really_see_our_own_copy` derives that set by
running the audit rather than trusting the constant, so the sentence cannot drift from the
behaviour it describes.

## What this must NOT become

The tempting "fix" is to exclude our own copy from B181 so the old sentence becomes true.
That would silence a true positive — B181 detected a real post-install modification when
this was found. The sentence was what was wrong.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from clawseccheck import audit
from clawseccheck.report import SELF_EXCLUDED_NOTE, SELF_EXCLUDED_STILL_CHECKED_IDS

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
OWN_INSTALL = FIXTURES / "clean_ownname_genuine_clawseccheck"
_ZERO = "0" * 64


def _home_with_lock(tmp_path: Path, name: str, *, tamper: bool = False, **entry_mods) -> Path:
    """A home carrying a genuine own install plus a workspace ClawHub lock for it."""
    home = tmp_path / name
    shutil.copytree(OWN_INSTALL, home)
    workspace = home / "workspace-home"
    skill = workspace / "skills" / "clawseccheck"
    digests = {
        str(p.relative_to(skill)): (_ZERO if tamper
                                    else hashlib.sha256(p.read_bytes()).hexdigest())
        for p in sorted(skill.rglob("*")) if p.is_file()
    }
    entry = {
        "version": "3.61.0", "installedAt": 1786033098305,
        "registry": "https://clawhub.ai",
        "artifact": {"kind": "archive", "sha256": _ZERO},
        "skillFile": {"path": "SKILL.md", "sha256": digests.get("SKILL.md", _ZERO)},
        "files": [{"path": k, "sha256": v} for k, v in digests.items()],
        "verification": {"schema": "clawhub.skill.verify.v1", "ok": True,
                         "decision": "pass", "reasons": []},
    }
    entry.update(entry_mods)
    (workspace / ".clawhub").mkdir(parents=True, exist_ok=True)
    (workspace / ".clawhub" / "lock.json").write_text(
        json.dumps({"version": 1, "skills": {"clawseccheck": entry}}), encoding="utf-8")
    return home


def _ids_naming_our_own_copy(home: Path) -> set:
    _ctx, findings, _score = audit(home)
    return {f.id for f in findings if "clawseccheck" in (f.detail or "").lower()}


_LOCK_STATES = {
    "tamper": dict(tamper=True),
    "failed_verification": dict(verification={"schema": "clawhub.skill.verify.v1",
                                              "ok": False, "decision": "fail",
                                              "reasons": ["scanner flagged the artifact"]}),
    "foreign_registry": dict(registry="https://evil-registry.example"),
}


# ------------------------------------------------------------------ the claim is true


def test_the_note_names_exactly_the_checks_that_really_see_our_own_copy(tmp_path):
    """The self-maintaining half. The set is derived by running the audit, so a check that
    starts or stops seeing our own copy fails here instead of quietly making the sentence
    wrong again."""
    seen = set()
    for label, mods in _LOCK_STATES.items():
        seen |= _ids_naming_our_own_copy(_home_with_lock(tmp_path, label, **mods))
    assert seen == set(SELF_EXCLUDED_STILL_CHECKED_IDS), sorted(seen)
    for cid in sorted(seen):
        assert cid in SELF_EXCLUDED_NOTE, f"{cid} sees our own copy but the note omits it"


def test_the_note_does_not_claim_blanket_exclusion():
    """The exact wording that made the report contradict itself."""
    assert "excluded from its own audit" not in SELF_EXCLUDED_NOTE
    assert "content scan" in SELF_EXCLUDED_NOTE
    assert "still checked" in SELF_EXCLUDED_NOTE


def test_a_clean_own_install_is_still_excluded_from_the_content_ring(tmp_path):
    """The exclusion itself is unchanged: with every digest agreeing, nothing names it."""
    assert _ids_naming_our_own_copy(_home_with_lock(tmp_path, "clean")) == set()


# ----------------------------------------------- the coverage that must not be "fixed"


def test_our_own_copy_is_still_convicted_for_a_post_install_modification(tmp_path):
    """**Pin against the tempting repair.** Excluding our copy from B181 would make the
    OLD sentence true by silencing a true positive — this is the check that caught a real
    post-install modification when B-557 was found. If this ever goes green-by-absence,
    the wrong half was changed."""
    _ctx, findings, _score = audit(_home_with_lock(tmp_path, "tampered", tamper=True))
    b181 = [f for f in findings if f.id == "B181"]
    assert b181 and b181[0].status == "FAIL", [(f.id, f.status) for f in findings]
    assert "clawseccheck" in b181[0].detail.lower()


# --------------------------------------------------------------- one sentence, one source


def test_the_sentence_has_exactly_one_definition_in_the_package():
    """It was four copies across `cli.py` and `report.py`, which is how a fix reaches one
    surface and leaves the claim false on the other three."""
    literals = 0
    for path in (REPO_ROOT / "clawseccheck").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if path.name == "report.py":
            # the definition itself, plus the docstring above it quoting the old wording
            literals += text.count('"not graded -- ClawSecCheck\'s own installed copy is ')
            continue
        assert "ClawSecCheck's own installed copy is excluded" not in text, path.name
    assert literals == 1, "SELF_EXCLUDED_NOTE must be defined exactly once"


def test_every_render_site_uses_the_constant():
    for name in ("cli.py", "report.py"):
        text = (REPO_ROOT / "clawseccheck" / name).read_text(encoding="utf-8")
        assert "SELF_EXCLUDED_NOTE" in text, name
