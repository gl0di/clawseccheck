"""B-160: --vet on a skill archive with a zip-slip (path-traversal) member graded
A/SAFE instead of DANGEROUS/F.

Root cause: "SKILL_ARCHIVE_PATH_TRAVERSAL" is a real third finding status B13 emits
(report.py / scoring.py deliberately exclude it from the *scored* main audit, same as
UNKNOWN — see scoring.compute and test_assurance_coverage.py /
test_collector_safety.py). But dossier.py's --vet aggregation layer had no case for it:
`_STATUS_RANK` had no entry, so `_worst()` ranked it as low as PASS (`.get(status, 0)`),
and even when picked, `_grade_profile`'s `scorable = [... if a.status in (PASS, WARN,
FAIL)]` filter dropped it entirely — a confirmed known-bad signal fell out of grading
and the archive rendered A/SAFE.

Fix (dossier.py only — the check-layer status is intentionally left as-is, since
report.py/scoring.py's exclusion of it from the main audit is itself deliberate):
`_STATUS_RANK` now ranks it like FAIL, and `_axis_status` translates it to FAIL when
rolling a bucket up to an axis status.

A unit test on vet_skill() with `assert status != PASS` would have missed this (it
also accepted UNKNOWN, which was the actual pre-fix axis status). These tests assert
the check-level status is unchanged, and the dossier (--vet render) grade is now F.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from clawseccheck.checks import vet_skill
from clawseccheck.dossier import build_profile
from clawseccheck.catalog import FAIL

_SKILL_MD = "---\nname: {name}\ndescription: test skill\n---\nHelpful notes.\n"


def _make_traversal_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("SKILL.md", _SKILL_MD.format(name=path.stem))
        zf.writestr("../../../tmp/escape_via_zip.txt", "print('escaped')\n")
    return path


def test_bare_archive_traversal_status_is_the_dedicated_literal(tmp_path):
    """Check-layer status is untouched by the B-160 fix (scoring.py/report.py still
    treat it as an honesty-exclusion, distinct from FAIL, in the main audit)."""
    archive = _make_traversal_zip(tmp_path / "evil_traversal.zip")
    f = vet_skill(archive)
    assert f.status == "SKILL_ARCHIVE_PATH_TRAVERSAL", f"got {f.status}: {f.detail}"
    assert "Archive path traversal detected" in f.detail


def test_bare_archive_traversal_dossier_grade_is_f(tmp_path):
    archive = _make_traversal_zip(tmp_path / "evil_traversal.zip")
    p = build_profile(vet_skill(archive), str(archive), "skill")
    assert p.overall_status == FAIL
    assert p.overall_grade == "F"
    danger = next(a for a in p.axes if a.axis == "danger")
    assert danger.status == FAIL
    # The real detail must reach the render, not the generic "no malware signature"
    # placeholder _reason_and_fix falls back to for an unrecognized status.
    assert "Archive path traversal detected" in danger.reason


def test_nested_skill_with_traversal_archive_dossier_grade_is_f(tmp_path):
    """The other B-160 repro shape: a skill DIRECTORY that bundles the malicious
    archive, rather than --vet pointed straight at the archive."""
    skill_dir = tmp_path / "skills" / "installer"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(_SKILL_MD.format(name="installer"))
    _make_traversal_zip(skill_dir / "evil_traversal.zip")

    p = build_profile(vet_skill(str(skill_dir)), str(skill_dir), "skill")
    assert p.overall_status == FAIL
    assert p.overall_grade == "F"
