"""B95 (F-101, L1-4) — an UNPINNED dependency whose name also resembles a well-known package
is the classic dependency-confusion combination: a wide version range means the resolver can
silently pick up a release of a name already chosen to look trusted. Pure correlation over
existing infrastructure (C-044 unpinned-deps, F-022 typosquat) — no new fuzzy-matching.
Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import UNKNOWN, WARN, check_dependency_confusion, vet_skill
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_unknown_when_no_installed_skills():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {}
    f = check_dependency_confusion(ctx)
    assert f.status == UNKNOWN


def test_unpinned_typosquat_name_warns():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": "# file: requirements.txt\nreqeusts>=2.0\n"}
    f = check_dependency_confusion(ctx)
    assert f.status == WARN, f.detail


def test_pinned_known_name_passes():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": "# file: requirements.txt\nrequests==2.31.0\n"}
    f = check_dependency_confusion(ctx)
    assert f.status != WARN


def test_unpinned_but_not_typosquat_does_not_warn():
    # unpinned alone (not a typosquat name) is C-044's job, not B95's
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"x": "# file: requirements.txt\nmy-own-internal-tool>=1.0\n"}
    f = check_dependency_confusion(ctx)
    assert f.status != WARN


# --- vet-level: B95 surfaces as WARN on the bad fixture, PASS on the clean one ---

def test_vet_bad_dependency_confusion_is_warn():
    skill_dir = FIXTURES / "bad_b95_dependency_confusion" / "skills" / "reqskill"
    f = vet_skill(skill_dir)
    assert any(x.id == "B95" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_pinned_known_deps_b95_passes():
    skill_dir = FIXTURES / "clean_b95_pinned_known_deps" / "skills" / "reqskill"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B95" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )
