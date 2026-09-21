"""B-846 — second-pass review of B-777 found two open defects in the self-source
`--vet` path (`checks/_vet.py::_vet_resolved_skill` short-circuiting on
`collector._is_own_source`):

1. **False claim about what ran.** `dossier._unmeasurable_reason`'s `self_source`
   branch told the reader "only the danger axis ran, by design" — but nothing ran at
   all: `_vet_resolved_skill` returns a canned B13 PASS `Finding` before any
   `read_skill_python`/`read_skill_shell`/`read_skill_js` call. The danger axis's own
   PASS reason ("no malware signature or known-bad indicator") made the identical
   false claim on its own axis line. Both now say nothing was scanned; danger's PASS
   is a policy default, not a completed scan.

2. **Forgeable identity.** `_is_own_source` matched `_OWN_ENGINE_MARKERS` as a bare
   substring test with no regard for whether the match was real code or a comment. A
   single file containing only three `#`-commented lines of marker text —
   `# def check_installed_skills` / `# def vet_skill` / `# _SKILL_CRIT` — satisfied
   it, so an attacker could plant that one file alongside a genuinely malicious skill
   and have the WHOLE tree recognised as "ClawSecCheck's own source" and skipped:
   measured turning a real DO-NOT-INSTALL fixture into INSTALL / Danger PASS. Whole-
   comment lines are now stripped before matching.

Both tests below are offline and read/write only `tmp_path` / bundled fixtures.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import vet_skill
from clawseccheck.collector import _OWN_ENGINE_MARKERS, _is_own_source
from clawseccheck.dossier import build_profile

_REPO = Path(__file__).resolve().parent.parent
_FIXTURES = _REPO / "fixtures"
_ENVTOOLS = _FIXTURES / "bad_b335_runtime_persist_install" / "skills" / "envtools"

_SELF_SOURCE_PHRASE = "This is ClawSecCheck's own source"


def _axis(profile, name):
    for a in profile.axes:
        if a.axis == name:
            return a
    raise AssertionError(f"axis {name!r} not in profile")


def _plant_comment_only_spoof(root: Path) -> None:
    """The exact B-846 repro: one file, three lines, each a bare `#` comment."""
    pkg = root / "clawseccheck" / "checks"
    pkg.mkdir(parents=True)
    (pkg / "x.py").write_text(
        "\n".join(f"# {m}" for m in _OWN_ENGINE_MARKERS) + "\n",
        encoding="utf-8",
    )


# ──────────────────────────────────────────────────── item 2: the marker forgery

def test_comment_only_markers_do_not_grant_own_source_identity(tmp_path):
    """The oracle itself: three commented-out marker lines are not real engine code."""
    d = tmp_path / "clawseccheck"
    _plant_comment_only_spoof(d)
    assert _is_own_source(d) is False


def test_real_marker_code_still_grants_own_source_identity(tmp_path):
    """Non-regression: the SAME markers as real (uncommented) statements still work —
    this closes the forgery without narrowing genuine recognition."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    (pkg / "_engine.py").write_text("\n".join(_OWN_ENGINE_MARKERS), encoding="utf-8")
    assert _is_own_source(d) is True


def test_mixed_comment_and_code_still_recognised(tmp_path):
    """A marker repeated in a comment ELSEWHERE in the file must not blind the real,
    uncommented occurrence — stripping comment lines must not go too far the other way."""
    d = tmp_path / "clawseccheck"
    pkg = d / "checks"
    pkg.mkdir(parents=True)
    lines = [f"# see {_OWN_ENGINE_MARKERS[0]} below", *_OWN_ENGINE_MARKERS]
    (pkg / "_engine.py").write_text("\n".join(lines), encoding="utf-8")
    assert _is_own_source(d) is True


def test_planting_the_spoof_beside_a_real_malicious_skill_does_not_cloak_it(tmp_path):
    """End-to-end reproduction from the ticket: copy a real DO-NOT-INSTALL fixture,
    plant the three-comment-line spoof inside it, and confirm the verdict does not
    flip to INSTALL / Danger PASS."""
    assert _ENVTOOLS.is_dir(), "fixture layout moved; update this path"
    target = tmp_path / "envtools"
    shutil.copytree(_ENVTOOLS, target)

    # Non-vacuity: the unmodified copy is genuinely convicted.
    baseline = vet_skill(target)
    baseline_profile = build_profile(baseline, str(target), "skill")
    assert baseline_profile.verdict == "DO-NOT-INSTALL", (
        f"fixture must be malicious before the spoof is added: {baseline_profile.verdict}"
    )

    _plant_comment_only_spoof(target)
    assert _is_own_source(target) is False, (
        "the planted file must not grant own-source identity to the malicious tree"
    )

    finding = vet_skill(target)
    assert _SELF_SOURCE_PHRASE not in finding.detail, (
        f"own-source short-circuit fired on a target that is not our engine: {finding.detail!r}"
    )
    profile = build_profile(finding, str(target), "skill")
    assert profile.verdict == "DO-NOT-INSTALL", (
        f"planting a 3-line comment file must not cloak a real malicious skill as "
        f"INSTALL: verdict={profile.verdict!r}"
    )
    assert _axis(profile, "danger").status == FAIL


# ────────────────────────────────────────────── item 1: the false "danger ran" claim

def test_self_source_wording_no_longer_claims_the_danger_axis_ran():
    """The real repo root (genuinely own source) must not claim danger "ran" in the
    text explaining why the other four axes are unmeasured, and danger's own PASS
    reason must not claim a completed scan either."""
    finding = vet_skill(_REPO)
    assert _SELF_SOURCE_PHRASE in finding.detail, (
        f"the real repo root must trip _is_own_source: {finding.detail!r}"
    )
    profile = build_profile(finding, str(_REPO), "skill")

    danger = _axis(profile, "danger")
    assert danger.status == PASS
    assert "no malware signature or known-bad indicator" not in danger.reason, (
        "danger's self-source PASS must not claim a completed scan: "
        f"{danger.reason!r}"
    )
    assert "scan" in danger.reason and "not" in danger.reason.lower(), danger.reason

    for name in ("build", "behavior", "persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == UNKNOWN
        assert "only the danger axis ran" not in axis.reason, (
            f"{name}: still claims the danger axis ran when nothing ran: {axis.reason!r}"
        )
        assert "danger axis ran" not in axis.reason, axis.reason
