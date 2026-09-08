"""B-613 — B335 (runtime-computed sitecustomize/usercustomize/PYTHONSTARTUP
auto-execution persistence install) reached the Build-quality axis but never the
Persistence axis, so a skill whose whole file installs dormant auto-execution printed
a contradiction under --vet:

    Build quality  WARN   Runtime-computed Python auto-execution persistence install: ...
    Persistence    PASS   no dormant or staged code detected

B335's own finding text says "persistence install" — nothing was undetected; the
dossier's finding->axis routing (dossier.py's `_AXIS_BY_ID` + `build_profile`'s
bucketing loop) simply never sent it to the axis whose job is exactly this question.
Fixed by routing B335 to BOTH "build" and "persistence": `_AXIS_BY_ID["B335"] = None`
(opting out of `axis_for`'s single-axis inference) plus an explicit
`elif f.id == "B335":` branch that appends the SAME Finding object into both buckets —
no `dc_replace`, so `Finding.detail` stays byte-identical and no fingerprint manifest
entry moves (only WHICH axis renders the text is new).

This file pins the CONTRADICTION, not the wording:
  * Persistence must no longer PASS over a file Build quality WARNs on for this shape.
  * B335 must still reach Build quality — the half that already worked, and a future
    edit could silently drop it while "fixing" the routing.
  * The clean B335 FP controls must not start manufacturing a Persistence finding out
    of the routing change alone — it only fires when B335 itself fires.

Offline, reads only bundled fixtures.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import vet_skill
from clawseccheck.dossier import build_profile

_REPO = Path(__file__).resolve().parent.parent
_FIX = _REPO / "fixtures"


def _axis(profile, name):
    return next(a for a in profile.axes if a.axis == name)


def test_persistence_no_longer_passes_over_the_no_extension_installer():
    """The exact repro from the bug report: `install` computes a sitecustomize.py
    target under site-packages at runtime and writes to it. Before B-613 this WARNed
    Build quality and PASSed Persistence over the identical file — the contradiction
    this change exists to close."""
    target = _FIX / "bad_b335_no_extension_installer" / "skills" / "envtools-installer"
    profile = build_profile(vet_skill(str(target)), "envtools-installer", "skill")

    build = _axis(profile, "build")
    persistence = _axis(profile, "persistence")

    assert build.status == WARN
    assert any(f.id == "B335" for f in build.findings), "B335 must still reach Build quality"
    assert persistence.status != PASS, (
        "Persistence PASSed over a file Build quality WARNs on for installing "
        "auto-execution persistence — the exact contradiction B-613 fixes"
    )
    assert persistence.status == WARN
    assert any(f.id == "B335" for f in persistence.findings)
    assert persistence.reason != "no dormant or staged code detected"


def test_b335_still_reaches_build_quality_on_the_two_mechanism_fixture():
    """The richer bad fixture — mechanism A (sitecustomize) and mechanism B
    (PYTHONSTARTUP shell-rc) each in their own file. Pins that dual-routing did not
    silently drop B335 from the axis it already worked on before this change, and that
    both axes render the identical text (same Finding object, no per-axis `dc_replace`
    fabrication)."""
    target = _FIX / "bad_b335_runtime_persist_install" / "skills" / "envtools"
    profile = build_profile(vet_skill(str(target)), "envtools", "skill")

    build = _axis(profile, "build")
    persistence = _axis(profile, "persistence")

    assert build.status == WARN
    assert any(f.id == "B335" for f in build.findings)
    assert persistence.status == WARN
    assert any(f.id == "B335" for f in persistence.findings)

    build_detail = next(f.detail for f in build.findings if f.id == "B335")
    persistence_detail = next(f.detail for f in persistence.findings if f.id == "B335")
    assert build_detail == persistence_detail, (
        "both axes must render byte-identical text — this is what proves no "
        "Finding.detail was fabricated per axis and no fingerprint moved"
    )


def test_clean_devtooling_fixture_stays_clean_on_both_axes():
    """The established B335 FP controls (site.getsitepackages() read-only,
    PYTHONSTARTUP set in-process only, never a shell rc write) must not start
    manufacturing a Persistence finding out of the routing change alone — routing only
    ever fires when B335 itself fires."""
    target = _FIX / "clean_b335_devtooling" / "skills" / "venv-doctor"
    profile = build_profile(vet_skill(str(target)), "venv-doctor", "skill")

    build = _axis(profile, "build")
    persistence = _axis(profile, "persistence")

    assert build.status == PASS
    assert persistence.status == PASS
    assert not any(f.id == "B335" for f in build.findings)
    assert not any(f.id == "B335" for f in persistence.findings)
    # The generic axis-clean sentence, unchanged — proves the PASS branch still comes
    # from `_clean_reason`, not from a bucketed B335 PASS finding's own detail text.
    assert persistence.reason == "no dormant or staged code detected"


def test_clean_skill_md_doc_example_fixture_is_unaffected():
    """The Markdown-only fixture (a doc example, no executable file at all) never
    reaches B335's write-mode-open gate in the first place — pinned so the routing
    change can't be blamed for, or accidentally paper over, a doc-only skill's honest
    UNKNOWN. No Python source exists, so Persistence reads UNKNOWN (nothing to
    measure), not a fabricated PASS."""
    target = _FIX / "clean_b335_skill_md_doc_example" / "skills" / "py-devenv"
    profile = build_profile(vet_skill(str(target)), "py-devenv", "skill")

    build = _axis(profile, "build")
    persistence = _axis(profile, "persistence")

    assert build.status == PASS
    assert persistence.status == UNKNOWN
    assert not any(f.id == "B335" for f in build.findings)
    assert not any(f.id == "B335" for f in persistence.findings)
