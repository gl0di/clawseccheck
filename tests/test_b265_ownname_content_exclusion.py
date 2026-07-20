"""B-265 — own-skill self-exclusion must be CONTENT-verified, never basename-verified.

Skill discovery in ``collector._read_installed_skills`` used to drop any directory whose
basename was in ``_OWN_SKILL_NAMES`` (which included the retired ``clawshield``
namespace). ``ctx.installed_skills`` is the sole input to both the audit's installed-skill
checks and ``monitor._skill_sig``, so a single ``mv evil-skill clawshield`` erased a
malicious skill from the full audit AND from ``--monitor`` — with no content edit — while
``--vet`` aimed at the very same bytes still graded it F (DANGEROUS).

The fix routes discovery through ``_is_own_source``, the same content-verified oracle
``vet_skill`` already used, and drops ``clawshield`` outright.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.collector import _OWN_ENGINE_MARKERS, _OWN_SKILL_NAMES, _is_own_source, collect
from clawseccheck.monitor import _skill_sig, diff, snapshot

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

CLEAN = FIXTURES / "clean_ownname_genuine_clawseccheck"
BAD_CLAWSHIELD = FIXTURES / "bad_ownname_clawshield"
BAD_SQUAT = FIXTURES / "bad_ownname_clawseccheck_squat"
HOME_SAFE = FIXTURES / "home_safe"


def _audit(home: Path):
    """audit() returns (ctx, findings, score); re-ordered here for readability."""
    ctx, findings, score = audit(home)
    return findings, score, ctx


def _statuses(home: Path):
    findings, score, _ = _audit(home)
    return {f.id: f.status for f in findings}, score


# ---------------------------------------------------------------- the cloak is closed

@pytest.mark.parametrize(
    "fixture, skill_key",
    [
        (BAD_CLAWSHIELD, "clawshield"),          # matching frontmatter (name: clawshield)
        (BAD_SQUAT, "clawseccheck"),             # NON-matching frontmatter (name: invoice-helper)
    ],
)
def test_cloaked_skill_enters_the_inventory(fixture, skill_key):
    """BAD: a malicious skill wearing an own-skill directory name is inventoried."""
    ctx = collect(fixture)
    assert skill_key in ctx.installed_skills, (
        f"{fixture.name}: skill cloaked by directory name is missing from the inventory"
    )
    # the payload itself was actually read, not just the key registered
    assert ctx.installed_skill_dirs[skill_key].is_dir()


@pytest.mark.parametrize("fixture", [BAD_CLAWSHIELD, BAD_SQUAT])
def test_cloaked_skill_is_flagged_by_the_full_audit(fixture):
    """BAD: the audit reaches a FAIL verdict it previously could not see at all."""
    findings, score, _ = _audit(fixture)
    fails = [f.id for f in findings if f.status == "FAIL"]
    assert fails, f"{fixture.name}: cloaked payload produced no FAIL"
    assert score.grade != "A", f"{fixture.name}: grade unmoved by a malicious skill"


@pytest.mark.parametrize("fixture, skill_key", [(BAD_CLAWSHIELD, "clawshield"), (BAD_SQUAT, "clawseccheck")])
def test_cloaked_skill_fires_monitor_new_skill_alert(fixture, skill_key):
    """BAD: --monitor's NEW-skill alert fires; _skill_sig reads ctx.installed_skills."""
    safe_findings, safe_score, safe_ctx = _audit(HOME_SAFE)
    findings, score, ctx = _audit(fixture)
    assert skill_key in _skill_sig(ctx)

    prev = snapshot(safe_ctx, safe_findings, safe_score)   # clean home: no skills
    curr = snapshot(ctx, findings, score)                  # cloaked skill has landed
    alerts = diff(prev, curr)
    assert any(
        sev == "CRITICAL" and "NEW skill installed" in msg and skill_key in msg
        for sev, msg in alerts
    ), f"{fixture.name}: no NEW-skill alert for '{skill_key}' — monitor is still blind"


# ------------------------------------------------------- the genuine install still hides

def test_genuine_own_install_stays_excluded():
    """CLEAN: a real ClawSecCheck install under skills/clawseccheck/ is still excluded.

    A security auditor ships attack signatures as data; the fixture's checks/_engine.py
    embeds some, so a regression that inventoried it would self-flag immediately.
    """
    ctx = collect(CLEAN)
    assert ctx.installed_skills == {}, (
        "the genuine own install must not enter the inventory (it would self-flag)"
    )


def test_genuine_own_install_does_not_move_the_verdict():
    """CLEAN: verdict is identical to home_safe — zero finding-status delta."""
    safe_st, safe_score = _statuses(HOME_SAFE)
    clean_st, clean_score = _statuses(CLEAN)
    assert (clean_score.grade, clean_score.score) == (safe_score.grade, safe_score.score)
    assert [k for k in set(safe_st) | set(clean_st) if safe_st.get(k) != clean_st.get(k)] == []
    assert [f_id for f_id, st in clean_st.items() if st == "FAIL"] == []


# ------------------------------------------------------------------ the oracle itself

def test_clawshield_is_no_longer_a_reserved_name():
    """The retired v0.16.0 namespace protected nothing and was a free cloak."""
    assert _OWN_SKILL_NAMES == {"clawseccheck"}
    assert "clawshield" not in _OWN_SKILL_NAMES


def _write_engine(pkg: Path, markers) -> None:
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "_engine.py").write_text("\n".join(markers), encoding="utf-8")


def test_is_own_source_rejects_the_name_alone(tmp_path):
    """Name without engine content -> NOT own source (this is the whole fix)."""
    d = tmp_path / "clawseccheck"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: clawseccheck\n---\n", encoding="utf-8")
    assert _is_own_source(d) is False


def test_is_own_source_rejects_a_partial_marker_set(tmp_path):
    """All markers are required — a look-alike that copies one symbol is still scanned."""
    d = tmp_path / "clawseccheck"
    _write_engine(d / "checks", _OWN_ENGINE_MARKERS[:1])
    assert _is_own_source(d) is False


def test_is_own_source_accepts_the_real_package_layout(tmp_path):
    """Full marker set in a checks/ package under an own name -> own source."""
    d = tmp_path / "clawseccheck"
    _write_engine(d / "checks", _OWN_ENGINE_MARKERS)
    assert _is_own_source(d) is True


def test_is_own_source_accepts_the_install_dir_layout(tmp_path):
    """Nested clawseccheck/checks/ (repo root or install dir) is name-independent."""
    d = tmp_path / "some-other-name"
    _write_engine(d / "clawseccheck" / "checks", _OWN_ENGINE_MARKERS)
    assert _is_own_source(d) is True


def test_is_own_source_accepts_the_legacy_single_file_layout(tmp_path):
    """Pre-I-022 single-file checks.py still recognised."""
    d = tmp_path / "clawseccheck"
    d.mkdir()
    (d / "checks.py").write_text("\n".join(_OWN_ENGINE_MARKERS), encoding="utf-8")
    assert _is_own_source(d) is True


def test_is_own_source_is_false_when_the_engine_is_unreadable(tmp_path):
    """UNKNOWN-shaped path: unreadable engine source resolves to NOT-own (scan it).

    Failing closed here is the safe direction — an unreadable candidate gets audited
    rather than silently excluded.
    """
    d = tmp_path / "clawseccheck"
    checks = d / "checks"
    checks.mkdir(parents=True)
    src = checks / "_engine.py"
    src.write_text("\n".join(_OWN_ENGINE_MARKERS), encoding="utf-8")
    assert _is_own_source(d) is True          # readable: excluded
    src.chmod(0o000)
    try:
        if src.read_bytes():                  # running as root: chmod does not deny
            pytest.skip("cannot make a file unreadable in this environment")
    except OSError:
        pass
    assert _is_own_source(d) is False         # unreadable: fail closed, scan it
    src.chmod(0o600)


def test_docs_only_own_install_is_scanned(tmp_path):
    """C-135 accepted residual — pinned so it stays a decision, not a surprise.

    A hand-made partial copy of our own skill that ships the DOCS but not the engine is
    NOT recognised as own source, so the audit scans our prose (which quotes attack
    payloads) and may self-flag. This is not a shipped shape — both documented installs
    put clawseccheck/checks/ on disk — and every candidate mitigation keys on copyable
    doc content, i.e. the forgeable identity this change exists to remove. Failing
    closed is the safe direction; see the _is_own_source docstring.
    """
    repo = Path(__file__).resolve().parent.parent
    d = tmp_path / "clawseccheck"
    d.mkdir()
    (d / "SKILL.md").write_text((repo / "SKILL.md").read_text(encoding="utf-8"), encoding="utf-8")
    (d / "README.md").write_text((repo / "README.md").read_text(encoding="utf-8"), encoding="utf-8")
    assert _is_own_source(d) is False, (
        "docs-only own copy must NOT be granted identity — it carries no engine to verify"
    )
    # ...and the moment the engine is present, it is recognised again.
    _write_engine(d / "checks", _OWN_ENGINE_MARKERS)
    assert _is_own_source(d) is True


def test_is_own_source_is_false_for_an_unrelated_directory(tmp_path):
    d = tmp_path / "invoice-helper"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: invoice-helper\n---\n", encoding="utf-8")
    assert _is_own_source(d) is False


# --------------------------------------------------- layering + aggregator contract

def test_oracle_is_shared_by_both_surfaces_and_layering_holds():
    """One oracle object, reachable from every historical import site (CLAUDE.md §3.1-a).

    It now lives in collector.py (Layer 1) so discovery can use it; checks/_shared.py
    re-exports it, so vet_skill's import path is unchanged.
    """
    from clawseccheck.checks import _is_own_source as agg
    from clawseccheck.checks._shared import _is_own_source as shared
    from clawseccheck.checks._vet import _is_own_source as vet

    assert agg is shared is vet is _is_own_source

    from clawseccheck.checks import _OWN_ENGINE_MARKERS as agg_markers
    from clawseccheck.checks._shared import _OWN_SKILL_NAMES as shared_names

    assert agg_markers == _OWN_ENGINE_MARKERS
    assert shared_names == _OWN_SKILL_NAMES


def test_collector_does_not_import_the_checks_layer():
    """Layer 1 must never import Layer 2 — that is why the oracle moved down."""
    src = (Path(__file__).resolve().parent.parent / "clawseccheck" / "collector.py").read_text(
        encoding="utf-8"
    )
    assert "from .checks" not in src
    assert "import checks" not in src


# ------------------------------------------------------------------- end-to-end CLI

def test_rendered_report_names_the_cloaked_skill():
    """The rendered report actually names the skill — not just an internal dict key.

    Asserted on the clawshield fixture only: 'clawseccheck' occurs in every report as
    the tool's own name, so it cannot distinguish a leak from a hit.
    """
    from clawseccheck.report import render_json

    findings, score, ctx = _audit(BAD_CLAWSHIELD)
    blob = render_json(findings, score, ctx=ctx)
    payload = json.loads(blob)
    assert any(f["status"] == "FAIL" for f in payload["findings"])
    assert "clawshield" in blob, "report never names the cloaked skill"

    safe_blob = render_json(*_audit(HOME_SAFE)[:2], ctx=_audit(HOME_SAFE)[2])
    assert "clawshield" not in safe_blob   # control: the name is not boilerplate
