"""B-864 — extend the B-754 traversal disclosure to the other two coverage arms.

B-754 fixed exactly one of the three coverage arms `check_installed_skills` (B13) ranks
above the `path_traversal` arm: the unreadable-file sub-branch of `skill_limit_hits` now
names a CONFIRMED archive path traversal found in whatever WAS read, alongside the
coverage gap, instead of silently erasing it. That branch's own comment (and the B-746
comment above the cascade) name THREE coverage arms as outranking `path_traversal` —
`parse_error_paths`, `skill_limit_hits` (which itself has two winning shapes:
`padding_anomalies` WARN, and the generic "hit limits" UNKNOWN) — but only the
unreadable-file shape was actually fixed. The other two stayed silent: a confirmed
zip-slip sitting right next to an unparseable file, or a padded-out file, vanished from
the dossier, the audit report, and the JSON exactly the way B-754 describes for the
unreadable case.

This closes the same gap at those two remaining sites, with the identical technique:
`_path_traversal` (already computed once, ahead of every coverage arm, by B-754) is
appended to `detail` — never `fix`, for the same `baseline.fingerprint()` reason B-754's
own comment gives — when a coverage arm wins the cascade AND a confirmed traversal was
also found. Status, severity and the winning bucket name are UNCHANGED at both sites;
only the silence is fixed.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from clawseccheck import audit, scoring
from clawseccheck.catalog import UNKNOWN, WARN
from clawseccheck.checks import check_installed_skills, vet_skill
from clawseccheck.collector import _MAX_BYTES_PER_SKILL, _MAX_FILE_BYTES, _MAX_FILES_PER_SKILL, collect
from clawseccheck.dossier import build_profile
from clawseccheck.report import render_report, render_vet_dossier

_TRAVERSAL_MEMBER = "../../../tmp/b864_escape.txt"
_MANIFEST = "---\nname: b864-repro\ndescription: A friendly helper skill.\n---\n# Helper\n"

# Same sizing recipe as tests/test_truncation_coverage.py: each file individually stays
# under _MAX_FILE_BYTES (else it is dropped whole before the per-skill budget/entropy
# logic ever sees it), while the SUM across the two comfortably exceeds
# _MAX_BYTES_PER_SKILL, so the second one (alphabetically) is the one sliced.
_PER_FILE = min(_MAX_FILE_BYTES - 1, int(_MAX_BYTES_PER_SKILL * 0.75))

# Prose that is not valid Python at all — the same fixture shape
# tests/test_b455_degraded_scoring.py uses to trigger AST_UNANALYZABLE.
_UNPARSEABLE_PY = """\
This file is prose, not Python.

It documents how the helper works: it reads notes and prints them.
Nothing here parses as Python source at all -- there is no valid statement.
"""


def _add_traversal_archive(root: Path) -> None:
    with zipfile.ZipFile(root / "bundle.zip", "w") as zf:
        zf.writestr(_TRAVERSAL_MEMBER, "pwned")


def _skill_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(_MANIFEST, encoding="utf-8")
    return root


def _home(tmp_path: Path, skill_name: str) -> Path:
    home = tmp_path / "home"
    (home / "workspace" / "skills" / skill_name).mkdir(parents=True)
    cfg = home / "openclaw.json"
    cfg.write_text('{"model": "test"}\n', encoding="utf-8")
    cfg.chmod(0o600)
    return home


# =====================================================================================
# 1. parse_error_paths
# =====================================================================================

def test_parse_error_control_no_traversal_is_unchanged(tmp_path):
    """C-135 direction check: an unparseable file with NO archive at all must not start
    mentioning a traversal just because it happens to be unparseable."""
    skill = _skill_dir(tmp_path / "skill")
    (skill / "scripts").mkdir()
    (skill / "scripts" / "broken.py").write_text(_UNPARSEABLE_PY, encoding="utf-8")

    f = vet_skill(skill)
    assert f.status == UNKNOWN, f"{f.status}: {f.detail}"
    assert "could not analyze" in f.detail
    assert "traversal" not in f.detail.lower()
    assert "escape" not in f.detail.lower()


def test_parse_error_arm_names_a_confirmed_traversal(tmp_path):
    """The defect, fixed: an unrelated unparseable file must not erase a confirmed
    archive traversal from the finding, the dossier text, or the audit report."""
    skill = _skill_dir(tmp_path / "skill")
    _add_traversal_archive(skill)
    (skill / "scripts").mkdir()
    (skill / "scripts" / "broken.py").write_text(_UNPARSEABLE_PY, encoding="utf-8")

    f = vet_skill(skill)
    # Guard against a vacuous pass: the parse-error arm must still be the one that WON.
    assert f.status == UNKNOWN, f"{f.status}: {f.detail}"
    assert "could not analyze" in f.detail
    assert "broken.py" in f.detail
    assert f.engine_degraded is True, "parse_error_paths must keep its own engine_degraded contract"

    # The fix: the confirmed escape is now named too, alongside the parse-error gap.
    assert "b864_escape.txt" in f.detail, (
        f"the confirmed archive traversal must be named in the SAME finding as the "
        f"parse-error disclosure, not silently dropped: {f.detail!r}"
    )
    assert "b864_escape.txt" not in f.fix, "goes in detail, never fix (baseline.fingerprint() hashes detail only for identity, but the field contract mirrors B-754's unreadable-file branch)"

    p = build_profile(f, str(skill), "skill")
    danger = next(a for a in p.axes if a.axis == "danger")
    # B-746's ordering requirement, asserted rather than assumed: the coverage arm still
    # wins the VERDICT — a parse failure elsewhere must not produce a confident FAIL.
    assert danger.status == UNKNOWN, danger.status

    text = render_vet_dossier(p)
    assert "broken.py" in text, "parse-error disclosure missing from the rendered dossier text"
    assert "b864_escape.txt" in text, (
        "traversal missing from the rendered dossier text — the JSON alone is not enough"
    )


def test_parse_error_arm_names_the_traversal_on_the_home_audit_surface(tmp_path):
    home = _home(tmp_path, "b864-repro")
    skill = home / "workspace" / "skills" / "b864-repro"
    _skill_dir(skill)
    _add_traversal_archive(skill)
    (skill / "scripts").mkdir()
    (skill / "scripts" / "broken.py").write_text(_UNPARSEABLE_PY, encoding="utf-8")

    ctx, findings, score = audit(home)
    b13 = next(f for f in findings if f.id == "B13")
    assert b13.status == UNKNOWN, f"{b13.status}: {b13.detail}"
    assert "broken.py" in b13.detail
    assert "b864_escape.txt" in b13.detail

    text = render_report(findings, score, ctx=ctx)
    assert "broken.py" in text, "coverage disclosure missing from the rendered audit report"
    assert "b864_escape.txt" in text, (
        "traversal missing from the rendered audit report — the JSON alone is not enough"
    )


# =====================================================================================
# 2. skill_limit_hits — padding_anomalies (WARN)
# =====================================================================================

def _padded_skill(root: Path, *, with_archive: bool) -> Path:
    """SKILL.md + two low-entropy files whose sum exceeds the per-skill text cap, so the
    second (alphabetically: aaa_first.md, then zzz_second.md — bundle.zip sorts between
    them but is not TEXT-classified and consumes no budget) is sliced mid-way with a
    low-entropy tail. Optionally also a genuine zip-slip archive."""
    _skill_dir(root)
    if with_archive:
        _add_traversal_archive(root)
    (root / "aaa_first.md").write_text("A" * _PER_FILE, encoding="utf-8")
    (root / "zzz_second.md").write_text("A" * _PER_FILE, encoding="utf-8")
    return root


def test_padding_anomalies_control_no_traversal_is_unchanged(tmp_path):
    """C-135 direction check: padding alone, no archive, must not start mentioning a
    traversal."""
    skill = _padded_skill(tmp_path / "skill", with_archive=False)

    f = vet_skill(skill)
    assert f.status == WARN, f"{f.status}: {f.detail}"
    assert "padding" in f.detail.lower() or "low-entropy" in f.detail.lower()
    assert "traversal" not in f.detail.lower()
    assert "escape" not in f.detail.lower()


def test_padding_anomalies_arm_names_a_confirmed_traversal(tmp_path):
    """The defect, fixed: oversized low-entropy padding must not erase a confirmed
    archive traversal from the finding, the dossier text, or the audit report."""
    skill = _padded_skill(tmp_path / "skill", with_archive=True)

    f = vet_skill(skill)
    # Guard against a vacuous pass: the padding_anomalies arm must still be the winner.
    assert f.status == WARN, f"{f.status}: {f.detail}"
    assert "padding" in f.detail.lower() or "low-entropy" in f.detail.lower()

    # The fix: the confirmed escape is now named too, alongside the padding disclosure.
    assert "b864_escape.txt" in f.detail, (
        f"the confirmed archive traversal must be named in the SAME finding as the "
        f"padding disclosure, not silently dropped: {f.detail!r}"
    )

    p = build_profile(f, str(skill), "skill")
    danger = next(a for a in p.axes if a.axis == "danger")
    assert danger.status == WARN, danger.status

    text = render_vet_dossier(p)
    assert "b864_escape.txt" in text, (
        "traversal missing from the rendered dossier text — the JSON alone is not enough"
    )


def test_padding_anomalies_arm_names_the_traversal_on_the_home_audit_surface(tmp_path):
    """Same claim as test_home_audit_unreadable_file_still_names_the_traversal in
    tests/test_b754_unreadable_erases_traversal.py, but built from `check_installed_skills`
    + `scoring.compute` directly rather than the full `audit()` pipeline.

    Two deliberate departures from that pattern, both pre-existing and out of THIS task's
    scope (flagged separately, not silently worked around):

    1. `render_report` is fed a single-finding list, not the full `audit()` findings —
       cheap, and `render_report`'s own claim under test (does `Finding.detail` reach the
       rendered text) does not depend on what else ran.
    2. `scoring.compute` is called WITHOUT `ctx` (its docstring: omitting `ctx` means every
       ctx-dependent cap, including the trajaudit one below, is simply never consulted —
       existing, intended behaviour, not a workaround invented for this test). This is not
       just an optimization: passing this fixture's real `ctx` to `scoring.compute(ctx=ctx)`
       reliably HANGS (measured: 30s+ with no completion) inside
       `trajaudit.skill_indicators()` (`clawseccheck/trajaudit.py:334`,
       `rx.finditer(text)` over `ctx.installed_skills`) — a pre-existing, unguarded regex
       scan with none of B13's own per-file/per-skill scan budget, on the EXACT input shape
       (large low-entropy padding) B13's own `padding_anomalies` detector exists to flag.
       Confirmed by direct profiling outside pytest, not by inference from this test's own
       runtime. Flagged as CLAWSECCHECK follow-up work; not this task's fix to make.
    """
    home = _home(tmp_path, "b864-repro")
    skill = home / "workspace" / "skills" / "b864-repro"
    _padded_skill(skill, with_archive=True)

    ctx = collect(home)
    b13 = check_installed_skills(ctx)
    assert b13.status == WARN, f"{b13.status}: {b13.detail}"
    assert "b864_escape.txt" in b13.detail

    score = scoring.compute([b13])  # ctx intentionally omitted — see docstring
    text = render_report([b13], score, ctx=ctx)
    assert "b864_escape.txt" in text, (
        "traversal missing from the rendered audit report — the JSON alone is not enough"
    )


# =====================================================================================
# 3. skill_limit_hits — the generic "hit limits" UNKNOWN (neither padding nor unreadable)
# =====================================================================================

# Enough tiny, ordinary files to blow the per-skill FILE-COUNT cap (not the byte cap) —
# named so they sort AFTER "bundle.zip" (ASCII 'z' > 'b') so the archive itself is still
# well inside the walk's cap and gets scanned before the walk gives up.
_PAD_FILE_COUNT = _MAX_FILES_PER_SKILL + 20


def _many_small_files_skill(root: Path, *, with_archive: bool) -> Path:
    _skill_dir(root)
    if with_archive:
        _add_traversal_archive(root)
    for i in range(_PAD_FILE_COUNT):
        (root / f"zzzpad_{i:04d}.txt").write_text("ok\n", encoding="utf-8")
    return root


def test_generic_skill_limit_hits_control_no_traversal_is_unchanged(tmp_path):
    """C-135 direction check: hitting the file-count cap alone, no archive, must not
    start mentioning a traversal."""
    skill = _many_small_files_skill(tmp_path / "skill", with_archive=False)

    f = vet_skill(skill)
    assert f.status == UNKNOWN, f"{f.status}: {f.detail}"
    assert "hit limits" in f.detail or "truncated" in f.detail
    # This must land on the GENERIC branch, not the padding or unreadable siblings.
    assert "padding" not in f.detail.lower()
    assert "could not be READ" not in f.detail
    assert "traversal" not in f.detail.lower()
    assert "escape" not in f.detail.lower()


def test_generic_skill_limit_hits_arm_names_a_confirmed_traversal(tmp_path):
    """The defect, fixed: hitting the plain file-count cap must not erase a confirmed
    archive traversal from the finding, the dossier text, or the audit report."""
    skill = _many_small_files_skill(tmp_path / "skill", with_archive=True)

    f = vet_skill(skill)
    # Guard against a vacuous pass: this must still land on the generic branch (neither
    # padding_anomalies nor the unreadable-file sub-branch).
    assert f.status == UNKNOWN, f"{f.status}: {f.detail}"
    assert "hit limits" in f.detail or "truncated" in f.detail
    assert "padding" not in f.detail.lower()
    assert "could not be READ" not in f.detail
    assert f.engine_degraded is False, (
        "the generic skill_limit_hits arm's own engine_degraded contract is unchanged by "
        "this fix — only parse_error_paths and the unreadable sub-branch set it"
    )

    # The fix: the confirmed escape is now named too, alongside the coverage disclosure.
    assert "b864_escape.txt" in f.detail, (
        f"the confirmed archive traversal must be named in the SAME finding as the "
        f"generic coverage disclosure, not silently dropped: {f.detail!r}"
    )

    p = build_profile(f, str(skill), "skill")
    danger = next(a for a in p.axes if a.axis == "danger")
    assert danger.status == UNKNOWN, danger.status

    text = render_vet_dossier(p)
    assert "b864_escape.txt" in text, (
        "traversal missing from the rendered dossier text — the JSON alone is not enough"
    )


def test_generic_skill_limit_hits_arm_names_the_traversal_on_the_home_audit_surface(tmp_path):
    """Built the same lighter way as the padding_anomalies audit-surface test above (see
    its docstring) for consistency and to keep `render_report`'s claim isolated to a
    single finding. Unlike that fixture, `_PAD_FILE_COUNT` tiny files total only a few KB
    of skill text, so this one does not hit the `trajaudit.skill_indicators` slowdown
    that docstring describes — `ctx` could safely be passed to `scoring.compute` here too,
    it is just left out for the same isolation reason, not because it would hang."""
    home = _home(tmp_path, "b864-repro")
    skill = home / "workspace" / "skills" / "b864-repro"
    _many_small_files_skill(skill, with_archive=True)

    ctx = collect(home)
    b13 = check_installed_skills(ctx)
    assert b13.status == UNKNOWN, f"{b13.status}: {b13.detail}"
    assert "b864_escape.txt" in b13.detail

    score = scoring.compute([b13])  # ctx intentionally omitted — see docstring
    text = render_report([b13], score, ctx=ctx)
    assert "b864_escape.txt" in text, (
        "traversal missing from the rendered audit report — the JSON alone is not enough"
    )

# Note: no separate "cross-check against check_installed_skills directly" pass here —
# every test above already goes through `check_installed_skills(collect(...))` (`vet_skill`
# is a thin wrapper over the same call for a single skill path; the two audit-surface tests
# above call it directly), so a third rebuild of each fixture just to call it once more
# would triple the cost of the two expensive fixtures for zero additional coverage.
