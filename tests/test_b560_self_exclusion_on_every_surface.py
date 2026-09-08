"""B-560: every surface that shows the skill roster must say a member was not scanned.

ClawSecCheck's own installed copy is dropped from skill discovery by the collector's
identity oracle, so `check_installed_skills`' content ring never scans it. Measured on a
real host, three of the five audit surfaces said so and two said nothing at all:

    surface   before      after
    text      YES         YES
    json      YES         YES
    pdf       YES *       YES
    html      NO          YES
    sarif     NO          YES

HTML is the artifact the guided flow hands people to share, so the surface most likely to
be read by someone who did not run the scan was the one that did not mention the omission.
SARIF is the CI-facing one: a pipeline saw no results for `clawseccheck` and could not tell
"scanned and clean" from "not scanned".

(*) The PDF's "YES" held only because that host had other skills. Writing
`test_a_surface_that_shows_the_roster_discloses_the_exclusion` against a fixture whose ONLY
skill is our own copy found a third gap: `pdf.py` gated the whole Skills block on a
non-empty roster, so the run where the roster shrinks to nothing — the one where a reader
has no other way to notice — was the run that said nothing. Fixed with the same change.

## The invariant, stated behaviourally

`test_a_surface_that_shows_the_roster_discloses_the_exclusion` does not carry a list of
five renderers. It renders every audit surface, keeps the ones whose output actually shows
the skills roster, and requires each of those to disclose. A sixth renderer that grows a
roster is covered without this file being edited; one that has no roster is not asked for a
disclosure it has no place for.

## Wording

One sentence, composed in one place (`report.self_excluded_line`), which is where B-557 put
it after finding four copies. SARIF carries it in `run.properties.analysisCompleteness` —
a statement about the run's reach, not a `result` — beside a structured
`selfExcludedSkills` list, always present so "nothing excluded" and "this producer is too
old to say" are different to a consumer.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from _pdftext import shown_strings

from clawseccheck import audit, render_json, render_pdf, render_report, render_sarif
from clawseccheck.report import SELF_EXCLUDED_NOTE, render_html, self_excluded_line

REPO_ROOT = Path(__file__).resolve().parents[1]
OWN_INSTALL = REPO_ROOT / "fixtures" / "clean_ownname_genuine_clawseccheck"
NO_OWN_INSTALL = REPO_ROOT / "fixtures" / "home_safe"

# A marker every roster-bearing surface prints for the skills subject. Deliberately the
# subject LABEL rather than a phrase from the disclosure — the point is to find surfaces
# that show the roster, including any that show it without disclosing.
_ROSTER_MARKER = "Skills"
_DISCLOSURE_MARKERS = ("self-excluded", "not graded", "self_excluded", "selfExcludedSkills")


def _pdf_text(data: bytes) -> str:
    """PDF shown-strings in order.

    This was a private regex that scanned for ``endstream`` and joined EVERY stream into
    one blob before matching ``(...) Tj`` — the exact shape ``_pdftext``'s own docstring
    was written to eliminate, and it went wrong the moment the report's header mark became
    an embedded raster. The mascot's compressed samples are arbitrary bytes: measured, they
    carry 27 ESC and 57 BEL, while the page operators carry none. This test asserts that
    single control characters never reach a surface, so it convicted the renderer of a leak
    it did not have. ``shown_strings`` reads the operands of ``Tj`` from the drawing streams
    only, which is what a reader actually sees.
    """
    return shown_strings(data)


def _render_every_surface(home: Path) -> dict:
    ctx, findings, score = audit(home)
    return {
        "text": render_report(findings, score, ctx=ctx),
        "json": render_json(findings, score, ctx=ctx),
        "html": render_html(findings, score, ctx=ctx),
        "sarif": render_sarif(findings, score, ctx=ctx),
        "pdf": _pdf_text(render_pdf(findings, score, ctx=ctx)),
    }


def _discloses(body: str) -> bool:
    return any(m in body for m in _DISCLOSURE_MARKERS)


# ------------------------------------------------------------------------ the invariant


def test_a_surface_that_shows_the_roster_discloses_the_exclusion(tmp_path):
    home = tmp_path / "own"
    shutil.copytree(OWN_INSTALL, home)
    surfaces = _render_every_surface(home)

    with_roster = {n: b for n, b in surfaces.items() if _ROSTER_MARKER in b}
    assert len(with_roster) >= 4, sorted(with_roster)  # text/json/html/pdf at minimum
    silent = sorted(n for n, b in with_roster.items() if not _discloses(b))
    assert not silent, f"surface(s) show the roster and never say a member was skipped: {silent}"


def test_sarif_discloses_even_though_it_has_no_roster_to_show(tmp_path):
    """SARIF carries results, not an inventory, so the invariant above would not reach it
    — and a CI pipeline is exactly the consumer that cannot ask a human. Asserted
    separately rather than by loosening the invariant."""
    home = tmp_path / "own"
    shutil.copytree(OWN_INSTALL, home)
    ctx, findings, score = audit(home)
    completeness = json.loads(render_sarif(findings, score, ctx=ctx))[
        "runs"][0]["properties"]["analysisCompleteness"]
    assert completeness["selfExcludedSkills"] == ["clawseccheck"]
    assert any(SELF_EXCLUDED_NOTE in line for line in completeness["limitations"])


def test_sarif_always_carries_the_key_so_absence_is_not_ambiguous(tmp_path):
    """Empty list, not a missing key: otherwise "nothing was excluded" and "this producer
    predates the field" read identically to a consumer."""
    home = tmp_path / "plain"
    shutil.copytree(NO_OWN_INSTALL, home)
    ctx, findings, score = audit(home)
    completeness = json.loads(render_sarif(findings, score, ctx=ctx))[
        "runs"][0]["properties"]["analysisCompleteness"]
    assert completeness["selfExcludedSkills"] == []


# --------------------------------------------------------------- no surface invents it


def test_no_surface_discloses_an_exclusion_that_did_not_happen(tmp_path):
    home = tmp_path / "plain"
    shutil.copytree(NO_OWN_INSTALL, home)
    for name, body in _render_every_surface(home).items():
        assert "not graded --" not in body, name
        assert "excluded from the installed-skill content scan" not in body, name


def test_the_composer_returns_nothing_for_an_empty_roster():
    assert self_excluded_line([]) == ""
    assert self_excluded_line(None) == ""
    assert self_excluded_line(["a", "b"]).startswith("a, b ")


def test_a_bare_string_is_one_name_not_a_sequence_of_characters():
    """No caller passes one today; a future one would otherwise render "a, b, c"."""
    assert self_excluded_line("abc").startswith("abc ")


# ------------------------------------------------------- the name is attacker-chosen


def _own_install_named(tmp_path: Path, name: str) -> Path:
    """A home whose self-excluded skill carries *name*.

    The identity oracle recognises our own copy by package LAYOUT, not by name
    (`collector._is_own_source`), so the directory name is fully attacker-chosen — which
    is why it must be sanitised before it reaches any surface. The nested
    `<name>/clawseccheck/checks/` shape is what the oracle's first branch matches; a
    flat rename does NOT self-exclude, and a probe built that way silently measures
    nothing.
    """
    home = tmp_path / "hostile"
    shutil.copytree(OWN_INSTALL, home)
    skills = home / "workspace-home" / "skills"
    src = skills / "clawseccheck"
    target = skills / name
    (target / "clawseccheck" / "checks").mkdir(parents=True)
    shutil.copy(src / "SKILL.md", target / "SKILL.md")
    for leaf in ("__init__.py", "_engine.py"):
        shutil.copy(src / "checks" / leaf, target / "clawseccheck" / "checks" / leaf)
    shutil.rmtree(src)
    return home


def test_a_hostile_skill_name_reaches_no_surface_unsanitised(tmp_path):
    """**The C-135 break.** `render_html` escaped with `html.escape` alone, which handles
    `&<>"'` and nothing else, so ESC/BEL, U+200B and U+202E reached the page — and U+202E
    reverses the rendered order of the disclosure sentence itself, spoofing the very note
    this change adds. Sanitising in the composer makes every surface safe at once.
    """
    name = "ev\x1b[31mRED\x1b[0m‮il​skill\x07"
    home = _own_install_named(tmp_path, name)
    ctx, findings, score = audit(home)
    assert getattr(ctx, "self_excluded_skills", None), (
        "the probe did not self-exclude — the layout, not the name, is what the oracle "
        "matches, so a flat rename measures nothing")

    hostile_chars = {"ESC": "\x1b", "BEL": "\x07", "U+202E": "‮", "U+200B": "​"}
    surfaces = _render_every_surface(home)  # pdf entry is already shown-text, not bytes
    for surface, body in surfaces.items():
        leaked = sorted(k for k, ch in hostile_chars.items() if ch in body)
        assert not leaked, f"{surface} carries {leaked} from an attacker-chosen skill name"


# ------------------------------------------------------------------------- one wording


def test_html_escapes_the_disclosure(tmp_path):
    """Skill names reach this line and are attacker-chosen directory names."""
    home = tmp_path / "own"
    shutil.copytree(OWN_INSTALL, home)
    ctx, findings, score = audit(home)
    body = render_html(findings, score, ctx=ctx)
    assert "<p class=\"inv-note\">" in body
    # the apostrophe in "ClawSecCheck's" must arrive escaped, proving it went through esc()
    assert "ClawSecCheck&#x27;s own installed copy" in body
