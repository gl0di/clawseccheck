"""B-594: the inventory header kept saying "installed" after B-507 stopped the body.

Measured on a real machine (2026-08-20), one screen of `--dashboard --full`::

    · Inventory by subject ·
     🧩 Skills — ⛔ 0 flagged · 2 installed · 4 issue(s)
    …
    · Skills ·
     Skills (2 bundled with a plugin · 1 self-excluded) — ⛔ 4 issue(s)
       ✅ 2 clean: browser-automation, canvas

Exactly one skill was installed there — `~/.openclaw/workspace/skills/clawseccheck` — and
the two the header called "installed" ship inside OpenClaw's own npm package. So the header
counted the wrong population *and* omitted the only member of the right one, which is
precisely the sentence CLAWSECCHECK-B-507 was filed to remove. B-507 fixed
`_skills_inventory_lines`; `_subject_summary_rows` — the single source of the HTML table,
the PDF summary table and the chat card — was never updated.

`_subject_summary_rows`' own comment block records B-506 having made the same mistake in the
opposite direction: a fix applied to the terminal block and not to this function. Twice is a
structure problem, not a slip, so the fix is not "correct the f-string" but "delete the
f-string": both callers now read `_skills_roster_text` and have nothing else to describe a
roster with.

This file therefore asserts AGREEMENT between the two surfaces rather than the wording of
either. A per-surface assertion is how they drifted apart the first two times.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.collector import _OWN_ENGINE_MARKERS, collect
from clawseccheck.report import (
    _skills_roster_text,
    _subject_summary_rows,
    build_inventory,
    render_html,
    render_subject_inventory,
)
from clawseccheck.scoring import compute

REPO_ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ fixture builders

def _cfg(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8")
    cfg.chmod(0o600)


def _skill_md(d: Path, name: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A helper skill.\n---\n\nDoes something local.\n",
        encoding="utf-8")


def _own_engine(skill_dir: Path) -> None:
    """A genuine, content-verified ClawSecCheck install (B-265)."""
    _skill_md(skill_dir, "clawseccheck")
    checks = skill_dir / "checks"
    checks.mkdir(parents=True, exist_ok=True)
    (checks / "_engine.py").write_text("\n".join(_OWN_ENGINE_MARKERS), encoding="utf-8")


def _bundled(home: Path, name: str, pkg: Path) -> None:
    """A skill reachable only through the plugin-skills symlink root."""
    _skill_md(pkg, name)
    (home / "plugin-skills").mkdir(parents=True, exist_ok=True)
    (home / "plugin-skills" / name).symlink_to(pkg, target_is_directory=True)


def _the_real_shape(tmp_path: Path):
    """The machine this was found on: two bundled extensions, ClawSecCheck itself
    installed and self-excluded, nothing else."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    _own_engine(home / "skills" / "clawseccheck")
    _bundled(home, "browser-automation", tmp_path / "pkg-browser" / "skills" / "browser-automation")
    _bundled(home, "canvas", tmp_path / "pkg-canvas" / "skills" / "canvas")
    return collect(home)


def _header(ctx) -> str:
    """The Skills row's count text, as every summary surface receives it."""
    rows = {label: count for label, _status, count in _subject_summary_rows([], ctx)}
    hits = [c for label, c in rows.items() if "Skills" in label]
    assert len(hits) == 1, rows
    return hits[0]


def _body(ctx) -> str:
    return render_subject_inventory([], ctx, ascii_only=True)


# ------------------------------------------------------------------ the headline case

def test_header_and_body_describe_the_same_population(tmp_path):
    """The defect in one assertion — and the one that would have caught it."""
    ctx = _the_real_shape(tmp_path)
    assert ctx.self_excluded_skills == ["clawseccheck"]
    assert ctx.installed_skill_bundled == {"browser-automation", "canvas"}

    header, body = _header(ctx), _body(ctx)
    assert "2 bundled with a plugin" in header and "2 bundled with a plugin" in body
    assert "1 self-excluded" in header and "1 self-excluded" in body


def test_the_header_no_longer_calls_a_bundled_extension_installed(tmp_path):
    """The literal regression. `browser-automation` and `canvas` live inside OpenClaw's
    own package; a user cannot remove them independently and never chose them."""
    header = _header(_the_real_shape(tmp_path))
    assert not re.search(r"\b\d+ installed\b", header), header


def test_a_real_third_party_install_still_reads_installed(tmp_path):
    """The fix must not turn every roster into "bundled" — that would trade one false
    sentence for another, and it is the failure mode a narrow fix invites."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    _skill_md(home / "skills" / "notes-helper", "notes-helper")
    header = _header(collect(home))
    assert "1 installed" in header
    assert "bundled" not in header


def test_a_mixed_roster_names_both_populations(tmp_path):
    """One user-installed skill beside one bundled extension: a single total would imply
    the user chose both."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    _skill_md(home / "skills" / "notes-helper", "notes-helper")
    _bundled(home, "canvas", tmp_path / "pkg" / "skills" / "canvas")
    header, body = _header(ctx := collect(home)), _body(ctx)
    assert "1 installed, 1 bundled with a plugin" in header
    assert "1 installed, 1 bundled with a plugin" in body


def test_an_empty_roster_still_names_the_self_exclusion(tmp_path):
    """The sharpest case, and the one the old header got most wrong: a machine whose ONLY
    skill is ClawSecCheck has an empty graded roster, so the header said "none installed"
    about a user who had installed exactly one thing."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    _own_engine(home / "skills" / "clawseccheck")
    ctx = collect(home)
    assert ctx.installed_skills == {}
    header = _header(ctx)
    assert "none installed" in header
    assert "1 self-excluded" in header, "the header hides the only skill the user installed"


# ------------------------------------------------- the three consumers of the same row

def test_every_summary_surface_gets_the_same_sentence(tmp_path):
    """`_subject_summary_rows` feeds the chat card, the HTML table and the PDF summary
    table. Asserting them together is the point: each drifted from the body separately."""
    ctx = _the_real_shape(tmp_path)
    expected = _skills_roster_text(build_inventory([], ctx), ctx)
    assert "bundled with a plugin" in expected          # premise, not the assertion

    assert expected in _header(ctx)

    html = render_html([], compute([], ctx=ctx), ctx=ctx)
    assert expected in html or expected.replace("·", "&middot;") in html, \
        "the HTML summary table disagrees with the card"

    from clawseccheck.pdf import render_pdf
    pdf = render_pdf([], compute([], ctx=ctx), ctx=ctx)
    assert isinstance(pdf, bytes) and pdf.startswith(b"%PDF")


# ---------------------------------------------------- B-265 is untouched by all of this

def test_a_lookalike_that_fails_content_verification_is_counted_normally(tmp_path):
    """B-265's guarantee, pinned from this angle too: a skill merely NAMED clawseccheck
    that carries none of the engine markers must be scanned like any other and counted as
    installed — never allowed to inherit the self-exclusion by name alone."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    _skill_md(home / "skills" / "clawseccheck", "clawseccheck")     # name only, no engine
    ctx = collect(home)
    assert ctx.self_excluded_skills == []
    assert "clawseccheck" in ctx.installed_skills

    header = _header(ctx)
    assert "1 installed" in header
    assert "self-excluded" not in header


# --------------------------------------------------------- one wording, two callers

def test_neither_caller_spells_the_roster_out_itself():
    """Source-level guard. Both call sites hand-rolled this sentence once; the fix is
    only durable if a third hand-rolled copy fails the build instead of waiting to be
    noticed on someone's real machine.

    What it does NOT catch, deliberately stated so nobody leans on it for more than it
    does: a caller that stops using the helper and writes something *simpler* instead —
    the exact regression this task is about, since `"{n} installed"` contains none of the
    phrases below. Verified by reverting the header to its pre-fix line: this test still
    passed while five of the agreement tests above failed. Those are the ones that hold
    the fix; this one only stops the wording from being copied."""
    src = (REPO_ROOT / "clawseccheck" / "report.py").read_text(encoding="utf-8")
    body = src.split("def _skills_roster_text", 1)[1]
    after_helper = body.split("\ndef ", 2)[2]           # everything past the helper itself
    for phrase in ("bundled with a plugin", "self-excluded\"", "NOT inspected"):
        assert phrase not in after_helper, \
            f"a hand-rolled copy of the roster wording reappeared: {phrase!r}"
