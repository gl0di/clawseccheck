"""B-629: an evidence list that was cut says so, at every site that cuts one.

"Print at most N evidence bullets" was decided in three places and announced in one:

    cli.py  sweep_installed_skills   evidence[:12]   (+N more)   <- the only honest one
    report.py _render_finding        evidence[:12]   silent
    cli.py  --vet-mcp render         evidence[:4]    silent

A reader of the silent two saw N bullets with nothing to suggest there had been more —
and on the audit path the cut takes the FRONT of the list, so what disappears is the tail,
not the least important entries.

The correct behaviour already existed in the tree, which settled the design question: the
fix is not a fourth opinion about the right number, it is the one implementation shared by
all three. `test_no_renderer_cuts_an_evidence_list_on_its_own` is the half that makes it
stay that way — a helper alone does not stop a fourth site being written beside it.

**What counts as hidden is the cap alone**, and that is deliberately narrower than the
first sketch of this fix ("count what was printed"). An entry dropped for already appearing
in the `why` line is not hidden — the reader read those words a line earlier — and
promising it would send them looking for something they have already seen.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, Finding
from clawseccheck.cli import main
from clawseccheck.report import _evidence_bullets, _render_finding

_REPO = Path(__file__).resolve().parent.parent
_PKG = _REPO / "clawseccheck"

# The renderer layer. `checks/*.py` is deliberately NOT here: its many `ev[:4]` slices cap
# what a finding CARRIES, at construction time, which is a different decision from what a
# renderer PRINTS — and those findings state their own totals in `detail`. Conflating the
# two would make this guard fire ~15 times on code it has nothing to say about.
_RENDERERS = (
    "report.py", "cli.py", "sarif.py", "pdf.py", "guide.py",
    "dossier.py", "sar.py", "adjudication.py", "menu.py",
)


def _f(evidence, *, detail: str = "why line") -> Finding:
    return Finding("B13", "t", CRITICAL, FAIL, detail, "fix", "Skill Trust", False, evidence)


# --------------------------------------------------------------------------- #
# The helper: where the rule lives.                                           #
# --------------------------------------------------------------------------- #
def test_a_cut_list_says_how_much_was_cut():
    out = _evidence_bullets([f"e{i}" for i in range(20)], limit=5, indent="  ")
    assert len(out) == 6, out
    assert out[-1] == "  - (+15 more)", out[-1]


def test_a_list_that_fits_says_nothing():
    """Negative control. Without it every assertion here could pass on a build that
    always appends a disclosure."""
    out = _evidence_bullets(["a", "b"], limit=5, indent="  ")
    assert out == ["  - a", "  - b"], out


def test_an_empty_list_produces_no_lines_at_all():
    assert _evidence_bullets([], limit=5, indent="  ") == []
    assert _evidence_bullets(None, limit=5, indent="  ") == []


def test_entries_already_quoted_in_the_why_line_are_not_counted_as_hidden():
    """The rule this fix deliberately did NOT take from its own first sketch.

    Many checks build `detail` by joining their own evidence, so the "don't repeat the why
    line" filter drops bullets whose content the reader has just read. Counting those as
    "+N more" would promise information that is not hidden and cannot be retrieved by
    looking harder — a disclosure that misleads in the opposite direction.
    """
    out = _evidence_bullets(
        ["shown", "also shown", "new"], limit=5, indent="  ",
        already_shown="why: shown / also shown",
    )
    assert out == ["  - new"], out
    assert not any("more" in line for line in out), out


def test_an_entry_with_nothing_renderable_is_not_promised():
    """`_sanitize` strips control characters; an entry made only of them renders as
    nothing, so there is nothing to tell the reader to go and find."""
    out = _evidence_bullets(["\x00\x01", "real"], limit=5, indent="  ")
    assert out == ["  - real"], out


def test_the_disclosure_uses_the_callers_bullet():
    """--ascii picks `*` over `•` at the sweep site. A disclosure line hard-coding one of
    them would survive `asciify` but look foreign next to the bullets above it."""
    out = _evidence_bullets([f"e{i}" for i in range(9)], limit=3, indent="  ", bullet="*")
    assert out[-1] == "  * (+6 more)", out[-1]
    assert all(line.startswith("  * ") for line in out), out


def test_the_cap_takes_the_front_so_the_number_covers_the_tail():
    """Pins WHICH entries are hidden, not just how many — the audit-path cut drops the
    tail, and a future change to slice from the other end would silently invert what the
    number refers to."""
    out = _evidence_bullets(["first", "second", "third", "fourth"], limit=2, indent="  ")
    assert out[0].endswith("first") and out[1].endswith("second"), out
    assert out[-1] == "  - (+2 more)", out[-1]


# --------------------------------------------------------------------------- #
# The three sites, each through its own renderer.                             #
# --------------------------------------------------------------------------- #
def test_the_audit_report_finding_render_discloses_its_cut():
    lines: list[str] = []
    _render_finding(lines, _f([f"evidence line {i}" for i in range(30)]))
    body = "\n".join(lines)
    assert "(+18 more)" in body, body
    # Non-vacuity: real bullets are present too, so this is a cut and not a total drop.
    assert body.count("      - ") == 13, body


def test_the_audit_report_counts_the_cap_not_the_dedup_drop():
    """The interesting case, end to end: 30 entries, 12 survive the cap, and several of
    those are quoted verbatim in the why line. The bullet count falls; the number does
    not, because those entries were read, not hidden."""
    quoted = " / ".join(f"evidence line {i}" for i in range(4))
    lines: list[str] = []
    _render_finding(lines, _f([f"evidence line {i}" for i in range(30)], detail=quoted))
    body = "\n".join(lines)
    assert "(+18 more)" in body, body
    assert body.count("      - ") == 9, body  # 12 - 4 quoted, + the disclosure line


def test_the_installed_skill_sweep_still_discloses(tmp_path, capsys, monkeypatch):
    """Regression on the one site that was already right: it must keep working after
    being moved onto the shared helper.

    `vet_skill` is replaced so the sweep receives a finding with a known evidence
    length. What is under test is this function's RENDER of whatever the engine returns —
    building a real skill whose scan happens to produce thirteen evidence entries would
    be testing the engine, and would drift the moment a check's wording changed.
    """
    import clawseccheck.cli as cli_mod

    skill = tmp_path / "skills" / "probe"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: probe\ndescription: A helper skill.\n---\n\n# probe\n\nNotes.\n",
        encoding="utf-8",
    )
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli_mod, "vet_skill", lambda *a, **k: _f([f"e{i}" for i in range(20)]))

    sweep = cli_mod.sweep_installed_skills(tmp_path, narrate=True)
    out = capsys.readouterr().out
    # Non-vacuity: the sweep really reached the skill and rendered its evidence.
    assert "e0" in out, out[-2000:]
    assert "(+8 more)" in out, out[-2000:]
    assert sweep.findings, "the sweep produced no finding, so the render was never exercised"


def test_the_full_run_vet_mcp_section_discloses_its_cut(tmp_path, capsys, monkeypatch):
    """The third site, and the one whose location in the task description was wrong.

    It was filed as "the --vet-mcp render". It is not: `--vet-mcp` goes through
    `_run_vet_mcp`, which renders a risk dossier of axes and prints no evidence bullets
    at all. This loop lives in `--full`'s own vet-mcp section, so a test driving
    `--vet-mcp` exercises a different renderer entirely and passes while proving nothing —
    which is exactly what the first draft of this test did.

    Contract test on the render, and labelled as one: `vet_mcp` is replaced so the
    branch receives a finding with a known evidence length.
    """
    import clawseccheck.cli as cli_mod

    monkeypatch.setattr(
        cli_mod, "vet_mcp",
        lambda *a, **k: [_f([f"mcp evidence {i}" for i in range(7)]),
                         _f([f"mcp evidence {i}" for i in range(7)])],
    )
    cfg = {"mcp": {"servers": {"probe": {"command": "echo"}}}}
    (tmp_path / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    main(["--home", str(tmp_path), "--full", "--no-native", "--no-history"])
    out = capsys.readouterr().out

    section = out.split("CLAWSECCHECK VET-MCP", 1)
    assert len(section) == 2, "the --full run did not reach its vet-mcp section"
    body = section[1]
    assert "(+3 more)" in body, body[:3000]
    assert body.count("    - mcp evidence") == 8, body[:3000]


# --------------------------------------------------------------------------- #
# The half that makes it stay fixed.                                          #
# --------------------------------------------------------------------------- #
def test_no_renderer_cuts_an_evidence_list_on_its_own():
    """A shared helper does not prevent a fourth site — it only makes one available.

    This is what prevents it. Three copies of one decision is how the disclosure came to
    exist in only one of them, and the same shape lost three times in one day in
    `checks/_mcp.py`'s hand-maintained separator list. If a renderer genuinely needs a
    different cut, it goes through `_evidence_bullets`, or this test is updated
    deliberately with the reason.
    """
    slicer = re.compile(r"\.evidence\s*\[\s*:")
    offenders = []
    for name in _RENDERERS:
        path = _PKG / name
        if not path.is_file():
            continue
        src = path.read_text(encoding="utf-8")
        for m in slicer.finditer(src):
            offenders.append(f"{name}:{src[: m.start()].count(chr(10)) + 1}")
    assert not offenders, (
        "a renderer slices an evidence list inline instead of going through "
        f"_evidence_bullets, so its cut is silent again: {offenders}"
    )


def test_the_guard_is_not_vacuous():
    """The control for the test above: prove the pattern it searches for is one that
    actually occurs in this kind of code, so a green result means "none found" rather
    than "the regex never matches anything"."""
    slicer = re.compile(r"\.evidence\s*\[\s*:")
    assert slicer.search("        for ev in f.evidence[:12]:"), "the guard cannot match its own subject"
    assert not slicer.search("entries = list(evidence or [])")
