"""A skill the sweep could not finish is named WITH its reason on the coverage page.

Live finding (2026-11-06, a real chat run): the summary said "35 of 36 skills were
swept; `pptx` was not fully swept" and nothing else. Measured cause: the installed
`pptx` skill is 58 files / 1,163,822 bytes, over the 1,000,000-byte per-skill text
budget (`collector._MAX_BYTES_PER_SKILL`). Files are read in risk-priority order, so
SKILL.md and every script were read in full; the cut fell inside the bundled ISO
schema `.xsd` reference data (~163 KB unread). That bound is reasonable and the
per-skill finding already said so - but the coverage page printed only the NAME,
because its instance lists carried no reason (C-566 left that as a follow-up).

Pinned here:
* a TRUNCATED row's reason is the producer's own sentence, sanitized, with the
  "coverage is incomplete: " lead-in stripped;
* SKIPPED / UNKNOWN / budget-raise rows each say their own, different thing;
* a fully scanned sweep adds no reason and no line (the clean control);
* a sweep object without the method (the plugin sweep) still renders bare names;
* end to end through the real collector: an over-budget skill is TRUNCATED and the
  rendered page names the reason.

Offline; writes only under ``tmp_path``.
"""
from __future__ import annotations

import json
from pathlib import Path

from _vendor_neutral import neutral_config

import clawseccheck.coverage as cov
from clawseccheck.catalog import Finding
from clawseccheck.cli import SkillSweep, sweep_installed_skills
from clawseccheck.collector import collect

CAP_SENTENCE = (
    "text scan of skill 'pptx' hit the 1000KB/500-file cap — "
    "content beyond the cap was NOT scanned"
)


def _finding(detail: str, status: str = "UNKNOWN") -> Finding:
    return Finding(id="B13", title="t", severity="HIGH", status=status,
                   detail=detail, fix="f", framework="x")


def _sweep(rows, findings=()) -> SkillSweep:
    return SkillSweep(
        home_dir=Path("."), checked_dirs=[Path(".")],
        rows=list(rows), findings=[(n, f"/x/{n}", f) for n, f in findings],
    )


def test_truncated_reason_is_the_producers_sentence_without_the_lead_in():
    f = _finding("Skill scanning was truncated / hit limits — coverage is "
                 "incomplete: " + CAP_SENTENCE)
    sw = _sweep([("pptx", "TRUNCATED", 0)], [("pptx", f)])
    assert sw.not_scanned_reasons() == {"pptx": CAP_SENTENCE}


def test_each_unfinished_status_says_its_own_thing():
    sw = _sweep([("a", "SKIPPED", 0), ("b", "UNKNOWN", 0), ("c", "TRUNCATED", 0)])
    r = sw.not_scanned_reasons()
    assert set(r) == set(sw.not_scanned()) == {"a", "b", "c"}
    assert "time budget" in r["a"]
    assert "engine error" in r["b"]
    assert "budget ran out" in r["c"]          # no finding: the ScanBudgetExceeded arm
    assert len({r["a"], r["b"], r["c"]}) == 3


def test_clean_sweep_has_no_reasons_and_no_extra_line():
    sw = _sweep([("ok", "PASS", 0), ("meh", "WARN", 1)],
                [("ok", _finding("fine", "PASS"))])
    assert sw.not_scanned_reasons() == {}
    page = cov._sweep_coverage(sw)
    assert page["not_scanned"] == [] and page["not_scanned_reasons"] == {}
    lines = cov.coverage_page_lines({"skills": {**page, "checks": None}})
    assert not any("not swept" in ln for ln in lines)


def test_hostile_skill_name_in_the_reason_is_sanitized():
    f = _finding("coverage is incomplete: skill '\x1b[31mevil\x07' hit the cap")
    sw = _sweep([("evil", "TRUNCATED", 0)], [("evil", f)])
    why = sw.not_scanned_reasons()["evil"]
    assert "\x1b" not in why and "\x07" not in why and "evil" in why


def test_reason_is_bounded():
    f = _finding("coverage is incomplete: " + "x" * 5000)
    why = _sweep([("big", "TRUNCATED", 0)], [("big", f)]).not_scanned_reasons()["big"]
    assert len(why) <= 220


def test_page_and_text_carry_the_reason_for_the_named_skill():
    f = _finding("coverage is incomplete: " + CAP_SENTENCE)
    sw = _sweep([("ok", "PASS", 0), ("pptx", "TRUNCATED", 0)],
                [("ok", _finding("fine", "PASS")), ("pptx", f)])
    page = cov._sweep_coverage(sw)
    assert page["scanned"] == 1 and page["total"] == 2
    assert page["not_scanned_reasons"] == {"pptx": CAP_SENTENCE}
    text = "\n".join(cov.coverage_page_lines({"skills": {**page, "checks": None}}))
    assert f"skills not swept: pptx ({CAP_SENTENCE})" in text
    bare = "\n".join(cov.coverage_page_lines(
        {"skills": {**page, "checks": None}}, show_reasons=False))
    assert "skills not swept: pptx" in bare and CAP_SENTENCE not in bare


def test_sweep_without_the_method_still_renders_bare_names():
    class Plain:
        no_roots = no_targets = False

        def counts(self):
            return {"total": 2, "skipped": 0}

        def not_scanned(self):
            return ["p1"]

    page = cov._sweep_coverage(Plain())
    assert "not_scanned_reasons" not in page and page["not_scanned"] == ["p1"]
    text = "\n".join(cov.coverage_page_lines({"plugins": {**page, "checks": None}}))
    assert "plugins not swept: p1" in text and "(" not in text.split("p1", 1)[1]


def test_end_to_end_over_budget_skill_is_named_with_the_cap_reason(tmp_path):
    (tmp_path / "openclaw.json").write_text(json.dumps(neutral_config()), encoding="utf-8")
    d = tmp_path / "skills" / "bigdocs"
    (d / "ref").mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: bigdocs\ndescription: Formats reference tables.\n---\n"
        "# bigdocs\n\nFormats reference tables.\n", encoding="utf-8")
    for i in range(12):                       # 12 x 100 KB of plain reference text > 1,000,000
        (d / "ref" / f"table{i:02d}.txt").write_text(
            ("row %d: alpha beta gamma\n" % i) * 4200, encoding="utf-8")
    ctx = collect(tmp_path)
    sw = sweep_installed_skills(tmp_path, narrate=False, ctx=ctx)
    assert sw.not_scanned() == ["bigdocs"]
    why = sw.not_scanned_reasons()["bigdocs"]
    assert "bigdocs" in why and "NOT scanned" in why
    page = cov._sweep_coverage(sw)
    text = "\n".join(cov.coverage_page_lines({"skills": {**page, "checks": None}}))
    assert "skills not swept: bigdocs (" in text
