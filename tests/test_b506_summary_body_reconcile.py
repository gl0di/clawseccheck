"""B-506, second half — the HTML/PDF/card summary may not contradict the body either.

`tests/test_b506_inventory_reconciles.py` fixed and pinned ONE surface: the terminal
"INVENTORY BY SUBJECT" block. The same report builds its per-subject summary a second
time, in `report._subject_summary_rows`, and that function is the single source of the
HTML summary table, the PDF summary table AND the chat card. It was not fixed, and it
had the identical defect for the identical reason — it read the per-ITEM roster
(`inventory["skills"]`, `inventory["mcp"]`: lists of installed skills and configured
servers) and never the subject bucket, so a finding filed against the SUBJECT had
nowhere to land and an empty roster rendered as an assessed all-clear:

    chat card:   🧩 Skills — ✅ none installed          <- measured, before the fix
    same card:   │ Skills — 2 issue(s)                  <- the body, one screen down
    HTML table:  |Skills||none installed||PASS|

On the maintainer's own config the card read `✅ 0 flagged · 2 installed` above a body
saying `Skills — 3 issue(s)`, and `✅ none configured` above `MCP servers — 2 issue(s)`.

Two things are deliberate here:

* The invariant is swept over **every fixture in `fixtures/`**, not over synthetic
  subjects. The existing B-506 module parametrizes seven hand-built subjects and never
  touches the corpus, which is how a second renderer with the same bug stayed green.
  544 of the 646 fixture homes produce a Skills subject finding and 39 produce an MCP
  one, so the sweep is not vacuous — it fails 583 times without the fix.
* It asserts on **rendered output**: the card and the report body as a user sees them,
  never on `_subject_summary_rows` itself. A helper-level assertion cannot see a
  renderer that ignores the helper.

Stdlib-only, offline, writes nothing.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import CATALOG, FAIL, HIGH, PASS, SUBJECT_OF, WARN, Finding
from clawseccheck.collector import Context
from clawseccheck.report import render_dashboard, render_html, render_report
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# Subject -> real catalog ids, so a seeded finding routes through the same
# surface->subject map the renderer uses (a Finding carries no subject of its own).
_IDS_FOR: dict[str, list[str]] = {}
for _meta in CATALOG:
    _subject = SUBJECT_OF.get(_meta.surface)
    if _subject:
        _IDS_FOR.setdefault(_subject, []).append(_meta.id)

# Body detail header, e.g. "│ Skills — 3 issue(s)".
_BODY_RE = re.compile(r"│ (Skills|MCP servers) — (\d+) issue")
# Card summary row, e.g. " 🧩 Skills — ⛔ none installed · 3 issue(s)".
_CARD_RE = re.compile(r"(Skills|MCP servers) — .*?(\d+) issue")
_SUBJECT_EMOJI = ("\U0001f9e9", "\U0001f50c")   # 🧩 skills, 🔌 mcp


def _card_counts(card: str) -> dict:
    """Subject -> issue count as the CARD's own summary row states it; a row that
    states no count reads as 0, which is exactly the claim that used to be wrong."""
    out = {}
    for line in card.splitlines():
        if not any(e in line for e in _SUBJECT_EMOJI):
            continue
        m = _CARD_RE.search(line)
        if m:
            out[m.group(1)] = int(m.group(2))
        else:
            m2 = re.search(r"(Skills|MCP servers) — ", line)
            if m2:
                out.setdefault(m2.group(1), 0)
    return out


def _body_counts(text: str) -> dict:
    return {m.group(1): int(m.group(2)) for m in _BODY_RE.finditer(text)}


# ── the invariant, over the real corpus ──────────────────────────────────────

def test_card_summary_agrees_with_the_report_body_on_every_fixture():
    """One report, one set of numbers — swept across `fixtures/`."""
    dirs = sorted(p for p in FIXTURES.iterdir() if p.is_dir())
    assert len(dirs) > 100, f"the fixture corpus did not load ({len(dirs)} dirs)"

    disagreements = []
    exercised = {"Skills": 0, "MCP servers": 0}
    for path in dirs:
        ctx, findings, score = audit(path)
        body = _body_counts(render_report(findings, score, ctx=ctx))
        card = _card_counts(render_dashboard(findings, score, ctx=ctx))
        for subject in ("Skills", "MCP servers"):
            want = body.get(subject, 0)
            if want:
                exercised[subject] += 1
            got = card.get(subject, 0)
            if want != got:
                disagreements.append(f"{path.name}: {subject} card={got} body={want}")

    assert exercised["Skills"] > 100 and exercised["MCP servers"] > 10, (
        f"the sweep stopped exercising the defect ({exercised}) — the fixtures changed, "
        "so this invariant is now vacuous and must be re-grounded, not deleted")
    assert not disagreements, (
        f"{len(disagreements)} fixture(s) render a summary that contradicts their own "
        f"body; first 5: {disagreements[:5]}")


# ── the two surfaces, pinned by name ─────────────────────────────────────────

def _seeded():
    """Two skill-subject findings and one MCP-subject finding, over an EMPTY roster —
    the shape that used to read as clear on all three summary surfaces."""
    def _f(fid, status):
        return Finding(fid, f"seeded {fid}", HIGH, status, "detail", "fix", "framework")
    return [_f(_IDS_FOR["skills"][0], FAIL), _f(_IDS_FOR["skills"][1], WARN),
            _f(_IDS_FOR["mcp"][0], FAIL)]


def _ctx() -> Context:
    return Context(home=Path("/nonexistent"))


def test_html_summary_table_states_the_subject_findings():
    findings = _seeded()
    html = render_html(findings, compute(findings), ctx=_ctx())
    table = html.split('class="subj-table"')[1].split("</table>")[0]
    rows = {}
    for row in re.findall(r"<tr>.*?</tr>", table):
        cells = [c for c in re.split(r"<[^>]+>", row) if c.strip()]
        rows[cells[0]] = cells[1:]
    assert "2 issue(s)" in " ".join(rows["Skills"]), rows["Skills"]
    assert FAIL in rows["Skills"], rows["Skills"]
    assert "1 issue(s)" in " ".join(rows["MCP servers"]), rows["MCP servers"]
    assert FAIL in rows["MCP servers"], rows["MCP servers"]


def test_chat_card_states_the_subject_findings():
    findings = _seeded()
    card = render_dashboard(findings, compute(findings), ctx=_ctx())
    counts = _card_counts(card)
    assert counts.get("Skills") == 2, card
    assert counts.get("MCP servers") == 1, card


def test_a_genuinely_clean_subject_is_still_reported_clean():
    """Withholding the all-clear must not become unconditional — the fix may not
    invent an issue on a subject that carries none."""
    findings = [Finding(_IDS_FOR["openclaw"][0], "seeded", HIGH, PASS,
                        "detail", "fix", "framework")]
    html = render_html(findings, compute(findings), ctx=_ctx())
    table = html.split('class="subj-table"')[1].split("</table>")[0]
    skills_row = [r for r in re.findall(r"<tr>.*?</tr>", table) if ">Skills<" in r]
    assert skills_row, table
    assert "issue(s)" not in skills_row[0], skills_row[0]
    assert "not assessed" not in skills_row[0], skills_row[0]
    assert _card_counts(render_dashboard(findings, compute(findings), ctx=_ctx())) \
        .get("Skills", 0) == 0
