"""B-467 … B-471 — the guided agent path: what the host agent is told, and what it pastes.

- B-467 a grade capped by a submitted liveTest VULNERABLE verdict took `home_safe` from
  `Grade A · 97/100` to `Grade F · 49/100` over the same 11 findings, with no explanation
  anywhere in the card. The terminal report has disclosed this all along through the SAME
  shared cap cascade — the card simply never called it.
- B-468 the card the agent is ordered to paste VERBATIM contained the absolute report path
  and the line "Attach that PDF file itself into the chat; do not paste its path…" — an
  instruction addressed to the agent, inside text it must reproduce word for word. The
  observed resolution of that contradiction was the worst one available: a real session
  where the agent sent the user a link, twice, before attaching anything.
- B-469 `--menu` item 1 read "config + live agent test ⚡" for a mode that is entirely
  read-only, contradicting SKILL.md's own rendering of that screen and its statement that
  the live injection test "stays a separate, opt-in step — not part of item 1".
- B-470 the mandatory judge panel's per-item verdicts were computed and discarded; the only
  rendering anywhere was a bare count.
- B-471 `--functions` padded every row to the longest blurb in the palette, stretching all
  60 rows to 273 characters to align one.

Offline; writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit, menu
from clawseccheck.cli import main
from clawseccheck.palette import render_palette
from clawseccheck.report import _second_opinion_item_lines, render_dashboard
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
VULN = str(FIXTURES / "home_vuln")


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


# ---- B-467: the cap reason must reach the card ----

def _live_bundle(tmp_path: Path) -> str:
    p = tmp_path / "live.json"
    p.write_text(json.dumps({"liveTest": {"seed": "abc123", "verdicts": [
        {"tool": "canary", "id": "C1", "verdict": "VULNERABLE"}]}}), encoding="utf-8")
    return str(p)


def test_live_test_cap_is_disclosed_in_the_card(tmp_path, capsys):
    _, out, _ = _run(capsys, "--dashboard", "--full", "--judged-bundle",
                     _live_bundle(tmp_path), "--home", SAFE, "--no-color")
    assert "capped from" in out
    assert "VULNERABLE" in out


def test_uncapped_card_carries_no_cap_line(capsys):
    _, out, _ = _run(capsys, "--dashboard", "--full", "--home", SAFE,
                     "--no-color", "--no-history")
    assert "capped from" not in out


def test_card_cap_line_matches_the_shared_cascade(tmp_path):
    """The card must not grow a second, drifting explanation of the same cap."""
    ctx, findings, _ = audit(SAFE)
    capped = compute(findings, ctx, live_test_vulnerable=True,
                     live_test_reason="a live injection-test scenario reported VULNERABLE (canary:C1)")
    card = render_dashboard(findings, capped, ctx=ctx)
    assert "capped from" in card
    assert "canary:C1" in card


# ---- B-468: the paste must contain nothing addressed to the agent ----

def test_pasted_card_carries_no_path_and_no_agent_instruction(tmp_path, capsys):
    dest = tmp_path / "out" / "r.pdf"
    _, out, err = _run(capsys, "--dashboard", "--full", "--pdf", str(dest),
                       "--home", VULN, "--no-color")
    assert dest.is_file()
    # stdout is what gets pasted into the chat.
    assert str(dest) not in out
    assert str(tmp_path) not in out
    assert "do not paste" not in out.lower()
    assert "attach that pdf" not in out.lower()
    # ...and the agent still gets told, on its own channel.
    assert str(dest) in err
    assert "attach this PDF file itself" in err


def test_the_card_still_tells_the_reader_where_the_detail_is(tmp_path, capsys):
    dest = tmp_path / "out" / "r.pdf"
    _, out, _ = _run(capsys, "--dashboard", "--full", "--pdf", str(dest),
                     "--home", VULN, "--no-color")
    assert "attached PDF report" in out


def test_no_pdf_means_no_stray_note(capsys):
    _, _, err = _run(capsys, "--dashboard", "--full", "--home", SAFE,
                     "--no-color", "--no-history")
    assert "attach this PDF" not in err


# ---- B-469: the menu must not advertise a live test in a read-only mode ----

def test_menu_item_one_does_not_claim_to_touch_the_live_agent():
    labels = [row for row in menu._ITEMS if row[0] == "1"]
    assert labels, "expected a menu item 1"
    assert "live" not in labels[0][3].lower()
    assert labels[0][3] == "config + capability audit"


def test_rendered_menu_carries_no_live_claim_on_item_one(capsys):
    _, out, _ = _run(capsys, "--menu", "--home", SAFE, "--no-color")
    line = [ln for ln in out.splitlines() if "Check everything" in ln]
    assert line, "menu item 1 not rendered"
    assert "live agent test" not in line[0]
    assert "capability audit" in line[0]


# ---- B-470: the judge panel's per-item verdicts must be rendered somewhere ----

class _Phase:
    def __init__(self, rows):
        self.data = {"secondOpinion": rows}


def test_per_item_verdicts_are_rendered():
    rows = [{"finding_id": "B100", "target": "B100", "engine_disposition": "UNKNOWN",
             "judge_verdict": "SUSPICIOUS", "annotation": "worth a closer look"}]
    lines = _second_opinion_item_lines(_Phase(rows))
    assert lines and "B100" in lines[0]
    assert "UNKNOWN -> SUSPICIOUS" in lines[0]
    # A config-scoped item's target IS its id — do not print it twice.
    assert "[B100]" not in lines[0]


def test_unjudged_items_are_not_rendered_as_verdicts():
    rows = [{"finding_id": "B1", "target": "t", "engine_disposition": "WARN",
             "judge_verdict": None, "annotation": None}]
    assert _second_opinion_item_lines(_Phase(rows)) == []


def test_the_item_list_is_bounded_and_says_so():
    rows = [{"finding_id": f"B{i}", "target": "t", "engine_disposition": "WARN",
             "judge_verdict": "SAFE", "annotation": None} for i in range(80)]
    lines = _second_opinion_item_lines(_Phase(rows), limit=10)
    assert len(lines) == 11
    assert "+70 more" in lines[-1]


# ---- B-471: the palette must not pad every row to its longest blurb ----

def test_palette_rows_are_not_padded_to_the_longest_blurb():
    text = render_palette(n_checks=184)
    over = [ln for ln in text.splitlines() if len(ln) > 240]
    assert len(over) <= 1, f"{len(over)} rows still stretched past 240 chars"
    assert len(text) < 8000, f"palette is {len(text)} bytes"


def test_palette_still_lists_every_entry():
    """Guard against 'fixing' the width by dropping content."""
    text = render_palette(n_checks=184)
    for needle in ("Quick scan", "Vet anything", "Badge", "Self-test"):
        assert needle in text
