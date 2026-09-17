"""B-763 — three places where what the user is told does not match what happens.

1. **SKILL.md's manifest promise.** The frontmatter `description:`/`metadata.
   display_description.en` said the tool "changes nothing in your OpenClaw setup except
   through one opt-in, confirmation-gated command (--apply-ignore-proposals ...)" — but a
   bare `--pdf` also writes inside the OpenClaw home (auto-resolving to
   `<home>/media/outbound` when it exists), with no confirmation step. The promise both
   undercounted ("one") and overclaimed ("confirmation-gated" for the second path). Fixed
   to name both writers accurately, matching the wording `docs/USAGE.md`'s own write-
   boundary paragraph already used (grounded there, not invented fresh).

2. **`--help` on `--exit-code`.** Plain-audit `--exit-code` (any FAIL -> exit 1) and
   `--monitor --exit-code` (a HIGH+ alert -> exit 3, a store-write failure -> exit 1, a
   sub-HIGH or clean run -> exit 0) are different contracts sharing one flag name, and
   only the monitor contract was undocumented in `--help` — someone wiring a cron job off
   the published text alone would get a threshold (HIGH) they never chose. Grounded
   against the real branch in `cli.py`'s monitor-mode exit path, not just its comment.

3. **The unglossed "Lethal Trifecta: N/3".** Ships on the two artifacts meant to be
   posted publicly -- `report.render_card` (self-described "Shareable badge" -- the text
   card behind `--card` and the `--dashboard` header) and the PDF's own badge area
   (`pdf.py`, `--pdf`) -- with no explanation of the three legs anywhere on either
   artifact (the card never carries findings text at all, by design). Both now carry the
   same short gloss. The `--badge grade.svg` SVG file was checked and does not render
   this line at all, so it needed no change.

Offline; reads bundled files and exercises the real renderers/argparse, writes nothing
outside `tmp_path`.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from _pdftext import shown_strings

from clawseccheck.catalog import CRITICAL, FAIL, Finding
from clawseccheck.report import render_card
from clawseccheck.scoring import compute

_REPO = Path(__file__).resolve().parent.parent
_SKILL_MD = _REPO / "SKILL.md"


# ─────────────────────────────────────────────────────── 1. SKILL.md write promise

def test_frontmatter_no_longer_undercounts_the_write_paths():
    text = _SKILL_MD.read_text(encoding="utf-8")
    # The old, inaccurate clause named exactly ONE writer and called it the only one.
    assert "except through one opt-in" not in text, (
        "SKILL.md's frontmatter still claims a single write path into the OpenClaw "
        "setup, which was false the moment --pdf's auto-resolve was documented"
    )


def test_frontmatter_names_both_writers_into_the_openclaw_home():
    text = _SKILL_MD.read_text(encoding="utf-8")
    frontmatter = text.split("---", 2)[1]
    assert "--apply-ignore-proposals" in frontmatter
    assert "--pdf" in frontmatter
    assert "confirmation-gated" in frontmatter
    # --apply-ignore-proposals is the ONLY one that is actually confirmation-gated
    # (an interactive y/n, or --yes) -- --pdf's home-write is opt-in-by-flag, not
    # gated by a prompt. The promise must not claim a confirmation step --pdf never
    # has, which is exactly how the old text overclaimed the second writer once one
    # was added without changing the "confirmation-gated" wording to match.
    assert "confirmation-gated" not in frontmatter.split("--pdf", 1)[1].split(")", 1)[0], (
        "the --pdf clause must not (re)claim a confirmation step it does not have"
    )


def test_frontmatter_never_modifies_config_skill_or_bootstrap_claim_survives():
    """The one absolute claim in the promise -- config/skill/bootstrap files are never
    touched -- must stay, worded exactly as the body's own (already-accurate) write-
    boundary paragraph puts it, so the two do not drift into two different promises.
    """
    text = _SKILL_MD.read_text(encoding="utf-8")
    assert "ever changes your OpenClaw config, a skill, or a bootstrap file" in text


# ─────────────────────────────────────────────────────── 2. --help / --monitor exit codes

def test_help_documents_the_monitor_exit_code_contract():
    out = subprocess.run(
        [sys.executable, str(_REPO / "audit.py"), "--help"],
        cwd=_REPO, capture_output=True, text=True, timeout=30,
    ).stdout
    # Grounded against the real branch (cli.py's monitor-mode exit-code block): HIGH is
    # the default floor, exit 3 is the drift code, exit 1 is reserved for a store-write
    # failure, not for "any FAIL" (which is what a reader of the bare pre-existing
    # sentence would have assumed monitor mode shares with the plain-audit path).
    assert "--monitor" in out
    assert "HIGH" in out
    assert "3" in out, "the monitor drift exit code (3) must be documented in --help"


def test_help_exit_code_paragraph_distinguishes_the_two_contracts():
    out = subprocess.run(
        [sys.executable, str(_REPO / "audit.py"), "--help"],
        cwd=_REPO, capture_output=True, text=True, timeout=30,
    ).stdout
    # Non-vacuity + placement: the monitor-specific text must live in the SAME
    # paragraph as --exit-code's own help, not merely appear somewhere in --help
    # (which --exit-code-scheme's neighbouring help could already have satisfied).
    idx = out.find("--exit-code ")
    assert idx != -1
    # argparse wraps; take a generous window forward to the next flag's own entry.
    window = out[idx:idx + 800]
    assert "monitor" in window.lower()
    assert "DIFFERENT" in window or "different" in window


# ─────────────────────────────────────────────────────── 3. the trifecta gloss

def _findings():
    return [Finding(id="A1", title="Lethal Trifecta", severity=CRITICAL, status=FAIL,
                     detail="d", fix="f", framework="x", evidence=["a", "b"])]


def test_card_glosses_the_trifecta_line():
    out = render_card(compute(_findings()), _findings())
    assert "Lethal Trifecta" in out
    # The gloss must be present, and near the ratio it explains, not just anywhere.
    tri_line_idx = next(i for i, ln in enumerate(out.splitlines()) if "Lethal Trifecta" in ln)
    lines = out.splitlines()
    nearby = "\n".join(lines[tri_line_idx:tri_line_idx + 2])
    assert "untrusted input" in nearby and "egress" in nearby


def test_card_gloss_does_not_break_the_box_art():
    """Non-regression for the box-width mechanics the gloss line was threaded into --
    every row (top/bottom borders + all body rows) must still share one width.
    """
    out = render_card(compute(_findings()), _findings(), ascii_only=True)
    rows = [ln for ln in out.splitlines() if ln.startswith(("|", "+"))]
    assert rows
    assert len({len(ln) for ln in rows}) == 1, f"ragged card rows: {out}"


def test_pdf_badge_glosses_the_trifecta_line():
    from clawseccheck.pdf import render_pdf

    findings = _findings()
    pdf_bytes = render_pdf(findings, compute(findings))
    text = shown_strings(pdf_bytes)
    assert "Lethal Trifecta" in text
    tri_line = next(ln for ln in text.splitlines() if "Lethal Trifecta" in ln)
    assert "untrusted input" in tri_line and "egress" in tri_line


def test_badge_svg_carries_no_trifecta_line_to_gloss():
    """Non-vacuity / scope check for the bug's own claim: the SVG badge (--badge
    grade.svg) never renders this line at all, so it correctly needed no change here --
    pin that fact so a future SVG change either stays silent on it or gets its own gloss.
    """
    from clawseccheck.report import render_svg

    svg = render_svg(compute(_findings()), _findings())
    assert "Trifecta" not in svg
