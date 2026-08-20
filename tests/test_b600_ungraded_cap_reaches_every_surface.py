"""B-600: the HTML and the PDF dropped the cap entirely on an ungraded run.

C-423 established that a "capped from N" banner is noise when no N is printed, and both the
text report and the chat card kept the FACT anyway — `render_report`'s F-155/F-154 ungraded
paragraphs, `render_dashboard`'s card line. The HTML and the PDF took the first half of that
lesson and not the second:

    $ python3 -m clawseccheck --home fixtures/home_vuln --html /tmp/ung.html
    $ grep -i capped /tmp/ung.html
    .capped { margin-top: 0.35rem; color: #d9534f; font-size: 0.9rem; }

The CSS rule for the element, and never the element. 42 KB of report with no mention that
anything had capped the score — including, on the runs where it matters most, a submitted
VULNERABLE live-test verdict, which C-423 itself calls the most serious thing this tool can
report. Both are the copies that travel furthest from whoever ran them: the HTML is the
archivable one, the PDF is the one an agent attaches into a chat.

Each renderer's comment justified its skip by pointing at another renderer that "does the
same" — true of the banner, false of the paragraph underneath it. So this file asserts the
four surfaces AGAINST EACH OTHER rather than one at a time, because agreeing separately is
exactly what they were all doing while disagreeing.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import re
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from clawseccheck.catalog import CRITICAL, Finding
from clawseccheck.report import _UNGRADED_CAP_TAIL, render_html
from clawseccheck.scoring import compute

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")

_ATTEST = '{"schema": "clawseccheck-attest/1", "tools": ["read"], "network": "none"}'
_SEEDED = ('{"liveTest": {"seed": "s", "verdicts": [{"tool": "canary", "id": "canary",'
           ' "verdict": "RESISTANT"}]}}')
_VULN_LIVE = ('{"liveTest": {"seed": "s", "verdicts": [{"tool": "canary", "id": "canary",'
              ' "verdict": "VULNERABLE"}]}}')

# The em dash folds to "-" in the PDF: pdf.py ships base-14 fonts only (textnorm.asciify).
_TAIL_PDF = _UNGRADED_CAP_TAIL.replace("—", "-")


def _run(tmp_path: Path, *args: str, home: str = VULN):
    import os
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", home,
         "--data-dir", str(tmp_path / "state"), "--no-history", *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})


def _file(tmp_path: Path, name: str, body: str) -> str:
    dest = tmp_path / name
    dest.write_text(body, encoding="utf-8")
    return str(dest)


def _pdf_text(path: Path) -> list[str]:
    raw = path.read_bytes()
    out: list[str] = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        data = m.group(1)
        try:
            data = zlib.decompress(data)
        except Exception:
            pass
        for tj in re.finditer(rb"\((?:\\.|[^\\()])*\)\s*Tj", data):
            parts = re.findall(rb"\((?:\\.|[^\\()])*\)", tj.group(0))
            out.append(b"".join(p[1:-1] for p in parts).decode("latin-1"))
    return out


# ------------------------------------------------------------------ the headline case

def test_the_ungraded_html_names_the_cap(tmp_path):
    dest = tmp_path / "u.html"
    _run(tmp_path, "--html", str(dest))
    html = dest.read_text(encoding="utf-8")
    assert "open CRITICAL finding" in html
    assert _UNGRADED_CAP_TAIL in html


def test_the_ungraded_pdf_names_the_cap(tmp_path):
    """The PDF had the identical gap — and its own comment (B-531) describes the same
    over-correction, so finding one and not the other would have been half a fix."""
    dest = tmp_path / "u.pdf"
    _run(tmp_path, "--pdf", str(dest))
    assert any(_TAIL_PDF in ln for ln in _pdf_text(dest)), _pdf_text(dest)[:10]


def test_a_submitted_vulnerable_verdict_reaches_both(tmp_path):
    """The case C-423 was written for, and the one the silence cost most: the HTML and the
    PDF are the copies read long after the run."""
    html, pdf = tmp_path / "v.html", tmp_path / "v.pdf"
    bundle = _file(tmp_path, "v.json", _VULN_LIVE)
    # `--dashboard --full` is the shape that resolves the runtime caps at all; a STANDALONE
    # --html/--pdf returns before `_resolve_runtime_caps` and never sees the liveTest bucket
    # (the same B-379 family gap --percentile/--next were fixed for, still open for the side
    # outputs). Not this task's defect — but worth knowing that the composed shape is the
    # only one where this assertion is even reachable.
    # …and on home_safe, not home_vuln: `_cap_cascade` reports the signal that actually
    # BOUND the score, and on a config with an open CRITICAL the severity cap binds first,
    # so the live verdict is real but not the primary. home_safe is where it is observable.
    _run(tmp_path, "--dashboard", "--full", "--html", str(html),
         "--judged-bundle", bundle, home=SAFE)
    _run(tmp_path, "--dashboard", "--full", "--pdf", str(pdf),
         "--judged-bundle", bundle, home=SAFE)
    assert "VULNERABLE" in html.read_text(encoding="utf-8")
    assert any("VULNERABLE" in ln for ln in _pdf_text(pdf))


# ------------------------------------------------ the surfaces asserted against each other

def test_all_four_surfaces_agree_on_one_run(tmp_path):
    """Per-surface assertions are how these drifted: each renderer's comment cited another
    that "does the same", which was true of the banner and false of the fact."""
    html, pdf = tmp_path / "a.html", tmp_path / "a.pdf"
    card = _run(tmp_path, "--dashboard").stdout
    report = _run(tmp_path).stdout
    _run(tmp_path, "--html", str(html))
    _run(tmp_path, "--pdf", str(pdf))

    assert _UNGRADED_CAP_TAIL in card
    assert _UNGRADED_CAP_TAIL in html.read_text(encoding="utf-8")
    assert any(_TAIL_PDF in ln for ln in _pdf_text(pdf))
    # The text report's own severity-cap disclosure is the card's — it reaches this sentence
    # through the F-155/F-154/I-025 paragraphs, which need a submitted verdict. What it must
    # not do is contradict the other three by claiming the finding does not exist.
    assert "CRITICAL finding — it would have capped the grade; this run has none" not in report


def test_one_wording_no_fourth_copy():
    """B-593 put the sentence in one constant precisely so a renderer could not invent its
    own. Adding two more consumers is the moment that would break."""
    for rel in ("clawseccheck/report.py", "clawseccheck/pdf.py"):
        src = (REPO_ROOT / rel).read_text(encoding="utf-8")
        # Only lines that BUILD output can carry a copy; the constant's own definition and
        # the comments explaining it necessarily quote the sentence.
        emitting = [ln for ln in src.splitlines()
                    if ('f"' in ln or "f'" in ln) and "would have capped" in ln]
        assert not emitting, (rel, emitting)


# ------------------------------------------------------- what must NOT have changed

def test_the_graded_html_is_untouched(tmp_path):
    """This fix is scoped to the branch with no number. The graded banner was never wrong."""
    # home_vuln, not home_safe: a clean config earns a grade with nothing capping it, so
    # there is no banner to compare and the test would pass by vacuity.
    dest = tmp_path / "g.html"
    _run(tmp_path, "--dashboard", "--full",
         "--attest", _file(tmp_path, "a.json", _ATTEST),
         "--judged-bundle", _file(tmp_path, "b.json", _SEEDED),
         "--html", str(dest))
    html = dest.read_text(encoding="utf-8")
    assert re.search(r'class="capped"><strong>[^<]*</strong> from \d+ \(', html), \
        "the graded banner changed shape"
    assert _UNGRADED_CAP_TAIL not in html


def test_an_uncapped_run_gains_no_orphan_element(tmp_path):
    """A run that was not capped must not grow a paragraph claiming it would have been —
    the failure mode of "just always print it"."""
    findings = [Finding(id="B2", title="ok", severity=CRITICAL, status="PASS",
                        detail="d", fix="f", framework="x")]
    html = render_html(findings, compute(findings))
    assert 'class="capped"' not in html


class _Score:
    """A ScoreResult stand-in whose cap reason carries markup — the graded branch has always
    escaped it, and the branch added here must not be the one that forgets."""

    def __init__(self):
        self.score = None
        self.grade = None
        self.raw_score = 90
        self.capped = True
        self.graded = False
        self.missing_layers = (("live_behaviour", "unavailable"),)
        self.not_checked = ()
        self.config_blind_capped = False
        self.config_blind_reason = None
        self.runtime_capped = True
        self.runtime_cap_reason = "<script>alert(1)</script>"


def test_the_cap_reason_is_never_caller_supplied_text():
    """Safer than asserting we remembered `esc()`: the reason is mapped from a fixed
    vocabulary (`_runtime_cap_phrase` and friends), so markup arriving in a ScoreResult
    field cannot reach the page at all. `esc()` is still applied — belt and braces — but
    this pins the property that makes the branch safe by construction."""
    body = render_html([], _Score()).split('class="capped"', 1)[1].split("</p>", 1)[0]
    assert "<script>" not in body and "&lt;script&gt;" not in body, body
    assert "corroborated runtime signal" in body


@pytest.mark.parametrize("flag,name", [("--html", "x.html"), ("--pdf", "x.pdf")])
def test_the_artifact_is_still_written_and_the_run_still_succeeds(tmp_path, flag, name):
    dest = tmp_path / name
    proc = _run(tmp_path, flag, str(dest))
    assert proc.returncode == 0, proc.stderr[:300]
    assert dest.exists() and dest.stat().st_size > 0
