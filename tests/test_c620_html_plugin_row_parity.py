"""C-620 - the HTML report's Plugins row said "not scanned - run --full" on a run that
passed --full.

**The defect.** `--dashboard --full --html h.html` ran the plugin sweep (a `--full` phase)
and handed its result to the dashboard card and to the PDF, but
`_write_dashboard_side_outputs` had no `plugin_sweep` parameter, so the HTML rider was
rendered with `plugin_sweep=None`. `_subject_summary_rows` reads `None` as "no sweep ran"
and wrote `not scanned - run --full` / UNKNOWN. On a home with a flagged plugin that is a
FAIL supply-chain surface shown as a grey UNKNOWN, in the one file people keep and share;
the exit code was right (it reads the live sweep), so nothing else in the run gave it away.

**The fix** forwards the sweep to `render_html` on the `--full` call and only there. The
non-full dashboard, the standalone `--html` mode and `--full --fast` never ran a sweep, so
"not scanned" is true for them and the negative controls below pin that it stays.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import html as _html
import re
from pathlib import Path
from types import SimpleNamespace

from _pdftext import shown_strings
from clawseccheck import audit, cli
from clawseccheck.catalog import FAIL
from clawseccheck.checks._mcp import PluginSweep
from clawseccheck.cli import main
from test_f153_dashboard_full import _RISK_CFG, _sqlite_plugin_home

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE_HOME = FIXTURES / "home_safe"

# The row text is produced at runtime by report.py; spell the two non-ASCII glyphs as
# escapes so no literal above U+00FF lands in this file (publish one-byte constraint).
_DOT = "\u00b7"
_DASH = "\u2014"

_ROW_RE = re.compile(
    r'<td class="subj-name">Plugins</td><td class="subj-count">([^<]*)</td>'
    r'<td class="subj-status"><span[^>]*></span>([^<]*)</td>')

_BASE = ["--no-native", "--no-host", "--no-history", "--no-deptree"]


def _ascii(text: str) -> str:
    """pdf.py is ASCII-only: it draws the middle dot and the em dash as a hyphen."""
    return text.replace(_DOT, "-").replace(_DASH, "-")


def _plugins_row(html_text: str):
    m = _ROW_RE.search(html_text)
    assert m, "no Plugins inventory row in the HTML report"
    return _html.unescape(m.group(1)), _html.unescape(m.group(2))


def _run(tmp_path, home, *extra):
    h = tmp_path / "report.html"
    p = tmp_path / "report.pdf"
    argv = ["--home", str(home), *_BASE, "--data-dir", str(tmp_path / "state"),
            "--html", str(h), "--pdf", str(p), *extra]
    return main(argv), h, p


def _complete(tmp_path, capsys, home):
    """`--dashboard --full --html --pdf`; returns (html_text, pdf_text, stdout)."""
    rc, h, p = _run(tmp_path, home, "--dashboard", "--full")
    out = capsys.readouterr().out
    assert rc == 0
    return (h.read_text(encoding="utf-8"), shown_strings(p.read_bytes()), out)


# ---------------------------------------------------- the defect: --full must reach the row

def test_html_plugins_row_matches_pdf_when_no_plugin_index(tmp_path, capsys):
    html_text, pdf_text, out = _complete(tmp_path, capsys, SAFE_HOME)
    count, status = _plugins_row(html_text)
    assert count == "no plugin index found", count
    assert status == "UNKNOWN"
    assert "not scanned" not in count
    assert _ascii(count) in pdf_text
    assert "no plugin index found" in out


def test_html_plugins_row_carries_a_flagged_plugin(tmp_path, capsys):
    home = _sqlite_plugin_home(tmp_path, _RISK_CFG, plugin_bad=True)
    html_text, pdf_text, out = _complete(tmp_path, capsys, home)
    row = _plugins_row(html_text)
    # A literal, so a regression that is wrong in HTML and PDF alike cannot pass on parity.
    assert row == (f"1 flagged {_DOT} 1 installed", "FAIL"), row
    assert "not scanned" not in row[0]
    assert re.search(r"1 flagged - 1 installed\s+FAIL", pdf_text), pdf_text
    assert "1 flagged" in out


def test_html_plugins_row_carries_a_clean_plugin(tmp_path, capsys):
    home = _sqlite_plugin_home(tmp_path, _RISK_CFG, plugin_bad=False)
    html_text, pdf_text, _out = _complete(tmp_path, capsys, home)
    row = _plugins_row(html_text)
    assert row == (f"0 flagged {_DOT} 1 installed", "PASS"), row
    assert re.search(r"0 flagged - 1 installed\s+PASS", pdf_text), pdf_text


# ---------------------------------------------------- negative controls: still not scanned

def test_non_full_dashboard_html_still_says_not_scanned(tmp_path, capsys):
    """No `--full`, no sweep: "not scanned - run --full" is true and must survive."""
    rc, h, _p = _run(tmp_path, SAFE_HOME, "--dashboard")
    capsys.readouterr()
    assert rc == 0
    assert _plugins_row(h.read_text(encoding="utf-8")) == (
        f"not scanned {_DASH} run --full", "UNKNOWN")


def test_fast_full_dashboard_html_matches_pdf_not_scanned(tmp_path, capsys):
    """`--fast` drops the sweep phase, so the sweep is None: HTML and PDF agree."""
    home = _sqlite_plugin_home(tmp_path, _RISK_CFG, plugin_bad=True)
    rc, h, p = _run(tmp_path, home, "--dashboard", "--full", "--fast")
    capsys.readouterr()
    assert rc == 0
    count, status = _plugins_row(h.read_text(encoding="utf-8"))
    assert (count, status) == (f"not scanned {_DASH} run --full", "UNKNOWN")
    assert _ascii(count) in shown_strings(p.read_bytes())


def test_standalone_html_mode_is_unchanged(tmp_path, capsys):
    h = tmp_path / "solo.html"
    rc = main(["--home", str(SAFE_HOME), *_BASE, "--data-dir", str(tmp_path / "state"),
               "--html", str(h)])
    capsys.readouterr()
    assert rc == 0
    assert _plugins_row(h.read_text(encoding="utf-8")) == (
        f"not scanned {_DASH} run --full", "UNKNOWN")


# ---------------------------------------------------- the wiring, without a sweep

def _side_html(tmp_path, **kw) -> str:
    out = tmp_path / "side.html"
    args = SimpleNamespace(badge=None, html=str(out), sarif=None)
    ctx, findings, score = _audit_safe()
    cli._write_dashboard_side_outputs(
        args, findings, score, ctx, lambda v: Path(v), lambda s: None, **kw)
    return out.read_text(encoding="utf-8")


def _audit_safe():
    return audit(SAFE_HOME)


def test_write_dashboard_side_outputs_forwards_plugin_sweep(tmp_path):
    sweep = PluginSweep(home_dir=Path("/nonexistent"), checked_dirs=[Path("/plugins")],
                        rows=[("bad", FAIL, 2)])
    html_text = _side_html(tmp_path, plugin_sweep=sweep)
    assert _plugins_row(html_text) == (f"1 flagged {_DOT} 1 installed", "FAIL")
    assert "not scanned" not in _plugins_row(html_text)[0]


def test_write_dashboard_side_outputs_default_is_not_scanned(tmp_path):
    """Called without the kwarg (the non-full call site) the row stays "not scanned"."""
    assert _plugins_row(_side_html(tmp_path)) == (
        f"not scanned {_DASH} run --full", "UNKNOWN")


def test_a_hostile_plugin_name_never_reaches_the_row(tmp_path):
    """The row is counts and a fixed label only; a plugin name is never rendered here."""
    sweep = PluginSweep(home_dir=Path("/nonexistent"), checked_dirs=[Path("/plugins")],
                        rows=[("<img src=x>", FAIL, 1)])
    html_text = _side_html(tmp_path, plugin_sweep=sweep)
    assert _plugins_row(html_text) == (f"1 flagged {_DOT} 1 installed", "FAIL")
    assert "<img src=x>" not in html_text
