"""B-351: --full --save must write every section --full prints, not just the report
body.

cli.py's `body` (the report card) is assembled BEFORE the appended --full sections
(self-test, vet-mcp, skill sweep, and now the F-153 pipeline phases) are emitted, so
a naive `--save` that persisted only `body` silently dropped everything after it —
a user who saved a --full run got a file that disagreed with what they saw on
screen. The fix tees every _emit() call during the appended-sections block into
`_full_lines` and appends it to the saved content.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")
BASE = ["--no-native", "--no-history"]


def _strip_ansi(text: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_full_save_captures_every_appended_section(tmp_path, capsys):
    out = tmp_path / "report.txt"
    rc = main(["--home", VULN] + BASE + ["--full", "--save", str(out)])
    assert rc in (0, 1)
    saved = out.read_text(encoding="utf-8")
    for marker in ("CLAWSECCHECK SELF-TEST", "CLAWSECCHECK VET-MCP",
                  "CLAWSECCHECK SKILL SWEEP", "PLUGIN SWEEP", "BEHAVIORAL REPLAY",
                  "ADJUDICATION"):
        assert marker in saved, f"{marker!r} missing from the saved --full report"


def test_full_save_matches_stdout_modulo_ansi(tmp_path, capsys):
    out = tmp_path / "report.txt"
    rc = main(["--home", VULN] + BASE + ["--full", "--save", str(out)])
    assert rc in (0, 1)
    printed = _strip_ansi(capsys.readouterr().out)
    saved = out.read_text(encoding="utf-8")
    # Every saved line must have actually been printed — the save is a subset/tee of
    # stdout, never content invented for the file alone.
    for line in saved.splitlines():
        assert line in printed, f"saved line not found in stdout: {line!r}"


def test_full_quiet_save_also_captures_the_collapsed_sections(tmp_path, capsys):
    out = tmp_path / "report.txt"
    rc = main(["--home", VULN] + BASE + ["--full", "--quiet", "--save", str(out)])
    assert rc in (0, 1)
    saved = out.read_text(encoding="utf-8")
    assert "SELF-TEST:" in saved
    assert "VET-MCP:" in saved
    assert "SKILL SWEEP:" in saved


def test_plain_save_without_full_is_unaffected(tmp_path, capsys):
    """Regression guard: the tee only applies inside --full; a plain --save keeps
    saving exactly `body`, byte for byte, as it always did."""
    out = tmp_path / "report.txt"
    rc = main(["--home", VULN] + BASE + ["--save", str(out)])
    assert rc == 0
    saved = out.read_text(encoding="utf-8")
    assert "CLAWSECCHECK SELF-TEST" not in saved
    assert "PLUGIN SWEEP" not in saved
