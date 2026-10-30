"""C-738: the --vet dossier footer counts findings, not PASS rows."""
from __future__ import annotations

import re

from clawseccheck.catalog import FAIL, PASS, WARN, Finding
from clawseccheck.dossier import build_profile
from clawseccheck.report import render_vet_dossier

_FOOTER = re.compile(r"(\d+) findings? across (\d+) axes")


def _footer(findings, ascii_only=False):
    out = render_vet_dossier(build_profile(findings, "x", "skill"), ascii_only=ascii_only)
    m = _FOOTER.search(out)
    assert m, out
    return int(m.group(1)), int(m.group(2))


def test_all_pass_dossier_reports_zero_findings():
    f = Finding("B13", "t", "LOW", PASS, "ok", "", "fw")
    for ascii_only in (False, True):
        assert _footer([f], ascii_only)[0] == 0


def test_fail_and_warn_rows_are_counted_pass_rows_are_not():
    fs = [
        Finding("B13", "t", "CRITICAL", FAIL, "bad", "fix", "fw"),
        Finding("B14", "t", "LOW", WARN, "meh", "fix", "fw"),
        Finding("B15", "t", "LOW", PASS, "ok", "", "fw"),
    ]
    for ascii_only in (False, True):
        assert _footer(fs, ascii_only)[0] == 2
