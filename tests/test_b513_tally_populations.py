"""B-513 — no two counts in one report may read as contradicting each other.

Three items were filed as the B-506 remainder. Measured on the current build before
touching anything, two were already closed and one was live:

1. **Header tally vs body tally — closed by B-518.** The header counted
   `scored_findings` while the body counted every unsuppressed FAIL/WARN, so "2 FAIL,
   21 WARN" sat above "38 issue(s)". B-518 made the header count the exact list the body
   renders. Pinned below so it cannot drift back.
2. **Text/JSON parity — already correct.** The concern was that the text's pass/warn/fail
   figures were unlabelled as a subset. They are not: the line names its population
   ("over N *scored* checks") and states the exclusion ("UNKNOWN/advisory checks are
   excluded") in the same sentence. It renders only on a graded run, where it is true.
3. **C015 evidence truncation — was live, fixed here.** The detail stated the true count
   while the evidence list was sliced to 12 with no disclosure, so a home with 13 hits
   printed "13 home file(s)" over 12 rows. Every other capped evidence list in the engine
   already discloses its overflow; this one sat beside the convention without following
   it.

The task warned against the wrong fix for item 1 — a test that merely forces the two
numbers equal. They may legitimately differ; what may not happen is differing without
saying so. So the assertions below check the stated relationship, not equality for its
own sake.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, LOW, PASS, WARN, Finding
from clawseccheck.checks import check_secrets_at_rest_home
from clawseccheck.checks._config import _C015_MAX_EVIDENCE
from clawseccheck.collector import collect
from clawseccheck.report import render_report
from clawseccheck.scoring import compute

_TALLY = re.compile(r"^\((\d+) FAIL, (\d+) WARN\D+incl\.\s*(.+)\)$", re.M)
_BODY = re.compile(r"^(\d+) issue\(s\), grouped by subject", re.M)


def _f(fid, severity, status, *, scored=True):
    f = Finding(fid, f"check {fid}", severity, status, "detail", "fix", "framework")
    f.scored = scored
    return f


# ---- item 1: the two tallies describe the same population ----

def test_the_header_tally_and_the_body_count_agree():
    findings = [
        _f("A", CRITICAL, FAIL), _f("B", LOW, WARN),
        _f("C", LOW, WARN, scored=False), _f("D", LOW, WARN, scored=False),
        _f("E", LOW, PASS),
    ]
    out = render_report(findings, compute(findings), ascii_only=True, color=False)
    tally, body = _TALLY.search(out), _BODY.search(out)
    assert tally and body, out[:400]
    assert int(tally.group(1)) + int(tally.group(2)) == int(body.group(1))


def test_the_severity_breakdown_sums_to_the_headline():
    """The 'incl. …' clause must describe the same set the headline counts, or the reader
    has three numbers and no way to reconcile them."""
    findings = [_f("A", CRITICAL, FAIL), _f("B", LOW, WARN), _f("C", LOW, WARN, scored=False)]
    out = render_report(findings, compute(findings), ascii_only=True, color=False)
    tally = _TALLY.search(out)
    total = int(tally.group(1)) + int(tally.group(2))
    assert sum(int(n) for n in re.findall(r"(\d+) [A-Z]+", tally.group(3))) == total


# ---- item 2: the scored-subset line states its own population ----

def test_the_why_line_names_the_subset_it_counts():
    """It may legitimately count fewer findings than the body — it must say so."""
    findings = [_f("A", CRITICAL, FAIL), _f("B", LOW, WARN, scored=False)]
    out = render_report(findings, compute(findings), ascii_only=True, color=False)
    why = [ln for ln in out.splitlines() if ln.startswith("Why ")]
    assert why, "the graded run should carry a Why line"
    assert "scored" in why[0]
    assert "excluded" in why[0]


# ---- item 3: a capped evidence list discloses its overflow ----

def _home_with_secret_files(tmp_path: Path, n: int) -> Path:
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"gateway": {"bind": "127.0.0.1"}}), encoding="utf-8"
    )
    os.chmod(tmp_path / "openclaw.json", 0o600)
    # Assembled at runtime so no contiguous secret-shaped literal exists in this file.
    token = "sk-" + "a" * 40
    for i in range(n):
        f = tmp_path / f"cred{i}.json"
        f.write_text(json.dumps({"token": token}), encoding="utf-8")
        os.chmod(f, 0o600)
    return tmp_path


def test_c015_discloses_how_many_files_it_did_not_list(tmp_path):
    home = _home_with_secret_files(tmp_path, _C015_MAX_EVIDENCE + 6)
    f = check_secrets_at_rest_home(collect(str(home)))
    assert f.status == WARN, f.detail
    n_claimed = int(re.search(r"found in (\d+) home file\(s\)", f.detail).group(1))
    assert n_claimed > _C015_MAX_EVIDENCE
    assert f.evidence[-1] == f"(+{n_claimed - _C015_MAX_EVIDENCE} more file(s))"
    assert len(f.evidence) == _C015_MAX_EVIDENCE + 1


def test_c015_adds_no_overflow_row_when_nothing_is_hidden(tmp_path):
    """The disclosure must not appear when the list is complete — a '+0 more' would be
    its own small lie."""
    home = _home_with_secret_files(tmp_path, 3)
    f = check_secrets_at_rest_home(collect(str(home)))
    assert f.status == WARN, f.detail
    assert not any("more file(s)" in e for e in f.evidence)
    assert len(f.evidence) == 3


def test_c015_detail_and_evidence_cannot_disagree_silently(tmp_path):
    """The property the task actually asks for: the count and the list may differ, but
    never without the report saying by how much."""
    for n in (2, _C015_MAX_EVIDENCE, _C015_MAX_EVIDENCE + 1, _C015_MAX_EVIDENCE + 20):
        d = tmp_path / f"home{n}"
        d.mkdir()
        f = check_secrets_at_rest_home(collect(str(_home_with_secret_files(d, n))))
        claimed = int(re.search(r"found in (\d+) home file\(s\)", f.detail).group(1))
        rows = [e for e in f.evidence if "more file(s)" not in e]
        hidden = [e for e in f.evidence if "more file(s)" in e]
        accounted = len(rows) + (
            int(re.search(r"\+(\d+)", hidden[0]).group(1)) if hidden else 0
        )
        assert accounted == claimed, (n, f.detail, f.evidence)
