"""B-630: --advise must explain the verdict with the findings that caused it.

`render_advise` prints, on the one surface whose whole job is the install decision:

    How I decided: the verdict is the worst signal found across all checks. What drove it:

and then lists `_advise_reasons`. Three things stopped that heading being true, and the
first is the one that matters:

* the sort key carried **no severity** — `(status_is_fail, f.id)`, so within FAIL the order
  was lexicographic on the id STRING. `"B103" < "B13"`, so a HIGH sorted ahead of a
  CRITICAL and pushed it out of the five-line window. Measured on a plugin bundling five
  skills: five HIGH lines under that heading and the CRITICAL that set the verdict absent.
* the cut was **silent** — five lines read as the whole story;
* the docstring claimed **"deduplicated by id"**, which the body never did.

`_SEV_ORDER` was already defined in `report.py` and used by eight other sorts in the same
module. This one had simply been written without it — the same shape as `cli.py:783`
disclosing its evidence cut while two sibling sites do not (B-629).

The dedup claim was removed rather than implemented; `test_ids_repeat_on_purpose_and_are_
not_collapsed` pins why.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, WARN, Finding
from clawseccheck.report import _advise_reasons

_REPO = Path(__file__).resolve().parent.parent
_FIXTURES = _REPO / "fixtures"


def _f(fid: str, severity: str, status: str, detail: str = "detail") -> Finding:
    return Finding(fid, "t", severity, status, detail, "fix", "Skill Trust", False, [])


def _profile(*findings) -> SimpleNamespace:
    return SimpleNamespace(findings=list(findings))


def test_a_critical_outranks_a_lexicographically_earlier_high():
    """The defect, at its smallest. `"B103" < "B13"` is why the old key got this wrong."""
    reasons, omitted = _advise_reasons(
        _profile(_f("B103", HIGH, FAIL), _f("B13", CRITICAL, FAIL)), limit=1
    )
    assert reasons[0].startswith("B13 "), reasons
    assert omitted == 1, omitted


def test_severity_orders_the_whole_window_not_just_the_first_slot():
    """Non-vacuity for the test above: a key that special-cased one id would pass it."""
    reasons, _ = _advise_reasons(
        _profile(
            _f("B900", LOW, FAIL), _f("B103", HIGH, FAIL),
            _f("B13", CRITICAL, FAIL), _f("B500", MEDIUM, FAIL),
        )
    )
    assert [r.split(" ", 1)[0] for r in reasons] == ["B13", "B103", "B500", "B900"], reasons


def test_fail_still_outranks_warn_regardless_of_severity():
    """The pre-existing ordering that must survive: status is the verdict-bearing
    dimension, so a MEDIUM FAIL still comes before a CRITICAL WARN. Pinned because adding
    severity to the key could easily have been written as severity-first."""
    reasons, _ = _advise_reasons(_profile(_f("B900", CRITICAL, WARN), _f("B500", MEDIUM, FAIL)))
    assert [r.split(" ", 1)[0] for r in reasons] == ["B500", "B900"], reasons


def test_ids_repeat_on_purpose_and_are_not_collapsed():
    """The docstring's old "deduplicated by id" claim was removed, not implemented.

    On the plugin path, N lines sharing an id are N DIFFERENT bundled skills, each named
    in its own detail. Dedup by id would delete exactly what tells the reader which one to
    open — making the docstring true by making the output worse. Pinned so a later reader
    who spots the repetition does not "fix" it.
    """
    reasons, _ = _advise_reasons(
        _profile(*[_f("B13", CRITICAL, FAIL, f"[bundled skill 'sk{i}'] payload") for i in range(4)])
    )
    assert len(reasons) == 4, reasons
    assert len({r for r in reasons}) == 4, reasons


def test_nothing_is_omitted_when_everything_fits():
    """Negative control. Without it every assertion above could pass on a build that
    always reports an overflow."""
    reasons, omitted = _advise_reasons(_profile(_f("B13", CRITICAL, FAIL)))
    assert len(reasons) == 1 and omitted == 0, (reasons, omitted)


def test_passing_findings_never_become_reasons():
    """The filter, pinned: a clean finding under a "what drove it" heading is a lie of a
    different kind."""
    reasons, omitted = _advise_reasons(_profile(_f("B1", LOW, PASS), _f("B2", LOW, WARN)))
    assert [r.split(" ", 1)[0] for r in reasons] == ["B2"], reasons
    assert omitted == 0


# --------------------------------------------------------------------------- #
# End to end: the disclosure has to reach both rendered surfaces.              #
# --------------------------------------------------------------------------- #
def _plugin(tmp_path: Path, n: int) -> Path:
    root = tmp_path / "plug"
    (root / "skills").mkdir(parents=True)
    for i in range(n):
        shutil.copytree(
            _FIXTURES / "bad_b13_fetch_to_exec" / "skills" / "bootstrap-helper",
            root / "skills" / f"sk{i}",
        )
    (root / "openclaw.plugin.json").write_text(
        json.dumps({"id": "many", "configSchema": {"type": "object"}, "skills": ["skills"]}),
        encoding="utf-8",
    )
    for p in root.rglob("*"):
        if p.is_file():
            os.chmod(p, 0o600)
    return root


def _advise(root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--advise", str(root), *extra],
        capture_output=True, text=True, cwd=str(_REPO),
    )


def test_the_text_render_says_how_many_it_did_not_show(tmp_path):
    out = _advise(_plugin(tmp_path, 8)).stdout
    block = out.split("Reasons:", 1)[1].split("\n\n", 1)[0]
    assert "more FAIL/WARN finding(s) not shown" in block, block
    # Non-vacuity: the window really is full, so the disclosure is about a real cut.
    assert block.count("  - ") >= 6, block


def test_the_json_carries_the_omitted_count_as_a_number(tmp_path):
    """A consumer cannot parse "(+6 more)" out of prose, and B-560's lesson says an
    absent key is indistinguishable from nothing-to-report — so the key is always present."""
    payload = json.loads(_advise(_plugin(tmp_path, 8), "--json").stdout)
    assert payload["reasons_omitted"] >= 1, payload["reasons_omitted"]
    assert len(payload["reasons"]) == 5, payload["reasons"]

    small = json.loads(_advise(_plugin(tmp_path / "small", 1), "--json").stdout)
    assert small["reasons_omitted"] == 0, small["reasons_omitted"]
