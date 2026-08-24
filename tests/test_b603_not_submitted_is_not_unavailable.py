"""B-603: a bucket that was never submitted was reported as "not available here".

Live run 2026-08-20, session `csc-b596-0820`: at seq 22 the agent ran `--self-test` and the
canary returned RESISTANT. At seq 24 the report told it

    No grade yet — 1 of 5 layers did not run: live behaviour test (not available here).

It had just run the test. `pipeline.py` mapped "no valid entry arrived in the `liveTest`
bucket" -- a fact about the INPUT -- onto `STATUS_UNAVAILABLE`, whose own definition is
"no live agent / nothing to ask, by construction" -- a claim about the ENVIRONMENT. The tool
cannot tell those apart and was asserting the stronger one. Same shape for a missing
`--attest` on the self-report layer.

Two harms: it is a determinate claim standing in for an unknown (Golden Rule #4), and it
turns a fixable gap into a dead end -- "not available" says there is nothing to do, while
"not submitted" names the input that produces a grade.

The fix is a new status rather than a reworded phrase, and the reason is
`test_a_genuine_unavailability_still_says_not_available` below: `STATUS_UNAVAILABLE` has a
third assignment site where it is *correct* (a build without the installed-plugin sweep), so
restating its wording globally would have made that case wrong instead.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from clawseccheck import pipeline
from clawseccheck.layers import (
    INCOMPLETE_LAYER_STATUSES,
    LAYER_STATUSES,
    STATUS_NOT_SUBMITTED,
    STATUS_PHRASE,
    STATUS_RAN,
    STATUS_UNAVAILABLE,
    describe_layer,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")


def _run(tmp_path: Path, *args: str, store: str = "state"):
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, "--no-history",
         "--data-dir", str(tmp_path / store), *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})


def _judged_only(tmp_path: Path) -> str:
    p = tmp_path / "judged.json"
    p.write_text('{"judged": {"verdicts": []}}', encoding="utf-8")
    return str(p)


# ----------------------------------------------- the report stops inventing a cause

def test_an_unsubmitted_live_test_is_not_called_unavailable(tmp_path):
    """The exact line the live agent was shown. It had run the canary; the report said the
    layer was not available here."""
    out = _run(tmp_path, "--dashboard", "--full",
               "--judged-bundle", _judged_only(tmp_path), store="s1").stdout
    line = [ln for ln in out.splitlines() if "did not run" in ln]
    assert line, out[:400]
    assert "live behaviour test (not submitted)" in line[0], line[0]
    assert "live behaviour test (not available here)" not in line[0], line[0]


def test_a_missing_attestation_is_not_called_unavailable(tmp_path):
    """Same defect, same branch, second layer -- `pipeline.py` had the identical shape for
    an absent `--attest`, so fixing only the live layer would have left half of it."""
    out = _run(tmp_path, "--dashboard", "--full", store="s2").stdout
    line = [ln for ln in out.splitlines() if "did not run" in ln]
    assert line, out[:400]
    assert "agent self-report (not submitted)" in line[0], line[0]
    assert "agent self-report (not available here)" not in line[0], line[0]


# --------------------------------- the genuine case is exactly what must NOT change

def test_a_genuine_unavailability_still_says_not_available(monkeypatch, tmp_path):
    """This is why a new status and not a reworded phrase. `STATUS_UNAVAILABLE` has a third
    assignment site where it is right: `resolve_plugin_sweep()` returning None means the
    sweep genuinely is not in this build. Restating the phrase globally would have fixed two
    lies by telling a third."""
    monkeypatch.setattr(pipeline, "resolve_plugin_sweep", lambda: None)
    result = pipeline.run_plugin_sweep(str(tmp_path))
    assert result.status == STATUS_UNAVAILABLE
    assert "not available in this build" in result.detail
    assert STATUS_PHRASE[STATUS_UNAVAILABLE] == "not available here"


# ------------------------------------------------ the grading invariant is untouched

def test_the_run_is_still_ungraded(tmp_path):
    """The layer-status DECISION was always correct; only its wording was wrong. Renaming a
    status must not turn a withheld grade into an awarded one."""
    proc = _run(tmp_path, "--json", "--full", "--judged-bundle", _judged_only(tmp_path),
                store="s3")
    payload = json.loads(proc.stdout)
    assert payload["graded"] is False
    assert payload["grade"] is None


def test_complete_still_means_all_five_ran():
    """`INCOMPLETE_LAYER_STATUSES` is derived, so a new status joins it automatically -- but
    that derivation is the invariant `complete` rests on, and a future edit could hardcode
    the set instead. Asserted rather than assumed."""
    assert STATUS_NOT_SUBMITTED in LAYER_STATUSES
    assert STATUS_NOT_SUBMITTED in INCOMPLETE_LAYER_STATUSES
    assert INCOMPLETE_LAYER_STATUSES == LAYER_STATUSES - {STATUS_RAN}


def test_the_new_status_is_ranked_in_the_badness_map():
    """The trap: `_worse_status` reads `_STATUS_BADNESS.get(status, 99)`, so an unranked
    status silently ranks WORSE THAN ERROR. Adding a sibling without a rank would have made
    a merged phase look like it had blown up."""
    assert STATUS_NOT_SUBMITTED in pipeline._STATUS_BADNESS
    assert (pipeline._STATUS_BADNESS[STATUS_NOT_SUBMITTED]
            < pipeline._STATUS_BADNESS[pipeline.STATUS_ERROR])


# --------------------------------------------------------- reader- and machine-facing

def test_the_phrase_names_the_input_not_the_environment():
    assert STATUS_PHRASE[STATUS_NOT_SUBMITTED] == "not submitted"
    assert describe_layer("live_behaviour", STATUS_NOT_SUBMITTED) == \
        "live behaviour test (not submitted)"


def test_the_json_surface_carries_the_new_status(tmp_path):
    """`missing_layers[].status` is a documented public field, so this is a schema-visible
    change and not only a wording one."""
    proc = _run(tmp_path, "--json", "--full", "--judged-bundle", _judged_only(tmp_path),
                store="s4")
    payload = json.loads(proc.stdout)
    statuses = {e["layer"]: e["status"] for e in payload["missing_layers"]}
    assert statuses.get("live_behaviour") == "not_submitted"
    assert statuses.get("self_report") == "not_submitted"


def test_the_output_schema_doc_names_it():
    """C-125. The doc must name the status this task added.

    The COUNT assertions that used to live here are gone, and their removal is the point.
    They hard-coded the number of not-ran statuses as a literal — first `"four"`, then
    `"five"` — so each correction of the prose had to be mirrored here by hand, and the
    second time it was not: the doc was corrected to `"six"` (the true
    `len(INCOMPLETE_LAYER_STATUSES)`) and this pin kept demanding `"five"`, which turned the
    whole suite red on an accurate document.

    `tests/test_doc_facts.py::test_not_ran_status_counts_match_the_ledger` now DERIVES that
    number from `layers.INCOMPLETE_LAYER_STATUSES` and checks every doc that states it, so
    the count has one owner and cannot drift again. Re-pinning it here would be a second
    hand-written copy of a fact the code already owns — which is the defect, not the fix.

    What stays is what B-603 actually owns: the status it introduced is documented."""
    flat = " ".join((REPO_ROOT / "docs" / "OUTPUT_SCHEMA.md").read_text(encoding="utf-8").split())
    assert "`not_submitted`" in flat
    assert "`unavailable`" in flat, (
        "the doc must keep naming the status not_submitted was split OUT of, or a reader "
        "cannot tell which case each one covers"
    )
