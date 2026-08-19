"""B-585: the SARIF has to say whether the analysis was complete, not just how many
checks ran.

Measured on a home with **no OpenClaw config at all**, before this change::

    "analysisCompleteness": {
      "checksRun": 184, "checksTotal": 184, "failCount": 0,
      "limitations": ["host-posture checks require --host",
                      "attestation checks require --attest"]
    }

A field named *analysisCompleteness* reporting 184 of 184 checks run, zero failures, and
no limitation worth naming — for an audit that could not read a single byte of
configuration. `--json` on the same run carried `graded: false`, `missing_layers`,
`config_blind_capped: true`, `config_blind_reason: "absent"`; the dashboard card said it
out loud. Only the CI-facing surface was silent.

The counts were never wrong — 184 checks really did run. They answer a question about
CHECKS while the block's name promises one about the ANALYSIS, which since E-077 is the
five-layer ledger. So the layer figures are published beside them.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from clawseccheck.layers import LAYER_ORDER
from clawseccheck.sarif import _build_analysis_completeness, render_sarif

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"


def _run_sarif(tmp_path: Path, home: str, name: str = "out.sarif") -> dict:
    out = tmp_path / name
    subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", home, "--sarif", str(out),
         "--data-dir", str(tmp_path / "state"), "--no-history"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    return json.loads(out.read_text(encoding="utf-8"))["runs"][0]["properties"]


class _Score:
    """A ScoreResult stand-in carrying only the fields this block reads."""

    def __init__(self, *, graded=True, missing=(), not_checked=(),
                 blind_capped=False, blind_reason=None):
        self.graded = graded
        self.missing_layers = missing
        self.not_checked = not_checked
        self.config_blind_capped = blind_capped
        self.config_blind_reason = blind_reason


# ------------------------------------------------------------- the headline case

def test_a_home_with_no_config_no_longer_reads_as_a_complete_analysis(tmp_path):
    empty = tmp_path / "empty_home"
    empty.mkdir()
    ac = _run_sarif(tmp_path, str(empty))["analysisCompleteness"]

    # The counts stay exactly as they were — they were never the wrong number.
    assert ac["checksRun"] == ac["checksTotal"]
    # …and can no longer be mistaken for a complete analysis.
    assert ac["graded"] is False
    assert ac["layersRan"] < ac["layersTotal"] == len(LAYER_ORDER)
    assert ac["configBlind"] == {"capped": True, "reason": "absent"}
    assert any("absent" in line for line in ac["limitations"])


def test_the_absent_config_case_was_the_one_nothing_covered(tmp_path):
    """B-166 already surfaced a present-but-unparseable config in the sibling
    `analysis_completeness` block, so the SARIF was never blind to a BROKEN config — only
    to a wholly absent one (B-363). Both now answer through one field, and this pins that
    the older signal still works so the fix cannot be read as replacing it."""
    broken = tmp_path / "broken_home"
    broken.mkdir()
    (broken / "openclaw.json").write_text("{ not json", encoding="utf-8")
    props = _run_sarif(tmp_path, str(broken), "broken.sarif")
    assert props["analysis_completeness"]["config_parse_error"] is True     # B-166, intact
    assert props["analysisCompleteness"]["configBlind"]["reason"] == "unreadable"


def test_an_ordinary_ungraded_run_says_which_layers_are_missing(tmp_path):
    ac = _run_sarif(tmp_path, str(FIXTURES / "home_vuln"), "vuln.sarif")["analysisCompleteness"]
    assert ac["graded"] is False
    assert ac["missingLayers"], "an ungraded run must name what did not run"
    for entry in ac["missingLayers"]:
        assert set(entry) == {"layer", "status"}
        assert entry["layer"] in LAYER_ORDER
    assert ac["layersRan"] + len(ac["missingLayers"]) == ac["layersTotal"]


# --------------------------------------------------- what must NOT reach the artifact

def test_no_score_or_grade_is_ever_published_here(tmp_path):
    """The C-135 trap: `score`/`grade` are `null` on an ungraded run, and a consumer
    reading a `0` where `null` was meant would rank a blind audit as a perfect one — the
    leak C-423 closed in `render_json` and C-426 in `_percentile_line`. This block
    publishes the STATE, never a number the report withheld."""
    empty = tmp_path / "e2"
    empty.mkdir()
    ac = _run_sarif(tmp_path, str(empty), "e2.sarif")["analysisCompleteness"]
    assert "score" not in ac and "grade" not in ac
    assert "rawScore" not in ac and "raw_score" not in ac


def test_a_blind_config_still_produces_no_invented_fail(tmp_path):
    """The other C-135 trap: making `failCount` move by inventing a FAIL for an unreadable
    config would be a fabricated verdict (Golden Rule #4). The honest answer is UNKNOWN
    findings plus a stated limitation — which is what the gate now reads, not the count."""
    empty = tmp_path / "e3"
    empty.mkdir()
    ac = _run_sarif(tmp_path, str(empty), "e3.sarif")["analysisCompleteness"]
    assert ac["failCount"] == 0
    assert ac["unknownCount"] > 0


# ------------------------------------------------------------ the vet paths have none

def test_the_vet_paths_omit_the_layer_state_rather_than_claiming_ungraded():
    """Mode C produces no grade by construction, so `graded: false` there would imply a
    letter was withheld when none ever existed. `render_sarif` is called without a score
    on those paths; the keys are absent, and OUTPUT_SCHEMA §10 documents that absence."""
    sarif = json.loads(render_sarif([], None, "9.9.9"))
    ac = sarif["runs"][0]["properties"]["analysisCompleteness"]
    assert "checksRun" in ac                      # the block itself is still emitted
    for key in ("graded", "layersRan", "layersTotal", "missingLayers", "configBlind"):
        assert key not in ac, key


# ------------------------------------------------------------------ the graded branch

def test_a_complete_ledger_reports_a_complete_analysis():
    """Asserted at the unit level on purpose: no `--sarif` invocation can currently reach
    a graded run, because that mode does not honour `--full`/`--judged-bundle` — which is
    B-586, a separate open task. Pinning it here means the branch is correct the day that
    one lands, instead of shipping a field whose true case nothing ever exercised."""
    block = _build_analysis_completeness([], 184, 184, score=_Score(graded=True))
    assert block["graded"] is True
    assert block["missingLayers"] == []
    assert block["layersRan"] == block["layersTotal"] == len(LAYER_ORDER)
    assert not any("no grade" in line for line in block["limitations"])


def test_the_layer_arithmetic_cannot_drift_from_the_ledger():
    """`layersRan` is derived from `missing_layers` (every layer whose status is not
    `ran`), never counted a second way — a second count is how two figures start
    disagreeing about one fact."""
    block = _build_analysis_completeness(
        [], 184, 184,
        score=_Score(graded=False, missing=(("live_behaviour", "unavailable"),)),
    )
    assert block["layersRan"] == len(LAYER_ORDER) - 1
    assert block["missingLayers"] == [{"layer": "live_behaviour", "status": "unavailable"}]
    assert any("live_behaviour (unavailable)" in line for line in block["limitations"])


def test_not_checked_is_carried_separately_from_missing_layers():
    """They answer different questions (ScoreResult's own docstring): a layer that RAN but
    could not exhaust its subject, vs a layer that never ran. A run can have one without
    the other, so collapsing them would lose a fact."""
    block = _build_analysis_completeness(
        [], 184, 184,
        score=_Score(graded=True, not_checked=("55 log/transcript sink(s) not scanned",)),
    )
    assert block["missingLayers"] == []
    assert block["notChecked"] == ["55 log/transcript sink(s) not scanned"]
