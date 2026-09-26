"""B-758 (item #4): a `--full --json` document must not state two different answers about
which of the five layers ran.

`report.render_json` builds the top-level `graded`/`missing_layers`/`not_checked`/
`degraded_count` from the FINAL score -- the one `cli.py` gets only after re-projecting the
ledger through `full_pipeline.to_ledger(..., ctx=ctx)` -> `scoring.compute(...)` once the
installed-skill/plugin sweep (P6/P7) has actually run (B-723). `runState` (the same four
facts restated under `runState.graded`/`runState.missingLayers`/`runState.notChecked`/
`runState.degradedChecks`, B-623) used to be whatever `pipeline.run_adjudication` (P9) built
it as -- from the score the pipeline was CALLED with, which is the PRE-reprojection promise
`_resolve_runtime_caps` computed before P6/P7 ran. On a run where reprojection actually
changes the ledger -- a config-blind home whose `static` layer resolves to `unavailable`
only once the sweep can look, or any run where `installed_sweep` genuinely completes -- the
two blocks disagreed inside the SAME JSON document: one machine-readable fact, two answers.

`tests/test_b692_the_phase_keys_all_reach_the_output.py::test_the_frame_never_contradicts_the_payload_it_rides_in`
already asserts this same agreement, but drives `--full --fast --json`. Under `--fast`,
P6/P7/P8 never run at all, so the reprojection is a no-op and the pre- and post-reprojection
scores happen to be identical -- that test could not have caught this desync. These tests
drive plain `--full --json` (no `--fast`) so the sweep actually runs and the reprojection is
real, over three homes: config-blind (no config file at all), `fixtures/home_safe`, and
`fixtures/home_vuln`.

Offline, stdlib only, writes nothing outside tmp_path.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")

# runState's camelCase key <-> the top-level snake_case key stating the same fact -- mirrors
# _SAME_FACT_TWICE in test_b692_the_phase_keys_all_reach_the_output.py.
_SAME_FACT_TWICE = {
    "graded": "graded",
    "missingLayers": "missing_layers",
    "notChecked": "not_checked",
    "degradedChecks": "degraded_count",
}


def _blind_home(tmp_path: Path) -> str:
    home = tmp_path / "blind"
    home.mkdir()
    return str(home)  # no openclaw.json at all -- the config-blind case


def _full_json(home: str, data_dir: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", home, "--full", "--json",
         "--data-dir", str(data_dir), "--no-history", "--no-deptree", "--no-host"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    return json.loads(proc.stdout)


@pytest.mark.parametrize("home_name", ["blind", "safe", "vuln"])
def test_run_state_agrees_with_top_level_under_real_reprojection(tmp_path, home_name):
    """The DoD guard: same document, same answer, on the real (non-`--fast`) path."""
    home = {"blind": _blind_home(tmp_path), "safe": SAFE, "vuln": VULN}[home_name]
    payload = _full_json(home, tmp_path / "state")
    assert "runState" in payload, sorted(payload)
    for nested, top in _SAME_FACT_TWICE.items():
        assert payload["runState"][nested] == payload[top], (
            home_name, nested, top, payload["runState"].get(nested), payload.get(top))


def test_the_config_blind_home_actually_exercises_reprojection(tmp_path):
    """Non-vacuity for the `blind` case above: the config-blind home really does make the
    static layer unreadable, so this is not a green check against a payload where nothing
    reprojected. Without this, the parametrized test could pass on a home that never
    triggered the desync in the first place."""
    payload = _full_json(_blind_home(tmp_path), tmp_path / "state")
    assert payload["graded"] is False, payload.get("graded")
    layers = {entry["layer"] for entry in payload["missing_layers"]}
    assert "static" in layers, payload["missing_layers"]
