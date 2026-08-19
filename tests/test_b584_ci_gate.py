"""B-584: the documented CI recipe has to actually gate.

`docs/USAGE.md`'s "Gate my CI on this" row names `--sarif results.sarif` alongside
`--fail-on high` / `--exit-code`, and the canonical GitHub pattern is one step that writes
the SARIF *and* fails the job. Measured on `fixtures/home_vuln` (8 FAIL, 3 of them
CRITICAL) before this change::

    --exit-code                       rc 1     (gate fires)
    --sarif out.sarif --exit-code     rc 0     note: --exit-code has no effect with --sarif
    --sarif out.sarif --fail-on high  rc 0     note: --fail-on has no effect with --sarif

Same for `--html`, `--badge`, `--pdf`, `--dashboard`. The gate lived inline at the end of
`_main`, which every early-returning mode branch jumps over; `--json` and `--save` kept it
only because they are modifiers on the default report path rather than modes. A gate that
silently does not gate is worse than no gate — the user believes they have one — and in CI
a note on a green build's stderr is exactly where nobody looks.

The fix extracts `cli._findings_exit_gate` and routes the artifact-rendering modes through
it, the same move C-419 made for `--monitor`. This file pins both directions: the gate
fires where it must, and stays silent where it must.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.catalog import CRITICAL, FAIL, LOW, PASS, Finding
from clawseccheck.cli import _findings_exit_gate

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
VULN = str(FIXTURES / "home_vuln")
SAFE = str(FIXTURES / "home_safe")

# Every mode B-584 measured returning 0 on a 3-CRITICAL config. `--dashboard` takes no
# path argument, hence the None.
_ARTIFACT_MODES = [
    ("--sarif", "out.sarif"),
    ("--html", "out.html"),
    ("--badge", "out.svg"),
    ("--pdf", "out.pdf"),
    ("--dashboard", None),
]
_GATES = [["--exit-code"], ["--fail-on", "high"], ["--fail-on", "critical"]]


def _run(tmp_path: Path, home: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", home,
         "--data-dir", str(tmp_path / "state"), "--no-history", *args],
        cwd=REPO_ROOT, capture_output=True, text=True)


def _mode_args(tmp_path: Path, flag: str, name: str | None) -> list[str]:
    return [flag] if name is None else [flag, str(tmp_path / name)]


# ----------------------------------------------------------------- the gate must fire

@pytest.mark.parametrize("flag,name", _ARTIFACT_MODES)
@pytest.mark.parametrize("gate", _GATES)
def test_every_artifact_mode_gates_on_a_failing_config(tmp_path, flag, name, gate):
    proc = _run(tmp_path, VULN, *_mode_args(tmp_path, flag, name), *gate)
    assert proc.returncode == 1, f"{flag} {' '.join(gate)} did not gate: {proc.stderr[:200]}"


def test_the_documented_ci_recipe_verbatim(tmp_path):
    """`docs/USAGE.md`'s own line, run as written. The recipe IS the regression test."""
    out = tmp_path / "results.sarif"
    proc = _run(tmp_path, VULN, "--sarif", str(out), "--fail-on", "high")
    assert proc.returncode == 1
    assert out.exists() and out.stat().st_size > 0


def test_the_misleading_note_is_gone(tmp_path):
    """It was the only true thing in the old picture, and it must not survive as a lie in
    the other direction: the flag now HAS an effect, so claiming it does not would be the
    same defect rotated."""
    proc = _run(tmp_path, VULN, "--sarif", str(tmp_path / "o.sarif"), "--exit-code")
    assert "--exit-code has no effect" not in proc.stderr


def test_a_mode_that_genuinely_refuses_still_says_so(tmp_path):
    """The no-effect machinery is not what was broken and must keep working — otherwise
    this fix trades a silent non-gate for a silent non-disclosure."""
    proc = _run(tmp_path, VULN, "--sbom", "--exit-code")
    assert proc.returncode == 0
    assert "--exit-code has no effect with --sbom" in proc.stderr


# ------------------------------------------------------------- the gate must NOT fire

@pytest.mark.parametrize("flag,name", _ARTIFACT_MODES)
def test_a_clean_config_stays_green_and_still_writes_its_artifact(tmp_path, flag, name):
    proc = _run(tmp_path, SAFE, *_mode_args(tmp_path, flag, name), "--exit-code")
    assert proc.returncode == 0, proc.stderr[:200]
    if name is not None:
        assert (tmp_path / name).stat().st_size > 0


def test_the_artifact_is_written_on_a_gating_run(tmp_path):
    """Gate, not abort: a CI step that fails the build must still have the file to upload.
    Uploading a SARIF is usually the step AFTER the one that fails."""
    out = tmp_path / "g.sarif"
    proc = _run(tmp_path, VULN, "--sarif", str(out), "--fail-on", "critical")
    assert proc.returncode == 1
    assert out.stat().st_size > 0


# ------------------------------------------- a write failure must never read as a gate

def test_a_failed_write_still_exits_nonzero_on_a_clean_config(tmp_path):
    """`rc 1` now has two causes — gate tripped, artifact not written — and the dangerous
    confusion is only in one direction: a CI must never read a failed write as a passing
    gate. On a CLEAN config the gate would return 0, so this asserts the write failure
    still dominates."""
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        proc = _run(tmp_path, SAFE, "--sarif", str(ro / "x.sarif"), "--exit-code")
        assert proc.returncode == 1
        assert "could not write SARIF" in proc.stdout + proc.stderr
    finally:
        ro.chmod(0o700)


# ------------------------------------------------- parity with the default report path

def test_a_config_that_could_not_be_read_trips_the_gate_here_too(tmp_path):
    """B-166/B-363: an unreadable or absent config produces only UNKNOWN/WARN, so a
    FAIL-only gate would stay green on a run that audited nothing. The default path has
    tripped on that for two releases; the artifact modes now match it rather than offering
    a quieter version of the same flag. (This is also the CI-pointed-at-the-wrong---home
    case B-585 describes.)"""
    empty = tmp_path / "empty_home"
    empty.mkdir()
    baseline = _run(tmp_path, str(empty), "--exit-code")
    via_sarif = _run(tmp_path, str(empty), "--sarif", str(tmp_path / "e.sarif"), "--exit-code")
    assert baseline.returncode == 1
    assert via_sarif.returncode == baseline.returncode


def test_dashboard_full_is_not_weaker_than_full(tmp_path):
    """`--dashboard --full` runs the sweeps itself, so its gate is fed them too. Asserted
    as parity rather than on a contrived sweep-only fixture: the guarantee that matters is
    that one depth never answers differently from the other."""
    plain = _run(tmp_path, VULN, "--full", "--exit-code")
    dash = _run(tmp_path, VULN, "--dashboard", "--full", "--exit-code")
    assert plain.returncode == dash.returncode == 1


# --------------------------------------------------------- the helper's own contract

def _f(fid: str, status: str, severity: str) -> Finding:
    return Finding(id=fid, title=fid, severity=severity, status=status,
                   detail="d", fix="f", framework="x")


class _Args:
    def __init__(self, exit_code=False, fail_on=None):
        self.exit_code = exit_code
        self.fail_on = fail_on


class _Ctx:
    config_parse_error = False
    config_found = True


def test_extra_fail_joins_exit_code_but_never_fail_on():
    """The documented asymmetry, kept from the inline version: sweep/pipeline/vet-mcp
    results are bare booleans with no severity attached, and a severity-gated flag cannot
    rank what carries no severity. Pinned because collapsing the two would look like a
    tidy-up and would silently change what `--fail-on critical` means."""
    ctx = _Ctx()
    assert _findings_exit_gate(_Args(exit_code=True), [], ctx, extra_fail=True) == 1
    assert _findings_exit_gate(_Args(fail_on="critical"), [], ctx, extra_fail=True) == 0


def test_the_severity_threshold_is_respected():
    low_only = [_f("B1", FAIL, LOW), _f("B2", PASS, CRITICAL)]
    ctx = _Ctx()
    assert _findings_exit_gate(_Args(fail_on="critical"), low_only, ctx) == 0
    assert _findings_exit_gate(_Args(fail_on="low"), low_only, ctx) == 1
    # A bare --exit-code is FAIL-only and severity-blind — a LOW FAIL still trips it.
    assert _findings_exit_gate(_Args(exit_code=True), low_only, ctx) == 1


def test_no_gate_flag_means_no_gate():
    """Neither flag given must stay 0 whatever the findings say — `--fail-on`/`--exit-code`
    do not change the default exit code when omitted (docs/USAGE.md), and a mode branch
    now calling the gate unconditionally must not break that."""
    assert _findings_exit_gate(_Args(), [_f("B1", FAIL, CRITICAL)], _Ctx()) == 0
