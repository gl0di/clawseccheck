"""B-601: seven more modes measured a verdict and left no trace.

B-598 fixed `--dashboard` because that was the one reproduced against a live agent. Surveying
the rest first turned up that it was one of **nine** `_mode` branches which run a full audit
and return before the shared tail where the only history write lived:

    <default> RECORDS · --full RECORDS · --dashboard (B-598)
    --percentile · --next · --risk-paths · --badge · --html · --sarif · --pdf   -> nothing

The decision this task existed to make, written down rather than inherited: **a run that
measured a verdict for this setup records it.** That is what `cli.py`'s own module docstring
("Writes local ~/.clawseccheck score history by default") and `docs/USAGE.md` ("the timeline
stays unbroken") have always claimed; the code simply did not do it. Modes that measure
nothing — `--menu`, `--purge`, `--verify-*`, the `--vet` family — are untouched, because the
principle is about verdicts, not about invocations.

Two things the survey corrected in the task's own reasoning, kept here because both are the
kind of plausible-but-false premise that survives review:

* `--percentile` does NOT rank against the local history. `percentile.py` uses a built-in
  reference CDF and reads no history at all, so the "record before or after" question the task
  agonised over had no mechanism behind it.
* Resolving the liveTest cap in these branches is required for the F-155 gate to have a signal
  — but it is **display-neutral**, because a standalone export can never be graded (the
  installed-skills sweep needs `--full --dashboard`), so there is no number for the cap to
  move. Verified byte-identical rather than argued.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")

_ATTEST = '{"schema": "clawseccheck-attest/1", "tools": ["read"], "network": "none"}'
_SEEDED = ('{"liveTest": {"seed": "s", "verdicts": [{"tool": "canary", "id": "canary",'
           ' "verdict": "RESISTANT"}]}}')
_UNSEEDED_VULN = ('{"liveTest": {"verdicts": [{"tool": "canary", "id": "canary",'
                  ' "verdict": "VULNERABLE"}]}}')

# Every mode that MEASURES a verdict. The artifact-writing ones need a destination, so the
# value is a factory taking tmp_path.
_MEASURING_MODES = {
    "percentile": lambda t: ["--percentile"],
    "next": lambda t: ["--next"],
    "risk_paths": lambda t: ["--risk-paths"],
    "badge": lambda t: ["--badge", str(t / "a.svg")],
    "html": lambda t: ["--html", str(t / "a.html")],
    "sarif": lambda t: ["--sarif", str(t / "a.sarif")],
    "pdf": lambda t: ["--pdf", str(t / "a.pdf")],
}


def _run(tmp_path: Path, *args: str, home: str = VULN, store: str = "state"):
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", home,
         "--data-dir", str(tmp_path / store), *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})


def _rows(tmp_path: Path, store: str = "state") -> list[dict]:
    p = tmp_path / store / "history.jsonl"
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _file(tmp_path: Path, name: str, body: str) -> str:
    dest = tmp_path / name
    dest.write_text(body, encoding="utf-8")
    return str(dest)


# ---------------------------------------------------------------- the principle

@pytest.mark.parametrize("mode", sorted(_MEASURING_MODES))
def test_a_mode_that_measures_a_verdict_records_one(tmp_path, mode):
    _run(tmp_path, *_MEASURING_MODES[mode](tmp_path))
    assert len(_rows(tmp_path)) == 1


@pytest.mark.parametrize("mode", sorted(_MEASURING_MODES))
def test_no_history_still_suppresses_it(tmp_path, mode):
    """Free if the branch routes through `_record_history_point`, which is why it exists —
    and the assertion that catches a branch that reached for `history_record` directly."""
    _run(tmp_path, *_MEASURING_MODES[mode](tmp_path), "--no-history")
    assert _rows(tmp_path) == []


@pytest.mark.parametrize("mode", sorted(_MEASURING_MODES))
def test_an_unseeded_vulnerable_verdict_is_never_persisted(tmp_path, mode):
    """The F-155 seed-gate, which is the reason these branches had to resolve the liveTest
    cap at all rather than passing `None` and hoping."""
    _run(tmp_path, *_MEASURING_MODES[mode](tmp_path),
         "--judged-bundle", _file(tmp_path, "v.json", _UNSEEDED_VULN), home=SAFE)
    assert _rows(tmp_path) == []


def test_a_mode_that_measures_nothing_records_nothing(tmp_path):
    """The other half of the principle, and the one that keeps it from becoming "every
    invocation records". `--menu` renders a pre-scan screen; it audits nothing."""
    _run(tmp_path, "--menu")
    assert _rows(tmp_path) == []


# ------------------------------------------------------------- one run, one line

def test_a_side_output_riding_the_dashboard_records_once(tmp_path):
    """B-586 lets --badge/--html/--sarif/--pdf ride `--dashboard --full`, and that branch
    already records. Two write sites for one run would put the same verdict in the
    tamper-evident chain twice and make one audit look like two."""
    _run(tmp_path, "--dashboard", "--full",
         "--attest", _file(tmp_path, "a.json", _ATTEST),
         "--judged-bundle", _file(tmp_path, "b.json", _SEEDED),
         "--badge", str(tmp_path / "r.svg"), "--html", str(tmp_path / "r.html"),
         "--sarif", str(tmp_path / "r.sarif"), "--pdf", str(tmp_path / "r.pdf"),
         home=SAFE)
    assert len(_rows(tmp_path)) == 1


def test_a_failed_write_records_nothing(tmp_path):
    """Decided rather than inherited: a run that returns 1 because the artifact could not be
    written is one the user repeats, and two lines for one intended audit is a worse timeline
    than none."""
    unwritable = tmp_path / "nope"
    unwritable.mkdir()
    unwritable.chmod(0o500)
    try:
        proc = _run(tmp_path, "--badge", str(unwritable / "b.svg"))
        assert proc.returncode == 1, proc.stdout[:200]
        assert _rows(tmp_path) == []
    finally:
        unwritable.chmod(0o700)


# ------------------------------------------------- the premises the survey corrected

def test_percentile_does_not_rank_against_the_local_history():
    """The task reasoned about record-order because it assumed `--percentile` ranks against
    the recorded distribution. It does not — `percentile.py` carries a built-in reference CDF
    and reads no history — so there was never an ordering dependency to protect. Pinned so
    the false premise is not re-derived from the fixed code."""
    src = (REPO_ROOT / "clawseccheck" / "percentile.py").read_text(encoding="utf-8")
    assert "history" not in src.lower()
    assert "NOT telemetry" in src


def test_resolving_the_cap_does_not_change_a_standalone_artifact(tmp_path):
    """The widening these branches needed is display-neutral, because a standalone export is
    ungraded by construction: the installed-skills sweep only runs under `--dashboard --full`,
    so there is no number for the cap to move. Asserted rather than assumed."""
    plain, capped = tmp_path / "p.svg", tmp_path / "c.svg"
    _run(tmp_path, "--badge", str(plain), home=SAFE, store="s1")
    _run(tmp_path, "--badge", str(capped),
         "--judged-bundle", _file(tmp_path, "v.json", _UNSEEDED_VULN),
         home=SAFE, store="s2")
    assert plain.read_bytes() == capped.read_bytes()
    assert b"no grade yet" in plain.read_bytes(), "premise gone: a standalone badge is graded"
