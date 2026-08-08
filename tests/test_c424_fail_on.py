"""Tests for CLAWSECCHECK-C-424: ``--fail-on SEVERITY`` + per-severity JSON/SARIF counters.

CI has no live agent, so a CI run can never carry a letter grade under the layered product
model — it needs a binary gate over FINDINGS, not the score. ``--exit-code`` already
thresholds on any unsuppressed FAIL; ``--fail-on`` adds a severity floor to that same idea
(at-or-above, inclusive). ``--fail-under`` (score-based) was deprecated in its favor and
then removed outright by C-426, once the five-layer rule meant an ordinary run carries no
score for it to threshold.

Findings are injected via a thin wrapper around the REAL ``audit()`` (real ``ctx``, real
collector-derived findings, real score) rather than a hand-built duck-typed context, so the
whole downstream pipeline (JSON/SARIF rendering, coverage, subject grouping) sees a genuine
run — only the one or two Finding objects under test are synthetic, exactly the "test
doubles" case report.py's own ``_subject_of`` docstring already accounts for.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import cli
from clawseccheck.catalog import Finding
from clawseccheck.cli import main
from clawseccheck.report import surfaced_despite_suppression
from clawseccheck.scoring import compute

# Captured once, before any test monkeypatches cli.audit — this IS the real audit().
_REAL_AUDIT = cli.audit

BASE = ["--no-native", "--no-history", "--ascii"]


def _make_finding(severity: str, *, status: str = "FAIL", id_: str = "TESTFAIL1",
                  suppressed: bool = False) -> Finding:
    return Finding(
        id=id_,
        title="Synthetic test finding (tests/test_c424_fail_on.py)",
        severity=severity,
        status=status,
        detail="injected by tests/test_c424_fail_on.py — not a real check result",
        fix="n/a — test fixture",
        framework="Test",
        suppressed=suppressed,
    )


def _audit_with_injected(monkeypatch, injected: list) -> None:
    """Patch cli.audit so the real audit() findings are extended with `injected` before the
    score is recomputed over the combined list. ctx and every real finding stay genuine;
    only the injected Finding objects are synthetic — isolates severity/suppression without
    faking the whole pipeline.
    """
    def _fake_audit(home, **kwargs):
        ctx, findings, _score = _REAL_AUDIT(home, **kwargs)
        findings = list(findings) + list(injected)
        score = compute(findings, ctx)
        return ctx, findings, score

    monkeypatch.setattr(cli, "audit", _fake_audit)


def _run(tmp_path: Path, monkeypatch, injected: list, extra_args: list,
         home_name: str = "home") -> int:
    home = tmp_path / home_name
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    _audit_with_injected(monkeypatch, injected)
    return main(["--home", str(home)] + BASE + extra_args)


# ---------------------------------------------------------------------------
# (a)/(b): basic --fail-on critical semantics
# ---------------------------------------------------------------------------

def test_fail_on_critical_worst_high_exits_zero(tmp_path, monkeypatch, capsys):
    rc = _run(tmp_path, monkeypatch, [_make_finding("HIGH")], ["--fail-on", "critical"])
    capsys.readouterr()
    assert rc == 0


def test_fail_on_critical_with_critical_exits_one(tmp_path, monkeypatch, capsys):
    rc = _run(tmp_path, monkeypatch, [_make_finding("CRITICAL")], ["--fail-on", "critical"])
    capsys.readouterr()
    assert rc == 1


# ---------------------------------------------------------------------------
# (c): at-or-above boundary matrix across every --fail-on level
# ---------------------------------------------------------------------------

def test_fail_on_high_trips_on_critical(tmp_path, monkeypatch, capsys):
    rc = _run(tmp_path, monkeypatch, [_make_finding("CRITICAL")], ["--fail-on", "high"])
    capsys.readouterr()
    assert rc == 1


def test_fail_on_high_does_not_trip_on_medium(tmp_path, monkeypatch, capsys):
    rc = _run(tmp_path, monkeypatch, [_make_finding("MEDIUM")], ["--fail-on", "high"])
    capsys.readouterr()
    assert rc == 0


def test_fail_on_medium_trips_on_high(tmp_path, monkeypatch, capsys):
    rc = _run(tmp_path, monkeypatch, [_make_finding("HIGH")], ["--fail-on", "medium"])
    capsys.readouterr()
    assert rc == 1


def test_fail_on_medium_does_not_trip_on_low(tmp_path, monkeypatch, capsys):
    rc = _run(tmp_path, monkeypatch, [_make_finding("LOW")], ["--fail-on", "medium"])
    capsys.readouterr()
    assert rc == 0


def test_fail_on_low_trips_on_low_itself(tmp_path, monkeypatch, capsys):
    """LOW is the floor — nothing ranks below it, so a LOW FAIL alone must still trip."""
    rc = _run(tmp_path, monkeypatch, [_make_finding("LOW")], ["--fail-on", "low"])
    capsys.readouterr()
    assert rc == 1


def test_fail_on_critical_warn_does_not_trip(tmp_path, monkeypatch, capsys):
    """--fail-on is FAIL-only, matching --exit-code's own FAIL-only contract — a WARN,
    however severe, must not redden the gate."""
    rc = _run(tmp_path, monkeypatch, [_make_finding("CRITICAL", status="WARN")],
              ["--fail-on", "critical"])
    capsys.readouterr()
    assert rc == 0


# ---------------------------------------------------------------------------
# (d): suppression semantics — identical predicate to --exit-code
# ---------------------------------------------------------------------------

def test_fail_on_suppressed_finding_does_not_trip(tmp_path, monkeypatch, capsys):
    injected = [_make_finding("MEDIUM", id_="TESTSUPPRESSEDMED", suppressed=True)]
    rc = _run(tmp_path, monkeypatch, injected, ["--fail-on", "medium"])
    capsys.readouterr()
    assert rc == 0


def test_fail_on_suppressed_critical_still_trips(tmp_path, monkeypatch, capsys):
    """A suppressed CRITICAL/HIGH FAIL still counts (surfaced_despite_suppression) — one
    .clawseccheckignore line must not be able to silently flip a CI gate green."""
    injected = [_make_finding("CRITICAL", id_="TESTSUPPRESSEDCRIT", suppressed=True)]
    rc = _run(tmp_path, monkeypatch, injected, ["--fail-on", "critical"])
    capsys.readouterr()
    assert rc == 1


# ---------------------------------------------------------------------------
# (e): --fail-under is gone; --fail-on is the sole score-free CI gate
# ---------------------------------------------------------------------------
#
# Three tests lived here pinning the supersedes-relationship between the two flags
# (--fail-on decides when both are given, and --fail-under still worked alone). C-426
# removed --fail-under outright -- the five-layer rule means an ordinary run carries no
# score for it to threshold -- so that relationship no longer exists to be pinned. What
# replaces them is the property that actually matters going forward: --fail-on decides
# on its own, in both directions, with no score anywhere in the decision.


def test_fail_under_no_longer_parses(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit) as exc:
        _run(tmp_path, monkeypatch, [], ["--fail-on", "critical", "--fail-under", "100"])
    assert exc.value.code != 0
    assert "unrecognized arguments" in capsys.readouterr().err


def test_fail_on_decides_in_both_directions_without_any_score(tmp_path, monkeypatch, capsys):
    """The contract the removed pair used to demonstrate, stated directly.

    A HIGH finding does not trip `--fail-on critical`; a CRITICAL one does. Neither
    outcome consults a score -- which is exactly why this gate survives the rule change
    that killed --fail-under.
    """
    rc_pass = _run(tmp_path, monkeypatch, [_make_finding("HIGH")], ["--fail-on", "critical"])
    out = capsys.readouterr().out
    assert rc_pass == 0
    assert "No grade yet" in out, "the run under test must genuinely carry no score"

    rc_trip = _run(tmp_path, monkeypatch, [_make_finding("CRITICAL")], ["--fail-on", "critical"])
    capsys.readouterr()
    assert rc_trip == 1


# ---------------------------------------------------------------------------
# (f): the cli.py fast-path "bare run" onboarding guard must learn --fail-on
# ---------------------------------------------------------------------------

def test_bare_run_without_fail_on_shows_onboarding(tmp_path, capsys):
    home = tmp_path / "empty_home_bare"
    home.mkdir()
    rc = main(["--home", str(home)] + BASE)
    out = capsys.readouterr().out
    assert rc == 0
    assert "is here, but it's empty" in out


def test_fail_on_alone_is_not_treated_as_bare_run(tmp_path, capsys):
    """The contract: --fail-on takes the AUDIT path, not the friendly onboarding screen.

    C-426 changed the exit code here, and the change is the point rather than a
    casualty. This home holds no openclaw.json, so the run read nothing — and a gate
    that reddens only on FAIL findings would stay GREEN on it, because a config the
    tool could not read produces UNKNOWN and WARN, never FAIL. `--exit-code` has
    tripped on exactly this since B-166/B-363; `--fail-on` now does too, or removing
    the score-based `--fail-under` (which caught it via CONFIG_BLIND_CAP) would have
    left the replacement gate weaker in precisely the "hide the evidence, get a green
    build" case B-363 exists to prevent.
    """
    home = tmp_path / "empty_home_fail_on"
    home.mkdir()
    rc = main(["--home", str(home)] + BASE + ["--fail-on", "critical"])
    out = capsys.readouterr().out
    assert "is here, but it's empty" not in out
    assert "OpenClaw Security Audit" in out
    assert rc == 1, "a CI gate went green on a run that read no config at all"


# ---------------------------------------------------------------------------
# (g): per-severity counters in --json and --sarif, agreeing with each other
# and with an independently-derived expectation over the same findings list.
# ---------------------------------------------------------------------------

def _expected_fail_counts_by_severity(findings) -> dict:
    """Independent oracle: same "unsuppressed" predicate cli.py's --exit-code/--fail-on
    use, reimplemented here (not calling report.finding_counts_by_severity) so the test
    does not just check the production helper against itself.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.status != "FAIL":
            continue
        if getattr(f, "suppressed", False) and not surfaced_despite_suppression(f):
            continue
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1
    return counts


def test_json_and_sarif_fail_counters_agree_and_are_correct(tmp_path, monkeypatch, capsys):
    injected = [
        _make_finding("CRITICAL", id_="TESTFAIL_CRIT1"),
        _make_finding("HIGH", id_="TESTFAIL_HIGH1"),
        _make_finding("HIGH", id_="TESTFAIL_HIGH2"),
        _make_finding("LOW", id_="TESTFAIL_LOW1"),
        # suppressed, non-sensitive MEDIUM -- must NOT be counted
        _make_finding("MEDIUM", id_="TESTFAIL_MED_SUPPRESSED", suppressed=True),
        # suppressed CRITICAL -- still counted (surfaced_despite_suppression)
        _make_finding("CRITICAL", id_="TESTFAIL_CRIT_SUPPRESSED", suppressed=True),
    ]
    home = tmp_path / "home_counters"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    _audit_with_injected(monkeypatch, injected)

    rc_json = main(["--home", str(home)] + BASE + ["--json"])
    json_out = capsys.readouterr().out
    assert rc_json == 0
    payload = json.loads(json_out)
    json_counts = payload["fail_counts_by_severity"]

    sarif_path = tmp_path / "counters.sarif"
    _audit_with_injected(monkeypatch, injected)  # re-arm: main() re-reads cli.audit each call
    rc_sarif = main(["--home", str(home)] + BASE + ["--sarif", str(sarif_path)])
    assert rc_sarif == 0
    sarif_payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    sarif_counts = (
        sarif_payload["runs"][0]["properties"]["analysisCompleteness"]["failCountsBySeverity"]
    )

    assert json_counts == sarif_counts

    # The two synthetic findings plus whatever the real (near-empty) config genuinely
    # FAILs on -- expect at least the injected contribution, and an exact match against
    # the independent oracle over the SAME combined findings list actually produced.
    _, all_findings, _ = _REAL_AUDIT(str(home), include_native=False, include_host=True,
                                     include_sockets=True, include_deptree=True)
    all_findings = list(all_findings) + injected
    expected = _expected_fail_counts_by_severity(all_findings)
    assert json_counts == expected
    assert json_counts["critical"] >= 2  # TESTFAIL_CRIT1 + surfaced-despite-suppression one
    assert json_counts["high"] >= 2
    assert json_counts["low"] >= 1
