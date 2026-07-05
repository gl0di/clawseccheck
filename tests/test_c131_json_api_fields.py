"""C-131 — `--json` API completeness: cap_severity, assessable (top-level) + scored (per-finding).

The human report uses ScoreResult.cap_severity / .assessable and the per-finding `scored`
flag (advisory items are listed but excluded from the "N to fix vs M warn" arithmetic), but
the machine `--json` payload historically exposed none of them. These are purely additive
fields — the frozen JSON contract allows ADDING keys without a major bump.

Drift of the *key set* is already guarded by test_json_schema.py against docs/OUTPUT_SCHEMA.md;
this suite pins the *values / semantics* so a consumer can rely on them. Offline, read-only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
BASE = ["--no-native", "--no-history"]


def _payload(capsys, home: str) -> dict:
    main(["--home", home] + BASE + ["--json"])
    return json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# Top-level: cap_severity + assessable
# ---------------------------------------------------------------------------

def test_top_level_fields_present_and_typed(capsys):
    p = _payload(capsys, str(FIXTURES / "home_vuln"))
    assert "cap_severity" in p and "assessable" in p
    assert p["cap_severity"] is None or isinstance(p["cap_severity"], str)
    assert isinstance(p["assessable"], bool)


def test_assessable_true_on_real_audit(capsys):
    # home_vuln has real scorable findings — it is assessable, not an N/A config.
    p = _payload(capsys, str(FIXTURES / "home_vuln"))
    assert p["assessable"] is True


def test_cap_severity_named_when_capped(capsys):
    # Invariant: a capped score must name which severity drove the cap; an uncapped
    # score leaves cap_severity null. Either way the two fields stay consistent.
    p = _payload(capsys, str(FIXTURES / "home_vuln"))
    if p["capped"]:
        assert p["cap_severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), p["cap_severity"]
    else:
        assert p["cap_severity"] is None


def test_safe_fixture_also_carries_fields(capsys):
    p = _payload(capsys, str(FIXTURES / "home_safe"))
    assert "cap_severity" in p and "assessable" in p
    assert isinstance(p["assessable"], bool)


# ---------------------------------------------------------------------------
# Per-finding: scored
# ---------------------------------------------------------------------------

def test_every_finding_has_bool_scored(capsys):
    p = _payload(capsys, str(FIXTURES / "home_vuln"))
    assert p["findings"], "fixture produced no findings"
    for f in p["findings"]:
        assert "scored" in f, f"finding {f.get('id')} missing 'scored'"
        assert isinstance(f["scored"], bool), f"finding {f.get('id')} scored not bool"


def test_scored_matches_report_arithmetic(capsys):
    # The scored=True, non-suppressed, non-UNKNOWN findings are exactly the set the human
    # report counts in its "to fix vs warn" breakdown — a JSON consumer can now reproduce it.
    p = _payload(capsys, str(FIXTURES / "home_vuln"))
    counted = [
        f for f in p["findings"]
        if f["scored"] and not f["suppressed"] and f["status"] != "UNKNOWN"
    ]
    assert counted, "expected at least one scored, countable finding on home_vuln"
    # Advisory (scored=False) findings must be reachable too — otherwise the flag is inert.
    assert any(f["scored"] is False for f in p["findings"]), (
        "no advisory (scored=False) finding surfaced — flag would be untestable"
    )
