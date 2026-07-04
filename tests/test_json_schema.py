"""CI drift-guard: `--json` output shape vs. `docs/OUTPUT_SCHEMA.md` (CLAWSECCHECK-C-136).

Mirrors the structural pattern of `test_schema_grounding.py` (which grounds config
*input* paths against a recon doc) but for JSON *output* shape: parse the documented
top-level envelope keys and per-finding keys straight out of `docs/OUTPUT_SCHEMA.md`'s
markdown tables, run a real audit, render real `--json` output through the actual CLI
path, and assert the two sets match exactly.

This is a drift *guard*, not a schema *definition* — `docs/OUTPUT_SCHEMA.md` remains the
single source of truth. If someone adds/removes a field in `report.py` without updating
the doc (or vice versa), this test fails with the exact key names involved.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from clawseccheck.cli import main

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DOC = ROOT / "docs" / "OUTPUT_SCHEMA.md"
FIXTURES = ROOT / "fixtures"
VULN = str(FIXTURES / "home_vuln")
BASE = ["--no-native", "--no-history"]

_TABLE_ROW = re.compile(r"^\|\s*`([A-Za-z_]+)`\s*\|")


def _rows_between(text: str, start_marker: str, end_marker: str) -> list[str]:
    """Return the raw lines of the table between two literal markers (exclusive)."""
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker, start)
    return text[start:end].splitlines()


def _parse_keys(lines: list[str]) -> set[str]:
    """Extract backticked field names from the first column of markdown table rows."""
    keys = set()
    for line in lines:
        m = _TABLE_ROW.match(line.strip())
        if m:
            keys.add(m.group(1))
    return keys


def _schema_text() -> str:
    if not SCHEMA_DOC.exists():
        pytest.skip(f"Schema doc not found at: {SCHEMA_DOC} (running in CI)")
    return SCHEMA_DOC.read_text(encoding="utf-8")


def _documented_top_level_keys() -> set[str]:
    """Parse the '### Top-level envelope' table in §1 of docs/OUTPUT_SCHEMA.md."""
    text = _schema_text()
    lines = _rows_between(text, "### Top-level envelope", "### Skeleton")
    return _parse_keys(lines)


def _documented_finding_keys() -> set[str]:
    """Parse the Finding Object table in §2 of docs/OUTPUT_SCHEMA.md (incl. blast_radius)."""
    text = _schema_text()
    lines = _rows_between(text, "## 2. Finding Object", "### `blast_radius` object")
    return _parse_keys(lines)


def _real_json_payload(capsys, home: str = VULN) -> dict:
    """Run a real audit through the actual `--json` CLI path (clawseccheck.cli.main)."""
    main(["--home", home] + BASE + ["--json"])
    return json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# Top-level envelope
# ---------------------------------------------------------------------------

def test_top_level_keys_match_schema_doc(capsys):
    """Real --json top-level key set must exactly match docs/OUTPUT_SCHEMA.md §1."""
    documented = _documented_top_level_keys()
    payload = _real_json_payload(capsys)
    emitted = set(payload.keys())

    undocumented = emitted - documented
    missing = documented - emitted

    assert not undocumented and not missing, (
        "--json top-level keys drifted from docs/OUTPUT_SCHEMA.md §1 "
        "(Top-level envelope):\n"
        + (f"  emitted but undocumented: {sorted(undocumented)}\n" if undocumented else "")
        + (f"  documented but not emitted: {sorted(missing)}\n" if missing else "")
        + f"\nUpdate {SCHEMA_DOC} or clawseccheck/report.py::render_json() to resync."
    )


def test_top_level_keys_present_on_safe_fixture_too(capsys):
    """The always-present top-level keys must also all appear on a clean fixture."""
    documented = _documented_top_level_keys()
    payload = _real_json_payload(capsys, home=str(FIXTURES / "home_safe"))
    emitted = set(payload.keys())

    missing = documented - emitted
    assert not missing, (
        f"--json (home_safe) is missing documented top-level keys: {sorted(missing)}\n"
        f"Every key in docs/OUTPUT_SCHEMA.md §1 is declared 'yes' (always present) or "
        f"has an explicit conditional note; home_safe should still emit all of them."
    )


# ---------------------------------------------------------------------------
# Per-finding object (FAIL exercises blast_radius; PASS/WARN exercises its absence)
# ---------------------------------------------------------------------------

def test_finding_keys_match_schema_doc_for_fail_finding(capsys):
    """A real FAIL finding's key set (blast_radius included) must match §2 exactly."""
    documented = _documented_finding_keys()
    payload = _real_json_payload(capsys)

    fail = next((f for f in payload["findings"] if f["status"] == "FAIL"), None)
    assert fail is not None, "fixture home_vuln produced no FAIL finding to exercise blast_radius"

    emitted = set(fail.keys())
    undocumented = emitted - documented
    missing = documented - emitted

    assert not undocumented and not missing, (
        f"FAIL finding {fail.get('id')!r} keys drifted from docs/OUTPUT_SCHEMA.md §2 "
        "(Finding Object):\n"
        + (f"  emitted but undocumented: {sorted(undocumented)}\n" if undocumented else "")
        + (f"  documented but not emitted: {sorted(missing)}\n" if missing else "")
        + f"\nUpdate {SCHEMA_DOC} or clawseccheck/report.py::_finding_to_dict()/render_json() "
        "to resync."
    )


def test_finding_keys_match_schema_doc_for_non_fail_finding(capsys):
    """A real PASS/WARN/UNKNOWN finding must match §2 minus blast_radius (FAIL-only key)."""
    documented = _documented_finding_keys()
    payload = _real_json_payload(capsys)

    non_fail = next((f for f in payload["findings"] if f["status"] != "FAIL"), None)
    assert non_fail is not None, "fixture home_vuln produced no non-FAIL finding to check"

    emitted = set(non_fail.keys())
    expected = documented - {"blast_radius"}
    undocumented = emitted - documented
    missing = expected - emitted

    assert not undocumented and not missing, (
        f"{non_fail.get('status')} finding {non_fail.get('id')!r} keys drifted from "
        "docs/OUTPUT_SCHEMA.md §2 (Finding Object):\n"
        + (f"  emitted but undocumented: {sorted(undocumented)}\n" if undocumented else "")
        + (f"  documented but not emitted: {sorted(missing)}\n" if missing else "")
        + f"\nUpdate {SCHEMA_DOC} or clawseccheck/report.py to resync."
    )
    assert "blast_radius" not in emitted, (
        f"{non_fail.get('status')} finding {non_fail.get('id')!r} unexpectedly carries "
        "'blast_radius' — documented as FAIL-only in docs/OUTPUT_SCHEMA.md §2."
    )


def test_blast_radius_key_appears_at_least_once(capsys):
    """Sanity: the FAIL-only blast_radius path is actually exercised on home_vuln."""
    payload = _real_json_payload(capsys)
    fails = [f for f in payload["findings"] if f["status"] == "FAIL"]
    assert fails, "no FAIL findings in home_vuln fixture"
    assert all("blast_radius" in f for f in fails), (
        "not every FAIL finding carries 'blast_radius' in real --json output"
    )
