"""CLAWSECCHECK-B-727 — B77 must not call a truncated read "all recorded config writes".

`checks/_shared._read_jsonl_tail` is bounded at 1 MB (`_JSONL_SCAN_CAP`) because these
journals reach GB (B-104). It returns `(text, truncated)`. B77 discarded the flag and then
emitted, on the no-evidence path:

    PASS — all {total} recorded config write(s) are clean and openclaw-originated.

On a journal over the cap both halves are false: `total` counts the tail window, not the
file, and "all" covers only what was read. A write from an unexpected process before the
window is reported as absent — a clean verdict over a partial read, on the subject of who
wrote your config.

The tests build the over-cap journal in `tmp_path` rather than committing a >1 MB fixture:
it keeps the repo small AND keeps this out of the finding-fingerprint manifest, which is
keyed on `fixtures/`.

Offline, writes only inside pytest's tmp_path.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from clawseccheck.catalog import PASS, UNKNOWN, WARN  # noqa: E402
from clawseccheck.checks import check_config_audit_log  # noqa: E402
from clawseccheck.checks._shared import _JSONL_SCAN_CAP  # noqa: E402
from clawseccheck.collector import Context  # noqa: E402

_CLEAN = {"event": "config.write", "argv": ["/usr/bin/openclaw", "config", "set"]}
_SUSPICIOUS = {"event": "config.write", "argv": ["/usr/bin/openclaw"], "suspicious": ["marker"]}


def _journal(home: Path, records: list) -> Path:
    logs = home / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    path = logs / "config-audit.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def _pad_to_over_cap(lead: list) -> list:
    """`lead` first, then enough clean records to push everything before them out of the
    1 MB tail window."""
    filler_bytes = len(json.dumps(_CLEAN)) + 1
    return lead + [_CLEAN] * (_JSONL_SCAN_CAP // filler_bytes + 200)


# ---------------------------------------------------------------- the defect

def test_an_over_cap_journal_is_not_reported_as_all_clean(tmp_path):
    """The whole bug in one assertion. The suspicious record sits BEFORE the tail window,
    so the check cannot see it — and must not say it looked at everything."""
    home = tmp_path / "home"
    path = _journal(home, _pad_to_over_cap([_SUSPICIOUS]))
    assert path.stat().st_size > _JSONL_SCAN_CAP, "fixture did not exceed the cap"

    f = check_config_audit_log(Context(home=home))
    assert f.id == "B77"
    assert f.status != PASS, (
        "a partial read may not produce a clean verdict — "
        f"got {f.status}: {f.detail}")
    assert "all " not in f.detail, f.detail


def test_the_over_cap_verdict_says_what_it_could_not_read(tmp_path):
    """Golden Rule #4: state cannot be determined, so the answer is UNKNOWN — and the
    reason has to reach the reader, not just the status."""
    home = tmp_path / "home"
    _journal(home, _pad_to_over_cap([_SUSPICIOUS]))
    f = check_config_audit_log(Context(home=home))
    assert f.status == UNKNOWN, f.detail
    assert "most recent" in f.detail.lower() or "not read" in f.detail.lower(), f.detail


def test_truncation_never_swallows_evidence_inside_the_window(tmp_path):
    """The fix must not overcorrect: a suspicious record the check DID read is a finding
    regardless of what lies beyond the window. Downgrading it to UNKNOWN would trade a
    lying PASS for a lost WARN."""
    home = tmp_path / "home"
    _journal(home, _pad_to_over_cap([]) + [_SUSPICIOUS])
    f = check_config_audit_log(Context(home=home))
    assert f.status == WARN, f.detail
    assert any("suspicious" in e for e in f.evidence), f.evidence


# ---------------------------------------------------------------- the control

def test_an_under_cap_clean_journal_is_unchanged(tmp_path):
    """No new caveat on the normal case. This is what keeps the fix from becoming a
    permanent disclaimer on every run — the wording here is the pre-fix wording."""
    home = tmp_path / "home"
    path = _journal(home, [_CLEAN, _CLEAN, _CLEAN])
    assert path.stat().st_size <= _JSONL_SCAN_CAP

    f = check_config_audit_log(Context(home=home))
    assert f.status == PASS, f.detail
    assert f.detail == "all 3 recorded config write(s) are clean and openclaw-originated."


def test_an_under_cap_suspicious_journal_is_unchanged(tmp_path):
    home = tmp_path / "home"
    _journal(home, [_CLEAN, _SUSPICIOUS])
    f = check_config_audit_log(Context(home=home))
    assert f.status == WARN, f.detail
    assert "most recent" not in f.detail.lower(), (
        "the truncation caveat fired on a file that was read in full: " + f.detail)
