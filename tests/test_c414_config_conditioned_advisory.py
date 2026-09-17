"""C-414 — config-conditioned advisory rows in `_KNOWN_ADVISORIES`.

`check_known_vulns` (B33) used to match purely on version: `parsed <= row[1]`. That
can only ever say "you're on a vulnerable version" — never "and your config shape
actually reaches the defect", which is a much more precise, less noisy verdict for
advisories whose real-world impact depends on how a feature is configured.

This adds an OPTIONAL 5th tuple element, `condition: Callable[[dict], bool]`, taking
`ctx.config` and returning whether this host's config can reach the defect. A plain
4-tuple (every row shipped before this task, and the vast majority of rows after it)
is untouched and matches on version alone, exactly as before.

**Every test here uses a SYNTHETIC advisory id/row, monkeypatched onto
`_lifecycle._KNOWN_ADVISORIES` for the duration of one test and never touching the
real table.** Per this task's own hard sequencing gate (checks/_lifecycle.py's own
in-source note, right above the table): a row may only ever be added for an
ALREADY-DISCLOSED, ALREADY-FIXED OpenClaw defect, in the mandatory order (private
disclosure -> fix ships -> real version boundary + advisory id exists -> row added).
Pinning a real, currently-undisclosed condition in this test suite would be exactly
the mistake that gate exists to prevent, so the machinery is proven here against a
row that names no real defect at all.

Offline, stdlib only, writes nothing.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import _lifecycle, check_known_vulns
from clawseccheck.collector import Context

_SYNTH_ID = "TEST-SYNTHETIC-C414-0001"
# Deliberately far in the future so it can never collide with, or be mistaken for, a
# real advisory boundary if this table were ever printed or diffed against the truth.
_SYNTH_MAX_VULN = (2099, 1, 1)
_SYNTH_FIXED = "2099.1.2"
_SYNTH_TITLE = "Synthetic test advisory — never a real OpenClaw defect"


def _ctx(cfg: dict, version: str = "2026.1.1") -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = {**cfg, "meta": {"lastTouchedVersion": version}}
    return c


def _flag_condition(cfg: dict) -> bool:
    return cfg.get("testFlag") is True


def _raising_condition(cfg: dict) -> bool:
    raise RuntimeError("synthetic condition blew up")


def _patch_table(monkeypatch, row: tuple):
    """Replace the real table with ONLY the one synthetic row for this test's duration."""
    monkeypatch.setattr(_lifecycle, "_KNOWN_ADVISORIES", [row])


# ─────────────────────────────────────────── existing 4-tuple rows: unchanged behavior

def test_version_only_row_still_matches_on_version_alone(monkeypatch):
    """A plain 4-tuple (no 5th element) is the shape every real row still has —
    matching must stay pure version comparison, exactly as before this task.
    """
    row = (_SYNTH_ID, _SYNTH_MAX_VULN, _SYNTH_FIXED, _SYNTH_TITLE)
    _patch_table(monkeypatch, row)
    r = check_known_vulns(_ctx({}))
    assert r.status == FAIL
    assert _SYNTH_ID in r.evidence


def test_version_only_row_passes_once_past_the_fix(monkeypatch):
    row = (_SYNTH_ID, _SYNTH_MAX_VULN, _SYNTH_FIXED, _SYNTH_TITLE)
    _patch_table(monkeypatch, row)
    r = check_known_vulns(_ctx({}, version="2099.1.2"))
    assert r.status == PASS


# ─────────────────────────────────────────────────────── 5-tuple config-conditioned rows

def test_config_conditioned_row_fails_when_version_and_condition_both_match(monkeypatch):
    row = (_SYNTH_ID, _SYNTH_MAX_VULN, _SYNTH_FIXED, _SYNTH_TITLE, _flag_condition)
    _patch_table(monkeypatch, row)
    r = check_known_vulns(_ctx({"testFlag": True}))
    assert r.status == FAIL
    assert _SYNTH_ID in r.evidence


def test_config_conditioned_row_passes_when_version_matches_but_condition_does_not(monkeypatch):
    """The precision this task exists for: a vulnerable VERSION whose config shape
    cannot reach the defect must not FAIL -- that would be the exact bare-version
    noise a config-conditioned row is meant to remove."""
    row = (_SYNTH_ID, _SYNTH_MAX_VULN, _SYNTH_FIXED, _SYNTH_TITLE, _flag_condition)
    _patch_table(monkeypatch, row)
    r = check_known_vulns(_ctx({"testFlag": False}))
    assert r.status == PASS
    assert _SYNTH_ID not in r.evidence


def test_config_conditioned_row_passes_when_condition_key_is_absent(monkeypatch):
    row = (_SYNTH_ID, _SYNTH_MAX_VULN, _SYNTH_FIXED, _SYNTH_TITLE, _flag_condition)
    _patch_table(monkeypatch, row)
    r = check_known_vulns(_ctx({}))
    assert r.status == PASS


def test_config_conditioned_row_passes_when_version_does_not_match_regardless_of_condition(monkeypatch):
    """Version is checked first (`parsed <= row[1]`) -- a host already past the fix
    must PASS even if the condition would have returned True."""
    row = (_SYNTH_ID, _SYNTH_MAX_VULN, _SYNTH_FIXED, _SYNTH_TITLE, _flag_condition)
    _patch_table(monkeypatch, row)
    r = check_known_vulns(_ctx({"testFlag": True}, version="2099.1.2"))
    assert r.status == PASS


# ───────────────────────────────────────── Golden Rule #5: a broken condition never FAILs

def test_raising_condition_does_not_fail_the_check(monkeypatch):
    """A condition that raises must degrade to 'did not hold', never crash the audit
    and never manufacture a FAIL from an errored predicate (Golden Rule #5)."""
    row = (_SYNTH_ID, _SYNTH_MAX_VULN, _SYNTH_FIXED, _SYNTH_TITLE, _raising_condition)
    _patch_table(monkeypatch, row)
    r = check_known_vulns(_ctx({}))
    assert r.status == PASS
    assert _SYNTH_ID not in r.evidence


# ───────────────────────────────────────────────────────── mixed table, both row shapes

def test_mixed_table_reports_only_the_row_whose_condition_holds(monkeypatch):
    """A version-only row and a config-conditioned row both matching on version, only
    one of them (condition True) actually firing -- proves `matched_ids`/
    `highest_fixed_ver`'s row[0]/row[2] indexing works correctly across MIXED tuple
    lengths in the same table, not just a single-shape table.
    """
    version_only = ("TEST-SYNTHETIC-C414-VERSIONONLY", (2099, 1, 1), "2099.1.2",
                     "Synthetic version-only row")
    conditioned = ("TEST-SYNTHETIC-C414-CONDITIONED", (2099, 1, 1), "2099.1.3",
                   "Synthetic conditioned row", _flag_condition)
    monkeypatch.setattr(_lifecycle, "_KNOWN_ADVISORIES", [version_only, conditioned])

    r = check_known_vulns(_ctx({"testFlag": False}))
    assert r.status == FAIL
    assert "TEST-SYNTHETIC-C414-VERSIONONLY" in r.evidence
    assert "TEST-SYNTHETIC-C414-CONDITIONED" not in r.evidence
    # The unconditioned row's fixed version is the only one that actually clears this
    # finding (the conditioned row never matched), so the fix must target IT, not the
    # conditioned row's (higher) fixed version.
    assert "2099.1.2" in r.fix
    assert "2099.1.3" not in r.fix


def test_mixed_table_both_rows_fire_together(monkeypatch):
    version_only = ("TEST-SYNTHETIC-C414-VERSIONONLY", (2099, 1, 1), "2099.1.2",
                     "Synthetic version-only row")
    conditioned = ("TEST-SYNTHETIC-C414-CONDITIONED", (2099, 1, 1), "2099.1.3",
                   "Synthetic conditioned row", _flag_condition)
    monkeypatch.setattr(_lifecycle, "_KNOWN_ADVISORIES", [version_only, conditioned])

    r = check_known_vulns(_ctx({"testFlag": True}))
    assert r.status == FAIL
    assert "TEST-SYNTHETIC-C414-VERSIONONLY" in r.evidence
    assert "TEST-SYNTHETIC-C414-CONDITIONED" in r.evidence
    # Both matched -> the HIGHER fixed version is the one that actually clears both.
    assert "2099.1.3" in r.fix


# ─────────────────────────────────────────────── the real table is untouched by this file

def test_real_advisory_table_rows_are_all_plain_4_tuples_today():
    """Documents the current state the disclosure gate protects: as of this commit,
    every REAL row in the table is version-only. This is expected to change only when
    a disclosed, fixed, config-conditioned advisory earns a row -- if it ever does,
    this test simply starts asserting a smaller number, not failing outright (it
    counts, it does not forbid)."""
    real_table = _lifecycle._KNOWN_ADVISORIES
    assert real_table, "the real advisory table must not be empty"
    conditioned = [row for row in real_table if len(row) >= 5]
    assert conditioned == [], (
        f"found {len(conditioned)} config-conditioned row(s) in the REAL table: "
        f"{[row[0] for row in conditioned]} -- if this is a deliberately, properly "
        "disclosed addition, update this test's expectation rather than treating the "
        "failure as a bug"
    )
