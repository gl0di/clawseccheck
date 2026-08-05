"""C-361: the IOC dataset reports its own COVERAGE, not just its age.

Freshness was calibrated on the calendar alone. A dataset refreshed yesterday that
carries nothing for the ecosystem a user is exposed to is exactly as blind as a stale
one, and reported the same silence — while `vet_source`'s exact-match gate cannot
distinguish "checked against npm indicators and found nothing" from "carries no npm
indicators at all".

The load-bearing guard here is the last one: none of this may reach a `Finding`.
Offline, read-only, stdlib only.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import date
from pathlib import Path

from clawseccheck import iocdb
from clawseccheck.checks._vet import vet_source

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"


# ---------------------------------------------------------------------------
# coverage_notice — the shipped dataset's real state
# ---------------------------------------------------------------------------

def test_coverage_notice_names_every_ecosystem_with_no_records():
    """Every vocab ecosystem with an empty pool must be named. `any` is a wildcard
    matched against every pool, so it is never an empty pool and is excluded."""
    lines = iocdb.coverage_notice()
    assert lines, "the shipped dataset has empty ecosystems; the notice must not be silent"
    named = lines[0]
    for eco in iocdb._SOURCES_TYPE_VOCAB:
        if eco == iocdb._WILDCARD_SOURCE_TYPE:
            continue
        populated = any(r["type"] == eco for r in iocdb.SOURCES)
        if populated:
            assert f" {eco}" not in named, f"{eco} has records and must not be reported empty"
        else:
            assert eco in named, f"{eco} has no records and must be named"


def test_coverage_notice_mentions_an_entirely_empty_table():
    """PUBLISHERS ships empty today — a whole surface contributing no signal."""
    lines = iocdb.coverage_notice()
    assert any("publisher accounts" in ln for ln in lines)


def test_coverage_notice_says_a_clean_result_is_not_proof():
    joined = " ".join(iocdb.coverage_notice())
    assert "'nothing is known here'" in joined
    assert "not 'nothing bad exists'" in joined


def test_coverage_notice_declares_itself_offline():
    assert any("no network call" in ln for ln in iocdb.coverage_notice())


def test_coverage_notice_is_silent_when_every_ecosystem_is_populated(monkeypatch):
    """The notice must not become permanent furniture — a fully covered dataset says
    nothing, so the line keeps meaning something when it does appear."""
    full = tuple(
        {"value": f"x-{eco}", "type": eco, "first_seen": "2026-01-01",
         "source_url": "https://example.invalid/a", "source_name": "T", "note": "t"}
        for eco in iocdb._SOURCES_TYPE_VOCAB
    )
    monkeypatch.setattr(iocdb, "SOURCES", full)
    monkeypatch.setattr(iocdb, "PUBLISHERS", ({"value": "p"},))
    monkeypatch.setattr(iocdb, "HOSTS", ({"value": "h"},))
    assert iocdb.coverage_notice() == []


# ---------------------------------------------------------------------------
# determinism — coverage reads data, never the clock
# ---------------------------------------------------------------------------

def test_coverage_notice_reads_no_clock():
    """Unlike freshness_notice, this is a pure function of the shipped data. Pinned
    because a clock-derived advisory is what B-385 had to undo."""
    far_future = date(2099, 1, 1)
    before = iocdb.coverage_notice()
    assert iocdb.freshness_notice(today=far_future) != iocdb.freshness_notice(
        today=iocdb.revision_date()
    ), "sanity: freshness IS clock-dependent, so the contrast below is meaningful"
    assert iocdb.coverage_notice() == before


# ---------------------------------------------------------------------------
# THE INVARIANT: none of this may reach a Finding
# ---------------------------------------------------------------------------

def test_vet_source_finding_never_carries_the_coverage_notice():
    """B-385's rule, extended to the coverage half. Dataset metadata describes the
    SCANNER, not the audited subject; in a Finding it would drift the fingerprint
    manifest and orphan real users' .clawseccheckignore suppressions."""
    f = vet_source("clawhub:some-unknown-slug")
    blob = " ".join([f.detail or "", f.fix or ""] + list(f.evidence or []))
    for line in iocdb.coverage_notice():
        assert line not in blob
    assert "carries no indicators" not in blob


def test_coverage_notice_is_absent_from_json_output():
    """--json is a machine contract; advisory presentation metadata stays out of it."""
    out = subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--home", str(FIXTURES / "home_safe"),
         "--json"],
        capture_output=True, text=True, cwd=REPO, timeout=300,
    ).stdout
    assert "carries no indicators" not in out


# ---------------------------------------------------------------------------
# it actually reaches a normal audit now — the gap this task existed to close
# ---------------------------------------------------------------------------

def _run(*extra):
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--home", str(FIXTURES / "home_safe"),
         "--no-color", *extra],
        capture_output=True, text=True, cwd=REPO, timeout=300,
    ).stdout


def test_a_normal_audit_now_reports_dataset_coverage():
    """Before this, the dataset's age and coverage reached only --vet-source, so the
    overwhelmingly common path — auditing your own setup — was told nothing."""
    assert "carries no indicators" in _run()


def test_the_existing_opt_out_still_silences_it():
    assert "carries no indicators" not in _run("--no-freshness-notice")
