"""F-165: coverage.subject_coverage / build_coverage_page / coverage_page_lines —
the "was everything looked at" page, distinct from build_inventory's "what did we
find" view. Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import coverage as cov
from clawseccheck import pipeline as pl
from clawseccheck.catalog import BY_ID, SUBJECT_OF, Finding
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_BUCKET_SUBJECTS = ("openclaw", "host", "agents", "channels", "logs")


def _finding(id_: str, status: str = "PASS") -> Finding:
    return Finding(id=id_, title="synthetic", severity="LOW", status=status,
                   detail="synthetic detail", fix="synthetic fix", framework="Test")


# ---------------------------------------------------------------------------
# subject_coverage
# ---------------------------------------------------------------------------

def test_subject_coverage_only_covers_the_five_bucket_subjects():
    """skills/mcp/plugins get PER-INSTANCE coverage elsewhere (build_coverage_page) —
    subject_coverage must not invent bucket entries for them."""
    result = cov.subject_coverage([])
    assert set(result) == set(_BUCKET_SUBJECTS)


def test_subject_coverage_empty_findings_reports_everything_not_scanned():
    result = cov.subject_coverage([])
    for subject in _BUCKET_SUBJECTS:
        entry = result[subject]
        assert entry["total"] > 0, f"{subject} should own at least one catalog check"
        assert entry["scanned"] == 0
        assert len(entry["not_scanned"]) == entry["total"]


def test_subject_coverage_scanned_plus_not_scanned_equals_total_on_real_findings():
    """Cross-checked against a real audit run, not hand-picked ids — every subject's
    arithmetic must hold regardless of which checks happened to fire this run."""
    ctx = collect(FIXTURES / "clean_full")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    result = cov.subject_coverage(findings)
    for subject in _BUCKET_SUBJECTS:
        entry = result[subject]
        assert entry["scanned"] + len(entry["not_scanned"]) == entry["total"]
        # every catalog id routed to this subject must be accounted for exactly once
        expected_total = sum(
            1 for cid, meta in BY_ID.items() if SUBJECT_OF.get(meta.surface) == subject
        )
        assert entry["total"] == expected_total


def test_subject_coverage_a_pass_finding_counts_as_scanned():
    # B50 is routed to "host" (network IDS) — pick any real catalog id on that subject.
    host_id = next(cid for cid, meta in BY_ID.items() if SUBJECT_OF.get(meta.surface) == "host")
    result = cov.subject_coverage([_finding(host_id, "PASS")])
    assert host_id not in result["host"]["not_scanned"]
    assert result["host"]["scanned"] == 1


def test_subject_coverage_an_unknown_finding_counts_as_not_scanned():
    host_id = next(cid for cid, meta in BY_ID.items() if SUBJECT_OF.get(meta.surface) == "host")
    result = cov.subject_coverage([_finding(host_id, "UNKNOWN")])
    assert host_id in result["host"]["not_scanned"]
    assert result["host"]["scanned"] == 0


# ---------------------------------------------------------------------------
# build_coverage_page — skills/plugins/mcp
# ---------------------------------------------------------------------------

class _FakeSweep:
    def __init__(self, *, no_roots=False, no_targets=False, counts=None, not_scanned=None):
        self.no_roots = no_roots
        self.no_targets = no_targets
        self._counts = counts or {"total": 0, "skipped": 0}
        self._not_scanned = not_scanned or []

    def counts(self):
        return self._counts

    def not_scanned(self):
        return self._not_scanned


def test_build_coverage_page_ctx_none_returns_empty_dict():
    assert cov.build_coverage_page(None, []) == {}


def test_build_coverage_page_no_sweep_reports_needs_full():
    ctx = collect(FIXTURES / "clean_full")
    page = cov.build_coverage_page(ctx, [], skill_sweep=None, plugin_sweep=None)
    for subject in ("skills", "plugins"):
        assert page[subject]["total"] is None
        assert page[subject]["scanned"] is None
        assert "--full" in page[subject]["note"]


def test_build_coverage_page_no_roots_reports_none_installed():
    ctx = collect(FIXTURES / "clean_full")
    sweep = _FakeSweep(no_roots=True)
    page = cov.build_coverage_page(ctx, [], skill_sweep=sweep)
    assert page["skills"] == {"total": 0, "scanned": 0, "not_scanned": [], "note": "none installed"}


def test_build_coverage_page_truncated_targets_count_as_not_scanned():
    """A target the sweep only PARTIALLY scanned must not be claimed fully covered —
    counts()['total'] already excludes SKIPPED but still includes TRUNCATED rows, so
    'scanned' must subtract not_scanned() (which names both) separately."""
    ctx = collect(FIXTURES / "clean_full")
    # 4 installed total: 1 skipped (budget), 1 truncated (partial), 2 clean.
    sweep = _FakeSweep(counts={"total": 3, "skipped": 1}, not_scanned=["skipped-one", "truncated-one"])
    page = cov.build_coverage_page(ctx, [], skill_sweep=sweep)
    assert page["skills"]["total"] == 4  # counts.total(3) + counts.skipped(1)
    assert page["skills"]["scanned"] == 2  # 4 - len(not_scanned)
    assert page["skills"]["not_scanned"] == ["skipped-one", "truncated-one"]


def test_build_coverage_page_mcp_none_configured():
    ctx = collect(FIXTURES / "clean_full")
    page = cov.build_coverage_page(ctx, [])
    assert page["mcp"]["total"] == 0
    assert page["mcp"]["note"] == "none configured"


def test_build_coverage_page_includes_all_eight_subjects():
    ctx = collect(FIXTURES / "clean_full")
    page = cov.build_coverage_page(ctx, [])
    assert set(page) == {"openclaw", "host", "agents", "skills", "mcp", "plugins",
                         "channels", "logs"}


# ---------------------------------------------------------------------------
# coverage_page_lines
# ---------------------------------------------------------------------------

def test_coverage_page_lines_empty_page_is_no_lines():
    assert cov.coverage_page_lines({}) == []


def test_coverage_page_lines_formats_scanned_of_total():
    page = {"openclaw": {"total": 10, "scanned": 7, "not_scanned": []}}
    # fill the rest so SUBJECT_ORDER iteration doesn't KeyError on .get (None-safe)
    lines = cov.coverage_page_lines(page)
    assert any("7 of 10 scanned" in line for line in lines)


def test_coverage_page_lines_names_gaps_not_just_a_count():
    page = {"host": {"total": 2, "scanned": 0, "not_scanned": ["B50", "B51"]}}
    lines = cov.coverage_page_lines(page)
    joined = "\n".join(lines)
    assert "B50" in joined and "B51" in joined


def test_coverage_page_lines_caps_named_gaps_with_a_plus_n_more_suffix():
    not_scanned = [f"B{i}" for i in range(12)]
    page = {"agents": {"total": 12, "scanned": 0, "not_scanned": not_scanned}}
    lines = cov.coverage_page_lines(page)
    joined = "\n".join(lines)
    assert "+4 more" in joined
    assert "B11" not in joined  # the 12th id falls past the 8-shown cap


def test_coverage_page_lines_zero_total_reads_as_positive_not_a_blank():
    page = {"mcp": {"total": 0, "scanned": 0, "not_scanned": [], "note": "none configured"}}
    lines = cov.coverage_page_lines(page)
    assert any("0 of 0" in line and "none configured" in line for line in lines)


def test_coverage_page_lines_never_swept_states_it_explicitly():
    page = {"skills": {"total": None, "scanned": None, "not_scanned": [],
                       "note": "not scanned this run (needs --full)"}}
    lines = cov.coverage_page_lines(page)
    assert any("not scanned this run" in line for line in lines)


# ---------------------------------------------------------------------------
# End-to-end: run_pipeline wiring
# ---------------------------------------------------------------------------

def test_run_pipeline_coverage_page_present_in_json():
    ctx = collect(FIXTURES / "clean_full")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, fast=True)
    doc = result.to_json()
    assert "coveragePage" in doc
    assert set(doc["coveragePage"]) == {"openclaw", "host", "agents", "skills", "mcp",
                                        "plugins", "channels", "logs"}


def test_render_sections_includes_coverage_banner():
    ctx = collect(FIXTURES / "clean_full")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, fast=True)
    lines = pl.render_sections(result)
    assert any("COVERAGE" in line for line in lines)


def test_run_pipeline_ctx_none_page_absent_from_sections():
    result = pl.PipelineResult()
    assert result.coverage_page == {}
    assert not any("COVERAGE" in line for line in pl.render_sections(result))
