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

def test_subject_coverage_covers_every_check_owning_subject():
    """SUPERSEDES `..._only_covers_the_five_bucket_subjects` (B-565).

    The old pin said skills/mcp/plugins must get no bucket entry here, because they get
    a PER-INSTANCE count in `build_coverage_page` instead. The premise was wrong: an
    instance count answers "did we look at each installed thing", never "did every check
    about it resolve", and treating the two as alternatives put 68 of the catalog's ids
    (skills 55 + mcp 13) in neither tally on the page. `subject_coverage` now reports
    every subject the catalog routes; `build_coverage_page` decides where each one is
    rendered. The narrowing still exists, but as an explicit `subjects=` argument."""
    result = cov.subject_coverage([])
    expected = {SUBJECT_OF[s] for s in SUBJECT_OF}
    assert set(result) == expected
    assert {"skills", "mcp"} <= set(result)
    assert set(cov.subject_coverage([], subjects=_BUCKET_SUBJECTS)) == set(_BUCKET_SUBJECTS)


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
# not_scanned_reasons (C-566: "named with its reason", not just a bare id)
# ---------------------------------------------------------------------------

def test_not_scanned_reasons_covers_every_not_scanned_id():
    """Every id in `not_scanned` has a matching entry in `not_scanned_reasons` —
    the two lists must never drift apart."""
    result = cov.subject_coverage([])
    for subject, entry in result.items():
        assert set(entry["not_scanned_reasons"]) == set(entry["not_scanned"]), subject


def test_not_scanned_reason_is_the_findings_own_unknown_detail():
    """A check that DID fire (UNKNOWN) already explained itself in `detail`
    (docs/CHECK_AUTHORING.md's "UNKNOWN details name why" rule) — that real reason
    is reused, not replaced by a generic placeholder."""
    host_id = next(cid for cid, meta in BY_ID.items() if SUBJECT_OF.get(meta.surface) == "host")
    result = cov.subject_coverage([_finding(host_id, "UNKNOWN")])
    assert result["host"]["not_scanned_reasons"][host_id] == "synthetic detail"


def test_not_scanned_reason_names_absence_when_no_finding_exists_at_all():
    """A check that never fired this run (no Finding object whatsoever — e.g. an
    off-CHECKS behavioral detector that stayed inconclusive, B-558) has no
    producer-supplied reason to draw on: say so honestly rather than inventing one."""
    result = cov.subject_coverage([])
    host_id = next(cid for cid, meta in BY_ID.items() if SUBJECT_OF.get(meta.surface) == "host")
    assert result["host"]["not_scanned_reasons"][host_id] == "not evaluated this run"


def test_not_scanned_reason_is_sanitized_and_shortened():
    """A long, newline-bearing detail (the shape trajectory-sourced text can take,
    per behavioral.py's own `_sanitize` note on T1/T2/T3/B191) is folded to one
    plain-ASCII clause, never reproduced verbatim into a one-line list."""
    host_id = next(cid for cid, meta in BY_ID.items() if SUBJECT_OF.get(meta.surface) == "host")
    long_detail = ("first line of the reason\nsecond line, injected " + "x" * 80)
    findings = [Finding(id=host_id, title="t", severity="LOW", status="UNKNOWN",
                        detail=long_detail, fix="f", framework="Test")]
    result = cov.subject_coverage(findings)
    reason = result["host"]["not_scanned_reasons"][host_id]
    assert "\n" not in reason
    assert len(reason) <= 60
    assert reason.endswith("...")


def test_coverage_page_lines_renders_the_reason_in_parens():
    page = {"host": {"total": 1, "scanned": 0, "not_scanned": ["B50"],
                     "not_scanned_reasons": {"B50": "no network IDS configured"}}}
    lines = cov.coverage_page_lines(page)
    joined = "\n".join(lines)
    assert "B50 (no network IDS configured)" in joined


def test_coverage_page_lines_falls_back_to_bare_id_without_reasons():
    """Backward compatible: a page built without `not_scanned_reasons` (e.g. a
    hand-rolled dict, or the skills/plugins INSTANCE list) renders bare ids exactly
    as before this feature existed."""
    page = {"host": {"total": 2, "scanned": 0, "not_scanned": ["B50", "B51"]}}
    lines = cov.coverage_page_lines(page)
    joined = "\n".join(lines)
    assert "B50, B51" in joined
    assert "(" not in joined


def test_coverage_page_lines_show_reasons_false_omits_the_parens():
    """`show_reasons=False` (what `render_dashboard` passes under `--compact` —
    see its own C-566 comment) renders the exact same bare-id line a page with no
    `not_scanned_reasons` at all would, regardless of what the page dict carries."""
    page = {"host": {"total": 1, "scanned": 0, "not_scanned": ["B50"],
                     "not_scanned_reasons": {"B50": "no network IDS configured"}}}
    lines = cov.coverage_page_lines(page, show_reasons=False)
    joined = "\n".join(lines)
    assert "B50" in joined
    assert "no network IDS configured" not in joined
    assert "(" not in joined


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
    instance = {k: v for k, v in page["skills"].items() if k != "checks"}
    assert instance == {"total": 0, "scanned": 0, "not_scanned": [], "note": "none installed"}
    # B-565: "no skills installed" says nothing about the skill CHECKS, which still ran.
    # Asserting the whole dict used to be the point of this test; now it would silently
    # forbid the second tally, so the instance fields are compared exactly and the tally
    # is asserted present rather than dropped from the comparison and forgotten.
    assert page["skills"]["checks"]["total"] > 0


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
    # B-565: the unit is named. "7 of 10 scanned" was ambiguous on every row and actively
    # misleading on the three that count instances rather than checks.
    assert any("7 of 10 checks scanned" in line for line in lines)


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


# ---------------------------------------------------------------------------
# C-566 test-plan item 4: tie `coveragePage` totals to `phases[]`/`notScanned` —
# the two answer DIFFERENT questions and can legitimately diverge; this pins the
# real divergence an F-165 second-pass review found on fixtures/home_vuln rather
# than leaving it unreconciled and untested.
# ---------------------------------------------------------------------------

def test_coveragepage_logs_can_diverge_from_the_behavioral_phases_own_notscanned():
    """`phases[].behavioral.complete`/`notScanned` answers "did the behavioral PHASE
    run to conclusion" (yes, even when there was nothing to replay — an empty home
    is not a phase failure). `coveragePage.logs.not_scanned` answers a narrower
    question: "did each CATALOG check routed to `logs` reach a conclusive verdict
    THIS run" (T1/T2/T3/B191 only count as scanned via `evaluated_findings`, gated
    on `behavioral.analysis_is_conclusive` — see `build_coverage_page`'s B-558
    comment). "Nothing to replay" is conclusive for neither, so the phase can be
    `complete: true` with an empty `notScanned` while the SAME run's coverage page
    still lists those very check ids as not scanned. Pinned on fixtures/home_vuln,
    the exact fixture the divergence was first reproduced against — a hand-built
    minimal case would not prove the real pipeline still produces it.

    This is intentional, not a bug (same "still a gap" precedent docs/OUTPUT_SCHEMA.md
    already documents for a `not_applicable` UNKNOWN under the `openclaw` subject) —
    but until now nothing pinned it, so a future change that made either side silently
    "fix" the mismatch by UNDER-reporting (e.g. `logs` claiming full coverage on an
    empty home) would go unnoticed. Proven to have teeth by mutation: commenting out
    the `behavioral_is_conclusive(analysis)` gate in `pipeline.run_behavioral` (so an
    inconclusive replay's findings get merged as if scanned) makes this test's second
    assertion fail, since B191/T1/T2/T3 would then read as scanned.
    """
    from clawseccheck.checks import run_all
    ctx = collect(FIXTURES / "home_vuln")
    findings = run_all(ctx)
    result = pl.run_pipeline(ctx, findings, home_dir=ctx.home, fast=False)
    doc = result.to_json()

    behavioral_phase = next(p for p in doc["phases"] if p["name"] == "behavioral")
    assert behavioral_phase["status"] == "ran"
    assert behavioral_phase["complete"] is True
    assert behavioral_phase["notScanned"] == []

    logs_entry = doc["coveragePage"]["logs"]
    not_scanned = set(logs_entry["not_scanned"])
    # The off-CHECKS behavioral ids: not conclusive on this empty-of-trajectory
    # fixture, so `evaluated_findings` stayed empty and none of them reached the
    # coverage page's numerator — the divergence with the phase above.
    assert {"T1", "T2", "T3", "B191"} <= not_scanned
    # Each still carries an honest, non-fabricated reason (C-566 item 3) —
    # "not evaluated this run", since no Finding exists for any of them at all.
    reasons = logs_entry["not_scanned_reasons"]
    for cid in ("T1", "T2", "T3", "B191"):
        assert reasons[cid] == "not evaluated this run"


# ---------------------------------------------------------------------------
# End-to-end: the three renderers this page's DoD names (PDF / dashboard / HTML) —
# rejected three times over (2026-08-09, 08-11, 08-12, and again in the 2026-09-05
# sweep) for carrying the computation but never reaching these render paths. Each
# renderer gets both directions: the block appears when `coverage_page` is supplied,
# and every pre-existing caller (no `coverage_page` argument at all) is unaffected.
# ---------------------------------------------------------------------------

def _real_page():
    ctx = collect(FIXTURES / "clean_full")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    return ctx, findings, cov.build_coverage_page(ctx, findings)


def test_render_dashboard_includes_coverage_page_when_supplied():
    from clawseccheck.report import render_dashboard
    from clawseccheck.scoring import compute
    ctx, findings, page = _real_page()
    score = compute(findings, ctx)
    card = render_dashboard(findings, score, ctx=ctx, full=True, coverage_page=page)
    assert "Coverage page" in card
    assert "OpenClaw core" in card  # a real subject label, not just the heading


def test_render_dashboard_coverage_page_absent_by_default():
    """Every pre-existing caller passes no `coverage_page` — must stay byte-silent
    on this block, same as before this feature existed."""
    from clawseccheck.report import render_dashboard
    from clawseccheck.scoring import compute
    ctx, findings, _page = _real_page()
    score = compute(findings, ctx)
    card = render_dashboard(findings, score, ctx=ctx, full=True)
    assert "Coverage page" not in card


def test_render_html_includes_coverage_page_when_supplied():
    from clawseccheck.report import render_html
    from clawseccheck.scoring import compute
    ctx, findings, page = _real_page()
    score = compute(findings, ctx)
    html = render_html(findings, score, ctx=ctx, coverage_page=page)
    assert "Coverage page" in html
    assert "OpenClaw core" in html


def test_render_html_coverage_page_absent_by_default():
    from clawseccheck.report import render_html
    from clawseccheck.scoring import compute
    ctx, findings, _page = _real_page()
    score = compute(findings, ctx)
    html = render_html(findings, score, ctx=ctx)
    assert "Coverage page" not in html


def test_render_pdf_includes_coverage_page_when_supplied():
    from _pdftext import content_text
    from clawseccheck.pdf import render_pdf
    from clawseccheck.scoring import compute
    ctx, findings, page = _real_page()
    score = compute(findings, ctx)
    data = render_pdf(findings, score, ctx=ctx, coverage_page=page)
    text = content_text(data)
    assert "Coverage page" in text
    assert "OpenClaw core" in text


def test_render_pdf_coverage_page_absent_by_default():
    from _pdftext import content_text
    from clawseccheck.pdf import render_pdf
    from clawseccheck.scoring import compute
    ctx, findings, _page = _real_page()
    score = compute(findings, ctx)
    data = render_pdf(findings, score, ctx=ctx)
    text = content_text(data)
    assert "Coverage page" not in text
