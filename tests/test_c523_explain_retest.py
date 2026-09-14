"""CLAWSECCHECK-C-523: --explain FINDING_ID / --retest FINDING_ID.

The task's own premise needed correcting before any of this could be implemented:
`catalog.BY_ID` maps a finding id to its `CheckMeta` (metadata only) — nothing anywhere
mapped an id to the CALLABLE that produces it, and building that by running every check
to see what id it emits would cost exactly what --retest exists to avoid paying.

`checks.CHECKS_BY_ID` closes that gap with a STATIC (never-executed) reader of each
check's own source: every one of the 190 functions in CHECKS passes its id as a plain
string literal to `_finding`/`_custom`/`_config_unreadable`/`_host_finding` (the four
`_shared.py`/`_host.py` helpers that construct or forward a Finding's id), with two
functions delegating to a same-module helper instead of calling one of those four
directly. Four real catalog ids — B191, T1, T2, T3 — are never in CHECKS at all
(behavioral.py's own docstring: they run only under --behavioral); --explain/--retest
give those, and RISK-* ids (a different engine, risk.py, never in the check catalog),
a distinct, accurate error rather than a bare "unknown id".

`--explain`/`--retest` always run a FRESH check against the CURRENT target (never a
saved/past run) via `build_context()` + the one resolved check function — never
`audit()`/`run_all()`, which is what makes --retest's "does not run the full audit"
requirement true and testable by call count, not just by reading output.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from clawseccheck import audit, build_context
from clawseccheck.catalog import BY_ID as CATALOG_BY_ID
from clawseccheck.checks import CHECKS, CHECKS_BY_ID, check_gateway, run_all
from clawseccheck.cli import (
    _run_single_check,
    _single_check_lookup,
    _split_table_row,
    _threat_coverage_note,
    main,
)
from clawseccheck.report import render_explain

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
VULN = str(FIXTURES / "home_vuln")

# The four real catalog ids that are never in CHECKS by design (behavioral.py's own
# detectors) — see checks/__init__.py's CHECKS_BY_ID docstring.
_BEHAVIORAL_ONLY_IDS = frozenset({"B191", "T1", "T2", "T3"})


# --------------------------------------------------------------------- CHECKS_BY_ID


def test_checks_by_id_covers_every_check_in_CHECKS():
    """One entry per function in CHECKS, no collisions, no drops."""
    assert len(CHECKS_BY_ID) == len(CHECKS)


def test_checks_by_id_matches_catalog_except_the_documented_behavioral_gap():
    assert set(CATALOG_BY_ID) - set(CHECKS_BY_ID) == _BEHAVIORAL_ONLY_IDS
    assert set(CHECKS_BY_ID) - set(CATALOG_BY_ID) == set()


def test_a_direct_finding_call_resolves_to_its_own_function():
    assert CHECKS_BY_ID["B2"] is check_gateway


@pytest.mark.parametrize("fid", ["B58", "B59", "B18"])
def test_delegation_wrapper_functions_resolve_correctly(fid):
    """check_unicode_obfuscation/check_markdown_image_exfil/check_subagents each
    delegate their verdict to a same-module helper rather than calling
    _finding/_custom directly — the recursion case _finding_ids_for exists for."""
    assert fid in CHECKS_BY_ID


@pytest.mark.parametrize("fid", ["B50", "B51", "B52", "B53", "B54"])
def test_host_finding_helper_ids_resolve(fid):
    """check_host_* functions use _host_finding(cid, cls, ctx), a fourth id-carrying
    call name distinct from _finding/_custom/_config_unreadable."""
    assert fid in CHECKS_BY_ID


def test_every_resolved_function_actually_produces_the_id_it_is_registered_under():
    """The static map is a claim about what a function WOULD produce; spot-check it
    against reality for a sample spanning every recognised call shape, on a fixture
    exercising both branches (home_vuln fires more FAIL/WARN paths than home_safe)."""
    ctx = build_context(VULN)
    sample = ["B2", "B1", "B58", "B59", "B18", "B50", "A1", "C5"]
    for fid in sample:
        f = CHECKS_BY_ID[fid](ctx)
        assert f.id == fid, f"CHECKS_BY_ID[{fid!r}] produced a Finding.id of {f.id!r}"


# --------------------------------------------------------------------- _single_check_lookup


def test_unknown_id_is_refused_with_a_specific_message():
    chk, err = _single_check_lookup("NOPE-123")
    assert chk is None
    assert "unknown finding id" in err
    assert "NOPE-123" in err


def test_risk_id_is_refused_with_a_reason_distinct_from_unknown():
    chk, err = _single_check_lookup("RISK-03")
    assert chk is None
    assert "combinational" in err
    assert "unknown finding id" not in err


def test_behavioral_only_id_is_refused_with_a_reason_distinct_from_unknown():
    chk, err = _single_check_lookup("T1")
    assert chk is None
    assert "not retestable this way" in err
    assert "unknown finding id" not in err


def test_valid_id_resolves():
    chk, err = _single_check_lookup("B2")
    assert err is None
    assert chk is check_gateway


def test_run_single_check_builds_a_matching_context_and_invokes_the_right_check():
    args = SimpleNamespace(home=VULN, no_host=True, no_sockets=True, no_deptree=True,
                           no_dist=True, exhaustive=False)
    f, err = _run_single_check("B2", args)
    assert err is None
    assert f.id == "B2"
    assert f.status == "FAIL"


def test_run_single_check_propagates_the_lookup_error_untouched():
    args = SimpleNamespace(home=VULN, no_host=True, no_sockets=True, no_deptree=True,
                           no_dist=True, exhaustive=False)
    f, err = _run_single_check("RISK-03", args)
    assert f is None
    assert "combinational" in err


# --------------------------------------------------------------------- build_context refactor


def test_build_context_plus_run_all_matches_audit_exactly():
    """audit() was refactored to call build_context() internally — this pins that the
    split is behavior-preserving: the SAME findings/score either way."""
    ctx1, findings1, score1 = audit(SAFE, include_host=True, include_sockets=True)
    ctx2 = build_context(SAFE, include_host=True, include_sockets=True)
    findings2 = run_all(ctx2)
    assert [(f.id, f.status, f.detail) for f in findings1] == \
           [(f.id, f.status, f.detail) for f in findings2]
    assert score1.score == __import__("clawseccheck").compute(findings2, ctx2).score


# --------------------------------------------------------------------- _threat_coverage_note


def test_every_catalog_id_resolves_a_coverage_note():
    """docs/THREAT_COVERAGE.md's own closure guard (test_threat_coverage_ledger.py)
    already requires every catalog id to appear in exactly one [CHECK: ...] tag — this
    pins that --explain's reader actually finds all of them, not just most."""
    missing = [fid for fid in CATALOG_BY_ID if _threat_coverage_note(fid) is None]
    assert not missing, f"no coverage note resolved for real catalog ids: {missing}"


def test_an_escaped_pipe_inside_a_cell_does_not_truncate_the_note():
    """The Installed-skill-malware row's own 'curl\\|sh' broke a naive str.split('|')."""
    note = _threat_coverage_note("B13")
    assert note is not None
    assert "curl|sh" in note
    assert "\\|" not in note


def test_a_backtick_wrapped_tag_leaves_no_stray_backticks():
    note = _threat_coverage_note("B2")
    assert note is not None
    assert "`" not in note
    assert "[CHECK" not in note


def test_a_terse_row_falls_back_to_its_category():
    """B10's Notes cell is JUST the tag ('| ... | B10 | `[CHECK: B10]` |') — stripping
    the tag alone would leave an empty string, which used to read as 'not covered'."""
    note = _threat_coverage_note("B10")
    assert note == "Audit log & sensitive redaction"


def test_unresolvable_id_returns_none_not_an_error():
    assert _threat_coverage_note("Z999999") is None


def test_missing_doc_file_returns_none_never_raises(tmp_path):
    assert _threat_coverage_note("B2", path=tmp_path / "nope.md") is None


def test_split_table_row_unescapes_a_literal_pipe():
    assert _split_table_row("a | b\\|c | d") == ["a ", " b|c ", " d"]


def test_a_row_carrying_two_separate_check_tags_resolves_both(tmp_path):
    """C-135: every real row today carries at most one [CHECK: ...] tag (ids are
    comma-joined inside it), but the id-detection used to be a single .search() —
    correct for that shape, but silently blind to an id tagged only in a SECOND tag on
    the same line. A future doc edit could introduce that shape without anyone noticing
    the reader stopped seeing it. Pinned against a synthetic file so this doesn't
    depend on the real doc ever actually looking like this."""
    doc = tmp_path / "THREAT_COVERAGE.md"
    doc.write_text(
        "| Category | B10, B11 | first tag `[CHECK: B10, B11]` second tag "
        "`[CHECK: B12]` |\n",
        encoding="utf-8",
    )
    assert _threat_coverage_note("B10", path=doc) is not None
    assert _threat_coverage_note("B12", path=doc) is not None


# --------------------------------------------------------------------- --explain CLI


def test_explain_prints_full_detail_and_nothing_else(capsys):
    rc = main(["--explain", "B2", "--home", VULN])
    out = capsys.readouterr().out
    assert rc == 0
    assert "B2" in out
    assert "FAIL" in out
    assert "why:" in out
    assert "fix:" in out
    assert "coverage note" in out
    # nothing ELSE — no grade header, no other finding id printed
    assert "Grade" not in out
    assert "\nB1 " not in out and not out.startswith("B1 ")


def test_explain_on_a_clean_target_shows_pass():
    rc, out = None, None
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["--explain", "B2", "--home", SAFE])
    out = buf.getvalue()
    assert rc == 0
    assert "status: PASS" in out


def test_explain_unknown_id_errors_clearly_not_silently(capsys):
    rc = main(["--explain", "NOPE-123", "--home", SAFE])
    err = capsys.readouterr().err
    assert rc == 2
    assert "unknown finding id" in err
    assert "NOPE-123" in err


def test_explain_risk_id_errors_with_its_own_reason(capsys):
    rc = main(["--explain", "RISK-03", "--home", SAFE])
    err = capsys.readouterr().err
    assert rc == 2
    assert "combinational" in err


def test_explain_behavioral_only_id_errors_with_its_own_reason(capsys):
    rc = main(["--explain", "T1", "--home", SAFE])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not retestable this way" in err


def test_explain_blank_id_is_a_malformed_invocation(capsys):
    rc = main(["--explain", "", "--home", SAFE])
    assert rc == 2


def test_explain_is_read_only(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    before = sorted(store.iterdir())
    main(["--explain", "B2", "--home", SAFE, "--data-dir", str(store)])
    after = sorted(store.iterdir())
    assert before == after == []


# --------------------------------------------------------------------- --retest CLI


def test_retest_reports_current_status(capsys):
    rc = main(["--retest", "B2", "--home", VULN])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Retested B2" in out
    assert "status: FAIL" in out


def test_retest_of_a_fixed_finding_reports_cleared(capsys):
    """The DoD's own scenario: the same check, against a target where the condition
    no longer holds, reports the finding as no longer firing."""
    rc = main(["--retest", "B2", "--home", SAFE])
    out = capsys.readouterr().out
    assert rc == 0
    assert "status: PASS" in out


def test_retest_unknown_id_errors_clearly(capsys):
    rc = main(["--retest", "NOPE-123", "--home", SAFE])
    err = capsys.readouterr().err
    assert rc == 2
    assert "unknown finding id" in err


def test_retest_does_not_run_the_full_audit(monkeypatch, capsys):
    """The DoD's load-bearing requirement, verified by CALL COUNT/behavior, not just
    by reading output: patch run_all (the name audit() actually resolves it through,
    clawseccheck.__init__'s own `from .checks import ... run_all`) to explode if
    called, and confirm --retest succeeds without ever reaching it."""
    def _explode(*a, **kw):
        raise AssertionError("run_all() must not be called by --retest")
    monkeypatch.setattr("clawseccheck.run_all", _explode)

    rc = main(["--retest", "B2", "--home", VULN])
    assert rc == 0

    # Positive control: the patch genuinely intercepts a real run_all() call, so the
    # negative result above is not just "the patch never applied". Calls audit()
    # directly rather than through main(), which catches every exception (B-101) and
    # would otherwise turn this into a silent pass regardless of whether the patch fired.
    with pytest.raises(AssertionError, match="run_all"):
        audit(VULN)


def test_retest_calls_only_the_one_target_check(monkeypatch):
    """Stronger than the run_all check above: wrap the target AND two arbitrary other
    checks with counters and confirm only the target's fires."""
    calls = {"target": 0, "other_a": 0, "other_b": 0}
    real_target = CHECKS_BY_ID["B2"]
    other_a_id, other_b_id = "B1", "B4"
    real_other_a = CHECKS_BY_ID[other_a_id]
    real_other_b = CHECKS_BY_ID[other_b_id]

    def _wrap(key, real):
        def _wrapped(ctx):
            calls[key] += 1
            return real(ctx)
        return _wrapped

    monkeypatch.setitem(CHECKS_BY_ID, "B2", _wrap("target", real_target))
    monkeypatch.setitem(CHECKS_BY_ID, other_a_id, _wrap("other_a", real_other_a))
    monkeypatch.setitem(CHECKS_BY_ID, other_b_id, _wrap("other_b", real_other_b))

    rc = main(["--retest", "B2", "--home", VULN])
    assert rc == 0
    assert calls == {"target": 1, "other_a": 0, "other_b": 0}


def test_retest_blank_id_is_a_malformed_invocation():
    rc = main(["--retest", "", "--home", SAFE])
    assert rc == 2


def test_retest_is_read_only(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    before = sorted(store.iterdir())
    main(["--retest", "B2", "--home", VULN, "--data-dir", str(store)])
    after = sorted(store.iterdir())
    assert before == after == []


# --------------------------------------------------------------------- render_explain


def test_render_explain_shows_fix_which_render_finding_does_not():
    """_render_finding (the main report's per-finding renderer) never prints
    remediation text — render_explain is a deliberately different renderer, not a
    thin wrapper, specifically because of this gap."""
    ctx = build_context(VULN)
    f = CHECKS_BY_ID["B2"](ctx)
    out = render_explain(f)
    assert f.fix
    assert f.fix.split(";")[0].strip() in out


def test_render_explain_appends_coverage_note_as_its_own_paragraph():
    ctx = build_context(VULN)
    f = CHECKS_BY_ID["B2"](ctx)
    out = render_explain(f, coverage_note="a distinctive marker sentence")
    assert "a distinctive marker sentence" in out


def test_render_explain_omits_coverage_section_when_none_given():
    ctx = build_context(VULN)
    f = CHECKS_BY_ID["B2"](ctx)
    out = render_explain(f, coverage_note=None)
    assert "coverage note" not in out
