"""C-704 -- first screen and coverage wording.

Four defects an independent reviewer found reading the first screen of a gradeless run:

1. "No grade yet - 3 of 5 layers did not run: ..." counted layers it never named.
2. The coverage block said "checked 14, partial 0" next to "29 did not reach a verdict",
   and "20 HIGH or worse" counted checks the config had positively confirmed absent.
3. "Logs & trajectories - clear" sat over a not-checked list naming unread SQLite stores.
4. C015's "(+N more file(s))" was cut off by the renderer and replaced by "(+1 more)".

Every wording here is checked against the counts derived from the findings (or the
producer's own strings), never against a copy of the new text.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import CRITICAL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks import check_secrets_at_rest_home
from clawseccheck.checks._config import _C015_MAX_EVIDENCE
from clawseccheck.collector import collect
from clawseccheck.layers import (
    LAYER_LABEL,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    COVERAGE_PARTIAL,
    COVERAGE_UNKNOWN,
    STATUS_NOT_SUBMITTED,
    STATUS_RAN,
    LayerLedger,
    LayerState,
)
from clawseccheck.guide import render_next_actions, suggest_actions
from clawseccheck.pdf import render_pdf
from clawseccheck.pipeline import _b164_not_reached
from clawseccheck.report import (
    _coverage_lines,
    _evidence_bullets,
    _subject_of,
    build_inventory,
    render_dashboard,
    render_html,
    render_json,
    render_report,
    undetermined_summary,
)
from clawseccheck.scoring import compute

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _def() -> str:
    """The layers-definition sentence. Imported here, not at module level, so a tree
    without it fails these tests one by one instead of at collection."""
    from clawseccheck.layers import layers_definition_sentence  # noqa: PLC0415
    return layers_definition_sentence()


def _unexamined_of(score) -> tuple:
    """What the report layer reads off a score as 'the logs layer left this unread'."""
    from clawseccheck.report import _logs_unexamined  # noqa: PLC0415
    return _logs_unexamined(score)


# What B164 says when the SQLite stores were only partly read: the wording the pipeline's
# own regexes parse, so the ledger entries below come from the real producer.
_B164_DETAIL = (
    "No threat found in the logs read. 2293 transcript row(s) across 44 session(s) "
    "unexamined. 430 row(s) across 2 session(s) unexamined."
)


def _ledger(*, logs_not_reached=(), live=STATUS_NOT_SUBMITTED, self_report=STATUS_NOT_SUBMITTED,
            sweep="not_reached", sweep_not_reached=(),
            logs_coverage=COVERAGE_UNKNOWN) -> LayerLedger:
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    states["installed_sweep"] = LayerState(status=sweep, not_reached=tuple(sweep_not_reached))
    states[LAYER_SELF_REPORT] = LayerState(status=self_report)
    states["live_behaviour"] = LayerState(status=live)
    states[LAYER_LOGS_TRAJECTORIES] = LayerState(
        status=STATUS_RAN, not_reached=tuple(logs_not_reached), coverage=logs_coverage)
    return LayerLedger(states=states)


def _full_ledger(logs_not_reached=()) -> LayerLedger:
    states = {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}
    states[LAYER_LOGS_TRAJECTORIES] = LayerState(
        status=STATUS_RAN, not_reached=tuple(logs_not_reached))
    return LayerLedger(states=states)


def _unexamined_entries() -> tuple:
    b164 = Finding("B164", "log threat hunt", LOW, PASS, _B164_DETAIL, "", "fw")
    return _b164_not_reached([b164])


@pytest.fixture(scope="module")
def safe_run():
    ctx, findings, _score = audit(home=str(_FIXTURES / "home_safe"))
    return ctx, findings


def _with_clean_logs_subject(findings):
    """The same run with every logs-subject check PASSing: the one shape in which the
    by-finding bucket reads 'clear', so the only thing that can change the row is the
    not-checked list."""
    return [
        Finding(f.id, f.title, f.severity, PASS, "nothing found in what was read", "",
                f.framework)
        if _subject_of(f) == "logs" else f
        for f in findings
    ]


def _logs_lines(text: str) -> list:
    return [ln for ln in text.splitlines() if "Logs & trajectories" in ln]


# ---- item 1: the five layers are defined once on the first screen ------------------

def test_only_the_logs_layers_own_reasons_mark_the_logs_subject():
    """The attribution is structural (which LAYER carried the reason), not a phrase match."""
    entries = _unexamined_entries()
    assert len(entries) == 2, entries  # transcript rows + trajectory rows
    f = [Finding("B2", "x", LOW, PASS, "d", "", "fw")]
    assert _unexamined_of(compute(f, ledger=_ledger(logs_not_reached=entries))) == entries
    # a reason carried by a DIFFERENT layer is not a log store
    other = compute(f, ledger=_ledger(sweep_not_reached=("3 plugin manifests unscanned",)))
    assert other.not_checked and _unexamined_of(other) == ()
    assert _unexamined_of(compute(f)) == ()          # no ledger at all


def test_definition_sentence_names_every_layer_from_the_single_label_table():
    assert str(len(LAYER_ORDER)) in _def()
    for layer in LAYER_ORDER:
        assert LAYER_LABEL[layer] in _def()


def test_gradeless_text_report_defines_the_layers_once_next_to_the_headline(safe_run):
    ctx, findings = safe_run
    score = compute(findings, ledger=_ledger())
    assert not score.graded
    out = render_report(findings, score, ctx=ctx)
    assert out.count(_def()) == 1
    lines = out.splitlines()
    head = next(i for i, ln in enumerate(lines) if ln.startswith("No grade yet"))
    assert lines[head + 1] == _def()


def test_graded_run_does_not_carry_the_definition(safe_run):
    ctx, findings = safe_run
    score = compute(findings, ledger=_full_ledger())
    assert score.graded
    for out in (render_report(findings, score, ctx=ctx),
                render_dashboard(findings, score, ctx=ctx),
                render_html(findings, score, ctx=ctx)):
        assert _def() not in out


def test_gradeless_dashboard_defines_the_layers_once_but_the_compact_card_does_not(safe_run):
    ctx, findings = safe_run
    score = compute(findings, ledger=_ledger())
    full = render_dashboard(findings, score, ctx=ctx)
    assert full.count(_def()) == 1
    compact = render_dashboard(findings, score, ctx=ctx, compact=True)
    assert _def() not in compact


def test_gradeless_html_and_pdf_define_the_layers(safe_run):
    ctx, findings = safe_run
    score = compute(findings, ledger=_ledger())
    assert _def() in render_html(findings, score, ctx=ctx)
    assert render_pdf(findings, score, ctx=ctx).startswith(b"%PDF")


# ---- item 4: one counting rule for the coverage block ------------------------------

def _f(fid, severity, status, *, na=False, scored=True):
    return Finding(fid, f"seeded {fid}", severity, status, "detail", "fix", "fw",
                   scored=scored, not_applicable=na)


def _mixed_findings():
    return ([_f(f"P{i}", LOW, PASS) for i in range(6)]
            + [_f("W1", MEDIUM, WARN)]
            + [_f(f"N{i}", HIGH, UNKNOWN, na=True) for i in range(3)]   # confirmed absent
            + [_f(f"U{i}", HIGH, UNKNOWN) for i in range(2)]            # blind, HIGH
            + [_f("U9", LOW, UNKNOWN)]                                  # blind, LOW
            + [_f("X1", HIGH, UNKNOWN, scored=False)])                  # unscored: not counted


def _checks_line(lines):
    return next(ln for ln in lines if "scored checks reached a verdict" in ln)


def _degraded(fid, severity):
    return Finding(fid, f"seeded {fid}", severity, UNKNOWN, "detail", "fix", "fw",
                   engine_degraded=True)


def _high_or_worse(unknown):
    return [f for f in unknown if f.severity in (HIGH, CRITICAL)]


def test_headline_counts_equal_counts_derived_from_the_findings():
    findings = _mixed_findings()
    scored = [f for f in findings if f.scored]
    unknown = [f for f in scored if f.status == UNKNOWN]
    absent = [f for f in unknown if f.not_applicable]
    blind = [f for f in unknown if not f.not_applicable]
    line = _checks_line(_coverage_lines(findings, ascii_only=True, color=False))
    assert f"{len(scored) - len(unknown)} of {len(scored)} scored checks" in line, line
    # the baseline's figure: HIGH-or-worse over ALL undetermined checks, then the split
    assert (f"{len(unknown)} did not ({len(_high_or_worse(unknown))} HIGH or worse): "
            f"{len(absent)} not applicable (no such surface in your config), "
            f"{len(blind)} with no verdict;") in line, line


def test_text_counts_equal_the_json_assessable_block():
    findings = _mixed_findings()
    line = _checks_line(_coverage_lines(findings, ascii_only=True, color=False))
    summary = undetermined_summary(findings)
    payload = json.loads(render_json(findings, compute(findings)))
    assert payload["undetermined"] == summary
    nums = [int(n) for n in re.findall(r"(\d+)", line)]
    assert summary["scored_checks"] in nums
    assert summary["undetermined"] in nums
    assert summary["confirmed_absent"] in nums
    assert summary["no_signal"] + summary["engine_degraded"] in nums
    unknown = [f for f in findings if f.scored and f.status == UNKNOWN]
    assert len(_high_or_worse(unknown)) in nums


def test_degraded_high_check_is_counted_in_the_high_or_worse_figure():
    """engine_degraded checks are UNKNOWN too; the baseline counted them."""
    findings = [_f("P1", HIGH, PASS), _degraded("D1", HIGH), _f("U1", MEDIUM, UNKNOWN)]
    line = _checks_line(_coverage_lines(findings, ascii_only=True, color=False))
    assert "2 did not (1 HIGH or worse); an undetermined check neither earns" in line, line


def test_not_applicable_plus_degraded_keeps_the_high_or_worse_figure():
    findings = [_f("P1", LOW, PASS), _f("N1", LOW, UNKNOWN, na=True),
                _degraded("D1", HIGH), _f("U1", MEDIUM, UNKNOWN)]
    line = _checks_line(_coverage_lines(findings, ascii_only=True, color=False))
    assert ("3 did not (1 HIGH or worse): 1 not applicable (no such surface in your config), "
            "2 with no verdict;") in line, line


def test_no_high_at_all_prints_no_high_figure_in_either_shape():
    plain = [_f("P1", LOW, PASS), _f("U1", LOW, UNKNOWN)]
    split = [_f("P1", LOW, PASS), _f("N1", LOW, UNKNOWN, na=True), _f("U1", LOW, UNKNOWN)]
    a = _checks_line(_coverage_lines(plain, ascii_only=True, color=False))
    b = _checks_line(_coverage_lines(split, ascii_only=True, color=False))
    assert "1 did not;" in a and "HIGH or worse" not in a, a
    assert ("2 did not: 1 not applicable (no such surface in your config), "
            "1 with no verdict;") in b and "HIGH or worse" not in b, b


def test_no_absent_surface_keeps_the_established_wording():
    findings = [_f("P1", LOW, PASS), _f("U1", HIGH, UNKNOWN), _f("U2", LOW, UNKNOWN)]
    line = _checks_line(_coverage_lines(findings, ascii_only=True, color=False))
    assert "2 did not (1 HIGH or worse);" in line, line
    assert "not applicable" not in line, line


def test_surface_line_says_what_a_checked_surface_is():
    lines = _coverage_lines(_mixed_findings(), ascii_only=True, color=False)
    surf = next(ln for ln in lines if "config surfaces" in ln)
    assert "counts as checked once one of its checks gave a verdict" in surf, surf


# ---- item 5: a subject is never "clear" over a store it did not examine -----------

def test_the_control_logs_row_reads_clear_when_nothing_was_left_unread(safe_run):
    ctx, findings = safe_run
    findings = _with_clean_logs_subject(findings)
    score = compute(findings, ledger=_ledger())
    inv = build_inventory(findings, ctx, logs_unexamined=_unexamined_of(score))
    assert "unexamined" not in inv["logs"]
    assert inv["logs"]["status"] == PASS, inv["logs"]      # the control must be clean
    rows = _logs_lines(render_report(findings, score, ctx=ctx))
    assert rows and all("clear" in r for r in rows), rows


def test_no_surface_calls_the_logs_subject_clear_while_a_store_is_unexamined(safe_run):
    ctx, findings = safe_run
    findings = _with_clean_logs_subject(findings)
    entries = _unexamined_entries()
    score = compute(findings, ledger=_ledger(logs_not_reached=entries))
    assert _unexamined_of(score) == entries

    # positive control: the findings alone call this subject clean; only the not-checked
    # list says otherwise
    assert build_inventory(findings, ctx)["logs"]["status"] == PASS
    inv = build_inventory(findings, ctx, logs_unexamined=_unexamined_of(score))
    assert inv["logs"]["status"] == UNKNOWN
    assert inv["logs"]["unexamined"] == list(entries)

    surfaces = {
        "report": render_report(findings, score, ctx=ctx),
        "report-ascii": render_report(findings, score, ctx=ctx, ascii_only=True),
        "dashboard": render_dashboard(findings, score, ctx=ctx),
        "compact": render_dashboard(findings, score, ctx=ctx, compact=True),
        "html": render_html(findings, score, ctx=ctx),
    }
    for name, text in surfaces.items():
        rows = _logs_lines(text) if name != "html" else re.findall(
            r"Logs &amp; trajectories.{0,300}", text, re.S)
        assert rows, name
        for r in rows:
            assert "clear" not in r, (name, r)
        assert any("not fully examined" in r for r in rows), (name, rows)

    payload = json.loads(render_json(findings, score, ctx=ctx))
    assert payload["inventory"]["logs"]["unexamined"] == list(entries)
    assert payload["inventory"]["logs"]["status"] != PASS


def test_a_real_issue_in_the_logs_subject_keeps_its_own_count(safe_run):
    ctx, findings = safe_run
    entries = _unexamined_entries()
    bad = [Finding("B164", "log threat hunt", MEDIUM, WARN, _B164_DETAIL, "fix", "fw")
           if f.id == "B164" else f for f in _with_clean_logs_subject(findings)]
    inv = build_inventory(bad, ctx, logs_unexamined=entries)
    assert inv["logs"]["status"] == WARN        # never softened to UNKNOWN
    assert "B164" in inv["logs"]["findings"]
    assert inv["logs"]["unexamined"] == list(entries)


# ---- item 6: C015 discloses exactly how many files the report hid ------------------

def _home_with_secret_files(tmp_path: Path, n: int) -> Path:
    token = "sk-" + "a" * 40
    for i in range(n):
        f = tmp_path / f"cred{i}.json"
        f.write_text(json.dumps({"token": token}), encoding="utf-8")
        os.chmod(f, 0o600)
    return tmp_path


@pytest.mark.parametrize("extra", [1, 3, 8])
def test_c015_rendered_overflow_counts_the_files_actually_hidden(tmp_path, extra):
    home = _home_with_secret_files(tmp_path, _C015_MAX_EVIDENCE + extra)
    f = check_secrets_at_rest_home(collect(str(home)))
    n_files = int(re.search(r"found in (\d+) home file\(s\)", f.detail).group(1))
    assert n_files > _C015_MAX_EVIDENCE
    bullets = _evidence_bullets(f.evidence, limit=12, indent="")   # the renderers' own cap
    rows = [b for b in bullets if "more" not in b]
    tail = [b for b in bullets if "more" in b]
    assert len(tail) == 1, bullets
    hidden = int(re.search(r"\+(\d+) more", tail[0]).group(1))
    assert len(rows) + hidden == n_files, bullets   # shown + stated hidden == the detail's count
    assert "file(s)" in tail[0], tail                # the engine's own marker, not "(+1 more)"


# ---- the compact card stays inside its budget -------------------------------------

@pytest.mark.parametrize("home", ["home_safe", "home_vuln"])
def test_gradeless_compact_card_stays_within_4096_chars(home):
    ctx, findings, _ = audit(home=str(_FIXTURES / home))
    score = compute(findings, ledger=_ledger(logs_not_reached=_unexamined_entries()))
    card = render_dashboard(findings, score, ctx=ctx, compact=True)
    assert len(card) <= 4096, len(card)
    assert _def() not in card


# ---- item 3: a gradeless run does not advise what only a graded run can use ------

_GRADE_ONLY_ACTIONS = ("track_trend", "share_grade")


def test_gradeless_run_is_not_told_to_track_a_trend_or_share_a_badge(safe_run):
    ctx, findings = safe_run
    graded = suggest_actions(findings, compute(findings, ledger=_full_ledger()))
    gradeless_score = compute(findings, ledger=_ledger())
    assert not gradeless_score.graded
    gradeless = suggest_actions(findings, gradeless_score)
    # positive control: a graded run still carries both
    assert all(a in [x.id for x in graded] for a in _GRADE_ONLY_ACTIONS)
    ids = [x.id for x in gradeless]
    assert not [a for a in _GRADE_ONLY_ACTIONS if a in ids], ids
    # every other action survives, still ordered by (priority, id)
    assert ids == [x.id for x in sorted(gradeless, key=lambda a: (a.priority, a.id))]
    assert "setup_monitoring" in ids and "live_test" in ids, ids
    text = render_next_actions(gradeless, True)
    assert "--trend" not in text and "--badge" not in text, text


def test_gradeless_json_and_dashboard_next_actions_omit_them(safe_run):
    ctx, findings = safe_run
    score = compute(findings, ledger=_ledger())
    payload = json.loads(render_json(findings, score, ctx=ctx))
    cmds = " ".join(a["command"] for a in payload["next_actions"])
    assert "--trend" not in cmds and "--badge" not in cmds, cmds
    assert payload["next_actions"], "the other advice must survive"


# ---- the compact card keeps the baseline's short coverage block -------------------
#
# The compact card trims `why:` lines tier by tier to stay inside ~4096 chars, so every
# line added to it is paid for in findings text. The split and the surface-line gloss live
# in the long renderers only.

def test_compact_coverage_lines_are_the_baseline_wording():
    findings = _mixed_findings()
    short = _coverage_lines(findings, ascii_only=True, color=False, compact=True)
    long = _coverage_lines(findings, ascii_only=True, color=False)
    unknown = [f for f in findings if f.scored and f.status == UNKNOWN]
    assert _checks_line(short).endswith(
        f"{len(unknown)} did not ({len(_high_or_worse(unknown))} HIGH or worse); "
        "an undetermined check neither earns nor costs a point"), short
    surf = next(ln for ln in short if "config surfaces" in ln)
    assert surf.endswith("config surfaces)") and "counts as checked" not in surf, surf
    assert "not applicable" not in _checks_line(short)
    assert sum(map(len, short)) < sum(map(len, long))


# why: counts measured on the baseline tree (the same fixtures, `full=True, compact=True`).
_BASELINE_WHY = {"home_safe": 9, "home_vuln": 25, "bad_b103_ftp": 8}


@pytest.mark.parametrize("fixture", sorted(_BASELINE_WHY))
@pytest.mark.parametrize("graded", [True, False])
def test_compact_full_card_keeps_the_baseline_why_lines(fixture, graded):
    ctx, findings, score = audit(home=str(_FIXTURES / fixture))
    if not graded:
        score = compute(findings, ledger=_ledger())
    card = render_dashboard(findings, score, ctx=ctx, full=True, compact=True)
    assert card.count("why:") == _BASELINE_WHY[fixture], card.count("why:")
    # the short block, not the long one
    assert "Coverage of OpenClaw surfaces" in card
    assert "counts as checked once" not in card
    assert "with no verdict" not in card
    # and the long renderers still carry the split
    full = render_dashboard(findings, score, ctx=ctx, full=True)
    assert "counts as checked once" in full


# ---- item 5, second source: a logs-layer reason that is not one of B164's phrases ---

_SIDECAR_REASON = (
    "no trajectory sidecar was found at the current locator path, but other evidence "
    "shows this agent's trajectory history exists elsewhere (so the log hunt read none of it)"
)


def test_a_sidecar_reason_alone_keeps_the_logs_subject_from_reading_clear(safe_run):
    ctx, findings = safe_run
    findings = _with_clean_logs_subject(findings)
    score = compute(findings, ledger=_ledger(
        logs_not_reached=(_SIDECAR_REASON,), logs_coverage=COVERAGE_PARTIAL))
    assert _unexamined_of(score) == (_SIDECAR_REASON,)
    assert build_inventory(findings, ctx)["logs"]["status"] == PASS      # findings alone: clean
    inv = build_inventory(findings, ctx, logs_unexamined=_unexamined_of(score))
    assert inv["logs"]["status"] == UNKNOWN
    assert inv["logs"]["unexamined"] == [_SIDECAR_REASON]
    for name, text in {
        "report": render_report(findings, score, ctx=ctx),
        "dashboard": render_dashboard(findings, score, ctx=ctx),
        "compact": render_dashboard(findings, score, ctx=ctx, compact=True),
    }.items():
        rows = _logs_lines(text)
        assert rows, name
        assert all("clear" not in r for r in rows), (name, rows)
        assert any("not fully examined" in r for r in rows), (name, rows)
    payload = json.loads(render_json(findings, score, ctx=ctx))
    assert payload["inventory"]["logs"]["unexamined"] == [_SIDECAR_REASON]


def test_another_layers_reason_does_not_unclear_the_logs_subject(safe_run):
    ctx, findings = safe_run
    findings = _with_clean_logs_subject(findings)
    score = compute(findings, ledger=_ledger(sweep_not_reached=("3 plugin manifests unscanned",)))
    rows = _logs_lines(render_report(findings, score, ctx=ctx))
    assert rows and all("clear" in r for r in rows), rows
