"""F-153: clawseccheck/pipeline.py — the --full P7-P10 orchestration module.

Shipped previously with zero dedicated test coverage (762 lines). This pins the
budget arithmetic, the five honest phase states, the roll-up invariants, the
verbose/quiet render parity, and the judged-bundle parser's adversarial-input
handling.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import pipeline as pl
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Budget arithmetic
# ---------------------------------------------------------------------------

def test_start_deadline_none_when_budget_not_positive():
    assert pl.start_deadline(0.0) is None
    assert pl.start_deadline(-1.0) is None


def test_remaining_s_uncapped_is_infinite():
    assert pl.remaining_s(None) == float("inf")


def test_remaining_s_never_negative():
    expired = pl.start_deadline(1e-9)
    import time
    time.sleep(0.01)
    assert pl.remaining_s(expired) == 0.0


def test_sub_budget_uncapped_returns_phase_default():
    assert pl.sub_budget(None, 42.0) == 42.0


def test_sub_budget_clamps_to_whatever_remains():
    deadline = pl.start_deadline(1000.0)
    # A deadline that far out: remaining is close to 1000s, well under a huge default.
    assert pl.sub_budget(deadline, 5.0) == 5.0


def test_sub_budget_on_an_expired_deadline_is_zero():
    expired = pl.start_deadline(1e-9)
    import time
    time.sleep(0.01)
    assert pl.sub_budget(expired, 900.0) == 0.0


# ---------------------------------------------------------------------------
# PhaseResult — the five honest states
# ---------------------------------------------------------------------------

def test_phase_result_ran_property():
    assert pl.PhaseResult(name="x", status=pl.STATUS_RAN).ran is True
    for status in (pl.STATUS_SKIPPED, pl.STATUS_NOT_REACHED,
                   pl.STATUS_UNAVAILABLE, pl.STATUS_ERROR):
        assert pl.PhaseResult(name="x", status=status).ran is False


def test_skipped_helper():
    p = pl._skipped("x", "operator asked to skip")
    assert p.status == pl.STATUS_SKIPPED
    assert p.complete is False
    assert p.detail == "operator asked to skip"


def test_not_reached_helper_names_the_budget():
    p = pl._not_reached("x", 900.0)
    assert p.status == pl.STATUS_NOT_REACHED
    assert p.complete is False
    assert "900" in p.detail


def test_phase_result_to_json_sanitizes_and_rounds_elapsed():
    p = pl.PhaseResult(name="x", status=pl.STATUS_RAN, elapsed_s=1.23456789,
                       detail="hostile\x1b[31m text", not_scanned=["a\x07b"])
    d = p.to_json()
    assert d["elapsed_s"] == 1.235
    assert "\x1b" not in d["detail"]
    assert "\x07" not in d["notScanned"][0]


# ---------------------------------------------------------------------------
# P6 — record_skill_sweep (duck-typed on cli.SkillSweep's surface)
# ---------------------------------------------------------------------------

class _FakeSweep:
    def __init__(self, *, no_roots=False, no_targets=False, complete=True,
                has_fail=False, counts=None, not_scanned=None):
        self.no_roots = no_roots
        self.no_targets = no_targets
        self.complete = complete
        self.has_fail = has_fail
        self._counts = counts or {"total": 0, "fails": 0, "warns": 0, "safe": 0,
                                  "truncated": 0, "skipped": 0}
        self._not_scanned = not_scanned or []

    def counts(self):
        return self._counts

    def not_scanned(self):
        return self._not_scanned


def test_record_skill_sweep_none_is_skipped_and_unsectioned():
    p = pl.record_skill_sweep(None)
    assert p.status == pl.STATUS_SKIPPED
    assert p.section is False


def test_record_skill_sweep_no_roots():
    p = pl.record_skill_sweep(_FakeSweep(no_roots=True))
    assert p.status == pl.STATUS_RAN
    assert "no skills directory" in p.detail


def test_record_skill_sweep_carries_has_fail_and_not_scanned():
    sweep = _FakeSweep(has_fail=True, not_scanned=["evil-skill"],
                       counts={"total": 3, "fails": 1, "warns": 0, "safe": 1,
                              "truncated": 0, "skipped": 1})
    p = pl.record_skill_sweep(sweep, elapsed_s=2.5)
    assert p.has_fail is True
    assert p.not_scanned == ["evil-skill"]
    assert p.elapsed_s == 2.5
    assert "1 dangerous" in p.detail
    assert p.section is False  # the caller already printed this section


# ---------------------------------------------------------------------------
# P7 — run_plugin_sweep / resolve_plugin_sweep
# ---------------------------------------------------------------------------

def test_resolve_plugin_sweep_finds_the_real_implementation():
    from clawseccheck.checks._mcp import sweep_plugins
    assert pl.resolve_plugin_sweep() is sweep_plugins


def test_run_plugin_sweep_reports_unavailable_when_not_resolvable(monkeypatch):
    monkeypatch.setattr(pl, "resolve_plugin_sweep", lambda: None)
    p = pl.run_plugin_sweep(FIXTURES / "clean_full")
    assert p.status == pl.STATUS_UNAVAILABLE
    assert p.complete is False


def test_run_plugin_sweep_reports_error_without_crashing(monkeypatch):
    def _boom(*_a, **_k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(pl, "resolve_plugin_sweep", lambda: _boom)
    p = pl.run_plugin_sweep(FIXTURES / "clean_full")
    assert p.status == pl.STATUS_ERROR
    assert p.complete is False
    assert "kaboom" in p.detail


def test_run_plugin_sweep_no_plugins_found_runs_cleanly():
    p = pl.run_plugin_sweep(FIXTURES / "clean_full")
    assert p.status == pl.STATUS_RAN
    assert "no plugin" in p.detail.lower()


# ---------------------------------------------------------------------------
# P8 — run_behavioral
# ---------------------------------------------------------------------------

def test_run_behavioral_never_scores_a_fail():
    ctx = collect(FIXTURES / "clean_full")
    p = pl.run_behavioral(ctx)
    assert p.status == pl.STATUS_RAN
    assert p.has_fail is False


def test_run_behavioral_reports_error_without_crashing(monkeypatch):
    monkeypatch.setattr(pl, "render_behavioral_analysis",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
    ctx = collect(FIXTURES / "clean_full")
    p = pl.run_behavioral(ctx)
    assert p.status == pl.STATUS_ERROR
    assert p.has_fail is False


# ---------------------------------------------------------------------------
# P9 — run_adjudication
# ---------------------------------------------------------------------------

def test_run_adjudication_no_bundle_is_pending_not_a_verdict():
    ctx = collect(FIXTURES / "home_vuln")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    p = pl.run_adjudication(ctx, findings)
    assert p.status == pl.STATUS_RAN
    assert p.data["verdictsSubmitted"] is False
    assert "secondOpinion" not in p.data


def test_run_adjudication_with_empty_judged_bundle_emits_second_opinion():
    ctx = collect(FIXTURES / "home_vuln")
    from clawseccheck.checks import run_all
    findings = run_all(ctx)
    p = pl.run_adjudication(ctx, findings, bundle={"judged": {}})
    assert p.data["verdictsSubmitted"] is True
    assert isinstance(p.data["secondOpinion"], list)
    # unreviewed items still appear, per adjudication._second_opinion's own contract
    if p.data["secondOpinion"]:
        assert all(row["judge_verdict"] is None for row in p.data["secondOpinion"])


def test_run_adjudication_vet_packets_are_scoped_per_target():
    ctx = collect(FIXTURES / "clean_full")
    from clawseccheck.catalog import UNKNOWN, Finding
    fake_finding = Finding(id="B13", title="t", status=UNKNOWN, severity="LOW",
                           framework="c", scored=True, detail="d", fix="f",
                           evidence=["evil: something"])
    p = pl.run_adjudication(ctx, [], vet_targets=[("evil-skill", fake_finding)],
                            version="9.9.9")
    packets = p.data["vetPackets"]
    assert isinstance(packets, list)
    if packets:
        assert packets[0]["target"] == "evil-skill"
        assert "targetFingerprint" in packets[0]


# ---------------------------------------------------------------------------
# split_judged_bundle — adversarial input, never raises
# ---------------------------------------------------------------------------

_EMPTY_BUNDLE = {"attestation": None, "judged": None, "vetJudged": []}


def test_split_judged_bundle_non_string_input():
    assert pl.split_judged_bundle(None) == _EMPTY_BUNDLE  # type: ignore[arg-type]
    assert pl.split_judged_bundle(12345) == _EMPTY_BUNDLE  # type: ignore[arg-type]


def test_split_judged_bundle_oversized_payload_rejected():
    huge = json.dumps({"judged": {"x": "y" * (pl.MAX_BUNDLE_BYTES + 100)}})
    assert pl.split_judged_bundle(huge) == _EMPTY_BUNDLE


def test_split_judged_bundle_malformed_json():
    assert pl.split_judged_bundle("{not json") == _EMPTY_BUNDLE


def test_split_judged_bundle_top_level_not_a_dict():
    assert pl.split_judged_bundle(json.dumps([1, 2, 3])) == _EMPTY_BUNDLE
    assert pl.split_judged_bundle(json.dumps("a string")) == _EMPTY_BUNDLE


def test_split_judged_bundle_wrong_typed_buckets_are_dropped_not_crashed():
    raw = json.dumps({
        "attestation": "not-an-object",
        "judged": ["not", "an", "object"],
        "vetJudged": "not-a-list",
    })
    out = pl.split_judged_bundle(raw)
    assert out == _EMPTY_BUNDLE


def test_split_judged_bundle_vetjudged_filters_non_dict_entries():
    raw = json.dumps({"vetJudged": [{"a": 1}, "garbage", 42, {"b": 2}]})
    out = pl.split_judged_bundle(raw)
    assert out["vetJudged"] == [{"a": 1}, {"b": 2}]


def test_split_judged_bundle_happy_path_round_trips():
    raw = json.dumps({
        "attestation": {"x": 1},
        "judged": {"verdicts": []},
        "vetJudged": [{"target": "t", "verdicts": []}],
    })
    out = pl.split_judged_bundle(raw)
    assert out["attestation"] == {"x": 1}
    assert out["judged"] == {"verdicts": []}
    assert out["vetJudged"] == [{"target": "t", "verdicts": []}]


# ---------------------------------------------------------------------------
# read_judged_bundle — file path and stdin
# ---------------------------------------------------------------------------

def test_read_judged_bundle_missing_file_is_empty_not_a_crash(tmp_path):
    out = pl.read_judged_bundle(str(tmp_path / "does-not-exist.json"))
    assert out == _EMPTY_BUNDLE


def test_read_judged_bundle_reads_a_real_file(tmp_path):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps({"judged": {"a": 1}}), encoding="utf-8")
    out = pl.read_judged_bundle(str(p))
    assert out["judged"] == {"a": 1}


def test_read_judged_bundle_stdin(monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"judged": {"z": 9}})))
    out = pl.read_judged_bundle("-")
    assert out["judged"] == {"z": 9}


# ---------------------------------------------------------------------------
# PipelineResult roll-ups
# ---------------------------------------------------------------------------

def _result(*phases: pl.PhaseResult) -> pl.PipelineResult:
    r = pl.PipelineResult()
    for p in phases:
        r.add(p)
    return r


def test_pipeline_result_has_fail_is_any_phase():
    r = _result(
        pl.PhaseResult(name="a", status=pl.STATUS_RAN, has_fail=False),
        pl.PhaseResult(name="b", status=pl.STATUS_RAN, has_fail=True),
    )
    assert r.has_fail is True


def test_pipeline_result_complete_requires_every_phase_ran_and_complete():
    r = _result(pl.PhaseResult(name="a", status=pl.STATUS_RAN, complete=True))
    assert r.complete is True
    r2 = _result(
        pl.PhaseResult(name="a", status=pl.STATUS_RAN, complete=True),
        pl._skipped("b", "skipped by operator"),
    )
    assert r2.complete is False


def test_pipeline_result_not_scanned_unions_every_phase():
    r = _result(
        pl.PhaseResult(name="a", status=pl.STATUS_RAN, not_scanned=["x"]),
        pl.PhaseResult(name="b", status=pl.STATUS_RAN, not_scanned=["y", "z"]),
    )
    assert r.not_scanned() == ["x", "y", "z"]


def test_pipeline_result_by_name():
    p = pl.PhaseResult(name="behavioral", status=pl.STATUS_RAN)
    r = _result(p)
    assert r.by_name("behavioral") is p
    assert r.by_name("nope") is None


def test_pipeline_result_to_json_is_additive_and_sanitized():
    r = _result(
        pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=pl.STATUS_RAN,
                       detail="hostile\x1b[2Jtext"),
    )
    d = r.to_json()
    assert set(d.keys()) >= {"phases", "complete", "notScanned"}
    assert "\x1b" not in json.dumps(d)


def test_pipeline_result_to_json_folds_in_adjudication_and_plugin_sweep_keys():
    adj = pl.PhaseResult(
        name=pl.PHASE_ADJUDICATION, status=pl.STATUS_RAN,
        data={"judgePacket": [], "vetPackets": [], "attestTemplate": {}},
    )
    plug = pl.PhaseResult(
        name=pl.PHASE_PLUGIN_SWEEP, status=pl.STATUS_RAN,
        data={"no_roots": True, "no_targets": True, "complete": True,
              "counts": {}, "not_scanned": []},
    )
    d = _result(adj, plug).to_json()
    assert d["judgePacket"] == []
    assert d["vetPackets"] == []
    assert d["attestTemplate"] == {}
    assert d["pluginSweep"]["no_roots"] is True


def test_pipeline_result_to_json_omits_second_opinion_when_absent():
    adj = pl.PhaseResult(name=pl.PHASE_ADJUDICATION, status=pl.STATUS_RAN,
                         data={"judgePacket": []})
    d = _result(adj).to_json()
    assert "secondOpinion" not in d


# ---------------------------------------------------------------------------
# render_sections vs quiet_lines — same facts, different amounts of detail
# ---------------------------------------------------------------------------

def test_verbose_and_quiet_state_the_same_status_for_every_phase():
    r = _result(
        pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=pl.STATUS_RAN,
                       detail="3 skills vetted.", lines=["3 skills vetted."],
                       quiet_line="3 skills vetted."),
        pl._not_reached(pl.PHASE_BEHAVIORAL, 900.0),
    )
    verbose = "\n".join(pl.render_sections(r))
    quiet = "\n".join(pl.quiet_lines(r))
    assert "3 skills vetted." in verbose
    assert "3 skills vetted." in quiet
    assert "900" in verbose
    assert "900" in quiet


def test_render_sections_skips_unsectioned_phases():
    r = _result(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=pl.STATUS_RAN,
                               section=False, detail="printed elsewhere"))
    assert pl.render_sections(r) == []
    assert pl.quiet_lines(r) == []


def test_render_sections_marks_not_scanned_targets_and_caps_the_list():
    names = [f"skill-{i}" for i in range(20)]
    r = _result(pl.PhaseResult(name=pl.PHASE_SKILL_SWEEP, status=pl.STATUS_RAN,
                               lines=["ok"], not_scanned=names))
    out = "\n".join(pl.render_sections(r))
    assert "Not scanned" in out
    assert "(+8 more)" in out  # 20 names, 12 shown


# ---------------------------------------------------------------------------
# run_pipeline — the P7-P9 roll-up, including an already-expired deadline
# ---------------------------------------------------------------------------

def test_run_pipeline_fast_skips_the_deep_phases():
    ctx = collect(FIXTURES / "clean_full")
    result = pl.run_pipeline(ctx, [], home_dir=FIXTURES / "clean_full", fast=True)
    skill = result.by_name(pl.PHASE_SKILL_SWEEP)
    plugin = result.by_name(pl.PHASE_PLUGIN_SWEEP)
    behav = result.by_name(pl.PHASE_BEHAVIORAL)
    adj = result.by_name(pl.PHASE_ADJUDICATION)
    assert skill.status == pl.STATUS_SKIPPED
    assert plugin.status == pl.STATUS_SKIPPED
    assert behav.status == pl.STATUS_SKIPPED
    # P9 is deliberately NOT gated on --fast — it re-runs no check.
    assert adj.status == pl.STATUS_RAN


def test_run_pipeline_already_expired_deadline_reports_not_reached():
    ctx = collect(FIXTURES / "clean_full")
    expired = pl.start_deadline(1e-9)
    import time
    time.sleep(0.01)
    result = pl.run_pipeline(ctx, [], home_dir=FIXTURES / "clean_full",
                             deadline=expired)
    plugin = result.by_name(pl.PHASE_PLUGIN_SWEEP)
    behav = result.by_name(pl.PHASE_BEHAVIORAL)
    adj = result.by_name(pl.PHASE_ADJUDICATION)
    assert plugin.status == pl.STATUS_NOT_REACHED
    assert behav.status == pl.STATUS_NOT_REACHED
    # Adjudication still runs even past the deadline — it costs nothing to emit.
    assert adj.status == pl.STATUS_RAN


def test_run_pipeline_records_the_skill_sweep_it_was_handed():
    ctx = collect(FIXTURES / "clean_full")
    sweep = _FakeSweep(has_fail=True)
    result = pl.run_pipeline(ctx, [], home_dir=FIXTURES / "clean_full",
                             skill_sweep=sweep, skill_sweep_elapsed_s=1.5)
    skill = result.by_name(pl.PHASE_SKILL_SWEEP)
    assert skill.status == pl.STATUS_RAN
    assert skill.has_fail is True
    assert skill.elapsed_s == 1.5
