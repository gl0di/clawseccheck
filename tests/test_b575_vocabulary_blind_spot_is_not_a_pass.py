"""B-575: T1/T2 answer UNKNOWN, not PASS, when every verb-bearing event they read used a
verb outside `_classify_verb_role`'s ingress/sensitive/egress vocabulary.

Measured on a real 1,824-event trajectory corpus (task B-575): the entire verb
population was {bash, message, apply_patch, memory_search, web_search, sessions_spawn,
sessions_yield}. Only `web_search` (ingress) and `bash` (egress, via
`attest.classify_verb`'s EXEC/EGRESS fold — easy to miss reasoning about this by hand;
an earlier repro script for this bug missed exactly that step) actually classify. On a
log where NONE of the observed verbs classify at all, T1/T2 still rendered a plain green
PASS — a true statement about the verbs they could read, worded as a statement about the
log as a whole. This is B-559 (an unread FILE is not evidence of a clean log) one level
down: an unclassified VERB is not evidence either.

Deliberately gated at TOTAL blindness only (see `analysis_incompleteness`'s own comment)
— B-285 narrowed this vocabulary on purpose to hold a false-positive line, and a partial
gap is the expected, correct shape of almost every real log. Widening the vocabulary
itself is explicitly out of scope for this fix (C-135 warning in the task).

Offline, stdlib only.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from clawseccheck import behavioral as B
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TRAJ_HOME = FIXTURES / "traj_present_not_acted"

# All four verbs classify to None under `_classify_verb_role` — none matches
# `_EGRESS_ACTION_TOKENS`' first-token check, `_T_SENSITIVE_HINTS`, `attest.classify_verb`
# EGRESS/EXEC, or `INPUT_TOOL_HINTS`. Confirmed directly against the real function (not
# reasoned about by hand — that is exactly the mistake the task's own repro script made
# with `bash`, which DOES classify).
_UNCLASSIFIABLE_VERBS = ("read", "write", "apply_patch", "message")
for _v in _UNCLASSIFIABLE_VERBS:
    assert B._classify_verb_role(_v) is None, _v
# `bash` is the worked counter-example from the task write-up: it looks unclassified by
# eye but resolves to "egress" via `attest.classify_verb`. Pinned here so a future change
# to that fold can't silently make this fixture's premise stop holding.
assert B._classify_verb_role("bash") == "egress"


def _copy(tmp_path: Path, src: Path, name: str = "home") -> Path:
    home = tmp_path / name
    shutil.copytree(src, home)
    return home


def _line(seq: int, name: str) -> str:
    return (
        '{"traceSchema": "openclaw-trajectory", "schemaVersion": 1, "type": "tool.call", '
        f'"ts": "2026-07-05T00:00:0{seq}Z", "seq": {seq}, '
        f'"data": {{"name": "{name}", "toolCallId": "tc{seq}", "turnId": "t1"}}}}'
    )


def _write_sidecar(home: Path, verbs: "list[str]") -> None:
    sidecar = sorted(home.rglob("*.trajectory.jsonl"))[0]
    lines = [_line(i, v) for i, v in enumerate(verbs, start=1)]
    sidecar.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _statuses(home: Path) -> dict:
    return {f.id: f.status for f in B.analyze(collect(home))["findings"]}


# ------------------------------------------------------- the predicate, on its own


def test_coverage_helper_counts_unclassified_verbs_and_events():
    events = [{"name": n} for n in _UNCLASSIFIABLE_VERBS] * 3
    total, unclassified, names = B._verb_classification_coverage(events)
    assert total == 12 and unclassified == 12
    assert names == sorted(set(_UNCLASSIFIABLE_VERBS))


def test_coverage_helper_ignores_nameless_events():
    """A `prompt.submitted` event carries no `name` — it was never eligible to be a
    classified verb, so it must not inflate either count."""
    events = [{"type": "prompt.submitted"}, {"name": "web_search"}]
    total, unclassified, names = B._verb_classification_coverage(events)
    assert total == 1 and unclassified == 0 and names == []


def test_total_blindness_is_an_incompleteness_reason():
    reason = B.analysis_incompleteness({
        "present": True, "event_count": 4, "unknown_version": False, "truncated": False,
        "files_capped": False, "files_scanned": 1, "files_total": 1,
        "verb_event_count": 4, "unclassified_verb_event_count": 4,
        "unclassified_verb_names": ["apply_patch", "message"],
    })
    assert reason and "outside the ingress/sensitive/egress vocabulary" in reason, reason


def test_partial_coverage_is_not_an_incompleteness_reason():
    """The counter-fixture: one in-vocabulary verb among several is enough to keep the
    clean line — otherwise this caveat becomes universal noise on ordinary real logs
    (message/apply_patch/read/write are routinely and correctly out of vocabulary)."""
    reason = B.analysis_incompleteness({
        "present": True, "event_count": 4, "unknown_version": False, "truncated": False,
        "files_capped": False, "files_scanned": 1, "files_total": 1,
        "verb_event_count": 4, "unclassified_verb_event_count": 3,
        "unclassified_verb_names": ["apply_patch", "message"],
    })
    assert reason is None, reason


def test_zero_verb_events_is_not_treated_as_blindness():
    """A log made entirely of channel/prompt events (no tool verb at all) has nothing
    for this signal to say — it must not manufacture a reason out of an empty domain."""
    reason = B.analysis_incompleteness({
        "present": True, "event_count": 4, "unknown_version": False, "truncated": False,
        "files_capped": False, "files_scanned": 1, "files_total": 1,
        "verb_event_count": 0, "unclassified_verb_event_count": 0,
        "unclassified_verb_names": [],
    })
    assert reason is None, reason


# ------------------------------------------------------------------ the false PASS, closed


def test_a_log_whose_verbs_are_all_outside_the_vocabulary_is_not_a_pass(tmp_path):
    """Positive control: an end-to-end run through `analyze()` on a sidecar whose every
    verb is unclassifiable must not render T1/T2 as a clean PASS."""
    home = _copy(tmp_path, TRAJ_HOME)
    _write_sidecar(home, list(_UNCLASSIFIABLE_VERBS))
    result = B.analyze(collect(home))
    assert result["verb_event_count"] == 4
    assert result["unclassified_verb_event_count"] == 4
    statuses = {f.id: f.status for f in result["findings"]}
    assert statuses["T1"] == "UNKNOWN", statuses
    assert statuses["T2"] == "UNKNOWN", statuses
    t1 = next(f for f in result["findings"] if f.id == "T1")
    assert "outside the ingress/sensitive/egress vocabulary" in t1.detail, t1.detail
    assert "not a clean result" in t1.detail, t1.detail


def test_a_log_with_at_least_one_in_vocabulary_verb_still_passes(tmp_path):
    """Negative control: `web_search` (ingress) and `db_query` (sensitive) both classify
    with no trifecta sequence present — the clean PASS must survive."""
    home = _copy(tmp_path, TRAJ_HOME)
    _write_sidecar(home, ["web_search", "db_query", "message"])
    result = B.analyze(collect(home))
    assert 0 < result["unclassified_verb_event_count"] < result["verb_event_count"]
    statuses = {f.id: f.status for f in result["findings"]}
    assert statuses["T1"] == "PASS", statuses
    assert statuses["T2"] == "PASS", statuses


def test_a_firing_detector_survives_total_vocabulary_blindness_elsewhere(tmp_path):
    """Guard: a real trifecta in one thread stays WARN even when the file also contains
    other unclassifiable verbs — this signal must gate only the CLEAN branch, exactly
    like B-559's file-coverage signal does."""
    home = _copy(tmp_path, TRAJ_HOME)
    sidecar = sorted(home.rglob("*.trajectory.jsonl"))[0]
    lines = [
        _line(1, "web_search"),   # ingress
        _line(2, "db_query"),     # sensitive
        _line(3, "export_data"),  # egress
        _line(4, "message"),      # unclassifiable, same thread — irrelevant to the WARN
    ]
    sidecar.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = B.analyze(collect(home))
    statuses = {f.id: f.status for f in result["findings"]}
    assert statuses["T1"] == "WARN", statuses


# --------------------------------------------------- composes with B-559, not replaces it


def test_file_incompleteness_still_wins_when_both_signals_apply():
    """When a run is BOTH file-incomplete (B-559) and vocabulary-blind (B-575), the
    file reason is reported — the more fundamental, more actionable fact (ordered
    first in `analysis_incompleteness`) — proving the new check composes with the old
    one instead of silently replacing or masking it."""
    reason = B.analysis_incompleteness({
        "present": True, "event_count": 4, "unknown_version": False, "truncated": False,
        "files_capped": True, "files_scanned": 60, "files_total": 78,
        "verb_event_count": 4, "unclassified_verb_event_count": 4,
        "unclassified_verb_names": ["apply_patch", "message"],
    })
    assert "60" in reason and "78" in reason, reason
    assert "vocabulary" not in reason, reason


def test_vocabulary_blindness_fires_on_its_own_when_the_file_read_is_complete():
    """The mirror case: once the file-completeness axis is clean, the vocabulary axis
    is still consulted on its own — it is a second, independent signal, not dead code
    reachable only in combination with the first."""
    reason = B.analysis_incompleteness({
        "present": True, "event_count": 4, "unknown_version": False, "truncated": False,
        "files_capped": False, "files_scanned": 78, "files_total": 78,
        "verb_event_count": 4, "unclassified_verb_event_count": 4,
        "unclassified_verb_names": ["apply_patch", "message"],
    })
    assert reason and "vocabulary" in reason, reason
