"""C-664 slice C2: the readers of content someone hostile can shape take the shallow reader.

A fixed depth limit on these three was tried and rejected, because on content an attacker
controls a limit is an evasion:

* a judge verdict payload (the judge reads hostile skill prose) with ONE padded key was
  dropped whole, so ``--vet-skill <twin> --vet-judged <payload>`` went from CAUTION to
  INSTALL;
* a tampered LAST entry of the hash-chained events journal padded to 201 levels verified
  "OK (1 unparseable line skipped)" where the unbounded parse says "broken at entry 2".

So these readers use ``loads_shallow``: they read the fields they need exactly as
``json.loads`` does, whatever the document is padded with, and nothing recurses. Most hostile twins pad a DICT-shaped, otherwise valid document, so the padded key is the
only thing that differs from the clean twin; the 100,000-level "whole payload" and "whole
line" cases are deliberately bare nested lists or objects, and pin only that the reader
ends in its "not usable" / "broken" state without raising. The clean twin must come out
exactly as before. Where the unbounded parse still ran (201 levels; 100 levels), the
expected outcome is what it produced, stated explicitly; where it ended in a
RecursionError (100,000 levels) the expected outcome is the clean twin's, because the
padding is unrelated to every field the reader looks at.

One behaviour change is chosen, not inherited: a ``verdict`` that is itself a list or an
object made ``_parse_verdicts`` raise ``TypeError`` (unhashable) on dev. It is now an
unusable entry (the "no usable entries" note, no escalation), like any unknown verdict.

Readers covered: ``adjudication._parse_verdicts``, ``adjudication._verdicts_fingerprint_matches``
(both reach ``escalate_vet_output`` / ``--judged`` / ``--propose-ignore`` / ``--vet-judged``),
``pipeline.split_judged_bundle``, and ``monitorstore._iter_jsonl`` / ``verify_chain`` / ``_rotate_journal``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import monitorstore
from clawseccheck.adjudication import (
    _parse_verdicts,
    _verdicts_fingerprint_matches,
    _vet_run_fingerprint,
    escalate_vet_output,
)
from clawseccheck.catalog import FAIL, MEDIUM, WARN, Finding
from clawseccheck.pipeline import split_judged_bundle

DEPTHS = [201, 100_000]


def _nest(n: int) -> str:
    """JSON text of an array nested *n* levels (built as text: nothing here recurses)."""
    return "[" * n + "]" * n


def _buried(depth: int, leaf: str = '"payload"') -> str:
    """JSON text of *leaf* sitting *depth* levels down, wrapped in arrays."""
    return "[" * (depth - 1) + leaf + "]" * (depth - 1)


# -- the verdict payload ---------------------------------------------------------------

_TARGET = "skillx"
_FP = _vet_run_fingerprint(_TARGET)
_ENTRY = '{"finding_id": "B100", "target": "skillx", "verdict": "DANGEROUS"%s}'


def _payload(top_extra: str = "", entry_extra: str = "") -> str:
    return ('{"targetFingerprint": "%s", "verdicts": [%s]%s}'
            % (_FP, _ENTRY % entry_extra, top_extra))


_PLAIN = _payload()
_DANGEROUS = {("B100", "skillx"): {"verdict": "DANGEROUS", "votes": None}}


def _primary() -> Finding:
    return Finding(
        "B100", "ClickFix-style paste-into-terminal setup instruction", MEDIUM, WARN,
        "ClickFix-style setup instruction: skillx: '...' section instructs pasting a "
        "remote-fetch command into a terminal (ClickFix pattern)",
        "Replace the paste-into-terminal instruction ...", "Supply Chain / ClawHavoc",
        scored=False, evidence=["skillx: '...' section instructs pasting a remote-fetch "
                                 "command into a terminal (ClickFix pattern)"],
    )


def test_clean_verdict_payload_is_read_as_before():
    assert _parse_verdicts(_PLAIN) == _DANGEROUS
    assert _verdicts_fingerprint_matches(_PLAIN, _FP) is True
    assert escalate_vet_output(_primary(), _PLAIN, target=_TARGET).status == FAIL


@pytest.mark.parametrize("n", DEPTHS)
def test_padded_top_level_key_does_not_drop_the_verdicts(n):
    raw = _payload(top_extra=', "pad": ' + _nest(n))
    # json.loads parsed the 201-level text and applied DANGEROUS; it must still.
    assert _parse_verdicts(raw) == _DANGEROUS
    assert _verdicts_fingerprint_matches(raw, _FP) is True
    assert escalate_vet_output(_primary(), raw, target=_TARGET).status == FAIL


@pytest.mark.parametrize("n", DEPTHS)
def test_padded_key_inside_the_entry_does_not_drop_the_verdict(n):
    raw = _payload(entry_extra=', "pad": ' + _nest(n))
    assert _parse_verdicts(raw) == _DANGEROUS
    assert escalate_vet_output(_primary(), raw, target=_TARGET).status == FAIL


def test_evidence_buried_100_levels_deep_does_not_change_the_outcome():
    raw = _payload(entry_extra=', "evidence": ' + _buried(100))
    assert _parse_verdicts(raw) == _DANGEROUS
    assert escalate_vet_output(_primary(), raw, target=_TARGET).status == FAIL


@pytest.mark.parametrize("n", DEPTHS)
def test_deeply_nested_votes_come_back_serialisable_and_leave_the_verdict_alone(n):
    raw = _payload(entry_extra=', "votes": {"DANGEROUS": ' + _nest(n) + "}")
    entry = _parse_verdicts(raw)[("B100", "skillx")]
    assert entry["verdict"] == "DANGEROUS"
    json.dumps(entry)  # the marker the reader leaves for a subtree it did not follow is gone


@pytest.mark.parametrize("n", DEPTHS)
def test_the_needed_field_itself_too_deep_is_the_unusable_outcome(n):
    verdict_deep = ('{"targetFingerprint": "%s", "verdicts": [{"finding_id": "B100", '
                    '"target": "skillx", "verdict": %s}]}' % (_FP, _nest(n)))
    assert _parse_verdicts(verdict_deep) == {}
    assert escalate_vet_output(_primary(), verdict_deep, target=_TARGET).status == WARN
    fingerprint_deep = '{"targetFingerprint": %s, "verdicts": []}' % _nest(n)
    assert _verdicts_fingerprint_matches(fingerprint_deep, _FP) is False
    entries_deep = '{"targetFingerprint": "%s", "verdicts": %s}' % (_FP, _nest(n))
    assert _parse_verdicts(entries_deep) == {}


@pytest.mark.parametrize("raw", [
    _nest(100_000),
    "{" + '"a": {' * 100_000 + "}" * 100_000 + "}",
    '{"verdicts": [' + _nest(100_000) + "]}",
    "[" * 100_000,  # never closed: not valid JSON
])
def test_a_100k_level_payload_ends_in_the_not_usable_state_without_raising(raw):
    assert _parse_verdicts(raw) == {}
    assert _verdicts_fingerprint_matches(raw, _FP) is False
    assert escalate_vet_output(_primary(), raw, target=_TARGET).status == WARN


# -- the judged bundle -----------------------------------------------------------------

_EMPTY = {"attestation": None, "judged": None, "vetJudged": [], "liveTest": None}
_BUNDLE = ('{"judged": {"verdicts": [{"finding_id": "B100", "target": "skillx", '
           '"verdict": "DANGEROUS"}]%s}, "liveTest": {"ran": true}%s}')


def test_clean_bundle_is_split_as_before():
    out = split_judged_bundle(_BUNDLE % ("", ""))
    assert out["liveTest"] == {"ran": True}
    assert _parse_verdicts(json.dumps(out["judged"])) == _DANGEROUS


@pytest.mark.parametrize("n", DEPTHS)
def test_padded_top_level_key_does_not_drop_the_buckets(n):
    out = split_judged_bundle(_BUNDLE % ("", ', "pad": ' + _nest(n)))
    assert out["liveTest"] == {"ran": True}
    assert _parse_verdicts(json.dumps(out["judged"])) == _DANGEROUS


@pytest.mark.parametrize("n", DEPTHS)
def test_padded_key_inside_a_bucket_is_still_serialisable_for_the_verdict_parser(n):
    out = split_judged_bundle(_BUNDLE % (', "pad": ' + _nest(n), ""))
    # pipeline.run_full_pipeline hands this bucket to json.dumps and then _parse_verdicts
    assert _parse_verdicts(json.dumps(out["judged"])) == _DANGEROUS


@pytest.mark.parametrize("n", DEPTHS)
def test_padded_vet_judged_entry_still_matches_its_fingerprint(n):
    raw = ('{"vetJudged": [{"targetFingerprint": "%s", "verdicts": [{"finding_id": "B100", '
           '"target": "skillx", "verdict": "DANGEROUS"}], "pad": %s}]}' % (_FP, _nest(n)))
    (entry,) = split_judged_bundle(raw)["vetJudged"]
    text = json.dumps(entry)  # pipeline.run_full_pipeline does exactly this
    assert _verdicts_fingerprint_matches(text, _FP) is True
    assert _parse_verdicts(text) == _DANGEROUS


@pytest.mark.parametrize("raw", [
    _nest(100_000),
    "{" + '"a": {' * 100_000 + "}" * 100_000 + "}",
    '{"judged": ' + _nest(100_000) + "}",
    "[" * 100_000,
])
def test_a_100k_level_bundle_ends_in_nothing_applied_without_raising(raw):
    assert split_judged_bundle(raw) == _EMPTY


# -- the hash-chained events journal ---------------------------------------------------

def _chained(entries: list) -> list:
    prev, out = "", []
    for e in entries:
        h = monitorstore._chain_hash(prev, e)
        out.append({**e, "chain_hash": h})
        prev = h
    return out


_ROWS = _chained([{"event": "a"}, {"event": "alert", "msg": "installed evil"}, {"event": "c"}])


def _padded(entry: dict, n: int) -> str:
    return json.dumps(entry)[:-1] + ', "pad": ' + _nest(n) + "}"


def _verify(tmp_path: Path, lines: list) -> tuple:
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join(lines) + "\n")
    cause: list = []
    return monitorstore.verify_chain(p, cause)


def test_intact_journal_still_verifies(tmp_path):
    ok, msg = _verify(tmp_path, [json.dumps(r) for r in _ROWS])
    assert ok is True and msg == "OK"


@pytest.mark.parametrize("n", DEPTHS)
def test_tampered_last_entry_padded_deep_is_broken_not_skipped(tmp_path, n):
    lines = [json.dumps(r) for r in _ROWS[:2]] + [_padded(_ROWS[2], n)]
    assert _verify(tmp_path, lines) == (False, "broken at entry 2")


@pytest.mark.parametrize("n", DEPTHS)
def test_tampered_middle_entry_padded_deep_is_broken(tmp_path, n):
    lines = [json.dumps(_ROWS[0]), _padded(_ROWS[1], n), json.dumps(_ROWS[2])]
    assert _verify(tmp_path, lines) == (False, "broken at entry 1")


@pytest.mark.parametrize("n", DEPTHS)
def test_an_unchained_legacy_row_padded_deep_is_broken(tmp_path, n):
    legacy = _padded({"event": "old"}, n)
    assert _verify(tmp_path, [legacy] + [json.dumps(r) for r in _ROWS]) == (
        False, "broken at entry 0")


@pytest.mark.parametrize("line", [
    "{" + '"a": {' * 100_000 + "}" * 100_000 + "}",
    _nest(100_000),
    _nest(201),
])
def test_an_extra_deep_line_after_a_good_chain_is_broken(tmp_path, line):
    ok, msg = _verify(tmp_path, [json.dumps(r) for r in _ROWS] + [line])
    assert ok is False and msg == "broken at entry 3"


@pytest.mark.parametrize("tail", [
    json.dumps(_ROWS[2])[:30],  # an append that died mid-write
    "[" * 100_000,              # cut off before it closed: the same JSON error
])
def test_a_truncated_tail_keeps_its_leniency(tmp_path, tail):
    ok, msg = _verify(tmp_path, [json.dumps(r) for r in _ROWS[:2]] + [tail])
    assert ok is True
    assert msg == "OK (1 unparseable line skipped)"


def test_the_plain_reader_keeps_a_padded_entry_and_never_raises(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join([json.dumps(_ROWS[0]), _padded(_ROWS[1], 201),
                            _padded(_ROWS[2], 100_000), _nest(100_000)]) + "\n")
    skipped: list = []
    entries = list(monitorstore._iter_jsonl(p, skipped=skipped))
    assert [e["event"] for e in entries] == ["a", "alert", "c"]
    for e in entries:
        json.dumps(e)  # no reader marker survives into an entry a caller may re-serialise
    assert len(skipped) == 1  # the bare 100,000-level array is not an entry


# -- rotation must not launder a padded line -------------------------------------------

def _long_chain(n: int) -> list:
    return _chained([{"event": "e%d" % i} for i in range(n)])


def _write(tmp_path: Path, lines: list) -> Path:
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join(lines) + "\n")
    return p


@pytest.mark.parametrize("n", DEPTHS)
def test_rotation_leaves_a_journal_with_a_padded_tail_untouched(tmp_path, n):
    rows = _long_chain(30)
    p = _write(tmp_path, [json.dumps(r) for r in rows[:-1]] + [_padded(rows[-1], n)])
    before = p.read_bytes()
    assert monitorstore.verify_chain(p) == (False, "broken at entry 29")
    monitorstore._rotate_journal(p, max_lines=10, keep=5)
    assert p.read_bytes() == before
    assert monitorstore.verify_chain(p) == (False, "broken at entry 29")


@pytest.mark.parametrize("line", [_nest(100_000), "{" + '"a": {' * 100_000 + "}" * 100_000 + "}"])
def test_rotation_leaves_a_journal_with_a_deep_extra_line_untouched(tmp_path, line):
    p = _write(tmp_path, [json.dumps(r) for r in _long_chain(30)] + [line])
    before = p.read_bytes()
    monitorstore._rotate_journal(p, max_lines=10, keep=5)
    assert p.read_bytes() == before
    ok, _msg = monitorstore.verify_chain(p)
    assert ok is False


def test_rotation_of_a_clean_chain_is_unchanged(tmp_path):
    p = _write(tmp_path, [json.dumps(r) for r in _long_chain(30)])
    monitorstore._rotate_journal(p, max_lines=10, keep=5)
    lines = p.read_text().splitlines()
    assert len(lines) == 6  # the retention marker plus the newest 5
    assert json.loads(lines[0])["retention_pruned"] == 25
    assert [json.loads(x)["event"] for x in lines[1:]] == ["e%d" % i for i in range(25, 30)]
    assert monitorstore.verify_chain(p) == (True, "OK")
