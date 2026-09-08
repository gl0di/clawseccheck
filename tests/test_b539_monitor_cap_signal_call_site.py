"""B-539 — the monitor's behavioural filter was not pinned at its call site.

`cli.py` correctly feeds the monitor snapshot from `behavioral.grade_cap_signal(result)`
rather than the raw `result["findings"]`, and that distinction is load-bearing: a bare
B191 divergence under a rotated trajectory cap is documented benign noise, so raw findings
would put it in the drift stream on every run, forever.

Nothing pinned it. Measured before this file existed, by actually performing the mutation
— swapping the call site for `sorted(f.id for f in _b_result["findings"] if f.status ==
"WARN")` — and re-running the eight files that plausibly cover it:

    test_f173_behavioral_and_witness, test_monitor, test_monitor_chain,
    test_f154_behavioral_cap, test_c417_snapshot_enablers, test_c418_scoped_all_clear,
    test_c419_store_and_exit_code, test_behavioral        ->  299 passed

So the guard was genuinely absent, not merely hard to find.

These tests pin the SEMANTICS — that the filtered signal, not the raw finding list, is
what reaches the monitor — rather than the spelling of a function name. A test that
greps the source for an identifier is defeated by a rename and gives false comfort.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.behavioral import (
    _B191_STRONG_SUB_SIGNALS,
    BEHAVIORAL_CHECK_IDS,
    grade_cap_signal,
)
from clawseccheck.catalog import HIGH, WARN, Finding
from clawseccheck.cli import main

_SAFE = '{"agents": {"defaults": {}}}'


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(_SAFE, encoding="utf-8")
    os.chmod(cfg, 0o600)
    return home


def _f(fid: str, sub_signals=frozenset()):
    return Finding(fid, f"{fid} title", HIGH, WARN, f"{fid} detail", "fix", "fw",
                   sub_signals=sub_signals)


def _weak_b191():
    """A B191 WARN carrying only `divergence` — reported, but must never cap or drift."""
    return _f("B191", frozenset({"divergence"}))


def _strong_b191():
    return _f("B191", frozenset({sorted(_B191_STRONG_SUB_SIGNALS)[0]}))


def _result(*findings):
    return {"findings": list(findings), "files_capped": True}


# ------------------------------------------------------------------ the filter itself
def test_the_filter_drops_a_bare_divergence_and_keeps_a_strong_one():
    assert grade_cap_signal(_result(_weak_b191())) == frozenset()
    assert grade_cap_signal(_result(_strong_b191())) == frozenset({"B191"})


def test_the_raw_finding_list_and_the_filtered_signal_genuinely_differ():
    """If these ever agreed, every test below would pass for the wrong reason —
    the mutation would be undetectable because there would be nothing to detect."""
    result = _result(_weak_b191(), _f("T1"))
    raw = {f.id for f in result["findings"] if f.status == WARN}
    assert raw == {"B191", "T1"}
    assert grade_cap_signal(result) == {"T1"}


# ------------------------------------------------------------------ the CALL SITE
#
# The point of this file. The filter working proves nothing about whether the monitor
# uses it; that is precisely the gap the mutation exposed.

def _run_monitor_with(monkeypatch, tmp_path, result):
    import clawseccheck.cli as cli
    monkeypatch.setattr(cli, "_behavioral_analyze", lambda ctx: result)
    home, store = _home(tmp_path), tmp_path / "store"
    assert main(["--monitor", "--home", str(home), "--data-dir", str(store)]) == 0
    return json.loads((store / "state.json").read_text(encoding="utf-8"))


def test_a_bare_divergence_never_reaches_the_monitors_fired_dimension(
        monkeypatch, tmp_path, capsys):
    """The mutation's actual consequence: this run would report B191 as fired, it would
    show as drift on the transition, and then sit in the baseline forever."""
    saved = _run_monitor_with(monkeypatch, tmp_path, _result(_weak_b191()))
    capsys.readouterr()
    assert saved["behavioral_fired"] == []


def test_a_strong_signal_does_reach_it(monkeypatch, tmp_path, capsys):
    """The opposite direction, so the guard above cannot be satisfied by a monitor that
    simply drops the whole dimension."""
    saved = _run_monitor_with(monkeypatch, tmp_path, _result(_strong_b191()))
    capsys.readouterr()
    assert saved["behavioral_fired"] == ["B191"]


def test_the_monitor_records_the_filtered_set_not_the_raw_warn_ids(
        monkeypatch, tmp_path, capsys):
    """The mutation, stated as an assertion: with both present the raw list is
    {B191, T1} and the filtered signal is {T1}. Only the second may be persisted."""
    saved = _run_monitor_with(monkeypatch, tmp_path, _result(_weak_b191(), _f("T1")))
    capsys.readouterr()
    assert saved["behavioral_fired"] == ["T1"]
    assert "B191" not in saved["behavioral_fired"]


def test_a_finding_outside_the_behavioural_set_is_never_recorded(
        monkeypatch, tmp_path, capsys):
    """Raw WARN ids would sweep in any check that happened to be in the result."""
    assert "B13" not in BEHAVIORAL_CHECK_IDS
    saved = _run_monitor_with(monkeypatch, tmp_path, _result(_f("B13"), _f("T2")))
    capsys.readouterr()
    assert saved["behavioral_fired"] == ["T2"]
