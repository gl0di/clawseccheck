"""B-598: `--dashboard` recorded no history, so no chat-driven audit ever existed.

`SKILL.md` puts `--dashboard --full --attest … --judged-bundle … --pdf` in the guided flow,
so it is the command a user actually gets when they ask a chat agent to audit their setup.
That branch returns before the default path's tail, where the only history write lived — so
every such run was invisible to `--trend`, to `--percentile`, and to the pre-scan menu.

Measured live on 2026-08-20: two complete audits ran that morning, one of them graded
**F 49/100**, and at 12:21 the menu still opened with::

    🕒 Last check: 4 days ago

`docs/USAGE.md` goes out of its way to promise the opposite — *"A run that earned no grade
… still records its line, so the timeline stays unbroken"* — and `cli.py`'s own module
docstring says the history write is the default. Three documents said one thing and the mode
in the guided flow did another.

The guard now lives in one helper (`_record_history_point`) that the tail and both dashboard
exits call, because a second copy of the condition is how the two would drift on the next
F-155-shaped change. `cli.py` already records `--monitor` having had this exact shape of bug.

`test_every_mode_history_behaviour_is_pinned` is the part that matters most in a year: nine
modes run a full audit and return early, and only `--dashboard` was reproduced against a live
agent, so only it is changed. The others are pinned as they are — visible, not silent.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")

_ATTEST = '{"schema": "clawseccheck-attest/1", "tools": ["read"], "network": "none"}'
_SEEDED_OK = ('{"liveTest": {"seed": "s", "verdicts": [{"tool": "canary", "id": "canary",'
              ' "verdict": "RESISTANT"}]}}')
# No seed -> not reproducible: caps what this run reports, must never be persisted (F-155).
_UNSEEDED_VULN = ('{"liveTest": {"verdicts": [{"tool": "canary", "id": "canary",'
                  ' "verdict": "VULNERABLE"}]}}')


def _run(tmp_path: Path, *args: str, home: str = VULN, state: str = "state"):
    """Every run gets its own HOME so nothing can reach the real ~/.clawseccheck."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    import os
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", home,
         "--data-dir", str(tmp_path / state), *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})


def _rows(tmp_path: Path, state: str = "state") -> list[dict]:
    p = tmp_path / state / "history.jsonl"
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _bundle(tmp_path: Path, name: str, body: str) -> str:
    dest = tmp_path / name
    dest.write_text(body, encoding="utf-8")
    return str(dest)


# ------------------------------------------------------------------ the headline case

def test_a_dashboard_run_records_exactly_one_point(tmp_path):
    _run(tmp_path, "--dashboard")
    assert len(_rows(tmp_path)) == 1


def test_no_history_still_suppresses_it(tmp_path):
    _run(tmp_path, "--dashboard", "--no-history")
    assert _rows(tmp_path) == []


def test_the_graded_guided_flow_records_the_letter_it_earned(tmp_path):
    """The shape SKILL.md documents. Before this, the one run shape that can reach a grade
    was also the one shape guaranteed never to be recorded."""
    _run(tmp_path, "--dashboard", "--full",
         "--attest", _bundle(tmp_path, "a.json", _ATTEST),
         "--judged-bundle", _bundle(tmp_path, "b.json", _SEEDED_OK), home=SAFE)
    rows = _rows(tmp_path)
    assert len(rows) == 1
    assert isinstance(rows[0].get("score"), int)
    assert rows[0].get("grade") in list("ABCDEF")


def test_an_ungraded_run_records_a_line_with_no_number(tmp_path):
    """docs/USAGE.md's contract: the timeline stays unbroken, but an ungraded line carries
    no score and no letter — never a 0, which would rank a blind audit as a failing one."""
    _run(tmp_path, "--dashboard")
    row = _rows(tmp_path)[0]
    assert row.get("graded") is False
    assert "score" not in row and "grade" not in row

    from clawseccheck.history import load, verify
    path = str(tmp_path / "state" / "history.jsonl")
    loaded = load(path)
    assert loaded[0]["score"] is None and loaded[0]["grade"] is None
    assert verify(path)[0] is True, "the tamper-evident chain must still verify"


# ------------------------------------------------------------------- the F-155 gate

def test_an_unseeded_vulnerable_verdict_is_never_persisted(tmp_path):
    """A non-reproducible live-test signal caps what this run reports but must not reach
    history — recorded, it would manufacture drift on every re-run with a fresh token."""
    _run(tmp_path, "--dashboard",
         "--judged-bundle", _bundle(tmp_path, "v.json", _UNSEEDED_VULN))
    assert _rows(tmp_path) == []


def test_a_seeded_verdict_records_normally(tmp_path):
    """The other half of the same gate: reproducible signals were always meant to record."""
    _run(tmp_path, "--dashboard",
         "--judged-bundle", _bundle(tmp_path, "s.json", _SEEDED_OK))
    assert len(_rows(tmp_path)) == 1


# ------------------------------------------------------------------- the consumers

def test_trend_and_the_menu_can_finally_see_a_dashboard_run(tmp_path):
    """The two surfaces the loss was measured on. The menu's "last check" line is the one
    a user reads BEFORE deciding whether to audit at all, and it was understating their
    coverage by however long they had been using the tool through a chat agent."""
    _run(tmp_path, "--dashboard", "--full",
         "--attest", _bundle(tmp_path, "a.json", _ATTEST),
         "--judged-bundle", _bundle(tmp_path, "b.json", _SEEDED_OK), home=SAFE)

    menu = _run(tmp_path, "--menu", home=SAFE).stdout
    assert "Last check: today" in menu, menu[:400]

    trend = _run(tmp_path, "--trend", home=SAFE).stdout
    assert "Score Trend" in trend
    assert any(g in trend for g in "ABCDEF"), trend[:400]


# ------------------------------------------------ the decision, made visible

@pytest.mark.parametrize("flags,records", [
    ([], True),                                  # the default path — the original tail
    (["--full"], True),
    (["--dashboard"], True),                     # B-598: fixed here
    (["--dashboard", "--full"], True),           # B-598: the guided flow
    # Still NOT recording. Each runs a full audit and returns before the tail, exactly as
    # --dashboard did. Only --dashboard was reproduced against a live agent, so only it was
    # changed; these are pinned so the remaining holes are a visible decision rather than an
    # accident, and so a future fix has to come here and say so.
    (["--percentile"], False),
    (["--next"], False),
    (["--risk-paths"], False),
    (["--badge", "b.svg"], False),
    (["--html", "h.html"], False),
    (["--sarif", "s.sarif"], False),
    (["--pdf", "p.pdf"], False),
])
def test_every_mode_history_behaviour_is_pinned(tmp_path, flags, records):
    args = [str(tmp_path / f) if f.endswith((".svg", ".html", ".sarif", ".pdf")) else f
            for f in flags]
    _run(tmp_path, *args)
    assert bool(_rows(tmp_path)) is records, f"{flags} changed its history behaviour"


def test_trend_and_monitor_are_excluded_on_purpose(tmp_path):
    """C-251: these two record as part of their own job, including under --no-history, so
    they must NOT be routed through the shared gate — its docstring says so, and this is
    what would catch someone folding them in for tidiness."""
    _run(tmp_path, "--trend", "--no-history")
    assert len(_rows(tmp_path)) == 1


def test_one_run_never_records_twice(tmp_path):
    """Two write sites exist now. A path that reached both would put the same verdict in
    the chain twice and make a flat trend look like two audits."""
    _run(tmp_path, "--dashboard", "--full",
         "--attest", _bundle(tmp_path, "a.json", _ATTEST),
         "--judged-bundle", _bundle(tmp_path, "b.json", _SEEDED_OK), home=SAFE)
    assert len(_rows(tmp_path)) == 1
