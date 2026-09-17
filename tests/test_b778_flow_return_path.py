"""B-778 — Step 5 branches were dead ends: after the live test or the capability
self-report, nothing told the agent to feed the verdict back, re-render the Dashboard
card, attach the PDF, or show the next menu. A real user session hit exactly this: the
agent ran all five layers, got a grade, and replied with a bare prose line -- no card, no
PDF, no menu -- because nothing in the shipped flow told it to produce any of the three.

Three gaps, three fixes:

* **Gap 1** (`docs/FLOW_CHOICES.md` had no return path) -- the "deeper / capability check"
  and "live test" `## Choice:` sections now each end with an explicit closing step naming
  Step 3's combined command, and instructing the agent to paste the card, attach the PDF,
  and re-render Step 4's menu -- tested below by reading the doc text directly.
* **Gap 2** (the capability branch instructed a command that cannot earn a grade) -- the
  bare `--attest` block is now followed by a sentence stating plainly that it alone never
  produces a grade, and pointing at the new closing step for when one is wanted -- tested
  below alongside Gap 1.
* **Gap 3** (the tool itself gave no hint about the next command) -- `canary.py`,
  `redteam.py` and `dryrun.py`'s own closing lines now name the feed-back command,
  dynamically via `invocation.command_prefix()` so it matches however the tool was
  actually invoked -- tested below against the real renderers, not the doc.

Gap 3's other half -- a grade-bearing `--full --json` run emitting the same deliverable
note on stderr -- landed later, once `cli.py`/`report.py` were clear of the unrelated
in-flight session that blocked it at the time (both files carried substantial
*uncommitted* changes from another session; this sweep's own file-ownership rule is to
leave such a file alone rather than risk mixing an unrelated in-flight change into this
commit). `cli.py`'s `_main` now prints the note on stderr, right after the JSON `body` is
assembled, gated on `score.graded` (only a `--full --json` run that actually reached all
five layers has a finished result worth handing back -- see the comment beside the `if
score.graded:` block in `cli.py`). Tested below by driving the real CLI as a subprocess,
over both a graded and an ungraded `--full --json` run.

Offline; reads only the bundled doc, the three harness modules' own pure renderers, and
drives the packaged CLI as a subprocess against the bundled `fixtures/home_safe`.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from clawseccheck.canary import make_canary, render_canary
from clawseccheck.dryrun import make_scenarios, render_dryrun
from clawseccheck.redteam import make_suite, render_suite

_REPO = Path(__file__).resolve().parent.parent
_FLOW_CHOICES = _REPO / "docs" / "FLOW_CHOICES.md"
_SAFE_HOME = str(_REPO / "fixtures" / "home_safe")

# Same minimal shapes tests/test_b586_graded_artifacts.py uses to reach all five layers.
_ATTEST = '{"schema": "clawseccheck-attest/1", "tools": ["read"], "network": "none"}'
_BUNDLE = ('{"liveTest": {"verdicts": [{"tool": "canary", '
           '"id": "CLAWSECCHECK-CANARY-DEADBEEFCAFE0123", "verdict": "RESISTANT"}]}}')


def _choice_section(text: str, heading_substring: str) -> str:
    """The body of one `## Choice: ...` section, up to the next `## Choice:` (or EOF)."""
    headings = list(re.finditer(r"^## Choice: .*$", text, flags=re.MULTILINE))
    for i, m in enumerate(headings):
        if heading_substring in m.group(0):
            end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
            return text[m.start():end]
    raise AssertionError(f"no '## Choice:' heading contains {heading_substring!r}")


# ──────────────────────────────────────────────── Gap 1 + Gap 2: docs/FLOW_CHOICES.md

def test_capability_choice_states_the_bare_command_cannot_grade_and_names_return_path():
    section = _choice_section(_FLOW_CHOICES.read_text(encoding="utf-8"), "capability check")

    # Gap 2: plain statement that the bare --attest command alone earns no grade.
    assert "never earns a letter grade" in section or "never earn a letter grade" in section, (
        "the capability branch no longer states plainly that the bare --attest command "
        "cannot produce a grade (Gap 2)"
    )

    # Gap 1: an explicit closing step naming Step 3's combined command.
    assert "Step 6" in section, "no closing step in the capability branch (Gap 1)"
    assert "--dashboard" in section and "--full" in section and "--attest" in section, (
        "the capability branch's closing step must name Step 3's combined command"
    )
    assert re.search(r"[Rr]e-render.*Step 4|Step 4.*menu", section), (
        "the capability branch's closing step must send the agent back to Step 4's menu"
    )
    assert "MEDIA:" in section, (
        "the closing step must repeat Step 3's PDF delivery rule (the MEDIA: directive), "
        "not just the bare command"
    )


def test_live_test_choice_names_the_return_path():
    section = _choice_section(_FLOW_CHOICES.read_text(encoding="utf-8"), "live test")

    # The branch must not simply end at --redteam any more.
    redteam_pos = section.rfind("--redteam")
    assert redteam_pos != -1
    tail = section[redteam_pos:]
    assert "liveTest" in tail, (
        "the live-test branch's closing text (after the --redteam block) must name the "
        "liveTest bucket used to feed the verdict back (Gap 1)"
    )
    assert "--dashboard" in tail and "--full" in tail and "--judged-bundle" in tail, (
        "the live-test branch's closing text must name Step 3's combined command"
    )
    assert re.search(r"[Rr]e-render.*Step 4|Step 4.*menu", tail), (
        "the live-test branch's closing text must send the agent back to Step 4's menu"
    )
    assert "MEDIA:" in tail, (
        "the closing step must repeat Step 3's PDF delivery rule, not just the bare command"
    )


def test_flow_choices_still_parses_into_the_expected_sections():
    """Non-vacuity for the two tests above: `_choice_section` must find real sections,
    not silently match nothing (a heading rename would otherwise make both tests above
    pass by finding an empty/wrong span).
    """
    text = _FLOW_CHOICES.read_text(encoding="utf-8")
    cap = _choice_section(text, "capability check")
    live = _choice_section(text, "live test")
    assert "Step 1" in cap and "Step 5" in cap
    assert "--canary" in live and "--dryrun" in live


# ───────────────────────────────────────────── Gap 3 (harness half): the tool itself

def test_canary_output_names_the_feedback_command():
    out = render_canary(make_canary("t"))
    assert "--dashboard" in out and "--full" in out
    assert "--judged-bundle" in out and "--pdf" in out
    assert "liveTest" in out


def test_redteam_output_names_the_feedback_command():
    out = render_suite(make_suite("t"))
    assert "--dashboard" in out and "--full" in out
    assert "--judged-bundle" in out and "--pdf" in out
    assert "liveTest" in out


def test_dryrun_output_names_the_feedback_command():
    out = render_dryrun(make_scenarios("t"))
    assert "--dashboard" in out and "--full" in out
    assert "--judged-bundle" in out and "--pdf" in out
    assert "liveTest" in out


def test_feedback_command_survives_ascii_mode():
    """The section-sign in "OUTPUT_SCHEMA.md §12" must fold under --ascii, not break it
    (textnorm.asciify's ASCII_MAP already covers "§" -- this pins that the new line
    actually routes through it rather than bypassing asciify with an f-string built
    after the fact).
    """
    out = render_canary(make_canary("t"), ascii_only=True)
    assert "§" not in out
    assert "--judged-bundle" in out


# ─────────────────────────────────────── Gap 3 (json half): a grade-bearing --full --json

def _run_full_json(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", _SAFE_HOME, "--full", "--json",
         "--data-dir", str(tmp_path / "state"), "--no-history", *extra],
        cwd=_REPO, capture_output=True, text=True, timeout=600)


def test_a_graded_full_json_run_emits_the_deliverable_note_on_stderr(tmp_path):
    """The headline case from the real session: an agent runs `--full --json`, reaches a
    real grade, and used to get nothing on stderr telling it to produce a card/PDF/menu.
    """
    attest = tmp_path / "a.json"
    attest.write_text(_ATTEST, encoding="utf-8")
    bundle = tmp_path / "b.json"
    bundle.write_text(_BUNDLE, encoding="utf-8")
    proc = _run_full_json(tmp_path, "--attest", str(attest), "--judged-bundle", str(bundle))
    payload = json.loads(proc.stdout)
    assert payload["graded"] is True, (
        "fixture must actually reach a grade (non-vacuity)", proc.stderr[-500:])

    assert "this JSON payload carries a finished grade" in proc.stderr
    assert "--dashboard" in proc.stderr and "--full" in proc.stderr and "--pdf" in proc.stderr
    assert "--attest" in proc.stderr and "--judged-bundle" in proc.stderr
    assert "MEDIA" in proc.stderr, "must repeat the PDF delivery rule, not just the command"
    assert "Step 4" in proc.stderr, "must send the agent back to the menu"
    # Named dynamically, the same way canary/dryrun/redteam's own closing line is (Gap 3's
    # other half) -- not hardcoded to one invocation form.
    assert proc.stderr.count("--dashboard --full --attest") == 1


def test_an_ungraded_full_json_run_emits_no_deliverable_note(tmp_path):
    """Control for the test above: a bare `--full --json` run (no --attest/--judged-bundle,
    so 2 of 5 layers never ran) must print nothing -- the note is gated on `score.graded`,
    not on `--full --json` alone, and there is no finished result yet to hand back."""
    proc = _run_full_json(tmp_path)
    payload = json.loads(proc.stdout)
    assert payload["graded"] is False, (
        "fixture must actually be ungraded (non-vacuity)", proc.stderr[-500:])

    assert "this JSON payload carries a finished grade" not in proc.stderr
