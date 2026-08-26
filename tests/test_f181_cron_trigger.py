"""F-181 — the emitted cron recipe carries a `trigger.script`, so the agent is woken only
on drift and the alert window drops from six hours to the poll interval.

The recipe is a **shipped artifact that instructs another agent**, so these tests treat it
as executable rather than as prose. B-658 is the precedent: the recipe's payload told the
agent "exit 0 means nothing changed", which was false, and nobody noticed because the text
was only ever read.

Grounded against the installed OpenClaw `2026.7.1-2`, not invented:

- `runHeadless` resolves to `runCodeModeScriptHeadless` (`server-cron-Cwg2hJro.js:3647`),
  an isolated **quickjs-wasi** sandbox. Its own tool description states that Node modules
  and `require`/`import` are NOT available, and that any shell action must go through
  `tools.search` / `tools.describe` / `tools.call` (`code-mode-D5mNEiYV.js:731`).
- The script must return an object carrying a boolean `fire` (`:3572`, `:3607`).
- Budget: `HEADLESS_TRIGGER_TOOL_BUDGET = 5` tool calls (`:3464`) and
  `HEADLESS_TRIGGER_WALL_CLOCK_MS = 30000` (`:3463`).
- **A trigger that errors or times out is treated as `fire: false`** (`:2205-2209`).

That last one is why the script fails OPEN and why the recipe still ships an unconditional
backstop job. A security watch that goes quiet on error is indistinguishable from one with
nothing to report, and the platform's default is exactly that. The script covers the errors
it can see; only the second job covers being killed or timing out.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import re

from clawseccheck.guide import (
    _CRON_FAIL_ON,
    _CRON_POLL_MS,
    render_cron_recipe,
)

_BLOCK = re.compile(r"^\{$.*?^\}$", re.S | re.M)


def _jobs() -> list:
    return [json.loads(b) for b in _BLOCK.findall(render_cron_recipe())]


def test_the_recipe_emits_two_valid_json_jobs():
    """A malformed job is not a documentation defect, it is an artifact that cannot be
    pasted. Parsed, not pattern-matched."""
    jobs = _jobs()
    assert len(jobs) == 2, [j.get("name") for j in jobs]
    for job in jobs:
        assert job["payload"]["kind"] == "agentTurn"
        assert job["schedule"]["kind"] == "every"
        assert job["sessionTarget"] == "isolated"


def test_only_the_fast_job_is_trigger_gated():
    """The backstop must stay unconditional. If a future edit put a trigger on both, the
    whole fail-closed problem would come back with nothing covering it."""
    fast, backstop = _jobs()
    assert "trigger" in fast, fast
    assert "trigger" not in backstop, backstop
    assert fast["schedule"]["everyMs"] == _CRON_POLL_MS
    assert backstop["schedule"]["everyMs"] > fast["schedule"]["everyMs"]


def test_the_trigger_polls_with_probe_not_an_ordinary_run():
    """The entire point. A trigger that polled with a plain `--monitor` would RECORD the
    drift, and the agent turn it then woke would compare against the advanced baseline and
    find nothing — the poll would eat exactly what it exists to detect."""
    script = _jobs()[0]["trigger"]["script"]
    command = re.search(r'const CMD = "(.*?)";', script).group(1)
    assert "--probe" in command, command
    assert "--monitor" in command and "--exit-code" in command, command
    assert f"--fail-on {_CRON_FAIL_ON}" in command, command


def test_the_exit_code_is_read_from_output_not_from_a_guessed_field():
    """What `tools.call` hands back for an exec tool is a shape this project has NOT
    pinned. Reading `result.exitCode` would be a fabricated field path that fails silently
    when wrong; `echo CSC_RC=$?` puts the answer in stdout, which every exec tool returns
    in some readable form."""
    script = _jobs()[0]["trigger"]["script"]
    assert "CSC_RC=$?" in script, script
    assert "CSC_RC=(" in script, "the script must parse its own marker back out"
    assert "exitCode" not in script, "a guessed result field crept back in"


def test_the_script_fails_open_on_every_path_it_can_see():
    """OpenClaw turns a trigger error into `fire: false`. Every branch this script can
    reach must therefore fire unless it positively established that nothing changed.

    Counted rather than eyeballed: exactly one `fire: false`, and it is the one guarded by
    a zero exit code."""
    script = _jobs()[0]["trigger"]["script"]
    assert script.count("fire: false") == 1, script
    assert re.search(r"rc === 0\) return \{ fire: false \}", script), script
    assert script.count("fire: true") >= 4, script
    assert "catch (e)" in script, "an uncaught throw becomes a silent no-fire"


def test_the_script_uses_only_what_the_sandbox_provides():
    """quickjs-wasi with no Node modules and no require/import. A script reaching for
    `require`, `process` or `fetch` would throw on the first poll and — because a throwing
    trigger is a silent one — the watch would simply never fire again."""
    script = _jobs()[0]["trigger"]["script"]
    for forbidden in ("require(", "import ", "process.", "fetch(", "child_process"):
        assert forbidden not in script, (forbidden, script)
    assert "tools.search(" in script and "tools.call(" in script


def test_the_script_stays_inside_the_tool_budget():
    """`HEADLESS_TRIGGER_TOOL_BUDGET` is 5. This script needs two, and the headroom is not
    an invitation — a poll that exhausts the budget fails, and a failed trigger is
    silent."""
    script = _jobs()[0]["trigger"]["script"]
    calls = script.count("await tools.")
    assert calls <= 5, calls
    assert calls >= 2, "a poll that calls nothing cannot have measured anything"


def test_the_recipe_discloses_that_a_failed_trigger_is_silent():
    """The single most important sentence in the artifact. Without it a reader assumes the
    fast job is sufficient and drops the backstop, which converts a platform default into
    an undetected outage of their security watch."""
    out = render_cron_recipe()
    assert "do not fire" in out, out
    assert "SILENT" in out, out
    assert "backstop" in out.lower(), out


def test_the_woken_turn_is_told_the_probe_did_not_record():
    """The agent this wakes must know it is the run that records, and must not treat a
    resolved change as nothing worth saying."""
    message = _jobs()[0]["payload"]["message"]
    assert "did NOT" in message and "record" in message, message
    assert "Exit 0 here" in message, message


def test_the_recipe_is_deterministic():
    """No clock, no randomness — the same input prints the same text, so a diff of the
    recipe is a real change and not noise."""
    assert render_cron_recipe() == render_cron_recipe()
    assert render_cron_recipe(ascii_only=True) == render_cron_recipe(ascii_only=True)


def test_the_data_dir_reaches_both_the_probe_and_the_woken_run():
    """A probe pointed at a different store than the run it wakes would compare against a
    baseline nobody else advances, and would fire forever."""
    out = render_cron_recipe(data_dir="/tmp/custom-store")
    fast = json.loads(_BLOCK.findall(out)[0])
    assert "/tmp/custom-store" in fast["trigger"]["script"]
    assert "/tmp/custom-store" in fast["payload"]["message"]


def test_the_ascii_form_is_still_valid_json():
    """`--ascii` folds the prose; it must not fold the artifact into something unpasteable."""
    out = render_cron_recipe(ascii_only=True)
    blocks = _BLOCK.findall(out)
    assert len(blocks) == 2
    for b in blocks:
        json.loads(b)
