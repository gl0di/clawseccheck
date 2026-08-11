"""F-172 — print an OpenClaw cron job that runs the watch on a schedule.

"Watch continuously and tell me when something is wrong" needs periodicity and delivery.
This tool supplies neither and must not: a resident daemon breaks the skill shape and any
delivery of our own would be a network call. OpenClaw already provides both, so the right
move is to hand the user's agent a job it can create with its own `cron` tool.

Two properties this file exists to hold.

**It prints and does nothing else.** No file written, no config edited, no `openclaw cron`
invoked. A security tool that installs a recurring job as a side effect of being asked how
to install one has helped itself to a decision that was never offered.

**Every field name is grounded in the installed dist, not invented.** Golden Rule #4 makes
a fabricated field path a defect rather than a typo, so the schema keys are pinned here
against `cron-tool-C9qaFGtt.js`'s documented job shape. The `trigger` block is deliberately
ABSENT and that absence is pinned too — see the module comment in `guide.py` for the trace
showing `trigger.script` is JavaScript in a QuickJS sandbox, and for the one question that
remains unanswered about it.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import re

from clawseccheck.guide import render_cron_recipe

# Grounded against cron-tool-C9qaFGtt.js:830-875. A key not in this set is either invented
# or newly grounded — and if it is the latter, this set is where that gets recorded.
_JOB_KEYS = {"name", "schedule", "payload", "delivery", "sessionTarget"}
_SCHEDULE_KINDS = {"at", "every", "cron", "on-exit"}
_PAYLOAD_KINDS = {"systemEvent", "agentTurn"}
_DELIVERY_MODES = {"none", "announce", "webhook"}


def _job(text: str) -> dict:
    """The JSON object out of the printed recipe."""
    start = text.index("{")
    end = text.rindex("}") + 1
    return json.loads(text[start:end])


def test_the_emitted_job_uses_only_grounded_keys():
    job = _job(render_cron_recipe())
    assert set(job) <= _JOB_KEYS, set(job) - _JOB_KEYS
    assert job["schedule"]["kind"] in _SCHEDULE_KINDS
    assert job["payload"]["kind"] in _PAYLOAD_KINDS
    assert job["delivery"]["mode"] in _DELIVERY_MODES
    assert set(job["schedule"]) <= {"kind", "everyMs", "anchorMs"}
    assert set(job["delivery"]) <= {"mode", "channel", "to"}


def test_it_emits_valid_json():
    """The whole value is that it can be pasted. A recipe that does not parse is a recipe
    the agent has to repair before it can act on it."""
    assert isinstance(_job(render_cron_recipe()), dict)


def test_no_trigger_block_is_emitted():
    """Pinned as a DECISION, not an omission. `trigger.script` is grounded as JavaScript in
    a QuickJS/WASI sandbox with a 30s and five-tool-call budget; what is not grounded is
    whether that sandbox can run an external binary and read its exit status, without which
    a trigger cannot consult `--exit-code` at all. Emitting one anyway would be a guess
    about a field's contract."""
    assert "trigger" not in _job(render_cron_recipe())


def test_the_message_tells_the_agent_what_each_exit_code_means():
    """The job's value depends on the agent reading the code correctly, and the codes are
    not self-evident: 3 is drift, 1 is a MORE urgent failure to establish monitoring, and 2
    is argparse's usage error rather than any finding."""
    message = _job(render_cron_recipe())["payload"]["message"]
    for code in ("0", "1", "2", "3"):
        assert f"Exit {code}" in message or f"Exit {code} " in message, code
    assert "--exit-code" in message
    assert "not established" in message.lower()


def test_every_flag_in_the_message_is_a_real_flag(capsys):
    """A recipe that names a flag we do not ship is worse than no recipe.

    Replaces a weaker sibling that asserted `main(["--help"]) == 0 or True` — a condition
    no implementation can fail. Third time today I have written that shape; the suite
    caught it each time, which is the argument for the suite rather than for me.
    """
    import contextlib
    import io

    from clawseccheck.cli import main
    buf = io.StringIO()
    with contextlib.suppress(SystemExit), contextlib.redirect_stdout(buf):
        main(["--help"])
    help_text = buf.getvalue() + capsys.readouterr().out
    message = _job(render_cron_recipe())["payload"]["message"]
    for flag in sorted(set(re.findall(r"--[a-z-]+", message))):
        assert flag in help_text, f"{flag} is named in the recipe but not in --help"
    assert {"--monitor", "--exit-code", "--data-dir"} <= set(
        re.findall(r"--[a-z-]+", message))


def test_the_data_dir_is_reflected_in_both_the_command_and_the_disclosure():
    """The user is told which directory the job will write to before it exists — consent
    needs the real path, not the default one."""
    out = render_cron_recipe(data_dir="/srv/watch")
    assert "/srv/watch" in _job(out)["payload"]["message"]
    assert "/srv/watch" in out


def test_it_discloses_what_the_job_will_write_locally():
    out = render_cron_recipe()
    assert "three local files" in out
    assert "Nothing leaves the machine" in out


def test_output_is_deterministic():
    """No clock, no randomness — two calls are byte-identical, so the recipe can be
    diffed, tested and pasted twice without surprise."""
    assert render_cron_recipe() == render_cron_recipe()


def test_ascii_mode_leaves_no_unicode():
    out = render_cron_recipe(ascii_only=True)
    out.encode("ascii")  # raises if anything survived the fold
    assert isinstance(_job(out), dict), "the JSON must survive the fold too"


def test_it_writes_nothing_anywhere(tmp_path, monkeypatch):
    """Prints only, by construction. Asserted by running it inside an empty directory with
    HOME redirected and observing that nothing appeared in either."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.chdir(tmp_path)
    before = {p.name for p in tmp_path.iterdir()}
    render_cron_recipe()
    assert {p.name for p in tmp_path.iterdir()} == before
    assert not any(fake_home.iterdir())


def test_the_cli_flag_prints_and_exits_clean(capsys, tmp_path, monkeypatch):
    from clawseccheck.cli import main
    monkeypatch.chdir(tmp_path)
    rc = main(["--cron-recipe"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "clawseccheck-watch" in out
    assert not any(tmp_path.iterdir()), "the flag must not create anything"


def test_the_cli_flag_honours_the_data_dir(capsys):
    from clawseccheck.cli import main
    main(["--cron-recipe", "--data-dir", "/tmp/elsewhere"])
    assert "/tmp/elsewhere" in capsys.readouterr().out
