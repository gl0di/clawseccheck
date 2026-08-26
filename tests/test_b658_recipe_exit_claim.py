"""B-658 — the scheduled recipe must not tell the agent that exit 0 means nothing changed.

`--cron-recipe` prints an OpenClaw `agentTurn` payload that becomes another agent's standing
orders. That payload said:

    Exit 0 means nothing changed — say nothing and stop.

which is not what exit 0 means. A bare `--exit-code` pages at HIGH and above, and the arm
that reports a check leaving PASS (`No longer passing: ...`) emits at MEDIUM unconditionally,
so the whole status-regression arm sat below the line. Measured on the tree that shipped it:
`gateway.auth.mode` token -> none printed `2 change(s) detected since last check` on screen
and exited **0** — and the agent, obeying the recipe, said nothing about the gateway losing
authentication. That is the very case B-273's source comment names as its reason to exist.

`docs/USAGE.md` described the threshold correctly the whole time. The doc and the shipped
artifact disagreed, and the artifact is the one that runs unattended.

Two kinds of guard here, and the second is the one that matters.

**The claim is derived, not spelled.** `test_the_exit_zero_sentence_names_the_same_threshold`
reads the `--fail-on` value out of the emitted command and the severity word out of the
emitted sentence and requires them to be equal. A future edit to either half alone reddens
the suite. The predecessor test asserted only that the substrings `Exit 0`..`Exit 3` were
PRESENT, which is why a false sentence shipped under a green suite.

**The behaviour is measured through the CLI, with a negative control.** The end-to-end tests
run the flags the recipe actually emits, parsed out of the recipe itself rather than
hardcoded. `test_the_previous_default_would_have_stayed_silent` runs the SAME drift under a
bare `--exit-code` and requires 0 — without it, a drift that happened to carry a HIGH alert
would satisfy the positive test while proving nothing about the fix.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.guide import render_cron_recipe

# A gateway that authenticates, and the same gateway with authentication removed. This pair
# is B-273's own stated repro ("gateway auth token->none, B32 PASS->WARN"), chosen so the
# test fails for the reason the task was filed rather than for a reason of its own.
_AUTHED = {"gateway": {"bind": "127.0.0.1:8080",
                       "auth": {"mode": "token",
                                "token": "a-very-long-token-of-32-characters"}}}
_UNAUTHED = {"gateway": {"bind": "127.0.0.1:8080", "auth": {"mode": "none"}}}


def _message() -> str:
    text = render_cron_recipe()
    job = json.loads(text[text.index("{"):text.rindex("}") + 1])
    return job["payload"]["message"]


def _emitted_argv(store: Path) -> list[str]:
    """The flags the recipe actually tells the agent to run, with the store redirected.

    Parsed out of the emitted payload rather than restated here, so these tests exercise
    whatever the recipe currently says. Restating them would let the recipe drift while the
    tests kept passing against the version this file was written for.
    """
    first = _message().splitlines()[0]
    argv = first.split("clawseccheck", 1)[1].split()
    out: list[str] = []
    skip = False
    for i, tok in enumerate(argv):
        if skip:
            skip = False
            continue
        if tok == "--data-dir":
            out += ["--data-dir", str(store)]
            skip = True
            continue
        out.append(tok)
    return out


def _write(home: Path, body: dict) -> None:
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps(body), encoding="utf-8")
    os.chmod(cfg, 0o600)


def _baseline_then_drift(tmp_path: Path) -> tuple[Path, Path]:
    """A store holding a baseline of the authed gateway, and a home that has since lost it."""
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _AUTHED)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    _write(home, _UNAUTHED)
    return home, store


# ------------------------------------------------------------------ the derived claim

def test_the_exit_zero_sentence_names_the_same_threshold_the_command_sets():
    """The sentence describing exit 0 must name the threshold the command actually sets.

    This is the guard the original lacked. Both halves are read out of the SAME emitted
    string, so they cannot drift apart: change `--fail-on` without changing the sentence (or
    the reverse) and this fails.
    """
    message = _message()
    flag = re.search(r"--fail-on\s+([a-z]+)", message)
    assert flag, f"the emitted command sets no --fail-on threshold:\n{message}"

    sentence = next(line for line in message.splitlines() if "Exit 0" in line)
    named = re.search(r"nothing at ([a-z]+) severity or above", sentence)
    assert named, (
        "the exit-0 sentence does not name a severity threshold, so it cannot be checked "
        f"against the flag:\n{sentence}")
    assert named.group(1) == flag.group(1), (
        f"the recipe sets --fail-on {flag.group(1)} but tells the agent exit 0 means "
        f"nothing at {named.group(1)} or above")


def test_the_recipe_never_claims_exit_zero_means_nothing_changed():
    """The specific false claim, pinned by its shape rather than its wording.

    Exit 0 can mean "changes were detected, journaled and printed, none of them at or above
    the threshold". Any absolute reading of exit 0 is therefore wrong, whatever the
    threshold is set to.
    """
    message = _message().lower()
    assert "nothing changed" not in message, (
        "exit 0 does not mean nothing changed — it means nothing at or above the threshold "
        "was recorded")


def test_the_recipe_says_where_the_sub_threshold_changes_went():
    """Telling the agent to stay silent is only honest if the user can still find the rest.

    Sub-threshold alerts are journaled to events.jsonl and counted by --brief; a recipe that
    said "say nothing" without naming that route would be hiding them rather than ranking
    them.
    """
    assert "--brief" in _message()


# ------------------------------------------------- what the emitted flags actually do

def test_the_emitted_flags_page_on_a_gateway_losing_authentication(tmp_path, capsys):
    """End-to-end, through the real CLI, with the flags the recipe emits.

    `gateway.auth.mode` token -> none is a real security regression that produces a MEDIUM
    `No longer passing:` alert and nothing higher. Under the flags this recipe shipped with
    it exited 0.
    """
    home, store = _baseline_then_drift(tmp_path)
    rc = main(["--monitor", "--home", str(home), *_emitted_argv(store)])
    out = capsys.readouterr().out
    assert "change(s) detected" in out, out
    assert rc == 3, (
        f"the recipe's own flags returned {rc} on a gateway that lost authentication; the "
        "agent following this recipe would have said nothing")


def test_the_previous_default_would_have_stayed_silent_on_the_same_drift(tmp_path, capsys):
    """Negative control — the reason the test above proves anything.

    The same drift under a bare `--exit-code` (threshold HIGH, unchanged and documented)
    still returns 0. If this ever returns 3, the fixture has acquired a HIGH alert and the
    positive test above has stopped testing the MEDIUM band it was written for.
    """
    home, store = _baseline_then_drift(tmp_path)
    rc = main(["--monitor", "--home", str(home), "--data-dir", str(store), "--exit-code"])
    capsys.readouterr()
    assert rc == 0, (
        f"expected the HIGH default to stay silent on this MEDIUM-only drift, got {rc} — "
        "the fixture no longer isolates the band this task is about")


def test_an_unchanged_home_does_not_page_under_the_emitted_flags(tmp_path, capsys):
    """Lowering the threshold must not turn a quiet machine into a pager.

    A monitor that alerts on a machine where nothing moved gets switched off, and a switched
    off monitor is zero coverage — which is what makes this the other half of the fix rather
    than an afterthought.
    """
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _AUTHED)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    rc = main(["--monitor", "--home", str(home), *_emitted_argv(store)])
    out = capsys.readouterr().out
    assert rc == 0, f"an unchanged home paged under the recipe's flags:\n{out}"


def test_every_flag_the_recipe_emits_is_honoured_by_monitor_mode(tmp_path, capsys):
    """A flag `--monitor` refuses is worse than one we do not ship: the CLI accepts it,
    prints a no-effect note, and the agent never learns its instruction was dropped."""
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _AUTHED)
    main(["--monitor", "--home", str(home), *_emitted_argv(store)])
    err = capsys.readouterr().err
    assert "no effect" not in err.lower(), (
        f"the recipe emits a flag --monitor does not honour:\n{err}")
