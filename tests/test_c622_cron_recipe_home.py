"""C-622 -- `--cron-recipe` must carry `--home`, and must shell-quote what it splices.

`--cron-recipe --home /custom` was accepted silently and the emitted `--monitor` commands
carried no `--home`, so on a machine whose OpenClaw home is elsewhere the scheduled jobs took
their baseline of the default `~/.openclaw` and then reported "no drift" against it forever.
That is the false-assurance state B-781 (`--monitor` refuses to compare across a `--home`
mismatch) exists to prevent - the job never gave B-781 a home to compare.

`--data-dir` was also spliced raw into a shell command AND into two hand-built JSON string
fields AND (through the trigger script) into a JS double-quoted literal, so a space split the
argument and a quote broke the job's JSON.

There are exactly THREE places the recipe emits a `--monitor` command: the fast job's trigger
script (`const CMD`), the fast job's agent message and the backstop job's agent message.
Every test below reads all three and asserts on each, and asserts that it found three, so a
lost or a fourth site trips the suite.

Each test says which edit it fails without ("must fail before C-622"):

* `guide.py` (home / quoting not threaded): every test except the byte-identical default.
* `cli.py` (`home=args.home` not passed): `test_the_cli_passes_home_through` only - the
  others call `render_cron_recipe` directly.

Offline, read-only outside tmp_path, stdlib only, ASCII only.
"""
from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

import pytest

from clawseccheck.cli import main
from clawseccheck.guide import render_cron_recipe
from clawseccheck.monitor import _home_identity

_TRAILER_JS = [">/dev/null", "2>&1;", "echo", "CSC_RC=$?"]


def _jobs(out: str) -> list:
    """Every job the recipe emits, parsed (fast job first, backstop second)."""
    return [json.loads(b) for b in re.findall(r"^\{$.*?^\}$", out, re.S | re.M)]


def _commands(out: str) -> list[str]:
    """The three decoded `--monitor` command strings: fast message, backstop message, JS CMD."""
    jobs = _jobs(out)
    assert len(jobs) == 2, out
    fast, backstop = jobs
    cmds = []
    for job in (fast, backstop):
        first = job["payload"]["message"].splitlines()[0]
        assert first.startswith("Run: "), first
        cmds.append(first[len("Run: "):])
    m = re.search(r'const CMD = "((?:[^"\\]|\\.)*)"', fast["trigger"]["script"])
    assert m, fast["trigger"]["script"]
    cmds.append(json.loads('"' + m.group(1) + '"'))
    return cmds


def _flag_value(tokens: list[str], flag: str) -> str:
    assert tokens.count(flag) == 1, (flag, tokens)
    return tokens[tokens.index(flag) + 1]


def _write(home: Path, body: dict) -> None:
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps(body), encoding="utf-8")
    os.chmod(cfg, 0o600)


# ------------------------------------------------------------------ the bug itself

def test_a_non_default_home_reaches_every_monitor_command():
    """Must fail before C-622: the recipe emitted no `--home` at all."""
    cmds = _commands(render_cron_recipe(home="/srv/oc-alt", data_dir="/var/lib/csc"))
    assert len(cmds) == 3
    for cmd in cmds:
        tokens = shlex.split(cmd)
        assert "--monitor" in tokens, cmd
        assert _flag_value(tokens, "--home") == "/srv/oc-alt", cmd
        assert _flag_value(tokens, "--data-dir") == "/var/lib/csc", cmd


def test_the_cli_passes_home_through(capsys):
    """Must fail before the cli.py edit (guide.py alone is not enough): `--home` given on the
    command line has to reach all three commands, not just the function's default."""
    rc = main(["--cron-recipe", "--home", "/srv/oc-alt", "--data-dir", "/var/lib/csc"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("--home") == 3, out
    assert out.count("--home /srv/oc-alt") == 3, out


# ------------------------------------------------------------------ nothing else moves

def test_default_home_adds_no_flag_and_output_is_byte_identical(capsys):
    """The default recipe is a shipped artifact users have already installed: it must not
    change by a byte, and `--home` appears only when it differs from `~/.openclaw`."""
    base = render_cron_recipe()
    assert render_cron_recipe(home=None) == base
    assert render_cron_recipe(home="~/.openclaw") == base
    assert "--home" not in base
    # Pin the default literals (raw, i.e. still JSON-escaped, exactly as printed).
    assert "--fail-on medium --data-dir ~/.clawseccheck\\nExit 0" in base
    assert "--fail-on medium --data-dir ~/.clawseccheck\\nThe probe that woke you" in base
    cmds = _commands(base)
    assert len(cmds) == 3
    assert cmds[2].endswith(
        "--fail-on medium --data-dir ~/.clawseccheck >/dev/null 2>&1; echo CSC_RC=$?"), cmds[2]
    # ... and through the CLI, with and without --ascii.
    assert main(["--cron-recipe"]) == 0
    assert capsys.readouterr().out.rstrip("\n") == base.rstrip("\n")
    assert main(["--cron-recipe", "--ascii"]) == 0
    assert capsys.readouterr().out.rstrip("\n") == render_cron_recipe(ascii_only=True).rstrip("\n")


# ------------------------------------------------------------------ quoting

_HOSTILE = [
    "/var/lib/csc dir",
    "/tmp/x'; touch /tmp/pwn; echo '",
    '/tmp/a "quoted" \\dir $HOME',
    "~/my store",
    "/tmp/__FAILON__/__CSCCMD__/__STATE__",
    "/tmp/$(id)/`id`/*/-x",
]


@pytest.mark.parametrize("data_dir", _HOSTILE)
def test_a_data_dir_round_trips_through_the_shell_at_every_site(data_dir):
    """Must fail before C-622: the path was spliced raw (word-split by the shell, breaking
    the JSON on a quote, and a JS syntax error inside the trigger script)."""
    out = render_cron_recipe(data_dir=data_dir)
    assert len(_jobs(out)) == 2          # both jobs still parse: the JSON layer holds
    cmds = _commands(out)
    assert len(cmds) == 3
    for i, cmd in enumerate(cmds):
        tokens = shlex.split(cmd)
        assert _flag_value(tokens, "--data-dir") == data_dir, cmd
        assert "--home" not in tokens, cmd
        tail = tokens[tokens.index("--data-dir") + 2:]
        # No stray positional: nothing but the JS command's own redirect/echo trailer.
        assert tail == (_TRAILER_JS if i == 2 else []), (cmd, tail)
    if data_dir.startswith("~/"):
        assert "--data-dir ~/'my store'" in out      # the tilde stays unquoted so it expands


@pytest.mark.parametrize("home", ["/srv/my oc's home", '/srv/"oc" \\alt $HOME', ""])
def test_a_home_round_trips_through_the_shell_at_every_site(home):
    """Must fail before C-622. The empty string is faithfully emitted as `--home ''` (it is
    not the default); the CLI cannot produce it because an empty `--home` is falsy there."""
    out = render_cron_recipe(home=home, data_dir="/var/lib/csc dir")
    assert len(_jobs(out)) == 2
    cmds = _commands(out)
    assert len(cmds) == 3
    for i, cmd in enumerate(cmds):
        tokens = shlex.split(cmd)
        assert _flag_value(tokens, "--home") == home, cmd
        assert _flag_value(tokens, "--data-dir") == "/var/lib/csc dir", cmd
        tail = tokens[tokens.index("--data-dir") + 2:]
        assert tail == (_TRAILER_JS if i == 2 else []), (cmd, tail)


def test_a_non_ascii_path_survives_the_ascii_fold():
    """`--ascii` folds the whole recipe; a path must stay faithful and the JSON valid."""
    data_dir = "/srv/caf\u00e9 store"
    out = render_cron_recipe(ascii_only=True, data_dir=data_dir)
    assert all(ord(c) < 128 for c in out)
    for cmd in _commands(out):
        assert _flag_value(shlex.split(cmd), "--data-dir") == data_dir, cmd


# ------------------------------------------------------------------ end to end

def test_the_emitted_command_baselines_the_home_it_was_given(tmp_path):
    """The claim itself, not a string match: run the emitted backstop command and check the
    store it wrote describes the ALTERNATE home. Must fail before C-622: the emitted tokens
    carried no `--home`, so the run audited the (conftest-redirected) default home instead.
    Negative control: the same command with `--home` stripped baselines a different home."""
    alt, store = tmp_path / "alt", tmp_path / "store"
    _write(alt, {"gateway": {"bind": "127.0.0.1:8080",
                             "auth": {"mode": "token",
                                      "token": "a-very-long-token-of-32-characters"}}})
    backstop = _commands(render_cron_recipe(home=str(alt), data_dir=str(store)))[1]
    tokens = shlex.split(backstop)
    argv = tokens[tokens.index("--monitor"):]
    assert main(argv) in (0, 3)
    state = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert state["home_digest"] == _home_identity(alt)[0]

    stripped = list(argv)
    i = stripped.index("--home")
    del stripped[i:i + 2]
    stripped[stripped.index("--data-dir") + 1] = str(tmp_path / "store-default")
    assert main(stripped) in (0, 3)
    other = json.loads((tmp_path / "store-default" / "state.json").read_text(encoding="utf-8"))
    assert other["home_digest"] != _home_identity(alt)[0]
