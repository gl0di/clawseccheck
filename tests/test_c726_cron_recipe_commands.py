"""C-726 item 3: every command ``--cron-recipe`` emits names the home and the store it was given.

The backstop job's message named a second command (``--brief``) without ``--data-dir`` /
``--home``, so the scheduled brief read the default store instead of the one the recipe was
asked about. The test parses every command line the recipe prints (the two ``Run:`` lines, the
``--brief`` the backstop names, and the trigger script's probe) and RUNS each one against copies.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from clawseccheck.cli import main

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = REPO_ROOT / "fixtures" / "home_safe"


def _recipe(home: Path, store: Path) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert main(["--cron-recipe", "--home", str(home), "--data-dir", str(store)]) == 0
    return out.getvalue()


def _json_blocks(text: str) -> list:
    blocks, cur = [], None
    for line in text.splitlines():
        if line == "{":
            cur = [line]
        elif cur is not None:
            cur.append(line)
            if line == "}":
                blocks.append(json.loads("\n".join(cur)))
                cur = None
    return blocks


def _commands(text: str) -> "list[str]":
    """Every command line the recipe prints, as typed (no shell redirection)."""
    cmds = []
    for job in _json_blocks(text):
        message = job["payload"]["message"]
        cmds += re.findall(r"^Run: (.+)$", message, flags=re.M)
        cmds += re.findall(r"`([^`]* --brief[^`]*)`", message)
        script = job.get("trigger", {}).get("script")
        if script:
            literal = re.search(r'const CMD = ("(?:[^"\\]|\\.)*");', script).group(1)
            cmds.append(json.loads(literal).split(" >/dev/null")[0])
    return cmds


def _argv(cmd: str) -> "list[str]":
    return [os.path.expanduser(tok) for tok in shlex.split(cmd)]


def _flag_value(argv: "list[str]", flag: str) -> str:
    assert argv.count(flag) == 1, f"{flag} must appear exactly once in {argv}"
    return argv[argv.index(flag) + 1]


def test_the_recipe_prints_the_four_commands_it_documents(tmp_path):
    home = tmp_path / "home"
    shutil.copytree(SAFE, home)
    cmds = _commands(_recipe(home, tmp_path / "store"))
    assert len(cmds) == 4, cmds
    assert sum("--brief" in c for c in cmds) == 1
    assert sum("--probe" in c for c in cmds) == 1


def test_every_emitted_command_carries_both_home_and_data_dir(tmp_path):
    home, store = tmp_path / "my home", tmp_path / "my store"  # spaces: quoting must survive
    shutil.copytree(SAFE, home)
    for cmd in _commands(_recipe(home, store)):
        argv = _argv(cmd)
        assert _flag_value(argv, "--home") == str(home), cmd
        assert _flag_value(argv, "--data-dir") == str(store), cmd


def test_every_emitted_command_runs_against_copies_and_stays_in_the_given_store(tmp_path):
    home, store, fakehome = tmp_path / "home", tmp_path / "store", tmp_path / "fakehome"
    shutil.copytree(SAFE, home)
    fakehome.mkdir()
    cmds = _commands(_recipe(home, store))
    # Expand "~" with the REAL home (the emitted prefix is home-relative), then run with a
    # fake HOME: a command that fell back to the default store would create it there.
    argvs = [_argv(c) + ["--no-deptree", "--no-host"] for c in cmds]
    env = dict(os.environ, HOME=str(fakehome))
    # The monitor commands first (they write the store), the brief last (it reads it).
    for argv in sorted(argvs, key=lambda a: "--brief" in a):
        done = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace",
                              timeout=450, env=env, stdin=subprocess.DEVNULL)
        assert done.returncode == 0, (argv, done.returncode, done.stderr[-400:])
    assert (store / "state.json").is_file()
    assert not (fakehome / ".clawseccheck").exists()
