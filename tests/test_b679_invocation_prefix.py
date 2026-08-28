"""CLAWSECCHECK-B-679 — the commands the tool prints have to be runnable.

Everything emitted said `clawseccheck ...`, and on a ClawHub install there is no such
command: ClawHub installs a directory and `audit.py` is the shim. Measured on a real
machine before the fix:

    $ clawseccheck --monitor --probe --exit-code --fail-on medium --data-dir ~/.clawseccheck
    CSC_RC=127

The sharp end is `--cron-recipe`, whose trigger maps any exit code outside {0, 3} to
`fire: true` — correctly, so the watch fails loud. Fed a command that cannot exist, that is
a wake-up every five minutes forever.

Offline, read-only, stdlib only. Nothing here writes outside pytest's tmp_path.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck import invocation as inv
from clawseccheck.guide import _json_inner, render_cron_recipe

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "clawseccheck"

_CONSOLE = "/usr/local/bin/clawseccheck"
_MODULE = str(PKG / "__main__.py")
_SHIM = str(REPO / "audit.py")



def _fake_install(root: Path) -> Path:
    """A directory laid out the way an install is: `audit.py` beside a `clawseccheck/`
    package. `_is_our_entry_script` requires that, and rightly — under pytest `argv[0]` is
    `<...>/pytest/__main__.py`, and an earlier version happily emitted THAT as the command
    to hand a user."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "clawseccheck").mkdir(exist_ok=True)
    shim = root / "audit.py"
    shim.write_text("", encoding="utf-8")
    return shim

@pytest.fixture()
def argv0(monkeypatch):
    """Set sys.argv[0] without disturbing the real one."""
    def _set(value):
        monkeypatch.setattr(sys, "argv", [value], raising=False)
    return _set


# ---------------------------------------------------------------- the human form


@pytest.mark.parametrize("started_as,expected", [
    (_CONSOLE, "clawseccheck"),
    (_MODULE, "python3 -m clawseccheck"),
])
def test_the_human_form_matches_how_the_user_started_it(argv0, started_as, expected):
    argv0(started_as)
    assert inv.command_prefix() == expected


def test_a_script_path_is_absolutised_for_the_human_too(argv0, monkeypatch, tmp_path):
    """`sys.argv[0]` is whatever was typed. Measured: `python3 script.py` gives
    `'script.py'` and `python3 ./script.py` gives `'./script.py'` — either would resolve
    against the reader's cwd, which is not necessarily the one they ran it from."""
    monkeypatch.chdir(tmp_path)
    _fake_install(tmp_path)
    argv0("./audit.py")
    prefix = inv.command_prefix()
    assert prefix.startswith("python3 ")
    assert os.path.isabs(prefix.split(" ", 1)[1].strip("'"))


# ---------------------------------------------------------------- the machine form


def test_the_machine_form_never_relies_on_path_or_cwd(argv0):
    """Every shape must yield something a scheduler can run with a minimal environment."""
    for started_as in (_CONSOLE, _MODULE, _SHIM, "audit.py", "", "-c"):
        argv0(started_as)
        prefix = inv.machine_command_prefix()
        head = prefix.split(" ", 1)[0].strip("'")
        assert os.path.isabs(head), f"{started_as!r} -> {prefix!r} starts with a bare name"


def test_the_machine_form_prefers_the_shim_over_the_module_form(argv0):
    """`-m clawseccheck` resolves through `sys.path`, which for a source tree means the
    CURRENT DIRECTORY — a job started from anywhere else gets ModuleNotFoundError, which
    the fail-open trigger turns into the same alarm rc=127 gave. `audit.py` locates its own
    package, so it has no such dependency. This pins the ORDERING, which is the whole point
    of the function and the one thing a reader would plausibly 'simplify'."""
    argv0(_MODULE)
    prefix = inv.machine_command_prefix()
    assert prefix.endswith("audit.py") or "audit.py'" in prefix, prefix
    assert " -m " not in prefix, prefix


def test_the_machine_form_shell_quotes_a_path_with_spaces(argv0, tmp_path):
    spaced = _fake_install(tmp_path / "my skills")
    argv0(str(spaced))
    prefix = inv.machine_command_prefix()
    assert "'" in prefix, f"an unquoted space would split the command: {prefix!r}"
    assert '"' not in prefix, "double quotes would break the JS string the CMD sits in"


# ---------------------------------------------------------------- the recipe


def test_the_recipe_carries_no_bare_console_command(argv0):
    argv0(_SHIM)
    recipe = render_cron_recipe(data_dir="~/.clawseccheck")
    for line in recipe.splitlines():
        stripped = line.strip()
        # `clawseccheck-watch` is the JOB NAME, not a command.
        assert "clawseccheck --" not in stripped, line
        assert '"Run: clawseccheck' not in stripped, line


def test_the_recipe_command_is_the_machine_form(argv0):
    argv0(_SHIM)
    recipe = render_cron_recipe(data_dir="~/.clawseccheck")
    prefix = inv.machine_command_prefix()
    assert prefix in recipe, "the trigger CMD does not use the resolved prefix"
    assert recipe.count(prefix) >= 3, "the two agentTurn messages must use it too"


def test_json_inner_escapes_a_windows_path(argv0):
    """The recipe's `message` fields are hand-built JSON. A resolved path on Windows
    carries backslashes, which are a JSON escape character — unescaped, the emitted job is
    unparseable, and the user would find that out from OpenClaw, not from us."""
    assert _json_inner(r"C:\Users\dave\audit.py") == r"C:\\Users\\dave\\audit.py"
    assert _json_inner('say "hi"') == r'say \"hi\"'


# ---------------------------------------------------------------- the standing guard


def _emitted_string_constants(path: Path):
    """Every string literal in *path* that is not a docstring.

    AST rather than grep, because the three files that legitimately mention the console
    command do it in prose — `menu.py`'s module docstring, `integrity.py`'s, and this
    module's own. A line-based guard would either flag those or need a deny-list that
    rots.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in docstrings):
            yield node.lineno, node.value


def test_no_module_emits_the_bare_console_command_again():
    """The pin the task asked for: a new emitted string must go through the resolver.

    This is the failure mode that shipped — sixteen call sites, each individually
    reasonable, none of them aware that the command they name does not exist on the
    install shape the skill actually ships in.
    """
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "invocation.py":
            continue
        for lineno, text in _emitted_string_constants(path):
            if "clawseccheck --" in text or "clawseccheck -m" in text:
                offenders.append(f"{path.relative_to(REPO)}:{lineno}: {text[:70]}")
    assert not offenders, (
        "these emit the bare console command, which does not exist on a ClawHub "
        "install — route them through invocation.cmd()/command_prefix():\n  "
        + "\n  ".join(offenders))


# ---------------------------------------------------------------- end to end


def test_the_emitted_command_runs_from_a_foreign_cwd_with_a_minimal_path(tmp_path):
    """The test the fix exists for, done the way the defect was found: run what the tool
    PRINTS, from the environment a cron job actually has. Before the fix this was 127."""
    store = tmp_path / "store"
    store.mkdir()
    recipe = subprocess.run(
        [sys.executable, str(REPO / "audit.py"), "--cron-recipe",
         "--data-dir", str(store)],
        cwd=REPO, capture_output=True, text=True, timeout=600).stdout
    # NOTE ON SPEED: conftest.py redirects $HOME to a throwaway directory (B-519), so the
    # audit this launches has almost nothing to scan and finishes in well under a second —
    # against ~6 s on a real home. That is correct and must stay: the property under test
    # is that the emitted command is FOUND and executes (rc != 127), not how much it scans.
    line = next(ln for ln in recipe.splitlines() if "const CMD = " in ln)
    # The FIRST closing delimiter, not the last: the CMD is one escaped JS string on a
    # line that goes on to contain several more, and `rsplit` swallowed all of them.
    command = line.split('const CMD = \\"', 1)[1].split('\\"', 1)[0]
    assert "audit.py" in command or os.path.isabs(command.split(" ", 1)[0])

    run = subprocess.run(["sh", "-c", command], cwd="/", capture_output=True, text=True,
                         env={"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"]},
                         timeout=900)
    assert "CSC_RC=" in run.stdout, run.stdout + run.stderr
    rc = int(run.stdout.split("CSC_RC=")[1].split()[0])
    assert rc in (0, 3), f"the emitted probe exited {rc}; 127 is the defect this pins"


def test_the_printed_command_never_carries_the_username(argv0, monkeypatch, tmp_path):
    """These strings are pasted into chat. An absolute path under `/home/<name>` carries
    the operator's OS username — the leak B-381 fixed for the dashboard card, and what
    CLAUDE.md section 8 forbids in anything pasteable. A path under the home renders `~/`,
    which every consumer expands, including the `sh -c` a scheduler's exec tool runs."""
    home = tmp_path / "home"
    shim = _fake_install(home / "skills")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    argv0(str(shim))
    for prefix in (inv.command_prefix(), inv.machine_command_prefix()):
        assert str(home) not in prefix, prefix
        assert "~/skills/audit.py" in prefix, prefix


def test_a_path_outside_the_home_stays_absolute(argv0, monkeypatch, tmp_path):
    """Anti-vacuity for the test above: the tilde is a home-relative rendering, not a
    blanket rewrite, and a shim installed system-wide must still be addressable."""
    outside = tmp_path / "opt" / "clawseccheck"
    shim = _fake_install(outside)
    monkeypatch.setenv("HOME", str(tmp_path / "elsewhere"))
    argv0(str(shim))
    assert str(shim) in inv.command_prefix()


def test_a_script_that_is_not_ours_is_never_adopted_as_the_command(argv0, tmp_path):
    """The regression the suite caught, pinned.

    The first version tested only `argv[0].endswith(".py")`. Run under pytest that is
    `<...>/pytest/__main__.py`, and the tool cheerfully printed
    `python3 /usr/lib/python3/dist-packages/pytest/__main__.py --advise ...` as the command
    to hand a user — three existing tests failed on it, which is the only reason it did not
    ship. Any host that starts this tool from a script of its own would have got the same.
    """
    foreign = tmp_path / "someone-elses.py"
    foreign.write_text("", encoding="utf-8")
    for impostor in (str(foreign), "/usr/lib/python3/dist-packages/pytest/__main__.py"):
        argv0(impostor)
        for prefix in (inv.command_prefix(), inv.machine_command_prefix()):
            assert impostor not in prefix, prefix
        # And it must still produce something usable rather than giving up.
        assert inv.command_prefix()
