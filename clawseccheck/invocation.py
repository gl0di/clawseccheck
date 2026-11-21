"""How to invoke this tool again - resolved from how it was actually started.

B-679. Everything the tool printed said `clawseccheck ...`, and on a ClawHub install there
is no such command: ClawHub installs a DIRECTORY, and `audit.py` is the shim that exists for
exactly that reason. Measured on a real machine:

    $ clawseccheck --monitor --probe --exit-code --fail-on medium --data-dir ~/.clawseccheck
    CSC_RC=127

`[project.scripts]` only produces a binary under pip/pipx. `SKILL.md` correctly tells the
agent `python3 {baseDir}/audit.py`, and the 16 emitted command strings did not know that.

The sharp end is not the typo. `--cron-recipe` prints a job the agent installs VERBATIM, and
its trigger maps any exit code outside {0, 3} to `fire: true` - deliberately, so the watch
fails loud rather than silent. With rc=127 that is a wake-up every five minutes, forever,
about a probe that never ran. The fail-open design is right; it was being fed a command that
could not exist.

## Two forms, because two readers

`command_prefix()` is for a human copying a line out of a report into their own shell.
`machine_command_prefix()` is for a command this tool WRITES INTO a scheduled job, and it
differs in two ways that both come from the same fact - a cron job inherits neither the
user's shell nor their cwd:

  * the interpreter is `sys.executable`, absolute, not the word `python3`. A cron job's PATH
    really is minimal; `monitordims/_install.py` already records `env -i PATH=/usr/bin:/bin`
    failing to find the openclaw the same machine resolves interactively.
  * every path is absolutised and shell-quoted. `sys.argv[0]` is whatever the user typed -
    measured: `python3 script.py` gives `'script.py'`, and `python3 ./script.py` gives
    `'./script.py'`. Either would resolve against the job's cwd, not the user's.

## The shapes, measured rather than assumed

    python3 -m clawseccheck   ->  argv[0] = '<...>/clawseccheck/__main__.py'
    python3 audit.py          ->  argv[0] = 'audit.py'         (relative, as typed)
    python3 ./audit.py        ->  argv[0] = './audit.py'
    clawseccheck              ->  argv[0] = '<...>/bin/clawseccheck'

## B-776: a second reader for `_display_path`, with the opposite need

`display_path_for_delivery()` below exists because `_display_path`'s `~`-collapse - right
for a human's shell - is wrong for a `MEDIA:<path>` line emitted from inside an OpenClaw
sandbox: the gateway (not the sandboxed shell) expands that `~` using the HOST's real
home, producing a path outside the sandbox root that `assertSandboxPath` then rejects.
The caller (`cli.py`) decides *sandboxed* from `ctx.sandboxed` (collector.py); this module
still imports nothing from the package - it stays a leaf, the sandboxed/not choice arrives
as a plain bool.

Read-only, stdlib only. A LEAF: imports nothing from the package.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import sys
from pathlib import Path
from . import pathprobe

#: The console-script name declared in `pyproject.toml` `[project.scripts]`.
_CONSOLE_NAME = "clawseccheck"

#: The bundled-skill entrypoint, next to the package directory. Named here rather than
#: guessed at each call site, and only ever used as a FALLBACK - the resolved `argv[0]` is
#: better evidence than any path we reconstruct.
_SHIM_NAME = "audit.py"


def _argv0() -> str:
    argv = getattr(sys, "argv", None)
    first = argv[0] if isinstance(argv, (list, tuple)) and argv else ""
    return first if isinstance(first, str) else ""


def _looks_like_console_script(path: str) -> bool:
    """True when argv[0] is the installed console script rather than a source file.

    The suffix test matters: a directory named `clawseccheck/` holding `__main__.py` also
    ends in that name, and a source file called `clawseccheck.py` is not the binary either.
    """
    if not path:
        return False
    name = os.path.basename(path)
    return name in (_CONSOLE_NAME, _CONSOLE_NAME + ".exe")


def _is_module_form(path: str) -> bool:
    """True when started as `python -m clawseccheck`."""
    if not path.endswith("__main__.py"):
        return False
    return os.path.basename(os.path.dirname(path)) == _CONSOLE_NAME


def _is_our_entry_script(path: str) -> bool:
    """True only when *path* is plausibly THIS tool's entry script.

    A bare `argv[0].endswith(".py")` test is not enough, and the suite proved it: run under
    pytest, `sys.argv[0]` is `<...>/pytest/__main__.py`, and the first version of this
    module happily emitted `python3 /usr/lib/python3/dist-packages/pytest/__main__.py
    --advise ...` as the command to hand a user. Any host that starts this tool from a
    script of its own would have got the same. So the path has to be OURS: the shim sitting
    beside the package, or a file inside the package itself.
    """
    if not path.endswith(".py"):
        return False
    try:
        resolved = Path(_resolve(path))
        pkg = Path(__file__).resolve().parent
    except OSError:
        return False
    if resolved == pkg.parent / _SHIM_NAME:
        return True
    if resolved.name == _SHIM_NAME and pathprobe.is_dir(resolved.parent / _CONSOLE_NAME):
        # A shim beside a `clawseccheck/` package that is not the one we were imported
        # from - an installed skill running a checkout, say. Still ours.
        return True
    try:
        return pkg in resolved.parents
    except (OSError, ValueError):
        return False


#: pip's `#!/bin/sh` trampoline line, written when the interpreter path is long or has spaces.
_EXEC_TRAMPOLINE_RE = re.compile("^'''exec'\\s+(?:\"([^\"]+)\"|(\\S+))")


def _console_script_interpreter(script: str) -> "str | None":
    """The interpreter a console script runs, read from its shebang; None when that cannot
    be read (no `#!`: a Windows `.exe` launcher or another binary).

    Handles the three shapes pip writes: `#!/abs/python`, `#!/usr/bin/env python3` (resolved
    on PATH the way the kernel would), and the `#!/bin/sh` trampoline pip uses for a long or
    space-containing interpreter path (an `exec "/abs/python" "$0" "$@"` line after it).
    """
    try:
        with open(script, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if not head.startswith(b"#!"):
        return None
    lines = head.decode("utf-8", "replace").splitlines()
    parts = lines[0][2:].split()
    if not parts:
        return None
    if os.path.basename(parts[0]) == "env":
        args = [a for a in parts[1:] if not a.startswith("-")]
        return shutil.which(args[0]) if args else None
    if os.path.basename(parts[0]) in ("sh", "bash"):
        for line in lines[1:4]:
            m = _EXEC_TRAMPOLINE_RE.match(line.strip())
            if m:
                return m.group(1) or m.group(2)
        return None
    return parts[0]


def _console_script_for_this_install() -> "str | None":
    """`shutil.which("clawseccheck")`, but only when that script runs THIS installation.

    B-1115: a console script on PATH can belong to a different install - a pipx copy of an
    older release beside a source checkout, say - and a job this tool writes for a scheduler
    would then run that other version, not the one that wrote it. So the script is used only
    when its interpreter belongs to the running environment: the interpreter's prefix (the
    directory above its `bin/`) equals `sys.prefix`. Compared as plain paths, never
    symlink-resolved: a venv's `bin/python` usually links to the system interpreter, and
    resolving would make every venv look like the system one. When the interpreter cannot
    be read (a Windows `.exe` launcher), the script is trusted as before - there is no
    evidence it belongs elsewhere.
    """
    found = shutil.which(_CONSOLE_NAME)
    if not found:
        return None
    interp = _console_script_interpreter(found)
    if interp is None:
        return found
    prefix = os.path.dirname(os.path.dirname(os.path.abspath(interp)))
    here = os.path.abspath(sys.prefix)
    same = os.path.normcase(os.path.normpath(prefix)) == os.path.normcase(os.path.normpath(here))
    return found if same else None


def _shim_beside_the_package() -> "str | None":
    """The bundled `audit.py`, if this package is laid out as an installed skill."""
    candidate = Path(__file__).resolve().parent.parent / _SHIM_NAME
    try:
        return str(candidate) if pathprobe.is_file(candidate) else None
    except OSError:
        return None


def _resolve(path: str) -> str:
    """Absolutise without requiring the file to exist - `resolve()` is enough, and
    `strict=True` would turn a moved-but-still-runnable install into an exception."""
    try:
        # C-682: `os.path.realpath` never raises on a symlink loop, where `Path.resolve` raises RuntimeError on 3.12 and returns on 3.14.
        return os.path.realpath(path)
    except OSError:
        return os.path.abspath(path)


def _display_path(path: str) -> str:
    """An absolute path rendered for a command line, with the username removed.

    A path under the user's home becomes `~/rest`. That is not cosmetic: these strings go
    into the report's "what you can do next" and into the cron recipe, both of which users
    paste into a chat channel, and an absolute path under `/home/<name>` carries the
    operator's OS username -- the exact leak B-381 fixed for the dashboard card, and what
    CLAUDE.md section 8 forbids in anything pasteable.

    `~` survives because every consumer expands it: the shell the user types into, and
    `sh -c`, which is what a scheduler's exec tool runs. The recipe already relies on this
    for `--data-dir ~/.clawseccheck`.

    Quoting is applied to the REMAINDER only. `shlex.quote("~/x")` returns `'~/x'`, and a
    quoted tilde is a literal directory named `~` -- so quoting the whole thing would trade
    the leak for a command that cannot run.
    """
    resolved = _resolve(path)
    try:
        home = str(Path.home().resolve())
    except (OSError, RuntimeError):
        return shlex.quote(resolved)
    if home and home != os.sep and (resolved == home or resolved.startswith(home + os.sep)):
        rest = resolved[len(home):].lstrip(os.sep)
        return "~/" + shlex.quote(rest) if rest else "~"
    return shlex.quote(resolved)


def display_path_for_delivery(path: str, *, sandboxed: bool) -> str:
    """Path rendering for a string that LEAVES the process - a ``MEDIA:<path>`` line or an
    attach note - where the host and the sandboxed case need opposite treatment (B-776).

    Host (``sandboxed=False``): byte-identical to `_display_path` - collapse to ``~/...``,
    because a human types or pastes this string, and a bare absolute path under
    ``/home/<name>`` leaks the OS username (B-381).

    Sandboxed: the opposite is true, for two independent reasons. First, ``~`` in a
    ``MEDIA:`` line is expanded by the OPENCLAW GATEWAY, not by the sandboxed shell - and
    the gateway's own ``os.homedir()`` is the REAL HOST home, not the container's
    ``/workspace``. A sandboxed run that still collapsed to ``~/...`` would have the
    gateway re-expand it to a path OUTSIDE the sandbox root, and
    ``assertSandboxPath`` rejects it ("Path escapes sandbox root") - confirmed in a real
    transcript as ``attachment_error code=delivery-failed``. Second, there is no username
    to leak here in the first place: a sandboxed path reads ``/workspace/...``, never
    ``/home/<real-name>/...``, so returning it absolute costs nothing B-381 cared about.
    Never switches the HOST case to absolute - that would reopen B-381/B-757 for no
    sandboxed gain.
    """
    if sandboxed:
        return _resolve(path)
    return _display_path(path)


def command_prefix() -> str:
    """What to put in front of a flag so a HUMAN can run it in their own shell.

    Returns `clawseccheck`, `python3 -m clawseccheck`, or `python3 <absolute audit.py>`.
    The interpreter stays the readable word `python3` here: this string is read and typed
    by a person whose PATH does have it, and `sys.executable` would be an unreadable
    absolute path in the middle of a report. `machine_command_prefix()` is the one that
    cannot make that assumption.
    """
    argv0 = _argv0()
    if _looks_like_console_script(argv0):
        return _CONSOLE_NAME
    if _is_module_form(argv0):
        return "python3 -m " + _CONSOLE_NAME
    if _is_our_entry_script(argv0):
        return "python3 " + _display_path(argv0)
    # argv[0] told us nothing usable - an embedding host, or a frozen build. Prefer a
    # console script that DEMONSTRABLY exists over one we hope is installed; only then
    # fall back to the shim, and only then to the bare name.
    if _console_script_for_this_install():
        return _CONSOLE_NAME
    shim = _shim_beside_the_package()
    if shim:
        return "python3 " + _display_path(shim)
    return _CONSOLE_NAME


def machine_command_prefix() -> str:
    """What to put in front of a flag inside a job THIS TOOL WRITES for a scheduler.

    Absolute interpreter, absolute script, both shell-quoted. Never the bare word
    `python3` and never a relative path: the job runs with a PATH and a cwd that are not
    the user's, and a command that cannot be found there is the defect this module exists
    for - one that a fail-open trigger turns into a five-minutely false alarm.
    """
    argv0 = _argv0()
    exe = shlex.quote(sys.executable or "python3")

    # A DIRECT script path is the strongest evidence there is: it is what the caller
    # actually ran, and `audit.py` locates its own package (`sys.path.insert(0, parent)`),
    # so it keeps working from a cwd that is not the user's.
    if _is_our_entry_script(argv0) and not _is_module_form(argv0):
        return exe + " " + _display_path(argv0)

    # An absolute console script needs no PATH and no cwd.
    found = _console_script_for_this_install() or (
        argv0 if _looks_like_console_script(argv0) and os.path.isabs(argv0) else None)
    if found:
        return _display_path(found)

    # The shim BEFORE `-m`, deliberately, and this ordering is the point of the function.
    # `-m clawseccheck` resolves through `sys.path`, which for a source tree means the
    # CURRENT DIRECTORY - so a job started from anywhere else gets ModuleNotFoundError,
    # which the fail-open trigger turns into the same five-minutely alarm rc=127 gave.
    # The shim has no such dependency.
    shim = _shim_beside_the_package()
    if shim:
        return exe + " " + _display_path(shim)
    if _is_module_form(argv0):
        # Nothing else resolved, so the package really is importable from somewhere
        # stable enough to have been started this way.
        return exe + " -m " + _CONSOLE_NAME
    return _CONSOLE_NAME


def cmd(args: str) -> str:
    """`command_prefix()` joined to *args* - the form nearly every call site wants."""
    return command_prefix() + " " + args if args else command_prefix()
