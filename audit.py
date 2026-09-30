#!/usr/bin/env python3
"""ClawSecCheck - bundled-skill entrypoint: `python3 {baseDir}/audit.py [...]`.

This is a thin shim so the OpenClaw skill can run ClawSecCheck without installing it.
The real CLI lives in `clawseccheck/cli.py` (also exposed as the `clawseccheck` command
and `python -m clawseccheck` when pip/pipx-installed). Read-only, stdlib-only.
"""
# C-637: this guard must run before ANY other import. Python puts this file's directory
# at the front of sys.path, so an importable file dropped beside audit.py (json.py, re.py,
# sitecustomize.py, ...) is imported ahead of the standard library, and neither
# --verify-self (which digests clawseccheck/ only) nor the listed-file compare sees it.
# `from pathlib import Path` alone imports `re`, so the guard may use `os` and `sys` and
# nothing else (both are already loaded before a script starts). The same rule lives in
# clawseccheck/integrity.py (bundle_root_extras) for --verify-self; a test pins the two.
import os
import sys

_C637_ALLOWED = frozenset(("audit.py", "conftest.py", "clawseccheck", "__pycache__"))
_C637_SUFFIXES = (".py", ".pyc", ".pyw", ".pyd", ".so", ".pth")


def _bundle_extras(root):
    """Importable entries in `root` besides the shim and the package. os-only on purpose."""
    found = []
    for name in sorted(os.listdir(root)):  # OSError propagates to the caller
        if name in _C637_ALLOWED:
            continue
        low = name.lower()
        if low.endswith(_C637_SUFFIXES) or low.startswith(("sitecustomize", "usercustomize")):
            found.append(name)  # file OR symlink (dangling too): name-based
            continue
        path = os.path.join(root, name)
        if os.path.isdir(path):  # follows symlinks: a linked dir is importable
            try:
                inner = os.listdir(path)
            except OSError:
                continue
            if any(n.startswith("__init__.") and n.lower().endswith(_C637_SUFFIXES)
                   for n in inner):
                found.append(name + "/")
    return found


_C637_ROOT = os.path.dirname(os.path.realpath(__file__))
try:
    _C637_EXTRAS = _bundle_extras(_C637_ROOT)
except OSError:
    _C637_EXTRAS = None  # cannot list the bundle root: cannot rule strays out
if _C637_EXTRAS is None or _C637_EXTRAS:
    # ascii() renders an attacker-chosen file name without letting it inject terminal
    # escapes; the list is capped and the cap is stated, not silent.
    if _C637_EXTRAS is None:
        _c637_msg = ["clawseccheck: refusing to run - could not list " + ascii(_C637_ROOT)
                     + ", so a stray importable file cannot be ruled out."]
    else:
        _c637_msg = ["clawseccheck: refusing to run - importable file(s) beside audit.py in "
                     + ascii(_C637_ROOT) + ":"]
        _c637_msg.extend("  " + ascii(_n) for _n in _C637_EXTRAS[:10])
        if len(_C637_EXTRAS) > 10:
            _c637_msg.append("  (and %d more)" % (len(_C637_EXTRAS) - 10))
    _c637_msg.append("A stray module here is imported ahead of the Python standard library "
                     "every time this")
    _c637_msg.append("shim runs, and --verify-self does not hash it. Nothing was imported "
                     "or run.")
    _c637_msg.append("Remove the listed entries or reinstall the skill from a clean copy, "
                     "then run again.")
    _c637_msg.append("If you did not put them there, treat this install as compromised.")
    sys.stderr.write("\n".join(_c637_msg) + "\n")
    raise SystemExit(2)

from pathlib import Path  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))

# B-775: this shim is the documented way to run a ClawHub-installed skill (SKILL.md
# tells the agent to run `python3 {baseDir}/audit.py`), so the import below loads the
# `clawseccheck` package straight out of the ClawHub-managed install directory
# (`~/.openclaw/workspace/skills/clawseccheck/`) rather than from an installed
# distribution. Without this guard CPython writes `__pycache__/*.pyc` next to those
# sources on every run, which changes the installed file tree and makes OpenClaw's own
# updater classify the skill as locally modified (`openclaw skills update clawseccheck`
# then refuses with "has local file changes" until a `--force`, which reverts on the
# next run). Must be set before the package is ever imported, or the first import below
# already writes the cache this line exists to prevent.
sys.dont_write_bytecode = True

from clawseccheck.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
