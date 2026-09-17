#!/usr/bin/env python3
"""ClawSecCheck — bundled-skill entrypoint: `python3 {baseDir}/audit.py [...]`.

This is a thin shim so the OpenClaw skill can run ClawSecCheck without installing it.
The real CLI lives in `clawseccheck/cli.py` (also exposed as the `clawseccheck` command
and `python -m clawseccheck` when pip/pipx-installed). Read-only, stdlib-only.
"""
import sys
from pathlib import Path

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
