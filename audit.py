#!/usr/bin/env python3
"""ClawCheck — bundled-skill entrypoint: `python3 {baseDir}/audit.py [...]`.

This is a thin shim so the OpenClaw skill can run ClawCheck without installing it.
The real CLI lives in `clawcheck/cli.py` (also exposed as the `clawcheck` command
and `python -m clawcheck` when pip/pipx-installed). Read-only, stdlib-only.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from clawcheck.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
