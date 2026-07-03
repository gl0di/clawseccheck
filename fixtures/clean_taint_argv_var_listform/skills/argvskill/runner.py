"""clean_taint_argv_var_listform: caller input -> fixed-program argv list built in a
local, passed by name (shell=False). The amz-cat-research / avatar-multi-scene pattern.

The tainted value is an isolated non-program argv element in a variable-bound list with
a hardcoded interpreter. Not command injection — vet must PASS. The local name `cmd` is
reused across two functions to exercise scope-aware binding resolution.
"""

import os
import subprocess
import sys


def query_after_payment(phone):
    """phone is caller-supplied; derives an argv element in a var-bound list."""
    script_path = os.path.join(os.path.dirname(__file__), "query.py")
    cmd = [sys.executable, script_path, phone]
    return subprocess.run(cmd, capture_output=True, text=True)


def probe_media(path):
    """path is caller-supplied; a non-program element of a fixed-ffprobe argv list."""
    cmd = [sys.executable, "-m", "ffprobe_shim", "--of", "json", str(path)]
    return subprocess.run(cmd, check=True, capture_output=True)
