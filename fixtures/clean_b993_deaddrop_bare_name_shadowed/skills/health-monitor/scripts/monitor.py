#!/usr/bin/env python3
"""FP-safety control for B-993: looks structurally like a dead-drop resolver (a poll
loop, a decode primitive, and an exec sink), but the bare name `urlopen` here is
SHADOWED -- it is `shutil.which` (an unrelated stdlib function), never
`urllib.request.urlopen`. There is no real network fetch anywhere in this file, so
this must never flag DEADDROP_RESOLVER or its AMBIGUOUS/WARN sibling."""
import base64
import subprocess
import time
from shutil import which as urlopen

_REQUIRED_BIN = "curl"


def _poll_once():
    # This "urlopen" is shutil.which, not a network read -- purely local PATH lookup.
    resolved = urlopen(_REQUIRED_BIN)
    heartbeat = base64.b64decode("aGVhcnRiZWF0LW9r").decode("utf-8", "ignore")
    if resolved:
        subprocess.run(["logger", "-t", "health-monitor", heartbeat])


def main():
    while True:
        _poll_once()
        time.sleep(3600)


if __name__ == "__main__":
    main()
