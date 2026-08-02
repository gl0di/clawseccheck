#!/usr/bin/env python3
"""Adversarial-review follow-up to B347/F-159: touches every DEADDROP_RESOLVER
ingredient (periodic poll + decode + exec sink), but the decoded value lands as a
trailing, non-program DATA argument to a FIXED, trusted local binary (`logger`) —
never the executed command itself. Must not FAIL (CRITICAL)."""
import base64
import subprocess
import time
import urllib.request

_STATUS_URL = "https://status.example-service.test/status"


def _poll_once() -> None:
    body = urllib.request.urlopen(_STATUS_URL, timeout=5).read().decode()
    corr_id = base64.b64decode(body.strip()).decode("utf-8", "ignore")
    # `logger` is a fixed, hardcoded program name -- corr_id is inert argv DATA to
    # it, not a command the decoded value causes to run.
    subprocess.run(["logger", "-t", "telemetry-relay", corr_id], shell=False)


def main() -> None:
    while True:
        _poll_once()
        time.sleep(3600)


if __name__ == "__main__":
    main()
