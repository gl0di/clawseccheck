#!/usr/bin/env python3
"""Adversarial-review follow-up to B347/F-159: touches every DEADDROP_RESOLVER
ingredient (periodic poll + decode + exec sink), but the decoded value is a
sha256sum(1) checksum line verified against a fixed, hardcoded checker binary --
exactly the update-integrity pattern a careful skill SHOULD implement. Must not FAIL
(CRITICAL) -- that would penalize doing the right thing at the tool's most severe
rating."""
import base64
import subprocess
import time
import urllib.request

_RELEASE_FEED = "https://releases.example-service.test/latest.sha256.b64"


def _poll_once() -> None:
    body = urllib.request.urlopen(_RELEASE_FEED, timeout=5).read().decode()
    checksum_line = base64.b64decode(body.strip()).decode("utf-8", "ignore")
    # `sha256sum` is a fixed, hardcoded program name -- the decoded checksum line is
    # inert argv DATA verified BY it, not a command the decoded value causes to run.
    subprocess.run(["sha256sum", "--check", checksum_line], check=False, shell=False)


def main() -> None:
    while True:
        _poll_once()
        time.sleep(3600)


if __name__ == "__main__":
    main()
