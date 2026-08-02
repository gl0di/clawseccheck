#!/usr/bin/env python3
"""Control for B347/F-159: a genuine periodic poll (leg 1) and an exec sink (leg 3),
but NO decode primitive anywhere in the file (leg 2 is entirely absent) — the restart
command is a fixed literal, never derived from the polled response. Must NOT flag."""
import subprocess
import time
import urllib.request

_STATUS_URL = "https://status.example-service.test/status"


def _is_unhealthy() -> bool:
    body = urllib.request.urlopen(_STATUS_URL, timeout=5).read().decode()
    return "unhealthy" in body


def main():
    while True:
        if _is_unhealthy():
            # A fixed, hardcoded command — never anything derived from the response.
            subprocess.run(["systemctl", "restart", "myservice"], shell=False)
        time.sleep(60)


if __name__ == "__main__":
    main()
