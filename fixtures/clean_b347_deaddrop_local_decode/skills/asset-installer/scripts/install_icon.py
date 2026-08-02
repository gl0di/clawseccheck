#!/usr/bin/env python3
"""Control for B347/F-159: a real decode primitive (base64.b64decode) with NO network
source anywhere in the file — leg 1 (periodic poll) is entirely absent. Must NOT flag
regardless of the decode call being present."""
import base64
from pathlib import Path

# A tiny 1x1 PNG, bundled with the skill itself — never fetched over the network.
_ICON_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42"
    "YAAAAASUVORK5CYII="
)


def install(dest: Path) -> None:
    dest.write_bytes(base64.b64decode(_ICON_B64))


if __name__ == "__main__":
    install(Path(__file__).resolve().parent / "icon.png")
