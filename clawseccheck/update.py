"""Offline update advisory — tells the user their ClawSecCheck may be stale, WITHOUT a network call.

Golden rule #1 of this project is local-only / zero-network / no phone-home. Knowing whether a
*newer* version exists is server-side state, so the tool itself must never fetch it. Instead:

  1. A trusted distribution layer (the user's ClawHub client / auto-updater / their agent) MAY
     drop a small LOCAL hint file at ~/.clawseccheck/latest.json. We only *read* it — no network.
  2. Failing that, we fall back to a purely offline staleness nudge based on the baked-in build
     date (`__released__`) versus the local clock.

The hint file is UNTRUSTED input (it could be planted): we accept only a strict semver from its
`version` field and reconstruct it from parsed integers, so a hostile hint can at most misstate a
number — never inject text, a URL, or an action. This module never imports anything that does I/O
beyond reading that one local file, and never opens a socket.
"""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

DEFAULT_LATEST = "~/.clawseccheck/latest.json"

# A build older than this many days, with no hint file, earns a gentle offline nudge.
AGE_NUDGE_DAYS = 60

# Strict leading semver. We use match (not fullmatch) but ALWAYS reconstruct the version from the
# captured integers, so whatever trails the number is discarded — the echoed string is clean.
_SEMVER_RE = re.compile(r"^\s*(\d{1,6})\.(\d{1,6})\.(\d{1,6})")


def _ver_tuple(value) -> tuple[int, int, int] | None:
    """Parse a strict X.Y.Z prefix to a 3-int tuple, else None. Pure, no I/O."""
    m = _SEMVER_RE.match(str(value))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _clean_version(value) -> str | None:
    """Return a sanitized 'X.Y.Z' string (reconstructed from ints) or None. Injection-proof echo."""
    t = _ver_tuple(value)
    return ".".join(str(n) for n in t) if t else None


def _parse_date(value) -> date | None:
    """Parse a 'YYYY-MM-DD' prefix to a date, else None. Pure, no I/O, never raises out."""
    try:
        y, m, d = str(value).strip()[:10].split("-")
        return date(int(y), int(m), int(d))
    except (ValueError, TypeError):
        return None


def read_latest_hint(path: str = DEFAULT_LATEST) -> str | None:
    """Read the LOCAL update-hint file (no network). Return a sanitized version string or None.

    Tolerates a missing / unreadable / malformed file and a non-dict / non-semver `version`
    by returning None — the advisory simply stays silent rather than erroring.
    """
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return _clean_version(data.get("version"))


def update_notice(current: str, *, released: str | None = None,
                  latest_path: str = DEFAULT_LATEST, today: date | None = None) -> list[str]:
    """Build the OFFLINE update advisory: a list of plain lines (empty if there's nothing to say).

    NEVER makes a network call. Two local signals, in priority order:
      1. A local hint file says a strictly-newer version exists -> precise "update available".
      2. Otherwise, if this build is at least AGE_NUDGE_DAYS old by the local clock -> age nudge.

    `today` and `latest_path` are injectable so this is fully deterministic under test.
    """
    today = today or date.today()
    cur = _ver_tuple(current)

    latest = read_latest_hint(latest_path)
    if latest and cur and _ver_tuple(latest) > cur:
        return [
            f"A newer ClawSecCheck is available: v{latest} (you have v{current}).",
            "Security checks go stale — update via your ClawHub client.",
            "(offline notice: read from a local hint file; ClawSecCheck made no network call)",
        ]

    rel = _parse_date(released) if released else None
    if rel is not None:
        age = (today - rel).days
        if age >= AGE_NUDGE_DAYS:
            return [
                f"This ClawSecCheck build is {age} days old (v{current}, released {rel.isoformat()}).",
                "Security tooling should be kept current — check your ClawHub client for a newer version.",
                "(offline notice: based only on the build date; ClawSecCheck made no network call)",
            ]
    return []
