"""Pre-scan mode preference — remembers the last scan mode chosen (C-103).

Design: ``docs/research/pre-scan-menu.md`` (workspace-root internal note; never
ships). The pre-scan menu itself is SKILL.md-narrated (the host agent presents the
screen and maps the user's choice to an existing flag) — there is no deterministic
Python menu to dispatch. This module is only the small, local-only persistence piece:
"remember the last mode chosen" (item 1 of that doc's two optional engine touches),
so a future narration can default to it instead of always falling back to Quick.

Stores ``{"last_mode": "<mode>"}`` at ``~/.clawseccheck/prescan.json`` — a single
current-value preference, not a tamper-evident audit trail, so (unlike
``history.jsonl`` / ``ledger.py``'s ``record_run``) writes are a plain overwrite: no
``journal_lock``, no hash chain, no ``_schema`` stamp.

Local-only. No network. Pure stdlib. Python 3.9+.
"""
from __future__ import annotations

import json
from pathlib import Path

from .safeio import secure_dir, secure_write_text

DEFAULT_PRESCAN = "~/.clawseccheck/prescan.json"

# The resolved pre-scan menu's numbered modes (docs/research/pre-scan-menu.md,
# "Resolved menu (final)"): Quick / Deeper / Full / What changed. "Private" and
# "verify"/"vet"/"update" are modifiers/shortcuts, not modes, and are not stored here.
MODES: tuple[str, ...] = ("quick", "deeper", "full", "whatchanged")
DEFAULT_MODE = "quick"


def _path(home: str | None = None) -> Path:
    """Resolve the prescan.json path.

    Parameters
    ----------
    home:
        When given, treated as the user's HOME directory; the file lives at
        ``<home>/.clawseccheck/prescan.json``.  When ``None``, the default
        ``~/.clawseccheck/prescan.json`` (expanduser) is used.
    """
    if home is not None:
        return Path(home) / ".clawseccheck" / "prescan.json"
    return Path(DEFAULT_PRESCAN).expanduser()


def read_last_mode(home: str | None = None) -> str:
    """Return the last persisted pre-scan mode, or ``"quick"`` on ANY failure.

    Fails safe to the default (`"quick"`) for every unusable state: an absent file,
    an unreadable file, malformed JSON, a non-object payload, or a stored value that
    is not one of the known ``MODES`` — never raises.

    Parameters
    ----------
    home:
        Override the file's parent HOME dir (for testing).
        ``None`` → real ``~/.clawseccheck/`` via expanduser.
    """
    p = _path(home)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return DEFAULT_MODE
    if not isinstance(data, dict):
        return DEFAULT_MODE
    mode = data.get("last_mode")
    if not isinstance(mode, str) or mode not in MODES:
        return DEFAULT_MODE
    return mode


def record_mode(mode: str, home: str | None = None) -> None:
    """Persist *mode* as the last-chosen pre-scan mode (plain overwrite).

    Silently drops write errors (same "never crash the caller" contract as
    ``ledger.record_run``). An unknown/out-of-``MODES`` *mode* is ignored — nothing
    is written, and any prior recorded mode is left untouched.

    Parameters
    ----------
    mode:
        One of ``MODES`` (``"quick"``, ``"deeper"``, ``"full"``, ``"whatchanged"``).
    home:
        Override the file's parent HOME dir (for testing).
        ``None`` → real ``~/.clawseccheck/`` via expanduser.
    """
    if mode not in MODES:
        return
    p = _path(home)
    try:
        secure_dir(p.parent)
        secure_write_text(p, json.dumps({"last_mode": mode}, ensure_ascii=False) + "\n")
    except OSError:
        pass
