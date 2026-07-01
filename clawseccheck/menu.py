"""Capability menu — the guided Welcome screen as a runnable command.

``clawseccheck --menu`` prints the compact entry screen the skill shows in
``SKILL.md`` Step 1: the four common things you can do, plus two status nudges —
when you last ran a check, and an offline hint if this build looks stale.
Read-only, no network, pure stdlib (Python 3.9+).

``render_menu()`` is pure and fully injectable (version, ages, staleness) so it is
deterministic under test; ``cli.py`` wires the real local values in. English only —
the host agent localizes for the user's own language.
"""
from __future__ import annotations

from datetime import date

# (number, emoji, title, hint). The emoji is dropped in --ascii mode.
# Each item maps to a real capability: 1 -> --full (audit + live self-test),
# 2 -> --vet / --vet-mcp, 3 -> the report/save/trend/badge family, 4 -> the full
# function list. The "⚡" in item 1's hint discloses the live-agent test up front,
# so picking it is informed consent (read-only-by-default stays honest).
_ITEMS = (
    ("1", "🔍", "Check everything", "config + live agent test ⚡"),
    ("2", "📦", "Check before install", "skill · plugin · MCP"),
    ("3", "📄", "Report & history", "show · save · trend · badge"),
    ("4", "📋", "Menu", "everything else: verify · version · HTML · SARIF…"),
)

# Title column width, so hints line up. Padding is by plain-title length; emoji
# prefixes shift the emoji rows by a constant, so the columns still read.
_TITLE_COL = 22


def _ascii(text: str) -> str:
    """Fold the few non-ASCII glyphs we use down to safe ASCII for --ascii mode."""
    return (text
            .replace("⚡", "(live)")
            .replace("·", "-")
            .replace("—", "-")
            .replace("…", "..."))


def _last_check_line(days, ascii_only: bool) -> str:
    label = "Last check:" if ascii_only else "🕒 Last check:"
    if days is None:
        return f"{label} not checked yet"
    if days <= 0:
        return f"{label} today"
    unit = "day" if days == 1 else "days"
    return f"{label} {days} {unit} ago"


def _update_line(build_age_days, stale: bool, ascii_only: bool) -> str:
    """The 🆙 update affordance. Always shown so "update" is discoverable; louder when stale."""
    label = "Update:" if ascii_only else "🆙"
    if stale and build_age_days is not None and build_age_days > 0:
        body = 'build is {n} days old — a newer one may exist · say "update"'.format(n=build_age_days)
    elif stale:
        body = 'a newer ClawSecCheck may exist · say "update"'
    else:
        body = 'say "update" to check for a newer version'
    line = f"{label} {body}"
    return _ascii(line) if ascii_only else line


def compute_ages(*, released=None, last_check=None, today=None):
    """Return ``(build_age_days, last_check_days)``; ``None`` where unknown. Pure.

    Dates are parsed as a leading ``YYYY-MM-DD``; anything unparseable yields
    ``None`` so the menu degrades to "not checked yet" / no staleness rather than
    raising. ``today`` is injectable for deterministic tests.
    """
    today = today or date.today()

    def _iso(value):
        try:
            return date.fromisoformat(str(value).strip()[:10])
        except (ValueError, TypeError):
            return None

    rel = _iso(released)
    last = _iso(last_check)
    build_age = (today - rel).days if rel else None
    last_days = (today - last).days if last else None
    return build_age, last_days


def render_menu(*, version, build_age_days=None, last_check_days=None,
                stale: bool = False, ascii_only: bool = False) -> str:
    """Render the capability menu as plain text. Pure — no I/O, no clock read."""
    sep = " - " if ascii_only else " · "
    head = f"ClawSecCheck{sep}v{version}" if ascii_only else f"🦞 ClawSecCheck{sep}v{version}"
    lines = [head, ""]

    for num, emoji, title, hint in _ITEMS:
        prefix = f"  {num}  " if ascii_only else f"  {num}  {emoji} "
        pad = max(2, _TITLE_COL - len(title))
        hint_text = _ascii(hint) if ascii_only else hint
        lines.append(f"{prefix}{title}{' ' * pad}{hint_text}")

    lines.append("")
    lines.append("  " + _last_check_line(last_check_days, ascii_only))
    lines.append("  " + _update_line(build_age_days, stale, ascii_only))
    return "\n".join(lines)
