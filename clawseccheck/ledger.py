"""Coverage ledger — tracks when opt-in test capabilities were last run.

Records last-run dates for opt-in capabilities to a small JSON map at
``~/.clawseccheck/coverage.json`` and emits an advisory nudge when a
capability is stale or has never been run.

Capability mapping
------------------
``"self_test"``
    Covers all prompt-injection harnesses: ``--self-test``, ``--redteam``,
    ``--dryrun``, and ``--canary``.  Any of them resets the 30-day freshness
    clock.  They are collapsed under one key because they all exercise the
    same live-resistance surface.

``"vet_mcp"``
    Covers ``--vet-mcp`` (MCP supply-chain vetting).  14-day threshold.

Local-only. No network. Pure stdlib. Python 3.9+.
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

DEFAULT_COVERAGE = "~/.clawseccheck/coverage.json"

# Capability → stale threshold in days (hard-coded per spec).
THRESHOLDS: dict[str, int] = {
    "self_test": 30,
    "vet_mcp": 14,
}


def _ledger_path(home: str | None = None) -> Path:
    """Resolve the coverage.json ledger path.

    Parameters
    ----------
    home:
        When given, treated as the user's HOME directory; the ledger lives at
        ``<home>/.clawseccheck/coverage.json``.  When ``None``, the default
        ``~/.clawseccheck/coverage.json`` (expanduser) is used.
    """
    if home is not None:
        return Path(home) / ".clawseccheck" / "coverage.json"
    return Path(DEFAULT_COVERAGE).expanduser()


def load_ledger(home: str | None = None) -> dict[str, str]:
    """Load the coverage ledger from disk.

    Returns a ``{capability: last_run_iso_date}`` dict.
    Returns an empty dict if the file is missing, unreadable, or malformed —
    callers must handle the "never-run" case explicitly.

    Parameters
    ----------
    home:
        Override the ledger's parent HOME dir (for testing).
        ``None`` → real ``~/.clawseccheck/`` via expanduser.
    """
    p = _ledger_path(home)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Accept only string → string entries; discard anything malformed.
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def record_run(capability: str, *, home: str | None = None,
               today: date | None = None) -> None:
    """Record that *capability* was run today in the coverage ledger.

    Silently drops write errors (same "never crash the caller" contract as
    ``history.record``).  Reads the existing ledger first so other capabilities
    are preserved across writes.

    Parameters
    ----------
    capability:
        One of the known keys (``"self_test"``, ``"vet_mcp"``) or any future
        string key.  Unknown keys are stored verbatim and silently ignored by
        ``freshness_notice``.
    home:
        Override the ledger's parent HOME dir (for testing).
        ``None`` → real ``~/.clawseccheck/`` via expanduser.
    today:
        Override the recorded date (for testing).
        ``None`` → ``date.today()``.
    """
    from .safeio import secure_dir, secure_write_text  # avoid top-level import cycle

    today = today or date.today()
    ledger = load_ledger(home)
    ledger[capability] = today.isoformat()
    p = _ledger_path(home)
    try:
        secure_dir(p.parent)
        secure_write_text(p, json.dumps(ledger, indent=2, ensure_ascii=False) + "\n")
    except OSError:
        pass


def freshness_notice(ledger: dict[str, str], *, today: date | None = None,
                     skip: tuple[str, ...] = ()) -> list[str]:
    """Return advisory lines when a capability is stale or has never been run.

    Returns an empty list if all capabilities are within their thresholds.

    This function is ADVISORY ONLY.  It never alters score, grade, or findings.
    It reads only the provided *ledger* dict and the local clock (injectable via
    *today*) — it makes no network calls and writes nothing.

    Parameters
    ----------
    ledger:
        The map returned by ``load_ledger()``.
    today:
        Override the current date (for testing).  ``None`` → ``date.today()``.
    skip:
        Capability keys to omit from the advisory — used when the caller is
        refreshing those capabilities in the same run (e.g. ``--full``), so a
        stale/never nudge for them would be self-contradictory.
    """
    _NEVER_MSGS: dict[str, str] = {
        "self_test": (
            "Coverage gap: prompt-injection tests (--self-test / --redteam / --dryrun / --canary)"
            " have never been run. Run periodically to test live resistance, not just config."
            " (offline notice; ClawSecCheck made no network call)"
        ),
        "vet_mcp": (
            "Coverage gap: MCP supply-chain vetting (--vet-mcp) has never been run."
            " Run periodically to check your MCP servers for supply-chain risk."
            " (offline notice; ClawSecCheck made no network call)"
        ),
    }
    _STALE_TEMPLATES: dict[str, str] = {
        "self_test": (
            "Coverage gap: prompt-injection tests (--self-test / --redteam / --dryrun / --canary)"
            " last run {age} days ago (threshold: {threshold} days)."
            " Run again to keep resistance tests current."
            " (offline notice; ClawSecCheck made no network call)"
        ),
        "vet_mcp": (
            "Coverage gap: MCP supply-chain vetting (--vet-mcp) last run {age} days ago"
            " (threshold: {threshold} days). Run again to keep your MCP server vetting current."
            " (offline notice; ClawSecCheck made no network call)"
        ),
    }

    today = today or date.today()
    lines: list[str] = []

    for cap in THRESHOLDS:
        if cap in skip:
            # Caller is refreshing this capability in the same run (e.g. --full
            # runs the self-test + vet-mcp sections), so a staleness nudge for it
            # would contradict itself — suppress it.
            continue
        threshold = THRESHOLDS[cap]
        last = ledger.get(cap)

        if last is None:
            # Capability has never been run.
            if cap in _NEVER_MSGS:
                lines.append(_NEVER_MSGS[cap])
        else:
            try:
                last_date = date.fromisoformat(str(last).strip()[:10])
            except (ValueError, TypeError):
                # Corrupted/blank ledger entry → fail SAFE: treat it as never-run
                # so the advisory still nudges, rather than silently swallowing it
                # (fails-open is exactly what this tool warns others about).
                if cap in _NEVER_MSGS:
                    lines.append(_NEVER_MSGS[cap])
                continue
            age = (today - last_date).days
            if age > threshold and cap in _STALE_TEMPLATES:
                lines.append(_STALE_TEMPLATES[cap].format(age=age, threshold=threshold))

    return lines
