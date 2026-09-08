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


def _ledger_path(home: str | None = None, path: str | None = None) -> Path:
    """Resolve the coverage.json ledger path.

    Parameters
    ----------
    path:
        The ledger file itself. Wins over *home*. This is how the CLI keeps the
        ledger inside whatever local store the rest of the run is using — see
        B-599 below.
    home:
        When given, treated as the user's HOME directory; the ledger lives at
        ``<home>/.clawseccheck/coverage.json``.  When ``None``, the default
        ``~/.clawseccheck/coverage.json`` (expanduser) is used.

    B-599: ``home`` was documented "for testing" and no production path passed
    anything, so this always resolved to the REAL ``~/.clawseccheck`` — including
    under ``--data-dir``, whose own help text promises a scratch run "cannot
    half-redirect and write into your real history". Three of the store's four
    files moved with that flag and this one did not, so scratch, CI and test runs
    stamped the user's real freshness ledger with today's date. That is not
    hygiene: ``freshness_notice`` reads this file to tell the user when they last
    exercised a capability, so a stamp they never earned makes the tool report
    coverage that did not happen.
    """
    if path is not None:
        return Path(path).expanduser()
    if home is not None:
        return Path(home) / ".clawseccheck" / "coverage.json"
    return Path(DEFAULT_COVERAGE).expanduser()


def load_ledger(home: str | None = None, *, path: str | None = None) -> dict[str, str]:
    """Load the coverage ledger from disk.

    Returns a ``{capability: last_run_iso_date}`` dict.
    Returns an empty dict if the file is missing, unreadable, or malformed —
    callers must handle the "never-run" case explicitly.

    Parameters
    ----------
    home:
        Override the ledger's parent HOME dir (for testing).
        ``None`` → real ``~/.clawseccheck/`` via expanduser.
    path:
        The ledger file itself; wins over *home*. The CLI passes the store dir it
        is already using for history/state/events, so every local-state file of a
        run lands together (B-599).
    """
    p = _ledger_path(home, path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Accept only string → string entries; discard anything malformed. "_schema"
    # (C-162) is a reserved bookkeeping key, not a capability — never surfaced to
    # callers (freshness_notice iterates THRESHOLDS, so it would be ignored anyway,
    # but filtering here keeps the returned map a clean capability→date view).
    return {k: v for k, v in data.items()
            if isinstance(k, str) and isinstance(v, str) and k != "_schema"}


def record_run(capability: str, *, home: str | None = None,
               today: date | None = None, path: str | None = None) -> None:
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
    path:
        The ledger file itself; wins over *home*. See :func:`_ledger_path` for why
        production callers must pass this rather than relying on the default.
    """
    from .locking import journal_lock  # avoid top-level import cycle
    from .monitor import SCHEMA_VERSION  # avoid top-level import cycle
    from .safeio import secure_dir, secure_write_text  # avoid top-level import cycle

    today = today or date.today()
    p = _ledger_path(home, path)
    try:
        secure_dir(p.parent)
        # C-174: the read-modify-write cycle below was unlocked, so two real
        # concurrent processes (e.g. --self-test and --vet-mcp run back to
        # back) could each read the same stale ledger and overwrite each
        # other's key on write — a silent lost update. journal_lock (same
        # primitive history.py/monitor.py already use) serializes it.
        with journal_lock(p):
            # Read from the SAME file this is about to write. Passing `home` alone
            # here would read the default ledger and write the redirected one,
            # silently dropping every other capability's date on the first write.
            ledger = load_ledger(home, path=path)
            ledger[capability] = today.isoformat()
            # C-162: reserved "_schema" bookkeeping key, written last so it always
            # reflects this build regardless of write order above. load_ledger()
            # filters it back out.
            ledger["_schema"] = str(SCHEMA_VERSION)
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
