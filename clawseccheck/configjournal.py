"""Read OpenClaw's own config-write journal - a second witness we did not author.

A snapshot diff answers "what is different now". It structurally cannot see a change that
was made and then put back between two runs, and it cannot say WHO made one. OpenClaw
already records both and we ignored the file.

The journal carries one record per config write, each with a ``previousHash``/``nextHash``
pair over the config bytes. Measured on a live install: the newest record's ``nextHash``
equals ``sha256(openclaw.json)`` exactly, and ``nextBytes`` equals its size - so the chain
is real and it is authored by a different program than this one, which is what makes it
worth reading.

**Two containers, one record shape (C-674).** Older OpenClaw wrote
``~/.openclaw/logs/config-audit.jsonl``; current OpenClaw keeps the same records in the
state database (``state/openclaw.sqlite``, table ``diagnostic_events``, scope
``config-audit``) and renames the old file ``*.migrated``. The state database is read when
that table holds config-audit rows, else the legacy file; ``Journal.container`` says which.
A state database that is present but cannot be read is NOT a reason to read a stale file
instead - it is reported ``unreadable``. ``read_journals`` returns EVERY container found
(an older gateway after a rollback writes the file again, beside a database that already
holds rows), so a verdict can be taken over both rather than over whichever came first.
The payload field names did not change (it added ``changedPaths`` and ``origin``, which are
not read).

**What this module refuses to conclude.** A broken chain link is NOT evidence of tampering.
Measured on a healthy real machine: 2 of 42 links were already broken, both benignly - one
where the config was hand-edited outside OpenClaw's own writer (so no record exists for
that write), and one where two writes share the same ``previousHash``, i.e. they raced from
a common base or something was reverted and re-applied. Log rotation produces the same
shape. An honest reader reports a gap as *unknown provenance*, never as an attack.

Two more field caveats, measured rather than assumed on the same 43 records:
``changedPathCount`` was ``None`` on **every** one, so an absent value must never be read as
"0 paths changed"; and ``suspicious`` was present but empty on every one, which is a clean
false-positive baseline but also zero positive evidence that it ever fires - nothing
high-severity may rest on it alone.

Layer 1 leaf: stdlib, ``logsafe``, ``pathprobe``, ``configloader`` and the collector's
read-only state-DB reader. Read-only, offline, bounded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import pathprobe
from .collector import (
    CONFIG_AUDIT_OK,
    CONFIG_AUDIT_UNREADABLE,
    read_config_audit_rows,
)
from .configloader import loads_bounded
from .logsafe import redact

# Same bound and reasoning as checks/_shared.py's _read_jsonl_tail: these logs are
# append-only and can reach GB on a long-running agent, so the tail is read rather than
# the file. 512 KB covers hundreds of records; the live file is 44 KB at 43 records.
JOURNAL_SCAN_CAP = 512_000
JOURNAL_RELPATH = "logs/config-audit.jsonl"   # the LEGACY container (pre-C-674 installs)

# Which container one read came from. "" means neither was found.
CONTAINER_STATE_DB = "state_db"
CONTAINER_FILE = "file"

# Chain verdicts. Three, not two: "we could not check" is a distinct answer from "the chain
# holds", and collapsing them is how a monitor ends up reporting silence as safety.
CHAIN_OK = "ok"
CHAIN_GAP = "gap"            # a link does not join - provenance unknown, NOT tampering
CHAIN_UNKNOWN = "unknown"    # no journal, unreadable, or too few records to say anything


@dataclass
class ConfigWrite:
    """One journaled config write, with everything unsafe already stripped."""

    ts: str = ""
    pid: "int | None" = None
    ppid: "int | None" = None
    # BASENAME only. The full argv carries absolute paths, and `cwd` carries the user's
    # directory layout; neither may reach a report or the event journal, so neither is
    # kept here rather than being kept and carefully avoided later.
    argv0: str = ""
    previous_hash: str = ""
    next_hash: str = ""
    result: str = ""
    gateway_mode_before: "str | None" = None
    gateway_mode_after: "str | None" = None
    suspicious: tuple = ()
    # None means the field was absent - which is what it always is on a real install. Never
    # coerce to 0: "no paths changed" is a claim, and absence is not that claim.
    changed_path_count: "int | None" = None
    # Carried for B77, which judges the record's own event label and whether ANY argv
    # element names openclaw (the basename above is argv[0] only). Neither holds a path.
    event: str = "config.write"
    argv_names_openclaw: "bool | None" = None   # None: no argv recorded
    # argv[0] as a printable label even when it is not a string (the old inline B77 printed
    # "5" for an integer argv[0]); `argv0` above stays "" for that case.
    argv_label: str = ""


@dataclass
class Journal:
    """What one bounded read of the journal saw."""

    writes: list = field(default_factory=list)
    present: bool = False
    truncated: bool = False      # the tail was read, so earlier records exist off-window
    # Records (lines, or state-DB rows) that were seen but could not be read as a record:
    # bad JSON, nested past the bound, not an object, or a blank / NULL / non-text row.
    unparsable_lines: int = 0
    # State-DB rows larger than the whole byte budget: not examined (the file reader never
    # sees such a line either - it falls off the tail window). Distinct from unparsable.
    oversized_rows: int = 0
    rows_seen: int = 0           # state-DB rows examined or skipped, for honest wording
    container: str = ""          # CONTAINER_STATE_DB / CONTAINER_FILE / "" (neither found)
    # A container EXISTS but could not be read (permissions, a refused non-table, a locked
    # or corrupt database). Distinct from "not found": the caller must not read it as clean.
    unreadable: bool = False


def journal_path(home) -> Path:
    return pathprobe.expand_user(home) / JOURNAL_RELPATH


def _basename(argv) -> str:
    if not isinstance(argv, list) or not argv:
        return ""
    first = argv[0]
    if not isinstance(first, str):
        return ""
    # Split on BOTH separators. `os.path.basename` is `posixpath` on a POSIX host and does
    # not treat "\\" as a separator, so a Windows-style argv[0] - reachable from WSL, or a
    # home copied from Windows - survived whole: "C:\\Users\\dave\\secret\\x.exe" came out
    # unchanged and reached the alert string and the event journal with the user's
    # directory layout in it.
    tail = first.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return redact(tail)[:64]


def _label(argv) -> str:
    """Like ``_basename`` but a non-string argv[0] is printed, not blanked."""
    if not isinstance(argv, list) or not argv:
        return ""
    first = argv[0]
    return _basename([first if isinstance(first, str) else str(first)])


def _str(value) -> str:
    return value if isinstance(value, str) else ""


def _write_from(record: dict) -> ConfigWrite:
    susp = record.get("suspicious")
    count = record.get("changedPathCount")
    argv = record.get("argv")
    return ConfigWrite(
        event=str(record.get("event", "config.write")),
        argv_label=_label(argv),
        argv_names_openclaw=(any("openclaw" in str(a).lower() for a in argv)
                             if isinstance(argv, list) and argv else None),
        ts=_str(record.get("ts")),
        pid=record.get("pid") if isinstance(record.get("pid"), int) else None,
        ppid=record.get("ppid") if isinstance(record.get("ppid"), int) else None,
        argv0=_basename(record.get("argv")),
        previous_hash=_str(record.get("previousHash")),
        next_hash=_str(record.get("nextHash")),
        result=_str(record.get("result")),
        gateway_mode_before=record.get("gatewayModeBefore")
        if isinstance(record.get("gatewayModeBefore"), str) else None,
        gateway_mode_after=record.get("gatewayModeAfter")
        if isinstance(record.get("gatewayModeAfter"), str) else None,
        suspicious=tuple(redact(str(s))[:120] for s in susp) if isinstance(susp, list) else (),
        changed_path_count=count if isinstance(count, int) else None,
    )


def _same_config(record_path, wanted) -> bool:
    """Does this record describe the config file the audit actually read?

    The journal carries a ``configPath`` per record and OpenClaw would not carry it if one
    install could only ever have one. A write to a DIFFERENT config would otherwise move
    the journal head with no change to the file we are watching - which is exactly the
    shape the "changed and reverted" arm keys on, so it would fire on someone else's edit.

    A record with no ``configPath`` at all is KEPT: an older journal format saying nothing
    about which file it wrote is not evidence that it wrote a different one. That is the
    only fail-open here, and it is bounded to journals that predate the field.
    """
    if wanted is None or not isinstance(record_path, str) or not record_path:
        return True
    if record_path == str(wanted):
        return True
    try:
        return Path(record_path).resolve() == Path(wanted).resolve()
    except (OSError, ValueError, RuntimeError):
        return False


def read_writes(home, since: "str | None" = None,
                cap: int = JOURNAL_SCAN_CAP,
                config_path=None) -> Journal:
    """Bounded, read-only tail of the config-write journal, oldest record first.

    *config_path* - when given, records describing a different config file are dropped.
    See ``_same_config``: without it, a write to an unrelated config moves the journal head
    and the "changed and reverted" arm fires on someone else's edit.

    *since* - an ISO timestamp; records at or before it are dropped. The comparison is a
    plain string compare, which is correct for the fixed-width ISO-8601 UTC form OpenClaw
    writes and avoids parsing a foreign program's timestamps into our own clock.

    Reads the state database when it holds config-audit rows, else the legacy file (see the
    module docstring); ``Journal.container`` names the one read. *cap* bounds BOTH, in bytes.
    For a verdict over every container that exists use ``read_journals``.

    Never raises. A journal that is absent, unreadable, rotated or full of junk returns a
    ``Journal`` that says so; the caller's job is to report "could not tell", and a reader
    that crashed would take the whole monitor run down with it.
    """
    db = _read_state_db(home, since, cap, config_path)
    if db is not None:
        return db
    return _read_legacy_file(home, since, cap, config_path)


def read_journals(home, since: "str | None" = None,
                  cap: int = JOURNAL_SCAN_CAP,
                  config_path=None) -> "list[Journal]":
    """EVERY container that exists, state database first, each as its own ``Journal``.

    ``read_writes`` answers "which journal do I attribute from" and so stops at the first
    one; a verdict about the journal as a whole cannot. After an OpenClaw rollback an older
    gateway writes ``logs/config-audit.jsonl`` again beside a database that already holds
    rows, and a clean database says nothing about the file. A container that was not found
    is omitted; one that exists but could not be read is included with ``unreadable`` set.
    """
    out = []
    db = _read_state_db(home, since, cap, config_path)
    if db is not None:
        out.append(db)
    legacy = _read_legacy_file(home, since, cap, config_path)
    if legacy.container:
        out.append(legacy)
    return out


def _read_state_db(home, since, cap, config_path) -> "Journal | None":
    """The state-database journal, or ``None`` when that container is simply not there."""
    status, payloads, truncated, oversized, null_rows = read_config_audit_rows(home, cap)
    if status == CONFIG_AUDIT_UNREADABLE:
        # A state DB we could not read. Reading the legacy file INSTEAD would answer from a
        # stale journal about a database we never examined.
        return Journal(container=CONTAINER_STATE_DB, unreadable=True)
    if status != CONFIG_AUDIT_OK:
        return None
    out = Journal(container=CONTAINER_STATE_DB, present=True, truncated=truncated,
                  oversized_rows=oversized)
    out.unparsable_lines += null_rows
    out.rows_seen = len(payloads) + oversized + null_rows
    for payload in payloads:
        _ingest(out, payload, config_path, since, blank_is_unparsable=True)
    return out


def _read_legacy_file(home, since, cap, config_path) -> Journal:
    path = journal_path(home)
    out = Journal()
    try:
        if not pathprobe.is_file(path):
            return out
        out.container = CONTAINER_FILE
        size = path.stat().st_size
        if size <= cap:
            text = path.read_text(encoding="utf-8", errors="replace")
        else:
            with open(path, "rb") as fp:
                fp.seek(size - cap)
                text = fp.read(cap).decode("utf-8", errors="replace")
            out.truncated = True
            # The first line of a mid-file seek is almost certainly a fragment.
            newline = text.find("\n")
            text = text[newline + 1:] if newline != -1 else ""
    except OSError:
        out.container = CONTAINER_FILE
        out.unreadable = True
        return out

    out.present = True
    for line in text.splitlines():
        _ingest(out, line, config_path, since)
    return out


def _ingest(out: Journal, text, config_path, since, blank_is_unparsable=False) -> None:
    """Parse one journal record (a file line or a state-DB ``payload_json``) into *out*.

    A blank file line is just a blank line; a blank state-DB payload is a ROW that holds no
    record, so there it counts (*blank_is_unparsable*).
    """
    if not isinstance(text, str):
        out.unparsable_lines += 1
        return
    text = text.strip()
    if not text:
        if blank_is_unparsable:
            out.unparsable_lines += 1
        return
    try:
        record = loads_bounded(text)
    except ValueError:  # JSONNestingError too (C-664)
        out.unparsable_lines += 1
        return
    if not isinstance(record, dict):
        out.unparsable_lines += 1
        return
    if not _same_config(record.get("configPath"), config_path):
        return
    write = _write_from(record)
    if since and write.ts and write.ts <= since:
        return
    out.writes.append(write)


def chain_state(writes) -> str:
    """``CHAIN_OK`` / ``CHAIN_GAP`` / ``CHAIN_UNKNOWN`` over consecutive records.

    A gap is reported as a gap and nothing more. Every benign cause observed on a real
    machine produces one: an edit made outside OpenClaw's own writer leaves no record at
    all, so the next record's ``previousHash`` refers to bytes no journaled write produced;
    two writes racing from a common base share a ``previousHash``; and rotation simply
    removes the earlier half. None of those is an attack, and a tool that called them one
    would be wrong on its own maintainer's machine on day one.
    """
    usable = [w for w in writes if w.previous_hash and w.next_hash]
    if len(usable) < 2:
        return CHAIN_UNKNOWN
    for earlier, later in zip(usable, usable[1:]):
        if later.previous_hash != earlier.next_hash:
            return CHAIN_GAP
    return CHAIN_OK


def newest_hash(writes) -> str:
    """The most recent journaled ``nextHash``, or "" when there is none to read."""
    for write in reversed(list(writes)):
        if write.next_hash:
            return write.next_hash
    return ""


def find_by_hash(writes, digest: str) -> "ConfigWrite | None":
    """The newest journaled write that produced *digest*, if any recorded one did."""
    if not digest:
        return None
    for write in reversed(list(writes)):
        if write.next_hash == digest:
            return write
    return None
