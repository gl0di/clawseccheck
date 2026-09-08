"""Read OpenClaw's own config-write journal — a second witness we did not author.

A snapshot diff answers "what is different now". It structurally cannot see a change that
was made and then put back between two runs, and it cannot say WHO made one. OpenClaw
already records both and we ignored the file.

``~/.openclaw/logs/config-audit.jsonl`` carries one record per config write, each with a
``previousHash``/``nextHash`` pair over the config bytes. Measured on a live install: the
newest record's ``nextHash`` equals ``sha256(openclaw.json)`` exactly, and ``nextBytes``
equals its size — so the chain is real and it is authored by a different program than
this one, which is what makes it worth reading.

**What this module refuses to conclude.** A broken chain link is NOT evidence of tampering.
Measured on a healthy real machine: 2 of 42 links were already broken, both benignly — one
where the config was hand-edited outside OpenClaw's own writer (so no record exists for
that write), and one where two writes share the same ``previousHash``, i.e. they raced from
a common base or something was reverted and re-applied. Log rotation produces the same
shape. An honest reader reports a gap as *unknown provenance*, never as an attack.

Two more field caveats, measured rather than assumed on the same 43 records:
``changedPathCount`` was ``None`` on **every** one, so an absent value must never be read as
"0 paths changed"; and ``suspicious`` was present but empty on every one, which is a clean
false-positive baseline but also zero positive evidence that it ever fires — nothing
high-severity may rest on it alone.

Layer 1 leaf: stdlib plus ``logsafe`` only. Read-only, offline, bounded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .logsafe import redact

# Same bound and reasoning as checks/_shared.py's _read_jsonl_tail: these logs are
# append-only and can reach GB on a long-running agent, so the tail is read rather than
# the file. 512 KB covers hundreds of records; the live file is 44 KB at 43 records.
JOURNAL_SCAN_CAP = 512_000
JOURNAL_RELPATH = "logs/config-audit.jsonl"

# Chain verdicts. Three, not two: "we could not check" is a distinct answer from "the chain
# holds", and collapsing them is how a monitor ends up reporting silence as safety.
CHAIN_OK = "ok"
CHAIN_GAP = "gap"            # a link does not join — provenance unknown, NOT tampering
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
    # None means the field was absent — which is what it always is on a real install. Never
    # coerce to 0: "no paths changed" is a claim, and absence is not that claim.
    changed_path_count: "int | None" = None


@dataclass
class Journal:
    """What one bounded read of the journal saw."""

    writes: list = field(default_factory=list)
    present: bool = False
    truncated: bool = False      # the tail was read, so earlier records exist off-window
    unparsable_lines: int = 0


def journal_path(home) -> Path:
    return Path(home).expanduser() / JOURNAL_RELPATH


def _basename(argv) -> str:
    if not isinstance(argv, list) or not argv:
        return ""
    first = argv[0]
    if not isinstance(first, str):
        return ""
    # Split on BOTH separators. `os.path.basename` is `posixpath` on a POSIX host and does
    # not treat "\\" as a separator, so a Windows-style argv[0] — reachable from WSL, or a
    # home copied from Windows — survived whole: "C:\\Users\\dave\\secret\\x.exe" came out
    # unchanged and reached the alert string and the event journal with the user's
    # directory layout in it.
    tail = first.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return redact(tail)[:64]


def _str(value) -> str:
    return value if isinstance(value, str) else ""


def _write_from(record: dict) -> ConfigWrite:
    susp = record.get("suspicious")
    count = record.get("changedPathCount")
    return ConfigWrite(
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
    the journal head with no change to the file we are watching — which is exactly the
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

    *config_path* — when given, records describing a different config file are dropped.
    See ``_same_config``: without it, a write to an unrelated config moves the journal head
    and the "changed and reverted" arm fires on someone else's edit.

    *since* — an ISO timestamp; records at or before it are dropped. The comparison is a
    plain string compare, which is correct for the fixed-width ISO-8601 UTC form OpenClaw
    writes and avoids parsing a foreign program's timestamps into our own clock.

    Never raises. A journal that is absent, unreadable, rotated or full of junk returns a
    ``Journal`` that says so; the caller's job is to report "could not tell", and a reader
    that crashed would take the whole monitor run down with it.
    """
    path = journal_path(home)
    out = Journal()
    try:
        if not path.is_file():
            return out
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
        return out

    out.present = True
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            out.unparsable_lines += 1
            continue
        if not isinstance(record, dict):
            out.unparsable_lines += 1
            continue
        if not _same_config(record.get("configPath"), config_path):
            continue
        write = _write_from(record)
        if since and write.ts and write.ts <= since:
            continue
        out.writes.append(write)
    return out


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
