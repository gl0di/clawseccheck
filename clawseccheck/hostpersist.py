"""F-179: read-only enumeration of HOST-level persistence surfaces.

Every persistence verdict elsewhere in this package reasons about the *agent's* own
state: `openclaw.json`, the bootstrap files, the skill tree, OpenClaw's own `cron_jobs`
table. That is the whole subject of `--monitor` today, and it is structurally blind to
the mechanism that matters most in the published attack chain.

`docs/research/fourth-leg-persistence-2026-08-06.md` §2 tabulates every write path to an
identity file. Row 3 is a **host scheduled task** — Zenity Labs' demonstrated OpenClaw
chain, a job rewriting `SOUL.md` every two minutes from an attacker endpoint — and the
column "what stops it" reads, in full: *nothing in openclaw.json*. A config-only watch
cannot see that job, cannot see the shell profile that launched it, and cannot see the
systemd unit that keeps it alive. This module supplies that surface so
`monitor.snapshot()` can record it and `diff_with_notes()` can say it moved.

Doctrine (matches `hostwatch.py` and `sockets.py`): **no subprocess, no network.** We
read well-known paths directly. That constraint is not decoration here — it decides what
this module can and cannot see, and §"What is unreadable" below is the honest half of
this file.

RENDERS NO VERDICT. Like `sockets.py` → B340 and `deptree.py` → B349, this is a leaf: it
enumerates and digests, and the consumer decides what any of it means. It imports nothing
from the package.

**Metadata only, never content (ZKDS).** These files carry credentials in the real world
— B193 exists precisely because a gateway token can sit in a systemd unit, and a shell
profile is where people put `export API_KEY=`. Only a SHA-256 of the bytes ever leaves
this module. A digest cannot be un-hashed into the secret it covers, and it is exactly
enough to answer the one question the watch asks: *did this change?*

**No absolute paths carrying $HOME.** Home-rooted entries are recorded home-relative, for
the reason `openclawdist.py` records: a drift baseline reaches the event journal and any
report a user pastes into an issue, and an absolute path there names the user.
System-wide paths under `/etc` are recorded as-is — they identify nobody.

## What is unreadable, and why that is a finding rather than an omission

The **user's own crontab** — `/var/spool/cron/crontabs/<user>` on Debian-family systems,
`/var/spool/cron/<user>` elsewhere — is the closest thing on disk to Zenity's mechanism,
and on a normal machine it is **not readable by the user who owns it**. Measured on the
real box: `Permission denied` on the containing directory. The spool is mode 1730
root:crontab and `crontab -l` reads it through a setgid helper. Reading it therefore
requires either root or a subprocess, and a subprocess is exactly what this module's
doctrine forbids.

So we do not read it, and we must not let that absence read as "nothing scheduled".
:func:`scan` records such a path in ``unreadable`` and the monitor turns that into an
UNDETERMINED note. `checks/_lifecycle.py:1288` reached the same conclusion from the other
direction and tells the user to run `crontab -l` themselves; this module makes the gap
visible on every run instead of once in a report's prose.

What IS readable without privileges, and is therefore covered: `/etc/crontab`,
`/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/` (all world-readable), systemd
**user** units and timers under `~/.config/systemd/user/` including the
`timers.target.wants/` symlinks that decide whether a timer is actually armed, and the
shell startup files.

## What was removed after an adversarial pass, and why (C-135)

A fourth family — Python auto-execution hooks, the `.pth` files and `sitecustomize.py` that
B99 and B335 check — was implemented, tested green, and then **removed**, because the
adversarial pass showed it measured the OBSERVER rather than the SUBJECT.

Those files were located by walking the running interpreter's `sys.path`. That is a
property of *how this tool was invoked*, not of the machine being watched. Reproduced:
running the audit once from the system interpreter and once from a project virtualenv
containing a single ordinary `pip install -e` artefact produced

    system -> venv   MEDIUM  "Startup/scheduling file(s) appeared ... __editable__.myproj-0.1.0.pth"
    venv -> system   INFO    "Startup/scheduling file(s) were removed ... __editable__.myproj-0.1.0.pth"

on a host where nothing whatsoever had changed — and the MEDIUM arm is above the shipped
cron recipe's threshold, so it would have woken the user, in alternation, forever.

**A drift dimension must be a function of its subject.** The three families that remain are
all rooted in the machine — the account's home and `/etc` — and cannot move because of how
the tool was started.

This is a narrowing, not a silencing, and the distinction is load-bearing: `.pth` and
`sitecustomize` coverage does not disappear, it stays where it was before this module
existed. B99 and B335 still examine them on every audit, and `checks` is itself a watched
dimension, so a malicious hook appearing still reaches the watch through a check's status
moving. What is given up is digest-level drift on that one family — the state of affairs
before F-179 — in exchange for not paging on `pip install -e`.

## Why shell startup files are in scope for an OpenClaw audit

They look like a general host concern rather than an agent one. They are not: B324 covers
`env.shellEnv.enabled`, OpenClaw's option to **import the login shell's environment at
agent startup**. Where that is on, a line appended to `.bashrc` reaches the agent's
process environment directly.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

# Bounds. A persistence surface is small by nature; anything past these is either a
# pathological machine or something that is not really this surface, and in both cases a
# disclosed cap beats an unbounded walk inside a 6-hourly job.
MAX_ENTRIES = 400
MAX_FILE_BYTES = 2 * 1024 * 1024

# Shell startup files, in the order a login shell would consider them. `.zshenv` is
# included because it is read by EVERY zsh invocation, interactive or not, which makes it
# the quietest of the set.
SHELL_RC_NAMES = (
    ".bashrc", ".bash_profile", ".bash_login", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin",
)

# World-readable system cron locations. `/etc/cron.weekly` and `/etc/cron.monthly` are
# deliberately included: a monthly job is a better hiding place than an hourly one.
SYSTEM_CRON_PATHS = (
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
)

# Per-user crontab spools. Never read (see the module docstring) — probed only so their
# existence can be disclosed as UNDETERMINED rather than pass as absent.
USER_CRON_SPOOLS = (
    "/var/spool/cron/crontabs",
    "/var/spool/cron",
)

FAMILY_SYSTEMD = "systemd_user"
FAMILY_SHELL_RC = "shell_rc"
FAMILY_SYSTEM_CRON = "system_cron"
FAMILY_PYTHON_AUTOEXEC = "python_autoexec"

# `FAMILY_PYTHON_AUTOEXEC` is deliberately ABSENT from FAMILIES — see the C-135 note in
# the module docstring. The constant is kept so the removal reads as a decision rather than
# an oversight, and so a future reader who re-adds it finds the reason first.
FAMILIES = (FAMILY_SYSTEMD, FAMILY_SHELL_RC, FAMILY_SYSTEM_CRON)

# Human-facing family names. Kept here rather than in the renderer so the leaf and the
# consumer cannot drift apart on what a family is called.
FAMILY_LABELS = {
    FAMILY_SYSTEMD: "systemd user service",
    FAMILY_SHELL_RC: "shell startup file",
    FAMILY_SYSTEM_CRON: "system cron entry",
}


@dataclass(frozen=True)
class HostEntry:
    """One persistence file, identified but never quoted."""

    family: str
    path: str
    digest: str


@dataclass(frozen=True)
class HostPersistScan:
    entries: "tuple[HostEntry, ...]" = ()
    #: Paths that EXIST but this process could not read. Never empty on a normal Linux
    #: box — the user crontab spool lands here by design.
    unreadable: "tuple[str, ...]" = ()
    #: True when MAX_ENTRIES was hit, so the consumer can disclose a partial view rather
    #: than present it as whole.
    capped: bool = False
    families_seen: "tuple[str, ...]" = field(default=())


def _digest(path: Path) -> "str | None":
    """SHA-256 of a file's bytes, or None if it cannot be read.

    Returns None rather than "" for an unreadable file so the caller can tell "read it,
    it was empty" (a real digest) from "could not read it" — a distinction the whole
    unreadable/undetermined path depends on.
    """
    try:
        if path.is_symlink() and not path.exists():
            return None  # a dangling symlink is not a readable file
        if not path.is_file():
            return None
        if path.stat().st_size > MAX_FILE_BYTES:
            # Digest the bounded prefix and mark it, rather than silently digesting a
            # partial file and passing it off as whole.
            with open(path, "rb") as fh:
                head = fh.read(MAX_FILE_BYTES)
            return "trunc:" + hashlib.sha256(head).hexdigest()
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except (OSError, ValueError):
        return None


def _rel(path: Path, home: Path) -> str:
    """Home-relative where possible; otherwise the path as given.

    `os.path.relpath` is deliberately NOT used: it happily produces `../../etc/crontab`
    for a path outside home, which would both look absurd and vary with where home is.
    """
    try:
        return "~/" + str(path.relative_to(home))
    except ValueError:
        return str(path)


def scan(home: "str | Path | None" = None,
         system_cron_paths: "tuple[str, ...] | None" = None,
         user_cron_spools: "tuple[str, ...] | None" = None) -> HostPersistScan:
    """Enumerate the host persistence surface.

    *home* is taken from the caller, never from ``Path.home()``. That is not a style
    preference: ``Path.home()`` reads the password database on some platforms and ignores
    a redirected ``HOME``, which has already produced a check in this package that could
    not see what it was pointed at. ``--home`` must move this scan, and a test proves it
    does.

    The remaining parameters exist so tests can point the system-wide halves at a
    ``tmp_path`` instead of the real ``/etc``; production callers pass none of them.
    """
    home_path = Path(home).expanduser() if home else Path(os.path.expanduser("~"))
    crons = SYSTEM_CRON_PATHS if system_cron_paths is None else system_cron_paths
    spools = USER_CRON_SPOOLS if user_cron_spools is None else user_cron_spools

    entries: "list[HostEntry]" = []
    unreadable: "list[str]" = []
    seen_paths: "set[str]" = set()
    families_seen: "list[str]" = []
    capped = False

    def add(family: str, path: Path) -> None:
        nonlocal capped
        key = str(path)
        if key in seen_paths:
            return
        if len(entries) >= MAX_ENTRIES:
            capped = True
            return
        seen_paths.add(key)
        digest = _digest(path)
        if digest is None:
            unreadable.append(_rel(path, home_path))
            return
        entries.append(HostEntry(family=family, path=_rel(path, home_path), digest=digest))
        if family not in families_seen:
            families_seen.append(family)

    # ---- systemd user units, timers, and the symlinks that arm them ----------------
    systemd_root = home_path / ".config" / "systemd" / "user"
    if systemd_root.is_dir():
        if FAMILY_SYSTEMD not in families_seen:
            families_seen.append(FAMILY_SYSTEMD)
        try:
            for child in sorted(systemd_root.iterdir()):
                if child.is_dir():
                    # `*.target.wants/` holds the enable symlinks. A unit file that
                    # exists but is not linked here is inert; the link IS the arming, so
                    # a link appearing with no new unit file is the interesting case.
                    try:
                        for link in sorted(child.iterdir()):
                            add(FAMILY_SYSTEMD, link)
                    except OSError:
                        unreadable.append(_rel(child, home_path))
                else:
                    add(FAMILY_SYSTEMD, child)
        except OSError:
            unreadable.append(_rel(systemd_root, home_path))

    # ---- shell startup files -------------------------------------------------------
    for name in SHELL_RC_NAMES:
        candidate = home_path / name
        if candidate.exists() or candidate.is_symlink():
            if FAMILY_SHELL_RC not in families_seen:
                families_seen.append(FAMILY_SHELL_RC)
            add(FAMILY_SHELL_RC, candidate)

    # ---- system-wide cron (world-readable) -----------------------------------------
    for raw in crons:
        p = Path(raw)
        if not p.exists():
            continue
        if FAMILY_SYSTEM_CRON not in families_seen:
            families_seen.append(FAMILY_SYSTEM_CRON)
        if p.is_dir():
            try:
                for child in sorted(p.iterdir()):
                    add(FAMILY_SYSTEM_CRON, child)
            except OSError:
                unreadable.append(str(p))
        else:
            add(FAMILY_SYSTEM_CRON, p)

    # ---- the per-user crontab spool: probed, never read -----------------------------
    # Existence is checked without reading. On a normal box this is where the honest
    # "we cannot see your crontab" note comes from.
    for raw in spools:
        p = Path(raw)
        try:
            if not p.exists():
                continue
            readable = os.access(str(p), os.R_OK)
        except OSError:
            readable = False
        if not readable:
            unreadable.append(str(p))
        break  # the first spool that exists is this platform's; the rest are other distros'

    # Python auto-execution hooks (`.pth`, `sitecustomize.py`) are NOT scanned, and there is
    # deliberately no parameter left behind to re-enable them — see the C-135 note in the
    # module docstring. `test_a_pth_file_is_not_a_watched_family` pins the absence.

    return HostPersistScan(
        entries=tuple(entries),
        unreadable=tuple(sorted(set(unreadable))),
        capped=capped,
        families_seen=tuple(families_seen),
    )


def to_snapshot(result: HostPersistScan) -> dict:
    """Reduce a scan to the JSON-safe shape `monitor.snapshot()` stores.

    Sorted so two runs over an unchanged host produce byte-identical output — the drift
    engine compares these directly, and an unstable key order would fabricate a change on
    every run.
    """
    return {
        "entries": {e.path: {"family": e.family, "digest": e.digest}
                    for e in sorted(result.entries, key=lambda x: x.path)},
        "unreadable": list(result.unreadable),
        "capped": bool(result.capped),
        "families_seen": list(result.families_seen),
    }
