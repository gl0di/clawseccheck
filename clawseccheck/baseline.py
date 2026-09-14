"""Baseline suppression via .clawseccheckignore.

Entries are either a bare check id (e.g. ``B14``) or a full fingerprint
(e.g. ``B14:ab12cd34``).  Suppressed findings are excluded from the score,
the report, and the monitor snapshot.

A bare entry may also be a RISK-* id (e.g. ``RISK-03``): those are matched
directly against ``risk.RiskPath.id`` by ``risk.risk_paths(..., ignore=...)``,
not by this module — RiskPath objects are not part of the ``findings`` list
``apply()`` filters. Suppressing a RISK-id requires listing that RISK-id
explicitly; suppressing only the underlying check(s) does not implicitly
suppress a chain derived from it (see B-154).

C-519: a trailing ``#`` comment may carry optional, machine-parseable
``author=``/``date=``/``expires=`` fields ahead of free text, e.g.::

    B14            # accept the egress-surface advisory
    B12:1a2b3c4d   # author=dave date=2026-09-10 expires=2026-12-10 accept it

Parsing this out fixed a real bug, not just added a feature: the OLD line-level
parser (``if line and not line.startswith("#"): entries.add(line)``) never split
the entry from a trailing comment at all, so ``docs/USAGE.md``'s own shipped
example -- the first line above, verbatim -- produced the single entry
``"B14            # accept the egress-surface advisory"``, which matches no
``Finding.id`` or fingerprint ever, and silently suppressed nothing. A user who
copy-pasted the documented example got no error and no suppression.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .safeio import secure_append_text

# The exact shape fingerprint() produces: <id>:<8 lowercase hex chars>. Used by
# --apply-ignore-proposals (C-253, C-135 2026-07-22) to refuse a proposals-file
# "entry" that isn't actually a fingerprint -- e.g. a bare "B1"/"B2"/"B20" smuggled
# into a hand-crafted (not genuinely --propose-ignore-produced) proposals file,
# which would otherwise suppress that id file-wide via the bare-id match apply()
# already supports, on a file whose whole point is "only ever what a real
# --propose-ignore run already offered."
FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9_-]+:[0-9a-f]{8}$")


def is_fingerprint(entry: str) -> bool:
    """True when *entry* has fingerprint()'s exact ``<id>:<8-hex>`` shape."""
    return isinstance(entry, str) and bool(FINGERPRINT_RE.match(entry))


def fingerprint(finding) -> str:
    """Stable identifier: ``<id>:<sha1-8>`` of the finding detail string."""
    digest = hashlib.sha1(
        finding.detail.encode("utf-8", "replace")
    ).hexdigest()[:8]
    return f"{finding.id}:{digest}"


#: C-519: recognized structured fields in a trailing comment. Matched with word
#: boundaries and no embedded spaces in the value (a value is one whitespace-delimited
#: token) — good enough for an id/name/ISO-date and simple enough that the leftover
#: text after stripping them out is unambiguously "everything else", never a fragment
#: of a field whose own value happened to contain a space.
_STRUCTURED_FIELD_RE = re.compile(r"\b(author|date|expires)=(\S+)")


@dataclass(frozen=True)
class IgnoreEntry:
    """One parsed ``.clawseccheckignore`` line.

    ``entry`` is the bare id/fingerprint ``apply()``/``risk.risk_paths()`` match
    against — never the raw line, and never includes the comment. ``author``/``date``/
    ``expires`` are the structured fields when present (each ``None`` otherwise, not
    an empty string, so a caller can tell "not given" from "given as empty"). ``reason``
    is what remains of the comment after the structured fields are removed, stripped,
    or ``None`` when there was no comment at all. ``expired`` is computed once, here,
    against ``date.today()`` at LOAD time — never re-derived downstream, so a caller
    that reads it later in a long-running process cannot see the date change under it
    mid-run.
    """

    entry: str
    author: "str | None"
    date: "str | None"
    expires: "str | None"
    reason: "str | None"
    expired: bool


def _parse_ignore_line(raw: str) -> "IgnoreEntry | None":
    """One non-blank, non-full-line-comment line -> an ``IgnoreEntry``, or ``None``.

    ``None`` for a blank line, a line that is ENTIRELY a comment (starts with ``#``,
    the pre-C-519 format for a standalone note — ``append_entries`` still writes these
    ahead of a batch), or a line whose id half is empty once the comment is split off
    (a bare ``#`` with nothing before it, which the previous rule already exists to
    handle — this only catches the case where something is CLAIMED before it but
    turns out to be blank after stripping, e.g. a line of only whitespace before ``#``).
    """
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    entry_part, sep, comment_part = line.partition("#")
    entry = entry_part.strip()
    if not entry:
        return None
    comment = comment_part.strip() if sep else ""
    fields = {}
    for m in _STRUCTURED_FIELD_RE.finditer(comment):
        fields[m.group(1)] = m.group(2)
    reason = _STRUCTURED_FIELD_RE.sub("", comment).strip() or None
    expires = fields.get("expires")
    expired = False
    if expires:
        try:
            expired = date.fromisoformat(expires) < date.today()
        except ValueError:
            # An unparseable expires= is disclosed (the raw string survives on the
            # entry, so --show-suppressed can still show it), never treated as
            # "already expired" or "never expires" by guessing -- silently ranking
            # a value neither way here would let a genuine typo either drop a real
            # suppression or keep a genuinely-expired one alive forever.
            expired = False
    return IgnoreEntry(
        entry=entry, author=fields.get("author"), date=fields.get("date"),
        expires=expires, reason=reason, expired=expired,
    )


def load_ignore_entries(home: Path | str) -> "list[IgnoreEntry]":
    """Read ``<home>/.clawseccheckignore`` and return every entry, parsed.

    Includes EXPIRED entries — this is the "everything on file" view
    ``--show-suppressed`` needs to report them; ``load_ignore()`` below is the
    "currently active" view every suppression-consuming call site uses. Returns an
    empty list when the file is absent or unreadable, same fail-open-to-nothing shape
    ``load_ignore()`` always had.
    """
    p = Path(home).expanduser() / ".clawseccheckignore"
    if not p.is_file():
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: "list[IgnoreEntry]" = []
    for raw in text.splitlines():
        parsed = _parse_ignore_line(raw)
        if parsed is not None:
            out.append(parsed)
    return out


def load_ignore(home: Path | str) -> set[str]:
    """Read ``<home>/.clawseccheckignore`` and return the set of ACTIVE entries.

    Each non-blank, non-comment line is one entry (bare id or fingerprint) with any
    trailing ``#`` comment stripped. An entry whose ``expires=`` date (C-519) has
    already passed is excluded — auto-expiry falls out of this one filter, for free,
    for every caller: ``apply()``, ``dead_entries()``, and the bare RISK-id match in
    ``risk.risk_paths(..., ignore=...)`` all consume this same set and none of them
    needs to know expiry exists. Returns an empty set when the file is absent.
    """
    return {e.entry for e in load_ignore_entries(home) if not e.expired}


def apply(findings, ignore: set[str]) -> None:
    """Set ``finding.suppressed = True`` for every finding matched by *ignore*.

    A finding is matched when its bare id *or* its full fingerprint is in the
    ignore set.  Modifies findings in-place; returns nothing.
    """
    if not ignore:
        return
    for f in findings:
        if f.id in ignore or fingerprint(f) in ignore:
            f.suppressed = True


def dead_entries(findings, ignore: set[str]) -> set[str]:
    """B-769: fingerprint-form *ignore* entries that matched no finding this run.

    Only fingerprint entries (``<id>:<8-hex>``) can go dead — a bare id always
    matches its own check's Finding object regardless of status, since every
    registered check contributes exactly one Finding per run. A fingerprint stops
    matching when either the underlying issue was genuinely repaired (the good
    case) or the check's own `detail` wording changed under a ClawSecCheck
    upgrade (measured directly: 14 checks' fingerprints moved between two real
    releases over the same two fixture homes) — in the second case the same
    problem is silently un-suppressed and returns as a fresh, unexplained
    finding. Call this AFTER `apply()` has run, over the same *findings*/*ignore*
    pair, so the two can never disagree about what matched.
    """
    if not ignore:
        return set()
    live = {fingerprint(f) for f in findings}
    return {e for e in ignore if is_fingerprint(e) and e not in live}


def append_entries(home: Path | str, entries, *, comment: str | None = None) -> int:
    """Append *entries* to ``<home>/.clawseccheckignore``, creating it if absent.

    Used by ``--apply-ignore-proposals`` (C-253): the caller has already run its
    own confirmation gate, so this function performs the write unconditionally.
    Entries already present (exact-string match against ``load_ignore``) are
    skipped so a repeated apply cannot grow the file with duplicates. *comment*,
    if given, is written as one ``#``-prefixed line ahead of the new entries so
    a reader can see WHERE a suppression line came from — this does not change
    matching (``apply`` above ignores blank/comment lines) or any of the
    existing safety properties: a suppressed score-capping CRITICAL/HIGH FAIL
    or a ``SENSITIVE_SUPPRESSED_IDS`` id still surfaces regardless of how the
    entry got into this file (see ``report.surfaced_despite_suppression``), and
    any change to this file is still visible to ``--monitor`` (``ignore_hash``).
    Returns the number of entries actually written (0 if none were new).
    """
    p = Path(home).expanduser() / ".clawseccheckignore"
    existing = load_ignore(home)
    new_entries = [e for e in entries if e and e not in existing]
    if not new_entries:
        return 0
    lines = [f"# {comment}"] if comment else []
    lines.extend(new_entries)
    # C-135 (2026-07-22): symlink-safe append (O_NOFOLLOW under the hood) — this is
    # the one write path in this module, so it gets the same protection secure_write_text
    # already gives every other local-store writer in the package.
    secure_append_text(p, "\n".join(lines) + "\n")
    return len(new_entries)
