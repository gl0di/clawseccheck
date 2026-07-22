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
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def fingerprint(finding) -> str:
    """Stable identifier: ``<id>:<sha1-8>`` of the finding detail string."""
    digest = hashlib.sha1(
        finding.detail.encode("utf-8", "replace")
    ).hexdigest()[:8]
    return f"{finding.id}:{digest}"


def load_ignore(home: Path | str) -> set[str]:
    """Read ``<home>/.clawseccheckignore`` and return the set of entries.

    Each non-blank, non-comment line is one entry (bare id or fingerprint).
    Returns an empty set when the file is absent.
    """
    p = Path(home).expanduser() / ".clawseccheckignore"
    if not p.is_file():
        return set()
    entries: set[str] = set()
    try:
        for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                entries.add(line)
    except OSError:
        pass
    return entries


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
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(new_entries)
