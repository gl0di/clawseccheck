"""Two-pass confidence-based finding deduplication for ClawSecCheck.

Pass 1 — same-"file" dedup: collapses findings with the same check id, file/path
context, and matched-text snippet, keeping the highest-confidence instance.

Pass 2 — cross-file dedup: collapses findings with the same check id and matched
text regardless of file, again keeping the highest-confidence instance. Only runs
for findings that carry a non-empty matched_text (or detail) snippet so that distinct
findings that happen to share only a check id are never merged.

Both passes operate purely on Finding metadata — no I/O, no network, stdlib only.
"""
from __future__ import annotations

from typing import List

# Confidence tier → numeric score used when comparing two findings that share a
# dedup key. Higher score = stronger evidence = kept.
_CONF_MAP = {
    "high": 1.0,
    "attested": 0.75,
    "medium": 0.5,
    "low": 0.25,
}

# Sort order for status (primary) and severity (secondary) in the final output.
_STATUS_ORDER = {"FAIL": 0, "WARN": 1, "PASS": 2, "UNKNOWN": 3}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _confidence_score(f: object) -> float:
    """Return a numeric confidence for *f*, higher = more trustworthy."""
    c = getattr(f, "confidence", "HIGH")
    if isinstance(c, (int, float)):
        return float(c)
    return _CONF_MAP.get(str(c).lower(), 0.5)


def _matched_text_key(f: object) -> str:
    """Return a short content fingerprint for cross-file dedup.

    Prefers an explicit ``matched_text`` attribute (used by some scanners);
    falls back to the first 100 chars of ``detail``.  Returns ``""`` when
    neither is available so that findings without content are never cross-file
    deduped.
    """
    mt = getattr(f, "matched_text", None) or getattr(f, "detail", "") or ""
    return mt[:100]


def _check_id(f: object) -> str:
    """Return the check/rule identifier, supporting both ClawSecCheck and
    generic scanner Finding shapes."""
    # ClawSecCheck Finding uses ``f.id``; generic scanners may use
    # ``check_id`` or ``rule_id``.
    return (
        getattr(f, "check_id", None)
        or getattr(f, "rule_id", None)
        or getattr(f, "id", "")
        or ""
    )


def _path(f: object) -> str:
    """Return the file/path for same-file grouping.  ClawSecCheck Finding has
    no path field — returns ``""`` so all findings for a given check are
    treated as co-located."""
    return getattr(f, "path", None) or getattr(f, "file", None) or ""


def _sort_key(f: object):
    status = getattr(f, "status", "") or ""
    severity = getattr(f, "severity", "") or ""
    return (
        _STATUS_ORDER.get(status.upper(), 9),
        _SEV_ORDER.get(severity.upper(), 9),
        _path(f),
        getattr(f, "line", 0) or 0,
        _check_id(f),
    )


def deduplicate_findings(findings: List) -> List:
    """Two-pass dedup: same-file, then cross-file. Keep highest-confidence instance.

    Args:
        findings: list of Finding (or duck-type equivalent) objects.

    Returns:
        A new list with duplicates removed, sorted FAIL → WARN → PASS → UNKNOWN,
        then by severity (CRITICAL → HIGH → MEDIUM → LOW).
    """
    # ------------------------------------------------------------------ #
    # Pass 1: same-file dedup                                              #
    # Key = (check_id, path, matched_text[:100])                          #
    # ------------------------------------------------------------------ #
    same_file_seen: dict = {}
    pass1_order: list = []  # preserves insertion order

    for f in findings:
        key = (_check_id(f), _path(f), _matched_text_key(f))
        if key not in same_file_seen:
            same_file_seen[key] = f
            pass1_order.append(f)
        else:
            incumbent = same_file_seen[key]
            if _confidence_score(f) > _confidence_score(incumbent):
                idx = pass1_order.index(incumbent)
                pass1_order[idx] = f
                same_file_seen[key] = f

    # ------------------------------------------------------------------ #
    # Pass 2: cross-file dedup                                             #
    # Key = (check_id, matched_text[:100])                                 #
    # Only for findings that carry a non-empty content fingerprint.        #
    # ------------------------------------------------------------------ #
    cross_seen: dict = {}
    pass2: list = []

    for f in pass1_order:
        mt = _matched_text_key(f)
        if not mt:
            # No content fingerprint — cannot safely cross-file dedup.
            pass2.append(f)
            continue
        key = (_check_id(f), mt)
        if key not in cross_seen:
            cross_seen[key] = f
            pass2.append(f)
        else:
            incumbent = cross_seen[key]
            if _confidence_score(f) > _confidence_score(incumbent):
                idx = pass2.index(incumbent)
                pass2[idx] = f
                cross_seen[key] = f

    return sorted(pass2, key=_sort_key)
