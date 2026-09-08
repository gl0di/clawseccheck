"""The `skills` dimension — the installed skills and how much of them was read.

The signature records a per-skill digest AND the truncation frontier, because "this skill
did not change" and "we did not finish reading this skill" are different answers and only
one of them is an all-clear. `_scan_truncated_skills` is what keeps them apart.
"""

from __future__ import annotations
import re  # noqa: F401

from ._shared import NOTE_INSPECTION_CAPPED, _h  # noqa: F401


_SKILL_VERSION_RE = re.compile(r"(?im)^\s*version:\s*['\"]?([\w.\-+]+)['\"]?\s*$")


def _b62_families(name: str, ctx) -> "frozenset":
    """Thin wrapper around checks._b62_actual_families (lazy import, B62 substrate)."""
    from ..checks import _b62_actual_families  # noqa: PLC0415
    return _b62_actual_families(name, ctx, ctx.installed_skill_py.get(name, []))


def _skill_sig(ctx) -> dict:
    """name -> {hash, tree, tree_complete, scan_partial, caps, version}.

    ``hash`` is the historical digest of the SCANNED blob; ``tree`` is the B-267
    full-directory fingerprint that actually answers "did this skill change?". Old
    snapshots stored a bare hash string, and pre-B-267 snapshots carry a dict with no
    ``tree`` key; diff() handles both (see ``_skill_entry``).

    B-267: hashing only ``ctx.installed_skills[name]`` made the drift signal inherit the
    malware-scanner's budget. That blob is TEXT-only and capped, so the three stealthiest
    in-place backdoors — a same-size binary swap under ``bin/``, an appended directive in a
    file past the per-skill budget, and an edit inside a file dropped whole for exceeding
    the per-file cap — every one of them left the stored signature byte-identical and the
    monitor silent. Measured first-hand on all three before the fix: zero alerts. This is
    the exact scenario --monitor exists for (malware landing in a skill already trusted),
    and the tool was holding the contradicting evidence: the collector already records a
    ``limit_hits`` line saying content beyond the cap was NOT scanned, which monitor.py
    never read.

    ``scan_partial`` carries that evidence into the snapshot. It does NOT weaken the change
    signal — ``tree`` covers the unscanned region for change-detection purposes — but it
    marks a skill whose CONTENT was never fully vetted, so a "NEW"/"CHANGED" alert can say
    so rather than implying the new state was inspected and found benign.
    """
    from ..collector import skill_tree_signature  # noqa: PLC0415 (leaf import, no cycle)

    partial = _scan_truncated_skills(ctx)
    out = {}
    for name, blob in ctx.installed_skills.items():
        m = _SKILL_VERSION_RE.search(blob)
        entry = {
            "hash": _h(blob),
            "caps": sorted(_b62_families(name, ctx)),
            "version": m.group(1) if m else None,
            "scan_partial": name in partial,
        }
        skill_dir = (getattr(ctx, "installed_skill_dirs", None) or {}).get(name)
        if skill_dir is not None:
            try:
                sig = skill_tree_signature(skill_dir)
            except OSError:
                sig = None
            if sig is not None:
                entry["tree"] = sig["digest"]
                entry["tree_complete"] = bool(sig["complete"])
        out[name] = entry
    return out


# B-267: the collector's per-skill text-cap limit_hit, e.g.
#   text scan of skill 'clawstealth' hit the 1000KB/500-file cap — …
# Parsed rather than re-derived so there is a single source of truth for "was this skill's
# content fully scanned?" — the collector decides, monitor only reports.
_SCAN_TRUNCATED_RE = re.compile(r"text scan of skill '([^']+)' hit the ")


def _scan_truncated_skills(ctx) -> "set[str]":
    """Names of skills whose CONTENT scan the collector reports as truncated."""
    out: set[str] = set()
    for hit in (getattr(ctx, "limit_hits", None) or []):
        m = _SCAN_TRUNCATED_RE.search(str(hit))
        if m:
            out.add(m.group(1))
    return out


def _diff_skills_common(
        _skill_caps_unknown,
        _skill_changed,
        _skill_entry,
        _skill_ver_unknown,
        _ver_tuple,
        alerts,
        cs,
        ps,
) -> None:
    """Skills present on both sides: content, capabilities and version, each compared apart.

    Separate signals on purpose — a content change with an unchanged version is a different
    fact from a version bump, and collapsing them would lose the more interesting one.
    """
    for name in sorted(ps.keys() & cs.keys()):
        p_hash, p_caps, p_ver = _skill_entry(ps[name])
        c_hash, c_caps, c_ver = _skill_entry(cs[name])
        if _skill_changed(ps[name], cs[name]):
            _partial = isinstance(cs[name], dict) and cs[name].get("scan_partial")
            alerts.append(("HIGH",
                           f"Installed skill '{name}' CHANGED since last check — re-review it."
                           + (" NOTE: this skill is too large to scan in full, so the "
                              "change may lie outside the region the audit inspects."
                              if _partial else "")))
        elif (isinstance(cs[name], dict) and cs[name].get("tree")
              and cs[name].get("tree_complete") is False):
            # B-267: the fingerprint walk itself could not cover the whole directory, so an
            # unchanged digest is NOT proof of no change. Say so rather than let silence
            # imply coverage (the same B-074 rule that turns a truncated scan into UNKNOWN
            # instead of PASS).
            alerts.append(("INFO",
                           f"Installed skill '{name}' is too large to fingerprint in full — "
                           "part of its directory is not covered by change detection, so "
                           "'unchanged' cannot be confirmed for that region."))

        # Capability diff — only when BOTH sides carry structured caps (new-format
        # snapshots); a legacy/UNKNOWN side skips silently rather than fabricating a diff.
        if p_caps is None or c_caps is None:
            _skill_caps_unknown.add(name)
        if p_caps is not None and c_caps is not None:
            added = set(c_caps) - set(p_caps)
            removed = set(p_caps) - set(c_caps)
            if added:
                alerts.append(("HIGH",
                               f"Installed skill '{name}' UPDATE EXPANDED its capabilities: "
                               f"+{', '.join(sorted(added))} — the new version can now do more "
                               "than the version you last reviewed; re-vet it."))
            elif removed:
                alerts.append(("INFO",
                               f"Skill '{name}' capabilities shrank: -{', '.join(sorted(removed))}."))

        # Version regression — best-effort static downgrade signal only. Real TAM-09
        # "replay an old *signed* manifest" semantics require verifying a signature
        # against a trust root, which is impossible read-only/offline; this merely
        # compares the declared frontmatter version string across snapshots.
        if not (p_ver and c_ver):
            _skill_ver_unknown.add(name)
        if p_ver and c_ver:
            try:
                if _ver_tuple(c_ver) < _ver_tuple(p_ver):
                    alerts.append(("MEDIUM",
                                   f"Skill '{name}' declared version went BACKWARD: "
                                   f"{p_ver} -> {c_ver} — a manifest replay / downgrade signal "
                                   "(TAM-09, best-effort static)."))
            except TypeError:
                pass


def _diff_skills_added(alerts, cs, prev_sk_capped, prev_sk_partial, ps) -> None:
    """A skill that is here now and was not before.

    The truncation frontier is consulted first: a skill the previous run never finished
    reading was not absent, and calling it new would be an alert about our own cap.
    """
    for name in sorted(cs.keys() - ps.keys()):
        if name in prev_sk_capped:
            # Known to have been on disk last run, merely beyond the cap. Calling it NEW
            # would misdate the install — the CRITICAL says "this is when malware lands",
            # and that claim must not be made about a skill that was already there.
            continue
        _partial = isinstance(cs[name], dict) and cs[name].get("scan_partial")
        _scan_note = (" NOTE: this skill is too large to scan in full, so the audit's "
                      "verdict on it covers only part of its content." if _partial else "")
        if prev_sk_partial:
            # The previous frontier was itself truncated, so we cannot confirm this skill
            # is new. Down-rank and disclose rather than suppress: staying silent about a
            # possibly-just-installed skill is the worse error of the two, and this is the
            # project's standing rule that an ambiguous signal is reported at reduced
            # strength rather than asserted or dropped.
            alerts.append(("HIGH",
                           f"Skill '{name}' is now being inspected and was not inspected "
                           "last run — it may be newly installed, or it may have been "
                           "present all along outside the inspection cap (too many skills "
                           "were installed last run to tell). Vet its source." + _scan_note))
            continue
        alerts.append(("CRITICAL",
                       f"NEW skill installed since last check: '{name}' — vet its source "
                       "before trusting it (this is when malware lands)." + _scan_note))


def _note_skills_capped(_sk_capped_n, alerts, curr_sk_capped) -> None:
    """Disclose that this run did not finish reading every skill.

    An uncounted skill is not a clean one, and a cap the reader cannot see reads as
    "that was all of them".
    """
    if _sk_capped_n:
        _eg = sorted(curr_sk_capped)[:3]
        alerts.append((
            "HIGH",
            f"{_sk_capped_n} installed skill(s) were NOT collected — the inspection cap "
            "was reached, so they are neither scanned nor monitored for change"
            + (f" (e.g. {', '.join(_eg)})" if _eg else "")
            + ". Skills are collected in filename order, so which ones fall outside the "
            "cap is not a security decision. Reduce the number of installed skills to "
            "restore full coverage."))


def _diff_skills_removed(
        alerts,
        cs,
        curr_sk_capped,
        curr_sk_partial,
        ps,
        trust_removals,
) -> None:
    """A skill that is gone, once removals can be trusted at all."""
    if trust_removals:
        for name in sorted(ps.keys() - cs.keys()):
            # B-268: still on disk this run, just cap-evicted — not a removal. When the
            # frontier is itself truncated we cannot tell the two apart for ANY name, so
            # every removal is suppressed: a missed removal notice (INFO) is a far smaller
            # harm than a burst of fabricated ones, and the disclosure below states that
            # coverage is incomplete.
            if name in curr_sk_capped or curr_sk_partial:
                continue
            alerts.append(("INFO", f"Skill '{name}' was removed."))


def _note_skills_frontier_partial(curr, curr_sk_capped, curr_sk_partial, note) -> None:
    """The frontier is partial without a count — say so rather than inferring a number."""
    if curr_sk_partial and not (curr.get("skills_capped_count") or curr_sk_capped):
        note(NOTE_INSPECTION_CAPPED,
             "Skills that disappeared were not reported: this run could not establish the "
             "full list of what is installed, so removed cannot be told from not-looked-at.")


def _note_skills_prev_capped(note, prev_sk_capped) -> None:
    """The BASELINE was capped, so this run cannot tell an addition from a resumed read."""
    # C-418: THIS run's truncation already gets a HIGH alert below (`_sk_capped_n`), so it
    # is not repeated as a note. What has no voice at all is the PREVIOUS run's truncation:
    # a skill that was over the cap last time and is inspected now is deliberately not
    # announced as new — correctly, since calling it new would misdate the install — but
    # the user is then never told it appeared.
    if prev_sk_capped:
        note(NOTE_INSPECTION_CAPPED,
             f"{len(prev_sk_capped)} skill(s) now being inspected were beyond the "
             f"inspection cap last run, so they are not announced as newly installed.")
