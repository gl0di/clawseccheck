"""B-780 — the shipped `--monitor` description names every dimension family the watch
actually compares.

`docs/FLOW_CHOICES.md`'s monitoring section is what an agent paraphrases to a user *before*
they consent to a baseline, and `docs/USAGE.md`'s "Threat monitoring" section is the detailed
reference. Both drifted silently once already: `clawseccheck/monitordims/` grew from the
original 7-signal design to 19 dimension families (C-433's per-dimension split, plus B-664
execpolicy, B-676 coverage, B-677 credentials, F-174 install/provenance, F-179 hostpersist)
with nobody re-grounding the prose a user actually reads.

This guard does not text-mine the docs for arbitrary phrases — that would be as fragile as the
prose itself. It globs `monitordims/` the same way `tests/test_c417_snapshot_enablers.py`
already does (so a dimension that migrates is still seen), derives the family name from each
module's filename, and requires a maintained keyword for every family in `_FAMILY_KEYWORDS`
below. A new dimension module with no entry here fails this test immediately, forcing whoever
adds it to also decide what word describes it in the docs — and a keyword whose word no longer
appears in either doc's monitoring section fails too, so an edit that strips a family back out
of the prose is caught as surely as a family that was never added.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIMS_DIR = REPO / "clawseccheck" / "monitordims"
FLOW_CHOICES = REPO / "docs" / "FLOW_CHOICES.md"
USAGE = REPO / "docs" / "USAGE.md"

#: Modules in monitordims/ that are not a watched dimension family in their own right.
_NOT_A_FAMILY = {"_shared", "__init__"}

#: family (module stem, underscore stripped) -> a word/phrase that must appear (case-
#: insensitively) in a doc's monitoring prose for that family to count as documented.
#: Keep this in sync with clawseccheck/monitordims/ — a missing entry fails the test below,
#: by design: that is the point at which a new dimension forces a doc decision.
_FAMILY_KEYWORDS = {
    "behavioral": "recorded activity",
    "bootstrap": "SOUL.md",
    "channels": "channel",
    "checks": "leaving PASS",
    "configfile": "config",
    "coverage": "could not compare",
    "credentials": "credential",
    "execpolicy": "shell-command policy",
    "gateway": "gateway",
    "host": "host monitor",
    "hostpersist": "startup/scheduling",
    "install": "OpenClaw package's own digests",
    "mcp": "MCP server",
    "memory": "memory/",
    "native": "openclaw security audit",
    "plugins": "plugin",
    "provenance": "provenance",
    "score": "score",
    "skills": "installed skill",
}


def _dimension_families() -> set:
    families = set()
    for path in sorted(DIMS_DIR.glob("*.py")):
        stem = path.stem
        if stem in _NOT_A_FAMILY:
            continue
        families.add(stem.lstrip("_"))
    return families


def _monitoring_section(text: str, heading_pattern: str) -> str:
    """The text of one `## ...` section, up to (not including) the next `## ` heading."""
    m = re.search(heading_pattern, text)
    assert m, f"heading matching {heading_pattern!r} not found"
    rest = text[m.end():]
    nxt = re.search(r"\n## ", rest)
    return rest[: nxt.start()] if nxt else rest


def test_every_monitordims_module_has_a_keyword_mapping():
    """A new dimension module with no `_FAMILY_KEYWORDS` entry fails here first — before
    it can silently ship undocumented, the way the original 7-signal count did."""
    families = _dimension_families()
    missing = sorted(families - set(_FAMILY_KEYWORDS))
    assert not missing, (
        f"clawseccheck/monitordims/ grew {missing} with no doc keyword registered in "
        "tests/test_b780_monitor_doc_grounding.py::_FAMILY_KEYWORDS — add an entry, and "
        "make sure docs/FLOW_CHOICES.md and docs/USAGE.md's monitoring prose actually "
        "names it, before this test is allowed to go green again."
    )


def test_family_keyword_map_has_no_stale_entries():
    """The reverse direction: an entry for a family that no longer exists under
    monitordims/ is a stale mapping, not a documented dimension."""
    families = _dimension_families()
    stale = sorted(set(_FAMILY_KEYWORDS) - families)
    assert not stale, (
        f"_FAMILY_KEYWORDS names {stale}, which no longer has a module under "
        "clawseccheck/monitordims/ — remove the stale entry (or the family was renamed "
        "and the mapping key needs to follow it)."
    )


def test_flow_choices_monitoring_section_names_every_dimension_family():
    """FLOW_CHOICES.md's monitoring choice is what an agent paraphrases to a user before
    they consent to a baseline (the exact gap B-780 was filed over) — it must name every
    family, not a stale subset."""
    text = FLOW_CHOICES.read_text(encoding="utf-8")
    section = _monitoring_section(
        text, r"## Choice: monitoring / \"keep watching\""
    )
    missing = sorted(
        family
        for family, keyword in _FAMILY_KEYWORDS.items()
        if keyword.lower() not in section.lower()
    )
    assert not missing, (
        f"docs/FLOW_CHOICES.md's monitoring section no longer mentions: {missing} "
        "(checked via their _FAMILY_KEYWORDS keyword) — re-ground the prose."
    )


def test_usage_monitoring_section_names_every_dimension_family():
    """USAGE.md's '## Threat monitoring' section is the detailed reference a user or
    agent reads for what the watch actually compares — same completeness bar as
    FLOW_CHOICES.md, checked separately because the two sections are independent prose."""
    text = USAGE.read_text(encoding="utf-8")
    section = _monitoring_section(text, r"## Threat monitoring")
    missing = sorted(
        family
        for family, keyword in _FAMILY_KEYWORDS.items()
        if keyword.lower() not in section.lower()
    )
    assert not missing, (
        f"docs/USAGE.md's '## Threat monitoring' section no longer mentions: {missing} "
        "(checked via their _FAMILY_KEYWORDS keyword) — re-ground the prose."
    )
