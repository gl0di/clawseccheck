"""Structured Attestation Request (SAR) builder — F-020.

A SAR is a machine-readable intent-judgement question emitted by ClawSecCheck
for the *user's host agent* to answer.  The tool itself NEVER calls an LLM or
the network — it only assembles structured data that the agent can respond to
without reading raw skill source (which would expose it to prompt-injection from
that very source).

Each SAR covers one skill that B62 flagged as having a capability–intent mismatch
and contains:

  {
    "skill":            <str>    skill directory name / frontmatter name,
    "declared_purpose": <str>    description: from SKILL.md (redacted),
    "capability_set":   [<str>]  sorted actual capability families detected,
    "mismatches":       [        capabilities that were NOT expected for the category
      {
        "capability":  <str>,    e.g. "network"
        "declared":    false,    always false — the capability was NOT declared
        "evidence":    <str>     human-readable evidence fragment (redacted)
      }
    ],
    "computed_risk":    <str>    "high" (any network/exec/cred) or "medium",
    "question":         <str>    plain-language attestation question for the host agent
  }

Trust model:
  - Pure presentation/serialisation layer over what B62 already determined.
  - Does NOT re-run any check; reads only ctx.effect_profiles and ctx.installed_skills.
  - All text routed through logsafe.redact so no raw secrets appear in the SAR.
  - JSON-only output (machine-readable); no Hebrew/i18n needed.

Stdlib only.  No network, no subprocess, no writes.
"""
from __future__ import annotations

import re

from .logsafe import redact

# --------------------------------------------------------------------------- constants
_B62_HIGH_SURPRISE = frozenset({"network", "exec", "cred"})

# Regex to extract `description:` value from a SKILL.md frontmatter blob.
_DESC_RE = re.compile(
    r"^# file:\s+SKILL\.md\s*\n---\s*\n(?:.*?\n)*?description:\s*([^\n#]+)",
    re.MULTILINE,
)

# Regex to extract `name:` from the SKILL.md frontmatter.
_NAME_RE = re.compile(
    r"^# file:\s+SKILL\.md\s*\n---\s*\n(?:.*?\n)*?name:\s*([^\n#]+)",
    re.MULTILINE,
)


# --------------------------------------------------------------------------- helpers

def _extract_declared_purpose(blob: str) -> str:
    """Return the `description:` field from the frontmatter blob, or ''."""
    m = _DESC_RE.search(blob)
    return m.group(1).strip() if m else ""


def _extract_skill_name(blob: str, dir_key: str) -> str:
    """Return the frontmatter `name:`, falling back to the directory key."""
    m = _NAME_RE.search(blob)
    if m:
        name = m.group(1).strip()
        if name:
            return name
    return dir_key


def _compute_risk(surprising: frozenset) -> str:
    """'high' if any high-surprise family is present; 'medium' otherwise."""
    if surprising & _B62_HIGH_SURPRISE:
        return "high"
    return "medium"


def _build_question(skill_name: str, declared_purpose: str, surprising: frozenset) -> str:
    """Compose a plain-language attestation question for the host agent."""
    cap_list = ", ".join(sorted(surprising))
    purpose_clause = (
        f"declared as '{declared_purpose}'" if declared_purpose
        else f"named '{skill_name}'"
    )
    return (
        f"The skill '{skill_name}' is {purpose_clause} but has reachable "
        f"{cap_list} capabilities that were not expected for that category. "
        f"Is this intentional? [yes/no + reason]"
    )


# --------------------------------------------------------------------------- public API

def build_sars(ctx: object) -> list[dict]:
    """Build the SAR list from a Context that has been through a B62 pass.

    Reads ctx.installed_skills, ctx.installed_skill_py, and ctx.effect_profiles.
    Re-runs the lightweight B62 classification logic (same functions, same results)
    to enumerate mismatches; does NOT re-run the full check_capability_intent_mismatch
    to avoid importing checks.py (circular) — this module duplicates only the
    classification helpers it needs.

    Returns a list of SAR dicts (one per mismatch-flagged skill), sorted by skill name.
    An empty list means no mismatches — the host agent needs no answer.
    """
    installed = getattr(ctx, "installed_skills", {})
    installed_py = getattr(ctx, "installed_skill_py", {})

    if not installed:
        return []

    # Import the B62 helpers from checks here (lazy import avoids a top-level
    # circular dependency; checks.py does not import sar.py).
    from .checks import (  # noqa: PLC0415
        _b62_classify_category,
        _b62_extract_declaration,
        _b62_actual_families,
        _b62_surprising_families,
        _B62_EXPECTED,
        _B62_HIGH_SURPRISE as _CHECKS_HIGH_SURPRISE,
    )

    sars: list[dict] = []

    for dir_key, blob in sorted(installed.items()):
        py_sources = installed_py.get(dir_key, [])
        if not py_sources:
            continue

        name_raw, description_raw = _b62_extract_declaration(blob, dir_key)
        if not name_raw and not description_raw:
            continue

        category = _b62_classify_category(name_raw, description_raw)
        if category is None or category == "PERMISSIVE":
            continue

        expected = _B62_EXPECTED[category]
        actual = _b62_actual_families(dir_key, ctx, py_sources)
        if not actual:
            continue

        surprising = _b62_surprising_families(actual, expected)
        if not surprising:
            continue

        high_s = surprising & _CHECKS_HIGH_SURPRISE
        if not (high_s or len(surprising) >= 2):
            continue

        # ---- assemble the SAR for this skill --------------------------------

        skill_name = redact(_extract_skill_name(blob, dir_key))
        declared_purpose = redact(_extract_declared_purpose(blob))

        mismatches = [
            {
                "capability": cap,
                "declared": False,
                "evidence": redact(
                    f"'{dir_key}' declared as '{category}' but has reachable "
                    f"'{cap}' capability (not expected for that category)"
                ),
            }
            for cap in sorted(surprising)
        ]

        sars.append({
            "skill": skill_name,
            "declared_purpose": declared_purpose,
            "capability_set": sorted(actual),
            "mismatches": mismatches,
            "computed_risk": _compute_risk(surprising),
            "question": redact(_build_question(skill_name, declared_purpose, surprising)),
        })

    return sars
