"""Coherence guard for skill description across manifest copies.

Architecture note — canonical sources
--------------------------------------
ClawHub reads **SKILL.md** as the primary manifest. Its ``metadata:`` key is a
single-line JSON blob that carries the authoritative bilingual display strings:

    metadata.display_description.en  — EN display description (ClawHub EN)
    metadata.display_description.he  — HE display description (ClawHub HE)

SKILL_HE.md is the conversational HE manifest. It deliberately has **no**
``metadata:`` block; ClawHub fetches the HE display text from SKILL.md above.
SKILL_HE.md only carries its own ``description:`` scalar, which must mirror the
canonical HE string in SKILL.md so a reader of either file sees consistent text.

The two invariants this module guards:

  1. EN internal coherence (within SKILL.md):
       SKILL.md ``description`` == SKILL.md ``metadata.display_description.en``

  2. HE cross-manifest coherence:
       SKILL_HE.md ``description`` == SKILL.md ``metadata.display_description.he``

Cross-language equality (EN vs HE) is NOT checked; the two descriptions may
legitimately differ.

Do NOT "fix" a failing HE test by adding a ``metadata:`` block to SKILL_HE.md —
that block must not exist there. The right fix is to sync SKILL_HE.md
``description:`` with SKILL.md ``metadata.display_description.he``.

Stdlib-only, offline. Mirrors the frontmatter-parsing approach of
test_version_coherence.py.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_SKILL_EN_TEXT = (ROOT / "SKILL.md").read_text(encoding="utf-8")
_SKILL_HE_TEXT = (ROOT / "SKILL_HE.md").read_text(encoding="utf-8")


def _extract_frontmatter(text: str, filename: str) -> str:
    """Return the raw YAML frontmatter block (between the opening and closing ---)."""
    m = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not m:
        raise ValueError(f"No YAML frontmatter (--- block) found in {filename}")
    return m.group(1)


def _get_description(frontmatter: str) -> str | None:
    """Extract the scalar value of the ``description:`` key from frontmatter."""
    m = re.search(r"^description:\s*(.+)", frontmatter, re.M)
    return m.group(1).strip() if m else None


def _get_display_description(frontmatter: str, lang: str) -> str | None:
    """Extract ``metadata.display_description.<lang>`` from the inline JSON metadata blob.

    SKILL.md's ``metadata:`` value is a single-line JSON object.  Returns None
    if the key is absent, JSON is malformed, or the nested path does not exist.
    """
    m = re.search(r"^metadata:\s*(\{.+\})", frontmatter, re.M)
    if not m:
        return None
    try:
        metadata = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    return metadata.get("display_description", {}).get(lang)


_EN_FM = _extract_frontmatter(_SKILL_EN_TEXT, "SKILL.md")
_HE_FM = _extract_frontmatter(_SKILL_HE_TEXT, "SKILL_HE.md")

# EN: both values live inside SKILL.md
_SKILL_EN_DESC = _get_description(_EN_FM)
_SKILL_EN_DISPLAY = _get_display_description(_EN_FM, "en")

# HE: description lives in SKILL_HE.md; canonical display source is SKILL.md metadata
_SKILL_HE_DESC = _get_description(_HE_FM)
_SKILL_HE_DISPLAY = _get_display_description(_EN_FM, "he")  # sourced from SKILL.md


def test_en_description_copies_agree():
    """SKILL.md description: must equal SKILL.md metadata.display_description.en."""
    assert _SKILL_EN_DESC == _SKILL_EN_DISPLAY, (
        "EN description drift detected in SKILL.md — the two copies diverged:\n"
        f"  description:                     {_SKILL_EN_DESC!r}\n"
        f"  metadata.display_description.en: {_SKILL_EN_DISPLAY!r}"
    )


def test_he_description_copies_agree():
    """SKILL_HE.md description: must equal SKILL.md metadata.display_description.he.

    SKILL_HE.md carries no metadata block (by design); the canonical HE display
    string lives in SKILL.md metadata.display_description.he.  Both must match.
    """
    assert _SKILL_HE_DESC == _SKILL_HE_DISPLAY, (
        "HE description drift detected — the two copies diverged:\n"
        f"  SKILL_HE.md description:                  {_SKILL_HE_DESC!r}\n"
        f"  SKILL.md metadata.display_description.he: {_SKILL_HE_DISPLAY!r}"
    )
