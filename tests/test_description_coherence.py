"""Coherence guard for skill description across manifest copies.

Architecture note — canonical source
-------------------------------------
ClawHub reads **SKILL.md** as the primary manifest. Its ``metadata:`` key is a
single-line JSON blob that carries the authoritative EN display string:

    metadata.display_description.en  — EN display description (ClawHub)

The one invariant this module guards:

  EN internal coherence (within SKILL.md):
    SKILL.md ``description`` == SKILL.md ``metadata.display_description.en``

Stdlib-only, offline. Mirrors the frontmatter-parsing approach of
test_version_coherence.py.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_SKILL_EN_TEXT = (ROOT / "SKILL.md").read_text(encoding="utf-8")


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
_SKILL_EN_DESC = _get_description(_EN_FM)
_SKILL_EN_DISPLAY = _get_display_description(_EN_FM, "en")


def test_en_description_copies_agree():
    """SKILL.md description: must equal SKILL.md metadata.display_description.en."""
    assert _SKILL_EN_DESC == _SKILL_EN_DISPLAY, (
        "EN description drift detected in SKILL.md — the two copies diverged:\n"
        f"  description:                     {_SKILL_EN_DESC!r}\n"
        f"  metadata.display_description.en: {_SKILL_EN_DISPLAY!r}"
    )
