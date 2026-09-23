"""Coherence guard for skill description across manifest copies.

Architecture note — canonical source, and the deliberate split
----------------------------------------------------------------
ClawHub reads **SKILL.md** as the primary manifest. Its ``metadata:`` key is a
single-line JSON blob that carries a display string:

    metadata.display_description.en  — EN display description (ClawHub)

Until CLAWSECCHECK-B-733 these two copies were required to be byte-identical.
That invariant is gone on purpose: OpenClaw's authenticated personal/team skill
library (``openclaw skills library create``, new in the 9.x line) rejects any
frontmatter ``description`` over 1,024 characters — grounded against the
installed openclaw@2026.9.5 dist, ``prepareSkillLibraryBundle`` (bundle-*.mjs,
filename rotates every release; the symbol name and the message text below do
not):

    if (!frontmatter.name?.trim() || !frontmatter.description?.trim()
        || frontmatter.description.length > 1024)
      throw new SkillLibraryError("INVALID_BUNDLE",
        "SKILL.md requires name and description (at most 1,024 characters).");

That ``.length`` is a JS string length (UTF-16 code units), measured on the
UNTRIMMED value — the ``?.trim()`` calls only feed the earlier emptiness check,
they never re-assign ``frontmatter.description``. Every character actually
used in our description sits in the Basic Multilingual Plane (no emoji, no
astral characters), so JS ``.length`` and Python ``len()`` agree here.

The activation matcher reads frontmatter ``description`` only —
``discovery-*.mjs``: ``const description = frontmatter.description || "";`` —
never ``display_description``, so shortening the frontmatter copy costs no
activation surface as long as the trigger phrases survive the trim (checked
below). Splitting the two fields therefore trades nothing away: the frontmatter
copy stays under every distribution path's ceiling, and
``metadata.display_description.en`` keeps the full, unabridged text verbatim
for ClawHub's own display surface, which does not enforce this limit.

The invariants this module now guards:

  1. SKILL.md ``description`` (frontmatter) is non-empty after trimming and is
     at most 1,024 characters — the skill-library ceiling, pinned so it cannot
     silently regrow past it on a future edit.
  2. SKILL.md ``metadata.display_description.en`` is non-empty and at least as
     long as the frontmatter copy — catches an accidental shrink of the
     display copy, which is supposed to stay the long, canonical text.
  3. The frontmatter description still carries the activation trigger phrases
     a user's request is matched against, so trimming for length never quietly
     drops what makes the skill discoverable.

Stdlib-only, offline. Mirrors the frontmatter-parsing approach of
test_version_coherence.py.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# OpenClaw's skill-library bundle validator ceiling on frontmatter `description`
# (see module docstring for the dist grounding). Keep in sync with any future
# re-measurement against a newer installed OpenClaw.
_DESCRIPTION_CEILING = 1024

# A minimal set of activation trigger phrases the frontmatter description must
# keep verbatim — these are exactly the phrases the "When to use this skill"
# section (and this project's own SKILL.md prose) advertises as what a user
# says to activate it. Pinned so a future trim-for-length edit cannot silently
# drop the vocabulary that makes the skill discoverable.
_TRIGGER_PHRASES = (
    "check or audit your OpenClaw agent's security",
    "prompt-injection",
    "misconfiguration",
    "security score",
    "watch your OpenClaw setup for changes",
    "what changed since the last check",
)

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


def test_frontmatter_description_is_present():
    assert _SKILL_EN_DESC and _SKILL_EN_DESC.strip(), (
        "SKILL.md frontmatter description: is empty — OpenClaw's skill-library "
        "bundle validator rejects a blank description (see module docstring)."
    )


def test_frontmatter_description_within_skill_library_ceiling():
    """Pins the OpenClaw skill-library bundle ceiling (CLAWSECCHECK-B-733).

    SKILL.md frontmatter ``description`` must stay <= 1,024 characters so
    ``openclaw skills library create`` doesn't reject this SKILL.md with
    INVALID_BUNDLE. See the module docstring for the dist grounding — a future
    OpenClaw upgrade that changes this ceiling should re-measure it there
    rather than just bumping the constant here.
    """
    length = len(_SKILL_EN_DESC)
    assert length <= _DESCRIPTION_CEILING, (
        f"SKILL.md frontmatter description is {length} chars, over the "
        f"{_DESCRIPTION_CEILING}-char OpenClaw skill-library ceiling — trim it "
        "(the full text can still live in metadata.display_description.en, "
        "which this ceiling does not apply to)."
    )


def test_display_description_is_not_shorter_than_frontmatter():
    """metadata.display_description.en is meant to stay the long, canonical
    copy; catches an accidental shrink (e.g. someone copying the trimmed
    frontmatter description over it) rather than a deliberate divergence."""
    assert _SKILL_EN_DISPLAY, "SKILL.md metadata.display_description.en is empty"
    assert len(_SKILL_EN_DISPLAY) >= len(_SKILL_EN_DESC), (
        "metadata.display_description.en is shorter than the trimmed frontmatter "
        "description — it should hold the full, untrimmed text:\n"
        f"  description ({len(_SKILL_EN_DESC)} chars):                     "
        f"{_SKILL_EN_DESC!r}\n"
        f"  display_description.en ({len(_SKILL_EN_DISPLAY)} chars): "
        f"{_SKILL_EN_DISPLAY!r}"
    )


def test_frontmatter_description_keeps_trigger_phrases():
    """The trim must not cost activation vocabulary — see module docstring:
    the activation matcher reads frontmatter description only."""
    missing = [phrase for phrase in _TRIGGER_PHRASES if phrase not in _SKILL_EN_DESC]
    assert not missing, (
        "SKILL.md frontmatter description dropped activation trigger phrase(s) "
        f"during a trim: {missing!r}"
    )
