"""The skill manifest's text, as the agent actually sees it (C-709).

``SKILL.md`` is delivered whole-or-nothing by OpenClaw's ``skills_read``, so the body is kept
small and the long protocol text lives in on-demand files under ``docs/playbook/``. A test that
pins a sentence of the protocol therefore has to say *which* of two things it pins:

* ``skill_body()``   - ``SKILL.md`` alone: what is ALWAYS in the agent's context. Use it for a
                       mandatory rule that must never move out of the body.
* ``skill_corpus()`` - ``SKILL.md`` plus every ``docs/playbook/*.md``: the whole protocol, wherever
                       a section currently lives. Use it for a shape, an example or a description of
                       tool output, and for EVERY negative pin (``not in`` / ``not search``): a
                       phrase that is absent from the body alone is not absent from the protocol.

The corpus deliberately EXCLUDES ``docs/FLOW_CHOICES.md``, ``docs/ISOLATION.md`` and
``references/cli-flags.md``: those were never part of the manifest.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_MD = ROOT / "SKILL.md"
PLAYBOOK_DIR = ROOT / "docs" / "playbook"


def skill_body() -> str:
    """``SKILL.md`` alone, front matter included (``skills_read`` returns the raw file)."""
    return SKILL_MD.read_text(encoding="utf-8")


def playbook_files() -> list[Path]:
    """Every ``docs/playbook/*.md``, sorted by name (empty list when the directory is absent)."""
    if not PLAYBOOK_DIR.is_dir():
        return []
    return sorted(p for p in PLAYBOOK_DIR.glob("*.md") if p.is_file())


def skill_corpus() -> str:
    """``SKILL.md`` followed by every playbook file, each playbook file after a marker line.

    ``SKILL.md`` comes first and unprefixed on purpose: its front matter must stay the first thing
    in the string, so a test that parses the corpus as a manifest still finds ``---`` on line 1.
    Each playbook file is introduced by ``# file: docs/playbook/<NAME>.md`` on its own line.
    """
    parts = [skill_body()]
    for path in playbook_files():
        rel = path.relative_to(ROOT).as_posix()
        parts.append("\n# file: " + rel + "\n" + path.read_text(encoding="utf-8"))
    return "".join(parts)
