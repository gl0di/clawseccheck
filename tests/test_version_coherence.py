"""Version lock-step coherence guard (§6).

A release bumps the version in four places that different consumers read
(``clawseccheck.__version__``, ``__released__``, ``SKILL.md`` frontmatter, the
top ``CHANGELOG.md`` entry). The publish workflow only checks the git tag against
``SKILL.md`` at publish time — too late, and blind to ``__version__``/CHANGELOG.

This turns any desync into a red build *before* tagging:
  - __version__ == SKILL.md version: == top CHANGELOG version
  - __released__ == that CHANGELOG entry's date
  - __version__ is a valid X.Y.Z semver
  - __released__ is a valid ISO (YYYY-MM-DD) date

Offline, stdlib. See scripts/bump.py, which writes all four in one step.
"""
from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_INIT = (ROOT / "clawseccheck" / "__init__.py").read_text(encoding="utf-8")
_SKILL = (ROOT / "SKILL.md").read_text(encoding="utf-8")
_CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

_VERSION = re.search(r'^__version__ = "([^"]+)"', _INIT, re.M).group(1)
_RELEASED = re.search(r'^__released__ = "([^"]+)"', _INIT, re.M).group(1)
_SKILL_VERSION = re.search(r"^version:\s*(\S+)", _SKILL, re.M).group(1)

# Top CHANGELOG entry: "## [X.Y.Z] — YYYY-MM-DD" (tolerate em-dash or hyphen).
_CHANGELOG_TOP = re.search(r"^##\s*\[([^\]]+)\]\s*[—-]\s*(\S+)", _CHANGELOG, re.M)


def test_changelog_has_a_top_entry():
    assert _CHANGELOG_TOP, "CHANGELOG.md has no '## [version] — date' entry"


def test_version_sources_agree():
    chg_version = _CHANGELOG_TOP.group(1)
    assert _VERSION == _SKILL_VERSION == chg_version, (
        "version lock-step mismatch: "
        f"__version__={_VERSION!r}, SKILL.md={_SKILL_VERSION!r}, "
        f"CHANGELOG={chg_version!r} — run scripts/bump.py to sync."
    )


def test_released_matches_changelog_date():
    chg_date = _CHANGELOG_TOP.group(2)
    assert _RELEASED == chg_date, (
        f"__released__={_RELEASED!r} != top CHANGELOG date {chg_date!r}; "
        "bump __released__ to the release date (run scripts/bump.py)."
    )


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", _VERSION), (
        f"__version__={_VERSION!r} is not a bare X.Y.Z semver"
    )


def test_released_is_iso_date():
    try:
        _dt.date.fromisoformat(_RELEASED)
    except ValueError:  # pragma: no cover - the assert reports it
        raise AssertionError(f"__released__={_RELEASED!r} is not a valid ISO date") from None
