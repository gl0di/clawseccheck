"""Tests for BLK-04 supply-chain fixes in the ClawHub publish workflow.

Reads the YAML as plain text — no pyyaml dependency (stdlib only).
"""
import json
from pathlib import Path

import pytest

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "clawhub-publish.yml"
)
SKILL_PATH = Path(__file__).resolve().parents[1] / "SKILL.md"


def _skill_display_name_en() -> str:
    """The en display name declared in SKILL.md frontmatter metadata (inline JSON)."""
    fm = SKILL_PATH.read_text(encoding="utf-8").split("---", 2)[1]
    for line in fm.splitlines():
        if line.startswith("metadata:"):
            meta = json.loads(line.split("metadata:", 1)[1].strip())
            return meta["display_name"]["en"]
    raise AssertionError("no metadata: line in SKILL.md frontmatter")

# The published skill package ships without .github/ (CI files are repo-only), so these
# workflow-validation tests have nothing to read there. Skip — don't FAIL — when the file
# is absent, so the suite stays green whether run from the source repo or a packaged install.
pytestmark = pytest.mark.skipif(
    not WORKFLOW_PATH.exists(),
    reason="CI workflow file not present (packaged skill ships without .github/); "
           "publish-workflow tests run only from the source repo.",
)


def _lines() -> list[str]:
    return WORKFLOW_PATH.read_text(encoding="utf-8").splitlines()


def test_publish_workflow_pins_clawhub() -> None:
    """clawhub must be installed at an exact pinned version (clawhub@X.Y.Z).

    A bare 'npm i -g clawhub' line (with no '@' version suffix) must not exist.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    # The pinned form must be present.
    assert "clawhub@" in text, (
        "Expected 'clawhub@<version>' pin in workflow but found none."
    )
    # No bare unpinned install line (the pattern: contains 'npm' and 'clawhub'
    # but lacks '@' on the same line as 'clawhub').
    for line in _lines():
        stripped = line.strip()
        if "npm" in stripped and "clawhub" in stripped:
            assert "@" in stripped, (
                f"Found unpinned clawhub install line: {line!r}\n"
                "Change it to 'npm i -g clawhub@<version>'."
            )


def test_publish_workflow_runs_smoke_before_publish() -> None:
    """pytest and ruff check must both appear BEFORE the clawhub publish line."""
    lines = _lines()

    def first_index_containing(needle: str) -> int:
        for i, line in enumerate(lines):
            if needle in line:
                return i
        return -1

    pytest_idx = first_index_containing("pytest")
    ruff_idx = first_index_containing("ruff check")
    publish_idx = first_index_containing("clawhub publish")

    assert pytest_idx != -1, "No line containing 'pytest' found in workflow."
    assert ruff_idx != -1, "No line containing 'ruff check' found in workflow."
    assert publish_idx != -1, "No line containing 'clawhub publish' found in workflow."

    assert pytest_idx < publish_idx, (
        f"'pytest' (line {pytest_idx}) must appear before 'clawhub publish' "
        f"(line {publish_idx})."
    )
    assert ruff_idx < publish_idx, (
        f"'ruff check' (line {ruff_idx}) must appear before 'clawhub publish' "
        f"(line {publish_idx})."
    )


def test_publish_workflow_has_environment_gate() -> None:
    """The publish job must declare an 'environment:' field for the approval gate."""
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "environment:" in text, (
        "The publish job must declare 'environment:' to enable the manual-approval gate."
    )


def test_publish_workflow_dir_basename_matches_slug() -> None:
    """The published directory basename becomes the ClawHub display title (B-015).

    ClawHub title-cases the basename of the published dir (there is no display-name
    flag we pass). Publishing ./dist-skill produced the title "Dist Skill"; the
    staging dir must instead end in 'clawseccheck' so the title reads "Clawseccheck".
    """
    publish_line = next(
        (line for line in _lines() if "clawhub publish" in line), None
    )
    assert publish_line is not None, "No 'clawhub publish' line found in workflow."

    # Token right after 'clawhub publish' is the path being published.
    after = publish_line.split("clawhub publish", 1)[1].strip()
    published_path = after.split()[0]
    basename = published_path.rstrip("/").rsplit("/", 1)[-1]

    assert basename == "clawseccheck", (
        f"Published dir basename {basename!r} (from {published_path!r}) must be "
        "'clawseccheck' so the ClawHub title is not derived from a staging-dir name."
    )
    assert not basename.startswith("dist"), (
        f"Published dir basename {basename!r} still looks like a staging dir — "
        "ClawHub would title-case it into a wrong display name."
    )


def test_publish_sets_display_name_matching_skill_md() -> None:
    """The publish command must pass --name set to SKILL.md's display_name.en (B-015 #2).

    ClawHub titles a skill from --name (grounded: `clawhub publish --help`); without it the
    dir basename title-cases to "Clawseccheck". The flag value must equal the declared
    display name so the live title is "ClawSecCheck — …" and the two never drift.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    expected = _skill_display_name_en()
    assert f'--name "{expected}"' in text, (
        f"publish workflow must pass --name \"{expected}\" (from SKILL.md "
        "metadata.display_name.en); found no matching --name flag."
    )


def test_publish_workflow_does_not_echo_token() -> None:
    """No line must both echo/cat a value and reference CLAWHUB_TOKEN."""
    for line in _lines():
        lower = line.lower()
        references_token = "CLAWHUB_TOKEN" in line
        echoes = any(cmd in lower for cmd in ("echo ", "cat "))
        assert not (echoes and references_token), (
            f"Line appears to echo/cat CLAWHUB_TOKEN (supply-chain risk): {line!r}"
        )
