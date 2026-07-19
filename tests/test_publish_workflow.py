"""Tests for BLK-04 supply-chain fixes in the ClawHub publish workflow.

Reads the YAML as plain text — no pyyaml dependency (stdlib only).
"""
import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "clawhub-publish.yml"
SKILL_PATH = REPO_ROOT / "SKILL.md"

STAGING_DIR = "dist/clawseccheck"

# A markdown inline link: ](target). Captures everything up to the closing paren.
_MD_LINK_RE = re.compile(r"\]\(([^)]+)\)")


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


def _join_continuations(text: str) -> list[str]:
    """Collapse trailing-backslash shell line continuations into single logical lines."""
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.endswith("\\"):
            buf += stripped[:-1].strip() + " "
            continue
        logical.append((buf + stripped).strip())
        buf = ""
    if buf:
        logical.append(buf.strip())
    return logical


def _staged_paths(text: str) -> set[str]:
    """Paths (relative to the staging root) that the workflow's `cp` lines produce.

    Models the two shapes the staging step actually uses:
        cp -r A B C  dist/clawseccheck/           -> "A", "B", "C"
        cp references/cli-flags.md dist/clawseccheck/references/ -> "references/cli-flags.md"

    A `cp` of SRC into DEST lands at <DEST minus the staging prefix>/<basename(SRC)>.
    Anything later deleted by an `rm -rf dist/clawseccheck/...` line is removed again,
    so the deliberate `docs/assets` purge is honoured rather than papered over.
    """
    staged: set[str] = set()
    removed: set[str] = set()

    for line in _join_continuations(text):
        if line.startswith("rm -rf "):
            for token in line[len("rm -rf "):].split():
                if token.startswith(STAGING_DIR + "/"):
                    removed.add(token[len(STAGING_DIR) + 1:].rstrip("/"))
            continue
        if not line.startswith("cp "):
            continue
        args = [a for a in line[len("cp "):].split() if not a.startswith("-")]
        if len(args) < 2:
            continue
        sources, dest = args[:-1], args[-1].rstrip("/")
        if not dest.startswith(STAGING_DIR):
            continue
        subdir = dest[len(STAGING_DIR):].strip("/")
        for src in sources:
            base = src.rstrip("/").rsplit("/", 1)[-1]
            staged.add(f"{subdir}/{base}" if subdir else base)

    return {
        path
        for path in staged
        if not any(path == r or path.startswith(r + "/") for r in removed)
    }


def _skill_relative_links() -> list[str]:
    """Relative (non-URL, non-anchor) markdown link targets declared in SKILL.md."""
    targets = []
    for raw in _MD_LINK_RE.findall(SKILL_PATH.read_text(encoding="utf-8")):
        target = raw.strip().split()[0]  # drop an optional "title" suffix
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        targets.append(target.split("#", 1)[0])  # strip any anchor
    return targets


def test_staging_parser_is_not_vacuous() -> None:
    """Guard the guard: a parse that silently returns nothing would pass everything.

    Without this, a future reformat of the staging step (different quoting, a heredoc,
    a move to an action) would make _staged_paths() return an empty set and the
    dangling-link test below would go vacuously green — the exact hollow-PASS shape
    these cross-checks exist to prevent.
    """
    staged = _staged_paths(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert staged, (
        "_staged_paths() parsed no files out of the publish workflow. The staging step "
        "was probably reshaped — update the parser, don't let this test pass vacuously."
    )
    # SKILL.md is mandatory for any clawhub publish; if the parser cannot see it, it is
    # not actually reading the staging step.
    assert "SKILL.md" in staged, (
        f"Parser did not find SKILL.md among staged paths {sorted(staged)!r} — "
        "the staging step's cp lines are not being parsed correctly."
    )
    assert _skill_relative_links(), (
        "No relative markdown links parsed out of SKILL.md — the link cross-check "
        "below would be vacuous. Check _MD_LINK_RE against SKILL.md's actual syntax."
    )


def test_every_skill_md_relative_link_is_staged_for_publish() -> None:
    """Every relative link in SKILL.md must resolve in the published tree (B-254).

    Root cause this pins down: the staging step is a hand-maintained `cp` allowlist that
    nothing cross-checked against the manifest. `references/` was simply missing, so every
    ClawHub install shipped a dead link to references/cli-flags.md. Adding a link to
    SKILL.md without staging its target now fails the build here instead of silently
    shipping a 404 to users.
    """
    staged = _staged_paths(WORKFLOW_PATH.read_text(encoding="utf-8"))
    links = _skill_relative_links()

    for target in links:
        # The link must not be dangling in the source repo either.
        assert (REPO_ROOT / target).exists(), (
            f"SKILL.md links to {target!r}, which does not exist in the repo."
        )
        covered = any(
            target == entry or target.startswith(entry.rstrip("/") + "/")
            for entry in staged
        )
        assert covered, (
            f"SKILL.md links to {target!r} but the publish workflow's staging step never "
            f"copies it, so every ClawHub install ships a dangling link.\n"
            f"Staged paths: {sorted(staged)!r}\n"
            f"Fix: copy it into {STAGING_DIR}/ in the 'Stage publishable files' step."
        )


def test_dangling_link_guard_detects_a_missing_target() -> None:
    """Negative control: the cross-check must actually fire when staging drops a path.

    Feeds the parser a staging step with the references/ copy deleted — i.e. the exact
    pre-B-254 workflow — and asserts references/cli-flags.md is then reported as unstaged.
    This proves the guard has teeth without needing anyone to hand-mutate the workflow.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    regressed = "\n".join(
        line for line in text.splitlines()
        if "cp references/cli-flags.md" not in line
    )
    assert regressed != text, (
        "Expected to find the 'cp references/cli-flags.md' staging line to remove; "
        "the B-254 fix appears to have been reworded — update this negative control."
    )

    staged_after_regression = _staged_paths(regressed)
    assert not any(
        "references/cli-flags.md" == entry
        or "references/cli-flags.md".startswith(entry.rstrip("/") + "/")
        for entry in staged_after_regression
    ), (
        "Removing the references/ copy from the staging step did NOT make "
        "references/cli-flags.md look unstaged — the cross-check is not actually "
        "sensitive to the regression it is meant to catch."
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
