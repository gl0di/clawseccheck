"""Tests for BLK-04 supply-chain fixes in the ClawHub publish workflow.

Reads the YAML as plain text — no pyyaml dependency (stdlib only).
"""
import json
import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "clawhub-publish.yml"
SKILL_PATH = REPO_ROOT / "SKILL.md"
README_PATH = REPO_ROOT / "README.md"

# A real, trimmed GET /api/v1/skills/clawseccheck/versions/4.1.0 response, captured
# 2026-09-18. It exists because the stubbed bodies below were previously hand-written
# in a FLAT shape the API never served, which made clawhub-version-live.sh's signal 1
# unsatisfiable while every test around it stayed green (B-827) — both the script and
# its fixtures shared one wrong model. Deriving the stub shape from a captured response
# is the same discipline tests/dist_verified_paths.txt applies to the OpenClaw schema:
# ground the shape in evidence, don't retype it from a description.
CLAWHUB_VERSION_RESPONSE = REPO_ROOT / "tests" / "clawhub_version_response.json"


def _versions_body(version: str, files: list) -> dict:
    """Build a versions-endpoint body in the REAL nested shape.

    Everything the discriminator reads lives under the top-level `version` object;
    there is no top-level `files`. Starting from the captured response keeps the
    surrounding structure honest even though only these two keys are asserted on.
    """
    captured = json.loads(CLAWHUB_VERSION_RESPONSE.read_text(encoding="utf-8"))
    captured["version"]["version"] = version
    captured["version"]["files"] = files
    return captured

# Every shipped markdown file that links out to other repo paths. All of them are read by
# users of an installed skill, so a relative link the bundle does not carry is a 404 on
# every ClawHub install.
#
# DERIVED, never hand-listed. SKILL.md was guarded first (B-254), then README.md — and a
# hand-maintained pair is exactly what let the third site through: docs/README.md carried
# the same dangling ../CONTRIBUTING.md link and was invisible to a two-entry allowlist.
# `docs/` is copied wholesale, so a doc added there ships without anyone editing this
# file. Deriving the set from the workflow's own staging step means a new staged doc is
# covered the day it lands.
def _linking_staged_docs() -> dict:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    staged = _staged_paths(text)
    purged = _purged_paths(text)
    out = {}
    for path in sorted(REPO_ROOT.rglob("*.md")):
        if any(part in {".git", "node_modules", "fixtures", "dist"} for part in path.parts):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        # CHANGELOG.md is exempt for the same reason test_doc_facts.py exempts it: it is a
        # historical record, not a navigation surface. Its entries quote link syntax as
        # PROSE — the B59 entry contains a literal `![](http…?data=…)` illustrating the
        # exfil shape that check detects — which is a description, not a link to resolve.
        if rel == "CHANGELOG.md":
            continue
        if _is_shipped(rel, staged, purged) and _relative_links(path):
            out[rel] = path
    return out

STAGING_DIR = "dist/clawseccheck"

# A markdown inline link: ](target). Captures everything up to the closing paren.
_MD_LINK_RE = re.compile(r"\]\(([^)]+)\)")

#: B-606: a link inside a code span or a fenced block is not a link -- it is the literal
#: text of an example. The anti-link clause the skill prints to the host had to SHOW the
#: forbidden syntax (`[report.pdf](path)`) to be understood, and the naive regex read the
#: illustration as a dangling link to `references/path`. Stripped before matching rather
#: than filtered after, so nested cases need no special handling. Measured before changing
#: it: across every guarded doc, the only targets the naive regex sees and this one does not
#: are exactly those two illustrations -- the guard loses no real coverage.
_MD_FENCE_RE = re.compile(r"```.*?```", re.S)
_MD_CODE_SPAN_RE = re.compile(r"`[^`\n]*`")


def _prose_only(text: str) -> str:
    """*text* with fenced blocks and inline code spans removed."""
    return _MD_CODE_SPAN_RE.sub("", _MD_FENCE_RE.sub("", text))


def test_a_link_inside_a_code_span_is_not_treated_as_a_link(tmp_path):
    """Guard the guard (B-606). The skill's own anti-link clause has to SHOW the forbidden
    syntax to be understood, and the naive regex read that illustration as a dangling link.
    Both halves are asserted: an example inside a code span or a fence is ignored, and a
    real link in prose is still found -- a fix that stopped seeing links entirely would
    pass the first assertion alone."""
    doc = tmp_path / "d.md"
    doc.write_text(
        "Never write a link. `[report.pdf](path)` is one.\n\n"
        "```text\n[also.pdf](other)\n```\n\n"
        "See [the usage guide](docs/USAGE.md) for more.\n",
        encoding="utf-8")
    found = _relative_links(doc)
    assert "docs/USAGE.md" in found, found
    assert "path" not in found, found
    assert "other" not in found, found


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


def _code_lines() -> list[tuple[int, str]]:
    """(original 0-based lineno, text) for every line that is NOT a whole-line comment.

    Comments are prose: they *discuss* flags and commands they do not run. Scanning them
    as if they were code is how a guard starts passing on its own documentation — the
    `--dry-run` guard below was satisfied by the word "--dry-run" inside the explanatory
    comment above the step, so deleting the real flag left the suite green while the
    workflow would have uploaded twice for real. Strip comments before parsing anything.
    """
    return [
        (i, ln) for i, ln in enumerate(_lines()) if not ln.lstrip().startswith("#")
    ]


# A step begins with '- name:' or '- uses:' in the steps: list.
_STEP_RE = re.compile(r"^\s*-\s+(?:name|uses):")


def _steps() -> list[list]:
    """Group the workflow's comment-stripped lines into steps.

    Each element is the list of (lineno, text) pairs belonging to one step, starting
    with its '- name:'/'- uses:' line. Lines before the first step (the on:/jobs:
    preamble) are not part of any step and are dropped.
    """
    steps: list[list] = []
    current = None
    for lineno, text in _code_lines():
        if _STEP_RE.match(text):
            current = [(lineno, text)]
            steps.append(current)
        elif current is not None:
            current.append((lineno, text))
    return steps


def _publish_invocations() -> list[dict]:
    """Every step that actually RUNS `clawhub publish`, attributed to its own step.

    Step-aware on purpose (this is the fix for a real regression): the dry-run preflight
    step's `run:` body contains the literal `clawhub publish` too, so any guard that
    located "the publish command" by first-match over a flat line scan inspected the
    PREFLIGHT and left the real Publish step completely unguarded — its path and --name
    could both be broken with the suite still green. Each dict carries:
        name     the step's display name
        line     0-based lineno of the line where `clawhub publish` appears
        args     everything after `clawhub publish` (the path + flags), whitespace-normalised
        dry_run  whether this invocation passes --dry-run
    """
    invocations: list[dict] = []
    for step in _steps():
        body = " ".join(text.strip() for _, text in step)
        if "clawhub publish" not in body:
            continue
        name_match = re.search(r"-\s+name:\s*(.+)", step[0][1])
        line = next(
            (lineno for lineno, text in step if "clawhub publish" in text), step[0][0]
        )
        args = " ".join(body.split("clawhub publish", 1)[1].split())
        invocations.append(
            {
                "name": name_match.group(1).strip() if name_match else "<unnamed step>",
                "line": line,
                "args": args,
                "dry_run": "--dry-run" in args,
            }
        )
    return invocations


def _real_publish_invocation() -> dict:
    """The ONE invocation that actually writes to the registry (no --dry-run).

    Asserting exactly one is what makes the dry-run guard real: drop the --dry-run flag
    and this file suddenly declares two real publishes, which fails here loudly instead
    of quietly double-uploading the same version.
    """
    invocations = _publish_invocations()
    assert invocations, "No step in the workflow runs 'clawhub publish'."
    real = [inv for inv in invocations if not inv["dry_run"]]
    assert len(real) == 1, (
        f"Expected exactly ONE real (non --dry-run) 'clawhub publish', found {len(real)}: "
        f"{[inv['name'] for inv in real]}.\n"
        "Two real invocations would upload the same version twice (did a --dry-run flag "
        "get dropped?); zero means nothing is actually published."
    )
    return real[0]


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
    """pytest and ruff check must both run BEFORE any clawhub publish invocation.

    Anchored to the FIRST invocation (the dry-run preflight): that step already reaches
    the network and resolves the version against the registry, so the smoke gate has to
    precede it too, not merely the final upload. Comment lines are excluded so a mention
    of a command in prose cannot satisfy the ordering.
    """
    code = _code_lines()

    def first_index_containing(needle: str) -> int:
        for lineno, text in code:
            if needle in text:
                return lineno
        return -1

    pytest_idx = first_index_containing("pytest")
    ruff_idx = first_index_containing("ruff check")

    invocations = _publish_invocations()
    assert invocations, "No step in the workflow runs 'clawhub publish'."
    publish_idx = min(inv["line"] for inv in invocations)

    assert pytest_idx != -1, "No line containing 'pytest' found in workflow."
    assert ruff_idx != -1, "No line containing 'ruff check' found in workflow."

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

    ClawHub title-cases the basename of the published dir when --name is absent.
    Publishing ./dist-skill produced the title "Dist Skill"; the staging dir must
    instead end in 'clawseccheck' so even the fallback title reads "Clawseccheck".

    Anchored to the REAL invocation, not the first line that mentions one: the dry-run
    preflight step also runs `clawhub publish`, and a first-match line scan inspected
    that instead, leaving the actual published path unguarded.
    """
    real = _real_publish_invocation()

    # Token right after 'clawhub publish' is the path being published.
    published_path = real["args"].split()[0]
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

    Checked against the REAL invocation's own argument list. Searching the whole file for
    the string would be satisfied by the dry-run step's copy of the flag while the real
    publish shipped a wrong title.
    """
    expected = _skill_display_name_en()
    real = _real_publish_invocation()
    assert f'--name "{expected}"' in real["args"], (
        f"The real publish step must pass --name \"{expected}\" (from SKILL.md "
        f"metadata.display_name.en).\nIts actual arguments were: {real['args']!r}"
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


def _normalise_link_target(raw: str):
    """Reduce a raw `](...)` capture to a repo-relative path, or None to skip it.

    THE NORMALISATION CONTRACT — four rules, in this order:
      1. drop an optional `"title"` suffix (everything from the first whitespace)
      2. skip absolute URLs / mailto: / pure #anchors
      3. drop the #fragment
      4. drop a leading ./

    The publish workflow's preflight step re-implements these same four rules in shell,
    because the static check here and the runtime check there answer different questions
    ("does the workflow say it copies X" vs "is X actually in the tree we built"). Two
    implementations means they can disagree, and they did — in both directions: a valid
    titled link `[x](a.md "T")` passed here and FAILED the shell (a spurious
    release-blocker), while `[x](./a.md)` failed here and passed the shell.
    test_preflight_shell_agrees_with_python_normaliser executes the real shell block and
    diffs it against this function, so the two cannot drift apart again.
    """
    stripped = raw.strip()
    if not stripped:
        return None
    target = stripped.split()[0]                       # 1. drop the "title"
    if target.startswith(("http://", "https://", "mailto:", "#")):
        return None                                    # 2. not a repo-relative path
    target = target.split("#", 1)[0]                   # 3. drop the #fragment
    if target.startswith("./"):
        target = target[2:]                            # 4. drop a leading ./
    return target or None


def _relative_links(path: Path) -> list[str]:
    """Relative (non-URL, non-anchor) markdown link targets declared in *path*.

    Returned repo-relative, resolved against the LINKING DOC'S OWN directory: `CHECKS.md`
    inside docs/FAQ.md means docs/CHECKS.md, and `../clawseccheck/catalog.py` means
    clawseccheck/catalog.py. Resolving against the repo root instead was correct only
    while every guarded doc sat at the root, and reported ten false danglers the moment
    the guarded set grew to include docs/.
    """
    targets = []
    try:
        base = path.parent.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        # A doc outside the repo — the pre-fix guard test feeds a tmp_path copy of a
        # root-level doc. Treat it as sitting at the repo root, which is what it stands in for.
        base = ""
    for raw in _MD_LINK_RE.findall(_prose_only(path.read_text(encoding="utf-8"))):
        target = _normalise_link_target(raw)
        if target is None:
            continue
        resolved = os.path.normpath(os.path.join(base, target))
        # A link escaping the repo is not something the bundle can carry either way.
        if resolved.startswith(".."):
            continue
        targets.append(Path(resolved).as_posix())
    return targets


def _skill_relative_links() -> list[str]:
    """Relative markdown link targets declared in SKILL.md."""
    return _relative_links(SKILL_PATH)


def _purged_paths(text: str) -> set:
    """Staging-relative paths deleted by an `rm -rf dist/clawseccheck/...` line.

    Kept separate from _staged_paths() because the interesting case is a *prefix*
    deletion: `docs` is staged as a whole and `docs/assets` is then purged, so
    `docs/assets/x.png` is NOT shipped even though the staged entry `docs` covers it.
    The coverage predicate must subtract these or it reports a link as fine while the
    publish-time preflight (correctly) fails on it.
    """
    purged = set()
    for line in _join_continuations(text):
        if not line.startswith("rm -rf "):
            continue
        for token in line[len("rm -rf "):].split():
            if token.startswith(STAGING_DIR + "/"):
                purged.add(token[len(STAGING_DIR) + 1:].rstrip("/"))
    return purged


def _is_shipped(target: str, staged: set, purged: set) -> bool:
    """Does `target` survive into the published tree? (staged by some entry, not purged)"""
    def under(paths) -> bool:
        return any(
            target == p or target.startswith(p.rstrip("/") + "/") for p in paths
        )

    return under(staged) and not under(purged)


# Computed here rather than beside its definition: it needs the parsing helpers above,
# and it must exist at import time for the parametrize below.
LINKING_STAGED_DOCS = _linking_staged_docs()


def test_the_guarded_doc_set_is_derived_and_covers_the_known_sites() -> None:
    """Guard the guard: an empty or shrunken set would pass every link check silently.

    The floor names the three docs that have each shipped a dangling link — SKILL.md
    (B-254, references/), README.md and docs/README.md (both ../CONTRIBUTING.md). It is a
    floor, not an equality: the set is meant to grow on its own when a staged doc gains a
    relative link, which is the whole reason it is derived rather than hand-listed.
    """
    assert len(LINKING_STAGED_DOCS) >= 3, (
        f"only {len(LINKING_STAGED_DOCS)} staged docs with relative links were derived "
        f"({sorted(LINKING_STAGED_DOCS)!r}) — the staging parser or _relative_links is "
        "not seeing what it should, and the link cross-check is near-vacuous."
    )
    for required in ("SKILL.md", "README.md", "docs/README.md"):
        assert required in LINKING_STAGED_DOCS, (
            f"{required} is staged and links out, but fell out of the derived set — "
            "the cross-check below would no longer cover it."
        )


def test_staging_parser_is_not_vacuous() -> None:
    """Guard the guard: a parse that silently returns nothing would pass everything.

    Without this, a future reformat of the staging step (different quoting, a heredoc,
    a move to an action) would make _staged_paths() return an empty set and the
    dangling-link test below would go vacuously green — the exact hollow-PASS shape
    these cross-checks exist to prevent.
    """
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    staged = _staged_paths(workflow_text)
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
    for doc_name, doc_path in sorted(LINKING_STAGED_DOCS.items()):
        assert _relative_links(doc_path), (
            f"No relative markdown links parsed out of {doc_name} — the link cross-check "
            f"below would be vacuous for it. Check _MD_LINK_RE against its actual syntax."
        )
    # Each guarded doc must actually reach the bundle, or the cross-check guards a file
    # nobody ships. Tested with _is_shipped rather than literal membership: `docs/` is
    # copied as a directory, so docs/CHECKS.md never appears in `staged` by name.
    purged = _purged_paths(workflow_text)
    for doc_name in LINKING_STAGED_DOCS:
        assert _is_shipped(doc_name, staged, purged), (
            f"{doc_name} is cross-checked for dangling links but the staging step does "
            f"not carry it into the bundle. Either stage it or exclude it."
        )


@pytest.mark.parametrize("doc_name", sorted(LINKING_STAGED_DOCS))
def test_every_relative_link_in_a_staged_doc_is_staged_for_publish(doc_name: str) -> None:
    """Every relative link in a staged doc must resolve in the published tree (B-254).

    Root cause this pins down: the staging step is a hand-maintained `cp` allowlist that
    nothing cross-checked against the docs it copies. `references/` was simply missing, so
    every ClawHub install shipped a dead link to references/cli-flags.md. Adding a link
    without staging its target now fails the build here instead of silently shipping a
    404 to users.

    Covers README.md as well as SKILL.md: both are staged, both link out, and README
    carried the same defect (a relative CONTRIBUTING.md link, a file the bundle does not
    include). Guarding only the manifest left the other half of the published reading
    surface unchecked.

    Note the image links under docs/assets/ do not appear here: README references those
    with raw `<img src=...>` HTML, which `_MD_LINK_RE` deliberately does not match. That
    purge is intentional (~650KB of repo-page art kept out of installs) and stays
    unflagged without needing a special case.
    """
    doc_path = LINKING_STAGED_DOCS[doc_name]
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    staged = _staged_paths(text)
    purged = _purged_paths(text)

    for target in _relative_links(doc_path):
        # The link must not be dangling in the source repo either.
        assert (REPO_ROOT / target).exists(), (
            f"{doc_name} links to {target!r}, which does not exist in the repo."
        )
        assert _is_shipped(target, staged, purged), (
            f"{doc_name} links to {target!r} but the publish workflow's staging step "
            f"never copies it, so every ClawHub install ships a dangling link.\n"
            f"Staged paths: {sorted(staged)!r}\n"
            f"Fix: either copy it into {STAGING_DIR}/ in the 'Stage publishable files' "
            f"step, or make the link an absolute https://github.com/... URL if the "
            f"target is a repo-side concern that should not ship."
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


def test_readme_link_guard_detects_the_pre_fix_contributing_link(tmp_path) -> None:
    """Negative control: the README leg must fire on the exact defect it was added for.

    Before the fix, README's documentation table linked `[Contributing](CONTRIBUTING.md)`
    relatively. CONTRIBUTING.md is not in the staging step's `cp` allowlist, so that link
    404'd on every ClawHub install — the same defect class as the references/ one, in the
    other staged doc. Reconstructs that pre-fix README and asserts the shipped predicate
    reports it as unstaged, so this leg cannot go quietly vacuous the way a guard that
    only ever sees a fixed tree does.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    staged, purged = _staged_paths(text), _purged_paths(text)

    pre_fix = tmp_path / "README.md"
    pre_fix.write_text(
        "| [User guide](docs/USAGE.md) | Recipes |\n"
        "| [Contributing](CONTRIBUTING.md) | Dev setup |\n",
        encoding="utf-8",
    )
    targets = _relative_links(pre_fix)
    assert "CONTRIBUTING.md" in targets, (
        f"The pre-fix README fixture did not parse into a CONTRIBUTING.md link: {targets!r}"
    )

    assert not _is_shipped("CONTRIBUTING.md", staged, purged), (
        "CONTRIBUTING.md now counts as shipped, so the README leg of the link guard "
        "would no longer catch the regression it was added for. If the staging step "
        "genuinely started copying it, delete this control; do not leave it toothless."
    )
    # The control must not be self-fulfilling: a normal staged target still passes.
    assert _is_shipped("docs/USAGE.md", staged, purged), (
        "docs/USAGE.md must count as shipped — otherwise this control proves nothing "
        "beyond _is_shipped() rejecting everything."
    )

    # And the real README must no longer carry that relative link.
    assert "CONTRIBUTING.md" not in _relative_links(README_PATH), (
        "README.md links to CONTRIBUTING.md relatively again. It is not staged for "
        "publish, so that link is dead on every ClawHub install — use the absolute "
        "https://github.com/gl0di/clawseccheck/blob/main/CONTRIBUTING.md URL instead."
    )


def test_link_guard_honours_the_docs_assets_purge() -> None:
    """A link under a deliberately-purged directory must count as NOT shipped.

    `docs` is staged wholesale and `docs/assets` is then `rm -rf`'d (repo-page images,
    ~650KB, deliberately kept out of installs). A prefix match on the staged entry `docs`
    reported docs/assets/* as covered, so this guard would have waved through a SKILL.md
    link that the publish-time preflight then failed on — CI green, release blocked.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    staged, purged = _staged_paths(text), _purged_paths(text)

    assert "docs/assets" in purged, (
        f"Expected the docs/assets purge among {sorted(purged)!r} — the workflow's "
        "rm -rf line was reworded; update this control."
    )
    assert _is_shipped("docs/USAGE.md", staged, purged), (
        "A normal file under the staged docs/ tree must count as shipped."
    )
    assert not _is_shipped("docs/assets/banner.png", staged, purged), (
        "docs/assets/* is purged after staging, so it must NOT count as shipped."
    )


def _preflight_shell_block() -> str:
    """Extract the literal `run: |` body of the staged-tree preflight step.

    Executed verbatim by the agreement test below, so the thing under test is the real
    workflow shell rather than a paraphrase of it that could quietly stop matching.
    """
    lines = _lines()
    start = next(
        (
            i for i, ln in enumerate(lines)
            if ln.strip().startswith("- name:") and "verify the staged tree" in ln
        ),
        None,
    )
    assert start is not None, (
        "Could not find the '- name: Preflight — verify the staged tree locally' step "
        "in the workflow — it was renamed; update this extractor."
    )
    run_i = None
    for i in range(start + 1, len(lines)):
        if lines[i].strip().startswith("- name:"):
            break
        if lines[i].strip() == "run: |":
            run_i = i
            break
    assert run_i is not None, (
        "The preflight step no longer uses a 'run: |' literal block; update this extractor."
    )
    indent = len(lines[run_i]) - len(lines[run_i].lstrip())
    body = []
    for ln in lines[run_i + 1:]:
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
            break
        body.append(ln)
    return textwrap.dedent("\n".join(body))


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_preflight_shell_agrees_with_python_normaliser(tmp_path) -> None:
    """The shell and Python link resolvers must normalise every shape identically.

    Two implementations of one contract WILL drift, and these two did — in both
    directions (a valid titled link failed only in shell; a './'-prefixed link failed
    only in Python). A CI-green run then no longer implied a publish-safe bundle.

    Method: build a staged tree where every relative target is deliberately absent, run
    the REAL preflight block, and read back the targets it names in its `::error::` lines
    — that output IS the shell's normalised form. Compare to _normalise_link_target().
    Offline, deterministic, confined to tmp_path.
    """
    cases = [
        ("[a](nope/plain.md)", "nope/plain.md"),
        ('[b](nope/titled.md "A Title")', "nope/titled.md"),
        ("[c](./nope/dotslash.md)", "nope/dotslash.md"),
        ("[d](nope/anchored.md#usage)", "nope/anchored.md"),
        ("[e](./nope/all.md#frag)", "nope/all.md"),
        ("[f](https://example.com/not-a-file.md)", None),
        ("[g](http://example.com/x)", None),
        ("[h](mailto:someone@example.com)", None),
        ("[i](#local-anchor)", None),
        # EXTRACTION, not normalisation. These are why the comparison exists at all now:
        # the two sides agreed on all four normalisation rules and still disagreed about
        # what counts as a link, because only the Python side stripped code (B-606). The
        # shell published nothing for weeks and then blocked a release on the sentence
        # SKILL.md uses to warn against exactly this syntax.
        ("`[j](nope/in-code-span.md)`", None),
        ("```\n[k](nope/in-fence.md)\n```", None),
    ]

    staged_root = tmp_path / "dist" / "clawseccheck"
    staged_root.mkdir(parents=True)
    (staged_root / "SKILL.md").write_text(
        "\n".join(markdown for markdown, _ in cases) + "\n", encoding="utf-8"
    )

    script = tmp_path / "preflight.sh"
    script.write_text(_preflight_shell_block(), encoding="utf-8")
    proc = subprocess.run(
        ["bash", str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )

    shell_targets = re.findall(r"::error::SKILL\.md links to '([^']*)'", proc.stdout)
    python_targets = []
    for markdown, _ in cases:
        match = _MD_LINK_RE.search(_prose_only(markdown))
        if match is None:
            continue          # code span or fence — not a link on either side
        target = _normalise_link_target(match.group(1))
        if target is not None:
            python_targets.append(target)

    expected = [want for _, want in cases if want is not None]

    assert python_targets == expected, (
        "The Python normaliser did not produce the expected targets.\n"
        f"  got     : {python_targets!r}\n  expected: {expected!r}"
    )
    assert shell_targets == expected, (
        "The workflow's preflight shell normalised link targets differently from "
        "_normalise_link_target(). The two resolvers have drifted — a link can now pass "
        "CI and block the release (or vice versa).\n"
        f"  shell : {shell_targets!r}\n  python: {expected!r}\n"
        f"  stdout: {proc.stdout!r}"
    )
    assert proc.returncode != 0, (
        "Every relative target in this fixture is absent, so the preflight must exit "
        f"non-zero. It exited {proc.returncode}; the loop is not actually failing the job."
    )


def test_preflight_shell_passes_when_every_link_resolves(tmp_path) -> None:
    """Positive control: the preflight must exit 0 on a tree where the links do resolve.

    Without this, a preflight that failed unconditionally would still satisfy the
    negative case above while blocking every release.
    """
    if shutil.which("bash") is None:
        pytest.skip("bash not available")

    staged_root = tmp_path / "dist" / "clawseccheck"
    (staged_root / "references").mkdir(parents=True)
    (staged_root / "references" / "cli-flags.md").write_text("x", encoding="utf-8")
    (staged_root / "SKILL.md").write_text(
        '[a](references/cli-flags.md)\n'
        '[b](./references/cli-flags.md "Titled")\n'
        '[c](references/cli-flags.md#anchor)\n'
        '[d](https://example.com/remote)\n',
        encoding="utf-8",
    )

    script = tmp_path / "preflight.sh"
    script.write_text(_preflight_shell_block(), encoding="utf-8")
    proc = subprocess.run(
        ["bash", str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        "Preflight failed on a staged tree where every link resolves — it would block "
        f"every release.\n  stdout: {proc.stdout!r}\n  stderr: {proc.stderr!r}"
    )


def test_publish_workflow_node_satisfies_clawhub_engine() -> None:
    """Node must be >= the pinned clawhub's declared engine (C-248).

    clawhub@0.23.3 declares "engines": {"node": ">=22"} (unchanged since 0.22.0); running
    it on Node 20 emitted an EBADENGINE warning on every publish — the release-token-holding
    step executing outside its supported range.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    match = re.search(r'node-version:\s*"?(\d+)"?', text)
    assert match, "No node-version pin found in the publish workflow."
    assert int(match.group(1)) >= 22, (
        f"node-version is {match.group(1)}, but the pinned clawhub declares "
        "engines.node >= 22. Publishing would run the CLI outside its supported range."
    )


def test_publish_workflow_dry_runs_before_publishing() -> None:
    """A --dry-run preflight must precede the real upload (C-248).

    Grounded: clawhub 0.23.3's `publish` command exposes --dry-run (options.dryRun in
    dist/cli/commands/publish.js), which validates the folder/manifest/semver without
    uploading.

    Reads --dry-run out of an actual invocation's argument list, never out of the file
    as text. The earlier version matched the word inside this step's own explanatory
    comment, so deleting the real flag kept the suite green while turning the preflight
    into a second live upload of the same version.
    """
    invocations = _publish_invocations()
    dry = [inv for inv in invocations if inv["dry_run"]]
    real = [inv for inv in invocations if not inv["dry_run"]]

    assert len(dry) == 1, (
        f"Expected exactly one --dry-run preflight invocation, found {len(dry)}: "
        f"{[inv['name'] for inv in dry]}. A broken bundle must fail before the real "
        "publish writes anything to the registry."
    )
    assert len(real) == 1, (
        f"Expected exactly one real publish invocation, found {len(real)}: "
        f"{[inv['name'] for inv in real]}."
    )
    assert dry[0]["line"] < real[0]["line"], (
        f"The --dry-run preflight (line {dry[0]['line']}) must come BEFORE the real "
        f"publish (line {real[0]['line']}), not after it."
    )


def test_dry_run_preflight_exercises_the_same_flags_as_the_real_publish() -> None:
    """The preflight is only meaningful if it validates the bundle we actually ship.

    The workflow claims the dry-run uses "the identical flag set" as the real publish —
    that claim is what justifies the step, so pin it rather than trusting the comment.
    A preflight that dry-ran a different path or version would happily pass while the
    real upload shipped something else entirely.
    """
    invocations = _publish_invocations()
    dry = [inv for inv in invocations if inv["dry_run"]]
    real = [inv for inv in invocations if not inv["dry_run"]]
    assert len(dry) == 1 and len(real) == 1, (
        "Expected exactly one dry-run and one real publish invocation; found "
        f"{len(dry)} and {len(real)}."
    )

    assert dry[0]["args"] == real[0]["args"] + " --dry-run", (
        "The dry-run preflight and the real publish must pass an identical flag list, "
        "with --dry-run appended last, or the preflight validates a different bundle "
        "than the one that ships.\n"
        f"  dry-run: {dry[0]['args']!r}\n"
        f"  real   : {real[0]['args']!r}"
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


def test_publish_workflow_verifies_previous_release_surfaced() -> None:
    """A hard gate must confirm the PREVIOUS release is actually live on ClawHub.

    `clawhub publish` printing "OK. Published …" is not proof of publication: v3.54.0
    was accepted (with a version id) and never surfaced, because the registry's scan
    reported status "succeeded" while its primary verdict came back null. Nothing in the
    pipeline noticed for four hours. This gate is the detection mechanism — it must query
    the registry, and it must be able to fail the build.
    """
    code = _code_lines()
    joined = "\n".join(text for _, text in code)

    assert "/api/v1/skills/clawseccheck/versions/" in joined, (
        "The publish workflow must query the ClawHub versions endpoint to confirm a "
        "release actually surfaced. Without it, an accepted-but-invisible version looks "
        "like a successful release."
    )

    # The gate must precede the real upload: publishing on top of a release that never
    # surfaced buries the problem instead of surfacing it.
    def first_index_containing(needle: str) -> int:
        for lineno, text in code:
            if needle in text:
                return lineno
        return -1

    gate = first_index_containing("/api/v1/skills/clawseccheck/versions/")
    publish = _real_publish_invocation()["line"]
    assert 0 <= gate < publish, (
        f"The registry check (line {gate}) must run before the real publish "
        f"(line {publish}), so a broken previous release blocks the next upload."
    )


def test_helper_heredoc_bodies_carry_no_apostrophe() -> None:
    """A lone `'` inside a heredoc nested in `$( )` breaks the script on macOS only.

    bash 3.2 — still `/bin/bash` on GitHub's macOS runners — does not treat a heredoc
    body as literal while scanning a command substitution for its closing paren, so an
    apostrophe opens a quote it never closes and the script dies with "unexpected EOF
    while looking for matching `'`", exit 2. Linux bash 5.x parses the same file
    correctly, which is why `bash -n` here cannot catch it and why this is a text rule
    rather than a syntax check: a single possessive added to an explanatory comment
    (`C-368's`) reddened the macOS leg while both Ubuntu legs stayed green.
    """
    text = HELPER_SCRIPT.read_text(encoding="utf-8")
    bodies = re.findall(r"<<'(\w+)'\n(.*?)\n\1\n", text, re.S)
    assert bodies, "No quoted heredoc found in the helper — has its shape changed?"

    offenders = []
    for delim, body in bodies:
        for i, line in enumerate(body.splitlines(), 1):
            if "'" in line:
                offenders.append(f"<<{delim} line {i}: {line.strip()}")
    assert not offenders, (
        "Apostrophes inside a heredoc body nested in $( ) break bash 3.2 on macOS:\n  "
        + "\n  ".join(offenders)
    )


def test_previous_release_gate_separates_never_released_from_never_surfaced() -> None:
    """A 404 on the previous version has two causes, and they need different answers.

    On 2026-09-17 this gate blocked v4.2.0 and reported that 4.1.1 "was published but
    never surfaced". 4.1.1 had never been published at all: it was bumped and
    changelogged, the work sat unpushed and grew into 4.2.0, and only its CHANGELOG
    entry stayed behind. The gate derives the previous version from that entry, so it
    curled for a release that never existed — and its verdict sent the operator to
    investigate a publishing incident that had not happened.

    A 404 cannot separate the two on its own. The tag can: §6 tags before publishing, so
    no tag means no attempt was ever made, and the fault is a wrong CHANGELOG rather
    than a lost release. The gate must therefore consult the tag BEFORE writing the
    "never surfaced" verdict, and must not send a never-released version down the
    skip-the-check path — that would publish on top of a changelog describing a release
    that does not exist.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "git/ref/tags/v${PREV}" in text, (
        "The previous-release gate must check whether v<PREV> was ever tagged before "
        "concluding a 404 means the release was published and then lost."
    )

    tag_check = text.index("git/ref/tags/v${PREV}")
    surfaced_verdict = text.index("was published and never surfaced")
    assert tag_check < surfaced_verdict, (
        "The tag must be consulted before the 'published and never surfaced' verdict is "
        "written, or the gate misdiagnoses a version that was never released at all."
    )

    # The never-released branch must refuse the override rather than recommend it: the
    # fix there is to correct the CHANGELOG, not to publish past it.
    never_released = text.index("was never released")
    between = text[never_released:surfaced_verdict]
    assert "Do NOT reach for skip_previous_release_check" in between, (
        "The never-released branch must tell the operator not to skip the check — "
        "skipping publishes on top of a CHANGELOG that describes a phantom release."
    )


def test_publish_workflow_post_publish_check_is_warn_only() -> None:
    """The post-publish visibility poll must warn, never fail the build.

    Indexing lag is real and variable — v3.53.0 was processed in ~20 minutes while
    v3.52.1 still 404'd 29 minutes after upload and landed later. Turning this poll into
    a hard failure would produce a false alarm on ordinary releases, which this project
    does not ship. A version that genuinely never surfaces is caught by the
    previous-release gate on the NEXT run, where a 404 is unambiguous.
    """
    for step in _steps():
        body = "\n".join(text for _, text in step)
        if "warn only" not in body.lower():
            continue
        assert "::warning::" in body, (
            "The post-publish visibility step must emit a ::warning:: annotation."
        )
        assert "exit 1" not in " ".join(body.split()), (
            "The post-publish visibility poll must NOT fail the build — normal indexing "
            "lag has been observed well past its timeout, so failing here is a false "
            "alarm. Hard detection belongs in the previous-release gate."
        )
        return
    raise AssertionError(
        "No warn-only post-publish visibility step found in the publish workflow."
    )


def _step_name(step: list) -> str:
    m = re.search(r"-\s+(?:name|uses):\s*(.+)", step[0][1])
    return m.group(1).strip() if m else ""


def _size_guard_shell_block() -> str:
    """Extract the literal `run: |` body of the pre-upload bundle-size guard step.

    Same pattern as _preflight_shell_block(): executed verbatim by the tests below, so
    what's under test is the real workflow shell, not a paraphrase that could quietly
    stop matching (CLAWSECCHECK-B-440).
    """
    lines = _lines()
    # Anchored on the constant the guard IS, not on its display name: the step was renamed
    # once already (2026-08-05 recalibration) and a prose-keyed extractor turned that into
    # four unrelated test failures. `MAX_STAGED_BYTES=` appears nowhere else in the file.
    const_i = next(
        (i for i, ln in enumerate(lines) if "MAX_STAGED_BYTES=" in ln),
        None,
    )
    assert const_i is not None, (
        "No MAX_STAGED_BYTES= assignment anywhere in the workflow — the pre-upload "
        "bundle-size guard is gone, not merely renamed."
    )
    start = next(
        (
            i for i in range(const_i, -1, -1)
            if lines[i].strip().startswith("- name:")
        ),
        None,
    )
    assert start is not None, (
        "Found MAX_STAGED_BYTES= but no enclosing '- name:' step header above it."
    )
    run_i = None
    for i in range(start + 1, len(lines)):
        if lines[i].strip().startswith("- name:"):
            break
        if lines[i].strip() == "run: |":
            run_i = i
            break
    assert run_i is not None, (
        "The size-guard step no longer uses a 'run: |' literal block; update this "
        "extractor."
    )
    indent = len(lines[run_i]) - len(lines[run_i].lstrip())
    body = []
    for ln in lines[run_i + 1:]:
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
            break
        body.append(ln)
    return textwrap.dedent("\n".join(body))


def _size_guard_threshold_bytes() -> int:
    """The MAX_STAGED_BYTES constant declared inside the size-guard shell block."""
    match = re.search(r"MAX_STAGED_BYTES=(\d+)", _size_guard_shell_block())
    assert match, "No MAX_STAGED_BYTES=<int> assignment found in the size-guard step."
    return int(match.group(1))


def test_size_guard_step_runs_right_after_staging_and_before_any_publish() -> None:
    """The bundle-size guard must fail BEFORE any of the job's publish work runs.

    v3.59.0 discovered its 413 only at real-upload time — after the `environment:
    release` manual approval (one job-level gate, checked once before checkout — not a
    per-step resource that each later step individually "spends") had already let the
    whole job proceed on a bundle that was always going to fail (CLAWSECCHECK-B-440,
    folded from CLAWSECCHECK-B-443). Anchored to running immediately after the 'Stage
    publishable files' step (so it sees the CHANGELOG.md trim) and strictly before the
    first 'clawhub publish' invocation (including the --dry-run preflight), so an
    obviously bad bundle is caught before any of that later work runs on it.
    """
    steps = _steps()
    names = [_step_name(s) for s in steps]

    staging_idx = next(
        (i for i, n in enumerate(names) if "Stage publishable files" in n), None
    )
    # Same rename-proof anchor as _size_guard_shell_block(): identify the guard by the
    # constant it declares, not by its display name.
    guard_idx = next(
        (
            i for i, step in enumerate(steps)
            if any("MAX_STAGED_BYTES=" in ln for _, ln in step)
        ),
        None,
    )
    assert staging_idx is not None, "Could not find the 'Stage publishable files' step."
    assert guard_idx is not None, "Could not find the pre-upload bundle-size guard step."
    assert guard_idx == staging_idx + 1, (
        f"The size guard (step #{guard_idx}: {names[guard_idx]!r}) must be the step "
        f"immediately after staging (step #{staging_idx}: {names[staging_idx]!r}), so it "
        "fails before any preflight/dry-run/publish work runs and before another release "
        "tag's approval gate gets spent."
    )

    invocations = _publish_invocations()
    assert invocations, "No step in the workflow runs 'clawhub publish'."
    first_publish_line = min(inv["line"] for inv in invocations)
    guard_lines = [lineno for lineno, _ in steps[guard_idx]]
    assert max(guard_lines) < first_publish_line, (
        "The size guard must run entirely before the first 'clawhub publish' invocation."
    )


def test_size_guard_threshold_clears_the_last_known_good_publish() -> None:
    """The threshold must sit ABOVE a bundle size that really did publish.

    This assertion used to pin the threshold inside a 4.5MB-5.3MB gap, on the reading that
    v3.58.0's tree published fine while v3.59.0's 413'd. That bracket has since been
    disproved: the 413 was ClawHub routing uploads through a Vercel request-body cap far
    under its own documented 50MB limit (upstream openclaw/clawhub#3375), and once PR #3391
    moved staging to a direct Convex upload, the *same* v3.59.0 tree published successfully
    on 2026-08-05. So the old gap measured someone else's infrastructure, not our size, and
    a threshold inside it now blocks ordinary releases.

    What the guard is actually for is unchanged: catch accidental bloat — a stray binary, a
    re-added docs/assets tree — before the release-environment approval is spent on it.
    """
    threshold = _size_guard_threshold_bytes()
    # Measured from the v3.59.0 tag by replaying the staging step above, not quoted from a
    # `du -sh` figure: du reports allocated blocks, the guard sums real file bytes, and
    # conflating the two is what put the original threshold on the wrong side of this tree.
    last_known_good_publish = 5_235_253   # v3.59.0, published 2026-08-05 via the Convex route
    assert threshold > last_known_good_publish, (
        f"MAX_STAGED_BYTES={threshold} is at or below {last_known_good_publish} bytes — a "
        "staged tree that is known to have published successfully. A guard set below a "
        "proven-good size blocks ordinary releases instead of catching real bloat."
    )
    assert threshold < 50 * 1024 * 1024, (
        f"MAX_STAGED_BYTES={threshold} is not comfortably under ClawHub's documented "
        "50MB limit — check for a typo."
    )
    # The other failure direction: a threshold so loose it would wave through a bundle
    # nobody meant to publish. Keep it well inside the documented cap so it still has teeth.
    assert threshold <= 25 * 1024 * 1024, (
        f"MAX_STAGED_BYTES={threshold} is more than half ClawHub's documented 50MB cap — "
        "at that point the guard no longer catches accidental bloat before the approval "
        "gate, which is its only job."
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_size_guard_fires_on_an_oversized_staged_bundle(tmp_path) -> None:
    """The guard must actually FAIL when the staged tree exceeds its threshold.

    Builds a tmp `dist/clawseccheck` just over MAX_STAGED_BYTES and runs the REAL guard
    shell block against it — proving the guard has teeth, the same pattern as
    test_dangling_link_guard_detects_a_missing_target.
    """
    threshold = _size_guard_threshold_bytes()
    staged = tmp_path / "dist" / "clawseccheck"
    staged.mkdir(parents=True)
    (staged / "oversized.bin").write_bytes(b"\0" * (threshold + 4096))

    script = tmp_path / "guard.sh"
    script.write_text(_size_guard_shell_block(), encoding="utf-8")
    proc = subprocess.run(
        ["bash", str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )

    assert proc.returncode != 0, (
        "The size guard must exit non-zero when the staged tree exceeds "
        f"MAX_STAGED_BYTES ({threshold}).\nstdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )
    assert "::error::" in proc.stdout, (
        f"Expected an ::error:: annotation on an oversized bundle.\nstdout: {proc.stdout!r}"
    )
    assert str(threshold) in proc.stdout, (
        "The failure message should name the configured threshold so the CI log is "
        f"self-explanatory.\nstdout: {proc.stdout!r}"
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_size_guard_passes_on_a_staged_bundle_within_budget(tmp_path) -> None:
    """Positive control: a small staged tree must not be blocked.

    Without this, a guard that failed unconditionally would still satisfy the oversized
    case above while blocking every release.
    """
    staged = tmp_path / "dist" / "clawseccheck"
    staged.mkdir(parents=True)
    (staged / "small.txt").write_bytes(b"x" * 1024)

    script = tmp_path / "guard.sh"
    script.write_text(_size_guard_shell_block(), encoding="utf-8")
    proc = subprocess.run(
        ["bash", str(script)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        "The size guard must pass on a staged tree well within budget.\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )
    assert "Staged bundle size OK" in proc.stdout, (
        f"Expected the OK confirmation line in stdout.\nstdout: {proc.stdout!r}"
    )


# ---------------------------------------------------------------------------------
# CLAWSECCHECK-C-368: a false 'already exists' CLI exit used to abort the job right
# at Publish, silently skipping the GitHub Release and leaving the surfaced-check
# unable to run for a publish that had actually succeeded (v3.59.0, v3.60.0,
# v3.61.0). The fix decouples the Release/job-pass decision from the CLI's exit
# code: Publish gets continue-on-error, a Confirm step re-checks the ClawHub API
# itself on a reported failure, and a pure-logic Decide step turns
# {publish.outcome, pre-publish liveness, post-failure confirmation} into a verdict
# that a Finalize step turns into the job's actual pass/fail.
# ---------------------------------------------------------------------------------

HELPER_SCRIPT = REPO_ROOT / ".github" / "scripts" / "clawhub-version-live.sh"


def _step_shell_block(step_name: str) -> str:
    """Extract the literal `run: |` body of the step named *step_name*.

    Same pattern as _size_guard_shell_block(): executed verbatim by the tests below,
    so what's under test is the real workflow shell, not a paraphrase that could
    quietly stop matching.
    """
    lines = _lines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.strip() == f"- name: {step_name}"),
        None,
    )
    assert start is not None, f"No '- name: {step_name}' step found in the workflow."
    run_i = None
    for i in range(start + 1, len(lines)):
        if lines[i].strip().startswith("- name:"):
            break
        if lines[i].strip() == "run: |":
            run_i = i
            break
    assert run_i is not None, f"Step {step_name!r} has no 'run: |' literal block."
    indent = len(lines[run_i]) - len(lines[run_i].lstrip())
    body = []
    for ln in lines[run_i + 1:]:
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
            break
        body.append(ln)
    return textwrap.dedent("\n".join(body))


def test_c368_publish_resilience_step_wiring() -> None:
    """Probe -> Publish(continue-on-error) -> Confirm -> surfaced-check(warn) ->
    Decide -> Release(gated on decide) -> Finalize, in that exact relative order,
    with the specific fields each step must read/write.

    Pins the step order and wiring so a future edit cannot silently collapse this
    back into the old single-step shape where a CLI false-failure dropped the
    Release (the original C-368 defect).
    """
    steps = _steps()
    names = [_step_name(s) for s in steps]

    expected_order = [
        "Probe pre-publish liveness",
        "Publish skill",
        "Confirm publication surfaced",
        "Check whether this version surfaced (warn only)",
        "Decide release action",
        "Create GitHub Release",
        "Finalize job status",
    ]
    indices = []
    for name in expected_order:
        assert name in names, f"Missing step {name!r} in the publish workflow."
        indices.append(names.index(name))
    assert indices == sorted(indices), (
        f"C-368 tail steps are out of order. Expected this relative order: "
        f"{expected_order}. Found indices {indices} in {names}."
    )

    def body_of(name: str) -> str:
        return "\n".join(text for _, text in steps[names.index(name)])

    publish_body = body_of("Publish skill")
    assert "id: publish" in publish_body, (
        "The Publish step needs 'id: publish' so later steps can read "
        "steps.publish.outcome."
    )
    assert "continue-on-error: true" in publish_body, (
        "The Publish step needs continue-on-error: true so a CLI false-failure "
        "(#3349) does not abort the job before Confirm/Decide ever run."
    )
    # id:/continue-on-error: must sit above run: or _publish_invocations() sweeps
    # them into the invocation's own args (a known landmine from the A1-A4 pass).
    publish_lines = publish_body.splitlines()
    id_line = next(i for i, ln in enumerate(publish_lines) if "id: publish" in ln)
    run_line = next(i for i, ln in enumerate(publish_lines) if ln.strip() == "run: >")
    assert id_line < run_line, "id: publish must sit above run: in the Publish step."

    confirm_body = body_of("Confirm publication surfaced")
    assert "id: confirm" in confirm_body
    assert "steps.publish.outcome == 'failure'" in confirm_body, (
        "Confirm must only run when the CLI reported failure, so a normal success "
        "pays no poll cost."
    )
    assert "exit 1" not in " ".join(confirm_body.split()), (
        "Confirm must never exit 1 itself — Decide is the single place that turns a "
        "confirmed non-surfacing into a failed job."
    )

    decide_body = body_of("Decide release action")
    assert "id: decide" in decide_body
    for token in (
        "steps.publish.outcome", "steps.pre.outputs.live", "steps.confirm.outputs.live",
    ):
        assert token in decide_body, f"Decide must read {token!r}."

    release_body = body_of("Create GitHub Release")
    assert "steps.decide.outputs.create_release == 'true'" in release_body, (
        "The Release step must be gated on Decide's verdict, not on the Publish "
        "step's raw exit code or on steps.sign.outcome alone (that gate could not "
        "tell a real 413/auth failure apart from a false #3349 one — the original "
        "defect)."
    )
    assert "--clobber" not in release_body, (
        "The release-asset upload must not use --clobber: a DUPLICATE verdict must "
        "never let this run's bytes overwrite a prior, honestly-signed release."
    )

    finalize_body = body_of("Finalize job status")
    assert "if: always()" in finalize_body, (
        "Finalize must run with if: always() so it can report even after an "
        "earlier failure short of cancellation."
    )
    assert "steps.decide.outputs.fail_job" in finalize_body
    assert "exit 1" in " ".join(finalize_body.split()), (
        "Finalize must be able to exit 1 — it is the single pass/fail point for the "
        "job's publish verdict, since Publish's own continue-on-error would "
        "otherwise let a real publish failure go green."
    )


def test_probe_and_confirm_steps_use_the_shared_helper_script() -> None:
    """Both liveness checks must call the SAME helper script.

    Two independent inline implementations could drift apart; a shared script
    means the pre-publish probe and the post-failure confirm always agree on what
    "live" means.
    """
    assert HELPER_SCRIPT.exists(), (
        "clawhub-version-live.sh is missing — Probe/Confirm have nothing to call."
    )
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    count = text.count(".github/scripts/clawhub-version-live.sh")
    assert count == 2, (
        f"Expected exactly 2 references to the helper script (Probe + Confirm), "
        f"found {count}."
    )


def test_helper_script_is_never_staged_for_publish() -> None:
    """.github/scripts/*.sh is CI-only tooling — it must never ship to ClawHub
    installs alongside the audited skill.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    stage_start = text.index("Stage publishable files")
    stage_end = text.index("\n      - name:", stage_start + 1)
    stage_body = text[stage_start:stage_end]
    assert ".github" not in stage_body, (
        "The staging step must not copy .github/ (including the new "
        "clawhub-version-live.sh helper) into the published bundle."
    )


def test_helper_script_requires_both_signals() -> None:
    """The discriminator must AND its two signals, never OR them.

    Ground truth (task description): a genuine publish answers 200 with a matching
    `version` + non-empty `files` on the versions endpoint, AND
    `latestVersion.version` equals it on the skill endpoint. An OR would let
    either signal alone certify a live version, reopening exactly the false-signal
    risk this script exists to close.
    """
    text = HELPER_SCRIPT.read_text(encoding="utf-8")
    assert "/versions/" in text
    assert "latestVersion" in text
    assert "files" in text
    assert re.search(
        r'\[\s*"\$SIG1"\s*=\s*"true"\s*\]\s*&&\s*\[\s*"\$LATEST"\s*=\s*"\$VER"\s*\]',
        text,
    ), (
        "The helper's final line must AND signal 1 (versions/<ver> 200 + non-empty "
        "files) with signal 2 (latestVersion==<ver>)."
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    "name,versions_code,versions_body,skill_body,expect_live",
    [
        (
            "live",
            "200",
            _versions_body("9.9.9", files=[{"path": "a.py", "size": 1}]),
            {"latestVersion": {"version": "9.9.9"}},
            True,
        ),
        (
            "orphan-404",
            "404",
            {},
            {"latestVersion": {"version": "9.9.8"}},
            False,
        ),
        (
            "hollow-200-no-files",
            "200",
            _versions_body("9.9.9", files=[]),
            {"latestVersion": {"version": "9.9.9"}},
            False,
        ),
        (
            "stale-latest-version",
            "200",
            _versions_body("9.9.9", files=[{"path": "a.py", "size": 1}]),
            {"latestVersion": {"version": "9.9.8"}},
            False,
        ),
        (
            "null-latest-version-mid-reindex",
            "200",
            _versions_body("9.9.9", files=[{"path": "a.py", "size": 1}]),
            {"latestVersion": None},
            False,
        ),
        (
            # B-827 positive control: the FLAT shape these fixtures used to assert
            # (version and files at the top level) is not what the API serves. If a
            # future edit goes back to reading it, this case starts passing and the
            # suite says so.
            "flat-legacy-shape-is-not-live",
            "200",
            {"version": "9.9.9", "files": [{"path": "a.py", "size": 1}]},
            {"latestVersion": {"version": "9.9.9"}},
            False,
        ),
    ],
)
def test_clawhub_version_live_two_signal_discriminator(
    tmp_path, name, versions_code, versions_body, skill_body, expect_live,
) -> None:
    """The helper script executed for real, offline, against a stubbed `curl`.

    A successful publish answers 200 whose nested `version` object carries a matching
    `version` + non-empty `files`, AND `latestVersion.version` equal to it on the
    skill endpoint. Both shapes are taken from a captured live response
    (tests/clawhub_version_response.json), not from a description — the earlier
    fixtures were hand-written flat and agreed with a script that read the same wrong
    keys, so the pair was self-consistently wrong and green (B-827).

    The #3349 ghost-orphan fails signal 1 (404). A hollow 200 with no files (the
    v3.54.0 accepted-but-invisible shape), a stale or null latestVersion, and the
    flat legacy shape must each independently fail the discriminator — this is what
    stops either signal alone, or a regression to the old parse, from being trusted.
    """
    assert HELPER_SCRIPT.exists(), "clawhub-version-live.sh is missing."

    bin_dir = tmp_path / "stubbin"
    bin_dir.mkdir()
    stub = bin_dir / "curl"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'url=""\n'
        'out=""\n'
        "for ((i=1;i<=$#;i++)); do\n"
        '  a="${!i}"\n'
        '  case "$a" in http*) url="$a" ;; esac\n'
        '  if [ "$a" = "-o" ]; then j=$((i+1)); out="${!j}"; fi\n'
        "done\n"
        'case "$url" in\n'
        "  */versions/*)\n"
        '    cat "$STUB_VERSIONS_BODY" > "$out"\n'
        '    printf \'%s\' "$(cat "$STUB_VERSIONS_CODE")"\n'
        "    ;;\n"
        "  *)\n"
        '    cat "$STUB_SKILL_BODY"\n'
        "    ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)

    versions_body_file = tmp_path / "versions_body.json"
    versions_body_file.write_text(json.dumps(versions_body), encoding="utf-8")
    versions_code_file = tmp_path / "versions_code.txt"
    versions_code_file.write_text(versions_code, encoding="utf-8")
    skill_body_file = tmp_path / "skill_body.json"
    skill_body_file.write_text(json.dumps(skill_body), encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["STUB_VERSIONS_BODY"] = str(versions_body_file)
    env["STUB_VERSIONS_CODE"] = str(versions_code_file)
    env["STUB_SKILL_BODY"] = str(skill_body_file)

    proc = subprocess.run(
        ["bash", str(HELPER_SCRIPT), "clawseccheck", "9.9.9"],
        capture_output=True,
        text=True,
        env=env,
    )
    if expect_live:
        assert proc.returncode == 0, (
            f"[{name}] expected live=true (exit 0).\n"
            f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
        )
    else:
        assert proc.returncode != 0, (
            f"[{name}] expected live=false (nonzero exit).\n"
            f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
        )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    "case_id,publish_outcome,pre_live,confirm_live,is_tag,"
    "expected_verdict,expected_create,expected_fail",
    [
        ("normal-success", "success", "false", "", "true", "PUBLISHED", "true", "false"),
        (
            "false-failure-surfaces", "failure", "false", "true", "true",
            "PUBLISHED_VIA_GHOST", "true", "false",
        ),
        (
            "genuine-duplicate-retag", "failure", "true", "true", "true",
            "DUPLICATE", "true", "false",
        ),
        (
            "genuine-failure-never-surfaces", "failure", "false", "false", "true",
            "GENUINE_FAILURE", "false", "true",
        ),
        (
            "success-but-not-a-tag-run", "success", "false", "", "false",
            "PUBLISHED", "false", "false",
        ),
    ],
)
def test_decide_release_action_truth_table(
    tmp_path, case_id, publish_outcome, pre_live, confirm_live, is_tag,
    expected_verdict, expected_create, expected_fail,
) -> None:
    """Decide's pure-logic truth table, executed under `bash -eo pipefail` — the
    same shell mode GitHub Actions runs every `run:` block under — so an errexit
    trap (e.g. a `cond && action` short-circuit) would be caught here exactly as it
    would in CI, not just asserted by reading the source.

    Covers both DoD adversarial scenarios by name: a real failure that never
    surfaces must NOT release and must fail the job
    (genuine-failure-never-surfaces); a CLI false failure that DOES surface must
    release and must NOT fail the job (false-failure-surfaces). Also covers the
    #3349 ghost-reservation's DUPLICATE branch and the non-tag-run guard.
    """
    script = tmp_path / "decide.sh"
    script.write_text(_step_shell_block("Decide release action"), encoding="utf-8")
    output_file = tmp_path / "github_output"
    output_file.write_text("", encoding="utf-8")

    env = dict(os.environ)
    env.update(
        {
            "PUBLISH_OUTCOME": publish_outcome,
            "PRE_LIVE": pre_live,
            "CONFIRM_LIVE": confirm_live,
            "IS_TAG": is_tag,
            "GITHUB_OUTPUT": str(output_file),
        }
    )
    proc = subprocess.run(
        ["bash", "-eo", "pipefail", str(script)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, (
        f"[{case_id}] Decide must never fail itself (pure logic, no network).\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )

    outputs = dict(
        line.split("=", 1)
        for line in output_file.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    assert outputs.get("verdict") == expected_verdict, (
        f"[{case_id}] verdict: expected {expected_verdict!r}, got "
        f"{outputs.get('verdict')!r}.\nstdout: {proc.stdout!r}"
    )
    assert outputs.get("create_release") == expected_create, (
        f"[{case_id}] create_release: expected {expected_create!r}, got "
        f"{outputs.get('create_release')!r}."
    )
    assert outputs.get("fail_job") == expected_fail, (
        f"[{case_id}] fail_job: expected {expected_fail!r}, got "
        f"{outputs.get('fail_job')!r}."
    )
