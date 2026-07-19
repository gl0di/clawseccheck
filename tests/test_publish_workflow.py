"""Tests for BLK-04 supply-chain fixes in the ClawHub publish workflow.

Reads the YAML as plain text — no pyyaml dependency (stdlib only).
"""
import json
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

# Every shipped markdown file that the staging step copies AND that links out to other
# repo paths. Both are read by users of an installed skill, so a relative link in either
# one that the bundle does not carry is a 404 on every ClawHub install. SKILL.md was
# guarded first (B-254); README.md is staged by the same `cp` line and had the same
# defect — a relative CONTRIBUTING.md link to a file the bundle never included.
LINKING_STAGED_DOCS = {"SKILL.md": SKILL_PATH, "README.md": README_PATH}

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
    """Relative (non-URL, non-anchor) markdown link targets declared in *path*."""
    targets = []
    for raw in _MD_LINK_RE.findall(path.read_text(encoding="utf-8")):
        target = _normalise_link_target(raw)
        if target is not None:
            targets.append(target)
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
    for doc_name, doc_path in sorted(LINKING_STAGED_DOCS.items()):
        assert _relative_links(doc_path), (
            f"No relative markdown links parsed out of {doc_name} — the link cross-check "
            f"below would be vacuous for it. Check _MD_LINK_RE against its actual syntax."
        )
    # Both docs must actually be staged, or the cross-check guards a file nobody ships.
    for doc_name in LINKING_STAGED_DOCS:
        assert doc_name in staged, (
            f"{doc_name} is cross-checked for dangling links but the staging step does "
            f"not copy it. Either stage it or drop it from LINKING_STAGED_DOCS."
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
        raw = _MD_LINK_RE.search(markdown).group(1)
        target = _normalise_link_target(raw)
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

    clawhub@0.22.0 declares "engines": {"node": ">=22"}; running it on Node 20 emitted an
    EBADENGINE warning on every publish — the release-token-holding step executing outside
    its supported range.
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

    Grounded: clawhub 0.22.0's `publish` command exposes --dry-run ("Preview without
    publishing"), which validates the folder/manifest/semver without uploading.

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
