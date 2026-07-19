"""CLAWSECCHECK-C-125: public-boundary drift guard.

A lightweight, in-repo pytest gate that catches internal-only markers leaking into
files that actually ship in the public ClawHub release, BEFORE the (external, not
ported here — see recon) clawrange-style pre-release gates would catch it.

"What ships" is derived from the *actual* staging step in
`.github/workflows/clawhub-publish.yml` (the "Stage publishable files" step) — not
guessed. That step currently copies, across **all** of its `cp` lines:

    clawseccheck SKILL.md README.md LICENSE SECURITY.md SECURITY_MODEL.md
    CHANGELOG.md pyproject.toml docs audit.py
    references/cli-flags.md

`clawseccheck` and `docs` are directories; we expand them to every `git ls-files`
entry under those paths so new files added later are automatically covered without
editing this test. Per the workflow, `__pycache__` is pruned from `clawseccheck/`
after staging, so it is excluded here too (dev artifact, never actually ships).

Note the parser reads EVERY `cp` line into the staging dir, not just the `cp -r` one.
It originally matched only `cp -r ... dist/clawseccheck/`, so when a second, plain
`cp` line was added to stage `references/cli-flags.md`, that newly-published file fell
outside the scan set — this guard silently under-covered exactly what it promises to
drift loudly about. A file that ships must be scanned; adding a new `cp` line without
adding it to _EXPECTED_STAGED_SOURCES now fails loudly instead.

Markers checked (all internal-only; must never appear in a shipped file):
  - the internal Pulse server hostname (`pulse.in10ix`)
  - a Pulse task-ID shape (`CLAWSECCHECK-<LETTER>-<digits>`, e.g. this very task ID)
  - an absolute local dev path (`/home/glodi/`)
  - `Solomon` / `sbook` — an unrelated sibling project's persona/codename that must
    never bleed into this repo (see workspace CLAUDE.md 0.)

CHANGELOG.md gets no special exemption: the workspace CLAUDE.md's actual convention
(re-verified against the live file, not assumed) is that commits/artifacts never carry
a Pulse tag at all, and CHANGELOG.md is currently 100% clean of all four markers — so
the strictest reading (zero occurrences, everywhere, no exceptions) matches the real
enforced state and is what this test asserts.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "clawhub-publish.yml"

STAGING_DIR = "dist/clawseccheck"

# Every source path the workflow's staging step copies, in order, across all its `cp`
# lines. _staged_source_paths() below parses them out of the real workflow so this
# drifts loudly (test failure) rather than silently if the workflow changes what it
# ships. A new entry here means a newly-published file — check whether it needs marker
# scanning before you add it.
_EXPECTED_STAGED_SOURCES = [
    "clawseccheck",
    "SKILL.md",
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "SECURITY_MODEL.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "docs",
    "audit.py",
    "references/cli-flags.md",
]

pytestmark = pytest.mark.skipif(
    not WORKFLOW_PATH.exists(),
    reason="CI workflow file not present (packaged skill ships without .github/); "
           "the public-boundary drift guard only makes sense from the source repo.",
)

# --- internal-only markers -------------------------------------------------

_MARKERS: list[tuple[str, re.Pattern]] = [
    ("internal Pulse hostname", re.compile(r"pulse\.in10ix")),
    ("Pulse task-ID", re.compile(r"CLAWSECCHECK-[A-Z]-\d+")),
    ("absolute local dev path", re.compile(r"/home/glodi/")),
    ("cross-project persona/codename bleed", re.compile(r"\b(?:Solomon|sbook)\b")),
]


def _staged_source_paths() -> list[str]:
    """Parse EVERY `cp ... dist/clawseccheck/...` source path out of the workflow.

    This is the source of truth for "what ships" — we do not guess or hardcode
    independently of the workflow file. Handles both shapes the staging step uses:

        cp -r A B C dist/clawseccheck/                 -> ["A", "B", "C"]
        cp references/x.md dist/clawseccheck/references/ -> ["references/x.md"]

    Matching only the first shape is what let a newly-published file slip outside this
    guard's scan set, so every `cp` into the staging dir is read.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    # Join shell line-continuations so a multi-line `cp` reads as one command.
    joined = re.sub(r"\\\s*\n\s*", " ", text)

    sources: list[str] = []
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped.startswith("cp "):
            continue
        args = [a for a in stripped[len("cp "):].split() if not a.startswith("-")]
        if len(args) < 2 or not args[-1].startswith(STAGING_DIR):
            continue
        sources.extend(args[:-1])

    assert sources, (
        f"Could not find any 'cp ... {STAGING_DIR}/' staging line in {WORKFLOW_PATH} — "
        "the publish workflow's staging step changed shape; update this parser rather "
        "than letting the guard silently scan nothing."
    )
    assert sources == _EXPECTED_STAGED_SOURCES, (
        f"Publish workflow now stages {sources!r}, expected {_EXPECTED_STAGED_SOURCES!r} "
        "— update _EXPECTED_STAGED_SOURCES (and re-check whether newly shipped files "
        "need marker scanning) before trusting this test's coverage."
    )
    return sources


def _git_ls_files(*pathspecs: str) -> list[str]:
    """List tracked files under the given pathspecs (relative to REPO_ROOT)."""
    out = subprocess.run(
        ["git", "ls-files", "--", *pathspecs],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.splitlines() if line]


def _shipped_files() -> list[Path]:
    """Every file that actually ships, expanded from the workflow's staging line.

    Directories (`clawseccheck`, `docs`) are expanded via `git ls-files` (matching
    the pattern already used in tests/test_publish_workflow.py for reading repo
    state without a subprocess-heavy or YAML-parsing dependency). `__pycache__` is
    excluded to mirror the workflow's post-copy prune step.
    """
    entries = _staged_source_paths()
    files: list[Path] = []
    for entry in entries:
        abs_entry = REPO_ROOT / entry
        if abs_entry.is_dir():
            for rel in _git_ls_files(entry):
                if "__pycache__" in Path(rel).parts:
                    continue
                files.append(REPO_ROOT / rel)
        else:
            assert abs_entry.is_file(), (
                f"Workflow stages {entry!r} but it does not exist at {abs_entry}"
            )
            files.append(abs_entry)
    return files


def _shipped_md_and_py_files() -> list[Path]:
    """The slice this test actually scans: shipped .md files (any of them) plus
    shipped .py files under clawseccheck/ (task spec point 2)."""
    scanned = []
    for f in _shipped_files():
        if f.suffix == ".md":
            scanned.append(f)
        elif f.suffix == ".py":
            try:
                f.relative_to(REPO_ROOT / "clawseccheck")
            except ValueError:
                continue
            scanned.append(f)
    return scanned


# --- the actual gate --------------------------------------------------------


def test_workflow_stages_expected_source_paths() -> None:
    """Sanity check the staging step parses to a non-empty, sane file list."""
    entries = _staged_source_paths()
    assert entries, "Parsed an empty staging list from the publish workflow."
    assert "clawseccheck" in entries
    assert "SKILL.md" in entries


def test_every_staged_file_is_inside_the_marker_scan_set() -> None:
    """Guard the guard's SCOPE: every shipped .md must actually get scanned.

    The failure this pins down is a coverage hole, not a leak. A second `cp` line added
    `references/cli-flags.md` to the published bundle, but the parser only understood the
    `cp -r` line, so that file shipped without ever being checked for internal markers —
    while this module's docstring promised it would "drift loudly rather than silently".
    A guard that quietly stops covering new files is worse than no guard.
    """
    scanned = {str(p.relative_to(REPO_ROOT)) for p in _shipped_md_and_py_files()}
    missing = []
    for entry in _staged_source_paths():
        path = REPO_ROOT / entry
        if path.is_file() and path.suffix == ".md" and entry not in scanned:
            missing.append(entry)

    assert not missing, (
        f"These files are published but never scanned for internal markers: {missing!r}.\n"
        "Every shipped .md must be inside _shipped_md_and_py_files()."
    )


def test_shipped_md_and_py_files_are_nonempty() -> None:
    """Guard against the enumeration itself silently finding nothing (a test that
    can never fail is worse than no test)."""
    files = _shipped_md_and_py_files()
    md_count = sum(1 for f in files if f.suffix == ".md")
    py_count = sum(1 for f in files if f.suffix == ".py")
    assert md_count >= 5, f"Expected several shipped .md files, found {md_count}."
    assert py_count >= 10, f"Expected many shipped .py files, found {py_count}."


def test_no_internal_markers_in_shipped_files() -> None:
    """The drift guard: no shipped .md/.py file may contain an internal-only marker.

    Fails with the exact file, line number, marker name, and matched text so a
    future leak is trivial to locate and fix.
    """
    failures: list[str] = []
    for path in _shipped_md_and_py_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # Shipped .md/.py are always text; a decode failure is itself suspicious
            # but out of scope for this marker gate — surface it, don't hide it.
            failures.append(f"{path.relative_to(REPO_ROOT)}: could not decode as UTF-8")
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for marker_name, pattern in _MARKERS:
                m = pattern.search(line)
                if m:
                    rel = path.relative_to(REPO_ROOT)
                    failures.append(
                        f"{rel}:{lineno}: [{marker_name}] matched {m.group(0)!r} "
                        f"in line: {line.strip()!r}"
                    )

    assert not failures, (
        "Internal-only marker(s) leaked into publicly-shipped file(s):\n"
        + "\n".join(failures)
    )
