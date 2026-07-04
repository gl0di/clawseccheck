"""CLAWSECCHECK-C-125: public-boundary drift guard.

A lightweight, in-repo pytest gate that catches internal-only markers leaking into
files that actually ship in the public ClawHub release, BEFORE the (external, not
ported here — see recon) clawrange-style pre-release gates would catch it.

"What ships" is derived from the *actual* staging step in
`.github/workflows/clawhub-publish.yml` (the "Stage publishable files" step's
`cp -r ...` line) — not guessed. That line currently copies:

    clawseccheck SKILL.md README.md LICENSE SECURITY.md SECURITY_MODEL.md
    CHANGELOG.md pyproject.toml docs audit.py

`clawseccheck` and `docs` are directories; we expand them to every `git ls-files`
entry under those paths so new files added later are automatically covered without
editing this test. Per the workflow, `__pycache__` is pruned from `clawseccheck/`
after staging, so it is excluded here too (dev artifact, never actually ships).

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

# The workflow copies these top-level entries verbatim (see the "Stage publishable
# files" step). Kept as a literal fallback list; _staged_top_level_entries() below
# parses the real `cp -r` line out of the workflow so this drifts loudly (test
# failure) rather than silently if the workflow ever changes what it ships.
_EXPECTED_TOP_LEVEL = [
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


def _staged_top_level_entries() -> list[str]:
    """Parse the real `cp -r <entries> dist/clawseccheck/` line out of the workflow.

    This is the source of truth for "what ships" (task spec point 1) — we do not
    guess or hardcode independently of the workflow file. Falls back to the literal
    list above only if the expected line shape isn't found (so a workflow rewrite
    fails this test loudly instead of silently under-covering).
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    match = re.search(r"cp -r\s+(.*?)\s+dist/clawseccheck/", text, re.DOTALL)
    assert match is not None, (
        "Could not find the 'cp -r ... dist/clawseccheck/' staging line in "
        f"{WORKFLOW_PATH} — the publish workflow's file list changed shape; "
        "update this test's parsing (or the _EXPECTED_TOP_LEVEL fallback) to match."
    )
    # The cp line is continued across lines with trailing backslashes.
    entries = match.group(1).replace("\\", " ").split()
    assert entries == _EXPECTED_TOP_LEVEL, (
        f"Publish workflow now stages {entries!r}, expected {_EXPECTED_TOP_LEVEL!r} — "
        "update _EXPECTED_TOP_LEVEL (and re-check whether new shipped files need "
        "different marker handling) before trusting this test's coverage."
    )
    return entries


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
    entries = _staged_top_level_entries()
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


def test_workflow_stages_expected_top_level_entries() -> None:
    """Sanity check the staging line parses to a non-empty, sane file list."""
    entries = _staged_top_level_entries()
    assert entries, "Parsed an empty staging list from the publish workflow."
    assert "clawseccheck" in entries
    assert "SKILL.md" in entries


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
