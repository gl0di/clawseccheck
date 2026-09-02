"""CLAWSECCHECK-C-125: public-boundary drift guard.

A lightweight, in-repo pytest gate that catches internal-only markers leaking into
files that actually ship in the public ClawHub release, BEFORE the (external, not
ported here — see recon) clawrange-style pre-release gates would catch it.

"What ships" is derived from the *actual* staging step in
`.github/workflows/clawhub-publish.yml` (the "Stage publishable files" step) — not
guessed. That step currently copies, across **all** of its `cp` lines:

    clawseccheck SKILL.md README.md LICENSE SECURITY.md SECURITY_MODEL.md
    SUPPORT.md CHANGELOG.md pyproject.toml docs audit.py
    references/cli-flags.md

`clawseccheck` and `docs` are directories; we expand them to every `git ls-files`
entry under those paths so new files added later are automatically covered without
editing this test.

The staging step does not only copy — it also DELETES, and modelling only the `cp`
lines made this guard's picture of the release wrong in both directions at once
(B-711). Both prunes are mirrored here and pinned against the workflow text:

    find dist/clawseccheck -name '__pycache__' -type d -prune -exec rm -rf {} +
    rm -rf dist/clawseccheck/docs/assets

Everything that survives both prunes is scanned — **every file, not a suffix
allowlist**. The previous rule was ".md anywhere, plus .py under clawseccheck/",
which shipped three files past the guard: `audit.py` (the shim SKILL.md tells the
host agent to run, at the repo root and so outside the `clawseccheck/` prefix),
`LICENSE`, and `pyproject.toml`. It also scanned `docs/assets/src/README.md`, which
the `rm -rf` above removes and which therefore never ships at all.

A suffix allowlist is the wrong shape for this guard: the hole it opens is invisible
(a file simply stops being checked, silently, which is the exact failure the
`references/cli-flags.md` incident already taught once — one file type over). After
the prunes the published set is 100% text, so scanning all of it costs nothing and
cannot narrow again by accident. `test_the_published_set_is_all_text` pins the
premise that makes that safe, so a future binary addition fails loudly here rather
than crashing the marker scan with a decode error.

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
    # Ships beside LICENSE: MIT covers the code, not the name, and an installed copy
    # should carry that notice. CLA.md deliberately does NOT ship — it is contributor-
    # only and meaningless in an installed skill, so README links it by absolute URL.
    "TRADEMARK.md",
    "SECURITY.md",
    "SECURITY_MODEL.md",
    "SUPPORT.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "docs",
    "audit.py",
    "references/cli-flags.md",
]

# The staging step's post-copy DELETES, as literal fragments of the workflow. Pinned
# by test_workflow_still_prunes_what_we_model: if a prune is removed from the workflow
# the shipped set grows, and a guard modelling a prune that no longer happens would
# under-scan exactly the files that just started shipping.
_PRUNE_COMMANDS = [
    "find dist/clawseccheck -name '__pycache__' -type d -prune -exec rm -rf {} +",
    "rm -rf dist/clawseccheck/docs/assets",
]

# The corresponding path rule, applied to every staged file.
#
# `__pycache__` is currently INERT here and is kept deliberately: `_shipped_files()`
# enumerates through `git ls-files`, which never lists an ignored directory, so removing
# this entry changes nothing today (measured — the mutation passes the whole module). It
# stays because it mirrors a real workflow step and because the enumeration's use of
# `git ls-files` is the only reason it is inert; if that ever became a filesystem walk,
# this rule becomes live again. Documented rather than deleted, and documented rather than
# left looking load-bearing.
_PRUNED_PARTS = ("__pycache__",)
_PRUNED_PREFIXES = (("docs", "assets"),)


def _is_pruned(rel: Path) -> bool:
    """True when the workflow deletes this file after copying it."""
    parts = rel.parts
    if any(part in _PRUNED_PARTS for part in parts):
        return True
    return any(parts[: len(prefix)] == prefix for prefix in _PRUNED_PREFIXES)


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
    state without a subprocess-heavy or YAML-parsing dependency).

    **`git ls-files` is load-bearing, not a convenience.** It is what keeps ignored dev
    artefacts out of this enumeration without a second rule -- notably `.ruff_cache/`,
    which sits inside `clawseccheck/` and whose cache blob carries an absolute developer
    path from an unrelated project. It cannot reach a release today: it is gitignored,
    zero files are tracked, and CI publishes from a fresh checkout. Replace this with a
    filesystem walk (`rglob`) and that stops being true for anyone who publishes from a
    working tree -- the guard would enumerate the cache, the marker scan would hit a
    binary, and the failure would look like a bug in this test rather than a leak.

    Both of the staging step's post-copy prunes are applied, so this is the set the
    release actually contains — not the set the `cp` lines name.
    """
    entries = _staged_source_paths()
    files: list[Path] = []
    for entry in entries:
        abs_entry = REPO_ROOT / entry
        if abs_entry.is_dir():
            for rel in _git_ls_files(entry):
                if _is_pruned(Path(rel)):
                    continue
                files.append(REPO_ROOT / rel)
        else:
            assert abs_entry.is_file(), (
                f"Workflow stages {entry!r} but it does not exist at {abs_entry}"
            )
            if _is_pruned(Path(entry)):
                continue
            files.append(abs_entry)
    return files


def _shipped_md_and_py_files() -> list[Path]:
    """Every file the release actually contains — the scan set.

    Kept under its historical name so nothing that refers to it has to move; the
    name is now narrower than the thing, which is the safe direction. It used to
    return a suffix-filtered slice, and the three files that slice dropped
    (`audit.py`, `LICENSE`, `pyproject.toml`) shipped unscanned. See the module
    docstring for why an allowlist is the wrong shape here.
    """
    return _shipped_files()


# --- the actual gate --------------------------------------------------------


def test_workflow_stages_expected_source_paths() -> None:
    """Sanity check the staging step parses to a non-empty, sane file list."""
    entries = _staged_source_paths()
    assert entries, "Parsed an empty staging list from the publish workflow."
    assert "clawseccheck" in entries
    assert "SKILL.md" in entries


def test_the_scan_set_is_not_filtered_down_from_what_ships() -> None:
    """Guard the guard's SCOPE: the scan set must BE the shipped set, not a slice of it.

    This replaces an earlier "every staged .md is scanned" test. That test was written after
    a second `cp` line added `references/cli-flags.md` to the bundle and the parser only
    understood `cp -r`, so a published file fell outside the scan — and it asked about `.md`
    ONLY, which is why it could not see the identical hole one file type over: `audit.py` is
    staged by its own name, ships in every release, and sat unscanned for exactly as long.

    Once the suffix allowlist was dropped that test became tautological — it passed with the
    coverage question narrowed straight back to `.md` (measured). A test that cannot fail is
    worse than no test, so the property is now asserted where it still has teeth: the scan set
    is every shipped file, and re-introducing ANY filter fails here and in
    `test_the_scan_covers_the_files_a_suffix_allowlist_dropped` below.
    """
    scanned = {str(p.relative_to(REPO_ROOT)) for p in _shipped_md_and_py_files()}
    shipped = {str(p.relative_to(REPO_ROOT)) for p in _shipped_files()}
    assert scanned == shipped, (
        "These files ship but are not scanned for internal markers: "
        f"{sorted(shipped - scanned)!r}. The scan set must not be filtered."
    )
    for entry in _staged_source_paths():
        path = REPO_ROOT / entry
        if path.is_file() and not _is_pruned(Path(entry)):
            assert entry in scanned, f"{entry} is staged by name but never scanned"


def test_workflow_still_prunes_what_we_model() -> None:
    """Anchor the prunes on the producer, not on our own belief about them.

    We EXCLUDE `docs/assets/**` and `__pycache__` from the scan because the workflow
    deletes them after copying. If either `rm` is dropped from the workflow those files
    start shipping again, and a guard still modelling the prune would skip precisely the
    newly-shipped set — the failure would be silent, in the under-scanning direction.
    """
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    for command in _PRUNE_COMMANDS:
        assert command in text, (
            f"The publish workflow no longer runs {command!r}, so those files now ship. "
            "Remove the matching rule from _PRUNED_PARTS/_PRUNED_PREFIXES so they get "
            "scanned, rather than leaving this guard modelling a deletion that stopped "
            "happening."
        )


def test_the_published_set_is_all_text() -> None:
    """The premise that lets the scan drop its suffix allowlist.

    Scanning every shipped file is only safe while every shipped file is decodable text.
    Today it is — after the prunes the release is .py/.md plus LICENSE and pyproject.toml,
    and the images live entirely under the pruned `docs/assets`. If a binary is ever added
    to the published set this fails here, with a clear instruction, instead of surfacing
    as an unexplained decode error inside the marker scan.
    """
    binaries = []
    for path in _shipped_md_and_py_files():
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            binaries.append(str(path.relative_to(REPO_ROOT)))
    assert not binaries, (
        f"These shipped files are not text: {binaries!r}. The marker scan reads every "
        "shipped file; give it an explicit binary skip-list before adding these."
    )


def test_the_scan_covers_the_files_a_suffix_allowlist_dropped() -> None:
    """The regression, named. These three ship in every release and were never scanned:
    `audit.py` is the shim SKILL.md tells the host agent to run — the most executable
    thing in the bundle — and it sits at the repo root, outside the `clawseccheck/`
    prefix the old rule required. Asserted by name so a future narrowing has to delete
    this test rather than quietly satisfy it.
    """
    scanned = {str(p.relative_to(REPO_ROOT)) for p in _shipped_md_and_py_files()}
    for name in ("audit.py", "LICENSE", "pyproject.toml"):
        assert name in scanned, f"{name} ships but is not in the marker scan set"


def test_a_file_the_workflow_deletes_is_not_treated_as_shipped() -> None:
    """The other direction, and the reason this is not just "scan more". `docs/assets`
    is copied and then removed, so anything under it never reaches a release — including
    a README that the old scan set did include. Over-scanning is harmless for markers but
    the enumeration is also this module's stated model of what ships, and a model that is
    wrong in the generous direction is what makes the next narrowing look reasonable.
    """
    scanned = {str(p.relative_to(REPO_ROOT)) for p in _shipped_md_and_py_files()}
    assert not [s for s in scanned if s.startswith("docs/assets/")], (
        "docs/assets is deleted by the staging step; nothing under it ships"
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
