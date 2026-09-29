"""Every file ClawHub receives must be one-byte text: no character above U+00FF.

WHY (openclaw/clawhub#3831)
    ClawHub's skill-publish action decodes every file in the uploaded bundle and joins ALL
    of their text, twice, inside a 64 MiB Convex isolate. V8 keeps a string at one byte per
    character only while every character is at most U+00FF (Latin-1). A SINGLE character
    above that, anywhere in any file, makes the whole joined string two bytes per
    character, and the join happens twice. Before the v4.3.1 sweep about 26k such
    characters (em dashes, box-drawing, Cyrillic, arrows, emoji) sat in 134 of v4.3.0's
    139 staged files (10.4M characters). Latin-1 characters (section sign,
    middle dot, multiplication sign, e-acute, ...) are fine and were deliberately left alone.

    The fix is always in the SOURCE, never in this guard: `\\uXXXX` escapes in string
    literals (value-preserving), plain ASCII in comments and docstrings, and HTML entities
    (`&#x2014;`) in Markdown.

WHAT SHIPS
    The set is not listed here. It is derived from the publish workflow's "Stage publishable
    files" step by the parsers tests/test_publish_workflow.py already uses for its dangling-
    link guard (`_staged_paths` / `_purged_paths` / `_is_shipped`), so a file added to that
    step is covered the day it lands and the two cannot drift.

THREE LAYERS
    1. Source tree: every shipped source file, whole (CHANGELOG.md is checked in full, not
       just the entries the publish step keeps).
    2. Staged tree: the REAL staging step is replayed and what it produces is scanned, which
       also covers text the step itself injects (the trimmed CHANGELOG's trailer).
    3. The workflow's own "Guard" step, which repeats the rule on the runner over the exact
       bytes about to be uploaded. It is executed here, against planted characters, and
       compared with this module's scanner so the two implementations cannot diverge.

Everything is offline and writes only under pytest's `tmp_path`. This file is ASCII on
purpose, and the planted characters are spelled as escapes.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import unicodedata
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Set, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "clawhub-publish.yml"

# The published skill package ships without .github/, so there is no workflow to derive the
# shipped set from. Decided BEFORE the import below, so a genuine ImportError (a renamed
# helper) still fails loudly instead of being read as "no workflow".
if not WORKFLOW_PATH.exists():
    pytest.skip(
        "CI workflow file not present (packaged skill ships without .github/); the "
        "publish-bundle one-byte guard runs only from the source repo.",
        allow_module_level=True,
    )

from test_publish_workflow import (  # noqa: E402
    STAGING_DIR,
    _is_shipped,
    _publish_invocations,
    _purged_paths,
    _replay_staged_tree,
    _staged_paths,
    _step_name,
    _step_shell_block,
    _steps,
)

LIMIT = 0xFF  # U+00FF: the last code point V8 can keep at one byte per character
MAX_LISTED = 40  # how many offenders a failure message spells out

_WIDE_RE = re.compile(r"[^\x00-\xff]")

WHY = (
    "ClawHub's skill-publish action (openclaw/clawhub#3831) decodes every file in the "
    "bundle and joins ALL of their text, twice, inside a 64 MiB Convex isolate. V8 keeps a "
    "string at one byte per character only while every character is <= U+00FF, so ONE "
    "character above that anywhere makes the whole joined string two bytes per character "
    "and doubles the memory. Latin-1 characters (U+0080..U+00FF, e.g. the section sign, "
    "middle dot, e-acute) are allowed. Fix the SOURCE, not the guard: "
    r"use \uXXXX escapes in Python string literals (the value is unchanged), plain ASCII "
    "in comments and docstrings, and HTML entities (for example &#x2014;) in Markdown."
)


class Hit(NamedTuple):
    """One offence: a character above U+00FF, or a file that is not UTF-8 at all."""

    path: str
    line: int  # 1-based; 0 when the file did not decode
    col: int  # 1-based; 0 when the file did not decode
    what: str


def scan_bytes(rel: str, raw: bytes) -> List[Hit]:
    """Every offence in one file's bytes, in reading order.

    Lines are split on "\\n" ONLY, so the reported line number matches what an editor and
    `grep -n` show. `str.splitlines()` would also break on U+0085, U+2028 and the form-feed
    family and skew every line after one of them.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [Hit(rel, 0, 0, "not valid UTF-8 (" + exc.reason + ")")]
    hits: List[Hit] = []
    for lineno, line in enumerate(text.split("\n"), 1):
        for match in _WIDE_RE.finditer(line):
            ch = match.group()
            what = "U+%04X %s" % (ord(ch), unicodedata.name(ch, "<unnamed>"))
            hits.append(Hit(rel, lineno, match.start() + 1, what))
    return hits


def scan_files(files: Iterable[Tuple[str, Path]]) -> List[Hit]:
    hits: List[Hit] = []
    for rel, path in files:
        hits.extend(scan_bytes(rel, path.read_bytes()))
    return hits


def tree_files(root: Path) -> List[Tuple[str, Path]]:
    return [
        (p.relative_to(root).as_posix(), p)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    ]


def scan_tree(root: Path) -> List[Hit]:
    return scan_files(tree_files(root))


def explain(hits: List[Hit], scanned: int, where: str) -> str:
    """The failure message: why it matters, how to fix it, and file:line:col for each hit."""
    per_file: Dict[str, int] = {}
    for hit in hits:
        per_file[hit.path] = per_file.get(hit.path, 0) + 1
    worst = sorted(per_file.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    lines = [
        "%d offence(s) in %d of %d file(s) of %s: a character above U+00FF, or bytes that "
        "are not UTF-8." % (len(hits), len(per_file), scanned, where),
        WHY,
        "",
    ]
    lines.extend("  %s:%d:%d  %s" % h for h in hits[:MAX_LISTED])
    if len(hits) > MAX_LISTED:
        lines.append("  ... and %d more" % (len(hits) - MAX_LISTED))
    lines.append("")
    lines.append("worst files: " + ", ".join("%s (%d)" % kv for kv in worst))
    return "\n".join(lines)


def assert_one_byte(files: List[Tuple[str, Path]], where: str) -> None:
    """The guard itself. The real tests and the planted-character tests both call this."""
    assert files, "no files to scan in %s: the guard would pass vacuously." % where
    hits = scan_files(files)
    assert not hits, explain(hits, len(files), where)


# ---------------------------------------------------------------------------------
# What ships, derived from the workflow
# ---------------------------------------------------------------------------------


def _candidate_files(roots: List[str]) -> List[str]:
    """Repo-relative files under *roots*: tracked + untracked-but-not-ignored.

    `--others` matters: a new module that is not yet `git add`ed would otherwise pass here
    and fail in CI. Outside a git checkout (a source tarball) it falls back to a walk.

    The git argv is a plain literal list on purpose (no `*roots` splat, no pathspec): the
    roots are applied in Python below. tests/test_subprocess_*_hermeticity.py read every
    subprocess call's argv statically and cannot see through a splat of a function
    parameter, so a spread argv here is reported as "unresolved" even though this spawns
    `git`, not the clawseccheck CLI.
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=str(REPO_ROOT), capture_output=True, text=True,
        )
    except OSError:
        proc = None
    if proc is not None and proc.returncode == 0:
        return sorted({
            line
            for line in proc.stdout.splitlines()
            if any(line == root or line.startswith(root.rstrip("/") + "/") for root in roots)
        })
    found: List[str] = []
    for root in roots:
        path = REPO_ROOT / root
        if path.is_file():
            found.append(root)
        elif path.is_dir():
            found.extend(p.relative_to(REPO_ROOT).as_posix() for p in path.rglob("*") if p.is_file())
    return sorted(found)


def shipped_source_files() -> List[Tuple[str, Path]]:
    """(repo-relative path, absolute path) of every source file the staging step ships."""
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    staged = _staged_paths(text)
    purged = _purged_paths(text)
    out: List[Tuple[str, Path]] = []
    for rel in _candidate_files(sorted(staged)):
        if "__pycache__" in Path(rel).parts:
            continue  # the staging step deletes every __pycache__ after copying
        if not _is_shipped(rel, staged, purged):
            continue  # e.g. docs/assets, which the staging step purges
        path = REPO_ROOT / rel
        if path.is_file():  # a deleted-but-still-indexed path has nothing to scan
            out.append((rel, path))
    return out


def test_the_shipped_file_set_is_derived_from_the_workflow_and_is_not_vacuous() -> None:
    """Guard the guard: an empty or shrunken set would pass the one-byte check silently."""
    rels = {rel for rel, _ in shipped_source_files()}
    for required in (
        "SKILL.md",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "pyproject.toml",
        "audit.py",
        "references/cli-flags.md",
        "clawseccheck/__init__.py",
        "clawseccheck/checks/__init__.py",
        "docs/CHECKS.md",
    ):
        assert required in rels, (
            f"{required} ships in every release but fell out of the derived set, so the "
            "one-byte check below would no longer cover it."
        )
    assert len(rels) >= 100, (
        f"only {len(rels)} shipped files were derived; the staging parser or the git "
        "listing is not seeing what it should."
    )
    assert not any(r.startswith("docs/assets/") for r in rels), "docs/assets is purged, not shipped"
    assert not any("__pycache__" in r for r in rels), "__pycache__ is pruned, not shipped"
    assert not any(r.startswith(("tests/", "fixtures/", ".github/")) for r in rels), (
        "tests/, fixtures/ and .github/ are never staged; the derived set picked one up."
    )


# ---------------------------------------------------------------------------------
# The real guards
# ---------------------------------------------------------------------------------


def test_every_shipped_source_file_is_one_byte_text() -> None:
    """Layer 1: no character above U+00FF in any file that ships (CHANGELOG.md in full)."""
    assert_one_byte(shipped_source_files(), "the shipped source tree")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_the_staged_bundle_is_one_byte_text(tmp_path) -> None:
    """Layer 2: replay the REAL staging step and scan what it produces.

    This is the tree `clawhub publish` uploads, so it also catches text the step itself
    writes into a file (the trimmed CHANGELOG.md's "older entries omitted" trailer carried
    an em dash until this guard found it).
    """
    inside = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=str(REPO_ROOT), capture_output=True, text=True,
    )
    if inside.returncode != 0:
        pytest.skip("not a git checkout (source tarball): nothing to replay")
    work, _total, _per_top = _replay_staged_tree(tmp_path)
    assert_one_byte(tree_files(work / STAGING_DIR), "the replayed staged bundle")


# ---------------------------------------------------------------------------------
# The guard has teeth: planted characters, in tmp_path only
# ---------------------------------------------------------------------------------

# One representative of every class the real bundle used to carry, plus the exact boundary.
PLANTED = [
    pytest.param("\u2014", "U+2014 EM DASH", id="em-dash"),
    pytest.param("\u2013", "U+2013 EN DASH", id="en-dash"),
    pytest.param("\u2500", "U+2500 BOX DRAWINGS LIGHT HORIZONTAL", id="box-drawing"),
    pytest.param("\u2192", "U+2192 RIGHTWARDS ARROW", id="arrow"),
    pytest.param("\u2026", "U+2026 HORIZONTAL ELLIPSIS", id="ellipsis"),
    pytest.param("\u0416", "U+0416 CYRILLIC CAPITAL LETTER ZHE", id="cyrillic"),
    pytest.param("\U0001f99e", "U+1F99E LOBSTER", id="astral-emoji"),
    pytest.param("\ufeff", "U+FEFF ZERO WIDTH NO-BREAK SPACE", id="byte-order-mark"),
    pytest.param("\u0100", "U+0100 LATIN CAPITAL LETTER A WITH MACRON", id="first-code-point-over-the-limit"),
]


@pytest.mark.parametrize("planted, what", PLANTED)
def test_the_guard_catches_a_planted_character_and_names_file_line_column(
    tmp_path, planted, what
) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "pkg").mkdir(parents=True)
    (bundle / "pkg" / "mod.py").write_text(
        "x = 1\n# note " + planted + " here\ny = 2\n", encoding="utf-8"
    )
    (bundle / "README.md").write_text("plain ascii\n", encoding="utf-8")

    with pytest.raises(AssertionError) as caught:
        assert_one_byte(tree_files(bundle), "a planted bundle")
    message = str(caught.value)

    assert "pkg/mod.py:2:8  " + what in message, message
    assert "README.md" not in message, "the clean file must not be blamed:\n" + message
    # The message must carry the reason and the three fixes, or a red run is a mystery.
    for fragment in (
        "openclaw/clawhub#3831",
        "64 MiB",
        "U+00FF",
        "two bytes per character",
        r"\uXXXX",
        "ASCII",
        "HTML entities",
    ):
        assert fragment in message, f"failure message lost {fragment!r}:\n{message}"


def test_the_guard_accepts_latin_1_up_to_and_including_u_00ff(tmp_path) -> None:
    """Positive control: a guard that rejected Latin-1 would force churn for nothing."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "latin1.md").write_text(
        "\u0080 \u00a7 \u00b7 \u00d7 \u00e9 \u00ff\nplain\n", encoding="utf-8"
    )
    assert_one_byte(tree_files(bundle), "a Latin-1 bundle")


def test_the_guard_flags_a_file_that_is_not_utf_8(tmp_path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "blob.bin").write_bytes(b"ok\n\xff\xfe\x00")
    hits = scan_tree(bundle)
    assert [(h.path, h.line, h.col) for h in hits] == [("blob.bin", 0, 0)], hits
    assert hits[0].what.startswith("not valid UTF-8"), hits


def test_line_numbers_count_newlines_only(tmp_path) -> None:
    """U+0085 and U+2028 are line breaks to str.splitlines() but not to an editor or grep."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "a.md").write_text("a\u0085b\u2028c\n\u2014\n", encoding="utf-8")
    assert scan_tree(bundle) == [
        Hit("a.md", 1, 4, "U+2028 LINE SEPARATOR"),
        Hit("a.md", 2, 1, "U+2014 EM DASH"),
    ]


def test_an_empty_scan_set_is_an_error_not_a_pass(tmp_path) -> None:
    with pytest.raises(AssertionError, match="vacuously"):
        assert_one_byte([], "nothing")


# ---------------------------------------------------------------------------------
# The workflow's own Guard step: wired in the right place, and it agrees with this module
# ---------------------------------------------------------------------------------

_GUARD_NAME_FRAGMENT = "character above U+00FF"
_LISTING_RE = re.compile(
    r"^  (?P<path>\S+):(?P<line>\d+):(?P<col>\d+)  (?P<what>.+)$", re.M
)


def _ci_guard_step_name() -> str:
    names = [n for n in (_step_name(s) for s in _steps()) if _GUARD_NAME_FRAGMENT in n]
    assert len(names) == 1, (
        f"Expected exactly one workflow step guarding against characters above U+00FF, "
        f"found {names!r}."
    )
    return names[0]


def _run_ci_guard(tmp_path: Path, files: Dict[str, bytes]) -> "subprocess.CompletedProcess[str]":
    """Execute the workflow's REAL guard shell block over a planted dist/clawseccheck."""
    root = tmp_path / "dist" / "clawseccheck"
    root.mkdir(parents=True)
    for rel, raw in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    script = tmp_path / "guard.sh"
    script.write_text(_step_shell_block(_ci_guard_step_name()), encoding="utf-8")
    return subprocess.run(
        ["bash", str(script)], cwd=str(tmp_path), capture_output=True, text=True,
    )


def _listed(stdout: str) -> Set[Hit]:
    return {
        Hit(m["path"], int(m["line"]), int(m["col"]), m["what"])
        for m in _LISTING_RE.finditer(stdout)
    }


def test_ci_guard_step_sits_after_the_size_guard_and_before_signing_and_publishing() -> None:
    steps = _steps()
    names = [_step_name(s) for s in steps]

    def index_of(fragment: str) -> int:
        idx = [i for i, n in enumerate(names) if fragment in n]
        assert idx, f"No step containing {fragment!r} in {names!r}"
        return idx[0]

    stage_i = index_of("Stage publishable files")
    size_i = next(
        i for i, step in enumerate(steps) if any("MAX_STAGED_BYTES=" in t for _, t in step)
    )
    guard_i = names.index(_ci_guard_step_name())
    digest_i = index_of("Generate trusted engine digest")
    assert stage_i < size_i < guard_i < digest_i, (
        "The one-byte guard must scan the STAGED tree (after 'Stage publishable files' and "
        "the size guard) and must fail before anything is signed or published: got step "
        f"positions stage={stage_i}, size guard={size_i}, one-byte guard={guard_i}, "
        f"digest={digest_i}."
    )
    first_publish_line = min(inv["line"] for inv in _publish_invocations())
    assert max(line for line, _ in steps[guard_i]) < first_publish_line, (
        "the one-byte guard must run entirely before the first `clawhub publish` invocation."
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_ci_guard_passes_on_a_one_byte_bundle(tmp_path) -> None:
    proc = _run_ci_guard(
        tmp_path,
        {
            "SKILL.md": b"# ascii\n",
            "docs/latin1.md": "\u00a7 \u00b7 \u00d7 \u00e9 \u00ff\n".encode("utf-8"),
            "clawseccheck/mod.py": b"x = '\\u2014'\n",
        },
    )
    assert proc.returncode == 0, f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    assert "one-byte text" in proc.stdout, proc.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_ci_guard_fails_on_planted_characters_and_agrees_with_the_pytest_guard(tmp_path) -> None:
    """Run the workflow's shell block against planted offences; it must report the same set."""
    planted = {
        "a.md": "line one\nem \u2014 dash\n".encode("utf-8"),
        "sub/b.py": "# fine \u00a7\nx = 1  # \u2500\u2500 \U0001f99e\n".encode("utf-8"),
        "sub/deeper/c.md": "\u0100 first code point over the limit\n".encode("utf-8"),
        "d.txt": b"ok\n\xff\xfe\x00",
        "clean.md": b"nothing to see\n",
    }
    proc = _run_ci_guard(tmp_path, planted)
    assert proc.returncode != 0, (
        "The CI guard passed a bundle with characters above U+00FF in it.\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )
    assert "::error::" in proc.stdout, proc.stdout
    for fragment in ("openclaw/clawhub#3831", "64 MiB", r"\uXXXX", "HTML entities"):
        assert fragment in proc.stdout, f"CI guard message lost {fragment!r}:\n{proc.stdout}"

    expected = set(scan_tree(tmp_path / "dist" / "clawseccheck"))
    assert len(expected) == 6, expected  # em dash, 2 box, lobster, U+0100, undecodable
    assert _listed(proc.stdout) == expected, (
        "The workflow's guard and tests/test_publish_bundle_one_byte.py disagree about what "
        f"is an offence.\n  workflow: {sorted(_listed(proc.stdout))}\n  pytest  : {sorted(expected)}"
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_ci_guard_caps_its_listing_but_still_fails(tmp_path) -> None:
    body = "".join("\u2014 %d\n" % i for i in range(MAX_LISTED + 20)).encode("utf-8")
    proc = _run_ci_guard(tmp_path, {"big.md": body})
    assert proc.returncode != 0, proc.stdout
    assert len(_listed(proc.stdout)) == MAX_LISTED, proc.stdout
    assert "... and 20 more" in proc.stdout, proc.stdout
    assert ("%d character(s)" % (MAX_LISTED + 20)) in proc.stdout, proc.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_ci_guard_refuses_an_empty_bundle(tmp_path) -> None:
    proc = _run_ci_guard(tmp_path, {})
    assert proc.returncode != 0, "a scan of zero files must not pass"
    assert "vacuously" in proc.stdout, proc.stdout


def test_ci_guard_and_pytest_guard_share_one_limit() -> None:
    """The two implementations state the same threshold in the same words."""
    block = _step_shell_block(_ci_guard_step_name())
    assert r'WIDE = re.compile(r"[^\x00-\xff]")' in block, (
        "the CI guard no longer scans for characters above U+00FF the way "
        "tests/test_publish_bundle_one_byte.py does"
    )
    assert _WIDE_RE.pattern == r"[^\x00-\xff]"
    assert LIMIT == 0xFF
