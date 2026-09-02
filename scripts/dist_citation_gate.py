#!/usr/bin/env python3
"""Dist-citation gate: stop new UNQUALIFIED stale bundle-filename citations.

Our shipped source cites OpenClaw dist bundles by their content-hashed filename, e.g.
``agent-scope-config-BxAUeF6t.js:66-69``. That filename rotates on essentially every
release -- measured on the installed 2026.8.2: of 206 distinct bundle names cited
across the tree, 194 no longer exist, 94%. A dated citation ("grounded against
openclaw@2026.7.1-2 (2026-07-25), schema-...:389") is CORRECT as history: it records
what was true when the claim was made, and a reader can tell that at a glance. An
UNDATED one asserts the present tense about a file that is not there, and a reader has
no way to tell "renamed, claim still true" from "removed, claim now false" without
grepping the dist by hand.

    python3 scripts/dist_citation_gate.py record   # freeze the CURRENT violation set
    python3 scripts/dist_citation_gate.py compare  # fail on any NEW one (default)

WHY THE FIX IS THE CITATION CONVENTION, NOT REWRITING 538 STRINGS
-------------------------------------------------------------------
538 unqualified violations already exist across 24 files, and hand-fixing all of them
solves nothing: the next OpenClaw release rotates the survivors' hashes too, and the
count is back within a release or two. What actually lasts is a HABIT -- every new
citation carries either a live filename or a date/version qualifier -- and a gate that
enforces the habit going forward. So: freeze the existing 538 as a baseline (this gate
is not asked to fix history), and fail the build only on a citation ADDED after the
baseline that is neither live nor qualified. Pairs that drop out of the violation set
(a citation got fixed, or the file was deleted) are reported as progress and never
block -- this gate exists to stop new rot, not to freeze cleanup, mirroring
``fleet_fp_gate.py``'s ``resolved`` set.

WHAT THIS CANNOT CATCH
-----------------------
* A citation whose bundle still exists on disk but whose cited LINE RANGE moved --
  this gate only checks that the filename resolves, not that ``:66-69`` still points
  at the right code.
* A claim that is wrong for reasons other than a stale filename (a mis-described
  behavior, a renamed field) -- this gate reads filenames, not semantics.
* A symbol cited with no filename attached at all -- e.g. plain prose naming
  ``resolveEffectiveToolFsRootExpansionAllowed`` without a ``foo-HASH.js`` beside it.
  That is in fact the MORE durable citation: of 55 vendor symbols cited across this
  project's own Pulse tasks, 47 survived the 7.1-2 -> 8.2 transition while 94% of the
  filenames alongside them did not. A symbol name is not hash-rotated by the bundler;
  a filename is. Prefer citing the symbol and treat the filename as a (rotting)
  pointer to today's line number, not as the identity of the claim.

BASELINE MODEL
---------------
``tests/dist_citation_baseline.txt`` is a shipped, GENERATED snapshot -- same shape as
``tests/dist_verified_paths.txt``: a header comment (tool, date, the OpenClaw version
resolved against, counts), then sorted entries. Entries are
``<relative-file-path>\\t<bundle-name>`` pairs, NOT line numbers: a line number churns
on any unrelated edit to the same file, while the (file, bundle) pair stays stable and
still names exactly what needs fixing.

Exit codes: 0 clean (no NEW violation), 1 new violation(s), 2 could not run.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from clawseccheck.deptree import find_package_root  # noqa: E402

SCHEMA = 1
BASELINE_DEFAULT = Path(__file__).resolve().parents[1] / "tests" / "dist_citation_baseline.txt"

EXIT_OK = 0
EXIT_NEW_VIOLATION = 1
EXIT_CANNOT_RUN = 2

# A content-hashed bundle filename: PREFIX-HASH.EXT. The hash segment is deliberately
# loose (any run of 8+ alnum/underscore/dash) because different bundlers/releases have
# used different hash alphabets; being loose here is safe because existence is always
# re-checked against the real dist, never assumed from the shape alone.
_CITATION_RE = re.compile(r"[A-Za-z0-9._-]+-[A-Za-z0-9_-]{8,}\.(?:js|d\.ts|mjs)")

# A citation is "qualified" -- correct AS HISTORY -- when a dated or versioned anchor
# appears in the surrounding block. Deliberately permissive (OR of four shapes) because
# the existing convention in this tree already uses all four inconsistently
# ("grounded against openclaw@2026.7.1-2 (2026-07-25)", "as of 2026-08-26", a bare
# "2026-08-06" nearby) and a gate that only recognized one shape would flag correct,
# already-dated prose as a violation.
_QUALIFIER_RE = re.compile(
    r"2026\.\d+\.\d+|\d{4}-\d{2}-\d{2}|grounded (?:against|per)|as of "
)

# Window around a citation searched for a qualifier: 12 lines back, 4 forward. Back-
# heavy because our own convention puts the "grounded against ... (date)" preamble
# above the citations it covers (see collector.py, catalog.py), not beside each one.
_WINDOW_BACK = 12
_WINDOW_FORWARD = 4

_SCAN_GLOBS = ("clawseccheck/**/*.py", "docs/**/*.md")
_SCAN_EXTRA = ("SKILL.md", "README.md")


# --------------------------------------------------------------------------- dist

def _dist_basenames(dist_dir: Path):
    """Every file basename under an OpenClaw dist tree, recursively.

    BASENAME ONLY, and existence is a set-membership test against this -- never a
    prefix/stem match. A stem match would call ``schema-DRyO1XBt.js`` alive because
    ``schema-wieIB86h.js`` exists (same topic bundle, different release, different
    hash): that is exactly the false reassurance this gate exists to prevent, since
    two different hashes on the same stem is the ROTATION itself, not evidence the
    old file survived it.
    """
    names = set()
    for root, _dirs, files in os.walk(dist_dir):
        names.update(files)
    return names


def _locate_dist():
    """The installed OpenClaw's ``dist/`` directory and its declared version, or
    ``(None, None)`` when no matching install can be found on this machine.

    Uses ``deptree.find_package_root`` -- the SAME PATH-based, name-verified resolver
    ``openclawdist.py`` already relies on -- rather than a second, hand-written search,
    so this gate cannot disagree with the rest of the tree about where OpenClaw lives.
    """
    root = find_package_root("openclaw")
    if root is None:
        return None, None
    dist_dir = root / "dist"
    if not dist_dir.is_dir():
        return None, None
    version = None
    try:
        manifest = json.loads((root / "package.json").read_text(encoding="utf-8"))
        version = manifest.get("version")
    except (OSError, ValueError):
        pass
    return dist_dir, version


# --------------------------------------------------------------------------- scan

def _scan_files(repo_root: Path):
    """Every file this gate reads, as paths relative to *repo_root*, sorted."""
    found = set()
    for pattern in _SCAN_GLOBS:
        found.update(repo_root.glob(pattern))
    for name in _SCAN_EXTRA:
        p = repo_root / name
        if p.is_file():
            found.add(p)
    return sorted(found)


def scan_citations(repo_root: Path, dist_basenames):
    """Return ``(violations, total_citations)``.

    ``violations`` is a sorted list of ``(relative_path, bundle)`` pairs: a citation
    whose bundle is absent from *dist_basenames* AND has no qualifier in its
    surrounding window. ``total_citations`` counts every regex match found, resolved
    or not -- the positive control's input (see ``main``): a broken extractor and a
    genuinely clean tree both produce zero violations, and only the total tells them
    apart.
    """
    violations = set()
    total = 0
    for path in _scan_files(repo_root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.split("\n")
        rel = path.relative_to(repo_root).as_posix()
        for match in _CITATION_RE.finditer(text):
            total += 1
            bundle = match.group(0)
            if bundle in dist_basenames:
                continue  # resolves on the installed dist -> OK
            line_no = text.count("\n", 0, match.start()) + 1  # 1-indexed
            start = max(0, line_no - 1 - _WINDOW_BACK)
            end = min(len(lines), line_no - 1 + _WINDOW_FORWARD + 1)
            window = "\n".join(lines[start:end])
            if _QUALIFIER_RE.search(window):
                continue  # dead, but dated/versioned -> OK as history
            violations.add((rel, bundle))
    return sorted(violations), total


# --------------------------------------------------------------------------- baseline

def _read_baseline(path: Path):
    """Sorted ``(file, bundle)`` pairs recorded in the baseline, or ``None`` if the
    file is missing/unreadable -- the caller turns that into ``EXIT_CANNOT_RUN``,
    never into an empty (and therefore always-failing-fresh) baseline."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    pairs = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        pairs.append((parts[0], parts[1]))
    return sorted(pairs)


def _write_baseline(path: Path, pairs, *, version):
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    header = (
        "# GENERATED by scripts/dist_citation_gate.py record. Do not hand-edit.\n"
        "#\n"
        "# Every entry is a (file, bundle-filename) pair citing an OpenClaw dist\n"
        "# bundle that does NOT resolve on the installed dist and carries no\n"
        "# date/version qualifier in its surrounding block -- i.e. an unqualified\n"
        "# citation that asserts the present tense about a file that is not there.\n"
        "# This is a FROZEN baseline of pre-existing violations, not an allowlist to\n"
        "# grow: `compare` fails on any pair NOT in this file. Fixing an entry and\n"
        "# re-recording removes it here; that is progress, never a failure.\n"
        "#\n"
        f"# openclaw-version: {version}\n"
        f"# generated: {generated}\n"
        f"# violations: {len(pairs)}\n"
        "#\n"
    )
    body = "".join(f"{f}\t{b}\n" for f, b in pairs)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + body, encoding="utf-8")


# --------------------------------------------------------------------------- cli

def _run(baseline_path: Path, repo_root: Path, *, record: bool):
    dist_dir, version = _locate_dist()
    if dist_dir is None:
        print(
            "cannot run: no installed OpenClaw package found on PATH (or it has no "
            "dist/ directory). This gate needs a real install to know which bundle "
            "names currently exist -- run it on a machine with OpenClaw installed.",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    dist_basenames = _dist_basenames(dist_dir)
    violations, total = scan_citations(repo_root, dist_basenames)

    # Positive control. A silent zero must never read as "the tree is clean" -- it is
    # far more likely the extractor stopped matching (a glob typo, a moved directory)
    # than that every citation in the tree vanished at once.
    if total == 0:
        print(
            "cannot run: extracted ZERO bundle-filename citations from the scanned "
            "tree -- the extractor is broken, not the tree clean.",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    print(f"openclaw dist   : {dist_dir}")
    print(f"openclaw version: {version}")
    print(f"citations found : {total}   unqualified-dead (violations): {len(violations)}")
    print()

    if record:
        _write_baseline(baseline_path, violations, version=version)
        print(f"baseline recorded: {baseline_path}  ({len(violations)} pair(s))")
        return EXIT_OK

    baseline = _read_baseline(baseline_path)
    if baseline is None:
        print(
            f"error: no recorded baseline at {baseline_path} -- run "
            "`python3 scripts/dist_citation_gate.py record` first.",
            file=sys.stderr,
        )
        return EXIT_CANNOT_RUN

    now = set(violations)
    then = set(baseline)
    new = sorted(now - then)
    resolved = sorted(then - now)

    for f, b in resolved:
        print(f"  resolved  {f}\t{b}")
    for f, b in new:
        print(f"  NEW       {f}\t{b}")

    if new:
        print(
            f"\nBLOCKED: {len(new)} new unqualified stale dist citation(s). Add a live "
            "bundle filename, or a date/version qualifier ('grounded against "
            "openclaw@X.Y.Z (YYYY-MM-DD)', 'as of YYYY-MM-DD', or a bare YYYY-MM-DD / "
            "2026.N.N nearby) if the citation is meant as history."
        )
        return EXIT_NEW_VIOLATION

    print(f"\nOK: no new unqualified stale dist citation against the recorded baseline."
          f" ({len(resolved)} resolved since baseline.)")
    return EXIT_OK


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="dist_citation_gate.py",
        description="Stop NEW unqualified stale OpenClaw dist-bundle citations.",
    )
    ap.add_argument(
        "cmd", nargs="?", default="compare", choices=("record", "compare"),
        help="record: freeze the current violation set as the baseline. "
             "compare (default): fail on any pair not in the baseline.",
    )
    ap.add_argument("--baseline", type=Path, default=BASELINE_DEFAULT)
    ap.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1],
        help="root to scan clawseccheck/, docs/, SKILL.md, README.md under",
    )
    args = ap.parse_args(argv)

    return _run(
        args.baseline.expanduser(),
        args.repo_root.expanduser(),
        record=(args.cmd == "record"),
    )


if __name__ == "__main__":
    raise SystemExit(main())
