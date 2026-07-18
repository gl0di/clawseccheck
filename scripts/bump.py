#!/usr/bin/env python3
"""Release version bumper for ClawSecCheck — stdlib only.

Writes the version in lock-step across every source a consumer reads, so a
release can't ship a mismatch (the §6 lock-step, automated):

  - clawseccheck/__init__.py   __version__
  - clawseccheck/__init__.py   __released__   -> today (or --date)
  - SKILL.md                   version:
  - CHANGELOG.md               a new top "## [X.Y.Z] — DATE" stub (prose is yours)

Usage:
  python3 scripts/bump.py patch|minor|major     # bump from current __version__
  python3 scripts/bump.py --set X.Y.Z           # set an explicit version
  python3 scripts/bump.py --suggest             # print the level recommended by
                                                # Conventional Commits since the last
                                                # tag, then exit (writes nothing)
  python3 scripts/bump.py patch --date 2026-06-23   # override the release date
  python3 scripts/bump.py patch --dry-run       # show changes, write nothing

It deliberately NEVER tags, commits, or pushes — releasing stays a manual,
token-gated act. After running:

  1. fill in the CHANGELOG prose,
  2. run `python3 -m pytest -q` and `ruff check .`,
  3. git commit, then `git tag vX.Y.Z && git push origin main --tags`.
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / "clawseccheck" / "__init__.py"
SKILL = ROOT / "SKILL.md"
CHANGELOG = ROOT / "CHANGELOG.md"
THREAT_COVERAGE = ROOT / "docs" / "THREAT_COVERAGE.md"

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _current_version() -> str:
    m = re.search(r'^__version__ = "([^"]+)"', INIT.read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit("error: could not find __version__ in clawseccheck/__init__.py")
    return m.group(1)


def _next_version(cur: str, level: str) -> str:
    major, minor, patch = (int(x) for x in cur.split("."))
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _commits_since_last_tag() -> list[str]:
    try:
        tag = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        rng = f"{tag}..HEAD"
    except (subprocess.CalledProcessError, FileNotFoundError):
        rng = "HEAD"  # no tags yet (or no git) — consider all reachable commits
    try:
        out = subprocess.run(
            ["git", "log", rng, "--format=%s%n%b%x00"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [c.strip() for c in out.split("\x00") if c.strip()]


def _suggest_level(commits: list[str]) -> str:
    """Map Conventional Commits to a bump level (highest wins)."""
    level = None
    for c in commits:
        subject = c.splitlines()[0]
        if "BREAKING CHANGE" in c or re.match(r"^\w+(\([^)]*\))?!:", subject):
            return "major"
        if re.match(r"^feat(\([^)]*\))?:", subject):
            level = "minor"
        elif level != "minor" and re.match(r"^fix(\([^)]*\))?:", subject):
            level = "patch"
    return level or "patch"


def _sub_or_die(path: Path, pattern: str, repl: str, label: str) -> str:
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, text, count=1, flags=re.M)
    if n != 1:
        sys.exit(f"error: could not update {label} in {path.relative_to(ROOT)}")
    return new


def _changelog_stub(version: str, date: str) -> str:
    return (
        f"## [{version}] — {date}\n\n"
        "_TODO: one-line summary of what changed and why._\n\n"
        "### Added\n- _TODO_\n\n"
        "### Fixed\n- _TODO_\n\n"
        "### Changed\n- _TODO_\n\n"
    )


def _insert_changelog(version: str, date: str, dry: bool) -> str:
    text = CHANGELOG.read_text(encoding="utf-8")
    m = re.search(r"^##\s*\[", text, re.M)
    if not m:
        sys.exit("error: CHANGELOG.md has no existing '## [..]' entry to insert above")
    stub = _changelog_stub(version, date)
    new = text[: m.start()] + stub + text[m.start() :]
    if not dry:
        CHANGELOG.write_text(new, encoding="utf-8")
    return stub


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Bump ClawSecCheck version in lock-step.")
    p.add_argument("level", nargs="?", choices=["patch", "minor", "major"],
                   help="bump level (omit when using --set or --suggest)")
    p.add_argument("--set", dest="explicit", metavar="X.Y.Z",
                   help="set an explicit version instead of bumping")
    p.add_argument("--suggest", action="store_true",
                   help="print the level recommended by Conventional Commits, then exit")
    p.add_argument("--date", help="release date (YYYY-MM-DD); default today")
    p.add_argument("--dry-run", action="store_true", help="show changes, write nothing")
    args = p.parse_args(argv)

    cur = _current_version()

    if args.suggest:
        commits = _commits_since_last_tag()
        level = _suggest_level(commits)
        print(f"current: {cur}")
        print(f"commits since last tag: {len(commits)}")
        print(f"suggested bump: {level}  ->  {_next_version(cur, level)}")
        return 0

    if args.explicit:
        new_version = args.explicit
        if not _SEMVER.match(new_version):
            sys.exit(f"error: --set value {new_version!r} is not a bare X.Y.Z semver")
    elif args.level:
        new_version = _next_version(cur, args.level)
    else:
        p.error("give a bump level (patch|minor|major), or --set X.Y.Z, or --suggest")

    if new_version == cur:
        sys.exit(f"error: target version {new_version} equals the current version")

    if args.date:
        try:
            dt.date.fromisoformat(args.date)
        except ValueError:
            sys.exit(f"error: --date {args.date!r} is not a valid ISO date")
        date = args.date
    else:
        date = dt.date.today().isoformat()

    # Compute all edits first (fail before writing anything).
    init_new = _sub_or_die(
        INIT, r'^__version__ = "[^"]+"', f'__version__ = "{new_version}"', "__version__")
    # apply the second edit to the already-updated init text
    init_new2, n = re.subn(
        r'^__released__ = "[^"]+"', f'__released__ = "{date}"', init_new, count=1, flags=re.M)
    if n != 1:
        sys.exit("error: could not update __released__ in clawseccheck/__init__.py")
    skill_new = _sub_or_die(
        SKILL, r"^version:\s*\S+", f"version: {new_version}", "version:")
    # The threat matrix states which release it was last ground against; if that line
    # goes stale the matrix silently claims coverage it never re-verified. Restamping it
    # here keeps tests/test_doc_facts.py green — but the stamp is a claim, so re-read the
    # matrix when the catalog changed.
    threat_new = _sub_or_die(
        THREAT_COVERAGE,
        r"Updated \d{4}-\d{2}-\d{2} for v\d+\.\d+\.\d+",
        f"Updated {date} for v{new_version}",
        "THREAT_COVERAGE 'Updated … for v…' line")

    if args.dry_run:
        print(f"[dry-run] {cur} -> {new_version}  (released {date})")
        print("[dry-run] would update: clawseccheck/__init__.py, SKILL.md, "
              "CHANGELOG.md, docs/THREAT_COVERAGE.md")
        print("[dry-run] CHANGELOG stub:\n" + _changelog_stub(new_version, date))
        return 0

    INIT.write_text(init_new2, encoding="utf-8")
    SKILL.write_text(skill_new, encoding="utf-8")
    THREAT_COVERAGE.write_text(threat_new, encoding="utf-8")
    _insert_changelog(new_version, date, dry=False)

    print(f"bumped {cur} -> {new_version}  (released {date})")
    print("updated: clawseccheck/__init__.py, SKILL.md, CHANGELOG.md, "
          "docs/THREAT_COVERAGE.md")
    print("next: fill the CHANGELOG prose, re-ground the docs whose facts changed")
    print("      (python3 -m pytest tests/test_doc_facts.py -q names any that drifted),")
    print("      run tests + ruff, then:")
    print(f"  git commit -am 'chore: v{new_version} — <summary>'")
    print(f"  git tag v{new_version} && git push origin main --tags")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
