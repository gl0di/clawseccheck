"""Materialize the fixture corpus's SKILL.md files from `tests/fixture_skill_md/` (C-809).

WHY THE FIXTURE SKILL.md FILES ARE NOT TRACKED WHERE THEY ARE USED
-----------------------------------------------------------------
Third-party skill catalogs index any file named exactly ``SKILL.md`` in a public GitHub
repository as an installable skill. On 2026-11-20 verified-skill.com listed about 200 of this
repository's test fixtures under the publisher ``gl0di`` with an install command, among them
deliberately unsafe ones (e.g. ``fixtures/bad_b638_exec_env_joined_path/skills/demo-packager``),
and its rules flag an author's whole portfolio when one skill is found malicious. So no file
named ``SKILL.md`` is tracked under ``fixtures/``.

The content lives in a mirror tree instead: ``tests/fixture_skill_md/<path under fixtures>/
SKILL.md.fixture``. Before anything reads the corpus, ``materialize()`` writes each one back
to ``fixtures/<path>/SKILL.md``, which ``.gitignore`` excludes. The mirror sits OUTSIDE every
fixture home on purpose: a ``SKILL.md.fixture`` beside the generated file would itself be
scanned as part of the skill and change verdicts.

WHY IN PLACE, NOT A COPY UNDER tmp_path
---------------------------------------
Dave ruled this on 2026-11-20 as an exception to CLAUDE.md §4 ("tests write only under
pytest's tmp_path"), of the same kind as the in-place mode pinning in ``_fixtureperms``. A
copy of the corpus under pytest's tmp_path would sit under the system temp dir, and the tool
treats temp-dir paths differently (quarantine detection in ``--advise``, among others), so
verdicts would move with the location alone.

Idempotent: a file whose bytes already match is left alone. A generated ``SKILL.md`` whose
source is gone is removed, but only when git does not track it.

To ADD a fixture skill: write ``tests/fixture_skill_md/<fixture>/.../<skill>/SKILL.md.fixture``
and run the suite. Never commit a ``SKILL.md`` under ``fixtures/``;
``tests/test_c809_no_skill_md_under_fixtures.py`` fails if one is tracked.
"""
from __future__ import annotations

import os
import tempfile
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
FIXTURES = _REPO / "fixtures"
MIRROR = _REPO / "tests" / "fixture_skill_md"
SOURCE_NAME = "SKILL.md.fixture"
TARGET_NAME = "SKILL.md"


def sources() -> "list[Path]":
    return sorted(MIRROR.rglob(SOURCE_NAME))


def target_for(source: Path) -> Path:
    return FIXTURES / source.parent.relative_to(MIRROR) / TARGET_NAME


def _tracked_skill_md() -> "set[Path]":
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--", "fixtures"], cwd=_REPO, capture_output=True,
            check=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return set()  # no git (e.g. an sdist): nothing is tracked, so nothing is protected
    return {
        _REPO / p for p in out.decode("utf-8", "surrogateescape").split("\0")
        if p and Path(p).name == TARGET_NAME
    }


def materialize() -> int:
    """Write every fixture SKILL.md from its mirror source. Returns how many were written."""
    written = 0
    wanted = set()
    for src in sources():
        dst = target_for(src)
        wanted.add(dst)
        # A directory that held nothing but SKILL.md files is not in git at all (git tracks
        # no empty directory), so a fresh checkout lacks it. 43 whole fixture homes are like
        # that (e.g. bad_b100_clickfix_ip_fetch is just skills/quick-tool/SKILL.md). Create
        # the path; `_fixtureperms.pin_fixture_modes()` gives it the corpus-wide 0700.
        # exist_ok: parallel pytest processes (shards, xdist workers) materialize the same tree
        dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if dst.is_symlink():
            raise AssertionError(f"{dst} is a symlink; refusing to write through it.")
        data = src.read_bytes()
        if dst.is_file() and dst.read_bytes() == data:
            continue
        # Atomic: write a temp file OUTSIDE every fixture home (so no scan can see it), then
        # os.replace onto the target, so a concurrent reader sees the old file or the whole
        # new one, never a half-written SKILL.md.
        fd, tmp = tempfile.mkstemp(prefix=".materialize-", dir=MIRROR)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            # keep git's one recorded bit (owner-execute) the way the tracked file carried it
            os.chmod(tmp, 0o700 if src.stat().st_mode & 0o100 else 0o600)
            os.replace(tmp, dst)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        written += 1
    tracked = _tracked_skill_md()
    for stale in FIXTURES.rglob(TARGET_NAME):
        if stale not in wanted and stale not in tracked and not stale.is_symlink():
            stale.unlink()
    return written
