"""Every fixture path carries a mode that is a property of the FIXTURE, never of the
machine that checked it out.

WHY THIS EXISTS. git records exactly one permission bit (owner-execute), so every other
mode bit on a checked-out fixture is decided by the checkout umask. Three checks read
those bits -- B19 (data at rest), B20 (bootstrap write protection), B85 (trajectory
tamper-resistance) -- which made 95 of the 496 fixture homes produce a DIFFERENT
``Finding.detail``, and therefore a different ``baseline.fingerprint()``, under ``umask
002`` (dev box: 0775/0664) than under ``umask 022`` (GitHub runner: 0755/0644). A fully
green local run consequently shipped a red CI on
``tests/test_finding_fingerprint_manifest.py``.

The same class had already been patched three times one path at a time (B182, B188, the
three B-309 follow-ups) and grew straight back each time, because the defect is not in any
particular path -- it is that an unpinned path inherits the umask. ``conftest.py`` now pins
the whole corpus (0700 dirs / 0600 files, owner-execute preserved) with a short exception
table; this file is what stops the next fix from being a fourth one-path patch.

Nothing here needs the audit engine: these are properties of the corpus on disk, asserted
after ``conftest.py``'s session-scoped ``_deterministic_fixture_perms`` has run.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

# Load the ROOT conftest by path, deliberately not `import conftest`: `fixtures/conftest.py`
# (the collect_ignore_glob shim) is also basenamed `conftest`, and on a full-suite run it is
# the one that wins the bare name -- so `import conftest` resolves to whichever pytest
# imported last, i.e. it works on a scoped run and fails on the full one.
_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_root_conftest", _ROOT / "conftest.py")
conftest = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(conftest)

FIXTURES = conftest._FIXTURES


def _rel(p) -> str:
    return p.relative_to(FIXTURES).as_posix()


def test_every_fixture_path_carries_its_deterministic_mode():
    """The pin actually landed, on every path, not just the ones someone remembered."""
    wrong = {
        _rel(p): (oct(p.stat().st_mode & 0o777), oct(conftest.expected_mode(p)))
        for p in conftest.iter_fixture_paths()
        if (p.stat().st_mode & 0o777) != conftest.expected_mode(p)
    }
    assert not wrong, (
        "fixture paths whose mode is not the deterministic one conftest.py pins "
        f"(got, want): {sorted(wrong.items())[:10]}"
    )


def test_no_fixture_path_is_group_or_world_writable():
    """The invariant in the form a reviewer can check by hand:

        find fixtures -perm -g+w   ->  nothing
        find fixtures -perm -o+w   ->  nothing

    Group-writability is what B20/B85 key on, and it is also what drags the RUNNING
    MACHINE's group database into the verdict: while anything here is group-writable,
    ``_group_has_other_members()`` decides between a MEDIUM WARN and the B-127 LOW
    downgrade from /etc/group, so the corpus would vary by machine even at a fixed umask.
    Every check's group/world-write branch is covered by tmp_path tests that set the mode
    explicitly (``tests/test_b20.py``, ``tests/test_b85_incident_readiness.py``,
    ``tests/test_new_checks.py``) -- the corpus does not need to be loose to exercise them.
    """
    loose = sorted(
        _rel(p) for p in conftest.iter_fixture_paths() if p.stat().st_mode & 0o022
    )
    assert not loose, (
        "fixture paths writable by group or world -- their B19/B20/B85 verdict is a "
        f"property of the checkout umask, not of the fixture: {loose[:10]}"
    )


def test_the_pinned_exception_table_has_no_stale_entries():
    """An exception is a claim that some test asserts a permission-derived outcome on
    that exact shipped path. A key that no longer exists is a claim about nothing."""
    missing = sorted(
        rel for rel in conftest._PINNED_FIXTURE_MODES if not (FIXTURES / rel).exists()
    )
    assert not missing, f"_PINNED_FIXTURE_MODES names paths that do not exist: {missing}"


def test_the_two_pinned_paths_keep_the_exact_modes_their_owning_tests_need():
    """Named, with the test that holds each one -- so a future edit to the table has to
    go and look at that test.

    * ``bad_b182_clawhub_token_store/.config/clawhub/config.json`` at 0644: the exposed
      token store IS the B182 finding. Held by ``tests/test_b182_clawhub_token_store.py::
      test_the_shipped_bad_fixture_demonstrates_the_finding_in_place``.
    * ``clean_b127_singleton_group_write/workspace/MEMORY.md`` at 0644: the value
      ``tests/test_b20.py::test_b20_clean_fixture_singleton_group_write_end_to_end``
      restores after chmod'ing it 0664 to drive B20's singleton branch. A pin that
      disagreed would make the corpus fingerprint depend on test ordering.
    """
    assert conftest._PINNED_FIXTURE_MODES == {
        "bad_b182_clawhub_token_store/.config/clawhub/config.json": 0o644,
        "clean_b127_singleton_group_write/workspace/MEMORY.md": 0o644,
    }


def test_the_pin_preserves_the_one_bit_git_records():
    """Owner-execute is the only permission bit in the git index, so clearing it would
    flip a fixture's tracked mode 100755 -> 100644 and leave the tree dirty after every
    test run. It is also the only bit a umask cannot plausibly clear, which is why the
    rule may safely read it back off disk."""
    dropped = sorted(
        _rel(p) for p in conftest.iter_fixture_paths()
        if p.is_file() and (p.stat().st_mode & 0o100)
        and not (conftest.expected_mode(p) & 0o100)
    )
    assert not dropped, f"the pin would clear a tracked executable bit on: {dropped}"
