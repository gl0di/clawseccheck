"""Fixture permission pinning, shared by the pytest session (``conftest.py``'s autouse
``_deterministic_fixture_perms`` fixture) and by any standalone tool that must audit the
fixture corpus OUTSIDE pytest.

WHY THIS IS ITS OWN MODULE, NOT INLINE IN ``conftest.py`` (B-842). ``tests/
test_finding_fingerprint_manifest.py --write`` runs the real ``audit()`` over the whole
fixture corpus -- exactly like the pytest guard whose manifest it regenerates -- but it
runs OUTSIDE pytest, so ``conftest.py``'s autouse fixture never fires for it. Six checks
read raw filesystem permission bits (B1, B11, B19, B20, B85, B188), so the corpus must
carry the exact modes below before EITHER path fingerprints it, or the two disagree. That
is precisely what happened: a fresh git worktree checks out fixture files at 0644 and
directories at 0755 (git records no permission bit but owner-execute), so a ``--write``
run there fingerprinted those raw checkout modes -- and the pytest run right after, which
DOES pin them, then rejected 608 of 757 rows as "changed".

Importing this module by its own name (never ``import conftest``) is deliberate: this
tree has two ``conftest.py`` files (this one's owner and ``fixtures/conftest.py``), and
the bare name ``conftest`` resolves to whichever one pytest imported last on a full-suite
run (see ``tests/test_fixture_perm_determinism.py``'s own comment on the same trap, which
is why IT loads the root conftest by file path instead of importing it). A leaf module
whose name collides with nothing -- the same pattern ``tests/_realhome.py`` already uses
-- can be imported by its own name both from ``conftest.py`` (which inserts ``tests/``
onto ``sys.path`` before importing ``_realhome``, and now this) and from a standalone
script run as ``python3 tests/test_finding_fingerprint_manifest.py`` (whose own directory,
``tests/``, Python puts on ``sys.path[0]`` automatically).

============================================================================================
FIXTURE PERMISSIONS ARE PINNED CORPUS-WIDE, NOT PATH BY PATH.

git records exactly ONE permission bit -- the owner-execute bit. Every other mode bit on
a checked-out fixture is decided by the umask of whoever (or whatever) checked it out.
That turns three checks -- B19 (data at rest), B20 (bootstrap write protection) and B85
(trajectory tamper-resistance) -- into readers of a property of the MACHINE rather than of
the fixture:

    umask 002 (a typical dev box)   -> 0775 dirs / 0664 files -> their group-write
                                       branches fire
    umask 022 (a GitHub runner)     -> 0755 dirs / 0644 files -> they do not
    fresh `git worktree` checkout   -> 0755 dirs / 0644 files -> ditto (B-842)

Same commit, different findings, different ``Finding.detail``, different
``baseline.fingerprint()``. This class of defect had already been patched three times, one
path at a time (B182, B188, and the three B-309 follow-ups) and grew straight back,
because the bug is not in those paths: it is that ANY unpinned fixture path inherits the
ambient umask (or checkout mechanism). So the rule is corpus-wide:

    every directory  ->  0700
    every file       ->  0600     (0700 when git records it executable -- see below)

Consequence, and the point of the exercise: a fixture's audit verdict is a function of its
CONTENT alone. No finding anywhere in the corpus is permission-derived unless a fixture
explicitly asks for that in ``_PINNED_FIXTURE_MODES``. ``tests/
test_fixture_perm_determinism.py`` enforces it, so patch number five cannot be a one-path
patch, and this module's ``pin_fixture_modes()`` is the ONLY place that applies it, so a
sixth call site (a new standalone tool) cannot silently reintroduce a seventh one-path
patch by duplicating the logic instead of calling this.

WHY THE EXECUTABLE BIT IS PRESERVED RATHER THAN FLATTENED TO 0600: owner-execute is the
one bit git DOES track. Clearing it on a tracked-executable fixture would flip its index
mode 100755 -> 100644, so every run would leave the working tree dirty. Deriving the
replacement mode from the bit already on disk is safe for the same reason it is necessary:
umask can only ever CLEAR bits, and no plausible umask (or checkout mechanism) clears
owner-execute, so this bit -- unlike every other -- means the same thing on every machine.

WHY TIGHT (0700/0600) RATHER THAN A LOOSER DEFAULT: tight is the mode a real OpenClaw home
should have, it is what the pre-existing pins (openclaw.json, B188's state DB, the three
B-309 log dirs) already chose, and it is the only choice that leaves NO permission-derived
finding in the corpus for a future umask (or checkout mechanism) to flip.
============================================================================================
"""
from __future__ import annotations

from pathlib import Path

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_EXEC_FILE_MODE = 0o700


# The exceptions: fixtures whose POINT is a specific mode, so the corpus-wide rule above
# would silently disarm them. Keep this list SHORT -- an entry here is a claim that some
# test asserts a permission-derived outcome on this exact shipped path, and
# ``test_fixture_perm_determinism.py`` fails on a stale entry.
#
# Note what is NOT here, because the names invite the mistake:
# ``bad_b283_group_allowall``, ``bad_risk21_group_proven_exec``,
# ``clean_risk21_group_allowlisted``, ``clean_risk21_group_low_blast`` and
# ``traj_channel_group_ingress`` are all about a CHAT-channel group policy / a
# ``telegram:group:`` session-key origin -- not about POSIX groups -- and
# ``bad_b86_import_from_writable`` is a static-AST finding about a writable sys.path
# entry, which never stat()s anything. None of them needs a loose mode; the group-write
# findings they used to emit here were pure umask noise (and were already absent on CI).
_PINNED_FIXTURE_MODES = {
    # B182 -- LOOSE ON PURPOSE. The ClawHub CLI token store this fixture exposes to other
    # local users IS the finding, so under the corpus-wide 0600 the bad fixture would
    # stop being bad and B182 would return PASS.
    # ``tests/test_b182_clawhub_token_store.py::
    #   test_the_shipped_bad_fixture_demonstrates_the_finding_in_place`` holds this pin.
    "bad_b182_clawhub_token_store/.config/clawhub/config.json": 0o644,

    # B-127 -- an ORDINARY pin now, and the history is worth keeping because the coupling
    # it used to describe was a real hazard.
    #
    # ``tests/test_b20.py::test_b20_clean_fixture_singleton_group_write_end_to_end`` used
    # to be the only test that chmod'd a SHIPPED fixture at runtime -- 0664 to drive B20's
    # singleton group-write branch through the real collect() path, restored to 0644 in a
    # ``finally``. So this pin had to AGREE with that restore value, or the file's mode --
    # and therefore the whole corpus fingerprint -- depended on whether test_b20 had
    # already run, i.e. on test selection and ordering.
    #
    # Isolated 2026-09-03: that test now copies the fixture into ``tmp_path`` and chmods
    # the COPY, so nothing mutates the corpus in place and this value stands on its own.
    # The ordering dependency is gone, and with it a race that a parallel runner would
    # have made non-deterministic rather than merely order-dependent: a ``finally``
    # restores within one process, but cannot hold a shared file steady while another
    # worker walks the corpus for the fingerprint manifest.
    #
    # Verified by measurement, not by reading: the corpus mode-fingerprint is byte-equal
    # before and after running test_b20, test_b182 and the fingerprint manifest together
    # (729 tests), and no test anywhere still chmods a path rooted at ``fixtures/``.
    "clean_b127_singleton_group_write/workspace/MEMORY.md": 0o644,
}

# Superseded by the corpus-wide rule, recorded so the history is not lost: openclaw.json
# (pinned 0600 since the first at-rest check), ``clean_b188_state_db/state`` + its
# ``openclaw.sqlite`` (0700/0600, so the corpus actually EXERCISES B188 instead of exiting
# at its "no state database found" branch), and the three B-309 C-135 follow-ups
# ``clean_i025_b164_{residual,own_api_log,host_mention_no_verb}_no_cap/logs`` + their
# ``app.log`` (0700/0600, to keep an unrelated umask-dependent B19 WARN out of the score
# comparison against ``clean_i025_b164_baseline``). All five now get exactly those modes
# from the default, so they need no entry -- which is the whole point.


def expected_mode(path: Path) -> int:
    """The deterministic mode *path* must carry, by the rule documented above.

    Shared by every reader of this module -- the pytest fixture, ``tests/
    test_fixture_perm_determinism.py``'s guard, and ``tests/
    test_finding_fingerprint_manifest.py``'s standalone ``--write`` path -- so the pin
    and its guards can never drift apart: they are the same function.
    """
    rel = path.relative_to(_FIXTURES).as_posix()
    pinned = _PINNED_FIXTURE_MODES.get(rel)
    if pinned is not None:
        return pinned
    if path.is_dir():
        return _DIR_MODE
    return _EXEC_FILE_MODE if (path.stat().st_mode & 0o100) else _FILE_MODE


def iter_fixture_paths():
    """Every real fixture path, deepest-last. Symlinks are skipped: ``Path.chmod()``
    follows them, so chmod'ing one would change the mode of its target rather than of the
    link, and a link that ever points outside ``fixtures/`` would reach out of the corpus.

    There ARE symlinks now -- B-747 added two (the editable-checkout-beside-a-wheel pair),
    where the symlink is not incidental but the whole subject of the fixture. Both point
    inside their own home, and ``tests/test_b746_b747_corpus_fixtures.py`` asserts that
    property so a future one cannot quietly point elsewhere. Skipping them stays correct
    either way, and costs nothing: ``rglob`` does not descend into a symlinked directory,
    so each target is still visited by its own real path and still gets its mode pinned.
    """
    for p in sorted(_FIXTURES.rglob("*")):
        if p.is_symlink():
            continue
        if p.is_dir() or p.is_file():
            yield p


def pin_fixture_modes() -> None:
    """Chmod the whole fixture corpus to its deterministic modes (see ``expected_mode()``
    above). The ONE place this logic lives (B-842): call this before fingerprinting the
    corpus from ANY entry point, pytest or standalone, rather than duplicating the chmod
    loop -- a duplicate is exactly how the standalone ``--write`` path drifted from what
    pytest's own autouse fixture pins in the first place.
    """
    _FIXTURES.chmod(_DIR_MODE)
    for p in iter_fixture_paths():
        p.chmod(expected_mode(p))
