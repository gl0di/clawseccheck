import os
import sys
from pathlib import Path

import pytest

# make the skill package importable when running pytest from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parent))
# ...and the test-support modules (tests/_realhome.py). Explicit rather than relying on
# pytest's own basedir insertion, so `conftest` itself can import it below.
sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))

_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# B-519: the maintainer's ACTUAL home, captured before ``_isolate_local_store`` below
# redirects $HOME. Defined in tests/_realhome.py -- NOT here -- because this tree has two
# conftest files and the bare name ``conftest`` resolves to fixtures/conftest.py on a
# full-suite run. Re-exported for readability at the fixture's use site.
from _realhome import REAL_HOME  # noqa: E402  (must follow the sys.path insert above)

# B-842: the fixture mode-pinning logic itself (constants, `expected_mode()`,
# `iter_fixture_paths()`, `pin_fixture_modes()`) lives in tests/_fixtureperms.py, not
# here -- so the standalone `tests/test_finding_fingerprint_manifest.py --write` path
# (which runs OUTSIDE pytest and therefore never sees the autouse fixture below) can
# import and call the exact same pinning code instead of duplicating it.
# `tests/test_fixture_perm_determinism.py` asserts the pin directly against
# `_fixtureperms` too (not through this module) -- see its own docstring.
from _fixtureperms import pin_fixture_modes  # noqa: E402  (must follow the sys.path insert above)


# ==========================================================================================
# FIXTURE PERMISSIONS ARE PINNED CORPUS-WIDE, NOT PATH BY PATH.
#
# git records exactly ONE permission bit -- the owner-execute bit. Every other mode bit on
# a checked-out fixture is decided by the umask (or checkout mechanism) of whoever checked
# it out. That turns three checks -- B19 (data at rest), B20 (bootstrap write protection)
# and B85 (trajectory tamper-resistance) -- into readers of a property of the MACHINE
# rather than of the fixture:
#
#     umask 002 (a typical dev box)   -> 0775 dirs / 0664 files -> their group-write
#                                        branches fire
#     umask 022 (a GitHub runner)     -> 0755 dirs / 0644 files -> they do not
#     fresh `git worktree` checkout   -> 0755 dirs / 0644 files -> ditto (B-842)
#
# Same commit, different findings, different ``Finding.detail``, different
# ``baseline.fingerprint()``. That is not hypothetical: it is exactly how a fully green
# local run shipped a red CI on ``tests/test_finding_fingerprint_manifest.py`` -- 95 of the
# 496 fixture homes disagreed between the two umasks (65 on B20, 34 on B19, 26 on B85), and
# later how a fresh worktree's checkout modes made a hand-run ``--write`` regeneration
# there disagree with this very fixture on 608 of 757 rows (B-842). The same variance also
# reached ``_group_has_other_members()``: while anything in the corpus is group-writable,
# B20/B85 additionally consult the RUNNING MACHINE's group database to decide between a
# MEDIUM WARN and the B-127 LOW downgrade, so the corpus depended on /etc/group too.
#
# This class of defect had already been patched four times, one path (or one entry point)
# at a time (B182, B188, the three B-309 follow-ups, B-842) and grew straight back, because
# the bug is not in those paths: it is that ANY unpinned fixture path, fingerprinted from
# ANY entry point, inherits the ambient umask or checkout mechanism. So the rule is
# corpus-wide, applied by ONE function (``tests/_fixtureperms.pin_fixture_modes()``, so a
# new entry point calls it rather than re-deriving the chmod loop) -- and the exception
# table there is the small part:
#
#     every directory  ->  0700
#     every file       ->  0600     (0700 when git records it executable)
#
# Consequence, and the point of the exercise: a fixture's audit verdict is a function of
# its CONTENT alone. No finding anywhere in the corpus is permission-derived unless a
# fixture explicitly asks for that in ``tests/_fixtureperms._PINNED_FIXTURE_MODES``.
# ``tests/test_fixture_perm_determinism.py`` enforces it, so patch number five cannot be a
# one-path patch.
#
# The mode values, the exception table, ``expected_mode()`` and ``iter_fixture_paths()``
# all live in ``tests/_fixtureperms.py`` now (imported above), not here -- see that
# module's docstring for why (B-842: the standalone ``tests/
# test_finding_fingerprint_manifest.py --write`` path must pin the exact same modes this
# fixture does, and can only do that by calling the same function).
# ==========================================================================================


@pytest.fixture(scope="session", autouse=True)
def _deterministic_fixture_perms():
    """Pin fixture perms corpus-wide so at-rest permission checks are deterministic
    regardless of the umask (or checkout mechanism) at checkout time. Delegates to
    ``tests/_fixtureperms.pin_fixture_modes()`` -- see that module for why this must be
    the only place the chmod loop is written."""
    pin_fixture_modes()
    yield


@pytest.fixture(autouse=True)
def _stub_deptree_scan(monkeypatch):
    """Keep B349's dependency-tree walk off the real machine across the suite.

    The CLI enables the walk by default, so without this every CLI end-to-end test
    traversed this box's actual global npm install: measured at ~2.4s per invocation,
    which turned four `test_b351_full_save` tests from ~0.11s into ~2.5s each and the
    whole suite from ~340s into ~1350s. Worse than slow, it is the same hermeticity
    break `_stub_host_detect` below exists to prevent — a test reading real machine
    state it never set up.

    Every audit()/CLI run therefore sees no tree, and B349 reports UNKNOWN (never a
    clean PASS over something unexamined). Tests that exercise the walk build their own
    ctx.dep_tree from a fixture tree (tests/test_f167_deptree_hooks.py) and are
    unaffected by this stub.
    """
    import clawseccheck
    monkeypatch.setattr(clawseccheck, "_deptree_scan", lambda root=None: None)


@pytest.fixture(autouse=True)
def _stub_host_detect(monkeypatch):
    """Keep host-monitor detection deterministic and offline across the suite.

    Every audit()/CLI run sees an 'unsupported' host, so the B50–B54 host-posture
    checks report UNKNOWN and never touch the score on the CI/dev machine (whose
    real host monitors are nondeterministic). Tests that exercise host detection
    call clawseccheck.hostwatch.detect() directly (with a fake root), or re-patch
    clawseccheck._host_detect themselves, and are unaffected by this stub.
    """
    import clawseccheck
    monkeypatch.setattr(
        clawseccheck, "_host_detect",
        lambda root="/", **_: {"system": "test", "supported": False, "classes": {}},
    )


@pytest.fixture(scope="session", autouse=True)
def _isolate_local_store(tmp_path_factory):
    """B-519: point $HOME at a throwaway directory so the suite cannot write into the
    maintainer's real ``~/.clawseccheck/`` store.

    It had been writing there since the store existed. Measured before this fixture:
    4,414 of the 4,547 rows in the real ``history.jsonl`` -- 97%, and 937 KB -- came from
    test runs, leaving 132 genuine audits buried in suite noise. ``--trend`` reads that
    file, so the user's own security history was mostly our exhaust.

    F-128's ``source="test"`` tag (history.py ``_run_source``) is what made this survive
    so long: it marks the rows filterable, which reads like containment but is not. The
    row is still appended, still hashed into the chain, still there for anything that
    does not filter.

    WHY $HOME AND NOT THE SIX ``DEFAULT_*`` CONSTANTS. Six modules name a store path
    (history/ledger/monitor x2/prescan/update), but ``record(score, path=DEFAULT_HISTORY)``
    binds its default AT DEF TIME, so ``monkeypatch.setattr(history, "DEFAULT_HISTORY", ...)``
    never reaches the already-bound value. The bound value is the *string*
    ``"~/.clawseccheck/history.jsonl"``, expanded by ``expanduser()`` at write time -- so
    redirecting $HOME does catch it, and catches every store path at once, including any
    added later. Same reasoning as the corpus-wide permission pin above: this class of
    defect regrows when patched one path at a time.

    WHY THIS IS NOT A BLANKET SANDBOX. Eight tests deliberately read this machine
    (real-fleet SKILL.md globs, the recorded fleet-FP baseline, the installed OpenClaw
    dist, the real ``~/.openclaw``, and two "no machine-specific path may leak" assertions).
    A naive redirect makes four of them skip and two of them assert against a /tmp path --
    i.e. it would fix the writes by silently disabling the guards, which is the exact
    failure this project keeps finding elsewhere. Those tests use ``REAL_HOME`` above.
    """
    fake_home = tmp_path_factory.mktemp("isolated-home")
    # REAL_HOME is captured at import, before this runs; if they ever coincide the
    # redirect is not redirecting and every write below lands in the user's store.
    assert fake_home != REAL_HOME, f"isolation is a no-op: {fake_home}"
    saved = {name: os.environ.get(name) for name in ("HOME", "USERPROFILE")}
    for name in saved:
        os.environ[name] = str(fake_home)
    try:
        yield fake_home
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
