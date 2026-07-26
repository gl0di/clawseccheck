import sys
from pathlib import Path

import pytest

# make the skill package importable when running pytest from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parent))

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ==========================================================================================
# FIXTURE PERMISSIONS ARE PINNED CORPUS-WIDE, NOT PATH BY PATH.
#
# git records exactly ONE permission bit -- the owner-execute bit. Every other mode bit on
# a checked-out fixture is decided by the umask of whoever checked it out. That turns three
# checks -- B19 (data at rest), B20 (bootstrap write protection) and B85 (trajectory
# tamper-resistance) -- into readers of a property of the MACHINE rather than of the
# fixture:
#
#     umask 002 (a typical dev box)   -> 0775 dirs / 0664 files -> their group-write
#                                        branches fire
#     umask 022 (a GitHub runner)     -> 0755 dirs / 0644 files -> they do not
#
# Same commit, different findings, different ``Finding.detail``, different
# ``baseline.fingerprint()``. That is not hypothetical: it is exactly how a fully green
# local run shipped a red CI on ``tests/test_finding_fingerprint_manifest.py`` -- 95 of the
# 496 fixture homes disagreed between the two umasks (65 on B20, 34 on B19, 26 on B85).
# The same variance also reached ``_group_has_other_members()``: while anything in the
# corpus is group-writable, B20/B85 additionally consult the RUNNING MACHINE's group
# database to decide between a MEDIUM WARN and the B-127 LOW downgrade, so the corpus
# depended on /etc/group too.
#
# This class of defect had already been patched three times, one path at a time (B182,
# B188, and the three B-309 follow-ups) and grew straight back, because the bug is not in
# those paths: it is that ANY unpinned fixture path inherits the ambient umask. So the rule
# is corpus-wide now, and the exception table below is the small part:
#
#     every directory  ->  0700
#     every file       ->  0600     (0700 when git records it executable -- see below)
#
# Consequence, and the point of the exercise: a fixture's audit verdict is a function of
# its CONTENT alone. No finding anywhere in the corpus is permission-derived unless a
# fixture explicitly asks for that in ``_PINNED_FIXTURE_MODES``. ``tests/
# test_fixture_perm_determinism.py`` enforces it, so patch number five cannot be a
# one-path patch.
#
# WHY THE EXECUTABLE BIT IS PRESERVED RATHER THAN FLATTENED TO 0600: owner-execute is the
# one bit git DOES track. Clearing it on a tracked-executable fixture would flip its index
# mode 100755 -> 100644, so every test run would leave the working tree dirty. Deriving the
# replacement mode from the bit already on disk is safe for the same reason it is
# necessary: umask can only ever CLEAR bits, and no plausible umask clears owner-execute,
# so this bit -- unlike every other -- means the same thing on every machine.
#
# WHY TIGHT (0700/0600) RATHER THAN THE RUNNER'S 0755/0644: tight is the mode a real
# OpenClaw home should have, it is what the pre-existing pins (openclaw.json, B188's state
# DB, the three B-309 log dirs) already chose, and it is the only choice that leaves NO
# permission-derived finding in the corpus for a future umask to flip. Under 0755/0644 the
# B19 "group/world-readable at rest" branch still fires on 34 homes purely as an artifact
# of the checkout, which is noise in every score comparison those fixtures take part in.
# ==========================================================================================

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

    # B-127 -- pinned to the value ``tests/test_b20.py::
    # test_b20_clean_fixture_singleton_group_write_end_to_end`` restores. That test is the
    # only one that chmods a SHIPPED fixture at runtime: it sets 0664 to drive B20's
    # singleton group-write branch through the real collect() path, then restores exactly
    # 0644 in a ``finally``. If the session-start pin disagreed with that restore value,
    # this file's mode -- and therefore the whole corpus fingerprint -- would depend on
    # whether test_b20 had already run, i.e. on test selection and ordering.
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

    Shared with ``tests/test_fixture_perm_determinism.py`` so the pin and its guard can
    never drift apart -- they are the same function.
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
    follows them, so chmod'ing one would reach outside the corpus (there are none today,
    and this keeps it that way)."""
    for p in sorted(_FIXTURES.rglob("*")):
        if p.is_symlink():
            continue
        if p.is_dir() or p.is_file():
            yield p


@pytest.fixture(scope="session", autouse=True)
def _deterministic_fixture_perms():
    """Pin fixture perms corpus-wide so at-rest permission checks are deterministic
    regardless of the umask at checkout time."""
    _FIXTURES.chmod(_DIR_MODE)
    for p in iter_fixture_paths():
        p.chmod(expected_mode(p))
    yield


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
