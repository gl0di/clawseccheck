"""B-293 (DISK-2) — at-rest permissions on ~/.openclaw/state/openclaw.sqlite (B188).

The state database stores raw secrets at rest. Verified as real ``CREATE TABLE`` statements
in the installed dist's OPENCLAW_STATE_SCHEMA_SQL (openclaw-state-db-DzSsA9Ji.js):
``device_identities.private_key_pem``, ``device_auth_tokens.token``,
``device_bootstrap_tokens.token``, ``web_push_vapid_keys.private_key``,
``apns_registrations.token``, ``auth_profile_stores.store_json``.

Before B188 nothing stat'ed this file: B19 covers workspace memory/logs, bare *.log files
and F-120 transcripts/backups (``state/`` absent from every leg); B11 reads only
``ctx.config_mode``, i.e. openclaw.json's mode alone; B182 enumerates only ClawHub CLI token
stores. So a 0644 state DB under a 0755 home produced a clean permission report.

SCOPE: this is a conventional at-rest FILE-PERMISSION check. It never opens the database,
so it neither mines nor discloses any stored secret.
"""
from __future__ import annotations

import os
import sys

import pytest

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _ancestors_allow_other_access,
    _other_can_reach_write,
    check_state_db_atrest,
)
from clawseccheck.collector import Context

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="POSIX mode bits only; B188 returns UNKNOWN elsewhere"
)


@pytest.fixture
def reachable_ancestors(monkeypatch):
    """Neutralize the ancestor-chain gate so the IN-TREE permission logic can be exercised.

    B188 asserts an exposure only when BOTH halves hold: the modes inside ~/.openclaw expose
    the file, AND the directory chain above ~/.openclaw lets a non-owner traverse into it.
    Under pytest the second half is never satisfiable — tmp_path and both of its parents
    (/tmp/pytest-of-<user>/pytest-N/test_x0) are all created 0700 — so the real gate always
    answers False and would mask every in-tree assertion in this section.

    This fixture is scoped to the tests that are about the in-tree half. The gate itself is
    pinned unpatched, against a chain the test fully controls, by the
    ``_ancestors_allow_other_access`` block at the bottom; and
    ``test_parent_chain_seals_a_loose_tree`` asserts the real un-patched composition.
    """
    import clawseccheck.checks._egress as _egress
    monkeypatch.setattr(
        _egress, "_ancestors_allow_other_access", lambda home, stop=None: True
    )


def _home(tmp_path, *, home_mode=0o700, state_mode=0o700, db_mode=0o600,
          siblings=(), make_db=True):
    """Build a fake ~/.openclaw with a state DB at the given modes. Only under tmp_path."""
    home = tmp_path / "openclaw"
    home.mkdir(parents=True)
    if make_db:
        state = home / "state"
        state.mkdir()
        db = state / "openclaw.sqlite"
        # Deliberately NOT a real SQLite file: B188 must never open it, and this proves it.
        db.write_bytes(b"not-a-real-sqlite-file")
        os.chmod(db, db_mode)
        for name, mode in siblings:
            sib = state / name
            sib.write_bytes(b"x")
            os.chmod(sib, mode)
        os.chmod(state, state_mode)
    os.chmod(home, home_mode)
    return Context(home=home)


# --------------------------------------------------------------------------------------
# The FALSE-POSITIVE guard comes first — this is the whole design of the check.
# --------------------------------------------------------------------------------------

def test_loose_db_sealed_inside_a_tight_home_does_not_fire(tmp_path):
    """THE false-positive guard. A 0644 database under a 0700 home is the routine umask-022
    outcome and is NOT exploitable — no other user can traverse into the home to reach it.

    The naive design (a bare ``os.stat()`` mode test) WAS tried and empirically fires here:

        db=0644 sealed inside home=0700 -> naive mode check FIRES,
                                           path-aware _other_can_reach_read = False
        db=0644 inside home=0755        -> both fire (genuinely exposed)

    B188 therefore reuses ``_other_can_reach_read`` — the same path-aware helper F-120
    introduced to kill exactly this false WARN on session transcripts — rather than testing
    mode bits in isolation. Golden Rule #5.
    """
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o700, state_mode=0o700, db_mode=0o644))
    assert f.status == PASS


def test_real_box_chain_passes(tmp_path):
    """The reference chain on the real machine: 0700 home / 0700 state / 0600 db."""
    f = check_state_db_atrest(_home(tmp_path))
    assert f.status == PASS
    assert f.pass_confidence == "verified"


def test_group_writable_service_dir_alone_does_not_fail(tmp_path):
    """Group-writable/readable modes are normal on some distros' service dirs. Group bits
    count only when the owning group is KNOWN to have members beyond the owner (UPG-safe),
    so a user-private-group box must not FAIL. Under pytest the tmp dirs are owned by the
    user's own private group, which is exactly that case."""
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o770, state_mode=0o770, db_mode=0o660))
    assert f.status != FAIL


def test_c135_group_only_versus_world_readable_boundary(tmp_path, reachable_ancestors):
    """C-135 adversarial pass, pinned. The brief's warning — "group-writable is normal on
    some distros' service dirs" — is real, and the sweep did surface a FAIL on the umask-002
    shape 0775/0775/0664. That FAIL is CORRECT, not a false positive: 0664's *other* digit
    is 4, so the file is world-readable, and 0775 dirs are world-traversable — every local
    account can read the device private keys. The genuinely benign group-only shape is
    0770/0660, which has no world bits at all and correctly stays silent.

    This test pins both halves of that discriminator so a future "relax the permission
    check" change cannot quietly collapse them into one.

    C-135 outcome, CORRECTED. The original note here claimed "swept all 424 fixture homes
    plus the real ~/.openclaw (zero FAILs)" as evidence of cleanliness. That evidence was
    VACUOUS and the claim has been removed: re-running the sweep showed 423 of 423 fixture
    dirs returned UNKNOWN, because not one of them contained a state database at all, so
    every home exited at the "no state database found" branch before any permission logic
    ran. Zero FAILs from a code path that never executed proves nothing.

    What holds now: ``fixtures/clean_b188_state_db`` carries a real state DB (modes pinned in
    conftest.py, since git does not record them), so the corpus sweep genuinely reaches this
    check; the permission matrix below is exercised directly against controlled trees; and a
    second, independent C-135 pass found a real false positive that the sweep had missed —
    the parent chain above ~/.openclaw was never consulted, so a 0700 $HOME could not seal a
    loose tree. That is fixed and pinned by ``test_parent_chain_seals_a_loose_tree``.
    """
    # Group-only, user-private group: NOT reachable by anyone else -> must not FAIL.
    assert check_state_db_atrest(
        _home(tmp_path / "grouponly", home_mode=0o770, state_mode=0o770, db_mode=0o660)
    ).status != FAIL
    # World-readable: 0o664 grants read to *other*, not just group -> genuine exposure.
    assert check_state_db_atrest(
        _home(tmp_path / "worldread", home_mode=0o775, state_mode=0o775, db_mode=0o664)
    ).status == FAIL


# --------------------------------------------------------------------------------------
# The genuine exposures.
# --------------------------------------------------------------------------------------

def test_world_readable_db_in_a_traversable_home_fails(tmp_path, reachable_ancestors):
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o755, state_mode=0o755, db_mode=0o644))
    assert f.status == FAIL
    assert "openclaw.sqlite" in f.detail
    # The fix must tell the user that rotation is needed, not just chmod: a copy taken while
    # the file was readable stays valid.
    assert "rotate" in f.fix.lower()


def test_x_without_r_chain_fails(tmp_path, reachable_ancestors):
    """The case OpenClaw's own native audit never catches. Its ``fs.state_dir.perms_readable``
    fires on group/world-READABLE directories, so a 0711 home — traversable but not
    readable — keeps it silent, while a 0644 database at a known fixed filename is fully
    readable by any local user who simply types the path."""
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o711, state_mode=0o711, db_mode=0o644))
    assert f.status == FAIL


def test_exposed_wal_sibling_is_detected(tmp_path, reachable_ancestors):
    """The -wal holds recently written rows that have not been checkpointed into the main
    database yet, so a tight .sqlite with a loose -wal is still an exposure."""
    ctx = _home(tmp_path, home_mode=0o755, state_mode=0o755, db_mode=0o600,
                siblings=[("openclaw.sqlite-wal", 0o644)])
    f = check_state_db_atrest(ctx)
    assert f.status == FAIL
    assert any("openclaw.sqlite-wal" in e for e in f.evidence)
    assert not any(e.startswith("state/openclaw.sqlite ") for e in f.evidence)


def test_shm_sibling_is_covered_too(tmp_path, reachable_ancestors):
    ctx = _home(tmp_path, home_mode=0o755, state_mode=0o755, db_mode=0o600,
                siblings=[("openclaw.sqlite-shm", 0o644)])
    assert check_state_db_atrest(ctx).status == FAIL


def test_writable_state_dir_is_a_warn_not_a_fail(tmp_path, reachable_ancestors):
    """Swap vector, mirroring B182's ``swappable`` branch: the secrets stay unreadable, but
    another user can replace the database under the running agent."""
    ctx = _home(tmp_path, home_mode=0o755, state_mode=0o777, db_mode=0o600)
    f = check_state_db_atrest(ctx)
    assert f.status == WARN
    assert "replace the database" in f.detail


def test_readable_beats_writable_when_both_apply(tmp_path, reachable_ancestors):
    """A readable DB is the more severe finding and must win over the swap WARN."""
    ctx = _home(tmp_path, home_mode=0o755, state_mode=0o777, db_mode=0o644)
    assert check_state_db_atrest(ctx).status == FAIL


# --------------------------------------------------------------------------------------
# UNKNOWN paths.
# --------------------------------------------------------------------------------------

def test_unknown_when_no_state_db(tmp_path):
    f = check_state_db_atrest(_home(tmp_path, make_db=False))
    assert f.status == UNKNOWN
    assert "No state database found" in f.detail


def test_unknown_when_state_dir_exists_but_holds_no_db(tmp_path):
    home = tmp_path / "openclaw"
    (home / "state").mkdir(parents=True)
    assert check_state_db_atrest(Context(home=home)).status == UNKNOWN


def test_unknown_on_non_posix(tmp_path, monkeypatch):
    """NTFS ACLs make st_mode meaningless — UNKNOWN, never a false PASS."""
    import clawseccheck.checks._shared as _shared
    monkeypatch.setattr(_shared, "_is_posix", lambda: False)
    f = check_state_db_atrest(_home(tmp_path))
    assert f.status == UNKNOWN
    assert "NTFS ACL" in f.detail


# --------------------------------------------------------------------------------------
# Invariants.
# --------------------------------------------------------------------------------------

def test_symlinked_db_is_not_followed(tmp_path):
    """Symlink-safe, like every other collector/check read."""
    home = tmp_path / "openclaw"
    state = home / "state"
    state.mkdir(parents=True)
    real = tmp_path / "elsewhere.sqlite"
    real.write_bytes(b"x")
    os.chmod(real, 0o644)
    (state / "openclaw.sqlite").symlink_to(real)
    assert check_state_db_atrest(Context(home=home)).status == UNKNOWN


def test_check_never_opens_the_database(tmp_path, reachable_ancestors):
    """§8 / scope honesty: B188 is a stat()-only check. The fixture DB is deliberately not
    valid SQLite — if the check ever tried to open or parse it, every test here would error.
    Assert explicitly that the bytes are untouched and no content reaches the finding."""
    ctx = _home(tmp_path, home_mode=0o755, state_mode=0o755, db_mode=0o644)
    db = ctx.home / "state" / "openclaw.sqlite"
    before = db.read_bytes()
    f = check_state_db_atrest(ctx)
    assert db.read_bytes() == before
    blob = f.detail + f.fix + " ".join(f.evidence)
    assert "not-a-real-sqlite-file" not in blob


def test_b188_is_scored_and_high(tmp_path):
    meta = BY_ID["B188"]
    assert meta.scored is True
    assert meta.severity == "HIGH"


# --------------------------------------------------------------------------------------
# The parent chain above ~/.openclaw. Found by an independent C-135 pass, which reproduced
# a HIGH scored FAIL on a tree that no other user can reach.
# --------------------------------------------------------------------------------------

def test_parent_chain_seals_a_loose_tree(tmp_path):
    """THE regression test for the C-135 false positive. Deliberately NO ``reachable_
    ancestors`` fixture: this asserts the real, unpatched composition.

    The reported shape is $HOME at 0700 (the Fedora/RHEL/Arch default) with ~/.openclaw at
    0755, state/ at 0755 and openclaw.sqlite at 0644. B188 emitted FAIL "readable by other
    users", but 0700 on the parent denies o+x to every non-owner, so the database is
    unreachable and nothing is exposed. It reproduced identically at parent modes 700, 750
    and 755 — the parent mode had no effect on the verdict at all, which is the tell that
    the chain above ``home`` was never consulted.

    pytest's own tmp root supplies the sealed parent for free: tmp_path and both of its
    parents are created 0700, so the loose tree below is genuinely unreachable here.
    """
    ctx = _home(tmp_path, home_mode=0o755, state_mode=0o755, db_mode=0o644)
    f = check_state_db_atrest(ctx)
    assert f.status == PASS
    # ...and it must say WHY, rather than reading like a clean 0600 install.
    assert "denies access to other users" in f.detail
    assert "chmod 600" in f.fix  # still nudges toward fixing it at the source


def test_parent_mode_actually_changes_the_verdict(tmp_path, monkeypatch):
    """The other direction, and the one that proves the fix did not simply delete the
    detection: with the identical loose tree, an OPEN parent chain still FAILs. Only the
    ancestor gate differs between this test and the one above."""
    ctx = _home(tmp_path, home_mode=0o755, state_mode=0o755, db_mode=0o644)
    import clawseccheck.checks._egress as _egress
    monkeypatch.setattr(
        _egress, "_ancestors_allow_other_access", lambda home, stop=None: True
    )
    assert check_state_db_atrest(ctx).status == FAIL


def test_ancestor_gate_open_when_every_parent_is_world_traversable(tmp_path):
    chain = tmp_path / "a" / "b" / "openclaw"
    chain.mkdir(parents=True)
    os.chmod(tmp_path / "a" / "b", 0o755)
    os.chmod(tmp_path / "a", 0o755)
    assert _ancestors_allow_other_access(chain, stop=tmp_path) is True


def test_ancestor_gate_closed_by_a_single_0700_parent(tmp_path):
    """One untraversable link anywhere in the chain seals everything below it — this is the
    $HOME-at-0700 shape, with a world-traversable directory below it to prove that a single
    closed ancestor is enough."""
    chain = tmp_path / "a" / "b" / "openclaw"
    chain.mkdir(parents=True)
    os.chmod(tmp_path / "a" / "b", 0o755)
    os.chmod(tmp_path / "a", 0o700)
    assert _ancestors_allow_other_access(chain, stop=tmp_path) is False


def test_ancestor_gate_group_traversable_parent_is_not_assumed_shared(tmp_path):
    """A g+x parent counts only when the owning group is KNOWN to have members beyond the
    owner. Under pytest the tmp tree is owned by the user's own private group, so 0710 must
    NOT be treated as traversable — mirroring the UPG-safe rule the two reach helpers use."""
    chain = tmp_path / "a" / "openclaw"
    chain.mkdir(parents=True)
    os.chmod(tmp_path / "a", 0o710)
    assert _ancestors_allow_other_access(chain, stop=tmp_path) is False


def test_ancestor_gate_walks_to_the_real_root_in_production(tmp_path):
    """No ``stop`` is passed in production, so the walk runs past tmp_path to the filesystem
    root. pytest creates /tmp/pytest-of-<user> at 0700, so the real chain is sealed here —
    which is exactly why the in-tree tests above need the ``reachable_ancestors`` fixture."""
    home = tmp_path / "openclaw"
    home.mkdir()
    os.chmod(home, 0o755)
    assert _ancestors_allow_other_access(home) is False


def test_ancestor_gate_is_conservative_when_a_parent_cannot_be_stat_ed(tmp_path, monkeypatch):
    """Golden Rule #4: ignorance must not manufacture an exposure. If an ancestor cannot be
    stat'ed we cannot prove reachability, so the gate closes and B188 declines to FAIL."""
    home = tmp_path / "openclaw"
    home.mkdir()

    def _boom(self, *a, **k):
        raise OSError("no stat for you")

    monkeypatch.setattr("pathlib.Path.stat", _boom)
    assert _ancestors_allow_other_access(home, stop=None) is False


def test_other_can_reach_write_is_path_aware(tmp_path):
    """The write-bit twin of _other_can_reach_read shares its path-awareness: a
    world-writable directory sealed inside a 0700 home is unreachable, so not an exposure."""
    home = tmp_path / "h"
    inner = home / "state"
    inner.mkdir(parents=True)
    os.chmod(inner, 0o777)
    os.chmod(home, 0o700)
    assert _other_can_reach_write(home, inner) is False
    os.chmod(home, 0o755)
    assert _other_can_reach_write(home, inner) is True


def test_other_can_reach_write_rejects_paths_outside_home(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    os.chmod(outside, 0o777)
    home = tmp_path / "h"
    home.mkdir()
    assert _other_can_reach_write(home, outside) is False


@pytest.mark.skipif(sys.platform == "darwin", reason="mode semantics differ for this probe")
def test_unreadable_target_does_not_raise(tmp_path):
    """Never raises — a stat() failure must yield False, not crash the audit."""
    home = tmp_path / "h"
    home.mkdir()
    assert _other_can_reach_write(home, home / "gone" / "missing") is False
