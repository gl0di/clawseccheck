"""B-1111 - B188 also stats the client credential store OpenClaw 2026.11.5 introduced.

On 2026.11.5 the device identity (``device_identities.private_key_pem``) and the device auth
tokens moved out of ``state/openclaw.sqlite`` into ``<stateDir>/client/credentials.sqlite``
(``resolveClientCredentialStorePath``, client-credential-paths-*.mjs). Before this change no
at-rest permission check looked at that file. Same rules as the state-DB leg: path-aware
reachability (a 0644 file under a 0700 directory must not fire), the ancestor gate above
~/.openclaw, and the database is never opened.
"""
from __future__ import annotations

import os

import pytest

from clawseccheck import pathprobe
from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import check_state_db_atrest
from clawseccheck.collector import Context

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits only")


@pytest.fixture
def reachable_ancestors(monkeypatch):
    """Open the gate above ~/.openclaw (tmp_path's parents are 0700 under pytest)."""
    import clawseccheck.checks._egress as _egress
    monkeypatch.setattr(_egress, "_ancestors_allow_other_access", lambda home, stop=None: True)


def _home(tmp_path, *, home_mode=0o700, client_mode=0o700, store_mode=0o600,
          client_files=("credentials.sqlite",), state_db_mode=None):
    home = tmp_path / "openclaw"
    home.mkdir(parents=True)
    if state_db_mode is not None:
        state = home / "state"
        state.mkdir()
        db = state / "openclaw.sqlite"
        db.write_bytes(b"not-a-real-sqlite-file")
        os.chmod(db, state_db_mode)
        os.chmod(state, 0o755 if state_db_mode & 0o004 else 0o700)
    if client_files:
        client = home / "client"
        client.mkdir()
        for name in client_files:
            f = client / name
            # Not a real SQLite file: B188 must never open it.
            f.write_bytes(b"not-a-real-sqlite-file")
            os.chmod(f, store_mode)
        os.chmod(client, client_mode)
    os.chmod(home, home_mode)
    return Context(home=home)


def test_world_readable_store_in_a_traversable_chain_fails(tmp_path, reachable_ancestors):
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o755, client_mode=0o755,
                                    store_mode=0o644))
    assert f.status == FAIL
    assert any(e.startswith("client/credentials.sqlite (mode 644)") for e in f.evidence)
    assert "device private key" in f.detail
    assert "~/.openclaw/client/credentials.sqlite*" in f.fix
    assert "~/.openclaw/client" in f.fix


def test_umask_022_store_under_a_0700_client_dir_passes(tmp_path, reachable_ancestors):
    # C-135: the routine umask-022 file inside the 0700 directory OpenClaw creates.
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o755, client_mode=0o700,
                                    store_mode=0o644))
    assert f.status == PASS


def test_umask_022_tree_under_a_0700_home_passes(tmp_path, reachable_ancestors):
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o700, client_mode=0o755,
                                    store_mode=0o644))
    assert f.status == PASS


def test_loose_store_sealed_by_the_real_ancestor_gate_passes_with_seal_wording(tmp_path):
    # No gate patch: tmp_path's own parents are 0700, which seals everything below.
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o755, client_mode=0o755,
                                    store_mode=0o644))
    assert f.status == PASS
    assert "denies access to other users" in f.detail
    assert "client/credentials.sqlite" in f.detail


def test_store_alone_without_a_state_db_is_assessed_not_unknown(tmp_path):
    f = check_state_db_atrest(_home(tmp_path))
    assert f.status == PASS
    assert "client/credentials.sqlite" in f.detail


def test_neither_store_present_stays_unknown(tmp_path):
    f = check_state_db_atrest(_home(tmp_path, client_files=()))
    assert f.status == UNKNOWN


@pytest.mark.parametrize("sibling", [
    "credentials.sqlite-journal", "credentials.sqlite-wal", "credentials.sqlite-shm",
])
def test_exposed_sibling_fails(tmp_path, reachable_ancestors, sibling):
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o755, client_mode=0o755,
                                    store_mode=0o644, client_files=(sibling,)))
    assert f.status == FAIL
    assert any(e.startswith(f"client/{sibling} ") for e in f.evidence)


def test_symlinked_store_is_not_followed(tmp_path):
    home = tmp_path / "openclaw"
    (home / "client").mkdir(parents=True)
    target = tmp_path / "elsewhere.sqlite"
    target.write_bytes(b"x")
    (home / "client" / "credentials.sqlite").symlink_to(target)
    assert check_state_db_atrest(Context(home=home)).status == UNKNOWN


def test_both_stores_exposed_names_both(tmp_path, reachable_ancestors):
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o755, client_mode=0o755,
                                    store_mode=0o644, state_db_mode=0o644))
    assert f.status == FAIL
    assert {e.split(" ")[0] for e in f.evidence} == {
        "state/openclaw.sqlite", "client/credentials.sqlite"
    }
    assert "the client credential store" in f.detail and "the state database" in f.detail
    assert f.fix.index("state/openclaw.sqlite*") < f.fix.index("client/credentials.sqlite*")


def test_state_only_fail_wording_is_build_honest(tmp_path, reachable_ancestors):
    # On 2026.11.5 the state DB no longer holds VAPID keys or the device key; the wording
    # must not claim it does unconditionally.
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o755, client_files=(),
                                    state_db_mode=0o644))
    assert f.status == FAIL
    assert "VAPID" not in f.detail
    assert "before 2026.11.5" in f.detail
    assert "client/credentials.sqlite" not in f.fix


def test_a_tight_store_beside_an_exposed_state_db_does_not_appear_as_evidence(
    tmp_path, reachable_ancestors
):
    f = check_state_db_atrest(_home(tmp_path, home_mode=0o755, client_mode=0o700,
                                    store_mode=0o600, state_db_mode=0o644))
    assert f.status == FAIL
    assert all(not e.startswith("client/") for e in f.evidence)


def _unsearchable_client(monkeypatch):
    real = pathprobe.is_file

    def fake(p):
        if p.parent.name == "client":
            raise PermissionError(13, "Permission denied", str(p))
        return real(p)
    monkeypatch.setattr(pathprobe, "is_file", fake)


def test_unsearchable_reachable_client_dir_is_unknown(tmp_path, reachable_ancestors, monkeypatch):
    ctx = _home(tmp_path, home_mode=0o755, client_mode=0o755, state_db_mode=0o600)
    _unsearchable_client(monkeypatch)
    f = check_state_db_atrest(ctx)
    assert f.status == UNKNOWN
    assert "client/credentials.sqlite" in f.detail


def test_unsearchable_client_dir_sealed_from_others_still_passes(
    tmp_path, reachable_ancestors, monkeypatch
):
    ctx = _home(tmp_path, home_mode=0o755, client_mode=0o700, state_db_mode=0o600)
    _unsearchable_client(monkeypatch)
    assert check_state_db_atrest(ctx).status == PASS


def _unsearchable_state(monkeypatch):
    real = pathprobe.is_file

    def fake(p):
        if p.parent.name == "state":
            raise PermissionError(13, "Permission denied", str(p))
        return real(p)
    monkeypatch.setattr(pathprobe, "is_file", fake)


def test_unsearchable_reachable_state_dir_is_unknown_even_with_a_client_store(
    tmp_path, reachable_ancestors, monkeypatch
):
    # C-135 F1: the client store's presence must not turn an unlooked state DB into a PASS.
    ctx = _home(tmp_path, home_mode=0o755, state_db_mode=0o604)  # state/ -> 0755
    _unsearchable_state(monkeypatch)
    f = check_state_db_atrest(ctx)
    assert f.status == UNKNOWN
    assert "state/openclaw.sqlite" in f.detail


def test_unsearchable_state_dir_sealed_from_others_still_passes(
    tmp_path, reachable_ancestors, monkeypatch
):
    ctx = _home(tmp_path, home_mode=0o755, state_db_mode=0o600)  # state/ -> 0700
    _unsearchable_state(monkeypatch)
    assert check_state_db_atrest(ctx).status == PASS


def test_device_key_impersonation_sentence_is_build_honest(
    tmp_path, reachable_ancestors
):
    state_only = check_state_db_atrest(_home(tmp_path / "a", home_mode=0o755, client_files=(),
                                             state_db_mode=0o644))
    assert "with the device private key, impersonate" not in state_only.detail
    assert "on OpenClaw before 2026.11.5, where this file still held" in state_only.detail
    client = check_state_db_atrest(_home(tmp_path / "b", home_mode=0o755, client_mode=0o755,
                                         store_mode=0o644))
    assert "with the device private key, impersonate a paired device" in client.detail
