"""B182 (B-259) — the ClawHub CLI's plaintext API-token store, and who can read it.

The CLI stores a long-lived API token in a plaintext JSON file at documented, fixed paths
OUTSIDE the OpenClaw home. C015 is rooted at the OpenClaw home, so it never reached this
file and nothing checked its permissions — yet the token can publish new versions of the
user's own skills. Anything able to read it (another agent, another skill, any local
account) gains a supply-chain pivot onto every install.

Grounding (Golden Rule #4), read out of the installed CLI (clawhub@0.22.0):
  * dist/config.js getGlobalConfigPath()/resolveConfigPath() — $CLAWHUB_CONFIG_PATH and
    $CLAWDHUB_CONFIG_PATH override everything; otherwise darwin uses
    `<home>/Library/Application Support/clawhub/config.json`, $XDG_CONFIG_HOME or
    %APPDATA% are used when set, and the default is `<home>/.config/clawhub/config.json`.
    Each has a legacy `clawdhub/` sibling that resolveConfigPath() falls back to.
  * dist/schema/schemas.js GlobalConfigSchema — `{registry: string, token?: string}`.
  * dist/config.js writeGlobalConfig() writes the file 0600 and re-chmods it on every
    write ("This protects API tokens from being read by other users"), so a looser mode is
    a real deviation rather than a default.

The token VALUE is never read into a message, logged, or placed in evidence — these tests
assert that too (§8). The fixture's token is an inert, clearly-labelled placeholder: it is
not secret-shaped, so secret scanners stay quiet.

Most permission-sensitive cases run against a COPY of the fixture inside pytest's tmp_path,
so the mode is set explicitly rather than inherited from the checkout umask, and nothing is
written into the repository. That isolation has a cost: it means the SHIPPED fixture could
stop demonstrating anything without a single test noticing, which is exactly what happened
(it fired only because a umask-002 checkout left it 0664). conftest.py now pins that one
file open, and `test_the_shipped_bad_fixture_demonstrates_the_finding_in_place` scans it
where it lives to hold the pin.

The env-override ladder ($CLAWHUB_CONFIG_PATH / $XDG_CONFIG_HOME / …) points at absolute
paths unrelated to the audited home, so the check consults it only when auditing this
process's own home. Tests that exercise the ladder opt in with `_own_home`; the rest prove
the auditor's environment cannot steer a scan of someone else's home.
"""
from __future__ import annotations

import json

import shutil
from pathlib import Path

import pytest

from clawseccheck.catalog import CATALOG, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _b182_candidate_stores,
    check_clawhub_token_store,
)
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CLEAN = FIXTURES / "clean_b182_clawhub_token_store"
BAD = FIXTURES / "bad_b182_clawhub_token_store"

# The value in the bad fixture. Kept here only so the tests can prove it never escapes
# into a finding; it is an inert placeholder, not a credential.
_FIXTURE_PLACEHOLDER = "fixture-placeholder-not-a-real-token"


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch):
    """Clear the CLI's env overrides so a real value in the developer's environment cannot
    steer a test at a real file.

    Defence in depth only. The check itself now ignores these variables unless it is
    auditing this process's own home, so scrubbing them here is no longer what makes the
    suite hermetic — it just keeps each test's starting state explicit. The tests that
    exercise the override ladder opt back in via `_own_home`."""
    for var in (
        "CLAWHUB_CONFIG_PATH",
        "CLAWDHUB_CONFIG_PATH",
        "XDG_CONFIG_HOME",
        "APPDATA",
    ):
        monkeypatch.delenv(var, raising=False)


def _ctx(user_home):
    """ctx.home is the OpenClaw home, so its parent is the user's home — the same idiom
    B150 uses to reach ~/.config."""
    return Context(home=Path(user_home) / ".openclaw")


def _copy(fixture, tmp_path, mode=0o600) -> Path:
    home = tmp_path / "home"
    shutil.copytree(fixture, home)
    store = home / ".config" / "clawhub" / "config.json"
    store.chmod(mode)
    store.parent.chmod(0o700)
    return home


# ---------------------------------------------------------------------------
# The two required fixtures
# ---------------------------------------------------------------------------


def test_pass_when_the_store_holds_no_token():
    f = check_clawhub_token_store(_ctx(CLEAN))
    assert f.id == "B182"
    assert f.status == PASS
    assert "no API token" in f.detail


def test_fail_when_a_stored_token_is_readable_by_others(tmp_path):
    home = _copy(BAD, tmp_path, mode=0o644)
    f = check_clawhub_token_store(_ctx(home))
    assert f.id == "B182"
    assert f.status == FAIL
    assert any("644" in e for e in f.evidence)


def test_the_same_token_at_0600_is_a_pass(tmp_path):
    """Permissions are the discriminator, not the mere presence of a token — otherwise
    every logged-in ClawHub user would carry a permanent finding (Golden Rule #5)."""
    home = _copy(BAD, tmp_path, mode=0o600)
    f = check_clawhub_token_store(_ctx(home))
    assert f.status == PASS
    assert "owner" in f.detail


# ---------------------------------------------------------------------------
# §8 — the token value must never surface
# ---------------------------------------------------------------------------


def test_the_token_value_never_reaches_the_finding(tmp_path):
    for mode in (0o644, 0o600, 0o604):
        home = _copy(BAD, tmp_path / f"m{mode}", mode=mode)
        f = check_clawhub_token_store(_ctx(home))
        blob = " ".join([f.detail, f.fix, *f.evidence])
        assert _FIXTURE_PLACEHOLDER not in blob, mode
        # Not even a prefix of it — the value is never bound to a reported string.
        assert "fixture-placeholder" not in blob, mode


def test_world_readable_but_not_group_readable_still_fails(tmp_path):
    home = _copy(BAD, tmp_path, mode=0o604)
    assert check_clawhub_token_store(_ctx(home)).status == FAIL


# ---------------------------------------------------------------------------
# UNKNOWN paths — an absent store is never a FAIL (and never a fake PASS)
# ---------------------------------------------------------------------------


def test_unknown_when_no_store_exists_anywhere(tmp_path):
    (tmp_path / ".openclaw").mkdir()
    f = check_clawhub_token_store(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert "No ClawHub CLI token store was found" in f.detail


def test_unknown_when_the_store_is_unparseable(tmp_path):
    home = _copy(CLEAN, tmp_path)
    (home / ".config" / "clawhub" / "config.json").write_text("{not json", encoding="utf-8")
    f = check_clawhub_token_store(_ctx(home))
    assert f.status == UNKNOWN
    assert any("could not be read or parsed" in e for e in f.evidence)


def test_unknown_when_the_store_is_not_a_json_object(tmp_path):
    home = _copy(CLEAN, tmp_path)
    (home / ".config" / "clawhub" / "config.json").write_text("[1, 2]", encoding="utf-8")
    assert check_clawhub_token_store(_ctx(home)).status == UNKNOWN


def test_an_empty_token_string_is_not_a_stored_token(tmp_path):
    home = _copy(BAD, tmp_path, mode=0o644)
    store = home / ".config" / "clawhub" / "config.json"
    store.write_text(json.dumps({"registry": "https://clawhub.ai", "token": "   "}),
                     encoding="utf-8")
    store.chmod(0o644)
    assert check_clawhub_token_store(_ctx(home)).status == PASS


# ---------------------------------------------------------------------------
# Directory-level exposure
# ---------------------------------------------------------------------------


def test_warn_when_the_directory_is_writable_by_others(tmp_path):
    """Owner-only file, but the file can be swapped out from under the CLI."""
    home = _copy(BAD, tmp_path, mode=0o600)
    (home / ".config" / "clawhub").chmod(0o777)
    try:
        f = check_clawhub_token_store(_ctx(home))
        assert f.status == WARN
        assert any("writable by others" in e for e in f.evidence)
    finally:
        (home / ".config" / "clawhub").chmod(0o700)


def test_an_exposed_file_outranks_a_writable_directory(tmp_path):
    home = _copy(BAD, tmp_path, mode=0o644)
    (home / ".config" / "clawhub").chmod(0o777)
    try:
        assert check_clawhub_token_store(_ctx(home)).status == FAIL
    finally:
        (home / ".config" / "clawhub").chmod(0o700)


# ---------------------------------------------------------------------------
# Path resolution — every documented location, both directory names
# ---------------------------------------------------------------------------


def test_legacy_clawdhub_directory_is_checked(tmp_path):
    """resolveConfigPath() falls back to the legacy `clawdhub/` name, so both must be
    covered (Golden Rule #6 — no hardcoding one variant)."""
    home = _copy(BAD, tmp_path, mode=0o644)
    (home / ".config" / "clawhub").rename(home / ".config" / "clawdhub")
    assert check_clawhub_token_store(_ctx(home)).status == FAIL


def test_macos_application_support_location_is_checked(tmp_path):
    home = _copy(BAD, tmp_path, mode=0o644)
    dest = home / "Library" / "Application Support" / "clawhub"
    dest.parent.mkdir(parents=True)
    (home / ".config" / "clawhub").rename(dest)
    assert check_clawhub_token_store(_ctx(home)).status == FAIL


def _own_home(monkeypatch, home):
    """Make the audited home look like the one THIS process belongs to.

    The env overrides describe where this user's CLI keeps its token, so the check only
    consults them when auditing this user's own home — see
    `test_env_overrides_are_ignored_when_auditing_someone_elses_home` for why.
    """
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path(home)))


def test_xdg_config_home_override_is_honoured_for_this_users_own_home(tmp_path, monkeypatch):
    home = _copy(BAD, tmp_path, mode=0o644)
    xdg = tmp_path / "xdg"
    (home / ".config").rename(xdg)
    _own_home(monkeypatch, home)
    assert check_clawhub_token_store(_ctx(home)).status == UNKNOWN
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    assert check_clawhub_token_store(_ctx(home)).status == FAIL


def test_explicit_config_path_override_is_honoured_for_this_users_own_home(tmp_path, monkeypatch):
    home = _copy(BAD, tmp_path, mode=0o644)
    moved = tmp_path / "elsewhere.json"
    shutil.move(str(home / ".config" / "clawhub" / "config.json"), str(moved))
    moved.chmod(0o644)
    _own_home(monkeypatch, home)
    assert check_clawhub_token_store(_ctx(home)).status == UNKNOWN
    monkeypatch.setenv("CLAWHUB_CONFIG_PATH", str(moved))
    assert check_clawhub_token_store(_ctx(home)).status == FAIL


@pytest.mark.parametrize(
    "var",
    ["XDG_CONFIG_HOME", "APPDATA", "CLAWHUB_CONFIG_PATH", "CLAWDHUB_CONFIG_PATH"],
)
def test_env_overrides_are_ignored_when_auditing_someone_elses_home(tmp_path, monkeypatch, var):
    """A `--home`/fixture scan must not be steered by the AUDITOR's own environment.

    Regression guard. The env vars hold absolute paths with no relationship to the audited
    home, so honouring them unconditionally attributed the auditor's own token store to
    whatever home was being scanned: a world-readable store anywhere on the box turned
    every clean fixture into a B182 FAIL (Golden Rule #5), and even a correctly-locked one
    silently flipped clean fixtures from UNKNOWN to PASS.
    """
    # A world-readable token store somewhere else entirely — the auditor's own.
    elsewhere = tmp_path / "auditor" / "clawhub"
    elsewhere.mkdir(parents=True)
    store = elsewhere / "config.json"
    store.write_text(json.dumps({"registry": "https://clawhub.ai", "token": "x" * 20}))
    store.chmod(0o644)

    audited = _copy(CLEAN, tmp_path, mode=0o600)  # a different, benign home
    monkeypatch.setenv(var, str(store if var.endswith("PATH") else elsewhere.parent))

    finding = check_clawhub_token_store(_ctx(audited))
    assert finding.status != FAIL, f"${var} steered the audit of an unrelated home"
    assert str(tmp_path / "auditor") not in finding.detail
    assert all(str(tmp_path / "auditor") not in str(p) for p in _b182_candidate_stores(_ctx(audited)))


def test_candidate_list_is_deduplicated_and_home_derived(tmp_path):
    stores = _b182_candidate_stores(_ctx(tmp_path))
    assert stores == list(dict.fromkeys(stores)), "duplicate candidate paths"
    assert all(str(s).startswith(str(tmp_path)) for s in stores), (
        "candidates must come from ctx.home.parent, not the process's real HOME"
    )
    names = {s.parent.name for s in stores}
    assert names == {"clawhub", "clawdhub"}


def test_a_nonexistent_candidate_cannot_manufacture_a_finding(tmp_path):
    """Widening the candidate set is safe precisely because a missing path contributes
    nothing — the check must not read or report anything for one."""
    (tmp_path / ".openclaw").mkdir()
    for store in _b182_candidate_stores(_ctx(tmp_path)):
        assert not store.exists()
    assert check_clawhub_token_store(_ctx(tmp_path)).status == UNKNOWN


# ---------------------------------------------------------------------------
# Platform + metadata
# ---------------------------------------------------------------------------


def test_no_mode_based_finding_on_a_non_posix_platform(tmp_path, monkeypatch):
    """Windows uses NTFS ACLs, so st_mode is meaningless there and must never produce a
    permission FAIL."""
    from clawseccheck.checks import _shared

    home = _copy(BAD, tmp_path, mode=0o644)
    ctx = _ctx(home)
    monkeypatch.setattr(_shared, "_is_posix", lambda: False)
    f = check_clawhub_token_store(ctx)
    assert f.status == UNKNOWN
    assert any("not meaningful on this platform" in e for e in f.evidence)


def test_meta_is_scored_secrets():
    m = next(c for c in CATALOG if c.id == "B182")
    assert m.scored is True
    assert m.surface == "secrets"
    assert m.confidence == "HIGH"


def test_the_shipped_bad_fixture_demonstrates_the_finding_in_place():
    """The bad fixture is scanned WHERE IT SHIPS, not as a chmod'd tmp_path copy.

    Every other permission case copies the fixture and sets the mode explicitly, so all of
    them passed even when the shipped file did not actually demonstrate anything: its mode
    was inherited from the checkout umask (0664 on a umask-002 box), and under `umask 077`
    it checked out 0600 and the audit returned PASS. conftest.py now pins it open the same
    way it pins openclaw.json shut, and this test is what holds that pin in place.
    """
    finding = check_clawhub_token_store(_ctx(BAD))
    assert finding.status == FAIL, (
        "the shipped bad fixture no longer demonstrates B182 — check conftest.py's "
        "_LOOSE_FIXTURE_FILES pin"
    )
    assert _FIXTURE_PLACEHOLDER not in finding.detail
    assert all(_FIXTURE_PLACEHOLDER not in e for e in finding.evidence)


def test_the_shipped_clean_fixture_passes_in_place():
    assert check_clawhub_token_store(_ctx(CLEAN)).status == PASS
