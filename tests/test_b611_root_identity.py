"""B-611 — the "location-free" workspace identity was neither location-free nor stable.

`_root_identity` feeds `SkillOrigin.winner_root`, which reaches the drift baseline, the event
journal and any report a user pastes into an issue. `skillprovenance.py`'s own module docstring
states the doctrine: "the skill NAME goes into the snapshot and the on-disk location does not …
That holds for `winner_root` too."

Two ways the implementation contradicted it:

* it returned the **raw relative path** for any root under home, on the reasoning that those are
  "OpenClaw's own fixed directory names … they carry nothing personal". True of the three
  `WORKSPACE_DIRS` entries and of nothing else — a config-declared `~/.openclaw/client-acme-private`
  published its own name;
* it digested the **unresolved** string while `workspace_roots` de-duplicates on the resolved one,
  so one directory reached through a symlink had two identities. `_prov_comparable` keys its
  stand-down on this field, so an edit that changed nothing real manufactured the
  disclosed-but-blind state.

Offline, read-only, stdlib only; writes nothing outside ``tmp_path``.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from clawseccheck.monitor import _prov_comparable
from clawseccheck.skillprovenance import WORKSPACE_DIRS, _root_identity

_DIGEST = re.compile(r"^x[0-9a-f]{16}$")


def _home(tmp_path: Path) -> Path:
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True, exist_ok=True)
    return home


# ---------------------------------------------------------------------------
# Nothing moves for the shape every real machine has
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(WORKSPACE_DIRS))
def test_the_public_constants_keep_their_literal_identity(tmp_path, name):
    """The pin that keeps this change from moving a single existing baseline.

    These three names are public constants of this module and OpenClaw's own documented
    example layout; they carry nothing personal and must render exactly as before. Digesting
    them would change `winner_root` for essentially every user at once, and
    `_prov_comparable` keys its stand-down on that field.
    """
    home = _home(tmp_path)
    (home / name).mkdir()
    assert _root_identity(home, home / name) == name


# ---------------------------------------------------------------------------
# §8: no user-chosen path component may reach the snapshot
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dirname", [
    "client-acme-private", "employer-internal", "project-x", "workspace-personal",
])
def test_a_user_chosen_directory_name_is_digested_not_published(tmp_path, dirname):
    """Including `workspace-<agent id>`: an agent id is user-chosen too.

    B-610 made those derived roots real scan targets, so they reach this function now. The
    name of an agent is exactly the kind of thing that should not travel to an issue tracker
    with a drift report.
    """
    home = _home(tmp_path)
    (home / dirname).mkdir()

    ident = _root_identity(home, home / dirname)

    assert _DIGEST.match(ident), ident
    assert dirname not in ident
    # Only meaningful fragments: a one- or two-character part matches hex noise by chance
    # (`project-x` against the `x` prefix), and an assertion that fires on coincidence is one
    # people learn to weaken — which is how a real leak gets waved through later.
    for part in dirname.split("-"):
        if len(part) >= 3:
            assert part not in ident


def test_a_root_outside_home_is_digested_too(tmp_path):
    home = _home(tmp_path)
    outside = tmp_path / "somewhere-identifying"
    outside.mkdir()
    ident = _root_identity(home, outside)
    assert _DIGEST.match(ident), ident
    assert "identifying" not in ident


# ---------------------------------------------------------------------------
# One directory, one identity — as far as `resolve()` can tell
# ---------------------------------------------------------------------------
#
# `resolve()` follows symlinks and normalises `..`; it does not see through a bind mount, so
# one directory reached through two mount paths still gets two identities. Harmless here —
# the two records are identical, so `ambiguous` stays False and the comparison never reaches
# `winner_root` — but the heading should not claim more than the mechanism delivers.

def test_a_directory_and_a_symlink_to_it_share_one_identity(tmp_path):
    """`workspace_roots` de-duplicates on the resolved path and says why. This agrees now."""
    home = _home(tmp_path)
    real = tmp_path / "elsewhere"
    real.mkdir()
    link = tmp_path / "link-to-elsewhere"
    link.symlink_to(real)

    assert _root_identity(home, real) == _root_identity(home, link)


def test_a_symlink_to_a_public_workspace_resolves_to_its_literal_name(tmp_path):
    """A config workspace pointing at the default one is the default one, and says so."""
    home = _home(tmp_path)
    (home / "workspace").mkdir()
    link = home / "my-alias"
    link.symlink_to(home / "workspace")

    assert _root_identity(home, link) == "workspace"


def test_an_unresolvable_path_does_not_raise(tmp_path):
    """This runs inside a scheduled scan; a hostile or broken path must degrade, not crash."""
    home = _home(tmp_path)
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    for candidate in (loop, tmp_path / "never-existed", Path("\x00bad")):
        ident = _root_identity(home, candidate)
        assert isinstance(ident, str) and ident


# ---------------------------------------------------------------------------
# The migration cost, stated rather than discovered later
# ---------------------------------------------------------------------------

def test_the_identity_change_costs_one_disclosed_standdown_and_only_on_ambiguous_records():
    """Changing what `winner_root` contains moves it, and `_prov_comparable` reads it.

    The blast radius is bounded and worth pinning so nobody has to rediscover it: a record that
    is not ambiguous never reaches the `winner_root` comparison at all, and the three public
    names do not change. What remains is a single run's stand-down for an ambiguous record
    whose winner is a config-declared root — and a stand-down is disclosed by contract, never
    silent.
    """
    # And the cost of that stand-down is a MISSED alert, not a late one: the arm `continue`s
    # past all three alert branches, and the next run compares against a baseline that already
    # holds the new record. An independent pass measured the control — with the identity left
    # alone the same swap emits HIGH "The skill 'demo' was replaced with different content".
    old = {"ambiguous": True, "winner_root": "client-acme-private"}
    new = {"ambiguous": True, "winner_root": "x5c0175ba8e37d1ef"}
    assert _prov_comparable(old, new) is False

    plain_old = {"ambiguous": False, "winner_root": "client-acme-private"}
    plain_new = {"ambiguous": False, "winner_root": "x5c0175ba8e37d1ef"}
    assert _prov_comparable(plain_old, plain_new) is True

    ws = {"ambiguous": True, "winner_root": "workspace"}
    assert _prov_comparable(ws, dict(ws)) is True


# ---------------------------------------------------------------------------
# End to end: the name is absent from what actually gets stored
# ---------------------------------------------------------------------------

def test_the_directory_name_is_absent_from_the_whole_snapshot_dimension(tmp_path):
    """Asserted on the serialised dimension, not on the helper, because that is the thing
    that travels — into the baseline, the journal, and a pasted report."""
    import json

    from clawseccheck.skillprovenance import read_provenance

    home = _home(tmp_path)
    secret = "client-acme-private"
    root = home / secret / ".clawhub"
    root.mkdir(parents=True)
    (root / "lock.json").write_text(json.dumps({
        "version": 1,
        "skills": {"demo": {"version": "1.0.0", "installedAt": 1,
                            "artifact": {"sha256": "a" * 64},
                            "skillFile": {"sha256": "b" * 64}}},
    }), encoding="utf-8")

    cfg = {"agents": {"list": [{"id": "main"}, {"id": "x", "workspace": secret}]}}
    scan = read_provenance(home, cfg)

    assert "demo" in scan.skills, "fixture must actually be found, or this passes vacuously"
    blob = json.dumps(scan.as_dimension())
    assert secret not in blob
    assert "acme" not in blob
