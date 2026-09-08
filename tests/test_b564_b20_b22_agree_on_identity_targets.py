"""B-564: B22 must not assert "no writable identity/skill targets found" about a file
B20 just convicted in the same run.

B20 (`check_bootstrap_write_protection`) scans the hardcoded WORKSPACE_DIRS *plus* any
workspace the config declares (`collector._config_workspace_dirs`, the B-161 input) *plus*
the paths the agent attested. B22 (`check_self_modification`) reaches the filesystem
through `_writable_identity_files`, which was wired to the hardcoded names only. So a
world-writable SOUL.md living in a custom or attested location produced, in ONE report:

    B20  FAIL     ... world-writable ... : customws/SOUL.md (mode 666)
    B22  UNKNOWN  ... no group/world-writable identity/skill targets found ...

B22 is HIGH and scored, so the contradiction reached the grade, not just the text. B20's
own in-source comment had already stated the rule this violates -- "Using the same helper
keeps the two scans in sync" -- one check over.

The controls matter as much as the cases: a fix that made B22 fire more often would be a
false-positive engine, so a clean layout must still produce no finding, and the DEFAULT
workspace (which worked before this change) must be unaffected.

Offline, stdlib only; writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawseccheck import audit

# `tools.exec.mode` is what `_enabled_tools` reads to decide B22's condition (a); without
# it B22 short-circuits to "No fs_write/exec/elevated tools detected" and never reaches
# the filesystem at all -- i.e. the probe would never touch the branch under test.
_TOOLS = {"exec": {"mode": "auto"}}


def _write_home(tmp_path: Path, *, agents: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    cfg: dict = {"gateway": {"bind": "127.0.0.1"}, "tools": _TOOLS}
    if agents:
        cfg["agents"] = agents
    cfg_path = home / "openclaw.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(cfg_path, 0o600)
    return home


def _soul(d: Path, mode: int) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    f = d / "SOUL.md"
    f.write_text("# identity\n", encoding="utf-8")
    os.chmod(f, mode)
    return f


def _statuses(home: Path, attestation: dict | None = None) -> dict:
    _ctx, findings, _score = audit(str(home), attestation=attestation)
    return {f.id: f for f in findings if f.id in ("B20", "B22")}


@pytest.fixture
def restore_modes():
    """Leave nothing unreadable/odd behind for the next test if an assertion fails."""
    touched: list[Path] = []
    yield touched.append
    for p in touched:
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


def test_config_declared_workspace_is_visible_to_both_checks(tmp_path, restore_modes):
    """The wider half of the bug: no attestation involved, config alone reproduces it."""
    custom = tmp_path / "customws"
    home = _write_home(tmp_path, agents={"defaults": {"workspace": str(custom)}})
    restore_modes(_soul(custom, 0o666))

    got = _statuses(home)
    assert got["B20"].status == "FAIL", got["B20"].detail
    assert got["B22"].status != "UNKNOWN", (
        "B22 still reports no writable identity target for a file B20 just convicted: "
        f"{got['B22'].detail}"
    )
    assert "SOUL.md" in got["B22"].detail, got["B22"].detail


def test_attested_identity_file_is_visible_to_both_checks(tmp_path, restore_modes):
    """The reported half: --ask invites the agent to say where its identity files live."""
    hidden = tmp_path / "hidden"
    home = _write_home(tmp_path)
    soul = _soul(hidden, 0o666)
    restore_modes(soul)

    att = {"paths": {"bootstrap": [str(soul)]}}
    got = _statuses(home, attestation=att)
    assert got["B20"].status == "FAIL", got["B20"].detail
    assert got["B22"].status != "UNKNOWN", got["B22"].detail


def test_attested_path_never_renders_an_absolute_path(tmp_path, restore_modes):
    """§8: the attested path is supplied as an absolute path and carries the user's login
    name. B22 must label it by basename. Uses a synthetic home so the assertion cannot
    pass merely because the suite redirects HOME."""
    hidden = tmp_path / "hidden"
    home = _write_home(tmp_path)
    soul = _soul(hidden, 0o666)
    restore_modes(soul)

    got = _statuses(home, attestation={"paths": {"bootstrap": [str(soul)]}})
    # Non-vacuity: the branch really fired, so the absence below means redaction, not
    # that nothing was found.
    assert got["B22"].status != "UNKNOWN", got["B22"].detail
    assert str(hidden) not in got["B22"].detail, got["B22"].detail
    assert "SOUL.md [attested]" in got["B22"].detail, got["B22"].detail


def test_default_workspace_is_unchanged(tmp_path, restore_modes):
    """Control: the path that already worked before this change still works."""
    home = _write_home(tmp_path)
    restore_modes(_soul(home / "workspace", 0o666))

    got = _statuses(home)
    assert got["B20"].status == "FAIL", got["B20"].detail
    assert got["B22"].status != "UNKNOWN", got["B22"].detail


def test_clean_custom_workspace_fires_nothing(tmp_path):
    """Control against the opposite failure: widening B22's reach must not invent a
    finding. Same custom-workspace layout, tight modes."""
    custom = tmp_path / "customws"
    home = _write_home(tmp_path, agents={"defaults": {"workspace": str(custom)}})
    _soul(custom, 0o600)
    os.chmod(custom, 0o700)

    got = _statuses(home)
    assert got["B20"].status != "FAIL", got["B20"].detail
    assert "SOUL.md" not in got["B22"].detail, got["B22"].detail


def test_repeated_attested_paths_cannot_evict_other_evidence(tmp_path, restore_modes):
    """C-135 blocker: the rendered evidence is `"; ".join(writable[:6])`, so duplicate
    entries push real ones out of the report.

    `attestation.paths.bootstrap` is authored by the agent, so a prompt-injected one could
    list the same identity file many times and evict the world-writable skills dir and
    config -- the two most actionable items -- from a finding that still reads WARN. The
    verdict never changes, which is what makes it a suppression channel rather than a
    visible bug. A symlink, or attesting a file that already lives in a scanned workspace,
    reaches the same state with no adversary at all.
    """
    home = _write_home(tmp_path)
    soul = _soul(home / "workspace", 0o666)
    restore_modes(soul)
    skills = home / "skills"
    skills.mkdir()
    os.chmod(skills, 0o777)
    restore_modes(skills)
    cfg_path = home / "openclaw.json"
    os.chmod(cfg_path, 0o666)
    restore_modes(cfg_path)

    baseline = _statuses(home)["B22"].detail
    padded = _statuses(
        home, attestation={"paths": {"bootstrap": [str(soul)] * 8}}
    )["B22"].detail

    # Non-vacuity: the two items that would be evicted are present to begin with.
    assert "skills/" in baseline and "openclaw.json" in baseline, baseline
    assert "skills/" in padded, f"skills dir evicted by padded attestation: {padded}"
    assert "openclaw.json" in padded, f"config evicted by padded attestation: {padded}"
    assert baseline == padded, (
        "repeating one attested path changed the rendered evidence:\n"
        f"  baseline: {baseline}\n  padded:   {padded}"
    )


def test_attesting_a_file_already_in_a_scanned_workspace_names_it_once(tmp_path,
                                                                       restore_modes):
    """The no-adversary form of the same defect: the dir loop and the attested loop are
    two paths to one file, and it must be counted once."""
    home = _write_home(tmp_path)
    soul = _soul(home / "workspace", 0o666)
    restore_modes(soul)

    detail = _statuses(
        home, attestation={"paths": {"bootstrap": [str(soul)]}}
    )["B22"].detail
    assert detail.count("SOUL.md") == 1, detail
