"""C-700: C015 must look at the high-value roots (workspace/, credentials/, identity/, devices/,
root-level config/env files) BEFORE the bulk trees, so a large alphabetically-early bulk tree
(agents/, npm/, sandboxes/, logs/) cannot spend the whole walk budget first. Measured on a real
home: 500 files scanned, 0 of them under workspace/, which held a plaintext password note.
The total scanned-file bound is unchanged; when a top-level directory was not reached the
finding names it in `fix` (never in `detail`, which a fingerprint hashes).

Round 3 (reviewer): the priority pass has a sub-budget, but a sub-cap that trips while the
total budget is mostly unspent must not drop a file the baseline scanned (the priority roots
are topped up from the unspent budget), and `capped` is reported only when the whole budget
was really spent. A pass that fills its cap exactly lost nothing, so the disclosure names a
directory only when files were really left behind in it or it was never reached.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _C015_MAX_SCAN_FILES,
    _c015_candidate_files,
    _config,
    check_secrets_at_rest_home,
)
from clawseccheck.collector import Context


def _ctx(home: Path) -> Context:
    ctx = Context(home=home)
    ctx.config = {}
    return ctx


def _secret() -> str:
    # assembled at runtime: no contiguous secret-shaped literal lives in the repo
    return "ghp" + "_" + "B" * 36


def _bulk(dirpath: Path, count: int, ext: str = ".md", prefix: str = "file") -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (dirpath / f"{prefix}{i:05d}{ext}").write_text("nothing here\n", encoding="utf-8")


def _note_with_secret(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("- Password: " + _secret() + "\n", encoding="utf-8")


def _walk(home: Path):
    capped: list = []
    unreached: list = []
    files = _c015_candidate_files(_ctx(home), capped, [], [], unreached)
    return files, capped, unreached


@pytest.fixture
def small_caps(monkeypatch):
    """Total budget 20, priority sub-budget 5: the same logic at a size a test can enumerate."""
    monkeypatch.setattr(_config, "_C015_MAX_SCAN_FILES", 20)
    monkeypatch.setattr(_config, "_C015_PRIORITY_MAX_FILES", 5)


# --------------------------------------------------------------------------- bad: it fires


def test_workspace_secret_is_found_when_an_early_bulk_tree_exceeds_the_budget(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents" / "main", _C015_MAX_SCAN_FILES + 100)
    _note_with_secret(tmp_path / "workspace" / "PASSWORDS.md")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    assert any("workspace/PASSWORDS.md" in item for item in f.evidence)
    assert _secret() not in f.detail and all(_secret() not in e for e in f.evidence)


def test_credentials_identity_and_devices_are_scanned_before_the_bulk_trees(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents" / "main", _C015_MAX_SCAN_FILES + 100)
    _note_with_secret(tmp_path / "credentials" / "token.json")
    _note_with_secret(tmp_path / "identity" / "device.json")
    _note_with_secret(tmp_path / "devices" / "paired.json")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    joined = "\n".join(f.evidence)
    assert "credentials/token.json" in joined
    assert "identity/device.json" in joined
    assert "devices/paired.json" in joined


def test_per_agent_workspace_dirs_are_priority_roots_too(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents" / "main", _C015_MAX_SCAN_FILES + 100)
    _note_with_secret(tmp_path / "workspace-work-laptop" / "notes.md")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    assert any("workspace-work-laptop/notes.md" in item for item in f.evidence)


def test_a_bulk_secret_is_still_found_and_a_priority_secret_is_listed_once(tmp_path):
    (tmp_path / ".env").write_text("API_TOKEN=" + _secret() + "\n", encoding="utf-8")
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _note_with_secret(tmp_path / "agents" / "main" / "auth.json")
    _note_with_secret(tmp_path / "workspace" / "PASSWORDS.md")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    joined = "\n".join(f.evidence)
    assert "agents/main/auth.json" in joined
    assert "workspace/PASSWORDS.md" in joined
    # a root file belongs to the priority pass only: it must not be scanned twice
    assert sum(1 for e in f.evidence if e.startswith(".env:")) == 1


# --------------------------------------------------------------------------- clean: no finding


def test_clean_workspace_with_an_over_budget_bulk_tree_is_not_a_warn(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents" / "main", _C015_MAX_SCAN_FILES + 100)
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace" / "notes.md").write_text("just notes\n", encoding="utf-8")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    # the bulk tree genuinely outran its budget: UNKNOWN (coverage gap), never PASS, never WARN
    assert f.status == UNKNOWN
    assert f.evidence == [] or not any("secret-like" in e for e in f.evidence)


def test_small_clean_home_with_a_workspace_still_passes(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents" / "main", 40)
    _bulk(tmp_path / "workspace", 40)

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == PASS
    assert "Scanned 81 home file(s)" in f.detail
    assert "walk cap" not in f.detail


def test_installed_skill_dirs_do_not_spend_the_priority_budget(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "workspace" / "skills" / "vendored", _C015_MAX_SCAN_FILES + 100)
    _note_with_secret(tmp_path / "workspace" / "PASSWORDS.md")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    assert "walk cap" not in f.detail
    assert any("workspace/PASSWORDS.md" in item for item in f.evidence)


# ------------------------------------------- round 3: the sub-cap must not drop what baseline scanned


def test_a_priority_secret_past_the_sub_cap_is_found_while_the_total_budget_is_unspent(tmp_path):
    """Reviewer repro: 400 notes under workspace/memory with the secret in the 350th, plus 20
    files under agents/. The baseline scanned all of it (WARN, one evidence file); the first
    two-pass cut stopped the priority pass at its 300-file sub-cap and reported UNKNOWN with
    320 files scanned out of a 500-file budget."""
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    memory = tmp_path / "workspace" / "memory"
    _bulk(memory, 400, prefix="note")
    _note_with_secret(memory / "note00349.md")  # the 350th file in walk order
    _bulk(tmp_path / "agents" / "main", 20)

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    assert len(f.evidence) == 1 and "workspace/memory/note00349.md" in f.evidence[0]
    assert "walk cap" not in f.detail
    assert "Not fully covered" not in f.fix


def test_a_sub_cap_that_tripped_with_budget_to_spare_is_not_reported_as_the_walk_cap(tmp_path):
    """~372 files: the priority tree holds 350 (over its 300 sub-budget), agents/ 20. Everything
    fits in the 500-file budget, so the scan is complete: PASS, nothing capped, nothing named."""
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("just notes\n", encoding="utf-8")
    _bulk(tmp_path / "workspace" / "memory", 350)
    _bulk(tmp_path / "agents" / "main", 20)

    files, capped, unreached = _walk(tmp_path)
    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert len(files) == 372 and not capped and not unreached
    assert f.status == PASS
    assert "Scanned 372 home file(s)" in f.detail
    assert "walk cap" not in f.detail and "Not fully covered" not in f.fix


# --------------------------------------------------------------------------- bound + disclosure


def test_total_scanned_file_bound_is_unchanged(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents" / "main", _C015_MAX_SCAN_FILES + 100)
    _bulk(tmp_path / "workspace", _C015_MAX_SCAN_FILES + 100)

    capped: list = []
    files = _c015_candidate_files(_ctx(tmp_path), capped, [], [])

    tops = [p.relative_to(tmp_path).parts[0] for p in files]
    assert capped
    assert len(files) == _C015_MAX_SCAN_FILES
    # the priority pass has its own sub-budget: it cannot take the bulk trees' whole share ...
    assert "agents" in tops
    # ... and the bulk trees cannot take the priority roots' share either
    assert "workspace" in tops


def test_bulk_cap_names_the_unreached_top_level_dirs_in_fix_not_detail(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents" / "main", _C015_MAX_SCAN_FILES + 100)
    _bulk(tmp_path / "npm", 5)
    _bulk(tmp_path / "sandboxes", 5)
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace" / "notes.md").write_text("just notes\n", encoding="utf-8")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == UNKNOWN
    # `detail` keeps its existing wording (a fingerprint hashes it)
    assert f"{_C015_MAX_SCAN_FILES}-file walk cap" in f.detail
    assert "npm" not in f.detail and "agents" not in f.detail
    # `fix` names what was not (fully) reached, and does not claim workspace/ was missed
    assert "agents/" in f.fix and "npm/" in f.fix and "sandboxes/" in f.fix
    assert "workspace/" not in f.fix
    assert "credentials/, identity/, devices/, and workspace/ content not covered" not in f.fix


def test_priority_pass_cap_names_workspace_and_leaves_the_bulk_share_intact(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "workspace", _C015_MAX_SCAN_FILES)  # more than the whole priority share
    _note_with_secret(tmp_path / "agents" / "main" / "auth.json")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    assert any("agents/main/auth.json" in item for item in f.evidence)
    assert "workspace/" in f.fix


def test_warn_with_a_cap_also_names_the_unreached_dirs_in_fix(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents" / "main", _C015_MAX_SCAN_FILES + 100)
    _bulk(tmp_path / "zzz_last", 3)
    _note_with_secret(tmp_path / "workspace" / "PASSWORDS.md")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    assert "walk cap" in f.detail
    assert "zzz_last/" in f.fix
    assert "agents/" in f.fix


# ----------------------------------- round 3: the disclosure names only what really lost files


def test_a_pass_that_fills_its_cap_exactly_does_not_name_the_dir_that_lost_nothing(
    tmp_path, small_caps
):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents", 19)  # exactly the bulk share (20 - 1 root file)
    _bulk(tmp_path / "npm", 3)

    files, capped, unreached = _walk(tmp_path)

    assert capped and len(files) == 20
    assert unreached == ["npm/"]


def test_a_bulk_pass_that_exactly_fills_its_cap_with_nothing_behind_it_is_not_capped(
    tmp_path, small_caps
):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents", 19)

    files, capped, unreached = _walk(tmp_path)

    assert len(files) == 20 and not capped and not unreached


def test_a_priority_pass_that_exactly_fills_its_cap_with_nothing_behind_it_is_not_capped(
    tmp_path, small_caps
):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "workspace", 4)  # 1 root file + 4 = exactly the priority sub-budget
    _bulk(tmp_path / "agents", 3)

    files, capped, unreached = _walk(tmp_path)

    assert len(files) == 8 and not capped and not unreached


def test_topup_scans_the_whole_priority_tree_when_the_bulk_pass_left_budget_unspent(
    tmp_path, small_caps
):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "workspace", 12)  # over the 5-file sub-budget
    _bulk(tmp_path / "agents", 3)

    files, capped, unreached = _walk(tmp_path)

    assert len(files) == 16 and not capped and not unreached


def test_topup_never_exceeds_the_total_budget_and_names_the_priority_dir_it_cut(
    tmp_path, small_caps
):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "workspace", 30)
    _bulk(tmp_path / "agents", 3)

    files, capped, unreached = _walk(tmp_path)

    tops = [p.relative_to(tmp_path).parts[0] for p in files]
    assert capped and len(files) == 20  # 1 root + 16 workspace + 3 agents
    assert tops.count("agents") == 3 and tops.count("workspace") == 16
    assert unreached == ["workspace/"]


def test_a_home_root_files_cap_names_the_root_files_and_the_priority_dirs_ahead(
    tmp_path, small_caps
):
    _bulk(tmp_path, 25, prefix="r")  # 25 root-level .md files
    _bulk(tmp_path / "workspace", 2)
    _bulk(tmp_path / "agents", 2)

    files, capped, unreached = _walk(tmp_path)

    assert capped and len(files) == 20
    assert unreached == ["(home root files)", "workspace/"]


def test_top_level_names_that_sort_oddly_are_named_in_walk_order(tmp_path, small_caps):
    """Uppercase and dot names sort before lowercase, a non-ASCII name sorts after 'z', and
    'workspace-x' (a priority root) must not be confused with 'workspace2' (an ordinary dir
    that only shares the prefix and sorts after 'workspace-x')."""
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / ".hid", 5)
    _bulk(tmp_path / "Alpha", 8)
    _bulk(tmp_path / "agents", 4)  # .hid + Alpha + agents = the whole 17-file bulk share
    _bulk(tmp_path / "workspace-x", 2)  # priority root
    _bulk(tmp_path / "workspace2", 1)  # not a priority root
    _bulk(tmp_path / "zz-ünï", 3)
    _bulk(tmp_path / "ünï", 2)

    files, capped, unreached = _walk(tmp_path)

    tops = [p.relative_to(tmp_path).parts[0] for p in files]
    # 1 root file + 2 under workspace-x (priority) + the 17-file bulk share
    assert capped and len(files) == 20
    assert "workspace-x" in tops and "workspace2" not in tops
    assert unreached == ["workspace2/", "zz-ünï/", "ünï/"]


def test_a_symlinked_top_level_dir_is_never_followed_and_never_named(tmp_path, small_caps):
    """Unchanged from the baseline walk (symlinks are not followed): the link's target is not
    scanned, and the link is not listed as a directory the walk 'did not reach'."""
    outside = tmp_path / "outside"
    _bulk(outside, 5)
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(home / "agents", 19)
    _bulk(home / "npm", 3)
    os.symlink(outside, home / "zlink", target_is_directory=True)

    files, capped, unreached = _walk(home)

    assert capped
    assert all(outside not in p.parents for p in files)
    assert unreached == ["npm/"]


def test_an_entry_that_cannot_be_classified_is_named_not_dropped_and_does_not_crash(
    tmp_path, small_caps, monkeypatch
):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "agents", 19)
    _bulk(tmp_path / "npm", 3)
    (tmp_path / "zbad").mkdir()
    real_is_dir = _config.pathprobe.is_dir

    def flaky_is_dir(p):
        if Path(p).name == "zbad":
            raise PermissionError(13, "Permission denied", str(p))
        return real_is_dir(p)

    monkeypatch.setattr(_config.pathprobe, "is_dir", flaky_is_dir)

    files, capped, unreached = _walk(tmp_path)

    assert capped and len(files) == 20
    assert unreached == ["npm/", "zbad/"]


# ------------------- round 4: the priority roots have an explicit importance order of their own


def test_a_big_backups_tree_does_not_starve_credentials_and_workspace(tmp_path):
    """Reviewer repro: inside the priority pass the roots were walked alphabetically
    (.config-backups, backups, credentials, ..., workspace), so 600 small backup files used the
    whole priority share and the two secrets below were never read. Importance order is: root
    files, credentials, identity, devices, workspace[-*]; then backups; then the bulk trees."""
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "backups", 600, ext=".json")
    _note_with_secret(tmp_path / "credentials" / "token.json")
    _note_with_secret(tmp_path / "workspace" / "PASSWORDS.md")

    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert f.status == WARN
    joined = "\n".join(f.evidence)
    assert "credentials/token.json" in joined and "workspace/PASSWORDS.md" in joined
    assert f"{_C015_MAX_SCAN_FILES}-file walk cap" in f.detail
    assert "backups/" in f.fix
    assert "credentials/" not in f.fix and "workspace/" not in f.fix


def test_a_small_backups_tree_changes_nothing(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "backups", 30, ext=".json")
    _note_with_secret(tmp_path / "credentials" / "token.json")
    _note_with_secret(tmp_path / "workspace" / "PASSWORDS.md")

    files, capped, unreached = _walk(tmp_path)
    f = check_secrets_at_rest_home(_ctx(tmp_path))

    assert len(files) == 33 and not capped and not unreached
    assert f.status == WARN and len(f.evidence) == 2
    assert "walk cap" not in f.detail and "Not fully covered" not in f.fix


def test_a_big_backups_tree_cannot_take_the_bulk_trees_share_either(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "backups", 600, ext=".json")
    _bulk(tmp_path / "agents" / "main", 400)

    files, capped, unreached = _walk(tmp_path)

    tops = [p.relative_to(tmp_path).parts[0] for p in files]
    assert capped and len(files) == _C015_MAX_SCAN_FILES
    assert tops.count("agents") == 400  # the bulk trees were read in full
    assert unreached == ["backups/"]


def test_unreached_dirs_are_named_in_importance_order(tmp_path, small_caps, monkeypatch):
    """Total budget 20, first group 5, backups group 3. Walk order would put .config-backups and
    backups before workspace; the disclosure lists the groups most important first."""
    monkeypatch.setattr(_config, "_C015_BACKUP_MAX_FILES", 3, raising=False)
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _bulk(tmp_path / "workspace", 30)
    _bulk(tmp_path / ".config-backups", 10)
    _bulk(tmp_path / "backups", 2)
    _bulk(tmp_path / "agents", 3)

    files, capped, unreached = _walk(tmp_path)

    tops = [p.relative_to(tmp_path).parts[0] for p in files]
    assert capped and len(files) == 20
    assert tops.count("agents") == 3
    # the spare budget went to the most important capped group first
    assert tops.count("workspace") == 13 and tops.count(".config-backups") == 3
    assert unreached == ["workspace/", ".config-backups/", "backups/"]
