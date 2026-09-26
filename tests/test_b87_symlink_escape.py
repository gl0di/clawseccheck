"""B87 (TAM-07): symlink-escape finding.

A skill/workspace symlink whose realpath resolves into a sensitive host path
(~/.ssh, ~/.aws, keychains, browser profiles, .env, credential files) is a
data-exfiltration primitive. F-061 already traverses such links safely (never
followed); B87 turns the link itself into a verdict:

    FAIL    — target resolves into a sensitive host-path class
    WARN    — target escapes the skill/workspace tree (non-sensitive)
    PASS    — link stays inside the tree (intra-dir relative link)
    UNKNOWN — broken / dangling / unresolvable link (disclosed)

All offline; every symlink is fabricated inside pytest's tmp_path. Symlinks are
POSIX-only, so the FS assertions are gated on os.name == "posix".
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_symlink_escape, vet_skill
from clawseccheck.collector import Context

posix_only = pytest.mark.skipif(os.name != "posix", reason="symlinks are POSIX-only")


def _mk_skill(root, name="demo"):
    """A minimal, real-shaped skill dir with a SKILL.md (marks it a vet root)."""
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text("---\nname: %s\n---\nhello\n" % name, encoding="utf-8")
    return d


def _fake_store(root, *rel):
    """Fabricate a fake sensitive store inside tmp_path and return its path."""
    p = root.joinpath(*rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("secret-shaped", encoding="utf-8")
    return p


def _b87(finding):
    """Pull the B87 finding out of a vet result (primary or ring)."""
    for f in [finding, *getattr(finding, "ring_findings", [])]:
        if f.id == "B87":
            return f
    return None


# ---- direct check: the four verdicts ----------------------------------------


@posix_only
def test_symlink_to_ssh_dir_is_fail(tmp_path):
    """A directory symlink `data -> <fakehome>/.ssh` — the documented TAM-07 case.
    walk_dir_safely (F-061) misses directory symlinks; B87 must catch it."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")
    skill = _mk_skill(tmp_path / "skills")
    os.symlink(fakehome / ".ssh", skill / "data")

    f = check_symlink_escape(Context(home=skill))
    assert f.status == FAIL
    assert any(".ssh" in e for e in f.evidence)


@posix_only
def test_symlink_to_aws_credentials_file_is_fail(tmp_path):
    """A file symlink straight at a credential file is FAIL too (basename + _CRED_RE)."""
    cred = _fake_store(tmp_path / "fakehome", ".aws", "credentials")
    skill = _mk_skill(tmp_path / "skills")
    os.symlink(cred, skill / "aws.txt")

    f = check_symlink_escape(Context(home=skill))
    assert f.status == FAIL


@posix_only
def test_symlink_to_dotenv_is_fail(tmp_path):
    env = _fake_store(tmp_path / "elsewhere", ".env")
    skill = _mk_skill(tmp_path / "skills")
    os.symlink(env, skill / "config")

    assert check_symlink_escape(Context(home=skill)).status == FAIL


@posix_only
def test_symlink_to_ethereum_keystore_is_fail(tmp_path):
    """C-198: ~/.ethereum/keystore is Geth/go-ethereum's real default wallet-keystore
    dir — same exfil-primitive class as .ssh/.aws, now covered by _SENSITIVE_PATH_SEGMENTS."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ethereum" / "keystore").mkdir(parents=True)
    (fakehome / ".ethereum" / "keystore" / "UTC--2024-01-01T00-00-00").write_text(
        "x", encoding="utf-8"
    )
    skill = _mk_skill(tmp_path / "skills")
    os.symlink(fakehome / ".ethereum" / "keystore", skill / "data")

    f = check_symlink_escape(Context(home=skill))
    assert f.status == FAIL
    assert any(".ethereum" in e for e in f.evidence)


@posix_only
def test_symlink_to_solana_keypair_is_fail(tmp_path):
    """C-198: ~/.config/solana/id.json is the Solana CLI's real default keypair file."""
    keypair = _fake_store(tmp_path / "fakehome", ".config", "solana", "id.json")
    skill = _mk_skill(tmp_path / "skills")
    os.symlink(keypair, skill / "wallet.json")

    assert check_symlink_escape(Context(home=skill)).status == FAIL


@posix_only
def test_symlink_to_solana_toolchain_dir_is_not_fail(tmp_path):
    """C-198 adversarial C-135 finding: a bare "solana" path SEGMENT must not anchor
    sensitivity — the official Solana CLI toolchain install dir
    (~/.local/share/solana/install/active_release/bin, the documented solana-install
    default) and an ordinary dev checkout named "solana" both have a "solana" path
    component with zero wallet-credential meaning. Only the specific .config/solana
    keypair path (via _CRED_RE) is sensitive; escapes outside the tree to anything else
    are WARN, not a false FAIL."""
    toolchain = _fake_store(
        tmp_path / "fakehome", ".local", "share", "solana", "install",
        "active_release", "bin", "solana",
    )
    skill = _mk_skill(tmp_path / "skills")
    os.symlink(toolchain, skill / "solana-cli")

    assert check_symlink_escape(Context(home=skill)).status == WARN


@posix_only
def test_intra_dir_relative_link_is_pass(tmp_path):
    """A relative link to a sibling inside the skill stays inside the tree -> PASS."""
    skill = _mk_skill(tmp_path / "skills")
    (skill / "real.txt").write_text("hi", encoding="utf-8")
    os.symlink("real.txt", skill / "alias.txt")  # relative, intra-dir

    assert check_symlink_escape(Context(home=skill)).status == PASS


@posix_only
def test_link_into_same_workspace_is_pass(tmp_path):
    """A link that resolves elsewhere in the same workspace/home tree is PASS,
    not WARN (zero-FP requirement)."""
    home = tmp_path / "openclaw"
    home.mkdir()
    other = home / "shared" / "note.txt"
    other.parent.mkdir(parents=True)
    other.write_text("hi", encoding="utf-8")
    sk = home / "skills" / "demo"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("---\nname: demo\n---\n", encoding="utf-8")
    os.symlink(other, sk / "link")

    assert check_symlink_escape(Context(home=home)).status == PASS


@posix_only
def test_escape_outside_tree_is_warn(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f.txt").write_text("x", encoding="utf-8")
    skill = _mk_skill(tmp_path / "skills")
    os.symlink(outside / "f.txt", skill / "ext")

    assert check_symlink_escape(Context(home=skill)).status == WARN


@posix_only
def test_dangling_link_is_unknown(tmp_path):
    skill = _mk_skill(tmp_path / "skills")
    os.symlink(skill / "does-not-exist", skill / "broken")

    f = check_symlink_escape(Context(home=skill))
    assert f.status == UNKNOWN
    # Control for the B-899 round-1 gap-only case below: a REAL broken link keeps the
    # broken-link remediation lead-in.
    assert f.fix.startswith("Fix or remove broken links")


@posix_only
def test_sensitive_but_absent_target_is_fail_not_unknown(tmp_path):
    """A `-> .../.ssh` whose target does NOT exist on this box is still FAIL: the exfil
    intent is a property of the target path, not of the host's current filesystem."""
    skill = _mk_skill(tmp_path / "skills")
    absent_ssh = tmp_path / "nowhere" / ".ssh"  # deliberately never created
    os.symlink(absent_ssh, skill / "keys")

    assert check_symlink_escape(Context(home=skill)).status == FAIL


# ---- full-audit mode (ctx.home is the OpenClaw home) ------------------------


@posix_only
def test_full_audit_flags_installed_skill_symlink(tmp_path):
    """In the full audit the scan roots are the installed skill dirs, not ctx.home."""
    home = tmp_path / "openclaw"
    home.mkdir()
    aws = _fake_store(tmp_path / "victim", ".aws", "credentials")
    sk = home / "skills" / "evil"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("---\nname: evil\n---\n", encoding="utf-8")
    os.symlink(aws.parent, sk / "aws")  # -> <victim>/.aws

    assert check_symlink_escape(Context(home=home)).status == FAIL


@posix_only
def test_full_audit_clean_home_is_pass_or_unknown(tmp_path):
    """A home with an installed skill and only an intra-tree link must not FAIL/WARN."""
    home = tmp_path / "openclaw"
    home.mkdir()
    sk = home / "skills" / "good"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("---\nname: good\n---\n", encoding="utf-8")
    (sk / "real.txt").write_text("hi", encoding="utf-8")
    os.symlink("real.txt", sk / "alias.txt")

    assert check_symlink_escape(Context(home=home)).status in (PASS, UNKNOWN)


# ---- vet integration (through the content ring) -----------------------------


@posix_only
def test_vet_surfaces_b87_fail_on_bad_skill(tmp_path):
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    skill = _mk_skill(tmp_path / "skills", name="malicious")
    os.symlink(fakehome / ".ssh", skill / "keys")

    b87 = _b87(vet_skill(skill))
    assert b87 is not None and b87.status == FAIL


@posix_only
def test_vet_clean_skill_drops_b87(tmp_path):
    """A clean skill's B87 PASS is dropped by the ring (only FAIL/WARN surface)."""
    skill = _mk_skill(tmp_path / "skills", name="benign")
    (skill / "real.txt").write_text("hi", encoding="utf-8")
    os.symlink("real.txt", skill / "alias.txt")

    assert _b87(vet_skill(skill)) is None


# ---- no-root / zero-FP ------------------------------------------------------


def test_no_skill_dir_is_unknown(tmp_path):
    """A ctx.home that is neither a skill dir nor an OpenClaw home -> UNKNOWN, not FAIL."""
    empty = tmp_path / "nothing"
    empty.mkdir()
    assert check_symlink_escape(Context(home=empty)).status == UNKNOWN


@posix_only
def test_own_repo_home_safe_fixture_has_no_symlink_fail():
    """Zero-FP: the shipped clean fixtures must not trip B87."""
    from pathlib import Path

    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    for name in ("home_safe", "home_vuln"):
        home = fixtures / name
        if not home.is_dir():
            continue
        f = check_symlink_escape(Context(home=home))
        assert f.status in (PASS, UNKNOWN, WARN)  # never a false sensitive-path FAIL
        if f.status == FAIL:  # pragma: no cover - explicit guard
            raise AssertionError(f"{name}: unexpected B87 FAIL: {f.detail}")


# ---- B-899: an unsearchable skill dir must degrade honestly, never crash or mask -----
#
# `Path.is_symlink()` needs search (`x`) permission on the PARENT directory to `lstat()`
# an entry inside it. A skill dir at mode 0644 (listable via `r`, not searchable) makes
# every `is_symlink()` call on its own contents raise `PermissionError` -- which used to
# propagate straight out of `_enumerate_symlinks`/`check_symlink_escape`, taking a
# confirmed FAIL on a sibling skill down with it. 0000 (unlistable too) took a different,
# quieter path: `os.walk`'s default `onerror=None` discarded the failure and the check
# fell through to a false-clean PASS instead of raising. Root runs bypass the directory
# search-permission check entirely (CAP_DAC_OVERRIDE), so these are skipped under root
# exactly like this repo's other 0644/0000 permission tests (see test_b551_unsearchable_dir.py).

root_skip = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses directory search-permission checks",
)


@pytest.fixture
def unlock():
    """Restore a chmod'd directory's mode even when an assertion fails, so a red test
    never leaves an unsearchable/unlistable directory behind for the next one."""
    locked: list = []
    yield locked.append
    for d in locked:
        try:
            d.chmod(0o755)
        except OSError:
            pass


def _two_skill_layout(tmp_path):
    """`aaa` carries a real, out-of-tree sensitive-path escape (FAIL-worthy on its own);
    `zzz` is an unrelated, otherwise-clean sibling whose permission bits get mangled by
    each test. Mirrors the exact layout from the B-899 report."""
    home = tmp_path / "openclaw"
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")
    aaa = _mk_skill(home / "workspace" / "skills", name="aaa")
    zzz = _mk_skill(home / "workspace" / "skills", name="zzz")
    os.symlink(fakehome / ".ssh", aaa / "keys")
    return home, zzz


@posix_only
@root_skip
def test_unsearchable_sibling_0644_does_not_crash_and_keeps_real_fail(tmp_path, unlock):
    home, zzz = _two_skill_layout(tmp_path)
    zzz.chmod(0o644)
    unlock(zzz)

    f = check_symlink_escape(Context(home=home))  # must not raise
    assert f.status == FAIL
    assert any(".ssh" in e for e in f.evidence)


@posix_only
@root_skip
def test_unsearchable_sibling_0000_does_not_crash_and_keeps_real_fail(tmp_path, unlock):
    home, zzz = _two_skill_layout(tmp_path)
    zzz.chmod(0o000)
    unlock(zzz)

    f = check_symlink_escape(Context(home=home))  # must not raise
    assert f.status == FAIL
    assert any(".ssh" in e for e in f.evidence)


@posix_only
@root_skip
def test_solo_unsearchable_skill_0644_is_unknown_not_a_false_pass(tmp_path, unlock):
    """No sibling FAIL to fall back on: an unsearchable skill dir with nothing else to
    scan must surface as an honest, engine-side UNKNOWN -- never the false-clean PASS
    the 0000 shape produced before this fix (the bare crash the 0644 shape produced is
    covered by the "does not crash" tests above)."""
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="onlyzzz")
    sk.chmod(0o644)
    unlock(sk)

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


@posix_only
@root_skip
def test_solo_unsearchable_skill_0000_is_unknown_not_a_false_pass(tmp_path, unlock):
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="onlyzzz")
    sk.chmod(0o000)
    unlock(sk)

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


@posix_only
@root_skip
def test_unreadable_path_is_disclosed_in_fix_not_detail(tmp_path, unlock):
    """The disclosure belongs in `fix`: `baseline.fingerprint()` hashes only `detail`
    (sha1 keyed by finding id), so folding a host-specific path into `detail` would give
    every affected machine its own fingerprint and orphan any `.clawseccheckignore` entry
    already written against this UNKNOWN."""
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="onlyzzz")
    sk.chmod(0o644)
    unlock(sk)

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert "onlyzzz" not in f.detail, f.detail
    assert "onlyzzz" in f.fix, f.fix


@posix_only
@root_skip
def test_healthy_root_is_unaffected_by_the_guard(tmp_path):
    """Control: an ordinary, fully-searchable skill tree is scored exactly as before --
    the new guard must never fire (and never set engine_degraded) on a normal run."""
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="clean")
    (sk / "real.txt").write_text("hi", encoding="utf-8")
    os.symlink("real.txt", sk / "alias.txt")

    f = check_symlink_escape(Context(home=home))
    assert f.status == PASS
    assert f.engine_degraded is False


# ---- B-899 C-135 round 1: the reviewer's three defects --------------------------------
#
# Round 1's fix (commit 70c006eb) turned every walk/stat failure into a graded,
# engine_degraded gap. The review found that treatment too blunt in one direction (a
# vanished temp dir, or a benign directory this uid cannot reach anyway, should not cost
# the run) and too loose in another (a pre-existing defect: an unreadable SKILL_DIRS base
# was silently dropped instead of degrading). This block pins the corrected rule.


@posix_only
def test_vanished_subdir_during_walk_is_pass_not_degraded(tmp_path, monkeypatch):
    """A subdirectory that disappears between os.walk listing its parent and descending
    into it (a build/pytest/npm temp dir being cleaned, a git checkout) must NOT count as
    a coverage gap: it existed when listed and is gone now, and a directory that no
    longer exists cannot hide a symlink. Before this rule a churn thread doing exactly
    this flipped a clean home to UNKNOWN + engine_degraded (DEGRADED_CHECK_CAP) in 158 of
    200 runs, with remediation text naming a path that no longer existed."""
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="clean")
    victim = sk / "tmp_build"
    victim.mkdir()  # left empty: os.rmdir needs no scandir of its own (shutil.rmtree would)
    real_scandir = os.scandir

    def flaky_scandir(path="."):
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == os.fspath(victim):
            os.rmdir(victim)  # gone by the time we look
            raise FileNotFoundError(2, "No such file or directory", str(victim))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", flaky_scandir)

    f = check_symlink_escape(Context(home=home))
    assert f.status == PASS
    assert f.engine_degraded is False


@posix_only
def test_swapped_in_symlink_on_vanished_path_is_still_assessed(tmp_path, monkeypatch):
    """The one thing a vanished path CAN still be: a symlink put in its place between the
    listing and the descent. That must land on the verdict (here, a sensitive escape),
    never be silently dropped alongside the ordinary ENOENT case above."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")

    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="clean")
    victim = sk / "swapped"
    victim.mkdir()  # left empty: removed with plain rmdir below, no nested scandir
    real_scandir = os.scandir

    def flaky_scandir(path="."):
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == os.fspath(victim):
            os.rmdir(victim)
            os.symlink(fakehome / ".ssh", victim)
            raise NotADirectoryError(20, "Not a directory", str(victim))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", flaky_scandir)

    f = check_symlink_escape(Context(home=home))
    assert f.status == FAIL
    assert any(".ssh" in e for e in f.evidence)


@posix_only
@root_skip
def test_own_unsearchable_workspace_dir_is_still_graded(tmp_path, unlock):
    """A non-skill workspace directory this uid OWNS but chmod'd unsearchable is not a
    real barrier -- the owner can chmod it back at will -- so it stays a graded
    engine_degraded gap, not a free disclosure. Contrast with the foreign-owned case
    below."""
    home = tmp_path / "openclaw"
    _mk_skill(home / "workspace" / "skills", name="clean")
    data = home / "workspace" / "proj" / "data"
    data.mkdir(parents=True)
    data.chmod(0o000)
    unlock(data)

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


@posix_only
@root_skip
def test_benign_foreign_owned_workspace_dir_is_disclosed_not_graded(tmp_path, monkeypatch, unlock):
    """A benign, foreign-owned, unsearchable workspace data directory (the real-world
    shape: a Docker volume such as postgres data owned by uid 999, mode 0700) must not
    fail the whole scan. A same-uid agent cannot traverse a directory it cannot search
    either, so a foreign-owned one without search permission hides no link the agent
    could follow -- disclose it in `fix`, but PASS. Before this rule one such directory
    took a healthy home's score from 98/A to 49/F (degraded_capped).

    An unprivileged test cannot really chown to another uid, so `_b87_uid_of` -- a
    deliberate seam -- is monkeypatched to report the directory as foreign-owned; the
    chmod 0o000 is real, so the actual OS permission check (condition 5) is not faked."""
    import clawseccheck.checks._content as content_mod

    home = tmp_path / "openclaw"
    _mk_skill(home / "workspace" / "skills", name="clean")
    pgdata = home / "workspace" / "proj" / "pgdata"
    pgdata.mkdir(parents=True)
    pgdata.chmod(0o000)
    unlock(pgdata)

    real_uid_of = content_mod._b87_uid_of

    def fake_uid_of(path):
        if os.fspath(path) == os.fspath(pgdata):
            return (real_uid_of(path) or 0) + 1  # anything other than our own euid
        return real_uid_of(path)

    monkeypatch.setattr(content_mod, "_b87_uid_of", fake_uid_of)

    f = check_symlink_escape(Context(home=home))
    assert f.status == PASS
    assert f.engine_degraded is False
    assert "pgdata" in f.fix
    assert "pgdata" not in f.detail


@posix_only
@root_skip
def test_unreadable_skills_base_0000_is_unknown_not_a_lost_detection_pass(tmp_path, unlock):
    """Pre-existing lost-detection defect, same root cause, fixed here: an unreadable
    SKILL_DIRS base (e.g. ~/.openclaw/skills at mode 0000) used to have its
    `base.iterdir()` OSError swallowed by `_symlink_scan_roots`'s bare
    `except OSError: continue`, dropping the whole skills tree silently and reporting
    PASS on a home whose skills were never listed -- even with a real escape symlink
    inside (skills/evil/keys -> ~/.ssh). A skills root is skill content by definition, so
    the gap must be graded: UNKNOWN + engine_degraded, never a false PASS."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")

    home = tmp_path / "openclaw"
    evil = home / "skills" / "evil"
    evil.mkdir(parents=True)
    os.symlink(fakehome / ".ssh", evil / "keys")
    (home / "workspace").mkdir(parents=True)  # an ordinary sibling root, per the report

    skills = home / "skills"
    skills.chmod(0o000)
    unlock(skills)

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


@posix_only
@root_skip
def test_unreadable_skills_base_0111_is_also_unknown(tmp_path, unlock):
    """Same defect, the other permission shape from the report: 0111 (search-only, no
    read) lets `is_dir()`/`is_symlink()` on the base succeed but `iterdir()` fail."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")

    home = tmp_path / "openclaw"
    evil = home / "skills" / "evil"
    evil.mkdir(parents=True)
    os.symlink(fakehome / ".ssh", evil / "keys")

    skills = home / "skills"
    skills.chmod(0o111)
    unlock(skills)

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


@posix_only
@root_skip
def test_gap_only_unknown_drops_the_broken_link_prefix(tmp_path, unlock):
    """When the only UNKNOWN reason is a coverage gap (no actual broken/dangling link
    anywhere in the run), the fix text must not open with the broken-link remediation --
    there is no broken link to fix or remove, only an unreadable directory."""
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="onlyzzz")
    sk.chmod(0o644)
    unlock(sk)

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert not f.fix.startswith("Fix or remove broken links"), f.fix


# ---- B-899 C-135 round 3: the reviewers' four defects (this is the last fix round) ----
#
# Round 2 (commit 79174085) generalized `_on_walk_error` but left the sibling per-entry
# trigger unfixed, dropped a root-that-is-itself-a-symlink silently, and could report one
# real escape twice when a SKILL_DIRS root nests inside a WORKSPACE_DIRS one. Both
# independent round-2 reviews reproduced the per-entry blocker; this block pins its fix
# and the other three round-3 defects.


@posix_only
def test_vanished_file_entry_before_lstat_is_pass_not_degraded(tmp_path, monkeypatch):
    """The blocker (both C-135 round-2 reviews): an already-`os.walk`-listed FILE entry
    vanishing before this code's own per-entry `is_symlink()` lstat -- a linter/build-tool
    temp file rotated away between the parent listing and this call, on an otherwise
    completely healthy home -- must not count as a coverage gap. Round 2 generalized
    `_on_walk_error` (the directory-level onerror callback) but left this sibling
    per-entry trigger path unconditionally grading any vanished entry, even though the
    same commit touched both of these blocks (renaming state['unreadable'] to gaps)."""
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="clean")
    victim = sk / "flaky.tmp"
    victim.write_text("x", encoding="utf-8")
    real_is_symlink = Path.is_symlink

    def flaky_is_symlink(self):
        if self == victim:
            victim.unlink()
            raise FileNotFoundError(2, "No such file or directory", str(victim))
        return real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", flaky_is_symlink)

    f = check_symlink_escape(Context(home=home))
    assert f.status == PASS
    assert f.engine_degraded is False


@posix_only
def test_vanished_subdir_entry_before_lstat_is_pass_not_degraded(tmp_path, monkeypatch):
    """Same defect, the SUBDIRECTORY-entry trigger (the `dirnames` loop, not `filenames`):
    an already-listed subdirectory vanishing before this code's own `is_symlink()` lstat
    must not count as a coverage gap either."""
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="clean")
    victim = sk / "vanishing_dir"
    victim.mkdir()
    real_is_symlink = Path.is_symlink

    def flaky_is_symlink(self):
        if self == victim:
            victim.rmdir()
            raise FileNotFoundError(2, "No such file or directory", str(victim))
        return real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", flaky_is_symlink)

    f = check_symlink_escape(Context(home=home))
    assert f.status == PASS
    assert f.engine_degraded is False


@posix_only
def test_permission_denied_per_entry_still_grades_the_gap(tmp_path, monkeypatch):
    """Control for the two tests above: a per-entry `is_symlink()` failure that is NOT a
    vanish (a real, persistent permission denial) must still be recorded as a coverage gap
    and graded -- the new ENOENT/ENOTDIR short-circuit must not swallow every OSError,
    only the ones that mean the entry is provably gone."""
    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="clean")
    victim = sk / "stuck.tmp"
    victim.write_text("x", encoding="utf-8")
    real_is_symlink = Path.is_symlink

    def denied_is_symlink(self):
        if self == victim:
            raise PermissionError(13, "Permission denied", str(victim))
        return real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", denied_is_symlink)

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert f.engine_degraded is True


@posix_only
def test_recreated_ordinary_dir_after_vanish_is_a_toctou_limit_not_a_false_pass(
    tmp_path, monkeypatch
):
    """Accepted residual (C-135 round 3), not a regression: a directory that vanishes and
    is then RECREATED AS AN ORDINARY DIRECTORY (not a symlink) before `_on_walk_error`'s
    own re-lstat -- with a real escape already planted inside it by the same race -- still
    returns PASS, not an honest UNKNOWN. Grading this reappearance was considered and
    rejected: an ordinary build tool's atomic replace (rmdir+mkdir, or write-temp-then-
    rename) recreates a plain, empty-ish directory in exactly this shape on every run, so
    grading "vanished, now an ordinary directory" would reopen the same churn-FP class
    round 1 fixed (158/200 clean-home runs going UNKNOWN+degraded), trading it for a rare
    adversarial case a single point-in-time `os.walk` cannot reliably close anyway (a live
    filesystem watch or a re-scan-on-suspicion pass could; a static single pass cannot).
    Measured over 40 real, non-monkeypatched `rmtree`+`mkdir`+`symlink` trials against a
    live scan target: this race landed on an undetected PASS in 25/40 runs on the fixed
    code and 32/40 on the pre-round-3 base -- i.e. this round changes neither the exposure
    nor its cause. This test pins the CURRENT, deliberate behaviour so a future change
    does not silently reopen the churn FP trying to close it."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")

    home = tmp_path / "openclaw"
    sk = _mk_skill(home / "workspace" / "skills", name="clean")
    victim = sk / "reappeared"
    victim.mkdir()  # left empty: os.rmdir needs no scandir of its own
    real_scandir = os.scandir

    def flaky_scandir(path="."):
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == os.fspath(victim):
            os.rmdir(victim)
            victim.mkdir()  # recreated as an ordinary dir before the re-lstat fires
            os.symlink(fakehome / ".ssh", victim / "escape")  # a real escape, hidden inside
            raise FileNotFoundError(2, "No such file or directory", str(victim))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", flaky_scandir)

    f = check_symlink_escape(Context(home=home))
    assert f.status == PASS
    assert f.engine_degraded is False


@posix_only
def test_workspace_root_symlink_to_sensitive_path_is_fail(tmp_path):
    """A WORKSPACE_DIRS entry that is itself a symlink into a sensitive store must FAIL
    like any other symlink escape. Before this it vanished with no FAIL, no WARN, no gap
    and no disclosure anywhere: `Path.is_dir()`/`is_symlink()` both swallow
    ENOENT/ENOTDIR/EBADF/ELOOP internally and simply return False/True without raising, so
    `_add`'s `is_dir() and not is_symlink()` boolean check silently rejected it as "not a
    usable root" with nothing to distinguish a malicious link from a dangling one. This
    also closes the round-1-flagged "a root symlink is skipped entirely" residual."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")

    home = tmp_path / "openclaw"
    home.mkdir()
    os.symlink(fakehome / ".ssh", home / "workspace")

    f = check_symlink_escape(Context(home=home))
    assert f.status == FAIL
    assert any(".ssh" in e for e in f.evidence)


@posix_only
def test_skill_dir_itself_a_symlink_to_sensitive_path_is_fail(tmp_path):
    """An installed *skill* directory that is itself a symlink (a SKILL_DIRS sub-entry,
    not a link found inside one) must FAIL exactly like a root symlink does -- the same
    silent-drop bug, reached through `_add(sub, base)` instead of `_add(home / ws, home)`.
    Uses the top-level `skills` SKILL_DIRS entry (not nested under any WORKSPACE_DIRS
    root) so this is reachable ONLY through that code path, not through an overlapping
    workspace walk."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".aws").mkdir(parents=True)
    (fakehome / ".aws" / "credentials").write_text("x", encoding="utf-8")

    home = tmp_path / "openclaw"
    skills = home / "skills"
    skills.mkdir(parents=True)
    os.symlink(fakehome / ".aws", skills / "evil")

    f = check_symlink_escape(Context(home=home))
    assert f.status == FAIL
    assert any(".aws" in e for e in f.evidence)


@posix_only
def test_skill_dirs_base_itself_a_symlink_to_sensitive_path_is_fail(tmp_path):
    """The SKILL_DIRS *base* itself (`skills`, not one of its children) being a symlink
    hits a separate inline check in `_symlink_scan_roots` (not `_add`) with the identical
    silent-drop bug -- must also be classified, not skipped. Uses the top-level `skills`
    entry so this is reachable only through that base-level check."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")

    home = tmp_path / "openclaw"
    home.mkdir()
    os.symlink(fakehome / ".ssh", home / "skills")

    f = check_symlink_escape(Context(home=home))
    assert f.status == FAIL
    assert any(".ssh" in e for e in f.evidence)


@posix_only
def test_self_referential_workspace_root_is_disclosed_not_silent(tmp_path):
    """An unresolvable (ELOOP) root symlink must surface as an honest, disclosed UNKNOWN
    naming the link -- never a silent drop into a bare "nothing to inspect" result that
    says nothing about the loop. `os.path.realpath`'s default (non-strict) mode does not
    raise on a cycle -- it stops resolving and hands back the unresolved path -- so this
    lands on the same "broken / dangling" disclosure a plain dangling link gets, via
    `Path.exists()` (which DOES report False for a self-referential symlink) rather than
    an OSError branch."""
    home = tmp_path / "openclaw"
    home.mkdir()
    loop = home / "workspace"
    os.symlink(loop, loop)  # self-referential: ELOOP once anything tries to fully resolve it

    f = check_symlink_escape(Context(home=home))
    assert f.status == UNKNOWN
    assert "workspace" in f.detail


@posix_only
def test_benign_workspace_root_symlink_is_warn_not_fail(tmp_path):
    """A benign root symlink -- a workspace kept on another disk, a stow/chezmoi-managed
    dotfile link, `~/.openclaw/workspace -> ~/code/project` -- must never FAIL. It escapes
    the tree but is not sensitively named, so it gets the same WARN-for-a-human-look
    treatment any other non-sensitive escaping link gets; this is not a special case for
    roots, it falls out of the existing rubric applied uniformly."""
    home = tmp_path / "openclaw"
    home.mkdir()
    project = tmp_path / "code" / "project"
    project.mkdir(parents=True)
    (project / "README.md").write_text("hi", encoding="utf-8")
    os.symlink(project, home / "workspace")

    f = check_symlink_escape(Context(home=home))
    assert f.status == WARN


@posix_only
def test_nested_skill_root_is_not_double_reported(tmp_path):
    """A skill living under the standard `workspace/skills/<name>` layout is simultaneously
    a SKILL_DIRS entry and a descendant of the `workspace` WORKSPACE_DIRS entry -- a real
    escape inside it must be reported exactly once, not once per overlapping root."""
    fakehome = tmp_path / "fakehome"
    (fakehome / ".ssh").mkdir(parents=True)
    (fakehome / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")

    home = tmp_path / "openclaw"
    aaa = _mk_skill(home / "workspace" / "skills", name="aaa")
    os.symlink(fakehome / ".ssh", aaa / "keys")

    f = check_symlink_escape(Context(home=home))
    assert f.status == FAIL
    hits = [e for e in f.evidence if ".ssh" in e]
    assert len(hits) == 1, f.evidence


def test_symlink_scan_roots_collapses_nested_roots(tmp_path):
    """Unit-level pin for the root-level dedup itself, not just its externally-visible
    effect (which `check_symlink_escape`'s own belt-and-suspenders link-level dedup would
    also mask): walking BOTH the inner and outer root wastes scan-cap budget and CPU on
    every real audit, so the outermost survivor must actually be the only root returned,
    not merely the only one that ends up reported."""
    from clawseccheck.checks import _symlink_scan_roots

    home = tmp_path / "openclaw"
    _mk_skill(home / "workspace" / "skills", name="aaa")

    roots, root_links = _symlink_scan_roots(Context(home=home))
    assert not root_links
    assert roots == [home / "workspace"]
