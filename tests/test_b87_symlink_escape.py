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

    assert check_symlink_escape(Context(home=skill)).status == UNKNOWN


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
