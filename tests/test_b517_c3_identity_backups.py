"""B-517: C3 (check_backups) must credit only backup/archive/snapshot copies that are
name-tied to the agent's identity files (SOUL.md/MEMORY.md/AGENTS.md) — not just any
`.bak`/`.backup` file (e.g. a plain `openclaw.json.bak` config backup, the defect this
task fixes) or any file whose parent dir merely has "backup" as a substring.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks._lifecycle import check_backups
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# The exact WARN text `check_backups` has always returned when nothing backup-shaped is
# found at all — B-517 must leave this byte-identical.
_NOTHING_FOUND_DETAIL = (
    "No backups of SOUL.md / MEMORY.md found — if the agent's identity or memory "
    "is poisoned or corrupted, there's nothing to restore from."
)
_NOTHING_FOUND_FIX = (
    "Keep versioned, owner-only backups of SOUL.md/AGENTS.md/MEMORY.md outside the "
    "agent's writable workspace."
)


def _ctx(tmp_path):
    ctx = Context(home=tmp_path)
    ctx.bootstrap = {"SOUL.md": "you are an agent"}
    return ctx


# ---------------------------------------------------------------------------
# ACCEPT shapes (verdict 1: CREDIT -> PASS, pass_confidence="verified")
# ---------------------------------------------------------------------------

def test_c3_accepts_soul_md_bak(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "SOUL.md.bak").write_text("backup of soul")
    f = check_backups(ctx)
    assert f.status == "PASS"
    assert f.pass_confidence == "verified"
    assert "SOUL.md.bak" in f.detail


def test_c3_accepts_soul_backup_dated(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "SOUL.backup.20260801").write_text("backup of soul")
    f = check_backups(ctx)
    assert f.status == "PASS"
    assert f.pass_confidence == "verified"
    assert "SOUL.backup.20260801" in f.detail


def test_c3_accepts_soul_archive_token(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "SOUL_archive").write_text("backup of soul")
    f = check_backups(ctx)
    assert f.status == "PASS"
    assert f.pass_confidence == "verified"
    assert "SOUL_archive" in f.detail


def test_c3_accepts_soul_md_trailing_digit(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "SOUL.md.1").write_text("backup of soul")
    f = check_backups(ctx)
    assert f.status == "PASS"
    assert f.pass_confidence == "verified"
    assert "SOUL.md.1" in f.detail


def test_c3_accepts_soul_md_old(tmp_path):
    ctx = _ctx(tmp_path)
    (tmp_path / "SOUL.md.old").write_text("backup of soul")
    f = check_backups(ctx)
    assert f.status == "PASS"
    assert f.pass_confidence == "verified"
    assert "SOUL.md.old" in f.detail


def test_c3_accepts_soul_md_under_dated_backups_dir(tmp_path):
    """`backups/2026-08-01/SOUL.md` — an ANCESTOR (not just the immediate parent)
    named "backups" is enough, even though the immediate parent is a date dir."""
    ctx = _ctx(tmp_path)
    nested = tmp_path / "backups" / "2026-08-01"
    nested.mkdir(parents=True)
    (nested / "SOUL.md").write_text("backup of soul")
    f = check_backups(ctx)
    assert f.status == "PASS"
    assert f.pass_confidence == "verified"
    assert "SOUL.md" in f.detail


def test_c3_credits_git_tracked_identity_directory(tmp_path):
    """A `.git` dir covering the identity file's directory counts as credited (VCS is
    its own recovery mechanism) even with no backup-shaped file anywhere."""
    ctx = _ctx(tmp_path)
    (tmp_path / ".git").mkdir()
    f = check_backups(ctx)
    assert f.status == "PASS"
    assert f.pass_confidence == "verified"


# ---------------------------------------------------------------------------
# The defect repro: a plain config backup must NOT credit an identity-file question.
# ---------------------------------------------------------------------------

def test_c3_config_backup_alone_is_defect_repro_not_pass(tmp_path):
    """openclaw.json.bak alone (no SOUL/MEMORY/AGENTS-tied backup) -> verdict 3: WARN,
    never PASS. This is the exact defect B-517 fixes."""
    ctx = _ctx(tmp_path)
    (tmp_path / "openclaw.json.bak").write_text("{}")
    f = check_backups(ctx)
    assert f.status == "WARN"
    assert f.status != "PASS"
    assert "1" in f.detail
    assert "none corresponding to SOUL.md/MEMORY.md/AGENTS.md" in f.detail


def test_c3_config_backup_in_backup_named_dir_is_also_defect_repro(tmp_path):
    """Same defect, via the OLD "parent dir name contains 'backup'" bug shape: a
    config backup living inside a directory literally named "backup"."""
    ctx = _ctx(tmp_path)
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    (backup_dir / "openclaw.json").write_text("{}")
    f = check_backups(ctx)
    assert f.status == "WARN"
    assert f.status != "PASS"
    assert "1" in f.detail
    assert "none corresponding to SOUL.md/MEMORY.md/AGENTS.md" in f.detail


# ---------------------------------------------------------------------------
# Negative: an identity TOKEN alone, with no COPY signal, must not credit.
# ---------------------------------------------------------------------------

def test_c3_identity_token_without_copy_signal_does_not_credit(tmp_path):
    """state/memory.json has the "memory" identity token but nothing backup-shaped
    about its name or location — must not credit, must fall through to the plain
    "nothing found" WARN (not the "found N backup-like files" WARN either)."""
    ctx = _ctx(tmp_path)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "memory.json").write_text("{}")
    f = check_backups(ctx)
    assert f.status == "WARN"
    assert f.detail == _NOTHING_FOUND_DETAIL
    assert f.fix == _NOTHING_FOUND_FIX


# ---------------------------------------------------------------------------
# Verdict 4: nothing found at all -> byte-identical to the pre-B-517 text.
# ---------------------------------------------------------------------------

def test_c3_nothing_found_text_is_byte_identical_to_before(tmp_path):
    ctx = _ctx(tmp_path)
    f = check_backups(ctx)
    assert f.status == "WARN"
    assert f.detail == _NOTHING_FOUND_DETAIL
    assert f.fix == _NOTHING_FOUND_FIX


# ---------------------------------------------------------------------------
# No bootstrap at all -> UNKNOWN, unchanged.
# ---------------------------------------------------------------------------

def test_c3_no_bootstrap_is_unknown(tmp_path):
    ctx = Context(home=tmp_path)
    f = check_backups(ctx)
    assert f.status == "UNKNOWN"


# ---------------------------------------------------------------------------
# The two new fixtures, end-to-end through clawseccheck.audit().
# ---------------------------------------------------------------------------

def test_clean_c517_identity_backup_fixture_passes():
    _, findings, _score = audit(FIXTURES / "clean_c517_identity_backup")
    f = {x.id: x for x in findings}["C3"]
    assert f.status == "PASS"
    assert f.pass_confidence == "verified"


def test_bad_c517_config_backup_only_fixture_warns_not_pass():
    _, findings, _score = audit(FIXTURES / "bad_c517_config_backup_only")
    f = {x.id: x for x in findings}["C3"]
    assert f.status == "WARN"
    assert f.status != "PASS"
    assert "none corresponding to SOUL.md/MEMORY.md/AGENTS.md" in f.detail


# --- the OPAQUE arm must not become the next lying PASS -----------------------------

def _home_with_soul(tmp_path):
    (tmp_path / "SOUL.md").write_text("identity", encoding="utf-8")
    ctx = Context(home=tmp_path)
    ctx.bootstrap = {"SOUL.md": "identity"}
    return ctx


def test_c3_stray_archive_is_not_a_backup(tmp_path):
    """Found during review of this very change: keying OPAQUE on the archive SUFFIX alone
    let any zipped file in the home grant a PASS. A `holiday-photos.zip` is not a backup
    of SOUL.md, and the whole point of this task is that C3 stops crediting things it has
    no reason to believe in."""
    ctx = _home_with_soul(tmp_path)
    (tmp_path / "holiday-photos.zip").write_text("x", encoding="utf-8")
    assert check_backups(ctx).status == WARN


def test_c3_vendored_tarball_is_not_a_backup(tmp_path):
    ctx = _home_with_soul(tmp_path)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "leftpad-1.0.0.tgz").write_text("x", encoding="utf-8")
    assert check_backups(ctx).status == WARN


def test_c3_archive_in_a_backups_dir_is_still_opaque_pass(tmp_path):
    ctx = _home_with_soul(tmp_path)
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / "agent-2026-08-01.tar.gz").write_text("x", encoding="utf-8")
    f = check_backups(ctx)
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


def test_c3_archive_named_backup_is_still_opaque_pass(tmp_path):
    ctx = _home_with_soul(tmp_path)
    (tmp_path / "agent-backup.tar.gz").write_text("x", encoding="utf-8")
    f = check_backups(ctx)
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"
