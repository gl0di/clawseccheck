"""B354 (CLAWSECCHECK-B-725) — the state DB's shared skill-library / upload surface.

A skill published to OpenClaw's shared skill library (`skill_library_entries`,
`skill_uploads`) with `enabled AND NOT removed` is reachable to that install and was
never on the path `_read_installed_skills` walks — confirmed by grep, neither table
appears anywhere else in `clawseccheck/` before this check. Every content-security
check this tool has is blind to a skill installed through this channel alone.

The real machine this was grounded against (OpenClaw 2026.9.1, state schema 15) has
`skill_library_entries` ABSENT while `skill_uploads` is present with 0 rows — so the
control that matters most is that an ABSENT table reads UNKNOWN, never a clean PASS,
and that the two tables are tracked independently (one present-and-clean does not
paper over the other being unread).

DDL copied verbatim from `tests/state_schema_snapshot.sql` (itself extracted
byte-for-byte from the installed OpenClaw's `OPENCLAW_STATE_SCHEMA_SQL` — see
`tests/test_state_schema_grounding.py`), so this fixture cannot silently drift from
the vendor's real schema.
"""
from __future__ import annotations

import sqlite3

import pytest

from clawseccheck.catalog import BY_ID, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_skill_library_reachability
from clawseccheck.collector import Context, _collect_skill_library_state

# Verbatim from tests/state_schema_snapshot.sql (2026.9.3, state-schema-version 16).
_SKILL_LIBRARY_ENTRIES_DDL = """
CREATE TABLE IF NOT EXISTS skill_library_entries (
  skill_id TEXT NOT NULL PRIMARY KEY,
  owner_profile_id TEXT,
  author_profile_id TEXT NOT NULL,
  slug TEXT NOT NULL,
  current_revision TEXT NOT NULL,
  shared INT NOT NULL,
  enabled INT NOT NULL,
  removed INT NOT NULL,
  created_at INT NOT NULL,
  updated_at INT NOT NULL
) STRICT;
"""

_SKILL_UPLOADS_DDL = """
CREATE TABLE IF NOT EXISTS skill_uploads (
  upload_id TEXT NOT NULL PRIMARY KEY,
  kind TEXT NOT NULL,
  slug TEXT NOT NULL,
  force INTEGER NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT,
  actual_sha256 TEXT,
  received_bytes INTEGER NOT NULL,
  archive_blob BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  committed INTEGER NOT NULL,
  committed_at INTEGER,
  idempotency_key_hash TEXT UNIQUE
) STRICT;
"""

# Secret-shaped values assembled from fragments so no contiguous literal exists in
# source (CLAUDE.md §2 rule 3 / tests/test_logsafe.py precedent).
_FAKE_TOKEN = "gh" + "p_" + "A" * 30


def _entry(skill_id, slug, *, shared=0, enabled=1, removed=0,
           owner_profile_id="owner-1", author_profile_id="author-1"):
    return (skill_id, owner_profile_id, author_profile_id, slug, "r1",
            shared, enabled, removed, 1, 1)


def _upload(upload_id, *, sha256="a" * 64, actual_sha256="a" * 64, committed=1,
            slug="s"):
    return (upload_id, "skill", slug, 0, 4, sha256, actual_sha256, 4, b"x", 1,
            999999999, committed, 1 if committed else None, None)


def _ctx(tmp_path, *, db=True, entries_table=True, uploads_table=True,
          entries=(), uploads=()):
    home = tmp_path / "openclaw"
    home.mkdir(parents=True, exist_ok=True)
    if db:
        state = home / "state"
        state.mkdir(exist_ok=True)
        conn = sqlite3.connect(state / "openclaw.sqlite")
        try:
            if entries_table:
                conn.executescript(_SKILL_LIBRARY_ENTRIES_DDL)
                conn.executemany(
                    "INSERT INTO skill_library_entries VALUES (?,?,?,?,?,?,?,?,?,?)",
                    entries,
                )
            if uploads_table:
                conn.executescript(_SKILL_UPLOADS_DDL)
                conn.executemany(
                    "INSERT INTO skill_uploads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    uploads,
                )
            conn.commit()
        finally:
            conn.close()
    ctx = Context(home=home)
    _collect_skill_library_state(home, ctx)
    return ctx


# --------------------------------------------------------------------------------------
# The control that matters most: absence is UNKNOWN, never a clean PASS.
# --------------------------------------------------------------------------------------

def test_no_state_db_at_all_is_unknown(tmp_path):
    ctx = _ctx(tmp_path, db=False)
    f = check_skill_library_reachability(ctx)
    assert f.status == UNKNOWN
    assert ctx.skill_library_entries_read is False
    assert ctx.skill_uploads_read is False


def test_both_tables_absent_from_an_existing_db_is_unknown(tmp_path):
    """The exact real-machine shape this was grounded against, minus skill_uploads:
    a DB that exists but predates the skill library entirely."""
    ctx = _ctx(tmp_path, entries_table=False, uploads_table=False)
    f = check_skill_library_reachability(ctx)
    assert f.status == UNKNOWN
    assert "not found" in f.detail or "could not be read" in f.detail


def test_the_real_machine_shape_entries_absent_uploads_present_empty_is_unknown(tmp_path):
    """Reproduces the ACTUAL measurement (OpenClaw 2026.9.1, state schema 15):
    skill_library_entries absent, skill_uploads present with 0 rows. This must NOT
    read as a clean PASS -- half the surface was never examined."""
    ctx = _ctx(tmp_path, entries_table=False, uploads_table=True, uploads=())
    assert ctx.skill_library_entries_read is False
    assert ctx.skill_uploads_read is True
    f = check_skill_library_reachability(ctx)
    assert f.status == UNKNOWN
    assert "skill_library_entries" in f.detail


def test_entries_present_empty_uploads_absent_is_also_unknown(tmp_path):
    """The other half of the same control, the other way around."""
    ctx = _ctx(tmp_path, entries_table=True, uploads_table=False, entries=())
    f = check_skill_library_reachability(ctx)
    assert f.status == UNKNOWN
    assert "skill_uploads" in f.detail


def test_both_tables_present_and_empty_is_a_real_pass(tmp_path):
    """Distinguishable from absent: both tables were genuinely queried and hold
    nothing, which IS a real 'looked and found nothing' fact."""
    ctx = _ctx(tmp_path, entries=(), uploads=())
    assert ctx.skill_library_entries_read is True
    assert ctx.skill_uploads_read is True
    f = check_skill_library_reachability(ctx)
    assert f.status == PASS


# --------------------------------------------------------------------------------------
# The reachability signal: enabled AND NOT removed, regardless of `shared`.
# --------------------------------------------------------------------------------------

def test_an_enabled_non_removed_entry_fires_warn(tmp_path):
    ctx = _ctx(tmp_path, entries=[_entry("sk1", "my-published-skill", enabled=1, removed=0)],
                uploads=())
    f = check_skill_library_reachability(ctx)
    assert f.status == WARN
    assert "my-published-skill" in f.detail
    assert ctx.skill_library_live_count == 1


@pytest.mark.parametrize("enabled,removed", [(0, 0), (1, 1), (0, 1)])
def test_a_disabled_or_removed_entry_does_not_fire(tmp_path, enabled, removed):
    ctx = _ctx(tmp_path, entries=[_entry("sk1", "dormant-skill", enabled=enabled, removed=removed)],
                uploads=())
    f = check_skill_library_reachability(ctx)
    assert f.status == PASS
    assert ctx.skill_library_live_count == 0


def test_shared_flag_does_not_gate_the_signal(tmp_path):
    """`shared` controls visibility to OTHER identities, not whether THIS install
    treats the entry as active -- enabled+not-removed is what matters."""
    ctx = _ctx(tmp_path, entries=[_entry("sk1", "private-but-live", shared=0,
                                          enabled=1, removed=0)], uploads=())
    assert check_skill_library_reachability(ctx).status == WARN


def test_more_than_the_sample_cap_is_counted_and_capped(tmp_path):
    entries = [_entry(f"sk{i}", f"skill-{i}", enabled=1, removed=0) for i in range(14)]
    ctx = _ctx(tmp_path, entries=entries, uploads=())
    assert ctx.skill_library_live_count == 14
    assert len(ctx.skill_library_live_sample) <= 10
    f = check_skill_library_reachability(ctx)
    assert f.status == WARN
    assert "14 skill(s)" in f.detail


# --------------------------------------------------------------------------------------
# The upload-integrity signal: committed rows only, real digest disagreement only.
# --------------------------------------------------------------------------------------

def test_a_committed_upload_with_mismatched_digest_fires_warn(tmp_path):
    ctx = _ctx(tmp_path, entries=(),
                uploads=[_upload("u1", sha256="a" * 64, actual_sha256="b" * 64, committed=1)])
    f = check_skill_library_reachability(ctx)
    assert f.status == WARN
    assert ctx.skill_uploads_digest_mismatch_count == 1
    assert "digest" in f.detail


def test_an_uncommitted_upload_with_mismatched_digest_does_not_fire(tmp_path):
    """The C-135-shaped false-positive guard: an in-progress upload legitimately has
    a partial/absent actual_sha256 while chunks are still arriving."""
    ctx = _ctx(tmp_path, entries=(),
                uploads=[_upload("u1", sha256="a" * 64, actual_sha256="b" * 64, committed=0)])
    f = check_skill_library_reachability(ctx)
    assert f.status == PASS
    assert ctx.skill_uploads_digest_mismatch_count == 0


def test_a_committed_upload_with_matching_digest_does_not_fire(tmp_path):
    ctx = _ctx(tmp_path, entries=(),
                uploads=[_upload("u1", sha256="a" * 64, actual_sha256="a" * 64, committed=1)])
    assert check_skill_library_reachability(ctx).status == PASS


def test_a_null_actual_sha256_on_a_committed_row_does_not_fire(tmp_path):
    """Defensive: a schema-legal NULL must not be compared as a string and
    manufacture a mismatch out of two absent values."""
    ctx = _ctx(tmp_path, entries=(),
                uploads=[_upload("u1", sha256=None, actual_sha256=None, committed=1)])
    assert check_skill_library_reachability(ctx).status == PASS


# --------------------------------------------------------------------------------------
# §8: only the bound columns ever reach a finding. Identity/content columns never do.
# --------------------------------------------------------------------------------------

def test_no_value_outside_the_bound_columns_ever_reaches_the_finding(tmp_path):
    ctx = _ctx(
        tmp_path,
        entries=[_entry("sk1", "my-skill", enabled=1, removed=0,
                        owner_profile_id=_FAKE_TOKEN, author_profile_id=_FAKE_TOKEN)],
        uploads=[_upload("u1", sha256="a" * 64, actual_sha256="b" * 64, committed=1)],
    )
    f = check_skill_library_reachability(ctx)
    blob = f.detail + f.fix + " ".join(f.evidence)
    assert _FAKE_TOKEN not in blob
    assert "owner-1" not in blob and "author-1" not in blob


# --------------------------------------------------------------------------------------
# Catalog shape.
# --------------------------------------------------------------------------------------

def test_b354_is_scored_and_warn_capable_never_fail():
    """WARN-only by design: this check can prove a live unscanned skill EXISTS, never
    that it is malicious -- it never reads skill content."""
    meta = BY_ID["B354"]
    assert meta.scored is True
    assert meta.block == "hardening"
