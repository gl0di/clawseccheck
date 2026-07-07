"""B20 Bootstrap / memory write protection tests."""
from pathlib import Path

from clawseccheck.checks import check_bootstrap_write_protection
from clawseccheck.collector import Context, collect
from clawseccheck.catalog import LOW, MEDIUM

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home):
    c = Context(home=Path(home))
    c.config = {}
    c.bootstrap = {}
    return c


def _ws(tmp_path):
    """Create workspace dir and return it."""
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


# ---- world-writable SOUL.md -> FAIL ----
def test_b20_world_writable_soul_fails(tmp_path):
    ws = _ws(tmp_path)
    soul = ws / "SOUL.md"
    soul.write_text("identity")
    soul.chmod(0o644)          # start tight
    soul.chmod(0o646)          # world-write (o+w)
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "FAIL"
    assert result.id == "B20"
    assert any("SOUL.md" in e for e in result.evidence)


# ---- world-writable parent workspace dir with tight SOUL.md -> FAIL ----
def test_b20_world_writable_parent_dir_fails(tmp_path):
    ws = _ws(tmp_path)
    soul = ws / "SOUL.md"
    soul.write_text("identity")
    soul.chmod(0o600)          # file itself is tight
    ws.chmod(0o757)            # workspace dir is world-writable
    try:
        result = check_bootstrap_write_protection(_ctx(tmp_path))
        assert result.status == "FAIL"
        assert result.id == "B20"
        assert any("workspace/" in e for e in result.evidence)
    finally:
        ws.chmod(0o755)        # restore so tmp_path cleanup can proceed


# ---- world-writable MEMORY.md -> WARN (soft bootstrap) ----
def test_b20_world_writable_memory_warns(tmp_path):
    ws = _ws(tmp_path)
    mem = ws / "MEMORY.md"
    mem.write_text("memories")
    mem.chmod(0o646)           # world-write
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "WARN"
    assert result.id == "B20"


# ---- group-writable MEMORY.md -> WARN ----
def test_b20_group_writable_memory_warns(tmp_path):
    ws = _ws(tmp_path)
    mem = ws / "MEMORY.md"
    mem.write_text("memories")
    mem.chmod(0o664)           # group-write
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "WARN"
    assert result.id == "B20"


# ---- Windows / non-POSIX -> UNKNOWN ----
def test_b20_windows_is_unknown(monkeypatch, tmp_path):
    from clawseccheck import checks
    monkeypatch.setattr(checks._shared, "_is_posix", lambda: False)
    ws = _ws(tmp_path)
    (ws / "SOUL.md").write_text("identity")
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "UNKNOWN"


# ---- no bootstrap files at all -> UNKNOWN ----
def test_b20_no_files_unknown(tmp_path):
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "UNKNOWN"


# ---- UNKNOWN must guide the user to --home / --attest, not dead-end ----
def test_b20_unknown_message_is_actionable(tmp_path):
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "UNKNOWN"
    text = f"{result.detail} {result.fix}"
    assert "--home" in text
    assert "--attest" in text
    # must not be the old dead-end placeholder
    assert result.fix.strip() != "—"


# ---- B-127: group-writable, but group has NO other members -> WARN downgraded to LOW ----
def test_b20_group_writable_singleton_group_is_low_severity(monkeypatch, tmp_path):
    from clawseccheck import checks
    monkeypatch.setattr(checks._shared, "_group_has_other_members", lambda gid, uid: False)
    ws = _ws(tmp_path)
    mem = ws / "MEMORY.md"
    mem.write_text("memories")
    mem.chmod(0o664)           # group-write
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "WARN"
    assert result.id == "B20"
    assert result.severity == LOW
    assert "no other group members" in result.detail.lower()
    # must not assert an active exploit threat when there is no other member
    assert "members of the" not in result.detail.lower()


# ---- B-127: group-writable, group HAS other members -> unchanged WARN/MEDIUM behavior ----
def test_b20_group_writable_multi_member_group_stays_medium_warn(monkeypatch, tmp_path):
    from clawseccheck import checks
    monkeypatch.setattr(checks._shared, "_group_has_other_members", lambda gid, uid: True)
    ws = _ws(tmp_path)
    mem = ws / "MEMORY.md"
    mem.write_text("memories")
    mem.chmod(0o664)           # group-write
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "WARN"
    assert result.id == "B20"
    assert result.severity == MEDIUM
    assert "can overwrite agent identity/memory" in result.detail.lower()


# ---- B-127: group membership UNKNOWN (grp/pwd unavailable) -> unchanged WARN/MEDIUM ----
def test_b20_group_writable_membership_unknown_stays_medium_warn(monkeypatch, tmp_path):
    from clawseccheck import checks
    monkeypatch.setattr(checks._shared, "_group_has_other_members", lambda gid, uid: None)
    ws = _ws(tmp_path)
    mem = ws / "MEMORY.md"
    mem.write_text("memories")
    mem.chmod(0o664)           # group-write
    result = check_bootstrap_write_protection(_ctx(tmp_path))
    assert result.status == "WARN"
    assert result.severity == MEDIUM


# ---- B-127: end-to-end clean fixture via the real collector/audit path ----
def test_b20_clean_fixture_singleton_group_write_end_to_end(monkeypatch):
    """clean_b127_singleton_group_write: a real on-disk MEMORY.md, chmod'd group-writable
    at runtime (perms are not portable through git) with the group-membership lookup
    mocked to a deterministic singleton, through the real collect() -> check ->
    LOW-severity, reworded-hygiene path (rather than an unmockable dependency on this
    box's actual /etc/group contents)."""
    from clawseccheck import checks
    monkeypatch.setattr(checks._shared, "_group_has_other_members", lambda gid, uid: False)
    fixture_dir = FIXTURES / "clean_b127_singleton_group_write"
    mem = fixture_dir / "workspace" / "MEMORY.md"
    mem.chmod(0o664)  # group-write
    try:
        ctx = collect(fixture_dir)
        result = check_bootstrap_write_protection(ctx)
        assert result.status == "WARN"
        assert result.severity == LOW
        assert "no other group members" in result.detail.lower()
    finally:
        mem.chmod(0o644)  # restore to a fixed, non-group-writable mode for git cleanliness


# ---- tight perms on all bootstrap files -> PASS ----
def test_b20_tight_perms_passes(tmp_path):
    ws = _ws(tmp_path)
    ws.chmod(0o700)
    for fname in ("SOUL.md", "AGENTS.md", "TOOLS.md", "MEMORY.md", "HEARTBEAT.md"):
        f = ws / fname
        f.write_text(f"# {fname}")
        f.chmod(0o600)
    try:
        result = check_bootstrap_write_protection(_ctx(tmp_path))
        assert result.status == "PASS"
    finally:
        ws.chmod(0o755)        # restore for cleanup
