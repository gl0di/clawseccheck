"""B20 Bootstrap / memory write protection tests."""
from pathlib import Path

from clawseccheck.checks import check_bootstrap_write_protection
from clawseccheck.collector import Context


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
