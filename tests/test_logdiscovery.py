"""logdiscovery.py — read-only enumeration of the agent's own log/transcript sinks
(F-124/E-044 Phase 1 substrate). Paths only, never file content."""
from __future__ import annotations

from pathlib import Path

from clawseccheck import logdiscovery
from clawseccheck.collector import Context


def _ctx(home: Path, config: dict | None = None) -> Context:
    return Context(home=home, config=config or {})


def _kinds(sinks) -> set:
    return {s.kind for s in sinks}


def test_discover_returns_empty_for_nonexistent_home(tmp_path):
    ctx = _ctx(tmp_path / "does-not-exist")
    assert logdiscovery.discover_log_sinks(ctx) == []


def test_discover_returns_empty_when_home_not_a_path():
    class FakeCtx:
        home = "not-a-path"
        config = {}

    assert logdiscovery.discover_log_sinks(FakeCtx()) == []


def test_discover_finds_config_declared_log_file(tmp_path):
    log_file = tmp_path / "custom.log"
    log_file.write_text("hello\n", encoding="utf-8")
    ctx = _ctx(tmp_path, {"logging": {"file": str(log_file)}})
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert any(s.kind == "config_log" and s.path == log_file and s.source == "config" for s in sinks)


def test_discover_config_log_relative_path_resolved_against_home(tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "rel.log").write_text("x\n", encoding="utf-8")
    ctx = _ctx(tmp_path, {"logging": {"file": "logs/rel.log"}})
    sinks = logdiscovery.discover_log_sinks(ctx)
    matches = [s for s in sinks if s.kind == "config_log" and s.source == "config"]
    assert any(s.path == tmp_path / "logs" / "rel.log" for s in matches)


def test_discover_ignores_config_log_when_unset(tmp_path):
    ctx = _ctx(tmp_path, {})
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert not any(s.source == "config" and s.kind == "config_log" for s in sinks)


def test_discover_ignores_config_log_when_file_missing(tmp_path):
    ctx = _ctx(tmp_path, {"logging": {"file": str(tmp_path / "nope.log")}})
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert not any(s.source == "config" for s in sinks)


def test_discover_finds_cache_trace_sink(tmp_path):
    ct = tmp_path / "cache-trace.jsonl"
    ct.write_text("{}\n", encoding="utf-8")
    ctx = _ctx(tmp_path, {"logging": {"cacheTrace": {"filePath": str(ct)}}})
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert any(s.kind == "cache_trace" and s.path == ct for s in sinks)


def test_discover_finds_trajectory_sinks(tmp_path):
    sess = tmp_path / "agents" / "main" / "sessions"
    sess.mkdir(parents=True)
    traj = sess / "s1.trajectory.jsonl"
    traj.write_text('{"traceSchema": "openclaw-trajectory"}\n', encoding="utf-8")
    ctx = _ctx(tmp_path)
    sinks = logdiscovery.discover_log_sinks(ctx)
    matches = [s for s in sinks if s.kind == "trajectory"]
    assert len(matches) == 1
    assert matches[0].path == traj


def test_discover_transcript_sinks_exclude_trajectory_files(tmp_path):
    """agents/*/sessions/*.jsonl are 'transcript' sinks, but *.trajectory.jsonl files
    under the same directory must be claimed ONLY by the trajectory source, never
    double-counted as a transcript too."""
    sess = tmp_path / "agents" / "main" / "sessions"
    sess.mkdir(parents=True)
    (sess / "s1.trajectory.jsonl").write_text("{}\n", encoding="utf-8")
    (sess / "s1.jsonl").write_text("{}\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    sinks = logdiscovery.discover_log_sinks(ctx)
    transcripts = [s for s in sinks if s.kind == "transcript"]
    trajectories = [s for s in sinks if s.kind == "trajectory"]
    assert len(transcripts) == 1
    assert transcripts[0].path == sess / "s1.jsonl"
    assert len(trajectories) == 1
    assert trajectories[0].path == sess / "s1.trajectory.jsonl"


def test_discover_finds_config_audit_sink(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    audit_log = logs_dir / "config-audit.jsonl"
    audit_log.write_text("{}\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert any(s.kind == "config_audit" and s.path == audit_log for s in sinks)


def test_discover_finds_generic_rotated_logs(tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    ad_hoc = logs_dir / "app.log"
    ad_hoc.write_text("line\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    sinks = logdiscovery.discover_log_sinks(ctx)
    generic = [s for s in sinks if s.kind == "config_log" and s.source == "convention"]
    assert any(s.path == ad_hoc for s in generic)


def test_discover_finds_memory_sinks(tmp_path):
    mem_dir = tmp_path / "workspace-home" / "memory"
    mem_dir.mkdir(parents=True)
    note = mem_dir / "note.md"
    note.write_text("some memory content\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert any(s.kind == "memory" and s.path == note for s in sinks)


def test_discover_finds_install_backup_sinks(tmp_path):
    backup_dir = tmp_path / ".openclaw-install-backups"
    backup_dir.mkdir()
    b = backup_dir / "openclaw.json.bak"
    b.write_text("{}\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert any(s.kind == "backup" and s.path == b for s in sinks)


def test_discover_all_kinds_together(tmp_path):
    """A realistic home with every sink source populated at once — every kind is
    discovered, and the total is exactly one sink per source (no double-counting)."""
    log_file = tmp_path / "custom.log"
    log_file.write_text("x\n", encoding="utf-8")
    ct = tmp_path / "cache-trace.jsonl"
    ct.write_text("{}\n", encoding="utf-8")
    sess = tmp_path / "agents" / "main" / "sessions"
    sess.mkdir(parents=True)
    (sess / "s1.trajectory.jsonl").write_text("{}\n", encoding="utf-8")
    (sess / "s1.jsonl").write_text("{}\n", encoding="utf-8")
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "config-audit.jsonl").write_text("{}\n", encoding="utf-8")
    (logs_dir / "app.log").write_text("x\n", encoding="utf-8")
    mem_dir = tmp_path / "workspace-home" / "memory"
    mem_dir.mkdir(parents=True)
    (mem_dir / "note.md").write_text("x\n", encoding="utf-8")
    backup_dir = tmp_path / ".openclaw-install-backups"
    backup_dir.mkdir()
    (backup_dir / "openclaw.json.bak").write_text("{}\n", encoding="utf-8")

    ctx = _ctx(tmp_path, {"logging": {"file": str(log_file), "cacheTrace": {"filePath": str(ct)}}})
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert _kinds(sinks) == {
        "config_log", "cache_trace", "trajectory", "transcript",
        "config_audit", "memory", "backup",
    }
    # exactly one sink per distinct file — none double-counted
    assert len(sinks) == len({str(s.path) for s in sinks})


def test_discover_symlinked_log_dir_is_ignored(tmp_path):
    real_dir = tmp_path / "real_logs"
    real_dir.mkdir()
    (real_dir / "app.log").write_text("x\n", encoding="utf-8")
    (tmp_path / "logs").symlink_to(real_dir, target_is_directory=True)
    ctx = _ctx(tmp_path)
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert not any(s.kind == "config_log" and s.source == "convention" for s in sinks)


def test_discover_symlinked_log_file_is_ignored(tmp_path):
    real = tmp_path / "real.log"
    real.write_text("x\n", encoding="utf-8")
    ctx = _ctx(tmp_path, {"logging": {"file": str(tmp_path / "link.log")}})
    (tmp_path / "link.log").symlink_to(real)
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert not any(s.source == "config" for s in sinks)


def test_discover_caps_total_sinks(tmp_path, monkeypatch):
    monkeypatch.setattr(logdiscovery, "_MAX_SINKS", 3)
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    for i in range(10):
        (logs_dir / f"app{i}.log").write_text("x\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    sinks = logdiscovery.discover_log_sinks(ctx)
    assert len(sinks) == 3


def test_discover_no_sinks_on_empty_home(tmp_path):
    ctx = _ctx(tmp_path)
    assert logdiscovery.discover_log_sinks(ctx) == []
