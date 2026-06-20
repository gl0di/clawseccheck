"""Agent Watch (0.24): connection/trust-surface drift + the event journal.

Extends --monitor to watch MCP servers, channels and the gateway bind, and to
append each change to a local owner-only event journal. Offline, deterministic.
"""
from __future__ import annotations

from clawseccheck import audit, diff, load_events, record_events, snapshot
from clawseccheck.report import render_events

_BASE = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
         "mcp": {}, "channels": {}, "gateway_bind": "127.0.0.1"}


def _with(**kw):
    d = dict(_BASE)
    d.update(kw)
    return d


def _levels(alerts):
    return [lvl for lvl, _ in alerts]


# ---------------------------------------------------------------------------
# MCP / channel / gateway drift
# ---------------------------------------------------------------------------

def test_new_mcp_server_is_critical():
    a = diff(_BASE, _with(mcp={"srv": "h1"}))
    assert "CRITICAL" in _levels(a)
    assert any("MCP server" in m and "srv" in m for _, m in a)


def test_changed_mcp_server_is_high():
    a = diff(_with(mcp={"srv": "h1"}), _with(mcp={"srv": "h2"}))
    assert "HIGH" in _levels(a)
    assert any("CHANGED" in m for _, m in a)


def test_removed_mcp_server_is_info():
    a = diff(_with(mcp={"srv": "h1"}), _BASE)
    assert any(lvl == "INFO" and "removed" in m for lvl, m in a)


def test_new_channel_is_high():
    a = diff(_BASE, _with(channels={"tg": "c1"}))
    assert "HIGH" in _levels(a)
    assert any("channel" in m and "tg" in m for _, m in a)


def test_changed_channel_is_medium():
    a = diff(_with(channels={"tg": "c1"}), _with(channels={"tg": "c2"}))
    assert "MEDIUM" in _levels(a)


def test_gateway_exposed_is_critical():
    a = diff(_BASE, _with(gateway_bind="0.0.0.0"))
    assert "CRITICAL" in _levels(a)
    assert any("exposed" in m for _, m in a)


def test_gateway_change_to_other_loopback_is_high_not_critical():
    a = diff(_BASE, _with(gateway_bind="192.168.1.5"))
    assert "HIGH" in _levels(a)
    assert "CRITICAL" not in _levels(a)


def test_host_monitor_lost_is_high():
    prev = _with(host={"network_ids": "present"})
    curr = _with(host={"network_ids": "absent"})
    a = diff(prev, curr)
    assert "HIGH" in _levels(a)
    assert any("no longer detected" in m for _, m in a)


# ---------------------------------------------------------------------------
# upgrade safety: an old snapshot without the new keys must not spew alerts
# ---------------------------------------------------------------------------

def test_old_snapshot_without_mcp_key_no_spurious_alert():
    old = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}}
    new = _with(mcp={"srv": "h1"}, channels={"tg": "c1"})
    a = diff(old, new)
    # no mcp/channels/gateway keys in `old` -> those diffs are skipped entirely
    assert not any("MCP server" in m or "channel" in m or "Gateway bind" in m for _, m in a)


def test_identical_real_snapshots_no_alerts(tmp_path):
    (tmp_path / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}')
    ctx, f, s = audit(tmp_path)
    snap = snapshot(ctx, f, s)
    assert diff(snap, dict(snap)) == []


def test_snapshot_captures_connection_surface(tmp_path):
    (tmp_path / "openclaw.json").write_text(
        '{"gateway": {"bind": "0.0.0.0"}, "channels": {"tg": {"dmPolicy": "open"}}}')
    ctx, f, s = audit(tmp_path)
    snap = snapshot(ctx, f, s)
    assert "mcp" in snap and "channels" in snap and "gateway_bind" in snap
    assert snap["gateway_bind"] == "0.0.0.0"
    assert "tg" in snap["channels"]


# ---------------------------------------------------------------------------
# event journal
# ---------------------------------------------------------------------------

def test_journal_roundtrip_and_order(tmp_path):
    p = tmp_path / "events.jsonl"
    record_events([("HIGH", "first")], p, when="2026-06-20T10:00:00")
    record_events([("CRITICAL", "second")], p, when="2026-06-20T11:00:00")
    ev = load_events(p)
    assert [e["message"] for e in ev] == ["first", "second"]  # chronological append
    assert ev[0]["level"] == "HIGH" and ev[1]["ts"] == "2026-06-20T11:00:00"


def test_journal_no_alerts_is_noop(tmp_path):
    p = tmp_path / "events.jsonl"
    record_events([], p, when="2026-06-20T10:00:00")
    assert not p.exists()
    assert load_events(p) == []


def test_journal_limit(tmp_path):
    p = tmp_path / "events.jsonl"
    record_events([("INFO", f"e{i}") for i in range(5)], p, when="2026-06-20T10:00:00")
    assert [e["message"] for e in load_events(p, limit=2)] == ["e3", "e4"]


def test_render_events_empty_and_nonempty():
    assert "No recorded change" in render_events([])
    out = render_events([{"ts": "2026-06-20T10:00:00", "level": "CRITICAL", "message": "boom"}])
    assert "boom" in out and "2026-06-20T10:00:00" in out


def test_journal_file_is_owner_only(tmp_path):
    import os
    import stat
    p = tmp_path / "events.jsonl"
    record_events([("HIGH", "x")], p, when="2026-06-20T10:00:00")
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600
