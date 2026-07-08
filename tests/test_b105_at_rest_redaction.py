"""B-105 — redaction must hold AT REST, not just at display time.

monitor.py wrote MCP url/command/args0 and memory-file URLs verbatim into state.json and
events.jsonl. MCP URLs routinely embed credentials (https://user:token@host, ?api_key=…),
so a privacy-branded tool was copying secrets into a second plaintext file that persists
forever and is exactly what a user attaches to a drift-alert report.

The fix sanitizes at the point values ENTER the snapshot (_mcp_detail_sig,
_extract_memory_signals), so state.json never holds the secret and every drift alert built
from those fields inherits the redaction. Host-level drift (the security signal) is
preserved; only the secret-bearing parts collapse. Offline, stdlib only.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from clawseccheck.monitor import (
    _extract_memory_signals,
    _mcp_detail_sig,
    diff,
    record_events,
    save_state,
)

# secret-shaped values assembled from fragments so no contiguous literal exists in source
# (Golden Rule #3) — these stand in for real credentials embedded in URLs.
_URL_TOK = "s3cr" + "et" + "Tok" + "en42"
_QRY_KEY = "ap" + "ikey" + "V4lue"
_ARG_TOK = "arg" + "Tok" + "en99"
_MEM_TOK = "mem" + "Tok" + "en77"
_HOST = "evil.example.com"


def _ctx(url_host: str = _HOST) -> SimpleNamespace:
    return SimpleNamespace(config={
        "mcp": {"servers": {"srv": {
            "url": f"https://user:{_URL_TOK}@{url_host}/path?api_key={_QRY_KEY}",
            "command": "npx",
            "args": [f"--registry=https://{_ARG_TOK}@reg.example.com/", "pkg"],
            "transport": "stdio",
        }}}
    })


def test_mcp_detail_sig_redacts_url_and_args_at_source():
    sig = _mcp_detail_sig(_ctx())
    blob = json.dumps(sig)
    assert sig, "expected the MCP server to be captured"
    for secret in (_URL_TOK, _QRY_KEY, _ARG_TOK):
        assert secret not in blob, f"{secret!r} leaked into the snapshot: {blob}"
    # host-only forms survive so drift detection still works
    assert _HOST in blob and "reg.example.com" in blob


def test_memory_urls_reduced_to_host_only():
    sig = _extract_memory_signals(
        f"See notes at https://user:{_MEM_TOK}@mem.example.com/x?api_key={_QRY_KEY} for more."
    )
    blob = json.dumps(sig)
    assert _MEM_TOK not in blob and _QRY_KEY not in blob, blob
    assert sig["urls"] == ["https://mem.example.com"], sig["urls"]


def test_state_json_on_disk_holds_no_secret(tmp_path):
    # end-to-end: snapshot the MCP detail into a state.json and read the raw bytes back.
    snap = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "mcp_detail": _mcp_detail_sig(_ctx())}
    state = tmp_path / "state.json"
    save_state(state, snap)
    raw = state.read_text(encoding="utf-8")
    for secret in (_URL_TOK, _QRY_KEY, _ARG_TOK):
        assert secret not in raw, f"{secret!r} persisted at rest in state.json"
    assert _HOST in raw  # host preserved for drift


def test_events_jsonl_on_disk_holds_no_secret(tmp_path):
    # An RP3 endpoint repoint builds a HIGH alert from the (already sanitized) url fields.
    prev = {"mcp_detail": _mcp_detail_sig(_ctx(url_host="old.example.com"))}
    curr = {"mcp_detail": _mcp_detail_sig(_ctx(url_host="new.example.com"))}
    # wrap in the shape diff() expects
    for s in (prev, curr):
        s.update({"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}})
    alerts = diff(prev, curr)
    assert alerts, "expected an RP3 url-repoint alert"
    events = tmp_path / "events.jsonl"
    record_events(alerts, path=events, when="2026-07-05T00:00:00")
    raw = events.read_text(encoding="utf-8")
    for secret in (_URL_TOK, _QRY_KEY, _ARG_TOK):
        assert secret not in raw, f"{secret!r} persisted at rest in events.jsonl"
    assert "old.example.com" in raw and "new.example.com" in raw  # host drift preserved


# ---------------------------------------------------------------------------
# C-178 — RP2/RP3 must not false-positive across the redaction-format boundary
# ---------------------------------------------------------------------------

def test_rp3_no_false_positive_when_prev_snapshot_predates_redaction():
    """A prev state.json written by a pre-cde6798 build still holds the RAW url
    (this commit's own fix landed AFTER some users' state.json was written).
    The very next --monitor run after upgrading must not treat "raw url" vs.
    "same endpoint, now sanitized" as a rug-pull — same host, no real change."""
    curr_sig = _mcp_detail_sig(_ctx(url_host="api.example.com"))
    # Simulate a pre-redaction snapshot: same server, RAW (unsanitized) url.
    prev_sig = json.loads(json.dumps(curr_sig))
    prev_sig["srv"]["url"] = f"https://user:{_URL_TOK}@api.example.com/mcp?api_key={_QRY_KEY}"

    prev = {"mcp_detail": prev_sig}
    curr = {"mcp_detail": curr_sig}
    for s in (prev, curr):
        s.update({"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}})

    alerts = diff(prev, curr)
    rp3 = [a for a in alerts if "RP3" in a[1]]
    assert not rp3, f"unexpected RP3 false-positive across a migration boundary: {rp3}"


def test_rp3_still_fires_and_never_echoes_stale_credential_on_a_real_repoint():
    """A REAL endpoint change (old.example.com -> new.example.com) must still
    fire RP3 even when the prev snapshot predates redaction — and the alert
    text must never contain the stale raw credential from the old snapshot."""
    curr_sig = _mcp_detail_sig(_ctx(url_host="new.example.com"))
    prev_sig = json.loads(json.dumps(curr_sig))
    prev_sig["srv"]["url"] = f"https://user:{_URL_TOK}@old.example.com/mcp?api_key={_QRY_KEY}"

    prev = {"mcp_detail": prev_sig}
    curr = {"mcp_detail": curr_sig}
    for s in (prev, curr):
        s.update({"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}})

    alerts = diff(prev, curr)
    rp3 = [a for a in alerts if "RP3" in a[1]]
    assert rp3, "expected RP3 to fire on a genuine endpoint repoint"
    blob = " ".join(a[1] for a in rp3)
    assert _URL_TOK not in blob and _QRY_KEY not in blob, blob
    assert "old.example.com" in blob and "new.example.com" in blob


def test_rp2_no_false_positive_when_prev_command_predates_redaction():
    """Same migration-boundary issue for RP2's command/args0 comparison."""
    curr_sig = _mcp_detail_sig(_ctx())
    prev_sig = json.loads(json.dumps(curr_sig))
    prev_sig["srv"]["args0"] = f"--registry=https://{_ARG_TOK}@reg.example.com/"

    prev = {"mcp_detail": prev_sig}
    curr = {"mcp_detail": curr_sig}
    for s in (prev, curr):
        s.update({"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}})

    alerts = diff(prev, curr)
    rp2 = [a for a in alerts if "RP2" in a[1]]
    assert not rp2, f"unexpected RP2 false-positive across a migration boundary: {rp2}"
