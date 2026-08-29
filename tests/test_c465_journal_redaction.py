"""CLAWSECCHECK-C-465 — the permanent channel must not be protected less than the screen.

`record_events` wrote the alert message verbatim. Both transient channels redact: the text
renderer and `--monitor --json` run every message through `report._sanitize`, which calls
`logsafe.redact`, and that helper's comment says why it is one shared point — "secret
redaction cannot be accidentally implemented for JSON while remaining absent from
text/SARIF/HTML". The journal is not a renderer, so it sat outside that boundary, and it is
the one channel that is append-only and hash-chained: a value leaked there is permanent.

No live leak today — redaction is done at the source. This is the net that makes a future
secret-bearing dimension (B-677's credential store, for one) safe by construction.

Secret-shaped values are assembled at runtime from fragments so no contiguous literal
exists in this file (CLAUDE.md section 2.3). Offline, read-only, tmp_path only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.monitorstore import record_events, verify_chain


def _secretish() -> str:
    """A token shape `logsafe.redact` recognises, built so the file contains no literal."""
    return "sk-" + "ant-" + "api03-" + ("A" * 40)


def _entries(path: Path) -> list:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def test_a_secret_in_an_alert_never_reaches_the_journal(tmp_path):
    token = _secretish()
    events = tmp_path / "events.jsonl"
    assert record_events([("HIGH", f"Server 'x' now launches with token {token}")],
                         events) is None
    body = events.read_text(encoding="utf-8")
    assert token not in body, "the raw token was written to the tamper-evident journal"
    assert "<redacted>" in body


def test_the_call_site_is_what_is_pinned(tmp_path, monkeypatch):
    """Mutating the HELPER proves nothing — `logsafe.redact` has its own tests and would
    stay green with the call deleted. This asserts the wiring: replace `redact` with a
    marker and require the marker to appear in what `record_events` actually wrote."""
    import clawseccheck.logsafe as logsafe
    monkeypatch.setattr(logsafe, "redact", lambda text: "MARKER::" + (text or ""))
    events = tmp_path / "events.jsonl"
    record_events([("HIGH", "anything at all")], events)
    assert _entries(events)[0]["message"].startswith("MARKER::"), (
        "record_events did not route the message through logsafe.redact")


def test_ordinary_alert_text_is_untouched(tmp_path):
    """Anti-vacuity, and the false-positive direction: redaction must not mangle the
    sentences every real alert is made of. An IP is not a card number and a version is not
    a token, which is why `redact` Luhn-checks its PAN candidates."""
    plain = "Gateway bind changed: '127.0.0.1' -> '0.0.0.0' (now exposed to the network!)"
    events = tmp_path / "events.jsonl"
    record_events([("CRITICAL", plain)], events)
    assert _entries(events)[0]["message"] == plain


def test_redaction_is_idempotent_so_a_source_redacted_value_is_unchanged(tmp_path):
    """`monitordims/_mcp.py` already redacts URLs before they enter the snapshot, so a
    message can arrive here carrying `<redacted>`. Applying it twice must not corrupt it —
    the same property `_mcp.py:332` relies on when it re-applies redaction before
    comparing."""
    already = "Server 'x' url changed to https://<redacted>@example.invalid/"
    events = tmp_path / "events.jsonl"
    record_events([("HIGH", already)], events)
    assert _entries(events)[0]["message"] == already


def test_the_chain_still_verifies_across_the_change(tmp_path):
    """The hash is taken over the entry as written, so redaction changes what NEW entries
    hash — and nothing else. A journal spanning both must still verify."""
    events = tmp_path / "events.jsonl"
    record_events([("LOW", "first, written before")], events)
    record_events([("HIGH", f"second, carrying {_secretish()}")], events)
    record_events([("LOW", "third, written after")], events)
    ok, detail = verify_chain(events)
    assert ok, detail
    assert len(_entries(events)) == 3


def test_a_non_string_message_does_not_take_the_run_down(tmp_path):
    """`record_events` never raises — `tests/test_symlink_safety.py` pins that a planted
    symlink must not take a monitor run down, and a malformed alert must not either."""
    events = tmp_path / "events.jsonl"
    assert record_events([("LOW", None)], events) is None
    assert _entries(events)[0]["message"] == ""
