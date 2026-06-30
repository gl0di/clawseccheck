"""BLK-03: Verify that all output channels sanitize untrusted finding fields.

Hostile skill names / file content can embed ANSI escape sequences, OSC-52
clipboard sequences, Unicode bidi overrides, and zero-width characters to
attack the terminal or spoof displayed text.  All rendering paths
(render_prompts, render_json, render_sarif, render_html) must strip these
before output.

Sequences are assembled from escape literals at runtime so no contiguous
control-byte literal exists in source (CLAUDE.md §2 rule 3 — secret-scanner
hygiene applies equally to hostile-payload literals in tests).
"""
from __future__ import annotations

import json

from clawseccheck.catalog import FAIL, HIGH, Finding
from clawseccheck.report import render_html, render_json, render_prompts
from clawseccheck.sarif import render_sarif
from clawseccheck.scoring import compute

# ---------------------------------------------------------------------------
# Hostile payload fragments — assembled at runtime, never stored as literals
# ---------------------------------------------------------------------------

# OSC-52 clipboard-write sequence: ESC ] 52 ; c ; <base64> BEL
_ESC = "\x1b"
_BEL = "\x07"
_OSC52 = _ESC + "]52;c;dGVzdA==" + _BEL   # would write "test" to clipboard

# ANSI SGR bold sequence: ESC [ 1 m
_ANSI_BOLD = _ESC + "[1m"

# Unicode bidi right-to-left override (U+202E) — reverses displayed text
_BIDI = "‮"

# Zero-width space (U+200B) — invisible glyph used to break word matching
_ZWS = "​"


# ---------------------------------------------------------------------------
# Helper: build a hostile Finding
# ---------------------------------------------------------------------------

def _hostile_finding(suffix: str = "") -> Finding:
    """Return a FAIL Finding whose title/detail/fix embed all four hostile chars."""
    hostile = _ANSI_BOLD + _OSC52 + _BIDI + _ZWS + "evil-payload" + suffix
    return Finding(
        id="B2",
        title="Hostile title " + hostile,
        severity=HIGH,
        status=FAIL,
        detail="Hostile detail " + hostile,
        fix="Hostile fix " + hostile,
        framework="Test",
        scored=True,
        evidence=[],
        suppressed=False,
    )


def _score(findings):
    return compute(findings)


# ---------------------------------------------------------------------------
# render_prompts — terminal / agent injection channel
# ---------------------------------------------------------------------------

def test_render_prompts_strips_ansi_osc52():
    """render_prompts must remove ESC bytes and OSC sequences from finding fields."""
    f = _hostile_finding()
    out = render_prompts([f])
    assert _ESC not in out, "ESC byte leaked into render_prompts output"
    assert _BEL not in out, "BEL byte from OSC-52 leaked into render_prompts output"
    # Confirm the benign text still reaches the output
    assert "evil-payload" in out


def test_render_prompts_strips_bidi_and_zerowidth():
    """render_prompts must remove bidi overrides and zero-width characters."""
    f = _hostile_finding()
    out = render_prompts([f])
    assert _BIDI not in out, "Bidi override (U+202E) leaked into render_prompts output"
    assert _ZWS not in out, "Zero-width space (U+200B) leaked into render_prompts output"


def test_render_prompts_has_untrusted_boundary():
    """render_prompts must include the untrusted-data boundary warning."""
    f = _hostile_finding()
    out = render_prompts([f])
    # The boundary phrase must contain the key word "untrusted" and clarify
    # that the content is data, not instructions.
    assert "untrusted" in out.lower(), (
        "render_prompts output is missing the untrusted-data boundary line"
    )
    assert "not instructions" in out.lower() or "data, not" in out.lower(), (
        "render_prompts boundary line does not clarify that content is data, not instructions"
    )


def test_render_prompts_empty_findings_unaffected():
    """render_prompts with no FAIL/WARN findings must still return the nothing-to-fix message."""
    out = render_prompts([])
    assert "Nothing to fix" in out or "nothing" in out.lower()


# ---------------------------------------------------------------------------
# render_json — JSON API channel
# ---------------------------------------------------------------------------

def test_json_sanitizes_finding_fields():
    """render_json must strip ANSI/OSC/bidi/zero-width from title, detail, and fix."""
    f = _hostile_finding()
    out = render_json([f], _score([f]))
    payload = json.loads(out)
    finding = payload["findings"][0]

    for field_name in ("title", "detail", "fix"):
        value = finding[field_name]
        assert _ESC not in value, (
            f"render_json finding.{field_name} contains raw ESC byte"
        )
        assert _BIDI not in value, (
            f"render_json finding.{field_name} contains bidi override"
        )
        assert _ZWS not in value, (
            f"render_json finding.{field_name} contains zero-width space"
        )
    # Payload text must still carry the benign content
    assert "evil-payload" in finding["title"]


def test_json_sanitizes_action_title_and_command():
    """render_json must sanitize next_actions title and command."""
    f = _hostile_finding()
    out = render_json([f], _score([f]))
    payload = json.loads(out)
    for action in payload.get("next_actions", []):
        for key in ("title", "command"):
            val = action.get(key, "")
            assert _ESC not in val, (
                f"render_json next_actions[].{key} contains raw ESC byte"
            )


# ---------------------------------------------------------------------------
# render_sarif — SARIF output channel
# ---------------------------------------------------------------------------

def test_sarif_sanitizes_message_text():
    """render_sarif must strip ANSI/OSC/bidi/zero-width from result message text."""
    f = _hostile_finding()
    out = render_sarif([f], _score([f]))
    doc = json.loads(out)
    results = doc["runs"][0]["results"]
    assert len(results) == 1, "Expected one SARIF result for the FAIL finding"
    msg = results[0]["message"]["text"]

    assert _ESC not in msg, "render_sarif message.text contains raw ESC byte"
    assert _BIDI not in msg, "render_sarif message.text contains bidi override"
    assert _ZWS not in msg, "render_sarif message.text contains zero-width space"
    assert "evil-payload" in msg


def test_sarif_fallback_to_title_is_also_sanitized():
    """When detail is empty, render_sarif falls back to title — title must be sanitized too."""
    hostile = _ANSI_BOLD + _OSC52 + _BIDI + _ZWS + "evil-title"
    f = Finding(
        id="B2",
        title="Title: " + hostile,
        severity=HIGH,
        status=FAIL,
        detail="",   # force fallback to title
        fix="fix",
        framework="Test",
        scored=True,
        evidence=[],
        suppressed=False,
    )
    out = render_sarif([f], _score([f]))
    doc = json.loads(out)
    msg = doc["runs"][0]["results"][0]["message"]["text"]

    assert _ESC not in msg, "render_sarif title-fallback contains raw ESC byte"
    assert _BIDI not in msg, "render_sarif title-fallback contains bidi override"
    assert _ZWS not in msg, "render_sarif title-fallback contains zero-width space"
    assert "evil-title" in msg


# ---------------------------------------------------------------------------
# render_html — HTML channel (must strip bidi/zero-width before html.escape)
# ---------------------------------------------------------------------------

def test_html_sanitizes_bidi_and_zerowidth_before_escaping():
    """render_html must call _sanitize() before html.escape() so bidi/ZWS are stripped."""
    f = _hostile_finding()
    score_obj = type("ScoreResult", (), {
        "score": 50,
        "grade": "D",
        "capped": False,
        "raw_score": 50,
        "failed_critical": 0,
        "failed_high": 1,
    })()
    out = render_html([f], score_obj)

    assert _BIDI not in out, "render_html output contains bidi override"
    assert _ZWS not in out, "render_html output contains zero-width space"
    # html.escape converts & < > — confirm the title still appears (escaped)
    assert "Hostile title" in out


def test_html_strips_ansi_and_osc52():
    """render_html must strip ANSI escape and OSC sequences from finding fields."""
    f = _hostile_finding()
    score_obj = type("ScoreResult", (), {
        "score": 50,
        "grade": "D",
        "capped": False,
        "raw_score": 50,
        "failed_critical": 0,
        "failed_high": 1,
    })()
    out = render_html([f], score_obj)

    assert _ESC not in out, "render_html output contains raw ESC byte"
    assert _BEL not in out, "render_html output contains BEL byte from OSC-52"
