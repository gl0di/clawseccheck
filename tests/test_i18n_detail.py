"""Tests for Hebrew detail + fix translation coverage (Stage 3).

Verifies:
- tp() returns Hebrew for a sample of static fix and detail strings added to PHRASES.
- tp(<dynamic string not in PHRASES>, "he") falls back to the English input.
- Rendering a Hebrew report shows Hebrew in at least one detail line.
- An EN report is byte-identical whether lang="en" is explicit or omitted.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawcheck import audit
from clawcheck.i18n import PHRASES, tp
from clawcheck.report import render_report

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _audit_vuln():
    """Return (findings, score) for home_vuln — always has FAIL/WARN issues."""
    _, findings, score = audit(FIXTURES / "home_vuln", include_native=False)
    return findings, score


# ---------------------------------------------------------------------------
# tp() — static fix strings present in PHRASES
# ---------------------------------------------------------------------------

class TestTpStaticFixStrings:
    """A sample of static fix strings from checks.py must be in PHRASES with Hebrew."""

    @pytest.mark.parametrize("phrase", [
        "Keep redaction on.",
        "Keep sandbox.mode enabled.",
        "Keep auth on and channels on allowlist.",
        "Keep least privilege: explicit allowlists only.",
        "Keep audit + redaction on.",
        "Keep data local where possible.",
        "Keep it enabled and make sure its alerts actually reach you.",
        "Keep bootstrap files free of language that weakens human approval gates.",
        "Keep all entries pinned and review updates manually.",
        "Keep a trusted/untrusted separation rule in SOUL.md.",
        "Keep approval gating on all high-impact tools.",
        "Keep transport encrypted and credential files locked down.",
        "Keep secrets out of bootstrap files and keep config perms at 600.",
        "Keep verifying skill provenance before install.",
        "Keep the egress allowlist tight.",
        "Keep heartbeat task lists write-protected and review them periodically.",
        "Keep memory and log directories at chmod 700/600.",
        "Keep workspace dirs at chmod 700 and bootstrap files at chmod 600.",
        "Keep approval gating enabled for all subagent-accessible tools.",
        "Keep MCP server specs pinned, env vars minimal, and allowedHosts restricted.",
        "Keep PATH directories owner-only (chmod 755 at most, never group/world-writable).",
        "Keep backups owner-only and outside the agent's writable workspace.",
        "Keep OpenClaw updated and re-run the installed-skill checks after updating.",
    ])
    def test_static_fix_has_hebrew_translation(self, phrase):
        result = tp(phrase, "he")
        assert result != phrase, f"No Hebrew translation for fix: {phrase!r}"
        assert result, f"Empty Hebrew for: {phrase!r}"

    def test_hebrew_differs_from_english_for_fix(self):
        """Spot-check: five fix strings each produce distinct non-English output."""
        samples = [
            "Keep redaction on.",
            "Keep sandbox.mode enabled.",
            "Keep least privilege: explicit allowlists only.",
            "Keep transport encrypted and credential files locked down.",
            "Keep all entries pinned and review updates manually.",
        ]
        for phrase in samples:
            he = tp(phrase, "he")
            assert he != phrase
            assert he  # non-empty


# ---------------------------------------------------------------------------
# tp() — static detail strings present in PHRASES
# ---------------------------------------------------------------------------

class TestTpStaticDetailStrings:
    """A sample of static detail strings from checks.py must be in PHRASES with Hebrew."""

    @pytest.mark.parametrize("phrase", [
        "No exposed plaintext secrets.",
        "Gateway is loopback/authenticated and channels are not open.",
        "No config loaded — cannot assess gateway.",
        "exec tooling present but sandbox.mode not set — likely host execution.",
        "Execution is sandboxed.",
        "No plugins/skills declared in config.",
        "Plugin/skill installs are pinned with integrity and allowlisted.",
        "No bootstrap files found to inspect.",
        "No blanket-obedience / injection-prone directives in bootstrap files.",
        "No memory file found.",
        "Memory is writable from external messages without sanitization.",
        "Agent has persistent memory; confirm it is not written from untrusted input.",
        "No destructive/outbound tools detected.",
        "Destructive tools (exec/send/write) present with no clear approval gate.",
        "Destructive actions require human approval.",
        "logging.redactSensitive is off — secrets/system prompt can surface in tool output/logs.",
        "logging.redactSensitive not set — default may expose secrets in output.",
        "Sensitive redaction is enabled.",
        "Audit logging with redaction is enabled.",
        "Transport is loopback/TLS and config perms are tight.",
        "No model config found.",
        "Models are local-first.",
        "No installed third-party skills found to inspect.",
        "No MCP servers configured.",
        "No threat monitoring / detection is set up — if your agent gets compromised "
        "(e.g. a malicious skill), nothing will alert you.",
        "No autonomy/heartbeat signal detected.",
        "Agent has persistent memory; confirm it is not written from untrusted input.",
        "No subagent delegation configured.",
        "Subagents can be spawned but elevated/exec actions require approval.",
        "Subagents can be spawned and may inherit elevated/exec tools without "
        "human approval.",
        "POSIX permission checks not applicable on this platform.",
        "No memory/log directories found to inspect.",
        "Memory/log directories have tight permissions (owner-only).",
        "No workspace bootstrap files found to inspect.",
        "Bootstrap identity and memory files have tight write permissions.",
        "No bootstrap files found — cannot assess tool-output trust boundary.",
        "Bootstrap contains an explicit rule treating tool/web/email/MCP output "
        "as untrusted data, not instructions.",
        "No trust-boundary rule in bootstrap, but no web/fetch tools or skills "
        "detected — risk cannot be determined.",
        "No fs_write/exec/elevated tools detected — self-modification risk not applicable.",
        "Dangerous tools present but no writable identity/skill targets found — "
        "self-modification risk could not be confirmed.",
        "No bootstrap files found — cannot scan for approval-bypass directives.",
        "No approval-bypass directives detected in bootstrap files.",
        "No plugin/skill source or version info found — pinning hygiene cannot be determined.",
        "Plugin/skill entries present but version format could not be classified as pinned or floating.",
        "No bootstrap/memory files found to back up.",
        "No backups of SOUL.md / MEMORY.md found — if the agent's identity or memory "
        "is poisoned or corrupted, there's nothing to restore from.",
        "OpenClaw version not recorded in config.",
        "openclaw not found on PATH — cannot assess binary PATH safety.",
        "PATH safety check not applicable on non-POSIX platforms.",
        "Elevated tools are restricted and tool reachability is constrained.",
    ])
    def test_static_detail_has_hebrew_translation(self, phrase):
        result = tp(phrase, "he")
        assert result != phrase, f"No Hebrew translation for detail: {phrase!r}"
        assert result, f"Empty Hebrew for: {phrase!r}"

    def test_hebrew_differs_from_english_for_detail(self):
        """Spot-check: five detail strings each produce distinct non-English output."""
        samples = [
            "No exposed plaintext secrets.",
            "Execution is sandboxed.",
            "Sensitive redaction is enabled.",
            "No MCP servers configured.",
            "No autonomy/heartbeat signal detected.",
        ]
        for phrase in samples:
            he = tp(phrase, "he")
            assert he != phrase
            assert he


# ---------------------------------------------------------------------------
# tp() — dynamic (non-static) strings must fall back to English
# ---------------------------------------------------------------------------

class TestTpDynamicFallback:
    """tp() now translates dynamic strings via DETAIL_RULES when a pattern matches,
    and falls back to the input text only for truly unknown strings."""

    @pytest.mark.parametrize("text,expected_he_differs", [
        # These strings ARE covered by DETAIL_RULES — they get translated
        ("Active legs 3/3: untrusted input, sensitive data, outbound actions. Rule: keep ≤2 of 3.", True),
        ("gateway.bind=0.0.0.0 exposed with auth.mode=none", True),
        ("tools.elevated.allowFrom has 30 entries (too broad)", True),
        ("sandbox.mode is off (exec runs on the host)", True),
        ("secret-like string in SOUL.md", True),
        ("Cloud model(s) in use: openai.", True),
        # This string does NOT match any DETAIL_RULES pattern → falls back
        ("Some totally unknown string that is not in PHRASES at all.", False),
        # Empty string always falls back
        ("", False),
    ])
    def test_dynamic_string_translation(self, text, expected_he_differs):
        result = tp(text, "he")
        if expected_he_differs:
            assert result != text, f"Expected Hebrew translation for: {text!r}"
            assert result, "Expected non-empty Hebrew translation"
        else:
            assert result == text, f"Expected fallback (unchanged) for: {text!r}"

    def test_mcp_server_detail_is_translated(self):
        """B24 detail strings with MCP server count ARE translated."""
        text = "1 MCP server(s) (my-mcp): some-issue"
        result = tp(text, "he")
        # The pattern "(\d+) MCP server(s) (name): detail" is a DETAIL_RULES match
        assert result != text
        assert "MCP" in result  # server name preserved

    def test_empty_string_unchanged_for_any_lang(self):
        assert tp("", "he") == ""
        assert tp("", "en") == ""

    def test_unknown_text_returns_itself(self):
        unique = "This exact sentence is definitely not in PHRASES 99999."
        assert tp(unique, "he") == unique


# ---------------------------------------------------------------------------
# tp() — English always returns input unchanged
# ---------------------------------------------------------------------------

class TestTpEnPassthrough:
    """tp() with lang="en" must never modify the input, even for PHRASES entries."""

    @pytest.mark.parametrize("phrase", [
        "Keep redaction on.",
        "Keep sandbox.mode enabled.",
        "No exposed plaintext secrets.",
        "Execution is sandboxed.",
        "No MCP servers configured.",
    ])
    def test_en_returns_input_unchanged(self, phrase):
        assert tp(phrase, "en") == phrase

    def test_en_default_is_passthrough(self):
        # Default lang is "en" — same as explicit "en"
        phrase = "Keep redaction on."
        assert tp(phrase) == phrase


# ---------------------------------------------------------------------------
# PHRASES dict integrity
# ---------------------------------------------------------------------------

class TestPhrasesIntegrity:
    def test_all_phrases_have_he_key(self):
        for k, v in PHRASES.items():
            assert "he" in v, f"PHRASES[{k!r}] missing 'he'"

    def test_all_he_translations_non_empty(self):
        for k, v in PHRASES.items():
            assert v["he"], f"PHRASES[{k!r}]['he'] is empty"

    def test_all_he_translations_differ_from_key(self):
        for k, v in PHRASES.items():
            assert v["he"] != k, f"PHRASES[{k!r}]['he'] is identical to the English key"

    def test_phrase_count_at_least_60(self):
        """We added substantially more than the original 12 entries."""
        assert len(PHRASES) >= 60, f"Expected ≥60 PHRASES entries, got {len(PHRASES)}"


# ---------------------------------------------------------------------------
# Hebrew report rendering — detail lines contain Hebrew text
# ---------------------------------------------------------------------------

class TestHebrewDetailRendering:
    def test_he_report_contains_hebrew_in_detail_line(self):
        """A Hebrew report for the vulnerable fixture must show Hebrew in at least
        one 'why' (detail) line, proving tp(f.detail, lang) is being called."""
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="he")
        # The Hebrew label for "why" is "מדוע"
        assert "מדוע:" in out, "Hebrew 'why' label not found in he report"
        # Find lines that start with the Hebrew why label and check at least one
        # contains Hebrew text after the colon (i.e. the detail was translated).
        he_detail_lines = [
            line for line in out.splitlines()
            if "מדוע:" in line
        ]
        assert he_detail_lines, "No detail lines found in he report"
        # At least one detail line must contain a Hebrew character beyond the label.
        # Hebrew Unicode block: U+05D0–U+05EA.
        def has_hebrew_beyond_label(line: str) -> bool:
            after_label = line.split("מדוע:", 1)[-1]
            return any("א" <= ch <= "ת" for ch in after_label)

        assert any(has_hebrew_beyond_label(ln) for ln in he_detail_lines), (
            "No detail line contains Hebrew text after the label — "
            "tp(f.detail, lang) may not be wired up in _render_finding"
        )

    def test_he_fix_line_contains_hebrew(self):
        """At least one fix line in a Hebrew report must contain Hebrew text."""
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="he")
        fix_lines = [ln for ln in out.splitlines() if "תיקון:" in ln]
        assert fix_lines, "No fix lines found in he report"

        def has_hebrew(line: str) -> bool:
            return any("א" <= ch <= "ת" for ch in line)

        assert any(has_hebrew(ln) for ln in fix_lines), (
            "No fix line contains Hebrew text"
        )


# ---------------------------------------------------------------------------
# English byte-identity guarantee
# ---------------------------------------------------------------------------

class TestEnByteIdentity:
    def test_en_explicit_equals_no_lang_arg(self):
        """render_report(lang='en') must be byte-identical to render_report() (no lang)."""
        findings, score = _audit_vuln()
        assert render_report(findings, score, lang="en") == render_report(findings, score)

    def test_en_explicit_equals_no_lang_arg_safe_fixture(self):
        """Same guarantee on the clean fixture."""
        _, findings, score = audit(FIXTURES / "home_safe", include_native=False)
        assert render_report(findings, score, lang="en") == render_report(findings, score)

    def test_en_report_detail_is_english(self):
        """In an EN report, detail lines must not contain Hebrew characters."""
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="en")
        detail_lines = [ln for ln in out.splitlines() if "    why:" in ln]
        for line in detail_lines:
            assert not any("א" <= ch <= "ת" for ch in line), (
                f"Hebrew character found in EN detail line: {line!r}"
            )

    def test_en_report_fix_is_english(self):
        """In an EN report, fix lines must not contain Hebrew characters."""
        findings, score = _audit_vuln()
        out = render_report(findings, score, lang="en")
        fix_lines = [ln for ln in out.splitlines() if "    fix:" in ln]
        for line in fix_lines:
            assert not any("א" <= ch <= "ת" for ch in line), (
                f"Hebrew character found in EN fix line: {line!r}"
            )
