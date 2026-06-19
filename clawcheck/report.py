"""Render plain-language report + shareable card.

The shareable card NEVER lists findings — only grade + score + trifecta ratio
(tiered disclosure: sharing your card must not publish your vulns to attackers).

Every renderer supports `ascii_only=True` for terminals that can't encode the
unicode icons/box (e.g. a legacy Windows cp1252 console).
"""
from __future__ import annotations

import html
import json
import re

from .catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from .scoring import ScoreResult

# Findings, skill names, decoded payload previews and native-audit fields are UNTRUSTED
# data. Strip terminal-control sequences (ANSI/OSC incl. OSC-52 clipboard), bidi overrides
# and zero-width chars so a hostile skill/finding can't attack the terminal or spoof text.
_ANSI_OSC_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b.")
_BAD_CHARS_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f"
    "\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]")



def _sanitize(s: str) -> str:
    if not s:
        return s
    s = _BAD_CHARS_RE.sub("", _ANSI_OSC_RE.sub("", s))
    for c in "\r\n\t":
        s = s.replace(c, " ")
    return s

_SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
_ICON = {FAIL: "⛔", WARN: "⚠️", PASS: "✅", UNKNOWN: "❔"}
_ICON_ASCII = {FAIL: "[X]", WARN: "[!]", PASS: "[OK]", UNKNOWN: "[?]"}

_ASCII_MAP = str.maketrans({
    "×": "x", "≤": "<=", "≥": ">=", "—": "-", "–": "-", "…": "...",
    "’": "'", "‘": "'", "“": '"', "”": '"', "≈": "~", "→": "->", "•": "*",
})


def _asciify(text: str) -> str:
    """Fold the unicode we emit down to pure ASCII for legacy consoles."""
    return text.translate(_ASCII_MAP).encode("ascii", "replace").decode("ascii")


def _trifecta_ratio(findings: list[Finding]) -> str:
    for f in findings:
        if f.id == "A1":
            return f"{len(f.evidence)}/3"
    return "?/3"


def _render_finding(lines, icon, f):
    lines.append(f"{icon[f.status]} [{f.severity}] {_sanitize(f.title)}")
    if f.detail:
        lines.append(f"    why: {_sanitize(f.detail)}")
    lines.append(f"    fix: {_sanitize(f.fix)}")
    lines.append("")


def render_report(findings: list[Finding], score: ScoreResult,
                  ascii_only: bool = False, native=None) -> str:
    icon = _ICON_ASCII if ascii_only else _ICON
    ok = "[OK]" if ascii_only else "✅"
    suppressed_count = sum(1 for f in findings if getattr(f, "suppressed", False))
    issues = [f for f in findings
              if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)]
    issues.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.status != FAIL))
    lines = ["ClawCheck - OpenClaw Security Audit", "=" * 44,
             f"Score: {score.score}/100   Grade: {score.grade}   "
             f"Lethal Trifecta: {_trifecta_ratio(findings)}"]
    if score.capped:
        lines.append(f"(capped from {score.raw_score} - open "
                     f"{'CRITICAL' if score.failed_critical else 'HIGH'} finding)")
    lines.append("")
    if not issues:
        lines.append(f"No issues found by ClawCheck. Keep it that way. {ok}")
    else:
        lines.append(f"{len(issues)} thing(s) to fix (ClawCheck) - most urgent first:")
        lines.append("")
        for f in issues:
            _render_finding(lines, icon, f)

    if suppressed_count:
        lines.append(f"({suppressed_count} finding(s) suppressed via .clawcheckignore)")

    if native is not None:
        lines.append("--- Also from OpenClaw's built-in `security audit` ---")
        if getattr(native, "status", "") == "ok":
            nf = sorted(native.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
            if nf:
                lines.append(f"{len(nf)} additional finding(s) the platform's own audit reports:")
                lines.append("")
                for f in nf:
                    _render_finding(lines, icon, f)
            else:
                lines.append("Clean — openclaw security audit found nothing.")
        else:
            lines.append(f"(not included: {native.note})")
        lines.append("")

    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


def render_card(score: ScoreResult, findings: list[Finding], ascii_only: bool = False) -> str:
    """Shareable badge — grade + score + trifecta ONLY. No findings, ever."""
    l1 = f"  OpenClaw Security: {score.grade:<2} ({score.score:>3}/100)"
    l2 = f"  Lethal Trifecta: {_trifecta_ratio(findings)}"
    l3 = "  audited by ClawCheck" + ("" if ascii_only else " 🔍")
    width = 39
    if ascii_only:
        top = bot = "+" + "-" * width + "+"
        body = "\n".join(f"|{ln:<{width}}|" for ln in (l1, l2, l3))
        return _asciify(f"{top}\n{body}\n{bot}")
    top = "┌" + "─" * width + "┐"
    bot = "└" + "─" * width + "┘"
    # the magnifier emoji is double-width in many terminals; pad l3 one less
    body = "\n".join([
        f"│{l1:<{width}}│",
        f"│{l2:<{width}}│",
        f"│{l3:<{width - 1}}│",
    ])
    return f"{top}\n{body}\n{bot}"


def render_monitor(alerts, score: ScoreResult, ascii_only: bool = False,
                   baseline: bool = False) -> str:
    mark = {"CRITICAL": "[X]", "HIGH": "[!]", "INFO": "[i]"} if ascii_only \
        else {"CRITICAL": "⛔", "HIGH": "⚠️", "INFO": "ℹ️"}
    order = {"CRITICAL": 0, "HIGH": 1, "INFO": 2}
    lines = ["ClawCheck - Threat Monitor", "=" * 30,
             f"Current: {score.score}/100  Grade: {score.grade}"]
    if baseline:
        lines += ["", "Baseline saved. Future runs will alert on what changes since now."]
    elif not alerts:
        lines += ["", "No new threats since last check. " + ("[OK]" if ascii_only else "✅")]
    else:
        lines += ["", f"{len(alerts)} change(s) detected since last check:", ""]
        for level, msg in sorted(alerts, key=lambda a: order.get(a[0], 9)):
            lines.append(f"{mark.get(level, '[*]')} {msg}")
    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


_GRADE_COLOR = {"A": "#4c1", "B": "#97ca00", "C": "#dfb317", "D": "#fe7d37", "F": "#e05d44"}


def render_svg(score: ScoreResult, findings: list[Finding]) -> str:
    """A shields.io-style SVG badge (grade + score only — never findings)."""
    label = "OpenClaw Security"
    value = f"{score.grade} {score.score}/100"
    color = _GRADE_COLOR.get(score.grade, "#9f9f9f")
    lw = 8 + len(label) * 6          # rough text widths
    vw = 8 + len(value) * 7
    w = lw + vw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" '
        f'stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<rect rx="3" width="{w}" height="20" fill="#555"/>'
        f'<rect rx="3" x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        f'<rect rx="3" width="{w}" height="20" fill="url(#s)"/>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="{lw / 2:.0f}" y="14">{label}</text>'
        f'<text x="{lw + vw / 2:.0f}" y="14">{value}</text>'
        f'</g></svg>'
    )


def render_prompts(findings: list[Finding], ascii_only: bool = False) -> str:
    """One copy-paste remediation prompt per finding — paste into your agent."""
    issues = [f for f in findings if f.status in (FAIL, WARN)]
    issues.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.status != FAIL))
    if not issues:
        out = "Nothing to fix. " + ("[OK]" if ascii_only else "✅") + "\n"
        return out
    lines = ["ClawCheck - copy-paste fix prompts", "=" * 36,
             "Paste each into your OpenClaw agent to fix it:", ""]
    for i, f in enumerate(issues, 1):
        lines.append(f"{i}. [{f.severity}] {f.title}")
        lines.append(
            f'   "My ClawCheck security audit flagged this on my OpenClaw agent: '
            f'{f.title} — {f.detail} Please fix it: {f.fix} '
            f'Show me the exact change and ask before applying anything."')
        lines.append("")
    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out


def render_json(findings: list[Finding], score: ScoreResult) -> str:
    return json.dumps({
        "score": score.score,
        "grade": score.grade,
        "capped": score.capped,
        "raw_score": score.raw_score,
        "trifecta": _trifecta_ratio(findings),
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity,
             "status": f.status, "detail": f.detail, "fix": f.fix,
             "framework": f.framework}
            for f in findings
        ],
    }, ensure_ascii=True, indent=2)


def render_html(findings: list[Finding], score: ScoreResult, native=None) -> str:
    """Standalone self-contained HTML report (inline CSS, no external assets).

    Includes grade badge (colored by _GRADE_COLOR), score, Lethal Trifecta ratio,
    and FAIL/WARN findings list. Owner view — shows findings with a note that
    this is private and must not be shared publicly.

    All finding text is HTML-escaped.
    """
    issues = [f for f in findings
              if f.status in (FAIL, WARN) and not getattr(f, "suppressed", False)]
    issues.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.status != FAIL))

    badge_color = _GRADE_COLOR.get(score.grade, "#9f9f9f")
    trifecta = _trifecta_ratio(findings)

    # Build the findings HTML
    findings_html = ""
    if not issues:
        findings_html = '<div style="padding:1rem;background:#f0f8f0;border-radius:0.5rem;color:#0a4;font-weight:500;">No issues found. Keep it that way.</div>'
    else:
        findings_html = '<div style="padding:0;">'
        for f in issues:
            severity_color = {CRITICAL: "#e05d44", HIGH: "#fe7d37",
                            MEDIUM: "#dfb317", LOW: "#97ca00"}.get(f.severity, "#999")
            icon_char = "✕" if f.status == FAIL else "⚠"
            findings_html += f'''
            <div style="margin-bottom:1.5rem;border-left:4px solid {severity_color};padding-left:1rem;">
                <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;">
                    <span style="font-size:1.2rem;color:{severity_color};">{html.escape(icon_char)}</span>
                    <strong style="color:#333;">{html.escape(f.title)}</strong>
                    <span style="background:{severity_color};color:#fff;padding:0.125rem 0.5rem;border-radius:0.25rem;font-size:0.85rem;font-weight:600;">{html.escape(f.severity)}</span>
                </div>
                {f'<div style="color:#666;margin:0.5rem 0;"><strong>Why:</strong> {html.escape(f.detail)}</div>' if f.detail else ''}
                <div style="color:#666;"><strong>Fix:</strong> {html.escape(f.fix)}</div>
            </div>
            '''
        findings_html += '</div>'

    html_body = f'''<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>ClawCheck Security Audit Report</title>
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: #fff;
            border-radius: 0.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 2rem;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid #eee;
            padding-bottom: 1.5rem;
        }}
        .header h1 {{
            font-size: 1.8rem;
            margin-bottom: 1rem;
            color: #222;
        }}
        .grade-badge {{
            display: inline-block;
            background: {badge_color};
            color: #fff;
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            font-size: 2rem;
            font-weight: 700;
            margin: 1rem 0;
        }}
        .score-info {{
            font-size: 1rem;
            color: #666;
            margin-top: 1rem;
        }}
        .section {{
            margin-bottom: 2rem;
        }}
        .section h2 {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: #222;
            border-bottom: 2px solid #eee;
            padding-bottom: 0.5rem;
        }}
        .warning-box {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1.5rem;
            color: #856404;
        }}
        .warning-box strong {{
            display: block;
            margin-bottom: 0.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ClawCheck Security Audit Report</h1>
            <div class="grade-badge">{html.escape(score.grade)}</div>
            <div class="score-info">
                <div><strong>Score:</strong> {score.score}/100</div>
                <div><strong>Lethal Trifecta:</strong> {html.escape(trifecta)}</div>
                {f'<div style="color:#d9534f;"><strong>Capped:</strong> from {score.raw_score} (open {"CRITICAL" if score.failed_critical else "HIGH"} finding)</div>' if score.capped else ''}
            </div>
        </div>

        <div class="warning-box">
            <strong>⚠ Private Report</strong>
            This report contains detailed security findings and must <strong>NOT</strong> be shared publicly.
            Use the shareable badge instead (available via <code>--badge</code>).
        </div>

        <div class="section">
            <h2>Findings</h2>
            {findings_html}
        </div>
    </div>
</body>
</html>'''

    return html_body
