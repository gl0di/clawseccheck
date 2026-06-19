"""Render plain-language report + shareable card.

The shareable card NEVER lists findings — only grade + score + trifecta ratio
(tiered disclosure: sharing your card must not publish your vulns to attackers).

Every renderer supports `ascii_only=True` for terminals that can't encode the
unicode icons/box (e.g. a legacy Windows cp1252 console).
"""
from __future__ import annotations

import json

from .catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Finding
from .scoring import ScoreResult

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
    lines.append(f"{icon[f.status]} [{f.severity}] {f.title}")
    if f.detail:
        lines.append(f"    why: {f.detail}")
    lines.append(f"    fix: {f.fix}")
    lines.append("")


def render_report(findings: list[Finding], score: ScoreResult,
                  ascii_only: bool = False, native=None) -> str:
    icon = _ICON_ASCII if ascii_only else _ICON
    ok = "[OK]" if ascii_only else "✅"
    issues = [f for f in findings if f.status in (FAIL, WARN)]
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
