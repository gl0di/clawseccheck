"""ClawSecCheck command-line interface.

Exposed as the `clawseccheck` console script (see pyproject.toml), as `python -m clawseccheck`,
and via the bundled skill entrypoint `python3 {baseDir}/audit.py`.

Read-only. No network. No writes by default. Pure stdlib. Cross-platform.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import (
    audit, diff, fingerprint, load_ignore, load_state, make_canary, render_canary,
    render_card, render_json, render_monitor, render_prompts, render_report, render_svg,
    save_state, snapshot, vet_mcp, vet_skill,
)
from . import risk as _risk
from .guide import render_next_actions, suggest_actions
from .integrity import package_digest
from .report import render_html
from .monitor import DEFAULT_STATE
from .redteam import make_suite, render_suite
from .dryrun import make_scenarios, render_dryrun
from .sarif import render_sarif
from .history import DEFAULT_HISTORY, load as history_load, record as history_record, render_trend
from .percentile import render_percentile
from .logsafe import get_logger


def _default_lang() -> str:
    """Infer output language from the environment (LC_ALL then LANG)."""
    for var in ("LC_ALL", "LANG"):
        val = os.environ.get(var, "")
        if val.startswith("he"):
            return "he"
    return "en"


def _unicode_ok() -> bool:
    """Best-effort: make stdout UTF-8 and report whether unicode is safe to print."""
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    if "utf" in enc:
        return True
    try:  # Python 3.7+: try to force UTF-8 (works on most modern Windows terminals)
        sys.stdout.reconfigure(encoding="utf-8")
        return True
    except Exception:
        return False


def _emit(text: str) -> None:
    """Print, falling back to ASCII-safe bytes if the console can't encode it."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="clawseccheck",
                                description="ClawSecCheck OpenClaw security self-audit (read-only).")
    p.add_argument("--home", default="~/.openclaw", help="OpenClaw home dir (default: ~/.openclaw)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--card", action="store_true", help="print only the shareable badge")
    p.add_argument("--ascii", action="store_true", help="ASCII-only output (no unicode icons/box)")
    p.add_argument("--no-native", action="store_true",
                   help="do not also run the built-in `openclaw security audit`")
    p.add_argument("--save", metavar="PATH", help="also write the report to a file")
    p.add_argument("--monitor", action="store_true",
                   help="monitor mode: alert on what changed since the last check")
    p.add_argument("--state", default=DEFAULT_STATE, metavar="PATH",
                   help=f"snapshot file for --monitor (default: {DEFAULT_STATE})")
    p.add_argument("--vet", metavar="PATH",
                   help="vet a skill (dir or SKILL.md) for malware BEFORE installing it")
    p.add_argument("--vet-mcp", nargs="?", const="", metavar="NAME|FILE",
                   help="vet configured MCP servers (or a NAME/FILE) for supply-chain risk before trusting them")
    p.add_argument("--canary", action="store_true",
                   help="active prompt-injection canary self-test")
    p.add_argument("--redteam", action="store_true",
                   help="print a live red-team payload suite for adversarial self-testing")
    p.add_argument("--dryrun", action="store_true",
                   help="print a behavioral dry-run harness (prompt-injection self-test across all sources)")
    p.add_argument("--badge", metavar="PATH", help="write a shareable SVG badge to PATH")
    p.add_argument("--html", metavar="PATH", help="write a standalone HTML report to PATH")
    p.add_argument("--prompts", action="store_true",
                   help="print a copy-paste fix prompt for each finding")
    p.add_argument("--show-suppressed", action="store_true",
                   help="list suppressed finding ids + fingerprints and exit")
    p.add_argument("--verify-self", action="store_true",
                   help="print the SHA-256 digest of the ClawSecCheck engine source for tamper detection")
    p.add_argument("--lang", choices=("en", "he"), default=_default_lang(),
                   help="output language (en|he; he is right-to-left)")
    p.add_argument("--sarif", metavar="PATH",
                   help="write a SARIF 2.1.0 report to PATH")
    p.add_argument("--fail-under", metavar="N", type=int, default=None,
                   help="exit 1 if score is below N")
    p.add_argument("--exit-code", action="store_true",
                   help="exit 1 if any unsuppressed FAIL finding exists")
    p.add_argument("--trend", action="store_true",
                   help="record this run to history, print trend + percentile, and exit")
    p.add_argument("--percentile", action="store_true",
                   help="print offline percentile rank for the current score and exit")
    p.add_argument("--history", default=DEFAULT_HISTORY, metavar="PATH",
                   help=f"path for trend history file (default: {DEFAULT_HISTORY})")
    p.add_argument("--no-history", action="store_true",
                   help="do not record this run to the local score history (default: record)")
    p.add_argument("--next", action="store_true",
                   help="print recommended next actions based on the audit result")
    p.add_argument("--risk-paths", action="store_true",
                   help="print only the highest-risk capability chains and exit")
    p.add_argument("--verbose", action="store_true",
                   help="emit INFO-level log breadcrumbs to stderr")
    p.add_argument("--debug", action="store_true",
                   help="emit DEBUG-level log breadcrumbs to stderr")
    p.add_argument("--log", metavar="PATH", default=None,
                   help="also write log output to PATH (only when given)")
    args = p.parse_args(argv)

    ascii_only = args.ascii or not _unicode_ok()

    # Set up safe logger early — level from --verbose/--debug; file only when --log given.
    logger = get_logger(
        verbose=getattr(args, "verbose", False),
        debug=getattr(args, "debug", False),
        logfile=getattr(args, "log", None),
    )

    # standalone modes that don't audit ~/.openclaw
    if args.verify_self:
        from . import __version__
        combined, per_file = package_digest()
        lines = [f"ClawSecCheck {__version__} — engine source digest (SHA-256)",
                 f"combined : {combined}",
                 ""]
        for name, digest in sorted(per_file.items()):
            lines.append(f"  {digest}  {name}")
        lines.append("")
        lines.append("Compare the 'combined' value against the digest printed by a trusted release.")
        lines.append("Any mismatch means a source file was modified after that release.")
        _emit("\n".join(lines))
        return 0

    if args.vet:
        f = vet_skill(args.vet)
        verdict = {"FAIL": "DANGEROUS", "WARN": "SUSPICIOUS", "PASS": "looks SAFE",
                   "UNKNOWN": "could not assess"}[f.status]
        icon = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]"}[f.status] \
            if ascii_only else {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔"}[f.status]
        _emit(f"{icon} Vetting '{args.vet}': {verdict} [{f.severity}]\n    {f.detail}\n    {f.fix}")
        return 0 if f.status in ("PASS", "UNKNOWN") else 1

    if args.vet_mcp is not None:
        target = args.vet_mcp if args.vet_mcp else None
        findings = vet_mcp(target=target, home=args.home)
        # "No servers configured" case: single UNKNOWN finding.
        if len(findings) == 1 and findings[0].status == "UNKNOWN":
            f = findings[0]
            icon = "[?]" if ascii_only else "❔"
            _emit(f"{icon} {f.detail}")
            return 0
        worst_status = "PASS"
        for f in findings:
            if f.status == "FAIL":
                worst_status = "FAIL"
                break
            if f.status == "WARN" and worst_status != "FAIL":
                worst_status = "WARN"
        _STATUS_ICON = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]"}
        _STATUS_ICON_UNI = {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔"}
        _VERDICT = {"FAIL": "DANGEROUS", "WARN": "SUSPICIOUS", "PASS": "SAFE", "UNKNOWN": "UNKNOWN"}
        for f in findings:
            icon = _STATUS_ICON[f.status] if ascii_only else _STATUS_ICON_UNI[f.status]
            verdict = _VERDICT[f.status]
            _emit(f"{icon} {verdict}: {f.title}")
            if f.evidence:
                for ev in f.evidence[:4]:
                    _emit(f"    - {ev}")
            _emit(f"    fix: {f.fix}")
            _emit("")
        return 0 if worst_status in ("PASS", "UNKNOWN") else 1

    if args.canary:
        _emit(render_canary(make_canary(), ascii_only))
        return 0

    if args.redteam:
        _emit(render_suite(make_suite(), ascii_only))
        return 0

    if args.dryrun:
        _emit(render_dryrun(make_scenarios(), ascii_only))
        return 0

    if args.show_suppressed:
        ignore = load_ignore(Path(args.home).expanduser())
        if not ignore:
            _emit("No .clawseccheckignore entries found.")
        else:
            _emit(f"{len(ignore)} suppressed entry/entries in .clawseccheckignore:")
            ctx, findings, _ = audit(args.home, include_native=False)
            suppressed = [f for f in findings if getattr(f, "suppressed", False)]
            if suppressed:
                for f in suppressed:
                    _emit(f"  {f.id}  {fingerprint(f)}  ({f.title})")
            else:
                for entry in sorted(ignore):
                    _emit(f"  {entry}")
        return 0

    logger.info("auditing home=%s", args.home)
    ctx, findings, score = audit(args.home, include_native=not args.no_native)
    logger.debug("ran %d checks", len(findings))
    logger.info("score=%s grade=%s", score.score, score.grade)

    paths = _risk.risk_paths(ctx, findings)

    if args.risk_paths:
        _emit(_risk.render_risk_paths(paths, ascii_only=ascii_only))
        return 0

    if args.badge:
        try:
            Path(args.badge).expanduser().write_text(render_svg(score, findings), encoding="utf-8")
            _emit(f"(badge written to {args.badge})")
        except OSError as exc:
            _emit(f"(could not write badge: {exc})")
        return 0

    if args.html:
        try:
            Path(args.html).expanduser().write_text(
                render_html(findings, score, native=ctx.native, lang=args.lang),
                encoding="utf-8")
            _emit(f"(HTML report written to {args.html})")
        except OSError as exc:
            _emit(f"(could not write HTML report: {exc})")
        return 0

    if args.sarif:
        from . import __version__
        try:
            Path(args.sarif).expanduser().write_text(
                render_sarif(findings, score, __version__),
                encoding="utf-8")
            _emit(f"(SARIF written to {args.sarif})")
        except OSError as exc:
            _emit(f"(could not write SARIF: {exc})")
        return 0

    if args.trend:
        history_record(score, args.history)
        rows = history_load(args.history)
        _emit(render_trend(rows, ascii_only))
        _emit(render_percentile(score.score, ascii_only))
        return 0

    if args.percentile:
        _emit(render_percentile(score.score, ascii_only))
        return 0

    if args.prompts:
        _emit(render_prompts(findings, ascii_only, lang=args.lang))
        return 0

    if args.next:
        _emit(render_next_actions(suggest_actions(findings, score), ascii_only, lang=args.lang))
        return 0

    if args.monitor:
        prev = load_state(args.state)
        snap = snapshot(ctx, findings, score)
        _emit(render_monitor(diff(prev, snap), score, ascii_only, baseline=prev is None,
                             lang=args.lang))
        try:
            save_state(args.state, snap)
        except OSError as exc:
            _emit(f"\n(could not save monitor state: {exc})")
        history_record(score, args.history)
        return 0

    if args.json:
        body = render_json(findings, score, risk=paths)
    elif args.card:
        body = render_card(score, findings, ascii_only, lang=args.lang)
    else:
        parts = [render_report(findings, score, ascii_only, native=ctx.native, lang=args.lang,
                               risk=paths),
                 "", render_card(score, findings, ascii_only, lang=args.lang)]
        if ctx.errors:
            parts.append("\nnotes:\n" + "\n".join(f"  - {e}" for e in ctx.errors))
        parts.append("")
        parts.append(render_next_actions(
            suggest_actions(findings, score), ascii_only, lang=args.lang))
        body = "\n".join(parts)

    _emit(body)

    if args.save:
        try:
            Path(args.save).expanduser().write_text(body, encoding="utf-8")
            _emit(f"\n(report saved to {args.save})")
        except OSError as exc:
            _emit(f"\n(could not save report: {exc})")

    if not args.no_history and not args.trend and not args.monitor:
        history_record(score, args.history)

    if args.fail_under is not None and score.score < args.fail_under:
        return 1

    if args.exit_code:
        has_fail = any(
            not getattr(f, "suppressed", False) and f.status == "FAIL"
            for f in findings
        )
        if has_fail:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
