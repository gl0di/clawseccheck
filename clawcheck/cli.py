"""ClawCheck command-line interface.

Exposed as the `clawcheck` console script (see pyproject.toml), as `python -m clawcheck`,
and via the bundled skill entrypoint `python3 {baseDir}/audit.py`.

Read-only. No network. No writes by default. Pure stdlib. Cross-platform.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import (
    audit, diff, fingerprint, load_ignore, load_state, make_canary, render_canary,
    render_card, render_json, render_monitor, render_prompts, render_report, render_svg,
    save_state, snapshot, vet_skill,
)
from .integrity import package_digest
from .report import render_html
from .monitor import DEFAULT_STATE
from .redteam import make_suite, render_suite
from .dryrun import make_scenarios, render_dryrun


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
    p = argparse.ArgumentParser(prog="clawcheck",
                                description="ClawCheck OpenClaw security self-audit (read-only).")
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
                   help="print the SHA-256 digest of the ClawCheck engine source for tamper detection")
    args = p.parse_args(argv)

    ascii_only = args.ascii or not _unicode_ok()

    # standalone modes that don't audit ~/.openclaw
    if args.verify_self:
        from . import __version__
        combined, per_file = package_digest()
        lines = [f"ClawCheck {__version__} — engine source digest (SHA-256)",
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
            _emit("No .clawcheckignore entries found.")
        else:
            _emit(f"{len(ignore)} suppressed entry/entries in .clawcheckignore:")
            ctx, findings, _ = audit(args.home, include_native=False)
            suppressed = [f for f in findings if getattr(f, "suppressed", False)]
            if suppressed:
                for f in suppressed:
                    _emit(f"  {f.id}  {fingerprint(f)}  ({f.title})")
            else:
                for entry in sorted(ignore):
                    _emit(f"  {entry}")
        return 0

    ctx, findings, score = audit(args.home, include_native=not args.no_native)

    if args.badge:
        try:
            Path(args.badge).expanduser().write_text(render_svg(score, findings), encoding="utf-8")
            _emit(f"(badge written to {args.badge})")
        except OSError as exc:
            _emit(f"(could not write badge: {exc})")
        return 0

    if args.html:
        try:
            Path(args.html).expanduser().write_text(render_html(findings, score, native=ctx.native), encoding="utf-8")
            _emit(f"(HTML report written to {args.html})")
        except OSError as exc:
            _emit(f"(could not write HTML report: {exc})")
        return 0

    if args.prompts:
        _emit(render_prompts(findings, ascii_only))
        return 0

    if args.monitor:
        prev = load_state(args.state)
        snap = snapshot(ctx, findings, score)
        _emit(render_monitor(diff(prev, snap), score, ascii_only, baseline=prev is None))
        try:
            save_state(args.state, snap)
        except OSError as exc:
            _emit(f"\n(could not save monitor state: {exc})")
        return 0

    if args.json:
        body = render_json(findings, score)
    elif args.card:
        body = render_card(score, findings, ascii_only)
    else:
        parts = [render_report(findings, score, ascii_only, native=ctx.native),
                 "", render_card(score, findings, ascii_only)]
        if ctx.errors:
            parts.append("\nnotes:\n" + "\n".join(f"  - {e}" for e in ctx.errors))
        body = "\n".join(parts)

    _emit(body)

    if args.save:
        try:
            Path(args.save).expanduser().write_text(body, encoding="utf-8")
            _emit(f"\n(report saved to {args.save})")
        except OSError as exc:
            _emit(f"\n(could not save report: {exc})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
