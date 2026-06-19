#!/usr/bin/env python3
"""ClawCheck OpenClaw audit — entrypoint invoked by the skill.

Read-only. No network. No writes. Pure stdlib. Cross-platform (Linux/macOS/Windows).

Usage:
    python3 audit.py [--home ~/.openclaw] [--json] [--card] [--ascii]
    # on Windows:  python audit.py   (or:  py audit.py)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from clawcheck import (  # noqa: E402
    audit, diff, load_state, make_canary, render_canary, render_card, render_json,
    render_monitor, render_prompts, render_report, render_svg, save_state, snapshot,
    vet_skill,
)
from clawcheck.monitor import DEFAULT_STATE  # noqa: E402


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
    p = argparse.ArgumentParser(description="ClawCheck OpenClaw security self-audit (read-only).")
    p.add_argument("--home", default="~/.openclaw", help="OpenClaw home dir (default: ~/.openclaw)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--card", action="store_true", help="print only the shareable badge")
    p.add_argument("--ascii", action="store_true", help="ASCII-only output (no unicode icons/box)")
    p.add_argument("--no-native", action="store_true",
                   help="do not also run the built-in `openclaw security audit`")
    p.add_argument("--save", metavar="PATH",
                   help="also write the report to a file")
    p.add_argument("--monitor", action="store_true",
                   help="monitor mode: alert on what changed since the last check")
    p.add_argument("--state", default=DEFAULT_STATE, metavar="PATH",
                   help=f"snapshot file for --monitor (default: {DEFAULT_STATE})")
    p.add_argument("--vet", metavar="PATH",
                   help="vet a skill (dir or SKILL.md) for malware BEFORE installing it")
    p.add_argument("--canary", action="store_true",
                   help="active prompt-injection canary self-test")
    p.add_argument("--badge", metavar="PATH", help="write a shareable SVG badge to PATH")
    p.add_argument("--prompts", action="store_true",
                   help="print a copy-paste fix prompt for each finding")
    args = p.parse_args(argv)

    ascii_only = args.ascii or not _unicode_ok()

    # standalone modes that don't audit ~/.openclaw
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

    ctx, findings, score = audit(args.home, include_native=not args.no_native)

    if args.badge:
        from pathlib import Path as _Path
        try:
            _Path(args.badge).expanduser().write_text(render_svg(score, findings), encoding="utf-8")
            _emit(f"(badge written to {args.badge})")
        except OSError as exc:
            _emit(f"(could not write badge: {exc})")
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
        from pathlib import Path as _Path
        try:
            _Path(args.save).expanduser().write_text(body, encoding="utf-8")
            _emit(f"\n(report saved to {args.save})")
        except OSError as exc:
            _emit(f"\n(could not save report: {exc})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
