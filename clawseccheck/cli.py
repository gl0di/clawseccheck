"""ClawSecCheck command-line interface.

Exposed as the `clawseccheck` console script (see pyproject.toml), as `python -m clawseccheck`,
and via the bundled skill entrypoint `python3 {baseDir}/audit.py`.

Read-only with respect to OpenClaw config.
Writes local ~/.clawseccheck score history by default unless --no-history/--trend/--monitor.
No network. Pure stdlib. Cross-platform.
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

from . import (
    audit, diff, fingerprint, load_events, load_ignore, load_state, make_canary, record_events,
    render_canary, render_card, render_dashboard, render_dashboard_findings, render_events,
    render_json, render_monitor,
    render_report, render_svg, render_vet_json, save_state, snapshot,
    detect_vet_type, vet_mcp, vet_plugin, vet_skill, vet_source,
)
from . import __released__, __version__
from .update import update_notice
from .ledger import freshness_notice as _compute_freshness, load_ledger, record_run
from . import risk as _risk
from .guide import render_next_actions, suggest_actions
from .integrity import package_digest
from .report import render_html
from .report import _sanitize
from .ansi import should_color, strip_ansi
from .monitor import DEFAULT_EVENTS, DEFAULT_STATE
from .redteam import make_suite, render_suite
from .dryrun import make_scenarios, render_dryrun
from .multiturn import make_multiturn, render_multiturn
from .sarif import render_sarif
from .history import DEFAULT_HISTORY, load as history_load, record as history_record, render_trend
from .menu import compute_ages, render_menu, render_onboarding
from .palette import render_palette
from .percentile import render_percentile
from .logsafe import get_logger
from .safeio import secure_write_text


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


# Vet-MCP icon / verdict constants — shared by the standalone --vet-mcp path
# and the embedded vet-mcp section inside --full.
_VET_ICON_ASCII: dict[str, str] = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]"}
_VET_ICON_UNI: dict[str, str] = {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔"}
_VET_VERDICT: dict[str, str] = {"FAIL": "DANGEROUS", "WARN": "SUSPICIOUS", "PASS": "SAFE", "UNKNOWN": "UNKNOWN"}


def vet_all(home_dir: Path, ascii_only: bool = False) -> int:
    """Vet every installed skill under home_dir/skills/.

    Finds all subdirectories of home_dir/skills/ that contain a SKILL.md file,
    runs vet_skill on each, prints per-skill verdicts and an aggregate summary
    table, then returns 0 if all findings are PASS/UNKNOWN, or 1 if any WARN/FAIL.
    """
    skills_dir = home_dir / "skills"
    if not skills_dir.exists():
        _emit(f"No skills directory found at {skills_dir}")
        return 0

    skill_paths: list[Path] = []
    try:
        for entry in sorted(skills_dir.iterdir()):
            if entry.is_dir() and (entry / "SKILL.md").exists():
                skill_paths.append(entry)
    except PermissionError as exc:
        _emit(f"(could not read skills directory: {exc})")
        return 0

    if not skill_paths:
        _emit(f"No skills found under {skills_dir}")
        return 0

    _ASCII = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]"}
    _UNI = {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔"}
    _VERDICT = {
        "FAIL": "DANGEROUS", "WARN": "SUSPICIOUS",
        "PASS": "looks SAFE", "UNKNOWN": "could not assess",
    }

    results: list[tuple[str, str, int]] = []  # (name, status, evidence_count)
    worst = "PASS"

    for skill_dir in skill_paths:
        skill_name = skill_dir.name
        _emit(f"\n=== {_sanitize(skill_name)} ===")
        try:
            f = vet_skill(str(skill_dir))
        except Exception as exc:  # noqa: BLE001
            _emit(f"  (error vetting {_sanitize(skill_name)}: {_sanitize(str(exc))})")
            results.append((skill_name, "UNKNOWN", 0))
            continue

        if f.status == "FAIL":
            worst = "FAIL"
        elif f.status == "WARN" and worst != "FAIL":
            worst = "WARN"

        icon = _ASCII[f.status] if ascii_only else _UNI[f.status]
        lines = [
            f"{icon} '{_sanitize(skill_name)}': {_VERDICT[f.status]} [{f.severity}]",
            f"    {_sanitize(f.detail)}",
        ]
        if f.evidence:
            bullet = "*" if ascii_only else "•"
            lines.append("    Evidence:")
            for ev in f.evidence[:12]:
                lines.append(f"      {bullet} {_sanitize(ev)}")
            if len(f.evidence) > 12:
                lines.append(f"      {bullet} (+{len(f.evidence) - 12} more)")
        lines.append(f"    {_sanitize(f.fix)}")
        _emit("\n".join(lines))

        results.append((skill_name, f.status, len(f.evidence) if f.evidence else 0))

    # Aggregate summary table
    _emit("")
    _emit("=" * 50)
    _emit("Aggregate summary:")
    col_w = max(len(r[0]) for r in results) + 2
    _emit(f"  {'Skill':<{col_w}} {'Verdict':<12} Evidence items")
    _emit(f"  {'-' * col_w} {'-' * 12} --------------")
    for name, status, ev_count in results:
        icon = _ASCII[status] if ascii_only else _UNI[status]
        _emit(f"  {name:<{col_w}} {icon} {_VERDICT[status]:<13} {ev_count}")

    total = len(results)
    fails = sum(1 for _, s, _ in results if s == "FAIL")
    warns = sum(1 for _, s, _ in results if s == "WARN")
    safe = total - fails - warns
    _emit(f"\n  {total} skill(s) checked | {safe} safe | {warns} suspicious | {fails} dangerous")

    return 0 if worst in ("PASS", "UNKNOWN") else 1


def _run_vet_mcp(target, args, ascii_only: bool) -> int:
    """Run vet_mcp on `target` (None = all configured servers) and render the
    result — shared by the explicit --vet-mcp mode and the --vet autodetect
    route (F-072), so the two entry points can never drift."""
    findings = vet_mcp(target=target, home=args.home)
    # Side output: SARIF file (mirrors the full-audit --sarif behavior, incl.
    # the same graceful handling of an unwritable path — B-014).
    if args.sarif:
        try:
            secure_write_text(
                Path(args.sarif).expanduser(),
                render_sarif(findings, tool_version=__version__),
            )
            _emit(f"(SARIF written to {args.sarif})")
        except OSError as exc:
            _emit(f"(could not write SARIF: {exc})")
    # Primary output: machine-readable JSON (covers the no-servers UNKNOWN case too).
    if args.json:
        _emit(render_vet_json(findings, mode="vet-mcp",
                              target=target or "configured", version=__version__))
        worst = "PASS"
        for f in findings:
            if f.status == "FAIL":
                worst = "FAIL"
                break
            if f.status == "WARN" and worst != "FAIL":
                worst = "WARN"
        record_run("vet_mcp")
        return 0 if worst in ("PASS", "UNKNOWN") else 1
    # "No servers configured" case: single UNKNOWN finding.
    if len(findings) == 1 and findings[0].status == "UNKNOWN":
        f = findings[0]
        icon = "[?]" if ascii_only else "❔"
        _emit(f"{icon} {f.detail}")
        record_run("vet_mcp")
        return 0
    worst_status = "PASS"
    for f in findings:
        if f.status == "FAIL":
            worst_status = "FAIL"
            break
        if f.status == "WARN" and worst_status != "FAIL":
            worst_status = "WARN"
    for f in findings:
        icon = _VET_ICON_ASCII[f.status] if ascii_only else _VET_ICON_UNI[f.status]
        verdict = _VET_VERDICT[f.status]
        _emit(f"{icon} {verdict}: {_sanitize(f.title)}")
        if f.evidence:
            for ev in f.evidence[:4]:
                _emit(f"    - {_sanitize(ev)}")
        _emit(f"    fix: {_sanitize(f.fix)}")
        _emit("")
    record_run("vet_mcp")
    return 0 if worst_status in ("PASS", "UNKNOWN") else 1


# --- Flag-coherence pre-flight (B-066 / B-067) ---------------------------------
# main() resolves "modes" via a fixed-order cascade of early returns; a second mode
# flag, or a global modifier the chosen mode doesn't honor, would otherwise be dropped
# silently. We never change a mode's behavior — we only surface, on stderr (so
# machine-readable stdout stays clean), what is being ignored. Warn-and-continue.

# Primary modes in the EXACT precedence order main() resolves them below.
# kind "opt" → active when the value is not None; "bool" → active when truthy.
_PRIMARY_MODES = [
    ("menu", "--menu", "bool"),
    ("functions", "--functions", "bool"),
    ("verify_self", "--verify-self", "bool"),
    ("vet", "--vet", "opt"),
    ("vet_skill", "--vet-skill", "opt"),
    ("vet_plugin", "--vet-plugin", "opt"),
    ("vet_all", "--vet-all", "bool"),
    ("vet_mcp", "--vet-mcp", "opt"),
    ("vet_source", "--vet-source", "opt"),
    ("canary", "--canary", "bool"),
    ("redteam", "--redteam", "bool"),
    ("dryrun", "--dryrun", "bool"),
    ("multiturn", "--multiturn", "bool"),
    ("self_test", "--self-test", "bool"),
    ("ask", "--ask", "bool"),
    ("show_suppressed", "--show-suppressed", "bool"),
    ("watch_log", "--watch-log", "bool"),
    ("risk_paths", "--risk-paths", "bool"),
    ("badge", "--badge", "opt"),
    ("html", "--html", "opt"),
    ("sarif", "--sarif", "opt"),
    ("trend", "--trend", "bool"),
    ("percentile", "--percentile", "bool"),
    ("next", "--next", "bool"),
    ("dashboard", "--dashboard", "bool"),
    ("dashboard_findings", "--dashboard-findings", "bool"),
    ("monitor", "--monitor", "bool"),
]

# Which tracked global modifiers each primary mode actually honors. The default
# report path (no primary mode) honors all of them. --sarif additionally rides
# along as a side output under --vet/--vet-mcp (handled specially below).
_MODE_HONORS = {
    "vet": frozenset({"json"}),
    "vet_skill": frozenset({"json"}),
    "vet_plugin": frozenset({"json"}),
    "vet_mcp": frozenset({"json"}),
    "vet_source": frozenset({"json"}),
}

# Primary modes that run AFTER the --attest block in main()'s cascade: their findings
# come from audit(attestation=...), so --attest is genuinely consumed there, not ignored.
_ATTEST_CONSUMERS = frozenset({
    "risk_paths", "badge", "html", "sarif", "trend", "percentile",
    "next", "dashboard", "dashboard_findings", "monitor",
})


def _mode_active(args, attr: str, kind: str) -> bool:
    v = getattr(args, attr, None)
    return v is not None if kind == "opt" else bool(v)


def _flag_coherence_notes(args) -> list[str]:
    """Notes for ignored modes / no-effect global modifiers. Never mutates args."""
    active = [(a, f) for a, f, k in _PRIMARY_MODES if _mode_active(args, a, k)]
    notes: list[str] = []
    if not active:
        # No primary mode: the default path resolves output as --json > --card > text.
        # If both format flags are set, --json wins and --card is silently dropped.
        if bool(getattr(args, "json", False)) and bool(getattr(args, "card", False)):
            notes.append("note: --card ignored (running --json)")
        return notes  # the default path honors every tracked global modifier
    win_attr, win_flag = active[0]
    ignored = [
        f for a, f in active[1:]
        # --sarif is a side output under --vet/--vet-mcp, not an ignored mode.
        if not (a == "sarif" and win_attr in ("vet", "vet_skill", "vet_plugin", "vet_mcp"))
    ]
    # --card is a default-path output selector; any primary mode supersedes it.
    if bool(getattr(args, "card", False)):
        ignored.append("--card")
    if ignored:
        notes.append(f"note: {', '.join(ignored)} ignored (running {win_flag})")
    honored = _MODE_HONORS.get(win_attr, frozenset())
    no_effect: list[str] = []
    if bool(getattr(args, "json", False)) and "json" not in honored:
        no_effect.append("--json")
    if getattr(args, "save", None) is not None and "save" not in honored:
        no_effect.append("--save")
    if bool(getattr(args, "exit_code", False)) and "exit_code" not in honored:
        no_effect.append("--exit-code")
    if getattr(args, "fail_under", None) is not None and "fail_under" not in honored:
        no_effect.append("--fail-under")
    # --full / --attest are enrichment modifiers a winning primary mode can silently
    # defeat (B-068). --full is consumed only on the default report path, so ANY
    # winning mode drops it. --attest feeds audit(), so modes that run AFTER the
    # attest block genuinely consume it (their findings reflect B43/B44) — only the
    # early-returning modes (menu/vet/live-test family) truly ignore it.
    if bool(getattr(args, "full", False)) and "full" not in honored:
        no_effect.append("--full")
    if getattr(args, "attest", None) is not None and win_attr not in _ATTEST_CONSUMERS:
        no_effect.append("--attest")
    # --trend / --monitor record a score-history point as part of their job, so
    # --no-history cannot suppress it there (every other mode either records on the
    # default path or writes no history at all, where --no-history is a no-op).
    if win_attr in ("trend", "monitor") and bool(getattr(args, "no_history", False)):
        no_effect.append("--no-history")
    if no_effect:
        notes.append(f"note: {', '.join(no_effect)} has no effect with {win_flag}")
    return notes


def _onboarding_reason(home: Path) -> str | None:
    """Screen-13 trigger: is there genuinely nothing to audit?

    Returns ``"missing"`` (home path absent), ``"empty"`` (home is a bare directory),
    or ``None`` (something is there — hand off to the normal audit path). A home that
    exists but is unreadable (perms) returns ``None`` on purpose: that is the "config
    present but unreadable" case, which the dashboard/error path surfaces distinctly —
    onboarding must not hide a real, permission-blocked setup behind a welcome screen.
    """
    if not home.exists():
        return "missing"
    try:
        if home.is_dir() and not any(home.iterdir()):
            return "empty"
    except OSError:
        return None
    return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="clawseccheck",
                                description="ClawSecCheck OpenClaw security self-audit (read-only).")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__} ({__released__})",
                   help="print version and exit")
    p.add_argument("--home", default="~/.openclaw", help="OpenClaw home dir (default: ~/.openclaw)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--card", action="store_true", help="print only the shareable badge")
    p.add_argument("--functions", action="store_true",
                   help="print the full capability palette (everything the skill can do, "
                        "as speakable prompts) and exit — Screen 12, reached from the menu")
    p.add_argument("--menu", action="store_true",
                   help="print the capability menu (the guided Welcome screen) and exit")
    p.add_argument("--ascii", action="store_true", help="ASCII-only output (no unicode icons/box)")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI colour (also honoured via the NO_COLOR env var; "
                        "colour is auto-off when output is not a terminal)")
    p.add_argument("--no-native", action="store_true",
                   help="do not also run the built-in `openclaw security audit`")
    p.add_argument("--no-host", action="store_true",
                   help="skip host-monitor detection (IDS / audit / FIM / EDR / firewall posture)")
    p.add_argument("--save", metavar="PATH", help="also write the report to a file")
    p.add_argument("--monitor", action="store_true",
                   help="monitor mode: alert on what changed since the last check")
    p.add_argument("--state", default=DEFAULT_STATE, metavar="PATH",
                   help=f"snapshot file for --monitor (default: {DEFAULT_STATE})")
    p.add_argument("--events", default=DEFAULT_EVENTS, metavar="PATH",
                   help=f"Agent Watch event journal (default: {DEFAULT_EVENTS})")
    p.add_argument("--watch-log", action="store_true",
                   help="print the Agent Watch event journal (timeline of what changed)")
    p.add_argument("--vet", metavar="TARGET",
                   help="vet a skill / plugin / MCP target BEFORE installing it — the type is "
                        "autodetected by content (explicit flags below force an engine)")
    p.add_argument("--vet-skill", metavar="PATH", dest="vet_skill",
                   help="vet a skill (dir or SKILL.md) for malware BEFORE installing it")
    p.add_argument("--vet-plugin", metavar="PATH", dest="vet_plugin",
                   help="vet an OpenClaw plugin (root dir or openclaw.plugin.json) "
                        "BEFORE installing it")
    p.add_argument("--vet-mcp", nargs="?", const="", metavar="NAME|FILE",
                   help="vet configured MCP servers (or a NAME/FILE) for supply-chain risk before trusting them")
    p.add_argument("--vet-source", metavar="SLUG|URL|PKG", dest="vet_source",
                   help="pre-download reputation gate: vet the identity of a source (IOC / typosquat / "
                        "host heuristics) BEFORE fetching anything — zero network, bundled catalogs")
    p.add_argument("--vet-all", "--recursive", action="store_true", dest="vet_all",
                   help="vet every installed skill under ~/.openclaw/skills/* (one verdict per skill + aggregate)")
    p.add_argument("--canary", action="store_true",
                   help="active prompt-injection canary self-test")
    p.add_argument("--redteam", action="store_true",
                   help="print a live red-team payload suite for adversarial self-testing")
    p.add_argument("--seed", default=None, metavar="VALUE",
                   help="fixed seed for --redteam tokens (reproducible CI runs); "
                        "default is a fresh random seed each run")
    p.add_argument("--dryrun", action="store_true",
                   help="print a behavioral dry-run harness (prompt-injection self-test across all sources)")
    p.add_argument("--multiturn", action="store_true",
                   help="print a two-phase multi-turn taint harness (plant a poisoned rule, "
                        "then trigger it in a later turn)")
    p.add_argument("--self-test", action="store_true",
                   help="run canary + live red-team + dry-run harnesses together")
    p.add_argument("--full", action="store_true",
                   help="run audit + self-test + vet-mcp in one command "
                        "(human output path; self-test emits deterministic test material only, "
                        "does not attack; extra sections skipped in --json / --card mode)")
    p.add_argument("--ask", action="store_true",
                   help="emit an attestation template (JSON) for the agent to self-report "
                        "facts the config can't show; fill it, then pass --attest")
    p.add_argument("--attest", metavar="PATH",
                   help="enrich the audit with an agent self-report JSON (enables B43/B44); "
                        "use '-' to read the JSON from stdin")
    p.add_argument("--badge", metavar="PATH", help="write a shareable SVG badge to PATH")
    p.add_argument("--html", metavar="PATH", help="write a standalone HTML report to PATH")
    p.add_argument("--show-suppressed", action="store_true",
                   help="list suppressed finding ids + fingerprints and exit")
    p.add_argument("--verify-self", action="store_true",
                   help="print the SHA-256 digest of the ClawSecCheck engine source for tamper detection")
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
    p.add_argument("--no-update-notice", action="store_true",
                   help="suppress the offline 'your build may be stale' reminder "
                        "(also suppressible via CLAWSECCHECK_NO_UPDATE_NOTICE=1; offline, never a network call)")
    p.add_argument("--no-freshness-notice", action="store_true",
                   help="suppress the coverage-freshness reminder for opt-in tests "
                        "(also suppressible via CLAWSECCHECK_NO_FRESHNESS_NOTICE=1; offline, never a network call)")
    p.add_argument("--next", action="store_true",
                   help="print recommended next actions based on the audit result")
    p.add_argument("--dashboard", action="store_true",
                   help="print the deterministic chat Dashboard card (grade + FIX FIRST "
                        "projection + framed findings, Sections 1-3) and exit")
    p.add_argument("--dashboard-findings", action="store_true",
                   help="print only the framed Section-3 Findings block for the chat Dashboard "
                        "(FAIL/WARN, high-confidence, grouped by family) and exit")
    p.add_argument("--risk-paths", action="store_true",
                   help="print only the highest-risk capability chains and exit")
    p.add_argument("--verbose", action="store_true",
                   help="emit INFO-level log breadcrumbs to stderr")
    p.add_argument("--debug", action="store_true",
                   help="emit DEBUG-level log breadcrumbs to stderr")
    p.add_argument("--log", metavar="PATH", default=None,
                   help="also write log output to PATH (only when given)")
    args = p.parse_args(argv)

    # Surface (on stderr) any second mode flag or global modifier the resolved mode
    # won't honor, so nothing is dropped silently (B-066 / B-067). Warn-and-continue:
    # the cascade below is unchanged.
    for _note in _flag_coherence_notes(args):
        print(_note, file=sys.stderr)

    ascii_only = args.ascii or not _unicode_ok()
    # Colour is a terminal-only presentation layer: auto-off when piped/redirected,
    # always overridable by --no-color / NO_COLOR (see ansi.should_color). Saved reports
    # are stripped back to plain text below so files never carry escape codes.
    use_color = should_color(no_color_flag=args.no_color)

    # Set up safe logger early — level from --verbose/--debug; file only when --log given.
    logger = get_logger(
        verbose=getattr(args, "verbose", False),
        debug=getattr(args, "debug", False),
        logfile=getattr(args, "log", None),
    )

    # standalone modes that don't audit ~/.openclaw
    if args.verify_self:
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

    if args.menu:
        # The guided Welcome screen as a runnable command. Read-only: reads local
        # score history for the "last check" nudge and the offline staleness hint;
        # no network, no writes, no record_run().
        rows = history_load(args.history)
        last_check = rows[-1]["date"] if rows else None
        build_age, last_days = compute_ages(released=__released__, last_check=last_check)
        stale = bool(update_notice(__version__, released=__released__))
        _emit(render_menu(version=__version__, build_age_days=build_age,
                          last_check_days=last_days, stale=stale, ascii_only=ascii_only))
        return 0

    if args.functions:
        # Screen 12 — the full capability palette (Welcome's "menu"/item 4 expands here).
        # Read-only: no scan, no network, no writes — just the grounded capability list.
        from .checks import CHECKS  # noqa: PLC0415
        _emit(render_palette(n_checks=len(CHECKS), ascii_only=ascii_only))
        return 0

    # F-072 (D1): --vet autodetects the artifact type by content and routes to the
    # right engine; --vet-skill / --vet-plugin / --vet-mcp are the explicit escape
    # hatches. The detected-type note goes to stderr so machine stdout stays clean.
    _vet_route = None  # (kind, target) with kind in {"skill", "plugin", "mcp"}
    if args.vet:
        detected = detect_vet_type(args.vet, home=args.home)
        print(f"detected type: {detected}", file=sys.stderr)
        # 'unknown' routes to the skill engine, which answers with an honest UNKNOWN —
        # exactly today's --vet behavior for a non-skill target (never a guessed PASS).
        _vet_route = (detected if detected in ("plugin", "mcp") else "skill", args.vet)
    elif getattr(args, "vet_skill", None):
        _vet_route = ("skill", args.vet_skill)
    elif getattr(args, "vet_plugin", None):
        _vet_route = ("plugin", args.vet_plugin)

    if _vet_route and _vet_route[0] in ("skill", "plugin"):
        vet_kind, vet_path = _vet_route
        vet_target = Path(vet_path).expanduser()
        f = vet_skill(vet_path) if vet_kind == "skill" else vet_plugin(vet_path)
        # rc: FAIL/WARN → 1 (dangerous/suspicious target);
        # UNKNOWN + target absent (not found / path unusable) → 1;
        # UNKNOWN + target exists (valid target, inconclusive assessment) → 0;
        # PASS → 0.
        if f.status in ("FAIL", "WARN"):
            _vet_rc = 1
        elif f.status == "UNKNOWN" and not vet_target.exists():
            _vet_rc = 1
        else:
            _vet_rc = 0
        # Record the run in the coverage ledger, symmetric with --vet-mcp (C-128).
        # freshness_notice has no "vet" threshold, so this updates the ledger without
        # adding a staleness nudge — it just keeps the vet modes consistent.
        record_run("vet" if vet_kind == "skill" else "vet_plugin")
        # Side output: SARIF file (mirrors the full-audit --sarif behavior, incl.
        # the same graceful handling of an unwritable path — B-014).
        if args.sarif:
            try:
                secure_write_text(
                    Path(args.sarif).expanduser(),
                    render_sarif([f, *getattr(f, "ring_findings", [])],
                                 tool_version=__version__, ctx=getattr(f, "ctx", None)),
                )
                _emit(f"(SARIF written to {args.sarif})")
            except OSError as exc:
                _emit(f"(could not write SARIF: {exc})")
        # Primary output: machine-readable JSON, else the human text report.
        if args.json:
            _emit(render_vet_json([f, *getattr(f, "ring_findings", [])],
                                  mode="vet" if vet_kind == "skill" else "vet-plugin",
                                  target=vet_path, version=__version__))
            return _vet_rc
        verdict = {"FAIL": "DANGEROUS", "WARN": "SUSPICIOUS", "PASS": "looks SAFE",
                   "UNKNOWN": "could not assess"}[f.status]
        icon = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]"}[f.status] \
            if ascii_only else {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔"}[f.status]
        safe_vet = _sanitize(vet_path)
        lines = [f"{icon} Vetting '{safe_vet}': {verdict} [{f.severity}]", f"    {_sanitize(f.detail)}"]
        if f.evidence:
            bullet = "*" if ascii_only else "•"
            lines.append("    Evidence:")
            for ev in f.evidence[:12]:
                lines.append(f"      {bullet} {_sanitize(ev)}")
            if len(f.evidence) > 12:
                lines.append(f"      {bullet} (+{len(f.evidence) - 12} more)")
        lines.append(f"    {_sanitize(f.fix)}")
        ring = getattr(f, "ring_findings", [])
        if ring:
            bullet = "*" if ascii_only else "•"
            lines.append("    Additional signals:")
            for rf in ring[:12]:
                lines.append(f"      {bullet} [{rf.status}] {rf.id} — {_sanitize(rf.detail)}")
            if len(ring) > 12:
                lines.append(f"      {bullet} (+{len(ring) - 12} more)")
        _emit("\n".join(lines))
        return _vet_rc

    if _vet_route and _vet_route[0] == "mcp":
        # --vet routed to the MCP engine: mode "vet" keeps its table precedence
        # (above --vet-all), so the shared renderer runs here, not further below.
        return _run_vet_mcp(_vet_route[1], args, ascii_only)

    if args.vet_all:
        home_dir = Path(args.home).expanduser()
        return vet_all(home_dir, ascii_only=ascii_only)

    if args.vet_mcp is not None:
        return _run_vet_mcp(args.vet_mcp if args.vet_mcp else None, args, ascii_only)

    if getattr(args, "vet_source", None):
        # F-073: pre-download reputation gate — identity only, zero network, no fetch.
        f = vet_source(args.vet_source)
        _src_rc = 1 if f.status in ("FAIL", "WARN") else 0
        record_run("vet_source")
        if args.json:
            _emit(render_vet_json([f], mode="vet-source",
                                  target=args.vet_source, version=__version__))
            return _src_rc
        band = {"FAIL": "KNOWN-BAD — do not fetch",
                "WARN": "SUSPICIOUS — quarantine only",
                "UNKNOWN": "no known-bad record — proceed via quarantine"}[f.status]
        icon = {"FAIL": "[X]", "WARN": "[!]", "UNKNOWN": "[?]"}.get(f.status, "[?]") \
            if ascii_only else {"FAIL": "⛔", "WARN": "⚠️", "UNKNOWN": "❔"}.get(f.status, "❔")
        lines = [f"{icon} Source vet '{_sanitize(args.vet_source)}': {band} [{f.severity}]",
                 f"    {_sanitize(f.detail)}"]
        if f.evidence:
            bullet = "*" if ascii_only else "•"
            for ev in f.evidence[:8]:
                lines.append(f"      {bullet} {_sanitize(ev)}")
        lines.append(f"    {_sanitize(f.fix)}")
        _emit("\n".join(lines))
        return _src_rc

    if args.canary:
        _emit(render_canary(make_canary(), ascii_only))
        record_run("self_test")
        return 0

    if args.redteam:
        seed = args.seed if args.seed is not None else secrets.token_hex(8)
        _emit(render_suite(make_suite(seed), ascii_only, seed=seed))
        record_run("self_test")
        return 0

    if args.dryrun:
        _emit(render_dryrun(make_scenarios(), ascii_only))
        record_run("self_test")
        return 0

    if args.multiturn:
        _emit(render_multiturn(make_multiturn(), ascii_only))
        record_run("self_test")
        return 0

    if args.self_test:
        seed = args.seed if args.seed is not None else secrets.token_hex(8)
        _emit(render_canary(make_canary(), ascii_only))
        _emit("")
        _emit(render_suite(make_suite(seed), ascii_only, seed=seed))
        _emit("")
        _emit(render_dryrun(make_scenarios(), ascii_only))
        _emit("")
        _emit(render_multiturn(make_multiturn(), ascii_only))
        record_run("self_test")
        return 0

    if args.ask:
        import json as _json  # noqa: PLC0415
        from . import attest as _attest  # noqa: PLC0415
        _emit(_json.dumps(_attest.template(), indent=2, ensure_ascii=False))
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

    if args.watch_log:
        _emit(render_events(load_events(args.events), ascii_only))
        return 0

    attestation = None
    if args.attest:
        from . import attest as _attest  # noqa: PLC0415
        if args.attest == "-":
            attestation = _attest.parse_attestation(sys.stdin.read())
            src = "stdin"
        else:
            attestation = _attest.load_attestation(Path(args.attest).expanduser())
            src = args.attest
        if not attestation:
            # Diagnostic, not report content: keep machine-readable stdout (--json/--sarif)
            # clean — a stdout warning here corrupts `--attest bad.json --json` (B-070).
            print(f"⚠ could not read a valid attestation from {src} "
                  "(ignored; B43/B44 stay UNKNOWN). See 'clawseccheck --ask'.",
                  file=sys.stderr)

    # First-run onboarding (Screen 13): when there is genuinely nothing to audit —
    # ~/.openclaw missing, or an empty directory — don't render a wall of UNKNOWNs;
    # show a friendly "point me at your config" screen. BARE human runs only: any
    # machine/CI/artifact/work flag (--json/--card, --fail-under/--exit-code, --save,
    # --full, --badge/--html/--sarif, --attest, or any primary mode) takes the normal
    # audit path so nothing is silently dropped and CI gates keep failing loud (B-075).
    # Checked BEFORE audit() so a missing home never burns a scan or the native-audit
    # subprocess just to print a welcome.
    _bare_run = (
        not any(_mode_active(args, a, k) for a, _f, k in _PRIMARY_MODES)
        and not args.json and not args.card and not args.save and not args.full
        and args.fail_under is None and not args.exit_code and not args.attest
    )
    if _bare_run:
        first_run = _onboarding_reason(Path(args.home).expanduser())
        if first_run:
            from .checks import CHECKS  # noqa: PLC0415
            _emit(render_onboarding(reason=first_run, home=_sanitize(args.home),
                                    n_checks=len(CHECKS), ascii_only=ascii_only))
            return 0

    logger.info("auditing home=%s", args.home)
    # A home that exists but can't be read at all must be a controlled, honest outcome
    # for a security tool — a plain-language error, never a raw traceback (B-076).
    try:
        ctx, findings, score = audit(args.home, include_native=not args.no_native,
                                     include_host=not args.no_host,
                                     attestation=attestation)
    except (PermissionError, OSError) as exc:
        _emit(f"Cannot read the OpenClaw home at {_sanitize(args.home)}: {_sanitize(str(exc))}")
        _emit("Fix the permissions (or run as the owning user) and re-run the audit.")
        return 1
    logger.debug("ran %d checks", len(findings))
    logger.info("score=%s grade=%s", score.score, score.grade)

    paths = _risk.risk_paths(ctx, findings)

    if args.risk_paths:
        _emit(_risk.render_risk_paths(paths, ascii_only=ascii_only))
        return 0

    if args.badge:
        try:
            secure_write_text(Path(args.badge).expanduser(), render_svg(score, findings))
            _emit(
                f"(badge written to {args.badge} — attach this SVG file as-is; "
                "do not redraw, rasterize, or generate your own badge image)"
            )
            return 0
        except OSError as exc:
            _emit(f"(could not write badge: {exc})")
            return 1

    if args.html:
        try:
            secure_write_text(
                Path(args.html).expanduser(),
                render_html(findings, score, native=ctx.native),
            )
            _emit(f"(HTML report written to {args.html})")
            return 0
        except OSError as exc:
            _emit(f"(could not write HTML report: {exc})")
            return 1

    if args.sarif:
        try:
            secure_write_text(Path(args.sarif).expanduser(), render_sarif(findings, score, __version__, ctx=ctx))
            _emit(f"(SARIF written to {args.sarif})")
            return 0
        except OSError as exc:
            _emit(f"(could not write SARIF: {exc})")
            return 1

    if args.trend:
        # --trend's job is to record the point AND show the trend, so it records even
        # under --no-history (a documented, tested contract). The conflict is surfaced
        # as a stderr note by _flag_coherence_notes rather than silently honored (B-066).
        history_record(score, args.history)
        rows = history_load(args.history)
        _emit(render_trend(rows, ascii_only))
        _emit(render_percentile(score.score, ascii_only))
        return 0

    if args.percentile:
        _emit(render_percentile(score.score, ascii_only))
        return 0

    if args.next:
        _emit(render_next_actions(suggest_actions(findings, score), ascii_only))
        return 0

    if args.dashboard:
        _emit(render_dashboard(findings, score, ascii_only=ascii_only))
        return 0

    if args.dashboard_findings:
        _emit(render_dashboard_findings(findings, ascii_only=ascii_only))
        return 0

    if args.monitor:
        prev = load_state(args.state)
        snap = snapshot(ctx, findings, score)
        alerts = diff(prev, snap)
        _emit(render_monitor(alerts, score, ascii_only, baseline=prev is None))
        try:
            save_state(args.state, snap)
        except OSError as exc:
            _emit(f"\n(could not save monitor state: {exc})")
        record_events(alerts, args.events)  # Agent Watch: append the drift to the local journal
        # --monitor records a score-history point as part of tracking drift, even under
        # --no-history; the conflict is surfaced as a stderr note (B-066), not silently
        # honored, to keep monitor's drift baseline intact.
        history_record(score, args.history)
        return 0

    if args.json:
        body = render_json(findings, score, risk=paths, ctx=ctx)
    elif args.card:
        body = render_card(score, findings, ascii_only)
    else:
        # Offline staleness advisory — human report only; never in --json/--card/--sarif.
        # Reads only the local clock + an optional local hint file; makes no network call.
        notice = []
        if not args.no_update_notice and not os.environ.get("CLAWSECCHECK_NO_UPDATE_NOTICE"):
            notice = update_notice(__version__, released=__released__)
        # Coverage freshness advisory — human report only; never in --json/--card/--sarif.
        # Reads only the local coverage ledger and the local clock; makes no network call.
        # Advisory only: never alters score, grade, or findings.
        f_notice: list[str] = []
        if not args.no_freshness_notice and not os.environ.get("CLAWSECCHECK_NO_FRESHNESS_NOTICE"):
            # Under --full the self-test + vet-mcp sections run later in this same
            # invocation and refresh their ledger entries, so suppress their
            # freshness lines here — otherwise the report prints "never run" directly
            # above the sections that run them (the freshness is computed pre-run).
            _refreshed = ("self_test", "vet_mcp") if args.full else ()
            f_notice = _compute_freshness(load_ledger(), skip=_refreshed)
        parts = [render_report(findings, score, ascii_only, native=ctx.native,
                               risk=paths, update_notice=notice, freshness_notice=f_notice,
                               openclaw_detected=ctx.config_found, ctx=ctx, color=use_color),
                 "", render_card(score, findings, ascii_only)]
        if ctx.errors:
            parts.append("\nnotes:\n" + "\n".join(f"  - {_sanitize(e)}" for e in ctx.errors))
        parts.append("")
        parts.append(render_next_actions(
            suggest_actions(findings, score), ascii_only))
        body = "\n".join(parts)

    _emit(body)

    vm_has_fail = False
    if args.full and not args.json and not args.card:
        # --- Self-test section (canary + red-team + dry-run) ---
        seed = args.seed if args.seed is not None else secrets.token_hex(8)
        _emit("")
        _emit("=" * 60)
        _emit("CLAWSECCHECK SELF-TEST")
        _emit("=" * 60)
        _emit(render_canary(make_canary(), ascii_only))
        _emit("")
        _emit(render_suite(make_suite(seed), ascii_only, seed=seed))
        _emit("")
        _emit(render_dryrun(make_scenarios(), ascii_only))
        _emit("")
        _emit(render_multiturn(make_multiturn(), ascii_only))
        record_run("self_test")
        # --- vet-mcp section ---
        _emit("")
        _emit("=" * 60)
        _emit("CLAWSECCHECK VET-MCP")
        _emit("=" * 60)
        vm_findings = vet_mcp(target=None, home=args.home)
        if len(vm_findings) == 1 and vm_findings[0].status == "UNKNOWN":
            vmf = vm_findings[0]
            vm_icon = "[?]" if ascii_only else "❔"
            _emit(f"{vm_icon} {vmf.detail}")
        else:
            vm_has_fail = any(vmf.status == "FAIL" for vmf in vm_findings)
            for vmf in vm_findings:
                vm_icon = _VET_ICON_ASCII[vmf.status] if ascii_only else _VET_ICON_UNI[vmf.status]
                vm_verdict = _VET_VERDICT[vmf.status]
                _emit(f"{vm_icon} {vm_verdict}: {_sanitize(vmf.title)}")
                if vmf.evidence:
                    for vm_ev in vmf.evidence[:4]:
                        _emit(f"    - {_sanitize(vm_ev)}")
                _emit(f"    fix: {_sanitize(vmf.fix)}")
                _emit("")
        record_run("vet_mcp")

    _save_failed = False
    if args.save:
        try:
            # Persist plain text — a saved report must never carry ANSI escape codes,
            # even when the on-screen copy was colourised for the terminal.
            secure_write_text(Path(args.save).expanduser(), strip_ansi(body))
            _emit(f"\n(report saved to {args.save})")
        except OSError as exc:
            _emit(f"\n(could not save report: {exc})")
            _save_failed = True

    if not args.no_history and not args.trend and not args.monitor:
        history_record(score, args.history)

    if _save_failed:
        return 1

    if args.fail_under is not None and score.score < args.fail_under:
        return 1

    if args.exit_code:
        has_fail = any(
            not getattr(f, "suppressed", False) and f.status == "FAIL"
            for f in findings
        )
        if has_fail or vm_has_fail:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
