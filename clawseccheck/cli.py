"""ClawSecCheck command-line interface.

Exposed as the `clawseccheck` console script (see pyproject.toml), as `python -m clawseccheck`,
and via the bundled skill entrypoint `python3 {baseDir}/audit.py`.

Read-only with respect to OpenClaw config.
Writes local ~/.clawseccheck score history by default; opt out with --no-history.
C-251: --trend and --monitor are NOT suppressors of that write — they are the two modes
that record a history point unconditionally, as part of their own job, so --no-history
has no effect on them (see _flag_coherence_notes / the --no-history --help text).
No network. Pure stdlib. Cross-platform.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import date
from pathlib import Path

from . import (
    audit, diff, fingerprint, load_events, load_ignore, make_canary, record_events,
    render_canary, render_card, render_dashboard, render_dashboard_findings, render_events,
    render_json, render_monitor,
    render_report, render_svg, render_vet_json, save_state, snapshot,
    detect_vet_type, vet_mcp, vet_plugin, vet_skill, vet_source,
)
from . import __released__, __version__
from .brand import WORDMARK
from .collector import SKILL_DIRS
# B-270: the shared baseline predicate. Imported from the submodule rather than the package
# root so the new vocabulary does not have to widen the curated public API in __init__.py.
from .monitor import (
    BASELINE_ABSENT, BASELINE_CORRUPT, BASELINE_CORRUPT_ALERT, BASELINE_OK, read_baseline,
)
from .update import update_notice
from .ledger import freshness_notice as _compute_freshness, load_ledger, record_run
from . import risk as _risk
from .guide import render_next_actions, suggest_actions
from .integrity import package_digest
from .report import render_html
from .report import (
    _sanitize,
    render_advise,
    render_advise_json,
    render_permission_manifest,
    render_vet_dossier,
    render_vet_plan,
    surfaced_despite_suppression,
)
from .adjudication import (
    escalate_vet_output,
    render_ignore_proposals_json,
    render_judge_packet_json,
    render_judged_json,
    render_vet_judge_packet_json,
)
from .baseline import append_entries, is_fingerprint
from .dossier import build_profile
from .ansi import should_color, strip_ansi
from .monitor import DEFAULT_EVENTS, DEFAULT_STATE, verify_chain
from .tamperscore import tamper_subgrade
from .redteam import make_suite, render_suite
from .dryrun import make_scenarios, render_dryrun
from .multiturn import make_multiturn, render_multiturn
from .sarif import render_sarif
from .history import (
    DEFAULT_HISTORY,
    load as history_load,
    record as history_record,
    render_trend,
    verify as history_verify,
)
from .menu import compute_ages, render_menu, render_onboarding
from .palette import render_palette
from .percentile import render_percentile
from .logsafe import get_logger
from .safeio import secure_write_text
from .incident import render_incident
from .trajaudit import render_trajectory_analysis
from .behavioral import render_behavioral_analysis
from .sbom import render_sbom


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


def _record_run(capability: str, args) -> None:
    """Coverage-ledger write, gated by --no-history (B-156).

    Every opt-in capability path (vet/vet-mcp/vet-plugin/vet-source/self-test
    family/behavioral) funnels through here instead of calling
    ``ledger.record_run`` directly, so ``--no-history`` reliably suppresses
    the ``~/.clawseccheck/coverage.json`` write everywhere, not just on the
    audit-trend path (Golden Rule #2: local-only / no surprise writes).
    """
    if getattr(args, "no_history", False):
        return
    record_run(capability)


# Vet-MCP icon / verdict constants — shared by the standalone --vet-mcp path
# and the embedded vet-mcp section inside --full.
_VET_ICON_ASCII: dict[str, str] = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]"}
_VET_ICON_UNI: dict[str, str] = {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔"}
_VET_VERDICT: dict[str, str] = {"FAIL": "DANGEROUS", "WARN": "SUSPICIOUS", "PASS": "NO KNOWN ISSUE", "UNKNOWN": "UNKNOWN"}


def vet_all(home_dir: Path, ascii_only: bool = False) -> int:
    """Vet every installed skill discovered under any of collector.SKILL_DIRS.

    Mirrors the real OpenClaw skill-discovery locations the full audit engine
    already uses (skills/, workspace/skills/, workspace-home/skills/,
    workspace-work/skills/, .agents/skills/ — see collector.SKILL_DIRS), not
    just the single legacy home_dir/skills/ path (B-147). Finds all
    subdirectories across those roots that contain a SKILL.md file, dedups by
    resolved path, runs vet_skill on each, prints per-skill verdicts and an
    aggregate summary table, then returns 0 if all findings are PASS/UNKNOWN,
    or 1 if any WARN/FAIL.
    """
    skill_paths: list[Path] = []
    seen: set[Path] = set()
    checked_dirs: list[Path] = []
    for rel in SKILL_DIRS:
        skills_dir = home_dir / rel
        try:
            if not skills_dir.is_dir():
                continue
            checked_dirs.append(skills_dir)
            for entry in sorted(skills_dir.iterdir()):
                if not (entry.is_dir() and (entry / "SKILL.md").exists()):
                    continue
                try:
                    resolved = entry.resolve()
                except OSError:
                    resolved = entry
                if resolved in seen:
                    continue
                seen.add(resolved)
                skill_paths.append(entry)
        except PermissionError as exc:
            _emit(f"(could not read skills directory {skills_dir}: {exc})")
            continue

    if not checked_dirs:
        _emit(f"No skills directory found under {home_dir}")
        return 0

    if not skill_paths:
        dirs_str = ", ".join(str(d) for d in checked_dirs)
        _emit(f"No skills found under {dirs_str}")
        return 0

    _ASCII = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]"}
    _UNI = {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔"}
    _VERDICT = {
        "FAIL": "DANGEROUS", "WARN": "SUSPICIOUS",
        "PASS": "looks like no known issue", "UNKNOWN": "could not assess",
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
    verdict_w = max(len(v) for v in _VERDICT.values()) + 1
    _emit(f"  {'Skill':<{col_w}} {'Verdict':<{verdict_w}} Evidence items")
    _emit(f"  {'-' * col_w} {'-' * verdict_w} --------------")
    for name, status, ev_count in results:
        icon = _ASCII[status] if ascii_only else _UNI[status]
        _emit(f"  {name:<{col_w}} {icon} {_VERDICT[status]:<{verdict_w}} {ev_count}")

    total = len(results)
    fails = sum(1 for _, s, _ in results if s == "FAIL")
    warns = sum(1 for _, s, _ in results if s == "WARN")
    safe = total - fails - warns
    _emit(f"\n  {total} skill(s) checked | {safe} safe | {warns} suspicious | {fails} dangerous")

    return 0 if worst in ("PASS", "UNKNOWN") else 1


def _run_vet_mcp(target, args, ascii_only: bool) -> int:
    """Run vet_mcp on `target` (None = all configured servers) and render the risk
    dossier — shared by the explicit --vet-mcp mode and the --vet autodetect route
    (F-072), so the two entry points can never drift."""
    findings = vet_mcp(target=target, home=args.home)
    profile = build_profile(findings, target or "configured", "mcp")
    # Side output: SARIF file (mirrors the full-audit --sarif behavior, incl. the same
    # graceful handling of an unwritable path — B-014).
    if args.sarif:
        try:
            secure_write_text(
                Path(args.sarif).expanduser(),
                render_sarif(findings, tool_version=__version__, profile=profile),
            )
            _emit(f"(SARIF written to {args.sarif})")
        except OSError as exc:
            _emit(f"(could not write SARIF: {exc})")
    _record_run("vet_mcp", args)
    _vet_rc = 1 if profile.overall_status in ("FAIL", "WARN") else 0
    if args.json:
        _emit(render_vet_json(profile, mode="vet-mcp", version=__version__))
    else:
        _emit(render_vet_dossier(profile, ascii_only=ascii_only))
    return _vet_rc


# --- Flag-coherence pre-flight (B-066 / B-067) ---------------------------------
# main() resolves "modes" via a fixed-order cascade of early returns; a second mode
# flag, or a global modifier the chosen mode doesn't honor, would otherwise be dropped
# silently. We never change a mode's behavior — we only surface, on stderr (so
# machine-readable stdout stays clean), what is being ignored. Warn-and-continue.

# Primary modes in the EXACT precedence order main() resolves them below.
# kind "opt" → active when the value is not None; "bool" → active when truthy.
#
# B-276: this list used to be hand-ordered and had drifted from _main()'s real
# cascade in 27 pairs — so _flag_coherence_notes named the WRONG winner. The worst
# case was `--monitor --judge-packet`: stderr said "--judge-packet ignored (running
# --monitor)" while _main() actually ran --judge-packet at :1048 (before --monitor at
# :1074), printed the judge packet, and never advanced the monitor baseline. The note
# accused the mode that had in fact won. Detection was deferred, not destroyed (the
# baseline never advanced, so a later monitor-only run still fires), but three
# consecutive combined runs each returned rc=0, wrote nothing, and repeated the lie.
#
# The order below is now the order tests/test_mode_drift_guard.py extracts from
# _main()'s top-level `if` cascade, and that test asserts EQUALITY, not membership.
# Reordering this list changes only which mode the stderr note NAMES — dispatch has
# always been decided by _main()'s cascade and is untouched.
_PRIMARY_MODES = [
    ("purge", "--purge", "bool"),
    ("apply_ignore_proposals", "--apply-ignore-proposals", "opt"),
    ("verify_self", "--verify-self", "bool"),
    ("verify_history", "--verify-history", "bool"),
    ("verify_events", "--verify-events", "bool"),
    ("vet_plan", "--vet-plan", "opt"),
    ("menu", "--menu", "bool"),
    ("functions", "--functions", "bool"),
    ("vet", "--vet", "opt"),
    ("vet_skill", "--vet-skill", "opt"),
    ("vet_plugin", "--vet-plugin", "opt"),
    ("vet_all", "--vet-all", "bool"),
    ("vet_mcp", "--vet-mcp", "opt"),
    ("vet_source", "--vet-source", "opt"),
    ("advise", "--advise", "opt"),
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
    ("sbom", "--sbom", "bool"),
    ("incident", "--incident", "bool"),
    ("judge_packet", "--judge-packet", "bool"),
    ("judged", "--judged", "opt"),
    ("propose_ignore", "--propose-ignore", "opt"),
    ("analyze_trajectory", "--analyze-trajectory", "opt"),
    ("behavioral", "--behavioral", "opt"),
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
    "advise": frozenset({"json"}),
}

# Primary modes that run AFTER the --attest block in main()'s cascade: their ctx and
# findings come from audit(attestation=...), so --attest is genuinely consumed there,
# not ignored. This is exactly the tail of _PRIMARY_MODES from "risk_paths" onward —
# every mode dispatched below the audit() call at _main():~960 — and
# tests/test_mode_drift_guard.py derives that tail from the AST and asserts equality,
# so the set cannot drift from the cascade again.
#
# B-301 (adjacent): "behavioral" was missing here, so `--behavioral --attest f.json`
# printed "note: --attest has no effect with --behavioral" — false in the opposite
# direction, since T3 reads ctx.attestation. "sbom", "incident", "judge_packet",
# "judged" and "analyze_trajectory" were missing for the same reason.
_ATTEST_CONSUMERS = frozenset({
    "risk_paths", "badge", "html", "sarif", "trend", "percentile",
    "next", "dashboard", "dashboard_findings", "sbom", "incident",
    "judge_packet", "judged", "propose_ignore", "analyze_trajectory",
    "behavioral", "monitor",
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
        # --quiet only collapses --full's appended sections; alone it has nothing to do.
        if bool(getattr(args, "quiet", False)) and not bool(getattr(args, "full", False)):
            notes.append("note: --quiet has no effect without --full")
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
    # --quiet is a --full modifier; a winning primary mode drops --full, so --quiet too.
    if bool(getattr(args, "quiet", False)) and "full" not in honored:
        no_effect.append("--quiet")
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


# --- --purge: opt-in, confirmation-gated local-store cleanup (C-164) -----------

# The ONLY files --purge will ever touch, plus their advisory-lock sidecars
# (locking.journal_lock creates "<file>.lock" next to history.jsonl/events.jsonl).
# Deliberately a fixed whitelist, never a glob/rmtree of the store directory —
# an unrelated file a user happens to keep in ~/.clawseccheck/ must never be at risk.
_PURGE_FILENAMES = ("history.jsonl", "events.jsonl", "state.json", "coverage.json")


def _confirm_purge(paths: "list[Path]") -> "tuple[bool, bool]":
    """Print the exact files to be deleted and ask for confirmation.

    Returns (proceed, eof):
      - (True, False)  — explicit y/yes answer: proceed.
      - (False, False) — any other typed answer (including blank/"n"): declined,
        a normal (non-error) abort.
      - (False, True)  — EOFError (no stdin / non-interactive): abort loudly,
        the caller reports this as an error (rc 1), never a silent proceed.
    Kept as its own function so tests can monkeypatch it.
    """
    _emit("The following files will be permanently deleted:")
    for p in paths:
        _emit(f"  {p}")
    try:
        answer = input("Delete these files? [y/N]: ")
    except EOFError:
        return False, True
    return answer.strip().lower() in ("y", "yes"), False


def _run_purge(args) -> int:
    """Delete ClawSecCheck's local store (opt-in, confirmation-gated).

    Resolves the store directory from --history's parent (all four known files
    live alongside each other under ~/.clawseccheck/ by default). Operates ONLY
    on the fixed whitelist of known filenames plus their ".lock" sidecars —
    never globs or rmtree's the directory, so an unrelated file the user happens
    to keep there is never at risk. Read-only until the user (or --yes) confirms.
    """
    store_dir = Path(args.history).expanduser().parent
    candidates = [store_dir / name for name in _PURGE_FILENAMES]
    candidates += [store_dir / (name + ".lock") for name in _PURGE_FILENAMES]
    existing = [p for p in candidates if p.exists()]

    if not existing:
        _emit("Nothing to purge — no ClawSecCheck local store files found.")
        return 0

    if not args.yes:
        proceed, eof = _confirm_purge(existing)
        if not proceed:
            if eof:
                _emit("Purge aborted — no confirmation input available (not a tty / EOF).")
                return 1
            _emit("Purge aborted — no files were deleted.")
            return 0
    else:
        _emit("The following files will be permanently deleted:")
        for p in existing:
            _emit(f"  {p}")

    deleted = 0
    for p in existing:
        try:
            p.unlink()
            deleted += 1
        except OSError as exc:
            _emit(f"(could not delete {p}: {exc})")

    _emit(f"Purged {deleted} file(s) from {store_dir}.")
    return 0


# --- --apply-ignore-proposals: opt-in, confirmation-gated (C-253) --------------

def _confirm_apply_ignore(entries: "list[str]", ignore_path: Path) -> "tuple[bool, bool]":
    """Same (proceed, eof) contract as _confirm_purge — kept separate so tests can
    monkeypatch either confirmation independently."""
    _emit(f"The following entries will be appended to {ignore_path}:")
    for e in entries:
        _emit(f"  {e}")
    try:
        answer = input("Apply these judge-proposed suppressions? [y/N]: ")
    except EOFError:
        return False, True
    return answer.strip().lower() in ("y", "yes"), False


def _run_apply_ignore_proposals(args) -> int:
    """Apply a --propose-ignore output (opt-in, confirmation-gated, C-253).

    Reads the exact JSON --propose-ignore rendered and appends each proposal's
    ``entry`` fingerprint to <home>/.clawseccheckignore via baseline.append_entries.
    Never invents an entry beyond what that file already listed — this step can
    only mutate the SAME suppression mechanism baseline.py already implements, and
    every existing safety property (a suppressed score-capping CRITICAL/HIGH FAIL or
    a SENSITIVE_SUPPRESSED_IDS id still surfaces; any .clawseccheckignore change is
    still flagged by --monitor) is untouched by this being the write's origin.
    """
    try:
        raw = Path(args.apply_ignore_proposals).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        _emit(f"clawseccheck: could not read proposals file ({type(exc).__name__}).")
        return 1
    try:
        data = json.loads(raw)
    except ValueError:
        _emit("clawseccheck: proposals file is not valid JSON.")
        return 1
    proposals = data.get("proposedIgnoreEntries") if isinstance(data, dict) else None
    if not isinstance(proposals, list):
        _emit("clawseccheck: proposals file has no 'proposedIgnoreEntries' list — nothing to apply.")
        return 1
    # C-135 (2026-07-22): only ever apply something SHAPED like a real fingerprint()
    # output. A hand-crafted (not genuinely --propose-ignore-produced) proposals file
    # could otherwise carry a bare "entry": "B1"/"B2"/"B20" and suppress that id
    # file-wide via apply()'s bare-id match — exactly what this command's whole
    # premise ("only ever what --propose-ignore already offered") is meant to rule
    # out. A non-fingerprint entry is skipped and named, never silently dropped.
    entries: list = []
    rejected: list = []
    for p in proposals:
        if not (isinstance(p, dict) and isinstance(p.get("entry"), str)):
            continue
        candidate = p["entry"].strip()
        if not candidate:
            continue
        if is_fingerprint(candidate):
            entries.append(candidate)
        else:
            rejected.append(candidate)
    if rejected:
        _emit(
            "clawseccheck: ignoring "
            f"{len(rejected)} proposal entr{'y' if len(rejected) == 1 else 'ies'} not "
            f"shaped like a real fingerprint (refusing to apply): {', '.join(rejected)}"
        )
    if not entries:
        _emit("Nothing to apply — no proposed entries in that file.")
        return 0

    ignore_path = Path(args.home).expanduser() / ".clawseccheckignore"
    if not args.yes:
        proceed, eof = _confirm_apply_ignore(entries, ignore_path)
        if not proceed:
            if eof:
                _emit("Apply aborted — no confirmation input available (not a tty / EOF).")
                return 1
            _emit("Apply aborted — no entries were written.")
            return 0
    else:
        _emit(f"The following entries will be appended to {ignore_path}:")
        for e in entries:
            _emit(f"  {e}")

    try:
        written = append_entries(
            args.home, entries, comment=f"judge-proposed, applied {date.today().isoformat()}"
        )
    except OSError as exc:
        # C-135: append_entries writes via safeio.secure_append_text, which refuses
        # to follow a symlinked .clawseccheckignore (OSError/ELOOP) rather than
        # writing through it — surface that plainly instead of a generic crash.
        _emit(f"clawseccheck: could not write {ignore_path} ({type(exc).__name__}); nothing applied.")
        return 1
    _emit(f"Applied {written} judge-proposed suppression(s) to {ignore_path}.")
    return 0


def main(argv=None) -> int:
    """Thin top-level guard (B-101): never dump a raw traceback at users.

    Any unexpected error inside the audit/render pipeline becomes a clean one-line
    stderr message (stdout stays clean for --json/--sarif). The full traceback is
    shown only under --debug. KeyboardInterrupt / SystemExit propagate untouched —
    they derive from BaseException, not Exception. Only the exception *type* is
    named, never its message, so a path or config value can't leak (§8, B-076).
    """
    try:
        return _main(argv)
    except Exception as exc:  # noqa: BLE001 — a security tool must fail readably, not crash
        raw = list(sys.argv[1:] if argv is None else argv)
        if "--debug" in raw:
            raise
        print(
            f"clawseccheck: unexpected internal error ({type(exc).__name__}); "
            "re-run with --debug for the traceback.",
            file=sys.stderr,
        )
        return 1


def _main(argv=None) -> int:
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
                   help=f"Agent Watch event journal, read by --watch-log/--incident and "
                        f"written by --monitor (default: {DEFAULT_EVENTS})")
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
    p.add_argument("--advise", metavar="PATH", dest="advise",
                   help="INSTALL / CAUTION / DO-NOT-INSTALL recommendation for a quarantined "
                        "skill or plugin (dir autodetected same as --vet), with reasons + a "
                        "cleanup command — pairs with --vet-plan")
    p.add_argument("--vet-plan", metavar="SLUG|URL|PKG", dest="vet_plan",
                   help="print the zero-network fetch+isolate+advise+cleanup commands for "
                        "vetting a source before installing it (the tool never touches the "
                        "network — you or your agent run these commands)")
    p.add_argument("--incident", action="store_true",
                   help="print a local, read-only incident-response evidence pack: findings "
                        "snapshot, skill/MCP hashes (--sbom), trajectory-sidecar hashes, the "
                        "credential rotation list, and monitor event history from --events "
                        "(recorded in the pack as monitor_events_source) — never rotates "
                        "or deletes anything itself")
    p.add_argument("--analyze-trajectory", nargs="?", const="", default=None, metavar="PATH",
                   dest="analyze_trajectory",
                   help="post-hoc incident analysis: correlate installed skills' credential / "
                        "exfil / secret-path indicators against tool.call arguments in OpenClaw "
                        "trajectory sidecars (agents/*/sessions/*.trajectory.jsonl) to see if a "
                        "skill's instruction was actually acted on at runtime. Read-only; reads "
                        "data.arguments only in memory to test known indicators, never echoes "
                        "raw args. Optional PATH to one .trajectory.jsonl; default scans the home")
    p.add_argument("--behavioral", nargs="?", const="", default=None, metavar="PATH",
                   dest="behavioral",
                   help="behavioral trajectory audit: reconstruct observed tool-call SEQUENCES "
                        "from OpenClaw trajectory sidecars (agents/*/sessions/*.trajectory.jsonl) "
                        "and flag a proven-by-log behavioral trifecta (T1: ingress -> sensitive "
                        "-> egress verb order) or an outcome anomaly (T2: repeated failure then "
                        "success on a sensitive verb). Read-only, metadata-only — never reads "
                        "call/return payloads, only verb identity and sequencing. WARN-only, "
                        "never scored. Optional PATH to one .trajectory.jsonl; default scans "
                        "the home")
    p.add_argument("--emit-manifest", action="store_true", dest="emit_manifest",
                   help="print a proposed permission manifest (YAML-shaped) derived from "
                        "static effect analysis; use with --vet/--vet-skill on a single skill")
    p.add_argument("--vet-judge-packet", action="store_true", dest="vet_judge_packet",
                   help="use with --vet/--vet-skill/--vet-plugin: print the vetted "
                        "target's own borderline findings as JSON for a host-agent judge "
                        "— never changes the vet verdict")
    p.add_argument("--vet-judged", metavar="PATH", dest="vet_judged",
                   help="use with --vet/--vet-skill/--vet-plugin: feed back a host-agent "
                        "judge panel's verdicts for a prior --vet-judge-packet — the judge "
                        "may only ESCALATE a finding (never lower one) since this is "
                        "untrusted third-party content, not the user's own config; "
                        "use '-' to read from stdin")
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
    p.add_argument("--quiet", action="store_true",
                   help="only with --full: collapse the appended self-test and vet-mcp "
                        "sections to one-line summaries (lighter for CI logs / scroll); the "
                        "full detail stays available via --self-test / --vet-mcp")
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
                   help="do not record this run to the local score history (default: record) "
                        "— has no effect under --trend/--monitor, which always record one "
                        "regardless (a stderr note says so if combined)")
    p.add_argument("--verify-history", action="store_true",
                   help="verify the score history file's tamper-evident hash-chain and exit")
    p.add_argument("--verify-events", action="store_true",
                   help="verify the Agent Watch event journal's (--events) tamper-evident "
                        "hash-chain and exit — same check as --verify-history, run against "
                        "--events instead of --history")
    p.add_argument("--purge", action="store_true",
                   help="delete ClawSecCheck's local store (history/events/state/coverage "
                        "files + their lock sidecars) and exit — confirmation-gated unless "
                        "--yes is also given; nothing else is touched")
    p.add_argument("--apply-ignore-proposals", metavar="PATH", dest="apply_ignore_proposals",
                   help="apply a --propose-ignore output: append its proposed entries to "
                        "<home>/.clawseccheckignore — confirmation-gated unless --yes is also "
                        "given; never invents entries beyond what that file already proposed")
    p.add_argument("--yes", action="store_true",
                   help="skip the interactive confirmation prompt for --purge or "
                        "--apply-ignore-proposals (for scripted use); has no effect without "
                        "one of those two")
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
    p.add_argument("--sbom", action="store_true",
                   help="export a local bill-of-materials (skills, MCP servers, hashes, "
                        "declared/unpinned deps) as deterministic JSON to stdout and exit")
    p.add_argument("--judge-packet", action="store_true", dest="judge_packet",
                   help="export the borderline finding band (UNKNOWN, FN-prone WARN, "
                        "B62, dropped taint) as JSON for a host-agent judge to review "
                        "— never changes the grade")
    p.add_argument("--judged", metavar="PATH", dest="judged",
                   help="feed back a host-agent judge panel's verdicts JSON for a prior "
                        "--judge-packet; renders the audit's UNCHANGED grade/findings plus "
                        "an advisory secondOpinion panel — use '-' to read from stdin")
    p.add_argument("--propose-ignore", metavar="PATH", dest="propose_ignore",
                   help="feed back a host-agent judge panel's verdicts JSON for a prior "
                        "--judge-packet; prints PROPOSED (not applied) .clawseccheckignore "
                        "entries for findings verdicted SAFE — use '-' to read from stdin, "
                        "then --apply-ignore-proposals to actually write them")
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
    if args.purge:
        # Dispatched FIRST, before any audit()/history-record call-site below, so
        # purge can never race its own uninstall by writing a fresh history point.
        return _run_purge(args)

    if args.apply_ignore_proposals:
        # C-253: like --purge, this only touches its own known file (.clawseccheckignore
        # under --home) and needs no audit() pass, so it is dispatched here too.
        return _run_apply_ignore_proposals(args)

    if args.verify_self:
        combined, per_file = package_digest()
        lines = [f"{WORDMARK} {__version__} — engine source digest (SHA-256)",
                 f"combined : {combined}",
                 ""]
        for name, digest in sorted(per_file.items()):
            lines.append(f"  {digest}  {name}")
        lines.append("")
        lines.append("Compare the 'combined' value against the digest printed by a trusted release.")
        lines.append("Any mismatch means a source file was modified after that release.")
        lines.append(f"Trusted digest: see SHA256SUMS.txt on the v{__version__} GitHub Release, signed via cosign.")
        lines.append("")
        lines.append("A checksum you just read off a web page or a chat reply proves nothing by")
        lines.append("itself — it could be tampered with too. Verify the cosign signature instead")
        lines.append("(after downloading SHA256SUMS.txt and SHA256SUMS.txt.bundle from that Release):")
        lines.append("")
        lines.append("  cosign verify-blob \\")
        lines.append("    --bundle SHA256SUMS.txt.bundle \\")
        lines.append('    --certificate-identity-regexp "^https://github.com/gl0di/clawseccheck/" \\')
        lines.append("    --certificate-oidc-issuer https://token.actions.githubusercontent.com \\")
        lines.append("    SHA256SUMS.txt")
        _emit("\n".join(lines))
        return 0

    if args.verify_history:
        ok, msg = history_verify(args.history)
        if ok:
            _emit(f"History chain OK ({args.history}): {msg}")
            return 0
        _emit(f"History chain BROKEN ({args.history}): {msg}")
        return 1

    if args.verify_events:
        # C-250(c): --verify-history --history <events-path> already verified an events
        # journal correctly (verify_chain() is the same entry-agnostic algorithm for both
        # journals — see history.verify()'s own docstring), but its output always said
        # "History chain" regardless of which journal was actually named. This is the
        # discoverable, correctly-worded entry point --events users were missing.
        ok, msg = verify_chain(args.events)
        if ok:
            _emit(f"Events chain OK ({args.events}): {msg}")
            return 0
        _emit(f"Events chain BROKEN ({args.events}): {msg}")
        return 1

    if getattr(args, "vet_plan", None):
        # F-065: zero-network plan emitter — prints commands, touches nothing itself.
        _emit(render_vet_plan(args.vet_plan))
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

    if args.emit_manifest and not (_vet_route and _vet_route[0] == "skill"):
        print(
            "note: --emit-manifest requires --vet/--vet-skill on a single skill; ignored",
            file=sys.stderr,
        )
    if (args.vet_judge_packet or args.vet_judged) and not (
        _vet_route and _vet_route[0] in ("skill", "plugin")
    ):
        print(
            "note: --vet-judge-packet/--vet-judged require --vet/--vet-skill/--vet-plugin "
            "on a single skill or plugin; ignored",
            file=sys.stderr,
        )

    if _vet_route and _vet_route[0] in ("skill", "plugin"):
        vet_kind, vet_path = _vet_route
        vet_target = Path(vet_path).expanduser()
        f = vet_skill(vet_path) if vet_kind == "skill" else vet_plugin(vet_path)
        # C-254: use with --vet/--vet-skill/--vet-plugin only (checked above) — a
        # distinct stdout artifact, same pattern as --emit-manifest below.
        if args.vet_judge_packet:
            _emit(render_vet_judge_packet_json(f, target=vet_path, version=__version__))
            return 0
        if args.vet_judged:
            if args.vet_judged == "-":
                verdicts_raw = sys.stdin.read()
            else:
                try:
                    verdicts_raw = Path(args.vet_judged).expanduser().read_text(encoding="utf-8")
                except OSError:
                    verdicts_raw = ""
            # Escalate-only: rebuild f's ring_findings so a borderline finding can only
            # rank higher, never lower, than the deterministic engine already ranked it
            # (adjudication._escalated_status). build_profile below is UNCHANGED —
            # it re-derives overall_status/score/grade from this pool the normal way.
            f = escalate_vet_output(f, verdicts_raw, target=vet_path)
        profile = build_profile(f, vet_path, vet_kind)
        # rc: overall FAIL/WARN → 1 (dangerous/suspicious target);
        # UNKNOWN + target absent (not found / path unusable) → 1;
        # UNKNOWN + target exists (valid target, inconclusive assessment) → 0;
        # PASS → 0.
        if profile.overall_status in ("FAIL", "WARN"):
            _vet_rc = 1
        elif profile.overall_status == "UNKNOWN" and not vet_target.exists():
            _vet_rc = 1
        else:
            _vet_rc = 0
        # --emit-manifest: a stdout side output, single-skill vet only (B98/F-083).
        # Never runs the normal dossier/JSON render below — this is a distinct artifact.
        if args.emit_manifest and vet_kind == "skill":
            _emit(render_permission_manifest(getattr(f, "ctx", None), vet_path))
            return _vet_rc
        # Record the run in the coverage ledger, symmetric with --vet-mcp (C-128).
        # freshness_notice has no "vet" threshold, so this updates the ledger without
        # adding a staleness nudge — it just keeps the vet modes consistent.
        _record_run("vet" if vet_kind == "skill" else "vet_plugin", args)
        # Side output: SARIF file (mirrors the full-audit --sarif behavior, incl.
        # the same graceful handling of an unwritable path — B-014).
        if args.sarif:
            try:
                secure_write_text(
                    Path(args.sarif).expanduser(),
                    render_sarif([f, *getattr(f, "ring_findings", [])],
                                 tool_version=__version__, ctx=getattr(f, "ctx", None),
                                 profile=profile),
                )
                _emit(f"(SARIF written to {args.sarif})")
            except OSError as exc:
                _emit(f"(could not write SARIF: {exc})")
        # Primary output: machine-readable JSON dossier, else the human dossier.
        if args.json:
            _emit(render_vet_json(profile,
                                  mode="vet" if vet_kind == "skill" else "vet-plugin",
                                  version=__version__))
            return _vet_rc
        _emit(render_vet_dossier(profile, ascii_only=ascii_only))
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
        profile = build_profile(f, args.vet_source, "source")
        _src_rc = 1 if profile.overall_status in ("FAIL", "WARN") else 0
        _record_run("vet_source", args)
        if args.json:
            _emit(render_vet_json(profile, mode="vet-source", version=__version__))
            return _src_rc
        _emit(render_vet_dossier(profile, ascii_only=ascii_only))
        return _src_rc

    if getattr(args, "advise", None):
        # F-067: same vet engines/profile as --vet, reframed as an install decision.
        advise_target = args.advise
        detected = detect_vet_type(advise_target, home=args.home)
        print(f"detected type: {detected}", file=sys.stderr)
        advise_kind = detected if detected in ("plugin",) else "skill"
        f = vet_skill(advise_target) if advise_kind == "skill" else vet_plugin(advise_target)
        profile = build_profile(f, advise_target, advise_kind)
        _advise_rc = 1 if profile.overall_status in ("FAIL", "WARN") else 0
        _record_run("vet" if advise_kind == "skill" else "vet_plugin", args)
        if args.json:
            _emit(render_advise_json(profile, version=__version__))
            return _advise_rc
        _emit(render_advise(profile, ascii_only=ascii_only))
        return _advise_rc

    if args.canary:
        _emit(render_canary(make_canary(), ascii_only))
        _record_run("self_test", args)
        return 0

    if args.redteam:
        seed = args.seed if args.seed is not None else secrets.token_hex(8)
        _emit(render_suite(make_suite(seed), ascii_only, seed=seed))
        _record_run("self_test", args)
        return 0

    if args.dryrun:
        _emit(render_dryrun(make_scenarios(), ascii_only))
        _record_run("self_test", args)
        return 0

    if args.multiturn:
        _emit(render_multiturn(make_multiturn(), ascii_only))
        _record_run("self_test", args)
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
        _record_run("self_test", args)
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
            # B-154: a bare "RISK-NN" entry matches a RiskPath.id, not any Finding —
            # surface those explicitly too, or --show-suppressed silently missed them.
            suppressed_risk = [p for p in _risk.risk_paths(ctx, findings, ignore=ignore)
                                if p.suppressed]
            if suppressed or suppressed_risk:
                for f in suppressed:
                    _emit(f"  {f.id}  {fingerprint(f)}  ({f.title})")
                for p in suppressed_risk:
                    _emit(f"  {p.id}  ({p.title})")
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

    # B-154: RISK-* chains must honor .clawseccheckignore too — pass the same
    # ignore set findings were suppressed with, then drop suppressed chains
    # before they reach any render/JSON path.
    _risk_ignore = load_ignore(Path(args.home).expanduser())
    paths = [p for p in _risk.risk_paths(ctx, findings, ignore=_risk_ignore)
             if not p.suppressed]

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

    if args.sbom:
        _emit(render_sbom(ctx))
        return 0

    if args.incident:
        # B-277: --events was accepted and silently dropped here, so the pack
        # harvested the DEFAULT journal no matter what the operator named. Threaded
        # like --watch-log (:~915) and --monitor (:~1078) already do.
        _emit(render_incident(ctx, findings, score, events=args.events))
        return 0

    if args.judge_packet:
        _emit(render_judge_packet_json(ctx, findings, version=__version__))
        return 0

    if args.judged:
        if args.judged == "-":
            verdicts_raw = sys.stdin.read()
        else:
            try:
                verdicts_raw = Path(args.judged).expanduser().read_text(encoding="utf-8")
            except OSError:
                verdicts_raw = ""
        _emit(render_judged_json(ctx, findings, score, verdicts_raw=verdicts_raw))
        return 0

    if args.propose_ignore:
        if args.propose_ignore == "-":
            verdicts_raw = sys.stdin.read()
        else:
            try:
                verdicts_raw = Path(args.propose_ignore).expanduser().read_text(encoding="utf-8")
            except OSError:
                verdicts_raw = ""
        _emit(render_ignore_proposals_json(findings, verdicts_raw=verdicts_raw, version=__version__))
        return 0

    if args.analyze_trajectory is not None:
        _emit(render_trajectory_analysis(
            ctx, explicit_path=args.analyze_trajectory or None, ascii_only=ascii_only))
        return 0

    if args.behavioral is not None:
        _record_run("behavioral", args)
        _emit(render_behavioral_analysis(
            ctx, explicit_path=args.behavioral or None, ascii_only=ascii_only))
        return 0

    if args.monitor:
        # B-270: ONE predicate decides what "no usable baseline" means, and it tells
        # *absent* (a real first run) apart from *corrupt* (a prior baseline existed and is
        # gone). Both used to collapse into `prev is None`, so a destroyed baseline
        # rendered the same reassuring "Baseline saved." line as a healthy first run.
        base_status, prev = read_baseline(args.state)
        # B-269: snapshot() needs the previous state so that a run which could not read
        # openclaw.json preserves the last known-good config baseline instead of writing
        # the collapsed (empty) view over it — see monitor._degrade_snapshot.
        snap = snapshot(ctx, findings, score, prev=prev)
        alerts = diff(prev, snap)
        if base_status == BASELINE_CORRUPT:
            # prev is None here, so diff() produced nothing to compare — the lost baseline
            # IS the event. Prepended (not rendered separately) so the identical string
            # reaches the screen and the tamper-evident journal.
            alerts = [BASELINE_CORRUPT_ALERT] + alerts
        # ── B-278 + B-271: write order is a deliberate choice, documented here ──────────
        # Journal FIRST, then advance the baseline, and skip the advance if the journal
        # write failed. The alternative (advance first) is what lost drift permanently: a
        # `chmod 0444` events.jsonl swallowed a CRITICAL gateway-exposure alert while the
        # baseline moved on, so the next run compared against the NEW state and reported
        # "No new threats" over an exposed gateway. Not advancing keeps the event
        # unconsumed: the same drift is re-detected next run and gets another chance to be
        # recorded. That re-detection is not a false alert — the change really is still
        # there — and a later, unrelated change is still caught, because the diff is taken
        # against the older baseline and reports the union.
        # The accepted cost: if the journal succeeds and the *state* write then fails, the
        # next run re-detects the same drift and journals it a second time. A duplicated
        # line in the timeline is strictly recoverable; a missing one is not, and the
        # duplicate only follows a failure that is now loud and non-zero anyway.
        journal_err = record_events(alerts, args.events)
        state_err = None
        if journal_err is None:
            try:
                save_state(args.state, snap)
            except OSError as exc:
                state_err = str(exc)
        persisted = journal_err is None and state_err is None
        # B-271: render AFTER the writes, and tell the renderer whether they landed — the
        # success wording used to be printed before the save was even attempted.
        _emit(render_monitor(alerts, score, ascii_only,
                             baseline=base_status == BASELINE_ABSENT,
                             persisted=persisted,
                             baseline_corrupt=base_status == BASELINE_CORRUPT))
        # --monitor records a score-history point as part of tracking drift, even under
        # --no-history; the conflict is surfaced as a stderr note (B-066), not silently
        # honored, to keep monitor's drift baseline intact. Recorded even on the failure
        # paths below: this run's score was really measured, and the trend should not gain
        # a hole because a different file was unwritable.
        history_record(score, args.history)
        # B-271/B-278: a write mode that could not write must not report success. --badge /
        # --html / --sarif / --save all return 1 on OSError; --monitor was the sole outlier,
        # returning 0 forever while persisting nothing, so cron saw a healthy job.
        if journal_err is not None:
            print(f"MONITORING NOT ESTABLISHED — could not record drift events to "
                  f"{args.events}: {journal_err}\n"
                  "The drift above was NOT written to the journal, so the baseline was "
                  "deliberately left unchanged and this run's changes will be re-reported "
                  "next time. Fix the journal path's permissions and re-run.",
                  file=sys.stderr)
            return 1
        if state_err is not None:
            print(f"MONITORING NOT ESTABLISHED — could not write monitor state to "
                  f"{args.state}: {state_err}\n"
                  "No baseline was saved, so this run cannot detect future changes. Fix "
                  "the state path's permissions and re-run.", file=sys.stderr)
            return 1
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
        # Tamper Score sub-grade — human report only; presentation-layer only, never
        # alters score/grade/findings. mon_present reflects whether a --monitor
        # baseline snapshot already exists on disk for this state file.
        # B-270: the SAME predicate the --monitor path uses, instead of this call site's
        # own `is not None` rule. A state file holding `{}` used to satisfy `is not None`
        # and earn full HIGH-weight tamper credit for a baseline that cannot detect
        # anything — measured on fixtures/home_safe as 24/100 vs 3/100 with no file at all.
        mon_present = read_baseline(args.state)[0] == BASELINE_OK
        tamper = tamper_subgrade(findings, mon_present)
        parts = [render_report(findings, score, ascii_only, native=ctx.native,
                               risk=paths, update_notice=notice, freshness_notice=f_notice,
                               openclaw_detected=ctx.config_found, ctx=ctx, color=use_color,
                               tamper=tamper),
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
        seed = args.seed if args.seed is not None else secrets.token_hex(8)
        if args.quiet:
            # C-110: --full --quiet — the appended self-test material + per-server
            # vet-mcp detail are what push --full to ~490 lines; collapse each to a
            # single honest summary line (the concise report above is unchanged).
            # The self-test harnesses emit generated adversarial *scenarios* for the
            # agent to run — there is no PASS/score the tool computes, so the summary
            # states counts, not a verdict (Golden Rule #4: no fabricated result).
            # record_run() / vm_has_fail still fire, so ledger freshness and
            # --exit-code behave identically to the verbose path.
            n_rt = len(make_suite(seed))
            n_dr = len(make_scenarios())
            n_mt = len(make_multiturn())
            _emit("")
            _emit(f"SELF-TEST: 1 canary + {n_rt} red-team + {n_dr} dry-run + {n_mt} multi-turn "
                  "injection scenario(s) generated — run them against your agent "
                  "(RESISTANT = good). Full harness: --self-test.")
            _record_run("self_test", args)
            vm_findings = vet_mcp(target=None, home=args.home)
            vm_has_fail = any(vmf.status == "FAIL" for vmf in vm_findings)
            if len(vm_findings) == 1 and vm_findings[0].status == "UNKNOWN":
                _emit(f"VET-MCP: {_sanitize(vm_findings[0].detail)}")
            else:
                _vc = {st: sum(1 for v in vm_findings if v.status == st)
                       for st in ("FAIL", "WARN", "PASS", "UNKNOWN")}
                _summary = (f"VET-MCP: {len(vm_findings)} server-check(s) — "
                            f"{_vc['FAIL']} FAIL, {_vc['WARN']} WARN, {_vc['PASS']} PASS")
                if _vc["UNKNOWN"]:
                    _summary += f", {_vc['UNKNOWN']} UNKNOWN"
                _emit(_summary + ". Full detail: --vet-mcp.")
            _record_run("vet_mcp", args)
        else:
            # --- Self-test section (canary + red-team + dry-run) ---
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
            _record_run("self_test", args)
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
            _record_run("vet_mcp", args)

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
            f.status == "FAIL"
            and (
                not getattr(f, "suppressed", False)
                or surfaced_despite_suppression(f)
            )
            for f in findings
        )
        # B-166: a present-but-unparseable openclaw.json produces only UNKNOWN/WARN, so a
        # FAIL-only gate would stay green on a broken config. Trip on it explicitly.
        if has_fail or vm_has_fail or getattr(ctx, "config_parse_error", False):
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
