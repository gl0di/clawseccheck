"""ClawSecCheck — OpenClaw security self-audit engine (read-only, stdlib-only).

The local checks are offline and never shell out. Optionally (`include_native`)
ClawSecCheck also runs the user's own `openclaw security audit` and surfaces those
findings too — the single, fixed, read-only external command it can run.
"""
from __future__ import annotations

from pathlib import Path

from . import baseline as _baseline
from .baseline import apply as apply_baseline
from .baseline import fingerprint, load_ignore
from .canary import evaluate, make_canary, render_canary
from .checks import run_all, vet_mcp, vet_skill
from .collector import collect
from .hostwatch import detect as _host_detect
from .monitor import (
    DEFAULT_EVENTS, diff, load_events, load_state, record_events, save_state, snapshot,
)
from .native import run_native_audit
from .report import (
    render_card, render_events, render_fix, render_json, render_monitor, render_prompts,
    render_report, render_svg, render_vet_json,
)
from .risk import risk_paths, render_risk_paths
from .scoring import ScoreResult, compute
from .i18n import t, tp, title_for, is_rtl
from .sarif import render_sarif
from .history import load as history_load, record as history_record, render_trend, DEFAULT_HISTORY
from .guide import suggest_actions, render_next_actions
from .update import update_notice, read_latest_hint, DEFAULT_LATEST

__version__ = "1.14.0"
# Build/release date, baked in at release time (offline staleness nudge reads this; no network).
__released__ = "2026-06-24"


def audit(home: Path | str = "~/.openclaw", include_native: bool = False,
          include_host: bool = False, host_root: str = "/",
          native_bin: str = "openclaw", native_timeout: int = 60,
          attestation: dict | None = None):
    """Run the full audit. Returns (ctx, findings, ScoreResult).

    `include_native=False` and `include_host=False` keep the engine fully offline
    (default, hermetic for tests). The CLI passes both as True so end users also get
    OpenClaw's built-in `openclaw security audit` findings and the host-monitor
    posture (B50–B54) in the same report.

    Host detection is populated BEFORE run_all so the B50–B54 checks can read it.
    When off, ctx.host stays None and those checks report UNKNOWN (no score impact).

    `attestation` (the agent's self-report; see attest.py) enriches the audit: when
    omitted, the attestation checks (B43/B44) report UNKNOWN and the score is
    unchanged. Passed straight through to ctx so the engine stays deterministic.
    """
    ctx = collect(home)
    ctx.include_host = include_host
    if include_host:
        ctx.host = _host_detect(root=host_root)
    if attestation:
        ctx.attestation = attestation
    findings = run_all(ctx)
    ignore = _baseline.load_ignore(home)
    _baseline.apply(findings, ignore)
    score = compute(findings)
    if include_native:
        ctx.native = run_native_audit(native_bin, native_timeout)
    return ctx, findings, score


__all__ = [
    "audit", "collect", "run_all", "compute", "ScoreResult", "run_native_audit",
    "render_report", "render_card", "render_json", "render_monitor",
    "render_svg", "render_prompts", "render_fix", "render_vet_json", "vet_skill", "vet_mcp",
    "make_canary", "evaluate", "render_canary",
    "snapshot", "diff", "load_state", "save_state", "__version__", "__released__",
    "update_notice", "read_latest_hint", "DEFAULT_LATEST",
    "record_events", "load_events", "render_events", "DEFAULT_EVENTS",
    "load_ignore", "apply_baseline", "fingerprint",
    "t", "tp", "title_for", "is_rtl",
    "render_sarif",
    "history_load", "history_record", "render_trend", "DEFAULT_HISTORY",
    "suggest_actions", "render_next_actions",
    "risk_paths", "render_risk_paths",
]
