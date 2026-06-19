"""ClawCheck — OpenClaw security self-audit engine (read-only, stdlib-only).

The local checks are offline and never shell out. Optionally (`include_native`)
ClawCheck also runs the user's own `openclaw security audit` and surfaces those
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
from .monitor import diff, load_state, save_state, snapshot
from .native import run_native_audit
from .report import (
    render_card, render_json, render_monitor, render_prompts, render_report, render_svg,
)
from .scoring import ScoreResult, compute
from .i18n import t, tp, title_for, is_rtl
from .sarif import render_sarif
from .history import load as history_load, record as history_record, render_trend, DEFAULT_HISTORY
from .guide import suggest_actions, render_next_actions

__version__ = "0.14.0"


def audit(home: Path | str = "~/.openclaw", include_native: bool = False,
          native_bin: str = "openclaw", native_timeout: int = 60):
    """Run the full audit. Returns (ctx, findings, ScoreResult).

    `include_native=False` keeps the engine fully offline (default, hermetic for
    tests). The CLI passes `include_native=True` so end users also get OpenClaw's
    built-in `openclaw security audit` findings in the same report.
    """
    ctx = collect(home)
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
    "render_svg", "render_prompts", "vet_skill", "vet_mcp",
    "make_canary", "evaluate", "render_canary",
    "snapshot", "diff", "load_state", "save_state", "__version__",
    "load_ignore", "apply_baseline", "fingerprint",
    "t", "tp", "title_for", "is_rtl",
    "render_sarif",
    "history_load", "history_record", "render_trend", "DEFAULT_HISTORY",
    "suggest_actions", "render_next_actions",
]
