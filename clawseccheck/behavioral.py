"""Behavioral trajectory audit — post-hoc sequence detectors over observed tool-call
order (E-032 v1, `--behavioral`). Layer 3, same "post-hoc/self-test" shelf as
`trajaudit.py`/`redteam.py`/`dryrun.py`.

Everything else in ClawSecCheck answers "what could the agent do" (static config +
skill-source audit). This module answers the complementary question: "what did the
agent actually DO" — reconstructed from OpenClaw's trajectory sidecar
(`agents/*/sessions/*.trajectory.jsonl`, schema grounded in
`docs/research/openclaw-schema-recon.md` §9.1), proven by the log rather than inferred
from declared capability.

§8 privacy boundary: reads ONLY `trajectory.read_events()`'s metadata — `type`, `name`,
`ts`, `seq`, `turnId`, `threadId`, `outcome`. NEVER reads `arguments`/`output`/`result`/
`contentItems` (the sensitive call/return payloads).

Findings are WARN-only, `scored=False` (Golden Rule #5) — a heuristic on observed VERB
NAMES classified by role (ingress/sensitive/egress), not on the untouched payload
content, so confidence stays MEDIUM even though "this verb ran" itself is log-observed
HIGH-confidence fact. T1/T2 never run as part of the main `audit()`/CHECKS list or the
A-F score — only through `--behavioral`, mirroring `--analyze-trajectory`'s own
`trajaudit.py` scope.
"""
from __future__ import annotations

from .catalog import PASS, WARN
from .checks import (
    INPUT_TOOL_HINTS,
    OUTBOUND_TOOL_HINTS,
    SENSITIVE_TOOL_HINTS,
    _finding,
)
from .trajectory import read_events


def _classify_verb_role(name: str | None) -> str | None:
    """Classify one tool verb as "ingress" / "sensitive" / "egress" / None.

    Reuses the SAME hint tuples A1 (the static Lethal Trifecta check) already uses for
    its config-side ingress/sensitive/outbound legs (`checks/_shared.py`) — a single
    source of truth for what counts as each role, never a forked taxonomy. Substring
    match on the lowered verb name, first matching role wins (ingress checked first: a
    verb like "web_fetch" is unambiguously an input source, not sensitive-data access).
    """
    if not name:
        return None
    n = name.lower()
    if any(h in n for h in INPUT_TOOL_HINTS):
        return "ingress"
    if any(h in n for h in SENSITIVE_TOOL_HINTS):
        return "sensitive"
    if any(h in n for h in OUTBOUND_TOOL_HINTS):
        return "egress"
    return None


def _sort_key(event: dict):
    """Deterministic (seq, ts) ordering key — events with a missing/non-int seq sort
    after those with one (so partial data never silently reorders known-good events)."""
    seq = event.get("seq")
    has_seq = isinstance(seq, int)
    return (0 if has_seq else 1, seq if has_seq else 0, str(event.get("ts") or ""))


def group_events_by_thread(events: list[dict]) -> dict[str, list[dict]]:
    """Group events by `threadId` (fallback `turnId`), each group sorted by (seq, ts).

    Events with neither threadId nor turnId fall into one shared "" bucket — a known,
    documented limitation (rare in grounded real data; every observed tool.call/
    tool.result carries at least a turnId), not silently dropped.
    """
    groups: dict[str, list[dict]] = {}
    for ev in events:
        key = ev.get("threadId") or ev.get("turnId") or ""
        groups.setdefault(str(key), []).append(ev)
    for key in groups:
        groups[key].sort(key=_sort_key)
    return groups


# ---------------------------------------------------------------------------
# T1 — behavioral trifecta: ingress-verb -> sensitive-verb -> egress-verb, in that
# order (by seq/ts), within one thread.
# ---------------------------------------------------------------------------

def _t1_thread_trifecta(thread_events: list[dict]) -> bool:
    """True when this thread's events show ingress before sensitive before egress."""
    seen_ingress = False
    seen_sensitive_after_ingress = False
    for ev in thread_events:
        role = _classify_verb_role(ev.get("name"))
        if role == "ingress":
            seen_ingress = True
        elif role == "sensitive" and seen_ingress:
            seen_sensitive_after_ingress = True
        elif role == "egress" and seen_sensitive_after_ingress:
            return True
    return False


def check_behavioral_trifecta(groups: dict[str, list[dict]]) -> object:
    """T1 — behavioral trifecta, proven by the trajectory log (not declared capability).

    WARN — at least one thread shows an ingress-verb, then a sensitive-verb, then an
           egress-verb, in that order.
    PASS — threads present, no thread shows the ordered sequence.
    """
    firing: list[str] = []
    for thread_id, thread_events in groups.items():
        if _t1_thread_trifecta(thread_events):
            firing.append(thread_id or "(no thread/turn id)")

    if firing:
        detail = "; ".join(firing[:6]) + (f" (+{len(firing) - 6} more)" if len(firing) > 6 else "")
        return _finding(
            "T1",
            WARN,
            "Behavioral trifecta observed — an ingress verb, then a sensitive-data "
            f"verb, then an egress verb, ran in this order within a thread: {detail}.",
            "Review the trajectory sidecar for the named thread(s) manually. This is "
            "proof-by-log of the same pattern A1 flags by capability — untrusted input "
            "reached sensitive data and then left the agent, in one observed sequence.",
            firing[:6],
        )
    return _finding(
        "T1",
        PASS,
        "No thread shows an ingress -> sensitive -> egress verb sequence in the "
        "trajectory log.",
        "No action needed.",
    )


# ---------------------------------------------------------------------------
# T2 — outcome anomaly: fail -> fail -> success series on a sensitive verb, within one
# thread (from tool.result status/isError/success).
# ---------------------------------------------------------------------------

_T2_MIN_FAILURES = 2  # at least this many consecutive failures before the success


def _t2_thread_anomaly(thread_events: list[dict]) -> bool:
    """True when a sensitive-verb tool.result shows >=2 consecutive failures then a
    success, for the SAME verb, within this thread — conservative on purpose: an
    isolated failure (the overwhelming common case) never counts."""
    # Track a running fail-streak per verb name so an unrelated verb's success doesn't
    # reset a different verb's fail streak.
    streaks: dict[str, int] = {}
    for ev in thread_events:
        if ev.get("type") != "tool.result":
            continue
        name = ev.get("name")
        if _classify_verb_role(name) != "sensitive":
            continue
        outcome = ev.get("outcome")
        if outcome == "failed":
            streaks[name] = streaks.get(name, 0) + 1
        elif outcome == "success":
            if streaks.get(name, 0) >= _T2_MIN_FAILURES:
                return True
            streaks[name] = 0
        # outcome is None (ambiguous) — leave the streak untouched, never guessed.
    return False


def check_outcome_anomaly(groups: dict[str, list[dict]]) -> object:
    """T2 — outcome anomaly: repeated failure then success on a sensitive verb.

    WARN — a sensitive verb failed at least twice in a row, then succeeded, within one
           thread (persistence past initial denial — e.g. permission probing).
    PASS — threads present, no such series found.
    """
    firing: list[str] = []
    for thread_id, thread_events in groups.items():
        if _t2_thread_anomaly(thread_events):
            firing.append(thread_id or "(no thread/turn id)")

    if firing:
        detail = "; ".join(firing[:6]) + (f" (+{len(firing) - 6} more)" if len(firing) > 6 else "")
        return _finding(
            "T2",
            WARN,
            "Outcome anomaly observed — a sensitive-data tool call failed at least "
            f"{_T2_MIN_FAILURES} times in a row and then succeeded, within a thread: "
            f"{detail}.",
            "Review the trajectory sidecar for the named thread(s) manually — repeated "
            "failure followed by success on sensitive-data access can indicate "
            "persistence past an initial denial (e.g. permission/path probing).",
            firing[:6],
        )
    return _finding(
        "T2",
        PASS,
        "No fail->fail->success series on a sensitive verb found in the trajectory log.",
        "No action needed.",
    )


def analyze(ctx, *, explicit_path: str | None = None) -> dict:
    """Run the v1 behavioral detectors (T1, T2) and return a result dict."""
    home = getattr(ctx, "home", None)
    events, meta = read_events(home, explicit_path=explicit_path)
    result = {
        "present": meta["present"],
        "files_scanned": meta["files_scanned"],
        "unknown_version": meta["unknown_version"],
        "event_count": len(events),
        "thread_count": 0,
        "findings": [],
    }
    if not meta["present"]:
        return result

    groups = group_events_by_thread(events)
    result["thread_count"] = len(groups)
    result["findings"] = [
        check_behavioral_trifecta(groups),
        check_outcome_anomaly(groups),
    ]
    return result


def render_behavioral_analysis(ctx, *, explicit_path: str | None = None, ascii_only: bool = False) -> str:
    """Human-readable, §8-safe behavioral report for --behavioral."""
    r = analyze(ctx, explicit_path=explicit_path)
    warn = "[!]" if ascii_only else "⚠"
    ok = "[ok]" if ascii_only else "✓"
    q = "[?]" if ascii_only else "?"
    lines = ["Behavioral trajectory audit (post-hoc, read-only, metadata-only)"]

    if not r["present"]:
        lines.append(f"  {q} No trajectory sidecars found "
                     "(agents/*/sessions/*.trajectory.jsonl). Nothing to analyze — run on a "
                     "host where an OpenClaw agent has produced session trajectories.")
        return "\n".join(lines)

    lines.append(
        f"  scanned {r['files_scanned']} trajectory file(s), {r['event_count']} event(s) "
        f"across {r['thread_count']} thread(s)/turn(s)."
    )
    if r["unknown_version"]:
        lines.append(f"  {q} Some records used an unrecognised trajectory schema version — "
                     "results are INCOMPLETE (treat as UNKNOWN, not authoritative).")

    any_warn = False
    for f in r["findings"]:
        if f.status == WARN:
            any_warn = True
            lines.append(f"  {warn} {f.id} — {f.detail}")
            lines.append(f"      fix: {f.fix}")
        else:
            lines.append(f"  {ok} {f.id} — {f.detail}")

    if not any_warn:
        lines.append(f"  {ok} No behavioral anomalies found.")
    return "\n".join(lines)
