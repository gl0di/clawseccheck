"""Lightweight built-in monitoring: scheduled re-audit + change detection.

Complements the B16 check (which asks "do you HAVE monitoring?"). This is an
optional, opt-in way to GET some: run the deterministic audit on a schedule,
store a compact snapshot, and alert on what CHANGED since last time — the moments
threats actually appear (a new/modified installed skill, SOUL.md drift, a dropped
score, a check going PASS -> FAIL).

It is the only part of ClawCheck that persists state: a single JSON snapshot
(default ~/.clawcheck/state.json). Everything else stays read-only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .catalog import BY_ID, FAIL

SNAPSHOT_VERSION = 1
DEFAULT_STATE = "~/.clawcheck/state.json"


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def snapshot(ctx, findings, score) -> dict:
    native = getattr(ctx, "native", None)
    native_count = len(getattr(native, "findings", []) or []) if native else 0
    return {
        "version": SNAPSHOT_VERSION,
        "score": score.score,
        "grade": score.grade,
        "checks": {f.id: f.status for f in findings},
        "skills": {n: _h(b) for n, b in ctx.installed_skills.items()},
        "bootstrap": {n: _h(t) for n, t in ctx.bootstrap.items()},
        "native_count": native_count,
    }


def diff(prev: dict | None, curr: dict) -> list[tuple[str, str]]:
    """Return (level, message) alerts. Empty on first run or no change."""
    if not prev:
        return []
    alerts: list[tuple[str, str]] = []

    ps, cs = prev.get("skills", {}), curr.get("skills", {})
    for name in sorted(cs.keys() - ps.keys()):
        alerts.append(("CRITICAL",
                       f"NEW skill installed since last check: '{name}' — vet its source "
                       "before trusting it (this is when malware lands)."))
    for name in sorted(ps.keys() & cs.keys()):
        if ps[name] != cs[name]:
            alerts.append(("HIGH", f"Installed skill '{name}' CHANGED since last check — re-review it."))
    for name in sorted(ps.keys() - cs.keys()):
        alerts.append(("INFO", f"Skill '{name}' was removed."))

    pb, cb = prev.get("bootstrap", {}), curr.get("bootstrap", {})
    for name in sorted(pb.keys() & cb.keys()):
        if pb[name] != cb[name]:
            alerts.append(("HIGH", f"{name} changed since last check — possible prompt / memory "
                                   "poisoning (drift)."))
    for name in sorted(cb.keys() - pb.keys()):
        alerts.append(("INFO", f"New bootstrap file appeared: {name}."))

    if curr.get("score", 0) < prev.get("score", 0):
        alerts.append(("HIGH", f"Security score dropped: {prev.get('grade')} {prev.get('score')} "
                               f"-> {curr.get('grade')} {curr.get('score')}."))

    pc, cc = prev.get("checks", {}), curr.get("checks", {})
    for cid, status in cc.items():
        if status == FAIL and pc.get(cid) != FAIL:
            title = BY_ID[cid].title if cid in BY_ID else cid
            alerts.append(("HIGH", f"Now FAILING: {title}."))

    if curr.get("native_count", 0) > prev.get("native_count", 0):
        delta = curr["native_count"] - prev["native_count"]
        alerts.append(("INFO", f"openclaw security audit reports {delta} more issue(s) than last time."))

    return alerts


def load_state(path: str | Path = DEFAULT_STATE) -> dict | None:
    p = Path(path).expanduser()
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_state(path: str | Path, snap: dict) -> None:
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snap, indent=2), encoding="utf-8")
