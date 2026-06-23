"""Lightweight built-in monitoring: scheduled re-audit + change detection.

Complements the B16 check (which asks "do you HAVE monitoring?"). This is an
optional, opt-in way to GET some: run the deterministic audit on a schedule,
store a compact snapshot, and alert on what CHANGED since last time — the moments
threats actually appear (a new/modified installed skill, SOUL.md drift, a dropped
score, a check going PASS -> FAIL).

It is the only part of ClawSecCheck that persists state: a single JSON snapshot
(default ~/.clawseccheck/state.json). Everything else stays read-only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .catalog import BY_ID, FAIL
from .safeio import secure_append_text, secure_dir, secure_write_text


def _ignore_hash(home: Path) -> str:
    """Return sha256 of the .clawseccheckignore file contents, or '' if absent."""
    p = home / ".clawseccheckignore"
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

SNAPSHOT_VERSION = 1
DEFAULT_STATE = "~/.clawseccheck/state.json"
DEFAULT_EVENTS = "~/.clawseccheck/events.jsonl"


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _mcp_sig(ctx) -> dict:
    """name -> hash of each MCP server spec, so new/changed/removed servers drift."""
    from .checks import _mcp_servers  # noqa: PLC0415 (avoid import-order coupling)
    out = {}
    for name, spec in (_mcp_servers(ctx.config) or {}).items():
        try:
            out[name] = _h(json.dumps(spec, sort_keys=True, default=str))
        except (TypeError, ValueError):
            out[name] = _h(str(spec))
    return out


def _channel_sig(ctx) -> dict:
    """name -> hash of a channel's openness/auth signature (drift = openness change)."""
    out, chans = {}, ctx.config.get("channels")
    if isinstance(chans, dict):
        for name, c in chans.items():
            if not isinstance(c, dict):
                continue
            nodes = [c] + list((c.get("accounts") or {}).values())
            dm = any(isinstance(n, dict) and n.get("dmPolicy") == "open" for n in nodes)
            grp = any(isinstance(n, dict) and n.get("groupPolicy") == "open" for n in nodes)
            has_auth = bool(c.get("token") or c.get("auth") or c.get("allowFrom")
                            or c.get("allowlist") or c.get("allowedSenders"))
            out[name] = _h(f"dm={dm};grp={grp};auth={has_auth}")
    return out


def _gateway_bind(ctx) -> str:
    from .checks import parse_bind_host  # noqa: PLC0415
    from .collector import dig  # noqa: PLC0415
    return parse_bind_host(dig(ctx.config, "gateway.bind")
                           or dig(ctx.config, "gateway.host") or "")


def snapshot(ctx, findings, score) -> dict:
    native = getattr(ctx, "native", None)
    native_count = len(getattr(native, "findings", []) or []) if native else 0
    snap = {
        "version": SNAPSHOT_VERSION,
        "score": score.score,
        "grade": score.grade,
        "checks": {f.id: f.status for f in findings
                   if not getattr(f, "suppressed", False)},
        "skills": {n: _h(b) for n, b in ctx.installed_skills.items()},
        "bootstrap": {n: _h(t) for n, t in ctx.bootstrap.items()},
        "native_count": native_count,
        "ignore_hash": _ignore_hash(ctx.home),
        # Agent Watch — connection / trust surface, so drift in what the agent is
        # joined to (MCP servers, channels, gateway bind) raises an alert.
        "mcp": _mcp_sig(ctx),
        "channels": _channel_sig(ctx),
        "gateway_bind": _gateway_bind(ctx),
    }
    host = getattr(ctx, "host", None)
    if host and host.get("supported"):
        snap["host"] = {cls: info.get("status")
                        for cls, info in (host.get("classes") or {}).items()}
    return snap


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

    prev_ih = prev.get("ignore_hash", "")
    curr_ih = curr.get("ignore_hash", "")
    if prev_ih != curr_ih:
        alerts.append(("HIGH",
                       "your .clawseccheckignore changed — a suppression was added/removed "
                       "(review to ensure a real hole is not hidden)."))

    # --- Agent Watch: connection / trust-surface drift (guarded so an old snapshot
    #     without these keys never produces spurious 'new X' alerts after upgrade) ---
    if "mcp" in prev and "mcp" in curr:
        pm, cm = prev["mcp"], curr["mcp"]
        for name in sorted(cm.keys() - pm.keys()):
            alerts.append(("CRITICAL", f"NEW MCP server connected since last check: '{name}' — "
                           "vet it before trusting (new tool/data trust surface)."))
        for name in sorted(pm.keys() & cm.keys()):
            if pm[name] != cm[name]:
                alerts.append(("HIGH", f"MCP server '{name}' configuration CHANGED — "
                               "re-review its transport, secret passthrough and scope."))
        for name in sorted(pm.keys() - cm.keys()):
            alerts.append(("INFO", f"MCP server '{name}' was removed."))

    if "channels" in prev and "channels" in curr:
        pch, cch = prev["channels"], curr["channels"]
        for name in sorted(cch.keys() - pch.keys()):
            alerts.append(("HIGH", f"NEW channel '{name}' appeared since last check — "
                           "confirm its auth / allowlist before it can reach the agent."))
        for name in sorted(pch.keys() & cch.keys()):
            if pch[name] != cch[name]:
                alerts.append(("MEDIUM", f"Channel '{name}' openness/auth changed — review it."))

    if "gateway_bind" in prev and "gateway_bind" in curr and prev["gateway_bind"] != curr["gateway_bind"]:
        from .checks import EXPOSED_BINDS  # noqa: PLC0415
        cb = curr["gateway_bind"]
        exposed = cb in EXPOSED_BINDS
        alerts.append(("CRITICAL" if exposed else "HIGH",
                       f"Gateway bind changed: '{prev['gateway_bind']}' -> '{cb}'"
                       + (" (now exposed to the network!)" if exposed else "")))

    if "host" in prev and "host" in curr:
        ph, ch = prev["host"], curr["host"]
        for cls in sorted(set(ph) & set(ch)):
            if ph[cls] == "present" and ch[cls] != "present":
                alerts.append(("HIGH", f"Host monitor '{cls}' is no longer detected — "
                               "a watcher on this machine was removed or disabled."))

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
    # Symlink-safe: create the dir 0700 and refuse to follow a symlinked target,
    # so a planted symlink can never turn this write into an arbitrary-file clobber.
    secure_dir(p.parent)
    secure_write_text(p, json.dumps(snap, indent=2))


def record_events(alerts, path: str | Path = DEFAULT_EVENTS, when: str | None = None) -> None:
    """Append each drift alert to a local, owner-only event journal (a timeline of
    what changed when). No-op when there are no alerts. Never uploaded — local only."""
    if not alerts:
        return
    if when is None:
        from datetime import datetime  # noqa: PLC0415
        when = datetime.now().isoformat(timespec="seconds")
    p = Path(path).expanduser()
    body = "".join(json.dumps({"ts": when, "level": lvl, "message": msg}) + "\n"
                   for lvl, msg in alerts)
    try:  # symlink-safe append; never raise from the event journal
        secure_dir(p.parent)
        secure_append_text(p, body)
    except OSError:
        pass


def load_events(path: str | Path = DEFAULT_EVENTS, limit: int | None = None) -> list[dict]:
    """Read the event journal (chronological). Returns [] if absent/unreadable."""
    p = Path(path).expanduser()
    if not p.is_file():
        return []
    out: list[dict] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return out[-limit:] if limit else out
