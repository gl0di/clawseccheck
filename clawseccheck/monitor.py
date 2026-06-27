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
import re
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


def _chain_hash(prev_hash: str, entry: dict) -> str:
    """Return sha256(prev_hash + canonical_json(entry)) as a hex digest.

    *entry* must not contain the 'chain_hash' key itself.
    *prev_hash* is '' for the genesis entry.
    """
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    raw = (prev_hash + canonical).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def verify_chain(events_path: "str | Path") -> "tuple[bool, str]":
    """Verify the hash-chain integrity of an events.jsonl file.

    Returns (True, "OK") when:
    - the file is absent or empty, or
    - all entries lack a 'chain_hash' field (legacy graceful mode), or
    - every 'chain_hash' field matches the recomputed value.

    Returns (False, "broken at entry N") on the first mismatch.
    Never raises — any IO/parse error causes (True, "OK") (graceful).
    """
    p = Path(events_path).expanduser()
    try:
        if not p.is_file():
            return True, "OK"
        lines = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError:
        return True, "OK"

    prev_hash = ""
    for idx, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        stored = entry.get("chain_hash")
        if stored is None:
            # Legacy entry — skip chain verification for this entry, carry prev_hash
            continue

        # Recompute over the entry *without* the chain_hash field
        base = {k: v for k, v in entry.items() if k != "chain_hash"}
        expected = _chain_hash(prev_hash, base)
        if stored != expected:
            return False, f"broken at entry {idx}"
        prev_hash = stored

    return True, "OK"


_MEMORY_MAX_BYTES = 200_000
_MEMORY_MAX_FILES = 256
_MEMORY_TEXT_EXTS = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
_MEMORY_FILE_NAMES = {
    "SOUL.md", "AGENTS.md", "TOOLS.md", "MEMORY.md", "memory.md",
}
_MEMORY_INJECTION_PATTERNS = (
    re.compile(r"ignore (all|any|previous|prior) (instructions|messages)", re.I),
    re.compile(r"obey (all|any|every|whatever)", re.I),
    re.compile(r"follow (all|any|every|whatever) (instruction|command|request)", re.I),
    re.compile(r"do (whatever|anything) (the )?(user|sender|message|email) (says|asks|wants)", re.I),
)
_MEMORY_URL_RE = re.compile(r"https?://[^\s]+", re.I)


def _has_memory_name(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(name.lower()) for name in _MEMORY_FILE_NAMES)


def _extract_memory_signals(text: str) -> dict:
    signals: list[str] = []
    for pattern in _MEMORY_INJECTION_PATTERNS:
        if pattern.search(text):
            signals.append(pattern.pattern)

    raw_urls = _MEMORY_URL_RE.findall(text)
    urls = sorted({u.rstrip(")>\"") for u in raw_urls if u})
    return {
        "signals": sorted(signals),
        "urls": urls,
    }


def _snapshot_memory_text(path: str, text: str) -> dict:
    return {
        "path": path,
        "hash": _h(text),
        **_extract_memory_signals(text),
    }


def _snapshot_memory_files(ctx) -> dict:
    from .collector import WORKSPACE_DIRS

    seen: set[Path] = set()
    out: dict[str, dict] = {}

    for name, text in ctx.bootstrap.items():
        if _has_memory_name(name):
            out[name] = _snapshot_memory_text(name, text)

    for ws in WORKSPACE_DIRS:
        mem_dir = ctx.home / ws / "memory"
        if not mem_dir.is_dir():
            continue
        for p in sorted(mem_dir.rglob("*")):
            if len(out) >= _MEMORY_MAX_FILES:
                break
            if p.is_symlink() or not p.is_file():
                continue
            if p.suffix.lower() not in _MEMORY_TEXT_EXTS and p.suffix:
                continue
            try:
                rel = p.relative_to(ctx.home)
            except OSError:
                rel = p
            if rel in seen:
                continue
            seen.add(rel)
            try:
                raw = p.read_bytes()
            except OSError:
                continue
            if len(raw) > _MEMORY_MAX_BYTES or b"\x00" in raw:
                continue
            try:
                text = raw.decode("utf-8", "replace")
            except UnicodeError:
                continue
            out[str(rel)] = _snapshot_memory_text(str(rel), text)

    return out


def _append_memory_alerts(prev: dict, curr: dict, alerts: list[tuple[str, str]]) -> None:
    pm, cm = prev.get("memory", {}), curr.get("memory", {})
    for path in sorted(cm.keys() - pm.keys()):
        entry = cm[path]
        if entry.get("signals") or entry.get("urls"):
            alerts.append((
                "MEDIUM",
                f"New persistent memory file '{path}' appears with suspicious content.",
            ))

    for path in sorted(pm.keys() & cm.keys()):
        p = pm[path]
        c = cm[path]
        if not isinstance(p, dict) or not isinstance(c, dict):
            continue
        if p.get("hash") == c.get("hash"):
            continue

        p_signals = set(p.get("signals", []))
        c_signals = set(c.get("signals", []))
        p_urls = set(p.get("urls", []))
        c_urls = set(c.get("urls", []))

        added_signals = sorted(c_signals - p_signals)
        added_urls = sorted(c_urls - p_urls)

        if added_signals:
            alerts.append((
                "HIGH",
                f"Potential memory-poisoning change in '{path}' — new instruction override patterns: "
                + ", ".join(added_signals) + ".",
            ))
        elif added_urls:
            alerts.append((
                "MEDIUM",
                f"Persistent memory file '{path}' changed and now includes new endpoint(s): "
                + ", ".join(added_urls) + ".",
            ))

    for path in sorted(pm.keys() - cm.keys()):
        alerts.append(("INFO", f"Persistent memory file removed since last check: '{path}'."))


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


def _mcp_detail_sig(ctx) -> dict:
    """name -> structured per-server snapshot for rug-pull (RP1-RP3) detection.

    Captures real MCP spec fields (command, args[0], transport, url, env key names,
    oauth.scope) — confirmed real fields per recon docs §1/§4.  Env VALUES are never
    stored; only the key names are recorded (SECRET_KEY_RE keys get a ``*``-marker so
    their presence is visible but no value leaks).
    """
    from .checks import SECRET_KEY_RE, _mcp_servers  # noqa: PLC0415
    out: dict = {}
    for name, spec in (_mcp_servers(ctx.config) or {}).items():
        if not isinstance(spec, dict):
            continue
        args = spec.get("args") or []
        args0 = str(args[0]) if isinstance(args, list) and args else ""
        env = spec.get("env") or {}
        env_keys: list[str] = []
        if isinstance(env, dict):
            for k in env:
                k_str = str(k)
                env_keys.append(
                    k_str + ":*" if SECRET_KEY_RE.search(k_str) else k_str
                )
        oauth = spec.get("oauth") or {}
        oauth_scope = str(oauth.get("scope") or "") if isinstance(oauth, dict) else ""
        tool_sigs: dict[str, str] = {}
        tools = spec.get("tools")
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    tool_name = str(tool.get("name") or "").strip()
                    if not tool_name:
                        continue
                    tool_desc = str(tool.get("description") or "")
                    tool_sigs[tool_name] = _h(tool_desc)
                elif isinstance(tool, (str, bytes)):
                    tool_name = str(tool).strip()
                    if tool_name:
                        tool_sigs[tool_name] = ""
        out[name] = {
            "command": str(spec.get("command") or ""),
            "args0": args0,
            "transport": str(spec.get("transport") or ""),
            "url": str(spec.get("url") or ""),
            "env_keys": sorted(env_keys),
            "oauth_scope": oauth_scope,
            "tool_sigs": dict(sorted(tool_sigs.items())),
        }
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
        "memory": _snapshot_memory_files(ctx),
        "native_count": native_count,
        "ignore_hash": _ignore_hash(ctx.home),
        # Agent Watch — connection / trust surface, so drift in what the agent is
        # joined to (MCP servers, channels, gateway bind) raises an alert.
        "mcp": _mcp_sig(ctx),
        # Rug-pull detection (RP1-RP3): per-server structured fields for fine-grained
        # privilege/transport/endpoint drift analysis (added F-008).
        "mcp_detail": _mcp_detail_sig(ctx),
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

    _append_memory_alerts(prev, curr, alerts)

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

    # --- Rug-pull detection (RP1-RP3): fine-grained MCP server manifest drift ---
    # Only runs when BOTH snapshots carry the structured mcp_detail key (guarded so an
    # old snapshot without this key never produces spurious alerts after upgrade).
    if "mcp_detail" in prev and "mcp_detail" in curr:
        pd, cd = prev["mcp_detail"], curr["mcp_detail"]
        for name in sorted(set(pd) & set(cd)):
            ps, cs = pd[name], cd[name]
            if not isinstance(ps, dict) or not isinstance(cs, dict):
                continue

            # RP1 — scope/privilege expansion (HIGH): oauth.scope gained a new token or
            # was broadened (e.g. read → read+write, or any → */all/admin).
            p_scope = ps.get("oauth_scope", "")
            c_scope = cs.get("oauth_scope", "")
            if p_scope != c_scope and c_scope:
                p_tokens = set(p_scope.split()) if p_scope else set()
                c_tokens = set(c_scope.split()) if c_scope else set()
                gained = c_tokens - p_tokens
                _BROAD = {"*", "all", "admin", "write", "read:write"}
                is_broad = any(t.endswith(("*", ":write", ":admin", ":all")) or t in _BROAD
                               for t in gained)
                if gained:
                    sev = "HIGH" if is_broad else "MEDIUM"
                    alerts.append((sev,
                                   f"MCP server '{name}' rug-pull RP1: oauth.scope expanded "
                                   f"'{p_scope}' -> '{c_scope}' (gained: {' '.join(sorted(gained))}) "
                                   "— server gained privilege post-approval, re-vet it."))

            # RP2 — command/transport change (HIGH): the executable, first arg, or
            # transport changed — a different thing now runs under the same trusted name.
            p_transport = ps.get("transport", "")
            c_transport = cs.get("transport", "")
            p_cmd = ps.get("command", "")
            c_cmd = cs.get("command", "")
            p_args0 = ps.get("args0", "")
            c_args0 = cs.get("args0", "")
            transport_changed = p_transport != c_transport
            cmd_changed = p_cmd != c_cmd
            args0_changed = p_args0 != c_args0
            if transport_changed or cmd_changed or args0_changed:
                parts = []
                if cmd_changed:
                    parts.append(f"command '{p_cmd}'->'{c_cmd}'")
                if args0_changed:
                    parts.append(f"args[0] '{p_args0}'->'{c_args0}'")
                if transport_changed:
                    parts.append(f"transport '{p_transport}'->'{c_transport}'")
                alerts.append(("HIGH",
                               f"MCP server '{name}' rug-pull RP2: "
                               + ", ".join(parts)
                               + " — a different binary/package/transport now runs under "
                               "this trusted name, re-vet it."))

            # RP3 — endpoint/default repoint (HIGH): url or env values that look like
            # endpoints changed.  We snapshot env KEY names only, so this detects an env
            # var disappearing or appearing; the url field is snapshotted directly.
            p_url = ps.get("url", "")
            c_url = cs.get("url", "")
            if p_url != c_url:
                # Determine severity: host change is always HIGH; adding/clearing url is HIGH.
                alerts.append(("HIGH",
                               f"MCP server '{name}' rug-pull RP3: url repointed "
                               f"'{p_url}' -> '{c_url}' "
                               "— trusted endpoint changed, verify the destination."))

            # RP4/RP5 — tool surface drift (HIGH): new tool appeared or a declared tool's
            # description changed under the same trusted server name.
            p_tools = ps.get("tool_sigs") or {}
            c_tools = cs.get("tool_sigs") or {}
            if isinstance(p_tools, dict) and isinstance(c_tools, dict):
                for tool in sorted(set(c_tools) - set(p_tools)):
                    alerts.append(("HIGH",
                                   f"MCP server '{name}' rug-pull RP4: new tool '{tool}' "
                                   "appeared in the manifest — re-vet the tool surface."))
                for tool in sorted(set(p_tools) & set(c_tools)):
                    if p_tools[tool] != c_tools[tool]:
                        alerts.append(("HIGH",
                                       f"MCP server '{name}' rug-pull RP5: tool description "
                                       f"changed for '{tool}' — re-review the server's "
                                       "declared affordances."))

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


def _last_chain_hash(p: Path) -> str:
    """Return the 'chain_hash' of the last entry in a JSONL file, or '' if none."""
    if not p.is_file():
        return ""
    try:
        lines = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError:
        return ""
    for line in reversed(lines):
        try:
            entry = json.loads(line)
            val = entry.get("chain_hash")
            if val is not None:
                return str(val)
        except json.JSONDecodeError:
            continue
    return ""


def record_events(alerts, path: str | Path = DEFAULT_EVENTS, when: str | None = None) -> None:
    """Append each drift alert to a local, owner-only event journal (a timeline of
    what changed when). No-op when there are no alerts. Never uploaded — local only.

    Each entry carries a 'chain_hash' field: sha256(prev_chain_hash + canonical_json)
    so the journal is tamper-evident. Existing entries without 'chain_hash' are treated
    as the chain genesis (backward compatible).
    """
    if not alerts:
        return
    if when is None:
        from datetime import datetime  # noqa: PLC0415
        when = datetime.now().isoformat(timespec="seconds")
    p = Path(path).expanduser()
    try:  # symlink-safe append; never raise from the event journal
        secure_dir(p.parent)
        prev_hash = _last_chain_hash(p)
        lines_out: list[str] = []
        for lvl, msg in alerts:
            base = {"ts": when, "level": lvl, "message": msg}
            ch = _chain_hash(prev_hash, base)
            entry = {**base, "chain_hash": ch}
            lines_out.append(json.dumps(entry))
            prev_hash = ch
        secure_append_text(p, "\n".join(lines_out) + "\n")
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
