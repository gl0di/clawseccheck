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

from .catalog import BY_ID, FAIL, UNKNOWN
from .locking import journal_lock
from .logsafe import redact_urls_in_text, sanitize_url_host_only
from .safeio import secure_append_text, secure_dir, secure_write_text


def _ignore_hash(home: Path) -> str:
    """Return sha256 of the .clawseccheckignore file contents, or '' if absent."""
    p = home / ".clawseccheckignore"
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

SNAPSHOT_VERSION = 2
DEFAULT_STATE = "~/.clawseccheck/state.json"
DEFAULT_EVENTS = "~/.clawseccheck/events.jsonl"

# C-162: schema stamp for hash-chained journal lines (history.jsonl / events.jsonl).
# Stamped INSIDE the hashed payload (so verify_chain authenticates it too — a planted
# _schema value breaks the chain like any other tampered field). Bumped only for a
# genuine future format change to the chained entry shape; loaders skip a line whose
# _schema is a newer major than this build understands (see _iter_jsonl consumers)
# rather than risk misparsing it. Absent _schema (legacy pre-C-162 lines) still loads.
SCHEMA_VERSION = 1

# C-164: retention/rotation for the hash-chained journals (history.jsonl /
# events.jsonl). Once a journal exceeds _JOURNAL_MAX_LINES, it is pruned down to
# the last _JOURNAL_KEEP entries in one amortized batch (not every append) — see
# _rotate_journal. The gap between the two keeps rotation infrequent relative to
# append volume.
_JOURNAL_MAX_LINES = 5000
_JOURNAL_KEEP = 4000


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


def _iter_jsonl(p: Path):
    """Stream-parse a JSONL file, yielding one dict per well-formed non-blank line.

    C-164: iterates the open file object line-by-line (never
    ``read_text().splitlines()``), so memory stays flat even on a large journal.
    Blank lines, JSON-decode errors, and non-dict top-level values are silently
    skipped (same graceful contract the previous read_text()-based loops had).

    C-177: opened with ``errors="replace"`` (same pattern as baseline.py's
    ``load_ignore``) so a non-UTF-8 byte anywhere in the file — a plausible
    crash-mid-write artifact — degrades that one line to unparseable-JSON
    (skipped, same as any other malformed line) instead of raising
    ``UnicodeDecodeError`` and permanently wedging every future invocation.
    """
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                yield entry


def verify_chain(events_path: "str | Path") -> "tuple[bool, str]":
    """Verify the hash-chain integrity of an events.jsonl file.

    Returns (True, "OK") when:
    - the file is absent or empty, or
    - all entries lack a 'chain_hash' field (legacy graceful mode), or
    - every 'chain_hash' field matches the recomputed value.

    When the chain is intact but the file carries N entries whose '_schema' the
    loaders skip (unknown future major, or a malformed but honestly-chained value),
    returns (True, "OK (N unknown-schema entr{y,ies} present)") instead of a bare
    "OK". Those lines are hidden-but-present: authenticated and physically on disk,
    yet invisible to load_events()/history.load(). Surfacing the count lets an
    operator who diffs on-disk line-count against loaded-row-count see the gap
    rather than trust a silent "OK" (C-167). Still (True, …) — this is honesty about
    a pre-existing "write access breaks tamper-evidence" boundary, not a new break.

    Returns (False, "broken at entry N") on the first mismatch.
    Never raises — any IO/parse error causes (True, "OK") (graceful).

    Authenticates every field of every entry (including '_schema', C-162, and any
    entry whose '_schema' is a newer major than this build understands) — the
    unknown-schema skip policy belongs to the *loaders* (load_events/history.load),
    not to chain verification, which must authenticate the whole file regardless.
    """
    p = Path(events_path).expanduser()
    try:
        if not p.is_file():
            return True, "OK"
        entries = list(_iter_jsonl(p))
    except OSError:
        return True, "OK"

    prev_hash = ""
    unknown_schema = 0
    for idx, entry in enumerate(entries):
        # Count lines the loaders would skip (C-167): present + authenticated here,
        # but hidden from load_events()/history.load() by the unknown-schema policy.
        if not _schema_ok(entry):
            unknown_schema += 1

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

    if unknown_schema:
        noun = "entry" if unknown_schema == 1 else "entries"
        return True, f"OK ({unknown_schema} unknown-schema {noun} present)"
    return True, "OK"


def _rotate_journal(p: Path, max_lines: int = _JOURNAL_MAX_LINES,
                    keep: int = _JOURNAL_KEEP) -> None:
    """C-164: prune *p* to its last *keep* entries once it exceeds *max_lines*.

    No-op (file left byte-identical) when the line-count is at or below
    *max_lines* — rotation is amortized, not per-append. When it does trigger, the
    survivors' chain is RE-GENESISED: chain_hash is recomputed forward starting
    from prev_hash="" over each entry's own non-hash fields (including '_schema'),
    so ``verify_chain`` reports OK over the whole survivor file afterwards — this
    is what prevents the spurious "chain BROKEN" that simply truncating the file
    would cause (the survivors' original hashes point at now-deleted history).

    This re-genesis is a deliberate, documented local trust boundary: rotation
    itself is not tamper-evident across the rotation boundary (an attacker with
    write access to the file could rotate-and-forge), only within a generation.

    Must be called from inside the caller's ``journal_lock`` critical section
    (immediately after an append) — it does not take the lock itself.
    Never raises: any OSError during read/rewrite is swallowed, leaving the
    file as last known good (an unrotated, still-valid, still-growing journal).
    """
    try:
        if not p.is_file():
            return
        entries = list(_iter_jsonl(p))
        if len(entries) <= max_lines:
            return  # no-op — file untouched, byte-identical

        survivors = entries[-keep:]
        prev_hash = ""
        rechained: list[str] = []
        for entry in survivors:
            base = {k: v for k, v in entry.items() if k != "chain_hash"}
            ch = _chain_hash(prev_hash, base)
            rechained.append(json.dumps({**base, "chain_hash": ch}))
            prev_hash = ch

        secure_write_text(p, "\n".join(rechained) + "\n")
    except OSError:
        pass


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

    # B-105: memory-file URLs can carry credentials in userinfo/query (?api_key=…);
    # reduce each to scheme://host before it enters the snapshot / any alert so the
    # secret is never persisted at rest in state.json/events.jsonl.
    raw_urls = _MEMORY_URL_RE.findall(text)
    urls = sorted({sanitize_url_host_only(u.rstrip(")>\"")) for u in raw_urls if u})
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


def _snapshot_memory_files(ctx, capped: "list | None" = None) -> dict:
    """Snapshot the persistent-memory surface.

    B-268: when *capped* (a list) is given, every path that is PRESENT on disk and eligible
    but did not make it into the returned dict because a cap evicted it is appended to it —
    the truncation frontier. Without it, `diff()` cannot tell "this file is gone" from "this
    file is still here, we just stopped looking", and reported the second as the first: a
    note grown past `_MEMORY_MAX_BYTES` produced "Persistent memory file removed" while `ls`
    showed it at 220,918 bytes, and 40 new early-sorting files pushed 34 untouched notes out
    of the count cap and reported every one of them as removed. Same out-param idiom as
    `walk_dir_safely`'s `skips`/`capped`, so existing callers are unaffected.

    Note the count cap is now evaluated per-candidate instead of breaking the loop: the walk
    must reach every eligible path to record an exact frontier. Only the READ is skipped, so
    the cap still bounds the work it exists to bound.
    """
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
            if len(out) >= _MEMORY_MAX_FILES:
                if capped is not None:
                    capped.append(str(rel))
                continue
            try:
                raw = p.read_bytes()
            except OSError:
                # Present on disk but unreadable (e.g. chmod 000). Same class of gap as a
                # cap eviction — absent from `out` for a collection reason, not a disk
                # fact — so it joins the frontier rather than being reported as removed.
                if capped is not None:
                    capped.append(str(rel))
                continue
            if len(raw) > _MEMORY_MAX_BYTES or b"\x00" in raw:
                # Present and eligible, but deliberately not fingerprinted (oversized, or
                # binary). Its absence from `out` is a scan decision, not a disk fact.
                if capped is not None:
                    capped.append(str(rel))
                continue
            try:
                text = raw.decode("utf-8", "replace")
            except UnicodeError:
                continue
            out[str(rel)] = _snapshot_memory_text(str(rel), text)

    return out


def _append_memory_alerts(prev: dict, curr: dict, alerts: list[tuple[str, str]],
                          trust_removals: bool = True) -> None:
    pm, cm = prev.get("memory", {}), curr.get("memory", {})
    # B-268: the cap frontier on each side — paths that were on disk but not fingerprinted.
    # An entry absent from a snapshot's `memory` dict is only evidence of absence when it is
    # also absent from that snapshot's frontier.
    prev_capped = set(prev.get("memory_capped") or ())
    curr_capped = set(curr.get("memory_capped") or ())
    for path in sorted(cm.keys() - pm.keys()):
        if path in prev_capped:
            # It did not "appear" — it was already on disk last run, merely beyond the cap.
            # Announcing it as new misdates the incident, which is exactly how a
            # pre-existing poisoned note got reported as freshly planted once unrelated
            # files were deleted and it fell back inside the cap.
            continue
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

    if not trust_removals:
        # B-269: this run could not read openclaw.json, so a memory file that lived under a
        # config-declared workspace has simply dropped out of the collected view. Its
        # "disappearance" is a collection artifact, not an event.
        return

    # B-275: SOUL/AGENTS/TOOLS/MEMORY/memory.md are BOTH bootstrap files and memory files,
    # so from here on their removal is already reported once by the bootstrap dimension.
    # Skip them here so a single deletion is not alerted twice at two different severities.
    bootstrap_owned = set(prev.get("bootstrap") or {})
    for path in sorted(pm.keys() - cm.keys()):
        if path in bootstrap_owned:
            continue
        if path in curr_capped:
            # B-268: still on disk this run, just cap-evicted. Not a removal.
            continue
        alerts.append(("INFO", f"Persistent memory file removed since last check: '{path}'."))

    # B-268 disclosure: a bare all-clear over a truncated view is the lie the FN twin
    # exploits — past the cap the region is never read, so a live injection/exfil payload
    # on an oversized note returned "No new threats since last check". Ordering is by
    # filename, i.e. attacker-controlled, so the eviction is something an attacker can
    # ARRANGE. State the gap instead of implying coverage.
    if curr_capped:
        n = len(curr_capped)
        alerts.append((
            "MEDIUM",
            f"{n} persistent memory file(s) are present but NOT monitored — they exceed "
            f"the {_MEMORY_MAX_FILES}-file / {_MEMORY_MAX_BYTES // 1000}KB inspection cap, "
            f"or could not be read (e.g. {', '.join(sorted(curr_capped)[:3])}). Content "
            "changes in those files are not detected. Split or archive oversized notes, "
            "reduce the number of memory files, or restore read access to regain full "
            "coverage.",
        ))


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
        # B-105: at-rest redaction. command/args0 can embed a credential inside a URL
        # arg (npx --registry https://TOKEN@reg/ …); url can be https://user:token@host or
        # carry ?api_key=…. Sanitize BEFORE the value enters the snapshot, so state.json
        # never holds the secret and every drift alert built from these fields (RP2/RP3)
        # inherits the redaction. Host-level drift (the security signal) is preserved;
        # only the secret-bearing parts collapse.
        out[name] = {
            "command": redact_urls_in_text(str(spec.get("command") or "")),
            "args0": redact_urls_in_text(args0),
            "transport": str(spec.get("transport") or ""),
            "url": sanitize_url_host_only(str(spec.get("url") or "")),
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
                # C-135/FIX4: shorthand form (e.g. "telegram": true) enables/disables the
                # channel without a per-channel policy object to inspect. Record it as
                # PRESENT with an unknown-but-tracked shape rather than skipping it
                # outright — the old `continue` here made the channel invisible to drift
                # detection, so switching between shorthand and an explicit {} object (or
                # vice versa) made a still-live channel read as "no longer configured" in
                # diff()'s removal branch. Keying on repr(c) still detects a genuine
                # true<->false flip while never fabricating a deletion.
                out[name] = _h(f"shorthand={c!r}")
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


_SKILL_VERSION_RE = re.compile(r"(?im)^\s*version:\s*['\"]?([\w.\-+]+)['\"]?\s*$")


def _b62_families(name: str, ctx) -> "frozenset":
    """Thin wrapper around checks._b62_actual_families (lazy import, B62 substrate)."""
    from .checks import _b62_actual_families  # noqa: PLC0415
    return _b62_actual_families(name, ctx, ctx.installed_skill_py.get(name, []))


def _skill_sig(ctx) -> dict:
    """name -> {hash, tree, tree_complete, scan_partial, caps, version}.

    ``hash`` is the historical digest of the SCANNED blob; ``tree`` is the B-267
    full-directory fingerprint that actually answers "did this skill change?". Old
    snapshots stored a bare hash string, and pre-B-267 snapshots carry a dict with no
    ``tree`` key; diff() handles both (see ``_skill_entry``).

    B-267: hashing only ``ctx.installed_skills[name]`` made the drift signal inherit the
    malware-scanner's budget. That blob is TEXT-only and capped, so the three stealthiest
    in-place backdoors — a same-size binary swap under ``bin/``, an appended directive in a
    file past the per-skill budget, and an edit inside a file dropped whole for exceeding
    the per-file cap — every one of them left the stored signature byte-identical and the
    monitor silent. Measured first-hand on all three before the fix: zero alerts. This is
    the exact scenario --monitor exists for (malware landing in a skill already trusted),
    and the tool was holding the contradicting evidence: the collector already records a
    ``limit_hits`` line saying content beyond the cap was NOT scanned, which monitor.py
    never read.

    ``scan_partial`` carries that evidence into the snapshot. It does NOT weaken the change
    signal — ``tree`` covers the unscanned region for change-detection purposes — but it
    marks a skill whose CONTENT was never fully vetted, so a "NEW"/"CHANGED" alert can say
    so rather than implying the new state was inspected and found benign.
    """
    from .collector import skill_tree_signature  # noqa: PLC0415 (leaf import, no cycle)

    partial = _scan_truncated_skills(ctx)
    out = {}
    for name, blob in ctx.installed_skills.items():
        m = _SKILL_VERSION_RE.search(blob)
        entry = {
            "hash": _h(blob),
            "caps": sorted(_b62_families(name, ctx)),
            "version": m.group(1) if m else None,
            "scan_partial": name in partial,
        }
        skill_dir = (getattr(ctx, "installed_skill_dirs", None) or {}).get(name)
        if skill_dir is not None:
            try:
                sig = skill_tree_signature(skill_dir)
            except OSError:
                sig = None
            if sig is not None:
                entry["tree"] = sig["digest"]
                entry["tree_complete"] = bool(sig["complete"])
        out[name] = entry
    return out


# B-267: the collector's per-skill text-cap limit_hit, e.g.
#   text scan of skill 'clawstealth' hit the 1000KB/500-file cap — …
# Parsed rather than re-derived so there is a single source of truth for "was this skill's
# content fully scanned?" — the collector decides, monitor only reports.
_SCAN_TRUNCATED_RE = re.compile(r"text scan of skill '([^']+)' hit the ")


def _scan_truncated_skills(ctx) -> "set[str]":
    """Names of skills whose CONTENT scan the collector reports as truncated."""
    out: set[str] = set()
    for hit in (getattr(ctx, "limit_hits", None) or []):
        m = _SCAN_TRUNCATED_RE.search(str(hit))
        if m:
            out.add(m.group(1))
    return out


# B-269 — dimensions of the snapshot that are built from ``ctx.config``. When
# openclaw.json cannot be read/parsed the collector falls back to ``ctx.config = {}`` and
# every one of these collapses to empty, which ``diff()`` used to read as fact.
_CONFIG_DIMENSIONS = ("mcp", "mcp_detail", "channels", "gateway_bind")

# B-269 — dimensions collected from disk that an unreadable config can still SHRINK,
# because the config declares extra roots to scan: ``agents.defaults.workspace`` /
# ``agents.list[].workspace`` add bootstrap + memory roots, ``skills.load.extraDirs`` adds
# skill roots. Verified first-hand: with those keys set, a chmod 000 on openclaw.json drops
# the custom-workspace SOUL.md and the extra-dir skill out of the collected view, which the
# old code reported as "Skill 'helper' was removed."
#
# The invariant that makes the repair sound: an unreadable config can only make an entry
# DISAPPEAR from the collected view, never appear. So on a blind run a disappearance here
# is untrustworthy, while an addition or a content change is still real evidence.
# Checked, not assumed: every config consumer in the collection path only ever EXTENDS the
# set of roots to scan — _read_installed_skills appends _config_workspace_dirs,
# _config_extra_skill_dirs and _config_plugin_load_paths to `roots`, and the bootstrap scan
# appends _config_workspace_dirs to `_ws_dirs`. No config key narrows or filters discovery,
# so ctx.config == {} yields a subset, never a superset.
_SHRINKABLE_DIMENSIONS = ("skills", "bootstrap", "memory")


def _degrade_snapshot(snap: dict, prev: "dict | None") -> None:
    """B-269/FIX2 (C-135 follow-up): mark and repair a snapshot taken while openclaw.json
    was unreadable, OR simply ABSENT this run after having previously been present (see
    ``snapshot()``'s widened blind predicate) — both leave the collector with the same
    collapsed ``ctx.config = {}`` view, so both need the same repair.

    Writing the collapsed (empty) config view into the baseline is what made ``diff()``
    fabricate "MCP server 'X' was removed." / "Gateway bind changed: '127.0.0.1' -> ''"
    against a byte-identical config, and then fire a burst of "NEW MCP server connected"
    CRITICALs the moment the file became readable again — all while the score *rose*,
    because the checks that would have failed had silently become UNKNOWN and UNKNOWN is
    excluded from the score denominator.

    The state is *unknown*, not empty, so the last known-good values are carried forward
    rather than overwritten:

    * ``_CONFIG_DIMENSIONS`` are taken wholesale from the previous snapshot.
    * ``_SHRINKABLE_DIMENSIONS`` are union-merged — previous entries survive, this run's
      values win wherever both sides have the key.

    Nothing is lost, only deferred: the next run that CAN read the config compares against
    this preserved baseline, so a real change made during the blind window is reported
    then, in the right direction, instead of being drowned in fabricated ones.

    ``config_baseline`` records whether a baseline actually existed to carry (``carried``)
    or the blind run had nothing to fall back on (``unknown`` — e.g. the very first monitor
    run was blind, or the previous run was blind too and never had a baseline itself).
    ``diff()`` refuses to compare config dimensions against an ``unknown`` baseline rather
    than treating emptiness as fact.

    This does NOT change scoring: the run's measured ``score``/``grade``/``checks`` are left
    exactly as the audit produced them (per GR#4 the UNKNOWN-exclusion design is correct).
    ``diff()`` declines to *compare* them across a blind boundary instead.
    """
    snap["config_parse_error"] = True
    have_baseline = isinstance(prev, dict) and (
        not prev.get("config_parse_error") or prev.get("config_baseline") == "carried"
    )
    if not have_baseline:
        snap["config_baseline"] = "unknown"
        return
    snap["config_baseline"] = "carried"
    for key in _CONFIG_DIMENSIONS:
        if key in prev:
            snap[key] = prev[key]
    for key in _SHRINKABLE_DIMENSIONS:
        prev_dim, curr_dim = prev.get(key), snap.get(key)
        if isinstance(prev_dim, dict) and isinstance(curr_dim, dict):
            snap[key] = {**prev_dim, **curr_dim}


def snapshot(ctx, findings, score, prev: "dict | None" = None) -> dict:
    """Build the drift snapshot for this run.

    *prev* is the previously saved snapshot, used to preserve the baseline when this run
    could not read openclaw.json (B-269 — see ``_degrade_snapshot``) and to carry forward
    the "was a real config ever seen" bit that decides whether a config that is simply
    ABSENT this run counts as blind too (C-135 FIX2 — see the ``config_ever_seen`` /
    ``config_missing_blind`` computation below). Passing None keeps the historical
    behaviour for a first run or a caller with no stored state.
    """
    native = getattr(ctx, "native", None)
    native_count = len(getattr(native, "findings", []) or []) if native else 0
    # B-268: capture each collection's truncation frontier alongside the collection itself,
    # so diff() can tell "absent from disk" from "absent from the capped view".
    _mem_capped: list[str] = []
    snap = {
        "version": SNAPSHOT_VERSION,
        "score": score.score,
        "grade": score.grade,
        "checks": {f.id: f.status for f in findings
                   if not getattr(f, "suppressed", False)},
        "skills": _skill_sig(ctx),
        "bootstrap": {n: _h(t) for n, t in ctx.bootstrap.items()},
        "memory": _snapshot_memory_files(ctx, capped=_mem_capped),
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
    snap["memory_capped"] = sorted(_mem_capped)
    # B-268: the skills frontier comes from the collector (which is where the cap lives).
    # `skills_capped` lists names present on disk but never read; `skills_frontier_partial`
    # says that list is itself incomplete, in which case diff() must not use it as a
    # completeness oracle and suppresses skill removals wholesale.
    snap["skills_capped"] = sorted(getattr(ctx, "skills_capped_names", None) or ())
    snap["skills_capped_count"] = int(getattr(ctx, "skills_capped_count", 0) or 0)
    snap["skills_frontier_partial"] = bool(getattr(ctx, "skills_frontier_partial", False))

    host = getattr(ctx, "host", None)
    if host and host.get("supported"):
        snap["host"] = {cls: info.get("status")
                        for cls, info in (host.get("classes") or {}).items()}

    # C-135 FIX2: sticky "was a real config ever seen" bit, carried forward across an
    # arbitrarily long run of blind snapshots (same "once True, stays True" pattern as
    # ``config_baseline == 'carried'``). It is what lets the widened blind predicate below
    # tell "openclaw.json used to be readable and just vanished" (a benign atomic-replace
    # window — `jq ... > tmp && mv tmp openclaw.json` — a `mv openclaw.json
    # openclaw.json.bak` mid-troubleshooting, or a home not yet mounted on a cron-driven
    # run) apart from "this home never had an openclaw.json at all" (a non-OpenClaw setup,
    # or the very first run ever). Only the former is treated as blind — a user who
    # genuinely never configured OpenClaw must never get a permanent "Could not read
    # openclaw.json" alert, which is exactly the false alarm B-269 exists to prevent.
    prev_had_config = bool(isinstance(prev, dict) and prev.get("config_ever_seen"))
    snap["config_ever_seen"] = bool(getattr(ctx, "config_found", False)) or prev_had_config

    parse_error = bool(getattr(ctx, "config_parse_error", False))
    # C-135 FIX2: collector.py defines config_parse_error = config_found and not parsed_ok,
    # so a config that is simply ABSENT this run (config_found False) leaves
    # config_parse_error False too — B-269's original guard never fired for it, so
    # _degrade_snapshot() never ran, trust_removals stayed True in diff(), and the same
    # collapsed ctx.config = {} view B-269 already knows is untrustworthy got written into
    # the baseline as fact: a full fabrication burst (skill/MCP/channel "removed", gateway
    # bind "changed") followed by a CRITICAL "NEW ... connected" burst the moment the file
    # reappeared unchanged. Gated on prev_had_config (see above) so a config-less setup is
    # unaffected.
    config_missing_blind = (not getattr(ctx, "config_found", False)) and prev_had_config
    if parse_error or config_missing_blind:
        _degrade_snapshot(snap, prev)
    return snap


def diff(prev: dict | None, curr: dict) -> list[tuple[str, str]]:
    """Return (level, message) alerts. Empty on first run or no change."""
    if not prev:
        return []
    alerts: list[tuple[str, str]] = []

    # --- B-269: was either side collected while openclaw.json was unreadable? ---------
    prev_blind = bool(prev.get("config_parse_error"))
    curr_blind = bool(curr.get("config_parse_error"))
    # A blind snapshot only carries a usable config baseline when there was a good one to
    # carry forward (see _degrade_snapshot); otherwise its config dimensions are empty
    # because nothing is known, not because nothing is configured.
    prev_config_usable = not prev_blind or prev.get("config_baseline") == "carried"
    compare_config = not curr_blind and prev_config_usable
    # A blind run's disappearances are collection artifacts, not events. _degrade_snapshot
    # already union-merges the shrinkable dimensions so these sets come out empty, but the
    # guard is kept independent of it so a caller that builds a snapshot without passing
    # *prev* still cannot fabricate a removal.
    trust_removals = not curr_blind

    if curr_blind:
        unknown = sum(1 for s in (curr.get("checks") or {}).values() if s == UNKNOWN)
        alerts.append((
            "HIGH",
            "Could not read openclaw.json this run — MCP, channel and gateway drift were "
            f"NOT evaluated and {unknown} check(s) report UNKNOWN. This run covers less "
            "ground than the last full one, so its score/grade are not comparable: a "
            "higher number here means reduced coverage, not improved security. The last "
            "known-good values were kept as the drift baseline. Fix or restore "
            "openclaw.json and re-run to resume full drift detection."))
    elif prev_blind:
        alerts.append((
            "INFO",
            "openclaw.json is readable again — full drift detection resumed; "
            + ("MCP/channel/gateway state was compared against the last known-good "
               "baseline." if prev_config_usable else
               "no known-good config baseline existed (the previous run could not read it "
               "either), so MCP/channel/gateway drift is measured from this run onward.")))

    def _skill_entry(v):
        if isinstance(v, dict):
            return v.get("hash", ""), v.get("caps"), v.get("version")
        return v, None, None          # legacy bare-hash snapshot

    def _skill_changed(p, c) -> bool:
        """B-267: did this skill change? Prefer the full-directory ``tree`` fingerprint.

        The scanned-text ``hash`` is a strict subset of the tree — TEXT-only, capped — so
        where the two disagree the tree is right and the hash is blind. Only when a side
        lacks ``tree`` (a legacy bare-hash snapshot, or one written before this fix) does
        the comparison fall back to the old hash, rather than fabricating a diff against a
        key that was never recorded. That fallback is self-healing: the first snapshot
        written after upgrade carries a tree, so at most one run stays on the old signal.
        """
        p_tree = p.get("tree") if isinstance(p, dict) else None
        c_tree = c.get("tree") if isinstance(c, dict) else None
        if p_tree and c_tree:
            return p_tree != c_tree
        return _skill_entry(p)[0] != _skill_entry(c)[0]

    def _ver_tuple(s: str) -> tuple:
        toks = re.split(r"[.\-+]", s)
        return tuple((0, int(t)) if t.isdigit() else (1, t) for t in toks)

    ps, cs = prev.get("skills", {}), curr.get("skills", {})
    # B-268: the skills truncation frontier on each side (see snapshot()). `ctx.installed_
    # skills` is capped at _MAX_SKILLS and its fill order is filename order — attacker-
    # controlled — so a flood of early-sorting skill dirs evicts real ones from the view.
    # Diffed as ground truth that produced a phantom "Skill 's299' was removed" while s299
    # sat on disk untouched (measured: 310 skills + one aaa*-named addition).
    prev_sk_capped = set(prev.get("skills_capped") or ())
    curr_sk_capped = set(curr.get("skills_capped") or ())
    prev_sk_partial = bool(prev.get("skills_frontier_partial"))
    curr_sk_partial = bool(curr.get("skills_frontier_partial"))
    for name in sorted(cs.keys() - ps.keys()):
        if name in prev_sk_capped:
            # Known to have been on disk last run, merely beyond the cap. Calling it NEW
            # would misdate the install — the CRITICAL says "this is when malware lands",
            # and that claim must not be made about a skill that was already there.
            continue
        _partial = isinstance(cs[name], dict) and cs[name].get("scan_partial")
        _scan_note = (" NOTE: this skill is too large to scan in full, so the audit's "
                      "verdict on it covers only part of its content." if _partial else "")
        if prev_sk_partial:
            # The previous frontier was itself truncated, so we cannot confirm this skill
            # is new. Down-rank and disclose rather than suppress: staying silent about a
            # possibly-just-installed skill is the worse error of the two, and this is the
            # project's standing rule that an ambiguous signal is reported at reduced
            # strength rather than asserted or dropped.
            alerts.append(("HIGH",
                           f"Skill '{name}' is now being inspected and was not inspected "
                           "last run — it may be newly installed, or it may have been "
                           "present all along outside the inspection cap (too many skills "
                           "were installed last run to tell). Vet its source." + _scan_note))
            continue
        alerts.append(("CRITICAL",
                       f"NEW skill installed since last check: '{name}' — vet its source "
                       "before trusting it (this is when malware lands)." + _scan_note))
    for name in sorted(ps.keys() & cs.keys()):
        p_hash, p_caps, p_ver = _skill_entry(ps[name])
        c_hash, c_caps, c_ver = _skill_entry(cs[name])
        if _skill_changed(ps[name], cs[name]):
            _partial = isinstance(cs[name], dict) and cs[name].get("scan_partial")
            alerts.append(("HIGH",
                           f"Installed skill '{name}' CHANGED since last check — re-review it."
                           + (" NOTE: this skill is too large to scan in full, so the "
                              "change may lie outside the region the audit inspects."
                              if _partial else "")))
        elif (isinstance(cs[name], dict) and cs[name].get("tree")
              and cs[name].get("tree_complete") is False):
            # B-267: the fingerprint walk itself could not cover the whole directory, so an
            # unchanged digest is NOT proof of no change. Say so rather than let silence
            # imply coverage (the same B-074 rule that turns a truncated scan into UNKNOWN
            # instead of PASS).
            alerts.append(("INFO",
                           f"Installed skill '{name}' is too large to fingerprint in full — "
                           "part of its directory is not covered by change detection, so "
                           "'unchanged' cannot be confirmed for that region."))

        # Capability diff — only when BOTH sides carry structured caps (new-format
        # snapshots); a legacy/UNKNOWN side skips silently rather than fabricating a diff.
        if p_caps is not None and c_caps is not None:
            added = set(c_caps) - set(p_caps)
            removed = set(p_caps) - set(c_caps)
            if added:
                alerts.append(("HIGH",
                               f"Installed skill '{name}' UPDATE EXPANDED its capabilities: "
                               f"+{', '.join(sorted(added))} — the new version can now do more "
                               "than the version you last reviewed; re-vet it."))
            elif removed:
                alerts.append(("INFO",
                               f"Skill '{name}' capabilities shrank: -{', '.join(sorted(removed))}."))

        # Version regression — best-effort static downgrade signal only. Real TAM-09
        # "replay an old *signed* manifest" semantics require verifying a signature
        # against a trust root, which is impossible read-only/offline; this merely
        # compares the declared frontmatter version string across snapshots.
        if p_ver and c_ver:
            try:
                if _ver_tuple(c_ver) < _ver_tuple(p_ver):
                    alerts.append(("MEDIUM",
                                   f"Skill '{name}' declared version went BACKWARD: "
                                   f"{p_ver} -> {c_ver} — a manifest replay / downgrade signal "
                                   "(TAM-09, best-effort static)."))
            except TypeError:
                pass
    if trust_removals:
        for name in sorted(ps.keys() - cs.keys()):
            # B-268: still on disk this run, just cap-evicted — not a removal. When the
            # frontier is itself truncated we cannot tell the two apart for ANY name, so
            # every removal is suppressed: a missed removal notice (INFO) is a far smaller
            # harm than a burst of fabricated ones, and the disclosure below states that
            # coverage is incomplete.
            if name in curr_sk_capped or curr_sk_partial:
                continue
            alerts.append(("INFO", f"Skill '{name}' was removed."))

    # B-268 disclosure. The FN twin is the serious half: a 300-skill flood hid a skill
    # exfiltrating an SSH key at Grade A, and replaced a live HIGH poisoning alert with
    # five fabricated "removed" lines. Since fill order is filename order, an attacker can
    # choose which skills fall outside the audited set. An all-clear over that view is not
    # honest, so the truncation is stated explicitly.
    _sk_capped_n = int(curr.get("skills_capped_count") or len(curr_sk_capped))
    if _sk_capped_n:
        _eg = sorted(curr_sk_capped)[:3]
        alerts.append((
            "HIGH",
            f"{_sk_capped_n} installed skill(s) were NOT collected — the inspection cap "
            "was reached, so they are neither scanned nor monitored for change"
            + (f" (e.g. {', '.join(_eg)})" if _eg else "")
            + ". Skills are collected in filename order, so which ones fall outside the "
            "cap is not a security decision. Reduce the number of installed skills to "
            "restore full coverage."))

    pb, cb = prev.get("bootstrap", {}), curr.get("bootstrap", {})
    for name in sorted(pb.keys() & cb.keys()):
        if pb[name] != cb[name]:
            alerts.append(("HIGH", f"{name} changed since last check — possible prompt / memory "
                                   "poisoning (drift)."))

    # C-135 FIX1: ctx.bootstrap is keyed "<workspace-label>/<NAME>.md", where the label
    # depends on scan order plus a resolved-path de-dup (collector.py). The exact same
    # inode, with byte-identical content still read by the agent, can land under a
    # DIFFERENT key after a benign refactor — e.g. deleting now-redundant symlinks so
    # files resolve under their real mount label, or renaming the workspace dir and
    # updating the config to match. A bare key-set diff cannot tell that apart from a real
    # deletion. Pair each removed key with an added key carrying the IDENTICAL content
    # hash and treat the pair as a MOVE — neither a removal nor a new file — before either
    # loop below runs. This cannot mask a genuine deletion: if identical content is still
    # present under another key, the agent is still reading it, so there is nothing left
    # to alert on either direction. (Measured separation: a benign rename pairs every
    # removed/added key as a move; a genuine deletion of guardrail files has no added side
    # to pair with at all.)
    _boot_removed, _boot_added = pb.keys() - cb.keys(), cb.keys() - pb.keys()
    _boot_moved_from: "set[str]" = set()
    _boot_moved_to: "set[str]" = set()
    for _r in sorted(_boot_removed):
        for _a in sorted(_boot_added - _boot_moved_to):
            if pb[_r] == cb[_a]:
                _boot_moved_from.add(_r)
                _boot_moved_to.add(_a)
                break

    for name in sorted(_boot_added - _boot_moved_to):
        alerts.append(("INFO", f"New bootstrap file appeared: {name}."))
    # B-275: the removal branch the bootstrap dimension never had — deleting SOUL.md /
    # IDENTITY.md / USER.md / HEARTBEAT.md / BOOTSTRAP.md used to be completely silent,
    # while *modifying* the same file alerted HIGH. That asymmetry manufactured confidence:
    # the cheapest way to drop the agent's standing guardrails was also the only way that
    # produced no alert at all.
    #
    # MEDIUM, not the HIGH used for a content change: removal is also ordinary
    # housekeeping — a user retiring a HEARTBEAT.md they never used is not an attack — and
    # unlike a content change there is no poisoning signal in the event itself, only lost
    # coverage. The wording states what was OBSERVED and asks for confirmation, and
    # deliberately covers both causes of a disappearance: the file was deleted/moved, or it
    # is still there but no longer readable (a chmod 000 on USER.md alone drops it from
    # ctx.bootstrap).
    #
    # C-135 FIX3: it deliberately stops at the observation and does NOT go on to assert
    # "so its standing instructions no longer reach the agent" — a key disappearing from
    # this scan-order-dependent map is not proof the agent stopped reading the underlying
    # file (the FIX1 move case immediately above is exactly that: the key changed, the
    # file did not). An unsupported claim about a consequence this tool cannot observe is
    # treated as a defect in its own right, independent of whether the underlying WARN/FAIL
    # verdict is correct.
    if trust_removals:
        for name in sorted(_boot_removed - _boot_moved_from):
            alerts.append(("MEDIUM",
                           f"Bootstrap file no longer being read: {name} (deleted, moved, "
                           "or no longer readable). Confirm you intended this."))

    _append_memory_alerts(prev, curr, alerts, trust_removals=trust_removals)

    # B-269: a partially-evaluated run is not comparable to a full one in EITHER direction
    # — a blind run's score is inflated by UNKNOWN-exclusion, so the run after it would
    # report a fabricated "score dropped" as the real checks come back. The coverage
    # alert above says so explicitly instead.
    if not (prev_blind or curr_blind) and curr.get("score", 0) < prev.get("score", 0):
        alerts.append(("HIGH", f"Security score dropped: {prev.get('grade')} {prev.get('score')} "
                               f"-> {curr.get('grade')} {curr.get('score')}."))

    pc, cc = prev.get("checks", {}), curr.get("checks", {})
    for cid, status in cc.items():
        if status == FAIL and pc.get(cid) != FAIL:
            # B-269: a check that read UNKNOWN only because the PREVIOUS run could not
            # parse the config was not passing then — re-reading it as FAIL now is the
            # config becoming legible again, not a new failure. Writing that into the
            # hash-chained journal would make a fabricated claim permanent.
            #
            # NARROWS, does not close: a snapshot records only the status, not WHY a check
            # was UNKNOWN, so this also mutes the rare check that read UNKNOWN during the
            # blind window for a config-independent reason and genuinely turned FAIL on the
            # very next run. That is a bounded one-run false negative (the FAIL is still in
            # the run's own report, and the next diff sees FAIL on both sides), accepted in
            # preference to writing a fabricated "Now FAILING" into a tamper-evident
            # journal. Distinguishing the two would need a per-check reason code in the
            # snapshot, which is a schema change (SNAPSHOT_VERSION) beyond this fix.
            # A blind run's checks dict is not a valid comparison baseline in ANY status,
            # not just UNKNOWN. Measured on the real ~/.openclaw: with openclaw.json
            # momentarily absent, A1 reads WARN (not UNKNOWN) off the collapsed
            # ctx.config == {} view, and the run scores C/79 against the true F/49. So a
            # guard keyed only on UNKNOWN let a definite "Now FAILING: Lethal Trifecta"
            # reach the tamper-evident journal on the very next run with nothing changed.
            #
            # Going silent instead would trade that lie for a false negative — a genuine
            # regression landing right after a blind window would never be announced. So
            # the alert still fires, but it is DOWN-RANKED and re-worded to disclose that
            # the comparison crossed a window where the baseline could not be trusted.
            # This follows the project rule that an ambiguous signal is reported at WARN
            # strength rather than asserted or suppressed.
            # prev UNKNOWN out of a blind run carries no information at all — the check
            # was not passing then, so announcing a transition would be pure fabrication.
            # That case stays fully muted.
            if prev_blind and pc.get(cid) == UNKNOWN:
                continue
            title = BY_ID[cid].title if cid in BY_ID else cid
            if prev_blind:
                alerts.append((
                    "MEDIUM",
                    f"Now FAILING: {title} — but the previous run could not read the "
                    "config, so its recorded state is not a trustworthy baseline. This "
                    "may be the config becoming legible again rather than a new failure. "
                    "Re-run to get a clean comparison.",
                ))
                continue
            alerts.append(("HIGH", f"Now FAILING: {title}."))
            # Honest labelling — what the prev_blind guard above does and does NOT fix.
            #
            # CLOSED here: no drift alert derived from a blind run's checks dict can reach
            # the journal any more, whatever status that run happened to record.
            #
            # NOT CLOSED, and not closable from monitor.py: the blind run's own verdict is
            # still wrong at the source. A check that mixes config-derived evidence without
            # calling checks/_shared.py's opt-in _config_unreadable() guard (B-228) keeps
            # computing a real-looking verdict from the collapsed ctx.config == {} view
            # that B-269 already established is untrustworthy. A1 (check_trifecta in
            # checks/_config.py) is one such check, so a blind run reports C/79 on a host
            # whose true grade is F/49 — an inflated grade, not merely a spurious alert.
            # Fixing that means giving A1 and its siblings the same opt-in guard B11 has,
            # which is a checks/_config.py change with its own adversarial review. Filed as
            # a follow-up; this module can only refuse to compare against the bad baseline,
            # which is what it now does.
            #
            # Accepted cost of keying on prev_blind alone: a check that genuinely turns FAIL
            # on the run right after a blind one is not announced for that one run. Bounded
            # and self-healing — the FAIL is still in that run's own report, and the next
            # diff sees FAIL on both sides. Preferred over writing a fabricated claim into
            # a tamper-evident journal, and consistent with the score-drop guard's identical
            # refusal to compare across a blind run.

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
    if compare_config and "mcp" in prev and "mcp" in curr:
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
    if compare_config and "mcp_detail" in prev and "mcp_detail" in curr:
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
            # C-178: command/args0 may hold a pre-cde6798 build's raw (unredacted)
            # value in ps; re-apply redact_urls_in_text (idempotent on an already-
            # redacted value) before comparing, same normalization as RP3's url.
            p_transport = ps.get("transport", "")
            c_transport = cs.get("transport", "")
            p_cmd = redact_urls_in_text(ps.get("command", ""))
            c_cmd = cs.get("command", "")
            p_args0 = redact_urls_in_text(ps.get("args0", ""))
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
            #
            # C-178: cs["url"] is always host-only sanitized at snapshot time
            # (_mcp_detail_sig), but ps["url"] may have been written by a build
            # predating the cde6798 redaction fix, in which case it is still the
            # RAW url (possibly carrying a credential). Re-sanitizing p_url here
            # (idempotent on an already-sanitized value) normalizes both sides to
            # the same form before comparing, so a version upgrade alone never
            # false-positives a rug-pull, and the stale raw credential is never
            # echoed into the alert text either.
            p_url = sanitize_url_host_only(ps.get("url", ""))
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

    if compare_config and "channels" in prev and "channels" in curr:
        pch, cch = prev["channels"], curr["channels"]
        for name in sorted(cch.keys() - pch.keys()):
            alerts.append(("HIGH", f"NEW channel '{name}' appeared since last check — "
                           "confirm its auth / allowlist before it can reach the agent."))
        for name in sorted(pch.keys() & cch.keys()):
            if pch[name] != cch[name]:
                alerts.append(("MEDIUM", f"Channel '{name}' openness/auth changed — review it."))
        # B-275: the channels dimension had no removal branch either. INFO, not HIGH:
        # de-configuring a channel SHRINKS the agent's reachable surface, and users retire
        # channels routinely — worth recording in the journal, not worth alarming over.
        # (Unreachable on a blind run: this whole block is behind compare_config, so a
        # collapsed config can never present itself as a channel deletion.)
        for name in sorted(pch.keys() - cch.keys()):
            alerts.append(("INFO", f"Channel '{name}' is no longer configured — the agent "
                           "can no longer be reached over it."))

    if (compare_config and "gateway_bind" in prev and "gateway_bind" in curr
            and prev["gateway_bind"] != curr["gateway_bind"]):
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
    """Return the 'chain_hash' of the last entry in a JSONL file, or '' if none.

    C-164: streams via ``_iter_jsonl`` (line-by-line) rather than reading the
    whole file into one big list-of-lines, so memory stays flat on a large file;
    only the running "last chain_hash seen so far" is retained.
    """
    if not p.is_file():
        return ""
    last = ""
    try:
        for entry in _iter_jsonl(p):
            val = entry.get("chain_hash")
            if val is not None:
                last = str(val)
    except OSError:
        return ""
    return last


def record_events(alerts, path: str | Path = DEFAULT_EVENTS, when: str | None = None) -> None:
    """Append each drift alert to a local, owner-only event journal (a timeline of
    what changed when). No-op when there are no alerts. Never uploaded — local only.

    Each entry carries a 'chain_hash' field: sha256(prev_chain_hash + canonical_json)
    so the journal is tamper-evident. Existing entries without 'chain_hash' are treated
    as the chain genesis (backward compatible). Each entry also carries '_schema'
    (C-162) INSIDE the hashed payload, so it is itself tamper-evident.

    B-108: the read-last-hash→append critical section runs under an advisory
    ``journal_lock`` so two concurrent monitor runs can't both read the same prev
    chain_hash and each append, which would otherwise leave a spurious
    "chain BROKEN" that neither writer actually caused.

    C-164: after appending, the file is opportunistically rotated (pruned +
    re-chained) once it exceeds the retention cap — see ``_rotate_journal``.
    """
    if not alerts:
        return
    if when is None:
        from datetime import datetime  # noqa: PLC0415
        when = datetime.now().isoformat(timespec="seconds")
    p = Path(path).expanduser()
    try:  # symlink-safe append; never raise from the event journal
        secure_dir(p.parent)
        with journal_lock(p):
            prev_hash = _last_chain_hash(p)
            lines_out: list[str] = []
            for lvl, msg in alerts:
                base = {"ts": when, "level": lvl, "message": msg, "_schema": SCHEMA_VERSION}
                ch = _chain_hash(prev_hash, base)
                entry = {**base, "chain_hash": ch}
                lines_out.append(json.dumps(entry))
                prev_hash = ch
            secure_append_text(p, "\n".join(lines_out) + "\n")
            _rotate_journal(p)
    except OSError:
        pass


def _schema_ok(entry: dict) -> bool:
    """C-162 loader policy: absent/legacy _schema loads; == current loads; a NEWER
    major than this build understands is skipped (no crash, no misparse).

    Skipping is a *loader* concern only: an unknown-future-schema line is
    hidden-but-present, not deleted, and verify_chain() authenticates it, counts it,
    and surfaces the count in its OK message (C-167 — a forged _schema on an honest
    line breaks the chain). So this skip cannot silently erase evidence beyond the
    pre-existing "write access breaks tamper-evidence" boundary."""
    raw = entry.get("_schema")
    if raw is None:
        return True
    try:
        return int(raw) <= SCHEMA_VERSION
    except (TypeError, ValueError):
        # Non-numeric _schema is itself a malformed/tampered line — don't misparse it.
        return False


def load_events(path: str | Path = DEFAULT_EVENTS, limit: int | None = None) -> list[dict]:
    """Read the event journal (chronological). Returns [] if absent/unreadable.

    C-162: a line whose '_schema' is a newer major than this build understands is
    skipped (siblings still load); absent/legacy or current '_schema' loads normally.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        return []
    out: list[dict] = []
    try:
        # C-164: stream line-by-line via _iter_jsonl (not read_text().splitlines())
        # so memory stays flat on a large journal.
        for entry in _iter_jsonl(p):
            if not _schema_ok(entry):
                continue
            out.append(entry)
    except OSError:
        return []
    return out[-limit:] if limit else out
