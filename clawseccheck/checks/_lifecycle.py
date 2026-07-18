"""Topic module: lifecycle checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from .. import attest as _attest
from ..catalog import (
    BY_ID,
    FAIL,
    LOW,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..collector import (
    Context,
    dig,
)
from ..safeio import walk_dir_safely
from ..textnorm import (
    normalize_for_scan,
)

from ._content import (
    _B58_HTML_COMMENT_RE,
    _B64_HIGH_CONFIDENCE_RE,
    _b64_classify,
    _b63_scan,
    _CLICKFIX_REMOTE_FETCH_RE,
    _clickfix_trusted_installer,
    _fence_ranges,
    _secrecy_credential_or_encoding_anchor,
)
from . import _shared
from ._shared import (
    INJECTION_PATTERNS,
    OUTBOUND_TOOL_HINTS,
    SECRET_KEY_RE,
    _DESTRUCTIVE_HINTS,
    _HOOK_EXEC_RE,
    _config_unreadable,
    _custom,
    _enabled_tools,
    _finding,
    _has_approval_gate,
    _hint,
    _mcp_servers,
    _read_jsonl_tail,
    _safe_mtime,
    _skill_frontmatter_block,
)


# ---------- B23: approval-bypass directives in bootstrap ----------
# Matches explicit directives that tell the agent to skip human confirmation.
# Patterns are deliberately narrow to avoid matching benign text:
#   - "do not ask for confirmation" / "do not ask confirmation"
#   - "assume user approved" / "assume the user approved"
#   - "auto-approve" / "autoapprove" (as a directive, not a variable name like auto_approve)
#   - "approval is implied"
#   - "never bother the user"
#   - "no need to confirm"
#   - "skip confirmation"
# Note: "without asking" is already covered by B6 (INJECTION_PATTERNS).
_APPROVAL_BYPASS_RE = re.compile(
    r"\bdo\s+not\s+ask\s+(?:for\s+)?confirmation\b"
    r"|\bassume\s+(?:the\s+)?user\s+approved\b"
    r"|\bauto-approve\b"  # hyphenated directive form only
    r"|\bapproval\s+is\s+implied\b"
    r"|\bnever\s+bother\s+the\s+user\b"
    r"|\bno\s+need\s+to\s+confirm\b"
    r"|\bskip\s+confirmation\b",
    re.I,
)


# ---------- B20: bootstrap / memory write protection (POSIX only) ----------
_CRITICAL_BOOTSTRAP = ("SOUL.md", "AGENTS.md", "TOOLS.md")


# ---------- B25: update / pinning hygiene ----------
# Ref strings that are unambiguously floating (a supply-chain risk for skills).
_FLOATING_REF_RE = re.compile(
    r"^(?:latest|main|master|HEAD|dev|develop|trunk|stable|nightly|canary|edge|next|beta|alpha)$",
    re.I,
)


# C6 (C-052): hook-composition tool-policy drop, fixed in this OpenClaw version.
_HOOK_POLICY_FIX_VERSION = (2026, 6, 10)


# ---------- B22: self-modification risk ----------
# Identity / skill files that, if rewritten by the agent itself, change its behaviour.
# We look for: SOUL.md in any workspace*, plus the skills dirs under ctx.home.
_IDENTITY_TARGETS = ("SOUL.md",)  # minimal — the single file that defines the agent


# ---------- B33: known-vulnerable OpenClaw version gate ----------
# Advisory table — update this list as new OpenClaw advisories are published.
# Unknown / future versions that do not appear in this table are treated as PASS
# only against the entries here; they may still be vulnerable to undiscovered issues.
# Each entry: (ghsa_id, max_vulnerable_version_tuple, fixed_version_str, short_desc)
_KNOWN_ADVISORIES: list[tuple[str, tuple[int, ...], str, str]] = [
    (
        "GHSA-g8p2-7wf7-98mq",
        (2026, 1, 28),
        "2026.1.29",
        "Control UI gatewayUrl → gateway token exfiltration",
    ),
    (
        "GHSA-mc68-q9jw-2h3v",
        (2026, 1, 28),
        "2026.1.29",
        "Docker sandbox authenticated command injection via unsafe PATH handling",
    ),
    (
        "GHSA-g6q9-8fvw-f7rf",
        (2026, 2, 13),
        "2026.2.14",
        "Gateway tool SSRF via unvalidated gatewayUrl override",
    ),
    (
        "GHSA-cv7m-c9jx-vg7q",
        (2026, 2, 13),
        "2026.2.14",
        "Browser upload path traversal via Playwright setInputFiles",
    ),
]


# Keys under plugins/skills that are structural config, not installable entries.
_NON_ENTRY_KEYS = frozenset({"entries", "allow", "deny", "mcp", "items"})


# A pinned ref looks like a commit SHA (7–40 hex chars) or a semver tag.
_PINNED_REF_RE = re.compile(
    r"^v?\d+\.\d+[\.\d]*(?:[+\-][^\s]*)?$"  # semver tag: v1.2.3 / 1.2.3-rc1
    r"|^[0-9a-f]{7,40}$",  # git commit SHA (short or full)
    re.I,
)


# ---------- B42: skill/plugin install-time policy ----------
# Non-redundant with B25 (auto-update/pinning), B13 (skill malware content), B22 (writable
# identity + dangerous tools). B42 surfaces install-time supply-chain risk: an install hook
# that runs code on install/auto-update, and skill dirs writable by OTHER local users.
_POSTINSTALL_RE = re.compile(r'"(pre|post)install"\s*:\s*"([^"]{1,200})"', re.I)


_SOFT_BOOTSTRAP = ("MEMORY.md", "HEARTBEAT.md")


_VERSION_LEADING_INTS_RE = re.compile(r"^(\d+(?:\.\d+)*)")


def _iter_entries(cfg: dict):
    """Yield (namespace, name, entry_dict) for plugins/skills entries, supporting BOTH
    the nested `<ns>.entries.<name>` shape and the legacy flat `<ns>.<name>` shape.

    In the legacy fallback, structural keys (entries/allow/deny/mcp/items) are skipped so
    a non-plugin block such as plugins.mcp is never mistaken for an installable entry; the
    caller's source/version guard (an entry with no ref info is skipped) is a second line
    of defense. Previously the flat shape was dropped entirely → a legacy unpinned plugin
    silently went UNKNOWN instead of WARN.
    """
    for ns in ("plugins", "skills"):
        block = cfg.get(ns)
        if not isinstance(block, dict):
            continue
        entries = block.get("entries")
        if isinstance(entries, dict):
            for name, entry in entries.items():
                if isinstance(entry, dict):
                    yield ns, name, entry
        else:
            for name, entry in block.items():
                if name not in _NON_ENTRY_KEYS and isinstance(entry, dict):
                    yield ns, name, entry


def _parse_version(ver: str) -> tuple[int, ...] | None:
    """Parse the leading dotted-integer portion of a version string.

    Handles "2026.2.9", "2026.1.28", and strips any trailing "-dev"/"-beta"/
    "-rc1"/etc. suffix.  Returns None if fewer than 2 integer components can
    be parsed.

    Examples:
        "2026.1.29"     -> (2026, 1, 29)
        "2026.2.9"      -> (2026, 2, 9)
        "2026.1.28-dev" -> (2026, 1, 28)
        "nightly"       -> None
        "2026"          -> None   (single component — ambiguous)
    """
    m = _VERSION_LEADING_INTS_RE.match(str(ver).strip())
    if not m:
        return None
    parts = tuple(int(x) for x in m.group(1).split("."))
    if len(parts) < 2:
        return None
    return parts


def _writable_by_others(st) -> bool:
    """True when a file/dir is writable by someone OTHER than its owner: world-writable is
    unambiguous; group-writable counts ONLY when the owning group has other members. A
    user-private-group / umask-002 singleton (e.g. Fedora/RHEL defaults: 0o664 files, 0o775
    dirs owned by the user's own private group) is not actually exploitable by anyone else,
    so it must not FAIL (B-189)."""
    mode = st.st_mode & 0o777
    if mode & 0o002:
        return True
    if mode & 0o020:
        return _shared._group_has_other_members(st.st_gid, st.st_uid) is not False
    return False


def _writable_identity_files(ctx: Context) -> list[str]:
    """Return relative paths of identity/skill targets writable by someone other than the
    owner (world-writable, or group-writable with a non-singleton owning group), OR whose
    parent dir is. Only called on POSIX. Returns paths relative to ctx.home.

    B-189: the singleton down-rank applies to EVERY leg — SOUL.md, the workspace/skills dirs,
    and openclaw.json — so a user-private-group / umask-002 box never false-FAILs.
    """
    writable: list[str] = []
    from ..collector import SKILL_DIRS, WORKSPACE_DIRS

    # Check SOUL.md (and the workspace dir that contains it)
    for ws in WORKSPACE_DIRS:
        ws_dir = ctx.home / ws
        if not ws_dir.is_dir():
            continue
        # Workspace dir itself writable-by-others gives write to all files inside
        try:
            st = ws_dir.stat()
            if _writable_by_others(st) and any(
                (ws_dir / f).is_file() for f in _IDENTITY_TARGETS
            ):
                writable.append(f"{ws}/ (dir mode {oct(st.st_mode & 0o777)[-3:]})")
        except OSError:
            pass
        # Individual identity files
        for fname in _IDENTITY_TARGETS:
            f = ws_dir / fname
            if not f.is_file():
                continue
            try:
                st = f.stat()
                if _writable_by_others(st):
                    writable.append(f"{ws}/{fname} (mode {oct(st.st_mode & 0o777)[-3:]})")
            except OSError:
                pass

    # Check the skills directories (writing here installs new skills)
    for rel in SKILL_DIRS:
        d = ctx.home / rel
        if not d.is_dir():
            continue
        try:
            st = d.stat()
            if _writable_by_others(st):
                writable.append(f"{rel}/ (dir mode {oct(st.st_mode & 0o777)[-3:]})")
        except OSError:
            pass

    # openclaw.json writable-by-others is a self-escalation target — a skill with fs_write
    # (running as the agent) could rewrite tool grants, widen tools.exec.mode, or delete the
    # approval gate: strictly worse than the read exposure B1/B11 already flag. Write bit only
    # (a merely group-READABLE config is B1/B11's concern). (F-121)
    cfg_path = ctx.home / "openclaw.json"
    try:
        cst = cfg_path.stat()
    except OSError:
        cst = None
    if cst is not None and _writable_by_others(cst):
        writable.append(f"openclaw.json (mode {oct(cst.st_mode & 0o777)[-3:]})")

    return writable


def _writable_skill_dirs(ctx: Context):
    """POSIX group/world-writable skill dirs (base dirs + immediate skill dirs).

    Returns a list of (path, who, mode) — possibly empty — or None when perms are
    not assessable (Windows / non-POSIX), so the caller reports honestly.
    """
    if not _shared._is_posix():
        return None
    from ..collector import SKILL_DIRS  # noqa: PLC0415

    bad, seen = [], 0
    for rel in SKILL_DIRS:
        base = ctx.home / rel
        try:
            if not base.is_dir() or base.is_symlink():
                continue
        except OSError:
            continue
        candidates = [base]
        try:
            for c in sorted(base.iterdir()):
                if seen >= 200:
                    break
                if c.is_dir() and not c.is_symlink():
                    candidates.append(c)
                    seen += 1
        except OSError:
            pass
        for d in candidates:
            try:
                mode = d.stat().st_mode & 0o777
            except OSError:
                continue
            # Only WORLD-writable is unambiguous: any user on the box can drop a skill.
            # Group-writable is benign on the common user-private-group setup (umask 002),
            # so flagging it would be a false positive — we skip it.
            if mode & 0o002:
                bad.append((str(d), "world", mode))
    return bad


def check_approval_bypass(ctx: Context) -> Finding:
    """B23 — Approval-bypass directives in bootstrap.

    Scans the concatenated bootstrap blob for language that instructs the
    agent to skip human confirmation / approval.

    FAIL    — bypass directive present AND destructive/outbound tools are enabled.
    WARN    — bypass directive present but no destructive/outbound tools detected.
    PASS    — bootstrap present and no bypass directives found.
    UNKNOWN — no bootstrap files to inspect.
    """
    if not ctx.bootstrap:
        return _finding(
            "B23",
            UNKNOWN,
            "No bootstrap files found — cannot scan for approval-bypass directives.",
            "Add an explicit rule to SOUL.md/AGENTS.md requiring human confirmation "
            "before any destructive or outbound action.",
        )

    blob = ctx.bootstrap_blob
    matches = [m.group() for m in _APPROVAL_BYPASS_RE.finditer(blob)]

    if not matches:
        return _finding(
            "B23",
            PASS,
            "No approval-bypass directives detected in bootstrap files.",
            "Keep bootstrap files free of language that weakens human approval gates.",
        )

    # Bypass directive found — severity depends on whether destructive tools are active.
    tools = _enabled_tools(ctx.config)
    has_destructive = _hint(tools, _DESTRUCTIVE_HINTS) or bool(
        dig(ctx.config, "tools.elevated.allowFrom")
    )

    ev = matches[:6]
    extra = f" (+{len(matches) - 6} more)" if len(matches) > 6 else ""
    directive_summary = "; ".join(f'"{m}"' for m in ev) + extra

    if has_destructive:
        return _finding(
            "B23",
            FAIL,
            f"Bootstrap contains approval-bypass directive(s) AND destructive/outbound "
            f"tools are enabled — the agent may act without human sign-off: "
            f"{directive_summary}",
            "Remove the bypass directive(s) from SOUL.md/AGENTS.md/TOOLS.md and "
            "ensure tools.exec.mode is 'ask' or 'allowlist' for all "
            "destructive/outbound actions.",
            evidence=ev,
        )

    return _finding(
        "B23",
        WARN,
        f"Bootstrap contains approval-bypass directive(s) (no destructive tools "
        f"currently detected, but directive remains a risk if tools are added later): "
        f"{directive_summary}",
        "Remove the bypass directive(s) from bootstrap files. Human approval gates "
        "must never be weakened in the agent's identity/instruction files.",
        evidence=ev,
    )


# ---------- B17: autonomy / heartbeat actions ----------
def _heartbeat_file_has_real_content(text: str) -> bool:
    """B-129: does a HEARTBEAT.md body contain an actual task entry?

    True only when at least one line is non-blank AND not a comment. A comment
    line either starts with ``#`` (markdown heading/comment convention used
    elsewhere in bootstrap files) or falls inside/adjacent to an HTML
    ``<!-- -->`` comment block. A file that is empty, whitespace-only, or
    contains nothing but comments is treated as a disabled template, not an
    active schedule.
    """
    in_html_comment = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Track (possibly multi-line) HTML comment blocks; a line that is
        # entirely inside one, or is itself a one-line <!-- ... --> comment,
        # never counts as real content.
        if in_html_comment:
            if "-->" in line:
                in_html_comment = False
                remainder = line.split("-->", 1)[1].strip()
                if remainder and not remainder.startswith("#"):
                    return True
            continue
        if line.startswith("<!--"):
            if "-->" in line:
                remainder = line.split("-->", 1)[1].strip()
                if remainder and not remainder.startswith("#"):
                    return True
            else:
                in_html_comment = True
            continue
        if line.startswith("#"):
            continue
        return True
    return False


def check_autonomy(ctx: Context) -> Finding:
    """Does the agent act autonomously (heartbeat) and can it take outbound actions?"""
    cfg = ctx.config

    # Signal 1: a HEARTBEAT.md bootstrap file with actual (non-blank, non-comment)
    # task content — B-129: a filename match alone proves nothing; a disabled,
    # comments-only template must not be reported as an active schedule.
    heartbeat_texts = [v for k, v in ctx.bootstrap.items() if k.endswith("HEARTBEAT.md")]
    has_heartbeat_file = any(_heartbeat_file_has_real_content(t) for t in heartbeat_texts)
    # Signal 2: real heartbeat / cron keys in config
    # Real paths: agents.defaults.heartbeat or agents.list[].heartbeat; top-level cron
    # heartbeat (top-level) and schedule do NOT exist in OpenClaw schema — removed
    has_heartbeat_cfg = bool(
        dig(cfg, "agents.defaults.heartbeat")
        or any(
            dig(agent, "heartbeat")
            for agent in (dig(cfg, "agents.list") or [])
            if isinstance(agent, dict)
        )
        or dig(cfg, "cron")
    )
    autonomous = has_heartbeat_file or has_heartbeat_cfg

    if not autonomous:
        # Either no HEARTBEAT.md/config signal at all, OR a HEARTBEAT.md exists but
        # is empty/comments-only with no heartbeat/cron config key — both are
        # "nothing to reason about", not an active schedule.
        if heartbeat_texts:
            return _finding(
                "B17",
                UNKNOWN,
                "A HEARTBEAT.md file is present but contains no task content (empty or "
                "comments-only) and no heartbeat/cron config key was found — cannot "
                "confirm the agent actually runs on an active schedule.",
                "If heartbeat scheduling is intended, add real task entries to "
                "HEARTBEAT.md or set agents.defaults.heartbeat / a per-agent heartbeat.",
            )
        return _finding("B17", UNKNOWN, "No autonomy/heartbeat signal detected.", "—")

    tools = _enabled_tools(cfg)
    has_outbound = _hint(tools, OUTBOUND_TOOL_HINTS)

    if has_outbound:
        return _finding(
            "B17",
            WARN,
            "Agent runs autonomously (heartbeat) and can take outbound actions — "
            "ensure it cannot act on untrusted input without approval.",
            "Add an approval gate (tools.exec.mode='ask' or tools.exec.security='ask') "
            "for all outbound/exec actions triggered by heartbeat tasks; validate any "
            "external content before acting on it.",
        )
    return _finding(
        "B17",
        WARN,
        "Agent runs on a heartbeat schedule — verify heartbeat tasks cannot be "
        "manipulated by untrusted input (e.g. memory poisoning, injected task files).",
        "Keep heartbeat task lists write-protected and review them periodically.",
    )


# ---------- C3: backups of SOUL.md / memory (advisory) ----------
def check_backups(ctx: Context) -> Finding:
    """Are the agent's identity/memory files backed up (recoverable after drift/poisoning)?"""
    has_bootstrap = any(n.endswith(("SOUL.md", "MEMORY.md", "AGENTS.md")) for n in ctx.bootstrap)
    if not has_bootstrap:
        return _finding("C3", UNKNOWN, "No bootstrap/memory files found to back up.", "—")
    found = []
    _backup_search_roots = [ctx.home]
    for _candidate in (
        ctx.home.parent / "backups",
        ctx.home.parent / ".backups",
        Path.home() / ".backups",
    ):
        if _candidate != ctx.home and _candidate not in _backup_search_roots:
            _backup_search_roots.append(_candidate)
    for _root in _backup_search_roots:
        try:
            for entry in _root.rglob("*"):
                n = entry.name.lower()
                if entry.is_file() and (
                    n.endswith((".bak", ".backup")) or "backup" in entry.parent.name.lower()
                ):
                    found.append(entry.name)
                    if len(found) >= 5:
                        break
        except OSError:
            pass
        if len(found) >= 5:
            break
    if found:
        return _finding(
            "C3",
            PASS,
            f"Backups present ({', '.join(found[:3])}{'…' if len(found) > 3 else ''}).",
            "Keep backups owner-only and outside the agent's writable workspace.",
        )
    return _finding(
        "C3",
        WARN,
        "No backups of SOUL.md / MEMORY.md found — if the agent's identity or memory "
        "is poisoned or corrupted, there's nothing to restore from.",
        "Keep versioned, owner-only backups of SOUL.md/AGENTS.md/MEMORY.md outside the "
        "agent's writable workspace.",
    )


def check_bootstrap_injection(ctx: Context) -> Finding:
    """Coverage gap: the native audit does not scan bootstrap-file content; this check does."""
    if not ctx.bootstrap:
        return _finding(
            "B6",
            UNKNOWN,
            "No bootstrap files found to inspect.",
            "Run on the host where workspace SOUL.md/AGENTS.md/TOOLS.md live.",
        )
    ev = []
    for fname, text in ctx.bootstrap.items():
        norm = normalize_for_scan(text)
        for pat in INJECTION_PATTERNS:
            if pat.search(norm):
                ev.append(f"{fname}: matches '{pat.pattern[:40]}…'")
                break
    if ev:
        return _finding(
            "B6",
            FAIL,
            "; ".join(ev),
            "Remove blanket 'obey/follow any instruction' directives "
            "from SOUL.md/AGENTS.md/TOOLS.md. Add an explicit rule: treat content from "
            "channels/web/email as untrusted data, never as instructions.",
            ev,
        )
    return _finding(
        "B6",
        PASS,
        "No blanket-obedience / injection-prone directives in bootstrap files.",
        "Keep a trusted/untrusted separation rule in SOUL.md.",
        pass_confidence="verified",
    )


def check_bootstrap_write_protection(ctx: Context) -> Finding:
    """Bootstrap identity files and their workspace dirs must not be writable by others.

    FAIL  — world-writable (mode & 0o002) on SOUL.md / AGENTS.md / TOOLS.md
            or the parent workspace dir that contains them.
    WARN  — group-writable (mode & 0o020) on SOUL.md / AGENTS.md / TOOLS.md
            or their parent workspace dir; OR group/world-writable (& 0o022)
            on MEMORY.md / HEARTBEAT.md.
    UNKNOWN — non-POSIX platform, or no relevant files found.
    PASS  — files found, all perms are tight.

    Only stat() is called — no file contents are read.
    """
    if not _shared._is_posix():
        return _finding(
            "B20",
            UNKNOWN,
            "On Windows, file security uses NTFS ACLs, not POSIX mode bits — "
            "ClawSecCheck can't read those read-only (no extra tools), so this is "
            "UNKNOWN, never a false PASS.",
            "Check the ACLs yourself: `icacls <path>` should not grant write to "
            "Users / Everyone / Authenticated Users.",
        )

    world_write: list[str] = []  # -> FAIL
    group_write: list[str] = []  # -> WARN (if no FAIL); other group members exist/unknown
    group_write_singleton: list[str] = []  # -> LOW hygiene note: no other group members
    found_any = False

    from ..collector import WORKSPACE_DIRS

    seen: set = set()  # resolved paths already statted -> never double-report

    def _record_group_write(entry: str, st) -> None:
        """File/dir is group-writable: bucket by whether the group has other members.

        B-127: group-write alone does not mean an exploitable "other member" exists.
        Only downgrade when membership is POSITIVELY known to be singleton — an
        UNKNOWN membership result keeps the existing WARN behavior unchanged.
        *entry* is the already-formatted evidence string (e.g. "path (mode 664)").
        """
        other_members = _shared._group_has_other_members(st.st_gid, st.st_uid)
        if other_members is False:
            group_write_singleton.append(entry)
        else:
            group_write.append(entry)

    def _classify_file(path: Path, rel: str, *, soft: bool) -> bool:
        """stat one file; record world/group write. Returns True if the file existed.

        soft (MEMORY.md/HEARTBEAT.md): WARN on group OR world write.
        critical (SOUL/AGENTS/TOOLS): FAIL on world write, WARN on group write.
        """
        if not path.is_file():
            return False
        try:
            real = path.resolve()
        except OSError:
            real = path
        if real in seen:
            return True
        seen.add(real)
        try:
            st = path.stat()
        except OSError:
            return True
        mode = st.st_mode & 0o777
        if soft:
            if mode & 0o022:
                _record_group_write(f"{rel} (mode {oct(mode)[-3:]})", st)
        elif mode & 0o002:
            world_write.append(f"{rel} (mode {oct(mode)[-3:]})")
        elif mode & 0o020:
            _record_group_write(f"{rel} (mode {oct(mode)[-3:]})", st)
        return True

    # Scan the OpenClaw home ROOT ("") as well as each workspace dir. The root is
    # included so a bootstrap/memory file living OUTSIDE the three workspace dir names
    # (a common real layout) is no longer invisible — §6: never hardcode one shape.
    scan_dirs = [("", ctx.home)] + [(ws, ctx.home / ws) for ws in WORKSPACE_DIRS]
    for ws, ws_dir in scan_dirs:
        if not ws_dir.is_dir():
            continue
        prefix = f"{ws}/" if ws else ""
        has_critical_here = any((ws_dir / f).is_file() for f in _CRITICAL_BOOTSTRAP)
        has_any_here = has_critical_here or any((ws_dir / f).is_file() for f in _SOFT_BOOTSTRAP)
        if not has_any_here:
            continue

        found_any = True

        # Parent dir perms (only relevant when critical bootstrap files live here)
        if has_critical_here:
            try:
                dir_st = ws_dir.stat()
                dir_mode = dir_st.st_mode & 0o777
                rel = prefix.rstrip("/") or "."
                if dir_mode & 0o002:
                    world_write.append(f"{rel}/ (dir, mode {oct(dir_mode)[-3:]})")
                elif dir_mode & 0o020:
                    _record_group_write(f"{rel}/ (dir, mode {oct(dir_mode)[-3:]})", dir_st)
            except OSError:
                pass

        for fname in _CRITICAL_BOOTSTRAP:
            _classify_file(ws_dir / fname, f"{prefix}{fname}", soft=False)
        for fname in _SOFT_BOOTSTRAP:
            _classify_file(ws_dir / fname, f"{prefix}{fname}", soft=True)

    # Discovery-assisted: the agent may declare where its bootstrap/memory files really
    # live (any path, any name). The agent supplies WHERE; the engine still stat()s the
    # file itself, so this stays an authoritative permission check, not a weak self-report.
    for raw in _attest.attested_paths(ctx.attestation)["bootstrap"]:
        p = Path(raw).expanduser()
        # Classify by filename: a known identity file gets the critical (FAIL-on-world)
        # rule; anything else is treated as soft (memory) -> WARN only.
        soft = p.name not in _CRITICAL_BOOTSTRAP
        if _classify_file(p, f"{p} [attested]", soft=soft):
            found_any = True

    if not found_any:
        return _finding(
            "B20",
            UNKNOWN,
            "No workspace bootstrap files (SOUL.md/AGENTS.md/TOOLS.md/MEMORY.md) found "
            "under the audited home or known workspace dirs — they may live elsewhere.",
            "Point the audit at the directory holding these files with "
            "`clawseccheck --home <workspace>`, or declare their real paths via "
            "`--attest` (paths.bootstrap) so the engine can stat them.",
        )

    if world_write:
        joined = "; ".join(world_write[:8])
        extra = f" (+{len(world_write) - 8} more)" if len(world_write) > 8 else ""
        return _finding(
            "B20",
            FAIL,
            f"Bootstrap identity file(s) or workspace dir are world-writable — "
            f"any local user can overwrite the agent's identity/instructions: "
            f"{joined}{extra}",
            "Run `chmod o-w` on the listed files/dirs. For full protection use "
            "`chmod 700` on workspace dirs and `chmod 600` on bootstrap files.",
            evidence=world_write,
        )

    if group_write:
        joined = "; ".join(group_write[:8])
        extra = f" (+{len(group_write) - 8} more)" if len(group_write) > 8 else ""
        return _finding(
            "B20",
            WARN,
            f"Bootstrap or memory file(s) are group-writable — members of the "
            f"file's group can overwrite agent identity/memory: {joined}{extra}",
            "Run `chmod g-w` on the listed files/dirs, or tighten to `chmod 700`/`600`.",
            evidence=group_write,
        )

    if group_write_singleton:
        # B-127: group-write bit is set, but the owning group currently has no other
        # members — there is no "other group member" who could exploit it. Still a
        # least-privilege hygiene deviation, so keep a low-severity note rather than
        # asserting an active, exploitable threat.
        joined = "; ".join(group_write_singleton[:8])
        extra = f" (+{len(group_write_singleton) - 8} more)" if len(group_write_singleton) > 8 else ""
        return _custom(
            "B20", LOW, WARN,
            f"Bootstrap or memory file(s) are group-writable — tighten to 0600/0700; "
            f"no other group members currently: {joined}{extra}",
            "Run `chmod g-w` on the listed files/dirs, or tighten to `chmod 700`/`600` "
            "for defense in depth (group membership can change later).",
            group_write_singleton,
        )

    return _finding(
        "B20",
        PASS,
        "Bootstrap identity and memory files have tight write permissions.",
        "Keep workspace dirs at chmod 700 and bootstrap files at chmod 600.",
    )


def check_cron_scheduler(ctx: Context) -> Finding:
    """C048 — advisory UNKNOWN for the top-level OpenClaw `cron` field.

    The presence of `cron` confirms a recurring scheduler surface, but static config
    cannot tell legitimate schedules from attacker-planted persistence. This check is
    therefore UNKNOWN-only on presence and PASS when the field is absent.
    """
    unreadable = _config_unreadable("C048", ctx)
    if unreadable is not None:
        return unreadable
    cron = dig(ctx.config, "cron")
    if cron:
        return _finding(
            "C048",
            UNKNOWN,
            "Top-level `cron` scheduler is configured. Recurring scheduled tasks can "
            "become a persistence surface, but static config cannot distinguish a "
            "legitimate schedule from attacker-planted automation — manual review required.",
            "Review each scheduled cron task and confirm it was intentionally configured. "
            "Treat cron as a persistence surface and verify scheduled actions cannot run "
            "untrusted instructions unattended.",
            evidence=["top-level `cron` field is present"],
        )
    return _finding(
        "C048",
        PASS,
        "No top-level `cron` scheduler is configured.",
        "Keep recurring schedules disabled unless they are explicitly required and reviewed.",
    )


def check_cron_job_content(ctx: Context) -> Finding:
    """B168 (B-231 sub-item 1) — cron JOB STORE content scan.

    C048 (above) only sees the top-level `cron` config *key*; the actual scheduled job
    payloads live in a separate store the collector now reads read-only (B-231):
    ~/.openclaw/cron/jobs.json, or the SQLite-backed cron_jobs table when the JSON file
    is absent (see collector._collect_cron). Recurring, unattended-execution jobs are a
    persistence/exfil surface that was previously invisible — this CONSUMES the same
    content-ring detectors B169 reuses (does not edit checks/_content.py):

    - ``_B64_HIGH_CONFIDENCE_RE`` + ``_b64_classify`` (B64 instruction-hierarchy override).
    - ``_b63_scan`` (B63 silent-instruction / secrecy-framed directive).
    - ``_CLICKFIX_REMOTE_FETCH_RE`` + ``_clickfix_trusted_installer`` (remote-fetch/
      pipe-to-shell pattern, same detector B167/B169 reuse).

    Also flags a structural signal: `deleteAfterRun` combined with an executable
    trigger.script or a command-kind payload is a self-erasing job — a legitimate one-shot
    task can look like this too, so on its own it is WARN, not FAIL; it only adds to an
    already-FAILing job's evidence.

    FAIL    — a job's payload.message or trigger.script matches a high-confidence
              override/install directive.
    WARN    — a weaker/ambiguous content-ring signal, or a deleteAfterRun+exec job with
              no other signal.
    UNKNOWN — no cron store found (~/.openclaw/cron/jobs.json and the SQLite cron_jobs
              table are both absent), or the store was found but could not be parsed/read.
    PASS    — a cron store was read and no job triggers any signal.
    """
    if not ctx.cron_found:
        return _finding(
            "B168",
            UNKNOWN,
            "No cron job store found (~/.openclaw/cron/jobs.json and the SQLite-backed "
            "cron_jobs table are both absent) — cannot determine.",
            "If cron jobs are configured, ensure the store is owner-readable so a future "
            "audit can inspect scheduled job payloads.",
        )
    if ctx.cron_parse_error:
        return _finding(
            "B168",
            UNKNOWN,
            "A cron job store was found but could not be parsed/read — cannot determine.",
            "Fix the cron store (jobs.json or the state SQLite database) so it is valid "
            "and owner-readable, then re-run the audit.",
        )

    fail_ev: list[str] = []
    warn_ev: list[str] = []

    def _scan_field(label: str, text) -> None:
        if not isinstance(text, str) or not text.strip():
            return
        norm = normalize_for_scan(text)
        fr = _fence_ranges(norm)
        cr = [(mm.start(), mm.end()) for mm in _B58_HTML_COMMENT_RE.finditer(norm)]

        # B-231: a STRONG, unambiguous anchor gates whether a B63 secrecy hit may grade-cap
        # on this cron surface. A bare secrecy phrase + a bare _EXFIL_RE keyword ("post") is
        # AMBIGUOUS (a benign digest that withholds a detail vs a covert-exfil directive), so
        # per project doctrine (§5 — ambiguous suppression → WARN, not FAIL) it stays WARN
        # unless a B64 instruction-override, a curl|bash pipe-to-shell install directive, or a
        # credential-path co-occurs in the same field. (The former base64-blob anchor was
        # dropped in Wave-2 round-4 — a blob can't be told apart from a URL/path/hash in
        # short text; see _content.py.)
        field_has_strong = False

        for mm in _B64_HIGH_CONFIDENCE_RE.finditer(norm):
            disp = _b64_classify(norm, mm.start(), mm.end(), fr, cr)
            if disp == "skip":
                continue
            snippet = mm.group().strip()
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            if disp == "warn":
                warn_ev.append(f'{label}: instruction-override "{snippet}"')
            else:
                fail_ev.append(f'{label}: instruction-override "{snippet}"')
                field_has_strong = True

        cf = _CLICKFIX_REMOTE_FETCH_RE.search(norm)
        if cf and not _clickfix_trusted_installer(cf.group(0)):
            snippet = cf.group(0).strip()
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            fail_ev.append(f'{label}: remote-fetch/pipe-to-shell install directive "{snippet}"')
            field_has_strong = True

        if _secrecy_credential_or_encoding_anchor(norm):
            field_has_strong = True

        # B63 silent-instruction / secrecy-framed directive. B-231: on this cron surface a
        # bare secrecy phrase + bare outbound verb ("post") is ambiguous with a benign
        # scheduled digest that withholds one detail, so it only FAILs when a strong anchor
        # co-occurs; otherwise it surfaces as WARN (no grade cap).
        for snippet, is_anchored in _b63_scan(norm, fr):
            note = f'{label}: silent-instruction directive "{snippet}"'
            (fail_ev if (is_anchored and field_has_strong) else warn_ev).append(note)

    for job in ctx.cron_jobs:
        job_label = f"cron job '{job.get('id') or job.get('name') or '?'}'"
        _scan_field(f"{job_label}.payload.message", job.get("payload_message"))
        _scan_field(f"{job_label}.trigger.script", job.get("trigger_script"))

        is_exec = bool(job.get("trigger_script")) or job.get("payload_kind") == "command"
        if job.get("delete_after_run") and is_exec:
            warn_ev.append(
                f"{job_label}: deleteAfterRun + exec trigger/command payload "
                "(self-erasing job)"
            )

    if fail_ev:
        ev_summary = "; ".join(fail_ev[:4])
        extra = f" (+{len(fail_ev) - 4} more)" if len(fail_ev) > 4 else ""
        return _finding(
            "B168",
            FAIL,
            "A cron job's payload.message or trigger.script carries an embedded "
            "instruction-override or install directive: " + ev_summary + extra,
            "Remove the embedded directive from the cron job. Treat cron as an unattended-"
            "execution surface — never let a scheduled job carry a live instruction to the "
            "agent or a remote-fetch/pipe-to-shell command.",
            fail_ev + warn_ev,
        )
    if warn_ev:
        ev_summary = "; ".join(warn_ev[:4])
        extra = f" (+{len(warn_ev) - 4} more)" if len(warn_ev) > 4 else ""
        return _finding(
            "B168",
            WARN,
            "A cron job matches a weaker/ambiguous signal: " + ev_summary + extra,
            "Review the flagged cron job. A deleteAfterRun one-shot exec job or an "
            "ambiguous directive may be legitimate — confirm it was intentionally "
            "configured.",
            warn_ev,
        )
    return _finding(
        "B168",
        PASS,
        f"Scanned {len(ctx.cron_jobs)} cron job(s): no embedded instruction-override or "
        "install directive found.",
        "Keep cron job payloads free of embedded directives; review new scheduled jobs "
        "before they run unattended.",
        pass_confidence="verified",
    )


def check_exec_approvals_grants(ctx: Context) -> Finding:
    """B172 (B-236, re-scoped): inventory of standing exec-approvals.json "allow-always"
    grants.

    ``~/.openclaw/exec-approvals.json`` is OpenClaw's persisted per-agent exec-approval
    store (grounded against the dist: exec-approvals-BIKWP8_V.js). A historical "always
    allow" click on an exec confirmation prompt writes a durable
    ``agents.<id>.allowlist[]`` entry with ``source: "allow-always"`` -- a standing,
    per-command exec grant living entirely outside openclaw.json that, before this
    check, no check in the project ever read.

    B-236 was originally filed on the premise that such a grant SILENTLY OVERRIDES the
    ``tools.exec`` gate, making B8/B22/B23/B48 report a lying-PASS. That premise was
    adversarially REFUTED during the task's own review: OpenClaw computes the effective
    exec policy as ``minSecurity(tools.exec.security, execApprovals.security) +
    maxAsk(tools.exec.ask, execApprovals.ask)`` (bash-tools*.js:581-582;
    exec-approvals-BIKWP8_V.js:1126-1140 -- runtime comment "Stricter values from
    tools.exec and ...exec-approvals both apply") -- a standing grant can only TIGHTEN
    the openclaw.json gate, never loosen it. So this check never contradicts B8/B22/
    B23/B48's PASS; it is a pure visibility/inventory advisory (a persisted grant you
    may have forgotten about), not a correctness fix for those checks.

    WARN    — at least one agent has 1+ "allow-always" allowlist entries: name them so
              the user can review/revoke stale standing grants.
    PASS    — the store was read and no agent has an "allow-always" entry (the common
              case -- e.g. freshly-provisioned defaults/agents are both empty `{}`).
    UNKNOWN — exec-approvals.json is absent (or a symlink, never followed), or was
              found but could not be parsed/read.
    """
    if not ctx.exec_approvals_found:
        return _finding(
            "B172",
            UNKNOWN,
            "No exec-approvals.json store found at ~/.openclaw/exec-approvals.json — "
            "cannot determine whether any standing 'always allow' exec grants are "
            "persisted.",
            "If exec approvals have ever been granted, ensure the store is "
            "owner-readable so a future audit can inventory it.",
        )
    if ctx.exec_approvals_parse_error:
        return _finding(
            "B172",
            UNKNOWN,
            "exec-approvals.json was found but could not be parsed/read — cannot "
            "determine whether any standing 'always allow' exec grants are persisted.",
            "Fix the exec-approvals.json store so it is valid JSON and owner-readable, "
            "then re-run the audit.",
        )

    grants = [g for g in ctx.exec_approvals_grants if g.get("allow_always_count")]
    if not grants:
        return _finding(
            "B172",
            PASS,
            "exec-approvals.json was read and no agent has a standing 'allow-always' "
            "exec grant.",
            "Standing grants are created by clicking 'always allow' on an exec "
            "confirmation prompt — avoid them for anything you would not want run "
            "unattended.",
            pass_confidence="verified",
        )

    evidence = [
        f"agent '{g['agent_id']}': {g['allow_always_count']} allow-always pattern(s)"
        + (f", security={g['security']}" if g.get("security") else "")
        + (f", ask={g['ask']}" if g.get("ask") else "")
        for g in grants
    ]
    ev_summary = "; ".join(evidence[:4])
    extra = f" (+{len(evidence) - 4} more)" if len(evidence) > 4 else ""
    return _finding(
        "B172",
        WARN,
        "OpenClaw has standing 'allow-always' exec grant(s) persisted outside "
        "openclaw.json: " + ev_summary + extra + ". These do NOT bypass the "
        "openclaw.json tools.exec gate (OpenClaw always applies the stricter of the "
        "two), but they ARE a durable per-command exec authority that may have been "
        "forgotten.",
        "Review standing exec approvals with `openclaw approvals get`, then revoke any "
        "'always allow' pattern that is no longer wanted with `openclaw approvals "
        "allowlist remove \"<pattern>\"` (or inspect ~/.openclaw/exec-approvals.json "
        "directly).",
        evidence,
    )


def check_hook_policy_bypass(ctx: Context) -> Finding:
    """C6 (C-052) — advisory: pre-v2026.6.10 hook-registry composition could silently
    drop trusted tool policies at runtime (fixed v2026.6.10).

    This is a runtime evaluation-order effect with NO static config field (hooks.* /
    tools.trusted are not in the schema), so it is an honest UNKNOWN nudge — never a FAIL.
    UNKNOWN fires only when the recorded version predates the fix AND a tool policy
    (tools.exec.mode / tools.elevated.allowFrom) is configured (something that could have
    been dropped). Everything else PASSes, so there is no UNKNOWN flood.
    """
    unreadable = _config_unreadable("C6", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    raw = dig(cfg, "meta.lastTouchedVersion") or dig(cfg, "lastTouchedVersion")
    parsed = _parse_version(str(raw)) if raw else None
    has_policy = bool(dig(cfg, "tools.exec.mode")) or isinstance(
        dig(cfg, "tools.elevated.allowFrom"), dict
    )
    if parsed is not None and parsed < _HOOK_POLICY_FIX_VERSION and has_policy:
        return _finding(
            "C6",
            UNKNOWN,
            "This OpenClaw version predates v2026.6.10, which fixed a hook-registry "
            "composition bug that could silently drop trusted tool policies at runtime. "
            "Whether your tools.exec.mode / tools.elevated.allowFrom policy was affected is a "
            "runtime evaluation-order effect that cannot be read from config — state unknown.",
            "Upgrade to OpenClaw v2026.6.10 or later, then re-verify that tools.exec.mode and "
            "tools.exec.security are enforced as intended.",
            evidence=[f"lastTouchedVersion={raw} (predates the v2026.6.10 fix)"],
        )
    return _finding(
        "C6",
        PASS,
        "No pre-v2026.6.10 hook-composition tool-policy-drop exposure detected.",
        "Keep OpenClaw updated and re-verify tools.exec.mode after upgrades.",
    )


def check_human_approval(ctx: Context) -> Finding:
    cfg = ctx.config
    tools = _enabled_tools(cfg)
    destructive = _hint(tools, OUTBOUND_TOOL_HINTS)
    if not destructive:
        return _finding("B8", UNKNOWN, "No destructive/outbound tools detected.", "—")
    if _has_approval_gate(cfg):
        return _finding(
            "B8",
            PASS,
            "Destructive actions require human approval.",
            "Keep approval gating on all high-impact tools.",
        )
    return _finding(
        "B8",
        WARN,
        "Destructive tools (exec/send/write) present with no clear approval gate.",
        "Set tools.exec.mode to 'ask' or 'allowlist' (not 'full') and "
        "tools.exec.security='ask' to gate exec actions.",
    )


def check_install_policy(ctx: Context) -> Finding:
    from ..logsafe import redact as _redact  # noqa: PLC0415

    skills = ctx.installed_skills
    if not skills:
        return _finding(
            "B42",
            UNKNOWN,
            "No installed skills/plugins found to assess for install-time policy.",
            "Run on the host where skills live (~/.openclaw/skills, workspace/skills).",
        )
    warns: list[str] = []
    # install/postinstall hooks that execute code on install or auto-update
    for name, blob in skills.items():
        for m in _POSTINSTALL_RE.finditer(blob):
            kind, cmd = m.group(1).lower(), m.group(2)
            if _HOOK_EXEC_RE.search(cmd):
                warns.append(
                    f"{name}: {kind}install hook runs code on install/update -> "
                    f"'{_redact(cmd)[:80]}'"
                )
    # skill dirs writable by other local users (anyone can drop a skill the agent loads)
    perm_bad = _writable_skill_dirs(ctx)
    for path, who, mode in (perm_bad or [])[:6]:
        warns.append(f"{who}-writable skill dir {path} (mode {mode:o})")
    if warns:
        return _finding(
            "B42",
            WARN,
            "Install-time supply-chain risk: " + "; ".join(warns[:8]),
            "Review/disable any install hook you haven't read; pin skills to a reviewed "
            "commit; `chmod 700` skill dirs so only you can add skills; turn off skill "
            "auto-update until each hook is trusted.",
            warns,
        )
    return _finding(
        "B42",
        PASS,
        f"Scanned {len(skills)} installed skill(s): no risky install hooks, and skill "
        "dirs are not writable by other local users.",
        "Keep skill dirs owner-only and read any install/postinstall hook before trusting a skill.",
    )


# ---------- B174 (B-238): security.installPolicy.* operator gate + exec-hook escape flags ----------
# Distinct from B42 (post-install hook CONTENT scanned out of a skill's own package.json).
# B174 reads the operator-facing GATE itself: security.installPolicy.{enabled, targets,
# exec:{command, args, env, passEnv, trustedDirs, allowInsecurePath, allowSymlinkCommand}}.
# Grounded against the installed OpenClaw dist:
#   - zod-schema-O9ml_nmo.js:670-687 (the exact object shape, .strict())
#   - types.openclaw-CXjMEWAQ.d.ts:1597-1618 (same shape, doc comments)
#   - install-policy-Barp1EUw.js resolvePolicy(): `if (!policy || policy.enabled !== true)
#     return { kind: "disabled" }` -- ANY non-`true` enabled (absent key or explicit false)
#     means installs/updates run with NO operator-owned review at all. When enabled=true,
#     assertSecureCommandPath() validates the exec hook's own command path UNLESS
#     allowInsecurePath/allowSymlinkCommand explicitly bypass it (dist source text: "Set
#     allowInsecurePath=true for this policy to bypass this check when the path is trusted").
# FAIL is reserved for positive, ungated evidence of a bypassed safety check (C-135
# adversarial pass) -- the bare "not enabled" default state is common and often a
# deliberate choice (many hosts never touch this operator-only gate), so it is WARN-only.
#
# B-238 (C-135 adversarial re-pass, 2026-07-18): the original FAIL condition treated
# allowInsecurePath and allowSymlinkCommand as equally fatal literal booleans. Re-grounding
# against the installed dist (install-policy-Barp1EUw.js assertSecureCommandPath(),
# openclaw 2026.7.1-2) plus a live run of OpenClaw's OWN exported validateInstallPolicyStatic
# against a real on-disk stable-symlink layout proved that was wrong on two counts:
#
#   1. allowSymlinkCommand ALONE only skips the "command must not be a symlink" text check.
#      Execution then still: resolves the symlink, rejects a second-level symlink, enforces
#      trustedDirs containment (if set), and -- because allowInsecurePath is a SEPARATE flag
#      and stays false here -- runs the full permission probe (world/group-writable),
#      ancestor-directory ownership walk, and uid-ownership check against the RESOLVED
#      target. That is the standard update-alternatives/Homebrew/nix "stable alias ->
#      versioned binary" packaging idiom; a real repro (a symlink to a 0755 root/user-owned
#      versioned target) gets `{"issues":[]}` from OpenClaw's own validator. So this flag by
#      itself bypasses nothing an attacker could exploit without already having write access
#      the process would trust anyway -- it is DROPPED as a FAIL/WARN trigger entirely
#      (deleted, not special-cased further, per the standing "simplify by deleting a fragile
#      heuristic" lesson). It still shows up in evidence when paired with allowInsecurePath
#      below, since that combination is where it actually matters.
#   2. allowInsecurePath skips the permission/ownership checks on the (possibly
#      symlink-resolved) target -- but assertSecureCommandPath() enforces trustedDirs
#      containment BEFORE the `if (params.allowInsecurePath) return` early-out, so an
#      operator who also sets exec.trustedDirs has still constrained the command to a
#      directory they explicitly vouch for (this is OpenClaw's own documented remediation
#      for the Windows-ACL-unavailable case: permissions-sY2quqHz.js's "ACL verification
#      unavailable on Windows ... Set allowInsecurePath=true ... when the path is trusted").
#      allowInsecurePath WITHOUT any trustedDirs constraint is unrestrained -- it accepts
#      any path on the filesystem with zero permission/ownership verification -- and stays
#      FAIL. allowInsecurePath WITH a non-empty trustedDirs is downgraded to WARN: real
#      residual risk (trustedDirs containment doesn't itself verify the target file's own
#      permissions), but not the "anything, anywhere, unchecked" shape a FAIL should be
#      reserved for.
#
# passEnv forwards NAMED host env vars into the exec hook's child process by key; a
# secret-shaped NAME is a heuristic only (a legitimate install-policy script may need e.g.
# NPM_TOKEN to authenticate a private registry), so it stays WARN, never FAIL -- reuses the
# same SECRET_KEY_RE / secret-key-name pattern _mcp.py already applies to an MCP server's
# own `env` mapping.
#
# exec.command/args are deliberately NOT content-scanned for curl|sh pipe-to-shell shapes
# here (the task's original fix-direction suggested reusing B100/B103): the dist spawns the
# policy command directly with `shell: false` (install-policy-Barp1EUw.js runPolicyCommand),
# so args are never shell-interpreted -- a pipe/redirect substring in one argv element
# carries none of the risk it would in a shell-run string (unlike B167's
# plugins.entries.<name>.config.appServer.command reuse case, which IS shell-shaped).
# Transplanting that detector here would be an ungrounded, FP-prone reuse; skipped.
def check_install_policy_gate(ctx: Context) -> Finding:
    if not ctx.config_found:
        return _finding(
            "B174",
            UNKNOWN,
            "No openclaw.json found -- the install-policy gate (security.installPolicy) "
            "cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B174", ctx)
    if unreadable is not None:
        return unreadable

    policy = dig(ctx.config, "security.installPolicy")
    if not isinstance(policy, dict):
        policy = {}
    enabled = policy.get("enabled") is True

    if not enabled:
        return _finding(
            "B174",
            WARN,
            "security.installPolicy is not enabled (the key is absent, or "
            "enabled=false): skill/plugin installs and auto-updates run with no "
            "operator-owned install-time policy gate at all.",
            "Set security.installPolicy.enabled=true with a trusted "
            "security.installPolicy.exec command to require an install-time policy "
            "check before any skill/plugin install or update proceeds.",
        )

    exec_hook = policy.get("exec")
    if not isinstance(exec_hook, dict):
        return _finding(
            "B174",
            PASS,
            "security.installPolicy is enabled with no exec hook configured -- "
            "OpenClaw fails skill/plugin installs and updates closed until one is "
            "set, so there is no escape-hatch flag to assess.",
            "Configure security.installPolicy.exec with a trusted, absolute-path "
            "command if you want installs to actually complete under the policy gate.",
        )

    insecure_path = exec_hook.get("allowInsecurePath") is True
    symlink_command = exec_hook.get("allowSymlinkCommand") is True
    trusted_dirs = exec_hook.get("trustedDirs")
    has_trusted_dirs = isinstance(trusted_dirs, list) and any(
        isinstance(d, str) and d.strip() for d in trusted_dirs
    )

    if insecure_path:
        danger = ["exec.allowInsecurePath=true bypasses the install-policy command's "
                   "own permission/ownership verification"]
        if symlink_command:
            danger.append(
                "exec.allowSymlinkCommand=true also lets that command be a symlink, "
                "so the (unverified) resolved target is what actually runs"
            )
        if has_trusted_dirs:
            return _finding(
                "B174",
                WARN,
                "security.installPolicy.exec.allowInsecurePath=true skips the "
                "install-policy command's own permission/ownership checks, but "
                "exec.trustedDirs constrains it to an operator-declared directory: "
                + "; ".join(danger)
                + ".",
                "Confirm every directory in exec.trustedDirs is non-writable by "
                "other users and owned by a trusted account (trustedDirs "
                "containment does not itself verify the target file's own "
                "permissions); prefer removing allowInsecurePath if the platform's "
                "normal permission probe works.",
                danger,
            )
        danger.append(
            "no exec.trustedDirs is configured, so any filesystem path is "
            "accepted with zero verification"
        )
        return _finding(
            "B174",
            FAIL,
            "security.installPolicy.exec.allowInsecurePath=true bypasses the "
            "install-time policy command's own path-safety checks with no "
            "exec.trustedDirs to constrain it: "
            + "; ".join(danger)
            + ".",
            "Remove allowInsecurePath (or set it to false), or scope it with a "
            "non-empty exec.trustedDirs naming only directories you have "
            "independently verified are trusted -- this command runs on every "
            "skill/plugin install and update.",
            danger,
        )

    pass_env = exec_hook.get("passEnv")
    if isinstance(pass_env, list):
        secret_names = [
            str(k) for k in pass_env if isinstance(k, str) and SECRET_KEY_RE.search(k)
        ]
        if secret_names:
            return _finding(
                "B174",
                WARN,
                "security.installPolicy.exec.passEnv forwards secret-shaped host "
                "env var name(s) to the install-time policy command: "
                + ", ".join(secret_names[:6])
                + ".",
                "Confirm the install-policy command actually needs these; forward "
                "only what it uses, and prefer security.installPolicy.exec.env with "
                "a SecretRef indirection over passEnv for anything sensitive.",
                secret_names,
            )

    return _finding(
        "B174",
        PASS,
        "security.installPolicy is enabled with a configured exec hook and no "
        "unrestrained allowInsecurePath escape flag or secret-shaped passEnv "
        "forwarding detected (a bare allowSymlinkCommand does not itself bypass "
        "the resolved target's own permission/ownership checks).",
        "Keep the install-policy exec command's path owner-only and re-review it "
        "whenever the policy changes.",
    )


def check_known_vulns(ctx: Context) -> Finding:
    """B33 — Known-vulnerable OpenClaw version gate.

    FAIL    — installed version <= a known-advisory's max_vulnerable_version_tuple.
    PASS    — installed version is past all known advisory fixes.
    UNKNOWN — meta.lastTouchedVersion is missing or cannot be parsed.
    """
    raw_ver = dig(ctx.config, "meta.lastTouchedVersion") or dig(ctx.config, "lastTouchedVersion")
    if not raw_ver:
        return _finding(
            "B33",
            UNKNOWN,
            "OpenClaw version unknown (meta.lastTouchedVersion / lastTouchedVersion "
            "not set) — cannot check against known advisories.",
            "Set meta.lastTouchedVersion in openclaw.json (or upgrade to a current "
            "release) and keep OpenClaw current.",
        )

    parsed = _parse_version(str(raw_ver))
    if parsed is None:
        return _finding(
            "B33",
            UNKNOWN,
            f"OpenClaw version {raw_ver!r} could not be parsed — "
            "cannot check against known advisories.",
            "Verify your version string (expected dotted-integer format like '2026.1.29') "
            "and keep OpenClaw current.",
        )

    for ghsa_id, max_vuln, fixed_ver, desc in _KNOWN_ADVISORIES:
        if parsed <= max_vuln:
            return _finding(
                "B33",
                FAIL,
                f"OpenClaw {raw_ver} is affected by {ghsa_id}: {desc}. "
                f"Versions <= {'.'.join(str(x) for x in max_vuln)} are vulnerable.",
                f"Upgrade OpenClaw to >= {fixed_ver} to remediate {ghsa_id}.",
                evidence=[ghsa_id],
            )

    return _finding(
        "B33",
        PASS,
        f"OpenClaw {raw_ver} is at or past all known-advisory fixes.",
        "Keep OpenClaw updated and re-check after new advisories are published.",
    )


def check_memory_poisoning(ctx: Context) -> Finding:
    """Detect vector-memory / RAG-backed memory poisoning surface.

    Safe, schema-driven behavior:
    - PASS: vector-memory backend is configured and store access control exists
      (`auth` / `readOnly` present under memory.vectorStore).
    - UNKNOWN: vector-memory backend appears configured, but access control is not
      statically discoverable.
    - WARN / UNKNOWN fallback: legacy MEMORY.md file-only scenarios.
    """
    memory_cfg = ctx.config.get("memory")
    if not isinstance(memory_cfg, dict):
        memory_cfg = {}

    has_mem = any(name.endswith(("MEMORY.md", "memory.md")) for name in ctx.bootstrap)

    # Real schema signal: explicit vector/memory backend config.
    backend = memory_cfg.get("backend")
    backend_is_vector = isinstance(backend, str) and backend.strip().lower() not in ("", "builtin")
    has_qmd = isinstance(memory_cfg.get("qmd"), dict)
    has_vector_store = isinstance(memory_cfg.get("vectorStore"), dict)

    # Additional legacy-compatible signals (safe to check via cfg shape; no dig path).
    rag_cfg = ctx.config.get("rag")
    retrieval_cfg = ctx.config.get("retrieval")
    rag_enabled = (isinstance(rag_cfg, dict) and bool(rag_cfg.get("enabled"))) or bool(
        rag_cfg is True
    )
    has_retrieval_cfg = bool(isinstance(retrieval_cfg, dict) and retrieval_cfg)

    has_vector_surface = (
        backend_is_vector or has_qmd or has_vector_store or rag_enabled or has_retrieval_cfg
    )

    # Access control is only explicit when memory.vectorStore has auth/readOnly.
    vs = memory_cfg.get("vectorStore")
    has_vs_control = False
    if isinstance(vs, dict):
        has_vs_control = "auth" in vs or "readOnly" in vs
        if not has_vs_control:
            # Backward-compatible fallback: any nested path that is explicitly read-only.
            # (prevents missing controls when adapters place this under a nested object)
            for v in vs.values():
                if isinstance(v, dict) and ("auth" in v or "readOnly" in v):
                    has_vs_control = True
                    break

    if not has_vector_surface:
        if has_mem:
            return _finding(
                "B7",
                WARN,
                "Agent has persistent memory; confirm it is not written from untrusted input.",
                "Restrict memory writes to the owner; sanitize anything derived from external content.",
            )
        return _finding("B7", UNKNOWN, "No memory file found.", "—")

    if has_vs_control:
        return _finding(
            "B7",
            PASS,
            "Memory backend uses explicit vector-store access control.",
            "Keep vector-store access controls enabled and review ingestion isolation.",
        )
    return _finding(
        "B7",
        UNKNOWN,
        "Agent has persistent memory; confirm it is not written from untrusted input.",
        "Restrict memory writes to the owner; sanitize anything derived from external content.",
    )


def _b104_user_home(home: Path) -> "Path | None":
    """The user's home ONLY when *home* is a real ``~/.openclaw`` profile directly under it, so
    B104 adds the personal ``~/.agents/skills`` tier for a live audit but stays hermetic on
    fixture / custom --home scans (mirrors collector._read_installed_skills' gate)."""
    try:
        user_home = Path.home().resolve()
        audited = home.resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    if audited.parent == user_home and audited.name.startswith(".openclaw"):
        return user_home
    return None


def check_offboarding_hygiene(ctx: Context) -> Finding:
    """B104 — decommissioning / offboarding hygiene (F-089, NHI1 improper offboarding).

    Read-only filesystem/config reconciliation for leftover attack surface left by an
    incomplete offboarding:
      WARN — the same skill (by declared frontmatter `name:`) is installed in >1 load root.
             When the copies span DIFFERENT precedence tiers (F-122) the higher-precedence one
             silently SHADOWS the others (OpenClaw merges every root into one name-keyed map,
             last-merged wins, no warning — a planted higher-tier copy can override a trusted
             skill); same-tier copies are stale-copy hygiene. OR a configured stdio MCP
             server's ABSOLUTE command path does not exist on disk (a dead entry).
      PASS — no duplicate/shadowing skill installs and no dead MCP command paths.
      UNKNOWN — no OpenClaw home filesystem to inspect.

    §5 note: OpenClaw AUTO-LOADS skills by directory presence (recon §13), not by an
    explicit config reference, so "installed but not referenced in config" is NOT an orphan
    signal here — that sub-check is UNKNOWN-by-design and intentionally omitted so it can
    never produce a false "orphaned" finding on every legitimately auto-discovered skill.
    Symlinked skill dirs are skipped (plugin-skills symlink into a plugin's own skills/ dir,
    recon §13 — counting the link + its target would be a false duplicate). A bare MCP
    command (npx/node/uvx) is never flagged — it is PATH/runtime-resolved and
    container-safe; only an absolute path that is absent is a dead-entry signal.
    """
    # local import: avoid a module-load cycle
    from ..collector import SKILL_TIER_ORDER, skill_load_roots

    home = getattr(ctx, "home", None)
    if not isinstance(home, Path) or not home.exists():
        return _custom(
            "B104", LOW, UNKNOWN,
            "No OpenClaw home filesystem to inspect for offboarding hygiene.",
            "Run on a host with an OpenClaw home (~/.openclaw) to reconcile installed "
            "skills and MCP entries.",
        )

    # Duplicate skill installs: same declared name in >1 (non-symlink) dir. Scanned across the
    # FULL precedence-ordered load-root set (F-122) so a same-name copy planted in a
    # HIGHER-precedence tier — which silently SHADOWS a trusted skill (dist merges all roots
    # into one name-keyed map, last-merged wins, no warning) — is surfaced, not just same-tier
    # stale copies. name -> [(tier, rel_dir), ...].
    name_hits: dict[str, list[tuple[str, str]]] = {}
    for base, tier in skill_load_roots(home, ctx.config, user_home=_b104_user_home(home)):
        if not base.is_dir():
            continue
        try:
            entries = sorted(base.iterdir())
        except OSError:
            continue
        for sd in entries:
            if sd.is_symlink() or not sd.is_dir():
                continue
            skill_md = sd / "SKILL.md"
            if not skill_md.is_file():
                continue
            try:
                blob = skill_md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # A raw on-disk SKILL.md starts with `---` (the collector injects the
            # `# file: SKILL.md` header that _frontmatter_name needs, but we read raw), so
            # pull the declared name from the frontmatter block directly; fall back to the
            # dir name when there is no `name:`.
            block = _skill_frontmatter_block(blob)
            nm = re.search(r"^name:\s*([^\n#]+)", block, re.M) if block else None
            name = (nm.group(1).strip() if nm else sd.name).strip().lower()
            try:
                rel_dir = str(sd.relative_to(home))  # home-relative: no absolute path leak
            except ValueError:
                rel_dir = sd.name  # out-of-home root: bare dir name, never an absolute path
            name_hits.setdefault(name, []).append((tier, rel_dir))

    warns: list[str] = []
    for name, hits in sorted(name_hits.items()):
        uniq = sorted(set(hits))
        if len(uniq) < 2:
            continue
        tiers = {t for t, _ in uniq}
        dirs = [d for _, d in uniq]
        if len(tiers) > 1:
            # Cross-tier: the highest-precedence tier silently shadows the lower ones.
            winner = min(
                tiers,
                key=lambda t: SKILL_TIER_ORDER.index(t) if t in SKILL_TIER_ORDER else 99,
            )
            warns.append(
                f"skill '{name}' is installed in {len(uniq)} load roots spanning different "
                f"precedence tiers ({', '.join(sorted(tiers))}) — the '{winner}' copy silently "
                f"shadows the others: {', '.join(dirs)}"
            )
        else:
            warns.append(f"skill '{name}' installed in {len(uniq)} locations: " + ", ".join(dirs))

    # Dead MCP entries: a configured stdio server whose ABSOLUTE command path is missing.
    for name, spec in _mcp_servers(ctx.config or {}).items():
        if not isinstance(spec, dict):
            continue
        cmd = spec.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        expanded = os.path.expanduser(cmd.strip())
        if os.path.isabs(expanded) and not Path(expanded).exists():
            warns.append(f"MCP server '{name}' command path is missing: {cmd.strip()}")

    if warns:
        extra = f" (+{len(warns) - 6} more)" if len(warns) > 6 else ""
        return _custom(
            "B104", LOW, WARN,
            "Offboarding hygiene: " + "; ".join(warns[:6]) + extra,
            "Keep exactly one copy of each skill and remove dead MCP entries — a leftover "
            "install remains auto-loadable / spawnable attack surface after the skill or "
            "server was meant to be decommissioned (NHI1 improper offboarding). For a "
            "cross-tier collision, confirm the higher-precedence copy is the intended one: it "
            "silently shadows the rest, so a planted copy there overrides the trusted skill. "
            "If this config is audited from a different host than it runs on, verify the "
            "missing command path there before removing it.",
            warns,
        )
    return _custom(
        "B104", LOW, PASS,
        "No duplicate skill installs or dead MCP command paths found.",
        "Keep exactly one copy of each skill and remove MCP entries whose command no "
        "longer exists — leftover installs are decommissioning debt.",
    )


def check_self_modification(ctx: Context) -> Finding:
    """B22 — Self-modification risk.

    FAIL   — ALL three conditions hold:
               (a) fs_write/exec/elevated tools are enabled,
               (b) on POSIX, an identity target (SOUL.md) or skills dir is
                   group/world-writable (the agent process can rewrite its own
                   identity/skills without needing special escalation),
               (c) no approval gate is configured.
    WARN   — (a) + (b) hold but (c) — approval IS present.
    UNKNOWN — tools absent (condition a false), or not POSIX, or no writable
              identity files found.
    """
    cfg = ctx.config
    tools = _enabled_tools(cfg)

    # Condition (a): fs_write / exec / elevated tooling present
    has_dangerous_tools = (
        _hint(tools, OUTBOUND_TOOL_HINTS)  # includes fs_write, exec, shell, deploy …
        or bool(dig(cfg, "tools.elevated.allowFrom"))
    )
    if not has_dangerous_tools:
        return _finding(
            "B22",
            UNKNOWN,
            "No fs_write/exec/elevated tools detected — self-modification risk not applicable.",
            "—",
        )

    if not _shared._is_posix():
        return _finding(
            "B22",
            UNKNOWN,
            "On Windows, file security uses NTFS ACLs, not POSIX mode bits — ClawSecCheck "
            "can't read those read-only (no extra tools), so this is UNKNOWN, never a false PASS.",
            "Check the ACLs yourself: `icacls <path>` should not grant write to Users / Everyone.",
        )

    # Condition (b): writable identity or skills target
    writable = _writable_identity_files(ctx)
    if not writable:
        return _finding(
            "B22",
            UNKNOWN,
            "Dangerous tools present but no writable identity/skill targets found — "
            "self-modification risk could not be confirmed.",
            "Verify workspace SOUL.md and skills dirs are chmod 700/600.",
        )

    # Condition (c): approval gate (real OpenClaw field: tools.exec.mode/security/ask)
    has_approval = _has_approval_gate(cfg)

    joined = "; ".join(writable[:6])
    extra = f" (+{len(writable) - 6} more)" if len(writable) > 6 else ""

    if has_approval:
        return _finding(
            "B22",
            WARN,
            f"Agent has fs_write/exec tools AND writable identity/skill targets "
            f"({joined}{extra}), but an approval gate is configured — risk is reduced "
            f"but not eliminated if approval can be bypassed.",
            "Keep approval gating enabled; also tighten identity/skill file permissions "
            "to owner-only (chmod 700 workspace/, chmod 600 workspace/SOUL.md, "
            "chmod 700 skills/).",
            evidence=writable,
        )

    return _finding(
        "B22",
        FAIL,
        f"Agent can rewrite its own identity/skills WITHOUT approval: "
        f"fs_write/exec tools are enabled AND the following targets are "
        f"group/world-writable: {joined}{extra}",
        "Remove write access from group/other on identity and skill files "
        "(chmod 700 workspace/, chmod 600 workspace/SOUL.md, chmod 700 skills/). "
        "Also set tools.exec.mode to 'ask'/'allowlist' so any write action needs explicit sign-off.",
        evidence=writable,
    )


def check_session_approval_policy(ctx: Context) -> Finding:
    import json as _json

    no_sessions = _finding(
        "B79",
        UNKNOWN,
        "no Codex session logs found — cannot determine approval policy.",
        "Run sensitive sessions with a human approval gate (approval_policy other than "
        '"never"), or confirm this agent is intended to run fully autonomous.',
    )
    # Evaluate EACH agent independently (N=5 most-recent files per agent).
    # Worst-case posture wins: a single fully-auto-approving agent triggers WARN
    # regardless of how safe other agents are — safe agents cannot dilute a dangerous one.
    agents_root = ctx.home / "agents"
    agent_dirs: list[Path] = []
    if agents_root.is_dir():
        agent_dirs = sorted(p for p in agents_root.iterdir() if p.is_dir() and not p.is_symlink())

    any_sessions = False  # at least one .jsonl file found anywhere
    any_turns = False  # at least one turn_context event parsed

    # Worst-agent tracking (the most dangerous individual agent posture).
    worst_agent: str | None = None
    worst_total = 0
    worst_never = 0
    worst_files = 0

    # Grand totals used only for the PASS finding message.
    grand_total = 0
    grand_never = 0

    for agent_dir in agent_dirs:
        sessions_dir = agent_dir / "agent" / "codex-home" / "sessions"
        if not sessions_dir.is_dir():
            continue
        agent_files = [p for p in walk_dir_safely(sessions_dir) if p.name.endswith(".jsonl")]
        if not agent_files:
            continue
        any_sessions = True
        # B-109: pick the genuinely most-recent sessions by mtime, not by filename
        # (session filenames are not guaranteed lexicographically time-monotonic).
        recent = sorted(agent_files, key=_safe_mtime)[-5:]

        a_total = 0
        a_never = 0
        for fp in recent:
            try:
                raw, _ = _read_jsonl_tail(fp)
            except OSError:
                continue
            for ln in raw.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rec = _json.loads(ln)
                except ValueError:
                    continue
                if not isinstance(rec, dict) or rec.get("type") != "turn_context":
                    continue
                payload = rec.get("payload")
                if not isinstance(payload, dict):
                    continue
                a_total += 1
                any_turns = True
                if payload.get("approval_policy") == "never":
                    a_never += 1

        grand_total += a_total
        grand_never += a_never

        # Record this agent if it is fully auto-approving (all recent turns = never).
        # Keep the agent with the highest never count as the representative worst case.
        if a_total > 0 and a_never == a_total:
            if worst_agent is None or a_never > worst_never:
                worst_agent = agent_dir.name
                worst_total = a_total
                worst_never = a_never
                worst_files = len(recent)

    if not any_sessions:
        return no_sessions

    if not any_turns:
        return _finding(
            "B79",
            UNKNOWN,
            "Codex session logs found but no turn_context events recorded — cannot "
            "determine approval policy.",
            "Confirm whether recent sessions ran with a human approval gate.",
        )

    if worst_agent is not None:
        return _finding(
            "B79",
            WARN,
            f"all {worst_total} recent Codex turn(s) sampled (across {worst_files} session "
            f'file(s)) for agent "{worst_agent}" ran with approval_policy="never" — '
            "human approval was never required.",
            "If this agent performs sensitive or destructive actions, run at least some "
            'sessions with a human approval gate (approval_policy other than "never"). '
            "Fully unattended approval=never removes the human checkpoint before tool execution.",
            evidence=[
                f"agent: {worst_agent}",
                f"turns sampled: {worst_total}",
                f"approval_policy=never: {worst_never}",
                f"session files sampled: {worst_files}",
            ],
        )
    return _finding(
        "B79",
        PASS,
        f"recent Codex sessions include human-approval gates "
        f"({grand_never}/{grand_total} sampled turns were approval=never).",
        "Keep requiring human approval for sensitive actions; avoid defaulting all sessions "
        'to approval_policy="never".',
    )


# ---------- B136: Codex CLI project trust_level="trusted" (codex-home/config.toml) ----------
# Real shape (docs/research/openclaw-schema-recon.md §14.6, live install):
#   [projects."<absolute-workspace-path>"]
#   trust_level = "trusted"
# trust_level="trusted" disables Codex's own approval/sandbox gating for everything run
# under that project path. Same on-disk neighborhood as B79's codex-home/sessions read
# (agents/<id>/agent/codex-home/), different sub-path (config.toml, not sessions/).
#
# No TOML library is used anywhere else in this codebase (stdlib-only, no third-party
# TOML dep) and we only need to detect ONE specific shape, not parse general TOML — a
# narrow line-scan is sufficient and deliberately conservative (no false PASS on a
# section we can't confidently rule out).
_TOML_PROJECT_SECTION_RE = re.compile(r'^\[projects\.(?P<path>"(?:[^"\\]|\\.)*")\]\s*$')
_TOML_TRUST_LEVEL_TRUSTED_RE = re.compile(r'^trust_level\s*=\s*"trusted"\s*$')


def _codex_trusted_projects(text: str) -> list[str]:
    """Scan codex-home config.toml text for [projects."..."] sections with trust_level="trusted".

    Returns the list of project paths (quotes stripped) found trusted. A narrow,
    line-oriented scan — not a general TOML parser — since we only need to detect this
    one specific key/section shape.
    """
    trusted: list[str] = []
    current_project: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Any other top-level section (e.g. "[projects]" alone, or an unrelated table)
        # ends the current [projects."..."] context.
        m = _TOML_PROJECT_SECTION_RE.match(line)
        if m:
            current_project = m.group("path").strip('"')
            continue
        if line.startswith("[") and line.endswith("]"):
            current_project = None
            continue
        if current_project is not None and _TOML_TRUST_LEVEL_TRUSTED_RE.match(line):
            trusted.append(current_project)
            current_project = None  # one trust_level line per section is all we track
    return trusted


def check_codex_project_trust(ctx: Context) -> Finding:
    """B136 — Codex CLI project trust_level="trusted" (codex-home/config.toml).

    PASS    — codex-home/config.toml exists but no [projects."..."] section sets
              trust_level="trusted".
    WARN    — at least one project path has trust_level="trusted", which disables
              Codex's own approval/sandbox gating for everything run under that path.
    UNKNOWN — no agents/<id>/agent/codex-home/config.toml found anywhere (Codex CLI
              is not in use).
    """
    agents_root = ctx.home / "agents"
    agent_dirs: list[Path] = []
    if agents_root.is_dir():
        agent_dirs = sorted(p for p in agents_root.iterdir() if p.is_dir() and not p.is_symlink())

    any_config = False
    trusted_ev: list[str] = []

    for agent_dir in agent_dirs:
        config_path = agent_dir / "agent" / "codex-home" / "config.toml"
        if not config_path.is_file():
            continue
        any_config = True
        try:
            text = config_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for project_path in _codex_trusted_projects(text):
            trusted_ev.append(f"agent {agent_dir.name}: project {project_path!r}")

    if not any_config:
        return _finding(
            "B136",
            UNKNOWN,
            "no codex-home/config.toml found — Codex CLI does not appear to be in use.",
            "No action needed unless Codex CLI is adopted later.",
        )

    if trusted_ev:
        detail = "; ".join(trusted_ev[:6]) + (
            f" (+{len(trusted_ev) - 6} more)" if len(trusted_ev) > 6 else ""
        )
        return _finding(
            "B136",
            WARN,
            f"Codex CLI project trust is set to \"trusted\" for: {detail} — this disables "
            "Codex's own approval/sandbox gating for everything run under that project path.",
            "Only mark a project trusted if you fully trust everything that can run there; "
            'prefer the default (non-"trusted") level so Codex keeps its own approval/'
            "sandbox gate active.",
            evidence=trusted_ev[:6],
        )

    return _finding(
        "B136",
        PASS,
        "codex-home/config.toml found; no project has trust_level=\"trusted\".",
        "Keep project trust unset/default so Codex's own approval/sandbox gating stays active.",
    )


# ---------- B138: dangling high-scope pending device pairing (devices/pending.json) ----------
# Real shape (docs/research/openclaw-schema-recon.md §14.4): a dict keyed by request UUID;
# each entry: requestId, deviceId, publicKey, platform, clientId, clientMode, role, roles,
# scopes, silent, isRepair, ts. A request with isRepair=true and a high-privilege scope
# (operator.admin / operator.write) is awaiting human approval — if approved, it grants
# admin/write control-plane access.
_HIGH_SCOPE_NAMES = frozenset({"operator.admin", "operator.write"})


def check_pending_device_pairing_scope(ctx: Context) -> Finding:
    """B138 — dangling high-scope pending device pairing (devices/pending.json).

    PASS    — devices/pending.json is absent (no pending pairings at all — the common,
              expected case), OR present with no high-scope pending entries.
    WARN    — a pending entry requests a high-privilege scope (operator.admin /
              operator.write), especially combined with isRepair=true — this is a
              pending pairing awaiting human approval, not proof of compromise.
    UNKNOWN — devices/pending.json exists but is unreadable or not valid JSON.
    """
    import json as _json

    pending_path = ctx.home / "devices" / "pending.json"
    if not pending_path.is_file():
        return _finding(
            "B138",
            PASS,
            "no devices/pending.json found — no pending device pairing requests.",
            "No action needed.",
        )

    try:
        data = _json.loads(pending_path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return _finding(
            "B138",
            UNKNOWN,
            "devices/pending.json present but unreadable — cannot evaluate pending "
            "device pairing requests.",
            "Ensure devices/pending.json is owner-readable, or review it manually.",
        )
    except ValueError:
        return _finding(
            "B138",
            UNKNOWN,
            "devices/pending.json present but not valid JSON — cannot evaluate pending "
            "device pairing requests.",
            "Review devices/pending.json manually for pending pairing requests.",
        )

    if not isinstance(data, dict):
        return _finding(
            "B138",
            UNKNOWN,
            "devices/pending.json present but not in the expected format — cannot "
            "evaluate pending device pairing requests.",
            "Review devices/pending.json manually for pending pairing requests.",
        )

    high_scope_ev: list[str] = []
    for entry in data.values():
        if not isinstance(entry, dict):
            continue
        scopes = entry.get("scopes")
        if not isinstance(scopes, (list, tuple)):
            continue
        if not any(s in _HIGH_SCOPE_NAMES for s in scopes if isinstance(s, str)):
            continue
        device_id = entry.get("deviceId", "unknown")
        platform = entry.get("platform", "unknown")
        is_repair = bool(entry.get("isRepair", False))
        high_scope_ev.append(
            f"deviceId={device_id} platform={platform} isRepair={is_repair}"
        )

    if not data:
        return _finding(
            "B138",
            PASS,
            "devices/pending.json found but empty — no pending device pairing requests.",
            "No action needed.",
        )

    if high_scope_ev:
        detail = "; ".join(high_scope_ev[:6]) + (
            f" (+{len(high_scope_ev) - 6} more)" if len(high_scope_ev) > 6 else ""
        )
        return _finding(
            "B138",
            WARN,
            f"pending device pairing request(s) awaiting your approval request a "
            f"high-privilege scope (operator.admin/operator.write): {detail}.",
            "Review each pending pairing request before approving it. Only approve "
            "admin/write scope for a device you recognize and expect; reject/ignore "
            "unrecognized requests.",
            evidence=high_scope_ev[:6],
        )

    return _finding(
        "B138",
        PASS,
        f"{len(data)} pending device pairing request(s) found; none request a "
        "high-privilege scope (operator.admin/operator.write).",
        "Continue reviewing pending pairing requests before approving them.",
    )


# ---------- B135: accepted-despite-failed-verification skill install (.clawhub/lock.json) ----------
# Real shape (docs/research/openclaw-schema-recon.md §14.5): {"version": ..., "skills":
# {<slug>: {"version", "installedAt", "registry", "artifact", "skillFile", "verification":
# {"schema", "ok": bool, "decision": "pass"|"fail", "reasons": [...], "card": {...},
# "signature": {"status": ...}}}}}. verification.ok == False or decision == "fail" means
# the registry's OWN check rejected the skill, yet it is installed and present in this lock
# file — that explicit rejection is the trigger. Deliberately NOT triggered by signature
# ("unsigned"), provenance ("unavailable"), or a suspicious staticScan/skillSpector
# sub-signal alone: a live fleet install showed those exact sub-signals flagged while the
# registry's own aggregate decision was "pass" (a disclosed security-audit tool tripping its
# own detection regexes — see reference note on scanner FP against detection signatures) —
# flagging on the sub-signals would reproduce that false positive.
def check_clawhub_lock_verification(ctx: Context) -> Finding:
    """B135 — accepted-despite-failed-verification skill install (.clawhub/lock.json).

    PASS    — no .clawhub/lock.json found in any workspace, OR every locked skill's
              verification.ok is true and decision is not "fail".
    WARN    — at least one locked skill has verification.ok == False or
              decision == "fail" — the registry's own check rejected it, yet it is
              installed and present in the lock file.
    UNKNOWN — a .clawhub/lock.json was found but is unreadable or not valid JSON.
    """
    import json as _json

    from ..collector import WORKSPACE_DIRS

    lock_paths: list[Path] = []
    seen: set = set()
    for rel in [""] + list(WORKSPACE_DIRS):
        p = ctx.home / rel / ".clawhub" / "lock.json"
        if not p.is_file():
            continue
        try:
            real = p.resolve()
        except OSError:
            real = p
        if real in seen:
            continue
        seen.add(real)
        lock_paths.append(p)

    if not lock_paths:
        return _finding(
            "B135",
            PASS,
            "no .clawhub/lock.json found in any workspace — no ClawHub-installed skills "
            "to evaluate.",
            "No action needed.",
        )

    rejected_ev: list[str] = []
    any_parsed = False
    any_unreadable = False

    for lock_path in lock_paths:
        try:
            data = _json.loads(lock_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            any_unreadable = True
            continue
        if not isinstance(data, dict):
            any_unreadable = True
            continue
        skills = data.get("skills")
        if not isinstance(skills, dict):
            continue
        any_parsed = True
        for slug, entry in skills.items():
            if not isinstance(entry, dict):
                continue
            verification = entry.get("verification")
            if not isinstance(verification, dict):
                continue
            ok = verification.get("ok")
            decision = verification.get("decision")
            if ok is False or decision == "fail":
                reasons = verification.get("reasons")
                reasons_str = (
                    ", ".join(str(r) for r in reasons)
                    if isinstance(reasons, list) and reasons
                    else "none listed"
                )
                signature = verification.get("signature")
                sig_status = (
                    signature.get("status")
                    if isinstance(signature, dict)
                    else "unknown"
                )
                version = entry.get("version", "unknown")
                rejected_ev.append(
                    f"{slug}@{version}: decision={decision!r} ok={ok!r} "
                    f"reasons=[{reasons_str}] signature={sig_status}"
                )

    if rejected_ev:
        detail = "; ".join(rejected_ev[:6]) + (
            f" (+{len(rejected_ev) - 6} more)" if len(rejected_ev) > 6 else ""
        )
        return _finding(
            "B135",
            WARN,
            f"skill(s) installed despite failed ClawHub verification: {detail}.",
            "Review the flagged skill(s) manually — ClawHub's own verification rejected "
            "them but they are installed and running; uninstall or re-verify their "
            "provenance before trusting them.",
            evidence=rejected_ev[:6],
        )

    if not any_parsed and any_unreadable:
        return _finding(
            "B135",
            UNKNOWN,
            ".clawhub/lock.json found but unreadable or not valid JSON — cannot evaluate "
            "ClawHub skill-verification state.",
            "Review .clawhub/lock.json manually.",
        )

    return _finding(
        "B135",
        PASS,
        "all ClawHub-installed skills passed registry verification (or no lock file "
        "was found).",
        "No action needed.",
    )


def check_declared_skill_reconciliation(ctx: Context) -> Finding:
    """B158 (F-119) — a config declares a skill/plugin LOAD SOURCE that resolves to nothing on
    disk right now. The audit can only scan what is present, so a declared-but-absent source is
    an unaudited gap: if it later materializes (auto-update, install) it enters the auto-load
    surface the audit reported clean on. Advisory, WARN-only — declared-but-absent is legitimate
    on a fresh host, never a FAIL. Grounded declared sources (verified against the installed
    dist): skills.load.extraDirs, plugins.load.paths, and .clawhub/lock.json -> skills.<slug>.
    skillFile. (skills.entries/plugins.entries are apiKey/config OVERLAYS keyed by an already-
    installed id — they carry no source/url and are deliberately NOT reconciled here.)
    """
    import json as _json

    from ..collector import WORKSPACE_DIRS
    from ..skilldiscovery import config_extra_skill_dirs, config_plugin_load_paths

    if not ctx.config_found:
        return _finding(
            "B158",
            UNKNOWN,
            "No openclaw.json found — declared skill-load sources can't be reconciled "
            "against disk.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    # B-228: openclaw.json is present but unparseable/unreadable — same "can't reconcile
    # declared sources against disk" reasoning as the not-found branch above, since
    # skills.load.extraDirs / plugins.load.paths can't be read from a config that never
    # parsed (a broken config isn't distinguishable from "declares nothing").
    unreadable = _config_unreadable("B158", ctx)
    if unreadable is not None:
        return unreadable

    missing: list[str] = []
    for label, dirs in (
        ("skills.load.extraDirs", config_extra_skill_dirs(ctx.home, ctx.config)),
        ("plugins.load.paths", config_plugin_load_paths(ctx.home, ctx.config)),
    ):
        for d in dirs:
            try:
                present = d.is_dir()
            except OSError:
                present = False
            if not present:
                missing.append(f"{label}: '{d}' declared but not present on disk")

    seen: set = set()
    for rel in [""] + list(WORKSPACE_DIRS):
        lock = ctx.home / rel / ".clawhub" / "lock.json"
        if not lock.is_file():
            continue
        try:
            data = _json.loads(lock.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        skills = data.get("skills") if isinstance(data, dict) else None
        if not isinstance(skills, dict):
            continue
        for slug, rec in skills.items():
            if not isinstance(rec, dict):
                continue
            sf = rec.get("skillFile")
            if not isinstance(sf, str) or not sf.strip() or "\x00" in sf:
                continue
            p = Path(sf) if Path(sf).is_absolute() else (ctx.home / sf)
            try:
                gone = not p.parent.is_dir()
            except OSError:
                gone = True
            if gone and str(p) not in seen:
                seen.add(str(p))
                missing.append(
                    f".clawhub/lock.json: skill '{slug}' skillFile dir gone ({p.parent})"
                )

    if not missing:
        return _finding(
            "B158",
            PASS,
            "Every declared skill/plugin load source resolves to a present directory on disk.",
            "Keep declared load sources (skills.load.extraDirs, plugins.load.paths, ClawHub "
            "lock entries) in sync with what is actually installed.",
        )

    extra = f" (+{len(missing) - 6} more)" if len(missing) > 6 else ""
    return _finding(
        "B158",
        WARN,
        "Declared skill-load source(s) not present on disk — unaudited; if one materializes it "
        "enters the auto-load surface unscanned: " + "; ".join(missing[:6]) + extra,
        "Remove the stale declaration, or install the skill/plugin so ClawSecCheck can scan it "
        "before it auto-loads.",
        evidence=missing,
    )


def check_supply_chain(ctx: Context) -> Finding:
    cfg = ctx.config
    # plugins.installs_unpinned_npm_specs / plugins.installs_missing_integrity do NOT exist
    # in the OpenClaw schema — install metadata is per-manifest, not stored in config.
    # Pinning is checked by B25; MCP npx specs by B24.
    # plugins.tools_reachable_policy also does NOT exist in the OpenClaw schema.
    if not (cfg.get("plugins") or cfg.get("skills")):
        return _finding("B5", UNKNOWN, "No plugins/skills declared in config.", "—")
    # Pinning & integrity are not recorded in openclaw.json (per-manifest metadata), so B5
    # cannot assess supply-chain integrity from config alone — be honest (UNKNOWN) rather than
    # falsely reassure. Real coverage: B13 (content scan), B24 (MCP), B25 (update pinning).
    return _finding(
        "B5",
        UNKNOWN,
        "Plugins/skills are installed, but pinning/integrity is not in openclaw.json — "
        "cannot assess supply-chain integrity from config alone.",
        "Vet installed skills with --vet; see B13 (malware scan), B24 (MCP pinning), "
        "B25 (update pinning).",
    )


def check_update_pinning(ctx: Context) -> Finding:
    """B25 — Update / pinning hygiene.

    A malicious skill UPDATE is a supply-chain risk (runs with agent permissions).

    WARN  — auto-update for skills/plugins is enabled (blind trust in upstream);
            OR a plugin/skill entry records a floating ref (branch name / 'latest').
    PASS  — at least one entry is present and all have a pinned tag/commit or an
            integrity hash; no auto-update enabled.
    UNKNOWN — no plugin/skill config from which pinning can be determined.
    """
    cfg = ctx.config

    warn_ev: list[str] = []

    # ---- signal 1: auto-update enabled ----
    # Supported key shapes (conservative — only flag when clearly true):
    #   update.auto.enabled / update.auto / autoUpdate / auto_update
    auto_update = (
        dig(cfg, "update.auto.enabled")
        or dig(cfg, "update.auto")
        or cfg.get("autoUpdate")
        or cfg.get("auto_update")
    )
    # Only flag when the value is explicitly truthy (not just "present").
    if auto_update is True or (
        isinstance(auto_update, str) and auto_update.lower() in ("true", "yes", "1", "on")
    ):
        warn_ev.append(
            "auto-update for skills/plugins is enabled — blind trust in upstream is a supply-chain risk"
        )

    # ---- signal 2: per-entry pinning ----
    pinned_count = 0
    floating_count = 0
    total_with_source = 0

    for ns, name, entry in _iter_entries(cfg):
        # An integrity hash is the strongest signal — always counts as pinned.
        if entry.get("integrity") or entry.get("checksum") or entry.get("sha256"):
            pinned_count += 1
            total_with_source += 1
            continue

        source = entry.get("source") or entry.get("url") or entry.get("repo")
        version = (
            entry.get("version") or entry.get("ref") or entry.get("tag") or entry.get("commit")
        )

        if version is None and source is None:
            # Entry exists but carries no source/version info — skip (cannot determine).
            continue

        total_with_source += 1

        if version is not None:
            v = str(version).strip()
            if _FLOATING_REF_RE.match(v):
                floating_count += 1
                warn_ev.append(
                    f"{ns}.entries.{name}: version/ref {v!r} is a floating ref "
                    "(branch/latest) — not pinned"
                )
            elif _PINNED_REF_RE.match(v):
                pinned_count += 1
            else:
                # Non-empty but unrecognised format — cannot determine; don't flag.
                pass
        elif source is not None:
            # source present but no version — check if the source URL itself embeds
            # a branch name (e.g. github.com/owner/repo/tree/main).
            src_str = str(source).lower()
            if re.search(
                r"/(?:tree|archive|tarball|zipball)/(?:main|master|HEAD|dev|develop|latest)[/.]?",
                src_str,
            ):
                floating_count += 1
                warn_ev.append(
                    f"{ns}.entries.{name}: source URL references a floating branch — not pinned"
                )
            # No version and no floating branch in URL — cannot determine pinning.

    # ---- verdict ----
    if not warn_ev and total_with_source == 0 and not auto_update:
        return _finding(
            "B25",
            UNKNOWN,
            "No plugin/skill source or version info found — pinning hygiene cannot be determined.",
            "Record a pinned version/tag or integrity hash for every installed skill and plugin.",
        )

    if warn_ev:
        detail = "; ".join(warn_ev[:6]) + (
            f" (+{len(warn_ev) - 6} more)" if len(warn_ev) > 6 else ""
        )
        return _finding(
            "B25",
            WARN,
            detail,
            "Pin every skill/plugin to a specific tag or commit SHA and record an "
            "integrity hash (sha256/checksum). Disable auto-update for skills "
            "(update.auto.enabled = false) and review updates manually before applying.",
            evidence=warn_ev[:6],
        )

    if pinned_count > 0:
        return _finding(
            "B25",
            PASS,
            f"{pinned_count} plugin/skill entry(s) are pinned to a specific version/tag or "
            "integrity hash; no auto-update detected.",
            "Keep all entries pinned and review updates manually.",
        )

    # total_with_source > 0 but nothing was floating and nothing was pinned
    # (unrecognised version strings) — be conservative.
    return _finding(
        "B25",
        UNKNOWN,
        "Plugin/skill entries present but version format could not be classified as pinned or floating.",
        "Use a semver tag (e.g. v1.2.3), a git commit SHA, or an integrity hash for every entry.",
    )


# ---------- C4: version / update hygiene (advisory) ----------
def check_version(ctx: Context) -> Finding:
    ver = dig(ctx.config, "meta.lastTouchedVersion") or dig(ctx.config, "lastTouchedVersion")
    if not ver:
        return _custom(
            "C4", BY_ID["C4"].severity, UNKNOWN, "OpenClaw version not recorded in config.", "—"
        )
    # Advisory only — do NOT claim a vulnerability here. The grounded known-vulnerable
    # version gate is B33 (check_known_vulns), which compares against real advisories.
    # C4 stays a neutral update-hygiene reminder; it must not name a CVE it can't ground
    # or imply a current/patched version is outdated (it has no offline "latest" to judge).
    return _custom(
        "C4",
        BY_ID["C4"].severity,
        PASS,
        f"OpenClaw config last touched by version {ver}. Known-vulnerable releases "
        "are gated by B33; this is an update-hygiene reminder, not a vulnerability claim.",
        "Keep OpenClaw updated and re-run the checks after upgrading.",
    )
