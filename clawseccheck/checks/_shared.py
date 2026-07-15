"""Shared leaf for the checks/ package (I-022 R2).

Helpers, regexes and constants reused across two or more topic modules (or by
sibling modules via the clawseccheck.checks aggregator). Depends only on the
layer-1 modules (catalog/collector/...) and stdlib — never on a topic module.
Moved verbatim from the former single-file checks.py; no logic changes.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from urllib.parse import urlparse
from ..catalog import (
    BY_ID,
    Finding,
)
from ..collector import (
    _OWN_SKILL_NAMES,
    Context,
    dig,
)


def _is_posix() -> bool:
    return os.name == "posix"


def _perms_loose(ctx: Context) -> bool:
    """True only on POSIX when the config file is group/world-readable.

    Windows uses NTFS ACLs, not POSIX mode bits, so st_mode is not meaningful
    there — we never raise a false 'world-readable' finding on Windows.
    """
    if not _is_posix() or ctx.config_mode is None:
        return False
    return (ctx.config_mode & 0o077) != 0


def _group_has_other_members(gid: int, owner_uid: int) -> "bool | None":
    """Does *gid* currently have any member other than the uid that owns the file?

    Read-only, stdlib-only (``grp``/``pwd``), never shells out, never touches the
    network. A file's owning group can gain a member two ways: an explicit
    ``gr_mem`` entry in ``/etc/group``, or another user whose PRIMARY group
    (``pw_gid`` in ``/etc/passwd``) is *gid* — both are checked.

    Returns:
        True  — at least one other user is a member (explicit or primary-group).
        False — the group has no members besides the file's owner (a "singleton"
                group) — group-write is not actually exploitable by anyone else.
        None  — membership could not be determined (non-POSIX, ``grp``/``pwd``
                unavailable, or the gid/uid is unresolvable). Callers must treat
                this as "unknown" and NOT downgrade a finding on this basis.
    """
    if not _is_posix():
        return None
    try:
        import grp
        import pwd
    except ImportError:
        return None
    try:
        group = grp.getgrgid(gid)
    except (KeyError, OverflowError, ValueError):
        return None
    owner_name = None
    try:
        owner_name = pwd.getpwuid(owner_uid).pw_name
    except (KeyError, OverflowError, ValueError):
        pass
    for member in group.gr_mem:
        if member != owner_name:
            return True
    try:
        for entry in pwd.getpwall():
            if entry.pw_gid == gid and entry.pw_uid != owner_uid:
                return True
    except OSError:
        return None
    return False


LOOPBACK = {"127.0.0.1", "localhost", "::1", "", "loopback", "local"}


EXPOSED_BINDS = {"0.0.0.0", "::", "all", "public", "*"}


def parse_bind_host(value) -> str:
    """Extract the host portion from a gateway.bind value, handling IPv6 correctly.

    Zone IDs (e.g. ``%eth0``) are stripped from IPv6 addresses so that the
    loopback/wildcard classification works regardless of whether the caller
    appended a scope suffix.

    Examples::
        "127.0.0.1:8080"   -> "127.0.0.1"
        "[::1]:8765"        -> "::1"
        "[::1%eth0]:8765"   -> "::1"
        "::1%eth0"          -> "::1"
        "::"                -> "::"
        "[::]"              -> "::"
        "0.0.0.0"           -> "0.0.0.0"
        ""                  -> ""
    """
    s = str(value or "").strip().lower()
    if not s:
        return ""
    # Bracketed IPv6 with optional port: [::1]:port or [::]
    # Zone ID may appear inside the brackets: [::1%eth0]:port
    if s.startswith("["):
        end = s.find("]")
        if end != -1:
            host = s[1:end]  # e.g. "::1" or "::" or "::1%eth0"
            # Strip zone ID from bracketed form.
            if "%" in host:
                host = host.split("%", 1)[0]
            return host
    # Bare wildcard / known special values without colons
    if s in {"::", "0.0.0.0", "*"}:
        return s
    # host:port (IPv4 or hostname) — exactly one colon
    if s.count(":") == 1:
        return s.split(":", 1)[0]
    # Bare IPv6 address with multiple colons (no brackets, no port).
    # May carry a zone ID suffix: ::1%eth0
    if ":" in s:
        host = s
        if "%" in host:
            host = host.split("%", 1)[0]
        return host
    return s


SECRET_KEY_RE = re.compile(r"(password|secret|token|api[_-]?key|apikey|bottoken)", re.I)


SECRET_PATTERNS = [
    re.compile(r"sk-ant-[a-z0-9-]{8,}", re.I),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"(?:password|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}", re.I),
]


# Credential/secret access is only malicious when EXFILTRATED.
# Same-line rule: a line that touches a secret path AND ships it out (avoids flagging a
# skill that merely loads its own config).
# Extended set covers npm/pypi token files, netrc, Docker/k8s/gcloud creds, browser
# cookies, and crypto wallet paths (Electrum / Exodus).
# B-144: the browser-name co-occurrence for the Cookies alternative is now MANDATORY
# (was optional) — a bare "Cookies" mention matches any ordinary discussion of HTTP
# session cookies (a networking/privacy tool's documentation is full of these), not just
# the intended signal (a browser's on-disk Cookies credential-store FILE, e.g.
# `~/Library/Application Support/Google/Chrome/Default/Cookies`). Confirmed empirically
# against a real skill (clawstealth, a privacy/networking tool) whose extensive HTTP-
# cookie discussion — with no browser name anywhere nearby — fed a false cross-skill
# cred+exfil co-occurrence finding once its full text became scannable (B-144 follow-up).
#
# F-124/E-044 layer-fix: moved here VERBATIM from checks/_content.py so logscan.py (a
# Layer-1 leaf) can reuse it without importing a Layer-2 topic module — _content.py now
# imports it back from here like every other cross-topic name.
_CRED_RE = re.compile(
    r"find-generic-password|login\.keychain|\.ssh/id_[a-z0-9]+|\.aws/credentials|"
    r"wallet\.dat|keystore\.json|MetaMask|"
    r"\.npmrc|\.pypirc|\.netrc|\.docker/config\.json|"
    r"\.kube/config|\.config/gcloud|"
    r"\bCookies\b[^\n]{0,60}(?:Chrome|Firefox|Safari|Brave|Edge)|"
    r"(?:Chrome|Firefox|Safari|Brave|Edge)[^\n]{0,60}\bCookies\b|"
    r"Electrum[^\n]{0,40}wallets?|Exodus[^\n]{0,40}wallets?|"
    # C-198: real default on-disk crypto-wallet stores — Geth/go-ethereum's keystore dir
    # and the Solana CLI's default keypair path (both well-known, documented paths, not
    # fabricated — grounded the same way as the .aws/.kube/.config/gcloud entries above).
    r"\.ethereum/keystore|\.config/solana(?:/id\.json)?",
    re.I,
)


# Exfil transports — same set used for both same-line and cross-skill detection.
# B-144: discord.com/api/webhooks and api.telegram.org/bot are DUAL-USE notification
# hosts (see B-122's _SKILL_NOTIFY_HOST_RE in _vet.py) — a skill's own self-notification
# bot is their single most common legitimate use. R1/B-122 already built a dedicated,
# taint-aware discriminator for exactly these two hosts (CRITICAL only when an unrelated
# secret or local file-read reaches the same request; a bare mention is WARN) and folded
# it into check_installed_skills as its own finding. But _EXFIL_RE is a SHARED pattern
# also consumed by the same-line rule (_has_cred_exfil_outside_fence) and the cross-skill
# co-occurrence rule (_has_cross, below) — R1 never touched those two, so a skill that
# merely mentions a credential-shaped path AND its own notify host ANYWHERE (zero taint/
# proximity requirement for the cross-skill case) still FAILs via this second path. Since
# the dedicated B-122 discriminator already covers the genuinely-tainted case, these two
# ambiguous hosts are dropped from the shared unambiguous-exfil-sink list rather than
# duplicating taint logic in every consumer.
#
# F-124/E-044 layer-fix: moved here VERBATIM from checks/_content.py (see _CRED_RE note
# above for why).
_EXFIL_RE = re.compile(
    r"\bcurl\b|\bwget\b|\bnc\b|netcat|requests?\.post|fetch\(|\bPOST\b|\bscp\b|base64|"
    r"glot\.io|webhook\.site|transfer\.sh|pastebin|"
    r"rentry\.co|rentry\.org|"
    r"beeceptor\.com|interactsh\.com|oast\.|canarytokens\.|file\.io|"
    r"localtunnel\.me|trycloudflare\.com|"
    r"ngrok(?:-free)?\.(?:io|app)|pipedream\.net",
    re.I,
)


# C-211: the HOST-only leg of the B13 "paste / exfiltration host" crit signal, moved here
# (verbatim) so it can be reused outside skill-content scanning too — B166 (checks/_mcp.py)
# matches it against an MCP server's own command/args, a different data source than B13's
# skill-content blob. Deliberately narrower than _EXFIL_RE above: no generic curl/wget/
# base64 keywords, only known drop-point HOSTNAMES, since an MCP server's argv commonly
# contains a real `curl`/generic verb without that being any kind of signal.
_KNOWN_EXFIL_HOST_RE = re.compile(
    r"\b(glot\.io|pastebin\.com|hastebin|transfer\.sh|0x0\.st|webhook\.site|requestbin|"
    r"rentry\.co|rentry\.org|"
    r"beeceptor\.com|interactsh\.com|oast\.(?:pro|fun|me|live|site|online)|"
    r"canarytokens\.(?:com|net|org)|file\.io|localtunnel\.me|trycloudflare\.com|"
    r"[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app)|ngrok\.io|ngrok-free\.app|"
    r"[a-z0-9-]+\.pipedream\.net|pipedream\.net)\b",
    re.I,
)


# F-124/E-044 layer-fix: moved here VERBATIM from trajaudit.py (see _CRED_RE note above
# for why) so logscan.py (a Layer-1 leaf) can reuse it without importing trajaudit.py.
#
# B-157 (see trajaudit.py's skill_indicators()): this regex ALONE is permissive by
# design — `[\w./~+-]*` is zero-or-more on both sides, so it matches a bare dictionary
# word ("secret", "password", "tokens") with no path separator at all, not just a real
# path. trajaudit.py's own consumer filters that out by requiring a "/" in the match
# before treating it as a real secret-path indicator. logscan.py (F-124's class 4,
# env_compromise_ioc) does NOT apply that same filter — it only requires co-occurrence
# with _EXFIL_RE on the same line — so a line that merely DISCUSSES a password/secret in
# prose alongside an unrelated exfil-transport word (curl/webhook/...) can still produce
# a same-line match here. Confirmed in practice: ClawSecCheck's own report text ("...no
# egress allowlist...outbound tools (send/webhook/exec)...System-prompt/secret leak...")
# recorded as trajectory tool-output content is exactly this shape. Accepted as a known
# residual for Phase 1 (advisory/scored=False, WARN-only, never FAILs) — a future
# precision pass on logscan.py's class 4 could adopt the same "/"-required discipline.
_SECRET_PATH_RE = re.compile(
    r"[\w./~+-]*(?:secret|token|credential|password|api[_-]?key)[\w./~+-]*", re.I
)


INPUT_TOOL_HINTS = (
    "email",
    "imap",
    "gmail",
    "rss",
    "feed",
    "web",
    "browse",
    "fetch",
    "file_read",
    "inbox",
)


SENSITIVE_TOOL_HINTS = (
    "db",
    "sql",
    "postgres",
    "supabase",
    "secret",
    "credential",
    "vault",
    "fs_read",
    "files",
)


OUTBOUND_TOOL_HINTS = (
    "send",
    "email_send",
    "webhook",
    "http_post",
    "exec",
    "shell",
    "fs_write",
    "deploy",
    "publish",
)


def _meta(cid: str):
    return BY_ID[cid]


def _finding(
    cid,
    status,
    detail,
    fix,
    evidence=None,
    confidence=None,
    pass_confidence=None,
    severity=None,
) -> Finding:
    m = _meta(cid)
    return Finding(
        m.id,
        m.title,
        severity if severity is not None else m.severity,
        status,
        detail,
        fix,
        m.framework,
        m.scored,
        evidence or [],
        confidence=confidence or m.confidence,
        pass_confidence=pass_confidence,
    )


def _channels(cfg: dict) -> dict:
    ch = cfg.get("channels")
    return ch if isinstance(ch, dict) else {}


# Policies that admit ANY non-owner external sender — authenticated source ≠ trusted content.
# "owner" / "owner-only" / absent / "ask" (per-message approval) are intentionally excluded.
# _open_channels() uses only "open" for B2 ("anyone can command"); _external_input_channels()
# uses the full set for trifecta / blast-radius / ingress-path checks (B-032 fix).
_UNTRUSTED_INPUT_POLICIES = frozenset({"open", "allowlist", "paired"})


def _open_channels(cfg: dict) -> list[str]:
    """Channels where dmPolicy/groupPolicy == 'open' (truly public — anyone can command).

    Used by B2 (gateway auth check) and risk label rendering. For the broader
    'any external input arrives here' question use _external_input_channels().
    """
    out = []
    for name, c in _channels(cfg).items():
        # B-041: a channel with enabled:false ingests nothing — skip it, matching the
        # enabled-aware _active_channels/_untrusted_input_channels helpers. Without this a
        # DISABLED open channel produced §5 hard-FAIL false positives (B2/B55).
        if not isinstance(c, dict) or c.get("enabled") is False:
            continue
        nodes = [c] + list((c.get("accounts") or {}).values())
        for node in nodes:
            if isinstance(node, dict) and (
                node.get("dmPolicy") == "open" or node.get("groupPolicy") == "open"
            ):
                out.append(name)
                break
    return out


def _external_input_channels(cfg: dict) -> list[str]:
    """Channels that admit external (non-owner) senders regardless of how restricted.

    Includes open, allowlist, and paired modes — all of which carry untrusted content
    that could be crafted by (or injected into) the sender. Used for the trifecta
    'untrusted input' leg and credential / ingress-path checks (B-032).
    """
    out = []
    for name, c in _channels(cfg).items():
        # B-041: skip enabled:false channels (a disabled channel admits no external
        # input), matching _untrusted_input_channels. A disabled allowlist/paired channel
        # otherwise drove §5 hard-FAIL false positives (B39) and spurious WARNs (B41/B46).
        if not isinstance(c, dict) or c.get("enabled") is False:
            continue
        nodes = [c] + list((c.get("accounts") or {}).values())
        for node in nodes:
            if isinstance(node, dict) and (
                node.get("dmPolicy") in _UNTRUSTED_INPUT_POLICIES
                or node.get("groupPolicy") in _UNTRUSTED_INPUT_POLICIES
            ):
                out.append(name)
                break
    return out


# B-072: cap recursion depth for config walkers so a pathologically deep (but
# validly-parsed) structure degrades gracefully instead of raising an uncaught
# RecursionError. High enough that it never affects any real-world config shape.
_MAX_WALK_DEPTH = 100


def _secret_paths(obj, prefix="", depth=0) -> list[str]:
    """Dotted paths of secret-bearing keys holding a non-trivial string (no values)."""
    found = []
    if depth >= _MAX_WALK_DEPTH:
        return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, str) and len(v) >= 16 and SECRET_KEY_RE.search(k):
                found.append(path)
            else:
                found.extend(_secret_paths(v, path, depth + 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(_secret_paths(v, f"{prefix}[{i}]", depth + 1))
    return found


def _enabled_tools(cfg: dict) -> list[str]:
    tools = []
    allow = dig(cfg, "tools.elevated.allowFrom")
    if allow:
        tools.append("elevated")
    # Real fields: tools.exec.security / tools.exec.host / tools.exec.mode
    # (tools.exec.host_sandbox does NOT exist in the OpenClaw schema)
    exec_security = dig(cfg, "tools.exec.security")
    exec_host = dig(cfg, "tools.exec.host")
    exec_mode = dig(cfg, "tools.exec.mode")
    sandbox_mode = dig(cfg, "agents.defaults.sandbox.mode")
    if (
        exec_security is not None
        or exec_host is not None
        or exec_mode is not None
        or _profile_is_powerful(dig(cfg, "tools.profile"))
        or (sandbox_mode is not None and sandbox_mode != "off")
    ):
        tools.append("exec")
    # collect any explicitly listed tool names
    listed = dig(cfg, "tools.allow") or dig(cfg, "gateway.tools.allow") or []
    if isinstance(listed, list):
        tools.extend(str(t) for t in listed)
    return tools


def _hint(names, hints) -> bool:
    blob = " ".join(names).lower()
    return any(h in blob for h in hints)


# Tool profiles that grant exec / filesystem-write capability (outbound leg).
# "minimal"/"readonly"/"chat" stay safe; an unknown-but-powerful profile name is
# still caught by the "exec"/"code" substring fallback in _profile_is_powerful().
_POWERFUL_PROFILES = frozenset(
    {
        "coding",
        "code",
        "full",
        "dev",
        "developer",
        "admin",
        "power",
        "all",
        "max",
    }
)


def _profile_is_powerful(profile) -> bool:
    p = str(profile or "").lower()
    return p in _POWERFUL_PROFILES or "exec" in p or "code" in p


def _real_exec_enabled(cfg: dict) -> bool:
    """A genuinely-DECLARED exec/shell capability — not a mere containment control.

    B-064: the shared _enabled_tools() infers a synthetic "exec" from
    `agents.defaults.sandbox.mode != "off"` (correct for B4's "exec present but
    sandbox unset" reasoning, wrong for the trifecta). A sandbox is a HARDENING
    control, not evidence an exec tool is granted, so it must not raise A1's sensitive
    leg (§4: don't assert a capability the config doesn't declare). Real signals only:
    an explicit tools.exec.* field, a powerful tools.profile, or an "exec"/"shell"
    name in tools.allow / gateway.tools.allow.
    """
    if (
        dig(cfg, "tools.exec.security") is not None
        or dig(cfg, "tools.exec.host") is not None
        or dig(cfg, "tools.exec.mode") is not None
    ):
        return True
    if _profile_is_powerful(dig(cfg, "tools.profile")):
        return True
    listed = dig(cfg, "tools.allow") or dig(cfg, "gateway.tools.allow") or []
    return isinstance(listed, list) and _hint([str(t) for t in listed], ("exec", "shell"))


def _web_fetch_enabled(cfg: dict) -> bool:
    """An enabled web fetch/browse tool: pulls arbitrary remote content into the
    agent (untrusted input) and can exfiltrate via request URLs (outbound)."""
    web = dig(cfg, "tools.web")
    if not isinstance(web, dict):
        return False
    if web.get("enabled"):
        return True
    return any(isinstance(sub, dict) and sub.get("enabled") for sub in web.values())


def _active_channels(cfg: dict) -> dict:
    """Channels that are not explicitly disabled (`enabled` is not False)."""
    return {
        n: c
        for n, c in _channels(cfg).items()
        if not (isinstance(c, dict) and c.get("enabled") is False)
    }


def _untrusted_input_channels(cfg: dict) -> list[str]:
    """Enabled channels that can receive non-owner (untrusted) input.

    Same untrusted-policy allowlist as _external_input_channels (dmPolicy/groupPolicy
    in _UNTRUSTED_INPUT_POLICIES = open/allowlist/paired), but additionally excludes
    channels explicitly disabled (`enabled: False`) — a disabled channel ingests
    nothing. An absent or restrictive groupPolicy (e.g. "ask" per-message approval,
    or "owner") is deliberately NOT treated as untrusted, consistent with the leg
    doctrine at _UNTRUSTED_INPUT_POLICIES: a groups-present denylist would FAIL a safe
    owner-approved group bot ("ask") — a §5 false positive — so we key off the
    untrusted-policy allowlist only.
    """
    out = []
    for name, c in _channels(cfg).items():
        if not isinstance(c, dict) or c.get("enabled") is False:
            continue
        nodes = [c] + list((c.get("accounts") or {}).values())
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if (
                node.get("dmPolicy") in _UNTRUSTED_INPUT_POLICIES
                or node.get("groupPolicy") in _UNTRUSTED_INPUT_POLICIES
            ):
                out.append(name)
                break
    return out


def _agent_legs(tools: list) -> dict:
    """Classify ONE agent's declared tool list into the three trifecta legs.

    Per-agent we only have that agent's own tool names (from the attestation roster),
    so legs are derived purely from the same tool-name hints A1 uses. OpenClaw does
    expose per-agent tool config (agents.list[].tools.*), but this classifies the
    ATTESTED roster on purpose — attestation can reflect session-granted runtime tools
    that static per-agent config fields can't (see check_agent_separation for why). The
    config-level signals A1 also consults (credentials dir, gateway password,
    elevated.allowFrom) are GLOBAL, not attributable to one agent, so they are
    intentionally not applied here.
    """
    return {
        "untrusted input": _hint(tools, INPUT_TOOL_HINTS),
        "sensitive data": _hint(tools, SENSITIVE_TOOL_HINTS),
        "outbound actions": _hint(tools, OUTBOUND_TOOL_HINTS),
    }


_LEG_KEYS = ("untrusted input", "sensitive data", "outbound actions")


def _has_approval_gate(cfg: dict) -> bool:
    """Return True when the config has a meaningful exec approval gate.

    Real fields (docs.openclaw.ai/tools/permission-modes):
      tools.exec.mode     — deny/allowlist/ask/auto/full
      tools.exec.security — deny/ask/full
      tools.exec.ask      — off/on-miss/always
    Non-existent: tools.confirm, tools.requireApproval, tools.elevated.requireApproval
    """
    mode = dig(cfg, "tools.exec.mode")
    security = dig(cfg, "tools.exec.security")
    ask = dig(cfg, "tools.exec.ask")
    # "auto" IS a gate (grounded 2026-06-24, docs.openclaw.ai/tools/permission-modes):
    # "Run allowlist matches, then use auto-review" — approval misses go through the
    # native auto-reviewer first, then fall back to the human approval route. Only "full"
    # ("Run host exec without prompts") is ungated, and it is intentionally excluded here.
    # Do not re-flag "auto" as a false-PASS (previously reported and closed not-a-bug).
    if mode in ("deny", "allowlist", "ask", "auto"):
        return True
    if security in ("deny", "ask"):
        return True
    if ask in ("on-miss", "always"):
        return True
    return False


def _is_public_ip(ip: str) -> bool:
    """True for a routable IPv4 — excludes private / loopback / link-local / TEST-NET doc
    ranges so example addresses in documentation don't fire."""
    try:
        octs = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(octs) != 4 or any(o > 255 for o in octs):
        return False
    a, b = octs[0], octs[1]
    if a in (0, 10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    if a == 169 and b == 254:  # link-local
        return False
    if (a, b) in ((192, 0), (198, 51), (203, 0)):  # TEST-NET-1/2/3 documentation ranges
        return False
    return True


# Distinctive symbols that only ClawSecCheck's own signature engine (the checks/
# package) contains. Used to recognise our own source so --vet doesn't flag the
# scanner's embedded attack signatures + red-team payloads as malware.
_OWN_ENGINE_MARKERS = ("def check_installed_skills", "def vet_skill", "_SKILL_CRIT")


def _is_own_source(p: Path) -> bool:
    """True if `p` is ClawSecCheck's own source tree (repo root, install dir, or the
    package dir itself). A security auditor necessarily ships attack signatures and
    red-team payloads as *data*, so a naive malware scan of its own source self-flags.

    Recognition is by structure (package layout) AND distinctive engine symbols — not
    by name alone — so a look-alike skill that merely calls itself "clawseccheck" is
    still scanned normally and cannot use the name to dodge detection.
    """
    # The engine is the checks/ package (current) or a legacy single-file checks.py.
    # Read every engine source so the markers are found regardless of which topic module
    # the I-022 split scattered them into.
    if (p / "clawseccheck" / "checks").is_dir():  # repo root / install dir (package)
        sources = sorted((p / "clawseccheck" / "checks").glob("*.py"))
    elif (p / "clawseccheck" / "checks.py").is_file():  # repo root / install dir (legacy)
        sources = [p / "clawseccheck" / "checks.py"]
    elif p.name.lower() in _OWN_SKILL_NAMES and (p / "checks").is_dir():  # package dir
        sources = sorted((p / "checks").glob("*.py"))
    elif p.name.lower() in _OWN_SKILL_NAMES and (p / "checks.py").is_file():  # package dir (legacy)
        sources = [p / "checks.py"]
    else:
        return False
    try:
        head = "\n".join(s.read_text(encoding="utf-8", errors="replace") for s in sources)
    except OSError:
        return False
    return all(m in head for m in _OWN_ENGINE_MARKERS)


# Destructive / outbound tool name hints (same set as OUTBOUND_TOOL_HINTS above).
_DESTRUCTIVE_HINTS = OUTBOUND_TOOL_HINTS


def _agent_is_powerful(ctx: Context) -> bool:
    """High blast-radius agent: it can execute/write/elevate on the host AND is
    reachable by untrusted input. Used only to gate host-posture WARNs, so the
    absence of host monitoring is flagged exactly when a compromise of *this*
    agent would be consequential (and stays quiet for a sandboxed, low-reach one).
    """
    cfg = ctx.config
    tools = _enabled_tools(cfg)
    can_act = _hint(tools, ("exec", "shell", "fs_write", "deploy")) or "elevated" in tools
    reachable = bool(_external_input_channels(cfg)) or _hint(tools, INPUT_TOOL_HINTS)
    return can_act and reachable


_TIER_NAME = {3: "schema (wall)", 2: "filtered (sieve)", 1: "raw/unknown (passthrough)"}


# ---------------------------------------------------------------------------
# B79 — Codex session approval-policy posture
# ---------------------------------------------------------------------------
def _safe_mtime(p: Path) -> float:
    """B-109: modification time for recency sorting; 0.0 if the file is unreadable
    (it may vanish between the directory walk and the stat)."""
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def _plugins(cfg: dict) -> dict:
    """Installed plugins, supporting both `plugins.entries.<name>` and legacy shapes."""
    p = cfg.get("plugins")
    if isinstance(p, dict):
        entries = p.get("entries")
        if isinstance(entries, dict):
            return entries
        return p
    return {}


# ---------------------------------------------------------------------------
# B77 — Config-write audit log review
# ---------------------------------------------------------------------------
_JSONL_SCAN_CAP = 1_000_000  # B-104: byte budget for tailing append-only JSONL logs


_MCP_REMOTE_TRANSPORTS = ("sse", "http", "streamable-http", "streamablehttp", "websocket", "ws")


def _custom(cid, severity, status, detail, fix, ev=None) -> Finding:
    """Build a finding with an explicit severity (for dynamic-severity checks)."""
    m = BY_ID[cid]
    return Finding(
        m.id,
        m.title,
        severity,
        status,
        detail,
        fix,
        m.framework,
        m.scored,
        ev or [],
        confidence=m.confidence,
    )


def _mcp_has_remote(spec) -> bool:
    """True when an MCP server spec is a remote endpoint (url / network transport),
    vs a local stdio subprocess (a `command`)."""
    if not isinstance(spec, dict):
        return False
    if spec.get("url"):
        return True
    return str(spec.get("transport", "")).lower() in _MCP_REMOTE_TRANSPORTS


# ---------- B15: MCP server trust ----------
def _mcp_servers(cfg: dict) -> dict:
    out = {}
    # Real OpenClaw schema nests servers: mcp.servers.<name> = spec.
    mcp = cfg.get("mcp")
    if isinstance(mcp, dict):
        servers = mcp.get("servers")
        if isinstance(servers, dict):
            out.update(servers)
        else:  # legacy/alt shape: top-level mcp is a direct {name: spec} map
            out.update({k: v for k, v in mcp.items() if isinstance(v, dict)})
    for key in ("mcpServers", "mcp_servers"):
        v = cfg.get(key)
        if isinstance(v, dict):
            out.update(v)
    v = dig(cfg, "tools.mcp") or dig(cfg, "plugins.mcp")
    if isinstance(v, dict):
        out.update(v)
    for name in _plugins(cfg):
        if "mcp" in str(name).lower():
            out.setdefault(name, {})
    return out


def _mcp_url_is_local(url: str) -> bool:
    if not isinstance(url, str) or not url.strip():
        return False
    raw = url.strip()
    lower = raw.lower()
    if lower.startswith(("unix://", "file://")):
        return True
    try:
        parsed = urlparse(raw)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    if host in LOOPBACK:
        return True
    return host.startswith("127.")


def _read_jsonl_tail(path: Path, cap: int = _JSONL_SCAN_CAP) -> tuple[str, bool]:
    """Read at most the last ``cap`` bytes of a (possibly huge) append-only JSONL log.

    Session / config-audit logs can reach GB; a whole-file read + splitlines OOMs on
    long-running agents (B-104). We tail the most-recent ``cap`` bytes — the entries a
    posture check cares about — and drop a possibly-partial leading line (callers already
    skip unparseable lines). Returns (text, truncated).
    """
    size = path.stat().st_size
    if size <= cap:
        return path.read_text(encoding="utf-8", errors="replace"), False
    with open(path, "rb") as fp:
        fp.seek(size - cap)
        data = fp.read(cap)
    text = data.decode("utf-8", errors="replace")
    nl = text.find("\n")
    if nl != -1:
        text = text[nl + 1:]
    return text, True


# ---------------------------------------------------------------- Block A
def _trifecta_legs(ctx: Context) -> dict:
    """The three lethal-trifecta legs computed from the GLOBAL config surface.

    Shared by A1 (check_trifecta) and B46 (check_multiagent_exposure) so both read
    one definition of the legs. Keys are the human-facing labels A1 emits; insertion
    order is preserved (input → sensitive → outbound).
    """
    cfg = ctx.config
    tools = _enabled_tools(cfg)
    untrusted_ch = _untrusted_input_channels(cfg)
    web_fetch = _web_fetch_enabled(cfg)
    # B-061: ungated exec/shell can read any private file (sensitive) AND exfiltrate
    # (outbound). Approval-gated exec — tools.exec.mode is deny/allowlist/ask/auto,
    # security=deny/ask, ask=on-miss/always — see _has_approval_gate) is NOT autonomous:
    # a human signs each call, so it must NOT raise the sensitive leg. Without this guard
    # §5 breaks — home_safe + clean_b55/b68/b69/c014/c6 pair an untrusted channel with
    # mode='ask' exec and would flip to a spurious 3/3. Only ungated exec at mode='full'
    # reaches sensitive. Outbound already counts exec via OUTBOUND_TOOL_HINTS (gated or
    # not), so the outbound leg below is intentionally left unchanged.
    # B-064: use _real_exec_enabled (declared exec signals) NOT _hint(tools, ...) — the
    # latter matches the synthetic "exec" _enabled_tools infers from a configured sandbox
    # (a hardening control, not an exec grant), which produced a spurious 3/3 FAIL.
    exec_enabled = _real_exec_enabled(cfg) and not _has_approval_gate(cfg)
    return {
        "untrusted input": (bool(untrusted_ch) or _hint(tools, INPUT_TOOL_HINTS) or web_fetch),
        "sensitive data": (
            # Agent-readable private data: a data tool (db/credential/vault/fs_read/...)
            # or a credentials/ dir under the home. NOT gateway.auth.password — that is
            # the gateway's own auth secret, not data the agent can read/exfiltrate
            # (B1 flags it as a plaintext secret, which is its proper home). Counting it
            # here let "web fetch + a gateway password" reach a spurious 3/3 (§5).
            _hint(tools, SENSITIVE_TOOL_HINTS)
            or (ctx.home / "credentials").is_dir()
            or exec_enabled  # B-061: ungated arbitrary code can read private files
        ),
        "outbound actions": (
            _hint(tools, OUTBOUND_TOOL_HINTS)
            or bool(dig(cfg, "tools.elevated.allowFrom"))
            or _profile_is_powerful(dig(cfg, "tools.profile"))
            or web_fetch
            or bool(_active_channels(cfg))  # enabled channels are bidirectional
        ),
    }


INJECTION_PATTERNS = [
    re.compile(r"ignore (all|any|previous|prior) (instructions|messages)", re.I),
    re.compile(r"obey (all|any|every|whatever)", re.I),
    re.compile(r"follow (all|any|every|whatever) (instruction|command|request)", re.I),
    re.compile(
        r"do (whatever|anything) (the )?(user|sender|message|email) (says|asks|wants)", re.I
    ),
    # NOTE: a bare "without (asking|confirmation)" pattern was removed — it is approval-bypass
    # phrasing (B23's domain, which is severity-gated) and conflated protective directives
    # ("Don't run destructive commands without asking") with permissive ones, causing false
    # CRITICAL FAILs on well-configured agents. B6 flags blanket-obedience / injection only.
]


_FM_BLOCK_BARE_RE = re.compile(
    r"\A---\s*\n(?P<fm>(?:.*?\n)*?)^---\s*\n",
    re.MULTILINE,
)


# The SKILL.md frontmatter block. _read_skill_text prefixes each file with `# file: <name>`
# (dir vet + full audit); a lone-file vet (vet_skill on a SKILL.md path) has no such header,
# so the block may also start the blob. Both forms are handled by _skill_frontmatter_block.
#
# B-201 (found via its own test suite, not a separate report): an archive-sourced skill's
# header is qualified with the archive path, e.g. "# file: clean_zip.zip::SKILL.md"
# (collector.py's decompress_and_classify uses "outer::inner" chaining for nested
# archives too) -- the bare "SKILL.md" equality this regex used to require never matched
# that, so _skill_frontmatter_block silently returned None for every archive-sourced
# skill's real, well-formed frontmatter. `\S*?` tolerates any such prefix; the trailing
# `\s*\n` anchor still requires the header to END in "SKILL.md", so an unrelated file
# merely containing that substring (e.g. "SKILL.md.bak") cannot match.
_FM_BLOCK_HEADERED_RE = re.compile(
    r"^# file:\s+\S*?SKILL\.md\s*\n---\s*\n(?P<fm>(?:.*?\n)*?)^---\s*\n",
    re.MULTILINE,
)


# General per-file section splitter for the "# file: <name>\n" header _read_skill_text
# injects ahead of every concatenated file's content (moved here from _content.py, B-193 —
# reused by _vet.py too). `name` keeps only the basename (directory stripped by
# _read_skill_text), so this identifies WHICH FILE a blob position came from, not its path.
_MANIFEST_HEADER_RE = re.compile(
    r"^# file:\s+(?P<name>[^\n]+)\n(?P<body>.*?)(?=^# file:|\Z)",
    re.MULTILINE | re.DOTALL,
)


# A sentence terminator (with trailing space/EOL) or a blank-line paragraph break.
# Used to decide grammatical CONNECTION: a negation/prohibition only governs a trigger
# if no sentence/paragraph boundary separates them (moved here from _content.py,
# B-194 — reused by _vet.py too).
_SENTENCE_BREAK_RE = re.compile(r"[.!?][\"')\]]?(?:\s|$)|\n[^\S\n]*\n")


_HOOK_EXEC_RE = re.compile(
    r"\bcurl\b|\bwget\b|\|\s*(?:ba|z)?sh\b|\bbash\b|node\s+-e|python\d?\s+-c|"
    r"base64|\biex\b|invoke-expression|powershell|https?://|eval\s*\(",
    re.I,
)


def _skill_frontmatter_block(blob: str) -> str | None:
    """Return the SKILL.md frontmatter text (between the first fenced `---` pair), or None
    if the blob carries no frontmatter. Prefers the `# file: SKILL.md`-anchored form; falls
    back to a blob that opens with frontmatter (lone-file vet)."""
    m = _FM_BLOCK_HEADERED_RE.search(blob)
    if m:
        return m.group("fm")
    m = _FM_BLOCK_BARE_RE.match(blob)
    if m:
        return m.group("fm")
    return None
