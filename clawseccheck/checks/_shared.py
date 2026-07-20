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
    UNKNOWN,
    Finding,
)
from ..collector import (
    Context,
    dig,
)
# Pure re-exports (B-265): these three moved DOWN into collector.py so Layer-1 skill
# discovery can share one self-identity oracle with vet_skill. They stay importable from
# here — `checks/_vet.py` and the aggregator both do `from ._shared import _is_own_source`
# (§3.1-a: no name that is importable today may stop being importable).
from ..collector import (  # noqa: F401
    _OWN_ENGINE_MARKERS,
    _OWN_SKILL_NAMES,
    _is_own_source,
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
    # C-226: the value is captured in group(1) so callers that need to distinguish a
    # pure SecretRef indirection (e.g. "${NAME}") from a real plaintext secret can
    # inspect just the value — see _is_secret_reference below. Adding the group does
    # not change what this pattern matches (group(0)/start()/end() are unaffected),
    # so existing .sub()/.search() callers (logsafe.redact, logscan.py) are unaffected.
    re.compile(r"(?:password|secret|api[_-]?key|token)\s*[:=]\s*['\"]?([^\s'\"]{8,})", re.I),
    # ClawHub CLI API token. Appended LAST on purpose: the index-referencing comments in
    # tests/test_b01.py (SECRET_PATTERNS[0]/[2]/[4]) stay correct.
    #
    # Grounding (Golden Rule #4): the `clh_` prefix is documented by the installed ClawHub
    # CLI itself — `clawhub login --token clh_...` in its README (clawhub@0.22.0). The CLI
    # performs NO client-side length/charset validation of the token: `dist/cli/authToken.js`
    # only reads `cfg?.token` and `dist/schema/schemas.js` types it as a bare `"string?"`.
    # So the suffix matcher below is deliberately generous rather than a claimed format —
    # over-matching only costs an extra redaction, while under-matching would let a real
    # publish-capable token through our own output.
    #
    # Why this belongs in the shared detector list and not only in logsafe's redaction-only
    # extras: a ClawHub token grants publish rights over the user's own skills, so a copy of
    # one sitting in an OpenClaw config/bootstrap file is exactly the plaintext-secret state
    # B1 exists to flag — a detection gap, not just a redaction gap. No capturing group, so
    # `_pattern_hits_real_secret` treats it like the other concrete literal formats
    # (sk-ant-…/AKIA…/AIza…) and fires on any match; a `${VAR}` indirection cannot collide
    # with a `clh_`-prefixed literal.
    re.compile(r"clh_[A-Za-z0-9_-]{8,}"),
]


# C-226: OpenClaw 2026.7.1 added secret-by-reference config values
# (SecretInput = string | SecretRef{source, provider, id}) so a value need not be a
# plaintext secret at all — our detectors must not FAIL/WARN on the indirection
# itself. Grounded against the installed OpenClaw 2026.7.1 dist
# (dist/types.secrets-*.d.ts + types.secrets-OocW4TQ1.js):
#   ENV_SECRET_REF_ID_RE       = /^[A-Z][A-Z0-9_]{0,127}$/
#   ENV_SECRET_TEMPLATE_RE     = /^\$\{(ID)\}$/   -> "${NAME}"
#   ENV_SECRET_SHORTHAND_RE    = /^\$(ID)$/       -> "$NAME"
#   LEGACY_SECRETREF_ENV_MARKER_PREFIX          = "secretref-env:" (+ ID, case-sensitive)
#   LEGACY_DOUBLE_UNDERSCORE_ENV_MARKER_PREFIX  = "__env__:" (+ ID, case-sensitive)
# The structured `{source, provider, id}` SecretRef object form is a dict, never a
# string, so _secret_paths (below) already skips it — it only ever flags STRING
# values under a secret-shaped key. No handling needed here for that shape.
_SECRET_REF_ENV_ID = r"[A-Z][A-Z0-9_]{0,127}"

_SECRET_REFERENCE_RE = re.compile(
    r"(?:\$\{%(id)s\}|\$%(id)s|secretref-env:%(id)s|__env__:%(id)s)"
    % {"id": _SECRET_REF_ENV_ID}
)


def _is_secret_reference(value: str) -> bool:
    """True only when *value*, after ``.strip()``, is EXACTLY one OpenClaw SecretRef
    indirection shorthand — never a substring or a prefix of something longer, so any
    real secret material appended (or prepended) to a reference shape still counts as
    a plaintext secret (C-226 adversarial requirement: the exclusion must stay narrow).
    """
    if not isinstance(value, str):
        return False
    return bool(_SECRET_REFERENCE_RE.fullmatch(value.strip()))


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


_CORR_INDICATOR_CAP = 256
_MIN_CORR_INDICATOR_LEN = 4


def _normalize_corr_token(tok: str) -> str:
    """Lowercase + strip a leading $HOME/ / ~/ / ~ so a skill-declared path/host matches
    the same IOC as it appears in a log line (membership test only)."""
    t = tok.strip().strip(".,;:\"'`)(")
    for prefix in ("$HOME/", "~/", "~"):
        if t.startswith(prefix):
            t = t[len(prefix):]
            break
    return t.lower()


def correlation_indicators(installed_skills):
    """Map each HIGH-SPECIFICITY IOC an installed skill NAMES -> the skill naming it (C-221).

    Deliberately narrower than trajaudit.skill_indicators: only tokens whose appearance in
    the agent's OWN log corpus is strong cross-artifact evidence — credential-shaped paths
    (_CRED_RE), secret-named paths WITH a '/' separator (_SECRET_PATH_RE + the B-157 filter),
    and KNOWN drop-point hosts (_KNOWN_EXFIL_HOST_RE). The bare _EXFIL_RE verbs
    (curl/wget/fetch/base64/POST) are EXCLUDED — base-rate noise in any web/exec-capable
    agent's logs. Keys are normalized (tilde-stripped, lowercased) for a case-insensitive
    substring membership test; values are the declaring skill name. Capped at
    _CORR_INDICATOR_CAP entries.
    """
    out = {}
    for name, text in (installed_skills or {}).items():
        if not isinstance(text, str):
            continue
        for rx in (_CRED_RE, _SECRET_PATH_RE, _KNOWN_EXFIL_HOST_RE):
            for m in rx.finditer(text):
                raw = m.group(0).strip().strip(".,;:\"'`)(")
                if rx is _SECRET_PATH_RE and "/" not in raw:
                    continue
                key = _normalize_corr_token(raw)
                if len(key) < _MIN_CORR_INDICATOR_LEN or key in out:
                    continue
                out[key] = str(name)
                if len(out) >= _CORR_INDICATOR_CAP:
                    return out
    return out


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


# B-228: openclaw.json present but unparseable/unreadable (ctx.config_parse_error, B-166)
# makes the collector fall back to ctx.config = {} — a check that reads ctx.config /
# dig(ctx.config, ...) with no other guard then sees an empty-but-VALID-looking config and
# emits an affirmative "clean" PASS it never actually earned (GR#4: report UNKNOWN, not a
# fake PASS/FAIL, when a check genuinely can't determine state). This is a per-check
# OPT-IN guard, not an engine-wide blanket: only a check whose verdict is primarily
# CONFIG-content-derived should call it. A check whose primary evidence is bootstrap/
# skills/host/trajectory data must not call this — it would suppress a real, config-
# independent finding that has nothing to do with openclaw.json parsing. For a check that
# mixes config-derived evidence with an independent non-config signal (e.g. B1's bootstrap-
# file secret scan, B11's file-permission check), call this immediately before the check's
# own terminal "clean" verdict rather than at the top of the function, so the independent
# signal still gets a chance to FAIL/WARN on its own merits.
def _config_unreadable(cid: str, ctx: Context) -> "Finding | None":
    """UNKNOWN finding for *cid* when ctx.config could not actually be parsed, else None.

    Callers: ``if (f := _config_unreadable("B1", ctx)) is not None: return f`` (or the
    non-walrus two-line form) before trusting ``ctx.config``/``dig(ctx.config, ...)`` for
    an affirmative verdict.
    """
    if not ctx.config_parse_error:
        return None
    return _finding(
        cid,
        UNKNOWN,
        "openclaw.json present but unparseable/unreadable — cannot determine.",
        "Fix openclaw.json so it is valid JSON and owner-readable, then re-run the audit.",
    )


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
#
# B-283 (a): this set previously read {"open", "allowlist", "paired"}. "paired" is NOT an
# OpenClaw policy value — grounded against the installed dist, DmPolicySchema is
# _enum(["open","pairing","allowlist"]) (channel-PR3XHV0V.js:84-88) and every bare "paired"
# literal in the dist is a DEVICE-pairing status or a provider-catalog order, never a
# dm/groupPolicy value (`grep 'dmPolicy === "paired"'` returns nothing). So the only member
# that could ever match was the one that never occurs, while "pairing" — which is the
# DEFAULT (`DmPolicySchema.optional().default("pairing")` at 6+ schema sites, plus ~15
# runtime `?? "pairing"` fallbacks) — evaluated as NOT untrusted input. That is a lying PASS
# on the most common real-world ingress path. Fixed: "paired" dropped as dead, "pairing"
# added.
#
# GROUNDING CORRECTION (C-135 review, B-283): the justification originally written here for
# ADDING "pairing" claimed "senders self-enrol" and "dm-policy-shared-BaGKWQzz.js never
# returns block" — both checked against the dist and found false, so replaced with what
# actually holds. (1) Pairing is NOT self-enrolment: admission requires an explicit owner
# action, `openclaw pairing approve <channel> <code>` ("Approve a pairing code and allow
# that sender", pairing-cli-C7VdpD0e.js:123) — a sender only sends a *request*; nothing
# admits it unattended. (2) The resolver DOES return block for an unapproved pairing sender:
# message-access-DucCKzfO.js:163-164 — `if (dmPolicy === "pairing" && event.mayPair) return
# block("dm_policy_pairing_required")`, then a final `return
# block(dmPolicy === "pairing" ? "event_pairing_not_allowed" : ...)` — both via the local
# `block()` at lines 138-144, whose `senderGate` carries `effect: "block-dispatch"`. The
# justification that actually holds: a sender who HAS completed pairing resolves through
# dm-policy-shared-BaGKWQzz.js:92 — `isSenderAllowed(effectiveAllowFrom) ? allow(...,
# DM_POLICY_ALLOWLISTED, ...) : ...` — to the exact same decision and reasonCode
# (`dm_policy_allowlisted`) that a `dmPolicy=="allowlist"` match produces; the modern
# resolver in message-access-DucCKzfO.js:152-160 agrees (`pairingStore.match.matched` also
# yields `reasonCode: "dm_policy_allowlisted"`). OpenClaw itself classifies a paired sender
# identically to an allow-listed one, and "allowlist" was already a member of this set —
# that is reason enough for "pairing" to join it, independent of the retracted claims above.
#
# Why the GR#4 schema-grounding guard could not catch this: both layers ground dig() PATHS.
# These helpers read raw node.get("dmPolicy") and compare VALUE LITERALS, which no guard
# grounds. The same shape can hide in any value-literal comparison.
#
# NOT closed here (deliberately out of scope, see B-283): an ABSENT dmPolicy still reads as
# "no untrusted ingress" even though the product default is "pairing". Treating absent as
# pairing would flip nearly every enabled-channel config to untrusted-ingress and could
# cascade into A1 grade changes; it needs its own C-135 pass and remains a separate task.
_UNTRUSTED_INPUT_POLICIES = frozenset({"open", "allowlist", "pairing"})


def _norm_group_policy(channel_name, value):
    """Normalize a raw ``groupPolicy`` literal to the value OpenClaw resolves it to.

    B-283 (a): Feishu's own ``GroupPolicySchema`` is
    ``union([_enum(["open","allowlist","disabled"]), literal("allowall").transform(() => "open")])``
    (channel-PR3XHV0V.js:89-93), and ``normalizeFeishuGroupPolicy`` does the same
    (policy-hydoYQvK.js:55-57). So a Feishu config written as ``groupPolicy: "allowall"``
    runs as ``"open"`` — the single most permissive setting.

    FEISHU SCOPE ONLY (GROUNDING CORRECTION, C-135 review). This was originally channel-
    agnostic — every ``== "open"`` / policy-set membership test in this package normalized
    every channel's groupPolicy the same way. Checked against the dist, that is wrong:
    Feishu is the ONLY channel schema in the installed dist that accepts the ``"allowall"``
    literal. LINE defines its own separate ``GroupPolicySchema`` as a bare
    ``_enum(["open","allowlist","disabled"])`` with no ``"allowall"`` member
    (reply-payload-transform-Ce9ZfUxA.js:19-23), and Telegram/Discord/Slack/Signal/Matrix/
    Nextcloud-Talk/Zalo/Zalouser all import the shared "core" ``GroupPolicySchema``, itself
    ``_enum(["open","disabled","allowlist"])`` with no ``"allowall"`` member
    (zod-schema.core-DviqqtPj.js:424-428). Both REJECT ``"allowall"`` — a config with e.g.
    ``channels.telegram.groupPolicy: "allowall"`` fails OpenClaw's own schema validation and
    so cannot be a config a running instance actually loaded. Normalizing it channel-
    agnostically meant this package could score a CRITICAL FAIL against a value zod would
    refuse to load — a fabricated schema fact in its own right, not just a wrong comment.
    Callers now pass the channel key; this function transforms the literal only when
    ``channel_name == "feishu"``. Every other channel's raw ``"allowall"`` (an already-
    invalid value there) passes through unchanged, same as any other unmodeled string.

    dmPolicy is untouched regardless of channel: ``allowall`` is not a member of
    ``DmPolicySchema`` on any channel checked, and Feishu's own ``normalizeFeishuDmPolicy``
    (policy-hydoYQvK.js:52-54) maps any unrecognised dmPolicy — including a stray
    ``"allowall"`` — to ``"pairing"``, NOT to ``"open"``. Normalizing dmPolicy="allowall" to
    "open" would therefore overstate the exposure of an already-invalid config.

    GROUNDING CORRECTION (item 4): a prior version of this docstring claimed the dmPolicy
    gap "is not a silent PASS" because "pairing" is in ``_UNTRUSTED_INPUT_POLICIES``. Checked
    against this package's own code, that is wrong: dmPolicy is never normalized anywhere,
    so an unrecognised dmPolicy literal (``"allowall"`` or any other unmodeled string) is
    compared as-is against ``_UNTRUSTED_INPUT_POLICIES`` and against ``"open"``, matches
    neither, and resolves as a silent PASS in this package's own output — indistinguishable
    from a genuinely-restrictive policy. That gap is real, applies to every unmodeled
    dmPolicy string (not just "allowall"), and is out of scope for this fix, which only
    corrects the groupPolicy alias.
    """
    return "open" if channel_name == "feishu" and value == "allowall" else value


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
                node.get("dmPolicy") == "open"
                or _norm_group_policy(name, node.get("groupPolicy")) == "open"
            ):
                out.append(name)
                break
    return out


def _external_input_channels(cfg: dict) -> list[str]:
    """Channels that admit external (non-owner) senders regardless of how restricted.

    Includes open, allowlist, and pairing modes — all of which carry untrusted content
    that could be crafted by (or injected into) the sender. Used for the trifecta
    'untrusted input' leg and credential / ingress-path checks (B-032). ``groupPolicy``
    is normalized first so a Feishu channel's ``"allowall"`` alias counts as ``"open"``
    (B-283; Feishu-scoped — see ``_norm_group_policy``).
    """
    out = []
    for name, c in _channels(cfg).items():
        # B-041: skip enabled:false channels (a disabled channel admits no external
        # input), matching _untrusted_input_channels. A disabled allowlist/pairing channel
        # otherwise drove §5 hard-FAIL false positives (B39) and spurious WARNs (B41/B46).
        if not isinstance(c, dict) or c.get("enabled") is False:
            continue
        nodes = [c] + list((c.get("accounts") or {}).values())
        for node in nodes:
            if isinstance(node, dict) and (
                node.get("dmPolicy") in _UNTRUSTED_INPUT_POLICIES
                or _norm_group_policy(name, node.get("groupPolicy"))
                in _UNTRUSTED_INPUT_POLICIES
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
            if (
                isinstance(v, str)
                and len(v) >= 16
                and SECRET_KEY_RE.search(k)
                and not _is_secret_reference(v)
            ):
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

    Same untrusted-policy allowlist as _external_input_channels (dmPolicy/groupPolicy in
    _UNTRUSTED_INPUT_POLICIES = open/allowlist/pairing, with a Feishu channel's groupPolicy
    normalized so its "allowall" alias counts as "open" — B-283, Feishu-scoped, see
    _norm_group_policy), but additionally excludes channels explicitly disabled
    (`enabled: False`) — a disabled channel ingests nothing. An absent or restrictive
    groupPolicy (e.g. "ask" per-message approval, or "owner") is deliberately NOT treated
    as untrusted, consistent with the leg doctrine at _UNTRUSTED_INPUT_POLICIES: a
    groups-present denylist would FAIL a safe owner-approved group bot ("ask") — a §5
    false positive — so we key off the untrusted-policy allowlist only.
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
                or _norm_group_policy(name, node.get("groupPolicy"))
                in _UNTRUSTED_INPUT_POLICIES
            ):
                out.append(name)
                break
    return out


def _channels_with_context_visibility_all(cfg: dict) -> list[str]:
    """Channel names whose effective ``contextVisibility`` resolves to ``"all"``.

    B-283 (c): the dist resolver's own doc comment reads *"Resolves supplemental context
    visibility using explicit, account, channel, default precedence"*
    (context-visibility-BVlvSMUZ.js:8-13):

        resolveAccountEntry(channelConfig?.accounts, accountId)?.contextVisibility
          ?? channelConfig?.contextVisibility
          ?? resolveDefaultContextVisibility(params.cfg)
          ?? "all"

    B26 and risk.py's mirror previously resolved channel -> default -> "all" and never
    descended ``accounts``, so ``channels.<p>.accounts.<id>.contextVisibility: "all"`` on a
    channel whose channel-level value was ``"allowlist"`` produced a PASS that was
    byte-indistinguishable from a genuinely-safe config. Per-account ``contextVisibility``
    is in the shipped schema for six providers (Telegram / Discord / Slack / Signal /
    iMessage / MSTeams), enum {all, allowlist, allowlist_quote}.

    A channel is reported when ANY node resolves to "all". Both directions are correct:
      * account overrides to "all" over an "allowlist" channel  -> reported (the override
        is what actually runs for that account);
      * ONE account overrides to "allowlist" on an "all" channel -> still reported, because
        accounts WITHOUT an override keep resolving to the channel value.

    This is not a heuristic: it fires only where the owner explicitly wrote the unsafe
    enum value, so it cannot manufacture a false positive. Same accounts-descent idiom as
    _open_channels / _external_input_channels / _untrusted_input_channels above; the
    project already paid for this bug shape once (B-058, see _agents.py).
    """
    channels = cfg.get("channels")
    if not isinstance(channels, dict):
        return []
    # Read via dig() so the path stays registered with the GR#4 schema-grounding guard
    # (tests/test_schema_grounding.py greps dig() call sites); an equivalent .get() chain
    # would silently drop channels.defaults.contextVisibility from the grounded manifest.
    global_default = dig(cfg, "channels.defaults.contextVisibility")
    out: list[str] = []
    for name, c in channels.items():
        # "defaults" holds defaults; it is not a channel.
        if name == "defaults" or not isinstance(c, dict):
            continue
        channel_value = c.get("contextVisibility")
        accounts = c.get("accounts")
        # isinstance guard, not the `or {}` idiom used by the older accounts walkers above:
        # a non-dict `accounts` (e.g. a bare string) is truthy, so `or {}` does not catch it
        # and .values() raises. Those older sites share that latent crash on a malformed
        # config; it is pre-existing and filed separately rather than widened into here.
        account_nodes = list(accounts.values()) if isinstance(accounts, dict) else []
        # [c] first so a channel with no accounts still resolves at channel scope.
        for node in [c] + account_nodes:
            if not isinstance(node, dict):
                continue
            # node is `c` itself for the channel-scope pass, which collapses this to
            # channel -> default -> "all"; for an account node it is the full
            # account -> channel -> default -> "all" precedence the dist implements.
            effective = (
                node.get("contextVisibility") or channel_value or global_default or "all"
            )
            if effective == "all":
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


# `_OWN_ENGINE_MARKERS` / `_is_own_source` used to be DEFINED here. B-265 relocated them
# down into `collector.py` (Layer 1) so skill *discovery* can use the same content-verified
# self-identity oracle that `vet_skill` uses — the Layer-1 collector may not import this
# Layer-2 module, and the basename-only skip it had instead was a free rename cloak. They
# are re-imported at the top of this file exactly as `_OWN_SKILL_NAMES`/`Context`/`dig`
# already are, so `from ._shared import _is_own_source` keeps working unchanged.

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


# ---------- B-229: MCP-granted capability folds into the lethal-trifecta legs ----------
# MCP is OpenClaw's primary capability-extension surface, yet the trifecta legs
# historically derived capability only from tools.*/credentials/ and never read
# mcp.servers — so a server granting broad filesystem/database/secret access (the
# "sensitive data" leg) or a remote/network endpoint (the "outbound" leg) counted for
# nothing, and A1 under-reported the leg count. The wiring below is deliberately
# CONSERVATIVE so a benign read-only MCP cannot manufacture a spurious 3/3 FAIL
# (§5 zero-FP / C-135): only a KNOWN data/db/secret server package name, OR a filesystem
# server rooted at a BROAD path, raises the sensitive leg — a narrowly project-scoped fs
# root does not; and a loopback MCP endpoint is NOT outbound.
#
# The two FP-suppression denylists below plus the command/args-only sensitive-data
# scoping were hardened across C-135 rounds 2-3 (false-FAILs removed without opening
# false-negatives); each carries its own FP/FN + accepted-residual rationale inline.

# Capability keywords that, when they name an MCP server via the canonical
# @scope/server-<cap> / mcp-server-<cap> / mcp-<cap> naming convention, mark a server
# that inherently exposes sensitive data — a whole database, secret store, or cloud
# drive. Grounded on the @modelcontextprotocol reference servers plus common third-party
# naming. The MCP-naming anchor is REQUIRED so a bare keyword in a path/host cannot match
# (e.g. a "db-helper" arg with no mcp/server- prefix stays unflagged). This pattern is
# matched ONLY against a stdio server's command/args (see _mcp_leg_contributions) —
# never a remote server's url, which says nothing about local data access.
_MCP_DATA_CAP_RE = re.compile(
    r"(?:@[\w.-]+/server-|mcp[-_]server[-_]|mcp[-_])"
    r"(postgres(?:ql)?|mysql|mariadb|sqlite|mongo(?:db)?|redis|database|"
    r"gdrive|google-?drive|dropbox|s3|vault|secrets?|credentials?|"
    r"keychain|keyring|1password|onepassword|bitwarden)\b",
    re.I,
)

# FP-suppression denylist (C-135 round 2, tightened round 3): a capability keyword
# immediately followed by one of these SHAPE-ONLY suffixes names a tool that inspects/
# documents a data store's STRUCTURE, not one that reads its contents — e.g.
# "database-diagram", "redis-docs", "server-database-schema". Matched right after
# _MCP_DATA_CAP_RE's keyword; a bare keyword with no such suffix (a real
# "server-postgres"/"server-vault") still flags.
#
# C-135 round 3 (FN-1): "viewer"/"explorer"/"dashboard"/"scanner" were REMOVED from this
# denylist — those suffixes name a READER, not a shape-only tool (a "vault-viewer" reads
# the actual secrets, a "postgres-viewer"/"mongodb-explorer"/"redis-viewer" reads DB rows,
# an "s3-explorer"/"gdrive-viewer" reads cloud objects, a "database-scanner" dumps a DB),
# so suppressing them was a real false-negative — they must still flag as data access.
_MCP_BENIGN_COMPOUND_RE = re.compile(
    r"\A[-_]?(diagram|designer|docs?|documentation|schema|erd)\b",
    re.I,
)

# A filesystem MCP server (canonical @modelcontextprotocol/server-filesystem plus the
# generic mcp-server-filesystem / filesystem-mcp naming). Anchored to the mcp/server-
# naming so a bare "filesystem" token in a path cannot match. It raises the sensitive
# leg ONLY when the server is ALSO rooted at a broad path (see _mcp_fs_root_is_broad).
# Matched ONLY against a stdio server's command/args, same scoping as _MCP_DATA_CAP_RE.
_MCP_FS_PKG_RE = re.compile(
    r"(?:@[\w.-]+/server-filesystem|mcp[-_]server[-_]filesystem|"
    r"filesystem[-_]mcp|server-filesystem)\b",
    re.I,
)

# Filesystem roots broad enough that read access constitutes the sensitive-data leg:
# the whole root, an entire user home, or a system-config tree. A project-scoped root
# (e.g. '/home/user/project', '.', a single sub-dir) is intentionally NOT broad.
_MCP_BROAD_FS_ROOTS = frozenset(
    {"/", "~", "~/", "$home", "${home}", "%userprofile%",
     "/home", "/users", "/root", "/etc", "/var"}
)

# FP-suppression denylist (C-135 round 2, tightened round 3, FP-A): basenames directly
# under /home or /Users that name a conventionally-shared/scratch/dev-workspace
# directory, NOT a private per-user home — e.g. the standard macOS /Users/Shared folder,
# or a team's /home/data /home/projects /home/workspace convention. A single path level
# under /home//Users is only "the whole user home" when it is a plausible username, i.e.
# NOT one of these.
#
# C-135 round 3 (FN-2): {git, backup, backups, www, srv, web, repo, repos} were REMOVED
# from this denylist — those are service-account / secret-bearing home directories, not
# harmless shares: /home/git is a git service user's home (~/.ssh deploy keys + every
# repo it serves), /home/backup(s) holds whole-system backups / DB dumps, /home/www
# ///srv//web are webroots (configs, .env, credentials), /home/repo(s) is a repo-hosting
# account. Rooting a filesystem MCP there is a genuine sensitive-data grant, so
# suppressing it was a real false-negative — they go back to broad (FAIL), a true
# positive.
#
# The remaining names ARE kept as an intentional, accepted residual (not a bug): the
# bare word after /home/ or /Users/ (e.g. "data", "projects", "workspace") is statically
# undecidable — it can equally be a team's shared scratch/dev folder (the common case) OR
# someone's actual private home directory named after its purpose. Per Golden Rule #5 a
# false-positive FAIL is the hard blocker, so this ambiguity is deliberately tie-broken
# toward PASS (no leg raised) rather than FAIL, accepting the narrower risk of a false
# NEGATIVE on the rarer case where one of these really is a private, sensitive home.
# Pinned by test_home_purpose_word_ambiguity_is_accepted_residual (do not "fix" this by
# re-adding these names to the denylist without re-litigating the GR#5 tradeoff).
_MCP_HOME_SHARED_BASENAMES = frozenset(
    {
        "shared", "public", "guest", "default", "common",
        "workspace", "workspaces", "projects", "project",
        "app", "apps", "data", "media", "docs", "doc",
        "tmp", "temp",
    }
)


def _mcp_fs_root_is_broad(raw) -> bool:
    """True when a filesystem-MCP root arg exposes broad private/system data.

    Broad = the whole root ('/'), an entire user home ('~'/'$HOME'/'/home/<user>'/
    '/Users/<user>'), or a system-config tree ('/etc', '/var'). A narrowly project-scoped
    root (a single sub-dir under a home, '.', a relative path) is NOT broad — it does not,
    by itself, raise the sensitive-data leg (§5 zero-FP). Flags (leading '-') are skipped.

    C-135 round 2 (FP-A), tightened round 3: a single level under /home or /Users is
    broad only when that basename is NOT a conventionally-shared/scratch name (see
    _MCP_HOME_SHARED_BASENAMES) — e.g. /Users/Shared or /home/data stay non-broad, even
    though nominally "one level under the homes parent". A service-account / secret-
    bearing home (/home/git, /home/backup, /home/www, ...) is deliberately NOT in that
    denylist (round 3, FN-2) and so still counts as broad.
    """
    p = str(raw).strip().strip('"').strip("'")
    if not p or p.startswith("-"):
        return False
    low = (p.rstrip("/") or "/").lower()
    if low in _MCP_BROAD_FS_ROOTS:
        return True
    # /home/<user> or /Users/<user> — exactly one level under the homes parent — grants
    # the whole user home = broad; a deeper path (/home/<user>/project) is project-scoped;
    # a shared/service basename (/Users/Shared, /home/data) is not a private home either.
    segs = [s for s in low.split("/") if s]
    if len(segs) == 2 and segs[0] in ("home", "users"):
        return segs[1] not in _MCP_HOME_SHARED_BASENAMES
    return False


def _mcp_sensitive_reason(local_blob: str, args: list) -> str:
    """Human-readable reason a STDIO MCP server grants the sensitive-data leg, else ''.

    ``local_blob`` must be the server's command+args ONLY (see _mcp_leg_contributions) —
    never a remote server's url/host, which says nothing about local data access (a
    remote endpoint's own risk is the outbound leg, not this one).

    Two sound signals: a known data/db/secret server package name that is NOT a
    shape-only compound (diagram/designer/docs/documentation/schema/erd — inspects the
    structure, doesn't read the data; _MCP_BENIGN_COMPOUND_RE), or a filesystem server
    ALSO rooted at a broad path. A reader/browser compound (viewer/explorer/dashboard/
    scanner) is deliberately NOT in that denylist (C-135 round 3, FN-1) — it still flags.
    """
    m = _MCP_DATA_CAP_RE.search(local_blob)
    if m and not _MCP_BENIGN_COMPOUND_RE.match(local_blob[m.end():]):
        return f"grants {m.group(1).lower()} access (a data/secret MCP server)"
    if _MCP_FS_PKG_RE.search(local_blob):
        broad = next((a for a in args if _mcp_fs_root_is_broad(a)), None)
        if broad is not None:
            return f"is a filesystem server rooted at a broad path ({broad!r})"
    return ""


# B-247 (a B-229 residual): a server package that itself pulls untrusted EXTERNAL
# content into the agent — fetch/web-search/browser/scraper, or a mailbox/feed/chat/
# issue-tracker reader. Mirrors INPUT_TOOL_HINTS, anchored to the MCP package-naming
# convention like _MCP_DATA_CAP_RE (a bare keyword with no such prefix cannot match).
# Narrower than INPUT_TOOL_HINTS's bare "web": "mcp-server-web3"/"mcp-server-webhook"
# name an unrelated blockchain tool / an OUTBOUND sink, not intake, so only the
# "web-search" compound counts. "filesystem" is excluded on purpose — that is the
# sensitive-data leg's domain (_MCP_FS_PKG_RE); folding it in here would duplicate it.
_MCP_INTAKE_CAP_RE = re.compile(
    r"(?:@[\w.-]+/server-|mcp[-_]server[-_]|mcp[-_])"
    r"(fetch|web[-_]?search|browse(?:r)?|scrape(?:r)?|"
    r"email|imap|gmail|rss|feed|slack|inbox|github[-_]?issues?)\b",
    re.I,
)


def _mcp_intake_reason(blob: str) -> str:
    """Human-readable reason an MCP server grants the trifecta's untrusted-input leg,
    else ''.

    Unlike ``_mcp_sensitive_reason``, ``blob`` is NOT local-only — callers pass
    command+args+url combined (see _mcp_leg_contributions). A remote fetch/web-search/
    inbox-style endpoint pulls untrusted external content into the agent's context just
    like a local stdio one does; the "url says nothing about local access" reasoning
    that excludes url from the sensitive-data probe is specific to LOCAL data exposure
    and does not apply here. Reuses the shared shape-only-compound denylist
    (_MCP_BENIGN_COMPOUND_RE), so a "mcp-server-slack-docs" (documentation ABOUT the
    API, not a live reader) does not flag, same as the sensitive-data leg.
    """
    m = _MCP_INTAKE_CAP_RE.search(blob)
    if m and not _MCP_BENIGN_COMPOUND_RE.match(blob[m.end():]):
        return f"is a {m.group(1).lower()} server (pulls untrusted external content)"
    return ""


def _mcp_leg_contributions(cfg: dict) -> dict:
    """Map trifecta leg -> list of MCP-server evidence strings that contribute to it.

    Each string NAMES the server so A1 can attribute the leg to its capability source.
    Untrusted-input contributors (B-247): a fetch/web-search/browser/scraper/email/
    imap/gmail/rss/feed/slack/inbox/github-issues package, matched against command+
    args+url combined — a remote intake endpoint is just as much an intake source as a
    local one (see _mcp_intake_reason). Sensitive-data contributors: a STDIO server
    whose command/args name a known data/db/secret package (not a benign diagram/docs/
    schema compound) or a broad-rooted fs root. A remote server's url/host is NEVER
    used for THIS leg (C-135 round 2, FP-B) — it says nothing about local data access.
    Outbound contributors: a remote/network endpoint that is NOT loopback (a localhost
    MCP keeps data on the machine and is not an exfil path).
    """
    contribs: dict = {"untrusted input": [], "sensitive data": [], "outbound actions": []}
    for name, spec in _mcp_servers(cfg).items():
        if not isinstance(spec, dict):
            spec = {}
        # B-247 FP fix: an `enabled: false` server contributes NO tools to the agent —
        # OpenClaw filters it out at every consumption site (server.enabled !== false in
        # bundle-mcp-config-CdwmTK7W.js / tool-policy-pipeline-C3edOW1F.js / bundle-mcp-
        # codex-DkMkPyae.js; McpServerSchema.enabled is optional boolean, zod-schema-
        # O9ml_nmo.js). Use `is False`, not falsy/`not spec.get("enabled")` — an omitted
        # key is the permissive default. This also repairs the pre-existing (B-229)
        # sensitive-data/outbound blindness to the same field, not just the new intake
        # leg: keeping a disabled entry in config (OpenClaw's own documented
        # `mcp configure --disable` workflow, and A1's own remediation advice) must not
        # itself manufacture a trifecta leg.
        if spec.get("enabled") is False:
            continue
        cmd = str(spec.get("command", ""))
        raw_args = spec.get("args")
        args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
        # Sensitive-data signal is local-only: command+args of a stdio server. A
        # remote server's url is deliberately excluded (FP-B) — see docstring.
        local_blob = " ".join([cmd] + args)
        reason = _mcp_sensitive_reason(local_blob, args)
        if reason:
            contribs["sensitive data"].append(f"MCP server {name!r} {reason}")
        url = str(spec.get("url", "") or "")
        # B-247: intake probe covers command+args+url — a remote endpoint's identity
        # IS meaningful here, unlike the sensitive-data probe above (see docstring).
        intake_blob = f"{local_blob} {url}" if url else local_blob
        intake_reason = _mcp_intake_reason(intake_blob)
        if intake_reason:
            contribs["untrusted input"].append(f"MCP server {name!r} {intake_reason}")
        if _mcp_has_remote(spec) and not (url and _mcp_url_is_local(url)):
            endpoint = url or str(spec.get("transport", "remote"))
            contribs["outbound actions"].append(
                f"MCP server {name!r} is a remote/network endpoint ({endpoint})"
            )
    return contribs


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
    # B-229: MCP is OpenClaw's primary capability-extension surface. A server granting
    # broad fs/db/secret access raises the sensitive leg; a remote (non-loopback) endpoint
    # raises the outbound leg. Deliberately conservative (see _mcp_leg_contributions) so a
    # benign read-only / localhost MCP cannot manufacture a spurious 3/3 FAIL (§5).
    # B-247 (a B-229 residual): a fetch/web-search/browser/scraper/mailbox/feed/chat/
    # issue-tracker MCP server raises the untrusted-input leg too — B-229 only wired the
    # sensitive-data and outbound legs, leaving a semantically identical MCP intake
    # source (e.g. @modelcontextprotocol/server-fetch) invisible next to tools.web.fetch.
    mcp_legs = _mcp_leg_contributions(cfg)
    return {
        "untrusted input": (
            bool(untrusted_ch)
            or _hint(tools, INPUT_TOOL_HINTS)
            or web_fetch
            or bool(mcp_legs["untrusted input"])  # B-247: fetch/web-search/inbox/... MCP
        ),
        "sensitive data": (
            # Agent-readable private data: a data tool (db/credential/vault/fs_read/...)
            # or a credentials/ dir under the home. NOT gateway.auth.password — that is
            # the gateway's own auth secret, not data the agent can read/exfiltrate
            # (B1 flags it as a plaintext secret, which is its proper home). Counting it
            # here let "web fetch + a gateway password" reach a spurious 3/3 (§5).
            _hint(tools, SENSITIVE_TOOL_HINTS)
            or (ctx.home / "credentials").is_dir()
            or exec_enabled  # B-061: ungated arbitrary code can read private files
            or bool(mcp_legs["sensitive data"])  # B-229: fs-at-broad-root / db / secret MCP
        ),
        "outbound actions": (
            _hint(tools, OUTBOUND_TOOL_HINTS)
            or bool(dig(cfg, "tools.elevated.allowFrom"))
            or _profile_is_powerful(dig(cfg, "tools.profile"))
            or web_fetch
            or bool(_active_channels(cfg))  # enabled channels are bidirectional
            or bool(mcp_legs["outbound actions"])  # B-229: remote/network MCP endpoint
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


# F-127 (2026-07-18, C-135): logscan.py's class 1 (`injection_against_agent`) used
# INJECTION_PATTERNS[0] alone and missed the single most canonical injection phrasing —
# "ignore all previous instructions" stacks TWO modifiers ("all" + "previous") where
# INJECTION_PATTERNS[0] allows exactly one, and "disregard"/"forget" (the next two most
# common override verbs — "Disregard all prior instructions", "Forget everything above")
# aren't covered by any verb there at all. Fixed end-to-end FN on check_memory_reconsumption_
# injection (B180): 3 of 4 textbook poisoned-memory payloads returned PASS despite an
# unambiguous cred-read + attacker-host exfil line the scanner DID see as a second class.
#
# Deliberately NOT folded into INJECTION_PATTERNS itself: that list is also consumed
# un-corroborated by check_bootstrap_injection (B6 — a bare match is a direct FAIL, no
# second-signal gate) and by the B58/C074 content-ring checks. Re-fleet testing (the §4
# C-135 adversarial pass) showed widening INJECTION_PATTERNS in place immediately reopened
# B6 as a FALSE FAIL on two clean fixtures whose SOUL.md legitimately QUOTES this exact
# phrase as a worked example in a prompt-injection-defense doc (fixtures/clean_b64_defensive,
# fixtures/clean_b64_signatures) — B6 has no quote/report-frame discriminator the way B64
# (`_b64_reported_or_quoted`) does, and retrofitting that machinery into B6 is a separate,
# larger change than this task's confirmed defect. This pattern is used ONLY by logscan.py's
# class 1, which feeds check_log_threat_hunt (B164) and check_memory_reconsumption_injection
# (B180) — BOTH of which already gate on 2-class corroboration in the SAME file before ever
# surfacing anything above PASS (see `_b180_corroborated` / `_log_hunt_corroborated`), so an
# isolated match here (the "security note quoting an attack" case) still cannot WARN on its
# own. Reuses the SAME bounded-filler shape checks/_content.py's `_B74_TURN_DIRECTIVE_RE`
# already uses for this identical "override imperative" concept (0-3 filler words between
# verb and target noun; bounded quantifier, no catastrophic-backtracking risk) — not a new
# heuristic, just the missing verb/modifier-count coverage, narrowly scoped to the two
# checks whose own corroboration gate already absorbs the quote-vs-live-directive ambiguity.
LOG_SCAN_INJECTION_PATTERNS = INJECTION_PATTERNS + [
    re.compile(
        r"\b(?:ignore|disregard|forget)\b(?:\s+\S+){0,3}?\s+"
        r"(?:instructions?|messages?|orders?|directives?|everything|above|before)\b",
        re.I,
    ),
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
