"""Topic module: config checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import ipaddress
import os
import re
from pathlib import Path
from .. import attest as _attest
from ..catalog import (
    CRITICAL,
    FAIL,
    HIGH,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..collector import (
    BOOTSTRAP_FILES,
    SKILL_DIRS,
    Context,
    dig,
    persistent_env_evidence,
)
from ..safeio import walk_dir_safely
from ..textnorm import normalize_for_scan

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
from ._shared import (
    EXPOSED_BINDS,
    INPUT_TOOL_HINTS,
    LOOPBACK,
    OUTBOUND_TOOL_HINTS,
    SECRET_PATTERNS,
    SENSITIVE_TOOL_HINTS,
    _LEG_KEYS,
    _channels,
    _config_unreadable,
    _enabled_tools,
    _external_input_channels,
    _finding,
    _hint,
    _is_secret_reference,
    _mcp_leg_contributions,
    _norm_group_policy,
    _open_channels,
    _perms_loose,
    _plugins,
    _profile_is_powerful,
    _secret_paths,
    _trifecta_legs,
    _web_fetch_enabled,
    parse_bind_host,
)


CLOUD_PROVIDERS = (
    "openai",
    "anthropic",
    "gpt",
    "claude",
    "google",
    "gemini",
    "grok",
    "mistral",
    "cohere",
)


# ---------- B32: Control-Plane Mutation Reachability ----------
# gateway.tools.allow — explicit re-enablement of a tool over the HTTP gateway.
# gateway.tools.deny  — explicit denial list.
# Control-plane / mutation tool names that are dangerous to expose over HTTP:
_B32_CONTROL_PLANE_TOOLS = frozenset(
    {
        "gateway",
        "cron",
        "sessions_spawn",
        "sessions_send",
        "config.apply",
        "update.run",
    }
)


# C015 mirrors logsafe's additional secret token shapes so the home-file scan catches
# the same secret families the logger already redacts, without ever echoing values.
_C015_EXTRA_SECRET_PATTERNS = [
    re.compile(r"gh[opsur]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{10,}"),
    re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # B-133: pretty-printed JSON quotes the key ("token": "value"), so the shared
    # SECRET_PATTERNS keyword pattern (which expects key[:=]value with no closing
    # quote in between) never matches identity/device-auth.json or devices/paired.json
    # style credential objects. This mirrors that same pattern for the quoted-JSON-key
    # shape, scoped to key names that only carry live credential/grant material
    # (password/secret/api[_-]key/*token/privateKey*) — not a general JSON-value scan.
    # `\w*token` (not just `token`) also covers accessToken/refreshToken-style keys
    # confirmed under identity/device-auth.json's and devices/paired.json's "tokens"
    # object.
    # C-226: value captured in group(1) so _pattern_hits_real_secret can tell a pure
    # SecretRef indirection (e.g. "secretref-env:NAME") apart from a real inline
    # secret sharing the same quoted-JSON-key shape.
    re.compile(
        r'"(?:password|secret|api[_-]?key|\w*token|private[_-]?key\w*)"\s*:\s*"([^"\s]{8,})"',
        re.I,
    ),
]


_C015_MAX_BYTES = 200_000


_C015_MAX_SCAN_FILES = 500


_C015_TEXT_EXTS = {
    ".env",
    ".json",
    ".jsonc",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".md",
    ".txt",
    ".properties",
    ".service",
    ".sh",
    ".envrc",
}


# per-agent sandbox docker flags (FAIL) — same leaf names under agents.list[]
_DANGER_AGENT_SANDBOX = (
    ("dangerouslyAllowContainerNamespaceJoin", "namespace join"),
    ("dangerouslyAllowExternalBindSources", "external bind sources"),
    ("dangerouslyAllowReservedContainerTargets", "reserved container targets"),
)


# ---------- B48: dangerous break-glass overrides (v1.8.0) ----------
# Grounded registry of OpenClaw "dangerously*/allowUnsafe*" break-glass flags, verified
# against the real `openclaw config schema` (2026.6.9). Each is documented there as
# DANGEROUS / "keep disabled". (path, risk label, FAIL?). Active (truthy) = a deliberate
# dangerous override. FAIL = sandbox escape or control-plane auth bypass; WARN = the rest.
_DANGER_FIXED = [
    (
        "agents.defaults.sandbox.docker.dangerouslyAllowContainerNamespaceJoin",
        "sandbox escape: joins another container's namespace",
        True,
    ),
    (
        "agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources",
        "sandbox escape: external host bind sources",
        True,
    ),
    (
        "agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets",
        "sandbox escape: reserved container targets",
        True,
    ),
    (
        "gateway.controlUi.dangerouslyDisableDeviceAuth",
        "control-plane: Control-UI device identity auth disabled",
        True,
    ),
    (
        "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback",
        "control-plane: Host-header origin fallback (CSRF/origin-bypass surface)",
        False,
    ),
    (
        "gateway.controlUi.allowExternalEmbedUrls",
        "control-plane: external embed URLs allowed (SSRF / clickjacking)",
        False,
    ),
    (
        "gateway.allowRealIpFallback",
        "x-real-ip fallback enabled (client-IP spoofing via forged header)",
        False,
    ),
    (
        "hooks.gmail.allowUnsafeExternalContent",
        "less-sanitized external Gmail content into processing (injection surface)",
        False,
    ),
]


# B-231: wildcard-authority detection for commands.ownerAllowFrom (FAIL/CRITICAL, above
# the scoped-list case) and gateway.nodes.pairing.autoApproveCidrs (WARN only -- see the
# NC-11 note below for why this one does NOT escalate to FAIL).
#   * commands.ownerAllowFrom: command-auth-*.js resolveOwnerAuthorizationState() sets
#     ownerAllowAll = hasWildcardAllowFrom(configOwnerAllowFromList), and
#     isWildcardAllowFromEntry() is a literal `entry.trim() === "*"` check -- a bare
#     "*" entry genuinely flips owner authority open to ANY sender. (The schema doc
#     string "'*' is ignored" describes a narrower filter that drops "*" from the
#     *explicit owner ID candidate* list built from the SAME array -- it does not
#     describe the ownerAllowAll gate, which is the actual authorization decision.)
#   * gateway.nodes.pairing.autoApproveCidrs: message-handler-*.js feeds the raw CIDR
#     list straight into isTrustedProxyAddress() -- a literal 0.0.0.0/0 (or ::/0) entry
#     matches every source IP, auto-approving first-time, ZERO-REQUESTED-SCOPE node
#     pairing from anywhere (role/scope/metadata/public-key upgrades still need manual
#     approval -- schema doc string). BUT: the internal schema recon (NC-11) records
#     that OpenClaw's own docs (docs.openclaw.ai/gateway/security "not a vulnerability by
#     design" list) explicitly name "reports treating configured
#     gateway.nodes.pairing.autoApproveCidrs as vulnerability by itself" as OUT OF SCOPE,
#     and the recon's own verdict is blunt: "Do NOT FAIL on gateway.nodes.pairing.* or
#     pairing.autoApproveCidrs." So even the world-open case stays WARN, never FAIL --
#     still surfaced (a 0.0.0.0/0 value is worth a human look), just not grade-capping.
#
# gateway.nodes.allowCommands is DELIBERATELY NOT given the same treatment: grounded
# against node-command-policy-*.js, a literal "*" there is folded into a plain Set of
# exact command-name strings (`allow.has(command)`) with NO wildcard special-case -- no
# real node command is ever named "*", so it is an inert, near-meaningless entry, not a
# broader grant than a scoped list. Escalating it above the existing scoped-list WARN
# would be a fabricated claim; the existing any-non-empty-list WARN (unchanged) already
# covers the real risk (a *named* dangerous command actually being allowed).
def _is_owner_wildcard_allow_from(value) -> bool:
    """True when *value* (``commands.ownerAllowFrom``) contains the literal ``"*"``
    sentinel that flips OpenClaw's owner-authorization gate open to any sender."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return False
    return any(isinstance(e, str) and e.strip() == "*" for e in value)


def _is_world_open_cidr_entry(entry) -> bool:
    """True when *entry* is a literal 'match any address' CIDR (0.0.0.0/0, ::/0) or the
    bare "*" sentinel -- not merely broad, a genuine zero-constraint wildcard. A scoped
    CIDR of any other prefix length (including a wide public range) is NOT flagged
    here — only the unambiguous, unconstrained case."""
    if not isinstance(entry, str):
        return False
    s = entry.strip()
    if not s:
        return False
    if s == "*":
        return True
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return False
    return net.prefixlen == 0


def _has_world_open_cidr(value) -> bool:
    """True when *value* (``gateway.nodes.pairing.autoApproveCidrs``) contains at
    least one world-open entry (see ``_is_world_open_cidr_entry``)."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return False
    return any(_is_world_open_cidr_entry(e) for e in value)


# F-036: for a 2/3 config, name the one missing leg + the concrete field that would
# complete the trifecta. Grounded only in field paths the engine already reads
# (_untrusted_input_channels / INPUT_TOOL_HINTS + web for input; SENSITIVE_TOOL_HINTS,
# ungated exec, credentials/ for sensitive; OUTBOUND_TOOL_HINTS, exec, elevated, web for
# outbound). No new schema invented.
_MISSING_LEG_ACTIVATORS = {
    "untrusted input": (
        "a non-owner channel (channels.<name>.dmPolicy/groupPolicy in "
        "open/allowlist/paired), an input tool (tools.allow: web/email/imap/rss/fetch), "
        "or tools.web.fetch.enabled"
    ),
    "sensitive data": (
        "a private-data tool (tools.allow: fs_read/db/sql/vault/credential), "
        "ungated exec, i.e. tools.exec.mode='full', or a readable credentials/ dir"
    ),
    "outbound actions": (
        "an outbound tool (tools.allow: send/webhook/http_post/fs_write/deploy), "
        "tools.exec, tools.elevated.allowFrom, or tools.web.fetch.enabled"
    ),
}


def _c015_is_codex_plugin_doc_cache(parts: tuple) -> bool:
    """True if *parts* (a resolved path's ``.parts``) sit under a Codex CLI plugin
    doc-cache directory: ``agents/<name>/agent/codex-home/.tmp/plugins/plugins/**``.

    OpenClaw's Codex CLI integration vendors third-party plugins' reference
    documentation into this cache (see ``codex-home/sessions`` in _lifecycle.py for
    the sibling ``agent/codex-home`` shape). Those `.md` files routinely contain
    placeholder examples like ``API_KEY=abc123`` or ``password:"..."`` that are not
    secrets — they were shipped by the plugin author, not created by the user or
    agent — so C015's generic keyword pattern false-positives on them (B-124).
    """
    marker = ("agent", "codex-home", ".tmp", "plugins", "plugins")
    n = len(marker)
    return any(parts[i : i + n] == marker for i in range(len(parts) - n + 1))


# B-244 round 2: a false WARN on the user's REAL ~/.openclaw. ``agent/plugins/<id>/
# catalog.json`` is OpenClaw's own machine-generated plugin model-catalog cache — not
# user-authored — grounded in the dist (not the recon):
#   dist/plugin-model-catalog-*.js  isPluginModelCatalogRelativePath(): the canonical
#     path shape is exactly ``plugins/<pluginId>/catalog.json`` relative to the agent
#     dir; isGeneratedPluginModelCatalog(): the written object's top-level
#     ``generatedBy`` is the literal string ``"openclaw-plugin-model-catalog-v1"``.
#   dist/models-config-*.js  buildPluginCatalogWrites(): writes exactly
#     ``{generatedBy: PLUGIN_MODEL_CATALOG_GENERATED_BY, providers}`` to that path —
#     no other code path writes this file.
#   dist/provider-catalog-*.js: the bundled nvidia provider's catalog entry ships
#     ``apiKey: "NVIDIA_API_KEY"`` verbatim — the env-var NAME, not a secret value —
#     confirmed at runtime by dist/extensions/nvidia/index.js reading
#     ``ctx.env.NVIDIA_API_KEY``.
# So a plugin-catalog ``apiKey`` field commonly holds a bare env-var name, which is
# not a C-226 SecretRef indirection in the narrow ``$NAME``/``${NAME}``/
# ``secretref-env:`` sense _is_secret_reference recognises, so C015's generic
# keyword pattern false-positived on it — same B-124 class as the codex plugin
# doc-cache exclusion above, at a different path.
#
# Deliberately requires BOTH the canonical path shape AND the ``generatedBy``
# content marker (mirroring OpenClaw's own two-part discriminator) rather than
# widening ``_is_secret_reference`` itself: that helper is shared by every other
# secret-detecting check, and a generic "bare SCREAMING_SNAKE_CASE value is a
# reference" rule would blind-spot a real hardcoded password typed in that shape
# anywhere else it is consulted. A file that merely sits at this path but lacks the
# marker (never written by OpenClaw) is still scanned normally.
def _c015_is_generated_plugin_model_catalog(parts: tuple, text: str) -> bool:
    """True if *parts* end in ``agent/plugins/<pluginId>/catalog.json`` and *text*
    parses as JSON carrying OpenClaw's own generated-catalog marker."""
    if len(parts) < 4 or parts[-1] != "catalog.json":
        return False
    if parts[-4] != "agent" or parts[-3] != "plugins":
        return False
    import json as _json

    try:
        parsed = _json.loads(text)
    except ValueError:
        return False
    return isinstance(parsed, dict) and parsed.get("generatedBy") == (
        "openclaw-plugin-model-catalog-v1"
    )


# ---------------------------------------------------------------- Block B
# B-244: the codex-doc-cache / skill-dir exclusions used to run AFTER walk_dir_safely
# already spent the _C015_MAX_SCAN_FILES budget on every raw file it saw — so a large
# excluded subtree (e.g. a vendored codex plugin doc cache) could exhaust the whole
# budget before the walk ever reached real candidate directories that sort later
# alphabetically (workspace/, credentials/, identity/, ...), and the resulting
# WARN/PASS carried no hint that the scan was incomplete. Both exclusions now run
# DURING the walk via `prune_dir`/`keep_file`, so excluded material never consumes the
# budget, and `capped` is threaded through so the caller can disclose a genuine
# truncation instead of reading a partial scan as a complete one.
def _c015_candidate_files(ctx: Context, capped: list | None = None) -> list[Path]:
    skip_roots = [(ctx.home / rel).resolve() for rel in SKILL_DIRS]
    skill_dir_parts = tuple(Path(rel).parts for rel in SKILL_DIRS)

    def _prune(rel_parts: tuple) -> bool:
        if _c015_is_codex_plugin_doc_cache(rel_parts):
            return True
        return any(rel_parts[: len(root)] == root for root in skill_dir_parts)

    def _keep_file(path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if any(
            resolved == root or root in resolved.parents for root in skip_roots if root.exists()
        ):
            return False
        if _c015_is_codex_plugin_doc_cache(resolved.parts):
            return False
        name = path.name.lower()
        return bool(
            path.suffix.lower() in _C015_TEXT_EXTS
            or name in {"openclaw.json", "openclaw.jsonc"}
            or name.startswith("openclaw.json.")
            or name.startswith("openclaw.jsonc.")
            or name.startswith(".env")
            or name in BOOTSTRAP_FILES
        )

    return walk_dir_safely(
        ctx.home,
        max_files=_C015_MAX_SCAN_FILES,
        exclude_pycache=True,
        prune_dir=_prune,
        keep_file=_keep_file,
        capped=capped,
    )


def _pattern_hits_real_secret(patterns, text: str) -> bool:
    """True if any *patterns* match in *text* with a value that is not a pure
    SecretRef indirection (C-226; see ``_is_secret_reference`` in checks/_shared.py).

    Patterns with no capturing group are concrete API-key literal formats
    (sk-ant-.../AKIA.../AIza...) that can never collide with `$NAME`/`${NAME}`/
    legacy-marker syntax, so any match on those fires immediately. Patterns WITH a
    capturing group (the generic ``keyword[:=]value`` shapes) have that captured
    value checked against ``_is_secret_reference`` before counting as a hit — via
    ``finditer`` over every match, not just the first, so a real secret elsewhere in
    the same text still fires even when an earlier match of the SAME pattern is a
    pure reference (a decoy reference in one field must never mask a real secret in
    another field scanned by the same pattern).
    """
    for pat in patterns:
        for m in pat.finditer(text):
            if pat.groups >= 1 and _is_secret_reference(m.group(1)):
                continue
            return True
    return False


def _c015_has_secret(text: str) -> bool:
    return _pattern_hits_real_secret(SECRET_PATTERNS, text) or _pattern_hits_real_secret(
        _C015_EXTRA_SECRET_PATTERNS, text
    )


def _capabilities_attested(ctx: Context) -> bool:
    """True when the user supplied an attestation roster (`--attest`): an OFF
    input/outbound leg can then be trusted instead of flagged 'cannot determine'.
    Unlike a no-op tools.allow entry, this is a real, deliberate declaration."""
    return bool(_attest.attested_agents(getattr(ctx, "attestation", {}) or {}))


def _distance_note(active: list) -> str:
    """F-036: when exactly 2 of 3 legs are active, return a sentence naming the single
    missing leg and the concrete config toggle that would complete 3/3. Returns '' for
    any other count, so it is a no-op for already-3/3 (FAIL) and for <2/3."""
    if len(active) != 2:
        return ""
    missing = next(k for k in _LEG_KEYS if k not in active)
    return (
        f" Two of three lethal-trifecta legs are active ({active[0]} and {active[1]});"
        f" the missing leg is '{missing}'. Avoid enabling"
        f" {_MISSING_LEG_ACTIVATORS[missing]}, which would complete 3/3 — if a third leg"
        f" activates it becomes immediately exploitable: one injected prompt is enough"
        f" to exfiltrate everything."
    )


def _mcp_leg_note(ctx: Context) -> str:
    """B-229 (+B-247): when an MCP server contributes to a trifecta leg, name it in the
    detail text (evidence stays the fixed 3 leg-name keys — see _trifecta_legs/_LEG_KEYS
    — so the MCP server names live here instead)."""
    mcp_legs = _mcp_leg_contributions(ctx.config)
    reasons = (
        mcp_legs["untrusted input"] + mcp_legs["sensitive data"] + mcp_legs["outbound actions"]
    )
    if not reasons:
        return ""
    return " MCP-granted capability: " + "; ".join(reasons) + "."


def _meaningful_tool_surface(ctx: Context) -> bool:
    """Whether the config exposes a RECOGNIZED capability surface (or the user has
    attested the agent's tools), so the A1 legs can be trusted instead of hedged with
    the thin-surface WARN. A no-op tools.allow entry that matches no capability hint
    does NOT count — that was the old PASS-wash (add 'noop' → WARN flips to PASS).

    Note: this is single-agent A1's notion of 'tool config is visible'; cross-agent
    aggregation deliberately stays out (B45/B46/B47 own the multi-agent reassembly)."""
    cfg = ctx.config
    tools = _enabled_tools(cfg)
    if (
        _hint(tools, INPUT_TOOL_HINTS)
        or _hint(tools, SENSITIVE_TOOL_HINTS)
        or _hint(tools, OUTBOUND_TOOL_HINTS)
    ):
        return True
    if _web_fetch_enabled(cfg) or _profile_is_powerful(dig(cfg, "tools.profile")):
        return True
    if bool(dig(cfg, "tools.elevated.allowFrom")):
        return True
    return _capabilities_attested(ctx)


def _model_names(cfg: dict) -> list[str]:
    names = []
    md = dig(cfg, "agents.defaults.model")  # real OpenClaw location
    if isinstance(md, dict):
        if md.get("primary"):
            names.append(str(md["primary"]))
        fb = md.get("fallbacks")
        if isinstance(fb, list):
            names.extend(str(x) for x in fb)
    models = cfg.get("models")
    if isinstance(models, dict):
        for name, m in models.items():
            names.append(str((m.get("provider") if isinstance(m, dict) else "") or name))
    elif isinstance(models, list):
        names.extend(str(m) for m in models)
    return names


# F-040: OpenClaw DOES resolve a default agent at runtime (defaultId ??
# sessionDefaults.defaultAgentId ?? "main") and DOES expose per-agent tool config
# (agents.list[].tools.{alsoAllow, profile, byProvider, toolsBySender}) — this check
# consults neither. A1's legs are computed from the GLOBAL config surface, so a
# multi-agent install's trifecta view stays an aggregate, not any single agent's real
# exposure; reading a specific agent's effective grants here is a deferred enhancement
# (check_agent_separation already offers an attested per-agent alternative today).
# Reframed from an interactive guide.py question (F-039) to this static note: a
# blocking input() prompt would hang under headless CLI invocation (the tool's primary
# usage — see SKILL.md), so this stays a caveat, not an attempt to resolve one agent.
def _multi_agent_note(ctx: Context) -> str:
    agent_list = dig(ctx.config, "agents.list")
    n = len(agent_list) if isinstance(agent_list, list) else 0
    if n <= 1:
        return ""
    return (
        f" Note: config declares {n} agents under agents.list — this trifecta view is"
        f" the aggregated global surface, not any single agent's effective grants. This"
        f" check does not resolve or read a specific agent's own tool config, so if you"
        f" run one named agent, its real exposure may differ from this global reading."
    )


def _peragent_sandbox_evidence(cfg: dict) -> list:
    """Unsafe per-agent sandbox OVERRIDES under agents.list[].sandbox.* (real schema:
    agents.list[N].sandbox.{mode,docker.network,docker.binds,workspaceAccess}). B4 otherwise
    reads only agents.defaults.sandbox, so a named agent that overrides a safe default is
    missed entirely (C-058). Returns attributed evidence strings; empty when none."""
    out = []
    agent_list = dig(cfg, "agents.list")
    if not isinstance(agent_list, list):
        return out
    for a in agent_list:
        if not isinstance(a, dict):
            continue
        sb = a.get("sandbox")
        if not isinstance(sb, dict):
            continue
        name = a.get("name") or "<unnamed>"
        if sb.get("mode") == "off":
            out.append(f"agent '{name}': sandbox.mode=off (exec runs on the host)")
        docker = sb.get("docker") if isinstance(sb.get("docker"), dict) else {}
        if docker.get("network") == "host":
            out.append(f"agent '{name}': sandbox.docker.network=host (no network isolation)")
        binds = docker.get("binds")
        if binds:
            out.append(f"agent '{name}': sandbox.docker.binds exposes host paths")
            binds_str = " ".join(str(b) for b in binds) if isinstance(binds, list) else str(binds)
            if "docker.sock" in binds_str:
                out.append(
                    f"agent '{name}': sandbox.docker.binds mounts docker.sock "
                    "(grants host control to the sandbox — container escape)"
                )
        if sb.get("workspaceAccess") == "rw":
            out.append(
                f"agent '{name}': sandbox.workspaceAccess=rw (agent can write the mounted workspace)"
            )
    return out


# B-233 round 3 (C-135): world-open / near-catch-all PUBLIC CIDRs (e.g. 0.0.0.0/0,
# ::/0, 0.0.0.0/1) are NOT a genuine trust boundary — every source IP matches, so the
# trusted-proxy identity header stays attacker-spoofable by anyone. Grounded against
# dist isTrustedProxyAddress -> isIpInCidr -> ipaddr.parseCIDR (prefix-len 0 matches
# all). A single host always constrains, and so does any PRIVATE range regardless of
# prefix length — a private range (RFC1918 IPv4, or an IPv6 ULA like fc00::/7 / RFC4193)
# is not globally routable, so an external attacker cannot source a connection from it,
# whatever its prefix. Only reject over-broad PUBLIC ranges: IPv4 prefixes shorter than
# /8 and IPv6 prefixes shorter than /16 — short enough that a genuine corp-sized public
# allocation (a /24, a /32 LB IP) still passes, while anything spanning (or nearly
# spanning) the public internet does not.
_MIN_IPV4_PREFIXLEN = 8
_MIN_IPV6_PREFIXLEN = 16

# Do NOT use ``ipaddress.*Network.is_private`` here — its meaning changed across the
# Python versions we support (3.9+). On older interpreters it was computed as
# "network address is private AND broadcast address is private", which makes
# ``0.0.0.0/0`` report is_private=True (0.0.0.0 falls in 0.0.0.0/8 and
# 255.255.255.255 is itself special-cased), and likewise ``0.0.0.0/1`` (broadcast
# 127.255.255.255 is loopback). Trusting it would accept a world-open proxy list as a
# genuine constraint on those interpreters — reinstating the exact spoofable-gateway
# lying-PASS this check exists to prevent. Test the containment explicitly instead, so
# the verdict is identical on every supported Python.
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _net_is_private(net) -> bool:
    """True when *net* is wholly contained in a non-globally-routable range."""
    return any(
        net.version == private.version and net.subnet_of(private)
        for private in _PRIVATE_NETS
    )


def _is_constraining_proxy_entry(entry) -> bool:
    """True when *entry* is a genuine trusted-proxy identifier: a specific host, a
    hostname, a private range (any prefix), or a public CIDR bounded enough to be a
    real trust boundary (not a catch-all)."""
    if not isinstance(entry, str):
        return False
    s = entry.strip()
    if not s or s == "*":
        return False
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        # Not a parseable IP/CIDR (e.g. a hostname) — a specific, non-wildcard
        # identifier is still a genuine constraint.
        return True
    if net.num_addresses == 1 or _net_is_private(net):
        return True
    if net.version == 4 and net.prefixlen < _MIN_IPV4_PREFIXLEN:
        return False
    if net.version == 6 and net.prefixlen < _MIN_IPV6_PREFIXLEN:
        return False
    return True


def _trusted_proxies_ok(value) -> bool:
    """True when *value* (``gateway.trustedProxies``) contains at least one
    genuinely-constraining entry once blank/wildcard/over-broad entries are ignored —
    e.g. ``["10.0.0.5", ""]`` is OK (OpenClaw ignores the blank candidate and still
    enforces 10.0.0.5); ``[]``, ``["*"]``, and ``["0.0.0.0/0"]`` are not."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return False
    return any(_is_constraining_proxy_entry(item) for item in value)


def check_control_plane_mutation(ctx: Context) -> Finding:
    """B32 — Control-plane mutation reachability via gateway.

    FAIL   — gateway.tools.allow re-enables a control-plane tool (config mutation,
             cron scheduling, or cross-session spawn/send exposed over HTTP).
    WARN   — gateway is exposed (non-loopback bind or auth.mode=="none") AND
             control-plane tools are not explicitly denied in gateway.tools.deny.
    PASS   — control-plane tools are denied / not re-enabled.
    UNKNOWN — no gateway config present.
    """
    cfg = ctx.config
    gw = cfg.get("gateway")
    if not isinstance(gw, dict):
        return _finding(
            "B32",
            UNKNOWN,
            "No gateway config — control-plane mutation reachability not applicable.",
            "—",
        )

    gw_tools = gw.get("tools") if isinstance(gw.get("tools"), dict) else {}
    allow_list: list[str] = gw_tools.get("allow") or [] if isinstance(gw_tools, dict) else []
    deny_list: list[str] = gw_tools.get("deny") or [] if isinstance(gw_tools, dict) else []

    if not isinstance(allow_list, list):
        allow_list = []
    if not isinstance(deny_list, list):
        deny_list = []

    allow_set = {str(t).strip() for t in allow_list}
    deny_set = {str(t).strip() for t in deny_list}

    # FAIL: a control-plane tool is explicitly re-enabled in gateway.tools.allow
    re_enabled = sorted(_B32_CONTROL_PLANE_TOOLS & allow_set)
    if re_enabled:
        return _finding(
            "B32",
            FAIL,
            "gateway.tools.allow re-enables control-plane tool(s) over the HTTP "
            "gateway — config mutation / cron / cross-session send is reachable via "
            f"HTTP: {', '.join(re_enabled)}",
            "Remove control-plane tools ("
            + ", ".join(sorted(_B32_CONTROL_PLANE_TOOLS))
            + ") from gateway.tools.allow. Add them to gateway.tools.deny to "
            "explicitly block HTTP access.",
            evidence=re_enabled,
        )

    # WARN: gateway is network-exposed and control-plane tools are not denied
    bind = parse_bind_host(gw.get("bind", ""))
    auth_mode = dig(cfg, "gateway.auth.mode")
    is_exposed = (
        bind and bind not in LOOPBACK and bind not in {"", "loopback"}
    ) or auth_mode == "none"
    cp_not_denied = not (_B32_CONTROL_PLANE_TOOLS & deny_set)

    if is_exposed and cp_not_denied:
        warn_detail = (
            f"Gateway is network-exposed (bind={bind or '?'}, auth.mode={auth_mode!r}) "
            "and control-plane tools are not explicitly in gateway.tools.deny — "
            "an authenticated caller could reach mutation endpoints"
        )
        return _finding(
            "B32",
            WARN,
            warn_detail,
            "Add control-plane tool names ("
            + ", ".join(sorted(_B32_CONTROL_PLANE_TOOLS))
            + ") to gateway.tools.deny to explicitly block HTTP mutation access, "
            "even for authenticated callers.",
            evidence=[warn_detail],
        )

    denied_preview = sorted(_B32_CONTROL_PLANE_TOOLS & deny_set)
    pass_detail = (
        "Control-plane tools are not re-enabled via gateway.tools.allow"
        + (f" and are denied: {', '.join(denied_preview)}" if denied_preview else "")
        + "."
    )
    return _finding(
        "B32",
        PASS,
        pass_detail,
        "Keep control-plane tools out of gateway.tools.allow and "
        "add them to gateway.tools.deny for defence-in-depth.",
    )


def check_controlui_origins(ctx: Context) -> Finding:
    """B56 (NC-4) — Control-UI cross-origin allow-all.

    Grounded (docs.openclaw.ai/gateway/security): for non-loopback Control UI
    deployments `gateway.controlUi.allowedOrigins` is required by default, and
    `["*"]` is "an explicit allow-all browser-origin policy, not a hardened default."
    A wildcard lets any website drive the Control UI (CSRF / origin bypass).

    UNKNOWN — allowedOrigins not set: the default is restrictive, and whether the
              Control UI is exposed beyond loopback is not determinable from config.
    FAIL    — the list contains "*".
    PASS    — an explicit non-wildcard origin allowlist.
    """
    cfg = ctx.config
    origins = dig(cfg, "gateway.controlUi.allowedOrigins")
    if origins is None:
        return _finding(
            "B56",
            UNKNOWN,
            "gateway.controlUi.allowedOrigins is not set — its default is restrictive "
            "(cross-origin denied), and whether the Control UI is exposed beyond loopback "
            "cannot be determined from config alone.",
            "If you expose the Control UI beyond loopback, set "
            "gateway.controlUi.allowedOrigins to an explicit list of trusted origins "
            '(never "*").',
        )
    vals = [str(o) for o in origins] if isinstance(origins, list) else [str(origins)]
    if "*" in vals:
        return _finding(
            "B56",
            FAIL,
            'gateway.controlUi.allowedOrigins contains "*" — an allow-all browser-origin '
            "policy, so any website can drive the Control UI (CSRF / origin bypass).",
            'Replace the "*" wildcard in gateway.controlUi.allowedOrigins with an '
            "explicit list of trusted origins.",
            evidence=['gateway.controlUi.allowedOrigins contains "*" (allow-all browser origins)'],
        )
    return _finding(
        "B56",
        PASS,
        'Control-UI allowed origins are an explicit allowlist (no "*" wildcard).',
        "Keep gateway.controlUi.allowedOrigins to an explicit list of trusted origins.",
    )


# ---------------------------------------------------------------------------
# B-290 (ENV-4): the gateway's auth credential can come from the ENVIRONMENT, not the
# config — and when it does, it supplies the auth MODE as well.
#
# resolveGatewayAuth (auth-resolve-NyPBrh8F.js:19-46) resolves the credential first, then
# derives the mode:
#     else if (authConfig.mode) { mode = authConfig.mode; ... }
#     else if (password)        { mode = "password"; modeSource = "password"; }
#     else if (token)           { mode = "token";    modeSource = "token"; }
# and the credential itself comes from resolveGatewayCredentialsFromValues
# (credentials-DesN22Ui.js:30-42), which reads env.OPENCLAW_GATEWAY_TOKEN and
# env.OPENCLAW_GATEWAY_PASSWORD (:32-33).
#
# The consequence is decisive for B2: server-runtime-config-r5ejxORO.js:78 refuses a
# non-loopback bind unless `hasSharedSecret`, and that shared secret may be entirely
# env-supplied — so a host with `gateway.bind=0.0.0.0` and NO `gateway.auth` block is
# genuinely authenticated, and B2's FAIL on it was a false positive on a correctly
# secured host.
#
# THREE deliberate constraints keep this from becoming a lying PASS:
#
# 1. It is ASYMMETRIC. Presence of an env credential is a POSITIVE signal only; ABSENCE
#    is never read as "no auth". The auditing process's environment is not the gateway
#    service's, so a check that FAILed on env absence would false-positive massively —
#    and B2's existing FAIL when nothing is observable is the CORRECT, deliberate
#    false-negative boundary (Golden Rule #5).
# 2. Evidence must be PERSISTENT and on disk — a systemd unit's Environment=/
#    EnvironmentFile=, or a global runtime dotenv file. `persistent_env_evidence`
#    explicitly does NOT fall back to os.environ: a token exported in the operator's
#    terminal says nothing about a service started months ago by systemd, and letting it
#    clear a CRITICAL finding would key the verdict on the shell the audit happened to be
#    launched from. The ambient-shell case therefore stays a FAIL, not a PASS.
# 3. "env WINS over config" is FALSE for server auth and is not relied on here.
#    resolveGatewayAuth passes tokenPrecedence/passwordPrecedence: "config-first"
#    (auth-resolve-NyPBrh8F.js:23-24), so a configured token beats the env one. The gap
#    is only the config-LESS path, which is exactly what the softening is scoped to.
#
# WHY THIS CANNOT PRODUCE A LYING PASS — the argument that justifies softening a CRITICAL
# check at all. Suppose an observed credential does NOT actually reach the running
# gateway (say it sits only in ~/.config/openclaw/gateway.env, which
# loadGlobalRuntimeDotEnvFiles loads by default, dotenv-global-mWLbBl_z.js:87-100, but
# which resolveGatewayRunDotEnvPaths — pre-bootstrap-8G8HyMEQ.js:55-62, <stateDir>/.env
# plus <configDir>/.env — does not name for `gateway run`). Then `hasSharedSecret` is
# false, and server-runtime-config-r5ejxORO.js:78 throws
# "refusing to bind gateway to <host>:<port> without auth" — an UNCONDITIONAL guard with
# no bypass flag anywhere in the dist. So the gateway does not start.
#
# The two outcomes are therefore: the credential reaches the gateway (it is authenticated,
# and the old FAIL was the false positive), or it does not (there is no listener at all).
# Neither leaves a live, exposed, unauthenticated gateway that this check has been talked
# out of reporting. That is the whole reason the softening is sound; if a future change to
# OpenClaw made that bind guard conditional, this reasoning — and this softening — would
# have to be revisited.
_GATEWAY_ENV_CREDENTIAL_VARS = ("OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_PASSWORD")


def _gateway_env_credential(ctx: Context) -> "tuple[str | None, str | None]":
    """An env-supplied gateway credential observed in a persistent artifact.

    Returns ``(value, source)`` or ``(None, None)``. The value is returned only so the
    caller can test presence — it is a secret and must never reach a message, evidence
    entry, or log (§8).
    """
    for var in _GATEWAY_ENV_CREDENTIAL_VARS:
        value, source = persistent_env_evidence(ctx, var)
        if value is not None and value.strip():
            return value, source or "an environment file"
    return None, None


def check_credential_blast_radius(ctx: Context) -> Finding:
    """B41 — Credential blast-radius assessment.

    Inventories the credential surface exposed in this OpenClaw config and
    assesses whether an attacker with untrusted ingress + outbound capability
    could reach ALL of them in a single compromise.

    WARN    — credentials exist AND the agent has an untrusted-ingress path
              (open channels or an input tool) AND an outbound/exec capability
              — one compromise's blast radius spans every listed provider.
    PASS    — credentials exist but the ingress+outbound combination is not
              present — blast radius is not broadly reachable.
    UNKNOWN — no auth.profiles and no gateway.auth.token found to assess.

    PRIVACY: provider names only are included in findings.  The account/email
    portion of profile keys (after ":") and any token values are NEVER emitted.
    """
    cfg = ctx.config

    # --- inventory credential surface ---
    profiles = dig(cfg, "auth.profiles") or {}
    has_gateway_token = bool(dig(cfg, "gateway.auth.token") or dig(cfg, "gateway.token"))
    # B-290 (ENV-4): the gateway credential does not have to be in the config at all.
    # resolveGatewayCredentialsFromValues (credentials-DesN22Ui.js:32-33) reads
    # OPENCLAW_GATEWAY_TOKEN / OPENCLAW_GATEWAY_PASSWORD straight from the environment, so
    # a config-only inventory undercounts a host whose gateway secret lives in its systemd
    # unit or a global dotenv file. Persistent artifacts only — never os.environ, whose
    # contents belong to the auditing shell rather than to the gateway service.
    _env_gw_token, _env_gw_src = _gateway_env_credential(ctx)
    has_env_gateway_token = _env_gw_token is not None

    # Collect unique provider names from profile keys of the form "<provider>:<account>"
    # CRITICAL: extract only the part BEFORE the first ":" — never the account/email.
    providers: list[str] = []
    if isinstance(profiles, dict):
        seen: set[str] = set()
        for key in profiles:
            provider = str(key).split(":", 1)[0]
            if provider and provider not in seen:
                seen.add(provider)
                providers.append(provider)

    has_credentials = bool(providers) or has_gateway_token or has_env_gateway_token

    if not has_credentials:
        return _finding(
            "B41",
            "UNKNOWN",
            "No credential profiles found to assess.",
            "—",
        )

    # --- assess reachability ---
    tools = _enabled_tools(cfg)
    has_untrusted_ingress = bool(_external_input_channels(cfg)) or _hint(tools, INPUT_TOOL_HINTS)
    has_outbound = _hint(tools, OUTBOUND_TOOL_HINTS) or bool(dig(cfg, "tools.elevated.allowFrom"))
    reachable = has_untrusted_ingress and has_outbound

    any_gateway_token = has_gateway_token or has_env_gateway_token
    n = len(providers) + (1 if any_gateway_token else 0)
    provider_list = ", ".join(sorted(providers))
    gateway_note = " + gateway token" if any_gateway_token else ""

    # Build evidence list — provider names and gateway marker only, never emails/values.
    # B-290: the env-supplied case records only WHERE the credential is configured, never
    # its value; `_gateway_env_credential` returns the value solely so presence can be
    # tested, and it is never placed in a message or in evidence (§8).
    evidence: list[str] = []
    if providers:
        evidence.append(f"providers: {provider_list}")
    if has_gateway_token:
        evidence.append("gateway-token: present")
    elif has_env_gateway_token:
        evidence.append(f"gateway-token: present, supplied by {_env_gw_src}")

    if reachable:
        detail = (
            f"{n} provider credential(s) (providers: {provider_list}){gateway_note} "
            "are reachable by an agent with untrusted ingress and outbound tools — "
            "one compromise's blast radius spans all of them. Use least-privilege "
            "scopes, isolate high-value profiles, and keep them rotatable."
        )
        return _finding(
            "B41",
            WARN,
            detail,
            "Use least-privilege OAuth scopes for each provider profile, isolate "
            "high-value credentials into dedicated agents with no untrusted-ingress "
            "channels, and ensure all credentials are rotatable. Remove open channel "
            "policies (dmPolicy/groupPolicy) or outbound tools where not needed.",
            evidence,
        )

    detail = (
        f"{n} credential profile(s) present; no untrusted-ingress + outbound path "
        "makes them broadly reachable."
    )
    return _finding(
        "B41",
        PASS,
        detail,
        "Keep channels on allowlist policies and avoid adding outbound tools "
        "alongside credential profiles without careful scope restrictions.",
        evidence,
    )


def check_dangerous_overrides(ctx: Context) -> Finding:
    """B48 — flag OpenClaw 'dangerously*/allowUnsafe*' break-glass toggles that are ACTIVE.

    These are explicit opt-in overrides OpenClaw documents as 'keep disabled'. Absent /
    false = nothing flagged (so a default config is a clean PASS — zero false positives).
    FAIL/CRITICAL when a wildcard-authority entry is active (commands.ownerAllowFrom or
    gateway.nodes.pairing.autoApproveCidrs contains an unscoped "*"/0.0.0.0/0/::/0 —
    B-231); FAIL/HIGH when a sandbox-escape or control-plane-auth-disable flag is on;
    WARN for the rest (including a *scoped*, non-wildcard override of the same fields).
    """
    unreadable = _config_unreadable("B48", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    fails: list[str] = []
    warns: list[str] = []
    # B-231: wildcard-authority entries — genuinely worse than the scoped-list case
    # below (an explicit, grounded "any sender"/"any IP" grant, not merely "a break-
    # glass toggle is on") — tracked separately so the verdict can escalate FAIL/
    # CRITICAL above the plain FAIL/HIGH the rest of this check returns.
    wildcard_fails: list[str] = []

    for path, label, is_fail in _DANGER_FIXED:
        if dig(cfg, path):
            (fails if is_fail else warns).append(f"{path} — {label}")

    owner_allow_from = dig(cfg, "commands.ownerAllowFrom")
    if _is_owner_wildcard_allow_from(owner_allow_from):
        wildcard_fails.append(
            "commands.ownerAllowFrom contains '*' — owner-only command authority is "
            "granted to ANY sender on any channel (not a scoped allowlist)"
        )

    auto_approve_cidrs = dig(cfg, "gateway.nodes.pairing.autoApproveCidrs")
    if _has_world_open_cidr(auto_approve_cidrs):
        # NC-11 (recon): OpenClaw's own "not a vulnerability by design" list names this
        # exact field — stays WARN, never escalates to FAIL/wildcard_fails.
        warns.append(
            "gateway.nodes.pairing.autoApproveCidrs contains a world-open CIDR "
            "(0.0.0.0/0 / ::/0 / '*') — first-time, zero-scope node-device pairing is "
            "auto-approved from ANY IP address (role/scope/metadata/key-upgrade pairing "
            "still requires manual approval)"
        )

    nc = dig(cfg, "gateway.nodes.allowCommands")
    if isinstance(nc, list) and nc:
        # B-231: a literal "*" entry here is NOT given the wildcard-authority
        # treatment above — grounded against node-command-policy-*.js, allowCommands
        # is folded into a plain Set of exact command-name strings with no wildcard
        # special-case (`allow.has(command)`), so "*" never matches a real node
        # command and is strictly inert, not a broader grant than a named command.
        warns.append(
            "gateway.nodes.allowCommands — extra node.invoke commands enabled "
            "(beyond gateway defaults; possible RCE surface)"
        )

    agent_list = dig(cfg, "agents.list")
    if isinstance(agent_list, list):
        for i, agent in enumerate(agent_list):
            if not isinstance(agent, dict):
                continue
            for flag, lbl in _DANGER_AGENT_SANDBOX:
                if dig(agent, f"sandbox.docker.{flag}"):
                    fails.append(f"agents.list[{i}].sandbox.docker.{flag} — sandbox escape: {lbl}")

    for name, c in _channels(cfg).items():
        if not isinstance(c, dict):
            continue
        # Check the provider object AND per-account sub-objects: these break-glass flags
        # can be set per-account (channels.<p>.accounts.<id>.*), mirroring B30 (B-060).
        nodes = [c]
        accounts = c.get("accounts")
        if isinstance(accounts, dict):
            nodes.extend(v for v in accounts.values() if isinstance(v, dict))
        if any(n.get("dangerouslyDisableSignatureValidation") for n in nodes):
            warns.append(
                f"channels.{name}.dangerouslyDisableSignatureValidation — "
                "webhook signature validation disabled (spoofable untrusted input)"
            )
        if any(n.get("dangerouslyAllowInheritedWebhookPath") for n in nodes):
            warns.append(
                f"channels.{name}.dangerouslyAllowInheritedWebhookPath — "
                "inherited webhook path accepted"
            )
        if any(dig(n, "network.dangerouslyAllowPrivateNetwork") for n in nodes):
            warns.append(
                f"channels.{name}.network.dangerouslyAllowPrivateNetwork — "
                "private-network access from this channel (SSRF)"
            )

    mappings = dig(cfg, "hooks.mappings")
    if isinstance(mappings, list):
        for i, m in enumerate(mappings):
            if isinstance(m, dict) and m.get("allowUnsafeExternalContent"):
                warns.append(
                    f"hooks.mappings[{i}].allowUnsafeExternalContent — "
                    "less-sanitized external content (injection surface)"
                )

    for name, p in _plugins(cfg).items():
        if isinstance(p, dict) and dig(p, "config.allowPrivateNetwork"):
            warns.append(
                f"plugins.entries.{name}.config.allowPrivateNetwork — "
                "plugin private-network access (SSRF)"
            )

    if wildcard_fails:
        # B-231: severity ABOVE the scoped-list / other-break-glass FAIL — an explicit
        # wildcard grant of owner authority or auto-approved device pairing to anyone
        # is a step beyond a single break-glass toggle being left on.
        return _finding(
            "B48",
            FAIL,
            "Wildcard-authority override(s) grant owner command authority or device "
            "auto-pairing to ANY sender/IP (see evidence).",
            "Replace the wildcard with an explicit, scoped allowlist — e.g. "
            "commands.ownerAllowFrom to your own channel-native ID(s), or "
            "gateway.nodes.pairing.autoApproveCidrs to a specific host/private range. "
            "Never leave either as an unscoped wildcard.",
            evidence=wildcard_fails + fails + warns,
            severity=CRITICAL,
        )
    if fails:
        return _finding(
            "B48",
            FAIL,
            "Dangerous break-glass override(s) that enable sandbox escape or control-plane "
            "auth bypass are active (see evidence).",
            "Disable these unless a specific, temporary break-glass need requires one — each "
            "opens sandbox escape or control-plane authentication bypass. Restore the safe "
            "default (set to false / remove).",
            evidence=fails + warns,
        )
    if warns:
        return _finding(
            "B48",
            WARN,
            "One or more dangerous break-glass override flag(s) are enabled (see evidence).",
            "Review each — OpenClaw documents these as 'keep disabled' break-glass toggles. "
            "Turn off any you do not actively need.",
            evidence=warns,
        )
    return _finding(
        "B48",
        PASS,
        "No dangerous break-glass override flags enabled.",
        "Keep these break-glass toggles off unless an incident temporarily requires one.",
        pass_confidence="verified",
    )


# B171 (B-235): the privileged, opt-in commands.* subflags this check treats as the
# "high-power in-chat surface" -- bash (raw host shell), config (read/write the running
# config from chat, incl. secrets/gateway auth), mcp (rewrite mcp.servers -- point the
# agent at an attacker-controlled MCP server), plugins (toggle plugin enablement). All
# four default to false/unset in the dist CommandsSchema (docs/research/
# openclaw-schema-recon.md §18) -- an absent/default config never trips this check.
# `debug` (runtime-only overrides) is folded in at WARN-only weight -- narrower blast
# radius than the four above, never drives a FAIL on its own.
# `restart` is DELIBERATELY EXCLUDED: it `.default(true)` in the dist schema, so treating
# it as a danger-enabled signal would false-FAIL every default config (Golden Rule #5).
_B171_HIGH_POWER = {
    "bash": "run arbitrary host shell commands (raw RCE)",
    "config": "read/write the running OpenClaw config from chat (incl. secrets/gateway auth)",
    "mcp": "rewrite mcp.servers from chat (point the agent at an attacker-controlled MCP server)",
    "plugins": "toggle plugin enablement from chat",
}
_B171_CRITICAL_COMMANDS = frozenset({"bash", "config"})
_B171_WARN_ONLY_COMMAND = "debug"
_B171_WARN_ONLY_LABEL = "runtime-only config overrides from chat"


# B171 (B-235 FP fix, grounded 2026-07-18): a channel's own
# dmPolicy/groupPolicy=='open' does NOT by itself mean every reachable sender also gets
# the in-chat commands.* surface. dm-policy-shared-*.js resolveOpenDmAllowlistAccess's own
# doc comment: "dmPolicy=open, where '*' means fully open and a configured allowlist still
# restricts the accepted sender set" -- a non-wildcard channel-/account-level `allowFrom`
# on an "open" dmPolicy blocks every other sender at ingress (reason
# dm_policy_not_allowlisted), so nobody but the listed sender(s) ever reaches the command
# layer at all. For groups, message ingress genuinely is unconditional once
# groupPolicy=='open' (group-access-*.js evaluateMatchedGroupAccessForPolicy), but
# resolveDmGroupAccessWithCommandGate still feeds the channel's own `allowFrom` AND
# `groupAllowFrom` into resolveControlCommandGate as separate command authorizers -- a
# configured, non-wildcard list there is real (if not exhaustively provider-verified)
# evidence that the privileged command itself is scoped, not open to "ANY sender". Treating
# `_open_channels()` (dmPolicy/groupPolicy=='open' alone, shared with B2's different
# "anyone can command" question) as sufficient evidence of unauthenticated command exposure
# false-FAILed exactly this shape. Fix: for THIS leg only, a channel counts as open only
# when the relevant sender list is itself absent/empty or wildcard; a scoped list falls
# through to the WARN leg below instead of asserting "ANY sender" with a FAIL/CRITICAL.
def _b171_scoped_list(value) -> bool:
    """True when *value* is a non-empty allow-from list that does NOT contain the "*"
    wildcard -- i.e. it genuinely narrows the accepted sender set rather than leaving it
    wide open."""
    return isinstance(value, list) and len(value) > 0 and not _is_owner_wildcard_allow_from(value)


def _b171_open_channels(cfg: dict) -> list[str]:
    """B171's own narrower notion of "open" for the no-commands-gate FAIL leg.

    Excludes a channel/account whose own dmPolicy=='open' is scoped by a non-wildcard
    channel-level `allowFrom`, or whose groupPolicy=='open' is scoped by a non-wildcard
    `groupAllowFrom`/`allowFrom` -- see the module comment above for the dist grounding.
    Deliberately duplicated rather than parameterizing the shared `_open_channels()` (B2):
    B2 asks a different question (gateway auth / "anyone can command") that is out of
    scope for this fix.
    """
    out: list[str] = []
    for name, c in _channels(cfg).items():
        if not isinstance(c, dict) or c.get("enabled") is False:
            continue
        nodes = [c] + list((c.get("accounts") or {}).values())
        for node in nodes:
            if not isinstance(node, dict):
                continue
            dm_open = node.get("dmPolicy") == "open" and not _b171_scoped_list(
                node.get("allowFrom")
            )
            # B-283 (a): normalize a Feishu channel's "allowall" alias, which Feishu's
            # GroupPolicySchema transforms to "open" (channel-PR3XHV0V.js:89-93) — without
            # this a Feishu channel written as groupPolicy:"allowall" ran wide open but
            # read as unrecognised. Feishu-scoped only: every other channel schema in the
            # dist rejects "allowall" outright, so it cannot appear on them in a config
            # that actually loaded — see _norm_group_policy's docstring for the grounding.
            group_open = _norm_group_policy(name, node.get("groupPolicy")) == "open" and not (
                _b171_scoped_list(node.get("groupAllowFrom"))
                or _b171_scoped_list(node.get("allowFrom"))
            )
            if dm_open or group_open:
                out.append(name)
                break
    return out


def _b171_wildcard_allow_from_evidence(cfg: dict) -> list[str]:
    """Wildcard-open commands.* gate entries.

    Reuses the B-231 wildcard-authority detector (``_is_owner_wildcard_allow_from``) over
    BOTH ``commands.ownerAllowFrom`` and every per-provider/global list inside
    ``commands.allowFrom`` (a record keyed by provider id or the literal ``"*"`` for "all
    providers" -- ``resolveCommandsAllowFromList`` in the dist's ``command-auth-*.js``,
    grounded 2026-07-18).
    """
    out: list[str] = []
    owner_allow_from = dig(cfg, "commands.ownerAllowFrom")
    if _is_owner_wildcard_allow_from(owner_allow_from):
        out.append("commands.ownerAllowFrom contains '*'")
    allow_from = dig(cfg, "commands.allowFrom")
    if isinstance(allow_from, dict):
        for key, value in allow_from.items():
            if _is_owner_wildcard_allow_from(value):
                out.append(f"commands.allowFrom[{key!r}] contains '*'")
    return out


def check_privileged_commands_exposure(ctx: Context) -> Finding:
    """B171 (B-235) — commands.bash/config/mcp/plugins in-chat privileged-command surface.

    OpenClaw's root ``commands.*`` block exposes raw shell (``bash``), full config
    read/write (``config``), MCP-server-registry rewrite (``mcp``), and plugin-enablement
    toggling (``plugins``) as IN-CHAT commands, gated only by their own owner/elevated
    allow-from mechanism (``commands.ownerAllowFrom`` / ``commands.allowFrom`` /
    ``commands.useAccessGroups``) — entirely separate from B2's channel dmPolicy/
    groupPolicy gate and B3's agent-tool allowlist. Before this check, ClawSecCheck had
    ZERO references to commands.bash/config/mcp/plugins (B-235): a config with all four
    enabled plus an open channel scored identically to the closed-channel baseline.

    FAIL/CRITICAL — ``bash`` or ``config`` is enabled and the gate is wildcard-open
        (``commands.ownerAllowFrom`` or an ``commands.allowFrom`` list contains ``"*"``),
        or is completely unconfigured on a channel with an open dmPolicy/groupPolicy —
        either way ANY chat sender who reaches that channel gets raw shell or full
        config-mutation.
    FAIL/HIGH — ``mcp`` or ``plugins`` is enabled under the same wildcard/open-channel-
        with-no-gate condition (still unauthenticated, narrower blast radius).
    WARN — a privileged command (incl. ``debug``) is enabled with no
        ownerAllowFrom/allowFrom configured, on a channel that is NOT open (allowlist/
        pairing/disabled still constrains who reaches the command layer, but no
        owner-scoped allowlist narrows it further — see docs/research §18); or
        ``commands.useAccessGroups`` is explicitly ``false`` alongside an enabled
        privileged command.
    UNKNOWN — a privileged command is enabled with no gate configured and no channels are
        configured at all (reachability genuinely can't be determined), or openclaw.json
        is unreadable.
    PASS — no privileged commands.* subflag is enabled, or every enabled one has a
        scoped, non-wildcard ownerAllowFrom/allowFrom.
    """
    unreadable = _config_unreadable("B171", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config

    # Literal dig() calls (not an f-string in a loop) so the §4 schema-grounding AST
    # scanner (tests/test_schema_grounding.py) can see each path statically.
    _commands_flags = {
        "bash": bool(dig(cfg, "commands.bash")),
        "config": bool(dig(cfg, "commands.config")),
        "mcp": bool(dig(cfg, "commands.mcp")),
        "plugins": bool(dig(cfg, "commands.plugins")),
        "debug": bool(dig(cfg, "commands.debug")),
    }
    enabled_high = [k for k in _B171_HIGH_POWER if _commands_flags[k]]
    debug_enabled = _commands_flags[_B171_WARN_ONLY_COMMAND]
    if not enabled_high and not debug_enabled:
        return _finding(
            "B171",
            PASS,
            "No privileged in-chat commands.* surface (bash/config/mcp/plugins/debug) is "
            "enabled.",
            "Keep these disabled unless you specifically need in-chat privileged control; "
            "if you do enable one, scope commands.ownerAllowFrom/allowFrom tightly.",
            pass_confidence="verified",
        )

    enabled_all = enabled_high + ([_B171_WARN_ONLY_COMMAND] if debug_enabled else [])
    descriptions = [
        f"commands.{k} enabled ({_B171_HIGH_POWER.get(k, _B171_WARN_ONLY_LABEL)})"
        for k in enabled_all
    ]

    wildcard_ev = _b171_wildcard_allow_from_evidence(cfg)
    if wildcard_ev:
        severity = CRITICAL if enabled_high and set(enabled_high) & _B171_CRITICAL_COMMANDS else HIGH
        return _finding(
            "B171",
            FAIL,
            "Privileged in-chat command(s) enabled with a wildcard-open owner/allow-from "
            "gate — ANY chat sender who reaches the gate is authorized: "
            + "; ".join(descriptions),
            "Replace the wildcard with an explicit, scoped allowlist — e.g. "
            "commands.ownerAllowFrom / commands.allowFrom to your own channel-native "
            "ID(s). Never leave either as an unscoped '*'.",
            evidence=descriptions + wildcard_ev,
            severity=severity,
        )

    owner_allow_from = dig(cfg, "commands.ownerAllowFrom")
    allow_from = dig(cfg, "commands.allowFrom")
    gate_configured = bool(owner_allow_from) or bool(allow_from)
    open_ch = _b171_open_channels(cfg)

    if not gate_configured and open_ch:
        severity = CRITICAL if enabled_high and set(enabled_high) & _B171_CRITICAL_COMMANDS else HIGH
        return _finding(
            "B171",
            FAIL,
            "Privileged in-chat command(s) enabled with NO owner/allow-from gate "
            "configured, on a channel with an open dm/group policy — ANY sender on that "
            "channel is authorized (an empty commands.ownerAllowFrom/allowFrom removes "
            "the owner-only check; see docs/research §18): " + "; ".join(descriptions),
            "Set commands.ownerAllowFrom or commands.allowFrom to your own channel-native "
            "ID(s), and/or set the open channel's dmPolicy/groupPolicy to 'allowlist' "
            "(see B2).",
            evidence=descriptions + [f"open channel(s): {', '.join(open_ch)}"],
            severity=severity,
        )

    if not gate_configured and not _channels(cfg):
        return _finding(
            "B171",
            UNKNOWN,
            "Privileged in-chat command(s) enabled with no owner/allow-from gate "
            "configured, and no channels are configured to assess reachability through: "
            + "; ".join(descriptions),
            "Set commands.ownerAllowFrom or commands.allowFrom to your own channel-native "
            "ID(s) before connecting any channel.",
            evidence=descriptions,
        )

    warn_ev = list(descriptions)
    if not gate_configured:
        warn_ev.append(
            "commands.ownerAllowFrom/allowFrom not configured — any sender the connected, "
            "non-open channel(s) already authorize is treated as command-owner"
        )
    if dig(cfg, "commands.useAccessGroups") is False:
        warn_ev.append(
            "commands.useAccessGroups=false — access-group enforcement layer disabled"
        )
    if warn_ev != descriptions:
        return _finding(
            "B171",
            WARN,
            "Privileged in-chat command(s) enabled with a broad or partially-configured "
            "gate: " + "; ".join(warn_ev),
            "Scope commands.ownerAllowFrom/allowFrom to your own channel-native ID(s), and "
            "keep commands.useAccessGroups enabled.",
            evidence=warn_ev,
        )

    return _finding(
        "B171",
        PASS,
        "Privileged in-chat command(s) enabled with a scoped owner/allow-from gate: "
        + "; ".join(descriptions),
        "Keep commands.ownerAllowFrom/allowFrom scoped to your own channel-native ID(s).",
        evidence=descriptions,
        pass_confidence="verified",
    )
# ---------- B173 (B-237): security.audit.suppressions self-blinds the native audit ----------
# Grounded: zod-schema-O9ml_nmo.js SecuritySchema — security.audit.suppressions is an array
# of { checkId: string().min(1), titleIncludes?, detailIncludes?, reason? } (all `.strict()`).
# audit-UjVvFwCi.js's runSecurityAudit() applies these via applySecurityAuditSuppressions()
# BEFORE returning `openclaw security audit --json`'s output — so a suppressed finding never
# reaches native.py's fold-in either (native.py execs that exact command and only ever sees
# the post-suppression `findings` array). A non-empty list is not itself a vulnerability —
# it is how an operator knowingly accepts a specific, reviewed native finding — so this stays
# WARN/disclosure by default. It escalates to FAIL only when a suppressed checkId is one this
# project has grounded, directly against audit-UjVvFwCi.js, as UNCONDITIONALLY
# severity:"critical" there (a literal `severity: "critical"` in the source, never a
# `cond ? "critical" : "warn"` ternary whose true branch we cannot re-derive statically without
# duplicating OpenClaw's own runtime-exposure logic — and a wrong guess would be exactly the
# false-FAIL Golden Rule #5 forbids) AND that literal-critical finding fires on an actual
# DEFECT with actionable remediation — not merely on a feature being enabled at all. Literal
# `severity: "critical"` in the native source is necessary but not sufficient: B-237 found
# `gateway.trusted_proxy_auth` is literally critical yet fires unconditionally whenever
# `gateway.auth.mode === "trusted-proxy"` (audit-UjVvFwCi.js:245-254), with a remediation that
# is a verification checklist ("Verify: (1)... (2)... (3)...", see the trusted-proxy setup
# guide), not a config change. There is no underlying condition a correctly-configured
# trusted-proxy operator (e.g. behind Pomerium/Caddy/nginx SSO) can fix to clear it — it is
# OpenClaw's own documented enterprise auth mode, and every operator running it will see this
# finding forever. Escalating a knowing, reviewed suppression of that notice to FAIL/CRITICAL
# is a false positive (an operator correctly using a supported feature gets told to abandon
# it) — so `gateway.trusted_proxy_auth` is deliberately excluded here and stays WARN-only via
# the disclosure path below. The three checkIds that fire on REAL trusted-proxy
# misconfiguration remain in the set and keep escalating: `gateway.trusted_proxy_no_proxies`
# ("All requests will be rejected" — empty trustedProxies), `gateway.trusted_proxy_no_user_header`
# (missing userHeader), and the generic `gateway.bind_no_auth` catch-all when trusted-proxy
# auth itself is misconfigured badly enough to not count as a shared secret. Deliberately
# scoped to the core `runSecurityAudit` orchestrator in audit-UjVvFwCi.js only; checkIds from
# its channel-security/deep-probe extension modules are covered by the disclosure WARN but
# never escalate here.
_NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS = frozenset({
    "gateway.bind_no_auth",
    "gateway.loopback_no_auth",
    "gateway.control_ui.allowed_origins_required",
    "gateway.tailscale_funnel",
    "gateway.control_ui.device_auth_disabled",
    "gateway.trusted_proxy_no_proxies",
    "gateway.trusted_proxy_no_user_header",
    "fs.state_dir.perms_world_writable",
    "fs.config.perms_writable",
    "fs.config.perms_world_readable",
})


def _is_native_unconditional_critical_check_id(check_id: str) -> bool:
    """True for a grounded always-critical native-audit checkId — an exact match from
    ``_NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS``, or the templated
    ``tools.elevated.allowFrom.<provider>.wildcard`` shape (audit-UjVvFwCi.js
    collectElevatedFindings — the provider name varies, the ``.wildcard`` suffix and
    unconditional ``severity: "critical"`` do not)."""
    return (
        check_id in _NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS
        or (
            check_id.startswith("tools.elevated.allowFrom.")
            and check_id.endswith(".wildcard")
        )
    )


def check_audit_suppressions(ctx: Context) -> Finding:
    """B173 (B-237) — ``security.audit.suppressions`` permanently silences specific findings
    of OpenClaw's OWN built-in ``openclaw security audit`` (and therefore native.py's
    fold-in of it too), with nothing previously disclosing that a suppression list exists.

    Absent/empty list → PASS (nothing suppressed). Non-empty → WARN, naming the suppressed
    checkId(s) — a suppression is a knowingly-accepted native finding, not itself a
    vulnerability. FAIL/CRITICAL only when a suppressed checkId is one this project has
    grounded as unconditionally critical in the native audit source (see
    ``_NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS``) — a config write that permanently quiets one
    of those is positive evidence, not a guess.
    """
    unreadable = _config_unreadable("B173", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    suppressions = dig(cfg, "security.audit.suppressions")
    if not isinstance(suppressions, list) or not suppressions:
        return _finding(
            "B173",
            PASS,
            "No security.audit.suppressions configured — OpenClaw's built-in "
            "`openclaw security audit` runs unfiltered.",
            "Keep security.audit.suppressions empty unless you are knowingly accepting a "
            "specific, reviewed native-audit finding.",
            pass_confidence="verified",
        )

    critical_hits: list[str] = []
    disclosed: list[str] = []
    for i, entry in enumerate(suppressions):
        if not isinstance(entry, dict):
            continue
        check_id = entry.get("checkId")
        if not isinstance(check_id, str) or not check_id.strip():
            continue
        check_id = check_id.strip()
        label = f"security.audit.suppressions[{i}]: checkId={check_id!r}"
        reason = entry.get("reason")
        if isinstance(reason, str) and reason.strip():
            # Disclose that a reason was recorded without echoing the operator-authored
            # free-text value itself into evidence/reports.
            label += " (reason given)"
        disclosed.append(label)
        if _is_native_unconditional_critical_check_id(check_id):
            critical_hits.append(check_id)

    if not disclosed:
        # Non-empty list but no entry had a recognizable checkId (malformed hand-edit —
        # OpenClaw's own schema requires checkId, so a real config always has one). Still
        # worth a look, but there is nothing concrete to name — WARN, not a guess FAIL.
        return _finding(
            "B173",
            WARN,
            "security.audit.suppressions is non-empty but no entry has a usable checkId.",
            "Check security.audit.suppressions for malformed entries — each needs a "
            "non-empty checkId string.",
            evidence=[f"security.audit.suppressions has {len(suppressions)} entrie(s)"],
        )

    if critical_hits:
        return _finding(
            "B173",
            FAIL,
            "security.audit.suppressions silences a native-audit check this project has "
            "grounded as unconditionally critical: "
            f"{', '.join(sorted(set(critical_hits)))}.",
            "Remove the suppression for the critical checkId(s) above and fix the underlying "
            "condition instead — do not permanently silence a critical finding of OpenClaw's "
            "own built-in security audit.",
            evidence=disclosed,
            severity=CRITICAL,
        )
    return _finding(
        "B173",
        WARN,
        f"security.audit.suppressions has {len(disclosed)} configured entry/entries — "
        "OpenClaw's built-in `openclaw security audit` (and ClawSecCheck's fold-in of it) "
        "will never show these findings again.",
        "Review each suppressed checkId periodically and remove it once the accepted risk "
        "no longer applies. A non-empty list is not itself a vulnerability, only a "
        "transparency signal.",
        evidence=disclosed,
    )


def check_hook_template_content(ctx: Context) -> Finding:
    """B169 (B-231 sub-item 2) — hooks.mappings[].messageTemplate / textTemplate content scan.

    A hook mapping's ``messageTemplate``/``textTemplate`` splices an untrusted external
    webhook payload into text the agent will read as part of a live turn (B48 only checks
    the separate ``allowUnsafeExternalContent`` opt-in flag; the template string itself was
    never routed through the content ring). This check CONSUMES the existing content-ring
    detectors from ``checks/_content.py`` -- it does not add new detection logic of its own:

    - ``_B64_HIGH_CONFIDENCE_RE`` + ``_b64_classify`` (B64 instruction-hierarchy override,
      e.g. "ignore all previous instructions").
    - ``_b63_scan`` (B63 silent-instruction / secrecy-framed directive).
    - ``_CLICKFIX_REMOTE_FETCH_RE`` + ``_clickfix_trusted_installer`` (the same remote-fetch/
      pipe-to-shell install-directive pattern B167 already reuses for appServer.command).

    FAIL    — a template string matches a high-confidence override/install directive.
    WARN    — a template string matches a weaker/ambiguous signal.
    UNKNOWN — openclaw.json present but unparseable/unreadable.
    PASS    — hooks.mappings has no messageTemplate/textTemplate, or none match.
    """
    unreadable = _config_unreadable("B169", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    mappings = dig(cfg, "hooks.mappings")
    fail_ev: list[str] = []
    warn_ev: list[str] = []
    if isinstance(mappings, list):
        for i, m in enumerate(mappings):
            if not isinstance(m, dict):
                continue
            for field_name in ("messageTemplate", "textTemplate"):
                text = m.get(field_name)
                if not isinstance(text, str) or not text.strip():
                    continue
                source = f"hooks.mappings[{i}].{field_name}"
                norm = normalize_for_scan(text)
                fr = _fence_ranges(norm)
                cr = [(mm.start(), mm.end()) for mm in _B58_HTML_COMMENT_RE.finditer(norm)]

                # B-231: a STRONG, unambiguous anchor gates whether a B63 secrecy hit may
                # grade-cap on this hook-template surface. A bare secrecy phrase + a bare
                # _EXFIL_RE keyword ("post") is AMBIGUOUS (a benign relayed digest that
                # withholds a detail vs a covert-exfil directive), so per project doctrine
                # (§5 — ambiguous suppression → WARN, not FAIL) it stays WARN unless a B64
                # instruction-override, a curl|bash pipe-to-shell install directive, or a
                # credential-path co-occurs in the same template field. (The former
                # base64-blob anchor was dropped in Wave-2 round-4 — a blob can't be told
                # apart from a URL/path/hash in short text; see _content.py.)
                field_has_strong = False

                # B64: instruction-hierarchy override ("ignore all previous instructions").
                for mm in _B64_HIGH_CONFIDENCE_RE.finditer(norm):
                    disp = _b64_classify(norm, mm.start(), mm.end(), fr, cr)
                    if disp == "skip":
                        continue
                    snippet = mm.group().strip()
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    if disp == "warn":
                        warn_ev.append(f'{source}: instruction-override "{snippet}"')
                    else:
                        fail_ev.append(f'{source}: instruction-override "{snippet}"')
                        field_has_strong = True

                # ClickFix-style remote-fetch/pipe-to-shell install directive (same
                # detector B167 reuses for plugins.entries.<name>.config.appServer.command).
                cf = _CLICKFIX_REMOTE_FETCH_RE.search(norm)
                if cf and not _clickfix_trusted_installer(cf.group(0)):
                    snippet = cf.group(0).strip()
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    fail_ev.append(f'{source}: remote-fetch/pipe-to-shell install directive "{snippet}"')
                    field_has_strong = True

                if _secrecy_credential_or_encoding_anchor(norm):
                    field_has_strong = True

                # B63: silent-instruction / secrecy-framed directive. B-231: on this
                # hook-template surface a bare secrecy phrase + bare outbound verb ("post")
                # is ambiguous with a benign relayed digest that withholds one detail, so it
                # only FAILs when a strong anchor co-occurs; otherwise it surfaces as WARN
                # (no grade cap).
                for snippet, is_anchored in _b63_scan(norm, fr):
                    label = f'{source}: silent-instruction directive "{snippet}"'
                    if is_anchored and field_has_strong:
                        fail_ev.append(label)
                    else:
                        warn_ev.append(label)

    if fail_ev:
        ev_summary = "; ".join(fail_ev[:4])
        extra = f" (+{len(fail_ev) - 4} more)" if len(fail_ev) > 4 else ""
        return _finding(
            "B169",
            FAIL,
            "A hooks.mappings[] messageTemplate/textTemplate carries an embedded "
            "instruction-override or install directive: " + ev_summary + extra,
            "Remove the embedded directive from the template, and treat inbound webhook "
            "payload fields spliced into the template as untrusted content — never let a "
            "hook template carry a live instruction to the agent.",
            fail_ev + warn_ev,
        )
    if warn_ev:
        ev_summary = "; ".join(warn_ev[:4])
        extra = f" (+{len(warn_ev) - 4} more)" if len(warn_ev) > 4 else ""
        return _finding(
            "B169",
            WARN,
            "A hooks.mappings[] messageTemplate/textTemplate matches a weaker/ambiguous "
            "directive signal: " + ev_summary + extra,
            "Review the flagged template. If it merely documents or quotes an example "
            "payload, no action is needed; if it is a live directive, remove it.",
            warn_ev,
        )
    return _finding(
        "B169",
        PASS,
        "No hooks.mappings[] messageTemplate/textTemplate carries an embedded directive.",
        "Keep hook templates free of instruction-override or install-directive content.",
        pass_confidence="verified",
    )


def check_hooks_enable_toggles(ctx: Context) -> Finding:
    """B179 (B-250): inventory of hooks.enabled / hooks.internal(.load.extraDirs)
    enable-toggles.

    Grounded against the installed dist (2026.7.1): the native audit's own inventory
    line labels its `hooks.enabled` reading "hooks.webhooks" for display purposes only
    (`audit.nondeep.runtime-C3y1Q5Fi.js:205-212` — `webhooksEnabled = cfg.hooks?.enabled
    === true`); there is no separate `hooks.webhooks` config key in
    `schema-DRyO1XBt.js`. The real internal-hooks surface is `hooks.internal.enabled`,
    `.entries`, `.installs`, and `.load.extraDirs` (`schema-DRyO1XBt.js:1063-1068`,
    mirrored by `hasConfiguredInternalHooks()` in `configured-pV8SaeM2.js:20-28`). Before
    this check, clawseccheck had zero references to any of these five fields (B169 only
    content-scans `hooks.mappings[].messageTemplate`/`textTemplate` — the template TEXT,
    not these enable-toggles).

    `hooks.internal.load.extraDirs` gets the sharpest wording: it names extra
    directories OpenClaw searches for internal hook MODULES at startup — a startup
    arbitrary-module-load / persistence surface, not merely an enable flag.

    WARN    — any of hooks.enabled, hooks.internal.enabled, an enabled
              hooks.internal.entries[] item, a hooks.internal.installs[] record, or a
              non-blank hooks.internal.load.extraDirs entry is configured (see evidence).
    UNKNOWN — openclaw.json present but unparseable/unreadable.
    PASS    — none of the above is configured (the common case — the real fleet config
              has no `hooks` key at all).
    """
    unreadable = _config_unreadable("B179", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    evidence: list[str] = []
    extra_dirs_hit = False

    if dig(cfg, "hooks.enabled") is True:
        evidence.append(
            "hooks.enabled — inbound webhook hooks endpoint + mapping execution "
            "pipeline enabled"
        )

    internal_enabled = dig(cfg, "hooks.internal.enabled")
    if internal_enabled is True:
        evidence.append(
            "hooks.internal.enabled — internal hook runtime enabled (all configured "
            "internal hooks may load)"
        )

    # Mirror hasConfiguredInternalHooks()'s own short-circuit (configured-pV8SaeM2.js:
    # "if (!internal || internal.enabled === false) return false"): an EXPLICIT
    # hooks.internal.enabled: false disables internal-hook loading outright, so stale
    # entries/installs/extraDirs left under a disabled block are not a live load
    # surface and must not WARN.
    if internal_enabled is not False:
        entries = dig(cfg, "hooks.internal.entries")
        if isinstance(entries, dict):
            enabled_names = sorted(
                name
                for name, entry in entries.items()
                if isinstance(name, str)
                and not (isinstance(entry, dict) and entry.get("enabled") is False)
            )
            if enabled_names:
                shown = ", ".join(enabled_names[:6])
                more = f" (+{len(enabled_names) - 6} more)" if len(enabled_names) > 6 else ""
                plural = "y" if len(enabled_names) == 1 else "ies"
                evidence.append(f"hooks.internal.entries — enabled entr{plural}: {shown}{more}")

        installs = dig(cfg, "hooks.internal.installs")
        if isinstance(installs, dict) and installs:
            evidence.append(
                f"hooks.internal.installs — {len(installs)} internal hook install(s) registered"
            )

        extra_dirs = dig(cfg, "hooks.internal.load.extraDirs")
        if isinstance(extra_dirs, list):
            named = sorted({d for d in extra_dirs if isinstance(d, str) and d.strip()})
            if named:
                extra_dirs_hit = True
                shown = ", ".join(named[:6])
                more = f" (+{len(named) - 6} more)" if len(named) > 6 else ""
                plural = "y" if len(named) == 1 else "ies"
                evidence.append(
                    "hooks.internal.load.extraDirs — additional startup module-load "
                    f"director{plural} searched for internal hooks: {shown}{more}"
                )

    if not evidence:
        return _finding(
            "B179",
            PASS,
            "hooks.enabled is not set and no hooks.internal load surface (enabled "
            "flag, an enabled entry, an install record, or load.extraDirs) is "
            "configured.",
            "No action needed. If hooks are enabled later, review "
            "hooks.internal.load.extraDirs closely — OpenClaw loads and executes any "
            "internal hook module it discovers in those directories at startup.",
            pass_confidence="verified",
        )

    ev_summary = "; ".join(evidence)
    if extra_dirs_hit:
        detail = (
            "hooks.internal.load.extraDirs configures additional startup module-load "
            "directories for internal hooks — a code-exec/persistence surface: "
            + ev_summary
        )
        fix = (
            "Review every directory in hooks.internal.load.extraDirs: OpenClaw loads "
            "and executes any internal hook module discovered there at startup. Keep "
            "the list minimal, point it only at directories you control and have "
            "reviewed, and treat it like any other trusted-code load path."
        )
    else:
        detail = (
            "Inbound webhook hooks and/or internal hook loading is enabled: " + ev_summary
        )
        fix = (
            "This is a visibility inventory, not a misconfiguration finding — "
            "hooks.enabled and hooks.internal are legitimate automation features. "
            "Confirm the enabled surface is intentional; hooks.token (B1), "
            "hooks.mappings[].allowUnsafeExternalContent (B48), and hook-template "
            "content scanning (B169) already cover the higher-risk adjacent settings."
        )
    return _finding("B179", WARN, detail, fix, evidence)


def check_gateway(ctx: Context) -> Finding:
    cfg = ctx.config
    ev = []
    # B-020: build the remediation from the conditions that ACTUALLY fired, one clause per
    # trigger, so the fix names the real problem (e.g. allowInsecureAuth alone -> "Disable
    # gateway.controlUi.allowInsecureAuth", not generic boilerplate the config already meets).
    # Clauses join with "; " so each fired condition contributes one fragment.
    fixes = []
    # B-290: clauses that are worth DISCLOSING but are not proof of a misconfiguration.
    # They never escalate the status; they only add a WARN when nothing FAIL-worthy fired.
    soft_ev: list[str] = []
    bind = parse_bind_host(dig(cfg, "gateway.bind", ""))
    auth = dig(cfg, "gateway.auth.mode")
    if bind and bind not in LOOPBACK and auth in (None, "none"):
        # B-290 (ENV-4): `auth is None` — i.e. gateway.auth.mode absent or null — is
        # EXACTLY the condition under which resolveGatewayAuth derives the mode from an
        # env-resolved credential instead (auth-resolve-NyPBrh8F.js:34-42, `else if
        # (authConfig.mode)`). So when a persistent artifact carries
        # OPENCLAW_GATEWAY_TOKEN/_PASSWORD, this bind is authenticated and the FAIL was a
        # false positive on a correctly secured host.
        #
        # `auth == "none"` is deliberately NOT softened: "none" is truthy in the dist, so
        # the mode stays "none", `hasSharedSecret` stays false, and
        # server-runtime-config-r5ejxORO.js:78 refuses the non-loopback bind outright.
        # An explicit mode=none is a decision, not an omission.
        #
        # NOT softened either: a config-supplied `gateway.auth.token` with no `mode`,
        # which the dist also treats as authenticated. That is a real adjacent
        # false-positive FAIL, but it is a config-only path with no env component, so it
        # is out of ENV-4's scope and left for separate triage rather than widened into
        # here on the way past.
        _env_cred, _env_cred_src = (
            _gateway_env_credential(ctx) if auth is None else (None, None)
        )
        # C-135 (independent adversarial pass on B-290): presence alone is NOT enough to
        # clear this FAIL, and softening on truthiness made the scanner lie. The bind guard
        # that justifies the softening at all — server-runtime-config-r5ejxORO.js:66,78 —
        # tests `hasSharedSecret`, which is satisfied by a ONE-CHARACTER token: mode derives
        # to "token", the throw does not fire, and the gateway binds to 0.0.0.0 and listens.
        # `assertGatewayAuthConfigured` (auth-B27MflKU.js:183-197) rejects only a MISSING
        # credential; no minimum length exists anywhere in the dist. So "authenticated, or
        # no listener at all" holds for the credential-ABSENT case but NOT for the
        # credential-WEAK case, which is a live, world-reachable gateway one guess deep.
        #
        # The bar is the one this very check already applies to a config token below
        # (`0 < len(token) < 24`) — identical posture must not get opposite verdicts
        # depending on where the credential is stored. It also realigns us with OpenClaw's
        # own audit, which fires `gateway.token_too_short` on exactly this input
        # (audit-UjVvFwCi.js:239, `auth.mode === "token" && token.length < 24`) — being
        # weaker than the vendor's audit on a CRITICAL check is not a defensible position.
        #
        # Only the LENGTH of the credential is read. The value never reaches evidence, a
        # message, a fix string, or a log (§8).
        _env_cred_strong = _env_cred is not None and len(_env_cred.strip()) >= 24
        if _env_cred is not None and _env_cred_strong:
            soft_ev.append(
                f"gateway.bind={bind} is non-loopback and the config sets no "
                f"gateway.auth.mode, but a gateway credential is supplied by the "
                f"environment ({_env_cred_src}) — OpenClaw derives auth.mode from it, so "
                "the gateway is authenticated. Reported as disclosure, not exposure"
            )
            fixes.append(
                "No action required if the environment-supplied gateway credential is "
                "intentional. Setting gateway.auth.mode explicitly makes the posture "
                "readable from the config alone"
            )
        elif _env_cred is not None:
            ev.append(
                f"gateway.bind={bind} is non-loopback and the only gateway credential is "
                f"an environment-supplied secret shorter than 24 chars ({_env_cred_src}) — "
                "OpenClaw binds and listens on it, so the gateway is world-reachable "
                "behind a guessable secret"
            )
            fixes.append(
                "Replace the environment-supplied gateway credential with one of at least "
                "24 characters, or bind the gateway to loopback"
            )
        else:
            ev.append(f"gateway.bind={bind or '?'} exposed with auth.mode={auth}")
            fixes.append(
                "Bind the gateway to loopback or require auth "
                "(gateway.auth.mode=token, token >=24 chars)"
            )
    # gateway.http.no_auth does NOT exist in OpenClaw schema (auth is enforced by default)
    if dig(cfg, "gateway.controlUi.allowInsecureAuth"):
        ev.append("gateway.controlUi.allowInsecureAuth enabled")
        fixes.append("Disable gateway.controlUi.allowInsecureAuth")
    # Real field: gateway.tailscale.mode (string "funnel"/"serve"/"off")
    # gateway.tailscale.funnel boolean does NOT exist in OpenClaw schema
    if dig(cfg, "gateway.tailscale.mode") == "funnel":
        ev.append("gateway.tailscale.mode=funnel exposes the gateway publicly")
        fixes.append("Set gateway.tailscale.mode to 'serve' or 'off' (not 'funnel')")
    # gateway.auth_no_rate_limit does NOT exist in OpenClaw schema
    # Rate limiting is configured via gateway.auth.rateLimit (optional object)
    token = dig(cfg, "gateway.auth.token") or dig(cfg, "gateway.token")
    if isinstance(token, str) and 0 < len(token) < 24:
        ev.append("gateway auth token shorter than 24 chars")
        fixes.append("Use a gateway auth token of at least 24 characters")
    # B-233: trusted-proxy auth is only as strong as the identity header it trusts. On a
    # non-loopback bind, without requiredHeaders/allowUsers genuinely constraining that
    # header, any direct network caller can self-declare identity — a spoofable full
    # auth bypass, not "authenticated". BUT (grounded: dist auth-B27MflKU.js
    # authorizeTrustedProxy / authorizeGatewayConnectCore, gated by
    # net-*.js isTrustedProxyAddress) OpenClaw itself rejects the connection before ever
    # reading the identity header when the caller's SOURCE IP is not in a configured
    # gateway.trustedProxies allow-list — so a genuine (non-wildcard) trustedProxies
    # list is an equally valid identity constraint; only the total absence of ALL THREE
    # (requiredHeaders, allowUsers, trustedProxies) is the real spoof surface.
    if (
        auth == "trusted-proxy"
        and bind
        and bind not in LOOPBACK
        and not dig(cfg, "gateway.auth.trustedProxy.requiredHeaders")
        and not dig(cfg, "gateway.auth.trustedProxy.allowUsers")
        and not _trusted_proxies_ok(dig(cfg, "gateway.trustedProxies"))
    ):
        user_header = dig(cfg, "gateway.auth.trustedProxy.userHeader") or "x-forwarded-user"
        ev.append(
            f"gateway.auth.mode=trusted-proxy on non-loopback bind={bind} with no "
            f"requiredHeaders/allowUsers/trustedProxies configured — the {user_header!r} "
            "identity header is attacker-spoofable"
        )
        fixes.append(
            "Configure gateway.auth.trustedProxy.requiredHeaders and/or allowUsers, or "
            "gateway.trustedProxies, to constrain identity, or bind the gateway to loopback"
        )
    open_ch = _open_channels(cfg)
    for name in open_ch:
        ev.append(f"channel '{name}' has an open dm/group policy (anyone can command it)")
    if open_ch:
        fixes.append("Set every open channel's dmPolicy/groupPolicy to 'allowlist'")
    if ev:
        _insecure_auth_only = ev == ["gateway.controlUi.allowInsecureAuth enabled"]
        sev = WARN if _insecure_auth_only else FAIL
        # soft_ev rides along in the detail so the report still says WHY the exposed bind
        # was not counted, but it can never raise the status — every escalation still
        # comes from `ev`.
        return _finding("B2", sev, "; ".join(ev + soft_ev), "; ".join(fixes), ev + soft_ev)
    if soft_ev:
        return _finding("B2", WARN, "; ".join(soft_ev), "; ".join(fixes), soft_ev)
    if not cfg:
        return _finding(
            "B2",
            UNKNOWN,
            "No config loaded — cannot assess gateway.",
            "Run on the host with ~/.openclaw present.",
        )
    # C-182: `if not cfg:` above only catches a WHOLE-CONFIG-empty state. A
    # present-but-malformed `gateway` value (e.g. `"gateway": null`, a list, a
    # number) makes every dig(cfg, "gateway...") lookup degrade to its default
    # ("absent") without raising — indistinguishable from "gateway key simply
    # not present" — and falls through to a confident PASS below. A field that
    # genuinely can't be assessed must read UNKNOWN, not a fabricated PASS.
    gw_present = isinstance(cfg, dict) and "gateway" in cfg
    gw = cfg.get("gateway") if gw_present else None
    if gw_present and not isinstance(gw, dict):
        return _finding(
            "B2",
            UNKNOWN,
            "gateway config value is present but malformed (not an object) — cannot assess.",
            "Fix `gateway` to be a config object, or remove the key.",
        )
    # B-233: this PASS is reached only when none of the ev-conditions above fired — i.e.
    # either the bind is loopback, or the bind is exposed but auth genuinely covers it
    # (token/password/trusted-proxy with identity constraints). Never claim "loopback"
    # for a bind that plainly isn't.
    if bind and bind not in LOOPBACK:
        return _finding(
            "B2",
            PASS,
            f"Gateway is authenticated (gateway.auth.mode={auth}) on a non-loopback bind "
            "and channels are not open.",
            "Keep auth on and channels on allowlist.",
        )
    return _finding(
        "B2",
        PASS,
        "Gateway is loopback/authenticated and channels are not open.",
        "Keep auth on and channels on allowlist.",
    )


def check_gateway_rate_limit(ctx: Context) -> Finding:
    """B80 — gateway auth without rate limiting on a non-loopback bind.

    Grounded (recon: gateway.auth.rateLimit). A token/password-authenticated gateway
    reachable beyond loopback with no rate limiting lets an attacker brute-force the
    credential.

    PASS — auth is not token/password, OR the bind is loopback, OR gateway.auth.rateLimit
           is configured.
    WARN — token/password auth AND non-loopback bind AND no gateway.auth.rateLimit.
    """
    unreadable = _config_unreadable("B80", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    mode = dig(cfg, "gateway.auth.mode")
    if mode not in ("token", "password"):
        return _finding(
            "B80",
            PASS,
            "Gateway auth does not rely on a brute-forceable token/password secret "
            "(or is not configured).",
            "If you enable token/password gateway auth on an exposed bind, configure "
            "gateway.auth.rateLimit to throttle credential guessing.",
        )
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    if bind_host in LOOPBACK:
        return _finding(
            "B80",
            PASS,
            "Gateway is bound to loopback, so the auth endpoint is not exposed to remote "
            "brute-force.",
            "Keep the gateway on loopback, or add gateway.auth.rateLimit before exposing it.",
        )
    if dig(cfg, "gateway.auth.rateLimit"):
        return _finding(
            "B80",
            PASS,
            "Gateway auth has rate limiting configured (gateway.auth.rateLimit).",
            "Keep gateway.auth.rateLimit aligned with the exposure of the gateway.",
        )
    return _finding(
        "B80",
        WARN,
        "Gateway uses token/password auth on a non-loopback bind but has no "
        "gateway.auth.rateLimit — the auth endpoint can be brute-forced.",
        "Configure gateway.auth.rateLimit (max attempts / window) to throttle credential "
        "guessing, or bind the gateway to loopback.",
        evidence=[
            f"gateway.auth.mode={mode!r}",
            f"gateway.bind host={bind_host!r} (non-loopback)",
            "gateway.auth.rateLimit is not set",
        ],
    )


def check_least_privilege(ctx: Context) -> Finding:
    cfg = ctx.config
    allow = dig(cfg, "tools.elevated.allowFrom")
    hard = []  # clear over-privilege -> FAIL
    soft = []  # missing allowlist hygiene -> WARN
    # Real shape: tools.elevated.allowFrom is a dict keyed by provider name
    # e.g. { "discord": ["user-id-123"], "telegram": ["*"] }
    # (not a flat list or bare "*" string in real OpenClaw configs)
    if isinstance(allow, dict):
        total_entries = sum(len(v) if isinstance(v, list) else 1 for v in allow.values())
        wildcard_providers = [
            p for p, v in allow.items() if v == "*" or (isinstance(v, list) and "*" in v)
        ]
        if wildcard_providers:
            hard.append(
                "tools.elevated.allowFrom grants '*' (every sender) for providers: "
                + ", ".join(wildcard_providers)
            )
        elif total_entries > 25:
            hard.append(
                f"tools.elevated.allowFrom has {total_entries} total entries across "
                f"{len(allow)} provider(s) (too broad)"
            )
    elif allow == "*":
        # Legacy / hypothetical flat wildcard
        hard.append("tools.elevated.allowFrom = '*' (every sender can use elevated tools)")
    elif isinstance(allow, list) and "*" in allow:
        hard.append("tools.elevated.allowFrom contains '*' (flat list form — every sender)")
    elif isinstance(allow, list) and len(allow) > 25:
        hard.append(f"tools.elevated.allowFrom has {len(allow)} entries (too broad)")
    profile = str(dig(cfg, "tools.profile", "")).lower()
    if profile and profile != "minimal":
        # a broader profile (e.g. "coding") is a least-privilege preference, not a hole —
        # WARN, never a hard FAIL (the native audit does not fail it either).
        soft.append(f"tools.profile='{dig(cfg, 'tools.profile')}' is broader than minimal")
    if dig(cfg, "plugins.allow") is None and _plugins(cfg):
        soft.append("no plugins.allow reachability allowlist (plugins.entries present)")
    # plugins.tools_reachable_policy does NOT exist in OpenClaw schema — removed
    fixes = []
    if hard:
        fixes.append("Restrict tools.elevated.allowFrom to specific provider/sender IDs (no '*')")
    if profile and profile != "minimal":
        fixes.append("Set tools.profile to 'minimal'")
    if dig(cfg, "plugins.allow") is None and _plugins(cfg):
        fixes.append("Define a plugins.allow array to limit which plugins may load")

    if hard:
        return _finding("B3", FAIL, "; ".join(hard + soft), "; ".join(fixes), hard + soft)
    if soft:
        return _finding("B3", WARN, "; ".join(soft), "; ".join(fixes), soft)
    # B-065: hedge to UNKNOWN when the privilege surface is ENTIRELY undeclared,
    # mirroring A1's _meaningful_tool_surface thin-surface guard (B-033 gold standard).
    # NARROW gate: only when EVERY privilege signal is absent — no elevated grant, no
    # tool profile, no plugins, no RECOGNIZED tool surface, and no --attest roster. A
    # declared-but-clean surface (small allowFrom, minimal profile, allow-listed plugins,
    # a recognized tools.allow entry) still PASSes. _capabilities_attested is redundant
    # with the tail of _meaningful_tool_surface but kept for self-documenting intent.
    surface_undeclared = (
        dig(cfg, "tools.elevated.allowFrom") is None
        and dig(cfg, "tools.profile") is None
        and not _plugins(cfg)
        and not _meaningful_tool_surface(ctx)
        and not _capabilities_attested(ctx)
    )
    if surface_undeclared:
        return _finding(
            "B3",
            UNKNOWN,
            "Least-privilege posture is indeterminate: the config declares no elevated-tool "
            "grant, tool profile, plugins, or recognized tool surface (runtime-granted tools "
            "are not visible to a static config audit), so there is nothing to verify as "
            "constrained.",
            "Declare the agent's tool surface (tools.profile / tools.allow / "
            "tools.elevated.allowFrom) or pass --attest so least privilege can be assessed.",
        )
    # B-042: PASS verifies a CONFIG-level least-privilege posture only (no over-broad
    # elevated grant, no profile/plugin escalation). It must NOT claim runtime "tool
    # reachability is constrained" — runtime-granted tools (message/exec_command/web_*)
    # are not in openclaw.json.
    return _finding(
        "B3",
        PASS,
        "No over-broad elevated-tool grant or profile/plugin escalation in "
        "config (runtime-granted tools are not visible to static config audit).",
        "Keep least privilege: explicit allowlists only.",
    )


def check_local_first(ctx: Context) -> Finding:
    names = _model_names(ctx.config)
    if not names:
        return _finding("B12", UNKNOWN, "No model config found.", "—")
    cloud = [n for n in names if any(c in n.lower() for c in CLOUD_PROVIDERS)]
    if cloud:
        return _finding(
            "B12",
            WARN,
            f"Cloud model(s) in use: {', '.join(sorted(set(cloud)))}.",
            "For maximum privacy prefer a local model; if cloud is required, ensure no "
            "sensitive data is sent to it. (Informational — low severity.)",
        )
    return _finding("B12", PASS, "Models are local-first.", "Keep data local where possible.")


def check_proxy_header_forging(ctx: Context) -> Finding:
    """C032 — advisory UNKNOWN when real-IP fallback lacks trusted proxy allow-list.

    If ``gateway.allowRealIpFallback`` is enabled, OpenClaw will parse forwarded
    client-address headers. Without an explicit proxy allow-list, that logic can be
    abused when an untrusted component injects spoofed values. The OpenClaw schema
    does not guarantee a single field-name shape for proxy trust across versions,
    so this check is intentionally conservative: it raises UNKNOWN rather than
    FAIL when fallback is enabled but trusted-proxy data is absent/invalid.
    """
    unreadable = _config_unreadable("C032", ctx)
    if unreadable is not None:
        return unreadable
    fallback = dig(ctx.config, "gateway.allowRealIpFallback")
    if not fallback:
        return _finding(
            "C032",
            PASS,
            "Real-IP fallback is not enabled, so proxied source headers are not broadly trusted.",
            "Enable proxy-source trust only when a reverse-proxy chain is in place and "
            "trusted proxy source values are explicit.",
        )
    trusted = dig(ctx.config, "gateway.trustedProxies")
    if _trusted_proxies_ok(trusted):
        return _finding(
            "C032",
            PASS,
            "Real-IP fallback has an explicit trusted-proxy allow-list configured.",
            "Keep ``gateway.trustedProxies`` aligned with the actual trusted proxy chain.",
            evidence=[f"gateway.trustedProxies={trusted!r}"],
        )
    detail = (
        "gateway.allowRealIpFallback is enabled but gateway.trustedProxies "
        "is not configured with an explicit allow-list."
    )
    return _finding(
        "C032",
        UNKNOWN,
        detail,
        "Constrain gateway.allowRealIpFallback to a declared proxy chain by setting"
        " gateway.trustedProxies to proxy IPs/CIDRs that are actually permitted.",
        evidence=[f"gateway.allowRealIpFallback is enabled; trustedProxies={trusted!r}"],
    )


def check_sandbox(ctx: Context) -> Finding:
    cfg = ctx.config
    # Real path: agents.defaults.sandbox.mode (values: "off", "non-main", "all")
    # The bare sandbox.* top-level path does NOT exist in OpenClaw schema
    mode = dig(cfg, "agents.defaults.sandbox.mode")
    ev = []
    if mode == "off":
        ev.append("agents.defaults.sandbox.mode is off (exec runs on the host)")
    # Real path: agents.defaults.sandbox.docker.network (not sandbox.network_mode)
    docker_network = dig(cfg, "agents.defaults.sandbox.docker.network")
    if docker_network == "host":
        ev.append("agents.defaults.sandbox.docker.network=host (no network isolation)")
    # Real path: agents.defaults.sandbox.docker.binds (not sandbox.bind_mount)
    binds = dig(cfg, "agents.defaults.sandbox.docker.binds")
    if binds:
        ev.append("agents.defaults.sandbox.docker.binds exposes host paths")
        # docker.sock bind hands full host control to the sandbox (container escape vector)
        if isinstance(binds, list):
            binds_str = " ".join(str(b) for b in binds)
        else:
            binds_str = str(binds)
        if "docker.sock" in binds_str:
            ev.append(
                "agents.defaults.sandbox.docker.binds mounts docker.sock — "
                "grants host control to the sandbox (container escape)"
            )
    # Real path: agents.defaults.sandbox.workspaceAccess ("none"/"ro"/"rw")
    workspace_access = dig(cfg, "agents.defaults.sandbox.workspaceAccess")
    if workspace_access == "rw":
        ev.append(
            "agents.defaults.sandbox.workspaceAccess=rw (agent can write the mounted workspace)"
        )
    # Per-agent sandbox overrides are explicit, unambiguous misconfig — a named agent can
    # re-expose the host even when agents.defaults.sandbox is safe (C-058). Report it as a
    # definite FAIL ahead of the defaults-only WARN/UNKNOWN/phantom branches.
    agent_ev = _peragent_sandbox_evidence(cfg)
    if agent_ev:
        return _finding(
            "B4",
            FAIL,
            "one or more named agents override agents.defaults.sandbox with unsafe "
            "settings (see evidence) — a per-agent override can re-expose the host even "
            "when the defaults are safe.",
            "Remove the unsafe per-agent sandbox overrides under agents.list[].sandbox "
            "(set mode to 'non-main'/'all', docker.network to 'bridge', workspaceAccess "
            "to 'none'/'ro', and drop host and docker.sock binds), or rely on "
            "agents.defaults.sandbox.",
            ev + agent_ev,
        )
    # NOTE: the agents.defaults.sandbox.docker.dangerouslyAllow* break-glass trio is
    # intentionally NOT checked here — check_dangerous_overrides (B48) already owns the
    # whole "dangerously*" registry (gateway + per-agent), so detecting it here too would
    # double-report the same finding. See the docker/sandbox section of the internal
    # openclaw-schema-recon.md.
    # sandbox.seccomp_profile / sandbox.apparmor_profile do NOT exist as first-class config
    # fields; Docker backend relies on Docker's own profile mechanism
    # A present-but-phantom top-level `sandbox` block (sandbox.mode=... etc.) is NOT a real
    # OpenClaw key — sandbox config lives under agents.defaults.sandbox. Say so explicitly so
    # a user who configured the wrong key doesn't think the tool missed it (C-057).
    phantom_sandbox = isinstance(cfg.get("sandbox"), dict)
    _move_fix = (
        "Move the sandbox settings under agents.defaults.sandbox "
        "(e.g. set agents.defaults.sandbox.mode to 'non-main' or 'all')."
    )
    # B-024: a populated defaults-evidence list is a definite FAIL (docker.sock bind,
    # network=host, workspaceAccess=rw, mode=off). Surface it BEFORE the softer "mode not
    # set" WARN below, so a real container-escape signal is not masked just because
    # agents.defaults.sandbox.mode happens to be unset while exec is enabled.
    if ev:
        fixes = []
        if mode == "off":
            fixes.append("Set agents.defaults.sandbox.mode to 'non-main' or 'all'")
        if docker_network == "host":
            fixes.append("Set agents.defaults.sandbox.docker.network to 'bridge' (not 'host')")
        if binds:
            if isinstance(binds, list):
                binds_str = " ".join(str(b) for b in binds)
            else:
                binds_str = str(binds)
            if "docker.sock" in binds_str:
                fixes.append(
                    "Remove the docker.sock bind from docker.binds (it grants host control to the sandbox)"
                )
            fixes.append("Remove broad host path binds from docker.binds")
        if workspace_access == "rw":
            fixes.append("Set workspaceAccess to 'none' or 'ro'")

        return _finding("B4", FAIL, "; ".join(ev), "; ".join(fixes), ev)
    if mode is None and "exec" in _enabled_tools(cfg):
        if phantom_sandbox:
            return _finding(
                "B4",
                WARN,
                "a top-level 'sandbox' block is set, but that is not a real "
                "OpenClaw config key (sandbox settings live under "
                "agents.defaults.sandbox), so it is ignored and exec tooling "
                "likely runs on the host.",
                _move_fix,
            )
        return _finding(
            "B4",
            WARN,
            "exec tooling present but agents.defaults.sandbox.mode not set — "
            "likely host execution.",
            "Set agents.defaults.sandbox.mode (e.g. 'non-main' or 'all') and "
            "configure agents.defaults.sandbox.docker for network isolation.",
        )
    if mode is None:
        if phantom_sandbox:
            return _finding(
                "B4",
                UNKNOWN,
                "a top-level 'sandbox' block is set, but that is not a real "
                "OpenClaw config key (sandbox settings live under "
                "agents.defaults.sandbox); no exec tools are configured, so it "
                "is not currently exploitable.",
                _move_fix,
            )
        return _finding("B4", UNKNOWN, "No exec tools and no sandbox config — not applicable.", "—")
    return _finding("B4", PASS, "Execution is sandboxed.", "Keep sandbox mode enabled.")


def check_secrets(ctx: Context) -> Finding:
    cfg = ctx.config
    ev = []
    # gateway.auth.password / hooks.token in config are flagged by the native audit too
    # (gateway.password top-level does not exist; password lives at gateway.auth.password)
    if dig(cfg, "gateway.auth.password"):
        ev.append("gateway.auth.password set in config")
    if dig(cfg, "hooks.token"):
        ev.append("hooks.token set in config")
    # secrets anywhere in the config are only a real risk if the file is readable by others
    secret_paths = _secret_paths(cfg)
    if secret_paths and _perms_loose(ctx):
        ev.append(
            f"{len(secret_paths)} secret(s) in config and openclaw.json is "
            f"group/world-readable ({oct(ctx.config_mode)[-3:]})"
        )
    # secrets hardcoded into bootstrap files (always wrong — injected into the prompt)
    for fname, text in ctx.bootstrap.items():
        if _pattern_hits_real_secret(SECRET_PATTERNS, text):
            ev.append(f"secret-like string in {fname}")
    if ev:
        return _finding(
            "B1",
            FAIL,
            "; ".join(ev),
            "Move secrets to `openclaw secrets configure` / env vars, never into "
            "bootstrap files; `chmod 600 ~/.openclaw/openclaw.json` and `chmod 700 "
            "~/.openclaw` so config-stored tokens are not readable by others.",
            ev,
        )
    # B-228: openclaw.json present but unparseable/unreadable — bootstrap-file secrets
    # (checked above, config-independent) still legitimately FAILed if present, but a
    # clean verdict at this point is only trustworthy if the config itself was actually
    # read. Guard the terminal PASS only (not the whole function) so the bootstrap scan
    # above keeps working normally under a broken openclaw.json.
    unreadable = _config_unreadable("B1", ctx)
    if unreadable is not None:
        return unreadable
    note = ""
    pc = "verified"
    if secret_paths:
        note = f" ({len(secret_paths)} token(s) in config, but file perms are tight)"
        pc = "no_signal"
    return _finding(
        "B1",
        PASS,
        f"No exposed plaintext secrets.{note}",
        "Keep secrets out of bootstrap files and keep config perms at 600.",
        pass_confidence=pc,
    )


def check_secrets_at_rest_home(ctx: Context) -> Finding:
    """C015 — read-only scan for plaintext secret-shaped values in the OpenClaw home.

    This complements B1: B1 owns openclaw.json/bootstrap semantics and permissions, while
    C015 inventories any user-owned text file under the audited home (excluding installed
    skill dirs) that appears to contain an inline secret/token value. Evidence names files
    only — secret values are never echoed.
    """
    capped: list = []
    candidates = _c015_candidate_files(ctx, capped)
    scan_capped = bool(capped)
    if not candidates:
        return _finding(
            "C015",
            UNKNOWN,
            "No candidate home files found for secrets-at-rest scan.",
            "Run on the OpenClaw home with config/bootstrap/env files present.",
        )

    hits = []
    for path in candidates:
        try:
            if path.stat().st_size > _C015_MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _c015_is_generated_plugin_model_catalog(path.parts, text):
            continue
        if _c015_has_secret(text):
            try:
                rel = path.relative_to(ctx.home)
            except ValueError:
                rel = path
            hits.append(f"{rel}: secret-like value detected")

    # B-244: the walk cap can still be hit on a very large home even after excluded
    # material is kept out of the budget (see _c015_candidate_files) — never let either
    # verdict below read as a complete scan when it wasn't.
    cap_note = (
        f" Scan hit the {_C015_MAX_SCAN_FILES}-file walk cap before the home was fully"
        " covered — additional secrets may exist in files not yet reached."
        if scan_capped
        else ""
    )

    if hits:
        detail = (
            f"Plaintext secret-shaped value(s) found in {len(hits)} home file(s) — see evidence."
            f"{cap_note}"
        )
        return _finding(
            "C015",
            WARN,
            detail,
            "Move plaintext secrets into `openclaw secrets configure` or narrowly-scoped environment variables, and keep bootstrap/config files free of inline tokens.",
            evidence=hits[:12],
        )

    if scan_capped:
        # GR#4/B-228 family: a coverage gap must never roll up to a confident "scanned
        # the home, all clean" headline — UNKNOWN, not PASS, until the rest is covered.
        return _finding(
            "C015",
            UNKNOWN,
            f"Scanned {len(candidates)} home file(s) before hitting the "
            f"{_C015_MAX_SCAN_FILES}-file walk cap; no plaintext secret-shaped values in"
            " what was scanned, but coverage is incomplete — the rest of the home was"
            " never reached.",
            "Re-run against a narrower home, or manually review any credentials/, "
            "identity/, devices/, and workspace/ content not covered by this scan.",
        )
    return _finding(
        "C015",
        PASS,
        f"Scanned {len(candidates)} home file(s); no plaintext secret-shaped values detected.",
        "Keep secrets out of home files; prefer the OpenClaw secrets store or environment injection.",
    )


def check_tls(ctx: Context) -> Finding:
    cfg = ctx.config
    bind = parse_bind_host(dig(cfg, "gateway.bind", ""))
    # Real path: gateway.tls.enabled (bool, default false)
    # gateway.tls as a bare boolean and gateway.https do NOT exist in OpenClaw schema
    tls = dig(cfg, "gateway.tls.enabled")
    ev = []
    exposed = bind in EXPOSED_BINDS or (bind and bind not in LOOPBACK)
    # Real tailscale field: gateway.tailscale.mode == "funnel" (not gateway.tailscale.funnel bool)
    if exposed and not tls:
        ev.append(f"gateway.bind={bind} is non-loopback without TLS configured")
    if _perms_loose(ctx):
        ev.append(
            f"openclaw.json is group/world-readable ({oct(ctx.config_mode)[-3:]}) — at-rest risk"
        )
    if ev:
        return _finding(
            "B11",
            WARN,
            "; ".join(ev),
            "Terminate TLS (reverse proxy / tailscale) for any non-loopback bind; "
            "`chmod 600 ~/.openclaw/openclaw.json` and `chmod 700 ~/.openclaw`.",
            ev,
        )
    # B-228: guard the terminal PASS only — _perms_loose(ctx) above is a real, config-
    # content-independent file-permission signal (still legitimately WARNs on a broken
    # openclaw.json that is ALSO group/world-readable), so only the "transport is fine"
    # claim (which needs the actual gateway.bind/gateway.tls.enabled values) is gated.
    unreadable = _config_unreadable("B11", ctx)
    if unreadable is not None:
        return unreadable
    return _finding(
        "B11",
        PASS,
        "Transport is loopback/TLS and config perms are tight.",
        "Keep transport encrypted and credential files locked down.",
    )


def check_trifecta(ctx: Context) -> Finding:
    legs = _trifecta_legs(ctx)
    active = [k for k, v in legs.items() if v]
    detail = f"Active legs {len(active)}/3: {', '.join(active) or 'none'}. Rule: keep ≤2 of 3."
    if len(active) >= 3:
        detail += (
            " All three legs are active — your agent takes outside input, can reach"
            " sensitive data, and can act outbound; one injected prompt is enough to"
            " exfiltrate everything."
        )
    detail += _distance_note(active)
    detail += _mcp_leg_note(ctx)
    detail += _multi_agent_note(ctx)

    if len(active) >= 3:
        return _finding(
            "A1",
            FAIL,
            detail,
            "Break the trifecta: remove one leg. Easiest wins — lock channels to "
            "owner only (no untrusted input), or gate all outbound/exec actions behind "
            "human approval, or move sensitive data out of the agent's reach.",
            evidence=active,
        )

    # Thin-surface guard (B-033): runtime tools granted at session start (message,
    # exec_command, web_*, memory_*) are NOT written to openclaw.json, so an
    # input/outbound leg that looks OFF can still be live. We only trust an OFF leg
    # when the user has attested the agent's real tool inventory (--attest). An
    # unrelated tools.allow entry must NOT silence this — a no-op name was previously
    # enough to flip WARN→PASS without changing real exposure.
    runtime_unknown = [
        k for k, v in legs.items() if not v and k in ("untrusted input", "outbound actions")
    ]
    if runtime_unknown and not _meaningful_tool_surface(ctx):
        return _finding(
            "A1",
            WARN,
            detail
            + (
                f" Cannot determine from config: {', '.join(runtime_unknown)}."
                " Runtime tools (e.g. message, exec_command, web_*) granted at"
                " session start are not reflected in openclaw.json."
            ),
            "Run `clawseccheck --ask` to generate an attestation template, then re-run"
            " with `--attest <file>` so these legs resolve — or treat as possible 3/3.",
            evidence=active,
        )

    return _finding(
        "A1", PASS, detail, "Keep it at ≤2 of 3 — do not add the third capability.", evidence=active
    )


def check_trustedproxy_loopback(ctx: Context) -> Finding:
    """B70 — trusted-proxy auth: non-loopback bind without identity constraints, or
    allowLoopback on a non-loopback bind.

    Grounded (dist zod-schema-O9ml_nmo.js / types.openclaw-CXjMEWAQ.d.ts):
    gateway.auth.mode='trusted-proxy', gateway.auth.trustedProxy.{userHeader,
    requiredHeaders,allowUsers,allowLoopback}. Trusted-proxy auth delegates
    authentication to a reverse-proxy-supplied identity header; on a non-loopback bind an
    attacker who can reach the port directly can forge that header unless
    requiredHeaders/allowUsers genuinely constrain it (B-233) — OR (grounded: dist
    auth-B27MflKU.js authorizeTrustedProxy / authorizeGatewayConnectCore, gated by
    net-*.js isTrustedProxyAddress) OpenClaw itself rejects the connection by source IP
    before ever reading the header when a genuine gateway.trustedProxies allow-list is
    configured, so that is an equally valid constraint.

    UNKNOWN — trusted-proxy auth is not configured (auth.mode != 'trusted-proxy' and
              gateway.auth.trustedProxy.allowLoopback is not set).
    FAIL    — auth.mode='trusted-proxy' AND the bind is non-loopback AND none of
              requiredHeaders, allowUsers, or a genuine gateway.trustedProxies allow-list
              is configured — any direct caller can self-declare identity via the
              (spoofable) trusted-proxy header.
    WARN    — gateway.auth.trustedProxy.allowLoopback=true AND the gateway bind is
              non-loopback (a same-host caller can still forge the header).
    PASS    — loopback bind, or requiredHeaders/allowUsers/trustedProxies genuinely
              constrain identity, or trusted-proxy is not configured.
    """
    cfg = ctx.config
    mode = dig(cfg, "gateway.auth.mode")
    allow_loopback = dig(cfg, "gateway.auth.trustedProxy.allowLoopback")
    configured = mode == "trusted-proxy" or allow_loopback is not None
    if not configured:
        return _finding(
            "B70",
            UNKNOWN,
            "gateway.auth.mode is not 'trusted-proxy' and "
            "gateway.auth.trustedProxy.allowLoopback is not set — trusted-proxy auth is "
            "not configured.",
            "If you use a reverse proxy, configure gateway.auth.mode=trusted-proxy "
            "explicitly (with requiredHeaders/allowUsers) and bind the gateway to "
            "loopback.",
        )
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    if mode == "trusted-proxy" and bind_host not in LOOPBACK:
        required_headers = dig(cfg, "gateway.auth.trustedProxy.requiredHeaders")
        allow_users = dig(cfg, "gateway.auth.trustedProxy.allowUsers")
        trusted_proxies_ok = _trusted_proxies_ok(dig(cfg, "gateway.trustedProxies"))
        if not required_headers and not allow_users and not trusted_proxies_ok:
            user_header = dig(cfg, "gateway.auth.trustedProxy.userHeader") or "x-forwarded-user"
            return _finding(
                "B70",
                FAIL,
                f"gateway.auth.mode=trusted-proxy is bound to a non-loopback address "
                f"(bind host={bind_host!r}) with no requiredHeaders/allowUsers/"
                f"trustedProxies configured — the {user_header!r} identity header is "
                "attacker-spoofable by any direct caller.",
                "Configure gateway.auth.trustedProxy.requiredHeaders and/or allowUsers, "
                "or gateway.trustedProxies, to constrain identity, or bind the gateway "
                "to loopback (127.0.0.1).",
                evidence=[
                    "gateway.auth.mode=trusted-proxy",
                    f"gateway.bind host={bind_host!r} (non-loopback)",
                    "gateway.auth.trustedProxy.requiredHeaders/allowUsers and "
                    "gateway.trustedProxies not set",
                ],
            )
    if allow_loopback is True and bind_host not in LOOPBACK:
        return _finding(
            "B70",
            WARN,
            "gateway.auth.trustedProxy.allowLoopback is true and the gateway is bound to a "
            "non-loopback address — a header-spoofing attacker can forge the trusted-proxy "
            "header.",
            "Bind the gateway to loopback (127.0.0.1) when using trustedProxy auth, or "
            "disable gateway.auth.trustedProxy.allowLoopback.",
            evidence=[
                "gateway.auth.trustedProxy.allowLoopback=true",
                f"gateway.bind host={bind_host!r} (non-loopback)",
            ],
        )
    return _finding(
        "B70",
        PASS,
        "Trusted-proxy auth is loopback-only, has requiredHeaders/allowUsers/"
        "trustedProxies constraining identity, or is not configured (no header-spoof "
        "risk detected).",
        "Keep gateway.auth.trustedProxy.requiredHeaders/allowUsers and/or "
        "gateway.trustedProxies configured, or bind the gateway to loopback.",
    )


def check_audit_target_divergence(ctx: Context) -> Finding:
    """B183 — the running agent may be reading a DIFFERENT config file than the one audited.

    B-281 (ENV-1). Every other check in this catalog describes ``ctx.config_path``. That is
    only useful if the agent is running that same file. OpenClaw's own resolver
    (``resolveConfigPath``, dist/paths-BMBAvkNf.js:136-152) consults
    ``OPENCLAW_CONFIG_PATH`` first and unconditionally, reaches a different home through
    ``OPENCLAW_HOME`` (home-dir-CJKEsOtx.js:34-42), and follows ``OPENCLAW_STATE_DIR`` —
    which is exactly what ``openclaw --profile <name>`` sets. It also prefers an EXISTING
    legacy ``clawdbot.json`` over the canonical name, so the target can move with no
    environment variable set at all.

    Left unreported, a stale hardened ``~/.openclaw/openclaw.json`` scores A while the live
    agent runs a wide-open profile — a lying PASS across the whole catalog at once, the same
    family as the E-052 phantom-path findings.

    WARN    — the path the product would resolve differs (by ``realpath``) from the audited
              one. Both paths are named.
    PASS    — the two resolve to the same file.
    UNKNOWN — the audited home is not this machine's default state directory (a fixture or
              ``--home`` scan), or the resolution could not be completed.

    Never FAIL: a divergence is a signal to re-point the audit, not a proven
    misconfiguration — the other file may be perfectly hardened.

    Three deliberate constraints, each of which would otherwise produce a spurious finding:

    * **``realpath`` comparison, not presence.** ``OPENCLAW_CONFIG_PATH`` explicitly set to
      the file we already audit, or reaching it through a symlink, is NOT a divergence. A
      naive "the variable is set → warn" would fire on a correct setup.
    * **Gated on the default state directory** (``audits_default_state_dir``). Under
      ``--home``/fixtures the user deliberately targeted a file and a warning would be
      noise; it also keeps the auditor's own environment from steering a fixture scan.
    * **A shell export in an ALREADY-RUNNING agent leaves no on-disk trace and is not
      observable from here.** That is a process boundary. So the quiet result is reported
      honestly and never as an affirmative all-clear beyond what was actually checked.
    """
    from ..collector import (  # noqa: PLC0415
        audits_default_state_dir,
        resolve_product_config_path,
    )

    audited = ctx.config_path
    if audited is None:
        return _finding(
            "B183",
            UNKNOWN,
            "The audited config path was not recorded, so it cannot be compared against "
            "the path OpenClaw itself would resolve.",
            "Re-run the audit with a current build of this skill.",
        )

    if not audits_default_state_dir(ctx.home):
        return _finding(
            "B183",
            UNKNOWN,
            f"This scan targets {audited} explicitly, which is not this machine's default "
            "OpenClaw state directory, so it cannot be compared against the path the "
            "running agent would resolve — the environment of this process describes a "
            "different subject.",
            "Run the audit with no --home argument to have it check whether the agent's "
            "own config resolution points somewhere else.",
        )

    product, reason = resolve_product_config_path()
    if product is None:
        return _finding(
            "B183",
            UNKNOWN,
            f"OpenClaw's own config path could not be resolved ({reason}), so it cannot be "
            f"confirmed that the agent reads the audited file {audited}.",
            "Check that HOME (or OPENCLAW_HOME) is set to a real directory, then re-run.",
        )

    try:
        same = os.path.realpath(str(audited)) == os.path.realpath(str(product))
    except (OSError, ValueError):
        same = str(audited) == str(product)

    if not same:
        return _finding(
            "B183",
            WARN,
            "The audited config file is NOT the one OpenClaw would load. Every other "
            f"finding in this report describes {audited}, but the agent resolves "
            f"{product} ({reason}) — so a clean grade here says nothing about the "
            "configuration the agent is actually running.",
            f"Re-run the audit against the live target: clawseccheck --home "
            f"{product.parent}. If the audited file is the intended one instead, unset "
            "OPENCLAW_CONFIG_PATH / OPENCLAW_HOME / OPENCLAW_STATE_DIR (these are what "
            "`openclaw --profile` sets) so the agent and the audit agree.",
            evidence=[f"audited: {audited}", f"OpenClaw resolves: {product}"],
        )

    return _finding(
        "B183",
        PASS,
        f"The audited config file ({audited}) is the same file OpenClaw's own resolver "
        "selects from this environment, so the rest of this report describes the "
        "configuration the agent loads on its next start.",
        "Keep OPENCLAW_CONFIG_PATH / OPENCLAW_HOME / OPENCLAW_STATE_DIR unset, or re-run "
        "the audit with --home pointed at the profile you actually run.",
        evidence=[f"audited: {audited}", f"resolved via {reason}"],
    )


# B-282 (ENV-6): break-glass environment toggles that relax a security control.
#
# Each entry is (variable, predicate, what it does) and each was grounded in the installed
# dist individually — the three toggles use THREE DIFFERENT truthiness rules and collapsing
# them into one would misreport at least two:
#
#   OPENCLAW_ALLOW_INSECURE_PRIVATE_WS  strict `=== "1"` (connection-details-BBobR8Xp.js:27)
#   OPENCLAW_LOAD_SHELL_ENV             isTruthyEnvValue {1,on,true,yes}
#                                       (shell-env-DaE9Xx3-.js:200-202 → env-CKdem44B.js:46)
#
# DELIBERATELY EXCLUDED, both would be false positives:
#
#   OPENCLAW_SHOW_SECRETS — its sense is INVERTED. status.scan-Bm3xXn8C.js:34 reads
#     `showSecrets: process.env.OPENCLAW_SHOW_SECRETS?.trim() !== "0"`, so display is ON by
#     default and the ONLY value that changes anything is "0", which HARDENS the `openclaw
#     status` output. Flagging this variable as "set" would warn about a setting identical
#     to the default, and warn hardest at the exact moment the user had improved matters.
#   OPENCLAW_CLI_CONTAINER_BYPASS — not a sandbox escape but the CLI's container-DELEGATION
#     recursion guard, injected by OpenClaw itself when exec'ing into the container
#     (startup-trace-Bc2ebu8Y.js:176-177). Its set state is the normal condition inside any
#     containerized install, so a check on it would fire on every correct deployment.
_ENV6_TOGGLES = (
    (
        "OPENCLAW_ALLOW_INSECURE_PRIVATE_WS",
        lambda v: v.strip() == "1",
        "lets the gateway accept a plaintext ws:// URL to a non-loopback address, so "
        "gateway credentials and chat traffic cross the network unencrypted",
    ),
    (
        "OPENCLAW_LOAD_SHELL_ENV",
        None,  # is_truthy_env_value; bound at call time to keep this table a leaf
        "makes the agent run your login shell to fill in credential variables that are "
        "missing from its own config, widening where its secrets can come from",
    ),
)


def check_env_breakglass_toggles(ctx: Context) -> Finding:
    """B192 — a break-glass environment toggle relaxes a security control.

    B-282 (ENV-6). Read from the two GLOBAL runtime dotenv files OpenClaw loads into
    ``process.env`` (``~/.openclaw/.env`` and ``~/.config/openclaw/gateway.env`` —
    dist/dotenv-global-mWLbBl_z.js:85-111), and from this process's own environment only
    when the audited home is this user's own.

    WARN    — a toggle is observably on. Never FAIL: both are DOCUMENTED break-glass
              switches. ``OPENCLAW_ALLOW_INSECURE_PRIVATE_WS`` is sanctioned in OpenClaw's
              own gateway security docs for trusted private networks and its plugin docs
              instruct users to set it. A FAIL would punish following the vendor's manual.
    PASS    — a global dotenv file exists and none of the toggles are on in it.
    UNKNOWN — no global dotenv file exists AND the audited home is not this user's own, so
              there is nothing to have read.

    **Scope, stated exactly.** A variable exported in the shell that launched an
    already-running agent leaves no on-disk trace and is not detectable from here — that
    is a process boundary. The two global dotenv files cover the *persistent* delivery
    paths, which are also the ones that survive a restart and therefore the ones an
    attacker or a compromised agent would use; a shell export dies with the shell. The
    residual is a false NEGATIVE, never a false positive. Accordingly this check never
    claims "no toggle is set" — only that none was found in the persistent locations.
    """
    from ..collector import dotenv_override, is_truthy_env_value  # noqa: PLC0415

    hits: "list[str]" = []
    for name, strict, what in _ENV6_TOGGLES:
        raw, source = dotenv_override(ctx, name)
        if raw is None:
            continue
        on = strict(raw) if strict is not None else is_truthy_env_value(raw)
        if on:
            hits.append(f"{name} is on ({source}) — it {what}")

    if hits:
        return _finding(
            "B192",
            WARN,
            "A break-glass environment toggle is switched on in a file OpenClaw loads at "
            "startup: " + "; ".join(hits) + ". These are legitimate escape hatches, but "
            "each one disables a protection that is on by default, and a value written to "
            "a dotenv file persists across restarts.",
            "Remove the variable from the dotenv file once the situation that needed it "
            "is over, so the protection returns on the next agent start. If it is needed "
            "permanently, record why — a persistent break-glass is a standing exception, "
            "not a default.",
            evidence=hits,
        )

    if ctx.dotenv_found:
        return _finding(
            "B192",
            PASS,
            "No break-glass environment toggle is switched on in the global dotenv files "
            "OpenClaw loads at startup (" + ", ".join(ctx.dotenv_files) + ").",
            "Keep OPENCLAW_ALLOW_INSECURE_PRIVATE_WS and OPENCLAW_LOAD_SHELL_ENV out of "
            "the global dotenv files except while actively working around a problem.",
        )

    from ..collector import audits_this_users_own_home  # noqa: PLC0415

    if audits_this_users_own_home(ctx.home):
        return _finding(
            "B192",
            PASS,
            "No global dotenv file is present and no break-glass environment toggle is "
            "set in this process's environment.",
            "Keep it that way outside of active debugging.",
        )

    return _finding(
        "B192",
        UNKNOWN,
        "No global dotenv file was found for the audited home, and this process's "
        "environment describes a different subject, so it cannot be determined whether a "
        "break-glass toggle is set for the agent that runs this configuration.",
        "Run the audit on the machine and account the agent runs as, with no --home "
        "argument, to have the persistent toggle locations checked.",
    )
