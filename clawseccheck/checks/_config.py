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
from .. import sockets as _sockets
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
    LIMIT_DOMAIN_CONFIG,
    SKILL_DIRS,
    Context,
    dig,
    env_evidence_readable,
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
    _canonical_ipv4,
    _channels,
    _config_unreadable,
    _enabled_tools,
    _external_input_channels,
    _finding,
    _gateway_remote_exposure_reason,
    _hint,
    _hooks_session_key_exposures,
    _is_secret_reference,
    _mcp_leg_contributions,
    _norm_group_policy,
    _open_channels,
    _perms_loose,
    _plugins,
    _profile_is_powerful,
    _secret_paths,
    _surface_absent,
    _trifecta_legs,
    _web_fetch_enabled,
    parse_bind_host,
)


def _detail_path(value, home) -> str:
    """Render *value* for a ``Finding.detail``: relative to the audited home when it lies
    inside it, with a single ``..`` segment when it lies under the home's parent (the
    ``~`` slot of a real OpenClaw home, where ``.config/...`` lives). Anything else is
    returned unchanged. A composite string that merely *starts* with such a path is
    rewritten the same way, so a source label like ``<unit> (Environment=)`` still works.

    ``baseline.fingerprint()`` hashes ``Finding.detail``, and a user's
    ``.clawseccheckignore`` keys a per-finding suppression on that hash — so an absolute
    scan-root path baked into a detail silently orphans that suppression the moment the
    workspace or the scanned skill moves, and it leaks the reporter's directory layout
    into any report they share. The audited root is printed once in the report header
    instead. A path the CONFIG itself declares in absolute form is deliberately left
    verbatim: that string is a function of the audited subject, so it belongs in the
    finding's identity (and in the text, since it is what the owner has to go fix).
    """
    text = str(value)
    for base, prefix in ((str(home), ""), (str(Path(home).parent), ".." + os.sep)):
        if base and base != os.sep and text.startswith(base + os.sep):
            return prefix + text[len(base) + 1:]
    return text


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
# (_untrusted_input_channels / _unpolicied_open_wildcard_group_channels (B-371) /
# INPUT_TOOL_HINTS + web for input; SENSITIVE_TOOL_HINTS, ungated exec, credentials/ for
# sensitive; OUTBOUND_TOOL_HINTS, exec, elevated, web for outbound). No new schema invented.
_MISSING_LEG_ACTIVATORS = {
    "untrusted input": (
        "a non-owner channel (channels.<name>.dmPolicy/groupPolicy in "
        "open/allowlist/paired), an unpolicied, unrestricted channels.<name>.groups[\"*\"] "
        "entry (B-297/B-371), an input tool (tools.allow: web/email/imap/rss/fetch), "
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
              F-140: sets ``not_applicable`` only when the config locus was read
              COMPLETELY and ``gateway`` is still not a dict. The HTTP gateway is the
              ONLY reachability path this check models — with no gateway there is no
              HTTP surface over which a control-plane tool could be reached, so absence
              here is genuine inapplicability rather than an unassessed risk. The whole
              read is ``ctx.config``, so config-locus completeness is the entire proof
              obligation; an absent/unparseable/truncated config degrades the flag back
              to ordinary UNKNOWN and the check keeps its blind-spot posture.
    """
    cfg = ctx.config
    gw = cfg.get("gateway")
    if not isinstance(gw, dict):
        return _finding(
            "B32",
            UNKNOWN,
            "No gateway config — control-plane mutation reachability not applicable.",
            "—",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
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


def _gateway_config_token(cfg: dict, auth_mode) -> "tuple[str | None, bool]":
    """The config-supplied gateway credential OpenClaw derives ``auth.mode`` from.

    B-312: `resolveGatewayAuth` derives `mode="token"` from `gateway.auth.token` /
    `gateway.token` whenever `authConfig.mode` is falsy (auth-resolve-NyPBrh8F.js:34-42),
    read config-FIRST (:23-24) ahead of any environment variable. This is the single
    source of truth for that derivation — B2 (`check_gateway`) and B80
    (`check_gateway_rate_limit`) both call it so they can never disagree about what
    counts as an authenticated config-token gateway (B-310 round 2 / C-135).

    Returns ``(token, strong)``: ``token`` is the stripped credential, or ``None`` when
    absent OR when ``auth_mode`` is not ``None`` (an explicit mode means OpenClaw is not
    deriving the mode from mere token presence — the caller already has ``auth_mode``
    directly). ``strong`` is whether the credential meets the same >=24-char bar as the
    env leg and as B2's own token-length clause (`hasSharedSecret` accepts ANY non-empty
    value — no minimum length exists in the dist — so only length is a signal; the value
    itself must never reach a message, evidence entry, fix string, or log, §8).
    """
    token = dig(cfg, "gateway.auth.token") or dig(cfg, "gateway.token")
    token = (
        token.strip()
        if auth_mode is None and isinstance(token, str) and token.strip()
        else None
    )
    strong = token is not None and len(token) >= 24
    return token, strong


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

    # B-306: `has_credentials`/`reachable` are not equally config-dependent.
    # `has_env_gateway_token` (above) is read from a PERSISTENT, config-INDEPENDENT
    # artifact (a systemd unit or global dotenv file — see _gateway_env_credential), so a
    # real credential can still be legitimately found even when openclaw.json itself is
    # unparseable/unreadable. `reachable`, however, is derived entirely from
    # ctx.config (_external_input_channels/_enabled_tools/tools.elevated.allowFrom) and
    # therefore collapses to False whenever ctx.config == {} — so the "not reachable" PASS
    # below is not actually known on a blind config, only assumed. Guarded here, right
    # before that PASS: the `reachable` WARN above needs no guard of its own because
    # `reachable` can never be True with ctx.config == {} in the first place.
    unreadable = _config_unreadable("B41", ctx)
    if unreadable is not None:
        return unreadable

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
        # B-378: a schema-drifted "accounts" (list/string instead of dict) must
        # degrade to "no accounts", never raise.
        accounts = c.get("accounts")
        nodes = [c] + (list(accounts.values()) if isinstance(accounts, dict) else [])
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

    B-288 widened the inventory from the ENABLE toggles to the root-`hooks`
    SESSION-KEY / AGENT-ROUTING policy family — `hooks.defaultSessionKey`,
    `hooks.allowRequestSessionKey`, `hooks.allowedSessionKeyPrefixes`,
    `hooks.allowedAgentIds` — which nothing in the package read before (grep: 0 hits
    each). See `_hooks_session_key_exposures` in `checks/_shared.py` for the dist
    grounding. Those lines are evidence only: they can never change this check's
    status, because they are gated on the same `hooks.enabled is True` that has
    already made the finding WARN.

    HONEST SCOPE. This covers the ROOT `hooks` object only. The plugin-scoped
    `plugins.entries.*.hooks.allowPromptInjection` / `.allowConversationAccess`
    (zod-schema-O9ml_nmo.js:789-795) are a DIFFERENT surface at a different path and
    remain uncovered — a separate task. Standalone this check also stays advisory: the
    escalation to a scored, FAIL-capable verdict happens only in RISK-20, which joins
    this posture with remote gateway exposure.

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

    # B-288: the SESSION-KEY / AGENT-ROUTING policy siblings under the same root
    # `hooks` object (defaultSessionKey, allowRequestSessionKey,
    # allowedSessionKeyPrefixes, allowedAgentIds). Deliberately OUTSIDE the
    # `internal_enabled is not False` block above — these govern the inbound webhook
    # endpoint, not internal-hook module loading, so an explicitly disabled
    # hooks.internal must not hide them.
    #
    # This cannot change B179's STATUS, only enrich its evidence:
    # _hooks_session_key_exposures returns [] unless `hooks.enabled is True`, and that
    # same condition has already appended the "hooks.enabled" evidence line above — so
    # every config these lines can reach was WARN before this change too. That is what
    # makes the extension free of any new false-positive surface, and it is pinned by
    # tests/test_b288_hooks_session_key.py::test_b179_status_never_changes_*.
    for _kind, _line in _hooks_session_key_exposures(cfg):
        evidence.append(_line)

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
        # B-312: a config-supplied `gateway.auth.token` with no `auth.mode` is the SAME
        # shape as the env case above — resolveGatewayAuth derives mode="token" from the
        # credential itself when authConfig.mode is falsy (auth-resolve-NyPBrh8F.js:34-42),
        # and the credential is read config-FIRST (:23-24). So when a config token exists,
        # it is what OpenClaw actually authenticates with, and the env variables below are
        # only ever consulted when no config token exists (mirrors the dist's own
        # precedence). Left OUT of ENV-4/B-290 deliberately (config-only, no env
        # component); closed here with its own triage.
        _cfg_token, _cfg_token_strong = _gateway_config_token(cfg, auth)
        _env_cred, _env_cred_src = (
            _gateway_env_credential(ctx) if auth is None and _cfg_token is None else (None, None)
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
        # message, a fix string, or a log (§8). The same bar applies to the config-token
        # leg (B-312) for the identical reason — a sub-24-char config token binds and
        # listens exactly like a sub-24-char env token.
        _env_cred_strong = _env_cred is not None and len(_env_cred.strip()) >= 24
        if _cfg_token is not None and _cfg_token_strong:
            soft_ev.append(
                f"gateway.bind={bind} is non-loopback and the config sets no "
                f"gateway.auth.mode, but gateway.auth.token is set — OpenClaw derives "
                "auth.mode from it, so the gateway is authenticated. Reported as "
                "disclosure, not exposure"
            )
            fixes.append(
                "No action required if the config-supplied gateway token with no "
                "explicit gateway.auth.mode is intentional. Setting gateway.auth.mode "
                "explicitly makes the posture readable from the config alone"
            )
        elif _cfg_token is not None:
            ev.append(
                f"gateway.bind={bind} is non-loopback and the only gateway credential is "
                "a config-supplied gateway.auth.token shorter than 24 chars — OpenClaw "
                "binds and listens on it, so the gateway is world-reachable behind a "
                "guessable secret"
            )
            fixes.append(
                "Replace the config-supplied gateway token with one of at least 24 "
                "characters, or bind the gateway to loopback"
            )
        elif _env_cred is not None and _env_cred_strong:
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
            # B-362: sets not_applicable only when the config locus was read COMPLETELY
            # and cfg is still empty. Every condition this check grades (bind, auth mode,
            # trusted-proxy identity, open channels) is a plain ctx.config read, so a
            # genuinely empty (but completely-read) config means none of that surface
            # exists to misconfigure -- not merely an unassessed risk. _surface_absent's
            # own config_found gate keeps a host with NO openclaw.json at all (a
            # non-OpenClaw machine) on the real-UNKNOWN side, matching the existing
            # check_control_plane_mutation precedent for the same "no gateway config"
            # wording.
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    # C-182: `if not cfg:` above only catches a WHOLE-CONFIG-empty state. A
    # present-but-malformed `gateway` value (e.g. `"gateway": null`, a list, a
    # number) makes every dig(cfg, "gateway...") lookup degrade to its default
    # ("absent") without raising — indistinguishable from "gateway key simply
    # not present" — and falls through to a confident PASS below. A field that
    # genuinely can't be assessed must read UNKNOWN, not a fabricated PASS.
    # B-362: this malformed-value branch stays a REAL UNKNOWN (never not_applicable)
    # -- a present-but-corrupt `gateway` value is not "no such surface", it is "we
    # cannot tell what was intended", which is exactly the ambiguous case the sweep
    # must not flip.
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

    PASS    — auth is not token/password (explicit config, AND, when config sets no
              explicit auth.mode, config-token- AND environment-derived), OR the bind
              is loopback, OR gateway.auth.rateLimit is configured.
    WARN    — token/password auth (explicit-config-, config-token-, or
              environment-derived) AND non-loopback bind AND no gateway.auth.rateLimit.
    UNKNOWN — config sets no explicit auth.mode, no config-supplied token authenticates
              either, and no persistent artifact (systemd unit or global dotenv) was
              readable to check for an environment-supplied credential, on a
              non-loopback bind — cannot tell whether the gateway is genuinely
              unauthenticated or env-authenticated, so this must not default to a
              fabricated PASS.

    B-310: this check used to read ONLY `gateway.auth.mode` from config, so a gateway
    authenticated by an environment-supplied credential (OPENCLAW_GATEWAY_TOKEN/
    _PASSWORD, resolved the same way B2/B-290 grounds — auth-resolve-NyPBrh8F.js:34-42,
    credential read at credentials-DesN22Ui.js:30-42) silently PASSed as "does not rely
    on a brute-forceable secret" without ever assessing rate limiting — the exact
    config-only blindness B-290 fixed for B2.

    B-312 gap (round 2, C-135): B-310's fix above stopped at the ENV leg and never
    re-derived `mode` from a config-supplied `gateway.auth.token` / `gateway.token` the
    way B2's own B-312 fix does — so a config-token-authenticated gateway (auth.mode
    absent, token >=24 chars) still fell all the way through to the same "does not rely
    on a brute-forceable secret" PASS as a genuinely unauthenticated one, even though B2
    correctly WARNs that identical config as authenticated-but-disclosed. Closed by
    sharing `_gateway_config_token` with B2 (config-first, mirroring the dist's own
    precedence, auth-resolve-NyPBrh8F.js:23-24) so the two checks cannot independently
    drift on what "authenticated by config" means — this docstring previously claimed
    parity with B2 while that config-token leg was still missing; it is genuine now.

    Same >=24-char strength bar as B2 (2a2f8af), for the identical reason:
    `hasSharedSecret` (server-runtime-config-r5ejxORO.js:66,78) accepts ANY non-empty
    credential, so a sub-bar config OR env value is not genuine auth — it is B2's
    exposed/guessable-secret FAIL, not this check's "authenticated-but-unthrottled"
    concern, and is treated the same as no credential at all here. Only the
    credential's LENGTH is read; the value never reaches evidence, detail, fix, or a
    log (§8).
    """
    unreadable = _config_unreadable("B80", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    # Loopback is checked before mode/credential resolution: a loopback bind is not
    # exposed to remote brute-force regardless of auth mode, so it must never need an
    # env-credential read to resolve — that would manufacture a spurious UNKNOWN on the
    # common, already-safe case.
    if bind_host in LOOPBACK:
        return _finding(
            "B80",
            PASS,
            "Gateway is bound to loopback, so the auth endpoint is not exposed to remote "
            "brute-force.",
            "Keep the gateway on loopback, or add gateway.auth.rateLimit before exposing it.",
        )
    mode = dig(cfg, "gateway.auth.mode")
    cred_src = None
    if mode is None:
        # B-312 parity: config wins over environment (config-first, identical to B2)
        # — a config-supplied token is only ever superseded by looking at the
        # environment when NO config token exists at all.
        _cfg_token, _cfg_token_strong = _gateway_config_token(cfg, mode)
        if _cfg_token is not None and _cfg_token_strong:
            mode = "token"
            cred_src = "a config-supplied gateway.auth.token"
        elif _cfg_token is None:
            _env_cred, _env_cred_src = _gateway_env_credential(ctx)
            if _env_cred is not None and len(_env_cred.strip()) >= 24:
                mode = "token"
                cred_src = f"an environment-supplied credential ({_env_cred_src})"
            elif _env_cred is None and not env_evidence_readable(ctx):
                return _finding(
                    "B80",
                    UNKNOWN,
                    "gateway.auth.mode is not set in config, the bind is non-loopback, and no "
                    "systemd user unit or global dotenv file was readable to check for an "
                    "environment-supplied gateway credential — cannot determine whether the "
                    "auth endpoint is brute-forceable.",
                    "Run the audit where it can read the OpenClaw systemd user unit and "
                    "global dotenv files, or set gateway.auth.mode explicitly.",
                )
            # else: env evidence was readable and carried nothing usable (absent, or a
            # sub-24-char value not treated as authenticating) -> mode stays None,
            # falls through to the ordinary "not token/password" PASS below, exactly as
            # before B-310 for a truly-unauthenticated gateway.
        # else: a config token IS present but below the 24-char bar. B2 already FAILs
        # this as an exposed/guessable-secret gateway (config-first — the environment is
        # never consulted, matching B2/B-312 exactly); it is not this check's
        # "authenticated-but-unthrottled" concern, so it is treated the same as no
        # credential at all here (mirrors the weak-env-credential leg above). mode stays
        # None, falls through to the ordinary PASS below.
    if mode not in ("token", "password"):
        return _finding(
            "B80",
            PASS,
            "Gateway auth does not rely on a brute-forceable token/password secret "
            "(or is not configured).",
            "If you enable token/password gateway auth on an exposed bind, configure "
            "gateway.auth.rateLimit to throttle credential guessing.",
        )
    if dig(cfg, "gateway.auth.rateLimit"):
        return _finding(
            "B80",
            PASS,
            "Gateway auth has rate limiting configured (gateway.auth.rateLimit).",
            "Keep gateway.auth.rateLimit aligned with the exposure of the gateway.",
        )
    evidence = (
        [f"gateway.auth.mode={mode!r}"]
        if cred_src is None
        else [
            f"gateway.auth.mode is not set in config, but {cred_src} authenticates the "
            "gateway"
        ]
    ) + [
        f"gateway.bind host={bind_host!r} (non-loopback)",
        "gateway.auth.rateLimit is not set",
    ]
    return _finding(
        "B80",
        WARN,
        "Gateway uses token/password auth on a non-loopback bind but has no "
        "gateway.auth.rateLimit — the auth endpoint can be brute-forced.",
        "Configure gateway.auth.rateLimit (max attempts / window) to throttle credential "
        "guessing, or bind the gateway to loopback.",
        evidence=evidence,
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
    # B-306: openclaw.json present but unparseable/unreadable (config_parse_error, B-166)
    # collapses ctx.config to {} — every dig(cfg, ...) lookup inside _trifecta_legs then
    # defaults to "absent", so the untrusted-input and outbound-action legs (100%
    # config-derived) read as OFF even when the real config has them ON. Guarded at the
    # top, before computing legs at all: unlike B1/B11 (whose independent, non-config
    # signal is a COMPLETE, self-sufficient basis for their own FAIL/WARN), the one
    # non-config contributor mixed into _trifecta_legs — `(ctx.home / "credentials")
    # .is_dir()`, feeding only the "sensitive data" leg — can never by itself clear the
    # >=3-legs FAIL threshold or satisfy the thin-surface WARN branch below (which keys on
    # the untrusted-input/outbound legs, not sensitive data). So guarding here cannot mask
    # an independently-provable verdict; it only stops a confidently-worded WARN/PASS from
    # being computed off a config the audit never actually saw. Measured impact on a real
    # blind run: A1 read WARN instead of its true FAIL, inflating the overall grade from
    # F/49 to C/79 — a lying two-grade improvement on the flagship CRITICAL check.
    unreadable = _config_unreadable("A1", ctx)
    if unreadable is not None:
        return unreadable
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
            # B-362: sets not_applicable only when the config locus was read COMPLETELY
            # and neither locus is set. Grounded (dist docs/gateway/index.md,
            # configuration-reference.md, onboard.md): "token" is the default auth mode
            # and trusted-proxy delegation is an explicit opt-in
            # (gateway.auth.mode="trusted-proxy") -- with mode not set to it AND
            # allowLoopback unset, the spoofable-header surface this check grades
            # genuinely does not exist, not merely an unassessed risk. Both loci are
            # plain ctx.config reads, so config-locus completeness is the whole proof
            # obligation. (Contrast: this is unlike check_sandbox's "no exec tools"
            # branch, which was left un-converted -- a full/unrestricted tool profile is
            # OpenClaw's own default when tools.profile is unset, so absence there does
            # NOT mean the surface is off.)
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    if mode == "trusted-proxy" and bind_host not in LOOPBACK:
        required_headers = dig(cfg, "gateway.auth.trustedProxy.requiredHeaders")
        allow_users = dig(cfg, "gateway.auth.trustedProxy.allowUsers")
        trusted_proxies_ok = _trusted_proxies_ok(dig(cfg, "gateway.trustedProxies"))
        if not required_headers and not allow_users and not trusted_proxies_ok:
            user_header = dig(cfg, "gateway.auth.trustedProxy.userHeader") or "x-forwarded-user"
            # B-315: was FAIL. B70 belongs to the B68-B73 block, whose catalog comment
            # documents the group as "WARN-only ... zero false-positive FAILs on real
            # configs" — this branch was the sole violator of that documented intent
            # (and this exact loopback/private-network predicate is the one CLAUDE.md
            # §6.1 records as version-dependent across Python 3.9/3.12). An unscored
            # check must not FAIL (Dave's ruling: scored=False caps at WARN); downgrading
            # also restores the block comment's original claim. Same evidence.
            return _finding(
                "B70",
                WARN,
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


def _parse_bind_port_raw(value) -> "str | None":
    """Extract the raw port SUBSTRING from a gateway.bind value (no range/decimal
    validation), mirroring parse_bind_host's own handling of the bracketed-IPv6 /
    host:port / bare forms (checks/_shared.py).

    Returns None when no port substring is present at all — an empty value, a bare
    address with no port, or a bare (unbracketed) IPv6 literal where "the port" would
    be ambiguous. Splitting this out from :func:`_parse_bind_port` (B-374 follow-up,
    C-135 round 2) lets a caller distinguish "gateway.bind names no port at all" from
    "gateway.bind names a port string that turned out to be invalid" — two different
    UNKNOWN reasons check_effective_bind reports distinctly.
    """
    s = str(value or "").strip()
    if not s:
        return None
    if s.startswith("["):
        end = s.find("]")
        if end != -1 and s[end + 1 :].startswith(":"):
            return s[end + 2 :]
        return None
    if s.count(":") == 1:
        _, _, port_str = s.partition(":")
        return port_str
    return None  # bare wildcard/IPv6 literal with no unambiguous port


def _parse_bind_port(value) -> "int | None":
    """Extract the port from a gateway.bind value as a validated 1-65535 int.

    Returns None when no port can be unambiguously extracted (see
    :func:`_parse_bind_port_raw`), the extracted text is not a plain decimal integer,
    or the value parses but falls outside the valid TCP port range.

    B-374 follow-up (C-135 round 2, 2026-07-31): uses ``str.isdecimal()``, not
    ``str.isdigit()``, before calling ``int()``. A handful of Unicode characters (e.g.
    the superscript ``"²"``) satisfy ``isdigit()`` while still raising ``ValueError``
    out of ``int()`` — the OLD code could crash on a config value shaped like
    ``"8080²"`` instead of degrading to UNKNOWN. ``isdecimal()`` only accepts
    characters ``int()`` can actually parse, so this now never raises. The 1-65535
    range check is new too — the old code accepted any positive int without an upper
    bound. check_effective_bind treats None as "nothing to look up", not a parse
    error — never raises.
    """
    port_str = _parse_bind_port_raw(value)
    if port_str is None or not port_str.isdecimal():
        return None
    try:
        port = int(port_str)
    except ValueError:  # pragma: no cover - isdecimal() already guards this
        return None
    if not (1 <= port <= 65535):
        return None
    return port


def _declared_bind_class(cfg: dict) -> str:
    """Classify the DECLARED ``gateway.bind`` as ``loopback`` / ``remote`` / ``ambiguous``.

    C-135 finding: a naive ``parse_bind_host(bind) in LOOPBACK`` test (what B2/B70 use
    for their own, different, purpose) is WRONG for two of the current schema's five
    ``gateway.bind`` profiles — ``auto`` resolves to loopback on bare metal but to
    ``0.0.0.0`` inside a container, and ``custom`` resolves through the SEPARATE
    ``gateway.customBindHost`` field, not the profile name itself. Reusing that naive
    test here would misclassify a container's ``bind=auto`` (genuinely, correctly
    ``0.0.0.0``) as "declared loopback", and the moment the effective socket confirms
    the wildcard bind, this check would FAIL a config that is working exactly as
    designed — a textbook false FAIL this module exists to never produce.

    So this reuses ``_gateway_remote_exposure_reason`` (checks/_shared.py) — the
    already-grounded, already-tested resolver RISK-20 relies on for the identical
    per-profile logic (``loopback``/``local``/host:port → the shared ``LOOPBACK``
    predicate; ``lan``/``tailnet`` → always remote; ``custom`` → discriminated by
    ``customBindHost``; Tailscale ``serve``/``funnel`` → always remote regardless of
    bind) — but does NOT stop at its ``Optional[str]`` return. That function
    deliberately collapses two different truths into one ``None``: "provably
    loopback" and "genuinely unprovable from a config file alone" (``auto``; ``custom``
    with no valid ``customBindHost``, which — per that function's own docstring — the
    product refuses to even start with). Corroboration needs the two kept apart:
    treating "unprovable" as "declared loopback" is exactly the false-FAIL risk above,
    so an ambiguous profile is reported as its own bucket instead — an honest UNKNOWN,
    never a guess in either direction.

    C-135 bug 2 (independent review, 2026-07-30): an ABSENT or empty ``gateway.bind``
    is classified the same as ``auto`` — ambiguous — NOT ``loopback``. Grounded against
    the installed dist (``net-BOKtNTf8.js:161-178``, ``defaultGatewayBindMode``): when
    ``gateway.bind`` is unset, the vendor's own effective default is ``loopback`` on
    bare metal but resolves through the SAME container-detecting path as an explicit
    ``auto`` — ``0.0.0.0`` inside a container, "for port-forwarding compatibility", by
    design. That is exactly the ambiguity the ``auto`` branch above exists to never
    guess at, and an absent bind reaches it through an identical vendor code path, not
    a different one — so it gets the identical verdict.
    """
    if _gateway_remote_exposure_reason(cfg) is not None:
        return "remote"
    profile = str(dig(cfg, "gateway.bind", "") or "").strip().lower()
    if profile in ("auto", ""):
        return "ambiguous"
    if profile == "custom" and _canonical_ipv4(dig(cfg, "gateway.customBindHost")) is None:
        return "ambiguous"
    return "loopback"


# B-374 (C-135 round 2, 2026-07-31): the ORIGINAL C-135 bug-1 fix (deleted here --
# see git history) matched a resolved process name against a list of substrings that
# COULD plausibly be the OpenClaw gateway ("node"/"openclaw"/"bun"/"deno") and used a
# match only to BLOCK a FAIL-downgrade, never to positively confirm anything. That is
# too coarse to serve as POSITIVE gateway evidence -- "node" is true of every unrelated
# Node.js process on the box, so it can rule things OUT of "definitely not the
# gateway" but can never rule anything IN as "definitely the gateway". Worse, the old
# design kept FAIL whenever a listener's identity was merely UNRESOLVED (no inode, no
# matching PID, permission denied, disagreeing names) -- "unattributable" read as
# FAIL, an unproven guess in the FAIL direction that Golden Rule #5 forbids.
#
# Replaced with a symmetric three-way classifier that requires POSITIVE identity
# evidence in either direction, using the fuller identity now available
# (sockets.ProcessIdentity.cmdline, added alongside this fix): "gateway" only when the
# resolved comm/cmdline actually NAMES OpenClaw (the invoking script's path usually
# does, e.g. ".../.openclaw/dist/cli.js" -- comm alone cannot); "foreign" when the
# identity resolves to something else nameable; "unknown" -- no positive evidence
# either way -- for everything else, INCLUDING an unresolved identity. See
# check_effective_bind for how "unknown" now degrades the verdict to UNKNOWN rather
# than keeping FAIL (the accepted-FN trade this ticket mandates: a real lying gateway
# whose /proc/<pid>/fd this reader cannot read now also reads UNKNOWN, not FAIL; B2/B70
# still assess the DECLARED posture regardless).
def _classify_listener_identity(identity: "object | None") -> str:
    """Classify a resolved ``sockets.ProcessIdentity`` (or ``None`` -- unresolved) for
    one non-loopback listener as ``"gateway"`` | ``"foreign"`` | ``"unknown"``.

    ``"gateway"``  -- positive evidence: the resolved process's ``comm`` or full
                      ``cmdline`` names OpenClaw itself (case-insensitive substring).
    ``"foreign"``  -- positive evidence of the opposite: the process resolved to a
                      specific, nameable identity that does NOT name OpenClaw (e.g.
                      Docker's userland proxy sharing the port number).
    ``"unknown"``  -- no identity evidence either way: the inode could not be resolved
                      to any process at all (permission denied reading another user's
                      ``/proc``, no inode recorded, the process vanished, or multiple
                      PIDs disagreed on a name).
    """
    if identity is None:
        return "unknown"
    haystack = f"{identity.name or ''} {identity.cmdline or ''}".lower()
    return "gateway" if "openclaw" in haystack else "foreign"


def check_effective_bind(ctx: Context) -> Finding:
    """B340 (F-156): corroborate the DECLARED ``gateway.bind`` against the ACTUAL
    listening socket, read from ``/proc/net/tcp{,6}`` (see ``sockets.py``).

    Every other gateway-exposure verdict (B2, B70) is declared-state only — it reads
    ``gateway.bind`` and reasons about that string. It never checks what the process is
    actually listening on, which is a real blind spot in both directions: a config that
    says loopback while an env override/wrapper/reverse-proxy actually exposes the port
    (false PASS elsewhere), or a config that says wide-open while the gateway is not
    even running (false FAIL elsewhere). This check adds the one runtime signal that
    closes that gap.

    Route decision (recorded per the task DoD): **no subprocess** — ``sockets.py``
    reads ``/proc/net/tcp{,6}`` directly, matching ``hostwatch.py``'s "no subprocess, no
    network" doctrine rather than ``native.py``'s guarded-subprocess precedent. Read-only,
    stdlib-only, and — because it parses the fixed ``local_address`` column instead of
    regexing a whole ``ss``/``netstat`` line — structurally immune to the peer-column bug
    a competitor tool shipped (see ``sockets.py``'s module docstring).

    Matching a listener to the declared port is still by PORT NUMBER first — that part
    of the original design is unchanged. C-135 bug 1 (independent review, 2026-07-30,
    live-reproduced on the reviewer's own machine against ``fixtures/home_safe`` —
    Docker's userland proxy sharing port 8080 with a correctly loopback-only declared
    gateway) showed that port-number-alone matching has a real false-positive-FAIL
    mode, so this adds the ``/proc/*/fd`` PID correlation the original design had
    scoped out as unneeded: when the declared-loopback/effective-non-loopback
    condition is reached, every non-loopback listener's owning process is resolved
    from its socket inode (``sockets.identify_listener_process``, one ``/proc`` walk
    shared across all of them via ``sockets.build_inode_index``) and classified by
    :func:`_classify_listener_identity`.

    B-374 (C-135 round 2, 2026-07-31) REPLACED the original one-sided calibration.
    The original fix could only ever DOWNGRADE FAIL to WARN, and only on POSITIVE
    evidence the listener was something else — any unresolved identity (permission
    denied, no matching inode, disagreeing names) kept the FAIL, which is itself an
    unproven guess in the FAIL direction (Golden Rule #5 forbids exactly this). Now:
    the verdict stays FAIL ONLY when at least one non-loopback listener is POSITIVELY
    confirmed to be the gateway itself (its ``comm``/``cmdline`` actually names
    OpenClaw — see :func:`_classify_listener_identity`); the moment NONE of them can
    be so confirmed — whether because they positively resolve to something else
    (Docker's userland proxy) or because identity resolution is inconclusive
    (permission denied is the common case) — this reports UNKNOWN instead of FAIL.
    This is a deliberate, accepted false-negative trade: a real lying gateway whose
    ``/proc/<pid>/fd`` this reader cannot read now also reads UNKNOWN, not FAIL. B2/B70
    still assess the DECLARED posture regardless, so the config's own stated exposure
    is never hidden — only THIS check's runtime corroboration backs off. Every
    existing synthetic ``Context`` the test suite injects with no inode data at all
    now resolves to UNKNOWN in this branch (not "keep FAIL" as before) — see
    ``tests/test_b340_effective_bind.py``.

    Scoring (B-387, C-135 round 2, 2026-07-31): every PASS and WARN branch below
    passes ``scored=False`` explicitly — B340 can never EARN a scored point, only ever
    COST one via the single FAIL branch (which stays scored, HIGH-capped at 79). Before
    this, a declared-remote config whose effective bind also read non-loopback (the
    "already assessed by B2/B70" PASS below) scored a full-weight PASS — so WIDENING
    ``gateway.bind`` from loopback to remote could swap a capped FAIL (a correctly
    -declared config hitting an attribution edge case) for a full-weight PASS, i.e. a
    LESS secure declaration scoring BETTER on this one check. Making every non-FAIL
    branch unscored closes that inversion structurally: widening the declared/actual
    exposure can only ever move this check from "scores a capped FAIL" to "scores
    nothing", never to "scores a PASS" — see ``tests/test_b340_effective_bind.py``'s
    monotonicity test.

    Fully enumerated verdict table (``declared`` = ``_declared_bind_class``, which
    resolves the FULL 5-profile ``gateway.bind`` enum — not a naive ``LOOPBACK``
    membership test, see its own docstring for why that would false-FAIL a container's
    ``bind=auto``; ``effective`` = every listener found on the declared port, ALL
    loopback or not — a dual-stack 127.0.0.1 + [::1] pair on the same port is ONE
    effective state, not two findings):

        declared      | effective         | verdict
        --------------+-------------------+----------------------------------------
        loopback      | loopback          | PASS (unscored) — corroborates B2
        loopback      | not loopback,      | FAIL (scored) — at least one non-loopback
                      | >=1 confirmed      |   listener positively confirmed as the
                      | gateway            |   gateway itself; the config lies
        loopback      | not loopback,      | UNKNOWN — no non-loopback listener could be
                      | none confirmed     |   positively tied to the gateway process
                      | gateway            |   (foreign process, or unresolvable)
        remote        | loopback           | WARN (unscored) — config is dangerous but
                      |                    |   not currently exposed
        remote        | not loopback       | PASS (unscored) — declared exposure is
                      |                    |   real; B2/B70 already assess it
        ambiguous     | (any)              | UNKNOWN — profile (auto / custom w/o a
                      |                    |   valid customBindHost) is not resolvable
                      |                    |   from the config alone; corroborating it
                      |                    |   either way would be a guess
        (any)         | no listener found  | UNKNOWN — gateway not running, nothing measured
        (any)         | /proc unavailable  | UNKNOWN — platform not supported, or scan not run
        (any)         | no port declared   | UNKNOWN — nothing to look up
        (any)         | port out of range  | UNKNOWN — gateway.bind/gateway.port names an
                      |                    |   invalid (non-1-65535) port

    Port source (C-135 finding, fixed before this shipped): this package's whole
    existing gateway-check family (B2, B70) reads ``gateway.bind`` as a ``host:port``
    string via ``parse_bind_host`` — the shape every fixture in this repo uses. But the
    CURRENT installed OpenClaw schema (grounded directly against the dist, since the
    recon doc does not cover this: ``zod-schema-O9ml_nmo.js``, the ``gateway: object({
    port: number().int().positive().optional(), mode: union([literal("local"),
    literal("remote")]).optional(), bind: union([literal("auto"), literal("lan"),
    literal("loopback"), literal("custom"), literal("tailnet")]).optional(),
    customBindHost: string().optional(), ... })`` block) makes ``gateway.bind`` a
    5-value MODE enum with no embedded port at all — confirmed against this machine's
    own live ``~/.openclaw/openclaw.json`` (``"bind": "loopback", "port": 18789``,
    sibling fields). Reading only an embedded port would make this check report UNKNOWN
    on every config shaped this way — a real coverage gap on the exact real-fleet
    config available for this check's own C-135 pass, not a false FAIL, but real
    enough that it defeats the check's purpose. So the port is resolved from EITHER
    source: an embedded ``host:port`` in ``gateway.bind`` (the fixture/legacy shape)
    first, falling back to the sibling ``gateway.port`` (grounded above; manifest entry
    in ``tests/grounded_schema_paths.txt``) when ``gateway.bind`` is a bare mode string.
    """
    cfg = ctx.config
    if not cfg:
        return _finding(
            "B340",
            UNKNOWN,
            "No config loaded — cannot corroborate gateway.bind against the actual "
            "listening socket.",
            "Run on the host with ~/.openclaw present.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    gw_present = isinstance(cfg, dict) and "gateway" in cfg
    gw = cfg.get("gateway") if gw_present else None
    if gw_present and not isinstance(gw, dict):
        return _finding(
            "B340",
            UNKNOWN,
            "gateway config value is present but malformed (not an object) — cannot "
            "corroborate it against the actual listening socket.",
            "Fix `gateway` to be a config object, or remove the key.",
        )

    bind_raw = dig(cfg, "gateway.bind", "")
    declared_class = _declared_bind_class(cfg)
    if declared_class == "ambiguous":
        return _finding(
            "B340",
            UNKNOWN,
            f"gateway.bind={bind_raw!r} is a profile whose actual bind cannot be "
            "determined from the config alone ('auto' resolves differently inside a "
            "container vs. bare metal; a 'custom' profile with no valid "
            "gateway.customBindHost cannot even start) — nothing to corroborate.",
            "Set gateway.bind to an explicit profile ('loopback'/'lan'/'tailnet'), or "
            "give a 'custom' profile a valid gateway.customBindHost, so this check can "
            "state what is actually declared.",
        )
    declared_loopback = declared_class == "loopback"
    # Port source, in order: an embedded host:port in gateway.bind (the shape every
    # fixture in this repo uses), falling back to the sibling gateway.port (the shape
    # the CURRENT OpenClaw schema actually uses when gateway.bind is a bare mode
    # string — see the docstring's "Port source" note; grounded against the dist,
    # manifest entry in tests/grounded_schema_paths.txt).
    bind_port_raw = _parse_bind_port_raw(bind_raw)
    port = _parse_bind_port(bind_raw)
    if port is None and bind_port_raw is not None:
        # B-374 follow-up (C-135 round 2): gateway.bind DID name a port substring, but
        # it is not a valid 1-65535 decimal port -- a distinct UNKNOWN from "no port
        # declared at all" below (never "gateway is not running").
        return _finding(
            "B340",
            UNKNOWN,
            f"gateway.bind={bind_raw!r} names a port ({bind_port_raw!r}) that is not a "
            "valid TCP port (1-65535) — cannot look up which listening socket to "
            "corroborate it against.",
            "Set gateway.bind to a valid host:port (port 1-65535), or set gateway.port "
            "to a valid port, so this check can corroborate it against the actual "
            "listening socket.",
        )
    if port is None:
        gw_port = dig(cfg, "gateway.port")
        if isinstance(gw_port, int) and not isinstance(gw_port, bool):
            if 1 <= gw_port <= 65535:
                port = gw_port
            else:
                # Same distinction as above, sourced from gateway.port instead.
                return _finding(
                    "B340",
                    UNKNOWN,
                    f"gateway.port={gw_port!r} is not a valid TCP port (1-65535) — "
                    f"cannot look up which listening socket to corroborate "
                    f"gateway.bind={bind_raw!r} against.",
                    "Set gateway.port to a valid port (1-65535) so this check can "
                    "corroborate the declared bind against the actual listening "
                    "socket.",
                )
    if port is None:
        return _finding(
            "B340",
            UNKNOWN,
            f"gateway.bind={bind_raw!r} names no explicit port, and gateway.port is not "
            "set either — cannot look up which listening socket to corroborate it "
            "against.",
            "Set gateway.bind to an explicit host:port (e.g. 127.0.0.1:8080), or set "
            "gateway.port, so this check can corroborate it against the actual "
            "listening socket.",
        )

    sockets_result = getattr(ctx, "sockets", None)
    if sockets_result is None:
        return _finding(
            "B340",
            UNKNOWN,
            "The effective-bind socket scan was not run (audit(include_sockets=True), "
            "or the CLI's --no-sockets was passed) — cannot corroborate gateway.bind "
            "against reality.",
            "Run the full CLI audit (omit --no-sockets) so this check can read "
            "/proc/net/tcp{,6} and corroborate the declared bind.",
        )
    if not sockets_result.available:
        return _finding(
            "B340",
            UNKNOWN,
            f"Could not read the host's listening-socket table: {sockets_result.reason}.",
            "Run ClawSecCheck on Linux with /proc mounted (the standard case) so this "
            "check can corroborate the declared bind against reality.",
        )

    matches = _sockets.listeners_for_port(sockets_result, port)
    if not matches:
        return _finding(
            "B340",
            UNKNOWN,
            f"Nothing is listening on port {port} (the port gateway.bind={bind_raw!r} "
            "declares) — the gateway is not running, or is listening elsewhere; nothing "
            "to corroborate.",
            "Start the gateway and re-run the audit so this check can corroborate "
            "gateway.bind against the actual listening socket.",
        )

    classes = {_sockets.classify_host(m.host) for m in matches}
    effective_loopback = classes <= {"loopback"}
    evidence = [
        f"gateway.bind={bind_raw!r} (declared class={declared_class!r})",
        "effective listener(s): "
        + ", ".join(f"{m.host}:{m.port} ({_sockets.classify_host(m.host)})" for m in matches),
    ]

    if declared_loopback and not effective_loopback:
        non_loopback = [m for m in matches if _sockets.classify_host(m.host) != "loopback"]
        proc_root = getattr(ctx, "proc_root", None) or "/proc"
        # One /proc walk serves every non-loopback listener on this port (B-374
        # follow-up) instead of re-scanning /proc/*/fd once per listener.
        inode_index = _sockets.build_inode_index(proc_root=proc_root)
        identities = [
            _sockets.identify_listener_process(
                getattr(m, "inode", ""), proc_root=proc_root, index=inode_index
            )
            for m in non_loopback
        ]
        confirmed_gateway = [
            m
            for m, ident in zip(non_loopback, identities)
            if _classify_listener_identity(ident) == "gateway"
        ]
        if not confirmed_gateway:
            # B-374: NONE of the non-loopback listeners on this port could be
            # POSITIVELY tied to the OpenClaw gateway process itself -- a foreign
            # process sharing the port number (Docker's userland proxy is the
            # live-reproduced example), or an identity this reader has no
            # permission/evidence to resolve either way (permission denied reading
            # another user's /proc is the normal case). Keeping FAIL here -- as the
            # original C-135 bug-1 fix did -- is itself an unproven guess in the FAIL
            # direction, which Golden Rule #5 forbids. Report UNKNOWN instead; this is
            # a deliberate, accepted false-negative trade (see the function
            # docstring): B2/B70 still assess the DECLARED posture regardless.
            reasons = []
            for m, ident in zip(non_loopback, identities):
                if ident is None:
                    reasons.append(f"{m.host}:{m.port} — process identity unresolvable")
                else:
                    reasons.append(
                        f"{m.host}:{m.port} held by pid {ident.pid} ({ident.name}) — "
                        "not identifiable as the OpenClaw gateway"
                    )
            return _finding(
                "B340",
                UNKNOWN,
                f"gateway.bind={bind_raw!r} declares a loopback bind, and a non-loopback "
                f"listener was found on port {port}, but it could not be positively tied "
                "to the OpenClaw gateway process itself: " + "; ".join(reasons) + ". This "
                "could be gateway.bind lying (env override/launch wrapper/reverse proxy), "
                "or an unrelated process coincidentally sharing the port number — not "
                "distinguishable from a config file and a /proc read alone.",
                f"Confirm what is actually listening on port {port} (e.g. `lsof -i "
                f":{port}` or `ss -tlnp` as root) to determine whether gateway.bind is "
                "being honored, then re-run this audit.",
                evidence=evidence + reasons,
            )
        return _finding(
            "B340",
            FAIL,
            f"gateway.bind={bind_raw!r} declares a loopback bind, but the gateway is "
            f"ACTUALLY listening on a non-loopback address on port {port} — the config "
            "lies and the port is reachable from the network (env override, launch "
            "wrapper, or a reverse proxy re-publishing it).",
            "Find why the running gateway does not match the declared bind (an "
            "env-var override or launch wrapper is the usual cause) and align it with "
            "gateway.bind, or update gateway.bind to state reality.",
            evidence=evidence
            + [
                f"{m.host}:{m.port} confirmed via pid {ident.pid} ({ident.name})"
                for m, ident in zip(non_loopback, identities)
                if _classify_listener_identity(ident) == "gateway"
            ],
            scored=True,
        )
    if not declared_loopback and effective_loopback:
        # B-374 follow-up (item 4): when the DECLARED-remote classification actually
        # comes from Tailscale serve/funnel (which requires a loopback gateway.bind —
        # see _gateway_remote_exposure_reason's docstring), name that reason instead
        # of telling the owner to "set gateway.bind to loopback" when it may already
        # BE loopback and Tailscale's own relay path is what exposes it.
        exposure_reason = _gateway_remote_exposure_reason(cfg)
        if exposure_reason is not None and exposure_reason.startswith("gateway.tailscale.mode="):
            detail = (
                f"{exposure_reason} publishes the gateway externally regardless of "
                f"gateway.bind={bind_raw!r} — the gateway is currently only listening "
                f"loopback-only on port {port} on this host, but Tailscale's own "
                "serve/funnel relay is what actually exposes it, not this machine's "
                "socket."
            )
            fix = (
                "Confirm the Tailscale serve/funnel exposure is intentional — it "
                "publishes the gateway regardless of gateway.bind. Disable "
                "gateway.tailscale.mode if that is not intended."
            )
        else:
            detail = (
                f"gateway.bind={bind_raw!r} declares a non-loopback bind, but the "
                f"gateway is currently only listening on loopback on port {port} — the "
                "config is dangerous even though nothing is exposed right now."
            )
            fix = (
                "Set gateway.bind to loopback (127.0.0.1) so the declared and actual "
                "posture match, or confirm the non-loopback bind is intentional before "
                "it takes effect."
            )
        return _finding(
            "B340",
            WARN,
            detail,
            fix,
            evidence=evidence,
            scored=False,
        )
    if declared_loopback:
        return _finding(
            "B340",
            PASS,
            f"gateway.bind={bind_raw!r} is loopback and the gateway is ACTUALLY "
            f"listening loopback-only on port {port} (corroborates B2).",
            "Keep gateway.bind loopback and re-run this corroboration after any config "
            "or deployment change.",
            evidence=evidence,
            scored=False,
        )
    return _finding(
        "B340",
        PASS,
        f"gateway.bind={bind_raw!r} declares a non-loopback bind and the gateway is "
        f"ACTUALLY listening non-loopback on port {port} — the declared exposure is "
        "real, and already assessed by B2/B70.",
        "See B2/B70 for the auth/exposure posture of this bind.",
        evidence=evidence,
        scored=False,
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

    # B-349: every branch below names the audited file RELATIVE to the audited home, and
    # keeps the absolute form in `evidence=` / the fix text. The report header already
    # prints the absolute audited path once ("Audited config: ..."), so nothing is lost —
    # but an absolute path inside `detail` is hashed by `baseline.fingerprint()`, which
    # made a fingerprint suppression for this finding die the moment the profile moved,
    # and put the reporter's home layout into every shared report.
    audited_rel = _detail_path(audited, ctx.home)

    if not audits_default_state_dir(ctx.home):
        return _finding(
            "B183",
            UNKNOWN,
            f"This scan targets {audited_rel} under an explicitly chosen home, which is "
            "not this machine's default OpenClaw state directory, so it cannot be "
            "compared against the path the running agent would resolve — the environment "
            "of this process describes a different subject.",
            "Run the audit with no --home argument to have it check whether the agent's "
            "own config resolution points somewhere else.",
            evidence=[f"audited: {audited}"],
        )

    product, reason = resolve_product_config_path()
    if product is None:
        return _finding(
            "B183",
            UNKNOWN,
            f"OpenClaw's own config path could not be resolved ({reason}), so it cannot be "
            f"confirmed that the agent reads the audited file {audited_rel}.",
            "Check that HOME (or OPENCLAW_HOME) is set to a real directory, then re-run.",
            evidence=[f"audited: {audited}"],
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
            f"finding in this report describes {audited_rel} under the audited home, but "
            f"the agent resolves a different file ({reason}) — so a clean grade here says "
            "nothing about the configuration the agent is actually running. Both paths "
            "are named in full in this finding's evidence and in the fix below.",
            f"Re-run the audit against the live target: clawseccheck --home "
            f"{product.parent}. If the audited file is the intended one instead, unset "
            "OPENCLAW_CONFIG_PATH / OPENCLAW_HOME / OPENCLAW_STATE_DIR (these are what "
            "`openclaw --profile` sets) so the agent and the audit agree.",
            evidence=[f"audited: {audited}", f"OpenClaw resolves: {product}"],
        )

    return _finding(
        "B183",
        PASS,
        f"The audited config file ({audited_rel}) is the same file OpenClaw's own resolver "
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
            hits.append(f"{name} is on ({_detail_path(source, ctx.home)}) — it {what}")

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
            "OpenClaw loads at startup ("
            + ", ".join(_detail_path(p, ctx.home) for p in ctx.dotenv_files)
            + ").",
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


def check_shell_env_fallback(ctx: Context) -> Finding:
    """B324 — env.shellEnv.enabled (E-060 item 7): agent-startup login-shell import.

    The CONFIG-KEY half of the same OR condition B192 already checks the ENV-VAR half
    of: OpenClaw enables its shell-env fallback when EITHER the
    ``OPENCLAW_LOAD_SHELL_ENV`` dotenv toggle is on (B192) OR
    ``env.shellEnv.enabled === true`` in openclaw.json (this check) — grounded directly
    against the dist: ``call-Bj6Erfmh.js:101`` / ``io-By0s-a_s.js:5268``:
    ``shouldEnableShellEnvFallback(env) || cfg.env?.shellEnv?.enabled === true``. When
    on, OpenClaw loads environment variables from the user's login shell at agent
    startup, so ``~/.bashrc``/``~/.zshrc`` content becomes agent-startup input — a
    persistence foothold or a PATH-hijack planted there becomes an agent-startup
    vector, not only an interactive-shell one.

    WARN-only, never FAIL: OpenClaw's own field description calls this a legitimate,
    commonly-wanted feature ("Keep this enabled when you depend on profile-defined
    secrets or PATH customizations" — schema-DRyO1XBt.js:91), mirroring B192's own
    break-glass framing for the sibling toggle.

    Scope, stated exactly: ``shouldEnableShellEnvFallback()`` also fires from the
    ``OPENCLAW_LOAD_SHELL_ENV`` runtime environment variable (B192's surface, not
    config) — a static config audit cannot observe that path, so this check's absence
    of a finding here does NOT mean shell-env loading is off, only that the openclaw.json
    key itself does not request it. That residual is a false NEGATIVE (already covered
    by B192 for the env-var path), never a false positive this check would introduce.

    WARN    — env.shellEnv.enabled == true.
    PASS    — env.shellEnv.enabled is absent or false.
    UNKNOWN — no config found at all, or present but unparseable/unreadable.
    """
    if not ctx.config_found:
        return _finding(
            "B324",
            UNKNOWN,
            "No openclaw.json found -- env.shellEnv.enabled cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B324", ctx)
    if unreadable is not None:
        return unreadable

    enabled = dig(ctx.config, "env.shellEnv.enabled")
    if enabled is True:
        return _finding(
            "B324",
            WARN,
            "env.shellEnv.enabled=true — OpenClaw loads environment variables from "
            "the user's login shell (~/.bashrc, ~/.zshrc, …) at agent startup, so "
            "shell rc file content becomes agent-startup input.",
            "Confirm this is needed (e.g. profile-defined secrets or PATH "
            "customizations the agent depends on); disable it in a locked-down "
            "service environment with explicit env management instead.",
        )

    return _finding(
        "B324",
        PASS,
        "env.shellEnv.enabled is absent or false — openclaw.json does not request "
        "login-shell environment import at startup (the OPENCLAW_LOAD_SHELL_ENV "
        "env-var path is checked separately by B192).",
        "Keep it that way unless a specific workflow depends on profile-defined "
        "secrets or PATH customizations from the login shell.",
    )


_B323_ENV_VAR_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _b323_parse_env_token_at(value: str, index: int) -> "tuple[str, int] | None":
    """Faithful port of OpenClaw's ``parseEnvTokenAt``
    (``env-substitution-CATXLg7n.js:32-58``).

    Returns ``("escaped", end)`` for a ``$${NAME}`` token, ``("substitution", end)``
    for a ``${NAME}`` token, or ``None`` if *index* isn't the start of either --
    including the case where ``NAME`` doesn't match OpenClaw's own
    ``ENV_VAR_NAME_PATTERN`` (``/^[A-Z_][A-Z0-9_]*$/``, all-caps only) or the ``}``
    is missing. *end* is the index of the closing ``}``.
    """
    if index >= len(value) or value[index] != "$":
        return None
    nxt = value[index + 1] if index + 1 < len(value) else ""
    after_next = value[index + 2] if index + 2 < len(value) else ""
    if nxt == "$" and after_next == "{":
        start = index + 3
        end = value.find("}", start)
        if end != -1:
            name = value[start:end]
            if _B323_ENV_VAR_NAME_RE.match(name):
                return ("escaped", end)
    if nxt == "{":
        start = index + 2
        end = value.find("}", start)
        if end != -1:
            name = value[start:end]
            if _B323_ENV_VAR_NAME_RE.match(name):
                return ("substitution", end)
    return None


def _b323_contains_env_var_reference(value: str) -> bool:
    """Faithful port of OpenClaw's ``containsEnvVarReference()``
    (``env-substitution-CATXLg7n.js:102-112``).

    Only an unescaped ``${ALL_CAPS_NAME}`` counts as a real, filtered reference.
    An escaped ``$${NAME}`` token, or a ``${...}``-shaped token whose name is not
    all-caps (lowercase/mixed-case, digit-leading, etc.) or is missing its closing
    ``}``, does NOT count -- OpenClaw's own ``isConfigRuntimeEnvVarAllowed()`` does
    not block those values; it applies them verbatim (literal ``$`` characters and
    all) to the runtime environment. A naive ``"${" in value`` substring test
    conflates these two cases and was found (C-135 adversarial pass) to silently
    miss a config-declared literal PATH override that OpenClaw actually applies,
    whenever the token merely *looks* like a substitution (e.g.
    ``${systemRoot}:/opt/evil/bin`` -- mixed-case name, not a real reference, but
    the naive check skipped it as if it were one).
    """
    if "$" not in value:
        return False
    i = 0
    n = len(value)
    while i < n:
        if value[i] != "$":
            i += 1
            continue
        token = _b323_parse_env_token_at(value, i)
        if token is not None:
            kind, end = token
            if kind == "escaped":
                i = end + 1
                continue
            if kind == "substitution":
                return True
        i += 1
    return False


def _b323_is_literal_path_override(key: object, value: object) -> bool:
    """True if *key* normalizes to PATH and *value* is a literal, non-empty string.

    "Literal" excludes a value containing a genuine, unresolved ``${ALL_CAPS}``
    substitution reference -- see ``_b323_contains_env_var_reference()`` for the
    faithful port of OpenClaw's own ``containsEnvVarReference()``
    (``env-substitution-CATXLg7n.js:102-112``): OpenClaw itself never applies such a
    value, so flagging it here would be a false positive on a config that merely
    references another variable indirectly. A value that merely *contains* the
    substring ``${`` without forming a real reference (wrong case, bad name, no
    closing brace, or an escaped ``$${...}``) is NOT excluded -- OpenClaw applies
    it verbatim, so it must still be flagged.
    """
    if not isinstance(key, str) or key.strip().upper() != "PATH":
        return False
    if not isinstance(value, str) or not value.strip():
        return False
    return not _b323_contains_env_var_reference(value)


def check_env_vars_path_override(ctx: Context) -> Finding:
    """B323 — env.vars.PATH / env.<KEY> catchall: an explicit PATH override.

    Narrowed on grounding from the epic's original framing ("report any env.vars /
    env.<KEY> catchall key OpenClaw's own blocklist doesn't already block"). Two
    catchall shapes reach the process environment identically —
    ``config-env-vars-DlUfO5Q_.js:43-59`` ``collectConfigEnvVarsByTarget()`` reads
    ``env.vars.<KEY>`` (a Zod ``record(string(), string())``,
    ``zod-schema-O9ml_nmo.js:1004``) AND any other ``env.<KEY>`` sibling except
    ``shellEnv``/``vars`` (a Zod ``.catchall(string())`` on the ``env`` object itself,
    ``zod-schema-O9ml_nmo.js:1005``) — and both funnel through the same
    ``isBlockedConfigEnvVar()`` gate (``config-env-vars-DlUfO5Q_.js:36-38``), which
    unions ``isDangerousHostEnvVarName()`` + ``isDangerousHostEnvOverrideVarName()``
    (``host-env-security-CWC2ZCy4.js:5-316``, ~254 explicit keys + 7 prefixes + 1
    regex — NODE_OPTIONS/PYTHONPATH/BASH_ENV/GIT_EXTERNAL_DIFF/RUSTC_WRAPPER/
    SSLKEYLOGFILE/EDITOR/HOME/AWS_*/GH_TOKEN/etc.). That blocklist is comprehensive
    enough that a check flagging every *other* residual key would false-WARN on the
    feature's own legitimate purpose (arbitrary app/API-key vars) — a Golden Rule #5
    violation. The one concrete, groundable gap is ``PATH`` itself: it does not
    appear anywhere in ``blockedEverywhereKeys``/``blockedOverrideOnlyKeys``
    (host-env-security-CWC2ZCy4.js:5-316) — the file's only literal ``"PATH"`` match
    is inside ``sanitizeHostEnvOverridesWithDiagnostics()`` (:497), a *different*,
    host-exec-override subsystem this config path never reaches.

    WARN-only, never FAIL: whether a config-declared PATH has any effect depends on a
    runtime fact this static auditor cannot observe. ``applyConfigEnvVars()``
    (``config-env-vars-DlUfO5Q_.js:~118-152``) never overwrites a key that already
    holds a non-empty value in the environment it is applied against, and every
    grounded live call site (``pre-bootstrap-8G8HyMEQ.js:195,332``,
    ``io-By0s-a_s.js:5267`` ``finalizeLoadedRuntimeConfig``,
    ``call-Bj6Erfmh.js:79`` ``resolveGatewayDispatchEnvVars``) defaults to
    ``process.env``, which always carries a non-empty ``PATH`` in a realistic launch
    — so this is closer to C5's own "declared trust expansion, real-world
    exploitability uncertain" WARN precedent (host-filesystem PATH/install-dir
    hijacking) than to B186's narrow-and-deterministic writable-root FAIL. A value
    containing an unresolved ``${...}`` substitution token is skipped, mirroring
    ``containsEnvVarReference()`` (``env-substitution-CATXLg7n.js:102-112``) — the
    config is referencing another variable indirectly, not hardcoding a literal path.

    WARN    — ``env.vars.PATH`` or the ``env.<KEY>`` catchall sets a literal
              (non-``${...}``) non-empty string value for a key that normalizes
              (case-insensitively) to ``PATH``.
    PASS    — no such entry.
    UNKNOWN — no openclaw.json found, or present but unparseable/unreadable.
    """
    if not ctx.config_found:
        return _finding(
            "B323",
            UNKNOWN,
            "No openclaw.json found -- env.vars.PATH / env.<KEY> catchall PATH override "
            "cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B323", ctx)
    if unreadable is not None:
        return unreadable

    env_cfg = ctx.config.get("env") if isinstance(ctx.config, dict) else None
    hits: "list[str]" = []
    if isinstance(env_cfg, dict):
        vars_block = env_cfg.get("vars")
        if isinstance(vars_block, dict):
            for key, value in vars_block.items():
                if _b323_is_literal_path_override(key, value):
                    hits.append(f"env.vars.{key}={value!r}")
        for key, value in env_cfg.items():
            if key in ("shellEnv", "vars"):
                continue
            if _b323_is_literal_path_override(key, value):
                hits.append(f"env.{key}={value!r}")

    if hits:
        return _finding(
            "B323",
            WARN,
            "openclaw.json explicitly sets PATH via the env.vars / env.<KEY> catchall "
            "mechanism (" + "; ".join(hits) + "). OpenClaw's own config-env-var "
            "blocklist covers ~254 dangerous keys/prefixes but does not include PATH "
            "itself, so this value is not filtered the way NODE_OPTIONS/PYTHONPATH/"
            "BASH_ENV and similar keys are.",
            "Confirm this is intentional. In practice it is usually inert -- OpenClaw "
            "never overwrites an env var that already holds a non-empty value at the "
            "point this is applied, and every normal launch already has a non-empty "
            "PATH -- but a launcher that starts the agent with an empty or unset PATH "
            "would let this value take effect unfiltered. Remove it unless there is a "
            "specific, documented reason to override the agent's PATH.",
            evidence=hits,
        )

    return _finding(
        "B323",
        PASS,
        "No env.vars.PATH or env.<KEY> catchall PATH entry found in openclaw.json.",
        "Keep it that way; if PATH customization is genuinely needed, prefer scoping "
        "it narrowly (e.g. a per-tool wrapper) and reviewing it periodically.",
    )
