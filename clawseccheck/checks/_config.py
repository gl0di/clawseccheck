"""Topic module: config checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import re
from pathlib import Path
from .. import attest as _attest
from ..catalog import (
    FAIL,
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
)
from ..safeio import walk_dir_safely

from ._shared import (
    EXPOSED_BINDS,
    INPUT_TOOL_HINTS,
    LOOPBACK,
    OUTBOUND_TOOL_HINTS,
    SECRET_PATTERNS,
    SENSITIVE_TOOL_HINTS,
    _LEG_KEYS,
    _channels,
    _enabled_tools,
    _external_input_channels,
    _finding,
    _hint,
    _is_secret_reference,
    _mcp_leg_contributions,
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


# ---------------------------------------------------------------- Block B
def _c015_candidate_files(ctx: Context) -> list[Path]:
    skip_roots = [(ctx.home / rel).resolve() for rel in SKILL_DIRS]
    out: list[Path] = []
    for path in walk_dir_safely(ctx.home, max_files=_C015_MAX_SCAN_FILES, exclude_pycache=True):
        if not path.is_file():
            continue
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if any(
            resolved == root or root in resolved.parents for root in skip_roots if root.exists()
        ):
            continue
        if _c015_is_codex_plugin_doc_cache(resolved.parts):
            continue
        name = path.name.lower()
        if (
            path.suffix.lower() in _C015_TEXT_EXTS
            or name in {"openclaw.json", "openclaw.jsonc"}
            or name.startswith("openclaw.json.")
            or name.startswith("openclaw.jsonc.")
            or name.startswith(".env")
            or name in BOOTSTRAP_FILES
        ):
            out.append(path)
    return out


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
    """B-229: when an MCP server contributes to a trifecta leg, name it in the detail
    text (evidence stays the fixed 3 leg-name keys — see _trifecta_legs/_LEG_KEYS — so
    the MCP server names live here instead)."""
    mcp_legs = _mcp_leg_contributions(ctx.config)
    reasons = mcp_legs["sensitive data"] + mcp_legs["outbound actions"]
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


def _trusted_proxies_ok(value) -> bool:
    if isinstance(value, str):
        return bool(value.strip()) and value.strip() != "*"
    if isinstance(value, list):
        if not value:
            return False
        for item in value:
            if not isinstance(item, str):
                return False
            if not item.strip() or item.strip() == "*":
                return False
        return True
    return False


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

    has_credentials = bool(providers) or has_gateway_token

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

    n = len(providers) + (1 if has_gateway_token else 0)
    provider_list = ", ".join(sorted(providers))
    gateway_note = " + gateway token" if has_gateway_token else ""

    # Build evidence list — provider names and gateway marker only, never emails/values
    evidence: list[str] = []
    if providers:
        evidence.append(f"providers: {provider_list}")
    if has_gateway_token:
        evidence.append("gateway-token: present")

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
    FAIL when a sandbox-escape or control-plane-auth-disable flag is on; WARN for the rest.
    """
    cfg = ctx.config
    fails: list[str] = []
    warns: list[str] = []

    for path, label, is_fail in _DANGER_FIXED:
        if dig(cfg, path):
            (fails if is_fail else warns).append(f"{path} — {label}")

    nc = dig(cfg, "gateway.nodes.allowCommands")
    if isinstance(nc, list) and nc:
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


def check_gateway(ctx: Context) -> Finding:
    cfg = ctx.config
    ev = []
    # B-020: build the remediation from the conditions that ACTUALLY fired, one clause per
    # trigger, so the fix names the real problem (e.g. allowInsecureAuth alone -> "Disable
    # gateway.controlUi.allowInsecureAuth", not generic boilerplate the config already meets).
    # Clauses join with "; " so each fired condition contributes one fragment.
    fixes = []
    bind = parse_bind_host(dig(cfg, "gateway.bind", ""))
    auth = dig(cfg, "gateway.auth.mode")
    if bind and bind not in LOOPBACK and auth in (None, "none"):
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
    open_ch = _open_channels(cfg)
    for name in open_ch:
        ev.append(f"channel '{name}' has an open dm/group policy (anyone can command it)")
    if open_ch:
        fixes.append("Set every open channel's dmPolicy/groupPolicy to 'allowlist'")
    if ev:
        _insecure_auth_only = ev == ["gateway.controlUi.allowInsecureAuth enabled"]
        sev = WARN if _insecure_auth_only else FAIL
        return _finding("B2", sev, "; ".join(ev), "; ".join(fixes), ev)
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
    candidates = _c015_candidate_files(ctx)
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
        if _c015_has_secret(text):
            try:
                rel = path.relative_to(ctx.home)
            except ValueError:
                rel = path
            hits.append(f"{rel}: secret-like value detected")

    if hits:
        detail = (
            f"Plaintext secret-shaped value(s) found in {len(hits)} home file(s) — see evidence."
        )
        return _finding(
            "C015",
            WARN,
            detail,
            "Move plaintext secrets into `openclaw secrets configure` or narrowly-scoped environment variables, and keep bootstrap/config files free of inline tokens.",
            evidence=hits[:12],
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
    """B70 — trustedProxy allowLoopback on non-loopback bind.

    Grounded (docs.openclaw.ai/gateway/security): gateway.auth.trustedProxy.allowLoopback
    (bool). Trusted-proxy auth delegates authentication to a reverse-proxy header; on a
    non-loopback bind an attacker can forge that header.

    UNKNOWN — field not set; trusted-proxy auth not configured.
    PASS    — allowLoopback=true AND gateway bind is loopback (legitimate local setup).
    WARN    — allowLoopback=true AND gateway bind is non-loopback (header-spoof surface).
    """
    cfg = ctx.config
    val = dig(cfg, "gateway.auth.trustedProxy.allowLoopback")
    if val is None:
        return _finding(
            "B70",
            UNKNOWN,
            "gateway.auth.trustedProxy.allowLoopback is not set — trusted-proxy auth is "
            "not configured.",
            "If you use a reverse proxy, configure gateway.auth.trustedProxy explicitly "
            "and bind the gateway to loopback.",
        )
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    if val is True and bind_host not in LOOPBACK:
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
        "Trusted-proxy auth is loopback-only or not configured (no header-spoof risk).",
        "Keep gateway.auth.trustedProxy.allowLoopback disabled or ensure the gateway "
        "binds to loopback.",
    )
