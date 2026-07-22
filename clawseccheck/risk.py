"""Risk engine: combinational chain detection (the Lethal Trifecta, generalised).

Detects dangerous CAPABILITY CHAINS — not isolated property checks. A chain
fires only on POSITIVE evidence for every link; UNKNOWN inputs yield no chain
(zero false-positives by design).

Chains are ADVISORY: they are derived from the audit, never part of it. No chain
carries a CheckMeta, and none can move the A–F grade — cli.py computes the score
before calling ``risk_paths``, and scoring.py does not import this module.

Almost every rule is a pure function of config + findings. The one exception is
RISK-21 (F-135), which additionally reads the trajectory sidecars under ``ctx.home``
— metadata only (tool verb names and session-key ORIGIN KINDS; never call arguments,
never the peer id) — so that "a channel is open to non-owner senders" and "a
high-blast verb provably ran from such a session" can finally be related.

English-only. Read-only. Pure stdlib.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import attest as _attest
from . import trajectory as _trajectory
from .catalog import CRITICAL, FAIL, HIGH, MEDIUM, WARN, Finding
from .checks import (
    _b62_actual_families,
    _b62_extract_declaration,
    _enabled_tools,
    _external_input_channels,
    _gateway_remote_exposure_reason,
    _has_approval_gate,
    _hint,
    _hooks_session_key_exposures,
    _open_wildcard_group_channels,
    _reassembly,
    _resolved_channel_nodes,
    SENSITIVE_TOOL_HINTS,
    INPUT_TOOL_HINTS,
    OUTBOUND_TOOL_HINTS,
)
from .collector import Context, dig

# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RiskPath:
    id: str
    severity: str   # CRITICAL | HIGH | MEDIUM
    title: str
    chain: list[str]  # ordered steps, rendered as A -> B -> C
    why: str          # plain-language explanation
    fix: str          # remediation guidance
    # B-154: mirrors Finding.suppressed — set when this RISK-id is listed in
    # .clawseccheckignore. Kept in the returned list (same pattern as findings)
    # so --show-suppressed can surface it; report/json renderers must filter it out.
    suppressed: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2}


def _finding_status(findings: list[Finding], check_id: str) -> str | None:
    """Return the status string for a finding by id, or None if absent.

    When the same id appears more than once (e.g. a real check result followed
    by a test-injected override), the LAST entry wins so callers can override
    a check result by appending a synthetic Finding at the end of the list.
    """
    result = None
    for f in findings:
        if f.id == check_id:
            result = f.status
    return result


def _has_exec_or_write_tools(tools: list[str]) -> bool:
    """True when exec, shell, fs_write or elevated tools are present."""
    return _hint(tools, ("exec", "shell", "fs_write", "deploy")) or "elevated" in tools


def _has_outbound(tools: list[str], cfg: dict) -> bool:
    channels = cfg.get("channels")
    return (
        _hint(tools, OUTBOUND_TOOL_HINTS)
        or bool(dig(cfg, "tools.elevated.allowFrom"))
        or bool(isinstance(channels, dict) and channels)  # channels are bidirectional
    )


def _has_sensitive_data(tools: list[str], ctx: Context) -> bool:
    return (
        _hint(tools, SENSITIVE_TOOL_HINTS)
        or (ctx.home / "credentials").is_dir()
        or bool(dig(ctx.config, "gateway.auth.password"))
    )


def _open_channel_labels(cfg: dict) -> list[str]:
    """Human-readable labels for open dm/group channels, e.g. 'telegram (open group)'.

    B-297: also labels the ``channels.<p>.groups {"*": ...}`` shape. That shape declares
    NO dmPolicy/groupPolicy field, so the policy-value tests below returned [] on the
    commonest real open-group config — and because RISK-01 gates on this helper alone
    (``if not open_ch: return None``), "Untrusted sender can reach host execution" could
    not fire on it at all, statically, no matter what the other legs said. The predicate
    is ``_open_wildcard_group_channels`` in checks/_shared.py, the SAME one B140 uses —
    imported through the checks aggregator per CLAUDE.md §3.1-a, deliberately NOT
    re-implemented here (a second, drifting copy of "wildcard means unrestricted" is the
    defect class this change removes).

    ADVISORY, not scored. Every RiskPath is outside the A–F score by construction:
    cli.py computes ``score = audit(...)`` before ``risk_paths(...)`` is called, and
    scoring.py does not import this module — so a chain that newly fires here cannot
    create a FAIL or move the grade. That is what keeps B140's WARN-never-FAIL contract
    intact (a community bot may intentionally accept any group) while still letting the
    chain be reported.

    A wildcard group's ``requireMention: true`` is surfaced as mitigating context in the
    label, NOT treated as closing the path: it changes what triggers the bot, not who is
    allowed to trigger it.
    """
    labels = []
    channels = cfg.get("channels")
    if not isinstance(channels, dict):
        return labels
    open_wildcard = _open_wildcard_group_channels(cfg)
    for name, c in channels.items():
        if not isinstance(c, dict):
            continue
        if name in open_wildcard:
            mention = any(
                isinstance(node.get("groups"), dict)
                and isinstance(node["groups"].get("*"), dict)
                and node["groups"]["*"].get("requireMention") is True
                for node in _resolved_channel_nodes(c)
            )
            suffix = ", any group, mention-gated" if mention else ", any group"
            labels.append(f"{name} (open group{suffix})")
            continue
        nodes = [c] + list((c.get("accounts") or {}).values())
        for node in nodes:
            if not isinstance(node, dict):
                continue
            parts = []
            if node.get("dmPolicy") == "open":
                parts.append("open DM")
            # B-283 (a), GROUNDING CORRECTION (C-135 review): Feishu's GroupPolicySchema
            # maps the "allowall" alias onto "open" (channel-PR3XHV0V.js:89-93) — canonical
            # helper is _norm_group_policy in checks/_shared.py; inlined here to keep
            # risk.py free of a non-aggregator import (see CLAUDE.md §3.1-a). Feishu-scoped
            # ONLY: every other channel schema checked in the dist (LINE
            # reply-payload-transform-Ce9ZfUxA.js:19-23; the "core" schema shared by
            # Telegram/Discord/Slack/Signal/Matrix/Nextcloud-Talk/Zalo,
            # zod-schema.core-DviqqtPj.js:424-428) rejects "allowall" outright, so it
            # cannot appear on those channels in a config that actually loaded — treating
            # it as "open" there would label a schema-impossible value as an open group.
            if node.get("groupPolicy") == "open" or (
                name == "feishu" and node.get("groupPolicy") == "allowall"
            ):
                parts.append("open group")
            if parts:
                labels.append(f"{name} ({', '.join(parts)})")
                break
    return labels


def _channels_with_visibility_all(cfg: dict) -> list[str]:
    """Channel names where effective contextVisibility is 'all' (untrusted input exposed).

    Mirrors B26's effective-visibility logic: per-ACCOUNT value first, then the per-channel
    value, then channels.defaults.contextVisibility, then the OpenClaw default of 'all' —
    the precedence the dist resolver documents and implements
    (context-visibility-BVlvSMUZ.js:8-13). Returns [] when no channels are configured
    (zero-FP on empty/absent channels key).

    B-283 (c): the accounts descent was missing here AND in B26. Because RISK-15 keys off
    B26's status and RISK-18 calls this helper directly, fixing only one site would have
    left one of the two chains blind — they had to move together. The canonical
    implementation is _channels_with_context_visibility_all in checks/_shared.py; this is a
    deliberate mirror (risk.py imports only via the checks aggregator, CLAUDE.md §3.1-a),
    so the two must be kept in step — tests/test_b283_shallow_reads.py pins them equal.
    """
    channels = cfg.get("channels")
    if not isinstance(channels, dict):
        return []
    defaults_node = channels.get("defaults")
    global_default = (
        defaults_node.get("contextVisibility")
        if isinstance(defaults_node, dict)
        else None
    )
    result = []
    for name, c in channels.items():
        if name == "defaults" or not isinstance(c, dict):
            continue
        channel_value = c.get("contextVisibility")
        accounts = c.get("accounts")
        # isinstance guard rather than `or {}` — a non-dict `accounts` is truthy and would
        # raise on .values(); mirrors _channels_with_context_visibility_all in
        # checks/_shared.py.
        for node in [c] + (list(accounts.values()) if isinstance(accounts, dict) else []):
            if not isinstance(node, dict):
                continue
            effective = (
                node.get("contextVisibility") or channel_value or global_default or "all"
            )
            if effective == "all":
                result.append(name)
                break
    return result


def _wildcard_elevated_providers(cfg: dict) -> list[str]:
    """Providers whose tools.elevated.allowFrom grants '*' (every sender).

    Mirrors B3's wildcard detection: allowFrom is a provider-dict
    {provider: ["*"|sender,...]}; a provider counts when its value is "*" or a
    list containing "*". Returns [] for any other shape (zero-FP).
    """
    allow = dig(cfg, "tools.elevated.allowFrom")
    if not isinstance(allow, dict):
        return []
    return [p for p, v in allow.items()
            if v == "*" or (isinstance(v, list) and "*" in v)]


def _has_heartbeat_cfg(cfg: dict) -> bool:
    """Autonomous heartbeat configured at agents.defaults or any per-agent entry."""
    if dig(cfg, "agents.defaults.heartbeat"):
        return True
    agents = dig(cfg, "agents.list")
    if isinstance(agents, list):
        return any(isinstance(a, dict) and dig(a, "heartbeat") for a in agents)
    return False


def _host_reaching_bind(cfg: dict) -> str | None:
    """Label for a docker bind that reaches the host filesystem broadly, else None.

    Matches docker.sock (full host control) or a root-level host source
    (/, /home, /root, /etc, /var, /usr). Narrow data binds (e.g. /data:/data) do
    NOT match — keeps the RISK-16 chain zero-FP.
    """
    binds = dig(cfg, "agents.defaults.sandbox.docker.binds")
    if isinstance(binds, str):
        binds = [binds]
    if not isinstance(binds, list):
        return None
    sensitive_roots = ("", "/", "/home", "/root", "/etc", "/var", "/usr")
    for b in binds:
        s = str(b)
        if "docker.sock" in s:
            return "docker.sock bind (full host control)"
        src = s.split(":", 1)[0].rstrip("/")
        if src in sensitive_roots:
            return f"root-level host bind from {src or '/'}"
    return None


def _has_untrusted_ingress(tools: list[str], cfg: dict) -> bool:
    """True when there is at least one vector for untrusted content to reach the agent.

    Uses _external_input_channels (open + allowlist + pairing, with a Feishu channel's
    groupPolicy "allowall" alias normalized to "open" — B-283, Feishu-scoped) rather than
    _open_channels (open only) so that restricted-but-external channels are correctly
    counted as ingress.
    """
    return bool(_external_input_channels(cfg)) or _hint(tools, INPUT_TOOL_HINTS)


def _sandbox_off(cfg: dict) -> bool:
    """True when sandbox is explicitly off OR completely absent alongside exec tools."""
    mode = dig(cfg, "agents.defaults.sandbox.mode")
    return mode == "off" or mode is None


def _has_mutable_identity(findings: list[Finding], cfg: dict) -> bool:
    """True when B30 FAILs OR any channel has dangerouslyAllowNameMatching."""
    b30 = _finding_status(findings, "B30")
    if b30 == FAIL:
        return True
    channels = cfg.get("channels")
    if isinstance(channels, dict):
        for c in channels.values():
            if isinstance(c, dict) and c.get("dangerouslyAllowNameMatching"):
                return True
    return False


def _browser_ssrf(findings: list[Finding], cfg: dict) -> bool:
    """True when B38 FAILs OR browser.ssrfPolicy.dangerouslyAllowPrivateNetwork is set."""
    if _finding_status(findings, "B38") == FAIL:
        return True
    return bool(dig(cfg, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"))


def _control_plane_exposed(findings: list[Finding], cfg: dict) -> bool:
    """True when B32 FAILs (control-plane reachable from an exposed surface)."""
    return _finding_status(findings, "B32") == FAIL


def _bootstrap_writable(findings: list[Finding]) -> bool:
    """True when B20 FAILs (bootstrap / memory files are world-writable)."""
    return _finding_status(findings, "B20") == FAIL


def _self_mod_exec(findings: list[Finding]) -> bool:
    """True when B22 FAILs (self-modification path open without approval)."""
    return _finding_status(findings, "B22") == FAIL


def _session_cross_user(findings: list[Finding], cfg: dict) -> bool:
    """True when B39 FAILs OR session.dmScope == 'main'."""
    if _finding_status(findings, "B39") == FAIL:
        return True
    return dig(cfg, "session.dmScope") == "main"


def _host_blind(ctx: Context) -> bool:
    """True only when host detection RAN, the platform is supported, and
    no visibility monitor is PRESENT across all four families (network IDS /
    audit / FIM / EDR) — every one is either definitively ABSENT or an honest
    UNKNOWN (B-172: a read-only, often non-root scan cannot PROVE one of these
    is absent, so a miss is UNKNOWN rather than a confident 'absent' — but it
    still means no monitor was CONFIRMED present).

    Any 'present' monitor yields no chain. A class status of ``None`` (the class
    key itself missing from the result) still yields no chain — that is a shape
    the real detector never produces, so it is treated as inconclusive, not
    blind. Firewall is excluded: it's prevention, not detection of a compromise.
    """
    host = getattr(ctx, "host", None)
    if not host or not host.get("supported"):
        return False
    classes = host.get("classes") or {}
    vis = ("network_ids", "host_audit", "file_integrity", "edr_av")
    statuses = [(classes.get(c) or {}).get("status") for c in vis]
    if any(s is None for s in statuses):
        return False
    return all(s in ("absent", "unknown") for s in statuses)


def _has_multi_user_channel(cfg: dict) -> bool:
    """True when any channel has a group policy (not necessarily open)."""
    channels = cfg.get("channels")
    if not isinstance(channels, dict):
        return False
    for c in channels.values():
        if isinstance(c, dict):
            if c.get("groupPolicy") is not None:
                return True
            for acc in (c.get("accounts") or {}).values():
                if isinstance(acc, dict) and acc.get("groupPolicy") is not None:
                    return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Rule implementations
# ──────────────────────────────────────────────────────────────────────────────

def _rule_open_sender_exec(ctx: Context, tools: list[str], cfg: dict) -> RiskPath | None:
    """CRITICAL: public/group sender + exec/write/elevated tool.

    An untrusted actor (anonymous DM or open group) can reach host execution
    or mutate state directly — no intermediary step required.
    """
    open_ch = _open_channel_labels(cfg)
    if not open_ch:
        return None
    if not (_has_exec_or_write_tools(tools) or "elevated" in tools):
        return None
    channel_label = open_ch[0]
    tool_label = "exec/write tool" if _hint(tools, ("exec", "shell", "fs_write", "deploy")) else "elevated tool"
    return RiskPath(
        id="RISK-01",
        severity=CRITICAL,
        title="Untrusted sender can reach host execution",
        chain=[channel_label, tool_label, "host / filesystem"],
        why=(
            f"The channel '{channel_label}' accepts messages from anyone "
            f"(dmPolicy or groupPolicy is 'open'). The agent also has "
            f"{tool_label} enabled. Any anonymous actor can craft a message "
            "that causes the agent to execute code or mutate files on the host "
            "— no additional privilege escalation required."
        ),
        fix=(
            "Lock every channel's dmPolicy and groupPolicy to 'allowlist' so only "
            "known, trusted senders can reach the agent. If open channels are required, "
            "remove or gate exec/write/elevated tools behind human approval "
            "(tools.exec.mode='ask' or tools.exec.security='ask')."
        ),
    )


def _rule_lethal_trifecta(ctx: Context, tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH: dirty input + sensitive data + outbound/exec — the explicit Trifecta path."""
    has_input = _has_untrusted_ingress(tools, cfg)
    has_sensitive = _has_sensitive_data(tools, ctx)
    has_outbound = _has_outbound(tools, cfg)
    if not (has_input and has_sensitive and has_outbound):
        return None
    open_ch = _open_channel_labels(cfg)
    input_label = open_ch[0] if open_ch else "input tool (email/web/feed)"
    sensitive_label = "secrets / credentials reachable"
    outbound_label = "outbound / exec action"
    return RiskPath(
        id="RISK-02",
        severity=HIGH,
        title="Lethal Trifecta: untrusted input → sensitive data → outbound",
        chain=[input_label, sensitive_label, outbound_label],
        why=(
            "All three legs of the Lethal Trifecta are active simultaneously: "
            "the agent ingests untrusted content, has access to sensitive data, "
            "and can take outbound or exec actions. A single prompt-injection in "
            "the untrusted input is sufficient to exfiltrate secrets or execute "
            "arbitrary commands."
        ),
        fix=(
            "Break at least one leg: (1) lock channels to allowlist and remove "
            "web/email input tools, OR (2) move secrets out of the agent's reach "
            "(use tools.exec.security='deny' for sensitive-data contexts), OR (3) "
            "gate ALL outbound/exec actions behind human approval. Keeping all "
            "three legs active is the highest-risk configuration possible."
        ),
    )


def _rule_sandbox_off_untrusted_exec(ctx: Context, tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH: sandbox off + untrusted ingress + fs_write/exec."""
    if not _sandbox_off(cfg):
        return None
    if not _has_untrusted_ingress(tools, cfg):
        return None
    if not (_hint(tools, ("exec", "shell", "fs_write", "deploy")) or "elevated" in tools):
        return None
    open_ch = _open_channel_labels(cfg)
    ingress_label = open_ch[0] if open_ch else "untrusted input (email/web/feed)"
    return RiskPath(
        id="RISK-03",
        severity=HIGH,
        title="No sandbox + untrusted ingress + exec/write tools",
        chain=[ingress_label, "no execution sandbox", "exec/write directly on host"],
        why=(
            "The execution sandbox is disabled (agents.defaults.sandbox.mode is "
            "'off' or absent), meaning exec and fs_write tools run directly on the "
            "host OS. Combined with an untrusted ingress channel, a prompt-injection "
            "payload delivered via that channel can execute code or write files on "
            "the host without any containment."
        ),
        fix=(
            "Enable the sandbox: set agents.defaults.sandbox.mode to 'non-main' or "
            "'all', and configure agents.defaults.sandbox.docker (network='bridge', "
            "no broad host binds). If sandboxing is not possible, remove exec/write "
            "tools or lock all ingress channels to a strict allowlist."
        ),
    )


def _rule_mutable_identity_elevated(ctx: Context, findings: list[Finding],
                                    tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH: mutable identity + elevated/privileged tools."""
    if not _has_mutable_identity(findings, cfg):
        return None
    if not ("elevated" in tools or _hint(tools, ("exec", "shell"))):
        return None
    return RiskPath(
        id="RISK-04",
        severity=HIGH,
        title="Mutable agent identity + elevated/privileged tools",
        chain=["identity spoofing or name-matching bypass", "elevated / exec tools", "privilege escalation"],
        why=(
            "The agent's identity can be impersonated or matched by name "
            "(dangerouslyAllowNameMatching is enabled or B30 fails), AND elevated "
            "or exec tools are present. An attacker who spoofs the agent's name "
            "in a channel can cause the agent to treat their messages as "
            "coming from a trusted source and invoke privileged capabilities."
        ),
        fix=(
            "Disable dangerouslyAllowNameMatching in all channel configurations "
            "and require cryptographic identity verification (e.g. token-based "
            "auth). Restrict elevated tool allowFrom to explicit, verified sender "
            "IDs — never '*' or name-matched identities."
        ),
    )


def _rule_browser_ssrf_secrets(ctx: Context, findings: list[Finding],
                                tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH: browser SSRF + secrets reachable."""
    if not _browser_ssrf(findings, cfg):
        return None
    if not _has_sensitive_data(tools, ctx):
        return None
    return RiskPath(
        id="RISK-05",
        severity=HIGH,
        title="Browser SSRF to private network + secrets reachable",
        chain=["browser tool", "SSRF to private/internal network", "secrets / credentials exfiltration"],
        why=(
            "The browser tool is allowed to reach private or internal network "
            "addresses (browser.ssrfPolicy.dangerouslyAllowPrivateNetwork is set "
            "or B38 fails), and the agent has access to sensitive credentials. "
            "A prompt-injection payload in a web page can redirect the browser "
            "to internal services (metadata APIs, credential stores) and exfiltrate "
            "the retrieved data."
        ),
        fix=(
            "Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false (or "
            "remove it). Configure an explicit allowlist of permitted domains. "
            "Move credentials out of the agent's reach, or gate browser tool "
            "invocations behind human approval."
        ),
    )


def _rule_control_plane_exposed(ctx: Context, findings: list[Finding],
                                 tools: list[str], cfg: dict) -> RiskPath | None:
    """CRITICAL: control-plane reachable from an exposed/open surface."""
    if not _control_plane_exposed(findings, cfg):
        return None
    open_ch = _open_channel_labels(cfg)
    has_open_surface = bool(open_ch) or _has_untrusted_ingress(tools, cfg)
    if not has_open_surface:
        return None
    surface_label = open_ch[0] if open_ch else "untrusted input surface"
    return RiskPath(
        id="RISK-06",
        severity=CRITICAL,
        title="Control plane reachable from open/exposed surface",
        chain=[surface_label, "control-plane endpoint", "full agent takeover"],
        why=(
            "The agent's control plane (management API, admin interface) is "
            "reachable from an open or untrusted surface (B32 fails). An attacker "
            "with access to an open channel or input vector can send commands "
            "directly to the control plane, potentially taking over the agent "
            "configuration, installing skills, or reading all secrets."
        ),
        fix=(
            "Restrict control-plane access to loopback or a trusted VPN "
            "interface only. Lock all external channels to an allowlist. "
            "Enable strong auth (token ≥ 24 chars) on the control-plane endpoint "
            "and never expose it on a public or open interface."
        ),
    )


def _rule_self_modification(ctx: Context, findings: list[Finding],
                             tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH: writable bootstrap + exec/fs_write without approval."""
    # Check B20 (bootstrap write) or B22 (self-modification) failing
    has_writable_bootstrap = (_finding_status(findings, "B20") == FAIL
                               or _finding_status(findings, "B22") == FAIL)
    if not has_writable_bootstrap:
        return None
    if not (_hint(tools, ("exec", "shell", "fs_write", "deploy")) or "elevated" in tools):
        return None
    # Only fire when there is no approval gate (real OpenClaw field: tools.exec.mode)
    if _has_approval_gate(cfg):
        return None
    return RiskPath(
        id="RISK-07",
        severity=HIGH,
        title="Self-modification: writable identity/bootstrap + exec without approval",
        chain=["exec / fs_write tool (no approval gate)", "writable bootstrap/identity files",
               "agent identity rewritten → persistent compromise"],
        why=(
            "Bootstrap or identity files (SOUL.md / AGENTS.md / TOOLS.md) are "
            "group- or world-writable (B20 or B22 fails), AND the agent has "
            "exec or fs_write tools enabled without a human approval gate. The "
            "agent can therefore rewrite its own instructions, identity, or "
            "installed skills — a single successful prompt-injection makes the "
            "compromise persistent across restarts."
        ),
        fix=(
            "Run 'chmod 700 workspace/ && chmod 600 workspace/SOUL.md "
            "workspace/AGENTS.md workspace/TOOLS.md' to remove group/world "
            "write access. Also add an approval gate: set tools.exec.mode='ask'/'allowlist' "
            "(or tools.exec.security='ask') so every write action needs explicit "
            "human sign-off."
        ),
    )


def _rule_session_cross_user(ctx: Context, findings: list[Finding], cfg: dict) -> RiskPath | None:
    """MEDIUM: session cross-user data leak + multi-user channel."""
    if not _session_cross_user(findings, cfg):
        return None
    if not _has_multi_user_channel(cfg):
        return None
    return RiskPath(
        id="RISK-08",
        severity=MEDIUM,
        title="Session context shared across users in a multi-user channel",
        chain=["multi-user channel", "session.dmScope='main' (shared session)", "cross-user data leak"],
        why=(
            "The session scope is set to 'main' (or B39 fails), meaning all "
            "users in a multi-user channel share the same session context. "
            "A message from one user can inadvertently reveal another user's "
            "conversation history, personal data, or injected context."
        ),
        fix=(
            "Set session.dmScope to 'per-user' so each DM participant receives "
            "an isolated session context. Audit channel configurations to ensure "
            "no group channel inadvertently shares session state across users."
        ),
    )


def _rule_malicious_skill_exfil(ctx: Context, findings: list[Finding],
                                tools: list[str], cfg: dict) -> RiskPath | None:
    """CRITICAL: a malicious installed skill (B13 FAIL) + outbound egress = active exfiltration.

    A flagged skill runs with the agent's FULL permissions; if the agent can also
    reach out (messaging channels, external-service skills, outbound tools), the
    malicious skill has a live path to read secrets/data and send them out.
    """
    if _finding_status(findings, "B13") != FAIL:
        return None
    has_egress = (
        _has_outbound(tools, cfg)
        or bool(cfg.get("channels"))
        or _finding_status(findings, "B14") in (FAIL, WARN)
    )
    if not has_egress:
        return None
    return RiskPath(
        id="RISK-09",
        severity=CRITICAL,
        title="Malicious installed skill can exfiltrate your data",
        chain=[
            "malicious installed skill (B13)",
            "runs with full agent permissions",
            "outbound egress (channels / external skills)",
            "credential & data exfiltration",
        ],
        why=(
            "ClawSecCheck flagged an installed skill as malicious (B13 — the ClawHavoc "
            "class). Skills run with the agent's FULL permissions, and this agent has "
            "an outbound egress surface (messaging channels and/or external-service "
            "skills). The malicious skill can read your secrets and conversation data "
            "and send them out — this is an active exfiltration path, not theoretical."
        ),
        fix=(
            "Uninstall the flagged skill(s) NOW (see the B13 finding for the name), and "
            "ROTATE every secret it could have reached — channel tokens, cloud keys, "
            "password managers. Only reinstall skills whose source you have read."
        ),
    )


def _rule_host_blind(ctx: Context, tools: list[str], cfg: dict) -> RiskPath | None:
    """MEDIUM: a high-privilege agent on a host with no CONFIRMED detection monitoring.

    Not an exploit chain like the others — a visibility gap: if this agent is
    compromised, nothing on the host (IDS / audit / FIM / EDR) would notice.
    Fires when no visibility class is confirmed present — each is either
    definitively absent or an honest unknown (B-172: a read-only miss is not
    proof of absence, but it is also not evidence of presence).
    """
    if not _host_blind(ctx):
        return None
    if not (_has_exec_or_write_tools(tools) and _has_untrusted_ingress(tools, cfg)):
        return None
    return RiskPath(
        id="RISK-10",
        severity=MEDIUM,
        title="Powerful agent on an unmonitored host — a breach would be invisible",
        chain=[
            "untrusted input reaches the agent",
            "agent can execute / write on the host",
            "no host detection (IDS / audit / file-integrity / EDR)",
            "a compromise would leave no trace",
        ],
        why=(
            "This agent can act on the host (exec / write / elevated tools) and is "
            "reachable by untrusted input, yet ClawSecCheck found no evidence of any "
            "host detection monitoring — no confirmed network IDS, audit logging, "
            "file-integrity monitor, or endpoint/EDR sensor (some of these may simply "
            "be unreadable by a non-root scan). If the agent were compromised via a "
            "prompt injection, the resulting activity would very likely go unseen."
        ),
        fix=(
            "Add at least one host detection layer so a compromise is observable: "
            "enable auditd with watches on the agent's files, install a file-integrity "
            "monitor (AIDE), and/or deploy an EDR/IDS (Wazuh, Suricata). Alternatively, "
            "shrink the agent's blast radius (sandbox it, lock channels to an allowlist, "
            "remove exec/write tools) so an unseen compromise matters less."
        ),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def _rule_delegation_reassembly(ctx: Context, findings: list[Finding]) -> RiskPath | None:
    """HIGH: the trifecta reassembles ACROSS agents via the attested delegation graph.

    Fires only when an untrusted-input agent can transitively reach both a sensitive-data
    and an outbound agent through an edge that is NOT a structural wall (schema return) —
    the same condition as B47's WARN. A fully-walled reach yields no chain (the wall
    blocks it), and no attestation yields no chain (zero false-positives by design).
    """
    r = _reassembly(ctx)
    if not r or not r.get("reachable") or (r.get("weakest_tier") or 1) >= 3:
        return None
    entry, sens, outb = r["entry"], r["sensitive_agent"], r["outbound_agent"]
    return RiskPath(
        id="RISK-11",
        severity=HIGH,
        title="Cross-agent trifecta reassembly (confused deputy)",
        chain=[f"{entry} (untrusted input)",
               f"{sens} (sensitive data)",
               f"{outb} (outbound)"],
        why=(
            "No single agent holds the full Lethal Trifecta, but the untrusted-input "
            f"agent '{entry}' can drive a sensitive-data agent and an outbound agent "
            "across delegation edges that are not structural walls (raw passthrough / "
            "text filter / undeclared return). A single prompt-injection at the entry "
            "agent can orchestrate the others to exfiltrate secrets or take action — the "
            "trifecta reassembles across the graph (a confused-deputy chain)."
        ),
        fix=(
            "Break one edge: make the callee return a typed/structured value (a wall) so "
            "injected instructions and raw data cannot flow back, OR remove the delegation "
            f"reach so '{entry}' cannot drive both a sensitive-data and an outbound agent."
        ),
    )


def _rule_fs_write_tamper(ctx: Context, findings: list[Finding],
                          tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH: broad filesystem-write capability (B55) + untrusted ingress = tamper/persistence.

    Fires only when B55 already found a write-capable tool that is broadly reachable or
    ungated (FAIL or WARN) AND there is an untrusted ingress vector. Keyed on the B55
    fs-write verdict rather than on raw tool names, so it is the capability-scoping framing
    of the write risk (distinct from RISK-01's open-sender-reaches-exec path).
    """
    if _finding_status(findings, "B55") not in (FAIL, WARN):
        return None
    if not _has_untrusted_ingress(tools, cfg):
        return None
    open_ch = _open_channel_labels(cfg)
    ingress_label = open_ch[0] if open_ch else "untrusted input (email/web/feed)"
    return RiskPath(
        id="RISK-12",
        severity=HIGH,
        title="Untrusted input + broad filesystem-write = tamper / persistence",
        chain=[ingress_label, "broad fs-write tool (unscoped, no approval gate)",
               "files overwritten → tamper / persistence implant"],
        why=(
            "The agent is granted a filesystem-write tool (fs_write / apply_patch) that "
            "B55 found broadly reachable or ungated, AND untrusted content can reach the "
            "agent (an open channel or an input tool). A single prompt-injection in that "
            "untrusted input can drive arbitrary file writes — overwriting bootstrap or "
            "skill files to implant persistent instructions, or tampering with data the "
            "agent later trusts."
        ),
        fix=(
            "Scope the write capability: set tools.exec.mode='ask' so writes need human "
            "sign-off, restrict tools.elevated.allowFrom to an explicit allowlist (no '*'), "
            "and lock ingress channels to 'allowlist'. Removing the fs_write/apply_patch "
            "grant entirely also breaks the chain."
        ),
    )


def _rule_markdown_image_persistence(ctx: Context, findings: list[Finding]) -> RiskPath | None:
    """HIGH (RISK-13): markdown-image exfil + writable bootstrap/memory = persistence/exfil.

    B59 already shows that remote markdown/HTML image URLs can leak data out of the
    agent context. If bootstrap or memory files are writable (B20 or B22 fail), the
    same attacker can write a payload or instruction back into files the agent reloads
    later. That turns a one-shot exfil channel into a persistence-plus-exfil path.
    """
    if _finding_status(findings, "B59") not in (FAIL, WARN):
        return None
    if not (_bootstrap_writable(findings) or _self_mod_exec(findings)):
        return None
    return RiskPath(
        id="RISK-13",
        severity=HIGH,
        title="Markdown-image exfil + writable memory/bootstrap = persistence / exfil",
        chain=[
            "remote markdown image URL with data-bearing query params",
            "writable bootstrap / memory files",
            "persisted payload + exfiltration channel",
        ],
        why=(
            "B59 shows that a remote markdown/image URL can carry data out of the agent "
            "context. If bootstrap or memory files are writable (B20 or B22 fails), the "
            "same attacker can write a payload or instruction back into files the agent "
            "reloads later. The result is a persistence-plus-exfil chain: steal data now, "
            "leave behind code or instructions that survive restart."
        ),
        fix=(
            "Remove remote markdown/image URLs from untrusted content, keep bootstrap and "
            "memory files read-only, and require approval for any filesystem write that "
            "could persist instructions."
        ),
    )


def _rule_sleeper_delayed_rce(ctx: Context, findings: list[Finding],
                              tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH (RISK-17): conditional sleeper trigger + scheduled exec = delayed RCE.

    B65 already flags conditional sleeper instructions that wait for a later trigger.
    If the agent also runs on a schedule (cron or heartbeat) and can execute code or
    write files, the hidden payload can sit dormant until the trigger occurs and then
    run without another review step.
    """
    if _finding_status(findings, "B65") not in (FAIL, WARN):
        return None
    scheduled = bool(dig(cfg, "cron")) or _has_heartbeat_cfg(cfg)
    if not scheduled:
        return None
    if not (_has_exec_or_write_tools(tools) or "elevated" in tools):
        return None
    schedule_label = "cron scheduler" if dig(cfg, "cron") else "heartbeat"
    return RiskPath(
        id="RISK-17",
        severity=HIGH,
        title="Conditional sleeper trigger + scheduled execution = delayed RCE",
        chain=[
            "conditional sleeper trigger in bootstrap or skill",
            f"{schedule_label} keeps the agent running later",
            "exec/write tool fires when the trigger condition appears",
            "delayed RCE",
        ],
        why=(
            "B65 surfaces hidden instructions that wait for a future trigger. If the agent "
            "also runs on a schedule and can execute code or write files, the hidden payload "
            "can sit dormant until the trigger appears and then run without another review. "
            "That turns a delayed instruction into a delayed remote code execution path."
        ),
        fix=(
            "Remove sleeper-trigger instructions, disable cron or heartbeat where they are not "
            "needed, and gate exec/write tools behind human approval."
        ),
    )


def _rule_self_escalating_autonomy(ctx: Context, findings: list[Finding],
                                   tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH (RISK-14): wildcard-elevated sender + heartbeat = self-escalating loop.

    A provider whose tools.elevated.allowFrom is '*' lets ANY sender invoke elevated
    tools (B3 flags this alone); a configured heartbeat makes the agent act unattended
    (B17 flags this alone). Neither existing check — nor any RISK rule — captures the
    conjunction: one injected instruction from an untrusted sender drives elevated
    actions that the heartbeat keeps re-running with no human in the loop (ATLAS
    AML.T0053). Fires only when BOTH legs are explicitly present → zero-FP.
    """
    providers = _wildcard_elevated_providers(cfg)
    if not providers:
        return None
    if not _has_heartbeat_cfg(cfg):
        return None
    return RiskPath(
        id="RISK-14",
        severity=HIGH,
        title="Wildcard-elevated sender + heartbeat = self-escalating autonomy loop",
        chain=[
            f"any sender via wildcard elevated provider(s): {', '.join(providers)}",
            "injected instruction invokes elevated tools",
            "heartbeat re-runs the agent unattended -> self-escalating privilege loop",
        ],
        why=(
            "A provider in tools.elevated.allowFrom is set to '*', so any sender on that "
            "channel can invoke elevated tools, and a heartbeat (agents.defaults.heartbeat "
            "or a per-agent heartbeat) makes the agent act on its own schedule. Together, a "
            "single prompt-injection from an untrusted sender can trigger elevated actions "
            "that the heartbeat keeps re-running unattended — a self-escalating autonomous "
            "privilege loop with no human in the path."
        ),
        fix=(
            "Replace the '*' in tools.elevated.allowFrom with an explicit per-provider "
            "sender allowlist, and gate elevated execution (tools.exec.mode='ask'). If "
            "unattended autonomy is not required, disable the heartbeat. Breaking either "
            "leg breaks the chain."
        ),
    )


def _rule_sandbox_cred_controlplane(ctx: Context, findings: list[Finding],
                                    tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH (RISK-16): rw workspace + host-reaching bind + plaintext gateway password.

    sandbox-escape -> credential-read -> control-plane takeover. B4 flags the rw
    workspace and the host bind; B1 flags the plaintext password — but no RISK rule
    unifies the three-leg path. Fires only when all three are explicitly present, so
    FP is no higher than the individual B4/B1 findings.
    """
    if dig(cfg, "agents.defaults.sandbox.workspaceAccess") != "rw":
        return None
    bind_label = _host_reaching_bind(cfg)
    if not bind_label:
        return None
    if not dig(cfg, "gateway.auth.password"):
        return None
    return RiskPath(
        id="RISK-16",
        severity=HIGH,
        title="Sandbox host-reach + plaintext gateway credential = control-plane takeover",
        chain=[
            f"rw workspace + {bind_label}",
            "agent reads plaintext gateway.auth.password from openclaw.json on the host",
            "authenticates to the control plane as admin -> takeover",
        ],
        why=(
            "The default agent sandbox grants workspaceAccess='rw' AND a docker bind that "
            "reaches the host filesystem broadly (docker.sock or a root-level source), so an "
            "exec-capable agent can read arbitrary host files. The gateway credential is "
            "stored in plaintext at gateway.auth.password in openclaw.json, so the agent can "
            "read it and authenticate to the control plane as admin — a sandbox weakness "
            "escalates to full control-plane takeover."
        ),
        fix=(
            "Set agents.defaults.sandbox.workspaceAccess to 'ro' or 'none', remove "
            "docker.sock and root-level host binds from agents.defaults.sandbox.docker.binds, "
            "and stop storing gateway.auth.password in plaintext (use gateway.auth.mode="
            "'token' with a secret from the environment / a manager). Breaking any one leg "
            "breaks the chain."
        ),
    )


def _rule_injection_browser_ssrf(ctx: Context, findings: list[Finding],
                                 tools: list[str], cfg: dict) -> RiskPath | None:
    """HIGH (RISK-15): untrusted-context ingress + browser SSRF to private network.

    Distinct from RISK-05, which keys on SECRETS being reachable: this keys on an
    untrusted-context channel (B26 FAIL/WARN — channels.<p>.contextVisibility='all') feeding a
    browser allowed onto the private network (B38). An injection in untrusted message
    content drives the browser to an internal metadata/credential endpoint and the response
    surfaces in tool output. RISK-05 and RISK-15 cover different entries (stored-cred reach
    vs injection-driven SSRF) and only co-fire when a config has both — each still names a
    distinct path. Fires only when both legs are positive → zero-FP.
    """
    if _finding_status(findings, "B26") not in (FAIL, WARN):
        return None
    if not _browser_ssrf(findings, cfg):
        return None
    return RiskPath(
        id="RISK-15",
        severity=HIGH,
        title="Untrusted context + browser SSRF to private network = metadata/credential exfil",
        chain=[
            "untrusted message content (channels.<p>.contextVisibility='all')",
            "agent browses an attacker-controlled URL",
            "SSRF to internal metadata/credential endpoint -> data in tool output",
        ],
        why=(
            "A channel exposes full untrusted context to the agent "
            "(channels.<p>.contextVisibility='all', B26), and the browser is allowed to reach "
            "private/internal addresses (browser.ssrfPolicy.dangerouslyAllowPrivateNetwork, "
            "B38). A prompt-injection in an untrusted message can make the agent fetch an "
            "internal URL — cloud metadata or a credential store — and the response surfaces "
            "in tool output. OpenClaw has no built-in egress allowlist, so the attacker-fetch "
            "leg is structurally unconstrained."
        ),
        fix=(
            "Set channels.<provider>.contextVisibility (or channels.defaults) to 'allowlist' "
            "or 'allowlist_quote', and set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork "
            "to false with an explicit browser.ssrfPolicy.hostnameAllowlist. Breaking either "
            "leg breaks the chain."
        ),
    )


def _rule_persistent_foothold(ctx: Context, findings: list[Finding],
                              cfg: dict) -> RiskPath | None:
    """HIGH (RISK-18): contextVisibility=all + cron + heartbeat = persistent foothold.

    Indirect prompt injection via a contextVisibility='all' channel plants a cron task
    that re-runs under heartbeat autonomy, creating a persistent autonomous foothold.
    Fires only when ALL THREE legs are explicitly confirmed → zero-FP.

    Attack path (ATLAS AML.T0054 / OWASP Agentic A05):
      1. Untrusted input reaches the agent via a channel with contextVisibility='all'.
      2. The injected instruction abuses the cron scheduler to schedule a persistent task.
      3. The heartbeat autonomously re-executes that task with no further human review.
    """
    vis_all_channels = _channels_with_visibility_all(cfg)
    if not vis_all_channels:
        return None
    if not dig(cfg, "cron"):
        return None
    if not dig(cfg, "agents.defaults.heartbeat"):
        return None
    ch_label = vis_all_channels[0]
    return RiskPath(
        id="RISK-18",
        severity=HIGH,
        title="Untrusted context + cron + heartbeat = persistent autonomous foothold",
        chain=[
            f"channel '{ch_label}' contextVisibility='all' → prompt injection via untrusted input",
            "injected instruction schedules a cron task (persistent scheduler surface)",
            "heartbeat re-executes cron task autonomously with no human review",
            "persistent autonomous foothold",
        ],
        why=(
            "A channel exposes full untrusted context to the agent "
            "(channels.<p>.contextVisibility='all'), a cron scheduler surface is active, "
            "and the agent runs autonomously on a heartbeat "
            "(agents.defaults.heartbeat). A prompt-injection in untrusted input can "
            "plant a cron task that the heartbeat re-executes indefinitely — no human "
            "approval is required after the initial injection. The result is a persistent "
            "autonomous foothold that survives restarts and continues running without "
            "further attacker interaction."
        ),
        fix=(
            "Set channels.<provider>.contextVisibility (or channels.defaults.contextVisibility) "
            "to 'allowlist' or 'allowlist_quote' to prevent untrusted content from reaching "
            "the agent. Disable the cron scheduler (remove the top-level 'cron' key) if "
            "scheduled tasks are not required. Set agents.defaults.heartbeat to a falsy value "
            "or add a human-approval gate for autonomous re-execution. Breaking any one leg "
            "breaks the chain."
        ),
    )


# C-197: Skill Composition Risk (SCR) — "Benign in Isolation, Harmful in Composition"
# (arXiv 2606.15242) names three mechanisms; Capability Flow is already covered at the
# agent/cred level by RISK-11's cross-agent reassembly. Architect-ratified design
# (2026-07-13): pursue Trust Transfer as a static RISK-* chain, the same way RISK-11
# reassembles trust across agents. Authorization Confusion (advisory context
# reinterpreted as formal approval) stays a documented, unimplemented residual — it is
# a RUNTIME reading of prose, not a structural property two co-installed skills expose
# statically (the same "thin static surface" honestly flagged when this task was filed).
_AUDIT_THEMED_RE = re.compile(
    r"\b(?:audit(?:s|ing|or)?|security[- ]?(?:scan(?:ner)?|check|review)|compliance|"
    r"vet(?:ting)?|verif(?:y|ies|ied|ication)|trust(?:ed)?[- ]?(?:score|report)|scanner)\b",
    re.I,
)
_SCR_HIGH_BLAST_FAMILIES = frozenset({"exec", "network", "write"})


def _rule_skill_composition_trust_transfer(ctx: Context) -> RiskPath | None:
    """MEDIUM (RISK-19, C-197): Skill Composition Risk — Trust Transfer.

    An audit/security/verification-themed installed skill is co-present with a
    SEPARATE installed skill that has exec, network, or write capability (per
    ctx.effect_profiles / _b62_actual_families, the same substrate B62 already
    uses). Neither skill is individually malicious — the risk is compositional: an
    agent can misread the audit-themed skill's benign-sounding output ("looks
    clean", "verified", "no issues found") as authorization to proceed with the
    OTHER skill's risky action. Fires only when BOTH a themed skill and a
    DIFFERENT high-capability skill are positively identified — zero-FP by design
    (a single skill matching both conditions is not a composition).
    """
    skills = getattr(ctx, "installed_skills", None)
    if not skills or len(skills) < 2:
        return None
    themed: list[str] = []
    high_blast: list[str] = []
    for name, blob in skills.items():
        decl_name, decl_desc = _b62_extract_declaration(blob, name)
        if _AUDIT_THEMED_RE.search(f"{decl_name} {decl_desc}"):
            themed.append(name)
        py_sources = ctx.installed_skill_py.get(name, [])
        if _b62_actual_families(name, ctx, py_sources) & _SCR_HIGH_BLAST_FAMILIES:
            high_blast.append(name)
    pair = next(((a, b) for a in themed for b in high_blast if a != b), None)
    if pair is None:
        return None
    audit_name, blast_name = pair
    return RiskPath(
        id="RISK-19",
        severity=MEDIUM,
        title="Audit/security-themed skill co-installed with a high-capability skill",
        chain=[
            f"{audit_name} (audit/security/verification-themed output)",
            "agent reads its output as an implicit approval signal",
            f"{blast_name} (exec / network / write capability)",
        ],
        why=(
            f"'{audit_name}' presents itself as an audit/security/verification tool, and "
            f"'{blast_name}' is a separate installed skill with exec, network, or write "
            "capability. Per the Skill Composition Risk literature (arXiv 2606.15242), a "
            "prompt injection can borrow the audit-themed skill's implied authority — its "
            f"benign-sounding summary ('looks clean', 'verified') — to green-light "
            f"'{blast_name}'s risky action, even though neither skill is individually "
            "malicious and no single skill holds both roles."
        ),
        fix=(
            f"Never let '{audit_name}'s output serve as an approval gate for "
            f"'{blast_name}' or any other high-capability skill's action — route genuinely "
            "risky actions (exec/network/write) through a human-approval step that reads "
            "the actual action, not a different skill's summary of it."
        ),
    )


# ──────────────────────────────────────────────────────────────────────────────
# B-288 / RISK-20 — hook session-key + agent-routing policy under REMOTE exposure
# ──────────────────────────────────────────────────────────────────────────────
# The two exposure kinds that are worth ESCALATING rather than merely inventorying,
# mapped to the plain-language chain step each contributes. Both are drawn from
# `_hooks_session_key_exposures` (checks/_shared.py), which transcribes the product's
# own collectHooksHardeningFindings.
#
# The product re-rates THREE checkIds from "warn" to "critical" when
# `isGatewayRemotelyExposed(cfg)` holds — `hooks.allowed_agent_ids_unrestricted`
# (audit.nondeep.runtime-C3y1Q5Fi.js:682), `hooks.request_session_key_enabled` (:689)
# and `hooks.request_session_key_prefixes_missing` (:696), each written
# `severity: remoteExposure ? "critical" : "warn"`. These arms are a deliberate SUBSET
# of those three, not a transcription of them: taking the vendor's escalation CONDITION
# is what keeps this chain aligned with `openclaw security audit`, but the choice of
# which findings deserve a chain is ours.
#
# So `request_session_key_enabled` is dropped even though the product does escalate it:
# on its own it is the OWNER'S DECISION to accept caller-chosen keys — dangerous only
# when unconstrained, which is precisely what `request_session_key_prefixes_missing`
# already reports, and `_hooks_session_key_exposures` only ever emits the latter
# alongside the former. Keeping both would double-count one posture in one chain.
# `default_session_key_unset` is not an arm either, and there the product agrees: it
# rates plain "warn" at every exposure level (:675-680), never escalating.
_R20_ARMS = {
    "request_session_key_prefixes_missing": (
        "request payloads may target arbitrary session keys "
        "(allowRequestSessionKey on, allowedSessionKeyPrefixes empty)"
    ),
    "allowed_agent_ids_unrestricted": (
        "hook requests may route to any configured agent "
        "(allowedAgentIds unset or '*')"
    ),
}


def _rule_hooks_session_key_takeover(ctx: Context, cfg: dict) -> RiskPath | None:
    """HIGH (RISK-20, B-288): remotely-reachable hook ingress with an unconstrained
    session-key or agent-routing policy.

    Fires only on positive evidence for every link:

    1. ``hooks.enabled`` is exactly ``True`` — the inbound webhook endpoint is actually
       serving. (Enforced inside ``_hooks_session_key_exposures``, which returns ``[]``
       otherwise, mirroring the product's own early return.)
    2. at least one of ``_R20_ARMS`` holds — the session-key or agent-routing policy is
       unconstrained;
    3. the gateway is PROVABLY reachable beyond loopback
       (``_gateway_remote_exposure_reason``) — proven from the config alone, not
       assumed from a profile name. ``gateway.bind=auto`` resolves to ``0.0.0.0`` only
       inside a container and to loopback otherwise, and ``gateway.bind=custom``
       resolves to whatever ``gateway.customBindHost`` says; neither is remote by
       virtue of not being the string "loopback". See that helper's docstring for the
       resolver grounding and for the residual false negative it accepts.

    WHY A CHAIN AND NOT A STANDALONE FAIL. Leg 2 is true in the DEFAULT state:
    ``allowedAgentIds`` unset means "any agent", so a standalone FAIL on it would fire on
    every hooks-enabled config with no owner misconfiguration whatever — a textbook
    Golden-Rule-#5 false positive. It is the JOIN with remote reachability that the
    product itself treats as critical, and that join is this module's job. The static
    halves stay visible unconditionally as B179 evidence.

    SEVERITY — HIGH, deliberately one notch below the vendor's "critical", and this is
    the one place we knowingly diverge. `hooks.enabled` cannot be served without a token:
    hooks-Bjrm8pWp.js:333-334 throws ``"hooks.enabled requires hooks.token"`` outright. So
    what this chain describes is BLAST-RADIUS AMPLIFICATION FOR A HOOK-TOKEN HOLDER — a
    principal who can already reach the endpoint gains cross-session write and arbitrary
    agent routing — not an unauthenticated takeover. Reserving CRITICAL for chains that
    need no credential keeps the tier meaningful. The token's own strength is B1/B179
    territory and is not re-litigated here.

    KNOWN NARROW RESIDUAL (C-135, and deliberately not "fixed"). Leg 1 uses the product
    audit's own gate, ``hooks.enabled === true`` (audit.nondeep.runtime-C3y1Q5Fi.js:633).
    The dist also has a STRICTER "hooks are actually live" predicate — ``enabled === true
    && Boolean(normalizeOptionalString(cfg.hooks.token))`` (audit-UjVvFwCi.js:389) —
    because hook resolution throws ``"hooks.enabled requires hooks.token"`` outright when
    the token is missing (hooks-Bjrm8pWp.js:332-334). So a config with ``hooks.enabled:
    true`` and NO ``hooks.token`` fires this chain while serving nothing. That is not a
    benign false positive worth narrowing the rule for: such a config does not start at
    all, so it is a broken config rather than a working one being maligned, and adopting
    the stricter leg would instead let a real, serving setup go unreported the moment its
    token moved somewhere this reader cannot see. Pinned by
    tests/test_b288_hooks_session_key.py::test_known_residual_enabled_without_token.

    HONEST LABELLING — what this does NOT claim. It does not claim the endpoint has been
    reached, nor that any cross-session write has occurred: every leg is config posture,
    and this module reads no hook request log (OpenClaw keeps none we could ground
    against). Read it as "the ingredients for cross-session takeover are all present and
    remotely reachable", not as evidence of compromise. Silence is likewise not an
    all-clear for hook exposure generally — it means these three specific legs did not
    all hold. It also covers the ROOT ``hooks`` object only; the plugin-scoped
    ``plugins.entries.*.hooks.*`` capability grants are a different surface at a
    different path and are not read by this rule or by anything else in the package yet.
    """
    kinds = {kind for kind, _ in _hooks_session_key_exposures(cfg)}
    arms = [label for kind, label in _R20_ARMS.items() if kind in kinds]
    if not arms:
        return None
    exposure = _gateway_remote_exposure_reason(cfg)
    if exposure is None:
        return None

    # Deterministic order: _R20_ARMS is a literal dict, so iteration follows source
    # order, not config key order — the report must not depend on how the user's JSON
    # happened to be written.
    detail = "; ".join(arms)
    return RiskPath(
        id="RISK-20",
        severity=HIGH,
        title="Remotely reachable hook ingress with an unconstrained session-key policy",
        chain=[
            f"gateway reachable beyond loopback ({exposure})",
            "hooks.enabled — inbound /hooks/agent endpoint serving",
            detail,
        ],
        why=(
            f"The gateway is reachable beyond loopback ({exposure}) and the inbound hook "
            f"endpoint is enabled, while its session/agent policy is unconstrained: "
            f"{detail}. A caller holding the hook token can therefore write into session "
            "keys it was never meant to touch — placing content into another session's "
            "history, where the agent reads it as trusted prior context — and/or route "
            "its request to any configured agent, including the default one. OpenClaw's "
            "own audit rates each of these critical under exactly this remote-exposure "
            "condition; ClawSecCheck reports it one notch lower because the endpoint "
            "still requires hooks.token, so this is blast-radius amplification for a "
            "token holder rather than an unauthenticated takeover. It is not evidence "
            "that the endpoint has been reached: every link here is config posture."
        ),
        fix=(
            "Constrain the hook policy rather than the network path, since the point of "
            "hooks is to be reachable. Set hooks.allowedSessionKeyPrefixes to a narrow "
            "prefix (for example [\"hook:\"]) so request-supplied keys cannot escape "
            "their own namespace — or set hooks.allowRequestSessionKey=false and let "
            "hooks.defaultSessionKey decide the session. Set hooks.allowedAgentIds to an "
            "explicit allowlist of the agents hooks may drive (or [] to deny hook agent "
            "routing entirely). If the gateway does not need to be remotely reachable, "
            "setting gateway.bind to the loopback profile closes the chain instead."
        ),
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-135 / RISK-21 — the first chain that joins CONFIG POSTURE with the LOG
# ──────────────────────────────────────────────────────────────────────────────
# Until now this engine took only static findings, and the log-observed half of the
# tool (behavioral.py / trajectory.py) was a terminal `--behavioral` branch that never
# reached the audit. So "a channel admits non-owner senders" and "a high-blast verb
# provably ran" were both known and never related. RISK-21 relates them.
#
# WHY THE COARSE JOIN IS NOT WHAT THIS IS. "An open channel exists" AND "a high-blast
# verb is proven somewhere in the log" fires on the maintainer's own machine: measured
# there, an open wildcard-group telegram channel sits beside 867 proven `bash` calls,
# and every one of those calls came from `telegram:direct` (the owner's own DM),
# `dashboard` (his own web UI) or an unrecognised `other` key — ZERO group/channel
# origins across 73 sidecars. The join therefore runs per SESSION ORIGIN
# (`trajectory.read_proven_tools_by_origin`), and it stays silent on that host, which is
# the single most important property of this rule.
#
# ADVISORY, and structurally so. RiskPaths are outside the A–F score by construction:
# cli.py computes `score = audit(...)` BEFORE calling `risk_paths(...)`, and scoring.py
# does not import this module (it lazily imports `trajaudit` instead — see
# scoring._runtime_cap_signal). That matters more here than for the static chains,
# because of the owner's I-025 ruling (implemented in B-309): only an ARGUMENTS-
# corroborated runtime signal may ever affect the grade, and only as a cap —
# exhaustively, a trajaudit-style indicator match, nothing else. This rule is
# metadata-only — it reads a verb NAME and a session-key ORIGIN KIND, never a call's
# arguments — so it is NOT the eligible signal and must not move the grade, and it
# cannot. `tests/test_risk21_*.py` pins that; `tests/test_i025_runtime_cap.py` pins
# the eligible-signal enumeration this rule is deliberately absent from.
#
# §8: the only strings that can escape are the bounded origin kind, the channel id and
# the tool verb names. The `sessionKey`'s peer-id segment is real PII (a live host's key
# reads `agent:main:telegram:direct:<telegram user id>`) and is never read into the
# bucket key — see `trajectory.parse_session_origin`.

# EGRESS is deliberately EXCLUDED from the blast classes below, though
# `attest.HIGH_BLAST_CLASSES` includes it. A channel-connected agent answers a group
# message by SENDING — an agent holding an MCP `slack_send_message` / `sessions_send`
# tool produces an EGRESS-classified call in essentially every group session it ever
# serves. Arming on that would make this chain fire on every group-enabled bot that has
# ever replied, i.e. on ordinary traffic, which is noise rather than signal. The three
# kept classes are the ones ordinary conversational traffic does NOT produce, and EXEC
# already subsumes egress in practice (attest.py's own taxonomy note: arbitrary command
# execution subsumes curl, rm and config mutation).
#
# HONEST LABELLING — this NARROWS the gap, it does not close it. Excluding EGRESS means
# a group-origin exfil performed purely through a dedicated send verb is a known false
# NEGATIVE here; the static posture for it is what A1/RISK-02 already report, and the
# runtime sequence is what T1 reports under `--behavioral`.
_R21_BLAST_CLASSES = ("EXEC", "DESTRUCTIVE", "MAILBOX_CONFIG")


def _open_group_channels(cfg: dict) -> dict:
    """Channel name -> reason, for channels whose GROUP ingress admits non-owner senders.

    Two arms, and deliberately no third notion of "open":

    * the wildcard-group shape, via ``_open_wildcard_group_channels`` — the SAME
      predicate B140 and the B-297 ingress leg use, imported through the checks
      aggregator (CLAUDE.md §3.1-a). It is already allowFrom-aware, already skips
      ``enabled: false`` channels and ``channels.defaults``, and already drops nodes
      whose group ingress is switched off outright.
    * an explicit ``groupPolicy: "open"`` (plus Feishu's ``"allowall"`` alias, which
      only Feishu's schema accepts — see ``_norm_group_policy``, mirrored inline here
      exactly as ``_open_channel_labels`` above mirrors it).

    The second arm needs NO allowFrom test, and that is a dist fact rather than a
    simplification: the live sender gate short-circuits
    ``if (params.policy.groupPolicy === "open") return allow("group_policy_open")``
    BEFORE it consults any allowlist (message-access-DucCKzfO.js:193, inside
    ``resolveChannelMessageIngress``), so a ``groupAllowFrom`` beside an open
    groupPolicy does not restrict anything. (The ``@deprecated`` SDK helper
    ``resolveSenderScopedGroupPolicy``, group-access-CyF0dAER.js:8-10, DOES downgrade
    open->allowlist when ``groupAllowFrom`` is non-empty — reading that one instead
    would have produced a silent false negative on every open group with a leftover
    allowlist.)

    DM policy is excluded on purpose. This helper feeds a join whose runtime leg is a
    GROUP/CHANNEL-origin session, so a channel that is open for DMs but allowlisted for
    groups must not arm it. ``_open_channel_labels`` above answers the different, broader
    question RISK-01 asks and correctly mixes both.

    An ABSENT ``groupPolicy`` never arms this. That is a positive-evidence choice with a
    real ambiguity behind it: the bundled zod schemas default several providers to
    ``"allowlist"`` (bundled-channel-config-schema-CkfMA6sO.js:250 and siblings) while
    the runtime resolver defaults a CONFIGURED provider to ``"open"``
    (``resolveOpenProviderRuntimeGroupPolicy``, runtime-group-policy-BEjP88cf.js:29-37).
    Arming on absence would therefore chain on a shape we cannot prove is open — a false
    positive. Not arming is a false negative, which is the safe direction here.
    """
    out = dict(_open_wildcard_group_channels(cfg))
    channels = cfg.get("channels")
    if not isinstance(channels, dict):
        return out
    for name, c in channels.items():
        if name == "defaults" or not isinstance(c, dict) or c.get("enabled") is False:
            continue
        if name in out:
            continue
        for node in _resolved_channel_nodes(c):
            if not isinstance(node, dict):
                continue
            policy = node.get("groupPolicy")
            if policy == "open" or (name == "feishu" and policy == "allowall"):
                out[name] = 'groupPolicy is "open" — any group member may command the agent'
                break
    return out


def _rule_open_group_proven_blast(ctx: Context, cfg: dict) -> RiskPath | None:
    """MEDIUM (RISK-21, F-135): open group ingress + a high-blast verb PROVEN from it.

    Fires only when all of the following hold, each on positive evidence:

    1. a channel's GROUP ingress admits non-owner senders (``_open_group_channels``);
    2. the trajectory log contains a ``tool.call`` whose session was opened from a
       GROUP or CHANNEL surface on THAT SAME channel (``EXTERNAL_ORIGIN_KINDS`` — the
       same bucket OpenClaw's own ``sessionKey.includes(":group:") ||
       includes(":channel:")`` discriminator uses, status-message-CQq9FqoB.js:445);
    3. that verb classifies EXEC / DESTRUCTIVE / MAILBOX_CONFIG (see
       ``_R21_BLAST_CLASSES`` on why EGRESS is excluded).

    HONEST LABELLING — what this does NOT claim. It does not prove a group sender
    CAUSED a particular tool call. The evidence is that the session carrying the call
    was opened from a multi-party surface and that surface is open to non-owner
    senders; the causal step between a specific message and a specific call needs the
    call's arguments, which the §8 metadata-only contract puts out of reach. Read it as
    "this exposure is not hypothetical here", not as an attribution.

    No trajectory (absent, or ``OPENCLAW_TRAJECTORY`` off) means the runtime leg is
    UNPROVEN, not proven-absent — and this rule then stays silent rather than inventing
    a chain, per this module's contract. The same holds when the scan's own bounds bite:
    ``read_proven_tools_by_origin`` caps at 60 sidecars / 8 MB each, so on a busy host a
    group-origin blast call sitting only in a dropped older session is a miss. Silence is
    therefore never an all-clear for this exposure — it means "not proven here". The
    STATIC half of it is what RISK-01 and A1 report unconditionally, and neither depends
    on the log.
    """
    open_groups = _open_group_channels(cfg)
    if not open_groups:
        return None
    home = getattr(ctx, "home", None)
    if not isinstance(home, Path):
        return None
    by_origin, meta = _trajectory.read_proven_tools_by_origin(home)
    if not meta.get("present"):
        return None

    # Config channel keys and session-key channel ids are both lowercase provider ids
    # in the dist (`normalizeLowercaseStringOrEmpty(params.channel)`,
    # session-key-VWT_xzM9.js:143), but fold both sides anyway so a hand-written
    # `channels.Telegram` cannot silently break the join.
    lowered = {name.lower(): name for name in open_groups}
    hits: dict = {}
    for (kind, channel), verbs in by_origin.items():
        if kind not in _trajectory.EXTERNAL_ORIGIN_KINDS:
            continue
        if not isinstance(channel, str):
            continue
        name = lowered.get(channel.lower())
        if name is None:
            continue
        blast = {v for v in verbs if _attest.classify_verb(v) in _R21_BLAST_CLASSES}
        if blast:
            hits.setdefault(name, set()).update(blast)
    if not hits:
        return None

    # Deterministic pick: by_origin's iteration order follows sidecar mtime, which is
    # not a property of the config and must never decide what the report says.
    channel_name = sorted(hits)[0]
    verbs = sorted(hits[channel_name])
    shown = ", ".join(verbs[:5]) + (", …" if len(verbs) > 5 else "")
    reason = open_groups[channel_name]
    return RiskPath(
        id="RISK-21",
        severity=MEDIUM,
        title="Group-origin session provably reached a high-blast tool",
        chain=[
            f"{channel_name} (open to non-owner senders: {reason})",
            "group / channel-origin session in the trajectory log",
            f"proven high-blast tool call ({shown})",
        ],
        why=(
            f"The channel '{channel_name}' admits group messages from senders who are "
            f"not the owner ({reason}), and the trajectory log records a session opened "
            f"from a group or channel surface on '{channel_name}' in which the agent "
            f"actually invoked {shown}. Both halves of this exposure were already "
            "visible in isolation — the posture as a config finding, the tool use as a "
            "log observation — but nothing related them, so a setup where an untrusted "
            "surface has demonstrably reached a high-blast primitive looked the same as "
            "one where it never had. It is not proof that a group sender caused those "
            "specific calls: that needs the call arguments, which this tool never reads."
        ),
        fix=(
            f"Decide whether group senders on '{channel_name}' are meant to reach "
            "exec/destructive/mailbox-config tools at all. If not, restrict the channel "
            "(set groupPolicy to 'allowlist' and list the permitted senders in "
            "groupAllowFrom, or scope the groups entry so it is not '*'). If open group "
            "access is intentional — a community bot, say — put the high-blast tools "
            "behind a human approval step (tools.exec.mode='ask') so an untrusted "
            "message cannot reach them unattended."
        ),
    )


def risk_paths(ctx: Context, findings: list[Finding],
                ignore: set[str] | None = None) -> list[RiskPath]:
    """Compute dangerous capability chains from config + existing findings.

    Returns [] when no chains are detected. Each rule fires only on POSITIVE
    evidence for every link — no chain is invented from absent data.
    Deduplicated by id; sorted by severity (CRITICAL first).

    F-135: RISK-21 additionally reads the trajectory sidecars under ``ctx.home``
    (metadata only — verb names and session-key ORIGIN KINDS, never call arguments or
    the peer id), so this function now performs bounded read-only file I/O. The bounds
    are ``trajectory``'s own (60 files / 8 MB per file); measured at ~0.1 s on a host
    with 73 sidecars. Every other rule remains a pure function of config + findings.

    `ignore` is the parsed `.clawseccheckignore` entry set (see baseline.py). A
    RiskPath whose id (e.g. "RISK-03") appears in `ignore` is marked
    `suppressed = True` but still RETURNED — same pattern as
    `baseline.apply()` on regular findings, so `--show-suppressed` can list it.
    Callers that render the report/JSON must filter `not p.suppressed`
    themselves (B-154: suppression here requires the RISK-id to be listed
    explicitly; suppressing an underlying check alone does not silently
    suppress the derived chain, since most chains read raw config directly
    rather than a single finding's status).
    """
    cfg = ctx.config
    tools = _enabled_tools(cfg)

    candidates: list[RiskPath] = []

    path = _rule_open_sender_exec(ctx, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_lethal_trifecta(ctx, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_sandbox_off_untrusted_exec(ctx, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_mutable_identity_elevated(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_browser_ssrf_secrets(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_control_plane_exposed(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_self_modification(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_session_cross_user(ctx, findings, cfg)
    if path:
        candidates.append(path)

    path = _rule_malicious_skill_exfil(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_host_blind(ctx, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_delegation_reassembly(ctx, findings)
    if path:
        candidates.append(path)

    path = _rule_fs_write_tamper(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_markdown_image_persistence(ctx, findings)
    if path:
        candidates.append(path)

    path = _rule_sleeper_delayed_rce(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_self_escalating_autonomy(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_sandbox_cred_controlplane(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_injection_browser_ssrf(ctx, findings, tools, cfg)
    if path:
        candidates.append(path)

    path = _rule_persistent_foothold(ctx, findings, cfg)
    if path:
        candidates.append(path)

    path = _rule_skill_composition_trust_transfer(ctx)
    if path:
        candidates.append(path)

    path = _rule_hooks_session_key_takeover(ctx, cfg)
    if path:
        candidates.append(path)

    path = _rule_open_group_proven_blast(ctx, cfg)
    if path:
        candidates.append(path)

    # Deduplicate by id (keep first occurrence)
    seen: set[str] = set()
    unique: list[RiskPath] = []
    for p in candidates:
        if p.id not in seen:
            seen.add(p.id)
            unique.append(p)

    # Sort by severity
    unique.sort(key=lambda p: _SEV_ORDER.get(p.severity, 9))

    # B-154: mark (don't drop) RISK-ids explicitly listed in .clawseccheckignore.
    if ignore:
        for p in unique:
            if p.id in ignore:
                p.suppressed = True

    return unique


# ──────────────────────────────────────────────────────────────────────────────
# Renderer
# ──────────────────────────────────────────────────────────────────────────────

_ASCII_MAP = str.maketrans({
    "→": "->",  # →
    "—": "-",   # —
    "–": "-",   # –
    "…": "...", # …
    "‘": "'",   # '
    "’": "'",   # '
    "“": '"',   # "
    "”": '"',   # "
})


def _asciify(text: str) -> str:
    return text.translate(_ASCII_MAP).encode("ascii", "replace").decode("ascii")


def render_risk_paths(paths: list[RiskPath], ascii_only: bool = False) -> str:
    """Render the 'Highest-risk paths' section as plain text.

    Returns a single string ending with a newline. When ascii_only=True, all
    non-ASCII characters are folded to ASCII equivalents.
    """
    if not paths:
        msg = "No dangerous capability chains detected.\n"
        return _asciify(msg) if ascii_only else msg

    arrow = " -> " if ascii_only else " → "  # ->  or  →
    # Imported lazily because report imports this renderer lazily too. Risk labels are
    # derived from untrusted channel/provider names and need the same output boundary as
    # ordinary findings.
    from .report import _sanitize  # noqa: PLC0415

    lines: list[str] = ["Highest-risk paths", "=" * 44, ""]

    for p in paths:
        sev_tag = f"[{_sanitize(p.severity)}]"
        # Include the id (RISK-NN) in the human output too — it was only in --json before,
        # so a finding referenced by id could not be cross-referenced in the text report.
        lines.append(f"{sev_tag} {_sanitize(p.id)}: {_sanitize(p.title)}")
        lines.append(f"  Chain : {arrow.join(_sanitize(step) for step in p.chain)}")
        lines.append(f"  Why   : {_sanitize(p.why)}")
        # Reports-only (F-074): the chain and why ARE the report; the structured
        # remediation stays available as --json data (risk_paths[].fix) only.
        lines.append("")

    out = "\n".join(lines).rstrip() + "\n"
    return _asciify(out) if ascii_only else out
