"""Risk engine: combinational chain detection (the Lethal Trifecta, generalised).

Detects dangerous CAPABILITY CHAINS — not isolated property checks. A chain
fires only on POSITIVE evidence for every link; UNKNOWN inputs yield no chain
(zero false-positives by design).

English-only. Read-only. Pure stdlib.
"""
from __future__ import annotations

from dataclasses import dataclass

from .catalog import CRITICAL, FAIL, HIGH, MEDIUM, WARN, Finding
from .checks import (
    _enabled_tools,
    _external_input_channels,
    _has_approval_gate,
    _hint,
    _reassembly,
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
    """Human-readable labels for open dm/group channels, e.g. 'telegram (open group)'."""
    labels = []
    channels = cfg.get("channels")
    if not isinstance(channels, dict):
        return labels
    for name, c in channels.items():
        if not isinstance(c, dict):
            continue
        nodes = [c] + list((c.get("accounts") or {}).values())
        for node in nodes:
            if not isinstance(node, dict):
                continue
            parts = []
            if node.get("dmPolicy") == "open":
                parts.append("open DM")
            if node.get("groupPolicy") == "open":
                parts.append("open group")
            if parts:
                labels.append(f"{name} ({', '.join(parts)})")
                break
    return labels


def _channels_with_visibility_all(cfg: dict) -> list[str]:
    """Channel names where effective contextVisibility is 'all' (untrusted input exposed).

    Mirrors B26's effective-visibility logic: per-channel value takes precedence, then
    channels.defaults.contextVisibility, then the OpenClaw default of 'all'. Returns []
    when no channels are configured (zero-FP on empty/absent channels key).
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
        effective = c.get("contextVisibility") or global_default or "all"
        if effective == "all":
            result.append(name)
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

    Uses _external_input_channels (open + allowlist + paired) rather than _open_channels
    (open only) so that restricted-but-external channels are correctly counted as ingress.
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


def risk_paths(ctx: Context, findings: list[Finding],
                ignore: set[str] | None = None) -> list[RiskPath]:
    """Compute dangerous capability chains from config + existing findings.

    Returns [] when no chains are detected. Each rule fires only on POSITIVE
    evidence for every link — no chain is invented from absent data.
    Deduplicated by id; sorted by severity (CRITICAL first).

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
