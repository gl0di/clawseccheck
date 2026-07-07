"""Topic module: capability checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import os
import re
import shutil
from pathlib import Path
from .. import attest as _attest
from .. import trajectory as _trajectory
from ..catalog import (
    BY_ID,
    FAIL,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..collector import (
    Context,
    dig,
)

from . import _shared
from ._shared import (
    _custom,
    _finding,
    _has_approval_gate,
    _hint,
    _open_channels,
)


_AUTO_GATE_BLAST = {
    "exec": ("EXEC",),
    "send": ("EGRESS",),
    "write": ("DESTRUCTIVE", "MAILBOX_CONFIG"),
}


_B31_BYPASS_CANDIDATES = ("apply_patch", "exec", "process")


# ---------- B31: Effective-tools bypass (illusory deny) ----------
# Grounded on docs.openclaw.ai (config-tools, exec, apply-patch pages).
# Deny lists can exist at three levels:
#   1. tools.deny  (global)
#   2. toolsBySender.<key>.deny  (global per-sender)
#   3. agents.list[N].tools.toolsBySender.<key>.deny  (per-agent per-sender)
# The documented footgun: denying "write"/"edit" does NOT deny "apply_patch",
# "exec", or "process" — each is a separate tool that can also write files.
# To block all file mutation use "group:fs" OR list every mutating tool.
_B31_WRITE_CLASS = frozenset({"write", "edit"})


_B71_INEFFECTIVE_RE = re.compile(r"[ *|&;/]|--")


# B55: filesystem-write tool names. Grounded: fs_write is in OUTBOUND_TOOL_HINTS and
# apply_patch is the canonical patch-writer (see B31 — "apply_patch/exec still write").
# Matched as substrings so write_file / writeFile variants of the same capability count.
_FS_WRITE_TOOL_HINTS = ("fs_write", "write_file", "writefile", "apply_patch")


def _approval_bypass_actors(
    ctx: Context,
    auto_gate_classes: set[str],
    high_classes: set[str],
) -> list[str]:
    """Return actor paths that can bypass approvals for high-blast actions.

    We only return auto-actors for action classes that map to held high-blast
    classes, and runtime actors declared in attestation evidence.
    """
    if not auto_gate_classes or not high_classes:
        return []
    relevant = set()
    for cls in auto_gate_classes:
        mapped = _AUTO_GATE_BLAST.get(cls, ())
        if any(c in high_classes for c in mapped):
            relevant.add(cls)
    if not relevant:
        return []

    actors = set(_attest.approval_bypass_actors(ctx.attestation))
    if _has_heartbeat_signal(ctx):
        actors.add("heartbeat")
    if dig(ctx.config, "cron"):
        actors.add("cron")
    return list(actors)


def _b31_collect_deny_lists(cfg: dict) -> list[tuple[str, set[str]]]:
    """Return (scope_label, deny_set) pairs for every deny list in the config.

    Scopes inspected:
      - tools.deny  (global)
      - toolsBySender.<key>.deny  (top-level, global per-sender)
      - agents.list[N].tools.toolsBySender.<key>.deny  (per-agent per-sender)
    """
    results: list[tuple[str, set[str]]] = []

    # 1. Global tools.deny
    global_deny = dig(cfg, "tools.deny")
    if isinstance(global_deny, list) and global_deny:
        deny_set = {str(t).strip().lower() for t in global_deny}
        results.append(("tools.deny (global)", deny_set))

    # 2. Top-level toolsBySender.<key>.deny
    tbs = cfg.get("toolsBySender")
    if isinstance(tbs, dict):
        for key, sender_cfg in tbs.items():
            if not isinstance(sender_cfg, dict):
                continue
            deny_val = sender_cfg.get("deny")
            if isinstance(deny_val, list) and deny_val:
                deny_set = {str(t).strip().lower() for t in deny_val}
                results.append((f"toolsBySender.{key}.deny", deny_set))

    # 3. Per-agent: agents.list[N].tools.toolsBySender.<key>.deny
    agents_cfg = cfg.get("agents")
    if isinstance(agents_cfg, dict):
        agents_list = agents_cfg.get("list")
        if isinstance(agents_list, list):
            for idx, agent in enumerate(agents_list):
                if not isinstance(agent, dict):
                    continue
                agent_tools = agent.get("tools")
                if not isinstance(agent_tools, dict):
                    continue
                agent_tbs = agent_tools.get("toolsBySender")
                if not isinstance(agent_tbs, dict):
                    continue
                for key, sender_cfg in agent_tbs.items():
                    if not isinstance(sender_cfg, dict):
                        continue
                    deny_val = sender_cfg.get("deny")
                    if isinstance(deny_val, list) and deny_val:
                        deny_set = {str(t).strip().lower() for t in deny_val}
                        results.append(
                            (f"agents.list[{idx}].tools.toolsBySender.{key}.deny", deny_set)
                        )

    return results


def _has_heartbeat_signal(ctx: Context) -> bool:
    """True when config/bootstrap indicates scheduled/heartbeat execution."""
    cfg = ctx.config
    return (
        any(path.endswith("HEARTBEAT.md") for path in getattr(ctx, "bootstrap", []))
        or dig(cfg, "agents.defaults.heartbeat")
        or any(
            dig(agent, "heartbeat")
            for agent in (dig(cfg, "agents.list") or [])
            if isinstance(agent, dict)
        )
    )


def check_attestation_mismatch(ctx: Context) -> Finding:
    """B44 — config grants a high-blast verb the agent did not self-report.

    Cross-checks the static allow-list against the attested inventory. A tool the
    config GRANTS but the agent OMITS is a drift / blind-spot / injection-mask signal:
    the dangerous verb is in reach per config, yet the self-report glossed over it.
    (The reverse — tools beyond the allow-list — is normal: built-ins and MCP tools
    are not listed there, so it is not flagged, to stay false-positive-free.)

    WARN    — config grants a high-blast verb absent from the attestation.
    PASS    — every high-blast verb in the allow-list is acknowledged.
    UNKNOWN — no attestation, or no explicit tools.allow inventory to compare.
    """
    att = ctx.attestation or {}
    reported = att.get("tools")
    if not isinstance(reported, list) or not reported:
        return _finding(
            "B44",
            UNKNOWN,
            "No tool inventory attested — nothing to cross-check against config.",
            "Provide '--attest <file>' with the agent's real 'tools' list.",
        )
    listed = dig(ctx.config, "tools.allow") or dig(ctx.config, "gateway.tools.allow") or []
    if not isinstance(listed, list) or not listed:
        return _finding(
            "B44",
            UNKNOWN,
            "Config has no explicit 'tools.allow' inventory to cross-check the "
            "self-report against.",
            "—",
        )
    # Compare on the NORMALIZED verb so MCP/provider namespacing doesn't cause a false
    # mismatch (config 'mcp__Gmail__send_email' vs attested 'send_email' are the same verb).
    reported_l = {_attest.normalize_verb(t) for t in reported if isinstance(t, (str, bytes))}
    undisclosed = [
        str(t)
        for t in listed
        if _attest.classify_verb(str(t)) in _attest.HIGH_BLAST_CLASSES
        and _attest.normalize_verb(t) not in reported_l
    ]
    if undisclosed:
        return _finding(
            "B44",
            WARN,
            "Config grants high-blast-radius tools the agent did not list in its "
            "self-report — the dangerous verb is in reach per config, but the "
            "attestation omitted it (config drift, agent blind spot, or masking).",
            "Reconcile: remove the unused grant from 'tools.allow', or have the agent "
            "re-attest its true inventory and review why it was omitted.",
            evidence=[f"granted but not attested: {n}" for n in sorted(set(undisclosed))],
        )
    return _finding(
        "B44",
        PASS,
        "Every high-blast-radius tool in the config allow-list is acknowledged in the "
        "agent's self-report — no undisclosed dangerous capability.",
        "Keep the allow-list and the attested inventory in sync.",
    )


def check_capability_blast_radius(ctx: Context) -> Finding:
    """B43 — classify the agent's REAL held verbs by blast radius.

    The config exposes tool *names* as opaque strings; it cannot tell a reversible
    'search' from an irreversible 'delete_forever' or a persistent 'create_filter'.
    The agent's self-reported inventory can. Verdict:

    PASS    — every held verb is reversible / non-egress: forward-exfil and
              delete-evidence are physically impossible (the verb isn't in hand).
    WARN    — a high-blast verb is held but a human-approval gate is reported.
    FAIL    — a high-blast verb is held AND a side-effect can fire without approval.
    UNKNOWN — no tool inventory attested (run --ask, then --attest).
    """
    att = ctx.attestation or {}
    tools = att.get("tools")
    if not isinstance(tools, list) or not tools:
        return _finding(
            "B43",
            UNKNOWN,
            "No tool inventory attested — capability blast-radius cannot be "
            "classified from config (tool names are opaque strings there).",
            "Run 'clawseccheck --ask' to emit a template, have the agent fill in its "
            "real 'tools' list, then re-run with '--attest <file>'.",
        )
    held = _attest.classify_tools(tools)
    if not held:
        # A non-empty list that yielded nothing classifiable (all non-string junk):
        # we read nothing, so report UNKNOWN rather than implying "verified safe".
        return _finding(
            "B43",
            UNKNOWN,
            "Attested tool inventory had no readable verb names — capability "
            "blast-radius could not be classified.",
            "Re-attest 'tools' as a list of the exact tool/verb name strings.",
        )
    high = {c: held[c] for c in _attest.HIGH_BLAST_CLASSES if c in held}
    if not high:
        return _finding(
            "B43",
            PASS,
            "All attested tools are reversible / non-egress — no high-blast-radius "
            "verb (arbitrary exec/shell, send/forward, delete-forever, mailbox-config) "
            "is in the agent's hands, so forward-exfil and delete-evidence are not "
            "possible.",
            "Keep the toolset minimal; re-attest after any tool grant.",
        )
    evidence = [f"{cls}: {', '.join(sorted(set(names)))}" for cls, names in high.items()]
    label = ", ".join(c.lower().replace("_", "-") for c in high)
    bypass_actors = _approval_bypass_actors(ctx, set(_attest.approval_gates_auto(att)), set(high))
    if bypass_actors or _attest.is_ungated(att):
        if bypass_actors:
            evidence.append(f"approval bypass actor(s): {', '.join(sorted(set(bypass_actors)))}")
        return _finding(
            "B43",
            FAIL,
            f"The agent holds high-blast-radius verbs ({label}) AND a side-effect "
            "can fire without human approval — a single injected instruction can "
            "reach exfil / destruction / a persistent forwarding rule.",
            "Drop the dangerous verbs the agent does not need (least privilege at "
            "the capability level), or require human approval before send/exec/write "
            "and for any mailbox-config change.",
            evidence=evidence,
        )
    return _finding(
        "B43",
        WARN,
        f"The agent holds high-blast-radius verbs ({label}). An approval gate is "
        f"reported, but holding these at all widens the blast radius if the gate is "
        f"ever bypassed.",
        "Remove any dangerous verb the agent does not strictly need; keep the "
        "approval gate on the rest.",
        evidence=evidence,
    )


def check_declared_effective_proven(ctx: Context) -> Finding:
    """B84 — declared (config) vs. effective (self-reported) vs. PROVEN (runtime-evidenced) tool use.

    B44 cross-checks two columns: what config GRANTS vs. what the agent SELF-REPORTS
    it holds. Neither proves the verb was ever actually exercised. B84 adds a third,
    stronger-inside-the-self-report-layer column: verbs the agent has LOG/TRACE
    evidence it ACTUALLY invoked (``proven_tools``). A proven high-blast verb fired
    with no approval gate is the headline signal this check exists for — it is no
    longer "the agent could" but "the agent did, ungated."

    Still an agent self-report end to end (declared < effective < proven in trust,
    but all three ultimately rest on what the agent chooses to disclose), so this
    carries ATTESTED confidence and is advisory (not scored) like B43/B44.

    PASS    — proven verbs are a subset of what's declared/effective and no proven
              high-blast verb fired without an approval gate.
    WARN    — a proven high-blast verb fired AND the attested posture is ungated
              (untrusted_to_action == 'ungated', or a runtime approval-bypass actor
              is reported) — evidence of an actual dangerous invocation, unguarded.
    UNKNOWN — no attestation, or no 'proven_tools' evidence cited (silent by default;
              this check needs runtime/log evidence, which most setups won't have).
    """
    att = ctx.attestation or {}
    # Prefer log-observed proven tool use (OpenClaw trajectory sidecar — HIGH confidence,
    # grounded in recon §9.1) over the agent's self-report (attestation — ATTESTED). Reads
    # only data.name (tool identity), never call/return payloads (§8).
    observed, _tmeta = (
        _trajectory.read_proven_tools(ctx.home) if isinstance(ctx.home, Path) else (set(), {})
    )
    if observed:
        proven = {_attest.normalize_verb(v) for v in observed}
        proven_source = "log-observed (trajectory sidecar)"
        conf = "HIGH"
    else:
        proven = _attest.attested_proven(att)
        proven_source = "agent attestation (self-report)"
        conf = None  # fall back to the catalog's ATTESTED confidence
    if not proven:
        return _finding(
            "B84",
            UNKNOWN,
            "No proven-tool-use evidence found — no trajectory log records tool calls and "
            "no 'proven_tools' were attested. This check reports ACTUAL invocation, not "
            "held capability.",
            "OpenClaw writes a per-session trajectory sidecar (on by default); run the "
            "audit on the host where those logs live, or run with '--attest' and cite "
            "'proven_tools'. With neither, the check stays UNKNOWN rather than guessing.",
        )
    declared = {
        _attest.normalize_verb(t)
        for t in (dig(ctx.config, "tools.allow") or [])
        if isinstance(t, (str, bytes))
    }
    reported = att.get("tools")
    effective = (
        {
            _attest.normalize_verb(t)
            for t in reported
            if isinstance(reported, list) and isinstance(t, (str, bytes))
        }
        if isinstance(reported, list)
        else set()
    )

    proven_high = sorted(
        v for v in proven if _attest.classify_verb(v) in _attest.HIGH_BLAST_CLASSES
    )
    bypass_actors = sorted(set(_attest.approval_bypass_actors(att)))
    ungated = _attest.is_ungated(att) or bool(bypass_actors)

    if proven_high and ungated:
        evidence = [f"proven high-blast verb: {v}" for v in proven_high]
        if bypass_actors:
            evidence.append(f"approval bypass actor(s): {', '.join(bypass_actors)}")
        elif _attest.is_ungated(att):
            evidence.append("untrusted_to_action: ungated")
        evidence.append(f"proven source: {proven_source}")
        return _finding(
            "B84",
            WARN,
            "The agent has PROVEN (log/trace evidence, not just self-reported "
            "capability) that it actually invoked a high-blast-radius verb, and the "
            "attested posture is ungated — this is no longer a theoretical capability, "
            "it is an evidenced dangerous invocation with no approval gate.",
            "Add a human-approval gate before this verb can fire, or remove the "
            "runtime actor that can trigger it without confirmation.",
            evidence=evidence,
            confidence=conf,
        )

    evidence = [f"proven source: {proven_source}"]
    dead_grants = sorted((declared or effective) - proven)
    if dead_grants:
        evidence.append(
            f"declared/effective but never proven (informational, not a finding): "
            f"{', '.join(dead_grants)}"
        )
    return _finding(
        "B84",
        PASS,
        "Proven tool use stays within the declared/effective grant, and no proven "
        "high-blast verb fired without an approval gate.",
        "Keep the trajectory sidecar (or attested 'proven_tools') current so this check "
        "keeps reflecting actual invocation, not just intent.",
        evidence=evidence,
        confidence=conf,
    )


def check_effective_tools(ctx: Context) -> Finding:
    """B31 — Effective-tools bypass (illusory deny).

    WARN    — at least one deny list blocks 'write' or 'edit' but leaves
               apply_patch/exec/process un-denied and does not use 'group:fs'.
    PASS    — deny lists exist and every one either uses 'group:fs' or denies
               the full mutating set (write, edit, apply_patch, exec, process).
    UNKNOWN — no deny lists configured anywhere.
    """
    deny_lists = _b31_collect_deny_lists(ctx.config)

    if not deny_lists:
        return _finding(
            "B31",
            UNKNOWN,
            "No tool deny-policy configured — effective-tools bypass not applicable.",
            "—",
        )

    bypassable_scopes: list[str] = []
    for scope, deny in deny_lists:
        denies_fs_group = "group:fs" in deny
        if denies_fs_group:
            # group:fs blocks all fs mutation — safe
            continue
        has_write_class = bool(_B31_WRITE_CLASS & deny)
        if not has_write_class:
            # No write/edit denied — bypass check not triggered for this list
            continue
        bypass_tools = [t for t in _B31_BYPASS_CANDIDATES if t not in deny]
        if bypass_tools:
            bypassable_scopes.append(
                f"{scope}: blocks {sorted(_B31_WRITE_CLASS & deny)!r} but not {bypass_tools!r}"
            )

    if bypassable_scopes:
        bypass_names = sorted(
            {
                t
                for scope, deny in deny_lists
                for t in _B31_BYPASS_CANDIDATES
                if t not in deny and (bool(_B31_WRITE_CLASS & deny)) and "group:fs" not in deny
            }
        )
        return _finding(
            "B31",
            WARN,
            f"A tool deny-list blocks 'write'/'edit' but not {bypass_names!r} "
            f"(and no 'group:fs') — file mutation is still possible via those tools, "
            f"so the restriction is bypassable.",
            "Deny the group token 'group:fs', or list every mutating tool "
            "(write, edit, apply_patch, exec, process) in the deny list.",
            evidence=bypassable_scopes,
        )

    return _finding(
        "B31",
        PASS,
        "Tool deny-policies block file mutation with no apply_patch/exec bypass.",
        "Keep the deny list complete or use 'group:fs' to block all file mutation.",
    )


def check_exec_applypatch_workspace(ctx: Context) -> Finding:
    """B68 — apply_patch workspace-only restriction.

    Grounded (docs.openclaw.ai/tools/exec): tools.exec.applyPatch.workspaceOnly (bool,
    default true). When false, apply_patch may write or delete files outside the workspace
    root, expanding the write blast radius.

    PASS — field is true or unset (safe default).
    WARN — field is explicitly false.
    """
    cfg = ctx.config
    val = dig(cfg, "tools.exec.applyPatch.workspaceOnly")
    if val is False:
        return _finding(
            "B68",
            WARN,
            "tools.exec.applyPatch.workspaceOnly is false — apply_patch may write or delete "
            "files outside the workspace root, expanding the write blast radius.",
            "Set tools.exec.applyPatch.workspaceOnly to true so apply_patch is restricted "
            "to the workspace directory.",
            evidence=["tools.exec.applyPatch.workspaceOnly=false (workspace restriction disabled)"],
        )
    return _finding(
        "B68",
        PASS,
        "apply_patch is restricted to the workspace (workspaceOnly=true or default).",
        "Keep tools.exec.applyPatch.workspaceOnly set to true.",
    )


def check_exec_strict_inline_eval(ctx: Context) -> Finding:
    """B69 — exec inline-eval approval gate.

    Grounded (docs.openclaw.ai/tools/exec): tools.exec.strictInlineEval (bool). With
    interpreter tools allowlisted, setting this true ensures inline eval still requires
    approval even when exec mode would allow automated execution.

    UNKNOWN — field not set; only relevant when interpreter tools are allowlisted.
    WARN    — field is false AND tools.exec.mode is set and not "deny".
    PASS    — field is true, or exec mode is "deny" / absent.
    """
    cfg = ctx.config
    val = dig(cfg, "tools.exec.strictInlineEval")
    if val is None:
        return _finding(
            "B69",
            UNKNOWN,
            "tools.exec.strictInlineEval is not set; the field is only relevant when "
            "interpreter tools are allowlisted alongside exec.",
            "If interpreter tools are allowlisted with exec enabled, set "
            "tools.exec.strictInlineEval to true.",
        )
    exec_mode = dig(cfg, "tools.exec.mode")
    if val is False and exec_mode is not None and exec_mode != "deny":
        return _finding(
            "B69",
            WARN,
            "tools.exec.strictInlineEval is false while exec is enabled — inline eval "
            "in interpreter tools can run without an approval gate.",
            "Set tools.exec.strictInlineEval to true so inline eval in interpreter "
            "tools still requires approval.",
            evidence=[
                "tools.exec.strictInlineEval=false",
                f"tools.exec.mode={exec_mode!r} (exec active)",
            ],
        )
    return _finding(
        "B69",
        PASS,
        "exec inline-eval approval is enforced or exec is not active.",
        "Keep tools.exec.strictInlineEval set to true when exec is enabled with interpreter tools.",
    )


def check_fs_write_exposure(ctx: Context) -> Finding:
    """B55 (C-013) — filesystem-write tool granted without scoping.

    A write-capable tool (fs_write / apply_patch) explicitly listed in the tool
    allowlist lets the agent create or overwrite files. Unscoped — reachable by a
    wildcard sender allowlist or an open channel without write-specific scoping — untrusted
    input can drive arbitrary writes (tamper / persistence). Advisory (scored=False):
    it names the capability and feeds RISK-12; the scored write/least-privilege
    dimensions stay with B3/B22/B31 so this never moves the grade.

    UNKNOWN — no tool allowlist declared (tools.allow / gateway.tools.allow absent):
              fs-write grants are not enumerable from config.
    PASS    — no write-capable tool granted, OR one is granted but scoped (an approval
              gate for non-open ingress, or a tight non-wildcard sender allowlist).
    WARN    — write tool granted, no approval gate and no explicit sender allowlist,
              but no proven broad reach.
    FAIL    — write tool granted AND reachable by untrusted senders (wildcard
              allowFrom or open channel) AND no approval gate.
    """
    cfg = ctx.config
    allow_a = dig(cfg, "tools.allow")
    allow_b = dig(cfg, "gateway.tools.allow")
    listed: list[str] = []
    for v in (allow_a, allow_b):
        if isinstance(v, list):
            listed.extend(str(t) for t in v)

    write_tools = sorted({t for t in listed if _hint([t], _FS_WRITE_TOOL_HINTS)})

    if allow_a is None and allow_b is None:
        return _finding(
            "B55",
            UNKNOWN,
            "Tool allowlist (tools.allow / gateway.tools.allow) is not declared in "
            "config, so filesystem-write tool grants cannot be enumerated.",
            "Declare tools.allow explicitly so write-capable tools are auditable, and "
            "scope any fs_write/apply_patch grant with an approval gate "
            "(tools.exec.mode='ask') or a tight tools.elevated.allowFrom allowlist.",
        )

    if not write_tools:
        return _finding(
            "B55",
            PASS,
            "No filesystem-write tool (fs_write / apply_patch) is granted in the tool allowlist.",
            "Keep write-capable tools out of the allowlist unless they are required.",
        )

    label = ", ".join(write_tools)
    gated = _has_approval_gate(cfg)
    allow_from = dig(cfg, "tools.elevated.allowFrom")
    tight_allowlist = isinstance(allow_from, list) and bool(allow_from) and "*" not in allow_from
    wildcard = allow_from == "*" or (isinstance(allow_from, list) and "*" in allow_from)
    # DELIBERATE: _open_channels (open-only), NOT _external_input_channels. This feeds the
    # FAIL gate below; a hard FAIL ("arbitrary writes reachable by untrusted senders")
    # requires proven-broad reach — a wildcard sender or a truly-open/public channel. An
    # allowlist/paired channel carries untrusted *content* but is not broad reach, so it
    # stays the WARN fallback (locked by test_ungated_write_without_broad_reach_warns).
    # Widening this to _external_input_channels would flip allowlist configs WARN->FAIL,
    # a §5 false-positive FAIL. B46 uses the broader helper because it is WARN-capped.
    open_ch = _open_channels(cfg)

    # Approval via tools.exec affects exec/shell-like actions; it is not a
    # write-specific boundary. Treat fs_write/apply_patch as scoped only when
    # there is a tight sender allowlist or no open-ingress channel.
    if tight_allowlist or (gated and not open_ch):
        return _finding(
            "B55",
            PASS,
            f"Filesystem-write tool granted ({label}) but scoped by an approval gate "
            f"or a tight sender allowlist.",
            "Scoping is in place — keep tools.exec.mode='ask' (or the "
            "tools.elevated.allowFrom allowlist) tight.",
            evidence=[f"write tool granted: {label}"],
        )

    if wildcard or open_ch:
        ev = [f"filesystem-write tool granted: {label}"]
        if wildcard:
            ev.append(
                "tools.elevated.allowFrom is a wildcard (any sender can invoke elevated tools)"
            )
        if open_ch:
            ev.append(f"open-ingress channel(s): {', '.join(open_ch)}")
        if not gated:
            ev.append("no approval gate (tools.exec.mode is not deny/allowlist/ask/auto)")
        elif open_ch:
            ev.append(
                "open-ingress bypasses exec-style approval and can still drive write-capable tools"
            )
        return _finding(
            "B55",
            FAIL,
            f"Broad filesystem-write capability ({label}) is reachable by untrusted "
            f"senders without write-specific scoping, so untrusted input can drive arbitrary "
            f"file writes (tamper / persistence).",
            "Add an approval gate (tools.exec.mode='ask') and restrict "
            "tools.elevated.allowFrom to an explicit allowlist (no '*'); lock open "
            "channels to 'allowlist'.",
            evidence=ev,
        )

    return _finding(
        "B55",
        WARN,
        f"Filesystem-write tool granted ({label}) without an approval gate and without "
        f"an explicit sender allowlist.",
        "Scope it: set tools.exec.mode='ask' or add a tight tools.elevated.allowFrom "
        "allowlist so only trusted senders can drive file writes.",
        evidence=[
            f"write tool granted: {label}",
            "no approval gate (tools.exec.mode is not deny/allowlist/ask/auto)",
        ],
    )


def check_node_denycommands_ineffective(ctx: Context) -> Finding:
    """B71 — gateway.nodes.denyCommands ineffective patterns.

    Grounded (docs.openclaw.ai/gateway/nodes): denyCommands matching is exact command-name
    only (e.g. 'system.run'); entries containing spaces, shell metacharacters, globs, or
    path separators are silently ineffective.

    UNKNOWN — denyCommands absent or empty; no deny list configured.
    WARN    — denyCommands non-empty and at least one entry looks non-exact.
    PASS    — all entries are bare exact command names.
    """
    cfg = ctx.config
    deny = dig(cfg, "gateway.nodes.denyCommands")
    if not deny or not isinstance(deny, list):
        return _finding(
            "B71",
            UNKNOWN,
            "gateway.nodes.denyCommands is absent or empty — no node command deny list "
            "is configured.",
            "If you want to block specific node commands, set gateway.nodes.denyCommands "
            "to bare exact command names (e.g. 'system.run').",
        )
    offenders = [str(e) for e in deny if isinstance(e, str) and _B71_INEFFECTIVE_RE.search(e)]
    if offenders:
        return _finding(
            "B71",
            WARN,
            "gateway.nodes.denyCommands contains entries with spaces, shell metacharacters, "
            "globs, or path separators — these patterns are silently ineffective because "
            "matching is exact command-name only.",
            "Replace ineffective denyCommands entries with bare exact command names only "
            "(e.g. 'system.run', not 'system.run --flag' or 'system*').",
            evidence=[f"ineffective denyCommands entry: {e!r}" for e in offenders],
        )
    return _finding(
        "B71",
        PASS,
        "All gateway.nodes.denyCommands entries are bare exact command names.",
        "Keep gateway.nodes.denyCommands entries as bare exact command names without "
        "spaces, globs, or path separators.",
    )


# ---------- C5: native binary PATH safety (advisory, POSIX only) ----------
def check_path_safety(ctx: Context) -> Finding:
    """C5 — Native binary PATH safety.

    A poisoned PATH or a writable install tree could shadow/replace the real openclaw
    binary. We check (POSIX only, stat() calls only — no file reads):

    1. The directory that contains the openclaw binary is group/world-writable.
    2. Any ANCESTOR install dir above the binary (e.g. the npm package root
       .../node_modules/openclaw) is group/world-writable — a group member could
       replace the subtree even if the immediate bin dir is tight.
    3. Any directory in $PATH that appears BEFORE the openclaw dir is
       group/world-writable (a fake 'openclaw' could be found first).

    A sticky world-writable dir (e.g. /tmp, mode 1777) is NOT flagged: the sticky bit
    blocks cross-owner rename/delete, so it is not a replace vector. The agent may also
    declare paths.openclaw_install via --attest when the binary isn't on PATH — discovery
    is agent-supplied, but the engine still stat()s the dir itself (so this stays a real
    permission check, HIGH confidence, not a weak self-report).

    WARN  — at least one such writable dir found.
    PASS  — openclaw located and binary dir / ancestors / earlier PATH dirs are tight.
    UNKNOWN — openclaw not on PATH and no attested install dir, or non-POSIX platform.

    Only stat() is called; no file contents are read.
    """
    # C5 inspects the host filesystem (PATH dirs + install-tree perms), so it belongs to
    # the host-scanning scope. When host scanning is off (--no-host / audit(include_host=
    # False)), do not stat the host — report UNKNOWN, consistent with B50–B54 (B-021).
    if not getattr(ctx, "include_host", False):
        return _custom(
            "C5",
            BY_ID["C5"].severity,
            UNKNOWN,
            "Host-filesystem scanning is disabled (--no-host), so binary-PATH "
            "safety was not assessed.",
            "Re-run without --no-host to check PATH / install-tree permissions.",
        )
    if not _shared._is_posix():
        return _custom(
            "C5",
            BY_ID["C5"].severity,
            UNKNOWN,
            "PATH safety check not applicable on non-POSIX platforms.",
            "—",
        )

    exe = shutil.which("openclaw")
    attested_install = _attest.attested_paths(ctx.attestation)["openclaw_install"]
    if not exe and not attested_install:
        return _custom(
            "C5",
            BY_ID["C5"].severity,
            UNKNOWN,
            "openclaw not found on PATH — cannot assess binary PATH safety.",
            "Run this check inside an environment where openclaw is installed, "
            "or declare paths.openclaw_install via --attest.",
        )

    writable: list[str] = []
    checked: set = set()

    def _writable_kind(d: Path) -> "tuple[str, object] | None":
        """The precise non-owner write exposure of *d*, or None if tight/sticky-exempt.
        Returns (kind, stat_result) where kind is 'group-writable', 'world-writable', or
        'group- and world-writable' so the evidence reflects the bits actually set — a
        0o775 dir is group-writable only and must never be reported as 'world-writable'.
        A sticky dir (e.g. /tmp, mode 1777) is exempt regardless of group/world bits: the
        sticky bit blocks cross-owner rename/delete, so it is not a replace vector (and
        the ancestor walk passes /tmp)."""
        try:
            st = d.stat()
        except OSError:
            return None
        m = st.st_mode
        if m & 0o1000:  # sticky -> cross-owner replace blocked
            return None
        g, w = bool(m & 0o020), bool(m & 0o002)
        if g and w:
            return "group- and world-writable", st
        if w:
            return "world-writable", st
        if g:
            return "group-writable", st
        return None

    def _flag(d: Path, prefix: str, suffix: str = "", *, replace_verb: str = "replace") -> None:
        try:
            rd = d.resolve()
        except OSError:
            rd = d
        if rd in checked:
            return
        checked.add(rd)
        result = _writable_kind(rd)
        if not result:
            return
        kind, st = result
        # B-127: a purely group-writable dir whose group currently has no members
        # besides the file's owner has no live "other member" to exploit it — note
        # the hygiene gap without asserting an active exploit. World-write (any
        # local user) and group-write with real/unknown other members are unchanged.
        if kind == "group-writable":
            other_members = _shared._group_has_other_members(st.st_gid, st.st_uid)
            if other_members is False:
                writable.append(
                    f"{prefix} is group-writable — tighten to 0755/0700; "
                    "no other group members currently"
                )
                return
        writable.append(f"{prefix} is {kind}{suffix}")

    def _walk_ancestors(start: Path, label: str, levels: int = 5) -> None:
        # Flag group/world-writable ancestor install dirs ABOVE the binary. A writable
        # ancestor (e.g. the npm package root .../node_modules/openclaw) lets a group
        # member replace the whole subtree even when the immediate bin dir is tight.
        cur = start
        for _ in range(levels):
            _flag(cur, f"{label} {cur}", " — a group member could replace the openclaw install")
            if cur.parent == cur:  # filesystem root
                break
            cur = cur.parent

    if exe:
        bin_dir = Path(exe).resolve().parent
        _flag(bin_dir, f"openclaw binary dir {bin_dir}")
        # NEW: ancestor install dirs above the resolved binary.
        _walk_ancestors(bin_dir.parent, "openclaw install ancestor dir")

        # PATH dirs that appear before the openclaw dir (shadow-attack surface).
        path_env = os.environ.get("PATH", "")
        path_dirs = [Path(p) for p in path_env.split(os.pathsep) if p]
        openclaw_index: int | None = None
        for i, d in enumerate(path_dirs):
            try:
                if d.resolve() == bin_dir:
                    openclaw_index = i
                    break
            except OSError:
                continue
        if openclaw_index is not None:
            for d in path_dirs[:openclaw_index]:
                _flag(
                    d,
                    f"PATH dir {d} (before openclaw dir)",
                    " — a fake openclaw could be planted there",
                )

    # Discovery-assisted: the agent may point at an install dir that `which` can't
    # resolve (non-PATH install). The engine still stat()s it itself.
    if attested_install:
        inst = Path(attested_install).expanduser()
        _flag(inst, f"openclaw install dir {inst} [attested]")
        _walk_ancestors(inst.parent, "openclaw install ancestor dir [attested]")

    if writable:
        detail = "; ".join(writable[:6]) + (
            f" (+{len(writable) - 6} more)" if len(writable) > 6 else ""
        )
        return _custom(
            "C5",
            BY_ID["C5"].severity,
            WARN,
            detail,
            "Remove group/world-write permission from the openclaw binary directory, "
            "its install-tree ancestors, and any PATH directories that precede it "
            "(`chmod o-w,g-w <dir>`). Only owner-controlled directories should hold or "
            "precede the openclaw install.",
            writable[:6],
        )

    where = exe or f"{attested_install} (attested)"
    return _custom(
        "C5",
        BY_ID["C5"].severity,
        PASS,
        f"openclaw at {where}; binary dir, install-tree ancestors, and earlier PATH "
        "dirs all have tight permissions.",
        "Keep install/PATH directories owner-only (chmod 755 at most, never group/world-writable).",
    )
