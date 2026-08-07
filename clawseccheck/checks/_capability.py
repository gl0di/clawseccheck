"""Topic module: capability checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import os
import re
import shutil
from pathlib import Path
from typing import NamedTuple
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
    LIMIT_DOMAIN_CONFIG,
    Context,
    dig,
)

from . import _shared
from ._shared import (
    _b323_contains_env_var_reference,
    _canon_tool,
    _config_unreadable,
    _custom,
    _external_input_channels,
    _finding,
    _has_approval_gate,
    _hint,
    _open_channels,
    _profile_is_powerful,
    _surface_absent,
    _unpolicied_open_wildcard_group_channels,
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


# B55: filesystem-write tool names. Matched as substrings so write_file / writeFile
# variants of the same capability count. B-395: NONE of these are real OpenClaw tool
# ids in the current dist (grounded: CORE_TOOL_DEFINITIONS names write/edit/apply_patch;
# "fs_write" appears only inside two legacy deny constants, never as a grantable id) —
# kept as a legacy-alias union (not the primary detection path any more, see
# _B55_FS_WRITE_TOOLS / check_fs_write_exposure below) purely so old-style configs and
# this project's own pre-existing fixtures/tests, which already use "fs_write" as their
# token, keep matching.
_FS_WRITE_TOOL_HINTS = ("fs_write", "write_file", "writefile", "apply_patch")

# B55/B-395: the real, canonical write-capable subset of _B68_FS_TOOLS. "read" is
# deliberately excluded — B68's tuple includes it because B68 asks a DIFFERENT question
# ("is any fs tool reachable"), but B55 asks specifically about WRITE exposure.
_B55_FS_WRITE_TOOLS = frozenset({"write", "edit", "apply_patch"})


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
    UNKNOWN — no attestation, or no explicit tools.allow/tools.alsoAllow inventory to
              compare (gateway.tools.allow is not a grant source — see _tool_policy_view).
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
    # B-423/B-411: grant resolution is delegated to _tool_policy_view (the same model
    # B55/B68/B84 use) rather than re-derived here. `named` is tools.allow +
    # tools.alsoAllow only -- gateway.tools.allow is deliberately excluded (it only
    # de-denies OpenClaw's default HTTP tool-deny list, never an additive grant; see
    # _tool_policy_view's docstring). grants_all (the alsoAllow-only implicit wildcard)
    # is deliberately NOT consumed here: it has no enumerable token set and no evidence
    # to cite, so there is nothing sound to compare against the self-report.
    view = _tool_policy_view(ctx.config)
    if not view.named:
        return _finding(
            "B44",
            UNKNOWN,
            "Config has no explicit tools.allow/tools.alsoAllow inventory to "
            "cross-check the self-report against.",
            "—",
        )
    # Compare on the NORMALIZED verb so MCP/provider namespacing doesn't cause a false
    # mismatch (config 'mcp__Gmail__send_email' vs attested 'send_email' are the same verb).
    reported_l = {
        _canon_tool(_attest.normalize_verb(t)) for t in reported if isinstance(t, (str, bytes))
    }
    undisclosed = [
        raw
        for canon, raw in zip(view.named, view.raw_named)
        if canon not in view.denied
        and _attest.classify_verb(raw) in _attest.HIGH_BLAST_CLASSES
        and _canon_tool(_attest.normalize_verb(raw)) not in reported_l
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
        # B-315: was FAIL, downgraded to WARN. B43 is ATTESTED/scored=False — the verdict
        # rests on the audited agent's OWN self-report, so a grade cap it could talk itself
        # into/out of is unsound (Dave's ruling: unscored checks cap at WARN).
        return _finding(
            "B43",
            WARN,
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
    stronger column: verbs the agent has LOG/TRACE evidence it ACTUALLY invoked
    (``proven_tools``). A proven high-blast verb fired with no approval gate is the
    headline signal — no longer "the agent could" but "the agent did, ungated."

    Still an agent self-report end to end (declared < effective < proven in trust, but
    all three rest on what the agent chooses to disclose), so this carries ATTESTED
    confidence and is advisory (not scored) like B43/B44.

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
    # B-423/B-411: grant resolution delegated to _tool_policy_view (the same model
    # B44/B55/B68 use). `declared` here is purely informational (the "dead grants"
    # evidence line below), never a verdict gate, so widening or narrowing it cannot
    # flip PASS->WARN. Like B44, grants_all (the alsoAllow-only implicit wildcard) is
    # deliberately NOT consumed — a "dead grants: everything minus proven" line would
    # not be a meaningful evidence line.
    view = _tool_policy_view(ctx.config)
    declared: set = {
        _canon_tool(_attest.normalize_verb(raw))
        for canon, raw in zip(view.named, view.raw_named)
        if canon not in view.denied
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
              B-362: ``not_applicable`` fires only on a COMPLETE config read with no
              deny list in any of the three scopes — with none declared, there is no
              list for a mutating tool to slip past (genuine absence, not unassessed
              risk).
    """
    deny_lists = _b31_collect_deny_lists(ctx.config)

    if not deny_lists:
        return _finding(
            "B31",
            UNKNOWN,
            "No tool deny-policy configured — effective-tools bypass not applicable.",
            "—",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
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


def _b68_fs_workspace_only_scopes(cfg: dict) -> list[tuple[str, object]]:
    """Every ``tools.fs.workspaceOnly`` value in the config, with its config path.

    B-283 (b): the field is wired at TWO scopes and a per-agent value overrides the
    global one — ``context.tools?.fs?.workspaceOnly ?? cfg.tools?.fs?.workspaceOnly``
    (audit.nondeep.runtime-C3y1Q5Fi.js:589). Reading only one scope would miss either a
    per-agent opt-out under a hardened global, or a global opt-out under agents that do
    not override it. Grounded: ``ToolFsSchema`` is referenced from ``ToolsSchema``
    (global ``tools.fs``) and ``AgentToolsSchema`` (``agents.list[].tools.fs``) —
    zod-schema.agent-runtime-C02vY4RT.js:413/542/747, with agents.list from
    zod-schema-O9ml_nmo.js:306-308.

    Returns the global scope first, then one entry per agent that sets the field.
    Unset scopes are omitted entirely so callers can distinguish "absent" from "false".
    """
    scopes: list[tuple[str, object]] = []
    global_val = dig(cfg, "tools.fs.workspaceOnly")
    if global_val is not None:
        scopes.append(("tools.fs.workspaceOnly", global_val))
    agents = dig(cfg, "agents.list")
    if isinstance(agents, list):
        for idx, agent in enumerate(agents):
            if not isinstance(agent, dict):
                continue
            val = dig(agent, "tools.fs.workspaceOnly")
            if val is not None:
                label = agent.get("name") or agent.get("id") or idx
                scopes.append((f"agents.list[{label}].tools.fs.workspaceOnly", val))
    return scopes


# The filesystem tool family tools.fs.workspaceOnly governs, verbatim from OpenClaw's own
# composite predicate: `["read","write","edit","apply_patch"].filter(isToolAllowedByPolicies)`
# (audit.nondeep.runtime-C3y1Q5Fi.js:583-588).
_B68_FS_TOOLS = ("read", "write", "edit", "apply_patch")


class _ToolPolicyView(NamedTuple):
    """One resolution of the GLOBAL tools.* layer, shared by B44/B55/B68/B84.

    Before this (B-423/B-411), each of the four had its own accumulator and the four
    disagreed (B44 read gateway.tools.allow as a grant, B84 did not; the helper
    alias-folded neither side of deny). One resolver, four projections: a check reads
    the field that answers ITS question, never re-derives the model.
    """

    named: tuple  # canonical literal tokens: tools.allow + tools.alsoAllow, deduped
    raw_named: tuple  # the ORIGINAL strings behind `named`, index-aligned (evidence)
    denied: frozenset  # canonical tools.deny tokens
    profile: object  # tools.profile as read (None when absent)
    grants_all: bool  # the effective allow list resolves to "*"
    implicit_all: bool  # grants_all came from unionAllow's injection, not a literal "*"
    enumerable: bool  # static config bounds the grant at all


def _agent_profile_widenings(cfg: dict) -> list:
    """Per-agent tools.profile entries that WIDEN beyond the global tools.profile.

    B-409: every OTHER per-agent/per-channel/per-sender policy layer this module
    doesn't read (allow/deny/group/toolsBySender/byProvider/subagent/inherited) is
    AND-ed against the global one via OpenClaw's own isToolAllowedByPolicies
    (`policies.every(...)`, tool-policy-match-CgU98OQh.js:32-34) -- narrowing-only,
    so being blind to them is an FP risk, never a false grant. tools.profile is
    different: it is resolved with `??` COALESCING, not AND-ing
    (agent-tools.policy-YD9HuYgO.js:94, and identically :232 in
    resolveEffectiveToolPolicy) -- a per-agent tools.profile REPLACES the global
    one in the AND-ed policies[] list rather than adding a second entry that
    constrains it. A global tools.profile="minimal" with a per-agent
    tools.profile="coding" therefore GRANTS write/edit/apply_patch to that agent
    even though the global layer alone would not -- the one layer this file's
    model was blind to that can WIDEN a grant, producing a lying PASS rather than
    just a missed WARN.

    Returns (path, profile_value) pairs, one per agents.list[N] whose tools.profile
    is powerful while the global tools.profile is not. When the global profile is
    already powerful no per-agent profile can widen further (there is nothing left
    to widen into), so the whole scan is skipped.
    """
    if _profile_is_powerful(dig(cfg, "tools.profile")):
        return []

    out: list = []
    agents = dig(cfg, "agents.list")
    if not isinstance(agents, list):
        return out
    for idx, entry in enumerate(agents):
        if not isinstance(entry, dict):
            continue
        profile = dig(entry, "tools.profile")
        if isinstance(profile, str) and profile and _profile_is_powerful(profile):
            out.append((f"agents.list[{idx}].tools.profile", profile))
    return out


def _tool_policy_view(cfg: dict) -> _ToolPolicyView:
    """Resolve the global tools.* layer the way the installed OpenClaw dist does.

    Three corrections over the four accumulators this replaces (B-423/B-411):

    (a) IMPLICIT WILDCARD. unionAllow (sandbox-tool-policy-ClB7s2K0.js:9-14) injects
        "*" into the effective allow list when tools.allow is absent OR an empty array
        AND tools.alsoAllow is non-empty -- so alsoAllow-only grants EVERY tool, not
        just the tokens it names. That resolver runs on the GLOBAL config, not only a
        sandbox sub-config: pickSandboxToolPolicy(params.cfg.tools) at
        agent-tools.policy-YD9HuYgO.js:96 (the function name is historical).

        SUPPRESSED when tools.profile is set. The profile is a SEPARATE policy entry
        in the same AND-ed policies[] list (agent-tools.policy-YD9HuYgO.js:92-102,
        profile at :94 and the allow/alsoAllow policy at :96) and gets alsoAllow via
        its own mergeAlsoAllowPolicy (tool-policy-BHUGxE3p.js:225-231), which has no
        unionAllow concept. The wildcard from the global layer is therefore
        intersected straight back down to the profile's own grant -- widening on it
        would override a legitimately narrow profile with "everything".

    (b) gateway.tools.allow is NOT read here, in any direction. It only REMOVES
        entries from OpenClaw's default HTTP tool-deny list
        (tool-resolution-XVJDzZpY.js:49-50, and dist docs at
        dangerous-tools-1CBnzkwG.js:22-24) -- a de-denylist over one surface. It can
        never put a tool in an agent's hands that the tool policy did not already
        grant, so treating it as a grant produced confident findings about tools the
        agent has no access to. The gateway surface is B32's (checks/_config.py).

    (c) Every token is alias-folded through _canon_tool BEFORE any comparison, on the
        allow side AND the deny side, exactly as the dist matcher does
        (tool-policy-match-CgU98OQh.js:9-19).

    NOT modelled, deliberately: allow/deny entries are glob patterns, not literals
    (compileGlobPatterns); an empty allow list with a non-empty deny means "everything
    not denied" (tool-policy-match-CgU98OQh.js:21); allowing "write" implicitly allows
    "apply_patch" (:22); and per-channel / toolsBySender / byProvider / subagent /
    inherited layers can only narrow further (each a NARROWING or verdict-neutral gap,
    never a false grant — the multi-layer-composer gap B-409 already filed).
    per-agent tools.profile is the ONE exception and is NOT in that "narrow only" set —
    see _agent_profile_widenings (B-409, Slice B): it is `??`-coalesced against the
    global profile rather than AND-ed (agent-tools.policy-YD9HuYgO.js:94, :232), so it
    can WIDEN a grant. `_b68_fs_tools_granted` unions its result in separately for
    exactly that reason; this resolver stays "the GLOBAL layer" and does not read it.
    """
    allow_raw = dig(cfg, "tools.allow")
    also_raw = dig(cfg, "tools.alsoAllow")
    deny_raw = dig(cfg, "tools.deny")
    profile = dig(cfg, "tools.profile")

    allow_is_list = isinstance(allow_raw, list)
    also_is_list = isinstance(also_raw, list)

    named: list = []
    raw_named: list = []
    seen: set = set()
    for src in (allow_raw if allow_is_list else (), also_raw if also_is_list else ()):
        for v in src:
            c = _canon_tool(v)
            if not c or c in seen:
                continue
            seen.add(c)
            named.append(c)
            raw_named.append(v if isinstance(v, str) else str(v))

    denied = frozenset(
        c for c in (_canon_tool(v) for v in (deny_raw if isinstance(deny_raw, list) else ())) if c
    )

    explicit_all = "*" in seen
    # unionAllow's own emptiness tests run on the RAW arrays, before blank-filtering
    # (sandbox-tool-policy-ClB7s2K0.js:10-12) -- so alsoAllow: [""] does inject the
    # wildcard even though it names no tool. Mirror that, do not "clean it up".
    implicit_all = (
        also_is_list
        and len(also_raw) > 0
        and (not allow_is_list or len(allow_raw) == 0)
        and profile is None  # see (a)
    )

    return _ToolPolicyView(
        named=tuple(named),
        raw_named=tuple(raw_named),
        denied=denied,
        profile=profile,
        grants_all=explicit_all or implicit_all,
        implicit_all=implicit_all,
        enumerable=bool(named) or explicit_all or implicit_all or profile is not None,
    )


def _b68_fs_tools_granted(cfg: dict) -> tuple[list[str], bool]:
    """Which filesystem tools config GRANTS, and whether that is knowable at all.

    B-283 (b). Returns ``(granted, enumerable)``. Delegates ALL policy resolution to
    _tool_policy_view — see its docstring for the grounding, including the alsoAllow
    implicit-wildcard (B-411) and the gateway.tools.allow de-denylist correction (B-423).

    Every grant source is ADDITIVE (union) so no source can narrow another: a narrow
    alsoAllow can never shrink a powerful profile's "every fs tool" verdict. deny is
    subtracted last, so nothing can defeat a deny.

    B-409: also unions in any per-agent tools.profile WIDENING (_agent_profile_widenings)
    — the one layer that can make an fs tool reachable even when the global view alone
    says nothing is granted / isn't enumerable. This runs AFTER the group:fs deny
    short-circuit above, deliberately: a global tools.deny entry is its own AND-ed
    policy layer in OpenClaw's real resolver (pickSandboxToolPolicy(cfg.tools), pushed
    unconditionally alongside the profile policy) and always intersects regardless of
    which profile substitutes in, so no per-agent widening can defeat it.

    C-135 (round 2, caught a real scored false FAIL): the widening contribution is
    INTERSECTED with the global tools.allow/alsoAllow layer when that layer is a real,
    non-empty, non-wildcard allowlist -- NOT unioned in wholesale. A first version
    unioned the full _B68_FS_TOOLS set in unconditionally whenever a widening existed,
    reasoning (wrongly) that the per-agent profile policy is the only thing that
    matters. But `pickSandboxToolPolicy(cfg.tools)` (the tools.allow/alsoAllow/deny
    layer) is its OWN separate, always-pushed AND-ed policy entry in OpenClaw's real
    resolver (agent-tools.policy-YD9HuYgO.js:92-98) -- independent of which profile
    substitutes in. `tools.allow: ["read","write"], tools.deny: ["write"]` plus a
    powerful per-agent profile has a TRUE effective set of exactly {"read"}: the
    profile grants the coding family, but the global allowlist only ever named "read"
    and "write" (and "write" is denied), so "edit"/"apply_patch" were never in the
    intersection at all -- unioning them in wholesale manufactured a grant the real
    resolver never produces, and (via B55's own explicit_write_grant computation
    picking up the separately-denied "write" token from view.named) escalated a
    genuinely benign config to a scored FAIL. When the global allow layer is empty/
    absent (or itself an explicit/implicit wildcard), it imposes no restriction on this
    axis, so the widening applies without intersection -- this is the ORIGINAL
    motivating case (a bare tools.profile with no tools.allow declared at all).

    B-409 (round 3, a false NEGATIVE this time -- previously documented as "STILL
    OPEN" in check_fs_write_exposure's docstring): a global `tools.profile` PLUS a
    non-empty global `tools.alsoAllow` used to fall straight into the "real allowlist"
    intersection branch above and lose the whole grant, because `view.named` was
    non-empty (populated by alsoAllow's own tokens) and `view.grants_all` was False.
    But `view.grants_all` is False here SOLELY because `_tool_policy_view.implicit_all`
    suppresses unionAllow's wildcard injection whenever the GLOBAL tools.profile is
    set (see its docstring, part (a)) -- sound for evaluating the global profile, but
    under a widening the profile actually AND-ed into OpenClaw's real resolver for
    this agent is the PER-AGENT one, and `pickSandboxToolPolicy(cfg.tools)` never
    reads `profile` at all, so alsoAllow's implicit "*" still applies at the
    global-allow layer for this agent regardless of which profile substitutes in.
    `view.named` being non-empty here is an ARTIFACT of the (irrelevant, for this
    agent) global-profile suppression, not a real, narrowing explicit allowlist -- so
    intersecting against it was wrong in the same direction C-135 round 2 above
    guards against being wrong in (a real allowlist that DOES narrow). Fixed by
    recomputing the same unionAllow emptiness test locally, ignoring the profile
    guard: when it says the global layer WOULD have granted "*" but for the profile
    guard, the widening applies wholesale (this new branch), exactly like the
    tools.allow-absent case already did. A real, non-empty, non-wildcard
    `tools.allow` is unaffected -- it makes the local emptiness test False too (same
    formula, minus the profile check), so it still lands in the intersection branch
    below, unchanged.
    """
    view = _tool_policy_view(cfg)
    if "group:fs" in view.denied:
        return [], True

    widenings = _agent_profile_widenings(cfg)

    granted: set = set()
    if view.grants_all or "group:fs" in view.named:
        granted |= set(_B68_FS_TOOLS)
    granted |= {t for t in _B68_FS_TOOLS if t in view.named}
    if view.profile is not None and _profile_is_powerful(view.profile):
        granted |= set(_B68_FS_TOOLS)
    if widenings:
        # The "STILL OPEN" gap this closes: when a global tools.profile is set AND
        # global tools.alsoAllow is also non-empty, _tool_policy_view's implicit_all
        # suppresses unionAllow's wildcard injection on the theory that the GLOBAL
        # profile policy governs instead (see its docstring, part (a)) -- correct for
        # that global profile. But under a widening, the profile actually AND-ed into
        # OpenClaw's real resolver for THIS agent is the per-agent one, not the global
        # one, and pickSandboxToolPolicy(cfg.tools) never reads `profile` at all -- so
        # alsoAllow's implicit "*" still applies at the global-allow layer for this
        # agent, unsuppressed by the (irrelevant, for this agent) global profile.
        # Recompute the same unionAllow eligibility test _tool_policy_view uses for
        # implicit_all, but WITHOUT the profile guard, so `view.named` being
        # non-empty ONLY because of that (now-irrelevant) suppression doesn't get
        # treated as a real, narrowing explicit allowlist below.
        global_allow_raw = dig(cfg, "tools.allow")
        global_also_raw = dig(cfg, "tools.alsoAllow")
        implicit_all_ignoring_profile = (
            isinstance(global_also_raw, list)
            and len(global_also_raw) > 0
            and (not isinstance(global_allow_raw, list) or len(global_allow_raw) == 0)
        )
        if (
            view.grants_all
            or not view.named
            or (view.profile is not None and implicit_all_ignoring_profile)
        ):
            granted |= set(_B68_FS_TOOLS)
        else:
            # A real, non-empty, non-wildcard global allowlist is its own separate
            # AND-ed policy layer that still constrains the widened profile -- only
            # the tools it ALSO names survive the intersection. This is untouched by
            # the disjunct above: when tools.allow is genuinely non-empty,
            # implicit_all_ignoring_profile is False by construction (same emptiness
            # test unionAllow itself uses), so a real explicit allowlist still lands
            # here exactly as before.
            granted |= set(_B68_FS_TOOLS) & set(view.named)

    if not view.enumerable and not widenings:
        return [], False
    return sorted(granted - view.denied), True


def _b55_write_tools_granted(
    cfg: dict,
) -> "tuple[list[str], bool, _ToolPolicyView, frozenset]":
    """B55's exact write-tool grant model (write/edit/apply_patch), factored out of
    `check_fs_write_exposure` (B-503) so a non-check consumer -- report.py's
    capability graph -- can ask "does config grant a write-capable tool" without
    re-deriving the model and silently drifting from it, the same bug class B-503
    fixed for `_enabled_tools` vs. `_b68_fs_tools_granted`: two resolvers answering
    the same question that disagree.

    Delegates to `_b68_fs_tools_granted` (the canonical write/edit/apply_patch/
    group:fs/profile/widening resolution B55/B68/B84 already share) and unions in
    B55's OWN legacy-alias fallback -- `_FS_WRITE_TOOL_HINTS` ("fs_write",
    "write_file", "writefile", "apply_patch") matched against the raw allow/
    alsoAllow tokens, because these are not real OpenClaw tool ids and
    `_b68_fs_tools_granted` only recognizes the canonical `_B68_FS_TOOLS` names (see
    check_fs_write_exposure's B-395 docstring section for why that union exists --
    real fixtures, e.g. bad_b55_fs_write_broad, still use the legacy alias).

    Returns ``(write_tools, enumerable, view, legacy_write)``: `write_tools` is the
    sorted write-capable subset (`_B55_FS_WRITE_TOOLS`) actually granted;
    `enumerable` mirrors `_b68_fs_tools_granted`'s own; `view` and `legacy_write` are
    returned too so `check_fs_write_exposure` can reuse them for its own
    `explicit_write_grant` computation (the EXPLICIT/WIDENED/IMPLICIT-WILDCARD
    distinction, which only matters for B55's internal FAIL/WARN split, not for a
    coarse "is a write tool granted at all" consumer) without a second
    `_tool_policy_view` call computing the identical thing.
    """
    granted, enumerable = _b68_fs_tools_granted(cfg)
    view = _tool_policy_view(cfg)
    legacy_write = {
        canon
        for canon, raw in zip(view.named, view.raw_named)
        if _hint([raw], _FS_WRITE_TOOL_HINTS)
    } - view.denied
    write_tools = sorted((set(granted) & _B55_FS_WRITE_TOOLS) | legacy_write)
    return write_tools, enumerable, view, legacy_write


def check_exec_applypatch_workspace(ctx: Context) -> Finding:
    """B68 — filesystem workspace-only confinement (apply_patch + the fs tool family).

    Grounded (docs.openclaw.ai/tools/exec): tools.exec.applyPatch.workspaceOnly (bool,
    default true). When false, apply_patch may write or delete files outside the workspace
    root, expanding the write blast radius.

    B-283 (b) widened this from ONE sibling of a pair to both: ``tools.fs.workspaceOnly``
    governs the whole fs read/write/edit/apply_patch family — *"Restrict filesystem tools
    (read/write/edit/apply_patch) to the workspace directory (default: false)"*
    (schema-DRyO1XBt.js:556) — so ``applyPatch.workspaceOnly: true`` alone could pass here
    while fs stayed wide open over ``~/.ssh`` / ``~/.openclaw`` / ``/etc``.

    THE DEFAULT IS FALSE, so a bare ``workspaceOnly !== true -> finding`` would fire on
    nearly every real config — a grade-wrecking blanket WARN, exactly the noise GR#5
    exists to prevent. Instead this uses OpenClaw's OWN composite predicate
    (audit.nondeep.runtime-C3y1Q5Fi.js:590)::

        fsUnguarded = fsTools.length > 0 && sandboxMode !== "all" && fsWorkspaceOnly !== true

    i.e. unconfined fs only matters when fs tools are actually GRANTED and the sandbox is
    not containing them. Every ingredient was already read by ClawSecCheck. Stays
    WARN-capable only (CheckMeta scored=False) — advisory, never moves the grade, never FAIL.

    PASS    — apply_patch confined, and fs is either workspace-confined, sandboxed
              (``agents.defaults.sandbox.mode == "all"``), or has no granted fs tools.
    WARN    — either sibling is explicitly ``false`` (OpenClaw's own dangerous-flag list,
              dangerous-config-flags-current-CrOoyQT2.js:48), or the composite predicate
              holds with the field merely absent.
    UNKNOWN — fs tool grants are not enumerable from config (no tools.allow /
              tools.alsoAllow naming an fs-family tool, and no tools.profile) and
              neither sibling is explicitly false, so the composite predicate
              genuinely cannot be evaluated.

    NARROWS, does not close: reasons over STATIC config only. Per-agent
    ``tools.allow``/``deny``/``profile`` overrides and group/sender-scoped tool policies
    can still grant fs tools to an agent this check reads as tool-less, and OpenClaw
    resolves the effective set at runtime; a config declaring no tool surface at all is
    reported UNKNOWN rather than guessed at.
    """
    unreadable = _config_unreadable("B68", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    evidence: list[str] = []

    val = dig(cfg, "tools.exec.applyPatch.workspaceOnly")
    if val is False:
        evidence.append(
            "tools.exec.applyPatch.workspaceOnly=false (workspace restriction disabled)"
        )

    fs_scopes = _b68_fs_workspace_only_scopes(cfg)
    # An explicit `false` at ANY scope is what OpenClaw itself enumerates as a dangerous
    # config flag — report it regardless of the composite predicate, because the owner
    # actively opted out of a confinement control.
    explicit_off = [(path, v) for path, v in fs_scopes if v is False]
    for path, _v in explicit_off:
        evidence.append(f"{path}=false (filesystem tools not confined to the workspace)")

    if evidence:
        return _finding(
            "B68",
            WARN,
            "Filesystem workspace confinement is explicitly disabled ("
            + ", ".join(e.split(" ", 1)[0] for e in evidence)
            + ") — file tools may read, write or delete outside the workspace root, "
            "expanding the blast radius to paths such as ~/.ssh and ~/.openclaw.",
            "Set tools.exec.applyPatch.workspaceOnly and tools.fs.workspaceOnly to true "
            "so file tools are restricted to the workspace directory.",
            evidence=evidence,
        )

    # Composite predicate: only meaningful when fs tools are actually reachable.
    #
    # Only the GLOBAL scope being true clears the whole config. A per-agent `true` under an
    # absent global confines that one agent while every agent without an override keeps the
    # product default (false) — so it is deliberately NOT treated as a blanket PASS. The
    # inverse (global true, one agent opting out with false) is already reported above,
    # because per-agent overrides global: `context.tools?.fs?.workspaceOnly ??
    # cfg.tools?.fs?.workspaceOnly` (audit.nondeep.runtime-C3y1Q5Fi.js:589).
    confined_globally = dig(cfg, "tools.fs.workspaceOnly") is True
    sandbox_mode = dig(cfg, "agents.defaults.sandbox.mode")
    if sandbox_mode == "all" or confined_globally:
        return _finding(
            "B68",
            PASS,
            "File tools are confined — workspaceOnly is set or the sandbox contains all "
            "agents (agents.defaults.sandbox.mode='all').",
            "Keep tools.exec.applyPatch.workspaceOnly and tools.fs.workspaceOnly true.",
        )

    granted, enumerable = _b68_fs_tools_granted(cfg)
    if not enumerable:
        return _finding(
            "B68",
            UNKNOWN,
            "tools.fs.workspaceOnly is not set and filesystem tool grants are not "
            "enumerable from config (no tools.allow / tools.alsoAllow naming an "
            "fs-family tool, and no tools.profile), so workspace confinement cannot "
            "be assessed. The OpenClaw default for tools.fs.workspaceOnly is false "
            "(unconfined).",
            "Declare tools.allow (or tools.profile) explicitly so tool grants are "
            "auditable, and set tools.fs.workspaceOnly to true.",
        )

    if granted:
        evidence = [
            "tools.fs.workspaceOnly unset (OpenClaw default: false)",
            f"filesystem tools granted: {', '.join(granted)}",
            f"agents.defaults.sandbox.mode={sandbox_mode!r} (not 'all')",
        ]
        widenings = _agent_profile_widenings(cfg)
        if widenings:
            global_profile = dig(cfg, "tools.profile")
            widen_desc = (
                f'widens beyond the global tools.profile={global_profile!r}'
                if global_profile is not None
                else "is the only declared tools.profile (no global tools.profile is set)"
            )
            evidence.append(
                f"grant includes a per-agent tools.profile that {widen_desc} (B-409): "
                + ", ".join(f'{path}="{profile}"' for path, profile in widenings)
            )
        return _finding(
            "B68",
            WARN,
            "Filesystem tools are granted "
            f"({', '.join(granted)}), the sandbox does not contain all agents "
            f"(agents.defaults.sandbox.mode={sandbox_mode!r}), and "
            "tools.fs.workspaceOnly is unset — its default is false, so file tools may "
            "read, write or delete anywhere the agent process can reach.",
            "Set tools.fs.workspaceOnly to true, or set agents.defaults.sandbox.mode to "
            "'all' so filesystem access is contained.",
            evidence=evidence,
        )

    return _finding(
        "B68",
        PASS,
        "apply_patch is restricted to the workspace and no filesystem tool is granted "
        "that could escape it.",
        "Keep tools.exec.applyPatch.workspaceOnly set to true, and set "
        "tools.fs.workspaceOnly to true before granting filesystem tools.",
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
    exec_active = (
        exec_mode is not None and exec_mode != "deny"
    ) or _profile_is_powerful(dig(cfg, "tools.profile"))
    if val is False and exec_active:
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

    A write-capable tool (write / edit / apply_patch) granted via the tool allowlist,
    a powerful tools.profile, or tools.alsoAllow lets the agent create or overwrite
    files. Unscoped — reachable by an open channel without write-specific scoping —
    untrusted input can drive arbitrary writes (tamper / persistence). CheckMeta stays
    scored=False (B3/B22/B31 own the general dimension); the FAIL branch is a
    per-Finding override.

    B-395: grant resolution is delegated to `_b68_fs_tools_granted` (the same helper
    B68 already uses for this identical tool family) rather than re-derived here — the
    prior independent accumulator only matched the LEGACY, non-canonical alias names in
    `_FS_WRITE_TOOL_HINTS` ("fs_write" is not a real OpenClaw tool id) against a raw
    `tools.allow` LIST only, so it produced a confident PASS on every real-world grant
    shape: the canonical tool ids (write/edit/apply_patch), group:fs, a wildcard "*"
    allowlist, tools.profile, and tools.alsoAllow all went undetected. The legacy alias
    list is kept as an additional union (see `write_tools` below) so old-style configs
    and this project's own pre-existing fixtures/tests keep matching.

    Also B-395: `tools.elevated.allowFrom` is REMOVED from this function's decision
    tree entirely — the only signals consulted are `open_ch` (proven-open channel
    reach), `gated` (a non-write-specific but still real `tools.exec.mode` approval
    gate), and `fs_confined` (workspace/sandbox confinement). Grounded against the
    installed OpenClaw dist: `tools.elevated` gates the exec/bash privileged-command
    escalation surface, never the ordinary write/edit/apply_patch tools this check is
    about — it is not one of OpenClaw's tool-policy resolution layers. A first pass
    dropped it only from the FAIL trigger (a wildcard elevated allowlist alone, no open
    channel, no untrusted ingress anywhere, used to produce a hard FAIL); an independent
    second-round review found that left an asymmetric false PASS — broadening grant
    detection above (a powerful profile / wildcard / group:fs / alsoAllow grant) meant
    a genuinely open channel + a granted write tool still PASSed outright whenever a
    TIGHT `tools.elevated.allowFrom` happened to also be set, even though that field
    cannot scope write-tool reachability either. Removed from both directions.

    Known, deliberately UNFIXED gap #1 in this same pass (documented rather than silently
    left, and filed as a follow-up, B-409): OpenClaw resolves the EFFECTIVE tool set
    through up to 8 composable policy layers (global allow/deny, per-agent allow/deny,
    byProvider ×2, channel/group tools, toolsBySender, subagent/inherited session
    policy — each AND-ed via `policies.every(...)`, `tool-policy-match-*.js:32-34`, so
    each of THESE layers can only further NARROW the set; per-agent `tools.profile` is
    the one exception and is covered separately as gap #4 below). This check reads only
    the global `tools.allow`/`tools.alsoAllow`/`tools.profile` layer for these eight. A
    narrower per-agent-allow, per-channel, or per-sender policy that actually removes
    the write tool from the agent reachable through an open channel is invisible here
    and can still produce a false FAIL. Closing this needs a real multi-layer policy
    composer, not a one-line patch — out of scope for this pass.

    Gap #2 (B-410) is now CLOSED: `gated` (`tools.exec.mode` having an approval-gate
    value) used to clear `not open_ch` straight to PASS, even though this same
    function's own FAIL-branch reasoning says `tools.exec.mode` "doesn't scope
    write-capable tools" either. Concretely, `tools.profile: "full"` (a B-395
    grant-detection path) + `tools.exec.mode: "ask"` + a channel that is declared but
    only `dmPolicy: "allowlist"` (untrusted CONTENT reachable, not "open"/proven-broad
    reach — the same category this function's own comment already carves out as
    "stays the WARN fallback" for the UNGATED case) used to PASS once gated, instead
    of staying WARN. `tools.exec.mode` is not PROVEN entirely irrelevant to
    write-tool reachability (only "not write-specific"), so the fix is not a clean
    removal like the elevated-allowFrom one above — it distinguishes "no channels
    declared at all" (`_external_input_channels` empty — still a defensible PASS,
    genuinely no proven ingress) from "channels declared, none proven open, but
    carrying untrusted content" (`_external_input_channels` non-empty — now WARN even
    when gated), which the old `not open_ch` test alone conflated. `open_ch` itself
    (feeding the FAIL gate below) is unchanged — this only narrows what `not open_ch`
    accepts as PASS-worthy.

    Gap #3 (alsoAllow-only implicit wildcard, B-411) is now CLOSED: `_b68_fs_tools_granted`
    delegates to `_tool_policy_view`, which models OpenClaw's `unionAllow` injection of an
    implicit "*" into the effective allow list whenever `tools.allow` is absent/empty and
    `tools.alsoAllow` is non-empty — so alsoAllow-only now grants EVERY tool, matching
    reality, and B44/B55/B68/B84 all resolve from the same one model (B-423 closed the
    companion gateway.tools.allow-as-grant defect the same way). See `_tool_policy_view`'s
    docstring for the full grounding and the profile-guard rationale.

    Gap #4 (per-agent tools.profile WIDENING, B-409 Slice B) is now fully CLOSED,
    including the combination noted below as previously "still open" — and is a
    different shape of bug than gap #1 above: every OTHER layer gap #1 lists is
    narrowing-only (AND-ed via `policies.every(...)`), so being blind to it can only
    produce a false FAIL, never a false PASS. `agents.list[N].tools.profile` is
    `??`-coalesced against the global profile instead (`agent-tools.policy-YD9HuYgO.js
    :94`, `:232`) — it REPLACES the global profile in the AND-ed policy list rather
    than adding a second, narrowing entry — so a global `tools.profile: "minimal"`
    with a per-agent `tools.profile: "coding"` grants write/edit/apply_patch to that
    agent even though the global layer alone grants nothing: a lying PASS, not a
    missed WARN. This is now unioned in via `_agent_profile_widenings` (see
    `_b68_fs_tools_granted`), and can only ever push a verdict from PASS toward WARN
    here — it deliberately never sets `explicit_write_grant` below, so it cannot alone
    drive a FAIL: the seven still-open narrowing layers in gap #1 could still remove
    the write tool for that specific agent/channel/sender combination, which this
    static check still cannot see.

    Gap #5 (global tools.profile + global tools.alsoAllow under a widening) is now
    also CLOSED. Previously documented here as "STILL OPEN": when a global
    `tools.profile` is set AND global `tools.alsoAllow` is also set, `_tool_policy_view`
    suppresses alsoAllow's implicit-wildcard injection on the theory that the profile
    policy governs (see its docstring, part (a)) — sound for the GLOBAL profile, but
    under a widening the EFFECTIVE profile is the per-agent one, and OpenClaw's real
    `pickSandboxToolPolicy` never reads `profile` at all, so alsoAllow's implicit "*"
    still applies at the global-allow layer regardless of which profile substitutes in.
    `{"tools": {"profile": "minimal", "alsoAllow": ["search"]}, "agents": {"list":
    [{"tools": {"profile": "coding"}}]}}` under a proven-open channel used to be a
    false NEGATIVE (PASS when the true grant includes write/edit/apply_patch) — never a
    false FAIL, so this never violated GR#5, and it was IDENTICAL to pre-B-409
    behavior (verified by neutralizing `_agent_profile_widenings` and confirming the
    verdict didn't change), so it was not a regression B-409 introduced. Fixed in
    `_b68_fs_tools_granted` (see its docstring): the widening branch now recomputes
    the same unionAllow emptiness test locally, ignoring the profile guard, so a
    `view.named` that is non-empty ONLY because of the (irrelevant, for the widened
    agent) global-profile suppression is no longer mistaken for a real, narrowing
    explicit allowlist. Like gap #4, this can only push PASS toward WARN — it does
    not set `explicit_write_grant`, so it cannot alone drive a FAIL.

    UNKNOWN — fs-write grants are not enumerable from config: no tools.allow /
              tools.alsoAllow declared as a LIST, no tools.profile set, and no
              per-agent tools.profile widening (B-409) either. A declared-but-non-list
              tools.allow (a scalar or mapping — schema-invalid, but seen in the wild)
              also lands here, not PASS.
    PASS    — no write-capable tool granted, OR one is granted, no open-ingress channel
              reaches it, AND no channel is declared at all with untrusted-content
              reach either (_external_input_channels empty), with tools.exec.mode
              set as an approval gate.
    WARN    — write tool granted with no proven broad reach and no approval gate
              (ungated), OR reachable by a declared-but-not-open channel carrying
              untrusted content (_external_input_channels non-empty, e.g.
              dmPolicy="allowlist"/"pairing") even when gated (B-410 — the gate is
              not write-specific), OR reachable by a proven-open channel but
              confined to the workspace (tools.fs.workspaceOnly / sandbox.mode='all'),
              OR reachable by a proven-open channel, unconfined, but the ONLY grant
              signal is tools.alsoAllow's implicit wildcard (B-411) with no explicit
              write/edit/apply_patch/"*"/"group:fs" token and no powerful global
              tools.profile -- an independent C-135 review found a real per-agent
              tools.profile can narrow that implicit grant away invisibly to this
              static check, so it stays the "ambiguous" WARN case rather than FAIL, OR
              reachable by a proven-open channel, unconfined, but the ONLY grant signal
              is a per-agent tools.profile WIDENING (B-409) with no explicit global
              grant -- deliberately never a FAIL, for the same "seven still-unread
              narrowing layers" reason gap #4 above gives.
    FAIL    — an EXPLICIT write tool grant (a literal write/edit/apply_patch/"*"/
              "group:fs" token, or a powerful tools.profile) AND reachable by a
              PROVEN-open channel, not confined, gated or not. scored=True.

    B-438: "PROVEN-open channel" (open_ch, feeding the FAIL gate) now also counts the
    wildcard-group-open shape (channels.<provider>.groups with a "*" key and no
    dmPolicy/groupPolicy at all) via _unpolicied_open_wildcard_group_channels — the same
    shape and same STRICT (no-policy-field-at-all) helper A1's B-371 fix uses, for the
    same reason: this check is also FAIL-capable, and the broader
    _open_wildcard_group_channels was proven by A1's own C-135 pass to false-FAIL an
    approval-gated or owner-only group bot (see
    test_a1_approval_gated_group_bot_not_untrusted_input /
    test_a1_owner_only_group_bot_not_untrusted_input). Before this, a write-capable tool
    reachable ONLY through a genuinely open groups["*"] entry (no dmPolicy/groupPolicy
    set) read as no proven-open reach at all — a false NEGATIVE (WARN instead of FAIL) on
    exactly the ingress shape B-297/B-371 already established is the commonest real
    open-group config.
    """
    cfg = ctx.config
    # B-503: grant resolution delegated to `_b55_write_tools_granted`, the same
    # write/edit/apply_patch model report.py's capability graph now also calls, so
    # the two can no longer disagree the way `_enabled_tools` vs.
    # `_b68_fs_tools_granted` did. `view`/`legacy_write` are still needed below for
    # `explicit_write_grant`'s EXPLICIT/WIDENED/IMPLICIT-WILDCARD distinction.
    write_tools, enumerable, view, legacy_write = _b55_write_tools_granted(cfg)
    widenings = _agent_profile_widenings(cfg)

    if not enumerable:
        return _finding(
            "B55",
            UNKNOWN,
            "Tool allowlist (tools.allow / tools.alsoAllow) is not declared as an "
            "enumerable list in config, and no tools.profile is set, so "
            "filesystem-write tool grants cannot be enumerated.",
            "Declare tools.allow explicitly (as a list) so write-capable tools are "
            "auditable, and scope any write/edit/apply_patch grant with an approval "
            "gate (tools.exec.mode='ask').",
        )

    if not write_tools:
        return _finding(
            "B55",
            PASS,
            "No filesystem-write tool (write / edit / apply_patch) is granted.",
            "Keep write-capable tools out of the allowlist unless they are required.",
        )

    # B-423/B-411 C-135 round 2 (independent adversarial review, same fix): the grant
    # above can now come SOLELY from _tool_policy_view's implicit wildcard
    # (tools.alsoAllow-only, tools.allow/tools.profile both absent -- OpenClaw's own
    # unionAllow injecting "*", sandbox-tool-policy-ClB7s2K0.js:9-14). The review found
    # a real false FAIL on that path: a per-agent tools.profile
    # (agents.list[N].tools.profile) is AND-ed into the SAME resolved policy OpenClaw's
    # real resolver reads first (agent-tools.policy-YD9HuYgO.js:232) and can legitimately
    # narrow the grant away from write -- but this check, like _tool_policy_view, only
    # reads the GLOBAL tools.profile, so it never sees that narrowing. OpenClaw itself
    # treats the implicit "*" as an artifact rather than confirmed operator intent: it
    # mints a dedicated provenance marker (IMPLICIT_ALLOW_ALL_FROM_ALSO_ALLOW,
    # sandbox-tool-policy-ClB7s2K0.js:7-14) purely to refuse to honor it wherever it
    # can (collectExplicitAllowlist substitutes the plugin-tools default instead,
    # tool-policy-BHUGxE3p.js:100-103). Mirror that caution: FAIL only when an EXPLICIT
    # signal backs the grant (a literal write/edit/apply_patch token, "*"/"group:fs", or
    # a powerful tools.profile) -- an implicit-wildcard-only grant stays the WARN
    # "ambiguous" case, not the FAIL "proven broad reach" case.
    #
    # C-135 (B-409 round 2): the first clause used to read `view.named` WITHOUT
    # subtracting `view.denied`, unlike `legacy_write` right below it (which already
    # does, `- view.denied` at its own definition) -- an explicitly-denied write token
    # (e.g. tools.allow: ["write"], tools.deny: ["write"]) could leak through as
    # "explicit" even though it grants nothing. This was provably unreachable before
    # B-409 (reaching this line already requires write_tools non-empty, which requires
    # a genuine, deny-survived write-family token elsewhere backing it), but B-409's
    # widening review found a path that made it reachable and consequential — fixed at
    # the root there too (the widening now intersects with a real global allowlist
    # instead of granting wholesale), but this clause is fixed to match `legacy_write`'s
    # existing pattern regardless, so it can't become a landmine for the next change.
    explicit_write_grant = bool(
        (set(view.named) & _B55_FS_WRITE_TOOLS) - view.denied
        or legacy_write
        or "*" in view.named
        or "group:fs" in view.named
        or (view.profile is not None and _profile_is_powerful(view.profile))
    )

    label = ", ".join(write_tools)
    gated = _has_approval_gate(cfg)
    # B-376 C-135 fix: B68 (same file) treats either field as sufficient fs confinement
    # for this identical tool family (its own composite predicate, quoted there).
    # Confined-but-reachable writes are a real but lesser risk than "arbitrary".
    fs_confined = (
        dig(cfg, "tools.fs.workspaceOnly") is True
        or dig(cfg, "agents.defaults.sandbox.mode") == "all"
    )
    # DELIBERATE: _open_channels (open-only), NOT _external_input_channels. This feeds the
    # FAIL gate below; a hard FAIL ("arbitrary writes reachable by untrusted senders")
    # requires proven-broad reach — a wildcard sender or a truly-open/public channel. An
    # allowlist/paired channel carries untrusted *content* but is not broad reach, so it
    # stays the WARN fallback (locked by test_ungated_write_without_broad_reach_warns).
    # Widening this to _external_input_channels would flip allowlist configs WARN->FAIL,
    # a §5 false-positive FAIL. B46 uses the broader helper because it is WARN-capped.
    #
    # B-438: _open_channels is deliberately scoped to dmPolicy/groupPolicy == "open" only
    # (see its own docstring) — it does not see the wildcard-group-open shape
    # (channels.<provider>.groups with a "*" key and no dmPolicy/groupPolicy at all);
    # the B-297 block comment right after _open_channels' definition in _shared.py
    # documents that as a SEPARATE ingress shape with its own helper family. B55 is
    # FAIL-capable (like A1/check_trifecta), so it follows A1's
    # B-371 precedent rather than reaching for the permissive _open_wildcard_group_channels:
    # union in ONLY the STRICT subset from _unpolicied_open_wildcard_group_channels — a
    # resolved channel node with NO dmPolicy/groupPolicy key at all, not merely an
    # unrecognized value. A1's own C-135 pass proved the permissive version produces real
    # false positives on an approval-gated or owner-only group bot (see
    # test_a1_approval_gated_group_bot_not_untrusted_input /
    # test_a1_owner_only_group_bot_not_untrusted_input in tests/test_checks.py); the same
    # two configs would false-FAIL here too if the broader helper were used instead.
    open_ch = sorted(
        set(_open_channels(cfg)) | set(_unpolicied_open_wildcard_group_channels(cfg))
    )

    # B-395 (C-135 round 2 on this same fix): `tools.elevated.allowFrom` — in ANY shape,
    # tight or wildcard — used to gate BOTH directions here (a wildcard drove FAIL, a
    # tight allowlist short-circuited to PASS). Grounded against the installed OpenClaw
    # dist: tools.elevated is a privileged-command / auto-approve ESCALATION control for
    # the exec/bash surface only (schema doc: "Elevated tool access controls for
    # privileged command surfaces"; consumed only in the exec/bash tool module,
    # bash-tools-*.js; zero hits across agent-tools.policy-*.js / tool-policy-
    # pipeline-*.js / tool-resolution-*.js / tool-dispatch-*.js) — it is not one of
    # OpenClaw's tool-policy resolution layers and says nothing about whether
    # write/edit/apply_patch are reachable. Dropping it from the FAIL trigger alone
    # (first round of this fix) left an asymmetric, confirmed false PASS: broadening
    # grant detection (this same change) meant a powerful tools.profile, a wildcard
    # allowlist, group:fs, or tools.alsoAllow granting write, reachable through a
    # genuinely open channel, still PASSed outright whenever a TIGHT
    # tools.elevated.allowFrom happened to also be set — a field this check's own
    # grounding says cannot scope write-tool reachability at all. Removed from both
    # directions: the only signals this function's decision tree consults now are
    # open_ch (proven broad reach), gated (a non-write-specific but still real
    # exec-mode approval gate), and fs_confined (workspace/sandbox confinement).
    #
    # B-410 (gap #2 above, third C-135 round on this same PASS branch): `gated` alone
    # used to clear straight to PASS whenever no channel was proven fully OPEN — but a
    # channel that IS declared with an untrusted-content policy (allowlist/pairing —
    # _external_input_channels, deliberately the BROADER helper here, unlike open_ch
    # above) still carries only the same non-write-specific gate this function's own
    # FAIL-branch reasoning already disclaims ("tools.exec.mode='ask' alone ... doesn't
    # scope write-capable tools"). PASS is reserved for genuinely NO declared ingress at
    # all; a declared-but-not-open channel downgrades to WARN even when gated.
    if not open_ch:
        ext_ch = _external_input_channels(cfg)
        if gated and not ext_ch:
            return _finding(
                "B55",
                PASS,
                f"Filesystem-write tool granted ({label}) but no ingress channel is "
                f"declared, and an approval gate (tools.exec.mode) is set.",
                "Scoping is in place — keep tools.exec.mode='ask' (or 'deny'/'allowlist').",
                evidence=[f"write tool granted: {label}"],
            )
        if gated and ext_ch:
            return _finding(
                "B55",
                WARN,
                f"Filesystem-write tool granted ({label}) is reachable by a declared "
                f"channel carrying untrusted content ({', '.join(ext_ch)}) that is not "
                f"proven open, and the only scoping is a non-write-specific approval "
                f"gate (tools.exec.mode) — it doesn't scope write-capable tools.",
                "Lock the channel(s) to 'owner' (or 'disabled'); tools.exec.mode='ask' "
                "alone does not clear this — it doesn't scope write-capable tools.",
                evidence=[
                    f"write tool granted: {label}",
                    f"declared, not-open, untrusted-content channel(s): {', '.join(ext_ch)}",
                    "approval gate present (tools.exec.mode) but not write-specific",
                ],
            )
    else:
        ev = [
            f"filesystem-write tool granted: {label}",
            f"open-ingress channel(s): {', '.join(open_ch)}",
        ]
        if not gated:
            ev.append("no approval gate (tools.exec.mode is not deny/allowlist/ask/auto)")
        else:
            ev.append(
                "open-ingress bypasses exec-style approval and can still drive write-capable tools"
            )
        # B-376/B-369 (2026-07-31): re-escalated from B-315's WARN, per B186's
        # narrow-FAIL-override precedent -- proven broad reach, gated or not (an
        # exec-only gate doesn't scope write tools). See test_b315_unscored_never_fails.
        if fs_confined:
            ev.append(
                "filesystem writes are confined to the workspace (tools.fs.workspaceOnly "
                "or agents.defaults.sandbox.mode='all') -- not arbitrary write reach"
            )
            return _finding(
                "B55",
                WARN,
                f"Filesystem-write capability ({label}) is reachable by untrusted senders, "
                f"but confined to the workspace, so writes can tamper the project itself "
                f"rather than reach arbitrary paths.",
                "Lock the open channel(s) to 'allowlist' to remove untrusted reach "
                "entirely.",
                evidence=ev,
            )
        if not explicit_write_grant:
            if widenings:
                global_profile = dig(cfg, "tools.profile")
                widen_desc = (
                    f'widens beyond the global tools.profile={global_profile!r}'
                    if global_profile is not None
                    else "is the only declared tools.profile (no global tools.profile is set)"
                )
                ev.append(
                    f"grant traces to a per-agent tools.profile that {widen_desc} "
                    "(B-409): "
                    + ", ".join(f'{path}="{profile}"' for path, profile in widenings)
                    + " -- not an explicit global write/edit/apply_patch grant, and "
                    "the seven still-unread narrowing layers (per-agent allow/deny, "
                    "channel/group, toolsBySender, byProvider) could remove it for "
                    "this agent unseen by this static check"
                )
                return _finding(
                    "B55",
                    WARN,
                    f"Filesystem-write capability ({label}) is reachable by untrusted "
                    f"senders, but the grant traces to a per-agent tools.profile that "
                    f"{widen_desc}, so this stays WARN pending confirmation this is "
                    f"intentional and not narrowed away by a policy layer this static "
                    f"check can't read.",
                    "Confirm the per-agent tools.profile grant is intentional, and "
                    "lock the open channel(s) to 'allowlist'.",
                    evidence=ev,
                )
            ev.append(
                "the only write-tool grant signal is tools.alsoAllow's implicit "
                "wildcard (tools.allow/tools.profile absent) -- not an explicit "
                "write/edit/apply_patch grant, and a narrower per-agent tools.profile "
                "could exist unseen by this static check"
            )
            return _finding(
                "B55",
                WARN,
                f"Filesystem-write capability ({label}) is reachable by untrusted "
                f"senders, but the grant itself is only the implicit result of an "
                f"alsoAllow-only config (tools.allow/tools.profile both absent) rather "
                f"than an explicit write-tool grant, so this stays WARN pending "
                f"confirmation of real intent.",
                "Set tools.allow explicitly (or a tools.profile) so the intended grant "
                "is unambiguous, and lock the open channel(s) to 'allowlist'.",
                evidence=ev,
            )
        return _finding(
            "B55",
            FAIL,
            f"Broad filesystem-write capability ({label}) is reachable by untrusted "
            f"senders with no write-specific scoping, so untrusted input can drive "
            f"arbitrary file writes (tamper / persistence).",
            "Lock the open channel(s) to 'allowlist'. tools.exec.mode='ask' alone "
            "does not clear this — it doesn't scope write-capable tools.",
            evidence=ev,
            scored=True,
        )

    return _finding(
        "B55",
        WARN,
        f"Filesystem-write tool granted ({label}) without an approval gate, and no "
        f"open-ingress channel was found to prove broader reach either way.",
        "Scope it: set tools.exec.mode='ask' (or 'deny'/'allowlist') so write-capable "
        "tools require approval.",
        evidence=[
            f"write tool granted: {label}",
            "no approval gate (tools.exec.mode is not deny/allowlist/ask/auto)",
        ],
    )


# ---------- B326: agents.defaults.elevatedDefault="full" bypasses human approval ----------
# Grounded against the installed OpenClaw dist (2026-07-28, v2026.7.1-2); full trail:
# docs/research/openclaw-schema-recon.md §39 (workspace root, not shipped). elevatedDefault
# is a ZodUnion of "off"|"on"|"ask"|"full" (config-schema.d.ts:985) feeding
# bash-tools-DHyGpWCr.js:3233-3293 (via resolvedElevatedLevel, get-reply-OTG64ybi.js:1626),
# where ONLY "full" bypasses approval outright. The trap: "on" (the stock default) LOOKS
# safe but is approval-gated identically to "ask" -- never flagged.
# resolveElevatedPermissions() (:1316-1391) is the ONE {enabled, allowed} object every
# consumer shares (get-reply.js / bash-tools.js -- no separate CLI/local escape). The bypass
# is hard-blocked when EITHER (1) tools.elevated.enabled is explicitly false, or (2) the
# GLOBAL allowFrom has no entry reachable by resolveElevatedAllowList()/
# isApprovedElevatedSender() (:1222-1314): an Array is required, and
# normalizeStringEntries() JS-.trim()s each element before checking emptiness -- JS .trim()
# != Python str.strip(), so _B326_JS_TRIM_CHARS pins the exact ECMA-262 whitespace set it
# strips (Node v22-verified). A PER-AGENT allowFrom only RESTRICTS once the global check
# passes (:1364-1374 returns early on a failed globalAllowed) -- only the GLOBAL leg matters.
_B326_JS_TRIM_CHARS = "".join(chr(c) for c in (
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0xFEFF, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
))


# B-397: OpenClaw's real bypass computation (grounded against the installed dist,
# bash-tools-*.js's createExecTool()/resolveExecModePolicy(), the same function the
# B326 grounding comment above already traces for tools.elevated) does NOT stop at
# tools.elevated.enabled/allowFrom -- the elevated "full" override is itself gated by
# whether the GLOBAL tools.exec.* policy already resolves to security="full"/ask="off"
# (`modePolicyAllowsFullBypass`). Absence of mode/security/ask resolves to that SAME
# permissive state (configuredSecurity defaults absent -> "full" for a non-sandbox
# host; ask defaults absent -> "off"; mode absent falls through the same way) -- so
# only an EXPLICIT blocking value counts. The common "nothing under tools.exec set at
# all" config genuinely reaches the bypass and must still FAIL; only a config that
# EXPLICITLY hardens mode/security/ask should downgrade.
_B326_BLOCKING_MODES = frozenset({"deny", "allowlist", "ask", "auto"})
_B326_BLOCKING_SECURITIES = frozenset({"deny", "allowlist"})
_B326_BLOCKING_ASKS = frozenset({"on-miss", "always"})


def _b326_exec_policy_blocking_reason(cfg: dict) -> str | None:
    """The GLOBAL tools.exec.* field (if any) that already blocks the elevated "full"
    override from reaching security="full"/ask="off", or None if nothing does.

    Deliberately checks all three fields independently rather than modelling the real
    resolver's mode-takes-precedence-when-present rule exactly: a malformed config
    that combines mode with security/ask (the real schema forbids this, so OpenClaw
    itself would refuse to start on one) could in principle make this return a
    blocking reason the real resolver would have ignored -- but that only pushes the
    verdict from FAIL to WARN, which is the safe direction (Golden Rule #5), never a
    false FAIL.

    Deliberately GLOBAL-scope only: a per-agent agents.list[].tools.exec.* override
    (which the real resolver layers under the global default, mirroring
    resolveExecConfig()) is not read here -- see the check's own docstring for why
    that is a documented, not silent, gap.
    """
    mode = dig(cfg, "tools.exec.mode")
    if isinstance(mode, str) and mode in _B326_BLOCKING_MODES:
        return f"tools.exec.mode={mode!r}"
    security = dig(cfg, "tools.exec.security")
    if isinstance(security, str) and security in _B326_BLOCKING_SECURITIES:
        return f"tools.exec.security={security!r}"
    ask = dig(cfg, "tools.exec.ask")
    if isinstance(ask, str) and ask in _B326_BLOCKING_ASKS:
        return f"tools.exec.ask={ask!r}"
    return None


def _b326_exec_policy_unresolved_reason(cfg: dict) -> str | None:
    """B-397 (C-135 round on this same fix): the field (if any) among
    tools.exec.mode/security/ask that contains an unresolved ${VAR} substitution --
    the identical hazard Defect 1 fixed for agents.defaults.elevatedDefault itself,
    just not originally extended to these three newer conjunct fields. OpenClaw's own
    substituteAny()/resolveConfigForRead() applies ${VAR} substitution recursively to
    every string value in the config tree, not just elevatedDefault, so
    'tools.exec.mode: "${MODE}"' is just as real a config shape. Whichever value it
    resolves to at runtime could be blocking or permissive; a static scan cannot tell,
    so this must route to UNKNOWN rather than silently falling through
    `_b326_exec_policy_blocking_reason` as "not blocking" (which produced a false
    FAIL: the field could easily resolve to a genuinely blocking value)."""
    for field, value in (
        ("tools.exec.mode", dig(cfg, "tools.exec.mode")),
        ("tools.exec.security", dig(cfg, "tools.exec.security")),
        ("tools.exec.ask", dig(cfg, "tools.exec.ask")),
    ):
        if isinstance(value, str) and _b323_contains_env_var_reference(value):
            return f"{field}={value!r}"
    return None


def _b326_elevated_allow_from_absent(cfg: dict) -> bool:
    """True when the GLOBAL tools.elevated.allowFrom grants no provider a reachable sender
    (mirrors the real resolver, not "is something configured" -- see the grounding comment
    above): needs a dict with a list value holding an entry non-empty after stripping
    _B326_JS_TRIM_CHARS."""
    allow = dig(cfg, "tools.elevated.allowFrom")
    if not isinstance(allow, dict):
        return True
    return not any(
        isinstance(v, list) and any(str(x).strip(_B326_JS_TRIM_CHARS) for x in v)
        for v in allow.values()
    )


def check_elevated_default_full(ctx: Context) -> Finding:
    """B326 — agents.defaults.elevatedDefault="full" bypasses human approval by default
    (see the grounding comment above for why "full" alone bypasses while "on"/"ask" don't).

    B-397 defect 1: elevatedDefault is compared against the literal string "full", which a
    value reaching "full" through OpenClaw's own ${VAR} substitution (env.vars / process
    env, applied by applyConfigEnvVars at startup) evades entirely -- the identical hazard
    B323 already models for a PATH override, via the same _b323_contains_env_var_reference
    this check now reuses (relocated to checks/_shared.py since it is reused by 2+ topics,
    per CLAUDE.md §3.1). Routed to UNKNOWN, never PASS: static config cannot resolve what
    an unresolved reference expands to.

    B-397 defect 2: the FAIL branch previously modelled only 2 of the real 4 conjuncts the
    installed dist requires for the bypass (see the B-397 grounding comment above
    _B326_BLOCKING_MODES for the createExecTool()/resolveExecModePolicy() trace) -- an
    explicit, hardening tools.exec.mode/security/ask at the GLOBAL scope also blocks it,
    and previously still produced a false FAIL. A 4th real conjunct
    (~/.openclaw/exec-approvals.json, mutable RUNTIME state OpenClaw itself writes, not
    static config) is a genuine additional gate the dist enforces but is deliberately NOT
    modelled here -- out of this tool's read-only static-config scope (Golden Rule #2), not
    an oversight. A 5th, per-agent agents.list[].tools.exec.* override (layered under the
    global default the same way B-395 found for tool-policy resolution generally) is also
    NOT modelled here -- the same deferred multi-layer-composition gap B-395 already filed
    as its own follow-up for tool-policy resolution generally.

    B-397 (C-135 round on this same fix): defect 1's ${VAR} handling covered
    elevatedDefault itself but not the three NEW exec-policy conjunct fields defect 2
    added -- 'tools.exec.mode: "${MODE}"' is just as real a config shape (OpenClaw's
    substitution is recursive over the whole config tree, not scoped to one field), and
    silently fell through _b326_exec_policy_blocking_reason as "not blocking" -> a false
    FAIL. _b326_exec_policy_unresolved_reason now catches this and routes to UNKNOWN.

    UNKNOWN — no openclaw.json, unparseable/unreadable, elevatedDefault contains an
              unresolved ${VAR} substitution, OR (once elevatedDefault=="full" and
              elevated tools are otherwise reachable) one of tools.exec.mode/security/
              ask contains an unresolved ${VAR} substitution -- either way, cannot
              determine what it resolves to.
    PASS    — elevatedDefault is absent, "off", "on", or "ask" (a literal, non-interpolated
              value).
    WARN    — "full" but dormant: tools.elevated.enabled=False, OR global allowFrom has no
              entry that could ever match a sender, OR an explicit, LITERAL GLOBAL
              tools.exec.mode/security/ask already hardens the exec-tool policy against
              the bypass (any one blocks the bypass today; reopening any of them later
              restores reachability).
    FAIL    — "full" and reachable: enabled not explicitly False, allowFrom has an entry,
              AND no explicit tools.exec.mode/security/ask hardening blocks it (absence of
              all three resolves to the SAME permissive state as an explicit "full"/"off",
              so absence does not clear this -- only an explicit, literal blocking value
              does; an unresolved ${VAR} in any of the three routes to UNKNOWN instead).
    """
    if not ctx.config_found:
        return _finding(
            "B326",
            UNKNOWN,
            "No openclaw.json found -- agents.defaults.elevatedDefault cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B326", ctx)
    if unreadable is not None:
        return unreadable

    cfg = ctx.config
    level = dig(cfg, "agents.defaults.elevatedDefault")

    # B-397: a value reaching "full" through OpenClaw's own ${VAR} substitution
    # (env.vars / process env, applied at startup by applyConfigEnvVars) evades a
    # literal "full" comparison entirely -- the same hazard already modelled for
    # B323's PATH-override check via _b323_contains_env_var_reference. Routed to
    # UNKNOWN, never PASS: static config cannot resolve what the variable expands to,
    # and a confident PASS here is the exact "lying when state is undeterminable"
    # Golden Rule #4 forbids. This must run BEFORE the `level != "full"` PASS below,
    # since an interpolated value is never the literal string "full" even when it
    # resolves to it at runtime.
    if isinstance(level, str) and _b323_contains_env_var_reference(level):
        return _finding(
            "B326",
            UNKNOWN,
            f"agents.defaults.elevatedDefault is {level!r}, which contains an "
            "unresolved ${VAR} substitution -- OpenClaw applies env-var references at "
            "startup, so whether this resolves to \"full\" (bypassing human approval) "
            "cannot be determined from static config alone.",
            "Avoid interpolating agents.defaults.elevatedDefault from an environment "
            "variable; set it to a literal \"ask\" (or leave it unset) so its effective "
            "value is auditable from config alone.",
        )

    if level != "full":
        level_label = repr(level) if level is not None else "absent"
        return _finding(
            "B326",
            PASS,
            f"agents.defaults.elevatedDefault is {level_label} "
            "-- human approval is not bypassed by default (only \"full\" bypasses it; "
            "\"on\"/\"ask\"/\"off\"/absent all keep the approval gate in place).",
            "No action needed; keep agents.defaults.elevatedDefault at \"ask\" (or leave "
            "it unset -- the runtime default is the equally-gated \"on\").",
        )

    enabled = dig(cfg, "tools.elevated.enabled")
    enabled_false = enabled is False
    allow_from_absent = _b326_elevated_allow_from_absent(cfg)
    exec_policy_block = _b326_exec_policy_blocking_reason(cfg)
    if enabled_false or allow_from_absent or exec_policy_block:
        reasons = [r for r, hit in (
            ("tools.elevated.enabled=false", enabled_false),
            ("tools.elevated.allowFrom is absent/empty for every provider", allow_from_absent),
            (exec_policy_block, exec_policy_block is not None),
        ) if hit]
        return _finding(
            "B326",
            WARN,
            "agents.defaults.elevatedDefault=\"full\" (skips human approval outright), but "
            + " and ".join(reasons) + " -- this unconditionally blocks the bypass today, "
            "but is not a clean bill of health: closing that gap later would restore it.",
            "Set agents.defaults.elevatedDefault to \"ask\" so the dangerous posture is not "
            "configured at all, rather than relying on the dormant gate to keep it inert.",
            evidence=["agents.defaults.elevatedDefault=\"full\""] + reasons,
        )

    # B-397 (C-135 round on this same fix): none of the three exec-policy fields
    # matched a known-blocking value above, but one of them may contain an unresolved
    # ${VAR} reference -- the same class of bug Defect 1 fixed for elevatedDefault
    # itself, just not originally extended to these three newer conjunct fields.
    # Whether an unresolved field would have resolved to a blocking value is
    # undeterminable from static config, so this must route to UNKNOWN rather than
    # confidently FAIL.
    exec_policy_unresolved = _b326_exec_policy_unresolved_reason(cfg)
    if exec_policy_unresolved is not None:
        return _finding(
            "B326",
            UNKNOWN,
            "agents.defaults.elevatedDefault=\"full\" and elevated tools are otherwise "
            f"reachable, but {exec_policy_unresolved} contains an unresolved ${{VAR}} "
            "substitution -- whether it resolves to a value that blocks the bypass "
            "cannot be determined from static config alone.",
            "Avoid interpolating tools.exec.mode/security/ask from an environment "
            "variable; set them to literal values so their effective posture is "
            "auditable from config alone.",
            evidence=[
                "agents.defaults.elevatedDefault=\"full\"",
                f"tools.elevated.enabled={enabled!r} (not explicitly false)",
                f"tools.elevated.allowFrom={dig(cfg, 'tools.elevated.allowFrom')!r} (reachable)",
                f"{exec_policy_unresolved} (unresolved)",
            ],
        )

    return _finding(
        "B326",
        FAIL,
        "agents.defaults.elevatedDefault=\"full\" -- elevated tools bypass human approval "
        "by default (tools.elevated.enabled is not explicitly false, "
        "tools.elevated.allowFrom grants at least one sender, and no tools.exec.mode/"
        "security/ask hardening blocks it), unlike \"on\"/\"ask\" which both still "
        "require approval.",
        "Set agents.defaults.elevatedDefault to \"ask\" (or leave it unset -- the runtime "
        "default is the equally-gated \"on\") so elevated actions still require human "
        "approval.",
        evidence=[
            "agents.defaults.elevatedDefault=\"full\"",
            f"tools.elevated.enabled={enabled!r} (not explicitly false)",
            f"tools.elevated.allowFrom={dig(cfg, 'tools.elevated.allowFrom')!r} (reachable)",
            "no tools.exec.mode/security/ask hardening blocks the bypass",
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
    2. Any group/world-writable ANCESTOR install dir above the binary (e.g. the npm
       package root .../node_modules/openclaw) — a group member could replace the
       subtree even if the immediate bin dir is tight.
    3. Any group/world-writable $PATH dir listed BEFORE the openclaw dir (a fake
       'openclaw' could be found there first).

    A sticky world-writable dir (e.g. /tmp, mode 1777) is NOT flagged: the sticky bit
    blocks cross-owner rename/delete, so it is not a replace vector. The agent may also
    declare paths.openclaw_install via --attest when the binary isn't on PATH — discovery
    is agent-supplied, but the engine still stat()s the dir itself (so this stays a real
    permission check, HIGH confidence, not a weak self-report).

    WARN  — at least one such writable dir found.
    PASS  — openclaw located and binary dir / ancestors / earlier PATH dirs are tight.
    UNKNOWN — openclaw not on PATH and no attested install dir, or non-POSIX platform.

    F-140 — only the non-POSIX branch sets ``not_applicable``: C5's locus is the host
    PLATFORM (not openclaw.json, so ``_surface_absent`` doesn't apply), and ``_is_posix()``
    is itself a complete reading of it — off POSIX the group/world/sticky mode bits this
    check models don't exist at all. The other two UNKNOWN branches stay ordinary
    (unassessed risk, not absence): ``--no-host`` means the operator opted out, and "not on
    PATH" is a discovery failure the fix text invites ``--attest`` to close. Full rationale
    + the three-way test: ``tests/test_f140_not_applicable_adversarial.py``.
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
            not_applicable=True,
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
