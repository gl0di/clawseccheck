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
from .. import toolpolicy as _toolpolicy
from .. import toolgrant as _toolgrant
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
    agent_roster,
    dig,
)

from . import _shared
from ._shared import (
    _fs_reads_are_confined,
    _b323_contains_env_var_reference,
    _B55_FS_WRITE_TOOLS,
    _canon_tool,
    _config_unreadable,
    _custom,
    _dir_replaceable_by_others,
    _external_input_channels,
    _finding,
    _has_approval_gate,
    _hint,
    _key_advice,
    _node_allow_skills,
    _node_commands,
    _open_channels,
    _profile_is_powerful,
    _surface_absent,
    _unpolicied_open_wildcard_group_channels,
)
from ..invocation import command_prefix


_AUTO_GATE_BLAST = {
    "exec": ("EXEC",),
    "send": ("EGRESS",),
    "write": ("DESTRUCTIVE", "MAILBOX_CONFIG"),
}


# Inverse of _AUTO_GATE_BLAST: which approval_gates class (if any) covers a given
# held high-blast class. COMMERCE has no entry — the attestation schema's
# approval_gates only covers exec/send/write (see attest.GATE_CLASSES), so a held
# COMMERCE verb never has a confirmable gate either way.
_GATE_CLASS_FOR_BLAST = {
    "EXEC": ("exec",),
    "EGRESS": ("send",),
    "DESTRUCTIVE": ("write",),
    "MAILBOX_CONFIG": ("write",),
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
# variants of the same capability count. B-735 correction: the claim this comment used
# to make — "NONE of these are real OpenClaw tool ids" — was wrong, and being believed
# is exactly why fs_delete/fs_move went unmodelled for as long as they did (a name
# believed fake is not a name anyone extends). Grounded against the installed 2026.9.4
# dist: "fs_write" (plus "fs_delete"/"fs_move", added below) sits in the vendor's OWN
# dangerous/fs tool family in two independent lists — DEFAULT_GATEWAY_HTTP_TOOL_DENY
# (dangerous-tools-*.mjs) and ACP_UNSUPPORTED_INHERITED_TOOL_DENY
# (subagent-capabilities-*.mjs), both grouping it with write/edit/apply_patch/exec. It
# IS a real, dispatchable tool id — kept as a legacy-alias union (not the primary
# detection path, see _B55_FS_WRITE_TOOLS / check_fs_write_exposure below) because this
# project's own pre-existing fixtures/tests already use "fs_write" as their token and
# because raw-token hint matching is what actually catches an EXPLICIT
# tools.allow/alsoAllow grant of a tool _B68_FS_TOOLS' canonical resolution does not
# enumerate (fs_delete/fs_move are not in _B68_FS_TOOLS — see that tuple's own comment).
#
# B-735: fs_delete / fs_move are the two other real fs-write-family tool ids the same
# two vendor lists name (grouped with fs_write, not with the non-fs dangerous tools in
# the same lists like terminal/portal/sessions_spawn) -- but deliberately NOT added to
# the substring tuple above. C-135 adversarial review found "fs_delete"/"fs_move" as
# SUBSTRINGS collide with plausible real tool names: "refs_delete"/"refs_move" (a git-
# refs tool) and "prefs_delete"/"prefs_move" (a preferences tool) both end in "fs"
# immediately before "_delete"/"_move" and would substring-match -- the identical B-395
# false-positive shape bare "write"/"edit" caused, not the "fs_write"/"write_file"
# shape (genuinely safe as a substring: no realistic tool name contains that exact
# multi-segment sequence by accident). Matched by EXACT canonical-name membership
# instead, the same treatment B-395 already gives "write"/"edit" for the same reason.
_FS_WRITE_TOOL_HINTS = ("fs_write", "write_file", "writefile", "apply_patch")

# The exact-match companion to _FS_WRITE_TOOL_HINTS -- see that tuple's B-735 comment
# for why fs_delete/fs_move are matched here (exact) rather than there (substring).
_FS_WRITE_TOOL_EXACT = frozenset({"fs_delete", "fs_move"})

# F-169: _B55_FS_WRITE_TOOLS now lives in ._shared (A1 asks the same question).


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
      - <agent>.tools.toolsBySender.<key>.deny  (per-agent per-sender, either roster shape)
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

    # 3. Per-agent: <agent>.tools.toolsBySender.<key>.deny
    #
    # B-699: through `agent_roster`, so BOTH roster shapes are seen. This site was missed
    # by the first pass — it walked `agents.get("list")` by hand rather than digging the
    # path, so a grep for the retired key did not surface it. Measured: with a per-agent
    # `toolsBySender.deny` expressed the 2026.8.1 way, this returned NO scopes at all and
    # B31 went UNKNOWN ("No tool deny-policy configured") instead of evaluating the policy
    # that is actually there. The scope label comes from the entry, so it names the key the
    # user's own file contains rather than a position in an array they may not have.
    for agent in agent_roster(cfg):
        agent_tools = agent.entry.get("tools")
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
                    (f"{agent.path}.tools.toolsBySender.{key}.deny", deny_set)
                )

    return results


def _has_heartbeat_signal(ctx: Context) -> bool:
    """True when config/bootstrap indicates scheduled/heartbeat execution."""
    cfg = ctx.config
    return (
        any(path.endswith("HEARTBEAT.md") for path in getattr(ctx, "bootstrap", []))
        or dig(cfg, "agents.defaults.heartbeat")
        # B-699: agents.entries as well as agents.list
        or any(dig(agent.entry, "heartbeat") for agent in agent_roster(cfg))
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
    WARN    — a high-blast verb is held. The wording distinguishes, per the
              specific held class's own reported gate (never any other class'
              gate — B-805), whether that class is confirmed gated, confirmed
              running without approval ('auto'), or unreported.
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
            f"Run '{command_prefix()} --ask' to emit a template, have the agent fill in its "
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
    # B-805: this used to say "An approval gate is reported" whenever ANY class
    # anywhere in approval_gates was 'required' — including a class the agent does
    # NOT hold (e.g. 'send: required' while only 'exec' is held, with 'exec:
    # auto'). Judge the HELD class(es) by their OWN mapped gate only: if any held
    # class's own gate is confirmed 'auto', say plainly that it runs ungated,
    # regardless of what an unheld class's gate says. Every other case (a genuine
    # 'required' gate on the held class, or no approval_gates reported at all)
    # keeps the original wording unchanged.
    gates_map = att.get("approval_gates")
    gates_map = gates_map if isinstance(gates_map, dict) else {}
    applicable_gates = set()
    for cls in high:
        applicable_gates.update(_GATE_CLASS_FOR_BLAST.get(cls, ()))
    auto_confirmed = sorted(
        gc for gc in applicable_gates
        if str(gates_map.get(gc, "")).strip().lower() == "auto"
    )
    if auto_confirmed:
        auto_label = ", ".join(auto_confirmed)
        return _finding(
            "B43",
            WARN,
            f"The agent holds high-blast-radius verbs ({label}). {auto_label} "
            f"run{'s' if len(auto_confirmed) == 1 else ''} without approval per "
            "the agent's self-report — there is no gate to bypass for that verb "
            "in the first place, and holding it at all widens the blast radius.",
            "Remove any dangerous verb the agent does not strictly need; "
            "require human approval (not 'auto') before exec/send/write and "
            "for any mailbox-config change.",
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
    for agent in agent_roster(cfg):  # B-699: agents.entries as well as agents.list
        val = dig(agent.entry, "tools.fs.workspaceOnly")
        if val is not None:
            name = agent.entry.get("name") or agent.id or agent.index
            scopes.append((f"{agent.labelled(name)}.tools.fs.workspaceOnly", val))
    return scopes


# The filesystem tool family tools.fs.workspaceOnly governs, verbatim from OpenClaw's own
# composite predicate: `["read","write","edit","apply_patch"].filter(isToolAllowedByPolicies)`
# (audit.nondeep.runtime-C3y1Q5Fi.js:583-588).
_B68_FS_TOOLS = ("read", "write", "edit", "apply_patch")

# B-736: `write` IMPLIES `apply_patch` (dist `tool-policy-match-DS7InkLt.js:24`,
# `createToolPolicyMatcher`'s `writeAllowsApplyPatch` parameter, default `true` --
# toolgrant.py's own module docstring "ALIAS TABLE"/implication section is the grounding
# citation; reused here rather than re-derived). A policy whose allow list names `write`
# but not `apply_patch` still lets `apply_patch` through THAT policy -- and, evaluated
# per policy inside the vendor's AND, a policy that DENIES `write` does NOT deny
# `apply_patch`: they are separate tokens at the deny layer, and the implication only
# ever adds on the allow side. `_tool_policy_view` (this module) modelled neither
# direction ("NOT modelled, deliberately" in its own docstring, before this fix) --
# `toolgrant.py` already modelled it correctly for the PER-AGENT scopes `_b68_fs_tools_
# granted` consults (B-668/S3's `scoped` set below), so the accumulator's GLOBAL layer
# was the one place a hardened `deny:["write"]` config still silently kept apply_patch
# reachable and told the operator otherwise. Grounded to be the ONLY such implication in
# the dist: `createToolPolicyMatcher` special-cases exactly this one pair, and
# toolgrant.py's own dist-executed grounding (tests/test_toolgrant_dist_grounding.py)
# has never found a second. Fixed LOCALLY in `_b68_fs_tools_granted` (not in
# `_tool_policy_view` itself, which B44 also reads for an unrelated self-report
# cross-check that has no vetted reason to inherit this) -- the narrower of the two
# options the task weighed, matching every other consumer of `_tool_policy_view` staying
# byte-identical to before.
_B68_WRITE_IMPLIES = "apply_patch"


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


def _b68_scope_confined(cfg: dict, own_tools, entry) -> bool:
    """B-942: whether ONE scope's own filesystem-tool policy confines it -- its own
    ``tools.fs.workspaceOnly`` (falling back to the global value when this scope
    doesn't set one) is ``True``, or its own sandbox mode (its own roster entry's
    ``sandbox.mode``, falling back to ``agents.defaults.sandbox.mode``) is ``"all"``.

    This is OpenClaw's own per-context ``fsUnguarded`` composite
    (``context.tools?.fs?.workspaceOnly ?? cfg.tools?.fs?.workspaceOnly``,
    ``audit.nondeep.runtime``), asked about ONE scope instead of only the global
    config -- factored out of `_fs_scope_grants`'s inline ``confinement=True`` test
    (B-737) so a second caller can ask the identical question about a roster entry
    it already has in hand (G1's `scoped`/widening resolution below, B-942) without
    duplicating the composite a second time and risking the two drifting apart.

    ``own_tools`` and ``entry`` are threaded separately, not derived from one
    another, because they come from different sources for the synthesised
    default-agent scope: its ``own_tools`` is ``agents.defaults.tools`` while its
    ``entry`` (for the sandbox-mode lookup) has no roster row at all. For a real
    roster agent both are the same entry's own dict (``entry.get("tools")`` and
    ``entry`` itself) -- exactly how `_fs_scope_grants` already threads
    ``scope.own_tools`` and ``scope.entry`` through this same test.
    """
    own_fs = own_tools.get("fs") if isinstance(own_tools, dict) else None
    workspace_only = own_fs.get("workspaceOnly") if isinstance(own_fs, dict) else None
    if workspace_only is None:
        workspace_only = dig(cfg, "tools.fs.workspaceOnly")
    # Reuses `toolpolicy._sandbox_mode` (own entry's `sandbox.mode`, falling back to
    # `agents.defaults.sandbox.mode`) rather than a second `dig(entry, "sandbox.mode")`
    # -- that helper already reads the per-entry field directly (not through `dig()`,
    # so it carries no `relative:` schema-grounding manifest entry of its own to
    # duplicate), and is the SAME resolution `_sandbox_confines`/`confined_scopes`
    # already use for this identical question elsewhere in this codebase.
    sandbox_mode = _toolpolicy._sandbox_mode(cfg, entry)
    return workspace_only is True or sandbox_mode == "all"


def _agent_profile_widenings(cfg: dict, *, skip_confined: bool = False) -> list:
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

    B-942: ``skip_confined=True`` additionally drops a widening whose OWN agent
    individually confines itself (`_b68_scope_confined`, the same per-scope
    ``tools.fs.workspaceOnly``/sandbox-mode composite `_fs_scope_grants` already
    asks) -- B68's confinement-aware caller passes this so a widening that grants
    an fs tool to an agent that ALSO opts that agent back into workspace
    confinement doesn't get named as an unconfined reason to WARN. Every other
    caller (B55, and G1's own default resolution) keeps the default ``False`` and
    is unaffected -- widening/narrowing is orthogonal to confinement for them.
    """
    if _profile_is_powerful(dig(cfg, "tools.profile")):
        return []

    out: list = []
    for agent in agent_roster(cfg):  # B-699: agents.entries as well as agents.list
        profile = dig(agent.entry, "tools.profile")
        if isinstance(profile, str) and profile and _profile_is_powerful(profile):
            if skip_confined and _b68_scope_confined(
                cfg, agent.entry.get("tools"), agent.entry
            ):
                continue
            out.append((f"{agent.path}.tools.profile", profile))
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

    # B-963: a schema-invalid, non-string `tools.profile` (a list or dict, e.g. from
    # `{"tools": {"profile": ["x"]}}`) used to count as a resolved answer here just
    # because it is not `None` -- `_profile_is_powerful` is crash-safe for it
    # (`str(profile or "").lower()` on a list/dict matches nothing), so a bare
    # non-string profile with no other grant signal made `_b68_fs_tools_granted`
    # return "fully resolved, nothing granted" (a confident PASS) instead of the
    # honest UNKNOWN a real OpenClaw config could never reach (`ToolProfileSchema`
    # is an enum of strings). Mirrors `toolgrant._block_well_formed`'s own
    # `isinstance(profile, str)` guard for the identical malformed-input class.
    # An empty string is unaffected (`"" is not None` was already `True` before
    # this, and `isinstance("", str)` is `True` too) -- only a non-string value
    # changes direction, from a confident answer to not-enumerable.
    profile_enumerable = isinstance(profile, str)
    return _ToolPolicyView(
        named=tuple(named),
        raw_named=tuple(raw_named),
        denied=denied,
        profile=profile,
        grants_all=explicit_all or implicit_all,
        implicit_all=implicit_all,
        enumerable=bool(named) or explicit_all or implicit_all or profile_enumerable,
    )


def _b68_fs_tools_granted(cfg: dict, *, confine_per_agent: bool = False) -> tuple[list[str], bool]:
    """Which filesystem tools config GRANTS, and whether that is knowable at all.

    B-283 (b). Returns ``(granted, enumerable)``. Delegates ALL policy resolution to
    _tool_policy_view — see its docstring for the grounding, including the alsoAllow
    implicit-wildcard (B-411) and the gateway.tools.allow de-denylist correction (B-423).

    B-942: ``confine_per_agent=True`` (B68's own call site only -- B44/B55/B84 keep the
    default and are byte-unaffected) drops a per-agent (``scoped``) or per-agent-profile
    (``widenings``) contribution whose OWN scope individually confines itself
    (`_b68_scope_confined`) -- the same ``tools.fs.workspaceOnly``/sandbox-mode composite
    `_fs_scope_grants` already applies for its NOT-ENUMERABLE residual, now also applied
    here, on G1's own ENUMERABLE path, which previously granted-then-warned about a
    per-agent scope without ever reading THAT scope's own confinement declaration. The
    GLOBAL accumulator (named/grants_all/profile) is untouched by this flag: it is not
    per-scope, and by the time B68 calls G1 the caller has already cleared the whole
    config on a TRUE global `tools.fs.workspaceOnly` (see `check_exec_applypatch_
    workspace`'s own short-circuit above its G1 call), so anything the global
    accumulator still contributes here is, by construction, genuinely unconfined.
    Enumerability (whether ANYTHING was resolvable at all) is computed from the RAW,
    unfiltered `widenings`/`scoped` below, deliberately -- confinement and resolvability
    are orthogonal questions; a config that resolves to "confined, nothing left
    unconfined" is a real, positive answer, not an unresolvable one.

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
    # B-942: the confinement-aware subset of `widenings` -- equal to `widenings` itself
    # unless `confine_per_agent` is set, in which case a widening whose own agent
    # individually confines itself is dropped. Only used to gate the grant contribution
    # below, never the enumerability test further down, which stays keyed on the RAW
    # `widenings` (see this function's own docstring for why).
    gating_widenings = (
        _agent_profile_widenings(cfg, skip_confined=True) if confine_per_agent else widenings
    )

    granted: set = set()
    if view.grants_all or "group:fs" in view.named:
        granted |= set(_B68_FS_TOOLS)
    granted |= {t for t in _B68_FS_TOOLS if t in view.named}
    if view.profile is not None and _profile_is_powerful(view.profile):
        granted |= set(_B68_FS_TOOLS)
    if gating_widenings:
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

    # B-668 (S3): resolve what the PER-AGENT scopes grant, resolved by the ported vendor
    # predicate rather than by the accumulator above.
    #
    # Everything above this line models the GLOBAL layer. A grant that exists only inside an
    # `agents.*` entry was therefore invisible, and the checks built on it returned a
    # confident "no filesystem-write tool is granted" on configs the runtime grants write on
    # — reproduced on `clean_b409_weak_agent_profile_no_widening` (scope `reader`) and
    # `toolscope_case6_per_agent_alsoallow_widens_with_profile` (scope `helper`), both
    # confirmed by EXECUTING the vendor's own resolveConfiguredToolPolicies +
    # isToolAllowedByPolicies against the installed 2026.9.1 dist.
    #
    # ONLY agents that DECLARE their own `tools` are consulted, and that restriction is the
    # whole design, not a shortcut. `toolgrant` is a faithful port, so asking it about an
    # agent that declares nothing returns the VENDOR DEFAULT — and that default is
    # permissive: measured, a config with no `tools` block at all grants read/write/edit/
    # apply_patch. Consulting every scope unconditionally therefore imports a second,
    # far larger change: 65 of 541 fixtures would newly count as granting write, none of
    # them because of a per-agent grant. That is a real blindness (B55 does not see the
    # permissive default) but it is a decision about what the tool asserts, not this
    # migration — see B-736. Restricted to declaring agents the blast radius is exactly the
    # two fixtures above, which is what a fix for B-668 should touch and nothing more.
    # B-941: `toolgrant.granted()` is a faithful, vendor-EXECUTED port -- trusting its
    # answer is right even when this SCOPE's own `tools.profile` is a string
    # `toolgrant._CORE_TOOL_PROFILES` does not recognise (e.g. "readonly" in the
    # `clean_b409_weak_agent_profile_no_widening` fixture below), as long as some OTHER
    # real, well-formed layer -- the global `tools.allow`/`alsoAllow`/`deny`, or this
    # agent's own -- still resolves to a non-empty `toolgrant._policies(cfg, scope)`.
    # `_profile_policy` already maps an unrecognised profile string to `None`, dropping
    # it from that AND-ed list exactly like an ABSENT profile would, so the resolution
    # is still the genuine vendor answer (that fixture's "readonly" silently drops the
    # global `minimal` restriction, and the global `alsoAllow` then injects unionAllow's
    # wildcard -- a real, differentially-verified grant, not a guess).
    #
    # The bug is narrower: when `_policies(cfg, scope)` comes back EMPTY *because the
    # only thing that would have constrained it is an unrecognised `tools.profile`* --
    # `all(...)` over zero policies vacuously returns `True` for every tool. A real
    # OpenClaw could never reach that state (`ToolProfileSchema` is a string enum, so
    # the config would fail to load), so reading it as a confident "everything granted"
    # WARN, rather than the honest "this value is unparseable" UNKNOWN, was the actual
    # defect (repro: a named agent whose ENTIRE own `tools` block is just an
    # unrecognised `profile`, with no global `tools` block either -- `{"agents": {"list":
    # [{"id": "main", "tools": {"profile": "Messaging"}}]}}`).
    #
    # `toolgrant._unresolved_profile(cfg, scope)` isolates exactly that reason, as
    # opposed to every OTHER way `_policies` can come back empty -- chiefly a real
    # config whose only `tools` key is an opaque `byProvider`/`toolsBySender` layer this
    # module cannot read at all (`OPAQUE_NARROWING_KEYS`). That second shape is now
    # handled too (B-938, below) -- NEVER `toolgrant._block_well_formed`, which would
    # also (wrongly) discard the "readonly" scope above -- it inspects this scope's OWN
    # tools block in isolation and cannot see the real global layer that still resolves
    # it. A scope this loop skips falls through to `_fs_scope_grants`
    # (`toolgrant.resolved_scopes`) below, which also lands on UNKNOWN for it (that
    # helper's own, stricter, whole-config `_block_well_formed` contract -- see its
    # docstring) -- never a silent drop to "nothing granted".
    #
    # B-938: this loop used to gate ONLY on `entry.id` + a truthy `entry.get("tools")`
    # before calling `toolgrant.granted(cfg, t, entry.id)` for each fs tool -- a
    # SEPARATE "is this scope enumerable" test from the one `_fs_scope_grants` below
    # already uses (`toolgrant.resolved_scopes(...).opaque`). The two disagreed on
    # exactly the shape `_unresolved_profile` above does not cover: a named entry whose
    # ONLY `tools` content is `byProvider`/`toolsBySender`. `_pick_policy` (and
    # `_profile_policy`, since neither key is a recognised `profile` string) never reads
    # either key, so such an entry's `_policies(cfg, scope)` comes back EMPTY --
    # `_unresolved_profile` is False for it (no `profile` key at all, let alone an
    # unresolved one), so the old gate above did not skip it -- and `all(...)` over zero
    # policies is vacuously True for every tool: a confident full grant manufactured
    # from a genuinely opaque, unresolvable config, not a real one. This loop now
    # consults the SAME `resolved_scopes` opaqueness verdict `_fs_scope_grants` already
    # trusts for this exact class, so the two gates can no longer disagree; a scope this
    # skips falls through to `_fs_scope_grants`'s own opaque-skip below, landing on the
    # same UNKNOWN `_fs_scope_grants` already produces for every other opaque scope --
    # never a silent drop to "nothing granted".
    scoped: set = set()
    # B-942: `scoped_unconfined` mirrors `scoped` exactly except it skips a roster
    # entry's contribution when that entry individually confines itself
    # (`_b68_scope_confined`) -- computed alongside `scoped` (not derived from it
    # afterwards) because `scoped` is a flat union of tool NAMES and cannot be
    # un-mixed by origin once merged. Only consulted by the caller when
    # `confine_per_agent` is set; `scoped` itself stays the full, unfiltered union so
    # the enumerability test below is unaffected by confinement.
    scoped_unconfined: set = set()
    _roster = agent_roster(cfg)
    _scope_opacity = {
        _res.scope: _res.opaque for _res in (_toolgrant.resolved_scopes(cfg) or ())
    }
    for _entry in _roster:
        if not _entry.id or not isinstance(_entry.entry, dict):
            continue
        if not _entry.entry.get("tools"):
            continue
        if _scope_opacity.get(_entry.id):
            continue
        if not _toolgrant._policies(cfg, _entry.id) and _toolgrant._unresolved_profile(cfg, _entry.id):
            continue
        _entry_granted = {t for t in _B68_FS_TOOLS if _toolgrant.granted(cfg, t, _entry.id)}
        scoped |= _entry_granted
        if not _b68_scope_confined(cfg, _entry.entry.get("tools"), _entry.entry):
            scoped_unconfined |= _entry_granted

    # `agents.defaults.tools` is the second DECLARED per-agent surface, and it is a scope
    # only when NO roster exists -- measured against the vendor: declared with no roster it
    # grants, declared alongside `agents.entries` it is ignored entirely, which is what the
    # shipped fixture `toolscope_case9_agents_defaults_tools_ignored_with_roster` is named
    # for. Consulted at global scope because that is where the vendor surfaces it in that
    # shape, and gated on the key being DECLARED for the same reason the loop above is gated
    # on `entry["tools"]`: an ungated global query returns the permissive vendor default and
    # reintroduces the 65-fixture expansion this migration is deliberately not making.
    # Same B-941 gate as the per-agent loop above -- this is the identical
    # `toolgrant.granted()` vacuous-grant shape, reached through `agents.defaults.tools`
    # instead of a roster entry (e.g. `{"agents": {"defaults": {"tools": {"profile":
    # "Messaging"}}}}`, no roster at all, no global `tools` block either).
    _defaults_vacuous_malformed = (
        not _toolgrant._policies(cfg) and _toolgrant._unresolved_profile(cfg)
    )
    if not _roster and dig(cfg, "agents.defaults.tools") and not _defaults_vacuous_malformed:
        # No roster exists here (the `if not _roster` guard), so this synthesised
        # default-agent scope cannot have its OWN per-entry `tools.fs.workspaceOnly`
        # override to individually confine it -- its confinement is exactly the
        # GLOBAL `tools.fs.workspaceOnly`/`agents.defaults.sandbox.mode` composite
        # `check_exec_applypatch_workspace` already clears before ever calling G1.
        # Always counted as unconfined-eligible here for that reason, not skipped.
        _defaults_granted = {t for t in _B68_FS_TOOLS if _toolgrant.granted(cfg, t)}
        scoped |= _defaults_granted
        scoped_unconfined |= _defaults_granted

    # The enumerability gate has to see `scoped`, and that ordering is the whole point of
    # computing it above rather than below. An independent C-135 pass on the first draft of
    # this change found the gate short-circuiting ahead of the per-agent resolution: on a
    # config with NO global `tools` block whose only grant is per-agent
    # (`agents.entries.main.tools.allow = ["write"]`), `view.enumerable` is False and
    # `widenings` is empty, so the early return fired and the migration never ran. The vendor
    # grants write and apply_patch there; we answered UNKNOWN. A config we CAN resolve must
    # not be reported as unresolvable, so a per-agent grant makes the answer enumerable on
    # its own.
    if not view.enumerable and not widenings and not scoped:
        return [], False

    # B-736: the write=>apply_patch implication (see _B68_WRITE_IMPLIES above), applied
    # ONCE here after every source that can grant "write" has already unioned in --
    # named/grants_all/group:fs/profile/widenings all reach this point through `granted`,
    # so this one line covers all of them instead of repeating the check at each site.
    # Deliberately BEFORE the deny subtraction below, mirroring the vendor's own order
    # (createToolPolicyMatcher checks deny first for the LITERAL token being tested, then
    # allow, then the implication) -- so a config that ALSO explicitly denies
    # "apply_patch" itself (not just "write") still has it removed at that step, exactly
    # as it should.
    if "write" in granted:
        granted.add(_B68_WRITE_IMPLIES)

    # `view.denied` is the GLOBAL deny list and is applied only to the globally-derived set.
    # `scoped` already came from the vendor predicate, which applies every deny layer itself
    # (verified: global `deny:["write"]` with a per-agent `allow:["write"]` resolves to
    # nothing at that agent's scope) -- subtracting it a second time could only remove a
    # grant the runtime keeps.
    #
    # B-942: `confine_per_agent` swaps in `scoped_unconfined` here -- the same per-agent
    # union, minus any scope that individually confines itself. `granted` (the global
    # accumulator) is untouched either way; see this function's own docstring for why.
    final_scoped = scoped_unconfined if confine_per_agent else scoped
    return sorted((granted - view.denied) | final_scoped), True


class _FsScopeGrants(NamedTuple):
    """Per-scope fs-tool grant resolution for B55/B68's NOT-ENUMERABLE branch (B-737).

    Split by PROVENANCE, never by scope identity: ``default_tools``/``declared_tools`` are the
    union of tools any non-opaque, non-confined scope of that provenance grants;
    ``default_scopes``/``declared_scopes``/``opaque_scopes`` are those scopes' labels, for
    wording only. ``inert_defaults_tools`` is true when ``agents.defaults.tools`` is set beside
    a declared roster key, where the vendor ignores it entirely (``toolscope_case9``) -- kept
    separate so a finding can say so without implying "nothing declared".

    B-943: ``fully_resolved`` and ``checked_scopes`` exist so a caller can tell "resolved,
    and genuinely grants nothing" apart from "could not resolve" instead of collapsing both
    into the same fallback. ``fully_resolved`` is true exactly when ``opaque_scopes`` is
    empty -- every scope ``resolved_scopes`` returned was assessable, so this function's own
    "cannot tell" reason never fired for ANY of them (the OTHER "cannot tell" reason -- the
    whole config being unresolvable -- is already the ``None`` return, one layer up).
    ``checked_scopes`` names every non-opaque (and, under ``confinement=True``, non-confined)
    scope this actually ran the grant test against, whether or not that test found anything --
    ``default_scopes``/``declared_scopes`` are the subset of it where something WAS found. A
    caller reporting "nothing granted" can therefore name exactly which scopes back that claim
    (``checked_scopes``) instead of a bare "trust me", and only when ``fully_resolved`` is true
    AND ``checked_scopes`` is non-empty -- e.g. every scope confined away under
    ``confinement=True`` leaves ``checked_scopes`` empty with nothing to back a claim, so that
    edge is deliberately left for the caller to keep reading as unresolved, not promoted to a
    PASS with no scope to name.
    """

    default_tools: frozenset
    declared_tools: frozenset
    default_scopes: "tuple[str, ...]"
    declared_scopes: "tuple[str, ...]"
    opaque_scopes: "tuple[str, ...]"
    inert_defaults_tools: bool
    checked_scopes: "tuple[str, ...]"
    fully_resolved: bool


def _fs_scope_grants(cfg: dict, family, *, confinement: bool = False) -> "_FsScopeGrants | None":
    """B-737: resolves ``family``'s per-scope grant over every scope ``toolgrant.
    resolved_scopes`` says the vendor actually resolves, for B55/B68's NOT-ENUMERABLE branch
    ONLY -- ``_b68_fs_tools_granted`` (G1, above) already resolves every shape it covers, and
    this function runs only on ITS residual (``not enumerable``), so the two can never
    double-count the same grant.

    This replaces three earlier, independently-drifting predicates for "does the operator's
    tool policy decide this scope" (a hand-written declared-keys list, and a ``toolgrant``
    query at ``GLOBAL_SCOPE`` that stopped being a real session scope once a roster existed)
    with one semantic test: ``toolgrant.resolved_scopes``'s ``provenance``, which asks whether
    any operator-written policy LAYER (``toolgrant.policy_layers``) constrains the scope the
    vendor actually resolves, not whether some hand-chosen set of config keys is present. See
    the ``toolgrant.py`` module docstring's ``resolved_scopes`` for the full grounding.

    Returns ``None`` when ``resolved_scopes`` itself returns ``None`` (an empty/malformed
    config, an unparseable tools block, or two roster agents that normalize to the same id) --
    the caller keeps its base UNKNOWN, never a guess.

    B-943: a non-``None`` result is now a THREE-way answer, not two:

    1. Something was found (``default_tools`` or ``declared_tools`` non-empty) -- a real grant,
       unchanged from before this change.
    2. Nothing was found, but ``fully_resolved`` is true and ``checked_scopes`` is non-empty --
       every scope this could examine WAS examined (none opaque), and genuinely grants nothing
       in ``family``. This is a real, positive "resolved, and resolved to nothing" result, not
       an "I couldn't tell" -- callers should read it as PASS, naming ``checked_scopes``.
    3. Nothing was found and either ``fully_resolved`` is false (at least one scope was opaque,
       so this function's own resolution genuinely fell short somewhere) or ``checked_scopes``
       is empty (nothing was left to examine, e.g. every scope confined away) -- the caller's
       base UNKNOWN, same as the ``None`` case, because there is no scope to back a claim
       either way.

    ``confinement=True`` (B68 only) additionally skips a scope whose OWN
    ``tools.fs.workspaceOnly`` (falling back to the global value) is ``True``, or whose sandbox
    mode (the scope's own roster entry, falling back to ``agents.defaults.sandbox.mode``) is
    ``"all"`` -- the vendor's own per-context fsUnguarded composite
    (``context.tools?.fs?.workspaceOnly ?? cfg.tools?.fs?.workspaceOnly``,
    ``audit.nondeep.runtime``), asked PER SCOPE instead of only at the global scope B68's own
    G1 path (and the global short-circuit above it) already read.
    """
    scopes = _toolgrant.resolved_scopes(cfg)
    if scopes is None:
        return None

    inert_defaults_tools = bool(dig(cfg, "agents.defaults.tools")) and _toolgrant._has_agent_roster(cfg)

    default_tools: set = set()
    declared_tools: set = set()
    default_scopes: list = []
    declared_scopes: list = []
    opaque_scopes: list = []
    checked_scopes: list = []
    for scope in scopes:
        if scope.opaque:
            opaque_scopes.append(scope.label)
            continue
        if confinement:
            # B-942: factored out into `_b68_scope_confined` so B68's own per-agent grant
            # loop (G1's `scoped`/widening resolution) can ask the identical composite
            # about a roster entry it already has in hand, instead of duplicating it a
            # second time -- see that helper's docstring for the full grounding.
            if _b68_scope_confined(cfg, scope.own_tools, scope.entry):
                # Deliberately NOT added to `checked_scopes`: this scope was resolved (it is
                # not opaque), but the grant question was never asked of it because
                # confinement already makes it moot -- B-943's PASS path only names a scope
                # it actually ran the grant test against.
                continue
        # B-943: recorded BEFORE the emptiness test below, so a scope that resolves and
        # grants nothing in `family` is still named as "checked" -- previously it silently
        # vanished (no branch recorded it), which is exactly why the caller had no way to
        # distinguish "resolved, nothing granted" from "could not resolve".
        checked_scopes.append(scope.label)
        got = {tool for tool in family if _toolgrant.granted(cfg, tool, scope.scope)}
        if not got:
            continue
        if scope.provenance == "default":
            default_tools |= got
            default_scopes.append(scope.label)
        else:
            declared_tools |= got
            declared_scopes.append(scope.label)

    return _FsScopeGrants(
        frozenset(default_tools),
        frozenset(declared_tools),
        tuple(default_scopes),
        tuple(declared_scopes),
        tuple(opaque_scopes),
        inert_defaults_tools,
        tuple(checked_scopes),
        not opaque_scopes,
    )


def _b737_provenance(result: "_FsScopeGrants") -> str:
    """"default", "declared" or "mixed" -- which of `result`'s two tool sets is non-empty.
    Only ever called after confirming at least one of them is (both callers check that
    before keeping a non-``None`` `scope_grants`), so this never needs a third "neither"
    answer."""
    if result.default_tools and result.declared_tools:
        return "mixed"
    return "default" if result.default_tools else "declared"


def _b737_provenance_sentences(result: "_FsScopeGrants") -> list:
    """The wording B-737's design mandates for a finding driven by `_fs_scope_grants`:
    name the specific scopes and tools a provenance applies to, never "declared anywhere"
    or "every agent" -- that would overstate a `default`/`mixed` result to every scope when
    only some of them are default, and understate a `declared` result by implying no policy
    applies. A `mixed` result gets both sentences, one per provenance."""
    out: list = []
    if result.default_scopes:
        out.append(
            f"No tool policy restricts {', '.join(result.default_scopes)}: OpenClaw's "
            f"permissive default grants {', '.join(sorted(result.default_tools))}."
        )
    if result.declared_scopes:
        out.append(
            f"The tool policy that applies to {', '.join(result.declared_scopes)} still "
            f"grants {', '.join(sorted(result.declared_tools))}."
        )
    if result.inert_defaults_tools:
        out.append(
            "agents.defaults.tools is set but ignored: OpenClaw drops it entirely once a "
            "roster (agents.entries / agents.list) is declared, even an empty one."
        )
    if result.opaque_scopes:
        out.append(
            "Not assessed for "
            + ", ".join(result.opaque_scopes)
            + ": a byProvider/toolsBySender tool-policy layer there is not readable from "
            "static config."
        )
    return out


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
    B55's OWN legacy-alias/raw-token fallback against the raw allow/alsoAllow tokens:
    `_FS_WRITE_TOOL_HINTS` ("fs_write", "write_file", "writefile", "apply_patch"),
    substring-matched, plus `_FS_WRITE_TOOL_EXACT` ("fs_delete", "fs_move"),
    exact-canonical-match (C-135: as substrings they collide with plausible real tool
    names like "refs_delete"/"prefs_move" -- see `_FS_WRITE_TOOL_HINTS`'s own B-735
    comment). These are treated as real tool ids (B-735 correction: this docstring used
    to claim otherwise; they are named in vendor deny lists, dispatchability is unproven, which is exactly why fs_delete/fs_move went unmodelled for as
    long as they did) -- the union exists because `_b68_fs_tools_granted` only
    enumerates the canonical `_B68_FS_TOOLS` names via profile/group:fs/widening
    resolution, and fs_write/fs_delete/fs_move are not in that tuple, so an EXPLICIT
    `tools.allow`/`alsoAllow` grant of one of them is only caught by matching the raw
    token directly (see check_fs_write_exposure's B-395 docstring section for the fuller
    history -- real fixtures, e.g. bad_b55_fs_write_broad/bad_b55_fs_delete_broad/
    bad_b55_fs_move_broad, use these tokens).

    KNOWN GAP (B-735, disclosed rather than silently left, same shape as
    check_fs_write_exposure's own documented gap #1): because fs_write/fs_delete/
    fs_move are not in `_B68_FS_TOOLS`, they are recognized ONLY via a literal raw
    token in `tools.allow`/`alsoAllow` -- never via `tools.profile="full"`, a bare
    wildcard `"*"` allow, or `group:fs`, the way write/edit/apply_patch already are
    through `_b68_fs_tools_granted`'s canonical resolution. A real OpenClaw `"*"`
    allowlist grants fs_delete/fs_move too (they are ordinary tools, not a separate
    permission), so `{"tools": {"allow": ["*"], "deny": ["write","edit","apply_patch"]}}`
    reads as NO write tool granted here even though the runtime still grants
    fs_delete/fs_move under the wildcard. Widening `_B68_FS_TOOLS` itself would close
    this but also changes B68's workspace-confinement verdict and B84's grant model for
    the SAME tuple -- a materially larger, differently-scoped change than this task
    asked for (see the task's own "decide whether the whole deny set or only its fs
    members" framing). Left as a follow-up, not fixed here.

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
        if _hint([raw], _FS_WRITE_TOOL_HINTS) or canon in _FS_WRITE_TOOL_EXACT
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
              (``agents.defaults.sandbox.mode == "all"``), has no granted fs tools per
              G1's direct resolution, OR (B-943) G1 is not enumerable but the B-737
              per-scope residual (``_fs_scope_grants``) resolved EVERY scope it could
              (none opaque) and none of them grants anything in the fs family — a real
              "resolved, and resolved to nothing" answer, named by the scopes actually
              checked, not a guess. (B-942) G1's own direct resolution is itself now
              per-agent confinement-aware (``confine_per_agent=True``): a scope that
              grants an fs tool but individually confines ITSELF (its own
              ``tools.fs.workspaceOnly`` or sandbox mode) does not count toward this
              function's grant, so an all-confined-per-agent config reaches this PASS
              via G1 directly rather than needing the not-enumerable residual.
    WARN    — either sibling is explicitly ``false`` (OpenClaw's own dangerous-flag list,
              dangerous-config-flags-current-CrOoyQT2.js:48), or the composite predicate
              holds with the field merely absent.
    UNKNOWN — fs tool grants are not enumerable from config (no tools.allow /
              tools.alsoAllow naming an fs-family tool, and no tools.profile), neither
              sibling is explicitly false, AND (B-943) the per-scope residual could not
              fully resolve either — at least one scope is opaque (a byProvider/
              toolsBySender layer), or every scope was confined away with none left to
              name a PASS against — so the composite predicate genuinely cannot be
              evaluated, not merely "evaluated to nothing".

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
    # Only the GLOBAL scope being true clears the whole config BLANKET-style here. A
    # per-agent `true` under an absent global confines that one agent while every agent
    # without an override keeps the product default (false) — so it is deliberately NOT
    # treated as a blanket PASS at this short-circuit. The inverse (global true, one
    # agent opting out with false) is already reported above, because per-agent
    # overrides global: `context.tools?.fs?.workspaceOnly ?? cfg.tools?.fs?.workspaceOnly`
    # (audit.nondeep.runtime-C3y1Q5Fi.js:589). B-942: the per-agent case this short-circuit
    # deliberately does NOT clear is no longer left unconfirmed either — G1 below is now
    # called with `confine_per_agent=True`, so a scope that grants an fs tool but
    # individually confines ITSELF (its own `tools.fs.workspaceOnly` or sandbox mode) is
    # excluded from the grant this function warns about, the same composite
    # `_fs_scope_grants` already applies for its own NOT-ENUMERABLE residual just below.
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

    granted, enumerable = _b68_fs_tools_granted(cfg, confine_per_agent=True)
    if not enumerable:
        # B-737: same residual as B55's (see its own comment) -- ask `toolgrant.
        # resolved_scopes` per scope instead of G1's syntactic "declared" vocabulary.
        # `confinement=True` also skips a scope that OpenClaw itself confines
        # (`tools.fs.workspaceOnly` / `sandbox.mode="all"`, own value or falling back
        # to the global/defaults one) -- the same composite the global short-circuit
        # above this function already reads at global scope only.
        scope_grants = _fs_scope_grants(cfg, _B68_FS_TOOLS, confinement=True)
        if scope_grants is not None and (scope_grants.default_tools or scope_grants.declared_tools):
            tools = sorted(scope_grants.default_tools | scope_grants.declared_tools)
            provenance = _b737_provenance(scope_grants)
            evidence = [
                f"filesystem tools granted ({', '.join(tools)}) by OpenClaw's own "
                f"tool-policy resolution, provenance={provenance}",
                f"agents.defaults.sandbox.mode={sandbox_mode!r} (not 'all')",
            ] + _b737_provenance_sentences(scope_grants)
            return _finding(
                "B68",
                WARN,
                f"Filesystem tools are granted ({', '.join(tools)}), the sandbox does "
                f"not contain all agents (agents.defaults.sandbox.mode={sandbox_mode!r}"
                "), and tools.fs.workspaceOnly is unset for at least one scope — its "
                "default is false, so file tools may read, write or delete anywhere "
                "the agent process can reach.",
                "Set tools.fs.workspaceOnly to true (per scope if needed), or set "
                "agents.defaults.sandbox.mode to 'all' so filesystem access is "
                "contained.",
                evidence=evidence,
            )
        # B-943: `scope_grants` resolved every scope it could (none opaque) and NONE of
        # them granted anything in the fs family — a real, positive "resolved, and
        # resolved to nothing" answer, distinct from the genuinely-unresolvable UNKNOWN
        # below. Only taken when there is at least one checked scope to name, so the
        # PASS message can point at exactly what was verified instead of asserting a
        # bare "trust me" (see `_fs_scope_grants`'s own docstring for why an all-confined
        # config, `checked_scopes` empty, deliberately falls through to UNKNOWN instead).
        if scope_grants is not None and scope_grants.fully_resolved and scope_grants.checked_scopes:
            checked = ", ".join(scope_grants.checked_scopes)
            return _finding(
                "B68",
                PASS,
                "No filesystem tool (read/write/edit/apply_patch) is granted in any "
                f"resolvable scope ({checked}), per OpenClaw's own tool-policy "
                "resolution — apply_patch has nothing to escape the workspace with.",
                "Keep it that way: if a filesystem tool is later granted, set "
                "tools.fs.workspaceOnly to true or agents.defaults.sandbox.mode to "
                "'all'.",
                evidence=[f"scopes checked, nothing granted: {checked}"],
            )
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
        # B-942: `skip_confined=True` so this evidence sentence never cites a widening
        # whose own agent individually confines itself as the reason for a WARN this
        # function only reaches once `granted` (already confinement-filtered above) is
        # non-empty from some OTHER, genuinely unconfined source.
        widenings = _agent_profile_widenings(cfg, skip_confined=True)
        if widenings:
            global_profile = dig(cfg, "tools.profile")
            widen_desc = (
                f'widens beyond the global tools.profile={global_profile!r}'
                if global_profile is not None
                else "is the only declared tools.profile (no global tools.profile is set)"
            )
            evidence.append(
                f"grant includes a per-agent tools.profile that {widen_desc}: "
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
            config_field_paths={"tools.exec.strictInlineEval"},
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


def _escaping_scope_label(cfg: dict, name: str) -> str:
    """B-670: a POSITIONAL label for one name `unconfined_write_scopes`
    returned — the roster entry's own config path (``agents.list[1]`` /
    ``agents.entries.web``), or ``"global scope"`` for the synthesised default-agent scope
    that has no roster row at all.

    Deliberately not the raw agent id. B-570 gated printing an attacker-authorable id
    string pending an owner ruling; this never constructs that string — it looks up the
    matching entry through `collector.agent_roster` (the one reader of both roster shapes,
    per B-699) and reports where the entry SITS, not what it is called. `AgentEntry.path`
    is exactly this: for `agents.list` it is the original array INDEX, not the id; for
    `agents.entries` it echoes the config's own record key, unmodified, the same way the
    roster reader already surfaces it everywhere else. No new string is authored from
    attacker input either way, so the B-570 question does not apply here.
    """
    for entry in agent_roster(cfg):
        if _toolpolicy._normalize_agent_id(entry.id) == name:
            return entry.path
    return "global scope"


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
    prior independent accumulator only matched the names in `_FS_WRITE_TOOL_HINTS`
    (real OpenClaw tool ids not enumerated by `_b68_fs_tools_granted`'s own canonical
    `_B68_FS_TOOLS` resolution — B-735 correction, this used to wrongly call them fake)
    against a raw `tools.allow` LIST only, so it produced a confident PASS on every real-world grant
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

    Gap #1, kept current rather than treated as a one-time snapshot (originally written
    during B-395; the composition problem it describes is real, but which layers this
    check actually reads has moved since): OpenClaw resolves the EFFECTIVE tool set
    through up to 8 composable policy layers (global allow/deny, per-agent allow/deny,
    byProvider ×2, channel/group tools, toolsBySender, subagent/inherited session
    policy — each AND-ed via `policies.every(...)`, `tool-policy-match-*.js:32-34`, so
    each of THESE layers can only further NARROW the set; per-agent `tools.profile` is
    the one exception and is covered separately as gap #4 below).

    RESOLVED since this was first written: per-agent `tools.allow`/`tools.deny`/
    `tools.profile` narrowing is no longer invisible here. The `_toolgrant.granted()`
    per-scope query in `_b68_fs_tools_granted` above (the B-668/S3 migration) consults
    every roster entry that declares its own `tools` block through the same ported
    vendor resolver `toolgrant.py` uses, and unions the result in as `scoped` — so this
    check now reads the global layer AND the per-agent layer, not the global layer alone.

    STILL OPEN, and not this check's job to close: the channel/group-scoped tools
    policy (`channels.<provider>.groups.<id>.tools` / `.direct.tools`) and the
    sender-keyed `toolsBySender` layer are both part of what OpenClaw's real resolver
    calls `extraPolicies` — `toolgrant.granted()` never receives them (see its own "NOT
    MODELLED" section), and nothing here maps a reachable channel back to the specific
    agent bound to it. A channel- or sender-scoped policy that actually removes the
    write tool from the agent reachable through that specific open channel is therefore
    still invisible here and can still produce a false FAIL. This is live, separately
    tracked work on the channel-attribution problem, not an abandoned gap — it stays
    named here until it lands.

    PERMANENT, not a follow-up: `byProvider` (keyed on the model provider/model id
    actually selected at request time — `resolveProviderToolPolicyEntry` reads
    `params.modelProvider`/`params.modelId`, neither of which static config carries)
    and subagent/inherited session policy (pure runtime session state, never present in
    config at all) cannot be resolved by a static scanner in principle, no matter how
    much more of this composer gets built. They are recorded here as a structural limit
    of a config-reading approach, not as unfinished work a future pass could finish.

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
    drive a FAIL: the channel/sender narrowing layers gap #1 still can't see (plus the
    two permanently-unreadable byProvider/subagent layers) could still remove the write
    tool for that specific agent/channel/sender combination.

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
              also lands here, not PASS. (B-943) The B-737 per-scope residual
              (``_fs_scope_grants``) also lands here, rather than PASS, when it could
              not fully resolve every scope either — at least one is opaque, or every
              scope was confined away with none left to name.
    PASS    — no write-capable tool granted, OR one is granted, no open-ingress channel
              reaches it, AND no channel is declared at all with untrusted-content
              reach either (_external_input_channels empty), with tools.exec.mode
              set as an approval gate. (B-943) Also PASS, naming the scopes checked,
              when G1 is not enumerable but the B-737 per-scope residual resolved EVERY
              scope it could (none opaque) and none of them grants a write-capable
              tool — a real "resolved, and resolved to nothing" answer, not the
              UNKNOWN this used to collapse into.
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
              grant -- deliberately never a FAIL, for the same reason gap #4 above
              gives: the channel/sender layers (plus the two permanently-unreadable
              ones) could still narrow it away unseen by this static check.
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

    # B-737: G1 (`_b68_fs_tools_granted`, via `_b55_write_tools_granted`) already resolves
    # every shape it covers; this residual asks `toolgrant.resolved_scopes` -- per SCOPE,
    # over the vendor's own policy layers -- instead of guessing from a syntactic "declared"
    # vocabulary (see `toolgrant.py`'s and `_fs_scope_grants`'s docstrings for why the three
    # earlier predicates here drifted). `scope_grants` stays `None` unless this residual is
    # what supplied `write_tools` below, so every later branch can tell whether it is
    # reasoning about a G1 grant (unchanged) or a B-737 per-scope one (needs provenance
    # wording) purely from `scope_grants is not None`.
    scope_grants = None
    if not enumerable:
        scope_grants = _fs_scope_grants(cfg, _B55_FS_WRITE_TOOLS & set(_B68_FS_TOOLS))
        if scope_grants is not None and (scope_grants.default_tools or scope_grants.declared_tools):
            write_tools = sorted(scope_grants.default_tools | scope_grants.declared_tools)
            enumerable = True
        elif scope_grants is not None and scope_grants.fully_resolved and scope_grants.checked_scopes:
            # B-943: every scope this could resolve WAS resolved (none opaque), and none
            # of them grants a write-capable tool -- a real, positive "resolved to
            # nothing" answer, not the "could not resolve" UNKNOWN below. Named scopes
            # back the claim instead of a bare "trust me" (see `_fs_scope_grants`'s
            # docstring for why an all-confined/empty-checked-scopes config deliberately
            # does NOT take this branch).
            checked = ", ".join(scope_grants.checked_scopes)
            return _finding(
                "B55",
                PASS,
                "No filesystem-write tool (write / edit / apply_patch) is granted in "
                f"any resolvable scope ({checked}), per OpenClaw's own tool-policy "
                "resolution.",
                "Keep write-capable tools out of the allowlist unless they are "
                "required.",
                evidence=[f"scopes checked, nothing granted: {checked}"],
            )
        else:
            scope_grants = None

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
    # B-736: "write" named in tools.allow drives the write=>apply_patch implication in
    # `_b68_fs_tools_granted` (see `_B68_WRITE_IMPLIES` there) — and naming "write" in
    # allow at ALL is an explicit operator action, never an implicit-wildcard artifact,
    # regardless of whether the literal "write" token itself survives the deny
    # subtraction. Without this disjunct, `tools.allow: ["write"], tools.deny:
    # ["write"]` reached `explicit_write_grant=False` even though write_tools is
    # ["apply_patch"] (a real, deny-surviving grant) — falling into the
    # "the only write-tool grant signal is tools.alsoAllow's implicit wildcard" WARN
    # branch below and reporting a FACTUALLY WRONG mechanism (tools.allow was not
    # absent). Guarded by `_B68_WRITE_IMPLIES not in view.denied` so it doesn't claim
    # explicitness for a config where apply_patch itself is ALSO explicitly denied —
    # symmetric with every other disjunct here already being deny-aware.
    #
    # `not widenings`: deliberately does NOT escalate when a per-agent tools.profile
    # widening is ALSO in play (B-409 C-135 round 2's confirmed false-FAIL territory —
    # test_b409_c135_exact_repro_no_longer_fails / _multi_token_deny_variant). That
    # round found the true effective grant under a widening carries MORE uncertainty
    # than the bare global layer alone: the channel/group and toolsBySender layers
    # (still unread) — plus byProvider and subagent/inherited session policy
    # (permanently unreadable from static config) — could remove it for that agent
    # unseen by this static check, so it stays the "traces to a per-agent
    # tools.profile" WARN below rather than jumping straight to FAIL. This disjunct is
    # scoped to the BARE GLOBAL case B-736's own repro is ("no agents at all... so no
    # per-agent resolution is involved") — exactly where no such extra layer exists to
    # be wrong about.
    explicit_write_grant = bool(
        (set(view.named) & _B55_FS_WRITE_TOOLS) - view.denied
        or legacy_write
        or "*" in view.named
        or "group:fs" in view.named
        or (view.profile is not None and _profile_is_powerful(view.profile))
        or (
            not widenings
            and "write" in view.named
            and _B68_WRITE_IMPLIES not in view.denied
        )
    )

    label = ", ".join(write_tools)
    gated = _has_approval_gate(cfg)
    # B-376 C-135 fix: B68 (same file) treats either field as sufficient fs confinement
    # for this identical tool family (its own composite predicate, quoted there).
    # Confined-but-reachable writes are a real but lesser risk than "arbitrary".
    #
    # B-670: both disjuncts USED to be read at global scope only, and both are per-agent
    # overridable — `resolveSandboxConfigForAgent` resolves `sandbox.mode` per FIELD with
    # `??`, and `resolveToolFsConfig` does the same for `tools.fs.workspaceOnly`. So a
    # global `sandbox.mode: "all"` beside a per-agent `sandbox.mode: "off"` fabricated
    # confinement for an agent that has none. That matters because `fs_confined` DOWNGRADES
    # a hard FAIL to WARN twenty lines below: the fabrication suppressed a real finding.
    #
    # The honest reading is per SCOPE -- one unconfined scope leaves the capability exposed
    # -- and unioning the other way (any scope confined => confined) would make the
    # suppression worse rather than better. Two attempts were retracted getting here:
    #
    # 1. Gating on `confined_scopes` alone made a hard FAIL out of an unconfined agent that
    #    cannot write at all: one whose own `tools.deny` removes the write family, or which
    #    runs `tools.profile: "messaging"` -- an ordinary notifier-bot layout beside a
    #    sandboxed coding agent. No path from untrusted input to an arbitrary write existed.
    # 2. Answering "can this scope write" by parametrising the READ stack in `toolpolicy` was
    #    UNSOUND: its profile and alias tables are read-specific, so
    #    `fixtures/bad_b55_fs_write_broad` -- `tools.allow: ["fs_write"]`, a legacy alias --
    #    resolved to "cannot write" and a designed-bad config was DOWNGRADED to WARN.
    # 3. A token heuristic over each scope's own `tools` block ("could this have removed the
    #    write family?") was wrong both ways -- it convicted allow:[write] + deny:[write,...]
    #    and acquitted profile:messaging + alsoAllow:[write] -- because it never resolved the
    #    grant.
    #
    # F-186: what survives COMPOSES two vendor-validated models instead of guessing.
    # `toolgrant.granted` resolves the per-scope grant (profile / allow / alsoAllow / deny,
    # agent replaces global) and `confined_scopes` the per-scope confinement;
    # `unconfined_write_scopes` is their conjunction, asked with THIS check's own write-tool
    # list so no third list of names exists. What it still cannot read in a scope's OWN tools
    # block -- byProvider, toolsBySender -- is treated as possible narrowing (quiet direction).
    # A per-channel/per-group tools block is NOT: it is not read at all, because it narrows
    # only the group turns of one provider -- never a DM, never another provider -- so it
    # cannot be credited to a scope (toolpolicy's "STILL OPEN" note). A config whose group
    # block really removes write therefore keeps this FAIL: the loud direction, left open.
    fs_confined = _fs_reads_are_confined(cfg)
    # Which unconfined scopes are demonstrably granted a write tool. Consumed at the FAIL
    # escalation below, NOT here: an empty list must never be read as confinement (see there).
    write_scopes = _toolpolicy.unconfined_write_scopes(cfg, write_tools)
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
        # B-737 (Dave's ruling): a grant that is only OpenClaw's permissive DEFAULT (no
        # operator policy layer decided it, `provenance` "default" or "mixed") never gets
        # the gated-and-no-ingress PASS below, even though it would look identical to a
        # genuinely narrow, operator-declared grant otherwise. A default grant is stricter
        # than an explicit one BY DESIGN here: an explicit grant reflects a decision this
        # check can point at, a default one reflects the absence of one.
        if gated and not ext_ch and scope_grants is not None and scope_grants.default_tools:
            return _finding(
                "B55",
                WARN,
                f"Filesystem-write tool granted ({label}) by OpenClaw's own permissive "
                f"default, not by any operator-written tool policy. No ingress channel "
                f"is declared, and an approval gate (tools.exec.mode) is set, but the "
                f"grant itself was never decided by config.",
                "Declare tools.allow (or tools.profile) explicitly so this grant is an "
                "operator decision, not the platform default.",
                evidence=[f"write tool granted: {label}"] + _b737_provenance_sentences(scope_grants),
            )
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
            evidence = [
                f"write tool granted: {label}",
                f"declared, not-open, untrusted-content channel(s): {', '.join(ext_ch)}",
                "approval gate present (tools.exec.mode) but not write-specific",
            ]
            if scope_grants is not None:
                evidence += _b737_provenance_sentences(scope_grants)
            return _finding(
                "B55",
                WARN,
                f"Filesystem-write tool granted ({label}) is reachable by a declared "
                f"channel carrying untrusted content ({', '.join(ext_ch)}) that is not "
                f"proven open, and the only scoping is a non-write-specific approval "
                f"gate (tools.exec.mode) — it doesn't scope write-capable tools.",
                "Lock the channel(s) to 'owner' (or 'disabled'); tools.exec.mode='ask' "
                "alone does not clear this — it doesn't scope write-capable tools.",
                evidence=evidence,
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
                "filesystem writes are confined to the workspace in EVERY declared scope "
                "(tools.fs.workspaceOnly or a fully-sandboxed session, resolved per agent) "
                "-- not arbitrary write reach"
            )
            if scope_grants is not None:
                ev += _b737_provenance_sentences(scope_grants)
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
            # B-737: a grant this check only knows about via `scope_grants` (the
            # not-enumerable residual) is, by construction, never an explicit global
            # write/edit/apply_patch grant and never a per-agent tools.profile widening
            # (`widenings` is guaranteed empty here -- see the comment where `scope_grants`
            # is computed above). The two branches below both assume a specific OTHER
            # mechanism produced the grant (a widening, or tools.alsoAllow's implicit
            # wildcard); neither is true here, so provenance wording replaces them instead
            # of running underneath a caption that describes a mechanism that didn't fire.
            if scope_grants is not None:
                ev += _b737_provenance_sentences(scope_grants)
                return _finding(
                    "B55",
                    WARN,
                    f"Filesystem-write capability ({label}) is reachable by untrusted "
                    f"senders, but the grant was resolved only for the not-enumerable "
                    f"residual (OpenClaw's own per-scope tool-policy resolution, not this "
                    f"check's own allow/alsoAllow/profile model), so this stays WARN "
                    f"pending confirmation of real intent.",
                    "Declare tools.allow (or tools.profile) explicitly so the intended "
                    "grant is unambiguous, and lock the open channel(s) to 'allowlist'.",
                    evidence=ev,
                )
            if widenings:
                global_profile = dig(cfg, "tools.profile")
                widen_desc = (
                    f'widens beyond the global tools.profile={global_profile!r}'
                    if global_profile is not None
                    else "is the only declared tools.profile (no global tools.profile is set)"
                )
                ev.append(
                    f"grant traces to a per-agent tools.profile that {widen_desc}: "
                    + ", ".join(f'{path}="{profile}"' for path, profile in widenings)
                    + " -- not an explicit global write/edit/apply_patch grant, and "
                    "the channel/group, toolsBySender, and byProvider layers this "
                    "static check still can't read could remove it for this agent "
                    "unseen here"
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
        # No unconfined scope is granted a write tool by its resolved policy, so nothing here
        # demonstrably carries a write out of the workspace. Deliberately NOT expressed by
        # making `fs_confined` true: a scope that cannot write is still not a confined scope,
        # and saying so would fabricate the confinement B-670 exists to stop fabricating.
        # It stays WARN rather than PASS because the layers `toolgrant` does not resolve
        # (byProvider, toolsBySender, per-channel tools) could only ever REMOVE a grant, and
        # this branch is reached on a grant the global resolver already established.
        # The sentence below describes the NARROWING TEST, not `widenings`. An earlier version
        # claimed "none of them widens toward the write family" while asserting it from
        # `_agent_profile_widenings`, which is profile-only and cannot see an allow/alsoAllow
        # widening -- so for `tools: {"allow": ["write"]}` the finding printed a claim the code
        # had never checked, about an override that names the write tool outright.
        #
        # `not widenings` used to gate this branch, because "sets its own tools" was too coarse
        # a proxy for "might have taken the grant away" and a per-agent `profile: coding`
        # GRANTS the family. The grant is resolved now, so a widened scope simply appears in
        # `write_scopes` when it can write and is absent when it cannot -- the proxy is gone.
        # B-712: when a scope is in `write_scopes` ONLY because its confinement could not be
        # resolved -- `sandbox.mode: "non-main"`, whose answer depends on which session runs
        # -- the FAIL below asserts "no write-specific scoping" and "arbitrary file writes"
        # about ground this check did not read. Keeping the scope is right (declining to
        # prove confinement is not proving it), but the evidence has to say which it is, or
        # the verdict fabricates certainty in the direction opposite to the confident `True`
        # the sandbox predicate used to return. Evidence-only: the verdict is unchanged.
        _undecided = _toolpolicy.undecided_write_scopes(cfg, write_tools) or []
        if _undecided:
            ev.append(
                f"{len(_undecided)} of the unconfined scope(s) are UNDECIDED rather than "
                "proven unconfined: they run under sandbox.mode 'non-main', where OpenClaw "
                "decides per session (the agent's own main session is unsandboxed, its "
                "others are not), so the config does not settle whether the write reach is "
                "real -- it only fails to rule it out"
            )
        if write_scopes is not None and not write_scopes:
            ev.append(
                "no unconfined scope is granted a write tool by its resolved tool policy "
                "(profile, allow, alsoAllow and deny resolved the way OpenClaw resolves "
                "them, an agent's own policy narrowing the global one), so none is shown "
                "to carry a write out of the workspace"
            )
            return _finding(
                "B55",
                WARN,
                f"Filesystem-write capability ({label}) is reachable by untrusted senders "
                f"and not confined to the workspace, but every unconfined scope narrows its "
                f"own tool policy, so broad write reach is not established.",
                "Confirm the per-agent tools.* policy really removes write/edit/"
                "apply_patch for those agents, and lock the open channel(s) to "
                "'allowlist'.",
                evidence=ev,
            )
        if write_scopes:
            # B-670: name WHICH scopes escaped, positionally (never the raw agent id —
            # see _escaping_scope_label). Evidence-only; the FAIL verdict above is
            # unchanged whether or not this appends.
            total_scopes = len(_toolpolicy.confined_scopes(cfg) or [])
            labels = [_escaping_scope_label(cfg, name) for name in write_scopes]
            ev.append(
                f"{len(write_scopes)} of {total_scopes} declared scope(s) are unconfined "
                f"and granted a write tool: {', '.join(labels)}"
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

    _bottom_ev = [
        f"write tool granted: {label}",
        "no approval gate (tools.exec.mode is not deny/allowlist/ask/auto)",
    ]
    if scope_grants is not None:
        _bottom_ev += _b737_provenance_sentences(scope_grants)
    return _finding(
        "B55",
        WARN,
        f"Filesystem-write tool granted ({label}) without an approval gate, and no "
        f"open-ingress channel was found to prove broader reach either way.",
        "Scope it: set tools.exec.mode='ask' (or 'deny'/'allowlist') so write-capable "
        "tools require approval.",
        evidence=_bottom_ev,
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
            config_field_paths={"agents.defaults.elevatedDefault"},
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
    """B71 — node command deny-list entries that are silently ineffective.

    Grounded (docs.openclaw.ai/gateway/nodes): deny matching is exact command-name
    only (e.g. 'system.run'); entries containing spaces, shell metacharacters, globs, or
    path separators are silently ineffective.

    Reads BOTH spellings via ``_node_commands`` (B-698) — ``gateway.nodes.commands.deny``
    on OpenClaw 2026.8.1+, ``gateway.nodes.denyCommands`` before it — and every
    user-facing string names the one actually found, so a reader is never pointed at a
    key their own config does not contain.

    UNKNOWN — deny list absent or empty; no deny list configured.
    WARN    — deny list non-empty and at least one entry looks non-exact.
    PASS    — all entries are bare exact command names.
    """
    cfg = ctx.config
    # B-698: both spellings — OpenClaw 2026.8.1 moved this under `gateway.nodes.commands`
    # and its migration is deferred, so an un-migrated config still carries the old key.
    deny, deny_path = _node_commands(cfg, "deny")
    if not deny or not isinstance(deny, list):
        return _finding(
            "B71",
            UNKNOWN,
            "gateway.nodes.commands.deny (pre-2026.8.1: gateway.nodes.denyCommands) is "
            "absent or empty — no node command deny list is configured.",
            "If you want to block specific node commands, set the node command deny list "
            "to bare exact command names (e.g. 'system.run') — gateway.nodes.commands.deny "
            "on OpenClaw 2026.8.1 and later, gateway.nodes.denyCommands before it.",
        )
    offenders = [str(e) for e in deny if isinstance(e, str) and _B71_INEFFECTIVE_RE.search(e)]
    if offenders:
        return _finding(
            "B71",
            WARN,
            f"{deny_path} contains entries with spaces, shell metacharacters, "
            "globs, or path separators — these patterns are silently ineffective because "
            "matching is exact command-name only.",
            f"Replace ineffective {deny_path} entries with bare exact command names only "
            "(e.g. 'system.run', not 'system.run --flag' or 'system*').",
            evidence=[f"ineffective {deny_path} entry: {e!r}" for e in offenders],
        )
    return _finding(
        "B71",
        PASS,
        f"All {deny_path} entries are bare exact command names.",
        f"Keep {deny_path} entries as bare exact command names without "
        "spaces, globs, or path separators.",
    )


def check_node_allowskills_default_on(ctx: Context) -> Finding:
    """B386 — gateway.nodes.allowSkills default-on paired-node skill push.

    Grounded against the installed 2026.9.5 dist (F-199): the vendor's own field
    description (schema-*.mjs) reads "Accept skills published by paired nodes while
    they are connected (default: true). Set false to ignore node-published skills." — a
    PAIRED node can publish executable skills into this setup while connected, and the
    gate defaults OPEN. `node-registry-*.mjs`'s own runtime confirms the effective-state
    rule this check applies: ``node.nodeSkills = cfg?.gateway?.nodes?.allowSkills ===
    false ? [] : policy.skills`` — only a literal ``false`` closes the gate; an absent
    key behaves exactly like an explicit ``true``.

    Reads BOTH spellings via ``_node_allow_skills`` (F-199) — ``gateway.nodes
    .allowSkills`` on OpenClaw 2026.8.1+, ``gateway.nodes.skills.enabled`` before it —
    the same dual-shape pattern B71 already applies to the sibling ``commands`` setting
    (B-698), and every user-facing string names the spelling actually found.

    WARN — the effective value is anything other than the literal ``False``: absent
           (vendor default true), explicit ``true``, or any other non-``False`` value.
           Same effective-state doctrine B196 applies to ``browser.evaluateEnabled`` —
           an absent key and an explicit ``true`` are the same runtime exposure, so a
           no-op deletion of the line cannot move the verdict two grades.
    PASS — explicitly ``False`` in either shape (the only state that closes the gate).
    UNKNOWN — openclaw.json not found, or present but unparseable.
    """
    if not ctx.config_found:
        return _finding(
            "B386",
            UNKNOWN,
            "No openclaw.json found -- gateway.nodes.allowSkills cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B386", ctx)
    if unreadable is not None:
        return unreadable

    value, path = _node_allow_skills(ctx.config)

    if value is False:
        return _finding(
            "B386",
            PASS,
            f"{path}=false -- paired gateway nodes may not publish skills into this "
            "setup.",
            f"Keep {path}=false unless a specific paired-node workflow needs it.",
        )

    if value is None:
        # Nothing found in either shape -- there is no single path to point the fix
        # at, so (like B71's own UNKNOWN-branch fix text) it names both spellings.
        spelling = ("gateway.nodes.allowSkills is not set (pre-2026.8.1: "
                    "gateway.nodes.skills.enabled)")
        fix = ("Set gateway.nodes.allowSkills=false unless this setup genuinely relies "
               "on a paired node publishing skills; on OpenClaw builds before 2026.8.1 "
               "the equivalent key is gateway.nodes.skills.enabled=false.")
    else:
        # A value WAS found in one shape -- point only at the spelling this config
        # actually contains, same precedent as B71's WARN/PASS branches (deny_path).
        spelling = (f"{path}=true" if value is True
                    else f"{path} is set to a value that is not the boolean false")
        fix = (f"Set {path}=false unless this setup genuinely relies on a paired node "
               "publishing skills.")

    return _finding(
        "B386",
        WARN,
        f"{spelling} -- OpenClaw's own default for this key is true, so a paired "
        "gateway node may publish skills into this setup the moment it is connected, "
        "with no operator opt-in. A pushed skill is executable surface reaching the "
        "same content-security scanning this tool applies to every installed skill's "
        "content -- pairing a node is not the same act as approving what it publishes.",
        fix,
        evidence=[spelling],
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

    def _flag(d: Path, label: str, suffix: str = "", *, after: str = "") -> None:
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
        # B-757: build the display prefix from the RESOLVED path so the username-
        # collapsing (_username_safe_path) always sees the canonical form, regardless
        # of whether the caller's own path variable was already resolved (bin_dir/cur
        # are; the raw PATH-dir / attested-install entries below are not until here).
        prefix = f"{label} {_shared._username_safe_path(rd)}{after}"
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
            _flag(cur, label, " — a group member could replace the openclaw install")
            if cur.parent == cur:  # filesystem root
                break
            cur = cur.parent

    if exe:
        bin_dir = Path(exe).resolve().parent
        _flag(bin_dir, "openclaw binary dir")
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
                    "PATH dir",
                    " — a fake openclaw could be planted there",
                    after=" (before openclaw dir)",
                )

    # Discovery-assisted: the agent may point at an install dir that `which` can't
    # resolve (non-PATH install). The engine still stat()s it itself.
    if attested_install:
        inst = Path(attested_install).expanduser()
        _flag(inst, "openclaw install dir", after=" [attested]")
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

    where = (_shared._username_safe_path(exe) if exe
             else f"{_shared._username_safe_path(attested_install)} (attested)")
    return _custom(
        "C5",
        BY_ID["C5"].severity,
        PASS,
        f"openclaw at {where}; binary dir, install-tree ancestors, and earlier PATH "
        "dirs all have tight permissions.",
        "Keep install/PATH directories owner-only (chmod 755 at most, never group/world-writable).",
    )


# B351: mirrors OpenClaw's own `normalizeCodeModeRawConfig`
# (code-mode-D5mNEiYV.js:36-41) rather than approximating it. The boolean shorthand is
# REAL - `codeMode: true` is a legal config with no `.enabled` key at all - and anything
# that is neither a boolean nor a record resolves to "absent", which the caller's `or {}`
# then turns into disabled. Reimplementing this by hand is how a lying-PASS gets written:
# reading `.enabled` off `True` returns nothing and reports the feature off.
def _b351_raw_code_mode(value):
    """The vendor's normalisation: bool -> {"enabled": bool}, record -> itself, else None."""
    if value is True:
        return {"enabled": True}
    if value is False:
        return {"enabled": False}
    return value if isinstance(value, dict) else None


def _b351_enabled(raw: dict) -> bool:
    """`readBoolean(raw.enabled, false)` (code-mode-D5mNEiYV.js:50-52).

    Only a real boolean counts. A truthy non-bool (`"true"`, `1`) falls back to the
    default, so it does NOT enable code mode - matching the vendor exactly instead of
    guessing, the same discipline B350 applies to gateway.terminal.enabled.
    """
    val = raw.get("enabled")
    return val if isinstance(val, bool) else False


# B351: OpenClaw's own agent-id canonicalisation, ported from `normalizeAgentId`
# (session-key-VWT_xzM9.js:95-101) and verified by EXECUTING the installed dist against
# these exact inputs rather than by reading the regex. The vendor resolves an agent by
# normalised ID, not by list position, so a check that loops raw entries reports agents
# the resolver can never reach.
_B351_VALID_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$", re.IGNORECASE)
_B351_INVALID_CHARS_RE = re.compile(r"[^a-z0-9_-]+")
_B351_DEFAULT_AGENT_ID = "main"


def _b351_normalize_agent_id(value) -> str:
    """`normalizeAgentId` — measured, not inferred.

    Executed against the real dist: ``None``/``""``/``"   "``/``"!!!"`` -> ``"main"``;
    ``"Main"`` -> ``"main"``; ``"my agent"`` -> ``"my-agent"``; ``"-x-"`` -> ``"x"``; a
    70-character id truncates to 64. A non-string id is treated as absent, matching the
    vendor's ``value ?? ""`` for null and the fact that the schema types `id` as a string
    so a number never loads.

    The consequence that matters: an entry with NO id normalises to ``"main"`` and
    therefore COLLIDES with an entry explicitly named ``main`` — it is not skipped.
    """
    trimmed = value.strip() if isinstance(value, str) else ""
    if not trimmed:
        return _B351_DEFAULT_AGENT_ID
    lowered = trimmed.lower()
    if _B351_VALID_ID_RE.match(trimmed):
        return lowered
    cleaned = _B351_INVALID_CHARS_RE.sub("-", lowered).strip("-")[:64]
    return cleaned or _B351_DEFAULT_AGENT_ID


def _b351_resolvable_agents(agents) -> list:
    """The entries the vendor's resolver can actually reach, in its own order.

    ``resolveAgentEntry`` is ``listAgentEntries(cfg).find(e => normalizeAgentId(e.id) ===
    id)`` (agent-scope-config-BxAUeF6t.js:66-69) and ``listAgentIds`` de-dups on the
    normalised id (:41-53), so for any id the FIRST matching entry wins and every later
    one is unreachable. Reporting a shadowed entry is a claim about an agent that cannot
    exist.

    B-699: takes the roster from ``collector.agent_roster`` rather than a raw
    ``agents.list``, so a 2026.8.1 ``agents.entries`` record resolves the same way. The
    de-dup key is unchanged -- the normalised id, which is the record KEY on the new shape
    and the entry's own ``id`` field on the legacy one.

    Returns ``[(normalized_id, AgentEntry), ...]``.
    """
    out = []
    seen = set()
    for agent in agents:
        aid = _b351_normalize_agent_id(agent.id)
        if aid in seen:
            continue
        seen.add(aid)
        out.append((aid, agent))
    return out


def check_code_mode_tool_surface(ctx: Context) -> Finding:
    """B351 - code mode replaces the model's tool surface with `exec` + `wait`.

    Grounded on the INSTALLED dist (openclaw@2026.7.1-2) and on its RESOLVER, not on the
    descriptions map. `tools.codeMode` is
    ``ZodOptional<ZodUnion<[ZodBoolean, ZodObject<{enabled?, runtime?, mode?, ...}>]>>``
    (plugin-sdk/config-schema.d.ts:3654), with a per-agent twin at
    ``agents.list[].tools.codeMode`` (:1583). OpenClaw's own description (:331) states
    that when enabled, "agent runs expose only `exec` and `wait` to the model and hide
    normal tools behind a QuickJS-WASI catalog bridge".

    WHY THIS IS WORTH A FINDING AT ALL. Code mode is not a hole - the guest runs in
    QuickJS-WASI and the feature fails closed when the runtime is unavailable (:332). It
    is reported because it silently changes what every OTHER tool-policy verdict MEANS: a
    `tools.allow` list, a profile, a deny entry all describe a surface the model no longer
    sees directly, while `exec` is exposed. An owner reading "tools are restricted to X"
    should know the model is actually being handed exec-and-wait over a catalog bridge.

    THE LYING-PASS THIS CLOSES, and why the check must walk agents. The resolver merges
    per-agent OVER global - ``agentRaw ? {...globalRaw, ...agentRaw} : globalRaw``
    (code-mode-D5mNEiYV.js:42-49) - so the override works in BOTH directions:

      global off + agent `codeMode: true`   -> ON for that agent   <- a global-only read
                                                                      reports PASS here
      global on  + agent `codeMode: false`  -> OFF for that agent  <- benign narrowing,
                                                                      must not fire
      global on  + agent `{timeoutMs: 100}` -> still ON (the agent object carries no
                                               `enabled`, so global's survives the spread)

    Reading only `tools.codeMode` would therefore report a clean surface while a named
    agent runs in code mode. Measured against the schema: `agents.defaults` carries no
    `tools.codeMode`, so there are exactly TWO layers and no third to miss.

    PASS    - resolved off everywhere: globally, and for every configured agent.
    WARN    - resolved on globally, or on for at least one named agent (which one is
              named in the detail).
    UNKNOWN - the config was not read, or is present and unparseable.

    Never FAILs: this is a capability disclosure about a sandboxed, fail-closed vendor
    feature, not a compromise. A FAIL tier would need its own independent C-135 pass.

    WHY THE VERDICT SAYS "QuickJS code mode" AND NOT "code mode". An independent pass
    found a SECOND, unrelated path to the same user-visible property:
    ``plugins.entries.<name>.config.appServer.codeModeOnly`` (config-fy-53tqM.js:122,
    read at :302) flows through to ``"features.code_mode_only": true`` for Codex
    app-server runs (run-attempt-CXZNKJ6y.js:2863 ->
    thread-lifecycle-DSMv62L1.js:2339,2346). That is a DIFFERENT engine - Codex native,
    not the QuickJS exec/wait bridge - so it is outside ``resolveCodeModeConfig`` and
    outside this check. Nothing in ``checks/`` reads it today. The honest response is to
    narrow the CLAIM rather than widen the check on ungrounded ground: an unqualified
    "code mode is off" is what a reader would believe, and it would be wrong for that
    config. Widening is a separate change with its own C-135 pass.

    AGENT IDENTITY IS THE VENDOR'S, NOT LIST POSITION. See
    ``_b351_resolvable_agents``: OpenClaw resolves an agent by NORMALISED id and takes
    the first entry that matches, so two entries whose ids normalise the same (``"Main"``
    and ``"main"``; an entry with no id, which normalises to ``"main"`` and collides with
    one) are ONE agent, and the later entry is unreachable. Looping raw list entries
    reported an agent the resolver can never produce - a false WARN, found by an
    independent adversarial pass and fixed here.
    """
    unreadable = _config_unreadable("B351", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B351",
            UNKNOWN,
            "No config was read, so whether code mode replaces the model's tool surface "
            "could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )

    global_raw = _b351_raw_code_mode(dig(cfg, "tools.codeMode")) or {}
    global_on = _b351_enabled(global_raw)

    on_agents: list[str] = []
    off_agents: list[str] = []
    for aid, agent in _b351_resolvable_agents(agent_roster(cfg)):
        agent_raw = _b351_raw_code_mode(dig(agent.entry, "tools.codeMode"))
        merged = {**global_raw, **agent_raw} if agent_raw is not None else global_raw
        label = agent.labelled(aid)
        (on_agents if _b351_enabled(merged) else off_agents).append(label)

    if not global_on and not on_agents:
        return _finding(
            "B351",
            PASS,
            "QuickJS code mode is off, so the model sees the ordinary tool surface "
            "rather than exec/wait over a catalog bridge.",
            "Keep it off unless you specifically want the exec/wait surface; it is off "
            "by default.",
        )

    if global_on:
        who = "for every agent" if not off_agents else (
            f"globally, and narrowed off for {', '.join(sorted(off_agents)[:4])}"
        )
        where = f"tools.codeMode is on {who}"
    else:
        where = (
            "tools.codeMode is off globally but ON for "
            f"{', '.join(sorted(on_agents)[:4])}"
        )
    return _finding(
        "B351",
        WARN,
        f"{where}. Those agent runs expose only `exec` and `wait` to the model and hide "
        "the normal tools behind a QuickJS-WASI catalog bridge, so any tools.allow / "
        "tools.profile / tools.deny policy describes a surface the model does not see "
        "directly.",
        "If code mode is intentional, read the tool-policy findings in this report as "
        "describing the CATALOG rather than what the model is handed, and confirm the "
        "exec surface is governed by tools.exec.*. If it is not intentional, set "
        "tools.codeMode.enabled to false (and check each per-agent entry under "
        f"{_key_advice(ctx, 'agents.list', 'agents.entries')}, which can "
        "turn it back on independently of the global setting).",
        evidence=sorted(on_agents)[:8] or None,
    )


# B352: PATH entries that OpenClaw puts ahead of everything the agent runs.
_B352_TMPISH = ("/tmp/", "/var/tmp/", "/dev/shm/")
# The vendor's own tilde predicate, verbatim: io-By0s-a_s.js PATH_VALUE_RE.
_B352_TILDE_RE = re.compile(r"^~(?=$|[\\\\/])")


def _b352_effective_prepends(cfg: dict) -> list:
    """Every (scope, host, entries) the runtime could actually apply.

    Grounded on `agent-tools-BD8WL7ny.js`, which resolves BOTH fields with `??` rather
    than a merge:

        host:         agentExec?.host        ?? globalExec?.host
        pathPrepend:  agentExec?.pathPrepend ?? globalExec?.pathPrepend

    So an agent carrying its own list REPLACES the global one wholesale, and an agent
    without one inherits it. The set of lists that can reach a shell is therefore the
    global list plus each agent's own - reading `tools.exec.pathPrepend` alone would miss
    a list only one agent has, the same per-agent shape B351 closed for code mode.
    """
    g = dig(cfg, "tools.exec") if isinstance(cfg, dict) else None
    g = g if isinstance(g, dict) else {}
    out = [("tools.exec", g.get("host"), g.get("pathPrepend"))]
    for aid, agent in _b351_resolvable_agents(agent_roster(cfg)):
        a = dig(agent.entry, "tools.exec")
        a = a if isinstance(a, dict) else {}
        entries = a.get("pathPrepend") if a.get("pathPrepend") is not None else g.get("pathPrepend")
        out.append((f"{agent.labelled(aid)}.tools.exec",
                    a.get("host") or g.get("host"), entries))
    return out


def _b352_risky(entry: str, home) -> "str | None":
    """Why this entry is a hijack surface, or None.

    Tilde entries are NOT relative: `normalize-paths` lists `pathPrepend` in
    `PATH_LIST_KEYS` and runs `resolveUserPath` over it (`io-By0s-a_s.js`), so `~/bin`
    reaches the runtime already absolute.
    """
    if not isinstance(entry, str) or not entry.strip():
        return None
    text = entry.strip()
    # Mirror the vendor's own predicate exactly: PATH_VALUE_RE is /^~(?=$|[\\/])/, so a
    # BARE `~` resolves to home just as `~/x` does, while `~user/x` does not resolve at
    # all (no slash directly after the tilde). Handling only the `~/` form reported a
    # bare `~` as relative — measured, and the test caught it.
    if _B352_TILDE_RE.match(text):
        rest = text[2:] if len(text) > 1 else ""
        text = str(Path(home).parent / rest) if rest else str(Path(home).parent)
    if not text.startswith("/"):
        return "relative, so which binary runs depends on the working directory"
    if any(text.rstrip("/").startswith(t.rstrip("/")) for t in _B352_TMPISH):
        return "under a world-writable temp directory"
    writable = _dir_replaceable_by_others(Path(text))
    if writable:
        return writable
    return None


def check_exec_path_prepend(ctx: Context) -> Finding:
    """B352 - directories OpenClaw puts AHEAD of the agent's PATH for every exec run.

    Grounded on the installed dist (openclaw@2026.7.1-2), on the code that applies it
    rather than on the descriptions map. `wrapPosixCommandWithPathPrepend`
    (bash-tools.exec-runtime-u4DiNcL4.js) rewrites the command itself:

        export PATH="${OPENCLAW_PREPEND_PATH}${PATH:+:$PATH}"; unset ...; <command>

    with the vendor's own reason: "This ensures our paths take precedence even if user RC
    files (e.g. ~/.zshenv) prepend their own entries to PATH during shell startup." So an
    entry here outranks the operator's own shell configuration by design. A directory on
    that list that someone else can write is a standing binary-hijack primitive: plant
    `git`, `curl` or `python` there and the agent runs it in preference to the real one,
    with no approval prompt, because nothing about the command changed.

    PASS    - nothing prepended, or every entry is an absolute path that only the owner
              can write. The entries are still listed in the detail, because "what is
              ahead of the agent's PATH" is worth knowing even when it is safe.
    WARN    - an entry is relative (its meaning depends on the working directory), lives
              under a world-writable temp directory, or is group/world-writable.
    UNKNOWN - the config was not read.

    TWO MITIGATIONS THAT ARE REAL, AND ARE RESPECTED RATHER THAN IGNORED.

    `host: "node"` - the runtime does not apply the list at all, and says so:
    "Warning: tools.exec.pathPrepend is ignored for host=node. Configure PATH on the node
    host/service instead." (bash-tools-DHyGpWCr.js). Reporting a hijack risk from a
    setting the engine discards would be a finding about nothing, so that scope is
    skipped and the skip is named in the detail.

    Windows - `wrapPosixCommandWithPathPrepend` returns the command unchanged on win32,
    so a prepend entry never actually reaches the shell there. This function itself has
    no `_is_posix()` branch or win32-specific wording, though: this is a self-audit, so
    the auditing platform IS the target platform, and the writability legs it calls
    (`_dir_replaceable_by_others`/group-membership resolution) already degrade to "could
    not determine" rather than a false PASS/WARN on a platform where st_mode isn't
    meaningful — see those helpers' own docstrings, not this one, for the actual guard.

    TILDE ENTRIES ARE NOT RELATIVE. `normalize-paths` puts `pathPrepend` in
    `PATH_LIST_KEYS` and resolves `~` through `resolveUserPath` (io-By0s-a_s.js), so
    `~/bin` arrives absolute. Treating it as relative would be a false positive on the
    commonest way an owner writes their own bin directory.

    Never FAILs: a writable PATH entry is a real hijack surface, but "someone else can
    write it" is a property of the filesystem at audit time, and a FAIL tier needs its
    own independent C-135 pass against real configs first.
    """
    unreadable = _config_unreadable("B352", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B352",
            UNKNOWN,
            "No config was read, so what is prepended to the agent's exec PATH could not "
            "be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )

    risky: list[str] = []
    listed: list[str] = []
    ignored_scopes: list[str] = []
    for scope, host, entries in _b352_effective_prepends(cfg):
        if not isinstance(entries, list) or not entries:
            continue
        if host == "node":
            ignored_scopes.append(scope)
            continue
        for entry in entries:
            if not isinstance(entry, str):
                continue
            listed.append(f"{scope}: {entry}")
            why = _b352_risky(entry, ctx.home)
            if why:
                risky.append(f"{scope}: {entry} — {why}")

    if not listed and not ignored_scopes:
        return _finding(
            "B352",
            PASS,
            "Nothing is prepended to the exec PATH, so the agent resolves binaries the "
            "way the host normally would.",
            "Keep it that way; an entry here outranks even your own shell startup files.",
        )

    tail = ""
    if ignored_scopes:
        tail = (
            f" Not assessed for {', '.join(sorted(ignored_scopes)[:3])}: exec runs "
            "through host=node there, and the runtime ignores pathPrepend for that host."
        )

    if not risky:
        # `listed` can be empty while `ignored_scopes` is not: every configured list sits
        # under host=node, which the runtime discards. Saying "prepends are absolute and
        # owner-only" there would be a sentence about an empty list.
        head = (
            f"Exec PATH prepends are absolute and owner-only: {'; '.join(sorted(listed)[:4])}."
            if listed else
            "No exec PATH prepend is applied on any scope this run could assess."
        )
        return _finding(
            "B352",
            PASS,
            head + tail,
            "Nothing to do. Re-check if any of those directories later becomes writable "
            "by another account.",
            evidence=sorted(listed)[:8] or None,
        )
    return _finding(
        "B352",
        WARN,
        f"{len(risky)} exec PATH prepend entr{'y is' if len(risky) == 1 else 'ies are'} a "
        f"binary-hijack surface: {'; '.join(sorted(risky)[:3])}. OpenClaw exports these "
        "ahead of $PATH for every exec run — deliberately outranking your own shell "
        "startup files — so a binary planted there runs instead of the real one, with no "
        "approval prompt because the command text is unchanged." + tail,
        "Make each entry an absolute path to a directory only your account can write, or "
        "remove tools.exec.pathPrepend and let the host resolve binaries normally. Check "
        "every per-agent entry under "
        f"{_key_advice(ctx, 'agents.list', 'agents.entries')} too: an agent's own entry "
        "replaces the global one.",
        evidence=sorted(risky)[:8] or None,
    )


def _b378_normalize_path_for_compare(raw: str, home: Path) -> str:
    """Light textual normalization for comparing two DECLARED path strings.

    NOT a port of ``resolveUserPath`` — it only expands a leading ``~`` against *home*
    and runs :func:`os.path.normpath`. Good enough to prove two config strings denote
    the same directory (the one thing ``check_agent_cwd_relocation`` uses it for); never
    used to derive a path that was not itself explicitly written into the config — see
    that check's own docstring for why the implicit workspace default is deliberately
    not reconstructed.
    """
    s = raw.strip()
    if s == "~" or s.startswith("~/") or s.startswith("~\\"):
        s = str(home) + s[1:]
    return os.path.normpath(s)


def check_agent_cwd_relocation(ctx: Context) -> Finding:
    """B378: ``agents.defaults.cwd`` / ``agents.entries.<id>.cwd``
    relocate an agent's task/exec working directory away from its workspace.

    New surface in OpenClaw 2026.9.1. Grounded directly against the installed
    2026.9.4 dist, not the descriptions map: the zod schema (``zod-schema-*.mjs``)
    carries ``cwd: string().optional()`` as a plain sibling of ``workspace`` on BOTH
    ``AgentDefaultsSchema`` and ``AgentEntryBaseSchema`` (the record-keyed
    ``agents.entries.<id>`` / legacy array ``agents.list[]`` entry shape). Resolution
    is ``resolveAgentRunCwd(cfg, agentId)`` (``agent-scope-config-*.mjs``):
    ``normalizeOptionalString(resolveAgentEntry(cfg, agentId)?.cwd) ??
    normalizeOptionalString(cfg.agents?.defaults?.cwd)`` — an agent's own ``cwd`` wins,
    the global default applies only when it is unset, and there is no containment
    check against the workspace at config-read time.

    Why it is worth a finding: ``resolveAttemptWorkspaceSandbox``
    (``workspace-sandbox-*.mjs``) throws *"cwd override is not supported for sandboxed
    embedded agent runs"* whenever ``sandbox?.enabled && requestedCwd && requestedCwd
    !== resolvedWorkspace`` — the identical guard (different wording) also covers
    compaction (``compact-*.mjs``) and subagent/visible-session runs
    (``sessions-spawn-tool-*.mjs``). So a configured ``cwd`` that differs from the
    workspace is a two-fact signal, not one: the run is necessarily UNSANDBOXED for
    that mismatch to succeed at all, AND the agent's exec/bash surface defaults to an
    arbitrary directory that neither B4 (sandbox) nor B-666/``toolpolicy.py``'s
    workspace-confinement reach model ever considers — both assume "the workspace" is
    where a run's tools actually operate.

    Deliberately narrow about what counts as a PROVEN no-op: a configured ``cwd`` is
    cleared only when it is textually equal (after ``~``-expansion) to that SAME
    scope's own EXPLICITLY declared ``workspace``. For the bare ``agents.defaults``
    scope (no roster declared at all — the single implicit agent), that workspace
    falls back to ``agents.defaults.workspace`` when none is set closer, which is
    sound: there is only one agent, and its real implicit workspace IS
    ``agents.defaults.workspace``.

    C-135 (independent, post-commit): a PER-AGENT roster entry with no ``workspace``
    of its own used to credit the same bare ``agents.defaults.workspace`` fallback —
    reasoned as "a non-default agent's real implicit workspace is
    ``join(agents.defaults.workspace, id)``, which would essentially never
    coincidentally equal a hand-written ``cwd``". Reproduced that this reasoning was
    wrong: an admin who wants a named agent to run in the shared project root
    naturally sets its ``cwd`` to the SAME string as ``agents.defaults.workspace`` —
    not a coincidence, a common intent — and that is exactly a relocation away from
    the agent's own (id-suffixed) implicit workspace. The check then falsely PASSed
    the one config shape it exists to catch. There is no reliable, non-fabricated way
    from config alone to tell "this roster entry IS the implicit default agent,
    explicitly listed" apart from "this is a genuinely different named agent", so a
    roster entry's proof target is now its OWN explicit ``workspace`` only — never the
    bare default. This check does NOT reconstruct OpenClaw's full
    ``resolveAgentWorkspaceDir`` fallback chain (the ``join(...)`` itself, or the
    unconfigured-implicit-directory case) to decide those cases either — porting that
    wrong would fabricate a comparison target rather than merely miss one, the exact
    failure mode the sibling ``agent_roster()`` / ``toolpolicy.py`` ports guard against
    with differential testing. Every other case WARNs instead: the field's own schema
    description ("Also used as the working directory when agents.defaults.cwd is
    unset") exists specifically so the two CAN differ, so a WARN default with one
    narrow, provable exemption (the bare-default-scope case above) is the reading that
    stays sound in the quiet direction, not a coin flip that risks a false PASS.

    UNKNOWN        — the config could not be read.
    not_applicable — no ``cwd`` is declared anywhere (the overwhelming majority of
                     configs today; the surface is brand new). When ``agents.list`` /
                     ``agents.entries`` is not declared at all, ``agents.defaults.cwd``
                     still applies to the single implicit agent (``resolveAgentEntry``
                     returns nothing for it, so resolution falls straight through to
                     the default) and is evaluated as that one scope.
    PASS           — every scope with a configured ``cwd`` has it textually equal to
                     that scope's own explicit ``workspace``.
    WARN           — at least one scope configures ``cwd`` with no proof it matches
                     its workspace. scored=True.

    Deliberately not double-counted: when a roster (``agents.list``/``agents.entries``)
    IS declared, ``agents.defaults.cwd`` is evaluated only through the specific roster
    entries that actually inherit it (those with no ``cwd`` of their own) — never also
    as a bare top-level scope, which would flag ``agents.defaults.cwd`` even when every
    declared agent overrides it with its own ``cwd`` and the default is genuinely dead
    config nothing resolves to.
    """
    unreadable = _config_unreadable("B378", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B378",
            UNKNOWN,
            "No config was read, so agents.*.cwd relocation could not be assessed.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )

    def _clean(v):
        return v.strip() if isinstance(v, str) and v.strip() else None

    default_cwd = _clean(dig(cfg, "agents.defaults.cwd"))
    default_workspace = _clean(dig(cfg, "agents.defaults.workspace"))
    roster = agent_roster(cfg)

    scopes: list[tuple[str, str, "str | None"]] = []
    if not roster:
        # No agents.list / agents.entries declared at all: exactly one implicit agent
        # runs, resolveAgentEntry() returns nothing for it regardless of id, and
        # resolveAgentRunCwd falls straight through to agents.defaults.cwd.
        if default_cwd is not None:
            scopes.append(("agents.defaults.cwd", default_cwd, default_workspace))
    else:
        for agent in roster:
            entry = agent.entry
            own_cwd = _clean(entry.get("cwd"))
            effective_cwd = own_cwd if own_cwd is not None else default_cwd
            if effective_cwd is None:
                continue
            own_workspace = _clean(entry.get("workspace"))
            # C-135 (independent, post-commit): this used to also credit bare
            # agents.defaults.workspace as a proof target for a roster entry with no
            # workspace of its own, reasoned as "a non-default agent's real implicit
            # workspace is join(agents.defaults.workspace, id), which would essentially
            # never coincidentally equal a hand-written cwd". Reproduced that this is
            # false: an admin who wants an agent to run in the shared project root
            # naturally sets cwd to the SAME string as agents.defaults.workspace, and
            # that is exactly a relocation away from the agent's own (id-suffixed)
            # implicit workspace -- the coarse comparison then falsely PASSed the one
            # config shape this check exists to catch. There is no reliable way from
            # config alone to tell "this roster entry IS the implicit default agent,
            # explicitly listed" apart from "this is a genuinely different named agent"
            # (this codebase's own rule elsewhere: never fabricate a comparison target),
            # so only this entry's OWN explicit workspace is a sound proof target now.
            # A roster entry declaring neither cwd nor workspace of its own now WARNs
            # instead of PASSing -- the safe direction for a WARN-only check.
            workspace_for_proof = own_workspace
            name = entry.get("name") or agent.id or agent.index
            scopes.append((f"{agent.labelled(name)}.cwd", effective_cwd, workspace_for_proof))

    if not scopes:
        return _finding(
            "B378",
            UNKNOWN,
            "No agents.defaults.cwd or per-agent cwd is configured.",
            "—",
            not_applicable=True,
        )

    relocated: list[str] = []
    for label, cwd_val, workspace_val in scopes:
        if workspace_val is not None and (
            _b378_normalize_path_for_compare(cwd_val, ctx.home)
            == _b378_normalize_path_for_compare(workspace_val, ctx.home)
        ):
            continue  # proven no-op: cwd is that same scope's own declared workspace
        note = (
            f"workspace={workspace_val!r}" if workspace_val
            else "no explicit workspace declared for this scope"
        )
        relocated.append(f"{label}={cwd_val!r} ({note})")

    if not relocated:
        return _finding(
            "B378",
            PASS,
            "Every configured agents.*.cwd matches that scope's own declared "
            "workspace — no relocation.",
            "Keep cwd in sync with workspace, or drop it if it was never meant to "
            "differ.",
            config_field_paths=frozenset(
                {"agents.defaults.cwd", "agents.defaults.workspace"}
            ),
        )

    return _finding(
        "B378",
        WARN,
        "agents.*.cwd relocates the task/exec working directory away from the "
        f"agent's own workspace for: {'; '.join(relocated)}. OpenClaw itself rejects "
        "a sandboxed run whose cwd differs from its workspace (\"cwd override is not "
        "supported for sandboxed ... runs\"), so this configuration either runs "
        "unsandboxed with an arbitrary exec/bash working directory outside the "
        "workspace, or fails at runtime.",
        "Confirm the relocation is intentional and that the agent is meant to run "
        "unsandboxed. If it should stay confined, remove cwd (or set it equal to "
        "workspace) instead of relying on the sandbox guard to catch a mismatch at "
        "runtime.",
        evidence=relocated,
        config_field_paths=frozenset(
            {"agents.defaults.cwd", "agents.defaults.workspace"}
        ),
    )
