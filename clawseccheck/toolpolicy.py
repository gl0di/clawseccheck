"""Does the agent's file-READ tool reach outside its workspace?

A faithful, stdlib-only port of one OpenClaw runtime predicate —
``resolveEffectiveToolFsRootExpansionAllowed`` (dist ``local-roots-CAoJyC6u.js``) — which
answers exactly one question: can this config's ``read`` tool open a file that is not
under the agent's workspace? That is the question A1's "sensitive data" leg needs and
could not previously ask, so it read a directory NAME instead (B-666).

Two config layers decide it, and BOTH matter — reading only one is wrong by a factor of
five on the local corpus (measured 2026-08-27: the fs layer alone says 483/581 homes are
exposed; both layers together say 98):

  1. ``tools.fs.workspaceOnly`` — confinement. The runtime normalizes it with
     ``createToolFsPolicy``: ``{ workspaceOnly: params.workspaceOnly === true }``, so the
     EFFECTIVE default when the field is absent is **false** — file tools are NOT confined
     unless the user writes ``true``. Do not be misled by ``options.workspaceOnly !== false``
     in ``agent-tools-*.js``: that reads an already-normalized strict boolean and never
     sees ``undefined``. OpenClaw's own audit agrees (``fsWorkspaceOnly === true ? ... : "false"``),
     as does its schema description ("default: false").
  2. the tool allow/deny policy — whether ``read`` is granted at all. An absent
     ``tools.profile`` pushes NO policy (``if (profilePolicy) policies.push(...)``), i.e.
     the permissive end again; ``minimal``/``messaging`` do not grant ``read``, ``coding``
     and ``full`` do, and ``tools.allow``/``deny``/``alsoAllow`` can override either way.

So both of this predicate's defaults sit at the permissive end, which is why an unread
layer here does not merely make the answer quieter — it inverts it (the lesson B-664's
``_execpolicy`` dimension learned the same way).

SCOPE: every scope the config declares — the global surface AND each entry of
``agents.list``, resolved the way ``resolveEffectiveToolFsRootExpansionAllowed`` resolves
one (``agentTools?.profile ?? cfg.tools?.profile``, an agent-level ``tools.fs``, and the
agent policy stacked on top of the global one). Global-only would have been quieter, not
safer: measured across the 22 local corpus configs that declare agents, five disagree with
their global answer and four of those are an AGENT that can read outside a global scope
that cannot. ``agents.defaults.tools`` is deliberately NOT a scope — ``resolveAgentConfig``
returns ``tools: entry.tools`` from the ``agents.list`` entry and never merges the defaults
block, so treating it as one would invent a confinement the runtime does not apply.

Verified against the vendor: this module's answer was compared with a real
``resolveEffectiveToolFsRootExpansionAllowed`` call over all 581 local corpus configs
plus a hand-built edge table — see ``tests/test_b666_read_reach.py``.
"""

from __future__ import annotations

import re

from .collector import agent_roster, dig

# ``TOOL_NAME_ALIASES`` (dist tool-policy-*.js). Nothing aliases TO "read", so this
# matters here only so an aliased entry in allow/deny normalizes the way the dist
# normalizes it before the glob match.
#
# DUPLICATED from ``checks/_shared.py``'s ``_TOOL_NAME_ALIASES``/``_canon_tool`` rather
# than imported, because this module is a LEAF and importing from the check layer would
# invert the dependency flow. Same arrangement, same reason, as ``skillprovenance.py``'s
# copy of WORKSPACE_DIRS — and, like that one, it is a copy WITH A GUARD:
# ``tests/test_b666_read_reach.py`` fails the build if the two tables ever disagree.
_TOOL_NAME_ALIASES = {"bash": "exec", "apply-patch": "apply_patch"}

# ``TOOL_GROUPS`` (dist tool-policy-*.js, built from CORE_TOOL_DEFINITIONS' sectionId).
# Only the one group that contains "read" is modelled: a group entry is expanded to its
# members before matching, so `allow: ["group:fs"]` grants read and `deny: ["group:fs"]`
# removes it. Other groups cannot change this predicate's answer.
_GROUP_FS = "group:fs"
_GROUP_FS_MEMBERS = ("read", "write", "edit", "apply_patch")

# ``CORE_TOOL_PROFILES`` (dist tool-catalog-*.js). Only the read-grant answer is kept
# rather than all four tool lists: the full tables are ~40 tool ids whose only use here
# would be to answer this one membership question, and every id is upgrade-rot surface.
# minimal -> ["session_status"]; messaging -> sessions/message; coding -> includes "read";
# full -> ["*"].
_PROFILES_GRANTING_READ = frozenset({"coding", "full"})
# ``ToolProfileSchema`` (dist zod-schema.agent-runtime-*.js). A value outside this set is
# not a profile the runtime recognizes: ``resolveCoreToolProfilePolicy`` returns undefined
# for it and NO policy is pushed — the permissive end, not a restriction.
_KNOWN_PROFILES = frozenset({"minimal", "coding", "messaging", "full"})


def _normalize(name) -> str:
    """``normalizeToolName``: fold to a trimmed lowercase string, then apply aliases.

    ``normalizeLowercaseStringOrEmpty`` returns "" for ANY non-string — a numeric or null
    entry in an allow list is dropped, not coerced to its digits.
    """
    text = name.strip().lower() if isinstance(name, str) else ""
    return _TOOL_NAME_ALIASES.get(text, text)


def _expand(entries) -> list:
    """``expandToolGroups``: normalize, expand a group id to its members, de-dup."""
    out: list = []
    for raw in entries or []:
        value = _normalize(raw)
        if not value:
            continue
        for item in (_GROUP_FS_MEMBERS if value == _GROUP_FS else (value,)):
            if item not in out:
                out.append(item)
    return out


def _matches(name: str, patterns) -> bool:
    """``compileGlobPatterns`` + ``matchesAnyGlobPattern`` for a single tool name.

    ``*`` is the only wildcard, and a bare ``*`` means "everything". Empty entries are
    dropped by the dist's own compile step, which ``_expand`` already did.
    """
    for pattern in patterns:
        if pattern == "*":
            return True
        if "*" not in pattern:
            if name == pattern:
                return True
            continue
        rx = ".*".join(re.escape(part) for part in pattern.split("*"))
        if re.fullmatch(rx, name):
            return True
    return False


def _allowed_by(name: str, policy) -> bool:
    """``isToolAllowedByPolicyName``: deny wins; an empty allow list means allow-all."""
    if not policy:
        return True
    if _matches(name, _expand(policy.get("deny"))):
        return False
    allow = _expand(policy.get("allow"))
    if not allow:
        return True
    return _matches(name, allow)


def _sandbox_tool_policy(tools):
    """``pickSandboxToolPolicy``: fold allow/alsoAllow/deny into one policy, or None.

    ``alsoAllow`` without ``allow`` is a WIDENING, not a restriction — the dist unions it
    onto an implicit ``"*"`` — so a config that only sets ``alsoAllow`` still allows every
    tool it did not name.
    """
    if not isinstance(tools, dict):
        return None
    allow = tools.get("allow")
    also = tools.get("alsoAllow")
    also_list = [a for a in also] if isinstance(also, list) else []
    if isinstance(allow, list):
        merged = list(allow) + also_list if also_list else list(allow)
        if also_list and not allow:
            merged = ["*"] + also_list
    elif also_list:
        merged = ["*"] + also_list
    else:
        merged = None
    deny = tools.get("deny") if isinstance(tools.get("deny"), list) else None
    if merged is None and deny is None:
        return None
    return {"allow": merged, "deny": deny}


def _profile_policy(tools, also_from=None):
    """``resolveToolProfilePolicy`` + ``mergeAlsoAllowPolicy``, reduced to allow/deny.

    *also_from* supplies ``alsoAllow`` when the profile came from a different scope than
    the one holding it — the runtime reads ``agentTools?.alsoAllow ?? globalTools?.alsoAllow``
    independently of where the profile came from.
    """
    if not isinstance(tools, dict):
        return None
    # EXACT, case-sensitive lookup — ``CORE_TOOL_PROFILES[profile]`` is a plain object
    # index with no trim and no case fold, unlike the tool-NAME normalization above. So
    # "Coding" or " coding " is not a profile the runtime knows: it resolves to no policy
    # at all, i.e. the permissive end, not to the profile the user meant.
    profile = tools.get("profile")
    name = profile if isinstance(profile, str) else ""
    if name not in _KNOWN_PROFILES:
        return None
    allow = ["*"] if name in _PROFILES_GRANTING_READ else []
    holder = also_from if isinstance(also_from, dict) and "alsoAllow" in also_from else tools
    also = holder.get("alsoAllow")
    if isinstance(also, list) and also:
        allow = list(allow) + [a for a in also]
    # An empty allow list would read as "allow everything" downstream (that is what an
    # absent allowlist means), so a profile that does NOT grant read is expressed as a
    # policy that allows something else — never as an empty one.
    return {"allow": allow or ["session_status"], "deny": None}


def _has_fs_flag(tools) -> bool:
    """Whether this scope SET ``tools.fs.workspaceOnly`` at all.

    ``resolveToolFsConfig`` is ``agent?.tools?.fs?.workspaceOnly ?? global?.fs?.workspaceOnly``
    — a nullish coalesce, so an agent that writes ``false`` overrides a global ``true``,
    while an agent that writes nothing inherits it.
    """
    fs = tools.get("fs") if isinstance(tools, dict) else None
    return isinstance(fs, dict) and fs.get("workspaceOnly") is not None


def _workspace_only_of(tools) -> bool:
    fs = tools.get("fs") if isinstance(tools, dict) else None
    return isinstance(fs, dict) and fs.get("workspaceOnly") is True


def _names_profile(tools) -> bool:
    return isinstance(tools, dict) and isinstance(tools.get("profile"), str)


def workspace_only(cfg: dict) -> bool:
    """``resolveEffectiveToolFsWorkspaceOnly`` for the global scope: ``=== true``."""
    return dig(cfg, "tools.fs.workspaceOnly") is True


_DEFAULT_AGENT_ID = "main"


def _normalize_agent_id(value) -> str:
    """``normalizeAgentId`` (dist account-selection-*.js).

    An entry with no ``id`` is not skipped — the dist folds a missing id to "main", so
    such an entry IS the main agent's config, and its tools really do apply. (The schema
    marks ``agents.list[].id`` required, so this only comes up on a config OpenClaw would
    reject; resolving it the dist's way keeps us from calling a real opt-out inert.)
    """
    text = value if isinstance(value, str) else ""
    folded = re.sub(r"[^a-z0-9_-]+", "-", text.strip().lower()).strip("-")
    return folded or _DEFAULT_AGENT_ID


def _agent_entries(cfg: dict) -> list:
    """``listAgentEntries``: ``(normalized id, entry)`` for every declared agent.

    B-699: the roster comes from ``collector.agent_roster``, which reads BOTH the 2026.8.1
    ``agents.entries`` record and the legacy ``agents.list`` array. Reading only the array
    made this module answer ``confined_scopes -> [True]`` for a roster it could not see --
    an INVERSION, not a silence, because both layers it reads default to the permissive
    end. Measured before the fix, with the global confined and one agent exposed:
    ``scopes_reaching_outside_workspace`` returned ``[]`` where the truth was
    ``["agent 'worker'"]``.
    """
    return [(_normalize_agent_id(agent.id), agent.entry) for agent in agent_roster(cfg)]


def _scope_reaches_outside(global_tools, agent_tools) -> bool:
    """One resolved scope's answer.

    Mirrors ``resolveEffectiveToolFsRootExpansionAllowed``: confinement first (the agent's
    own ``tools.fs.workspaceOnly`` if it set one, otherwise the global field), then the
    profile — taken from the AGENT when it names one, else the global — stacked with both
    the global and the agent allow/deny policies.
    """
    fs_scope = agent_tools if _has_fs_flag(agent_tools) else global_tools
    if _workspace_only_of(fs_scope):
        return False
    profile_tools = agent_tools if _names_profile(agent_tools) else global_tools
    policies = (
        _profile_policy(profile_tools, also_from=agent_tools or global_tools),
        _sandbox_tool_policy(global_tools),
        _sandbox_tool_policy(agent_tools),
    )
    return all(_allowed_by("read", policy) for policy in policies)


# KNOWN LIMIT, in the quiet direction: "outside the workspace" is the question the runtime
# asks, and it is not quite "outside the OpenClaw home". A config whose declared workspace
# CONTAINS the home (`agents.defaults.workspace: "/home/user"`, say) confines file tools to
# a root that includes openclaw.json and credentials/, so `workspaceOnly: true` protects
# nothing there and this returns False anyway. Not modelled because it is unobserved: of the
# 671 fixture homes plus the clawrange corpus, three set `workspaceOnly: true` at all and
# none of the three declares a workspace containing its home. Recorded rather than left
# implicit — the failure is a missed WARN, never a wrong one.
def read_reaches_outside_workspace(cfg: dict, agent_tools=None) -> bool:
    """True when a file-read tool is granted AND is not confined to the workspace.

    The port of ``resolveEffectiveToolFsRootExpansionAllowed``. True is the permissive
    answer and the default for a config that says nothing about tools.
    """
    if not isinstance(cfg, dict) or not cfg:
        # An unreadable/empty config is not evidence of exposure. Callers that need to
        # distinguish "said nothing" from "we never saw it" guard on the config first.
        return False
    return _scope_reaches_outside(cfg.get("tools"), agent_tools)


# ---------------------------------------------------------------- sandbox containment
# NOT part of the ported predicate — `resolveEffectiveToolFsRootExpansionAllowed` answers
# a POLICY question ("may this tool expand past the workspace root") and knows nothing
# about where the process can see. A sandboxed session is a second, independent
# confinement: `appendWorkspaceMountArgs` (dist docker-*.js) binds the workspace dirs and
# the read-only skill overlays into the container and NOTHING ELSE — the OpenClaw home is
# never mounted — so under `sandbox.mode: "all"` a granted `read` tool cannot open
# openclaw.json or the credential store however permissive the tool policy is. Saying it
# could would be a false alarm, so this layer subtracts those scopes.
#
# Grounded enum (`AgentSandboxSchema`, dist zod-schema.agent-runtime-*.js): off | non-main
# | all. Anything else is not a value OpenClaw recognizes and confines nothing.
_SANDBOX_ALL = "all"
_SANDBOX_NON_MAIN = "non-main"


def _default_agent_id(cfg: dict) -> str:
    """``resolveDefaultAgentId``: the entry marked ``default``, else the first one.

    Needed because "non-main" is defined against THIS id, not against the literal string
    "main" — a config whose only agent is `{"id": "bot"}` has `bot` as its main agent, so
    `non-main` does not sandbox it.
    """
    entries = [e for _, e in _agent_entries(cfg)]
    for entry in entries:
        if entry.get("default"):
            return _normalize_agent_id(entry.get("id"))
    if entries:
        return _normalize_agent_id(entries[0].get("id"))
    return _DEFAULT_AGENT_ID


def _sandbox_mode(cfg: dict, entry) -> str:
    scoped = entry.get("sandbox") if isinstance(entry, dict) else None
    mode = scoped.get("mode") if isinstance(scoped, dict) else None
    if mode is None:
        mode = dig(cfg, "agents.defaults.sandbox.mode")
    return mode if isinstance(mode, str) else ""


def _sandbox_confines(cfg: dict, agent_id: str, entry) -> bool:
    mode = _sandbox_mode(cfg, entry)
    if mode == _SANDBOX_ALL:
        return True
    # Under "non-main" the main agent runs unsandboxed, so only the others are confined.
    return mode == _SANDBOX_NON_MAIN and agent_id != _default_agent_id(cfg)


def confined_scopes(cfg: dict):
    """Per scope: is this scope's file READ confined? ``None`` when there is no config.

    C-462 needs a different question from ``scopes_reaching_outside_workspace``. That one
    asks whether the ``read`` tool is BOTH granted and unconfined, which is the right
    question for "is this agent exposed by default". This one asks only about the
    CONFINEMENT half, because its caller already has independent evidence that a read
    capability was DECLARED (a tool named in the config, or an attested roster) and only
    needs to know whether a guard neutralizes it. Asking the granted-question there would
    silently drop a declared tool whose name OpenClaw's policy stack does not recognize —
    ``fs_read``, for one, which two corpus fixtures grant and the runtime does not define.

    Guards are OpenClaw's own, from the predicate behind
    ``security.exposure.open_groups_with_runtime_or_fs``: ``tools.fs.workspaceOnly === true``
    (per scope, nullish-coalesced onto the global field) or a session the sandbox fully
    contains, where the OpenClaw home is not mounted at all.

    Returns one entry per declared scope — the main agent's surface plus each
    ``agents.list`` entry — so a caller can require ALL of them, which is the honest
    reading: one unconfined scope leaves the capability exposed.
    """
    if not isinstance(cfg, dict) or not cfg:
        return None
    main = _default_agent_id(cfg)
    entries = _agent_entries(cfg)
    by_id = dict(entries)
    scopes = [(main, by_id.get(main) or {})]
    scopes += [(name, entry) for name, entry in entries if name != main]
    out = []
    for name, entry in scopes:
        tools = entry.get("tools") if isinstance(entry, dict) else None
        fs_scope = tools if _has_fs_flag(tools) else cfg.get("tools")
        out.append(bool(_workspace_only_of(fs_scope)) or _sandbox_confines(cfg, name, entry))
    return out


def scopes_reaching_outside_workspace(cfg: dict) -> list:
    """Every declared scope whose file-read tool can reach files outside its workspace.

    ``"global"`` for the surface the main agent runs under, plus the id of each declared
    agent that resolves the same way. A scope whose sessions are sandboxed is subtracted
    (see above). Empty means no declared scope can read the OpenClaw home.
    """
    if not isinstance(cfg, dict) or not cfg:
        return []
    out = []
    main = _default_agent_id(cfg)
    main_entry = dict(_agent_entries(cfg)).get(main)
    if read_reaches_outside_workspace(cfg) and not _sandbox_confines(cfg, main, main_entry):
        out.append("global")
    for name, entry in _agent_entries(cfg):
        tools = entry.get("tools")
        if read_reaches_outside_workspace(cfg, agent_tools=tools) and not _sandbox_confines(
            cfg, name, entry
        ):
            out.append(f"agent {name!r}")
    return out
