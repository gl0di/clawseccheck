"""Does the agent's file-READ tool reach outside its workspace?

A faithful, stdlib-only port of one OpenClaw runtime predicate —
``resolveEffectiveToolFsRootExpansionAllowed`` (dist ``tool-fs-policy-*.js`` — declared
there, not in ``local-roots-*.js``, which only imports it; a hash-pinned
``local-roots-CAoJyC6u.js`` cited here before both rotated AND named the wrong file) —
which answers exactly one question: can this config's ``read`` tool open a file that is
not under the agent's workspace? That is the question A1's "sensitive data" leg needs
and could not previously ask, so it read a directory NAME instead (B-666).

Two config layers decide it, and BOTH matter — reading only one is wrong by a factor of
five on the local corpus (measured 2026-08-27: the fs layer alone says 483/581 homes are
exposed; both layers together say 98):

  1. ``tools.fs.workspaceOnly`` — confinement. The runtime normalizes it with a strict
     ``=== true``, so the EFFECTIVE default when the field is absent is **false** — file
     tools are NOT confined unless the user writes ``true``. Do not be misled by
     ``options.workspaceOnly !== false`` elsewhere: that reads an already-normalized strict
     boolean and never sees ``undefined``. OpenClaw's own audit agrees
     (``fsWorkspaceOnly === true ? ... : "false"``), as does its schema description
     ("default: false").

     Grounded on **openclaw@2026.8.2** (2026-09-02), ``resolveEffectiveToolFsWorkspaceOnly``:
     ``resolveToolFsConfig(params).workspaceOnly === true``, where ``resolveToolFsConfig``
     is the per-agent-then-global ``??`` chain. Cite those two SYMBOLS, not a file: bundle
     names are content-hashed and 94% of them rotate per release.

     This paragraph used to cite ``createToolFsPolicy``
     (``{ workspaceOnly: params.workspaceOnly === true }``), which **no longer exists** —
     2026.8.x inlined that normalization into the read site. Recorded because it is the
     instructive case: the CLAIM survived the rename unchanged and only the citation died,
     and from a dead citation alone a reader cannot tell that apart from the behaviour
     having changed. Re-verify by executing the resolver, not by grepping the old name.
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

CHANNELS ARE NOT A SCOPE HERE, AND THAT IS NOT A DISPROOF (executed against the installed
openclaw@2026.9.4, 2026-09-16). A raised schema-walk depth cap recovered six paths this
module has no scope for: ``channels.<provider>.accounts.<id>.guilds.<id>.channels.<id>.
tools.{allow,alsoAllow,deny}`` and the matching ``toolsBySender.<id>.*``. The question —
does a per-channel/per-group ``tools``/``toolsBySender`` block reach the runtime's real
tool-gating decision for a message — was answered BY EXECUTION, not inferred from the
schema. It does. Traced by symbol through the installed dist:
``resolveRequesterToolPolicies`` (``agent-tools.policy-*.mjs``) resolves ``groupPolicy``
via ``resolveGroupToolPolicy`` — which tries a channel PLUGIN's own
``plugin.groups.resolveToolPolicy`` hook first (Discord's ``guilds.<id>.channels.<id>``
nesting is exactly this kind of plugin-specific shape; that hook was not located and
examined — it lives in a per-provider plugin bundle, not the core dist files this module
already cites) and falls back to the generic ``resolveChannelGroupToolsPolicy``
(``channels.<channel>.groups.<id>.tools``/``.toolsBySender``, ``group-policy-*.mjs``) —
and the resolved ``groupPolicy``, alongside a separately-resolved ``senderPolicy``
(``resolveSenderToolPolicy``, ``sender-tool-policy-*.mjs`` — note: THIS one only ever reads
agent-level/global ``tools.toolsBySender``, not the channel-nested one), is threaded into
``buildDefaultToolPolicyPipelineSteps``/``applyToolPolicyPipeline``
(``tool-policy-pipeline-*.mjs``) as two MORE sequential AND-ed filter steps layered on top
of every policy ``resolveConfiguredToolPolicies`` already models — confirmed by reading
``ra=[profilePolicy,providerProfilePolicy,globalPolicy,globalProviderPolicy,agentPolicy,
agentProviderPolicy,groupPolicy,senderPolicy,...]`` feeding that pipeline in the live
message-handling call site.

So this is NOT the "add channel key names to a list" fix first suspected and rejected (see
the task) — it is also not simply "extend the scope enumeration" the task's own DoD
offered as the likely shape, because a channel is not an independent scope PARALLEL to an
agent the way ``agents.list`` entries are: it is a NARROWING FILTER that applies only to
messages a given agent receives THROUGH that specific channel/account/guild/sender
combination. ``confined_scopes``/``_sandbox_confines`` answer a per-AGENT confinement
question that has no channel-shaped analogue (a channel is not separately sandboxed), and
attributing a channel's narrowing to the right agent scope — rather than crediting an
agent with a channel it never actually receives traffic through — needs an agent-channel
ROUTING model this tool does not have and the schema recon does not establish. A `scopes`
list that just appended one entry per declared channel would silently answer a DIFFERENT,
unsound question ("does ANY channel anywhere narrow write") instead of the one this module
actually needs ("does THIS agent's effective policy get narrowed").

Left undone, deliberately, rather than shipped as a partial fix that reads as complete:
porting the plugin-hook shape (Discord's ``guilds``/``channels`` nesting specifically)
without first finding and reading its own resolver would be exactly the kind of
schema-inferred, unexecuted guess this task's own instructions forbid. This needs its own
scoped follow-up: (a) locate and read the channel-plugin ``groups.resolveToolPolicy`` hook
for at least Discord (the provider C-484's recovered paths named) to ground the
guild/channel-nesting shape rather than inferring it from ``resolveChannelGroupToolsPolicy``
alone; (b) design an agent-channel attribution model sound enough that a channel's
narrowing is only ever credited to a scope it can actually gate; (c) differential-validate
against the dist the way B-666/B-670 were. ``_OPAQUE_NARROWING_KEYS`` is unchanged — the
gap is the scope enumeration lacking a channel dimension at all, not a key this module
already visits and mishandles, exactly as the task's own developer comment concluded.

THE WRITE QUESTION (F-186) is not answered by the read stack above -- its profile and alias
tables are read-specific. ``unconfined_write_scopes`` composes ``confined_scopes`` with
``toolgrant.granted`` (a sibling leaf, itself validated against the vendor for any tool), so
this module imports exactly one other package module besides ``collector``.
Validated by ``tests/test_f186_write_reach.py`` against a vendor-executed battery.

Verified against the vendor: this module's answer was compared with a real
``resolveEffectiveToolFsRootExpansionAllowed`` call over all 581 local corpus configs
plus a hand-built edge table — see ``tests/test_b666_read_reach.py``.
"""

from __future__ import annotations

import re

from .collector import agent_roster, dig
from .toolgrant import GLOBAL_SCOPE, granted

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
    """One resolved scope's answer, for the file-READ tool.

    Mirrors ``resolveEffectiveToolFsRootExpansionAllowed``: confinement first (the agent's
    own ``tools.fs.workspaceOnly`` if it set one, otherwise the global field), then the
    profile — taken from the AGENT when it names one, else the global — stacked with both
    the global and the agent allow/deny policies.

    READ-ONLY BY CONSTRUCTION, and it must stay that way. B-670 briefly parametrised this by
    tool name so the same stack could answer the WRITE question. It cannot: two of the three
    layers below are read-specific. ``_PROFILES_GRANTING_READ`` answers only "does this
    profile grant read", so every profile returned the read verdict whatever tool was asked
    about; and ``_TOOL_NAME_ALIASES`` carries the aliases that matter for read, so
    ``tools.allow: ["fs_write"]`` -- which a real fixture uses -- resolved to "write not
    granted" and turned a designed-bad config into a WARN. ``confined_scopes`` documents this
    exact trap one tool over (``fs_read``); the write family needs its own vetted model, not
    a parameter here. The write answer is ``unconfined_write_scopes`` below, which composes
    the vendor-validated ``toolgrant.granted`` with ``confined_scopes`` instead.
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
_SANDBOX_OFF = "off"

# B-712: appended to a scope label whose confinement the config does not decide, so the
# uncertainty reaches the reader instead of being flattened into a bare assertion.
_UNDECIDED_SUFFIX = " (sandbox 'non-main' — confinement depends on which session runs)"


def any_confinement_undecided(labels) -> bool:
    """Does this scope list contain a scope whose confinement the config does not decide?

    B-712. A caller that renders `scopes_reaching_outside_workspace` into prose has to know
    this: "these scopes are not confined" is a different sentence from "these scopes are not
    PROVEN confined", and only the second one is true when a `non-main` scope is in the list.
    Exposed as a predicate rather than leaving callers to substring-match the suffix, so the
    marker stays this module's business.
    """
    return any(_UNDECIDED_SUFFIX in str(x) for x in (labels or ()))


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


def _sandbox_confines(cfg: dict, agent_id: str, entry) -> "bool | None":
    """Does the sandbox confine this scope? ``True`` / ``False`` / ``None`` for undecidable.

    B-712. This used to return a confident boolean for a property the config does not
    determine. The vendor's own predicate is four lines and says exactly where the boundary
    falls (``runtime-status-*.js``)::

        function shouldSandboxSession(cfg, sessionKey, mainSessionKey, sandboxRequired) {
            if (sandboxRequired) return true;
            if (cfg.mode === "off")  return false;
            if (cfg.mode === "all")  return true;
            return sessionKey.trim() !== mainSessionKey.trim();
        }

    ``all`` and ``off`` are decidable from config alone. ``non-main`` falls through to a
    comparison against the RUNNING session's key, which has no representation in
    ``openclaw.json`` — so the honest answer is that there is none.

    Two corrections to what this function used to assert, both measured by executing
    ``resolveSandboxRuntimeStatus`` for both session positions of each agent across 45
    generated configs (``tests/data/sandbox_battery.json``):

    * ``non-main`` is undecidable for EVERY agent, not only the non-default ones. The old
      ``agent_id != _default_agent_id(cfg)`` came from reading "non-main" as "not the main
      AGENT", but ``resolveMainSessionKeyForSandbox`` resolves per agent — so every agent has
      its own main session that runs unsandboxed, and its other sessions that do not.
    * An absent ``mode`` resolves to ``off``, not to "unknown". The vendor's effective mode
      for an absent key is ``off``, so ``False`` there is a real answer, not a guess.

    A value we do not recognise also yields ``None``. The schema restricts ``mode`` to the
    three literals (probed: ``"bogus"`` is rejected as ``invalid_union`` at both the defaults
    and the per-entry placement), so this is unreachable from a loadable config — it is the
    Golden-Rule-#4 default rather than a live branch.

    NOT modelled, and it matters for how a caller words itself: ``sandboxRequired`` is checked
    FIRST and returns true unconditionally. It is a runtime flag with no config expression, so
    even a ``False`` here means "not confined BY CONFIG", never "provably unconfined".
    """
    mode = _sandbox_mode(cfg, entry)
    if mode == _SANDBOX_ALL:
        return True
    if mode in ("", _SANDBOX_OFF):
        return False
    return None


# Layers this module does not resolve and that CAN restrict. Their presence is treated as
# possible narrowing, which is the quiet direction: it can cost a finding, never invent one.
_OPAQUE_NARROWING_KEYS = ("byProvider", "toolsBySender")


def _scope_rows(cfg: dict) -> list:
    """The scopes every per-scope answer here ranges over, in ONE order.

    ``(normalized name, entry, grant id)`` for the default agent first, then every other
    declared agent. The grant id is what ``toolgrant.granted`` must be asked with: the RAW
    roster id for a declared agent (its own normaliser is two-branch and differs from this
    module's -- ``a-`` stays ``a-`` there and becomes ``a`` here, so re-normalising our name
    would miss the entry), ``GLOBAL_SCOPE`` for the synthesised default agent that has no
    roster row. ``confined_scopes`` walks the same rows, so index N of its answer is scope N
    of this list.
    """
    main = _default_agent_id(cfg)
    rows = [(_normalize_agent_id(agent.id), agent.entry,
             agent.id if isinstance(agent.id, str) else "")
            for agent in agent_roster(cfg)]
    by_name = {name: (entry, raw) for name, entry, raw in rows}
    entry, raw = by_name.get(main, ({}, GLOBAL_SCOPE))
    return [(main, entry, raw)] + [row for row in rows if row[0] != main]


def _has_opaque_narrowing(entry) -> bool:
    tools = entry.get("tools") if isinstance(entry, dict) else None
    return isinstance(tools, dict) and any(k in tools for k in _OPAQUE_NARROWING_KEYS)


def _write_scopes(cfg: dict, tools, undecided_only: bool):
    if not isinstance(cfg, dict) or not cfg:
        return None
    confined = confined_scopes(cfg)
    if confined is None:
        return None
    out = []
    for is_confined, (name, entry, grant_id) in zip(confined, _scope_rows(cfg)):
        # `is True`, not truthiness: `confined_scopes` yields None for a scope the config does
        # not decide (sandbox.mode "non-main"). Such a scope is KEPT -- declining to prove
        # confinement is not proving exposure, but subtracting it would fabricate the
        # containment B-712 removed. `undecided_write_scopes` says which ones they were, so a
        # caller driving a FAIL can hedge instead of asserting what was not resolved.
        if is_confined is True:
            continue
        if undecided_only and is_confined is not None:
            continue
        if _has_opaque_narrowing(entry):
            continue
        if grant_id == GLOBAL_SCOPE and _has_opaque_narrowing(
                {"tools": dig(cfg, "agents.defaults.tools")}):
            # No roster: `agents.defaults.tools` IS this scope's own tools (toolgrant reads it
            # the same way), so its byProvider/toolsBySender are that scope's unresolved layers.
            continue
        if not any(granted(cfg, tool, grant_id) for tool in tools):
            continue
        out.append(name)
    return out


def unconfined_write_scopes(cfg: dict, tools):
    """Scopes that are NOT workspace-confined AND are granted at least one of ``tools``.

    ``None`` with no config. F-186: the answer to "which agent can actually write outside
    its workspace", by COMPOSING two models that were each validated against the vendor on
    their own -- ``toolgrant.granted`` (the resolved per-scope grant: profile, allow,
    alsoAllow, deny, the agent-replaces-global asymmetry) and ``confined_scopes``
    (``tools.fs.workspaceOnly`` / sandbox, per scope). It replaces a token heuristic that
    guessed whether a scope's own ``tools`` block "could remove" the write family and was
    wrong both ways: it convicted ``allow:[write]`` + ``deny:[write,...]`` (cannot write) and
    acquitted ``profile:messaging`` + ``alsoAllow:[write]`` (can).

    ``tools`` is the caller's own list of write-capable tool names, not a table kept here:
    B55 decides which names count (its legacy spellings included) and this module must not
    grow a third list of them. ``granted`` runs the vendor's matcher over whatever string it
    is given, so a legacy name needs no alias entry.

    A scope whose own tools carry ``byProvider``/``toolsBySender`` is left out: those layers
    can remove a grant and are not resolved here, and the quiet direction may cost a
    finding but never invents one. Returns scope NAMES (this module's normalised form).
    """
    return _write_scopes(cfg, tools, undecided_only=False)


def undecided_write_scopes(cfg: dict, tools):
    """Of ``unconfined_write_scopes``, those UNDECIDED rather than proven unconfined.

    B-712. A scope kept because ``sandbox.mode: "non-main"`` gives no static answer is not
    the same evidence as one kept because the sandbox is demonstrably off, and a verdict that
    cannot tell them apart words itself as though it could. ``None`` with no config.
    """
    return _write_scopes(cfg, tools, undecided_only=True)


def confinement_undecided_only(cfg: dict) -> bool:
    """True when nothing is PROVEN unconfined but something is UNDECIDED.

    B-712. The distinction a verdict has to make before it words itself: a scope with the
    sandbox demonstrably off is evidence; a scope on `sandbox.mode: "non-main"` is an absence
    of evidence. Both stop `_fs_reads_are_confined` from suppressing a leg — correctly, since
    suppression requires proof — but only the first justifies a sentence that asserts the
    exposure outright. False when any scope is proven unconfined (there is real evidence, so
    no hedge is owed) and False when everything is confined (nothing to say).
    """
    scopes = confined_scopes(cfg)
    if not scopes:
        return False
    return any(s is None for s in scopes) and not any(s is False for s in scopes)


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
    out = []
    for name, entry, _grant_id in _scope_rows(cfg):
        tools = entry.get("tools") if isinstance(entry, dict) else None
        fs_scope = tools if _has_fs_flag(tools) else cfg.get("tools")
        # B-712: three-state. `workspaceOnly: true` is proof on its own, so it wins outright;
        # otherwise the answer is the sandbox's, INCLUDING its `None`. Written out rather
        # than left as `a or b` — that expression happens to produce the same three values,
        # and a security predicate should not depend on a reader noticing that.
        if _workspace_only_of(fs_scope):
            out.append(True)
        else:
            out.append(_sandbox_confines(cfg, name, entry))
    return out


def scopes_reaching_outside_workspace(cfg: dict) -> list:
    """Every declared scope whose file-read tool can reach files outside its workspace.

    ``"global"`` for the surface the main agent runs under, plus the id of each declared
    agent that resolves the same way. A scope PROVEN sandboxed is subtracted (see above).
    Empty means no declared scope can read the OpenClaw home.

    B-712: a scope whose confinement is UNDECIDABLE from config — `sandbox.mode: "non-main"`,
    where the vendor's answer depends on which session is running — is NOT subtracted, and
    says so in its own label. Subtracting it would fabricate a containment the config does
    not establish; dropping the qualifier would assert a reach we have not established
    either. The caller renders these labels into its evidence, so the uncertainty travels
    with the finding instead of being resolved by whoever wrote the sentence.
    """
    if not isinstance(cfg, dict) or not cfg:
        return []
    out = []
    main = _default_agent_id(cfg)
    main_entry = dict(_agent_entries(cfg)).get(main)
    confined = _sandbox_confines(cfg, main, main_entry)
    if read_reaches_outside_workspace(cfg) and confined is not True:
        out.append("global" + _UNDECIDED_SUFFIX if confined is None else "global")
    for name, entry in _agent_entries(cfg):
        tools = entry.get("tools")
        confined = _sandbox_confines(cfg, name, entry)
        if read_reaches_outside_workspace(cfg, agent_tools=tools) and confined is not True:
            label = f"agent {name!r}"
            out.append(label + _UNDECIDED_SUFFIX if confined is None else label)
    return out
