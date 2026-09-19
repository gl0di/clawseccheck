"""``granted(cfg, tool, scope) -> bool`` — is TOOL granted to SCOPE by OpenClaw's own
runtime tool-policy resolver?

A full, faithful port of ``resolveConfiguredToolPolicies`` + ``isToolAllowedByPolicies``
(the ``agent-tools.policy-*`` and ``tool-policy-match-*`` dist bundles — content-hashed names
that rotate every release, so they are cited by symbol; ``tests/_toolgrantoracle.py`` locates
them by declaration; grounded on the installed **openclaw@2026.9.5**, 2026-09-19), not the
narrower FS-only model ``checks/_capability.py``'s ``_tool_policy_view`` +
``_agent_profile_widenings`` carry. That pair answers "does an fs tool leak" for four
specific checks and deliberately approximates two things this module does not:

* it SUPPRESSES the global ``tools.allow``/``alsoAllow`` layer whenever ``tools.profile``
  is set (``_tool_policy_view``'s own docstring, part (a)) — sound for that narrower
  question, but the real resolver never does this: ``pickSandboxToolPolicy(cfg.tools)`` is
  pushed onto the AND-ed ``policies[]`` list UNCONDITIONALLY, alongside the profile policy,
  whether or not a profile is set (line 103-104 below). This module does not suppress it.
* it reads a per-agent ``tools.profile`` widening as a bolt-on correction
  (``_agent_profile_widenings``) rather than as part of one resolution order. Here it falls
  out of the real order directly: ``profile = agentTools?.profile ?? cfg.tools?.profile`` —
  an agent's own profile REPLACES the global one (``??`` coalesce), while everything else
  (the raw global ``tools.allow``/``deny`` policy AND the raw agent ``tools.allow``/``deny``
  policy) is a SEPARATE, independently AND-ed layer that can only narrow. That asymmetry —
  one layer that coalesces, everything else that intersects — is the whole defect this
  module exists to close: a global ``tools.profile: "minimal"`` plus a per-agent
  ``tools.alsoAllow: ["write"]`` genuinely widens that agent's write grant, and neither
  ``B55`` nor ``B68`` could see it (measured — see ``tests/test_toolscope_per_scope_grants.py``).

RESOLUTION ORDER (``resolveConfiguredToolPolicies``, reproduced here for the citation)::

    profile = agentTools?.profile ?? cfg.tools?.profile
    profileAlsoAllow = agentTools?.alsoAllow ?? cfg.tools?.alsoAllow   # independent coalesce
    profilePolicy = mergeAlsoAllowPolicy(resolveToolProfilePolicy(profile), profileAlsoAllow)
    policies = [profilePolicy, pickSandboxToolPolicy(cfg.tools), pickSandboxToolPolicy(agentTools)]
    # (extraPolicies / sandboxMode=="all" push two more layers this module does not model —
    #  see "NOT MODELLED" below)
    granted = policies.every(p => isToolAllowedByPolicyName(tool, p))   # deny wins, then allow

``agentTools`` itself is resolved the way ``resolveEffectiveToolPolicy`` resolves it (its
``agentTools`` derivation, three lines): the matching roster entry's own ``tools`` block
(``collector.agent_roster``, which already reads both the 2026.8.1 ``agents.entries`` record
and legacy ``agents.list`` — B-699), falling back to ``agents.defaults.tools`` **only when
the config declares no roster at all** (``hasAgentRosterProperty`` — checked by whether
``agents.entries``/``agents.list`` is a KEY the config owns, not by whether the roster is
non-empty). Verified by executing the real function, not by reading it: two things this port
might otherwise have gotten wrong from reading alone —

* the fallback applies to the SCOPE param equally whether it names the default agent
  ("main") or any other id, and equally to the ``GLOBAL_SCOPE`` query (no explicit agent at
  all) — it is gated on "does a roster exist", not on which id was asked. ``agents.defaults.
  tools`` is a real, live scope precisely when there is no roster to read instead (the S1
  battery's ``toolscope_case8`` — 2026.9.1 says ``write=True`` there; ``toolpolicy.py:47-49``'s
  own comment calling this "deliberately NOT a scope" is right for the READ-CONFINEMENT
  predicate it guards but wrong as a general claim — do not port that comment here);
* the moment a roster IS declared (even an empty one), that fallback stops firing entirely —
  ``agents.defaults.tools`` is then dead weight (``toolscope_case9``).

GROUNDED TABLES. ``CORE_TOOL_PROFILES`` / ``CORE_TOOL_GROUPS`` below are not hand-transcribed
off ``CORE_TOOL_DEFINITIONS`` (the ``tool-catalog`` bundle) — they are the two tables that
module ITSELF builds (the ``CORE_TOOL_PROFILES`` object literal; ``CORE_TOOL_GROUPS`` via
``buildCoreToolGroupMap()``, spread into ``TOOL_GROUPS`` by ``tool-policy-shared``), dumped by
executing them against the installed dist so a mis-transcription of ~55 tool ids across 12
groups cannot happen. Re-grind by re-running the dump on upgrade, not by re-reading the
source: ``python3.12 tests/_toolgrantoracle.py --tables``.

The upgrade check is now WHOLE-TABLE and executed, not spot-checked. It used to assert five
tool ids and ``group:fs`` against a literal, which stayed green through 2026.9.5 while the
tables were wrong about ``gateway``, ``plugins``, ``ls``, ``openclaw`` and ``pdf``
(``tests/test_toolgrant_dist_grounding.py``). It now compares every profile, every group and
the alias map with a fresh execution of the vendor, and sweeps ``granted()`` against the vendor
over every tool name the catalog mentions. Re-ground history: 2026.9.2 (2026-09-06) identical
to the 2026.9.1 literals; 2026.9.5 (2026-09-19) moved three profiles and four groups — see the
comments on the two tables — and changed NO verdict for the six-tool family
``{read, write, edit, apply_patch, exec, automations}`` (0 of 3,354 previously pinned cells;
0 of 4,266 across the regenerated corpus and synthetic configs). That is why the drift was
invisible: ``checks/_capability.py`` (B55/B68) asks only about the four fs tools. The other
caller, the ``alsoAllow`` candidate filter in ``checks/_shared.py``, asks about whatever
names a user wrote, so it alone can see the moved tables — for ``gateway``, ``plugins``,
``ls``, ``openclaw`` and ``pdf`` reached through a group-level allow/deny. None of the 8
``alsoAllow`` entries in the fixture corpus changes its answer.

ALIAS TABLE — THREE ENTRIES, GROUNDED, NOT TWO. ``checks/_shared.py``'s ``_TOOL_NAME_ALIASES``
and ``toolpolicy.py``'s copy of the same table both carry only ``{"bash": "exec",
"apply-patch": "apply_patch"}``. The real ``TOOL_NAME_ALIASES`` (the ``tool-policy-shared``
bundle) has a third: ``"cron": "automations"`` — a "permanently accepted alias ... same
contract as bash -> exec" per the dist's own comment (``automations-tool-name-*``). Neither
existing copy is wrong for what it covers (bash/apply-patch), but a guard comparing them to
EACH OTHER (a peer) would stay green while both are missing the same third entry — the
"anchor a guard on the producer" lesson. This module's own three-entry table is grounded
against the dist directly in ``tests/test_toolgrant_dist_grounding.py``, not against either
sibling copy.

``write`` IMPLIES ``apply_patch`` (the ``tool-policy-match`` bundle,
``createToolPolicyMatcher``'s ``writeAllowsApplyPatch`` parameter, default ``true``): a
policy whose allow list names ``write`` but not ``apply_patch`` still lets ``apply_patch``
through THAT policy. It is evaluated per policy, inside the AND — a policy that denies
``apply_patch`` explicitly, or restricts allow to something that names neither, still blocks
it. ``checks/_capability.py``'s ``_tool_policy_view`` docstring marks this "NOT modelled,
deliberately"; this module models it because it is a real, unconditional part of the
resolver, not an approximation choice.

NOT MODELLED, deliberately, because each is a SEPARATE axis from "is TOOL granted" and
narrowing this module's own consumer question would need a vetted model of its own (the
same "don't invent a positive" discipline ``toolpolicy.py``'s ``_tools_may_remove_write``
docstring explains):

* ``sandboxMode`` / ``resolveSandboxToolPolicyForAgent`` — the sandbox-containment layer the
  real resolver only pushes when a caller passes ``sandboxMode === "all"``. This module never
  passes it (equivalent to always calling with ``sandboxMode`` absent), so it answers the
  DECLARED policy question, the same split ``toolpolicy.py`` already keeps between "is a tool
  granted" and "is the session sandbox-contained" (its own ``_sandbox_confines``).
* ``extraPolicies`` — per-provider (``byProvider``) and per-channel/group
  (``toolsBySender`` / plugin group policy) layers a caller can inject; none of this module's
  two inputs (global ``cfg.tools``, one resolved ``agentTools``) supply them, so they are
  simply absent from the AND, never approximated.
* the shipped-name expansions in ``expandShippedCoreToolPolicyNames`` (``tool-policy`` bundle,
  ``SHIPPED_PLUGIN_POLICY_FAMILY_CORE_TOOLS`` / ``SHIPPED_CORE_POLICY_RENAMES``): ``canvas`` ->
  ``[canvas, show_widget]`` and ``update_plan`` -> ``progress_card``. They run in the tool-
  CONSTRUCTION pipeline, after the resolver this module ports, so ``isToolAllowedByPolicies``
  never sees them — measured by execution on 2026.9.5: ``allow: ["canvas"]`` does not grant
  ``show_widget`` at this layer (``tests/test_toolgrant_dist_grounding.py``). No check asks
  about either target by name (only the ``alsoAllow`` filter could, with a user-written
  entry); a consumer that starts to would need this modelled and its own differential (the
  three-entry alias map above is unaffected — that is a different table).
* glob patterns other than a bare ``*`` interior wildcard are handled (``_matches`` below is
  the same compiled-regex approach ``toolpolicy.py::_matches`` already carries, grounded
  against ``glob-pattern-DFVWJ-hh.mjs`` — openclaw@2026.9.3) — this is modelled, not
  skipped; listed here only to say explicitly that it is NOT one of the omissions.

An unreadable/empty config is not evidence of a grant: ``granted()`` returns ``False`` for
``cfg`` that is not a non-empty ``dict``, a DELIBERATE divergence from the vendor (which
answers ``True`` for ``{}`` — nothing said restricts nothing) for the same reason
``toolpolicy.read_reaches_outside_workspace`` makes the identical choice (see its own
docstring / ``tests/test_b666_read_reach.py::test_a_blind_config_is_not_evidence_of_exposure``):
a config this tool never actually parsed must not read as "everything is granted". The S1
battery only exercises non-empty fixture configs, so this divergence sits outside its scope
by construction, not as an exception carved out of a disagreement.

Verified against the vendor: ``tests/test_toolgrant_battery.py`` replays assertions captured
by EXECUTING ``resolveConfiguredToolPolicies``/``isToolAllowedByPolicies`` — the six-tool
family one case per ``(fixture, scope, tool)`` over every plain-JSON, non-empty
``fixtures/*/openclaw.json`` (3,648 cases, including the nine ``fixtures/toolscope_case*`` edge
fixtures), and ``gateway``/``plugins``/``ls``/``openclaw``/``pdf`` plus 96 synthetic configs
(every group, profile, alias spelling and roster shape) in aggregate — pinned offline as data
(``tests/data/toolgrant_battery.json``) so the suite needs neither node nor the installed dist
to run. ``tests/_toolgrantoracle.py`` is the committed generator (``--write`` / ``--check``).
"""

from __future__ import annotations

import re

from .collector import agent_roster, dig

GLOBAL_SCOPE = "global"

# TOOL_NAME_ALIASES (the tool-policy-shared bundle; a Map since 2026.9.2, its three pairs
# unchanged through openclaw@2026.9.5 — compared whole against the EXECUTED Map on 2026-09-19).
# Three entries — see the module docstring's "ALIAS TABLE" section for why this is not a copy
# of checks/_shared.py's/toolpolicy.py's two-entry tables. Grounded directly against the dist
# in tests/test_toolgrant_dist_grounding.py, never against either sibling copy.
_TOOL_NAME_ALIASES = {"bash": "exec", "apply-patch": "apply_patch", "cron": "automations"}

# CORE_TOOL_GROUPS — the object the vendor's ``expandToolGroups`` actually consults
# (``TOOL_GROUPS = { ...CORE_TOOL_GROUPS }`` in tool-policy-shared, built by
# ``buildCoreToolGroupMap()`` in tool-catalog): "group:openclaw" plus one "group:<section>"
# per CORE_TOOL_SECTION_ORDER entry. Dumped by EXECUTING the installed dist, not transcribed —
# grounded against openclaw@2026.9.5 on 2026-09-19 (tests/_toolgrantoracle.py --tables), and
# compared WHOLE against a fresh execution by tests/test_toolgrant_dist_grounding.py. Versus
# 2026.9.2: group:fs gained "ls"; group:automation gained "plugins" and "openclaw";
# group:media gained "pdf"; group:openclaw gained "plugins", "openclaw" and "pdf".
_CORE_TOOL_GROUPS = {
    "group:openclaw": [
        "code_execution", "secrets", "web_search", "web_fetch", "x_search", "memory_search",
        "memory_get", "sessions", "sessions_list", "sessions_history", "sessions_search",
        "conversations_list", "conversations_send", "conversations_turn", "sessions_send",
        "sessions_spawn", "github_identity_status", "github_publish", "agents_wait",
        "sessions_yield", "subagents", "session_status", "suggest_task", "dismiss_task", "browser",
        "screen", "dashboard", "terminal", "portal", "show_widget", "message", "heartbeat_respond",
        "automations", "gateway", "plugins", "openclaw", "nodes", "computer", "mobile_ui",
        "agents_list", "get_goal", "create_goal", "update_goal", "progress_card", "ask_user",
        "skill_workshop", "view_image", "image_generate", "music_generate", "video_generate", "tts",
        "pdf",
    ],
    "group:fs": ["ls", "read", "write", "edit", "apply_patch"],
    "group:runtime": ["exec", "process", "code_execution", "secrets"],
    "group:web": ["web_search", "web_fetch", "x_search"],
    "group:memory": ["memory_search", "memory_get"],
    "group:sessions": [
        "sessions", "sessions_list", "sessions_history", "sessions_search", "conversations_list",
        "conversations_send", "conversations_turn", "sessions_send", "sessions_spawn",
        "github_identity_status", "github_publish", "agents_wait", "sessions_yield", "subagents",
        "session_status", "suggest_task", "dismiss_task",
    ],
    "group:ui": ["browser", "screen", "dashboard", "terminal", "portal", "canvas", "show_widget"],
    "group:messaging": ["message"],
    "group:automation": ["heartbeat_respond", "automations", "gateway", "plugins", "openclaw"],
    "group:nodes": ["nodes", "computer", "mobile_ui"],
    "group:agents": [
        "agents_list", "get_goal", "create_goal", "update_goal", "progress_card", "ask_user",
        "skill_workshop",
    ],
    "group:media": [
        "view_image", "image_generate", "music_generate", "video_generate", "tts", "pdf",
    ],
}

# CORE_TOOL_PROFILES — the literal object in tool-catalog, read through
# ``resolveCoreToolProfilePolicy(profile)`` for each key (an exact, case-sensitive object
# index). "full" is allow-all; the other three are the exact tool-id lists the runtime grants.
# Grounded against openclaw@2026.9.5 on 2026-09-19 by execution, and compared WHOLE against a
# fresh execution by tests/test_toolgrant_dist_grounding.py. Versus 2026.9.2: "gateway" joined
# minimal, coding AND messaging (the agent-facing gateway tool is now a default grant, which
# is why a "coding" agent can reach ``gateway``/``plugins`` without any allow entry);
# "plugins" joined coding; "ls" joined coding (already so on 2026.9.4).
_CORE_TOOL_PROFILES = {
    "minimal": ["session_status", "gateway"],
    "coding": [
        "ls", "read", "write", "edit", "apply_patch", "exec", "process", "code_execution",
        "secrets", "web_search", "web_fetch", "x_search", "memory_search", "memory_get", "sessions",
        "sessions_list", "sessions_history", "sessions_search", "conversations_list",
        "conversations_send", "conversations_turn", "sessions_send", "sessions_spawn",
        "github_identity_status", "github_publish", "agents_wait", "sessions_yield", "subagents",
        "session_status", "suggest_task", "dismiss_task", "screen", "dashboard", "terminal",
        "portal", "automations", "gateway", "plugins", "get_goal", "create_goal", "update_goal",
        "progress_card", "ask_user", "skill_workshop", "view_image", "image_generate",
        "music_generate", "video_generate", "bundle-mcp",
    ],
    "messaging": [
        "secrets", "sessions", "sessions_list", "sessions_history", "sessions_search",
        "conversations_list", "conversations_send", "conversations_turn", "sessions_send",
        "sessions_spawn", "sessions_yield", "subagents", "session_status", "message", "gateway",
        "ask_user", "bundle-mcp",
    ],
    "full": ["*"],
}

_DEFAULT_AGENT_ID = "main"
# normalizeAgentId (dist agent-id-GA8mwdTG.mjs, openclaw@2026.9.3 — the bundle graph
# reshuffled around it, but the function body is byte-identical to the old
# agent-id-CeT3w4ap.js). Two-branch, unlike toolpolicy.py's own
# single-branch approximation: an id that ALREADY matches VALID_ID_RE is returned merely
# lowercased (a trailing/leading dash survives, e.g. "a-" -> "a-"); only an id that fails
# the pattern goes through the invalid-char-fold + dash-strip + 64-char-truncate slow path.
# Differentially verified over an edge table (including "a-", "-a", "_x", "---", a 70-char
# id) in tests/test_toolgrant_dist_grounding.py — the two branches disagree on "a-" alone.
_VALID_AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$", re.IGNORECASE)
_INVALID_AGENT_ID_CHARS_RE = re.compile(r"[^a-z0-9_-]+")
_AGENT_ID_MAX_LEN = 64


def _normalize_agent_id(value) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if _VALID_AGENT_ID_RE.match(text):
        return text.lower()
    folded = _INVALID_AGENT_ID_CHARS_RE.sub("-", text.lower()).strip("-")[:_AGENT_ID_MAX_LEN]
    return folded or _DEFAULT_AGENT_ID


def _normalize_tool_name(name) -> str:
    """normalizeToolPolicyName: trim + lowercase (non-strings fold to ""), then alias."""
    text = name.strip().lower() if isinstance(name, str) else ""
    return _TOOL_NAME_ALIASES.get(text, text)


def _expand_groups(entries) -> list:
    """expandToolGroups: normalize each entry, expand a known group id to its members, dedup."""
    out: list = []
    for raw in entries or []:
        value = _normalize_tool_name(raw)
        if not value:
            continue
        members = _CORE_TOOL_GROUPS.get(value)
        for item in (members if members else (value,)):
            if item not in out:
                out.append(item)
    return out


def _matches(name: str, patterns) -> bool:
    """compileGlobPatterns + matchesAnyGlobPattern for one already-normalized tool name."""
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


def _policy_allows(name: str, policy) -> bool:
    """isToolAllowedByPolicyName + createToolPolicyMatcher: deny wins, then allow (empty
    allow == allow everything), then the write=>apply_patch implication."""
    if not policy:
        return True
    if _matches(name, _expand_groups(policy.get("deny"))):
        return False
    allow = _expand_groups(policy.get("allow"))
    if not allow:
        return True
    if _matches(name, allow):
        return True
    if name == "apply_patch" and _matches("write", allow):
        return True
    return False


def _union_allow(base, extra):
    """unionAllow (the sandbox-tool-policy bundle, re-read against openclaw@2026.9.5 on
    2026-09-19; behaviour covered by the battery): alsoAllow-only (or onto an empty allow)
    injects an implicit "*"; alsoAllow onto a real non-empty allow just unions in."""
    if not isinstance(extra, list) or not extra:
        return base
    if not isinstance(base, list) or not base:
        return ["*"] + list(extra)
    return list(base) + list(extra)


def _pick_policy(tools):
    """pickSandboxToolPolicy: the raw allow/alsoAllow/deny layer for one tools block."""
    if not isinstance(tools, dict):
        return None
    allow_raw = tools.get("allow")
    also_raw = tools.get("alsoAllow")
    if isinstance(allow_raw, list):
        allow = _union_allow(allow_raw, also_raw if isinstance(also_raw, list) else None)
    elif isinstance(also_raw, list) and also_raw:
        allow = _union_allow(None, also_raw)
    else:
        allow = None
    deny_raw = tools.get("deny")
    deny = deny_raw if isinstance(deny_raw, list) else None
    if allow is None and deny is None:
        return None
    return {"allow": allow, "deny": deny}


def _explicit_also_allow(tools):
    """resolveExplicitProfileAlsoAllow: tools.alsoAllow, only when it is really a list."""
    if isinstance(tools, dict) and isinstance(tools.get("alsoAllow"), list):
        return tools["alsoAllow"]
    return None


def _profile_policy(profile):
    """resolveToolProfilePolicy -> resolveCoreToolProfilePolicy: an EXACT, case-sensitive
    key lookup — "Coding"/" coding " match nothing, same as tools.profile everywhere else."""
    if not isinstance(profile, str) or not profile:
        return None
    resolved = _CORE_TOOL_PROFILES.get(profile)
    if resolved is None:
        return None
    return {"allow": list(resolved), "deny": None}


def _merge_also_allow(policy, also_allow):
    """mergeAlsoAllowPolicy: extend a profile policy's allow with alsoAllow, in place of a
    fresh policy object. A no-op when there is no profile policy or nothing to merge."""
    if not policy or not policy.get("allow") or not isinstance(also_allow, list) or not also_allow:
        return policy
    return {**policy, "allow": list(policy["allow"]) + list(also_allow)}


def _has_agent_roster(cfg: dict) -> bool:
    """hasAgentRosterProperty: does the config declare EITHER roster shape at all (even an
    empty/null one) -- as opposed to "resolves to a non-empty roster", which is a different
    and stronger question collector.agent_roster answers instead."""
    agents = cfg.get("agents")
    return isinstance(agents, dict) and ("entries" in agents or "list" in agents)


def _agent_entry_tools(cfg: dict, agent_id: str):
    """The matching roster entry's own ``tools`` block, or None if no entry resolves to
    this normalized id. Reuses collector.agent_roster (B-699: both roster shapes)."""
    target = _normalize_agent_id(agent_id)
    for agent in agent_roster(cfg):
        if _normalize_agent_id(agent.id) == target:
            return agent.entry.get("tools") if isinstance(agent.entry, dict) else None
    return None


def _agent_tools(cfg: dict, scope: str):
    """resolveEffectiveToolPolicy's agentTools derivation (the `agentTools` lines of
    agent-tools.policy-*.mjs, as of openclaw@2026.9.5): the
    resolved roster entry's tools, or -- ONLY when the config declares no roster at all,
    for ANY scope including GLOBAL_SCOPE -- agents.defaults.tools."""
    tools = None
    if scope != GLOBAL_SCOPE:
        tools = _agent_entry_tools(cfg, scope)
    if tools is None and not _has_agent_roster(cfg):
        tools = dig(cfg, "agents.defaults.tools")
    return tools


def granted(cfg: dict, tool: str, scope: str = GLOBAL_SCOPE) -> bool:
    """Is ``tool`` granted at ``scope`` ("global", or a declared agent id) by ``cfg``?

    The port of ``resolveConfiguredToolPolicies`` + ``isToolAllowedByPolicies`` — see the
    module docstring for the resolution order, the grounded tables, and what is
    deliberately not modelled (sandboxMode, extraPolicies).
    """
    if not isinstance(cfg, dict) or not cfg:
        return False

    agent_tools = _agent_tools(cfg, scope)
    global_tools = cfg.get("tools")

    profile = agent_tools.get("profile") if isinstance(agent_tools, dict) else None
    if profile is None:
        profile = global_tools.get("profile") if isinstance(global_tools, dict) else None

    also_allow = _explicit_also_allow(agent_tools)
    if also_allow is None:
        also_allow = _explicit_also_allow(global_tools)

    policies = []
    profile_policy = _merge_also_allow(_profile_policy(profile), also_allow)
    if profile_policy:
        policies.append(profile_policy)
    global_policy = _pick_policy(global_tools)
    if global_policy:
        policies.append(global_policy)
    agent_policy = _pick_policy(agent_tools)
    if agent_policy:
        policies.append(agent_policy)

    name = _normalize_tool_name(tool)
    return all(_policy_allows(name, policy) for policy in policies)
