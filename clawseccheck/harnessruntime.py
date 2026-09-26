"""Does this OpenClaw config make an agent run the Codex app-server harness? yes / no / unknown.

Two audit checks are conditional on the answer and used to say only "this audit does not
determine it": B333's modern leg (a tool whose own annotations waive its approval gate) and
B353 (a server pre-approving every tool). Both mechanisms live on the Codex app-server path
and are inert on any other harness, so a WARN that cannot say which one it is looking at
either cries wolf or hides a live grant.

SOUND BY CONSTRUCTION, and that is the whole design. The vendor's resolution chain spans
runtime pins in four scopes, a provider-owned implicit OpenAI rule that depends on route
facts, request params, an environment variable and the model id, and a per-agent
precedence with an "ambiguous" state. Porting all of it faithfully would be a second copy
of a moving target. This port instead answers only where it can prove the answer and
degrades every input it does not model to ``unknown``:

* ``yes``  -- a runtime pin normalises to ``codex`` (the vendor counts these
  unconditionally), or an agent's own primary/fallback ref is ``openai/...`` with NOTHING
  present that could change the implicit decision (no pin of any kind, no authored OpenAI
  provider config, no request params, no ``OPENAI_BASE_URL``).
* ``no``   -- every agent (and the defaults) names an explicit model, EVERY model
  reference the vendor enumerates (``model_refs``) is on a provider other than ``openai`` and
  the legacy Codex spellings, ``stray_model_signal`` finds no Codex-bound reference the vendor
  does NOT enumerate (bundled-plugin config reads its own keys), and no pin names a plugin
  runtime. Explicit matters: an agent with no model configured runs
  ``openai/gpt-5.6-sol`` on the validated build, so the vendor's own collector returning
  ``[]`` for such a config is not "no" -- it is the default-model trap.
* ``unknown`` -- everything else, including any build older than the one this was
  validated on, an unknown build, and any shape it does not recognise. This also covers a
  config shape a KNOWN legacy migration rewrites before the harness ever resolves it (a
  ``models.providers.codex``/``openai-codex`` block, or ``agents.entries: null`` beside a
  populated ``agents.list``): the oracle this port is graded against reads the config AS
  WRITTEN, never the migrated one, so it agrees with a ``no`` that the migrated config would
  not earn. See ``_LEGACY_CODEX_PROVIDER_BLOCK_IDS`` below.

VALIDATED DIFFERENTIALLY, not by reading. ``tests/_harnessoracle.py`` executes the
installed OpenClaw's own ``collectConfiguredAgentHarnessRuntimes`` /
``collectConfiguredModelRefs`` / ``resolveAgentHarnessPolicy`` over the config corpus, a
hand table and a generated grammar, and ``tests/data/harnessruntime_battery.json`` pins the
result so the suite replays it with no node and no dist. The contract asserted is
soundness -- a port ``yes`` is never an oracle ``no`` and vice versa -- with ``unknown``
always permitted, plus a guard that the battery actually exercises all three answers.

WHAT THIS DOES NOT SEE, and the callers must say so: only ``openclaw.json`` is read. A
model chosen at run time (a cron payload's ``model`` override, a ``/model`` switch), an
``OPENAI_BASE_URL`` set in the gateway's own environment rather than this process's, and
the Codex plugin's own ``appServer`` settings are invisible here. A ``no`` therefore means
"no configured model resolves to the Codex harness", never "Codex cannot run".

C-559 (2026-09-22) measured six further candidate blind spots against the installed
OpenClaw 2026.9.5 dist and recorded one decision each -- ACCEPT throughout, because every
surface, once actually opened, either never enters an agent turn at all or is already
caught by an existing rule. No code changed as a result; this paragraph IS the recorded
decision the ticket's own definition of done asks for.

1. ``tools.media.models[]`` -- the modern, capability-tagged replacement for the
   per-capability ``preferredModel`` this module already reads (real:
   ``zod-schema.core-CZ0zDyHR.mjs:912,969-975``; the migration off the old form is
   ``legacy-38PBEy7q.mjs``'s ``migrateModels``). The vendor's OWN
   ``collectConfiguredModelRefs`` does not enumerate it either. Traced its execution
   (``image-CQFbrtNB.mjs``, the capability-provider-runtime path): a single provider
   completion for captioning or generating media, never an agent turn with tool access.
   B333/B353 gate on tool-approval mechanics inside an agent's OWN turn; there is no tool
   to approve on this path on any provider. ACCEPT -- out of scope by what the mechanism
   does, not an oversight in what it enumerates.
2. The Codex ACP adapter (``agents.entries.*.runtime = {type: "acp", acp: {agent:
   "codex"}}`` -- real, ``acp-spawn-DBebUPRe.mjs:1077-1099``, whose own error text
   documents exactly this shape) spawns an EXTERNAL ``codex`` CLI subprocess under the
   ACP protocol -- a different harness from the embedded Codex app-server this module
   answers for. ``mcp.servers.*.codex.*``, the config B333/B353 actually read, is
   schema-described as projection metadata "in Codex app-server thread config"
   specifically (``schema-CwAIqZVE.mjs:147-149``) -- confirmed scoped to the embedded
   thread, not the ACP subprocess. ACCEPT -- a structurally separate mechanism, not a gap
   in this one.
3. Bare (non-provider-qualified) ids at ``channels.clickclack.model`` /
   ``channels.clickclack.accounts.*.model`` and Reef's ``guard.pinnedModel`` -- both real,
   bundled CHANNEL plugins (``extensions/clickclack``, ``extensions/reef`` in the
   installed dist) -- are one more measured instance of the "bundled plugin reads its own
   keys" class ``stray_model_signal`` already names below; a provider-qualified string at
   either is already refused by that function's whole-config walk regardless of key name.
   ``embeddedAgent.cyberFailover.model`` (``schema-CwAIqZVE.mjs:59-62``) fires only after
   an OpenAI cyber-policy refusal, which requires that SAME agent's own primary/fallback
   ref to already be ``openai/...`` -- a shape the ``yes``-via-implicit-OpenAI-rule branch
   above, or the explicit-ref scan below it, already catches before the ``no`` branch
   these PASS texts hinge on is ever reached, so a bare id here creates no new reachable
   ``no``. ``talk.realtime.model`` is a realtime VOICE session model on a separate
   provider path (``talk.realtime.providers.*``). ``memory.search.model``
   (``schema-CwAIqZVE.mjs:677``) is an EMBEDDING model override -- no completion, no
   tools, structurally incapable of an agent turn. ``tools.exec.applyPatch.allowModels``
   (``schema-CwAIqZVE.mjs:954``) is not a model reference at all -- it is an ALLOWLIST
   that only NARROWS which models may invoke ``apply_patch``, so it can never be the
   thing that makes an agent run anything. ACCEPT, all four groups -- same disclosed class
   as the plugin note below, or not a model reference to begin with.
4. Open key space in third-party plugins: already the stated residual in
   ``stray_model_signal``'s own docstring below ("a third-party plugin that selects a
   model through a key with no ``model`` in its name..."). ACCEPT -- already disclosed,
   nothing to add.
5. Run-time selection (a cron payload's ``model`` override, a ``/model`` switch, the
   Codex plugin's own ``appServer`` settings): already the stated residual in this
   paragraph's own opening, above. ACCEPT -- already disclosed, nothing to add.
6. ``OPENAI_BASE_URL`` set only in the GATEWAY's own environment, never this process's:
   measured the two real files the vendor's own dotenv loader reads before the gateway
   resolves any route (``dotenv-global-1I45H5ph.mjs:126-133``) -- ``<OPENCLAW_STATE_DIR or
   ~/.openclaw>/.env`` and ``~/.config/openclaw/gateway.env`` (also named in
   ``auth-token-source-conflict-CWrv-Qpc.mjs``'s own remediation text, so this is not a
   one-off reading). Missing either can overclaim a ``yes`` -- the opposite, riskier
   direction here, since a ``yes`` is what B333/B353 read as an asserted live grant --
   when the real route was actually redirected out from under the implicit-OpenAI
   assumption by a base-url override this process never sees. ACCEPT for now, not EXTEND:
   reading either file is a ``collector.py``-layer concern (this module is a declared
   leaf), the file can hold real secrets alongside the one wanted key, and this project
   requires a dedicated C-135 adversarial pass before a new read like that ships. Recorded
   here, with the exact paths, so that follow-up does not have to re-derive them.

Leaf: imports only ``collector.agent_roster``. Not in ``__all__``, matching its siblings
``toolpolicy.py`` / ``toolgrant.py``.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .collector import agent_roster

#: The window of builds this port was differentially validated on. Outside it -- older, newer,
#: or no known build -- every answer is ``unknown``: the vendor moved this chain between
#: builds before, and a definite ``no`` is the direction that turns a live WARN into a PASS.
#: The ceiling is deliberate, not a tidy-up: a newer build is exactly "an input this port does
#: not model", so it degrades to the previous WARN until the battery is re-run against that
#: build (``python3.12 tests/_harnessoracle.py --write``) and ``ORACLE_MAX`` is raised with it.
#: Only the first three components are compared, so a correction release of the validated
#: build (2026.9.5-1) stays inside the window; a new patch or minor does not.
#:
#: The floor moved off 2026.9.4 when the battery was regenerated on 2026.9.5, and that was a
#: measurement, not housekeeping: over the 770 pinned rows the vendor's own answer changed on
#: six, all in the same direction -- 9.5 THROWS where 9.4 returned a runtime. Two of the three
#: throw sites are reachable from ``collectConfiguredAgentHarnessRuntimes`` on config the
#: loader accepts: ``Object.keys(null)`` in ``model-extra-params-*.mjs`` (its guard is
#: ``source !== void 0``, which catches undefined but not null) when an agent carries
#: ``params: null`` AND a model that routes through the OpenAI path -- measured, an
#: ``anthropic/*`` model with the same ``params: null`` never reaches the check; and
#: ``value?.id?.trim is not a function`` in ``hasRuntimePolicy``
#: (``model-runtime-policy-*.mjs``) when ``models[ref].agentRuntime.id`` is a number -- the
#: optional chain guards null and undefined but not a non-string. So the two builds are NOT
#: interchangeable here, and after the regeneration nothing pins 9.4 any more. Keeping it in
#: the window would have asserted a validation this repo no longer holds evidence for.
#:
#: The ceiling moved to 2026.9.6 on 2026-09-25 and the floor deliberately did NOT: the
#: battery regenerated on 2026.9.6 answers identically to the 2026.9.5 one on all 771 rows
#: (only its ``build`` stamp differs), so the evidence for 9.5 is still measured, not
#: assumed. Raising the floor would have turned every 9.5 install's answer into ``unknown``
#: with no divergence to justify it.
ORACLE_MIN = (2026, 9, 5)
ORACLE_MAX = (2026, 9, 6)

YES, NO, UNKNOWN = "yes", "no", "unknown"

#: ``String.prototype.trim`` whitespace, which is NOT Python's ``str.strip`` set (Python
#: also strips U+001C..U+001F and U+0085, and does not strip U+FEFF).
_JS_WS = "\t\n\v\f\r            " \
         "      　﻿"

_DEFAULT_RUNTIMES = (None, "auto", "default")

#: Provider spellings the vendor accepts only at its legacy-migration boundary: a ref like
#: ``openai-codex/gpt-5.5`` is rewritten to ``openai/gpt-5.5`` on Codex, and the vendor's
#: ``modelRefUsesCodexRuntime`` answers true for it. TWO vendor tables feed this set, and it
#: is their union restricted to runtime ``codex``: ``LEGACY_CODEX_PROVIDER_IDS``
#: (``commands/doctor/shared/codex-route-model-ref``: ``codex``, ``openai-codex``) and
#: ``LEGACY_RUNTIME_MODEL_PROVIDER_ALIASES`` (``legacy-runtime-model-providers``: ``codex``,
#: ``codex-cli``). The runtime-collector oracle this port is graded against never sees the
#: migration, so it calls such a config Codex-free -- which is exactly why a ``no`` may not be
#: given over one. Matched on the provider alone, after the same trim + lowercase the vendor
#: applies.
_LEGACY_CODEX_PROVIDERS = frozenset(("codex", "codex-cli", "openai-codex"))

#: Provider spellings the vendor's OWN provider-BLOCK migration recognises as a whole
#: ``models.providers.<id>`` entry to move (``migrateLegacyOpenAICodexProvider`` /
#: ``config/legacy-codex-provider.ts``: ``LEGACY_CODEX_PROVIDER_IDS``, executed against the
#: installed dist 2026.9.5). Narrower than ``_LEGACY_CODEX_PROVIDERS`` above on purpose:
#: that set is for a REF STRING's provider half (``codex/gpt-5.5``); this one is a bare
#: ``models.providers.codex`` / ``models.providers.openai-codex`` BLOCK, which the migration
#: moves to ``models.providers.openai`` and stamps each of its models with
#: ``agentRuntime: {id: "codex"}`` -- something no ``_pin`` call here ever sees, because
#: the provider itself (not an ``agentRuntime`` field) is what marks it. "codex-cli" is not
#: in this table; it is only a legacy REF-string alias.
_LEGACY_CODEX_PROVIDER_BLOCK_IDS = frozenset(("codex", "openai-codex"))


@dataclass(frozen=True)
class HarnessReach:
    answer: str                      # "yes" | "no" | "unknown"
    reasons: "tuple[str, ...]" = ()  # config PATHS / short causes only -- never a value


def _trim(s: str) -> str:
    return s.strip(_JS_WS)


def _is_record(v) -> bool:
    return isinstance(v, dict)


def _runtime_id(raw):
    """``normalizeOptionalAgentRuntimeId``: None for a non-string or blank value."""
    if not isinstance(raw, str):
        return None
    value = _trim(raw).lower()
    if not value:
        return None
    if value in ("openclaw", "pi"):
        return "openclaw"
    if value == "codex-app-server":
        return "codex"
    return value


def _list_refs(value) -> "list[str]":
    """``listModelRefsFromConfigValue``: raw strings, primary first then fallbacks."""
    if isinstance(value, str):
        return [value]
    if not _is_record(value):
        return []
    out = []
    if isinstance(value.get("primary"), str):
        out.append(value["primary"])
    fb = value.get("fallbacks")
    if isinstance(fb, list):
        out.extend(f for f in fb if isinstance(f, str))
    return out


def _primary_ref(value):
    """The ref an agent actually STARTS on, or None when none is written.

    A record carrying only ``fallbacks`` has no primary -- the agent then starts on the
    build default, which is exactly what ``no`` must not paper over.
    """
    if isinstance(value, str):
        return value
    if _is_record(value) and isinstance(value.get("primary"), str):
        return value["primary"]
    return None


def _parse_ref(value):
    """``parseModelCatalogRef`` -> ``(provider, model)`` or None (no usable provider)."""
    t = _trim(value)
    slash = t.find("/")
    if slash <= 0 or slash >= len(t) - 1:
        return None
    provider = _trim(t[:slash]).lower()
    model = _trim(t[slash + 1:])
    if not provider or not model:
        return None
    return provider, model


def model_refs(cfg) -> "list[tuple[str, str]]":
    """``collectConfiguredModelRefs``: every configured model ref as ``(path, trimmed)``.

    Same locations, same order. Exposed because the differential asserts these values equal
    the vendor's own list exactly -- an under-enumeration here is what would let ``no``
    ignore a ref that runs Codex.
    """
    refs: "list[tuple[str, str]]" = []

    def push(path, value):
        if isinstance(value, str) and _trim(value):
            refs.append((path, _trim(value)))

    def selector(path, value):
        if isinstance(value, str):
            push(path, value)
            return
        if not _is_record(value):
            return
        if isinstance(value.get("primary"), str):
            push(f"{path}.primary", value["primary"])
        fb = value.get("fallbacks")
        if isinstance(fb, list):
            for i, f in enumerate(fb):
                if isinstance(f, str):
                    push(f"{path}.fallbacks.{i}", f)

    def rec(v):
        return v if _is_record(v) else {}

    def from_agent(path, agent, entry_selectors=False):
        if not _is_record(agent):
            return
        for key in ("model", "utilityModel", "imageModel", "voiceModel", "pdfModel"):
            selector(f"{path}.{key}", agent.get(key))
        media = rec(agent.get("mediaModels"))
        for cap in ("image", "video", "music"):
            selector(f"{path}.mediaModels.{cap}", media.get(cap))
        push(f"{path}.heartbeat.model", rec(agent.get("heartbeat")).get("model"))
        selector(f"{path}.subagents.model", rec(agent.get("subagents")).get("model"))
        comp = agent.get("compaction")
        if _is_record(comp):
            push(f"{path}.compaction.model", comp.get("model"))
            push(f"{path}.compaction.memoryFlush.model", rec(comp.get("memoryFlush")).get("model"))
        if _is_record(agent.get("models")):
            for ref in agent["models"]:
                push(f"{path}.models.{ref}", ref)
        if entry_selectors:
            exec_ = rec(rec(agent.get("tools")).get("exec"))
            selector(f"{path}.tools.exec.reviewer.model", rec(exec_.get("reviewer")).get("model"))
            push(f"{path}.tts.summaryModel", rec(agent.get("tts")).get("summaryModel"))

    root = rec(cfg)
    tools = rec(root.get("tools"))
    selector("tools.exec.reviewer.model", rec(rec(tools.get("exec")).get("reviewer")).get("model"))
    media = rec(tools.get("media"))
    for cap in ("image", "audio", "video"):
        push(f"tools.media.{cap}.preferredModel", rec(media.get(cap)).get("preferredModel"))
    agents = rec(root.get("agents"))
    from_agent("agents.defaults", agents.get("defaults"))
    if "entries" in agents:
        if _is_record(agents["entries"]):
            for aid, entry in agents["entries"].items():
                from_agent(f"agents.entries.{aid}", entry, True)
    elif isinstance(agents.get("list"), list):
        for i, entry in enumerate(agents["list"]):
            from_agent(f"agents.list.{i}", entry, True)
    channels = rec(root.get("channels"))
    for cid, cmap in rec(channels.get("modelByChannel")).items():
        if _is_record(cmap):
            for target, ref in cmap.items():
                push(f"channels.modelByChannel.{cid}.{target}", ref)
    hooks = rec(root.get("hooks"))
    if isinstance(hooks.get("mappings"), list):
        for i, m in enumerate(hooks["mappings"]):
            push(f"hooks.mappings.{i}.model", rec(m).get("model"))
    push("hooks.gmail.model", rec(hooks.get("gmail")).get("model"))
    push("tts.summaryModel", rec(root.get("tts")).get("summaryModel"))
    discord = rec(channels.get("discord"))

    def voice(path, value):
        v = rec(value)
        push(f"{path}.model", v.get("model"))
        push(f"{path}.tts.summaryModel", rec(v.get("tts")).get("summaryModel"))

    voice("channels.discord.voice", discord.get("voice"))
    if _is_record(discord.get("accounts")):
        for aid, acct in discord["accounts"].items():
            voice(f"channels.discord.accounts.{aid}.voice", rec(acct).get("voice"))
    return refs


class _Bail(Exception):
    """A shape this port does not model. Carries the reason; the answer becomes unknown."""


#: Bounds on the whole-config walk below: past either, the answer is ``unknown`` rather than a
#: partial scan passed off as a complete one. Iterative, so depth costs nothing but a bound.
_WALK_MAX_NODES = 50000
_WALK_MAX_DEPTH = 64

#: Where a model-shaped KEY with a value this port cannot resolve (a bare id, or a shape it does
#: not know) is refused. ``plugins`` is the verified surface (imap ``accounts.<id>.model``,
#: active-memory ``model``, memory-core dreaming all hand the value to an agent turn); the rest
#: of the config either is enumerated by ``model_refs`` or is not model-shaped by name.
_UNRESOLVABLE_MODEL_SCOPE = ("plugins",)


def _is_codex_provider_name(value) -> bool:
    """A BARE provider name that is ``openai`` or a legacy Codex spelling (``defaultProvider:
    "openai"``, ``{"provider": "openai", "id": ...}``): a plugin can combine it with a model id
    from elsewhere, and the vendor then routes the result to Codex."""
    return isinstance(value, str) and (
        _trim(value).lower() == "openai" or _trim(value).lower() in _LEGACY_CODEX_PROVIDERS)


def _has_unresolved_substitution(provider) -> bool:
    """``${VAR}`` inside the provider half of a ref: the vendor substitutes environment
    variables into any config string (``resolveConfigEnvVars``), so ``${P}/gpt-5.5`` is
    ``openai/gpt-5.5`` when ``P=openai`` and this port cannot know what it is."""
    return "${" in provider


def _is_codex_qualified(value) -> bool:
    """A ``provider/model`` string whose provider is ``openai`` or a legacy Codex spelling."""
    if not isinstance(value, str):
        return False
    parsed = _parse_ref(value)
    return bool(parsed) and (parsed[0] == "openai" or parsed[0] in _LEGACY_CODEX_PROVIDERS)


def _model_value_problem(value):
    """Why a value under a ``*model`` / ``*models`` key cannot be shown Codex-free, or None.

    ``None``/booleans/numbers cannot be a ref and are ignored. A string must be a
    ``provider/model`` reference (a bare id resolves through the DEFAULT provider, which on the
    validated build is OpenAI); a ``{primary, fallbacks}`` record and a list of strings are the
    two shapes with a known meaning; ANY other shape -- an object naming ``provider`` + ``id``,
    a map keyed by refs, a list of lists -- is one this port does not read.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return None
    if isinstance(value, str):
        if _trim(value):
            parsed = _parse_ref(value)
            if parsed is None:
                return ("is not a provider/model reference, so the provider it resolves to "
                        "cannot be seen")
            if _has_unresolved_substitution(parsed[0]):
                return ("has an environment substitution in its provider, so the provider it "
                        "resolves to cannot be seen")
        return None
    if _is_record(value) and set(value) <= {"primary", "fallbacks"}:
        refs = _list_refs(value)
        fb = value.get("fallbacks")
        if fb is not None and not isinstance(fb, list):
            return "has a shape this determination does not read"
        if any(not isinstance(v, str) for v in ([value.get("primary")] if "primary" in value else [])
               + (fb or [])):
            return "has a shape this determination does not read"
        return next((_model_value_problem(r) for r in refs if _model_value_problem(r)), None)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return next((_model_value_problem(v) for v in value if _model_value_problem(v)), None)
    return "has a shape this determination does not read"


#: Matches a leaf built ONLY by walking ``cfg["models"]["providers"][p]["models"][i]["id"/
#: "name"]`` (the walk below dot-joins real dict keys / list indices bottom-up, so this literal
#: shape cannot arise any other way short of a provider key containing this exact suffix as a
#: literal substring). ``(.+)`` is greedy, so a provider key that itself contains a ``.`` still
#: resolves to the rightmost, real ``.models.<digits>.(id|name)`` split.
_PROVIDER_CATALOG_FIELD_RE = re.compile(r"^models\.providers\.(.+)\.models\.\d+\.(?:id|name)$")


def _provider_catalog_field(path: str, providers=None):
    """The raw provider key ``<p>``, as spelled in the config, when *path* is a
    ``models.providers.<p>.models[i].id``/``.name`` leaf; else None.

    A dot-joined path cannot distinguish a provider key containing a ``.`` from a deeper
    nesting under a shorter key: ``models.providers.openai.extra.models.0.id`` captures
    ``openai.extra`` either way. So the capture is accepted only when it is an ACTUAL key of
    ``models.providers`` -- otherwise a leaf filed under provider ``openai`` could be exempted
    as if ``openai.extra`` were an unrelated provider, which the docstring above promises
    never happens (C-135 review of C-560). A rejected capture means no exemption, i.e. the
    pre-C-560 behaviour: ``unknown``, never a confident ``no``."""
    m = _PROVIDER_CATALOG_FIELD_RE.match(path)
    if not m:
        return None
    key = m.group(1)
    if not _is_record(providers) or key not in providers:
        return None
    return key


def stray_model_signal(cfg) -> "str | None":
    """A reason ``no`` cannot be given because of a model reference ``model_refs`` never lists.

    ``model_refs`` mirrors the vendor's own ``collectConfiguredModelRefs``, so the oracle the
    port is graded against shares its blind spots -- bundled plugins read their OWN config keys
    (``imap``'s ``accounts.<id>.model``, ``active-memory``'s ``model`` and ``modelFallback``,
    memory-core dreaming, ``clickclack``'s ``model`` / ``accounts.*.model``, Reef's
    ``guard.pinnedModel`` -- the last two measured under C-559) and hand the value to an agent
    turn. Two structural rules, deliberately
    not a list of plugin fields (a plugin's schema is the plugin's, and a third party's is
    unknowable):

    * anywhere in the config, any string -- a value OR a map key -- that is a
      ``provider/model`` reference on ``openai`` or a legacy Codex provider is refused, whatever
      key it sits under;
    * under ``_UNRESOLVABLE_MODEL_SCOPE``, any key containing ``model`` (any case: ``modelId``,
      ``model_name``, ``defaultModel``, ``allowedModels``...) whose value is not provably a
      Codex-free reference is refused (see ``_model_value_problem``), and so is any string that
      is a BARE ``openai`` / legacy-Codex provider name (``defaultProvider: "openai"``, a
      ``{"provider": "openai", ...}`` record) -- a plugin can pair it with a model id taken from
      elsewhere.

    What this cannot see, stated rather than hidden: a third-party plugin that selects a model
    through a key with no ``model`` in its name and no Codex-bound string in its value. A
    plugin's configuration space is open-ended, so the ``no`` PASS text says only openclaw.json
    was read.

    Over-refusing can only turn a ``no`` into ``unknown`` (the old WARN); under-refusing is the
    lying PASS this exists to prevent. Returns a path-only reason, never a value.

    C-560 narrows the whole-config walk in exactly two PROVABLY-Codex-free shapes, each argued
    on its own, neither by trusting a key NAME (round 2-3 of the earlier C-135 passes showed a
    reference can sit under any key, so a name-based skip is unsound in general):

    * ``models.providers.<p>.models[i].id``/``.name`` is a local CATALOG LABEL for one of
      provider ``<p>``'s own models, not a route -- the model resolves through ``<p>`` itself
      (e.g. ``lmstudio/openai/gpt-oss-20b``), and the label is free to spell anything, including
      another provider's name, without that provider ever seeing the request. Skipped only when
      ``<p>`` itself is not ``openai``/a legacy Codex spelling (``_is_codex_provider_name``) --
      the port already reads ``<p>`` structurally for this exact subtree in ``_analyse``, so the
      skip is keyed off the SAME field the vendor itself routes through, not off ``id``/``name``
      being harmless key names in general.
    * ``agents.list`` beside an ``agents.entries`` RECORD is a shape the vendor's own
      ``collectConfiguredModelRefs``/``collectConfiguredAgentHarnessRuntimes`` never reads, and
      that its legacy migration deletes. Not beside a non-record ``entries`` (``null``): there
      the migration moves ``list`` into ``entries``, so the list can still become a route --
      see the comment at the skip below. Mirrored inline here (not
      called: ``agent_roster`` returns the roster, not a walk-skip decision) rather than walking
      it and letting an under-Codex-shaped string report a reference nothing dispatches to.
    """
    if not _is_record(cfg):
        return None
    _models = cfg.get("models")
    _catalog_providers = _models.get("providers") if _is_record(_models) else None
    stack = [("", cfg, 0)]
    seen = 0
    while stack:
        path, node, depth = stack.pop()
        seen += 1
        if seen > _WALK_MAX_NODES or depth > _WALK_MAX_DEPTH:
            raise _Bail("the config is too large or too deep to scan for model references")
        if _is_record(node):
            # B-699: `list` beside `entries` is unread -- but ONLY when `entries` is a record.
            # The runtime roster reader picks `entries` whenever it is !== undefined
            # (agent-roster-DzcWJqlw.mjs:53-67, mirrored by collector.agent_roster), yet the
            # vendor's own legacy migration drops `list` only when getRecord(agents.entries)
            # is truthy (legacy-38PBEy7q.mjs:1983-1999). With `entries: null` the migration
            # MOVES `list` INTO `entries` instead -- and a gateway start offers that repair as
            # a single yes/no prompt (invalid-config-recovery-Dp32yq5b.mjs:16-25), after which
            # an `openai/...` list entry runs on the Codex harness. `entries: null` is
            # schema-invalid, so the raw-config oracle cannot see this; per this module's own
            # rule (a migration can change the answer, so `no` may not be given over it), a
            # non-record `entries` does not license the skip. Found by C-135 review of C-560.
            skip_ignored_list = path == "agents" and _is_record(node.get("entries"))
            for key, value in node.items():
                if skip_ignored_list and key == "list":
                    continue
                kp = f"{path}.{key}" if path else str(key)
                if _is_codex_qualified(key):
                    return f"{kp} is a map key naming a model on a provider that runs the " \
                           f"Codex harness (or is migrated onto it)"
                in_scope = kp.split(".", 1)[0] in _UNRESOLVABLE_MODEL_SCOPE
                if in_scope and isinstance(key, str) and "model" in key.lower():
                    problem = _model_value_problem(value)
                    if problem:
                        return f"{kp} {problem}"
                stack.append((kp, value, depth + 1))
        elif isinstance(node, list):
            for i, value in enumerate(node):
                stack.append((f"{path}.{i}", value, depth + 1))
        elif _is_codex_qualified(node):
            catalog_provider = _provider_catalog_field(path, _catalog_providers)
            if catalog_provider is None or _is_codex_provider_name(catalog_provider):
                return (f"{path} names a model on a provider that runs the Codex harness (or is "
                        f"migrated onto it)")
        elif path.split(".", 1)[0] in _UNRESOLVABLE_MODEL_SCOPE and _is_codex_provider_name(node):
            return (f"{path} names a provider that runs the Codex harness (or is migrated onto "
                    f"it), which a plugin can combine with a model id from elsewhere")
    return None


def _pin(holder, path, pins):
    """Record ``holder.agentRuntime.id`` (normalised) at *path*, or bail on a wrong shape."""
    if not _is_record(holder) or "agentRuntime" not in holder:
        return
    rt = holder["agentRuntime"]
    if rt is None:
        return
    if not _is_record(rt):
        raise _Bail(f"{path}.agentRuntime is not an object")
    raw = rt.get("id")
    if raw is None:
        return
    if not isinstance(raw, str):
        raise _Bail(f"{path}.agentRuntime.id is not a string")
    rid = _runtime_id(raw)
    if rid not in _DEFAULT_RUNTIMES:
        pins.append((f"{path}.agentRuntime.id", rid))


def _model_map_pins(models, path, pins):
    if not _is_record(models):
        return
    for key, entry in models.items():
        if _is_record(entry):
            _pin(entry, f"{path}.{key}", pins)
            # ``pickerRuntimes``: the vendor's collector counts each entry exactly like a pin
            # (``pushModelMapRuntimeIds``). Whether a runtime OFFERED for a model is the one
            # that runs it is not something this port resolves, so any non-default entry is
            # a shape it declines to answer over, in either direction.
            picker = entry.get("pickerRuntimes")
            if isinstance(picker, list):
                for value in picker:
                    rid = _runtime_id(value)
                    if rid not in _DEFAULT_RUNTIMES and rid != "openclaw":
                        raise _Bail(f"{path}.{key}.pickerRuntimes offers a runtime this "
                                    f"determination does not resolve")


def _has_params(holder) -> bool:
    """Any authored ``params`` at all. Deliberately broader than the vendor, which exempts
    a handful of runtime-only keys: over-blocking here only yields ``unknown``."""
    if not _is_record(holder) or "params" not in holder:
        return False
    # `params: null` counts as authored on purpose: the vendor's own check throws on it
    # (Object.keys(null)), i.e. no definite answer exists for that shape.
    p = holder["params"]
    return not (_is_record(p) and not p)


def _mentions_openai_base_url(cfg, environ) -> bool:
    """Whether ``OPENAI_BASE_URL`` is visible to THIS process: *environ* (by default
    ``os.environ``) or ``cfg.env``. Deliberately narrower than the real gateway process's own
    view -- the vendor's own dotenv loader also merges
    ``<OPENCLAW_STATE_DIR or ~/.openclaw>/.env`` and ``~/.config/openclaw/gateway.env``
    (``dotenv-global-1I45H5ph.mjs``) before it resolves any route, and this function does not
    read either file (C-559 item 6: accepted for now, not read here -- see the module
    docstring). Missing either can overclaim a ``yes``, never a ``no``, so it does not weaken
    the module's own soundness contract; it is recorded because it is the opposite of that
    contract's usual direction of concern.
    """
    val = environ.get("OPENAI_BASE_URL")
    if isinstance(val, str) and val != "":
        return True
    stack = [cfg.get("env")] if _is_record(cfg) else []
    while stack:
        cur = stack.pop()
        if _is_record(cur):
            for k, v in cur.items():
                if isinstance(k, str) and k.upper() == "OPENAI_BASE_URL":
                    return True
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return False


def _analyse(cfg, environ) -> HarnessReach:
    if not _is_record(cfg):
        raise _Bail("config is not an object")
    models = cfg.get("models")
    if models is not None and not _is_record(models):
        raise _Bail("models is not an object")
    providers = (models or {}).get("providers")
    if providers is not None and not _is_record(providers):
        raise _Bail("models.providers is not an object")
    agents = cfg.get("agents")
    if agents is not None and not _is_record(agents):
        raise _Bail("agents is not an object")
    agents = agents or {}
    defaults = agents.get("defaults")
    if defaults is not None and not _is_record(defaults):
        raise _Bail("agents.defaults is not an object")
    defaults = defaults or {}
    if "entries" in agents and agents["entries"] is not None and not _is_record(agents["entries"]):
        raise _Bail("agents.entries is not an object")
    if "entries" not in agents and "list" in agents and agents["list"] is not None \
            and not isinstance(agents["list"], list):
        raise _Bail("agents.list is not an array")
    roster = agent_roster(cfg)

    # A shape a KNOWN legacy migration rewrites before the harness is ever resolved. The
    # oracle this port is graded against never sees the migration, so it can agree with a
    # `no` the migrated config would not earn -- refuse the `no` and say why (B-883).
    migration_reasons: "list[str]" = []
    # ``entries`` present but null is schema-VALID on its own ("no entries"); a populated
    # ``list`` beside it is what makes the pair schema-invalid AS WRITTEN. The runtime (and
    # this port's `agent_roster`) then never consults `list` -- the KEY alone decides. But
    # the vendor's OWN migration visitor (`visitAgentEntries`, shared by many doctor
    # migrations) falls back to `list` whenever `entries` is not a record, null included,
    # so an `agentRuntime` pin sitting inside that `list` is invisible to this port even
    # though the migration would read and rewrite it.
    if "entries" in agents and agents.get("entries") is None \
            and isinstance(agents.get("list"), list) \
            and any(_is_record(e) for e in agents["list"]):
        migration_reasons.append(
            "agents.entries is null alongside a populated agents.list; OpenClaw's own "
            "config migration falls back to agents.list when agents.entries is null, but "
            "this determination's roster does not, so a runtime pin inside agents.list is "
            "invisible to it")

    pins: "list[tuple[str, str]]" = []
    wholeagent: "list[str]" = []
    openai_provider_cfg = False
    seen_providers: "set[str]" = set()
    for pname, pval in (providers or {}).items():
        norm = _trim(pname).lower() if isinstance(pname, str) else ""
        if norm in seen_providers:
            # Two spellings of one provider are MERGED by the vendor, and the merge throws
            # on some shapes; no definite answer is offered for that.
            raise _Bail("models.providers has two spellings of one provider")
        seen_providers.add(norm)
        if norm.startswith("openai"):
            openai_provider_cfg = True
        if pval is None:
            continue
        if not _is_record(pval):
            raise _Bail(f"models.providers.{pname} is not an object")
        if norm in _LEGACY_CODEX_PROVIDER_BLOCK_IDS:
            migration_reasons.append(
                f"models.providers.{pname} is a legacy Codex provider id; OpenClaw's own "
                f"config migration moves it to models.providers.openai and stamps each of "
                f"its models with a codex runtime pin, which this determination does not "
                f"simulate")
        _pin(pval, f"models.providers.{pname}", pins)
        pm = pval.get("models")
        if pm is not None and not isinstance(pm, list):
            raise _Bail(f"models.providers.{pname}.models is not an array")
        for i, m in enumerate(pm or []):
            if m is None:
                continue
            if not _is_record(m):
                raise _Bail(f"models.providers.{pname}.models[{i}] is not an object")
            _pin(m, f"models.providers.{pname}.models[{i}]", pins)
    _model_map_pins(defaults.get("models"), "agents.defaults.models", pins)
    for a in roster:
        _model_map_pins(a.entry.get("models"), f"{a.path}.models", pins)

    # The deprecated whole-agent spelling: the vendor's collector ignores it but the
    # runtime still reads it, so it is neither a `yes` nor something `no` may ignore.
    wa: "list[tuple[str, str]]" = []
    _pin(defaults, "agents.defaults", wa)
    for a in roster:
        _pin(a.entry, a.path, wa)
    wholeagent = [p for p, _ in wa]

    # `params: null` makes the vendor's own resolution THROW (Object.keys(null)), so no
    # definite answer -- not even a pin's `yes` -- exists for that shape.
    holders = [defaults] + [a.entry for a in roster]
    for h in list(holders):
        if _is_record(h.get("models")):
            holders.extend(e for e in h["models"].values() if _is_record(e))
    if any(_is_record(h) and "params" in h and h["params"] is None for h in holders):
        raise _Bail("a params value is null")

    codex_pins = [p for p, rid in pins if rid == "codex"]
    if codex_pins:
        return HarnessReach(YES, tuple(codex_pins[:5]))

    other_pins = [p for p, rid in pins if rid != "openclaw"]
    any_pin = [p for p, _ in pins]

    # ---- yes via the implicit OpenAI rule, on an agent's OWN primary/fallback refs ----
    scopes = [("agents.defaults", defaults)] if not roster else [(a.path, a.entry) for a in roster]
    effective: "list[tuple[str, list[str]]]" = []
    for path, agent in scopes:
        m = agent.get("model")
        if m is None:
            m, path = defaults.get("model"), "agents.defaults"
        effective.append((f"{path}.model", _list_refs(m)))
    openai_paths = []
    for path, refs in effective:
        for r in refs:
            parsed = _parse_ref(r)
            if parsed and parsed[0] == "openai":
                openai_paths.append(path)
                break
    if openai_paths:
        blockers = []
        if any_pin or wholeagent:
            blockers.append("a runtime pin is configured and could take precedence")
        if openai_provider_cfg:
            blockers.append("models.providers has an openai entry (route facts are authored)")
        if _has_params(defaults) or any(_has_params(a.entry) for a in roster) or any(
                _has_params(e) for m in [defaults.get("models")] + [a.entry.get("models") for a in roster]
                if _is_record(m) for e in m.values()):
            blockers.append("request params are authored, which can move the OpenAI route")
        if _mentions_openai_base_url(cfg, environ):
            blockers.append("OPENAI_BASE_URL is set, which moves the OpenAI route")
        if not blockers:
            return HarnessReach(YES, tuple(dict.fromkeys(openai_paths))[:5])
        return HarnessReach(UNKNOWN, tuple(blockers))

    # ---- no ----
    if other_pins or wholeagent:
        return HarnessReach(UNKNOWN, ("a runtime pin names a runtime other than the default "
                                      "embedded one",))
    starts = [("agents.defaults", defaults.get("model"))]
    for a in roster:
        m = a.entry.get("model")
        starts.append((a.path, m if m is not None else defaults.get("model")))
    for path, m in starts:
        ref = _primary_ref(m)
        parsed = _parse_ref(ref) if ref is not None else None
        if parsed is None:
            return HarnessReach(UNKNOWN, (
                f"{path} names no explicit provider/model, so the agent starts on the build "
                f"default, which is an OpenAI model",))
    for path, ref in model_refs(cfg):
        parsed = _parse_ref(ref)
        if parsed is None:
            return HarnessReach(UNKNOWN, (f"{path} is not a provider/model reference (an alias "
                                          f"or a bare model id resolves to a provider this "
                                          f"port cannot see)",))
        if parsed[0] == "openai":
            return HarnessReach(UNKNOWN, (f"{path} is an openai model outside an agent's own "
                                          f"primary/fallback list",))
        if parsed[0] in _LEGACY_CODEX_PROVIDERS:
            return HarnessReach(UNKNOWN, (f"{path} uses a legacy Codex provider spelling, which "
                                          f"the vendor migrates onto the Codex harness",))
        if _has_unresolved_substitution(parsed[0]):
            return HarnessReach(UNKNOWN, (f"{path} has an environment substitution in its "
                                          f"provider, so the provider it resolves to cannot "
                                          f"be seen",))
    # Model references the vendor's enumeration above never lists (bundled-plugin config and
    # any other provider-qualified Codex string): see ``stray_model_signal``.
    stray = stray_model_signal(cfg)
    if stray:
        return HarnessReach(UNKNOWN, (stray,))
    if migration_reasons:
        return HarnessReach(UNKNOWN, tuple(migration_reasons))
    return HarnessReach(NO, tuple(p for p, _ in starts[:5]))


def codex_harness_reach(cfg, version, environ=None) -> HarnessReach:
    """Whether a configured agent runs the Codex app-server harness. See the module docstring.

    *version* is the installed (or config-stamped) OpenClaw build as a numeric tuple such as
    ``(2026, 9, 5)``, or None when unknown. Outside ``ORACLE_MIN <= build[:3] <= ORACLE_MAX``
    every answer is ``unknown``. *environ* defaults to this process's environment; tests
    pass their own.
    """
    if not isinstance(version, tuple) or not version or tuple(version) < ORACLE_MIN \
            or tuple(version)[:3] > ORACLE_MAX:
        return HarnessReach(UNKNOWN, ("the installed OpenClaw build is unknown, or is not a "
                                      "build this determination was validated on",))
    env = os.environ if environ is None else environ
    try:
        return _analyse(cfg, env)
    except _Bail as exc:
        return HarnessReach(UNKNOWN, (str(exc),))
    except (TypeError, AttributeError, ValueError, KeyError):
        return HarnessReach(UNKNOWN, ("the config has a shape this determination does not model",))
