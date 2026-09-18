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
  reference anywhere in the config is on a provider other than ``openai``, and no pin
  names a plugin runtime. Explicit matters: an agent with no model configured runs
  ``openai/gpt-5.6-sol`` on the validated build, so the vendor's own collector returning
  ``[]`` for such a config is not "no" -- it is the default-model trap.
* ``unknown`` -- everything else, including any build older than the one this was
  validated on, an unknown build, and any shape it does not recognise.

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

Leaf: imports only ``collector.agent_roster``. Not in ``__all__``, matching its siblings
``toolpolicy.py`` / ``toolgrant.py``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .collector import agent_roster

#: The first build this port was differentially validated on. Below it, or with no known
#: build, every answer is ``unknown`` -- the vendor moved this chain between builds before.
ORACLE_MIN = (2026, 9, 4)

YES, NO, UNKNOWN = "yes", "no", "unknown"

#: ``String.prototype.trim`` whitespace, which is NOT Python's ``str.strip`` set (Python
#: also strips U+001C..U+001F and U+0085, and does not strip U+FEFF).
_JS_WS = "\t\n\v\f\r            " \
         "      　﻿"

_DEFAULT_RUNTIMES = (None, "auto", "default")


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
    return HarnessReach(NO, tuple(p for p, _ in starts[:5]))


def codex_harness_reach(cfg, version, environ=None) -> HarnessReach:
    """Whether a configured agent runs the Codex app-server harness. See the module docstring.

    *version* is the installed (or config-stamped) OpenClaw build as a numeric tuple such as
    ``(2026, 9, 4)``, or None when unknown. Below :data:`ORACLE_MIN` every answer is
    ``unknown``. *environ* defaults to this process's environment; tests pass their own.
    """
    if not isinstance(version, tuple) or not version or tuple(version) < ORACLE_MIN:
        return HarnessReach(UNKNOWN, ("the installed OpenClaw build is unknown or older than "
                                      "the build this determination was validated on",))
    env = os.environ if environ is None else environ
    try:
        return _analyse(cfg, env)
    except _Bail as exc:
        return HarnessReach(UNKNOWN, (str(exc),))
    except (TypeError, AttributeError, ValueError, KeyError):
        return HarnessReach(UNKNOWN, ("the config has a shape this determination does not model",))
