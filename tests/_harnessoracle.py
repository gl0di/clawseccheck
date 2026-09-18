"""The vendor oracle and the case tables for ``clawseccheck/harnessruntime.py``.

TEST-ONLY. This module shells out to ``node``; the shipped runtime never does.

WHAT IT ANSWERS. "Does this ``openclaw.json`` make some agent run the Codex app-server
harness?" — asked of OpenClaw ITSELF, by executing three of its own functions, bound by
their real export name (never by the minified alias letter, which rotates per build):

* ``collectConfiguredAgentHarnessRuntimes`` — the vendor's own "is the Codex plugin needed"
  predicate. It enumerates runtime pins (four scopes) and resolves every agent's primary /
  fallback / models-map ref through the policy chain below.
* ``collectConfiguredModelRefs`` — every configured model reference, on every surface
  (agents, subagents, heartbeat, compaction, exec reviewer, channel overrides, hooks, tts…).
  ``collectConfiguredAgentHarnessRuntimes`` alone MISSES most of these: a probe on the
  installed build returned ``[]`` for ``openai/*`` set as ``subagents.model``.
* ``resolveAgentHarnessPolicy`` — the model/provider -> runtime decision, including the
  provider-owned implicit OpenAI rule.

The oracle for a config is the UNION of (a) the collector's answer and (b) the policy
resolved over EVERY ref the second function lists, under the id of the agent that owns the
ref (none for a defaults / global ref) — the same scoping the collector itself uses.

THE DEFAULT-MODEL TRAP, recorded because a naive port falls straight into it: the dist has
``DEFAULT_PROVIDER = "openai"``, and an agent with no model configured therefore runs
Codex — while the collector returns ``[]`` for such a config. "The oracle says no" is NOT
"no agent runs Codex". The port (and its tests) treat that as UNKNOWN, never as ``no``.

Regenerate the pinned battery with ``python3.12 tests/_harnessoracle.py --write``. It needs
the matching OpenClaw installed and rewrites ``tests/data/harnessruntime_battery.json``.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

BATTERY_PATH = HERE / "data" / "harnessruntime_battery.json"
FIXTURES = HERE.parent / "fixtures"

#: The build the battery was generated against (recorded in the battery header).
ORACLE_BUILD = "2026.9.4"

# --------------------------------------------------------------------------------------
# node side
# --------------------------------------------------------------------------------------
_SCRIPT = r"""
import { readFileSync } from "node:fs";
const [, , collectMod, refsMod, policyMod, parseMod, casesPath, aliasJson] = process.argv;
const A = JSON.parse(aliasJson);
const collect = (await import(collectMod))[A.collectConfiguredAgentHarnessRuntimes];
const collectRefs = (await import(refsMod))[A.collectConfiguredModelRefs];
const policy = (await import(policyMod))[A.resolveAgentHarnessPolicy];
const parseRef = (await import(parseMod))[A.parseModelCatalogRef];
const cases = JSON.parse(readFileSync(casesPath, "utf8"));
const selectable = (r) => typeof r === "string" && r !== "" && r !== "auto" && r !== "default" && r !== "openclaw";

function agentIdForPath(cfg, path) {
  let m = /^agents\.entries\.([^.]+)\./.exec(path);
  if (m) return m[1];
  m = /^agents\.list\.(\d+)\./.exec(path);
  if (m) { const e = cfg?.agents?.list?.[Number(m[1])]; return typeof e?.id === "string" ? e.id : undefined; }
  return undefined;
}

const out = [];
for (const c of cases) {
  const saved = process.env.OPENAI_BASE_URL;
  delete process.env.OPENAI_BASE_URL;
  if (c.env && typeof c.env.OPENAI_BASE_URL === "string") process.env.OPENAI_BASE_URL = c.env.OPENAI_BASE_URL;
  const rec = {};
  try {
    rec.collect = collect(structuredClone(c.cfg));
    const refs = collectRefs(structuredClone(c.cfg));
    rec.refs = refs.map((r) => r.value);
    const runtimes = new Set(rec.collect);
    for (const r of refs) {
      const parsed = parseRef(r.value);
      if (!parsed) continue;
      {
        const agentId = agentIdForPath(c.cfg, r.path);
        const p = policy({ config: structuredClone(c.cfg), provider: parsed.provider, modelId: parsed.modelId, agentId });
        if (selectable(p.runtime)) runtimes.add(p.runtime);
      }
    }
    rec.runtimes = [...runtimes].sort();
  } catch (e) {
    rec.error = String(e && e.message || e).slice(0, 200);
  }
  if (saved === undefined) delete process.env.OPENAI_BASE_URL; else process.env.OPENAI_BASE_URL = saved;
  out.push(rec);
}
console.log("@@RESULT@@" + JSON.stringify(out));
"""

_ANCHORS = {
    "collect": ("harness-runtimes-*.mjs", "function collectConfiguredAgentHarnessRuntimes"),
    "refs": ("configured-model-refs-*.mjs", "function collectConfiguredModelRefs("),
    "policy": ("policy-*.mjs", "function resolveAgentHarnessPolicy"),
    "parse": ("model-catalog-refs-*.mjs", "function parseModelCatalogRef"),
}
_WANT = {
    "collect": "collectConfiguredAgentHarnessRuntimes",
    "refs": "collectConfiguredModelRefs",
    "policy": "resolveAgentHarnessPolicy",
    "parse": "parseModelCatalogRef",
}


def _exports(path: Path) -> "dict[str, str]":
    import re
    text = path.read_text(encoding="utf-8", errors="replace")
    out: "dict[str, str]" = {}
    for stmt in re.findall(r"^export \{(.+?)\};", text, re.M):
        for part in stmt.split(","):
            bits = part.strip().split(" as ")
            if len(bits) == 2:
                out[bits[0].strip()] = bits[1].strip()
    return out


def dist_version() -> "str | None":
    from _distgrounding import OPENCLAW_DIST
    try:
        return json.loads((OPENCLAW_DIST.parent / "package.json").read_text())["version"]
    except (OSError, ValueError, KeyError):
        return None


def run_oracle(cases: "list[dict]") -> "list[dict]":
    """Execute the vendor over *cases* (each ``{"cfg": ..., "env": {...}}``)."""
    from _distgrounding import dist_file
    paths = {k: dist_file(pat, symbol=_WANT[k], contains=needle)
             for k, (pat, needle) in _ANCHORS.items()}
    aliases: "dict[str, str]" = {}
    for k, p in paths.items():
        ex = _exports(p)
        assert _WANT[k] in ex, (
            f"{p.name} no longer exports {_WANT[k]} — re-ground the oracle; do NOT rebind "
            f"by letter. Exports: {sorted(ex)}")
        aliases[_WANT[k]] = ex[_WANT[k]]
    work = Path(tempfile.mkdtemp(prefix="hr-oracle-"))
    try:
        (work / "run.mjs").write_text(_SCRIPT, encoding="utf-8")
        (work / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k != "OPENAI_BASE_URL"}
        env["HOME"] = str(work / "home")
        (work / "home").mkdir()
        proc = subprocess.run(
            ["node", str(work / "run.mjs"), paths["collect"].as_uri(), paths["refs"].as_uri(),
             paths["policy"].as_uri(), paths["parse"].as_uri(), str(work / "cases.json"),
             json.dumps(aliases)],
            capture_output=True, text=True, timeout=600, env=env, cwd=str(work))
        assert proc.returncode == 0, proc.stderr[-2000:]
        line = [ln for ln in proc.stdout.splitlines() if ln.startswith("@@RESULT@@")][-1]
        return json.loads(line[len("@@RESULT@@"):])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def has_node() -> bool:
    return shutil.which("node") is not None


# --------------------------------------------------------------------------------------
# case tables
# --------------------------------------------------------------------------------------
def _agents(defaults=None, entries=None, lst=None) -> dict:
    a: dict = {}
    if defaults is not None:
        a["defaults"] = defaults
    if entries is not None:
        a["entries"] = entries
    if lst is not None:
        a["list"] = lst
    return {"agents": a}


def _case(label, cfg, env=None) -> dict:
    return {"label": label, "cfg": cfg, "env": env or {}}


def hand_cases() -> "list[dict]":
    """Every probe from the triage evidence, plus the shapes that decide soundness."""
    c: "list[dict]" = []
    add = lambda label, cfg, env=None: c.append(_case(label, cfg, env))  # noqa: E731
    add("empty", {})
    add("anthropic-primary", _agents({"model": "anthropic/claude-x"}))
    add("google-primary", _agents({"model": "google/gemini-x"}))
    add("openai-primary", _agents({"model": "openai/gpt-5.6-sol"}))
    add("openai-unknown-model-id", _agents({"model": "openai/zzz-not-a-model"}))
    add("openai-image-model-id", _agents({"model": "openai/gpt-image-1"}))
    add("openai-mixed-case", _agents({"model": "OpenAI/GPT-5"}))
    add("openai-padded", _agents({"model": "  openai/gpt-5  "}))
    add("openai-profile-suffix", _agents({"model": "openai/gpt-5:work"}))
    add("openai-primary-record", _agents({"model": {"primary": "openai/gpt-5"}}))
    add("openai-only-fallback", _agents({"model": {"fallbacks": ["openai/gpt-5"]}}))
    add("anthropic-primary-openai-fallback",
        _agents({"model": {"primary": "anthropic/c", "fallbacks": ["openai/gpt-5"]}}))
    add("openai-codex-provider", _agents({"model": "openai-codex/gpt-5"}))
    add("azure-openai", _agents({"model": "azure/gpt-5"}))
    add("openrouter-openai", _agents({"model": "openrouter/openai/gpt-5"}))
    add("bare-model-no-slash", _agents({"model": "gpt-5"}))
    add("empty-string-model", _agents({"model": ""}))
    add("number-model", _agents({"model": 5}))
    add("models-map-openai-key", _agents({"model": "anthropic/c", "models": {"openai/gpt-5": {}}}))
    add("models-map-anthropic-key", _agents({"model": "anthropic/c", "models": {"anthropic/x": {}}}))
    add("subagents-openai-only", _agents({"model": "anthropic/c", "subagents": {"model": "openai/gpt-5"}}))
    add("heartbeat-openai-only", _agents({"model": "anthropic/c", "heartbeat": {"model": "openai/gpt-5"}}))
    add("imagemodel-openai-only", _agents({"model": "anthropic/c", "imageModel": "openai/gpt-image-1"}))
    add("compaction-openai-only", _agents({"model": "anthropic/c", "compaction": {"model": "openai/gpt-5"}}))
    add("channel-override-openai",
        {**_agents({"model": "anthropic/c"}), "channels": {"modelByChannel": {"tg": {"1": "openai/gpt-5"}}}})
    add("hooks-mapping-openai",
        {**_agents({"model": "anthropic/c"}), "hooks": {"mappings": [{"model": "openai/gpt-5"}]}})
    add("tts-summary-openai", {**_agents({"model": "anthropic/c"}), "tts": {"summaryModel": "openai/gpt-5"}})
    add("exec-reviewer-openai",
        {**_agents({"model": "anthropic/c"}), "tools": {"exec": {"reviewer": {"model": "openai/gpt-5"}}}})
    # roster shapes
    add("entries-openai", _agents({"model": "anthropic/c"}, entries={"a": {"model": "openai/gpt-5"}}))
    add("list-openai", _agents({"model": "anthropic/c"}, lst=[{"id": "a", "model": "openai/gpt-5"}]))
    add("entries-inherit-openai-default", _agents({"model": "openai/gpt-5"}, entries={"a": {}}))
    add("list-inherit-openai-default", _agents({"model": "openai/gpt-5"}, lst=[{"id": "a"}]))
    add("entries-all-anthropic", _agents({"model": "anthropic/c"}, entries={"a": {"model": "anthropic/d"}}))
    add("entries-null-list-openai",
        {"agents": {"entries": None, "list": [{"id": "a", "model": "openai/gpt-5"}],
                    "defaults": {"model": "anthropic/c"}}})
    add("entries-and-list-both", {"agents": {"entries": {"a": {"model": "anthropic/d"}},
                                            "list": [{"id": "b", "model": "openai/gpt-5"}],
                                            "defaults": {"model": "anthropic/c"}}})
    add("entries-agent-no-model-defaults-anthropic",
        _agents({"model": "anthropic/c"}, entries={"a": {}, "b": {"model": "google/g"}}))
    add("entries-agent-no-model-no-defaults", _agents(None, entries={"a": {"model": "anthropic/c"}, "b": {}}))
    add("roster-only-no-defaults", _agents(None, entries={"a": {"model": "anthropic/c"}}))
    # runtime pins, four scopes
    for pin in ("codex", "Codex", " codex-app-server ", "pi", "openclaw", "auto", "default", "", "foo"):
        k = pin.strip() or "empty"
        add(f"pin-provider-{k}", {"models": {"providers": {"anthropic": {"agentRuntime": {"id": pin}}}},
                                  **_agents({"model": "anthropic/c"})})
        add(f"pin-provider-model-{k}", {"models": {"providers": {"anthropic": {
            "models": [{"id": "c", "agentRuntime": {"id": pin}}]}}}, **_agents({"model": "anthropic/c"})})
        add(f"pin-defaults-models-{k}", _agents({"model": "anthropic/c",
                                                 "models": {"anthropic/c": {"agentRuntime": {"id": pin}}}}))
        add(f"pin-agent-models-{k}", _agents({"model": "anthropic/c"}, entries={
            "a": {"models": {"anthropic/c": {"agentRuntime": {"id": pin}}}}}))
        add(f"pin-wholeagent-defaults-{k}", _agents({"model": "anthropic/c", "agentRuntime": {"id": pin}}))
        add(f"pin-openai-provider-{k}", {"models": {"providers": {"openai": {"agentRuntime": {"id": pin}}}},
                                         **_agents({"model": "openai/gpt-5"})})
        add(f"pin-openai-defaults-models-{k}", _agents({"model": "openai/gpt-5",
                                                        "models": {"openai/gpt-5": {"agentRuntime": {"id": pin}}}}))
    add("pin-pi-wildcard", _agents({"model": "openai/gpt-5", "models": {"openai/*": {"agentRuntime": {"id": "pi"}}}}))
    add("pin-codex-wildcard-anthropic", _agents({"model": "anthropic/c", "models": {"anthropic/*": {"agentRuntime": {"id": "codex"}}}}))
    add("pin-agent-pi-defaults-codex", _agents(
        {"model": "openai/gpt-5", "models": {"openai/gpt-5": {"agentRuntime": {"id": "codex"}}}},
        entries={"a": {"models": {"openai/gpt-5": {"agentRuntime": {"id": "pi"}}}}}))
    add("pin-two-provider-entries-ambiguous", _agents(
        {"model": "openai/gpt-5", "models": {"openai/gpt-5": {"agentRuntime": {"id": "pi"}},
                                             "zzz/gpt-5": {"agentRuntime": {"id": "codex"}}}}))
    add("pin-non-string-id", {"models": {"providers": {"anthropic": {"agentRuntime": {"id": 5}}}},
                              **_agents({"model": "anthropic/c"})})
    add("provider-models-not-list", {"models": {"providers": {"anthropic": {"models": {"x": 1}}}},
                                     **_agents({"model": "anthropic/c"})})
    add("provider-models-string", {"models": {"providers": {"anthropic": {"models": "zzz"}}},
                                   **_agents({"model": "anthropic/c"})})
    add("providers-not-record", {"models": {"providers": []}, **_agents({"model": "anthropic/c"})})
    add("provider-entry-null", {"models": {"providers": {"anthropic": None}}, **_agents({"model": "anthropic/c"})})
    # openai route facts
    add("openai-custom-base-url", {"models": {"providers": {"openai": {"baseUrl": "http://localhost:1/v1"}}},
                                   **_agents({"model": "openai/gpt-5"})})
    add("openai-provider-api", {"models": {"providers": {"openai": {"api": "openai-completions"}}},
                                **_agents({"model": "openai/gpt-5"})})
    add("openai-provider-empty-entry", {"models": {"providers": {"openai": {}}}, **_agents({"model": "openai/gpt-5"})})
    add("openai-provider-key-cased", {"models": {"providers": {"OpenAI": {"baseUrl": "http://x/v1"}}},
                                      **_agents({"model": "openai/gpt-5"})})
    add("openai-model-level-baseurl", {"models": {"providers": {"openai": {"models": [
        {"id": "gpt-5", "baseUrl": "http://x/v1"}]}}}, **_agents({"model": "openai/gpt-5"})})
    add("openai-model-level-api", {"models": {"providers": {"openai": {"models": [
        {"id": "gpt-5", "api": "openai-completions"}]}}}, **_agents({"model": "openai/gpt-5"})})
    add("openai-defaults-params", _agents({"model": "openai/gpt-5", "params": {"temperature": 0.2}}))
    add("openai-defaults-params-empty", _agents({"model": "openai/gpt-5", "params": {}}))
    add("openai-model-params", _agents({"model": "openai/gpt-5", "models": {"openai/gpt-5": {"params": {"temperature": 1}}}}))
    add("openai-model-params-runtime-key", _agents({"model": "openai/gpt-5",
                                                    "models": {"openai/gpt-5": {"params": {"thinking": "low"}}}}))
    add("openai-agent-params", _agents({"model": "anthropic/c"}, entries={"a": {"model": "openai/gpt-5",
                                                                                "params": {"temperature": 1}}}))
    add("openai-env-base-url-custom", _agents({"model": "openai/gpt-5"}), {"OPENAI_BASE_URL": "http://localhost:9/v1"})
    add("openai-env-base-url-platform", _agents({"model": "openai/gpt-5"}),
        {"OPENAI_BASE_URL": "https://api.openai.com/v1"})
    add("openai-env-base-url-empty", _agents({"model": "openai/gpt-5"}), {"OPENAI_BASE_URL": ""})
    add("openai-env-block-in-config", {**_agents({"model": "openai/gpt-5"}),
                                      "env": {"OPENAI_BASE_URL": "http://localhost:9/v1"}})
    add("anthropic-with-env-base-url", _agents({"model": "anthropic/c"}), {"OPENAI_BASE_URL": "http://x/v1"})
    add("agent-scoped-runtime-agent", _agents({"model": "openai/gpt-5"}, entries={"a": {"agentRuntime": {"id": "pi"}}}))
    add("agent-scoped-runtime-defaults-pi", _agents({"model": "openai/gpt-5", "agentRuntime": {"id": "pi"}}))
    add("agent-scoped-runtime-defaults-codex", _agents({"model": "anthropic/c", "agentRuntime": {"id": "codex"}}))
    add("agents-not-record", {"agents": []})
    add("agents-string", {"agents": "x"})
    add("defaults-model-list", _agents({"model": ["openai/gpt-5"]}))
    add("entries-value-not-record", _agents({"model": "anthropic/c"}, entries={"a": "x"}))
    add("list-with-null", _agents({"model": "anthropic/c"}, lst=[None, {"id": "b", "model": "openai/gpt-5"}]))
    add("discord-voice-openai", {**_agents({"model": "anthropic/c"}),
                                 "channels": {"discord": {"voice": {"model": "openai/gpt-5"}}}})
    add("params-null", _agents({"model": "openai/gpt-5", "params": None}))
    add("params-null-with-codex-pin", _agents({"model": "openai/gpt-5", "params": None,
                                               "models": {"openai/gpt-5": {"agentRuntime": {"id": "codex"}}}}))
    add("provider-two-spellings", {"models": {"providers": {" openai ": {}, "openai": None}},
                                   **_agents({"model": "openai/gpt-5"})})
    add("media-preferred-openai", {**_agents({"model": "anthropic/c"}),
                                   "tools": {"media": {"image": {"preferredModel": "openai/gpt-image-1"}}}})
    return c


def grammar_cases() -> "list[dict]":
    """provider x pin x pin-scope x roster shape, generated rather than hand-picked."""
    providers = ("anthropic", "openai", "openai-codex", "google")
    pins = (None, "codex", "pi", "auto", "foo")
    shapes = ("flat", "entries", "list")
    out: "list[dict]" = []
    for prov in providers:
        ref = f"{prov}/m1"
        for pin in pins:
            for scope in ("none", "provider", "defmodels", "agentmodels"):
                if pin is None and scope != "none":
                    continue
                if pin is not None and scope == "none":
                    continue
                for shape in shapes:
                    if scope == "agentmodels" and shape == "flat":
                        continue
                    pinobj = {"agentRuntime": {"id": pin}} if pin is not None else None
                    cfg: dict = {}
                    defaults: dict = {"model": ref}
                    if scope == "provider":
                        cfg["models"] = {"providers": {prov: dict(pinobj)}}
                    if scope == "defmodels":
                        defaults["models"] = {ref: dict(pinobj)}
                    agent: dict = {"model": ref}
                    if scope == "agentmodels":
                        agent["models"] = {ref: dict(pinobj)}
                    if shape == "flat":
                        cfg.update(_agents(defaults))
                    elif shape == "entries":
                        cfg.update(_agents(defaults, entries={"a": agent}))
                    else:
                        cfg.update(_agents(defaults, lst=[{"id": "a", **agent}]))
                    out.append(_case(f"grammar:{prov}:{pin}:{scope}:{shape}", cfg))
    # heterogeneous rosters: primary provider per agent
    for d in ("anthropic", "openai"):
        for a in ("anthropic", "openai", None):
            for shape in ("entries", "list"):
                agent = {"model": f"{a}/m"} if a else {}
                cfg = (_agents({"model": f"{d}/m"}, entries={"x": agent}) if shape == "entries"
                       else _agents({"model": f"{d}/m"}, lst=[{"id": "x", **agent}]))
                out.append(_case(f"grammar-roster:{d}:{a}:{shape}", cfg))
    return out


def fuzz_cases(seed: int = 20260918, n: int = 400) -> "list[dict]":
    """Seeded random configs over the whole grammar (roster shapes, pins, malformed values).

    Pinned at a small size; the live differential can be run at any size with a different
    seed -- 50,000 configs across five seeds were run against the dist while building this
    with zero soundness disagreements."""
    import random
    R = random.Random(seed)
    provs = ["openai", "anthropic", "google", "OpenAI", " openai ", "openai-codex", "azure", "x", "openai:w"]
    mods = ["m", "gpt-5", "gpt-5.6-sol", "gpt-image-1", "*", "m:work", "o3", "codex-mini"]
    pinv = ["codex", "pi", "openclaw", "auto", "default", "", "foo", "Codex-App-Server", None, 5]


    def ref():
        r = R.random()
        if r < .06:
            return R.choice(["gpt-5", "alias", "", 5, None, "/x", "x/"])
        return f"{R.choice(provs)}/{R.choice(mods)}"


    def selector():
        r = R.random()
        if r < .5:
            return ref()
        if r < .75:
            return {"primary": ref(), "fallbacks": [ref() for _ in range(R.randint(0, 2))]}
        if r < .9:
            return {"fallbacks": [ref()]}
        return R.choice([None, [], 5, {}])


    def pin():
        v = R.choice(pinv)
        return {"agentRuntime": {"id": v}} if R.random() < .9 else {"agentRuntime": R.choice([None, "x", 5, []])}


    def agentcfg():
        a = {}
        if R.random() < .8:
            a["model"] = selector()
        if R.random() < .15:
            a["subagents"] = {"model": selector()}
        if R.random() < .1:
            a["heartbeat"] = {"model": ref()}
        if R.random() < .1:
            a["imageModel"] = selector()
        if R.random() < .2:
            a["models"] = {}
            for _ in range(R.randint(1, 2)):
                k = ref()
                a["models"][k if isinstance(k, str) and k else "x/y"] = pin() if R.random() < .5 else {}
        if R.random() < .1:
            a["params"] = R.choice([{}, {"temperature": 1}, None, 5])
        if R.random() < .05:
            a["agentRuntime"] = {"id": R.choice(pinv[:8])}
        if R.random() < .05 and a.get("models"):
            k = list(a["models"])[0]
            a["models"][k] = {"params": R.choice([{}, {"a": 1}, {"thinking": "low"}])}
        return a


    def cfg():
        c = {}
        ag = {}
        if R.random() < .85:
            ag["defaults"] = agentcfg()
        s = R.random()
        if s < .35:
            ag["entries"] = {R.choice("abc"): agentcfg() for _ in range(R.randint(0, 3))}
        elif s < .7:
            ag["list"] = [dict(agentcfg(), id=R.choice("abc")) for _ in range(R.randint(0, 3))]
        elif s < .75:
            ag["entries"] = None
            ag["list"] = [{"id": "z"}]
        if R.random() < .05:
            ag = R.choice([[], "x", 5])
        c["agents"] = ag
        if R.random() < .35:
            pr = {}
            for _ in range(R.randint(1, 3)):
                p = {}
                if R.random() < .5:
                    p.update(pin())
                if R.random() < .3:
                    p["models"] = []
                    for _ in range(R.randint(0, 2)):
                        m = {"id": R.choice(mods)}
                        if R.random() < .5:
                            m.update(pin())
                        if R.random() < .2:
                            m["baseUrl"] = "http://x"
                        p["models"].append(m)
                if R.random() < .15:
                    p["baseUrl"] = "http://x/v1"
                if R.random() < .1:
                    p["api"] = "openai-completions"
                pr[R.choice(provs)] = p if R.random() < .95 else None
            c["models"] = {"providers": pr}
        if R.random() < .1:
            c["channels"] = {"modelByChannel": {"tg": {"1": ref()}}}
        if R.random() < .05:
            c["tts"] = {"summaryModel": ref()}
        if R.random() < .05:
            c["env"] = {"OPENAI_BASE_URL": "http://x"}
        return c


    out = []
    for i in range(n):
        env = ({"OPENAI_BASE_URL": R.choice(["", "http://x/v1", "https://api.openai.com/v1"])}
               if R.random() < .05 else {})
        out.append(_case(f"fuzz:{i}", cfg(), env))
    return out


_KEEP_TOP = ("agents", "models", "tools", "channels", "hooks", "tts", "env")


def prune(cfg) -> dict:
    """The slice of a config the vendor functions (and the port) can read. Keeps corpus rows
    self-contained in the battery, so a later edit to a shared fixture cannot silently
    change what a pinned row asserts."""
    if not isinstance(cfg, dict):
        return {}
    out: dict = {}
    for k in _KEEP_TOP:
        if k not in cfg:
            continue
        v = cfg[k]
        if k == "tools" and isinstance(v, dict):
            v = {kk: vv for kk, vv in v.items() if kk in ("exec", "media")}
            if isinstance(v.get("exec"), dict):
                v["exec"] = {kk: vv for kk, vv in v["exec"].items() if kk == "reviewer"}
        if k == "channels" and isinstance(v, dict):
            v = {kk: vv for kk, vv in v.items() if kk in ("modelByChannel", "discord")}
        if k == "hooks" and isinstance(v, dict):
            v = {kk: vv for kk, vv in v.items() if kk in ("mappings", "gmail")}
        out[k] = v
    return out


def corpus_cases() -> "list[dict]":
    from clawseccheck import configloader
    seen: "dict[str, str]" = {}
    out: "list[dict]" = []
    for d in sorted(FIXTURES.iterdir()):
        p = d / "openclaw.json"
        if not p.is_file():
            continue
        try:
            cfg = configloader.loads_json5(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(cfg, dict) or not cfg:
            continue
        pr = prune(cfg)
        key = json.dumps(pr, sort_keys=True)
        if key in seen:
            continue
        seen[key] = d.name
        out.append(_case(f"fixture:{d.name}", pr))
    return out


def all_cases() -> "list[dict]":
    cases = hand_cases() + grammar_cases() + fuzz_cases() + corpus_cases()
    labels = [c["label"] for c in cases]
    assert len(labels) == len(set(labels)), "duplicate case labels"
    return cases


def battery_digest(cases) -> str:
    return hashlib.sha256(json.dumps(
        [(c["label"], c["cfg"], c["env"]) for c in cases], sort_keys=True).encode()).hexdigest()


def write_battery() -> None:
    assert has_node(), "node is required to regenerate the battery"
    ver = dist_version()
    assert ver == ORACLE_BUILD, (
        f"installed OpenClaw is {ver}, the battery is pinned to {ORACLE_BUILD}. Re-baseline "
        f"deliberately: bump ORACLE_BUILD and harnessruntime._ORACLE_MIN together.")
    cases = all_cases()
    results = run_oracle(copy.deepcopy(cases))
    rows = []
    for c, r in zip(cases, results):
        rows.append({"label": c["label"], "cfg": c["cfg"], "env": c["env"], "oracle": r})
    BATTERY_PATH.parent.mkdir(exist_ok=True)
    BATTERY_PATH.write_text(json.dumps({"build": ver, "rows": rows}, indent=1) + "\n",
                            encoding="utf-8")
    print(f"wrote {len(rows)} rows for openclaw {ver} -> {BATTERY_PATH}")


if __name__ == "__main__":
    if "--write" in sys.argv:
        write_battery()
    else:
        print(__doc__)
