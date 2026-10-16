"""The vendor oracle and the case tables for ``clawseccheck/retiredformats.py``.

TEST-ONLY. This module shells out to ``node``; the shipped runtime never does.

WHAT IT ANSWERS. "Which retired config formats does OpenClaw ITSELF name in this
``openclaw.json``?" -- asked by executing the installed build's own
``findRetiredConfigUpgradeRequirement`` (bound by its real export name, never by the
minified alias letter, which rotates per build). The function returns ``undefined`` or a
``{message, nextAction}`` pair; the paths are inside the message and the bridge release is
inside the next action, so the battery pins BOTH strings verbatim and the replay
reassembles them from the port, rather than parsing a join that agent ids can make
ambiguous.

THREE CASE POPULATIONS (``all_cases``), all replayed offline from
``tests/data/retiredformats_battery.json``:

* ``one:`` rows -- one config per path the finder names (``FINDER_PATHS``, the explicit
  ledger "every path the installed finder names"). The generator asserts the vendor answers
  EXACTLY that one path for each, so a ledger row that stops firing is a generation error,
  not a silent pass.
* ``near:`` rows -- hand-built benign near-misses and shape traps: a key on the wrong scope,
  a retired key's neighbour, a non-record parent of every kind, a roster in both shapes, the
  prototype-key ids, integer-like key ordering, the two ``bridgeVersion`` outcomes.
* ``fuzz:`` rows -- a seeded grammar that merges the ``one:`` rows, scrambles intermediate
  nodes into junk and rewrites rosters, to reach combinations nobody wrote by hand.

``finder_sha256`` and ``vocabulary`` are recorded in the battery header. The digest covers
the finder's own region, the three traversal helpers and the two small helpers they import
(``isRecord``, the blocked-key set), so ANY vendor change to the function turns the live
grounding test red even if it only recombines key names the ledger already knows; the
vocabulary (every key name and retired value the finder mentions) says WHICH name is new.

Regenerate the pinned battery with ``python3.12 tests/_retiredformatsoracle.py --write``. It
needs node and the matching OpenClaw installed and rewrites
``tests/data/retiredformats_battery.json``.
"""
from __future__ import annotations

import copy
import hashlib
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

BATTERY_PATH = HERE / "data" / "retiredformats_battery.json"

#: The build the battery was generated against (recorded in the battery header).
ORACLE_BUILD = "2026.10.4"

_FINDER = "findRetiredConfigUpgradeRequirement"

# --------------------------------------------------------------------------------------
# node side
# --------------------------------------------------------------------------------------
_SCRIPT = r"""
import { readFileSync } from "node:fs";
const [, , finderMod, alias, casesPath] = process.argv;
const find = (await import(finderMod))[alias];
const cases = JSON.parse(readFileSync(casesPath, "utf8"));
const out = [];
for (const c of cases) {
  let rec;
  try {
    const r = find(c.cfg);
    rec = r === undefined ? null : { message: r.message, nextAction: r.nextAction };
  } catch (e) {
    rec = { error: String((e && e.message) || e).slice(0, 200) };
  }
  out.push(rec);
}
console.log("@@RESULT@@" + JSON.stringify(out));
"""


def _exports(path: Path) -> "dict[str, str]":
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


def finder_bundle() -> Path:
    """The ONE bundle that declares the finder (the sibling ``retired-config-formats-*``
    file only re-exports it)."""
    from _distgrounding import dist_declaring
    return dist_declaring(f"function {_FINDER}(", symbol=_FINDER)


def _region(text: str) -> str:
    """The text of the first ``//#region`` ... ``//#endregion`` block of a bundle."""
    start = text.index("//#region")
    return text[start:text.index("//#endregion", start)]


def _function_text(text: str, name: str) -> str:
    m = re.search(rf"^function {re.escape(name)}\(.*?\n}}\n", text, re.M | re.S)
    assert m, f"function {name} not found"
    return m.group(0)


def vendor_sources() -> "dict[str, str]":
    """The vendor text this port depends on, keyed by what it is. ``dist_file`` /
    ``dist_declaring`` fail loudly (never skip) on a present dist whose anchors moved."""
    from _distgrounding import dist_declaring, dist_file
    finder = finder_bundle().read_text(encoding="utf-8")
    shared = dist_declaring("function visitChannelEntries(", symbol="visitChannelEntries")
    shared_text = shared.read_text(encoding="utf-8")
    record = dist_file("record-coerce-*.mjs", symbol="isRecord",
                       contains="function isRecord(").read_text(encoding="utf-8")
    blocked = dist_file("prototype-keys-*.mjs", symbol="BLOCKED_OBJECT_KEYS",
                        contains="BLOCKED_OBJECT_KEYS").read_text(encoding="utf-8")
    return {
        "finder": _region(finder),
        "visitAgentEntries": _function_text(shared_text, "visitAgentEntries"),
        "visitAgentConfigScopes": _function_text(shared_text, "visitAgentConfigScopes"),
        "visitChannelEntries": _function_text(shared_text, "visitChannelEntries"),
        "isRecord": _function_text(record, "isRecord"),
        "blockedKeys": _region(blocked),
    }


def finder_digest() -> str:
    src = vendor_sources()
    blob = "\n@@\n".join(f"{k}\n{src[k]}" for k in sorted(src))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def vendor_vocabulary() -> "list[str]":
    """Every key name / retired value the finder's detection body mentions: its double-quoted
    literals plus the identifier words inside its template literals (``surfaces.${id}`` ->
    ``surfaces``), minus the closing ``return {message, nextAction}`` block (prose)."""
    body = vendor_sources()["finder"]
    body = body[:body.index("if (retired.length === 0) return;")]
    words: "set[str]" = set()
    for lit in re.findall(r'"([^"\\\n]*)"', body):
        words.add(lit)
    for tpl in re.findall(r"`([^`]*)`", body):
        for piece in re.split(r"\$\{[^}]*\}", tpl):
            words.update(re.findall(r"[A-Za-z][A-Za-z0-9-]*", piece))
    return sorted(words)


def run_oracle(cases: "list[dict]") -> "list[dict | None]":
    """Execute the vendor over *cases* (each ``{"cfg": ...}``); one record per case."""
    path = finder_bundle()
    ex = _exports(path)
    assert _FINDER in ex, (
        f"{path.name} no longer exports {_FINDER} -- re-ground the oracle; do NOT rebind "
        f"by letter. Exports: {sorted(ex)}")
    # tempfile.mkdtemp, not tmp_path: this module doubles as a standalone CLI
    # (`python3.12 tests/_retiredformatsoracle.py --write`) run OUTSIDE pytest.
    work = Path(tempfile.mkdtemp(prefix="rf-oracle-"))
    try:
        (work / "run.mjs").write_text(_SCRIPT, encoding="utf-8")
        (work / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
        proc = subprocess.run(
            ["node", str(work / "run.mjs"), path.as_uri(), ex[_FINDER],
             str(work / "cases.json")],
            capture_output=True, text=True, timeout=600, cwd=str(work))
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
def nest(segments: "list", value) -> dict:
    """``["a", "b", "c"], v`` -> ``{"a": {"b": {"c": v}}}``."""
    node = value
    for seg in reversed(segments):
        node = {seg: node}
    return node


def merge(into: dict, other: dict) -> dict:
    for key, value in other.items():
        if isinstance(value, dict) and isinstance(into.get(key), dict):
            merge(into[key], value)
        else:
            into[key] = copy.deepcopy(value)
    return into


_AGENT_KEYS = ["systemPromptOverride", "silentReplyRewrite", "embeddedPi", "embeddedHarness",
               "agentRuntime"]
_AGENT_NESTED = [["sandbox", "perSession"], ["silentReply", "direct"], ["model", "timeoutMs"],
                 ["subagents", "model", "timeoutMs"], ["memorySearch", "store", "path"],
                 ["memory", "search", "store", "path"]]
_QUEUE_MODES = ["queue", "steer-backlog", "steer+backlog"]


def _finder_paths() -> "list[tuple[str, dict, str]]":
    """(label, config, the ONE path the vendor must answer) for every path the finder names.
    This is the explicit ledger; ``all_cases`` and the live grounding test both read it."""
    rows: "list[tuple[str, dict, str]]" = []

    def add(segments, value, expected=None, label=None, prefix_cfg=None):
        cfg = nest(segments, value)
        path = expected or ".".join(str(s) for s in segments)
        rows.append((label or path, cfg, path))

    for seg in (["heartbeat"], ["routing", "allowFrom"], ["routing", "groupChat"],
                ["plugins", "installs"], ["browser", "relayBindHost"],
                ["browser", "ssrfPolicy", "allowPrivateNetwork"],
                ["memorySearch", "store", "path"], ["memory", "search", "store", "path"],
                ["session", "parentForkMaxTokens"], ["session", "threadBindings", "ttlHours"],
                ["agents", "defaults", "llm"], ["gateway", "webchat"], ["channels", "webchat"],
                ["channels", "telegram", "requireMention"],
                ["channels", "telegram", "groupMentionsOnly"]):
        add(seg, "x")
    for scope in (["agents", "defaults"], ["agents", "entries", "main"]):
        for key in _AGENT_KEYS:
            add(scope + [key], {"id": "x"})
        for nested in _AGENT_NESTED:
            add(scope + nested, "x")
    # the legacy roster shape: the path is `agents.list[0].<key>`
    for key in _AGENT_KEYS:
        rows.append((f"agents.list[0].{key}",
                     {"agents": {"list": [{"id": "main", key: {"id": "x"}}]}},
                     f"agents.list[0].{key}"))
    for nested in _AGENT_NESTED:
        rows.append(("agents.list[0]." + ".".join(nested),
                     {"agents": {"list": [{"id": "main", **nest(nested, "x")}]}},
                     "agents.list[0]." + ".".join(nested)))
    add(["surfaces", "web", "silentReplyRewrite"], "x")
    add(["surfaces", "web", "silentReply", "direct"], "x")
    for mode in _QUEUE_MODES:
        add(["messages", "queue", "mode"], mode, label=f"messages.queue.mode={mode}")
        add(["messages", "queue", "byChannel", "slack"], mode,
            label=f"messages.queue.byChannel.slack={mode}")
    for key in ("mode", "transport", "brain", "model", "voice"):
        add(["talk", key], "x")

    def channel_scopes(channel):
        return [["channels", channel], ["channels", channel, "accounts", "work"]]

    for scope in channel_scopes("whatsapp"):
        add(scope + ["exposeErrorText"], True)
    for scope in channel_scopes("discord"):
        for key in ("openai", "elevenlabs", "microsoft", "edge"):
            add(scope + ["voice", "tts", key], {})
        for key in ("allow", "agentId"):
            add(scope + ["guilds", "g1", "channels", "c1", key], "x")
    for scope in channel_scopes("telegram"):
        for key in ("streamMode", "chunkMode", "blockStreaming", "blockStreamingCoalesce",
                    "draftChunk"):
            add(scope + [key], "x")
        add(scope + ["dm"], {"policy": "open"})
        add(scope + ["streaming"], True, label=".".join(scope) + ".streaming=true")
        add(scope + ["streaming"], "partial", label=".".join(scope) + ".streaming=string")
        for key in ("nativeToolProgress", "nativeToolProgressAllowFrom"):
            add(scope + ["streaming", "preview", key], True)
        add(scope + ["direct", "chat1", "threadReplies"], True)
    for scope in channel_scopes("nextcloud-talk"):
        add(scope + ["allowPrivateNetwork"], True)
    for scope in channel_scopes("matrix"):
        add(scope + ["allowPrivateNetwork"], True)
        add(scope + ["dm", "policy"], "trusted")
        for section in ("groups", "rooms"):
            add(scope + [section, "r1", "allow"], True)
    for scope in channel_scopes("slack"):
        add(scope + ["channels", "c1", "allow"], True)
    for channel in ("discord", "line", "matrix", "telegram"):
        for scope in channel_scopes(channel):
            add(scope + ["threadBindings", "ttlHours"], 24)
    add(["channels", "feishu", "accounts", "work", "botName"], "x")
    return rows


FINDER_PATHS = _finder_paths()


def _near_cases() -> "list[tuple[str, dict]]":
    rows: "list[tuple[str, dict]]" = []

    def add(label, cfg):
        rows.append((f"near:{label}", cfg))

    add("empty", {})
    add("benign-live-config", {
        "agents": {"defaults": {"model": {"primary": "anthropic/x"}, "workspace": "w"},
                   "entries": {"main": {"tools": {"profile": "minimal"}}}},
        "messages": {"queue": {"mode": "collect", "byChannel": {"slack": "followup"}}},
        "talk": {"realtime": {"model": "m"}}, "session": {"scope": "main"},
        "channels": {"telegram": {"botToken": "x", "streaming": {"mode": "partial"}},
                     "matrix": {"dm": {"policy": "allowlist"}}}})
    # non-record roots and parents of every kind
    for junk_label, junk in (("null", None), ("list", []), ("str", "x"), ("num", 0),
                             ("true", True), ("empty-obj", {})):
        add(f"top-level-{junk_label}", {"routing": junk, "plugins": junk, "browser": junk,
                                        "talk": junk, "gateway": junk, "session": junk,
                                        "messages": junk, "surfaces": junk, "channels": junk,
                                        "agents": junk, "memory": junk, "memorySearch": junk})
        add(f"ssrf-parent-{junk_label}", {"browser": {"ssrfPolicy": junk}})
        add(f"channel-{junk_label}", {"channels": {k: junk for k in (
            "telegram", "discord", "matrix", "slack", "whatsapp", "feishu", "line")}})
        add(f"accounts-{junk_label}", {"channels": {"telegram": {"accounts": junk}}})
        add(f"account-entry-{junk_label}", {"channels": {"telegram": {"accounts": {"a": junk}}}})
        add(f"entries-{junk_label}", {"agents": {"entries": junk,
                                                 "list": [{"id": "a", "agentRuntime": 1}]}})
        add(f"list-{junk_label}", {"agents": {"list": junk}})
        add(f"defaults-{junk_label}", {"agents": {"defaults": junk}})
        add(f"entry-{junk_label}", {"agents": {"entries": {"a": junk}}})
        add(f"queue-{junk_label}", {"messages": {"queue": junk}})
        add(f"bychannel-{junk_label}", {"messages": {"queue": {"byChannel": junk}}})
        add(f"memory-search-{junk_label}", {"memory": {"search": junk}, "memorySearch": {"store": junk}})
        add(f"subagents-{junk_label}", {"agents": {"defaults": {"subagents": junk}}})
        add(f"guilds-{junk_label}", {"channels": {"discord": {"guilds": junk}}})
        add(f"guild-{junk_label}", {"channels": {"discord": {"guilds": {"g": junk}}}})
        add(f"guild-channels-{junk_label}",
            {"channels": {"discord": {"guilds": {"g": {"channels": junk}}}}})
        add(f"voice-{junk_label}", {"channels": {"discord": {"voice": junk}}})
        add(f"dm-{junk_label}", {"channels": {"telegram": {"dm": junk}, "matrix": {"dm": junk}}})
        add(f"streaming-{junk_label}", {"channels": {"telegram": {"streaming": junk}}})
        add(f"direct-{junk_label}", {"channels": {"telegram": {"direct": junk}}})
        add(f"matrix-groups-{junk_label}", {"channels": {"matrix": {"groups": junk,
                                                                     "rooms": {"r": junk}}}})
        add(f"slack-channels-{junk_label}", {"channels": {"slack": {"channels": junk}}})
        add(f"thread-bindings-{junk_label}", {"channels": {"discord": {"threadBindings": junk}},
                                              "session": {"threadBindings": junk}})
    # present-but-empty values still count (Object.hasOwn), absent keys do not
    for value in (None, False, "", 0, [], {}):
        add(f"present-value-{json.dumps(value)}", {"heartbeat": value,
                                                   "agents": {"defaults": {"agentRuntime": value}}})
    # near-misses that must NOT fire
    add("heartbeat-lookalikes", {"heartbeats": 1, "Heartbeat": 1, "agents": {
        "defaults": {"heartbeat": {"every": "5m"}}}})
    add("queue-case-and-space", {"messages": {"queue": {"mode": "Queue", "byChannel": {
        "a": "queue ", "b": " queue", "c": "steer_backlog", "d": ["queue"], "e": 1, "f": None,
        "g": {"mode": "queue"}}}}})
    add("queue-mode-non-string", {"messages": {"queue": {"mode": ["queue"]}}})
    add("matrix-dm-policy-near", {"channels": {"matrix": {"dm": {"policy": "Trusted"}}}})
    add("matrix-dm-policy-non-string", {"channels": {"matrix": {"dm": {"policy": ["trusted"]}}}})
    add("feishu-root-botname-exempt", {"channels": {"feishu": {"botName": "x"}}})
    add("feishu-account-botname", {"channels": {"feishu": {"botName": "x", "accounts": {
        "a": {"botName": "y"}, "b": {}}}}})
    add("agent-key-at-root", {"agentRuntime": {"id": "codex"}, "embeddedPi": 1,
                              "systemPromptOverride": "x"})
    add("agent-key-on-surface", {"surfaces": {"w": {"agentRuntime": 1, "embeddedPi": 1}}})
    add("channel-key-on-wrong-channel", {"channels": {"slack": {"streamMode": "x",
                                                                 "requireMention": True,
                                                                 "exposeErrorText": True}}})
    add("telegram-streaming-number-and-null", {"channels": {"telegram": {
        "streaming": 1, "accounts": {"a": {"streaming": None}, "b": {"streaming": []}}}}})
    add("talk-near", {"talk": {"realtime": {"mode": "x"}, "providers": {}, "modeX": 1}})
    add("session-near", {"session": {"parentFork": 1, "parentForkMaxTokensX": 1}})
    add("browser-near", {"browser": {"relayBindHostX": 1, "ssrfPolicy": {
        "dangerouslyAllowPrivateNetwork": True, "allowedHostnames": []}}})
    add("sandbox-perSession-on-defaults-only-via-scope",
        {"agents": {"defaults": {"sandbox": {"mode": "all", "perSessionX": 1}}}})
    # roster shapes
    add("entries-wins-over-list", {"agents": {"entries": {"a": {}},
                                              "list": [{"id": "b", "agentRuntime": 1}]}})
    add("empty-entries-hides-list", {"agents": {"entries": {},
                                                "list": [{"id": "b", "agentRuntime": 1}]}})
    add("list-index-and-non-record", {"agents": {"list": [None, "x", [], {"agentRuntime": 1},
                                                          {"id": 5, "embeddedPi": 1}]}})
    add("list-blocked-ids", {"agents": {"list": [{"id": "__proto__", "agentRuntime": 1},
                                                 {"id": "constructor", "agentRuntime": 1},
                                                 {"id": "prototype", "agentRuntime": 1},
                                                 {"id": "ok", "agentRuntime": 1}]}})
    add("entries-blocked-ids", {"agents": {"entries": {"__proto__": {"agentRuntime": 1},
                                                       "constructor": {"agentRuntime": 1},
                                                       "prototype": {"agentRuntime": 1},
                                                       "proto": {"agentRuntime": 1}}}})
    add("entries-dotted-and-odd-ids", {"agents": {"entries": {
        "a.b": {"embeddedPi": 1}, "": {"embeddedPi": 1}, "a, b": {"embeddedPi": 1},
        "ünï": {"embeddedPi": 1}}}})
    add("defaults-and-entries-and-main", {"agents": {
        "defaults": {"agentRuntime": 1}, "entries": {"main": {"agentRuntime": 1}}}})
    # key-order fidelity (Object.entries sorts array-index keys first)
    add("integer-like-surface-order", {"surfaces": {"b": {"silentReplyRewrite": 1},
                                                    "10": {"silentReplyRewrite": 1},
                                                    "2": {"silentReplyRewrite": 1},
                                                    "01": {"silentReplyRewrite": 1},
                                                    "-1": {"silentReplyRewrite": 1},
                                                    "4294967294": {"silentReplyRewrite": 1},
                                                    "4294967295": {"silentReplyRewrite": 1},
                                                    "1.5": {"silentReplyRewrite": 1},
                                                    "a": {"silentReplyRewrite": 1}}})
    add("integer-like-entries-order", {"agents": {"entries": {
        "z": {"embeddedPi": 1}, "9": {"embeddedPi": 1}, "100": {"embeddedPi": 1},
        "0": {"embeddedPi": 1}}}})
    add("integer-like-accounts-order", {"channels": {"telegram": {"accounts": {
        "b": {"streamMode": 1}, "3": {"streamMode": 1}, "1": {"streamMode": 1}}}}})
    add("huge-integer-like-key", {"surfaces": {"9" * 5000: {"silentReplyRewrite": 1},
                                               "1": {"silentReplyRewrite": 1}}})
    add("report-order-follows-the-finder-not-the-config", {
        "session": {"parentForkMaxTokens": 1}, "talk": {"voice": 1, "mode": 1},
        "heartbeat": 1, "channels": {"telegram": {"streamMode": 1}, "webchat": 1},
        "routing": {"groupChat": 1, "allowFrom": 1}})
    # bridgeVersion: 2026.9.7 only when the Discord visit added something
    add("bridge-default", {"heartbeat": 1})
    add("bridge-discord-tts", {"channels": {"discord": {"voice": {"tts": {"edge": {}}}}}})
    add("bridge-discord-guild-allow", {"channels": {"discord": {"guilds": {"g": {"channels": {
        "c": {"allow": True}}}}}}})
    add("bridge-discord-only-thread-bindings", {"channels": {"discord": {
        "threadBindings": {"ttlHours": 1}}}})
    add("bridge-discord-and-earlier-key", {"heartbeat": 1, "whatsappish": 1, "channels": {
        "whatsapp": {"exposeErrorText": True},
        "discord": {"accounts": {"a": {"guilds": {"g": {"channels": {"c": {"agentId": "x"}}}}}}}}})
    add("bridge-key-after-discord-only", {"channels": {"discord": {}, "telegram": {
        "streamMode": 1}, "matrix": {"allowPrivateNetwork": True}}})
    add("bridge-earlier-key-only-with-empty-discord", {"heartbeat": 1, "channels": {
        "discord": {"voice": {"tts": {}}, "guilds": {"g": {"channels": {"c": {}}}}}}})
    # an unrelated top-level config the loader might hand over
    everything: dict = {}
    for _label, cfg, path in FINDER_PATHS:
        if "list[" not in path:
            merge(everything, cfg)
    add("everything-at-once", everything)
    return rows


def _random_junk(rng: random.Random):
    return rng.choice([None, [], "x", 0, True, {}, [1, 2], {"a": 1}])


def _scramble(node, rng: random.Random, rate: float):
    """Replace some dict values (at any depth) with junk; keep keys and structure otherwise."""
    if isinstance(node, dict):
        out = {}
        keys = list(node)
        rng.shuffle(keys)
        for key in keys:
            value = node[key]
            if rng.random() < rate:
                out[key] = _random_junk(rng)
            else:
                out[key] = _scramble(value, rng, rate)
        return out
    if isinstance(node, list):
        return [_scramble(v, rng, rate) for v in node]
    return node


def _fuzz_cases(count: int = 700) -> "list[tuple[str, dict]]":
    rng = random.Random(20261012)
    pool = [cfg for _label, cfg, path in FINDER_PATHS]
    rows = []
    for i in range(count):
        cfg: dict = {}
        for _ in range(rng.randint(1, 6)):
            merge(cfg, copy.deepcopy(rng.choice(pool)))
        for _ in range(rng.randint(0, 3)):
            merge(cfg, rng.choice([
                {"agents": {"entries": {"extra": {"embeddedPi": 1}}}},
                {"channels": {"telegram": {"accounts": {"x": {"streamMode": 1}}}}},
                {"messages": {"queue": {"mode": rng.choice(_QUEUE_MODES + ["collect"])}}},
                {"surfaces": {"s2": {"silentReply": {"direct": 1}}, "3": {}, "1": {}}},
                {"channels": {"discord": {"guilds": {"g2": {"channels": {"c2": {"allow": 1}}}}}}},
            ]))
        cfg = _scramble(cfg, rng, rng.choice([0.0, 0.05, 0.15, 0.3]))
        if rng.random() < 0.2:
            agents = cfg.setdefault("agents", {})
            if isinstance(agents, dict):
                agents["entries"] = rng.choice([None, [], "x", {}])
                agents["list"] = [{"id": rng.choice(["main", "__proto__", 7]),
                                   "agentRuntime": 1, "sandbox": {"perSession": 1}}]
        rows.append((f"fuzz:{i:04d}", cfg))
    return rows


def all_cases() -> "list[dict]":
    cases = [{"label": f"one:{label}", "cfg": cfg, "expect": [path]}
             for label, cfg, path in FINDER_PATHS]
    cases += [{"label": label, "cfg": cfg, "expect": None} for label, cfg in _near_cases()]
    cases += [{"label": label, "cfg": cfg, "expect": None} for label, cfg in _fuzz_cases()]
    return cases


# --------------------------------------------------------------------------------------
# vendor record -> (paths, bridge) and battery IO
# --------------------------------------------------------------------------------------
_MSG_PREFIX = "Config contains retired pre-July-2026 settings: "
_MSG_SUFFIX = ". Doctor cannot remove these settings safely."
_BRIDGE_RE = re.compile(r'^Install OpenClaw (\S+), run "')


def reassemble_message(paths) -> str:
    """The vendor's ``message`` for *paths* (the sentence the port deliberately does not carry)."""
    return _MSG_PREFIX + ", ".join(paths) + _MSG_SUFFIX


def bridge_of(next_action: str) -> str:
    m = _BRIDGE_RE.match(next_action)
    assert m, next_action
    return m.group(1)


def write_battery() -> None:
    assert has_node(), "node is required to regenerate the battery"
    ver = dist_version()
    assert ver == ORACLE_BUILD, (
        f"installed OpenClaw is {ver}, the battery is pinned to {ORACLE_BUILD}. Re-baseline "
        f"deliberately: bump ORACLE_BUILD here, then diff the regenerated rows before moving "
        f"retiredformats.ORACLE_MIN / ORACLE_MAX to match.")
    cases = all_cases()
    results = run_oracle(copy.deepcopy(cases))
    rows = []
    for case, res in zip(cases, results):
        assert not (res and "error" in res), (case["label"], res)
        if case["expect"] is not None:
            assert res is not None and res["message"] == reassemble_message(case["expect"]), (
                f"{case['label']}: the vendor does not answer exactly {case['expect']}: {res}")
        rows.append({"label": case["label"], "cfg": case["cfg"], "vendor": res})
    BATTERY_PATH.parent.mkdir(exist_ok=True)
    BATTERY_PATH.write_text(json.dumps({
        "build": ver, "finder_sha256": finder_digest(), "vocabulary": vendor_vocabulary(),
        "rows": rows}, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} rows for openclaw {ver} -> {BATTERY_PATH}")


if __name__ == "__main__":
    if "--write" in sys.argv:
        write_battery()
    else:
        print(__doc__)
