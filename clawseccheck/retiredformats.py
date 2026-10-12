"""``find_retired(cfg)`` -- which retired config formats does OpenClaw's own finder name?

A faithful port of ``findRetiredConfigUpgradeRequirement`` (the ``retired-config-formats-*``
dist bundle, source ``src/commands/doctor/shared/retired-config-formats.ts``) with its two
traversal helpers ``visitAgentConfigScopes`` / ``visitAgentEntries`` / ``visitChannelEntries``
(the ``legacy-config-record-shared-*`` bundle). Bundle filenames are content-hashed and
rotate every release, so they are cited by symbol; ``tests/_retiredformatsoracle.py``
locates them by declaration. Grounded on the installed **openclaw@2026.10.2**
(2026-10-12). Its finder is identical to 2026.10.1's in the bundles compared on 2026-10-12:
the sha256 of the ``retired-config-formats``, ``legacy-config-record-shared``,
``record-coerce``, ``prototype-keys`` and ``command-format`` bundles of an extracted
2026.10.1 package equals the installed 2026.10.2's, under the same content-hashed file names
(so no bundle-name normalising was needed). Nothing else of 2026.10.1 was compared.

WHY IT IS A PORT AND NOT A TABLE. ``checks/_shared.py::_RETIRED_CONFIG_KEYS`` (B382) lists
keys that were MEASURED against a build's root config schema, one row at a time. The vendor
publishes the authoritative list as code, and from 2026.10.1 three commands stop on a hit:
Doctor (``assertSupportedConfig``, and the staged write in
``doctor-health-contribution-runners.config``), Doctor's automatic repair
(``canPlanAutomaticConfigRepair`` declines) and ``openclaw update`` (``admit`` +
``createUpdateConfigFailure``: "Update refused: configuration contains retired fields that
current Doctor cannot migrate"). The finder names about 79 concrete paths and values; a hand
table covered 4 of the 46 the root schema also rejects. Of the 79, 33 are ``channels.*``
keys the root schema passes through and the bundled channel schemas reject: Doctor and
``openclaw update`` refuse them all the same, so the finder -- not the schema -- is the unit
here.

WHAT IT RETURNS. ``None`` when the finder returns ``undefined`` (nothing retired), else a
``RetiredFormats``: the concrete dotted paths in the vendor's own order and the
``bridgeVersion`` the vendor's ``nextAction`` tells the user to install ("Install OpenClaw
2026.9.5, run `openclaw doctor --fix`, then upgrade to latest"): ``2026.9.7`` when any
Discord voice-TTS or guild-channel key was found, else ``2026.9.5``. The bridge version is a
property of the WHOLE config, not of one path (the vendor computes it once, from the Discord
visit's contribution), so it is reported once.

WHAT IS NOT PORTED, deliberately: the ``message`` / ``nextAction`` prose (the differential
test reassembles the message from the paths and compares it with the vendor's, so the join
is checked without a copy of the sentence living here), ``formatCliCommand`` (a CLI-name
cosmetic), and any file read -- the finder is a pure function of an already-parsed config.
``ctx.config`` is the ``$include``-resolved merged dict, which is what the vendor's
``sourceConfigBeforeMigrations ?? sourceConfig`` is as well.

JS FIDELITY, each measured against the vendor and pinned by the battery:

* ``isRecord`` is "a non-null, non-array object" (a ``dict`` here; a ``bool``/``list``/
  ``None``/``str`` is not).
* ``Object.hasOwn`` is key presence: ``false``, ``null``, ``""`` and ``{}`` all count.
* ``Object.entries`` order: array-index-like keys (``"0"``, ``"2"``, ``"10"``) come first in
  ascending numeric order, then the rest in insertion order (``_entries``). It decides the
  order of the reported paths and nothing else.
* ``agents.entries`` being a record (even an empty one) hides ``agents.list`` completely;
  an entry named ``__proto__`` / ``prototype`` / ``constructor`` (or a ``list`` entry whose
  ``id`` is one) is skipped.
* ``channels.feishu`` itself is exempt from ``botName``; only its accounts are checked.
* A retired VALUE is exact string equality: ``messages.queue.mode`` and each
  ``byChannel.*`` entry against ``queue`` / ``steer-backlog`` / ``steer+backlog``.

THE BUILD WINDOW is ``ORACLE_MIN..ORACLE_MAX``. 2026.9.9's finder is a different, smaller
function (about 17 families); 2026.10.1 and 2026.10.2 are the only builds the battery was
executed on. Outside the window ``in_window`` is False and the caller must NOT claim the
finder was applied: a newer build is exactly "an input this port does not model", so it
degrades to the hand table's answer until ``tests/_retiredformatsoracle.py --write`` is run
against it and ``ORACLE_MAX`` is raised.

Leaf: stdlib only, imports nothing from this package. Not in ``__all__``, matching its
siblings ``toolpolicy.py`` / ``toolgrant.py`` / ``harnessruntime.py``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: The window of builds this port was differentially validated on (first three components
#: compared, so a correction release of a validated build stays inside it).
ORACLE_MIN = (2026, 10, 1)
ORACLE_MAX = (2026, 10, 2)

#: The vendor's two ``bridgeVersion`` values, verbatim.
BRIDGE_DEFAULT = "2026.9.5"
BRIDGE_DISCORD = "2026.9.7"

_BLOCKED_OBJECT_KEYS = frozenset({"__proto__", "prototype", "constructor"})
_ARRAY_INDEX_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_MAX_ARRAY_INDEX = 4294967294
_RETIRED_QUEUE_MODES = ("queue", "steer-backlog", "steer+backlog")


@dataclass(frozen=True)
class RetiredFormats:
    """What the finder reported: the concrete retired paths and the bridge release."""

    paths: tuple
    bridge_version: str


def in_window(version) -> bool:
    """True when *version* (a tuple of ints, e.g. ``_numeric_version``) is a build the port
    was validated on. ``None`` / an empty or non-tuple value is False -- an unknown build is
    not a validated one."""
    if not isinstance(version, tuple) or len(version) < 3:
        return False
    head = tuple(version)[:3]
    return ORACLE_MIN <= head <= ORACLE_MAX


def _is_record(value) -> bool:
    return isinstance(value, dict)


def _entries(record: dict) -> "list[tuple[str, object]]":
    """``Object.entries`` order: ascending array-index keys first, then insertion order."""
    index_keys = []
    other_keys = []
    for key in record:
        if (isinstance(key, str) and len(key) <= 10 and _ARRAY_INDEX_RE.match(key)
                and int(key) <= _MAX_ARRAY_INDEX):
            index_keys.append(key)
        else:
            other_keys.append(key)
    index_keys.sort(key=int)
    return [(key, record[key]) for key in index_keys + other_keys]


def _visit_agent_entries(raw: dict, visitor) -> None:
    agents = raw.get("agents") if _is_record(raw.get("agents")) else None
    if agents is not None and _is_record(agents.get("entries")):
        for agent_id, entry in _entries(agents["entries"]):
            if agent_id not in _BLOCKED_OBJECT_KEYS and _is_record(entry):
                visitor(entry, f"agents.entries.{agent_id}")
        return
    if agents is not None and isinstance(agents.get("list"), list):
        for index, entry in enumerate(agents["list"]):
            if not _is_record(entry):
                continue
            entry_id = entry.get("id")
            if isinstance(entry_id, str) and entry_id in _BLOCKED_OBJECT_KEYS:
                continue
            visitor(entry, f"agents.list[{index}]")


def _visit_agent_config_scopes(raw: dict, visitor) -> None:
    agents = raw.get("agents") if _is_record(raw.get("agents")) else None
    if agents is not None and _is_record(agents.get("defaults")):
        visitor(agents["defaults"], "agents.defaults")
    _visit_agent_entries(raw, visitor)


def _visit_channel_entries(raw: dict, channel_id: str, visitor) -> None:
    channels = raw.get("channels")
    if not _is_record(channels):
        return
    channel = channels.get(channel_id)
    if not _is_record(channel):
        return
    visitor(channel, f"channels.{channel_id}")
    if not _is_record(channel.get("accounts")):
        return
    for account_id, account in _entries(channel["accounts"]):
        if _is_record(account):
            visitor(account, f"channels.{channel_id}.accounts.{account_id}")


def find_retired(cfg) -> "RetiredFormats | None":
    """The retired formats OpenClaw's own finder names in *cfg*, or ``None`` (nothing)."""
    if not _is_record(cfg):
        return None
    retired: "list[str]" = []

    def check_keys(scope, config_path: str, keys) -> None:
        if not _is_record(scope):
            return
        for key in keys:
            if key in scope:
                retired.append(f"{config_path}.{key}" if config_path else key)

    def child(scope, key):
        return scope.get(key) if _is_record(scope) else None

    check_keys(cfg, "", ["heartbeat"])
    check_keys(cfg.get("routing"), "routing", ["allowFrom", "groupChat"])
    check_keys(cfg.get("plugins"), "plugins", ["installs"])
    check_keys(cfg.get("browser"), "browser", ["relayBindHost"])
    check_keys(child(cfg.get("browser"), "ssrfPolicy"), "browser.ssrfPolicy",
               ["allowPrivateNetwork"])

    def check_memory_store(scope: dict, config_path: str) -> None:
        check_keys(child(scope.get("memorySearch"), "store"),
                   f"{config_path}memorySearch.store", ["path"])
        memory = scope.get("memory") if _is_record(scope.get("memory")) else None
        check_keys(child(child(memory, "search"), "store"),
                   f"{config_path}memory.search.store", ["path"])

    check_memory_store(cfg, "")

    def agent_scope(scope: dict, config_path: str) -> None:
        check_keys(scope, config_path, ["systemPromptOverride", "silentReplyRewrite",
                                        "embeddedPi", "embeddedHarness", "agentRuntime"])
        check_keys(scope.get("sandbox"), f"{config_path}.sandbox", ["perSession"])
        check_keys(scope.get("silentReply"), f"{config_path}.silentReply", ["direct"])
        check_keys(scope.get("model"), f"{config_path}.model", ["timeoutMs"])
        check_keys(child(scope.get("subagents"), "model"),
                   f"{config_path}.subagents.model", ["timeoutMs"])
        check_memory_store(scope, f"{config_path}.")

    _visit_agent_config_scopes(cfg, agent_scope)

    if _is_record(cfg.get("surfaces")):
        for surface_id, surface in _entries(cfg["surfaces"]):
            check_keys(surface, f"surfaces.{surface_id}", ["silentReplyRewrite"])
            check_keys(child(surface, "silentReply"), f"surfaces.{surface_id}.silentReply",
                       ["direct"])

    messages = cfg.get("messages") if _is_record(cfg.get("messages")) else None
    queue = messages.get("queue") if messages is not None and _is_record(
        messages.get("queue")) else None

    def check_queue_mode(value, config_path: str) -> None:
        if isinstance(value, str) and value in _RETIRED_QUEUE_MODES:
            retired.append(config_path)

    if queue is not None:
        check_queue_mode(queue.get("mode"), "messages.queue.mode")
        if _is_record(queue.get("byChannel")):
            for channel, mode in _entries(queue["byChannel"]):
                check_queue_mode(mode, f"messages.queue.byChannel.{channel}")

    check_keys(cfg.get("talk"), "talk", ["mode", "transport", "brain", "model", "voice"])

    channels = cfg.get("channels") if _is_record(cfg.get("channels")) else {}
    check_keys(cfg.get("gateway"), "gateway", ["webchat"])
    check_keys(channels, "channels", ["webchat"])
    check_keys(channels.get("telegram"), "channels.telegram",
               ["requireMention", "groupMentionsOnly"])

    _visit_channel_entries(cfg, "whatsapp",
                           lambda scope, path: check_keys(scope, path, ["exposeErrorText"]))

    before_discord = len(retired)

    def discord_scope(scope: dict, config_path: str) -> None:
        voice = scope.get("voice") if _is_record(scope.get("voice")) else {}
        check_keys(voice.get("tts"), f"{config_path}.voice.tts",
                   ["openai", "elevenlabs", "microsoft", "edge"])
        guilds = scope.get("guilds") if _is_record(scope.get("guilds")) else {}
        for guild_id, guild in _entries(guilds):
            guild_channels = (guild["channels"] if _is_record(guild)
                              and _is_record(guild.get("channels")) else {})
            for channel_id, channel in _entries(guild_channels):
                check_keys(channel, f"{config_path}.guilds.{guild_id}.channels.{channel_id}",
                           ["allow", "agentId"])

    _visit_channel_entries(cfg, "discord", discord_scope)
    bridge_version = BRIDGE_DISCORD if len(retired) > before_discord else BRIDGE_DEFAULT

    def telegram_scope(scope: dict, config_path: str) -> None:
        check_keys(scope, config_path, ["streamMode", "chunkMode", "blockStreaming",
                                        "blockStreamingCoalesce", "draftChunk"])
        if _is_record(scope.get("dm")):
            retired.append(f"{config_path}.dm")
        if isinstance(scope.get("streaming"), (bool, str)):
            retired.append(f"{config_path}.streaming")
        streaming = scope.get("streaming") if _is_record(scope.get("streaming")) else {}
        check_keys(streaming.get("preview"), f"{config_path}.streaming.preview",
                   ["nativeToolProgress", "nativeToolProgressAllowFrom"])
        if _is_record(scope.get("direct")):
            for chat_id, direct in _entries(scope["direct"]):
                check_keys(direct, f"{config_path}.direct.{chat_id}", ["threadReplies"])

    _visit_channel_entries(cfg, "telegram", telegram_scope)
    _visit_channel_entries(cfg, "nextcloud-talk",
                           lambda scope, path: check_keys(scope, path, ["allowPrivateNetwork"]))

    def matrix_scope(scope: dict, config_path: str) -> None:
        check_keys(scope, config_path, ["allowPrivateNetwork"])
        dm = scope.get("dm")
        if _is_record(dm) and dm.get("policy") == "trusted":
            retired.append(f"{config_path}.dm.policy")
        for section in ("groups", "rooms"):
            rooms = scope.get(section)
            if _is_record(rooms):
                for room_id, room in _entries(rooms):
                    check_keys(room, f"{config_path}.{section}.{room_id}", ["allow"])

    _visit_channel_entries(cfg, "matrix", matrix_scope)

    def slack_scope(scope: dict, config_path: str) -> None:
        if _is_record(scope.get("channels")):
            for channel_id, channel in _entries(scope["channels"]):
                check_keys(channel, f"{config_path}.channels.{channel_id}", ["allow"])

    _visit_channel_entries(cfg, "slack", slack_scope)

    for channel_id in ("discord", "line", "matrix", "telegram"):
        _visit_channel_entries(
            cfg, channel_id,
            lambda scope, path: check_keys(scope.get("threadBindings"),
                                           f"{path}.threadBindings", ["ttlHours"]))

    def feishu_scope(scope: dict, config_path: str) -> None:
        if config_path != "channels.feishu":
            check_keys(scope, config_path, ["botName"])

    _visit_channel_entries(cfg, "feishu", feishu_scope)

    session = cfg.get("session") if _is_record(cfg.get("session")) else {}
    check_keys(session, "session", ["parentForkMaxTokens"])
    check_keys(session.get("threadBindings"), "session.threadBindings", ["ttlHours"])
    check_keys(child(cfg.get("agents"), "defaults"), "agents.defaults", ["llm"])

    if not retired:
        return None
    return RetiredFormats(paths=tuple(retired), bridge_version=bridge_version)
