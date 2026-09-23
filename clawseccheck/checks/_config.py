"""Topic module: config checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import ipaddress
import os
import re
from pathlib import Path
from .. import attest as _attest
from .. import openclawdist as _openclawdist
from .. import sockets as _sockets
from .. import toolgrant as _toolgrant
from ..catalog import (
    CRITICAL,
    FAIL,
    HIGH,
    MEDIUM,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..collector import (
    BOOTSTRAP_FILES,
    LIMIT_DOMAIN_CONFIG,
    LIMIT_DOMAIN_ENV,
    SKILL_DIRS,
    Context,
    _AUTH_PROFILE_STORE_EMPTY_BYTES,  # B-749
    agent_roster,
    dig,
    env_evidence_readable,
    limit_hits_for,
    persistent_env_evidence,
)
from ..safeio import walk_dir_safely
from ..textnorm import normalize_for_scan
from ..toolpolicy import any_confinement_undecided, scopes_reaching_outside_workspace

from ._content import (
    _B58_HTML_COMMENT_RE,
    _B64_HIGH_CONFIDENCE_RE,
    _b64_classify,
    _b63_scan,
    _CLICKFIX_REMOTE_FETCH_RE,
    _clickfix_trusted_installer,
    _fence_ranges,
    _secrecy_credential_or_encoding_anchor,
)
from ._shared import (
    _b323_contains_env_var_reference,
    _B55_FS_WRITE_TOOLS,
    _C015_EXTRA_SECRET_PATTERNS,  # noqa: F401 — re-exported (moved to _shared, B-666)
    _c015_has_secret,
    _canonical_ipv4,
    _channel_has_implicit_default_account,
    _channels,
    _config_unreadable,
    _credential_store_state,
    _detail_path,
    _dir_replaceable_by_others,
    _DM_POLICY_NESTED_ONLY_CHANNELS,
    _enabled_tools,
    EXPOSED_BINDS,
    _external_input_channels,
    _file_readable_by_others,
    _finding,
    _gateway_remote_exposure_reason,
    _hint,
    _hooks_session_key_exposures,
    INPUT_TOOL_HINTS,
    _is_posix,
    _is_secret_reference,  # noqa: F401 — re-exported for existing importers
    _LEG_KEYS,
    LOOPBACK,
    _mcp_leg_contributions,
    _node_commands,
    _norm_group_policy,
    _numeric_version,
    _open_channels,
    _bind_mentions_docker_sock,
    _openclaw_generation,
    OUTBOUND_TOOL_HINTS,
    parse_bind_host,
    _pattern_hits_real_secret,
    _perms_loose,
    _plugins,
    _profile_is_powerful,
    _real_exec_enabled,
    _resolve_sandbox_scope,
    _retired_keys_present,
    _resolved_channel_nodes,
    _resolved_default_input_channels,
    _sandbox_docker_binds,
    _secret_paths,
    SECRET_KEY_RE,
    SECRET_PATTERNS,
    SENSITIVE_TOOL_HINTS,
    _substituted_dm_policy_channels,
    _surface_absent,
    _trifecta_leg_sources,
    _trifecta_legs,
    _username_safe_path,
    _web_fetch_enabled,
)
from ..invocation import command_prefix


CLOUD_PROVIDERS = (
    "openai",
    "anthropic",
    "gpt",
    "claude",
    "google",
    "gemini",
    "grok",
    "mistral",
    "cohere",
)


# ---------- B32: Control-Plane Mutation Reachability ----------
# gateway.tools.allow — explicit re-enablement of a tool over the HTTP gateway.
# gateway.tools.deny  — explicit denial list.
#
# B-835: this set is now grounded on the installed openclaw@2026.9.5 dist's own
# GATEWAY_CONTROL_PLANE_TOOLS (dangerous-tools-D5_2xo_6.mjs:35-39 — "Sensitive
# control-plane tools. `automations` can persist scheduled runs; `gateway` exposes
# config and self-update; `plugins` manages executable plugin lifecycles."), resolving
# its AUTOMATIONS_TOOL_NAME import to the canonical id "automations"
# (automations-tool-name-DBMZPbPL.mjs). Entries compared against this set MUST go
# through _normalize_tool_name (below) first, the same normalizeToolPolicyName the
# vendor itself applies (toolgrant._normalize_tool_name, reused rather than a third
# copy — toolgrant.py's own docstring names checks/_shared.py's and toolpolicy.py's
# two-entry alias tables as the narrower siblings NOT to copy from). Before this fix
# the set held the literal alias "cron" instead of the canonical "automations" and
# compared it against raw (non-normalised) config strings, so `gateway.tools.allow:
# ["automations"]` (the canonical, more likely spelling) PASSED while only the legacy
# alias "cron" FAILed — backwards from the vendor's own alias direction
# (TOOL_NAME_ALIASES maps "cron" -> "automations", tool-policy-shared bundle).
#
# "plugins" is new here (B-835): 9.5 added it to GATEWAY_CONTROL_PLANE_TOOLS AND to
# DEFAULT_GATEWAY_HTTP_TOOL_DENY (same file:25); on <=9.4 (dangerous-tools-*.mjs:34,41
# in that release) it was neither, so gateway.tools.allow:["plugins"] was inert there.
# Deliberately NOT made version-aware (contrast the version-gated
# `_workshop_symlink_knob`, checks/_shared.py:1049): "plugins" manages executable
# plugin lifecycles (dist comment above) — an explicit allow of it over the HTTP
# gateway is a real control-plane exposure on every build this check can see, whether
# or not the running OpenClaw version happens to default-deny it. A stale PASS on an
# old build is a worse failure mode than an occasional inert-but-flagged allow.
#
# "sessions_spawn"/"sessions_send" (real CORE_TOOL_DEFINITIONS ids, tool-catalog-*.mjs)
# stay for the "cross-session spawn/send" mutation this check has always modelled;
# vendor's own GATEWAY_CONTROL_PLANE_TOOLS does not name them (that list only covers
# automations/gateway/plugins) but they are still real, dangerous-over-HTTP tool ids
# per DEFAULT_GATEWAY_HTTP_TOOL_DENY, and dropping detection coverage is out of scope
# for this fix. "config.apply"/"update.run" also stay: they are real, grounded gateway
# control-plane identifiers (method-scopes-CF6Mdynq.mjs, tagged CONTROL_PLANE_WRITE,
# operator.admin scope) even though they name JSON-RPC *methods* on a different
# gateway authorization axis (operator scopes) than the *tool* ids gateway.tools.
# allow/deny governs — kept as a defensive, deliberately-conservative extra match on
# the (harmless if never hit) chance a config string is set to look like one of them.
#
# Deliberately EXCLUDED despite being real tool ids in the same two vendor deny lists
# (DEFAULT_GATEWAY_HTTP_TOOL_DENY and GATEWAY_OWNER_ONLY_CORE_TOOLS,
# dangerous-tools-D5_2xo_6.mjs:8-30,45-58): "nodes" ("Nodes + devices" — device
# pairing/control, tool-catalog-BAOwO8Un.mjs:369) and "openclaw" ("Delegate OpenClaw
# setup and repair", ibid:362). The vendor itself keeps both OUT of
# GATEWAY_CONTROL_PLANE_TOOLS while putting them in the broader, differently-justified
# GATEWAY_OWNER_ONLY_CORE_TOOLS (owner-identity requirement, not "control-plane
# mutation" — that list also adds sessions/screen/terminal/portal/conversations_*/
# computer/mobile_ui, none of which this check's "config mutation / cron scheduling /
# cross-session spawn-send" framing covers either). Folding device control or
# setup-delegation into a check specifically named "control-plane mutation" would
# assert a vendor classification the vendor's own source does not make — filed as an
# open question for a future check (owner-only-tool exposure is a different, real
# question) rather than smuggled into B32.
_B32_CONTROL_PLANE_TOOLS = frozenset(
    {
        "automations",
        "gateway",
        "plugins",
        "sessions_spawn",
        "sessions_send",
        "config.apply",
        "update.run",
    }
)


def _b32_normalize_tools(raw) -> set:
    """Normalise a gateway.tools.allow/deny entry list the same way the vendor's
    resolver does (trim + lowercase + alias fold — toolgrant._normalize_tool_name,
    itself grounded against the installed dist's TOOL_NAME_ALIASES) before comparing
    against _B32_CONTROL_PLANE_TOOLS. Non-string entries fold to "" (dropped), matching
    normalizeLowercaseStringOrEmpty rather than Python's str() (a stray int/dict/list
    entry is not a tool name, canonical or otherwise)."""
    return {n for n in (_toolgrant._normalize_tool_name(t) for t in raw) if n}


_C015_MAX_BYTES = 200_000
# B-513: how many matching files the finding lists before it says "+N more".
# Named rather than inline so the disclosure below cannot drift from the slice.
_C015_MAX_EVIDENCE = 12


_C015_MAX_SCAN_FILES = 500


_C015_TEXT_EXTS = {
    ".env",
    ".json",
    ".jsonc",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".md",
    ".txt",
    ".properties",
    ".service",
    ".sh",
    ".envrc",
}


# per-agent sandbox docker flags (FAIL) — same leaf names under agents.list[]
_DANGER_AGENT_SANDBOX = (
    ("dangerouslyAllowContainerNamespaceJoin", "namespace join"),
    ("dangerouslyAllowExternalBindSources", "external bind sources"),
    ("dangerouslyAllowReservedContainerTargets", "reserved container targets"),
)


# ---------- B48: dangerous break-glass overrides (v1.8.0) ----------
# Grounded registry of OpenClaw "dangerously*/allowUnsafe*" break-glass flags, verified
# against the real `openclaw config schema` (2026.6.9). Each is documented there as
# DANGEROUS / "keep disabled". (path, risk label, FAIL?). Active (truthy) = a deliberate
# dangerous override. FAIL = sandbox escape or control-plane auth bypass; WARN = the rest.
_DANGER_FIXED = [
    (
        "agents.defaults.sandbox.docker.dangerouslyAllowContainerNamespaceJoin",
        "sandbox escape: joins another container's namespace",
        True,
    ),
    (
        "agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources",
        "sandbox escape: external host bind sources",
        True,
    ),
    (
        "agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets",
        "sandbox escape: reserved container targets",
        True,
    ),
    (
        "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback",
        "control-plane: Host-header origin fallback (CSRF/origin-bypass surface)",
        False,
    ),
    (
        "gateway.controlUi.allowExternalEmbedUrls",
        "control-plane: external embed URLs allowed (SSRF / clickjacking)",
        False,
    ),
    (
        # C-507: grounded 2026-09-06 against the installed dist (openclaw@2026.9.2,
        # re-confirmed on 2026.9.4) — schema description, verbatim: "Allow user-
        # installed plugins to execute native JavaScript in the Control UI (default:
        # false). Bundled plugin views remain available. Custom UI shares the
        # signed-in operator's Gateway permissions; enable only for trusted plugins."
        # Runtime gate (dist/github-user-identity-*.js, isControlUiPluginAllowed):
        # `plugin.origin === "bundled" || ...customPlugins === true` — with the flag
        # on, a NON-bundled, user-installed plugin runs native JS in the Control UI at
        # the signed-in operator's own Gateway authority. WARN, not FAIL, matching the
        # sibling allowExternalEmbedUrls row directly above: opt-in, defaults false, so
        # a config setting it true is a deliberate operator act (same shape, same
        # severity) — the flag alone is not yet an attack, it needs an untrusted
        # installed plugin to combine with (tracked separately, not modelled as a
        # RISK-* chain here — see C-507's own comment for why).
        "gateway.controlUi.experimental.customPlugins",
        "control-plane: user-installed plugins may run native JS in the Control UI "
        "with the signed-in operator's Gateway permissions",
        False,
    ),
    (
        "gateway.allowRealIpFallback",
        "x-real-ip fallback enabled (client-IP spoofing via forged header)",
        False,
    ),
    (
        "hooks.gmail.allowUnsafeExternalContent",
        "less-sanitized external Gmail content into processing (injection surface)",
        False,
    ),
]


# B-701. Two SSRF break-glass flags that exist ONLY in the 2026.8.1+ schema, so B48 said
# "No dangerous break-glass override flags enabled." with one of them on — measured, not
# inferred. Both were confirmed by `safeParse` against the installed 2026.8.1 dist AND
# absent from 2026.7.1-2, each with a bogus-key control at the same parent (`gateway.tls`
# is a passthrough and accepts junk, so an ACCEPTED probe alone proves nothing).
#
# Vendor's own descriptions:
#   cron.webhookSsrfPolicy.dangerouslyAllowPrivateNetwork — "Allows automation webhooks
#     to private and internal network targets."
#   tools.web.fetch.ssrfPolicy.dangerouslyAllowPrivateNetwork — "Allows web_fetch access
#     to private and internal network targets. Keep disabled unless model-selected URLs
#     are trusted in this deployment."  <- model-SELECTED, i.e. an injected prompt turns
#     this into an SSRF primitive against the host's private network.
#
# C-135 pass, and the one judgement call it forced: neither row is gated on the surrounding
# feature being enabled. `tools.web.fetch.enabled: false` + the flag PARSES, and a per-agent
# scope cannot re-enable web fetch (`agents.entries.<k>.tools` rejects `web` -- measured), so
# the flag really can sit there inert. It still warns, for two grounded reasons: every
# sibling row behaves the same way (no `_DANGER_FIXED` entry gates on its feature, and B38
# FAILs on a browser SSRF flag with no browser block at all), and an inert flag goes live the
# moment the user flips `enabled` -- silently, with nothing to re-warn them. WARN, not FAIL,
# is what makes that the right trade.
#
# Also measured, on the whole check set rather than on B48 alone: no other check moves on
# either flag, so neither row double-counts.
#
# `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` is deliberately NOT here: B38 already
# FAILs on it (checks/_egress.py) and _egress.py's own no-double-count rule with B38
# applies. That was checked by running the whole check set on it, not by reading the code.
# This was a PRE-EXISTING miss -- browser.ssrfPolicy existed before 2026.8.1 and B38 has
# always owned it -- not 2026.8.1 drift like the two rows below it; do not re-derive it as
# upgrade damage in a future triage.
#
# Read WITHOUT dig() on purpose -- but note the ORIGINAL reason has expired, so do not
# re-derive it from this comment. The deferral was that a dig() path needs an entry in
# tests/grounded_schema_paths.txt, which in turn needs vouching by
# tests/dist_verified_paths.txt, and that snapshot was stamped 2026.7.1-2 and could not
# contain a key that version has no word for. The snapshot has since been regenerated
# against 2026.8.2, and these keys DO resolve there: measured via
# `_dist_accepts("cron.webhookSsrfPolicy.dangerouslyAllowPrivateNetwork", root, consts)`
# -> True, against a `gateway.nodes.zzzBogusControl` -> False control. So the blocker is
# gone and this is now ordinary outstanding work, not a thing waiting on the upgrade.
# `checks/_shared._node_commands` was the same arrangement and was converted once the
# snapshot moved; this site and `collector.agent_roster` were left because they belong to
# their own tasks, not because they still cannot be done.
_DANGER_FIXED_2026_8_1 = [
    (
        "cron.webhookSsrfPolicy.dangerouslyAllowPrivateNetwork",
        "automation webhooks may reach private/internal targets (SSRF)",
    ),
    (
        "tools.web.fetch.ssrfPolicy.dangerouslyAllowPrivateNetwork",
        "web_fetch may reach private/internal targets (SSRF via a model-selected URL)",
    ),
]


# B-795: the build that made gateway.controlUi.dangerouslyDisableDeviceAuth RETIRED and
# IGNORED rather than merely defaulted off. Grounded against the installed dist
# (openclaw@2026.9.3, legacy-*.mjs): a `defineLegacyConfigMigration` entry named
# "dangerouslyDisableDeviceAuth" whose message reads "gateway.controlUi.
# dangerouslyDisableDeviceAuth is retired and ignored. Control UI browsers pair through
# the normal device flow; run \"openclaw doctor --fix\" to remove the legacy key." —
# re-confirmed present, unchanged, on the installed 2026.9.4 dist. Setting the key no
# longer disables Control-UI device-identity auth or does anything else; the old
# unconditional FAIL/HIGH row named a live security exposure that does not exist on
# these builds.
#
# Same shape and same source order as `_workshop_symlink_knob` (B-783): only
# `installed_dist_version` decides outright (it is the build that reads or ignores the
# key right now); `meta.lastTouchedVersion` is consulted only once it already lands at
# or after the retirement release, because a stale stamp proves nothing about what is
# installed now. Not folded into `_openclaw_generation`'s modern/legacy split — that
# threshold is pinned to 2026.8.1 and is compared at two dozen other call sites; a wrong
# answer for THIS key must not move any of them.
#
# Caveat, recorded rather than hidden: 2026.9.3 is the first release this was actually
# grounded against, not independently proven to be the release that introduced the
# retirement — 2026.9.1/9.2 were not checked. If the real cutover lands earlier, this
# constant is too conservative in the safe direction (it still treats those builds as
# "honoured" and keeps the original FAIL), the same direction B-783 chose when it had
# the identical gap.
_DEVICE_AUTH_KNOB_RETIRED_MIN = (2026, 9, 3)


def _device_auth_knob(ctx) -> str:
    """Does the reader's OpenClaw still HONOUR gateway.controlUi.dangerouslyDisableDeviceAuth?

    ``"retired"`` / ``"honoured"`` / ``"unknown"`` — three answers for the same reason
    ``_workshop_symlink_knob`` has three: "we could not see the build" is not "the build
    still reads it", and collapsing them manufactures a claim. Only ``"retired"`` may
    silence the FAIL below; the other two both preserve today's behavior exactly.
    """
    installed = _numeric_version(getattr(ctx, "installed_dist_version", None))
    if installed is not None:
        return "retired" if installed >= _DEVICE_AUTH_KNOB_RETIRED_MIN else "honoured"
    stamped = _numeric_version(
        _openclawdist.self_reported_version(getattr(ctx, "config", None)))
    if stamped is not None and stamped >= _DEVICE_AUTH_KNOB_RETIRED_MIN:
        return "retired"
    return "unknown"


# B-231: wildcard-authority detection for commands.ownerAllowFrom (FAIL/CRITICAL, above
# the scoped-list case) and gateway.nodes.pairing.autoApproveCidrs (WARN only -- see the
# NC-11 note below for why this one does NOT escalate to FAIL).
#   * commands.ownerAllowFrom: on 2026.7.x, command-auth-*.js
#     resolveOwnerAuthorizationState() sets
#     ownerAllowAll = hasWildcardAllowFrom(configOwnerAllowFromList), and
#     isWildcardAllowFromEntry() is a literal `entry.trim() === "*"` check -- a bare
#     "*" entry genuinely flips owner authority open to ANY sender:
#
#         const senderIsOwner = senderIsOwnerByIdentity || senderIsOwnerByScope
#                            || ownerState.ownerAllowAll;
#         const isOwnerForCommands = !requireOwner ? true
#                                  : ownerState.ownerAllowAll ? true : ...;
#
#     (The schema doc string "'*' is ignored" describes a narrower filter that drops "*"
#     from the *explicit owner ID candidate* list built from the SAME array -- it does not
#     describe the ownerAllowAll gate, which is the actual authorization decision.)
#
#     B-705: that reasoning was correct when written and OpenClaw 2026.8.1 INVALIDATED it.
#     `ownerAllowAll` is gone from the entire 2026.8.1 dist -- grep: zero files, against one
#     in 2026.7.1-2 -- and the surviving code strips the wildcard before anything reads it:
#
#         const explicitOwners = Array.from(new Set(stripWildcardAllowFrom(configOwnerAllowFromList)));
#         const ownerAllowlistConfigured = ownerState.explicitOwners.length > 0;
#         const senderIsOwner = senderIsOwnerByIdentity || senderIsOwnerByScope;
#
#     So on 2026.8.1 `ownerAllowFrom: ["*"]` resolves to `explicitOwners = []`, which is
#     EXACTLY the state of the key being absent -- a state this check calls PASS. Keeping
#     the FAIL there would give two opposite verdicts to one configuration, at CRITICAL.
#     The leg is therefore version-scoped, not retracted: the 2026.7.x grant is real.
#
#     Note what the schema description could NOT settle: "'*' is ignored" reads the same
#     in both builds, so it was true of the candidate list in 7.x and became true of the
#     authorization decision in 8.1 without the sentence changing. Only the code moved.
#   * gateway.nodes.pairing.autoApproveCidrs: message-handler-*.js feeds the raw CIDR
#     list straight into isTrustedProxyAddress() -- a literal 0.0.0.0/0 (or ::/0) entry
#     matches every source IP, auto-approving first-time, ZERO-REQUESTED-SCOPE node
#     pairing from anywhere (role/scope/metadata/public-key upgrades still need manual
#     approval -- schema doc string). BUT: the internal schema recon (NC-11) records
#     that OpenClaw's own docs (docs.openclaw.ai/gateway/security "not a vulnerability by
#     design" list) explicitly name "reports treating configured
#     gateway.nodes.pairing.autoApproveCidrs as vulnerability by itself" as OUT OF SCOPE,
#     and the recon's own verdict is blunt: "Do NOT FAIL on gateway.nodes.pairing.* or
#     pairing.autoApproveCidrs." So even the world-open case stays WARN, never FAIL --
#     still surfaced (a 0.0.0.0/0 value is worth a human look), just not grade-capping.
#
# gateway.nodes.allowCommands is DELIBERATELY NOT given the same treatment: grounded
# against node-command-policy-*.js, a literal "*" there is folded into a plain Set of
# exact command-name strings (`allow.has(command)`) with NO wildcard special-case -- no
# real node command is ever named "*", so it is an inert, near-meaningless entry, not a
# broader grant than a scoped list. Escalating it above the existing scoped-list WARN
# would be a fabricated claim; the existing any-non-empty-list WARN (unchanged) already
# covers the real risk (a *named* dangerous command actually being allowed).
def _is_owner_wildcard_allow_from(value) -> bool:
    """True when *value* (``commands.ownerAllowFrom``) contains the literal ``"*"`` entry.

    PURE PREDICATE — it says what is in the list, not what OpenClaw does with it, because
    that differs by build (B-705, see the grounding block above): on 2026.7.x the entry
    sets `ownerAllowAll` and every sender becomes an owner; on 2026.8.1
    `stripWildcardAllowFrom` removes it before anything reads it, leaving the same state
    as an absent key. The version gate lives at the call site, so this stays a fact about
    the config rather than a claim about the runtime.
    """
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return False
    return any(isinstance(e, str) and e.strip() == "*" for e in value)


def _is_world_open_cidr_entry(entry) -> bool:
    """True when *entry* is a literal 'match any address' CIDR (0.0.0.0/0, ::/0) or the
    bare "*" sentinel -- not merely broad, a genuine zero-constraint wildcard. A scoped
    CIDR of any other prefix length (including a wide public range) is NOT flagged
    here — only the unambiguous, unconstrained case."""
    if not isinstance(entry, str):
        return False
    s = entry.strip()
    if not s:
        return False
    if s == "*":
        return True
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return False
    return net.prefixlen == 0


def _has_world_open_cidr(value) -> bool:
    """True when *value* (``gateway.nodes.pairing.autoApproveCidrs``) contains at
    least one world-open entry (see ``_is_world_open_cidr_entry``)."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return False
    return any(_is_world_open_cidr_entry(e) for e in value)


# F-036: for a 2/3 config, name the one missing leg + the concrete field that would
# complete the trifecta. Grounded only in field paths the engine already reads
# (_untrusted_input_channels / _unpolicied_open_wildcard_group_channels (B-371) /
# INPUT_TOOL_HINTS + web for input; SENSITIVE_TOOL_HINTS, ungated exec, a credential file
# in the store (B-666: its CONTENT, not the directory's name) for
# sensitive; OUTBOUND_TOOL_HINTS, exec, elevated, web for outbound). No new schema invented.
_MISSING_LEG_ACTIVATORS = {
    "untrusted input": (
        "a non-owner channel (channels.<name>.dmPolicy/groupPolicy in "
        "open/allowlist/paired), an unpolicied, unrestricted channels.<name>.groups[\"*\"] "
        "entry (OPEN-WILDCARD-GROUP), an input tool (tools.allow: web/email/imap/rss/fetch), "
        "or tools.web.fetch.enabled"
    ),
    "sensitive data": (
        "a private-data tool named in tools.allow (read/db/sql/vault/credential — a file "
        "`read` counts only while it is unconfined: tools.fs.workspaceOnly is not true "
        "and the agent is not fully sandboxed), ungated exec — "
        "tools.exec.mode/security/ask absent, or set to a non-gating value (e.g. "
        "mode='full') — or a plaintext credential in the credentials/ store"
    ),
    "outbound actions": (
        "an outbound tool (tools.allow: send/webhook/http_post/fs_write/deploy), "
        "tools.exec, tools.elevated.allowFrom, or tools.web.fetch.enabled"
    ),
}


def _c015_is_codex_plugin_doc_cache(parts: tuple) -> bool:
    """True if *parts* (a resolved path's ``.parts``) sit under a Codex CLI plugin
    doc-cache directory: ``agents/<name>/agent/codex-home/.tmp/plugins/plugins/**``.

    OpenClaw's Codex CLI integration vendors third-party plugins' reference
    documentation into this cache (see ``codex-home/sessions`` in _lifecycle.py for
    the sibling ``agent/codex-home`` shape). Those `.md` files routinely contain
    placeholder examples like ``API_KEY=abc123`` or ``password:"..."`` that are not
    secrets — they were shipped by the plugin author, not created by the user or
    agent — so C015's generic keyword pattern false-positives on them (B-124).
    """
    marker = ("agent", "codex-home", ".tmp", "plugins", "plugins")
    n = len(marker)
    return any(parts[i : i + n] == marker for i in range(len(parts) - n + 1))


# B-244 round 2: a false WARN on the user's REAL ~/.openclaw. ``agent/plugins/<id>/
# catalog.json`` is OpenClaw's own machine-generated plugin model-catalog cache — not
# user-authored — grounded in the dist (not the recon):
#   dist/plugin-model-catalog-*.js  isPluginModelCatalogRelativePath(): the canonical
#     path shape is exactly ``plugins/<pluginId>/catalog.json`` relative to the agent
#     dir; isGeneratedPluginModelCatalog(): the written object's top-level
#     ``generatedBy`` is the literal string ``"openclaw-plugin-model-catalog-v1"``.
#   dist/models-config-*.js  buildPluginCatalogWrites(): writes exactly
#     ``{generatedBy: PLUGIN_MODEL_CATALOG_GENERATED_BY, providers}`` to that path —
#     no other code path writes this file.
#   dist/provider-catalog-*.js: the bundled nvidia provider's catalog entry ships
#     ``apiKey: "NVIDIA_API_KEY"`` verbatim — the env-var NAME, not a secret value —
#     confirmed at runtime by dist/extensions/nvidia/index.js reading
#     ``ctx.env.NVIDIA_API_KEY``.
# So a plugin-catalog ``apiKey`` field commonly holds a bare env-var name, which is
# not a C-226 SecretRef indirection in the narrow ``$NAME``/``${NAME}``/
# ``secretref-env:`` sense _is_secret_reference recognises, so C015's generic
# keyword pattern false-positived on it — same B-124 class as the codex plugin
# doc-cache exclusion above, at a different path.
#
# Deliberately requires BOTH the canonical path shape AND the ``generatedBy``
# content marker (mirroring OpenClaw's own two-part discriminator) rather than
# widening ``_is_secret_reference`` itself: that helper is shared by every other
# secret-detecting check, and a generic "bare SCREAMING_SNAKE_CASE value is a
# reference" rule would blind-spot a real hardcoded password typed in that shape
# anywhere else it is consulted. A file that merely sits at this path but lacks the
# marker (never written by OpenClaw) is still scanned normally.
def _c015_is_generated_plugin_model_catalog(parts: tuple, text: str) -> bool:
    """True if *parts* end in ``agent/plugins/<pluginId>/catalog.json`` and *text*
    parses as JSON carrying OpenClaw's own generated-catalog marker."""
    if len(parts) < 4 or parts[-1] != "catalog.json":
        return False
    if parts[-4] != "agent" or parts[-3] != "plugins":
        return False
    import json as _json

    try:
        parsed = _json.loads(text)
    except ValueError:
        return False
    return isinstance(parsed, dict) and parsed.get("generatedBy") == (
        "openclaw-plugin-model-catalog-v1"
    )


# ---------------------------------------------------------------- Block B
# B-244: the codex-doc-cache / skill-dir exclusions used to run AFTER walk_dir_safely
# already spent the _C015_MAX_SCAN_FILES budget on every raw file it saw — so a large
# excluded subtree (e.g. a vendored codex plugin doc cache) could exhaust the whole
# budget before the walk ever reached real candidate directories that sort later
# alphabetically (workspace/, credentials/, identity/, ...), and the resulting
# WARN/PASS carried no hint that the scan was incomplete. Both exclusions now run
# DURING the walk via `prune_dir`/`keep_file`, so excluded material never consumes the
# budget, and `capped` is threaded through so the caller can disclose a genuine
# truncation instead of reading a partial scan as a complete one.
def _c015_candidate_files(ctx: Context, capped: list | None = None) -> list[Path]:
    skip_roots = [(ctx.home / rel).resolve() for rel in SKILL_DIRS]
    skill_dir_parts = tuple(Path(rel).parts for rel in SKILL_DIRS)

    def _prune(rel_parts: tuple) -> bool:
        if _c015_is_codex_plugin_doc_cache(rel_parts):
            return True
        return any(rel_parts[: len(root)] == root for root in skill_dir_parts)

    def _keep_file(path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if any(
            resolved == root or root in resolved.parents for root in skip_roots if root.exists()
        ):
            return False
        if _c015_is_codex_plugin_doc_cache(resolved.parts):
            return False
        name = path.name.lower()
        return bool(
            path.suffix.lower() in _C015_TEXT_EXTS
            or name in {"openclaw.json", "openclaw.jsonc"}
            or name.startswith("openclaw.json.")
            or name.startswith("openclaw.jsonc.")
            or name.startswith(".env")
            or name in BOOTSTRAP_FILES
        )

    return walk_dir_safely(
        ctx.home,
        max_files=_C015_MAX_SCAN_FILES,
        exclude_pycache=True,
        prune_dir=_prune,
        keep_file=_keep_file,
        capped=capped,
    )


def _capabilities_attested(ctx: Context) -> bool:
    """True when the user supplied an attestation roster (`--attest`): an OFF
    input/outbound leg can then be trusted instead of flagged 'cannot determine'.
    Unlike a no-op tools.allow entry, this is a real, deliberate declaration."""
    return bool(_attest.attested_agents(getattr(ctx, "attestation", {}) or {}))


def _distance_note(active: list, *, ingress_resolved_by_default: bool = False) -> str:
    """F-036: when exactly 2 of 3 legs are active, return a sentence naming the single
    missing leg and the concrete config toggle that would complete 3/3. Returns '' for
    any other count, so it is a no-op for already-3/3 (FAIL) and for <2/3.

    B-499: *ingress_resolved_by_default* says the untrusted-input leg is not cleanly
    missing — no channel DECLARED an ingress policy, but OpenClaw resolves the absent
    ``dmPolicy`` to "pairing", so at runtime that leg may already be live. Without this,
    the two sentences contradicted each other inside one paragraph: this note told the
    reader to "avoid enabling a non-owner channel" immediately before
    ``_resolved_default_note`` reported that a channel is already running on "pairing" —
    advice to avoid a state the same paragraph says is in force. The imperative is
    dropped in that case and the consequence kept, because the consequence is still true
    and is the part the reader needs."""
    if len(active) != 2:
        return ""
    missing = next(k for k in _LEG_KEYS if k not in active)
    lead = (
        f" Two of three lethal-trifecta legs are active ({active[0]} and {active[1]});"
        f" the missing leg is '{missing}'."
    )
    if ingress_resolved_by_default and missing == "untrusted input":
        return (
            lead + " No channel declares an ingress policy, so this leg is undeclared"
            " rather than closed — see the resolved-default note below. If it is live at"
            " runtime this is already 3/3: one injected prompt is enough to exfiltrate"
            " everything."
        )
    return (
        lead + f" Avoid enabling"
        f" {_MISSING_LEG_ACTIVATORS[missing]}, which would complete 3/3 — if a third leg"
        f" activates it becomes immediately exploitable: one injected prompt is enough"
        f" to exfiltrate everything."
    )


def _mcp_leg_note(ctx: Context) -> str:
    """B-229 (+B-247): when an MCP server contributes to a trifecta leg, name it in the
    detail text (evidence stays the fixed 3 leg-name keys — see _trifecta_legs/_LEG_KEYS
    — so the MCP server names live here instead)."""
    mcp_legs = _mcp_leg_contributions(ctx.config)
    reasons = (
        mcp_legs["untrusted input"] + mcp_legs["sensitive data"] + mcp_legs["outbound actions"]
    )
    if not reasons:
        return ""
    return " MCP-granted capability: " + "; ".join(reasons) + "."


def _leg_attribution_note(active: list, leg_sources: dict) -> str:
    """B-493: name the SPECIFIC config entries behind each active leg. `evidence` stays
    the fixed leg-name keys (see `_trifecta_legs`/`_LEG_KEYS`, and `_mcp_leg_note`'s own
    note above for why — `report.py`'s trifecta-ratio card reads `len(finding.evidence)`
    as the leg COUNT, and a dozen tests pin its exact leg-name membership, so it cannot
    become a per-entry list without corrupting both), so the per-entry attribution lives
    here instead, same idiom as `_mcp_leg_note`/`_resolved_default_note`.

    A leg can be OVER-DETERMINED — several independent suppliers, each sufficient alone
    — so every contributing entry is named, not just the first: removing only one from
    an over-determined leg leaves it active, and a reader needs to know that up front.
    """
    parts = []
    for leg in active:
        sources = leg_sources.get(leg) or []
        if sources:
            parts.append(f"{leg} — {'; '.join(sources)}")
    if not parts:
        return ""
    return " Sources: " + ". ".join(parts) + "."


def _resolved_default_fix(names: list) -> str:
    """B-619: the remediation for ``_resolved_default_note`` must recommend a key the
    TARGET channel's own schema actually accepts — googlechat and matrix are ``.strict()``
    with no flat ``dmPolicy`` field at all (see ``_DM_POLICY_NESTED_ONLY_CHANNELS``'s
    grounding comment in ``_shared.py``), so recommending flat `dmPolicy: "disabled"` to
    them is advice the config loader itself rejects — the exact "advice OpenClaw rejects"
    defect ``test_the_remediation_never_recommends_a_value_the_schema_rejects`` (B-499)
    already pins for the *value* axis (``"owner"``), now applied to the *path* axis.
    """
    # B-720 wording note. This clause used to say the flat key "is rejected there". Only
    # half of that is verified: matrix genuinely declares no flat `dmPolicy` (measured
    # against the vendor's generated schema), but `MatrixConfigSchema` is NOT `.strict()`,
    # and its wrapper's strictness was not traced. Absent `.strict()`, zod STRIPS an
    # unknown key rather than rejecting it — so the user would get silence, not an error.
    #
    # "does not close anything" is true under BOTH behaviours, and it is also the safer
    # message: told they would get an error, a user who sees none concludes it worked.
    # Do not restore the stronger claim without tracing buildChannelConfigSchema — this
    # whole check is being repaired from exactly one un-traced `.strict()` claim.
    nested_only = sorted(n for n in names if n in _DM_POLICY_NESTED_ONLY_CHANNELS)
    other = sorted(n for n in names if n not in _DM_POLICY_NESTED_ONLY_CHANNELS)
    parts = []
    if other:
        parts.append(
            f'Set `dmPolicy: "disabled"` on {", ".join(other)} to close DM ingress.'
        )
    if nested_only:
        parts.append(
            f'On {", ".join(nested_only)}, set the nested `dm.policy: "disabled"`'
            " instead — a flat `dmPolicy` is not part of that schema, so writing it"
            " there does not close anything."
        )
    return (
        " ".join(parts) + ' Leaving it unset is not a restriction — OpenClaw resolves'
        ' it to "pairing". Do not invent a value: `DmPolicySchema` accepts only open /'
        " pairing / allowlist / disabled (Feishu and Lark's own schema defines only the"
        ' first three — but `dmPolicy: "disabled"` is still honored by their runtime and'
        " blocks DMs, so it is the correct value to write there too), and the other"
        " three all admit a non-owner sender."
    )


def _resolved_default_note(ctx: Context) -> str:
    """B-499: name the channels whose dmPolicy is absent, and say plainly that the
    resolved default is NOT counted as a leg.

    Without this the reader cannot tell a config that restricts ingress from one that
    simply never wrote the field — the two look identical in A1's output, while OpenClaw
    runs the second one on "pairing". Disclosing the reading is what the leg count
    deliberately does not do; see _resolved_default_input_channels."""
    names = _resolved_default_input_channels(ctx.config)
    if not names:
        return ""
    return (
        f" Resolved default: {', '.join(sorted(names))} set no dmPolicy, so OpenClaw"
        ' runs them on its default "pairing" — a sender it has approved once can send'
        " again. Not counted as a leg above, because the config never asked for it."
    )


def _substituted_dm_policy_note(ctx: Context) -> str:
    """B-609: name the channels whose WRITTEN dmPolicy is not a value OpenClaw
    recognizes for them, AND the value it actually runs on instead.

    Without this the reader cannot tell a config that wrote an unrecognized dmPolicy
    from one that restricted ingress correctly — both looked identical (PASS) in A1's
    output, while OpenClaw silently substitutes "pairing" for the two channels this can
    currently be grounded on (see ``_norm_dm_policy``). Naming only the string the user
    wrote, without naming what is in effect instead, would leave them knowing this tool
    was confused without knowing they are exposed — so both are always named together.
    """
    subs = _substituted_dm_policy_channels(ctx.config)
    if not subs:
        return ""
    parts = [
        f"{name!r} wrote dmPolicy={written!r}, which {name} does not accept — OpenClaw"
        f' runs it on "{resolved}" instead'
        for name, (written, resolved) in sorted(subs.items())
    ]
    return (
        " Unmodeled dmPolicy: " + "; ".join(parts) + ". Not counted as a leg above,"
        " because a typo is not a deliberate choice — but the effective posture is not"
        " the one written; a sender it has approved once can send again."
    )


def _meaningful_tool_surface(ctx: Context) -> bool:
    """Whether the config exposes a RECOGNIZED capability surface (or the user has
    attested the agent's tools), so the A1 legs can be trusted instead of hedged with
    the thin-surface WARN. A no-op tools.allow entry that matches no capability hint
    does NOT count — that was the old PASS-wash (add 'noop' → WARN flips to PASS).

    Note: this is single-agent A1's notion of 'tool config is visible'; cross-agent
    aggregation deliberately stays out (B45/B46/B47 own the multi-agent reassembly)."""
    cfg = ctx.config
    tools = _enabled_tools(cfg)
    if (
        _hint(tools, INPUT_TOOL_HINTS)
        or _hint(tools, SENSITIVE_TOOL_HINTS)
        or _hint(tools, OUTBOUND_TOOL_HINTS)
    ):
        return True
    if _web_fetch_enabled(cfg) or _profile_is_powerful(dig(cfg, "tools.profile")):
        return True
    if bool(dig(cfg, "tools.elevated.allowFrom")):
        return True
    return _capabilities_attested(ctx)


def _model_names(cfg: dict) -> list[str]:
    names = []
    md = dig(cfg, "agents.defaults.model")  # real OpenClaw location
    if isinstance(md, dict):
        if md.get("primary"):
            names.append(str(md["primary"]))
        fb = md.get("fallbacks")
        if isinstance(fb, list):
            names.extend(str(x) for x in fb)
    models = cfg.get("models")
    if isinstance(models, dict):
        for name, m in models.items():
            names.append(str((m.get("provider") if isinstance(m, dict) else "") or name))
    elif isinstance(models, list):
        names.extend(str(m) for m in models)
    return names


# F-040: OpenClaw DOES resolve a default agent at runtime (defaultId ??
# sessionDefaults.defaultAgentId ?? "main") and DOES expose per-agent tool config
# (agents.list[].tools.{alsoAllow, profile, byProvider, toolsBySender}) — this check
# consults neither. A1's legs are computed from the GLOBAL config surface, so a
# multi-agent install's trifecta view stays an aggregate, not any single agent's real
# exposure; reading a specific agent's effective grants here is a deferred enhancement
# (check_agent_separation already offers an attested per-agent alternative today).
# Reframed from an interactive guide.py question (F-039) to this static note: a
# blocking input() prompt would hang under headless CLI invocation (the tool's primary
# usage — see SKILL.md), so this stays a caveat, not an attempt to resolve one agent.
def _persistence_note(ctx: Context) -> str:
    """F-169: breaking a leg does not remove what is already in the identity files.

    OpenClaw injects the bootstrap/identity files into context EVERY TURN, so a directive
    already written into one of them keeps loading no matter what the config says
    afterwards. Palo Alto (Mishra & Morgan, 2026-01-29) call persistent memory an
    accelerant on the trifecta; Zenity (Cohen & Donato, 2026-02-04) demonstrated the whole
    chain against OpenClaw — indirect injection, then a scheduled task rewriting SOUL.md
    every two minutes — under the framing "no software vulnerability is required".

    The user-visible gap this closes: someone who breaks a leg watches A1 flip to PASS and
    is told nothing about the directive still sitting in SOUL.md. Config hardening cannot
    clear a content finding — measured at v3.60.0, a content_injection home with every
    hardening lever applied at once (sandbox all, workspaceAccess ro, fs.workspaceOnly,
    exec gated, trifecta broken so A1 PASSes) still graded F/49 with B6 FAIL.

    Deliberately NOT a fourth leg in A1, and the reasons are recorded in F-169 so this is
    not re-litigated: the trifecta is a named three-part concept and printing "4/4" would
    redefine someone else's term in our own output; persistence is not a grantable
    capability, so the leg would be on for everyone and discriminate nothing; and A1 is
    CRITICAL and hard-caps the grade, so a 3-of-4 threshold would FAIL a config with
    input + sensitive + memory and no outbound, which cannot exfiltrate.

    The write-path term is `_real_exec_enabled` OR a granted write tool, not
    `_enabled_tools` alone: measured on this machine, the real config resolves to
    ``['exec']`` with no write tool in `_B55_FS_WRITE_TOOLS`, so keying on the write set
    alone would silence the note on precisely the setup it was written for. An exec
    capability IS a write path — a shell writes files.
    """
    # ctx.bootstrap is keyed by PATH ("workspace/AGENTS.md"), not by bare filename — a
    # membership test against BOOTSTRAP_FILES matches nothing at all. Measured: the first
    # version of this note never fired on any home, including the real one.
    # getattr, not attribute access: a caller can hand this a Context-shaped stub that
    # predates the field (tests/test_b283_shallow_reads.py does), and a note must never be
    # the thing that raises inside a check.
    present = sorted({
        n.rsplit("/", 1)[-1] for n in (getattr(ctx, "bootstrap", None) or {})
        if n.rsplit("/", 1)[-1] in BOOTSTRAP_FILES
    })
    if not present:
        return ""
    cfg = getattr(ctx, "config", None) or {}
    if not (_real_exec_enabled(cfg) or (set(_enabled_tools(cfg)) & _B55_FS_WRITE_TOOLS)):
        return ""
    # Names the RISK, not the check ids that find it. F-169 proposed pointing "at the
    # content ring (B6/B161)" and the first version printed those ids verbatim into
    # owner-facing output, which tests/test_brand_consistency.py rejects: a reader is
    # owed what to look at, not our internal numbering.
    named = ", ".join(present[:3]) + (", …" if len(present) > 3 else "")
    return (
        f" Note: {len(present)} identity/bootstrap file(s) ({named}) load into context"
        " every turn, and this config grants a write path to them. Breaking a trifecta leg"
        " changes what the agent can do NEXT — it does not remove a directive already"
        " written into those files, which keeps loading either way. Read what those files"
        " actually say, not just the config."
    )


def _multi_agent_note(ctx: Context) -> str:
    # B-699: both roster shapes, and the note names the one this config actually uses —
    # telling a 2026.8.1 user their agents are "under agents.list" names a key their file
    # does not contain.
    roster = agent_roster(ctx.config)
    n = len(roster)
    if n <= 1:
        return ""
    where = "agents.entries" if roster[0].path.startswith("agents.entries.") else "agents.list"
    return (
        f" Note: config declares {n} agents under {where} — this trifecta view is"
        f" the aggregated global surface, not any single agent's effective grants. This"
        f" check does not resolve or read a specific agent's own tool config, so if you"
        f" run one named agent, its real exposure may differ from this global reading."
    )


def _peragent_sandbox_evidence(cfg: dict) -> list:
    """Unsafe per-agent sandbox OVERRIDES under agents.list[].sandbox.* (real schema:
    agents.list[N].sandbox.{mode,docker.network,docker.binds,workspaceAccess}). B4 otherwise
    reads only agents.defaults.sandbox, so a named agent that overrides a safe default is
    missed entirely (C-058). Returns attributed evidence strings; empty when none."""
    out = []
    # `scope` resolves from the AGENT's sandbox first and the defaults second
    # (`resolveSandboxScope`), so the defaults node has to be in hand for every agent.
    # A plain walk, not `dig()`: this reads a non-leaf NODE, and a non-leaf `dig()` path
    # cannot be manifest-verified (`risk.py`'s own note on the same problem). The leaf
    # children under it are dist-verified already; the container is not a config setting.
    _defaults_sandbox = cfg.get("agents") if isinstance(cfg, dict) else None
    _defaults_sandbox = (_defaults_sandbox or {}).get("defaults") \
        if isinstance(_defaults_sandbox, dict) else None
    _defaults_sandbox = (_defaults_sandbox or {}).get("sandbox") \
        if isinstance(_defaults_sandbox, dict) else None
    if not isinstance(_defaults_sandbox, dict):
        _defaults_sandbox = {}
    for _agent in agent_roster(cfg):  # B-699: agents.entries as well as agents.list
        a = _agent.entry
        sb = a.get("sandbox")
        if not isinstance(sb, dict):
            continue
        # `id` is the record key on the 2026.8.1 shape, so it names the agent even when
        # the entry carries no `name` — better evidence than "<unnamed>" for every agent.
        name = a.get("name") or _agent.id or "<unnamed>"
        if sb.get("mode") == "off":
            out.append(f"agent '{name}': sandbox.mode=off (exec runs on the host)")
        docker = sb.get("docker") if isinstance(sb.get("docker"), dict) else {}
        # Computed once and reused for BOTH docker legs below (network and binds): the
        # vendor discards this agent's entire `sandbox.docker` under shared scope, not
        # just the binds half of it (see the comment block just below).
        _scope = _resolve_sandbox_scope(sb, _defaults_sandbox)
        if docker.get("network") == "host" and _scope != "shared":
            out.append(f"agent '{name}': sandbox.docker.network=host (no network isolation)")
        # B-673: two false FAILs lived in the four lines this replaces, and both were
        # Golden Rule #5 violations because `check_sandbox` turns any entry here into a
        # hard FAIL.
        #
        # 1. NO SCOPE GATE. Under `sandbox.scope: "shared"` (at either level, or the legacy
        #    `perSession: false`) OpenClaw DISCARDS this agent's whole `sandbox.docker` --
        #    BOTH its `network` and its `binds` -- so neither reaches a container. Executed
        #    against openclaw@2026.8.2 rather than read -- `resolveSandboxConfigForAgent`,
        #    dist/config-*.js:
        #        scope=shared at GLOBAL  -> binds ["/g:/g"]   (the agent's are gone)
        #        scope=shared at AGENT   -> binds null
        #        default (scope=agent)   -> binds ["/g:/g", "/a:/a"]  (a UNION, not override)
        #    We were accusing a user of mounting docker.sock on a config where the mount
        #    does not happen.
        # The fix is to USE the vetted `_resolve_sandbox_scope` rather than write a third
        # variant of it: it moved down out of `risk.py` into `_shared.py` in this change so a
        # Layer-2 check can reach it. Validated against the vendor over 151 configs -- the
        # shared/not-shared partition agreed 150/150, across both roster shapes, 17 `scope`
        # values and 9 `perSession` values.
        #
        # 2. NO `:ro` NARROWING -- and this one is DELIBERATELY still not applied. The first
        #    version of this fix also excused a verifiably read-only bind, borrowing
        #    `_bind_mode_is_ro` from `risk.py`. The C-135 pass killed it, and was right:
        #
        #      * OpenClaw's own `getBlockedBindReason`
        #        (dist/validate-sandbox-security-*.js) parses ONLY the source path and never
        #        looks at the mode segment. Executed: `/var/run/docker.sock:...:ro` and the
        #        same bind without `:ro` return an identical blocked verdict. **The vendor
        #        assigns `:ro` zero security value here.**
        #      * And the blocklist has a hole `:ro` walks straight through. `~/.ssh`,
        #        `/etc`, `/` and `docker.sock` ARE blocked, but `~/.openclaw` is not -- it is
        #        a sibling of the blocked `~/.config`/`~/.ssh` entries and matches none of
        #        them. Executed: `/home/<user>/.openclaw:/oc:ro` is ALLOWED and mounts. That
        #        directory holds `credentials/` and the state DB carrying live OAuth tokens
        #        (F-183), so a read-only mount of it is a total credential read.
        #
        #    `risk.py`'s "a `:ro` bind is information disclosure, a different risk class" is
        #    true for RISK-12, which is a write/tamper chain. It is FALSE for B4, whose own
        #    remediation says "drop host and docker.sock binds" with no mode qualifier.
        #    Importing a RISK-12-shaped helper into a general sandbox check was a category
        #    error. tests/test_b673_peragent_bind_scope.py pins the read-only case as
        #    REPORTED so nobody re-adds the narrowing.
        # C-454: normalization via the shared `_sandbox_docker_binds` (checks/_shared.py)
        # rather than this function's own dict-lookup-plus-isinstance chain -- same
        # divergence class B-673 already fixed for `_resolve_sandbox_scope` above, one
        # field over. `sb` (not `docker`, which was already coerced to `{}` above) is
        # passed so a malformed `sandbox.docker` shape normalizes to `None`.
        #
        # C-135 (independent, post-commit): the comment that used to sit here claimed
        # this branch "never fail-closed on that shape... before this extraction" --
        # false, reproduced directly against bf31513^: the pre-extraction code read
        # a direct dict lookup of the raw `binds` key, gated on bare Python truthiness, so ANY truthy value
        # (a dict, a non-empty string, a nonzero int) fired the evidence, same as a
        # well-formed list. `_sandbox_docker_binds` narrows that to string/list only and
        # returns `None` for anything else -- silently treating "malformed" the same as
        # "absent" here regressed a real FAIL to UNKNOWN (agents.defaults.sandbox.docker.
        # binds={"src": "/etc", "dst": "/etc"} verified FAIL on bf31513^, UNKNOWN on
        # bf31513). Fail closed on `None` instead, matching `_sandbox_has_writable_bind`'s
        # own `None -> True` treatment and the pre-extraction behavior this was supposed
        # to preserve.
        binds = _sandbox_docker_binds(sb)
        if binds is None and _scope != "shared":
            out.append(
                f"agent '{name}': sandbox.docker.binds is present but not a recognizable "
                "shape (expected a bind-spec string or a list of them) — cannot rule out "
                "a host-path bind"
            )
        elif binds and _scope != "shared":
            out.append(f"agent '{name}': sandbox.docker.binds exposes host paths")
            if _bind_mentions_docker_sock(binds):
                out.append(
                    f"agent '{name}': sandbox.docker.binds mounts docker.sock "
                    "(grants host control to the sandbox — container escape)"
                )
        if sb.get("workspaceAccess") == "rw":
            out.append(
                f"agent '{name}': sandbox.workspaceAccess=rw (agent can write the mounted workspace)"
            )
    return out


# B-233 round 3 (C-135): world-open / near-catch-all PUBLIC CIDRs (e.g. 0.0.0.0/0,
# ::/0, 0.0.0.0/1) are NOT a genuine trust boundary — every source IP matches, so the
# trusted-proxy identity header stays attacker-spoofable by anyone. Grounded against
# dist isTrustedProxyAddress -> isIpInCidr -> ipaddr.parseCIDR (prefix-len 0 matches
# all). A single host always constrains, and so does any PRIVATE range regardless of
# prefix length — a private range (RFC1918 IPv4, or an IPv6 ULA like fc00::/7 / RFC4193)
# is not globally routable, so an external attacker cannot source a connection from it,
# whatever its prefix. Only reject over-broad PUBLIC ranges: IPv4 prefixes shorter than
# /8 and IPv6 prefixes shorter than /16 — short enough that a genuine corp-sized public
# allocation (a /24, a /32 LB IP) still passes, while anything spanning (or nearly
# spanning) the public internet does not.
_MIN_IPV4_PREFIXLEN = 8
_MIN_IPV6_PREFIXLEN = 16

# Do NOT use ``ipaddress.*Network.is_private`` here — its meaning changed across the
# Python versions we support (3.9+). On older interpreters it was computed as
# "network address is private AND broadcast address is private", which makes
# ``0.0.0.0/0`` report is_private=True (0.0.0.0 falls in 0.0.0.0/8 and
# 255.255.255.255 is itself special-cased), and likewise ``0.0.0.0/1`` (broadcast
# 127.255.255.255 is loopback). Trusting it would accept a world-open proxy list as a
# genuine constraint on those interpreters — reinstating the exact spoofable-gateway
# lying-PASS this check exists to prevent. Test the containment explicitly instead, so
# the verdict is identical on every supported Python.
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _net_is_private(net) -> bool:
    """True when *net* is wholly contained in a non-globally-routable range."""
    return any(
        net.version == private.version and net.subnet_of(private)
        for private in _PRIVATE_NETS
    )


def _is_constraining_proxy_entry(entry) -> bool:
    """True when *entry* is a genuine trusted-proxy identifier: a specific host, a
    hostname, a private range (any prefix), or a public CIDR bounded enough to be a
    real trust boundary (not a catch-all)."""
    if not isinstance(entry, str):
        return False
    s = entry.strip()
    if not s or s == "*":
        return False
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        # Not a parseable IP/CIDR (e.g. a hostname) — a specific, non-wildcard
        # identifier is still a genuine constraint.
        return True
    if net.num_addresses == 1 or _net_is_private(net):
        return True
    if net.version == 4 and net.prefixlen < _MIN_IPV4_PREFIXLEN:
        return False
    if net.version == 6 and net.prefixlen < _MIN_IPV6_PREFIXLEN:
        return False
    return True


def _trusted_proxies_ok(value) -> bool:
    """True when *value* (``gateway.trustedProxies``) contains at least one
    genuinely-constraining entry once blank/wildcard/over-broad entries are ignored —
    e.g. ``["10.0.0.5", ""]`` is OK (OpenClaw ignores the blank candidate and still
    enforces 10.0.0.5); ``[]``, ``["*"]``, and ``["0.0.0.0/0"]`` are not."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return False
    return any(_is_constraining_proxy_entry(item) for item in value)


def check_control_plane_mutation(ctx: Context) -> Finding:
    """B32 — Control-plane mutation reachability via gateway.

    FAIL   — gateway.tools.allow re-enables a control-plane tool (plugin lifecycle,
             config mutation, cron/automations scheduling, or cross-session spawn/send
             exposed over HTTP).
    WARN   — gateway is exposed (non-loopback bind or auth.mode=="none") AND
             control-plane tools are not explicitly denied in gateway.tools.deny.
    PASS   — control-plane tools are denied / not re-enabled.
    UNKNOWN — no gateway config present.
              F-140: sets ``not_applicable`` only when the config locus was read
              COMPLETELY and ``gateway`` is still not a dict. The HTTP gateway is the
              ONLY reachability path this check models — with no gateway there is no
              HTTP surface over which a control-plane tool could be reached, so absence
              here is genuine inapplicability rather than an unassessed risk. The whole
              read is ``ctx.config``, so config-locus completeness is the entire proof
              obligation; an absent/unparseable/truncated config degrades the flag back
              to ordinary UNKNOWN and the check keeps its blind-spot posture.

    B-835: allow/deny entries are matched by NORMALISED identity (trim + lowercase +
    the vendor's own alias fold — ``toolgrant._normalize_tool_name``), the same way
    OpenClaw's own ``normalizeToolPolicyName`` resolves ``gateway.tools.allow``/
    ``deny`` before comparing — so ``"Automations"``, ``" automations "`` and the
    legacy alias ``"cron"`` are all recognised as the one canonical control-plane
    tool. The FAIL message still shows each entry in the SPELLING the operator wrote
    (not the canonical form), so a config that names the legacy alias is not reported
    back under a name that never appears in that config.
    """
    cfg = ctx.config
    gw = cfg.get("gateway")
    if not isinstance(gw, dict):
        return _finding(
            "B32",
            UNKNOWN,
            "No gateway config — control-plane mutation reachability not applicable.",
            "—",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )

    gw_tools = gw.get("tools") if isinstance(gw.get("tools"), dict) else {}
    allow_list: list[str] = gw_tools.get("allow") or [] if isinstance(gw_tools, dict) else []
    deny_list: list[str] = gw_tools.get("deny") or [] if isinstance(gw_tools, dict) else []

    if not isinstance(allow_list, list):
        allow_list = []
    if not isinstance(deny_list, list):
        deny_list = []

    deny_set = _b32_normalize_tools(deny_list)

    # FAIL: a control-plane tool is explicitly re-enabled in gateway.tools.allow.
    # Matched by normalised (canonical) identity, but reported back in the spelling
    # the operator actually wrote (raw, merely trimmed) — see the docstring's B-835
    # note. Deduplicated + sorted so two spellings of the same tool (e.g. "cron" and
    # "Automations" both present) do not repeat the same canonical finding twice.
    re_enabled = sorted(
        {
            t.strip()
            for t in allow_list
            if isinstance(t, str)
            and _toolgrant._normalize_tool_name(t) in _B32_CONTROL_PLANE_TOOLS
        }
    )
    if re_enabled:
        return _finding(
            "B32",
            FAIL,
            "gateway.tools.allow re-enables control-plane tool(s) over the HTTP "
            "gateway — config mutation / cron / cross-session send is reachable via "
            f"HTTP: {', '.join(re_enabled)}",
            "Remove control-plane tools ("
            + ", ".join(sorted(_B32_CONTROL_PLANE_TOOLS))
            + ") from gateway.tools.allow. Add them to gateway.tools.deny to "
            "explicitly block HTTP access.",
            evidence=re_enabled,
        )

    # WARN: gateway is network-exposed and control-plane tools are not denied
    bind = parse_bind_host(gw.get("bind", ""))
    auth_mode = dig(cfg, "gateway.auth.mode")
    is_exposed = (
        bind and bind not in LOOPBACK and bind not in {"", "loopback"}
    ) or auth_mode == "none"
    cp_not_denied = not (_B32_CONTROL_PLANE_TOOLS & deny_set)

    if is_exposed and cp_not_denied:
        warn_detail = (
            f"Gateway is network-exposed (bind={bind or '?'}, auth.mode={auth_mode!r}) "
            "and control-plane tools are not explicitly in gateway.tools.deny — "
            "an authenticated caller could reach mutation endpoints"
        )
        return _finding(
            "B32",
            WARN,
            warn_detail,
            "Add control-plane tool names ("
            + ", ".join(sorted(_B32_CONTROL_PLANE_TOOLS))
            + ") to gateway.tools.deny to explicitly block HTTP mutation access, "
            "even for authenticated callers.",
            evidence=[warn_detail],
        )

    denied_preview = sorted(_B32_CONTROL_PLANE_TOOLS & deny_set)
    pass_detail = (
        "Control-plane tools are not re-enabled via gateway.tools.allow"
        + (f" and are denied: {', '.join(denied_preview)}" if denied_preview else "")
        + "."
    )
    return _finding(
        "B32",
        PASS,
        pass_detail,
        "Keep control-plane tools out of gateway.tools.allow and "
        "add them to gateway.tools.deny for defence-in-depth.",
    )


def check_controlui_origins(ctx: Context) -> Finding:
    """B56 (NC-4) — Control-UI cross-origin allow-all.

    Grounded (docs.openclaw.ai/gateway/security): for non-loopback Control UI
    deployments `gateway.controlUi.allowedOrigins` is required by default, and
    `["*"]` is "an explicit allow-all browser-origin policy, not a hardened default."
    A wildcard lets any website drive the Control UI (CSRF / origin bypass).

    UNKNOWN — allowedOrigins not set: the default is restrictive, and whether the
              Control UI is exposed beyond loopback is not determinable from config.
    FAIL    — the list contains "*".
    PASS    — an explicit non-wildcard origin allowlist.
    """
    cfg = ctx.config
    origins = dig(cfg, "gateway.controlUi.allowedOrigins")
    if origins is None:
        return _finding(
            "B56",
            UNKNOWN,
            "gateway.controlUi.allowedOrigins is not set — its default is restrictive "
            "(cross-origin denied), and whether the Control UI is exposed beyond loopback "
            "cannot be determined from config alone.",
            "If you expose the Control UI beyond loopback, set "
            "gateway.controlUi.allowedOrigins to an explicit list of trusted origins "
            '(never "*").',
            config_field_paths={"gateway.controlUi.allowedOrigins"},
        )
    vals = [str(o) for o in origins] if isinstance(origins, list) else [str(origins)]
    if "*" in vals:
        return _finding(
            "B56",
            FAIL,
            'gateway.controlUi.allowedOrigins contains "*" — an allow-all browser-origin '
            "policy, so any website can drive the Control UI (CSRF / origin bypass).",
            'Replace the "*" wildcard in gateway.controlUi.allowedOrigins with an '
            "explicit list of trusted origins.",
            evidence=['gateway.controlUi.allowedOrigins contains "*" (allow-all browser origins)'],
        )
    return _finding(
        "B56",
        PASS,
        'Control-UI allowed origins are an explicit allowlist (no "*" wildcard).',
        "Keep gateway.controlUi.allowedOrigins to an explicit list of trusted origins.",
    )


# ---------------------------------------------------------------------------
# B-290 (ENV-4): the gateway's auth credential can come from the ENVIRONMENT, not the
# config — and when it does, it supplies the auth MODE as well.
#
# resolveGatewayAuth (auth-resolve-NyPBrh8F.js:19-46) resolves the credential first, then
# derives the mode:
#     else if (authConfig.mode) { mode = authConfig.mode; ... }
#     else if (password)        { mode = "password"; modeSource = "password"; }
#     else if (token)           { mode = "token";    modeSource = "token"; }
# and the credential itself comes from resolveGatewayCredentialsFromValues
# (credentials-DesN22Ui.js:30-42), which reads env.OPENCLAW_GATEWAY_TOKEN and
# env.OPENCLAW_GATEWAY_PASSWORD (:32-33).
#
# The consequence is decisive for B2: server-runtime-config-r5ejxORO.js:78 refuses a
# non-loopback bind unless `hasSharedSecret`, and that shared secret may be entirely
# env-supplied — so a host with `gateway.bind=0.0.0.0` and NO `gateway.auth` block is
# genuinely authenticated, and B2's FAIL on it was a false positive on a correctly
# secured host.
#
# THREE deliberate constraints keep this from becoming a lying PASS:
#
# 1. It is ASYMMETRIC. Presence of an env credential is a POSITIVE signal only; ABSENCE
#    is never read as "no auth". The auditing process's environment is not the gateway
#    service's, so a check that FAILed on env absence would false-positive massively —
#    and B2's existing FAIL when nothing is observable is the CORRECT, deliberate
#    false-negative boundary (Golden Rule #5).
# 2. Evidence must be PERSISTENT and on disk — a systemd unit's Environment=/
#    EnvironmentFile=, or a global runtime dotenv file. `persistent_env_evidence`
#    explicitly does NOT fall back to os.environ: a token exported in the operator's
#    terminal says nothing about a service started months ago by systemd, and letting it
#    clear a CRITICAL finding would key the verdict on the shell the audit happened to be
#    launched from. The ambient-shell case therefore stays a FAIL, not a PASS.
# 3. "env WINS over config" is FALSE for server auth and is not relied on here.
#    resolveGatewayAuth passes tokenPrecedence/passwordPrecedence: "config-first"
#    (auth-resolve-NyPBrh8F.js:23-24), so a configured token beats the env one. The gap
#    is only the config-LESS path, which is exactly what the softening is scoped to.
#
# WHY THIS CANNOT PRODUCE A LYING PASS — the argument that justifies softening a CRITICAL
# check at all. Suppose an observed credential does NOT actually reach the running
# gateway (say it sits only in ~/.config/openclaw/gateway.env, which
# loadGlobalRuntimeDotEnvFiles loads by default, dotenv-global-mWLbBl_z.js:87-100, but
# which resolveGatewayRunDotEnvPaths — pre-bootstrap-8G8HyMEQ.js:55-62, <stateDir>/.env
# plus <configDir>/.env — does not name for `gateway run`). Then `hasSharedSecret` is
# false, and server-runtime-config-r5ejxORO.js:78 throws
# "refusing to bind gateway to <host>:<port> without auth" — an UNCONDITIONAL guard with
# no bypass flag anywhere in the dist. So the gateway does not start.
#
# The two outcomes are therefore: the credential reaches the gateway (it is authenticated,
# and the old FAIL was the false positive), or it does not (there is no listener at all).
# Neither leaves a live, exposed, unauthenticated gateway that this check has been talked
# out of reporting. That is the whole reason the softening is sound; if a future change to
# OpenClaw made that bind guard conditional, this reasoning — and this softening — would
# have to be revisited.
_GATEWAY_ENV_CREDENTIAL_VARS = ("OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_PASSWORD")


def _gateway_env_credential(ctx: Context) -> "tuple[str | None, str | None]":
    """An env-supplied gateway credential observed in a persistent artifact.

    Returns ``(value, source)`` or ``(None, None)``. The value is returned only so the
    caller can test presence — it is a secret and must never reach a message, evidence
    entry, or log (§8).

    ``source`` IS meant to reach evidence/detail (every caller names it so the operator
    knows where to go fix the setting), so it is redacted here, once, for all three
    callers (B41/B2/B80) rather than at each call site — the same home-rooted-absolute-
    path hazard ``_detail_path`` exists for (B-856; ``persistent_env_evidence`` can hand
    back either a global dotenv's absolute path or a systemd unit path, and both can be
    home-rooted). ``_detail_path`` already renders the composite unit form
    (``"<unit> (Environment=)"``) correctly since it rewrites any string that merely
    *starts with* the home/home-parent prefix.
    """
    for var in _GATEWAY_ENV_CREDENTIAL_VARS:
        value, source = persistent_env_evidence(ctx, var)
        if value is not None and value.strip():
            return value, _detail_path(source, ctx.home) if source else "an environment file"
    return None, None


def _gateway_config_token(cfg: dict, auth_mode) -> "tuple[str | None, bool]":
    """The config-supplied gateway credential OpenClaw derives ``auth.mode`` from.

    B-312: `resolveGatewayAuth` derives `mode="token"` from `gateway.auth.token` /
    `gateway.token` whenever `authConfig.mode` is falsy (auth-resolve-NyPBrh8F.js:34-42),
    read config-FIRST (:23-24) ahead of any environment variable. This is the single
    source of truth for that derivation — B2 (`check_gateway`) and B80
    (`check_gateway_rate_limit`) both call it so they can never disagree about what
    counts as an authenticated config-token gateway (B-310 round 2 / C-135).

    Returns ``(token, strong)``: ``token`` is the stripped credential, or ``None`` when
    absent OR when ``auth_mode`` is not ``None`` (an explicit mode means OpenClaw is not
    deriving the mode from mere token presence — the caller already has ``auth_mode``
    directly). ``strong`` is whether the credential meets the same >=24-char bar as the
    env leg and as B2's own token-length clause (`hasSharedSecret` accepts ANY non-empty
    value — no minimum length exists in the dist — so only length is a signal; the value
    itself must never reach a message, evidence entry, fix string, or log, §8).
    """
    token = dig(cfg, "gateway.auth.token") or dig(cfg, "gateway.token")
    token = (
        token.strip()
        if auth_mode is None and isinstance(token, str) and token.strip()
        else None
    )
    strong = token is not None and len(token) >= 24
    return token, strong


def check_credential_blast_radius(ctx: Context) -> Finding:
    """B41 — Credential blast-radius assessment.

    Inventories the credential surface exposed in this OpenClaw config and
    assesses whether an attacker with untrusted ingress + outbound capability
    could reach ALL of them in a single compromise.

    WARN    — credentials exist AND the agent has an untrusted-ingress path
              (open channels or an input tool) AND an outbound/exec capability
              — one compromise's blast radius spans every listed provider.
    PASS    — credentials exist but the ingress+outbound combination is not
              present — blast radius is not broadly reachable.
    UNKNOWN — no auth.profiles and no gateway.auth.token found to assess. When the ONLY
              reason none was found is that a systemd unit or global dotenv file the
              collector read was truncated by its byte cap
              (``limit_hits_for(ctx, LIMIT_DOMAIN_ENV)``) — so an env-supplied
              OPENCLAW_GATEWAY_TOKEN/_PASSWORD could sit past the cut — this UNKNOWN is
              ``engine_degraded=True`` (B-657): the credential surface this
              check inventories may be non-empty and simply unread, not genuinely absent.

    PRIVACY: provider names only are included in findings.  The account/email
    portion of profile keys (after ":") and any token values are NEVER emitted.
    """
    cfg = ctx.config

    # --- inventory credential surface ---
    profiles = dig(cfg, "auth.profiles") or {}
    has_gateway_token = bool(dig(cfg, "gateway.auth.token") or dig(cfg, "gateway.token"))
    # B-290 (ENV-4): the gateway credential does not have to be in the config at all.
    # resolveGatewayCredentialsFromValues (credentials-DesN22Ui.js:32-33) reads
    # OPENCLAW_GATEWAY_TOKEN / OPENCLAW_GATEWAY_PASSWORD straight from the environment, so
    # a config-only inventory undercounts a host whose gateway secret lives in its systemd
    # unit or a global dotenv file. Persistent artifacts only — never os.environ, whose
    # contents belong to the auditing shell rather than to the gateway service.
    _env_gw_token, _env_gw_src = _gateway_env_credential(ctx)
    has_env_gateway_token = _env_gw_token is not None

    # Collect unique provider names from profile keys of the form "<provider>:<account>"
    # CRITICAL: extract only the part BEFORE the first ":" — never the account/email.
    providers: list[str] = []
    if isinstance(profiles, dict):
        seen: set[str] = set()
        for key in profiles:
            provider = str(key).split(":", 1)[0]
            if provider and provider not in seen:
                seen.add(provider)
                providers.append(provider)

    has_credentials = bool(providers) or has_gateway_token or has_env_gateway_token

    if not has_credentials:
        # B-657: "no credentials" is a claim that the env-sourced leg
        # (has_env_gateway_token, via _gateway_env_credential -> persistent_env_evidence)
        # was read to completion. A systemd unit or global dotenv file the collector DID
        # read but truncated at its byte cap can hide a real OPENCLAW_GATEWAY_TOKEN/
        # _PASSWORD past the cut, so this is present-but-unread, not genuinely absent —
        # the exact contrast catalog.py's Finding.engine_degraded exists for, same
        # DEGRADED_CHECK_CAP consequence as the B6/B172 fix (f748869).
        if limit_hits_for(ctx, LIMIT_DOMAIN_ENV):
            return _finding(
                "B41",
                "UNKNOWN",
                "No auth.profiles or gateway.auth.token found in the config, and no "
                "environment-supplied gateway credential was found in the systemd unit(s) "
                "or global dotenv file(s) that were read — but at least one of them "
                "exceeded the collector's byte cap, so a credential past the cut would not "
                "have been seen. The credential surface cannot be ruled empty.",
                "Keep OpenClaw's systemd unit files and global dotenv files "
                "(~/.openclaw/.env, ~/.config/openclaw/gateway.env) under the collector's "
                "size cap, then re-run the audit.",
                engine_degraded=True,
            )
        return _finding(
            "B41",
            "UNKNOWN",
            "No credential profiles found to assess.",
            "—",
        )

    # --- assess reachability ---
    tools = _enabled_tools(cfg)
    has_untrusted_ingress = bool(_external_input_channels(cfg)) or _hint(tools, INPUT_TOOL_HINTS)
    has_outbound = _hint(tools, OUTBOUND_TOOL_HINTS) or bool(dig(cfg, "tools.elevated.allowFrom"))
    reachable = has_untrusted_ingress and has_outbound

    any_gateway_token = has_gateway_token or has_env_gateway_token
    provider_list = ", ".join(sorted(providers))
    gateway_note = " + gateway token" if any_gateway_token else ""

    # Build evidence list — provider names and gateway marker only, never emails/values.
    # B-290: the env-supplied case records only WHERE the credential is configured, never
    # its value; `_gateway_env_credential` returns the value solely so presence can be
    # tested, and it is never placed in a message or in evidence (§8).
    evidence: list[str] = []
    if providers:
        evidence.append(f"providers: {provider_list}")
    if has_gateway_token:
        evidence.append("gateway-token: present")
    elif has_env_gateway_token:
        evidence.append(f"gateway-token: present, supplied by {_env_gw_src}")

    # The subject is built from what is actually present, never from `n` alone.
    # `n` counts the gateway token alongside the provider profiles, so a home with a
    # gateway token and no profiles used to render "1 provider credential(s)
    # (providers: )" — an empty parenthetical, and a count attached to the wrong noun.
    # The evidence list two blocks below has always been guarded this way; the prose
    # was not.
    if providers:
        subject = (
            f"{len(providers)} provider credential(s) "
            f"(providers: {provider_list}){gateway_note}"
        )
        verb = "are"
        blast = "one compromise's blast radius spans all of them"
    else:
        subject = "The gateway token"
        verb = "is"
        blast = "a compromise of it reaches everything it authorises"

    if reachable:
        detail = (
            f"{subject} {verb} reachable by an agent with untrusted ingress and "
            f"outbound tools — {blast}. Use least-privilege scopes, isolate "
            "high-value profiles, and keep them rotatable."
        )
        return _finding(
            "B41",
            WARN,
            detail,
            "Use least-privilege OAuth scopes for each provider profile, isolate "
            "high-value credentials into dedicated agents with no untrusted-ingress "
            "channels, and ensure all credentials are rotatable. Remove open channel "
            "policies (dmPolicy/groupPolicy) or outbound tools where not needed.",
            evidence,
        )

    # B-306: `has_credentials`/`reachable` are not equally config-dependent.
    # `has_env_gateway_token` (above) is read from a PERSISTENT, config-INDEPENDENT
    # artifact (a systemd unit or global dotenv file — see _gateway_env_credential), so a
    # real credential can still be legitimately found even when openclaw.json itself is
    # unparseable/unreadable. `reachable`, however, is derived entirely from
    # ctx.config (_external_input_channels/_enabled_tools/tools.elevated.allowFrom) and
    # therefore collapses to False whenever ctx.config == {} — so the "not reachable" PASS
    # below is not actually known on a blind config, only assumed. Guarded here, right
    # before that PASS: the `reachable` WARN above needs no guard of its own because
    # `reachable` can never be True with ctx.config == {} in the first place.
    unreadable = _config_unreadable("B41", ctx)
    if unreadable is not None:
        return unreadable

    # Same rule as the WARN branch above: `n` folds the gateway token into a count
    # whose noun is "credential profile", which a token is not.
    if providers:
        present = f"{len(providers)} credential profile(s){gateway_note} present"
    else:
        present = "The gateway token is present"
    detail = (
        f"{present}; no untrusted-ingress + outbound path "
        "makes them broadly reachable."
    )
    return _finding(
        "B41",
        PASS,
        detail,
        "Keep channels on allowlist policies and avoid adding outbound tools "
        "alongside credential profiles without careful scope restrictions.",
        evidence,
    )


# ---------------------------------------------------------------------------
# B373 (C-527): OPENCLAW_CONFIG_READONLY — an externally-managed,
# read-only config posture. New in the OpenClaw 2026.9.4 release; grounded against the
# LIVE installed 9.4 dist (not the changelog), verbatim:
#
#   paths-V8kKIUzt.mjs:60-67
#     function resolveIsNixMode(env = process.env) {
#         return env.OPENCLAW_NIX_MODE === "1";
#     }
#     function resolveIsConfigReadOnly(env = process.env) {
#         return env.OPENCLAW_CONFIG_READONLY === "1" || resolveIsNixMode(env);
#     }
#
# So Nix mode implies config-read-only, and only the exact string "1" enables either.
# `config-write-guard-Y0VYnQza.mjs` throws a dedicated `ConfigReadOnlyError`
# ("Config is externally managed (`OPENCLAW_CONFIG_READONLY=1`), so OpenClaw treats
# openclaw.json as immutable.") from every config-mutating command path
# (`management-mutations`, `plugins-{install,update,uninstall}-command`,
# `update-repair-command`, `onboarding-plugin-install`, …) — this is wired through the
# whole write surface, not a single guarded call site.
#
# The vendor treats the variable as security-relevant itself: `isBlockedConfigEnvVar`
# (config-env-vars-BeYgbFTQ.mjs:43-45) refuses to let `config.env` set
# OPENCLAW_CONFIG_READONLY (alongside OPENCLAW_ALLOW_OLDER_BINARY_DESTRUCTIVE_ACTIONS /
# OPENCLAW_INCLUDE_ROOTS / the isDangerousHostEnvVarName family) — a config cannot switch
# off its own read-only protection. It also sits in the path/identity env allowlist
# (`GATEWAY_CONFIG_SELECTION_ENV_KEYS`, io.read-helpers-Bj0GwcNP.mjs:23-42) next to
# OPENCLAW_AGENT_DIR/OPENCLAW_CONFIG_PATH/OPENCLAW_HOME/OPENCLAW_STATE_DIR/
# OPENCLAW_WORKSPACE_DIR, and daemon installs deliberately PRESERVE it across a service
# reinstall (`PRESERVED_OPENCLAW_OPERATOR_OPT_IN_ENV_KEYS`, daemon-install-helpers-
# BQ0CTd58.mjs:375-379) rather than wiping it like every other OPENCLAW_* key.
#
# WHY THIS IS DISCLOSURE-ONLY, NEVER A FAIL/WARN (per Golden Rule #5 and the task brief):
# there is no plausible bad state here. An externally-managed, read-only config is a
# hardening measure an operator opts into on purpose (Nix module, container/K8s-managed
# deployment); its ABSENCE is simply the default OpenClaw setup, not a gap. Reporting
# absence as a WARN would be recommending an operational posture (giving up in-place
# config mutation, wizard flows, plugin install/update) that is wrong advice for the
# overwhelming majority of installs.
#
# DETECTION CHANNEL: identical to B186/B41 — `persistent_env_evidence` (systemd
# Environment=/EnvironmentFile= for an OpenClaw-related unit, then the two global runtime
# dotenv files). Never `os.environ`: that is the auditing shell's environment, not the
# audited gateway process's, and the ambient-shell channel (an interactive export) is
# consciously left as the same permanent PASS-confidence ceiling B186 documents — it can
# never be seen by a persistent, on-disk read, however complete.
#
# CONSUMER CONTEXT (angle 1 of C-527, deliberately NOT wired into verdict logic here):
# under this mode OpenClaw itself never writes openclaw.json, so configjournal.py's
# journal-head comparison and the monitor's config-file identity dimension
# (monitordims/_configfile.py) both lose their usual "no journal entry between two runs"
# baseline — a config that DOES change while this mode is active is a STRONGER signal
# (nothing OpenClaw does should touch the file at all), not a weaker one. This check
# surfaces the mode itself, every run, which gives a reader the context needed to
# reinterpret a config-drift alert correctly without threading mode-awareness into
# configjournal.py or the monitordims C-433 dimension package (a materially larger,
# differentially-tested surface) — deferred, not implemented, see the C-527 Pulse
# comment for the full reasoning.
_CONFIG_READONLY_MODE_VARS = (
    ("OPENCLAW_CONFIG_READONLY", "read-only"),
    ("OPENCLAW_NIX_MODE", "Nix"),
)


def check_config_externally_managed(ctx: Context) -> Finding:
    """B373 — externally-managed, read-only config posture (OPENCLAW_CONFIG_READONLY /
    OPENCLAW_NIX_MODE), new in OpenClaw 2026.9.4.

    PASS    — a persistent artifact (systemd unit or global runtime dotenv file) shows
              OPENCLAW_CONFIG_READONLY=1 or OPENCLAW_NIX_MODE=1: OpenClaw refuses to
              rewrite openclaw.json while this is active. This is a positive, hardening
              observation, not a risk.
    PASS    — no such value was observed, but at least one persistent artifact was
              actually read (``env_evidence_readable``). Absence is the default OpenClaw
              posture and is not itself a finding; carries ``pass_confidence="no_signal"``
              because an ambient-shell export is invisible to any on-disk read, the same
              permanent ceiling B186 documents.
    UNKNOWN — no persistent artifact was even present to read (no OpenClaw-related
              systemd unit, no global dotenv file). There is no evidence to build a PASS
              on at all.

    Never WARN/FAIL — see the module comment above this function for why no adverse
    state exists for this signal.
    """
    hits: "list[tuple[str, str, str, str]]" = []  # (var, mode_label, value, source)
    for var, mode_label in _CONFIG_READONLY_MODE_VARS:
        value, source = persistent_env_evidence(ctx, var)
        if isinstance(value, str) and value.strip() == "1":
            hits.append((var, mode_label, value, source or "a persistent artifact"))

    if hits:
        evidence = [
            f"{var}=1 ({mode_label} mode) via {_detail_path(source, ctx.home)}"
            for var, mode_label, _value, source in hits
        ]
        return _finding(
            "B373",
            PASS,
            "This OpenClaw install is externally managed: " + "; ".join(evidence) + ". "
            "OpenClaw refuses every config-mutating command path (plugin install/update/"
            "uninstall, onboarding, repair, ordinary config writes) while this is active "
            "and treats openclaw.json as immutable. Because OpenClaw itself will not "
            "write this file, a config change observed while this mode is active did not "
            "come from OpenClaw's own writer and is worth confirming, not dismissing.",
            "No action needed — this is a deliberate hardening posture. Manage "
            "openclaw.json through your external deployment source (Nix module, "
            "container image, config-management tool) rather than through OpenClaw's "
            "own wizard/plugin-install flows, which will refuse to write while this is "
            "active.",
            evidence=evidence,
            confidence="HIGH",
        )

    if env_evidence_readable(ctx):
        return _finding(
            "B373",
            PASS,
            "No externally-managed read-only config mode (OPENCLAW_CONFIG_READONLY / "
            "OPENCLAW_NIX_MODE) was found in the systemd user unit(s) and global dotenv "
            "file(s) that were readable. This is the default OpenClaw posture — OpenClaw "
            "manages openclaw.json directly — and is not itself a finding. This PASS "
            "carries reduced confidence on purpose and can never reach full confidence: "
            "either variable can also be exported into the interactive shell that "
            "launches the agent, which leaves no artifact on disk for any local, "
            "read-only audit to see, however complete its read of persistent files is.",
            "No action needed. If you intend to manage this config externally (a Nix "
            "deployment or a container-managed install), set OPENCLAW_CONFIG_READONLY=1 "
            "(or rely on OPENCLAW_NIX_MODE=1) in a persistent unit/dotenv file so it "
            "survives a restart.",
            pass_confidence="no_signal",
            confidence="HIGH",
        )

    return _finding(
        "B373",
        UNKNOWN,
        "No externally-managed read-only config mode was found, but no systemd user "
        "unit or global dotenv file was present to read — so there is no evidence to "
        "build even a reduced-confidence PASS on.",
        "No action needed unless you intend to run OpenClaw under an externally-managed "
        "read-only config (Nix, a container-managed deployment).",
        confidence="HIGH",
    )


def check_retired_config_keys_invalid(ctx: Context) -> Finding:
    """B382 — openclaw.json still holds a key the installed OpenClaw build removed.

    The claim is deliberately narrow: the build's strict config schema rejects the file, so
    `openclaw config validate` and CLI commands that load it report it invalid until
    `openclaw doctor --fix` runs. It asserts nothing about the gateway, about the setting
    being in force, or about other findings being unreliable. Names are reported, never
    values. Gated on the INSTALLED build only (see ``_retired_keys_present``).

    WARN    — one or more retired keys are present and the installed build rejects them.
    UNKNOWN — no config was read (or it was unreadable).
    PASS    — none present; ``no_signal`` when the installed build could not be determined,
              because then "not present" was never actually assessable.

    Never FAIL: advisory, unscored (B-315).
    """
    unreadable = _config_unreadable("B382", ctx)
    if unreadable is not None:
        return unreadable
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B382",
            UNKNOWN,
            "No config was read, so whether openclaw.json holds a key the installed "
            "OpenClaw build removed could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    installed = getattr(ctx, "installed_dist_version", None)
    if _numeric_version(installed) is None:
        return _finding(
            "B382",
            PASS,
            "Installed OpenClaw version not determined; retired-key validity not assessed.",
            "No action needed. Run the audit where OpenClaw is installed (without "
            "--no-dist) to check the file against that build.",
            pass_confidence="no_signal",
        )
    found = _retired_keys_present(ctx)
    if not found:
        return _finding(
            "B382",
            PASS,
            f"The file audited holds no key that OpenClaw {installed} removed.",
            "No action needed.",
        )
    notes = [f"{key} ({'replaced by ' + repl if repl else 'removed'})" for key, repl in found]
    shown = "; ".join(notes[:6])
    extra = f" (+{len(notes) - 6} more)" if len(notes) > 6 else ""
    return _finding(
        "B382",
        WARN,
        f"The file audited still contains {len(found)} key(s) that OpenClaw {installed} "
        "removed, so its strict config schema rejects the file: `openclaw config validate` "
        "and CLI commands that load it report it invalid until the keys are migrated. "
        f"{shown}{extra}",
        "Run `openclaw doctor --fix` (it migrates or removes them), or delete the keys by "
        "hand. A config that uses $include may be refused automatic repair, so run the "
        "command explicitly.",
        evidence=[key for key, _repl in found],
    )


def check_dangerous_overrides(ctx: Context) -> Finding:
    """B48 — flag OpenClaw 'dangerously*/allowUnsafe*' break-glass toggles that are ACTIVE.

    These are explicit opt-in overrides OpenClaw documents as 'keep disabled'. Absent /
    false = nothing flagged (so a default config is a clean PASS — zero false positives).
    FAIL/CRITICAL when a wildcard-authority entry is active (commands.ownerAllowFrom or
    gateway.nodes.pairing.autoApproveCidrs contains an unscoped "*"/0.0.0.0/0/::/0 —
    B-231); FAIL/HIGH when a sandbox-escape or control-plane-auth-disable flag is on;
    WARN for the rest (including a *scoped*, non-wildcard override of the same fields).
    """
    unreadable = _config_unreadable("B48", ctx)
    if unreadable is not None:
        return unreadable
    # B-661: `_config_unreadable` only covers "present but unparseable" — on a host
    # with no openclaw.json at all, config_parse_error is False and ctx.config is
    # `{}`, so every dig() below would silently degrade to "absent" and fall through
    # to the PASS about a config nobody read.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B48",
            UNKNOWN,
            "No config was read, so whether any dangerously*/allowUnsafe* break-glass "
            "override is active could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    cfg = ctx.config
    fails: list[str] = []
    warns: list[str] = []
    # B-231: wildcard-authority entries — genuinely worse than the scoped-list case
    # below (an explicit, grounded "any sender"/"any IP" grant, not merely "a break-
    # glass toggle is on") — tracked separately so the verdict can escalate FAIL/
    # CRITICAL above the plain FAIL/HIGH the rest of this check returns.
    wildcard_fails: list[str] = []

    for path, label, is_fail in _DANGER_FIXED:
        if dig(cfg, path):
            (fails if is_fail else warns).append(f"{path} — {label}")

    # B-795: pulled out of _DANGER_FIXED's flat unconditional table because, unlike
    # every other row there, whether this one means anything at all depends on the
    # build — see `_device_auth_knob`. A build we could not identify keeps the
    # original FAIL (Golden Rule #4 — do not drop a real finding for a build we did
    # not see).
    device_auth_note = ""
    if dig(cfg, "gateway.controlUi.dangerouslyDisableDeviceAuth"):
        if _device_auth_knob(ctx) == "retired":
            device_auth_note = (
                " NOTE: gateway.controlUi.dangerouslyDisableDeviceAuth is present in "
                "the config, but OpenClaw 2026.9.3+ retired the key — it is ignored "
                "and grants nothing; Control UI browsers pair through the normal "
                "device flow instead. `openclaw doctor --fix` removes the stale line."
            )
        else:
            fails.append(
                "gateway.controlUi.dangerouslyDisableDeviceAuth — control-plane: "
                "Control-UI device identity auth disabled"
            )

    for path, label in _DANGER_FIXED_2026_8_1:
        node = cfg
        for key in path.split("."):
            node = node.get(key) if isinstance(node, dict) else None
        if node:
            warns.append(f"{path} — {label}")

    # B-705: gated on the build, because the same entry means opposite things. On
    # 2026.8.1 the wildcard is stripped before any authorization decision reads it, so
    # `["*"]` is the same configuration as no key at all — which this check calls PASS.
    # Nothing is emitted in its place: B48 is SCORED, and a warning about an entry that
    # is inert AND safe would cost the user grade for a state that carries no risk.
    owner_allow_from = dig(cfg, "commands.ownerAllowFrom")
    if (_is_owner_wildcard_allow_from(owner_allow_from)
            and _openclaw_generation(ctx) != "modern"):
        wildcard_fails.append(
            "commands.ownerAllowFrom contains '*' — owner-only command authority is "
            "granted to ANY sender on any channel (not a scoped allowlist)"
        )

    auto_approve_cidrs = dig(cfg, "gateway.nodes.pairing.autoApproveCidrs")
    if _has_world_open_cidr(auto_approve_cidrs):
        # NC-11 (recon): OpenClaw's own "not a vulnerability by design" list names this
        # exact field — stays WARN, never escalates to FAIL/wildcard_fails.
        warns.append(
            "gateway.nodes.pairing.autoApproveCidrs contains a world-open CIDR "
            "(0.0.0.0/0 / ::/0 / '*') — first-time, zero-scope node-device pairing is "
            "auto-approved from ANY IP address (role/scope/metadata/key-upgrade pairing "
            "still requires manual approval)"
        )

    nc, nc_path = _node_commands(cfg, "allow")
    if isinstance(nc, list) and nc:
        # B-231: a literal "*" entry here is NOT given the wildcard-authority
        # treatment above — grounded against node-command-policy-*.js, the allow list
        # is folded into a plain Set of exact command-name strings with no wildcard
        # special-case (`allow.has(command)`), so "*" never matches a real node
        # command and is strictly inert, not a broader grant than a named command.
        # Re-checked on 2026.8.1 (register-*.js): the new `commands.allow` spelling is
        # read the same way — `allowCommands.forEach` over exact trimmed strings — so
        # the inertness holds for both shapes, not just the one B-231 measured.
        warns.append(
            f"{nc_path} — extra node.invoke commands enabled "
            "(beyond gateway defaults; possible RCE surface)"
        )

    for agent in agent_roster(cfg):  # B-699: agents.entries as well as agents.list
        for flag, lbl in _DANGER_AGENT_SANDBOX:
            if dig(agent.entry, f"sandbox.docker.{flag}"):
                fails.append(
                    f"{agent.path}.sandbox.docker.{flag} — sandbox escape: {lbl}")

    for name, c in _channels(cfg).items():
        if not isinstance(c, dict):
            continue
        # Check the provider object AND per-account sub-objects: these break-glass flags
        # can be set per-account (channels.<p>.accounts.<id>.*), mirroring B30 (B-060).
        nodes = [c]
        accounts = c.get("accounts")
        if isinstance(accounts, dict):
            nodes.extend(v for v in accounts.values() if isinstance(v, dict))
        if any(n.get("dangerouslyDisableSignatureValidation") for n in nodes):
            warns.append(
                f"channels.{name}.dangerouslyDisableSignatureValidation — "
                "webhook signature validation disabled (spoofable untrusted input)"
            )
        if any(n.get("dangerouslyAllowInheritedWebhookPath") for n in nodes):
            warns.append(
                f"channels.{name}.dangerouslyAllowInheritedWebhookPath — "
                "inherited webhook path accepted"
            )
        if any(dig(n, "network.dangerouslyAllowPrivateNetwork") for n in nodes):
            warns.append(
                f"channels.{name}.network.dangerouslyAllowPrivateNetwork — "
                "private-network access from this channel (SSRF)"
            )

    mappings = dig(cfg, "hooks.mappings")
    if isinstance(mappings, list):
        for i, m in enumerate(mappings):
            if isinstance(m, dict) and m.get("allowUnsafeExternalContent"):
                warns.append(
                    f"hooks.mappings[{i}].allowUnsafeExternalContent — "
                    "less-sanitized external content (injection surface)"
                )

    for name, p in _plugins(cfg).items():
        if isinstance(p, dict) and dig(p, "config.allowPrivateNetwork"):
            warns.append(
                f"plugins.entries.{name}.config.allowPrivateNetwork — "
                "plugin private-network access (SSRF)"
            )

    if wildcard_fails:
        # B-231: severity ABOVE the scoped-list / other-break-glass FAIL — an explicit
        # wildcard grant of owner authority or auto-approved device pairing to anyone
        # is a step beyond a single break-glass toggle being left on.
        return _finding(
            "B48",
            FAIL,
            "Wildcard-authority override(s) grant owner command authority or device "
            "auto-pairing to ANY sender/IP (see evidence)." + device_auth_note,
            "Replace the wildcard with an explicit, scoped allowlist — e.g. "
            "commands.ownerAllowFrom to your own channel-native ID(s), or "
            "gateway.nodes.pairing.autoApproveCidrs to a specific host/private range. "
            "Never leave either as an unscoped wildcard.",
            evidence=wildcard_fails + fails + warns,
            severity=CRITICAL,
        )
    if fails:
        return _finding(
            "B48",
            FAIL,
            "Dangerous break-glass override(s) that enable sandbox escape or control-plane "
            "auth bypass are active (see evidence)." + device_auth_note,
            "Disable these unless a specific, temporary break-glass need requires one — each "
            "opens sandbox escape or control-plane authentication bypass. Restore the safe "
            "default (set to false / remove).",
            evidence=fails + warns,
        )
    if warns:
        return _finding(
            "B48",
            WARN,
            "One or more dangerous break-glass override flag(s) are enabled (see "
            "evidence)." + device_auth_note,
            "Review each — OpenClaw documents these as 'keep disabled' break-glass toggles. "
            "Turn off any you do not actively need.",
            evidence=warns,
        )
    return _finding(
        "B48",
        PASS,
        "None of the break-glass override flags checked here are enabled (browser "
        "SSRF's dangerouslyAllowPrivateNetwork is B38's subject, not B48's -- see "
        "B38)." + device_auth_note,
        "Keep these break-glass toggles off unless an incident temporarily requires one.",
        pass_confidence="verified",
    )


# B171 (B-235): the privileged, opt-in commands.* subflags this check treats as the
# "high-power in-chat surface" -- bash (raw host shell), config (read/write the running
# config from chat, incl. secrets/gateway auth), mcp (rewrite mcp.servers -- point the
# agent at an attacker-controlled MCP server), plugins (toggle plugin enablement). All
# four default to false/unset in the dist CommandsSchema (docs/research/
# openclaw-schema-recon.md §18) -- an absent/default config never trips this check.
# `debug` (runtime-only overrides) is folded in at WARN-only weight -- narrower blast
# radius than the four above, never drives a FAIL on its own.
# `restart` is DELIBERATELY EXCLUDED: it `.default(true)` in the dist schema, so treating
# it as a danger-enabled signal would false-FAIL every default config (Golden Rule #5).
_B171_HIGH_POWER = {
    "bash": "run arbitrary host shell commands (raw RCE)",
    "config": "read/write the running OpenClaw config from chat (incl. secrets/gateway auth)",
    "mcp": "rewrite mcp.servers from chat (point the agent at an attacker-controlled MCP server)",
    "plugins": "toggle plugin enablement from chat",
}
_B171_CRITICAL_COMMANDS = frozenset({"bash", "config"})
_B171_WARN_ONLY_COMMAND = "debug"
_B171_WARN_ONLY_LABEL = "runtime-only config overrides from chat"


# B171 (B-235 FP fix, grounded 2026-07-18): a channel's own
# dmPolicy/groupPolicy=='open' does NOT by itself mean every reachable sender also gets
# the in-chat commands.* surface. dm-policy-shared-*.js resolveOpenDmAllowlistAccess's own
# doc comment: "dmPolicy=open, where '*' means fully open and a configured allowlist still
# restricts the accepted sender set" -- a non-wildcard channel-/account-level `allowFrom`
# on an "open" dmPolicy blocks every other sender at ingress (reason
# dm_policy_not_allowlisted), so nobody but the listed sender(s) ever reaches the command
# layer at all. For groups, message ingress genuinely is unconditional once
# groupPolicy=='open' (group-access-*.js evaluateMatchedGroupAccessForPolicy), but
# resolveDmGroupAccessWithCommandGate still feeds the channel's own `allowFrom` AND
# `groupAllowFrom` into resolveControlCommandGate as separate command authorizers -- a
# configured, non-wildcard list there is real (if not exhaustively provider-verified)
# evidence that the privileged command itself is scoped, not open to "ANY sender". Treating
# `_open_channels()` (dmPolicy/groupPolicy=='open' alone, shared with B2's different
# "anyone can command" question) as sufficient evidence of unauthenticated command exposure
# false-FAILed exactly this shape. Fix: for THIS leg only, a channel counts as open only
# when the relevant sender list is itself absent/empty or wildcard; a scoped list falls
# through to the WARN leg below instead of asserting "ANY sender" with a FAIL/CRITICAL.
def _b171_scoped_list(value) -> bool:
    """True when *value* is a non-empty allow-from list that does NOT contain the "*"
    wildcard -- i.e. it genuinely narrows the accepted sender set rather than leaving it
    wide open."""
    return isinstance(value, list) and len(value) > 0 and not _is_owner_wildcard_allow_from(value)


def _b171_open_channels(cfg: dict) -> list[str]:
    """B171's own narrower notion of "open" for the no-commands-gate FAIL leg.

    Excludes a channel/account whose own dmPolicy=='open' is scoped by a non-wildcard
    channel-level `allowFrom`, or whose groupPolicy=='open' is scoped by a non-wildcard
    `groupAllowFrom`/`allowFrom` -- see the module comment above for the dist grounding.
    Deliberately duplicated rather than parameterizing the shared `_open_channels()` (B2):
    B2 asks a different question (gateway auth / "anyone can command") that is out of
    scope for this fix.

    B-390: reads the RESOLVED per-account node (`_resolved_channel_nodes`), not the raw
    ``[c] + accounts.values()`` idiom this used before -- see that helper's own docstring
    for the full grounding (mirrors the identical B-389 fix already landed in the sibling
    `_open_channels`). The bug this closes: a vestigial base-level `dmPolicy: "open"`
    (template scaffolding, no live credential behind it) was scored as open EVEN WHEN
    every real, running account overrode it to something restrictive -- because the raw
    walk evaluated the unmerged base node IN ADDITION TO each account's own raw node,
    never asking whether the account's override actually replaces it.

    Same C-135 follow-up as `_open_channels`: blindly dropping the base node whenever
    `accounts` is configured would trade that false positive for a worse false NEGATIVE --
    a channel-level credential (e.g. a `botToken`) does not stop running once `accounts`
    is added; OpenClaw synthesizes an extra IMPLICIT default account that keeps the base
    node's own (possibly still-open, no-gate) policy live alongside the explicit accounts.
    So the base node is added back to the walk exactly when
    `_channel_has_implicit_default_account` says it is genuinely still live -- never
    unconditionally.
    """
    out: list[str] = []
    for name, c in _channels(cfg).items():
        if not isinstance(c, dict) or c.get("enabled") is False:
            continue
        nodes = _resolved_channel_nodes(c)
        accounts = c.get("accounts")
        if isinstance(accounts, dict) and accounts and _channel_has_implicit_default_account(name, c):
            nodes = [*nodes, c]
        for node in nodes:
            if not isinstance(node, dict):
                continue
            # B-390: a resolved node's own `enabled: false` (a per-account disable --
            # e.g. a retired account left in place with its old, wide-open policy still
            # on record) means that account authorizes no in-chat commands at all, same
            # reasoning as the channel-level guard above.
            if node.get("enabled") is False:
                continue
            dm_open = node.get("dmPolicy") == "open" and not _b171_scoped_list(
                node.get("allowFrom")
            )
            # B-283 (a): normalize a Feishu channel's "allowall" alias, which Feishu's
            # GroupPolicySchema transforms to "open" (channel-PR3XHV0V.js:89-93) — without
            # this a Feishu channel written as groupPolicy:"allowall" ran wide open but
            # read as unrecognised. Feishu-scoped only: every other channel schema in the
            # dist rejects "allowall" outright, so it cannot appear on them in a config
            # that actually loaded — see _norm_group_policy's docstring for the grounding.
            group_open = _norm_group_policy(name, node.get("groupPolicy")) == "open" and not (
                _b171_scoped_list(node.get("groupAllowFrom"))
                or _b171_scoped_list(node.get("allowFrom"))
            )
            if dm_open or group_open:
                out.append(name)
                break
    return out


def _b171_wildcard_allow_from_evidence(cfg: dict, modern: bool = False) -> list[str]:
    """Wildcard-open commands.* gate entries.

    Reuses the B-231 wildcard-authority detector (``_is_owner_wildcard_allow_from``) over
    BOTH ``commands.ownerAllowFrom`` and every per-provider/global list inside
    ``commands.allowFrom`` (a record keyed by provider id or the literal ``"*"`` for "all
    providers" -- ``resolveCommandsAllowFromList`` in the dist's ``command-auth-*.js``,
    grounded 2026-07-18).

    B-705: the two halves are NOT the same claim any more, and only one of them is gated.

    * ``ownerAllowFrom`` -- dropped on 2026.8.1. The wildcard is stripped before any
      authorization decision reads it (``stripWildcardAllowFrom``), so the entry is the
      same configuration as no key at all. B48 carries the full grounding.
    * ``commands.allowFrom`` -- NEVER gated. The wildcard there is still honoured on
      2026.8.1: ``const allowAll = !hadResolutionError && (allowFromList.length === 0 ||
      hasWildcardAllowFrom(allowFromList))``. Gating both halves together would have
      traded one false FAIL for a false NEGATIVE on a genuinely open gate, which is the
      failure mode this fix was most at risk of.

    ``modern`` is passed rather than read from a Context so this stays a pure function of
    its arguments, like every other helper in this file.
    """
    out: list[str] = []
    owner_allow_from = dig(cfg, "commands.ownerAllowFrom")
    if _is_owner_wildcard_allow_from(owner_allow_from) and not modern:
        out.append("commands.ownerAllowFrom contains '*'")
    allow_from = dig(cfg, "commands.allowFrom")
    if isinstance(allow_from, dict):
        for key, value in allow_from.items():
            if _is_owner_wildcard_allow_from(value):
                out.append(f"commands.allowFrom[{key!r}] contains '*'")
    return out


def check_privileged_commands_exposure(ctx: Context) -> Finding:
    """B171 (B-235) — commands.bash/config/mcp/plugins in-chat privileged-command surface.

    OpenClaw's root ``commands.*`` block exposes raw shell (``bash``), full config
    read/write (``config``), MCP-server-registry rewrite (``mcp``), and plugin-enablement
    toggling (``plugins``) as IN-CHAT commands, gated only by their own owner/elevated
    allow-from mechanism (``commands.ownerAllowFrom`` / ``commands.allowFrom`` /
    ``commands.useAccessGroups``) — entirely separate from B2's channel dmPolicy/
    groupPolicy gate and B3's agent-tool allowlist. Before this check, ClawSecCheck had
    ZERO references to commands.bash/config/mcp/plugins (B-235): a config with all four
    enabled plus an open channel scored identically to the closed-channel baseline.

    FAIL/CRITICAL — ``bash`` or ``config`` is enabled and the gate is wildcard-open
        (``commands.ownerAllowFrom`` or an ``commands.allowFrom`` list contains ``"*"``),
        or is completely unconfigured on a channel with an open dmPolicy/groupPolicy —
        either way ANY chat sender who reaches that channel gets raw shell or full
        config-mutation.
    FAIL/HIGH — ``mcp`` or ``plugins`` is enabled under the same wildcard/open-channel-
        with-no-gate condition (still unauthenticated, narrower blast radius).
    WARN — a privileged command (incl. ``debug``) is enabled with no
        ownerAllowFrom/allowFrom configured, on a channel that is NOT open (allowlist/
        pairing/disabled still constrains who reaches the command layer, but no
        owner-scoped allowlist narrows it further — see docs/research §18); or
        ``commands.useAccessGroups`` is explicitly ``false`` alongside an enabled
        privileged command.
    UNKNOWN — a privileged command is enabled with no gate configured and no channels are
        configured at all (reachability genuinely can't be determined), or openclaw.json
        is unreadable.
    PASS — no privileged commands.* subflag is enabled, or every enabled one has a
        scoped, non-wildcard ownerAllowFrom/allowFrom.
    """
    unreadable = _config_unreadable("B171", ctx)
    if unreadable is not None:
        return unreadable
    # B-661: `_config_unreadable` only covers "present but unparseable" — on a host
    # with no openclaw.json at all, config_parse_error is False and ctx.config is
    # `{}`, so every commands.* dig() below would silently degrade to "absent" and
    # fall through to the PASS about a config nobody read.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B171",
            UNKNOWN,
            "No config was read, so whether any commands.bash/config/mcp/plugins "
            "privileged in-chat command surface is enabled could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    cfg = ctx.config

    # Literal dig() calls (not an f-string in a loop) so the §4 schema-grounding AST
    # scanner (tests/test_schema_grounding.py) can see each path statically.
    _commands_flags = {
        "bash": bool(dig(cfg, "commands.bash")),
        "config": bool(dig(cfg, "commands.config")),
        "mcp": bool(dig(cfg, "commands.mcp")),
        "plugins": bool(dig(cfg, "commands.plugins")),
        "debug": bool(dig(cfg, "commands.debug")),
    }
    enabled_high = [k for k in _B171_HIGH_POWER if _commands_flags[k]]
    debug_enabled = _commands_flags[_B171_WARN_ONLY_COMMAND]
    if not enabled_high and not debug_enabled:
        return _finding(
            "B171",
            PASS,
            "No privileged in-chat commands.* surface (bash/config/mcp/plugins/debug) is "
            "enabled.",
            "Keep these disabled unless you specifically need in-chat privileged control; "
            "if you do enable one, scope commands.ownerAllowFrom/allowFrom tightly.",
            pass_confidence="verified",
        )

    enabled_all = enabled_high + ([_B171_WARN_ONLY_COMMAND] if debug_enabled else [])
    descriptions = [
        f"commands.{k} enabled ({_B171_HIGH_POWER.get(k, _B171_WARN_ONLY_LABEL)})"
        for k in enabled_all
    ]

    wildcard_ev = _b171_wildcard_allow_from_evidence(
        cfg, modern=_openclaw_generation(ctx) == "modern")
    if wildcard_ev:
        severity = CRITICAL if enabled_high and set(enabled_high) & _B171_CRITICAL_COMMANDS else HIGH
        return _finding(
            "B171",
            FAIL,
            "Privileged in-chat command(s) enabled with a wildcard-open owner/allow-from "
            "gate — ANY chat sender who reaches the gate is authorized: "
            + "; ".join(descriptions),
            "Replace the wildcard with an explicit, scoped allowlist — e.g. "
            "commands.ownerAllowFrom / commands.allowFrom to your own channel-native "
            "ID(s). Never leave either as an unscoped '*'.",
            evidence=descriptions + wildcard_ev,
            severity=severity,
        )

    owner_allow_from = dig(cfg, "commands.ownerAllowFrom")
    allow_from = dig(cfg, "commands.allowFrom")
    # B-705: the EFFECTIVE owner list, not the raw one. On 2026.8.1 the runtime strips
    # every "*" entry (`stripWildcardAllowFrom`) before deciding whether an owner allowlist
    # exists, so `ownerAllowFrom: ["*"]` leaves `explicitOwners = []` — no gate at all.
    # Testing the RAW list's truthiness counted that as a configured gate and, on an open
    # channel, turned a CRITICAL FAIL into a PASS.
    #
    # This false negative did not exist before, and it is not hypothetical: it was created
    # by the fix above, which removed the wildcard FAIL that used to catch this shape on
    # its way past. Measured on `{channels.telegram.dmPolicy=open, commands.bash=true,
    # ownerAllowFrom=["*"]}` — FAIL/CRITICAL on 2026.7.x, PASS on 2026.8.1 until this line.
    # On 2026.7.x nothing changes: the wildcard FAILs earlier and never reaches here.
    effective_owner_allow_from = owner_allow_from
    if _openclaw_generation(ctx) == "modern" and isinstance(owner_allow_from, list):
        effective_owner_allow_from = [
            e for e in owner_allow_from
            if not (isinstance(e, str) and e.strip() == "*")
        ]
    gate_configured = bool(effective_owner_allow_from) or bool(allow_from)
    open_ch = _b171_open_channels(cfg)

    if not gate_configured and open_ch:
        severity = CRITICAL if enabled_high and set(enabled_high) & _B171_CRITICAL_COMMANDS else HIGH
        return _finding(
            "B171",
            FAIL,
            "Privileged in-chat command(s) enabled with NO owner/allow-from gate "
            "configured, on a channel with an open dm/group policy — ANY sender on that "
            "channel is authorized (an empty commands.ownerAllowFrom/allowFrom removes "
            "the owner-only check; see docs/research §18): " + "; ".join(descriptions),
            "Set commands.ownerAllowFrom or commands.allowFrom to your own channel-native "
            "ID(s), and/or set the open channel's dmPolicy/groupPolicy to 'allowlist' "
            "(see B2).",
            evidence=descriptions + [f"open channel(s): {', '.join(open_ch)}"],
            severity=severity,
        )

    if not gate_configured and not _channels(cfg):
        return _finding(
            "B171",
            UNKNOWN,
            "Privileged in-chat command(s) enabled with no owner/allow-from gate "
            "configured, and no channels are configured to assess reachability through: "
            + "; ".join(descriptions),
            "Set commands.ownerAllowFrom or commands.allowFrom to your own channel-native "
            "ID(s) before connecting any channel.",
            evidence=descriptions,
        )

    warn_ev = list(descriptions)
    if not gate_configured:
        warn_ev.append(
            "commands.ownerAllowFrom/allowFrom not configured — any sender the connected, "
            "non-open channel(s) already authorize is treated as command-owner"
        )
    # C-471: removed in OpenClaw 2026.8.1, and removed fail-SAFE. `useAccessGroups` appears
    # in ZERO of the 5,254 paths of the 2026.8.1 config schema (one in 2026.7.1-2), so no
    # config can turn it off any more, and the runtime reads
    # `const useAccessGroups = command.useAccessGroups ?? true` — enforcement on by default
    # with nothing left to override it. A key left on disk after an upgrade is inert, so
    # counting it as a gap would manufacture a WARN about a layer that cannot be disabled.
    #
    # NOT remapped to the root `accessGroups` key: that coexisted with this one in
    # 2026.7.1-2, which disqualifies it as a rename target by the same rule that killed
    # `dangerouslyDisableDeviceAuth` as a candidate for `allowInsecureAuth`.
    if (dig(cfg, "commands.useAccessGroups") is False
            and _openclaw_generation(ctx) != "modern"):
        warn_ev.append(
            "commands.useAccessGroups=false — access-group enforcement layer disabled"
        )
    if warn_ev != descriptions:
        return _finding(
            "B171",
            WARN,
            "Privileged in-chat command(s) enabled with a broad or partially-configured "
            "gate: " + "; ".join(warn_ev),
            "Scope commands.ownerAllowFrom/allowFrom to your own channel-native ID(s)."
            # B-700: `commands.useAccessGroups` was REMOVED in OpenClaw 2026.8.1 with no
            # replacement, so "keep it enabled" is an instruction a current build rejects.
            # The evidence clause above still names it when it is literally in the user's
            # file -- naming a key they already have is never wrong; telling them to add
            # one is. Whether the concept moved to the new root `accessGroups`/`security`
            # keys is C-471's question, not answered here.
            + ("" if _openclaw_generation(ctx) == "modern"
               else " Keep commands.useAccessGroups enabled."),
            evidence=warn_ev,
        )

    return _finding(
        "B171",
        PASS,
        "Privileged in-chat command(s) enabled with a scoped owner/allow-from gate: "
        + "; ".join(descriptions),
        "Keep commands.ownerAllowFrom/allowFrom scoped to your own channel-native ID(s).",
        evidence=descriptions,
        pass_confidence="verified",
    )
# ---------- B173 (B-237): security.audit.suppressions self-blinds the native audit ----------
# Grounded: zod-schema-O9ml_nmo.js SecuritySchema — security.audit.suppressions is an array
# of { checkId: string().min(1), titleIncludes?, detailIncludes?, reason? } (all `.strict()`).
# audit-UjVvFwCi.js's runSecurityAudit() applies these via applySecurityAuditSuppressions()
# BEFORE returning `openclaw security audit --json`'s output — so a suppressed finding never
# reaches native.py's fold-in either (native.py execs that exact command and only ever sees
# the post-suppression `findings` array). A non-empty list is not itself a vulnerability —
# it is how an operator knowingly accepts a specific, reviewed native finding — so this stays
# WARN/disclosure by default. It escalates to FAIL only when a suppressed checkId is one this
# project has grounded, directly against audit-UjVvFwCi.js, as UNCONDITIONALLY
# severity:"critical" there (a literal `severity: "critical"` in the source, never a
# `cond ? "critical" : "warn"` ternary whose true branch we cannot re-derive statically without
# duplicating OpenClaw's own runtime-exposure logic — and a wrong guess would be exactly the
# false-FAIL Golden Rule #5 forbids) AND that literal-critical finding fires on an actual
# DEFECT with actionable remediation — not merely on a feature being enabled at all. Literal
# `severity: "critical"` in the native source is necessary but not sufficient: B-237 found
# `gateway.trusted_proxy_auth` is literally critical yet fires unconditionally whenever
# `gateway.auth.mode === "trusted-proxy"` (audit-UjVvFwCi.js:245-254), with a remediation that
# is a verification checklist ("Verify: (1)... (2)... (3)...", see the trusted-proxy setup
# guide), not a config change. There is no underlying condition a correctly-configured
# trusted-proxy operator (e.g. behind Pomerium/Caddy/nginx SSO) can fix to clear it — it is
# OpenClaw's own documented enterprise auth mode, and every operator running it will see this
# finding forever. Escalating a knowing, reviewed suppression of that notice to FAIL/CRITICAL
# is a false positive (an operator correctly using a supported feature gets told to abandon
# it) — so `gateway.trusted_proxy_auth` is deliberately excluded here and stays WARN-only via
# the disclosure path below. The three checkIds that fire on REAL trusted-proxy
# misconfiguration remain in the set and keep escalating: `gateway.trusted_proxy_no_proxies`
# ("All requests will be rejected" — empty trustedProxies), `gateway.trusted_proxy_no_user_header`
# (missing userHeader), and the generic `gateway.bind_no_auth` catch-all when trusted-proxy
# auth itself is misconfigured badly enough to not count as a shared secret. Deliberately
# scoped to the core `runSecurityAudit` orchestrator in audit-UjVvFwCi.js only; checkIds from
# its channel-security/deep-probe extension modules are covered by the disclosure WARN but
# never escalate here.
_NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS = frozenset({
    "gateway.bind_no_auth",
    "gateway.loopback_no_auth",
    "gateway.control_ui.allowed_origins_required",
    "gateway.tailscale_funnel",
    "gateway.control_ui.device_auth_disabled",
    "gateway.trusted_proxy_no_proxies",
    "gateway.trusted_proxy_no_user_header",
    "fs.state_dir.perms_world_writable",
    "fs.config.perms_writable",
    "fs.config.perms_world_readable",
})


def _is_native_unconditional_critical_check_id(check_id: str) -> bool:
    """True for a grounded always-critical native-audit checkId — an exact match from
    ``_NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS``, or the templated
    ``tools.elevated.allowFrom.<provider>.wildcard`` shape (audit-UjVvFwCi.js
    collectElevatedFindings — the provider name varies, the ``.wildcard`` suffix and
    unconditional ``severity: "critical"`` do not)."""
    return (
        check_id in _NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS
        or (
            check_id.startswith("tools.elevated.allowFrom.")
            and check_id.endswith(".wildcard")
        )
    )


def check_audit_suppressions(ctx: Context) -> Finding:
    """B173 (B-237) — ``security.audit.suppressions`` permanently silences specific findings
    of OpenClaw's OWN built-in ``openclaw security audit`` (and therefore native.py's
    fold-in of it too), with nothing previously disclosing that a suppression list exists.

    Absent/empty list → PASS (nothing suppressed). Non-empty → WARN, naming the suppressed
    checkId(s) — a suppression is a knowingly-accepted native finding, not itself a
    vulnerability. FAIL/CRITICAL only when a suppressed checkId is one this project has
    grounded as unconditionally critical in the native audit source (see
    ``_NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS``) — a config write that permanently quiets one
    of those is positive evidence, not a guess.
    """
    unreadable = _config_unreadable("B173", ctx)
    if unreadable is not None:
        return unreadable
    # B-661: `_config_unreadable` only covers "present but unparseable" — on a host
    # with no openclaw.json at all, config_parse_error is False and ctx.config is
    # `{}`, so `dig(cfg, "security.audit.suppressions")` would silently resolve to
    # None and fall through to the (previously `pass_confidence="verified"`) PASS
    # about a config nobody read.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B173",
            UNKNOWN,
            "No config was read, so whether security.audit.suppressions silences any "
            "native-audit finding could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    cfg = ctx.config
    suppressions = dig(cfg, "security.audit.suppressions")
    if not isinstance(suppressions, list) or not suppressions:
        return _finding(
            "B173",
            PASS,
            "No security.audit.suppressions configured — OpenClaw's built-in "
            "`openclaw security audit` runs unfiltered.",
            "Keep security.audit.suppressions empty unless you are knowingly accepting a "
            "specific, reviewed native-audit finding.",
            pass_confidence="verified",
        )

    critical_hits: list[str] = []
    disclosed: list[str] = []
    for i, entry in enumerate(suppressions):
        if not isinstance(entry, dict):
            continue
        check_id = entry.get("checkId")
        if not isinstance(check_id, str) or not check_id.strip():
            continue
        check_id = check_id.strip()
        label = f"security.audit.suppressions[{i}]: checkId={check_id!r}"
        reason = entry.get("reason")
        if isinstance(reason, str) and reason.strip():
            # Disclose that a reason was recorded without echoing the operator-authored
            # free-text value itself into evidence/reports.
            label += " (reason given)"
        disclosed.append(label)
        if _is_native_unconditional_critical_check_id(check_id):
            critical_hits.append(check_id)

    if not disclosed:
        # Non-empty list but no entry had a recognizable checkId (malformed hand-edit —
        # OpenClaw's own schema requires checkId, so a real config always has one). Still
        # worth a look, but there is nothing concrete to name — WARN, not a guess FAIL.
        return _finding(
            "B173",
            WARN,
            "security.audit.suppressions is non-empty but no entry has a usable checkId.",
            "Check security.audit.suppressions for malformed entries — each needs a "
            "non-empty checkId string.",
            evidence=[f"security.audit.suppressions has {len(suppressions)} entrie(s)"],
        )

    if critical_hits:
        return _finding(
            "B173",
            FAIL,
            "security.audit.suppressions silences a native-audit check this project has "
            "grounded as unconditionally critical: "
            f"{', '.join(sorted(set(critical_hits)))}.",
            "Remove the suppression for the critical checkId(s) above and fix the underlying "
            "condition instead — do not permanently silence a critical finding of OpenClaw's "
            "own built-in security audit.",
            evidence=disclosed,
            severity=CRITICAL,
        )
    return _finding(
        "B173",
        WARN,
        f"security.audit.suppressions has {len(disclosed)} configured entry/entries — "
        "OpenClaw's built-in `openclaw security audit` (and ClawSecCheck's fold-in of it) "
        "will never show these findings again.",
        "Review each suppressed checkId periodically and remove it once the accepted risk "
        "no longer applies. A non-empty list is not itself a vulnerability, only a "
        "transparency signal.",
        evidence=disclosed,
    )


def check_hook_template_content(ctx: Context) -> Finding:
    """B169 (B-231 sub-item 2) — hooks.mappings[].messageTemplate / textTemplate content scan.

    A hook mapping's ``messageTemplate``/``textTemplate`` splices an untrusted external
    webhook payload into text the agent will read as part of a live turn (B48 only checks
    the separate ``allowUnsafeExternalContent`` opt-in flag; the template string itself was
    never routed through the content ring). This check CONSUMES the existing content-ring
    detectors from ``checks/_content.py`` -- it does not add new detection logic of its own:

    - ``_B64_HIGH_CONFIDENCE_RE`` + ``_b64_classify`` (B64 instruction-hierarchy override,
      e.g. "ignore all previous instructions").
    - ``_b63_scan`` (B63 silent-instruction / secrecy-framed directive).
    - ``_CLICKFIX_REMOTE_FETCH_RE`` + ``_clickfix_trusted_installer`` (the same remote-fetch/
      pipe-to-shell install-directive pattern B167 already reuses for appServer.command).

    FAIL    — a template string matches a high-confidence override/install directive.
    WARN    — a template string matches a weaker/ambiguous signal.
    UNKNOWN — openclaw.json present but unparseable/unreadable.
    PASS    — hooks.mappings has no messageTemplate/textTemplate, or none match.
    """
    unreadable = _config_unreadable("B169", ctx)
    if unreadable is not None:
        return unreadable
    # B-661: `_config_unreadable` only covers "present but unparseable" — on a host
    # with no openclaw.json at all, config_parse_error is False and ctx.config is
    # `{}`, so `dig(cfg, "hooks.mappings")` would silently resolve to None and fall
    # through to the PASS about a config nobody read.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B169",
            UNKNOWN,
            "No config was read, so whether any hooks.mappings[] messageTemplate/"
            "textTemplate carries an embedded directive could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    cfg = ctx.config
    mappings = dig(cfg, "hooks.mappings")
    fail_ev: list[str] = []
    warn_ev: list[str] = []
    if isinstance(mappings, list):
        for i, m in enumerate(mappings):
            if not isinstance(m, dict):
                continue
            for field_name in ("messageTemplate", "textTemplate"):
                text = m.get(field_name)
                if not isinstance(text, str) or not text.strip():
                    continue
                source = f"hooks.mappings[{i}].{field_name}"
                norm = normalize_for_scan(text)
                fr = _fence_ranges(norm)
                cr = [(mm.start(), mm.end()) for mm in _B58_HTML_COMMENT_RE.finditer(norm)]

                # B-231: a STRONG, unambiguous anchor gates whether a B63 secrecy hit may
                # grade-cap on this hook-template surface. A bare secrecy phrase + a bare
                # _EXFIL_RE keyword ("post") is AMBIGUOUS (a benign relayed digest that
                # withholds a detail vs a covert-exfil directive), so per project doctrine
                # (§5 — ambiguous suppression → WARN, not FAIL) it stays WARN unless a B64
                # instruction-override, a curl|bash pipe-to-shell install directive, or a
                # credential-path co-occurs in the same template field. (The former
                # base64-blob anchor was dropped in Wave-2 round-4 — a blob can't be told
                # apart from a URL/path/hash in short text; see _content.py.)
                field_has_strong = False

                # B64: instruction-hierarchy override ("ignore all previous instructions").
                for mm in _B64_HIGH_CONFIDENCE_RE.finditer(norm):
                    disp = _b64_classify(norm, mm.start(), mm.end(), fr, cr)
                    if disp == "skip":
                        continue
                    snippet = mm.group().strip()
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    if disp == "warn":
                        warn_ev.append(f'{source}: instruction-override "{snippet}"')
                    else:
                        fail_ev.append(f'{source}: instruction-override "{snippet}"')
                        field_has_strong = True

                # ClickFix-style remote-fetch/pipe-to-shell install directive (same
                # detector B167 reuses for plugins.entries.<name>.config.appServer.command).
                cf = _CLICKFIX_REMOTE_FETCH_RE.search(norm)
                if cf and not _clickfix_trusted_installer(cf.group(0)):
                    snippet = cf.group(0).strip()
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    fail_ev.append(f'{source}: remote-fetch/pipe-to-shell install directive "{snippet}"')
                    field_has_strong = True

                if _secrecy_credential_or_encoding_anchor(norm):
                    field_has_strong = True

                # B63: silent-instruction / secrecy-framed directive. B-231: on this
                # hook-template surface a bare secrecy phrase + bare outbound verb ("post")
                # is ambiguous with a benign relayed digest that withholds one detail, so it
                # only FAILs when a strong anchor co-occurs; otherwise it surfaces as WARN
                # (no grade cap).
                for snippet, is_anchored in _b63_scan(norm, fr):
                    label = f'{source}: silent-instruction directive "{snippet}"'
                    if is_anchored and field_has_strong:
                        fail_ev.append(label)
                    else:
                        warn_ev.append(label)

    if fail_ev:
        ev_summary = "; ".join(fail_ev[:4])
        extra = f" (+{len(fail_ev) - 4} more)" if len(fail_ev) > 4 else ""
        return _finding(
            "B169",
            FAIL,
            "A hooks.mappings[] messageTemplate/textTemplate carries an embedded "
            "instruction-override or install directive: " + ev_summary + extra,
            "Remove the embedded directive from the template, and treat inbound webhook "
            "payload fields spliced into the template as untrusted content — never let a "
            "hook template carry a live instruction to the agent.",
            fail_ev + warn_ev,
        )
    if warn_ev:
        ev_summary = "; ".join(warn_ev[:4])
        extra = f" (+{len(warn_ev) - 4} more)" if len(warn_ev) > 4 else ""
        return _finding(
            "B169",
            WARN,
            "A hooks.mappings[] messageTemplate/textTemplate matches a weaker/ambiguous "
            "directive signal: " + ev_summary + extra,
            "Review the flagged template. If it merely documents or quotes an example "
            "payload, no action is needed; if it is a live directive, remove it.",
            warn_ev,
        )
    return _finding(
        "B169",
        PASS,
        "No hooks.mappings[] messageTemplate/textTemplate carries an embedded directive.",
        "Keep hook templates free of instruction-override or install-directive content.",
        pass_confidence="verified",
    )


def check_hook_transform_modules(ctx: Context) -> Finding:
    """B380 (C-406) — hooks.mappings[].transform.module: config-loaded code run on
    every matching message/event.

    A configured hook transform is a relative module path OpenClaw dynamically
    imports and invokes on every matching message, BEFORE the agent (or any other
    check in this audit) ever sees the message -- `loadTransform` ->
    `importFileModule`/`resolveFunctionModuleExport`. Grounded against the installed
    OpenClaw dist (2026.9.4), by SYMBOL rather than bundle filename -- bundle names
    are content-hashed and rename every release (this task's own 2026-09-02
    re-grounding comment already caught one rename; `hooks-CwxdiIeO.mjs` today,
    `hooks-4_CM-Biu.js` on 2026.8.2, `hooks-Bjrm8pWp.js` originally):
      loadTransform / resolveContainedPath / resolveOptionalContainedPath
                                        hooks-CwxdiIeO.mjs
      importFileModule / resolveFunctionModuleExport
                                        module-loader-BF97Ap2W.mjs (stable across all
                                        three releases checked)
    Schema descriptions (schema-DbKC3IUo.mjs), quoted verbatim -- OpenClaw's OWN docs
    already flag this as a code-review surface:
      hooks.transformsDir: "Base directory for hook transform modules referenced by
        mapping transform.module paths. Use a controlled repo directory so dynamic
        imports remain reviewable and predictable."
      hooks.mappings[].transform.module: "Relative transform module path loaded from
        hooks.transformsDir to rewrite incoming payloads before delivery. Keep
        modules local, reviewed, and free of path traversal patterns."

    Never FAIL, deliberately -- re-verified against the installed dist before writing
    this check (not assumed from the task's own citations, which were themselves
    already stale once): BOTH the module path and `hooks.transformsDir` itself are
    CONFINED (`resolveContainedPath` requires the resolved path to stay inside its
    base directory, checked via `isPathInside` on both the nominal AND the
    realpath-resolved form; `resolveOptionalContainedPath` resolves a configured
    `hooks.transformsDir` AS A SUBDIRECTORY of `<configDir>/hooks/transforms`, not as
    an arbitrary path). So there is no `../`-escape or arbitrary-absolute-path vector
    to FAIL on -- this is disclosure only, the same advisory shape as B150/B171/B341.

    WARN    — a transform module is configured AND the resolved transforms directory
              is group- or world-writable (`_dir_replaceable_by_others`) -- another
              local account could plant or replace a transform module that then runs
              on the next matching message, unrelated to the confinement above (which
              only bounds WHERE the path resolves, not WHO can write there).
    WARN    — a transform module is configured but the directory is not writable by
              others (or its permissions could not be determined) -- still disclosed,
              since this is config-loaded local code executing on live messages
              regardless of directory permissions; MEDIUM only escalates when the
              writability exposure is also present.
    UNKNOWN — openclaw.json present but unparseable/unreadable, or not read at all.
    PASS    — no hooks.mappings[] declares a transform.module.
    """
    unreadable = _config_unreadable("B380", ctx)
    if unreadable is not None:
        return unreadable
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B380",
            UNKNOWN,
            "No config was read, so whether any hooks.mappings[] declares a "
            "transform.module could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    cfg = ctx.config
    mappings = dig(cfg, "hooks.mappings")
    modules: list[str] = []
    if isinstance(mappings, list):
        for i, m in enumerate(mappings):
            if not isinstance(m, dict):
                continue
            transform = m.get("transform")
            if not isinstance(transform, dict):
                continue
            mod = transform.get("module")
            if isinstance(mod, str) and mod.strip():
                modules.append(f"hooks.mappings[{i}].transform.module={mod.strip()!r}")

    if not modules:
        return _finding(
            "B380",
            PASS,
            "No hooks.mappings[] declares a transform.module.",
            "No action needed unless a hook transform is added later.",
        )

    # Best-effort resolution of the confined transforms directory, for a WRITABILITY
    # check only -- NOT a re-implementation of resolveContainedPath's own path-escape
    # validation (already re-verified above; irrelevant to "who can write here").
    # Mirrors the vendor's own base (`path.join(configDir, "hooks", "transforms")`,
    # configDir == ctx.home here) and its own resolution of a configured
    # transformsDir AS A SUBDIRECTORY of that base, not of configDir directly.
    transforms_dir = ctx.home / "hooks" / "transforms"
    custom = dig(cfg, "hooks.transformsDir")
    if isinstance(custom, str) and custom.strip():
        custom_clean = custom.strip()
        # C-135 (independent, post-commit): `Path.__truediv__` (`/`) discards the LEFT
        # operand entirely when the right one is absolute -- `base / "/tmp"` is "/tmp",
        # not "base/tmp". Node's `path.join`, which the comment above claims to mirror,
        # does the opposite: it treats every segment as a component to APPEND, so
        # `path.join(base, "/tmp")` is "base/tmp" (verified by executing the installed
        # node). An absolute `hooks.transformsDir` therefore used to point this check's
        # writability probe at an ENTIRELY DIFFERENT, uncontained directory than the one
        # OpenClaw's own resolveContainedPath actually confines writes to -- reproduced
        # both a false MEDIUM escalation (the naive absolute path happened to be
        # writable while the real confined directory was private) and a false negative
        # (the reverse: the real confined directory was world-writable, the naive path
        # was not, and the exposure was never inspected). Stripping any leading
        # separator/drive-letter component before the join mirrors Node's append-only
        # behavior for exactly this case, matching the vendor semantics the comment
        # already claims to follow.
        if Path(custom_clean).is_absolute():
            custom_clean = custom_clean.lstrip("/\\")
            # A bare Windows drive letter ("C:\foo" -> stripped to "C:foo") would still
            # be treated as a drive-relative root by pathlib on that platform; drop it
            # too so the whole string is an ordinary path component to append.
            if len(custom_clean) >= 2 and custom_clean[1] == ":":
                custom_clean = custom_clean[2:].lstrip("/\\")
        transforms_dir = transforms_dir / custom_clean if custom_clean else transforms_dir
    why = _dir_replaceable_by_others(transforms_dir)

    label = "; ".join(modules[:6])
    extra = f" (+{len(modules) - 6} more)" if len(modules) > 6 else ""
    if why:
        return _finding(
            "B380",
            WARN,
            f"{len(modules)} hooks.mappings[] transform.module(s) configured — "
            "config-loaded local code that runs on every matching message/event, "
            f"before the agent sees it — and the resolved transforms directory "
            f"({transforms_dir}) is {why}, so another local account could plant or "
            "replace a transform module: " + label + extra,
            "Restrict the transforms directory to owner-only (chmod 700), or move "
            "it out of a shared/group-writable location. Review each configured "
            "transform module's source either way.",
            evidence=modules,
            severity=MEDIUM,
        )
    return _finding(
        "B380",
        WARN,
        f"{len(modules)} hooks.mappings[] transform.module(s) configured — "
        "config-loaded local code that runs on every matching message/event, "
        "before the agent sees it: " + label + extra,
        "Review each transform module's source. The module path is confined to "
        "hooks.transformsDir and cannot escape it via '../', but a reviewed, "
        "version-controlled transforms directory is still the safer setup.",
        evidence=modules,
        confidence="HIGH",
    )


def check_hooks_enable_toggles(ctx: Context) -> Finding:
    """B179 (B-250): inventory of hooks.enabled / hooks.internal(.load.extraDirs)
    enable-toggles.

    Grounded against the installed dist (2026.7.1): the native audit's own inventory
    line labels its `hooks.enabled` reading "hooks.webhooks" for display purposes only
    (`audit.nondeep.runtime-C3y1Q5Fi.js:205-212` — `webhooksEnabled = cfg.hooks?.enabled
    === true`); there is no separate `hooks.webhooks` config key in
    `schema-DRyO1XBt.js`. The real internal-hooks surface is `hooks.internal.enabled`,
    `.entries`, `.installs`, and `.load.extraDirs` (`schema-DRyO1XBt.js:1063-1068`,
    mirrored by `hasConfiguredInternalHooks()` in `configured-pV8SaeM2.js:20-28`). Before
    this check, clawseccheck had zero references to any of these five fields (B169 only
    content-scans `hooks.mappings[].messageTemplate`/`textTemplate` — the template TEXT,
    not these enable-toggles).

    `hooks.internal.load.extraDirs` gets the sharpest wording: it names extra
    directories OpenClaw searches for internal hook MODULES at startup — a startup
    arbitrary-module-load / persistence surface, not merely an enable flag.

    B-288 widened the inventory from the ENABLE toggles to the root-`hooks`
    SESSION-KEY / AGENT-ROUTING policy family — `hooks.defaultSessionKey`,
    `hooks.allowRequestSessionKey`, `hooks.allowedSessionKeyPrefixes`,
    `hooks.allowedAgentIds` — which nothing in the package read before (grep: 0 hits
    each). See `_hooks_session_key_exposures` in `checks/_shared.py` for the dist
    grounding. Those lines are evidence only: they can never change this check's
    status, because they are gated on the same `hooks.enabled is True` that has
    already made the finding WARN.

    HONEST SCOPE. This covers the ROOT `hooks` object only. The plugin-scoped
    `plugins.entries.*.hooks.allowPromptInjection` / `.allowConversationAccess`
    (zod-schema-O9ml_nmo.js:789-795) are a DIFFERENT surface at a different path and
    remain uncovered — a separate task. Standalone this check also stays advisory: the
    escalation to a scored, FAIL-capable verdict happens only in RISK-20, which joins
    this posture with remote gateway exposure.

    WARN    — any of hooks.enabled, hooks.internal.enabled, an enabled
              hooks.internal.entries[] item, a hooks.internal.installs[] record, or a
              non-blank hooks.internal.load.extraDirs entry is configured (see evidence).
    UNKNOWN — openclaw.json present but unparseable/unreadable.
    PASS    — none of the above is configured (the common case — the real fleet config
              has no `hooks` key at all).
    """
    unreadable = _config_unreadable("B179", ctx)
    if unreadable is not None:
        return unreadable
    # B-661: `_config_unreadable` only covers "present but unparseable" — on a host
    # with no openclaw.json at all, config_parse_error is False and ctx.config is
    # `{}`, so every hooks.* dig() below would silently degrade to "absent" and fall
    # through to the PASS about a config nobody read.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B179",
            UNKNOWN,
            "No config was read, so whether any hooks.enabled / hooks.internal "
            "enable-toggle is configured could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    cfg = ctx.config
    evidence: list[str] = []
    extra_dirs_hit = False

    if dig(cfg, "hooks.enabled") is True:
        evidence.append(
            "hooks.enabled — inbound webhook hooks endpoint + mapping execution "
            "pipeline enabled"
        )

    internal_enabled = dig(cfg, "hooks.internal.enabled")
    if internal_enabled is True:
        evidence.append(
            "hooks.internal.enabled — internal hook runtime enabled (all configured "
            "internal hooks may load)"
        )

    # Mirror hasConfiguredInternalHooks()'s own short-circuit (configured-pV8SaeM2.js:
    # "if (!internal || internal.enabled === false) return false"): an EXPLICIT
    # hooks.internal.enabled: false disables internal-hook loading outright, so stale
    # entries/installs/extraDirs left under a disabled block are not a live load
    # surface and must not WARN.
    if internal_enabled is not False:
        entries = dig(cfg, "hooks.internal.entries")
        if isinstance(entries, dict):
            enabled_names = sorted(
                name
                for name, entry in entries.items()
                if isinstance(name, str)
                and not (isinstance(entry, dict) and entry.get("enabled") is False)
            )
            if enabled_names:
                shown = ", ".join(enabled_names[:6])
                more = f" (+{len(enabled_names) - 6} more)" if len(enabled_names) > 6 else ""
                plural = "y" if len(enabled_names) == 1 else "ies"
                evidence.append(f"hooks.internal.entries — enabled entr{plural}: {shown}{more}")

        # F-183: `hooks.internal.installs` moved into OpenClaw's machine-owned state store
        # in 2026.8.1, so the config read alone stops seeing registered internal hooks on a
        # current build. Both are consulted; the state wins where present. Only the COUNT
        # reaches the evidence line — the record's contents are never echoed (§8).
        installs = (getattr(ctx, "config_machine_state", None) or {}).get(
            "hooks.internal.installs")
        if not isinstance(installs, dict) or not installs:
            installs = dig(cfg, "hooks.internal.installs")
        if isinstance(installs, dict) and installs:
            evidence.append(
                f"hooks.internal.installs — {len(installs)} internal hook install(s) registered"
            )

        extra_dirs = dig(cfg, "hooks.internal.load.extraDirs")
        if isinstance(extra_dirs, list):
            named = sorted({d for d in extra_dirs if isinstance(d, str) and d.strip()})
            if named:
                extra_dirs_hit = True
                shown = ", ".join(named[:6])
                more = f" (+{len(named) - 6} more)" if len(named) > 6 else ""
                plural = "y" if len(named) == 1 else "ies"
                evidence.append(
                    "hooks.internal.load.extraDirs — additional startup module-load "
                    f"director{plural} searched for internal hooks: {shown}{more}"
                )

    # B-288: the SESSION-KEY / AGENT-ROUTING policy siblings under the same root
    # `hooks` object (defaultSessionKey, allowRequestSessionKey,
    # allowedSessionKeyPrefixes, allowedAgentIds). Deliberately OUTSIDE the
    # `internal_enabled is not False` block above — these govern the inbound webhook
    # endpoint, not internal-hook module loading, so an explicitly disabled
    # hooks.internal must not hide them.
    #
    # This cannot change B179's STATUS, only enrich its evidence:
    # _hooks_session_key_exposures returns [] unless `hooks.enabled is True`, and that
    # same condition has already appended the "hooks.enabled" evidence line above — so
    # every config these lines can reach was WARN before this change too. That is what
    # makes the extension free of any new false-positive surface, and it is pinned by
    # tests/test_b288_hooks_session_key.py::test_b179_status_never_changes_*.
    for _kind, _line in _hooks_session_key_exposures(cfg):
        evidence.append(_line)

    if not evidence:
        return _finding(
            "B179",
            PASS,
            "hooks.enabled is not set and no hooks.internal load surface (enabled "
            "flag, an enabled entry, an install record, or load.extraDirs) is "
            "configured.",
            "No action needed. If hooks are enabled later, review "
            "hooks.internal.load.extraDirs closely — OpenClaw loads and executes any "
            "internal hook module it discovers in those directories at startup.",
            pass_confidence="verified",
        )

    ev_summary = "; ".join(evidence)
    if extra_dirs_hit:
        detail = (
            "hooks.internal.load.extraDirs configures additional startup module-load "
            "directories for internal hooks — a code-exec/persistence surface: "
            + ev_summary
        )
        fix = (
            "Review every directory in hooks.internal.load.extraDirs: OpenClaw loads "
            "and executes any internal hook module discovered there at startup. Keep "
            "the list minimal, point it only at directories you control and have "
            "reviewed, and treat it like any other trusted-code load path."
        )
    else:
        detail = (
            "Inbound webhook hooks and/or internal hook loading is enabled: " + ev_summary
        )
        fix = (
            "This is a visibility inventory, not a misconfiguration finding — "
            "hooks.enabled and hooks.internal are legitimate automation features. "
            "Confirm the enabled surface is intentional; hooks.token (B1), "
            "hooks.mappings[].allowUnsafeExternalContent (B48), and hook-template "
            "content scanning (B169) already cover the higher-risk adjacent settings."
        )
    return _finding("B179", WARN, detail, fix, evidence)


def check_gateway(ctx: Context) -> Finding:
    cfg = ctx.config
    ev = []
    # B-020: build the remediation from the conditions that ACTUALLY fired, one clause per
    # trigger, so the fix names the real problem (e.g. allowInsecureAuth alone -> "Disable
    # gateway.controlUi.allowInsecureAuth", not generic boilerplate the config already meets).
    # Clauses join with "; " so each fired condition contributes one fragment.
    fixes = []
    # B-290: clauses that are worth DISCLOSING but are not proof of a misconfiguration.
    # They never escalate the status; they only add a WARN when nothing FAIL-worthy fired.
    soft_ev: list[str] = []
    bind = parse_bind_host(dig(cfg, "gateway.bind", ""))
    auth = dig(cfg, "gateway.auth.mode")
    if bind and bind not in LOOPBACK and auth in (None, "none"):
        # B-290 (ENV-4): `auth is None` — i.e. gateway.auth.mode absent or null — is
        # EXACTLY the condition under which resolveGatewayAuth derives the mode from an
        # env-resolved credential instead (auth-resolve-NyPBrh8F.js:34-42, `else if
        # (authConfig.mode)`). So when a persistent artifact carries
        # OPENCLAW_GATEWAY_TOKEN/_PASSWORD, this bind is authenticated and the FAIL was a
        # false positive on a correctly secured host.
        #
        # `auth == "none"` is deliberately NOT softened: "none" is truthy in the dist, so
        # the mode stays "none", `hasSharedSecret` stays false, and
        # server-runtime-config-r5ejxORO.js:78 refuses the non-loopback bind outright.
        # An explicit mode=none is a decision, not an omission.
        #
        # B-312: a config-supplied `gateway.auth.token` with no `auth.mode` is the SAME
        # shape as the env case above — resolveGatewayAuth derives mode="token" from the
        # credential itself when authConfig.mode is falsy (auth-resolve-NyPBrh8F.js:34-42),
        # and the credential is read config-FIRST (:23-24). So when a config token exists,
        # it is what OpenClaw actually authenticates with, and the env variables below are
        # only ever consulted when no config token exists (mirrors the dist's own
        # precedence). Left OUT of ENV-4/B-290 deliberately (config-only, no env
        # component); closed here with its own triage.
        _cfg_token, _cfg_token_strong = _gateway_config_token(cfg, auth)
        _env_cred, _env_cred_src = (
            _gateway_env_credential(ctx) if auth is None and _cfg_token is None else (None, None)
        )
        # C-135 (independent adversarial pass on B-290): presence alone is NOT enough to
        # clear this FAIL, and softening on truthiness made the scanner lie. The bind guard
        # that justifies the softening at all — server-runtime-config-r5ejxORO.js:66,78 —
        # tests `hasSharedSecret`, which is satisfied by a ONE-CHARACTER token: mode derives
        # to "token", the throw does not fire, and the gateway binds to 0.0.0.0 and listens.
        # `assertGatewayAuthConfigured` (auth-B27MflKU.js:183-197) rejects only a MISSING
        # credential; no minimum length exists anywhere in the dist. So "authenticated, or
        # no listener at all" holds for the credential-ABSENT case but NOT for the
        # credential-WEAK case, which is a live, world-reachable gateway one guess deep.
        #
        # The bar is the one this very check already applies to a config token below
        # (`0 < len(token) < 24`) — identical posture must not get opposite verdicts
        # depending on where the credential is stored. It also realigns us with OpenClaw's
        # own audit, which fires `gateway.token_too_short` on exactly this input
        # (audit-UjVvFwCi.js:239, `auth.mode === "token" && token.length < 24`) — being
        # weaker than the vendor's audit on a CRITICAL check is not a defensible position.
        #
        # Only the LENGTH of the credential is read. The value never reaches evidence, a
        # message, a fix string, or a log (§8). The same bar applies to the config-token
        # leg (B-312) for the identical reason — a sub-24-char config token binds and
        # listens exactly like a sub-24-char env token.
        _env_cred_strong = _env_cred is not None and len(_env_cred.strip()) >= 24
        if _cfg_token is not None and _cfg_token_strong:
            soft_ev.append(
                f"gateway.bind={bind} is non-loopback and the config sets no "
                f"gateway.auth.mode, but gateway.auth.token is set — OpenClaw derives "
                "auth.mode from it, so the gateway is authenticated. Reported as "
                "disclosure, not exposure"
            )
            fixes.append(
                "No action required if the config-supplied gateway token with no "
                "explicit gateway.auth.mode is intentional. Setting gateway.auth.mode "
                "explicitly makes the posture readable from the config alone"
            )
        elif _cfg_token is not None:
            ev.append(
                f"gateway.bind={bind} is non-loopback and the only gateway credential is "
                "a config-supplied gateway.auth.token shorter than 24 chars — OpenClaw "
                "binds and listens on it, so the gateway is world-reachable behind a "
                "guessable secret"
            )
            fixes.append(
                "Replace the config-supplied gateway token with one of at least 24 "
                "characters, or bind the gateway to loopback"
            )
        elif _env_cred is not None and _env_cred_strong:
            soft_ev.append(
                f"gateway.bind={bind} is non-loopback and the config sets no "
                f"gateway.auth.mode, but a gateway credential is supplied by the "
                f"environment ({_env_cred_src}) — OpenClaw derives auth.mode from it, so "
                "the gateway is authenticated. Reported as disclosure, not exposure"
            )
            fixes.append(
                "No action required if the environment-supplied gateway credential is "
                "intentional. Setting gateway.auth.mode explicitly makes the posture "
                "readable from the config alone"
            )
        elif _env_cred is not None:
            ev.append(
                f"gateway.bind={bind} is non-loopback and the only gateway credential is "
                f"an environment-supplied secret shorter than 24 chars ({_env_cred_src}) — "
                "OpenClaw binds and listens on it, so the gateway is world-reachable "
                "behind a guessable secret"
            )
            fixes.append(
                "Replace the environment-supplied gateway credential with one of at least "
                "24 characters, or bind the gateway to loopback"
            )
        else:
            ev.append(f"gateway.bind={bind or '?'} exposed with auth.mode={auth}")
            fixes.append(
                "Bind the gateway to loopback or require auth "
                "(gateway.auth.mode=token, token >=24 chars)"
            )
    # gateway.http.no_auth does NOT exist in OpenClaw schema (auth is enforced by default)
    # C-471: `gateway.controlUi.allowInsecureAuth` was REMOVED in OpenClaw 2026.8.1, and
    # the removal is fail-SAFE — unusual enough to state, because the usual shape is the
    # opposite. The escape hatch went from the config AND from the runtime:
    # `evaluateMissingDeviceIdentity` (`message-handler-*.js`) now reads
    #
    #     if (params.isControlUi) return { kind: "reject-control-ui-insecure-auth" };
    #
    # with no config consulted at all. Grep confirms it: on 2026.8.1 the string survives
    # only in `legacy-*.js`, the retired-path list, while on 2026.7.1-2 it is read by
    # `audit-*.js`, `dangerous-config-flags-current-*.js` and `gateway-chat-*.js`.
    #
    # So the leg STAYS — a 2026.7.x fleet still has the weakened state — but on a build we
    # can see is newer, a key left on disk after an upgrade is INERT, and reporting it as
    # an exposure would describe a state the runtime cannot be in. Same treatment as every
    # other stale key in this upgrade: the fact is reported, the verdict is not driven by
    # it. NOT remapped to `dangerouslyDisableDeviceAuth` — that key coexisted with this one
    # in 2026.7.1-2 (our own snapshot), so it is disqualified as a rename target.
    retired_insecure_auth = ""
    if dig(cfg, "gateway.controlUi.allowInsecureAuth"):
        if _openclaw_generation(ctx) == "modern":
            # Held back rather than appended here. B2's WARN is SCORED at CRITICAL, so a
            # note that lands in `soft_ev` on its own manufactures a scored critical
            # warning about a key that grants nothing — costing the user grade for a dead
            # line. It rides along only where a real finding already exists (below).
            retired_insecure_auth = (
                "gateway.controlUi.allowInsecureAuth is set but OpenClaw 2026.8.1 removed "
                "it — the Control-UI now requires device identity unconditionally, so this "
                "line grants nothing. Delete it (`openclaw doctor --fix` does)."
            )
        else:
            ev.append("gateway.controlUi.allowInsecureAuth enabled")
            fixes.append("Disable gateway.controlUi.allowInsecureAuth")
    # Real field: gateway.tailscale.mode (string "funnel"/"serve"/"off")
    # gateway.tailscale.funnel boolean does NOT exist in OpenClaw schema
    if dig(cfg, "gateway.tailscale.mode") == "funnel":
        ev.append("gateway.tailscale.mode=funnel exposes the gateway publicly")
        fixes.append("Set gateway.tailscale.mode to 'serve' or 'off' (not 'funnel')")
    # gateway.auth_no_rate_limit does NOT exist in OpenClaw schema
    # Rate limiting is configured via gateway.auth.rateLimit (optional object)
    token = dig(cfg, "gateway.auth.token") or dig(cfg, "gateway.token")
    if isinstance(token, str) and 0 < len(token) < 24:
        ev.append("gateway auth token shorter than 24 chars")
        fixes.append("Use a gateway auth token of at least 24 characters")
    # B-233: trusted-proxy auth is only as strong as the identity header it trusts. On a
    # non-loopback bind, without requiredHeaders/allowUsers genuinely constraining that
    # header, any direct network caller can self-declare identity — a spoofable full
    # auth bypass, not "authenticated". BUT (grounded: dist auth-B27MflKU.js
    # authorizeTrustedProxy / authorizeGatewayConnectCore, gated by
    # net-*.js isTrustedProxyAddress) OpenClaw itself rejects the connection before ever
    # reading the identity header when the caller's SOURCE IP is not in a configured
    # gateway.trustedProxies allow-list — so a genuine (non-wildcard) trustedProxies
    # list is an equally valid identity constraint; only the total absence of ALL THREE
    # (requiredHeaders, allowUsers, trustedProxies) is the real spoof surface.
    if (
        auth == "trusted-proxy"
        and bind
        and bind not in LOOPBACK
        and not dig(cfg, "gateway.auth.trustedProxy.requiredHeaders")
        and not dig(cfg, "gateway.auth.trustedProxy.allowUsers")
        and not _trusted_proxies_ok(dig(cfg, "gateway.trustedProxies"))
    ):
        user_header = dig(cfg, "gateway.auth.trustedProxy.userHeader") or "x-forwarded-user"
        ev.append(
            f"gateway.auth.mode=trusted-proxy on non-loopback bind={bind} with no "
            f"requiredHeaders/allowUsers/trustedProxies configured — the {user_header!r} "
            "identity header is attacker-spoofable"
        )
        fixes.append(
            "Configure gateway.auth.trustedProxy.requiredHeaders and/or allowUsers, or "
            "gateway.trustedProxies, to constrain identity, or bind the gateway to loopback"
        )
    open_ch = _open_channels(cfg)
    for name in open_ch:
        ev.append(f"channel '{name}' has an open dm/group policy (anyone can command it)")
    if open_ch:
        fixes.append("Set every open channel's dmPolicy/groupPolicy to 'allowlist'")
    if (ev or soft_ev) and retired_insecure_auth:
        soft_ev.append(retired_insecure_auth)
    if ev:
        _insecure_auth_only = ev == ["gateway.controlUi.allowInsecureAuth enabled"]
        sev = WARN if _insecure_auth_only else FAIL
        # soft_ev rides along in the detail so the report still says WHY the exposed bind
        # was not counted, but it can never raise the status — every escalation still
        # comes from `ev`.
        return _finding("B2", sev, "; ".join(ev + soft_ev), "; ".join(fixes), ev + soft_ev)
    if soft_ev:
        return _finding("B2", WARN, "; ".join(soft_ev), "; ".join(fixes), soft_ev)
    if not cfg:
        return _finding(
            "B2",
            UNKNOWN,
            "No config loaded — cannot assess gateway.",
            "Run on the host with ~/.openclaw present.",
            # B-362: sets not_applicable only when the config locus was read COMPLETELY
            # and cfg is still empty. Every condition this check grades (bind, auth mode,
            # trusted-proxy identity, open channels) is a plain ctx.config read, so a
            # genuinely empty (but completely-read) config means none of that surface
            # exists to misconfigure -- not merely an unassessed risk. _surface_absent's
            # own config_found gate keeps a host with NO openclaw.json at all (a
            # non-OpenClaw machine) on the real-UNKNOWN side, matching the existing
            # check_control_plane_mutation precedent for the same "no gateway config"
            # wording.
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    # C-182: `if not cfg:` above only catches a WHOLE-CONFIG-empty state. A
    # present-but-malformed `gateway` value (e.g. `"gateway": null`, a list, a
    # number) makes every dig(cfg, "gateway...") lookup degrade to its default
    # ("absent") without raising — indistinguishable from "gateway key simply
    # not present" — and falls through to a confident PASS below. A field that
    # genuinely can't be assessed must read UNKNOWN, not a fabricated PASS.
    # B-362: this malformed-value branch stays a REAL UNKNOWN (never not_applicable)
    # -- a present-but-corrupt `gateway` value is not "no such surface", it is "we
    # cannot tell what was intended", which is exactly the ambiguous case the sweep
    # must not flip.
    gw_present = isinstance(cfg, dict) and "gateway" in cfg
    gw = cfg.get("gateway") if gw_present else None
    if gw_present and not isinstance(gw, dict):
        return _finding(
            "B2",
            UNKNOWN,
            "gateway config value is present but malformed (not an object) — cannot assess.",
            "Fix `gateway` to be a config object, or remove the key.",
        )
    # B-233: this PASS is reached only when none of the ev-conditions above fired — i.e.
    # either the bind is loopback, or the bind is exposed but auth genuinely covers it
    # (token/password/trusted-proxy with identity constraints). Never claim "loopback"
    # for a bind that plainly isn't.
    if bind and bind not in LOOPBACK:
        return _finding(
            "B2",
            PASS,
            f"Gateway is authenticated (gateway.auth.mode={auth}) on a non-loopback bind "
            "and channels are not open.",
            "Keep auth on and channels on allowlist.",
        )
    return _finding(
        "B2",
        PASS,
        "Gateway is loopback/authenticated and channels are not open.",
        "Keep auth on and channels on allowlist.",
    )


def check_gateway_rate_limit(ctx: Context) -> Finding:
    """B80 — gateway auth without rate limiting on a non-loopback bind.

    Grounded (recon: gateway.auth.rateLimit). A token/password-authenticated gateway
    reachable beyond loopback with no rate limiting lets an attacker brute-force the
    credential.

    PASS    — auth is not token/password (explicit config, AND, when config sets no
              explicit auth.mode, config-token- AND environment-derived), OR the bind
              is loopback, OR gateway.auth.rateLimit is configured.
    WARN    — token/password auth (explicit-config-, config-token-, or
              environment-derived) AND non-loopback bind AND no gateway.auth.rateLimit.
    UNKNOWN — config sets no explicit auth.mode, no config-supplied token authenticates
              either, and no persistent artifact (systemd unit or global dotenv) was
              readable to check for an environment-supplied credential, on a
              non-loopback bind — cannot tell whether the gateway is genuinely
              unauthenticated or env-authenticated, so this must not default to a
              fabricated PASS. Also UNKNOWN, ``engine_degraded=True``
              (B-657), when a persistent artifact WAS read but the
              collector's byte cap truncated it (``limit_hits_for(ctx,
              LIMIT_DOMAIN_ENV)``) — an env-supplied credential could sit past the cut,
              so "no usable credential" is a claim about text that was never scanned,
              not a verified absence.

    B-310: this check used to read ONLY `gateway.auth.mode` from config, so a gateway
    authenticated by an environment-supplied credential (OPENCLAW_GATEWAY_TOKEN/
    _PASSWORD, resolved the same way B2/B-290 grounds — auth-resolve-NyPBrh8F.js:34-42,
    credential read at credentials-DesN22Ui.js:30-42) silently PASSed as "does not rely
    on a brute-forceable secret" without ever assessing rate limiting — the exact
    config-only blindness B-290 fixed for B2.

    B-312 gap (round 2, C-135): B-310's fix above stopped at the ENV leg and never
    re-derived `mode` from a config-supplied `gateway.auth.token` / `gateway.token` the
    way B2's own B-312 fix does — so a config-token-authenticated gateway (auth.mode
    absent, token >=24 chars) still fell all the way through to the same "does not rely
    on a brute-forceable secret" PASS as a genuinely unauthenticated one, even though B2
    correctly WARNs that identical config as authenticated-but-disclosed. Closed by
    sharing `_gateway_config_token` with B2 (config-first, mirroring the dist's own
    precedence, auth-resolve-NyPBrh8F.js:23-24) so the two checks cannot independently
    drift on what "authenticated by config" means — this docstring previously claimed
    parity with B2 while that config-token leg was still missing; it is genuine now.

    Same >=24-char strength bar as B2 (2a2f8af), for the identical reason:
    `hasSharedSecret` (server-runtime-config-r5ejxORO.js:66,78) accepts ANY non-empty
    credential, so a sub-bar config OR env value is not genuine auth — it is B2's
    exposed/guessable-secret FAIL, not this check's "authenticated-but-unthrottled"
    concern, and is treated the same as no credential at all here. Only the
    credential's LENGTH is read; the value never reaches evidence, detail, fix, or a
    log (§8).
    """
    unreadable = _config_unreadable("B80", ctx)
    if unreadable is not None:
        return unreadable
    # B-661: `_config_unreadable` only covers "present but unparseable" — on a host
    # with no openclaw.json at all, config_parse_error is False and ctx.config is
    # `{}`, so `dig(cfg, "gateway.bind", "")`'s `""` default lands in LOOPBACK below
    # and an unread config would be reported as a PROVEN loopback bind.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B80",
            UNKNOWN,
            "No config was read, so whether the gateway auth endpoint is exposed to "
            "remote brute-force could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    cfg = ctx.config
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    # Loopback is checked before mode/credential resolution: a loopback bind is not
    # exposed to remote brute-force regardless of auth mode, so it must never need an
    # env-credential read to resolve — that would manufacture a spurious UNKNOWN on the
    # common, already-safe case.
    if bind_host in LOOPBACK:
        return _finding(
            "B80",
            PASS,
            "Gateway is bound to loopback, so the auth endpoint is not exposed to remote "
            "brute-force.",
            "Keep the gateway on loopback, or add gateway.auth.rateLimit before exposing it.",
        )
    mode = dig(cfg, "gateway.auth.mode")
    cred_src = None
    if mode is None:
        # B-312 parity: config wins over environment (config-first, identical to B2)
        # — a config-supplied token is only ever superseded by looking at the
        # environment when NO config token exists at all.
        _cfg_token, _cfg_token_strong = _gateway_config_token(cfg, mode)
        if _cfg_token is not None and _cfg_token_strong:
            mode = "token"
            cred_src = "a config-supplied gateway.auth.token"
        elif _cfg_token is None:
            _env_cred, _env_cred_src = _gateway_env_credential(ctx)
            if _env_cred is not None and len(_env_cred.strip()) >= 24:
                mode = "token"
                cred_src = f"an environment-supplied credential ({_env_cred_src})"
            elif _env_cred is None and limit_hits_for(ctx, LIMIT_DOMAIN_ENV):
                # B-657: truncation implies the file WAS found and opened
                # (ctx.dotenv_found/unit_env_found are set before the byte-cap check
                # fires), so env_evidence_readable(ctx) is already True here and the
                # "not readable at all" branch below can never catch this case. A
                # credential past the cut is present-but-unread, not genuinely absent —
                # same DEGRADED_CHECK_CAP consequence as the B6/B172 fix (f748869).
                return _finding(
                    "B80",
                    UNKNOWN,
                    "gateway.auth.mode is not set in config, the bind is non-loopback, and no "
                    "usable environment-supplied gateway credential was found in the systemd "
                    "unit(s) or global dotenv file(s) that were read — but at least one of "
                    "them exceeded the collector's byte cap, so a credential past the cut "
                    "would not have been seen. Cannot determine whether the auth endpoint is "
                    "brute-forceable.",
                    "Keep OpenClaw's systemd unit files and global dotenv files "
                    "(~/.openclaw/.env, ~/.config/openclaw/gateway.env) under the collector's "
                    "size cap, or set gateway.auth.mode explicitly, then re-run the audit.",
                    config_field_paths={"gateway.auth.mode"},
                    engine_degraded=True,
                )
            elif _env_cred is None and not env_evidence_readable(ctx):
                return _finding(
                    "B80",
                    UNKNOWN,
                    "gateway.auth.mode is not set in config, the bind is non-loopback, and no "
                    "systemd user unit or global dotenv file was readable to check for an "
                    "environment-supplied gateway credential — cannot determine whether the "
                    "auth endpoint is brute-forceable.",
                    "Run the audit where it can read the OpenClaw systemd user unit and "
                    "global dotenv files, or set gateway.auth.mode explicitly.",
                    config_field_paths={"gateway.auth.mode"},
                )
            # else: env evidence was readable IN FULL and carried nothing usable (absent,
            # or a sub-24-char value not treated as authenticating) -> mode stays None,
            # falls through to the ordinary "not token/password" PASS below, exactly as
            # before B-310 for a truly-unauthenticated gateway.
        # else: a config token IS present but below the 24-char bar. B2 already FAILs
        # this as an exposed/guessable-secret gateway (config-first — the environment is
        # never consulted, matching B2/B-312 exactly); it is not this check's
        # "authenticated-but-unthrottled" concern, so it is treated the same as no
        # credential at all here (mirrors the weak-env-credential leg above). mode stays
        # None, falls through to the ordinary PASS below.
    if mode not in ("token", "password"):
        return _finding(
            "B80",
            PASS,
            "Gateway auth does not rely on a brute-forceable token/password secret "
            "(or is not configured).",
            "If you enable token/password gateway auth on an exposed bind, configure "
            "gateway.auth.rateLimit to throttle credential guessing.",
        )
    if dig(cfg, "gateway.auth.rateLimit"):
        return _finding(
            "B80",
            PASS,
            "Gateway auth has rate limiting configured (gateway.auth.rateLimit).",
            "Keep gateway.auth.rateLimit aligned with the exposure of the gateway.",
        )
    evidence = (
        [f"gateway.auth.mode={mode!r}"]
        if cred_src is None
        else [
            f"gateway.auth.mode is not set in config, but {cred_src} authenticates the "
            "gateway"
        ]
    ) + [
        f"gateway.bind host={bind_host!r} (non-loopback)",
        "gateway.auth.rateLimit is not set",
    ]
    return _finding(
        "B80",
        WARN,
        "Gateway uses token/password auth on a non-loopback bind but has no "
        "gateway.auth.rateLimit — the auth endpoint can be brute-forced.",
        "Configure gateway.auth.rateLimit (max attempts / window) to throttle credential "
        "guessing, or bind the gateway to loopback.",
        evidence=evidence,
    )


def check_least_privilege(ctx: Context) -> Finding:
    cfg = ctx.config
    allow = dig(cfg, "tools.elevated.allowFrom")
    hard = []  # clear over-privilege -> FAIL
    soft = []  # missing allowlist hygiene -> WARN
    # Real shape: tools.elevated.allowFrom is a dict keyed by provider name
    # e.g. { "discord": ["user-id-123"], "telegram": ["*"] }
    # (not a flat list or bare "*" string in real OpenClaw configs)
    if isinstance(allow, dict):
        total_entries = sum(len(v) if isinstance(v, list) else 1 for v in allow.values())
        wildcard_providers = [
            p for p, v in allow.items() if v == "*" or (isinstance(v, list) and "*" in v)
        ]
        if wildcard_providers:
            hard.append(
                "tools.elevated.allowFrom grants '*' (every sender) for providers: "
                + ", ".join(wildcard_providers)
            )
        elif total_entries > 25:
            hard.append(
                f"tools.elevated.allowFrom has {total_entries} total entries across "
                f"{len(allow)} provider(s) (too broad)"
            )
    elif allow == "*":
        # Legacy / hypothetical flat wildcard
        hard.append("tools.elevated.allowFrom = '*' (every sender can use elevated tools)")
    elif isinstance(allow, list) and "*" in allow:
        hard.append("tools.elevated.allowFrom contains '*' (flat list form — every sender)")
    elif isinstance(allow, list) and len(allow) > 25:
        hard.append(f"tools.elevated.allowFrom has {len(allow)} entries (too broad)")
    profile = str(dig(cfg, "tools.profile", "")).lower()
    if profile and profile != "minimal":
        # a broader profile (e.g. "coding") is a least-privilege preference, not a hole —
        # WARN, never a hard FAIL (the native audit does not fail it either).
        soft.append(f"tools.profile='{dig(cfg, 'tools.profile')}' is broader than minimal")
    if dig(cfg, "plugins.allow") is None and _plugins(cfg):
        soft.append("no plugins.allow reachability allowlist (plugins.entries present)")
    # plugins.tools_reachable_policy does NOT exist in OpenClaw schema — removed
    fixes = []
    if hard:
        fixes.append("Restrict tools.elevated.allowFrom to specific provider/sender IDs (no '*')")
    if profile and profile != "minimal":
        fixes.append("Set tools.profile to 'minimal'")
    if dig(cfg, "plugins.allow") is None and _plugins(cfg):
        fixes.append("Define a plugins.allow array to limit which plugins may load")

    if hard:
        return _finding("B3", FAIL, "; ".join(hard + soft), "; ".join(fixes), hard + soft)
    if soft:
        return _finding("B3", WARN, "; ".join(soft), "; ".join(fixes), soft)
    # B-065: hedge to UNKNOWN when the privilege surface is ENTIRELY undeclared,
    # mirroring A1's _meaningful_tool_surface thin-surface guard (B-033 gold standard).
    # NARROW gate: only when EVERY privilege signal is absent — no elevated grant, no
    # tool profile, no plugins, no RECOGNIZED tool surface, and no --attest roster. A
    # declared-but-clean surface (small allowFrom, minimal profile, allow-listed plugins,
    # a recognized tools.allow entry) still PASSes. _capabilities_attested is redundant
    # with the tail of _meaningful_tool_surface but kept for self-documenting intent.
    #
    # C-135 (independent, post-commit, B-803 sibling gap): the original gate let
    # `_capabilities_attested(ctx)` alone clear `surface_undeclared` to False even on
    # a config-blind run (no openclaw.json read at all) — an --attest roster then
    # walked this straight through to the unconditional PASS below, a confident
    # "no over-broad elevated-tool grant... in config" claim over a config that was
    # never read. Reproduced directly: config_found=False + a real --attest roster ->
    # PASS. Same root cause B-803 fixed for A1 (check_trifecta): an attestation only
    # speaks to the agent's own declared tools, not the rest of the config surface a
    # blind run never read. `config_blind` forces UNKNOWN here too, regardless of
    # attestation.
    config_blind = not getattr(ctx, "config_found", False) and not ctx.config
    surface_undeclared = config_blind or (
        dig(cfg, "tools.elevated.allowFrom") is None
        and dig(cfg, "tools.profile") is None
        and not _plugins(cfg)
        and not _meaningful_tool_surface(ctx)
        and not _capabilities_attested(ctx)
    )
    if surface_undeclared:
        detail = (
            "Least-privilege posture cannot be determined: no OpenClaw config was found "
            "to read at all — an attestation only speaks to the agent's own declared "
            "tools, not the rest of the config surface (tools.profile, plugins, "
            "elevated-tool allowlists) a config-blind run never read."
            if config_blind else
            "Least-privilege posture is indeterminate: the config declares no elevated-tool "
            "grant, tool profile, plugins, or recognized tool surface (runtime-granted tools "
            "are not visible to a static config audit), so there is nothing to verify as "
            "constrained."
        )
        fix = (
            "Run the audit against the real openclaw.json (or a --home pointing at it) so "
            "least privilege can be assessed against actual config."
            if config_blind else
            "Declare the agent's tool surface (tools.profile / tools.allow / "
            "tools.elevated.allowFrom) or pass --attest so least privilege can be assessed."
        )
        return _finding(
            "B3",
            UNKNOWN,
            detail,
            fix,
        )
    # B-042: PASS verifies a CONFIG-level least-privilege posture only (no over-broad
    # elevated grant, no profile/plugin escalation). It must NOT claim runtime "tool
    # reachability is constrained" — runtime-granted tools (message/exec_command/web_*)
    # are not in openclaw.json.
    return _finding(
        "B3",
        PASS,
        "No over-broad elevated-tool grant or profile/plugin escalation in "
        "config (runtime-granted tools are not visible to static config audit).",
        "Keep least privilege: explicit allowlists only.",
    )


def check_local_first(ctx: Context) -> Finding:
    names = _model_names(ctx.config)
    if not names:
        return _finding("B12", UNKNOWN, "No model config found.", "—")
    cloud = [n for n in names if any(c in n.lower() for c in CLOUD_PROVIDERS)]
    if cloud:
        return _finding(
            "B12",
            WARN,
            f"Cloud model(s) in use: {', '.join(sorted(set(cloud)))}.",
            "For maximum privacy prefer a local model; if cloud is required, ensure no "
            "sensitive data is sent to it. (Informational — low severity.)",
        )
    return _finding("B12", PASS, "Models are local-first.", "Keep data local where possible.")


def check_proxy_header_forging(ctx: Context) -> Finding:
    """C032 — advisory UNKNOWN when real-IP fallback lacks trusted proxy allow-list.

    If ``gateway.allowRealIpFallback`` is enabled, OpenClaw will parse forwarded
    client-address headers. Without an explicit proxy allow-list, that logic can be
    abused when an untrusted component injects spoofed values. The OpenClaw schema
    does not guarantee a single field-name shape for proxy trust across versions,
    so this check is intentionally conservative: it raises UNKNOWN rather than
    FAIL when fallback is enabled but trusted-proxy data is absent/invalid.
    """
    unreadable = _config_unreadable("C032", ctx)
    if unreadable is not None:
        return unreadable
    # B-661: `_config_unreadable` only covers "present but unparseable" — on a host
    # with no openclaw.json at all, config_parse_error is False and ctx.config is
    # `{}`, so `dig(ctx.config, "gateway.allowRealIpFallback")` would silently
    # resolve to None and fall through to the PASS about a config nobody read.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "C032",
            UNKNOWN,
            "No config was read, so whether gateway.allowRealIpFallback broadly trusts "
            "proxied source headers could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    fallback = dig(ctx.config, "gateway.allowRealIpFallback")
    if not fallback:
        return _finding(
            "C032",
            PASS,
            "Real-IP fallback is not enabled, so proxied source headers are not broadly trusted.",
            "Enable proxy-source trust only when a reverse-proxy chain is in place and "
            "trusted proxy source values are explicit.",
        )
    trusted = dig(ctx.config, "gateway.trustedProxies")
    if _trusted_proxies_ok(trusted):
        return _finding(
            "C032",
            PASS,
            "Real-IP fallback has an explicit trusted-proxy allow-list configured.",
            "Keep ``gateway.trustedProxies`` aligned with the actual trusted proxy chain.",
            evidence=[f"gateway.trustedProxies={trusted!r}"],
        )
    detail = (
        "gateway.allowRealIpFallback is enabled but gateway.trustedProxies "
        "is not configured with an explicit allow-list."
    )
    return _finding(
        "C032",
        UNKNOWN,
        detail,
        "Constrain gateway.allowRealIpFallback to a declared proxy chain by setting"
        " gateway.trustedProxies to proxy IPs/CIDRs that are actually permitted.",
        evidence=[f"gateway.allowRealIpFallback is enabled; trustedProxies={trusted!r}"],
    )


def check_sandbox(ctx: Context) -> Finding:
    cfg = ctx.config
    # Real path: agents.defaults.sandbox.mode (values: "off", "non-main", "all")
    # The bare sandbox.* top-level path does NOT exist in OpenClaw schema
    mode = dig(cfg, "agents.defaults.sandbox.mode")
    ev = []
    if mode == "off":
        ev.append("agents.defaults.sandbox.mode is off (exec runs on the host)")
    # Real path: agents.defaults.sandbox.docker.network (not sandbox.network_mode)
    docker_network = dig(cfg, "agents.defaults.sandbox.docker.network")
    if docker_network == "host":
        ev.append("agents.defaults.sandbox.docker.network=host (no network isolation)")
    # Real path: agents.defaults.sandbox.docker.binds (not sandbox.bind_mount). C-454:
    # extraction via the shared `_sandbox_docker_binds` (checks/_shared.py) rather than
    # this function's own isinstance chain. NOT `dig(cfg, "agents.defaults.sandbox")`:
    # that is a bare NON-LEAF object read, which test_schema_grounding.py's manifest
    # guard cannot verify by construction (same reasoning `_peragent_sandbox_evidence`
    # already documents for the identical problem) — plain dict traversal instead.
    #
    # C-135 (independent, post-commit): reproduced a real regression here directly
    # against bf31513^ -- the pre-extraction code was `dig(cfg, "...binds")` gated on
    # bare truthiness, so a malformed-but-truthy shape (e.g. a dict instead of a
    # string/list) still fired this evidence; `_sandbox_docker_binds` narrows that to
    # string/list and returns `None` otherwise, and treating `None` the same as `[]`
    # (ordinary absence) turned that case from FAIL into UNKNOWN. Fail closed on
    # `None`, matching `_sandbox_has_writable_bind`'s own `None -> True` treatment.
    _agents_node = cfg.get("agents") if isinstance(cfg, dict) else None
    _defaults_node = _agents_node.get("defaults") if isinstance(_agents_node, dict) else None
    default_sandbox = _defaults_node.get("sandbox") if isinstance(_defaults_node, dict) else None
    default_sandbox = default_sandbox if isinstance(default_sandbox, dict) else {}
    binds = _sandbox_docker_binds(default_sandbox)
    if binds is None:
        ev.append(
            "agents.defaults.sandbox.docker.binds is present but not a recognizable "
            "shape (expected a bind-spec string or a list of them) — cannot rule out "
            "a host-path bind"
        )
    elif binds:
        ev.append("agents.defaults.sandbox.docker.binds exposes host paths")
        # docker.sock bind hands full host control to the sandbox (container escape vector)
        if _bind_mentions_docker_sock(binds):
            ev.append(
                "agents.defaults.sandbox.docker.binds mounts docker.sock — "
                "grants host control to the sandbox (container escape)"
            )
    # Real path: agents.defaults.sandbox.workspaceAccess ("none"/"ro"/"rw")
    workspace_access = dig(cfg, "agents.defaults.sandbox.workspaceAccess")
    if workspace_access == "rw":
        ev.append(
            "agents.defaults.sandbox.workspaceAccess=rw (agent can write the mounted workspace)"
        )
    # Per-agent sandbox overrides are explicit, unambiguous misconfig — a named agent can
    # re-expose the host even when agents.defaults.sandbox is safe (C-058). Report it as a
    # definite FAIL ahead of the defaults-only WARN/UNKNOWN/phantom branches.
    agent_ev = _peragent_sandbox_evidence(cfg)
    if agent_ev:
        return _finding(
            "B4",
            FAIL,
            "one or more named agents override agents.defaults.sandbox with unsafe "
            "settings (see evidence) — a per-agent override can re-expose the host even "
            "when the defaults are safe.",
            # B-699: no container key is named here on purpose. The evidence identifies
            # each offending agent by id ("agent 'w': sandbox.mode=off"), which is true in
            # either roster shape, while `agents.list[]` is true in only one -- 2026.8.1
            # rejects that key, and a user on an older build has no `agents.entries`.
            # Naming one of them would point half the fleet at a key their file lacks.
            # B-738: 'non-main' dropped from the offer — it leaves each agent's own main
            # session on the host, so it does not remove the override's danger.
            "Remove the unsafe per-agent sandbox overrides named in the evidence "
            "(set sandbox.mode to 'all', sandbox.docker.network to 'bridge', "
            "sandbox.workspaceAccess to 'none'/'ro', and drop host and docker.sock "
            "binds), or rely on agents.defaults.sandbox.",
            ev + agent_ev,
        )
    # NOTE: the agents.defaults.sandbox.docker.dangerouslyAllow* break-glass trio is
    # intentionally NOT checked here — check_dangerous_overrides (B48) already owns the
    # whole "dangerously*" registry (gateway + per-agent), so detecting it here too would
    # double-report the same finding. See the docker/sandbox section of the internal
    # openclaw-schema-recon.md.
    # sandbox.seccomp_profile / sandbox.apparmor_profile do NOT exist as first-class config
    # fields; Docker backend relies on Docker's own profile mechanism
    # A present-but-phantom top-level `sandbox` block (sandbox.mode=... etc.) is NOT a real
    # OpenClaw key — sandbox config lives under agents.defaults.sandbox. Say so explicitly so
    # a user who configured the wrong key doesn't think the tool missed it (C-057).
    phantom_sandbox = isinstance(cfg.get("sandbox"), dict)
    _move_fix = (
        # B-738: names 'all' only. The point of this hint is that the user configured a
        # phantom key and has NO sandbox; sending them to a value that leaves their main
        # session on the host would answer that with a half-measure.
        "Move the sandbox settings under agents.defaults.sandbox "
        "(set agents.defaults.sandbox.mode to 'all')."
    )
    # B-024: a populated defaults-evidence list is a definite FAIL (docker.sock bind,
    # network=host, workspaceAccess=rw, mode=off). Surface it BEFORE the softer "mode not
    # set" WARN below, so a real container-escape signal is not masked just because
    # agents.defaults.sandbox.mode happens to be unset while exec is enabled.
    if ev:
        fixes = []
        if mode == "off":
            fixes.append(
                # B-738: 'all'. 'non-main' would clear this finding without containing the
                # agent's own main session, which is where exec actually runs.
                "Set agents.defaults.sandbox.mode to 'all' ('non-main' keeps the agent's "
                "own main session on the host)"
            )
        if docker_network == "host":
            fixes.append("Set agents.defaults.sandbox.docker.network to 'bridge' (not 'host')")
        if binds:
            if _bind_mentions_docker_sock(binds):
                fixes.append(
                    "Remove the docker.sock bind from docker.binds (it grants host control to the sandbox)"
                )
            fixes.append("Remove broad host path binds from docker.binds")
        if workspace_access == "rw":
            fixes.append("Set workspaceAccess to 'none' or 'ro'")

        return _finding("B4", FAIL, "; ".join(ev), "; ".join(fixes), ev)
    if mode is None and "exec" in _enabled_tools(cfg):
        if phantom_sandbox:
            return _finding(
                "B4",
                WARN,
                "a top-level 'sandbox' block is set, but that is not a real "
                "OpenClaw config key (sandbox settings live under "
                "agents.defaults.sandbox), so it is ignored and exec tooling "
                "likely runs on the host.",
                _move_fix,
            )
        return _finding(
            "B4",
            WARN,
            "exec tooling present but agents.defaults.sandbox.mode not set — "
            "likely host execution.",
            # B-738: see the structured remediation in catalog.py for the grounding.
            "Set agents.defaults.sandbox.mode to 'all' ('non-main' sandboxes only an "
            "agent's non-main sessions, leaving its own main session on the host) and "
            "configure agents.defaults.sandbox.docker for network isolation.",
        )
    if mode is None:
        if phantom_sandbox:
            return _finding(
                "B4",
                UNKNOWN,
                "a top-level 'sandbox' block is set, but that is not a real "
                "OpenClaw config key (sandbox settings live under "
                "agents.defaults.sandbox); no exec tools are configured, so it "
                "is not currently exploitable.",
                _move_fix,
                config_field_paths={"agents.defaults.sandbox.mode"},
            )
        return _finding("B4", UNKNOWN, "No exec tools and no sandbox config — not applicable.", "—",
                        config_field_paths={"agents.defaults.sandbox.mode"})
    return _finding("B4", PASS, "Execution is sandboxed.", "Keep sandbox mode enabled.")


# ---------- B391: nodeHost.workerRuns isolation disclosure ----------
# Re-grounded directly against the installed 2026.9.5 dist (the internal recon doc's
# descriptions map has no `nodeHost.workerRuns` entry at all — same documented gap class
# as B390/attachments, CLAUDE.md §4(c)):
#
#   dist/schema-CwAIqZVE.mjs:892-896 (vendor descriptions, verbatim):
#     "nodeHost.workerRuns": "Opt in to full OpenClaw worker session hosting from
#       Gateway-managed bundles. Disabled by default."
#     "nodeHost.workerRuns.enabled": "Allow this paired node to host sessions from exact
#       bundles installed by its Gateway (default: false)."
#     "nodeHost.workerRuns.isolation": "Select the worker-session process boundary: \"none\"
#       runs directly on the node host (default); \"container\" requires a working
#       Docker-compatible engine and never falls back to host execution."
#     "nodeHost.workerRuns.containerImage": "Optional Node 24.16+ or 26.1+ image for
#       container-isolated workers (default: \"node:24.19.0-slim\")."
#
#   dist/zod-schema-DN2u5FdA.mjs:576-580 (the actual schema, `NodeHostWorkerRunsSchema`):
#     enabled: boolean().optional()
#     capacity: number().int().min(1).max(NODE_WORKER_CAPACITY_MAX).optional()
#     isolation: _enum(["none", "container"]).optional()
#     containerImage: string().trim().min(1).optional()
#
# This re-grounding CONFIRMS an earlier shortlist reading three releases later (the
# feature shipped in 2026.8.1; the installed dist here is 2026.9.5): the path, the enum,
# and both defaults are unchanged. No FAIL-worthy shape turned up (containerImage is a
# plain trimmed string with no host/registry validation to interrogate, and the
# schema/defaults are identical to the originally filed gap) — this stays a "report it"
# reading, not a promotion to a FAIL-capable check.
#
# WHY THIS IS A REPORT, NOT A JUDGEMENT (never FAILs, and does not WARN on the default):
# isolation="none" is OpenClaw's OWN baseline for this setting, not a weakening a user
# introduced — the security-relevant question ("is this host's agent execution actually
# isolated?") is already asked by check_sandbox (B4) above, over a DIFFERENT config
# sub-tree (agents.defaults.sandbox.*). What is missing without this check is visibility:
# nodeHost.workerRuns governs a SEPARATE execution surface — worker sessions a paired
# Gateway dispatches to run on THIS node, from bundles that Gateway installed, entirely
# outside agents.defaults.sandbox — so a reader auditing "how isolated is code execution
# on this host" previously had no line naming it at all. The WARN branch below fires only
# once the feature is actually opted into (`enabled: true`); it is disclosure of a real,
# active surface, not a complaint about a default nobody touched.
def check_nodehost_workerruns_isolation(ctx: Context) -> Finding:
    """B391 — nodeHost.workerRuns execution-isolation disclosure, beside B4 (sandbox).

    PASS    — workerRuns is not enabled (absent, or `enabled` anything but `true` —
              the vendor default), so no worker session runs on this node at all; or
              workerRuns is enabled with `isolation: "container"` (the vendor's own
              isolated option), disclosing the image in use.
    WARN    — workerRuns is enabled and `isolation` resolves to anything other than
              `"container"` (absent, `"none"`, or an unrecognized value — all three
              collapse to the vendor's own host-execution default): worker sessions
              dispatched by a paired Gateway then run directly on this node host, a
              distinct surface from agents.defaults.sandbox.* and not covered by it.
              Advisory only (CheckMeta.scored=False) — never moves the grade.
    UNKNOWN — config unreadable/unparseable (engine-side), or no config was read at
              all (not_applicable in that second case — nothing to disclose about a
              host nobody looked at).

    Never FAILs: workerRuns is an explicit opt-in feature for hosting OTHER nodes'
    sessions, and its own documented default is the less-isolated option — reporting
    that as a failure would penalize the vendor's baseline, not a user's choice.
    """
    unreadable = _config_unreadable("B391", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B391",
            UNKNOWN,
            "No config was read, so nodeHost.workerRuns could not be assessed.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    enabled = dig(cfg, "nodeHost.workerRuns.enabled")
    if enabled is not True:
        return _finding(
            "B391",
            PASS,
            "nodeHost.workerRuns.enabled is not set to true (the vendor default), so "
            "this node does not host worker sessions dispatched by a paired Gateway — "
            "the isolation setting is moot.",
            "No action needed unless you intend this node to host sessions for other "
            "nodes; if you do enable it, review nodeHost.workerRuns.isolation first.",
            config_field_paths={"nodeHost.workerRuns.enabled"},
        )
    isolation = dig(cfg, "nodeHost.workerRuns.isolation")
    if isolation == "container":
        container_image = dig(cfg, "nodeHost.workerRuns.containerImage")
        image = (
            container_image
            if isinstance(container_image, str) and container_image.strip()
            else "node:24.19.0-slim (vendor default)"
        )
        return _finding(
            "B391",
            PASS,
            "nodeHost.workerRuns is enabled with isolation='container' — worker "
            f"sessions dispatched by a paired Gateway run inside a container boundary "
            f"(image: {image}), not directly on this node host.",
            "Keep isolation set to 'container'; prefer a digest-pinned or "
            "private-registry image over a mutable tag.",
            config_field_paths={
                "nodeHost.workerRuns.isolation",
                "nodeHost.workerRuns.containerImage",
            },
        )
    resolved = isolation if isinstance(isolation, str) and isolation else "none"
    return _finding(
        "B391",
        WARN,
        f"nodeHost.workerRuns is enabled with isolation={resolved!r} — worker sessions "
        "dispatched by a paired Gateway run directly on this node host, with no "
        "process boundary. 'none' is OpenClaw's own default for this setting, not a "
        "weakening introduced by this config, but it is a distinct execution surface "
        "from the agents.defaults.sandbox.* posture reported above and is not covered "
        "by it.",
        "If hosted worker sessions should not run directly on this host, set "
        "nodeHost.workerRuns.isolation to 'container' (requires a working "
        "Docker-compatible engine); otherwise no action is needed, since 'none' is "
        "the documented default.",
        config_field_paths={"nodeHost.workerRuns.isolation"},
    )


# ---------- B393: telemetry.enabled disclosure (F-202) ----------
# Re-grounded directly against the installed 2026.9.5 dist — the internal recon doc's
# descriptions map has no `telemetry` entry at all (same documented gap class as
# B389/B390/B391, CLAUDE.md §4(c)):
#
#   dist/zod-schema-DN2u5FdA.mjs:1487-1499 (TelemetryConfigShape, the actual schema):
#     telemetry: object({
#       enabled: boolean().optional(),       # registered label "Anonymous Feature
#                                             # Statistics"
#       consentedAt: string().datetime().optional(),
#     }).strict().optional()
#     The registered `enabled` help text (verbatim): "Shares enabled channel and
#     provider names, plugin count, and recent session count with the daily update
#     check. Disabled by default and always disabled when DO_NOT_TRACK=1."
#
#   dist/schema-CwAIqZVE.mjs:410 (the top-level `telemetry` description, verbatim):
#     "Explicit consent for anonymous feature statistics attached to the daily update
#     check. Feature statistics are disabled by default and never include messages,
#     credentials, or identifiers."
#
#   dist/telemetry-CwSEtSer.mjs:147-154 (`resolveTelemetryStatus`, the actual runtime
#   gate) shows the full precedence: an automated environment, the update check being
#   disabled, or DO_NOT_TRACK=1 (each checked in that order) independently force
#   telemetry off regardless of `telemetry.enabled` — `reason` resolves to "enabled"
#   only once all three earlier legs are clear AND `config.telemetry?.enabled ===
#   true`. DO_NOT_TRACK is read from `process.env` in the GATEWAY's own process
#   (`isDoNotTrackEnabled`, :92-95) — this audit is config-only and never reads
#   `os.environ` for a verdict about the audited host (that would answer "what is in
#   the auditing shell's environment", not the gateway's — the same doctrine
#   `checks/_lifecycle.py::check_update_pinning`'s own grounding note documents for
#   `OPENCLAW_NO_AUTO_UPDATE`), so this check cannot observe that suppression and does
#   not claim to.
#
#   dist/telemetry-CwSEtSer.mjs:167-195 (`prepareTelemetryPayload`, what actually goes
#   over the wire) shows the registered help text above UNDERSTATES the payload. It
#   says "plugin count"; the builder sends the count (`pluginsEnabled`) AND the sorted
#   ids of every enabled publicly-known plugin (`plugins`, :181). Full payload: schema
#   version, the OpenClaw version, platform/arch, the node runtime version, the request
#   surface, and under `features`: channel ids, provider families, plugin ids, the
#   enabled-plugin count, and a count of sessions in the last 24h. Channels, plugins
#   and provider families are each filtered to publicly-known ids first
#   (`isPubliclyKnownPluginId`, `publicChannelIds`, the built-in/official provider
#   test at :179), so a private or custom plugin, channel or provider name is never
#   sent. No message content, no credentials, no account or install identifier. The
#   user-facing detail below therefore names the PAYLOAD, not the help text: a
#   transparency line that repeats the vendor's understatement would be the one
#   thing this check exists not to be.
#
# WHY THIS IS INFO/DISCLOSURE-ONLY, NEVER FAIL OR WARN (CLAUDE.md §2 Golden Rule #5,
# and C-473's shortlist verdict, re-confirmed above against the current dist):
# telemetry is opt-in (disabled by default), unconditionally overridden off by
# DO_NOT_TRACK, and the vendor's own description of the payload is already the benign
# one this check quotes — feature-usage counts, never message content or secrets.
# There is no weakening here for a static audit to judge; naming what leaves the
# machine once an operator opts in is a transparency line for the reader, not a
# security verdict. This never escalates past PASS, so it needed no C-135 pass: there
# is no FAIL/WARN branch for one to adversarially test.
def check_telemetry_enabled(ctx: Context) -> Finding:
    """B393 (F-202) — telemetry.enabled: name what leaves the machine when a user
    opts in to OpenClaw's anonymous feature-usage statistics.

    PASS    — telemetry.enabled is not `True` (absent, `False`, or any other
              non-`True` shape — the vendor default): nothing leaves the machine via
              this channel. Also PASS when telemetry.enabled IS `True`, in which case
              the detail instead *names* what the payload builder actually sends
              (which is more than the vendor's own help text says) — a
              transparency line, not a verdict.
    UNKNOWN — config unreadable/unparseable (engine-side), or no config was read at
              all (not_applicable in that second case — nothing to disclose about a
              host nobody looked at).

    Never WARNs and never FAILs: opting in to anonymous feature statistics is not a
    weakening a static audit can judge (Golden Rule #4) — it is disabled by default,
    always suppressed under DO_NOT_TRACK, and the vendor's own description of the
    payload is already the benign one this check quotes. This is a transparency line,
    not a security verdict, so it never escalates past PASS.
    """
    unreadable = _config_unreadable("B393", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B393",
            UNKNOWN,
            "No config was read, so whether telemetry.enabled opts in to anonymous "
            "feature-usage statistics could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    enabled = dig(cfg, "telemetry.enabled")
    if enabled is not True:
        return _finding(
            "B393",
            PASS,
            "telemetry.enabled is not set to true (the vendor default) — no "
            "anonymous feature-usage statistics leave this machine via this "
            "channel.",
            "Nothing to do.",
            config_field_paths={"telemetry.enabled"},
        )
    return _finding(
        "B393",
        PASS,
        "telemetry.enabled is true — anonymous feature statistics are attached to "
        "the daily update check. As of OpenClaw 2026.9.5 that request carries: the "
        "OpenClaw version, platform and architecture, Node version and the invoking "
        "surface; the names of enabled channels and provider families and the ids "
        "of enabled plugins, publicly-known ones only, so a private or custom "
        "plugin, channel or provider name is not sent; and counts of enabled plugins "
        "and of sessions in the last 24 hours. No message content, credentials, or "
        "account or install identifier. OpenClaw's own help text calls the plugin "
        "part a count; the payload also names them. Always suppressed when "
        "DO_NOT_TRACK=1 is set in the gateway's own process environment, which this "
        "config-only audit cannot observe.",
        "Nothing to do — this is disclosure, not a finding. Run 'openclaw telemetry "
        "show' to see the exact request this build would send, or 'openclaw "
        "telemetry off' to disable it.",
        config_field_paths={"telemetry.enabled"},
    )


def check_secrets(ctx: Context) -> Finding:
    cfg = ctx.config
    ev = []
    # gateway.auth.password / hooks.token in config are flagged by the native audit too
    # (gateway.password top-level does not exist; password lives at gateway.auth.password)
    if dig(cfg, "gateway.auth.password"):
        ev.append("gateway.auth.password set in config")
    if dig(cfg, "hooks.token"):
        ev.append("hooks.token set in config")
    # secrets anywhere in the config are only a real risk if the file is readable by others
    secret_paths = _secret_paths(cfg)
    if secret_paths and _perms_loose(ctx):
        ev.append(
            f"{len(secret_paths)} secret(s) in config and openclaw.json is "
            f"group/world-readable ({oct(ctx.config_mode)[-3:]})"
        )
    # secrets hardcoded into bootstrap files (always wrong — injected into the prompt)
    for fname, text in ctx.bootstrap.items():
        if _pattern_hits_real_secret(SECRET_PATTERNS, text):
            ev.append(f"secret-like string in {fname}")
    if ev:
        # B-759: named against the audited home, not a hardcoded `~/.openclaw` — the
        # config path this run actually read (`ctx.config_path`, falling back to the
        # conventional filename under `ctx.home` for the rare case it was never
        # resolved) so the copy-pasted chmod acts on the config this run diagnosed,
        # not a different home on a machine that has several.
        _b1_cfg = ctx.config_path or (ctx.home / "openclaw.json")
        return _finding(
            "B1",
            FAIL,
            "; ".join(ev),
            "Move secrets to `openclaw secrets configure` / env vars, never into "
            f"bootstrap files; `chmod 600 {_b1_cfg}` and `chmod 700 {ctx.home}` so "
            "config-stored tokens are not readable by others.",
            ev,
        )
    # B-228: openclaw.json present but unparseable/unreadable — bootstrap-file secrets
    # (checked above, config-independent) still legitimately FAILed if present, but a
    # clean verdict at this point is only trustworthy if the config itself was actually
    # read. Guard the terminal PASS only (not the whole function) so the bootstrap scan
    # above keeps working normally under a broken openclaw.json.
    unreadable = _config_unreadable("B1", ctx)
    if unreadable is not None:
        return unreadable
    # Same gap as B11 (check_tls): config_mode stays None when openclaw.json parsed
    # fine but the separate permission-bits stat() call itself raised OSError, which
    # _config_unreadable() does not catch. config_found is required too -- config_mode
    # is ALSO None, legitimately, on a plain non-OpenClaw host where there is no
    # openclaw.json to stat() at all (config_found is False there), which must keep
    # reading as the ordinary "nothing to flag" PASS below, not a fake UNKNOWN. Only
    # matters here when there is something to protect (secret_paths) — an empty
    # config has nothing this check would flag regardless of whether perms could be
    # verified.
    if secret_paths and ctx.config_found and _is_posix() and ctx.config_mode is None:
        return _finding(
            "B1",
            UNKNOWN,
            f"{len(secret_paths)} token(s) in config, but file permissions could not "
            "be verified (the file parsed but its permission bits could not be read) "
            "— cannot confirm openclaw.json is not group/world-readable.",
            "Check why the audit could not stat() openclaw.json (see the run's errors) "
            "and re-run; in the meantime, manually confirm `chmod 600 "
            "~/.openclaw/openclaw.json`.",
        )
    # B-661: the two guards above ("present but unparseable" / "parsed but
    # unstattable") do not cover "no openclaw.json at all" — bootstrap-file secrets
    # (checked unconditionally above) still legitimately FAIL either way, but the
    # PASS wording below says "No exposed plaintext secrets", which conflates
    # "checked the config and found none" with "never checked the config at all".
    # secret_paths is necessarily empty here whenever config_found is False (it is
    # derived from an empty ctx.config), so this cannot mask a real config-content
    # finding — it only stops the terminal sentence from overclaiming.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B1",
            UNKNOWN,
            "No config was read, so whether openclaw.json itself carries a plaintext "
            "secret could not be determined. No secret-like string was found in the "
            "readable bootstrap files.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    note = ""
    pc = "verified"
    if secret_paths:
        note = f" ({len(secret_paths)} token(s) in config, but file perms are tight)"
        pc = "no_signal"
    return _finding(
        "B1",
        PASS,
        f"No exposed plaintext secrets.{note}",
        "Keep secrets out of bootstrap files and keep config perms at 600.",
        pass_confidence=pc,
    )


def check_secrets_at_rest_home(ctx: Context) -> Finding:
    """C015 — read-only scan for plaintext secret-shaped values in the OpenClaw home.

    This complements B1: B1 owns openclaw.json/bootstrap semantics and permissions, while
    C015 inventories any user-owned text file under the audited home (excluding installed
    skill dirs) that appears to contain an inline secret/token value. Evidence names files
    only — secret values are never echoed.
    """
    capped: list = []
    candidates = _c015_candidate_files(ctx, capped)
    scan_capped = bool(capped)
    if not candidates:
        return _finding(
            "C015",
            UNKNOWN,
            "No candidate home files found for secrets-at-rest scan.",
            "Run on the OpenClaw home with config/bootstrap/env files present.",
        )

    hits = []
    for path in candidates:
        try:
            if path.stat().st_size > _C015_MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _c015_is_generated_plugin_model_catalog(path.parts, text):
            continue
        if _c015_has_secret(text):
            try:
                rel = path.relative_to(ctx.home)
            except ValueError:
                rel = path
            hits.append(f"{rel}: secret-like value detected")

    # B-244: the walk cap can still be hit on a very large home even after excluded
    # material is kept out of the budget (see _c015_candidate_files) — never let either
    # verdict below read as a complete scan when it wasn't.
    cap_note = (
        f" Scan hit the {_C015_MAX_SCAN_FILES}-file walk cap before the home was fully"
        " covered — additional secrets may exist in files not yet reached."
        if scan_capped
        else ""
    )

    if hits:
        detail = (
            f"Plaintext secret-shaped value(s) found in {len(hits)} home file(s) — see evidence."
            f"{cap_note}"
        )
        # B-513: the detail states the true count while the evidence list was silently
        # truncated to 12, so a home with 13 hits printed "13 home file(s)" over 12 rows
        # and the reader had to notice the arithmetic themselves. Every other capped
        # evidence list in the engine already discloses its overflow (`(+N more)` in
        # _egress.py's B14, B164 and the loose-permission walk); this one did not follow
        # the convention it sits beside. Truncating is right — a home can hold hundreds of
        # matches and the report has to stay readable — but a silent truncation makes the
        # count and the list disagree, which is the same defect class as B-518.
        shown = hits[:_C015_MAX_EVIDENCE]
        if len(hits) > _C015_MAX_EVIDENCE:
            shown = shown + [f"(+{len(hits) - _C015_MAX_EVIDENCE} more file(s))"]
        return _finding(
            "C015",
            WARN,
            detail,
            "Move plaintext secrets into `openclaw secrets configure` or narrowly-scoped environment variables, and keep bootstrap/config files free of inline tokens.",
            evidence=shown,
        )

    if scan_capped:
        # GR#4/B-228 family: a coverage gap must never roll up to a confident "scanned
        # the home, all clean" headline — UNKNOWN, not PASS, until the rest is covered.
        return _finding(
            "C015",
            UNKNOWN,
            f"Scanned {len(candidates)} home file(s) before hitting the "
            f"{_C015_MAX_SCAN_FILES}-file walk cap; no plaintext secret-shaped values in"
            " what was scanned, but coverage is incomplete — the rest of the home was"
            " never reached.",
            "Re-run against a narrower home, or manually review any credentials/, "
            "identity/, devices/, and workspace/ content not covered by this scan.",
        )
    return _finding(
        "C015",
        PASS,
        f"Scanned {len(candidates)} home file(s); no plaintext secret-shaped values detected.",
        "Keep secrets out of home files; prefer the OpenClaw secrets store or environment injection.",
    )


# ---------- C-405: secrets stored at OpenClaw-redactor-blind config paths ----------
#
# MEASURED FIRST, per this task's own instruction, before writing anything here — both
# real consumers, not just the underlying patterns: `_secret_paths(cfg)` (B1's own
# detector) and `_c015_has_secret(text)` (C015's own detector) were run directly against
# five representative configs. Four missed; the positive control (an ordinary `apiKey`)
# was caught:
#   {"headers": {"Authorization": "Bearer <token>"}}     -> MISSED by both
#   {"auth": {"bearer": "<token>"}}                       -> MISSED by both
#   {"auth": {"tokens": ["<token>", "<token>"]}}          -> MISSED by both
#   {"encryption": {"key": "<token>"}}                    -> MISSED by both
#   {"tools": {"apiKey": "<token>"}}                      -> caught (control)
#
# Two DISTINCT reasons, not one:
#   1. `SECRET_KEY_RE` (checks/_shared.py) is `password|secret|token|api[_-]?key|
#      apikey|bottoken` -- "Authorization", "bearer", and bare "key" match none of
#      those alternatives at all, so `_secret_paths`'s key-name test never even
#      reaches the value.
#   2. `_secret_paths`'s own recursion only tests `SECRET_KEY_RE.search(k)` when a
#      dict value is a bare STRING; once it descends into a LIST (the `elif
#      isinstance(obj, list)` branch), each element is recursed into with no key at
#      all, so a `"tokens": ["<a>", "<b>"]` array is invisible even though "tokens"
#      itself matches `SECRET_KEY_RE` fine -- the key/value pairing is lost, not the
#      keyword.
#
# `logsafe.py`'s own redactor was also checked (this task's "separate, quick
# self-audit" ask): it imports this SAME `SECRET_KEY_RE` from `checks/_shared.py`
# rather than keeping a second copy, so gap #1 above is identical for our own log
# redaction -- widening the marker set below closes both at once, deliberately, rather
# than as a side effect.
#
# Deliberately a NEW, narrowly-scoped helper rather than widening the SHARED
# `SECRET_KEY_RE`/`_secret_paths` in place: `_secret_paths` feeds B1, a SCORED,
# FAIL-capable check, and `SECRET_KEY_RE` also feeds `logsafe.redact()`'s live output
# path. Adding a bare "key" alternative to that shared, UNANCHORED substring regex
# would match "primaryKey"/"foreignKey"/"sortKey"/"keyword" -- ordinary, non-secret
# field names that contain "key" as a substring -- and widen a scored FAIL surface on
# a false positive none of those deserve. This check's own key match
# (`_REDACTOR_BLIND_KEY_RE`) is anchored to the WHOLE key segment instead
# (`^(authorization|bearer|key)$`, case-insensitive) so "primaryKey" cannot collide,
# and it feeds only THIS new, unscored, WARN-only, never-FAIL check -- never B1.
_REDACTOR_BLIND_KEY_RE = re.compile(r"^(authorization|bearer|key)$", re.I)

# C-135 (independent, post-commit): a bare "key" segment is the broadest of the three
# alternatives above -- unlike "authorization"/"bearer", which are credential-typed by
# NAME alone, "key" is also the ordinary field name for a cloud resource identifier
# (a KMS key ARN, a Vault key ID) that is >=16 chars, not a SecretRef, and genuinely
# not a secret VALUE. Concrete false positive found and reproduced:
# {"encryption": {"key": "arn:aws:kms:us-west-2:123456789012:key/1234abcd-..."}}. This
# gate excludes values shaped like a structured resource identifier -- an ARN
# (`arn:<partition>:...`), a URI with a scheme (`scheme://...`), or a bare UUID --
# applied ONLY to the "key" alternative, never to "authorization"/"bearer": a Bearer
# token or an Authorization header value is never legitimately ARN/URI/UUID-shaped, so
# narrowing those two would only open a false negative for no matching benefit.
_REDACTOR_BLIND_STRUCTURED_ID_RE = re.compile(
    r"^arn:[a-z0-9-]+:|^[a-z][a-z0-9+.-]*://"
    r"|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)


def _redactor_blind_secret_paths(obj, prefix: str = "", depth: int = 0) -> list:
    """Dotted paths of a secret-shaped value sitting at a key name neither OpenClaw's
    own config-value redactor nor our own `_secret_paths`/`SECRET_KEY_RE` recognizes
    -- see the module comment above for the measurement and the two distinct gaps
    this closes. Mirrors `_secret_paths`'s own walk shape (same depth bound, same
    16-char / `_is_secret_reference` value gate) so the two stay easy to compare.
    """
    found: list = []
    if depth >= 100:  # mirrors _shared._MAX_WALK_DEPTH
        return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if (
                isinstance(v, str)
                and len(v) >= 16
                and not _is_secret_reference(v)
                and _REDACTOR_BLIND_KEY_RE.match(k)
                and not (
                    k.strip().lower() == "key"
                    and _REDACTOR_BLIND_STRUCTURED_ID_RE.match(v.strip())
                )
            ):
                found.append(path)
                continue
            if isinstance(v, list) and SECRET_KEY_RE.search(k):
                for i, item in enumerate(v):
                    if (
                        isinstance(item, str)
                        and len(item) >= 16
                        and not _is_secret_reference(item)
                    ):
                        found.append(f"{path}[{i}]")
            found.extend(_redactor_blind_secret_paths(v, path, depth + 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(_redactor_blind_secret_paths(v, f"{prefix}[{i}]", depth + 1))
    return found


def check_redactor_blind_secret_paths(ctx: Context) -> Finding:
    """B381 (C-405) — a secret-shaped value sits at a config path neither OpenClaw's
    own redactor nor this tool's own SECRET_KEY_RE-based detection recognizes (see the
    module comment above `_redactor_blind_secret_paths` for the measurement).

    Unlike B1, this is NOT gated on file permissions: the threat this check names is
    OpenClaw's own runtime echoing the value back through `config get` output,
    trajectory logs, or a message channel relay — a leak that happens regardless of
    who else can read openclaw.json on disk. Never FAIL: a false positive here costs
    a WARN, not a hard-capped grade, and this is a narrow, hand-anchored key-name
    match (see `_REDACTOR_BLIND_KEY_RE`'s own comment for why it is anchored rather
    than a substring test) rather than the exhaustively-vetted `SECRET_KEY_RE`.

    WARN    — a redactor-blind path holds a secret-shaped value.
    UNKNOWN — openclaw.json present but unparseable/unreadable, or not read at all.
    PASS    — no such path found.
    """
    unreadable = _config_unreadable("B381", ctx)
    if unreadable is not None:
        return unreadable
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B381",
            UNKNOWN,
            "No config was read, so whether a secret-shaped value sits at a "
            "redactor-blind path could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    paths = _redactor_blind_secret_paths(ctx.config)
    if not paths:
        return _finding(
            "B381",
            PASS,
            "No secret-shaped value found at a config path OpenClaw's own redactor "
            "does not recognize (Authorization/bearer/key/plural-tokens-as-a-list).",
            "No action needed.",
        )
    label = ", ".join(paths[:6])
    extra = f" (+{len(paths) - 6} more)" if len(paths) > 6 else ""
    return _finding(
        "B381",
        WARN,
        f"{len(paths)} secret-shaped value(s) at a config path OpenClaw's own "
        "redactor does not recognize, so it will not be masked in config-get "
        f"output, trajectory logs, or a relayed message channel: {label}{extra}",
        "Move the value to `openclaw secrets configure` (a SecretRef indirection), "
        "or to a path OpenClaw's redactor does recognize (a key name containing "
        "password/secret/token/apiKey) — never a bare Authorization/bearer/key field "
        "or a plural token array.",
        evidence=paths,
    )


def check_tls(ctx: Context) -> Finding:
    cfg = ctx.config
    bind = parse_bind_host(dig(cfg, "gateway.bind", ""))
    # Real path: gateway.tls.enabled (bool, default false)
    # gateway.tls as a bare boolean and gateway.https do NOT exist in OpenClaw schema
    tls = dig(cfg, "gateway.tls.enabled")
    ev = []
    exposed = bind in EXPOSED_BINDS or (bind and bind not in LOOPBACK)
    # Real tailscale field: gateway.tailscale.mode == "funnel" (not gateway.tailscale.funnel bool)
    if exposed and not tls:
        ev.append(f"gateway.bind={bind} is non-loopback without TLS configured")
    if _perms_loose(ctx):
        ev.append(
            f"openclaw.json is group/world-readable ({oct(ctx.config_mode)[-3:]}) — at-rest risk"
        )
    if ev:
        # B-759: see B1's own comment above — named against the audited home, not a
        # hardcoded `~/.openclaw`.
        _b11_cfg = ctx.config_path or (ctx.home / "openclaw.json")
        return _finding(
            "B11",
            WARN,
            "; ".join(ev),
            "Terminate TLS (reverse proxy / tailscale) for any non-loopback bind; "
            f"`chmod 600 {_b11_cfg}` and `chmod 700 {ctx.home}`.",
            ev,
        )
    # B-228: guard the terminal PASS only — _perms_loose(ctx) above is a real, config-
    # content-independent file-permission signal (still legitimately WARNs on a broken
    # openclaw.json that is ALSO group/world-readable), so only the "transport is fine"
    # claim (which needs the actual gateway.bind/gateway.tls.enabled values) is gated.
    unreadable = _config_unreadable("B11", ctx)
    if unreadable is not None:
        return unreadable
    # config_mode stays None when openclaw.json parsed fine but the SEPARATE stat()
    # call that reads its permission bits (collector.py) itself raised OSError —
    # config_parse_error is False in that case (the content WAS read), so the guard
    # above does not catch it. _perms_loose() then folds that "never checked" state
    # into the same False as "checked and found tight" (deliberately, for the
    # non-POSIX case — see tests/test_windows.py), which would make this a fake PASS
    # on the one POSIX sub-case that has no such excuse. config_found is required too
    # -- config_mode is ALSO None, legitimately, on a plain non-OpenClaw host with no
    # openclaw.json to stat() at all, which must keep reading as the ordinary
    # "nothing to flag" PASS below. Gated on _is_posix() as well: Windows keeps its
    # existing, intentionally-tested "skip, don't fabricate an NTFS-ACL verdict from
    # st_mode" PASS.
    if ctx.config_found and _is_posix() and ctx.config_mode is None:
        return _finding(
            "B11",
            UNKNOWN,
            "Config file permissions could not be verified (the file parsed but its "
            "permission bits could not be read) — cannot confirm openclaw.json is not "
            "group/world-readable.",
            "Check why the audit could not stat() openclaw.json (see the run's errors) "
            "and re-run; in the meantime, manually confirm `chmod 600 "
            "~/.openclaw/openclaw.json`.",
        )
    # B-661: the two guards above only cover "openclaw.json present but unparseable"
    # (_config_unreadable) and "parsed but unstattable" — on a host with NO
    # openclaw.json at all, config_found is False, config_parse_error is False, and
    # ctx.config is `{}`. `bind`/`tls` above then silently read as "absent" and this
    # PASS would assert a proven-safe transport about a config nobody read. The
    # `_perms_loose`-only WARN path above this stays reachable on a genuinely
    # unparseable config (a real, content-independent file-mode signal); only this
    # terminal "everything is fine" claim needs the config to have actually loaded.
    if (not isinstance(ctx.config, dict) or not ctx.config) and not ctx.config_found:
        return _finding(
            "B11",
            UNKNOWN,
            "No config was read, so whether the gateway transport is loopback/TLS "
            "could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    return _finding(
        "B11",
        PASS,
        "Transport is loopback/TLS and config perms are tight.",
        "Keep transport encrypted and credential files locked down.",
    )


def check_trifecta(ctx: Context) -> Finding:
    # B-306: openclaw.json present but unparseable/unreadable (config_parse_error, B-166)
    # collapses ctx.config to {} — every dig(cfg, ...) lookup inside _trifecta_legs then
    # defaults to "absent", so the untrusted-input and outbound-action legs (100%
    # config-derived) read as OFF even when the real config has them ON. Guarded at the
    # top, before computing legs at all: unlike B1/B11 (whose independent, non-config
    # signal is a COMPLETE, self-sufficient basis for their own FAIL/WARN), the one
    # non-config contributor mixed into _trifecta_legs — the credential-store CONTENT read
    # (B-666; was `(ctx.home / "credentials").is_dir()`), feeding only the "sensitive
    # data" leg — can never by itself clear the
    # >=3-legs FAIL threshold or satisfy the thin-surface WARN branch below (which keys on
    # the untrusted-input/outbound legs, not sensitive data). So guarding here cannot mask
    # an independently-provable verdict; it only stops a confidently-worded WARN/PASS from
    # being computed off a config the audit never actually saw. Measured impact on a real
    # blind run: A1 read WARN instead of its true FAIL, inflating the overall grade from
    # F/49 to C/79 — a lying two-grade improvement on the flagship CRITICAL check.
    unreadable = _config_unreadable("A1", ctx)
    if unreadable is not None:
        return unreadable
    legs = _trifecta_legs(ctx)
    active = [k for k, v in legs.items() if v]
    detail = f"Active legs {len(active)}/3: {', '.join(active) or 'none'}. Rule: keep ≤2 of 3."
    if len(active) >= 3:
        detail += (
            " All three legs are active — your agent takes outside input, can reach"
            " sensitive data, and can act outbound; one injected prompt is enough to"
            " exfiltrate everything."
        )
    resolved_default = _resolved_default_input_channels(ctx.config)
    substituted_dm = _substituted_dm_policy_channels(ctx.config)  # B-609
    detail += _distance_note(
        active, ingress_resolved_by_default=bool(resolved_default or substituted_dm)
    )
    detail += _mcp_leg_note(ctx)
    detail += _leg_attribution_note(active, _trifecta_leg_sources(ctx))  # B-493
    detail += _multi_agent_note(ctx)
    detail += _resolved_default_note(ctx)
    detail += _substituted_dm_policy_note(ctx)  # B-609
    detail += _persistence_note(ctx)  # F-169

    if len(active) >= 3:
        return _finding(
            "A1",
            FAIL,
            detail,
            "Break the trifecta: remove one leg. Easiest wins — lock channels to "
            "owner only (no untrusted input), or gate all outbound/exec actions behind "
            "human approval, or move sensitive data out of the agent's reach.",
            evidence=active,
        )

    # B-803: a run that never found openclaw.json at all leaves ctx.config == {} —
    # exactly the same shape as a genuinely empty, fully-read config (B-166's own note
    # at the top of this function). `_capabilities_attested`/`_meaningful_tool_surface`
    # below treat an attested roster as license to trust every OFF leg they gate, but an
    # attestation only speaks to the AGENT's own declared tools — it says nothing about
    # channels/dmPolicy or the rest of the config surface this run never read at all. A
    # config-blind run therefore let an attested roster silence every hedge and reach a
    # confident PASS on the flagship CRITICAL check, which is strictly worse than the
    # honest "Cannot determine" WARN a blind run gets without one (measured: PASS
    # 'Active legs 1/3' vs the correct WARN once attested tools are added to an
    # otherwise-empty home). `not ctx.config`, not just `not ctx.config_found`, so a
    # hand-built test Context that sets a real config dict without also setting
    # config_found=True (this file's own convention — see e.g. test_checks.py's `_a1`)
    # stays inert; only an ACTUALLY empty config participates.
    config_blind = not getattr(ctx, "config_found", False) and not ctx.config

    # Thin-surface guard (B-033): runtime tools granted at session start (message,
    # exec_command, web_*, memory_*) are NOT written to openclaw.json, so an
    # input/outbound leg that looks OFF can still be live. We only trust an OFF leg
    # when the user has attested the agent's real tool inventory (--attest). An
    # unrelated tools.allow entry must NOT silence this — a no-op name was previously
    # enough to flip WARN→PASS without changing real exposure. A config-blind run
    # (B-803) can never trust the attestation to stand in for the config it never saw,
    # so it forces this hedge regardless of what `_meaningful_tool_surface` says.
    runtime_unknown = [
        k for k, v in legs.items() if not v and k in ("untrusted input", "outbound actions")
    ]
    if runtime_unknown and (config_blind or not _meaningful_tool_surface(ctx)):
        return _finding(
            "A1",
            WARN,
            detail
            + (
                f" Cannot determine from config: {', '.join(runtime_unknown)}."
                " Runtime tools (e.g. message, exec_command, web_*) granted at"
                " session start are not reflected in openclaw.json."
            ),
            f"Run `{command_prefix()} --ask` to generate an attestation template, then re-run"
            " with `--attest <file>` so these legs resolve — or treat as possible 3/3.",
            evidence=active,
        )

    # B-499: a config that never wrote dmPolicy is not the same as one that restricted
    # ingress, but A1 reported them identically. Mirrors the runtime_unknown guard just
    # above — same shape, same reason: do not hand back a confident PASS for a posture the
    # config never actually stated. Deliberately WARN and not a leg: promoting a resolved
    # default to a full leg would move `active`, which is the one thing this change
    # forbids (measured: 0 A1 FAIL flips across 535 findings, 6 fixtures PASS->WARN).
    # `active` and `evidence` are untouched, so the leg count a reader sees is unchanged.
    if resolved_default:
        return _finding(
            "A1",
            WARN,
            detail,
            _resolved_default_fix(resolved_default),
            evidence=active,
        )

    # B-609: a WRITTEN dmPolicy that OpenClaw does not recognize for its channel is not
    # the same as one that restricted ingress, either — see _substituted_dm_policy_note.
    if substituted_dm:
        return _finding(
            "A1",
            WARN,
            detail,
            "Fix the typo: write one of the values `DmPolicySchema` actually accepts for"
            ' that channel (open / pairing / allowlist / disabled; Feishu and Lark accept'
            " the first, second, and third — see the note above for how `disabled` is"
            " still honored there). An unrecognized literal is not read as a restriction.",
            evidence=active,
        )

    # Ordering: this runs LAST of the three hedges, immediately before the PASS it
    # replaces. The other two answer "the config stated this leg's input ambiguously";
    # this one answers "the config never stated this leg at all", which is the weakest
    # claim of the three, so it yields to either of the more specific ones when both
    # apply. Putting it earlier stole B-499's remediation text on the risk21 fixtures.
    # B-666: the same reasoning as the two guards above, for the leg they do not cover.
    # `runtime_unknown` hedges an OFF input/outbound leg because runtime tools are not
    # written to openclaw.json; nothing hedged an OFF "sensitive data" leg, so a config
    # that simply never named a data tool got a confidently-worded PASS — the leg read as
    # KNOWN-ABSENT when it was only UNDECLARED. It is not merely undeclared, either: both
    # config layers that decide whether a file-read tool can leave the workspace default
    # to the PERMISSIVE end (see clawseccheck/toolpolicy.py), so on such a config the
    # agent really can read openclaw.json, credentials/ and anything else its user can.
    #
    # Deliberately a WARN and NOT a leg, following B-499 exactly: promoting this to a leg
    # was measured across 581 local corpus homes and produced 18 new CRITICAL FAILs, six
    # of them on `clean_*` fixtures — `active` and `evidence` stay untouched, so the leg
    # count a reader sees is unchanged and no new FAIL can come out of this branch.
    # (The wiring B-666 originally proposed — raise the leg from C015's at-rest scan or
    # B41's credential inventory — was measured too and is worse: 470 of 581 homes carry
    # a secret-shaped value in openclaw.json itself, so the leg would be ON for 81% of all
    # configs and A1 would collapse into "ingress AND outbound".)
    # Gated on the ATTESTATION alone, deliberately NOT on `_meaningful_tool_surface`
    # (which silences the runtime_unknown hedge above). That helper counts a powerful
    # `tools.profile` as a visible capability surface — and `coding` is precisely the
    # profile that GRANTS the unconfined `read` tool, so reusing it here would switch the
    # hedge off exactly where the exposure is most certain. Only a positive declaration
    # of the agent's real tool inventory can resolve a leg the config left undeclared.
    #
    # Known limitation, recorded rather than hidden: an attestation that NAMES a
    # data-read tool silences this hedge instead of raising the leg, because nothing
    # feeds attested tool names into `_trifecta_leg_sources`. Same root as the fact that
    # SENSITIVE_TOOL_HINTS does not know OpenClaw's real fs tool ids (`read`/`edit`/
    # `write`/`apply_patch`) — "read" cannot simply be added to a substring hint list
    # without matching "thread"/"spreadsheet". Tracked separately; not widened here,
    # because raising a leg is FAIL-capable movement and this change adds no FAIL.
    # B-803: same reasoning as the config_blind guard above, for the one leg this
    # thin-surface family doesn't already cover. `config_blind` forces this hedge too
    # (`or` below) — an attestation cannot single-handedly clear the sensitive-data leg
    # on a run that never read the config it would need to corroborate that with.
    if not legs["sensitive data"] and (config_blind or not _capabilities_attested(ctx)):
        reach = scopes_reaching_outside_workspace(ctx.config)
        store = _credential_store_state(getattr(ctx, "home", None))
        # B-749: the on-disk credentials/ scan above can read clean while OpenClaw's
        # machine-owned auth-profile store (config_machine_state["authProfiles.store"])
        # holds real material — measured on the fleet machine, 2026-09-06:
        # secret_files=[], incomplete=False (a confident "looked, nothing there"), while
        # the state DB held a non-trivial authProfiles.store row. Length-only (see
        # collector._collect_auth_profile_store_presence): a row longer than the
        # vendor's own empty-store shape ({"version":1,"profiles":{}}, 27 bytes,
        # grounded against the installed dist) means something is actually stored
        # there, without this check ever reading it. Deliberately a HEDGE here, not a
        # leg-raising signal: whether a non-empty row always means a USABLE credential
        # (vs. an expired/revoked profile) is unresolved, so asserting the leg is ON
        # would risk a new false-positive FAIL on the CRITICAL check that grade-caps
        # the whole audit — the same care B-730 already took in the other direction.
        auth_store_length = getattr(ctx, "auth_profile_store_length", None)
        auth_store_present = (
            getattr(ctx, "auth_profile_store_read", False)
            and auth_store_length is not None
            and auth_store_length > _AUTH_PROFILE_STORE_EMPTY_BYTES
        )
        # B-845: the SAME hedge, for a PER-AGENT auth store
        # (agents/<agent-id>/agent/openclaw-agent.sqlite, table auth_profile_store) --
        # a different file from the shared state DB above, grounded against the
        # installed dist (2026.9.5) to hold real credentials on its own: a home with an
        # empty credentials/ directory AND an empty-or-absent shared-store row can still
        # have real material sitting in an agent's own database, which the two checks
        # above are both blind to. Deliberately the SAME hedge, not a leg-raising signal
        # — see the auth_store_present comment above; the same "not yet resolved whether
        # a non-empty row always means a usable credential" reasoning applies here too.
        agent_auth_store_length = getattr(ctx, "agent_auth_profile_store_length", None)
        agent_auth_store_present = (
            getattr(ctx, "agent_auth_profile_store_read", False)
            and agent_auth_store_length is not None
            and agent_auth_store_length > _AUTH_PROFILE_STORE_EMPTY_BYTES
        )
        # B-845 (round 3, 2026-09-23): a C-135 review found the capped flag was read
        # ONLY inside the `agent_auth_store_present` sentence below -- so a home with
        # MORE agent databases than the sweep's own cap allows, where none of the
        # first `_MAX_SQLITE_DBS` checked happened to hold real material, read as a
        # confident, unhedged PASS: `agent_auth_store_present` was False (nothing
        # FOUND among the ones actually checked), so the whole `if` never fired and
        # the fact that the sweep stopped short of every agent was silently dropped.
        # Folded into the hedge condition itself so a capped-but-empty-so-far sweep
        # hedges on its own, independent of whether `agent_auth_store_present` is
        # True -- the same "a partial sweep is not the same fact as an exhaustive
        # one" discipline `store["incomplete"]` already gets above.
        agent_auth_capped = getattr(ctx, "agent_auth_profile_store_capped", False)
        if (
            reach
            or store["incomplete"]
            or config_blind
            or auth_store_present
            or agent_auth_store_present
            or agent_auth_capped
        ):
            why = []
            if reach:
                # B-712: when one of these scopes is `sandbox.mode: "non-main"`, whether it
                # is confined depends on which SESSION runs, which no config states. Saying
                # "are not confined" and "can read" would then assert what we have not
                # established — the same fabrication in the other direction as the confident
                # `True` this predicate used to return. The claim is weakened to match.
                undecided = any_confinement_undecided(reach)
                why.append(
                    f"file tools are {'not proven confined' if undecided else 'not confined'}"
                    f" to the workspace for {', '.join(reach)}"
                    " (tools.fs.workspaceOnly is not true there) and the `read` tool is"
                    f" still granted, so an injected prompt {'may be able to' if undecided else 'can'}"
                    " read openclaw.json, credentials/ and any other file this account can"
                )
            if store["incomplete"]:
                why.append(
                    "the credential store could not be read in full"
                    f" ({store['reason']}), so nothing found in it means 'not found',"
                    " not 'not there'"
                )
            if auth_store_present:
                why.append(
                    "the machine's own auth-profile store holds more than an empty"
                    f" shell ({auth_store_length} bytes in"
                    " config_machine_state['authProfiles.store'], vs. OpenClaw's own"
                    f" {_AUTH_PROFILE_STORE_EMPTY_BYTES}-byte empty-store shape), and"
                    " this scan only looked at the credentials/ directory on disk"
                )
            if agent_auth_store_present:
                why.append(
                    "at least one agent's own auth-profile store holds more than an"
                    f" empty shell ({agent_auth_store_length} bytes in its"
                    " agents/<agent-id>/agent/openclaw-agent.sqlite auth_profile_store"
                    f" table, vs. OpenClaw's own {_AUTH_PROFILE_STORE_EMPTY_BYTES}-byte"
                    " empty-store shape), and the sensitive-data leg is only ever"
                    " raised from files under credentials/, not from either database"
                )
            if agent_auth_capped:
                # B-845 (round 3, 2026-09-23): a STANDALONE clause, not folded into
                # the `agent_auth_store_present` sentence above -- it needs to fire
                # even when nothing was FOUND among the agent databases this scan did
                # manage to check (see the hedge-condition comment above for why: the
                # original wiring only ever read this flag from inside the "present"
                # branch, so a capped-but-nothing-found sweep silently dropped the
                # disclosure entirely). Matches how the C015 secrets-at-rest scan
                # discloses its own walk cap rather than letting a partial sweep read
                # as an exhaustive one.
                why.append(
                    "more per-agent databases exist under"
                    " agents/*/agent/openclaw-agent.sqlite than this scan's cap"
                    " allows, so not every agent's own auth-profile store could be"
                    " checked"
                )
            if config_blind:
                why.append(
                    "no OpenClaw config was found on this host at all, so nothing about"
                    " this leg was actually read — an attested roster speaks only to the"
                    " agent's own tools, not to channels or the rest of the config surface"
                )
            return _finding(
                "A1",
                WARN,
                detail
                + " Cannot determine from config: sensitive data. The leg is reported"
                f" off because no data tool is named in the config, but {'; and '.join(why)}.",
                (
                    "Run this audit against a host where openclaw.json exists, or attest"
                    " the full picture (tools, credential exposure) so this leg can be"
                    " resolved instead of left undetermined."
                    if config_blind
                    else "Set tools.fs.workspaceOnly=true, or narrow tools.profile to"
                    " 'minimal' or 'messaging' (or add 'read' to tools.deny), so file"
                    " tools cannot reach credentials outside the workspace."
                    if reach
                    else "Make the credential store readable to this audit (it is"
                    " normally mode 0700 and owned by you) and re-run, so the leg can"
                    " be established rather than left undetermined."
                    if store["incomplete"]
                    else "Check whether config_machine_state['authProfiles.store'] on"
                    " this host holds a real, usable credential (this audit only sees"
                    " its byte length, never its value) and treat this leg as ON if"
                    " it does."
                    if auth_store_present
                    else "Check whether any agent's own auth_profile_store table"
                    " (agents/<agent-id>/agent/openclaw-agent.sqlite) on this host"
                    " holds a real, usable credential (this audit only sees its byte"
                    " length, never its value) and treat this leg as ON if it does."
                    if agent_auth_store_present
                    else "This host has more per-agent databases under"
                    " agents/*/agent/openclaw-agent.sqlite than this scan's cap"
                    " allows, so its per-agent auth-profile store sweep did not cover"
                    " all of them; check the remaining agents' own auth_profile_store"
                    " tables by hand and treat this leg as ON if any hold a real,"
                    " usable credential."
                ),
                evidence=active,
            )

    return _finding(
        "A1", PASS, detail, "Keep it at ≤2 of 3 — do not add the third capability.", evidence=active
    )


def check_trustedproxy_loopback(ctx: Context) -> Finding:
    """B70 — trusted-proxy auth: non-loopback bind without identity constraints, or
    allowLoopback on a non-loopback bind.

    Grounded (dist zod-schema-O9ml_nmo.js / types.openclaw-CXjMEWAQ.d.ts):
    gateway.auth.mode='trusted-proxy', gateway.auth.trustedProxy.{userHeader,
    requiredHeaders,allowUsers,allowLoopback}. Trusted-proxy auth delegates
    authentication to a reverse-proxy-supplied identity header; on a non-loopback bind an
    attacker who can reach the port directly can forge that header unless
    requiredHeaders/allowUsers genuinely constrain it (B-233) — OR (grounded: dist
    auth-B27MflKU.js authorizeTrustedProxy / authorizeGatewayConnectCore, gated by
    net-*.js isTrustedProxyAddress) OpenClaw itself rejects the connection by source IP
    before ever reading the header when a genuine gateway.trustedProxies allow-list is
    configured, so that is an equally valid constraint.

    UNKNOWN — trusted-proxy auth is not configured (auth.mode != 'trusted-proxy' and
              gateway.auth.trustedProxy.allowLoopback is not set).
    FAIL    — auth.mode='trusted-proxy' AND the bind is non-loopback AND none of
              requiredHeaders, allowUsers, or a genuine gateway.trustedProxies allow-list
              is configured — any direct caller can self-declare identity via the
              (spoofable) trusted-proxy header.
    WARN    — gateway.auth.trustedProxy.allowLoopback=true AND the gateway bind is
              non-loopback (a same-host caller can still forge the header).
    PASS    — loopback bind, or requiredHeaders/allowUsers/trustedProxies genuinely
              constrain identity, or trusted-proxy is not configured.
    """
    cfg = ctx.config
    mode = dig(cfg, "gateway.auth.mode")
    allow_loopback = dig(cfg, "gateway.auth.trustedProxy.allowLoopback")
    configured = mode == "trusted-proxy" or allow_loopback is not None
    if not configured:
        return _finding(
            "B70",
            UNKNOWN,
            "gateway.auth.mode is not 'trusted-proxy' and "
            "gateway.auth.trustedProxy.allowLoopback is not set — trusted-proxy auth is "
            "not configured.",
            "If you use a reverse proxy, configure gateway.auth.mode=trusted-proxy "
            "explicitly (with requiredHeaders/allowUsers) and bind the gateway to "
            "loopback.",
            # B-362: sets not_applicable only when the config locus was read COMPLETELY
            # and neither locus is set. Grounded (dist docs/gateway/index.md,
            # configuration-reference.md, onboard.md): "token" is the default auth mode
            # and trusted-proxy delegation is an explicit opt-in
            # (gateway.auth.mode="trusted-proxy") -- with mode not set to it AND
            # allowLoopback unset, the spoofable-header surface this check grades
            # genuinely does not exist, not merely an unassessed risk. Both loci are
            # plain ctx.config reads, so config-locus completeness is the whole proof
            # obligation. (Contrast: this is unlike check_sandbox's "no exec tools"
            # branch, which was left un-converted -- a full/unrestricted tool profile is
            # OpenClaw's own default when tools.profile is unset, so absence there does
            # NOT mean the surface is off.)
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    if mode == "trusted-proxy" and bind_host not in LOOPBACK:
        required_headers = dig(cfg, "gateway.auth.trustedProxy.requiredHeaders")
        allow_users = dig(cfg, "gateway.auth.trustedProxy.allowUsers")
        trusted_proxies_ok = _trusted_proxies_ok(dig(cfg, "gateway.trustedProxies"))
        if not required_headers and not allow_users and not trusted_proxies_ok:
            user_header = dig(cfg, "gateway.auth.trustedProxy.userHeader") or "x-forwarded-user"
            # B-315: was FAIL. B70 belongs to the B68-B73 block, whose catalog comment
            # documents the group as "WARN-only ... zero false-positive FAILs on real
            # configs" — this branch was the sole violator of that documented intent
            # (and this exact loopback/private-network predicate is the one CLAUDE.md
            # §6.1 records as version-dependent across Python 3.9/3.12). An unscored
            # check must not FAIL (Dave's ruling: scored=False caps at WARN); downgrading
            # also restores the block comment's original claim. Same evidence.
            return _finding(
                "B70",
                WARN,
                f"gateway.auth.mode=trusted-proxy is bound to a non-loopback address "
                f"(bind host={bind_host!r}) with no requiredHeaders/allowUsers/"
                f"trustedProxies configured — the {user_header!r} identity header is "
                "attacker-spoofable by any direct caller.",
                "Configure gateway.auth.trustedProxy.requiredHeaders and/or allowUsers, "
                "or gateway.trustedProxies, to constrain identity, or bind the gateway "
                "to loopback (127.0.0.1).",
                evidence=[
                    "gateway.auth.mode=trusted-proxy",
                    f"gateway.bind host={bind_host!r} (non-loopback)",
                    "gateway.auth.trustedProxy.requiredHeaders/allowUsers and "
                    "gateway.trustedProxies not set",
                ],
            )
    if allow_loopback is True and bind_host not in LOOPBACK:
        return _finding(
            "B70",
            WARN,
            "gateway.auth.trustedProxy.allowLoopback is true and the gateway is bound to a "
            "non-loopback address — a header-spoofing attacker can forge the trusted-proxy "
            "header.",
            "Bind the gateway to loopback (127.0.0.1) when using trustedProxy auth, or "
            "disable gateway.auth.trustedProxy.allowLoopback.",
            evidence=[
                "gateway.auth.trustedProxy.allowLoopback=true",
                f"gateway.bind host={bind_host!r} (non-loopback)",
            ],
        )
    return _finding(
        "B70",
        PASS,
        "Trusted-proxy auth is loopback-only, has requiredHeaders/allowUsers/"
        "trustedProxies constraining identity, or is not configured (no header-spoof "
        "risk detected).",
        "Keep gateway.auth.trustedProxy.requiredHeaders/allowUsers and/or "
        "gateway.trustedProxies configured, or bind the gateway to loopback.",
    )


def _parse_bind_port_raw(value) -> "str | None":
    """Extract the raw port SUBSTRING from a gateway.bind value (no range/decimal
    validation), mirroring parse_bind_host's own handling of the bracketed-IPv6 /
    host:port / bare forms (checks/_shared.py).

    Returns None when no port substring is present at all — an empty value, a bare
    address with no port, or a bare (unbracketed) IPv6 literal where "the port" would
    be ambiguous. Splitting this out from :func:`_parse_bind_port` (B-374 follow-up,
    C-135 round 2) lets a caller distinguish "gateway.bind names no port at all" from
    "gateway.bind names a port string that turned out to be invalid" — two different
    UNKNOWN reasons check_effective_bind reports distinctly.
    """
    s = str(value or "").strip()
    if not s:
        return None
    if s.startswith("["):
        end = s.find("]")
        if end != -1 and s[end + 1 :].startswith(":"):
            return s[end + 2 :]
        return None
    if s.count(":") == 1:
        _, _, port_str = s.partition(":")
        return port_str
    return None  # bare wildcard/IPv6 literal with no unambiguous port


def _parse_bind_port(value) -> "int | None":
    """Extract the port from a gateway.bind value as a validated 1-65535 int.

    Returns None when no port can be unambiguously extracted (see
    :func:`_parse_bind_port_raw`), the extracted text is not a plain decimal integer,
    or the value parses but falls outside the valid TCP port range.

    B-374 follow-up (C-135 round 2, 2026-07-31): uses ``str.isdecimal()``, not
    ``str.isdigit()``, before calling ``int()``. A handful of Unicode characters (e.g.
    the superscript ``"²"``) satisfy ``isdigit()`` while still raising ``ValueError``
    out of ``int()`` — the OLD code could crash on a config value shaped like
    ``"8080²"`` instead of degrading to UNKNOWN. ``isdecimal()`` only accepts
    characters ``int()`` can actually parse, so this now never raises. The 1-65535
    range check is new too — the old code accepted any positive int without an upper
    bound. A ``None`` return here never raises — ``check_effective_bind`` falls back
    to ``gateway.port`` next (B-400: including OpenClaw's own grounded default port
    when ``gateway.port`` is itself absent — see ``_DEFAULT_GATEWAY_PORT``), not
    straight to "nothing to look up".
    """
    port_str = _parse_bind_port_raw(value)
    if port_str is None or not port_str.isdecimal():
        return None
    try:
        port = int(port_str)
    except ValueError:  # pragma: no cover - isdecimal() already guards this
        return None
    if not (1 <= port <= 65535):
        return None
    return port


def _declared_bind_class(cfg: dict) -> str:
    """Classify the DECLARED ``gateway.bind`` as ``loopback`` / ``remote`` / ``ambiguous``.

    C-135 finding: a naive ``parse_bind_host(bind) in LOOPBACK`` test (what B2/B70 use
    for their own, different, purpose) is WRONG for two of the current schema's five
    ``gateway.bind`` profiles — ``auto`` resolves to loopback on bare metal but to
    ``0.0.0.0`` inside a container, and ``custom`` resolves through the SEPARATE
    ``gateway.customBindHost`` field, not the profile name itself. Reusing that naive
    test here would misclassify a container's ``bind=auto`` (genuinely, correctly
    ``0.0.0.0``) as "declared loopback", and the moment the effective socket confirms
    the wildcard bind, this check would FAIL a config that is working exactly as
    designed — a textbook false FAIL this module exists to never produce.

    So this reuses ``_gateway_remote_exposure_reason`` (checks/_shared.py) — the
    already-grounded, already-tested resolver RISK-20 relies on for the identical
    per-profile logic (``loopback``/``local``/host:port → the shared ``LOOPBACK``
    predicate; ``lan``/``tailnet`` → always remote; ``custom`` → discriminated by
    ``customBindHost``; Tailscale ``serve``/``funnel`` → always remote regardless of
    bind) — but does NOT stop at its ``Optional[str]`` return. That function
    deliberately collapses two different truths into one ``None``: "provably
    loopback" and "genuinely unprovable from a config file alone" (``auto``; ``custom``
    with no valid ``customBindHost``, which — per that function's own docstring — the
    product refuses to even start with). Corroboration needs the two kept apart:
    treating "unprovable" as "declared loopback" is exactly the false-FAIL risk above,
    so an ambiguous profile is reported as its own bucket instead — an honest UNKNOWN,
    never a guess in either direction.

    C-135 bug 2 (independent review, 2026-07-30): an ABSENT or empty ``gateway.bind``
    is classified the same as ``auto`` — ambiguous — NOT ``loopback``. Grounded against
    the installed dist (``net-BOKtNTf8.js:161-178``, ``defaultGatewayBindMode``): when
    ``gateway.bind`` is unset, the vendor's own effective default is ``loopback`` on
    bare metal but resolves through the SAME container-detecting path as an explicit
    ``auto`` — ``0.0.0.0`` inside a container, "for port-forwarding compatibility", by
    design. That is exactly the ambiguity the ``auto`` branch above exists to never
    guess at, and an absent bind reaches it through an identical vendor code path, not
    a different one — so it gets the identical verdict.
    """
    if _gateway_remote_exposure_reason(cfg) is not None:
        return "remote"
    profile = str(dig(cfg, "gateway.bind", "") or "").strip().lower()
    if profile in ("auto", ""):
        return "ambiguous"
    if profile == "custom" and _canonical_ipv4(dig(cfg, "gateway.customBindHost")) is None:
        return "ambiguous"
    return "loopback"


# B-400 (2026-08-01, independent review): the B-374 classifier below this
# comment (see git history) DID fix the "unresolved identity keeps FAIL" bug (Golden
# Rule #5), but its POSITIVE "gateway" evidence was still a bare, case-insensitive
# substring test -- `"openclaw" in (identity.name + " " + identity.cmdline)` -- over
# the WHOLE joined command line. That credits ANY process whose argv merely mentions
# the word "openclaw" anywhere at all: `ssh -L 8080:localhost:8080
# user@my-openclaw-server` (the hostname), a text editor opened on this very repo's
# path, or a shell script invoked from a directory someone happened to name
# "openclaw" -- none of them are OpenClaw, all of them would have been confidently
# credited as the gateway, turning an unrelated decoy into a scored FAIL.
#
# Replaced with a two-signal classifier that requires the RESOLVED EXECUTABLE PATH
# (`/proc/<pid>/exe`, sockets.ProcessIdentity.exe -- added alongside this fix) to
# clear the candidate first: unlike argv/cmdline, this is a symlink the KERNEL points
# at the inode that was actually `execve()`'d, so nothing in a process's own
# arguments can spoof it.
#
#   1. exe unresolved (permission denied reading another UID's /proc/<pid>/exe is the
#      common, expected case -- sockets.py's own doctrine)  -> "unknown". Never trust
#      name/cmdline text alone when the one unspoofable signal is unavailable -- that
#      would just reintroduce the retired substring bug for exactly the processes it
#      is hardest to positively rule out.
#   2. exe resolves to a binary literally named "openclaw" (a compiled/bundled
#      single-binary install)                                -> "gateway" directly.
#   3. exe resolves to a real script-interpreter binary (node/bun/deno -- what
#      OpenClaw's own `#!/usr/bin/env node` launcher, confirmed against the installed
#      dist's `openclaw.mjs`, actually runs under) -- exe alone can never confirm
#      OpenClaw here, since /proc/<pid>/exe for an INTERPRETED process always names
#      the interpreter, never the invoked script. Fall back to cmdline, but
#      STRUCTURALLY: only a path-shaped token (contains "/") whose own path segments
#      name an OpenClaw install (see _names_openclaw_install) counts -- never a raw
#      substring test over the whole joined line, which is what let a bare hostname
#      argument like "user@my-openclaw-server" or a flag value count as evidence
#      before. Confirms  -> "gateway"; nothing matches -> "unknown" (a real node/bun/
#      deno process that plausibly isn't OpenClaw, but isn't positively ruled out
#      either -- see the module docstring's accepted-FN trade).
#   4. exe resolves to anything else specific and nameable (ssh, a text editor, bash,
#      ...)                                                   -> "foreign". This is
#      the exact defense the retired substring test could never provide: none of
#      these three ticket-cited decoys survive step 4, regardless of what
#      "openclaw"-shaped text appears anywhere in their argv, because their
#      executable is never node/bun/deno/openclaw in the first place.
_INTERPRETER_EXE_BASENAMES = frozenset({"node", "bun", "deno"})


def _names_openclaw_install(path: str) -> bool:
    """True when *path* — a single argv TOKEN already filtered by the caller to look
    like a filesystem path (contains ``/``), never arbitrary free text such as a
    hostname or a flag value — structurally names an OpenClaw install.

    Checked as PATH SEGMENTS (split on ``/``, compared whole, never a substring
    search), so a decoy directory that merely CONTAINS "openclaw" as part of a longer
    name (``/tmp/my-openclaw-notes/script.js``) does NOT match — only an EXACT
    segment does. Three real shapes match, all grounded against this project's own
    installed dist:

    * a segment exactly ``openclaw`` — covers both the standard npm package layout
      (``.../node_modules/openclaw/...``, global or local, any package manager) and a
      direct top-level install directory (``/opt/openclaw/...``);
    * a segment exactly ``.openclaw`` — the state/install directory convention
      (``~/.openclaw/dist/cli.js``, this machine's own live shape);
    * the final segment (basename) IS the real entry point itself — ``openclaw`` (the
      installed ``bin/openclaw`` symlink's own name, confirmed by actually invoking a
      shebang-symlinked launcher and inspecting its resulting ``argv`` — see this
      task's C-135 notes) or ``openclaw.mjs`` (the resolved package script,
      ``~/.npm-global/lib/node_modules/openclaw/openclaw.mjs`` on this machine).

    Deliberately NOT a bare substring test over the whole path or the whole cmdline —
    see the block comment above :func:`_classify_listener_identity` for exactly why
    that was the bug this replaces (B-400).
    """
    segments = [s for s in path.replace("\\", "/").lower().split("/") if s]
    if not segments:
        return False
    if "openclaw" in segments or ".openclaw" in segments:
        return True
    return segments[-1] in ("openclaw", "openclaw.mjs")


def _classify_listener_identity(identity: "object | None") -> str:
    """Classify a resolved ``sockets.ProcessIdentity`` (or ``None`` -- unresolved) for
    one non-loopback listener as ``"gateway"`` | ``"foreign"`` | ``"unknown"``.

    ``"gateway"``  -- positive evidence: the resolved executable IS OpenClaw (a
                      binary literally named ``openclaw``), or is a real
                      node/bun/deno interpreter AND the invoked script's path
                      structurally names an OpenClaw install
                      (:func:`_names_openclaw_install`).
    ``"foreign"``  -- positive evidence of the opposite: the resolved executable is a
                      specific, nameable binary that is neither OpenClaw itself nor a
                      script-interpreter that could plausibly be running it (e.g.
                      ``ssh``, a text editor, ``bash`` -- or Docker's userland proxy
                      sharing the port number).
    ``"unknown"``  -- no identity evidence either way: the inode could not be
                      resolved to any process at all (permission denied reading
                      another user's ``/proc``, no inode recorded, the process
                      vanished, multiple PIDs disagreed on a name), the resolved
                      process's ``/proc/<pid>/exe`` itself could not be read (equally
                      common, equally expected -- never silently fall back to
                      trusting argv/cmdline text alone when this happens), or the
                      executable IS a real interpreter but nothing in its command
                      line structurally names an OpenClaw install.
    """
    if identity is None:
        return "unknown"
    exe = getattr(identity, "exe", "") or ""
    if not exe:
        return "unknown"
    exe_basename = exe.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if exe_basename == "openclaw":
        return "gateway"
    if exe_basename in _INTERPRETER_EXE_BASENAMES:
        cmdline = getattr(identity, "cmdline", "") or ""
        for token in cmdline.split():
            if "/" in token and _names_openclaw_install(token):
                return "gateway"
        return "unknown"
    return "foreign"


# B-400 (2026-08-01): OpenClaw's OWN documented/grounded default gateway
# port, used when gateway.port is genuinely ABSENT from the config (never when it is
# present but malformed -- see the port-resolution block in check_effective_bind for
# that distinction). Ground truth is the installed dist's own resolver, not a guess:
# `paths-BMBAvkNf.js:193` -- `const DEFAULT_GATEWAY_PORT = 18789;` -- and
# `paths-BMBAvkNf.js:230-238`'s `resolveGatewayPort(cfg, env)`, which checks
# `OPENCLAW_GATEWAY_PORT` first, then `cfg?.gateway?.port` (if a positive finite
# number), and ONLY THEN falls back to this exact constant -- the identical
# precedence this check now mirrors for the config-only signal it can see. Also
# documented in the public dist's own `.d.ts`: `types.openclaw-CXjMEWAQ.d.ts:1224`,
# "Single multiplexed port for Gateway WS + HTTP (default: 18789)." Manifest entry:
# `gateway.port` (already grounded in tests/grounded_schema_paths.txt; this constant
# is the DEFAULT VALUE for that same field, additionally grounded in
# docs/research/openclaw-schema-recon.md's `gateway.port` entry).
#
# Before this fix, an absent gateway.port made check_effective_bind report UNKNOWN
# ("nothing to look up") even when a real, world-open listener sat on OpenClaw's own
# real default port -- a genuine coverage blind spot, not a false FAIL: the single
# most common real config shape (gateway.port simply never set, which is valid and
# common since the field is `.optional()`) got NO runtime corroboration at all.
_DEFAULT_GATEWAY_PORT = 18789


def check_effective_bind(ctx: Context) -> Finding:
    """B340 (F-156): corroborate the DECLARED ``gateway.bind`` against the ACTUAL
    listening socket, read from ``/proc/net/tcp{,6}`` (see ``sockets.py``).

    Every other gateway-exposure verdict (B2, B70) is declared-state only — it reads
    ``gateway.bind`` and reasons about that string. It never checks what the process is
    actually listening on, which is a real blind spot in both directions: a config that
    says loopback while an env override/wrapper/reverse-proxy actually exposes the port
    (false PASS elsewhere), or a config that says wide-open while the gateway is not
    even running (false FAIL elsewhere). This check adds the one runtime signal that
    closes that gap.

    Route decision (recorded per the task DoD): **no subprocess** — ``sockets.py``
    reads ``/proc/net/tcp{,6}`` directly, matching ``hostwatch.py``'s "no subprocess, no
    network" doctrine rather than ``native.py``'s guarded-subprocess precedent. Read-only,
    stdlib-only, and — because it parses the fixed ``local_address`` column instead of
    regexing a whole ``ss``/``netstat`` line — structurally immune to the peer-column bug
    a competitor tool shipped (see ``sockets.py``'s module docstring).

    Matching a listener to the declared port is still by PORT NUMBER first — that part
    of the original design is unchanged. C-135 bug 1 (independent review, 2026-07-30,
    live-reproduced on the reviewer's own machine against ``fixtures/home_safe`` —
    Docker's userland proxy sharing port 8080 with a correctly loopback-only declared
    gateway) showed that port-number-alone matching has a real false-positive-FAIL
    mode, so this adds the ``/proc/*/fd`` PID correlation the original design had
    scoped out as unneeded: when the declared-loopback/effective-non-loopback
    condition is reached, every non-loopback listener's owning process is resolved
    from its socket inode (``sockets.identify_listener_process``, one ``/proc`` walk
    shared across all of them via ``sockets.build_inode_index``) and classified by
    :func:`_classify_listener_identity`.

    B-374 (C-135 round 2, 2026-07-31) REPLACED the original one-sided calibration.
    The original fix could only ever DOWNGRADE FAIL to WARN, and only on POSITIVE
    evidence the listener was something else — any unresolved identity (permission
    denied, no matching inode, disagreeing names) kept the FAIL, which is itself an
    unproven guess in the FAIL direction (Golden Rule #5 forbids exactly this). Now:
    the verdict stays FAIL ONLY when at least one non-loopback listener is POSITIVELY
    confirmed to be the gateway itself — see :func:`_classify_listener_identity`; the
    moment NONE of them can be so confirmed — whether because they positively resolve
    to something else (Docker's userland proxy) or because identity resolution is
    inconclusive (permission denied is the common case) — this reports UNKNOWN instead
    of FAIL. This is a deliberate, accepted false-negative trade: a real lying gateway
    whose ``/proc/<pid>/fd`` this reader cannot read now also reads UNKNOWN, not FAIL.
    B2/B70 still assess the DECLARED posture regardless, so the config's own stated
    exposure is never hidden — only THIS check's runtime corroboration backs off. Every
    existing synthetic ``Context`` the test suite injects with no inode data at all
    now resolves to UNKNOWN in this branch (not "keep FAIL" as before) — see
    ``tests/test_b340_effective_bind.py``.

    B-400 (2026-08-01, independent review) tightened WHAT counts as
    "positively confirmed" again: B-374's own positive-evidence signal was still a
    bare substring test for ``"openclaw"`` over the whole joined ``comm``/``cmdline``
    text, which credits any decoy that merely MENTIONS the word anywhere in its argv
    (an SSH tunnel to a host named ``...openclaw...``, a text editor with this repo's
    path open, a shell script run from a directory literally named ``openclaw``) as
    the gateway itself. :func:`_classify_listener_identity` now requires the
    KERNEL-RESOLVED executable path (``/proc/<pid>/exe``, ``sockets.ProcessIdentity.
    exe`` — unlike argv, not something a process's own arguments can spoof) to name a
    real script interpreter or OpenClaw itself before cmdline is even consulted, and
    even then only a PATH-SHAPED, PATH-SEGMENT match counts, never a raw substring
    over free text. See that function's own docstring for the full four-way
    breakdown, and ``tests/test_b340_effective_bind.py``'s decoy-process tests
    (SSH tunnel, text editor, shell script from an ``openclaw``-named directory) for
    the exact shapes this now clears that the old substring test did not.

    Scoring (B-387, C-135 round 2, 2026-07-31): every PASS and WARN branch below
    passes ``scored=False`` explicitly — B340 can never EARN a scored point, only ever
    COST one via the single FAIL branch (which stays scored, HIGH-capped at 79). Before
    this, a declared-remote config whose effective bind also read non-loopback (the
    "already assessed by B2/B70" PASS below) scored a full-weight PASS — so WIDENING
    ``gateway.bind`` from loopback to remote could swap a capped FAIL (a correctly
    -declared config hitting an attribution edge case) for a full-weight PASS, i.e. a
    LESS secure declaration scoring BETTER on this one check. Making every non-FAIL
    branch unscored closes that inversion structurally: widening the declared/actual
    exposure can only ever move this check from "scores a capped FAIL" to "scores
    nothing", never to "scores a PASS" — see ``tests/test_b340_effective_bind.py``'s
    monotonicity test.

    Fully enumerated verdict table (``declared`` = ``_declared_bind_class``, which
    resolves the FULL 5-profile ``gateway.bind`` enum — not a naive ``LOOPBACK``
    membership test, see its own docstring for why that would false-FAIL a container's
    ``bind=auto``; ``effective`` = every listener found on the declared port, ALL
    loopback or not — a dual-stack 127.0.0.1 + [::1] pair on the same port is ONE
    effective state, not two findings):

        declared      | effective         | verdict
        --------------+-------------------+----------------------------------------
        loopback      | loopback          | PASS (unscored) — corroborates B2
        loopback      | not loopback,      | FAIL (scored) — at least one non-loopback
                      | >=1 confirmed      |   listener positively confirmed as the
                      | gateway            |   gateway itself; the config lies
        loopback      | not loopback,      | UNKNOWN — no non-loopback listener could be
                      | none confirmed     |   positively tied to the gateway process
                      | gateway            |   (foreign process, or unresolvable)
        remote        | loopback           | WARN (unscored) — config is dangerous but
                      |                    |   not currently exposed
        remote        | not loopback       | PASS (unscored) — declared exposure is
                      |                    |   real; B2/B70 already assess it
        ambiguous     | (any)              | UNKNOWN — profile (auto / custom w/o a
                      |                    |   valid customBindHost) is not resolvable
                      |                    |   from the config alone; corroborating it
                      |                    |   either way would be a guess
        (any)         | no listener found  | UNKNOWN — gateway not running, nothing measured
                      |                    |   (checked against the resolved port, which may
                      |                    |   be OpenClaw's own default — see "Port source")
        (any)         | /proc unavailable  | UNKNOWN — platform not supported, or scan not run
        (any)         | gateway.port       | UNKNOWN — gateway.bind embeds no port AND
                      | present, malformed |   gateway.port is present but not a valid
                      |                    |   1-65535 port (a real config error — never
                      |                    |   silently defaulted, see "Port source")
        (any)         | port out of range  | UNKNOWN — gateway.bind names an embedded port
                      |                    |   that is out of 1-65535 range

    Port source (C-135 finding, fixed before this shipped; B-400 extended
    it): this package's whole existing gateway-check family (B2, B70) reads
    ``gateway.bind`` as a ``host:port`` string via ``parse_bind_host`` — the shape every
    fixture in this repo uses. But the CURRENT installed OpenClaw schema (grounded
    directly against the dist, since the recon doc does not cover this:
    ``zod-schema-O9ml_nmo.js``, the ``gateway: object({ port:
    number().int().positive().optional(), mode: union([literal("local"),
    literal("remote")]).optional(), bind: union([literal("auto"), literal("lan"),
    literal("loopback"), literal("custom"), literal("tailnet")]).optional(),
    customBindHost: string().optional(), ... })`` block) makes ``gateway.bind`` a
    5-value MODE enum with no embedded port at all — confirmed against this machine's
    own live ``~/.openclaw/openclaw.json`` (``"bind": "loopback", "port": 18789``,
    sibling fields). Reading only an embedded port would make this check report UNKNOWN
    on every config shaped this way — a real coverage gap on the exact real-fleet
    config available for this check's own C-135 pass, not a false FAIL, but real
    enough that it defeats the check's purpose. So the port is resolved, in order: (1)
    an embedded ``host:port`` in ``gateway.bind`` (the fixture/legacy shape); (2) the
    sibling ``gateway.port`` (grounded above; manifest entry in
    ``tests/grounded_schema_paths.txt``) when ``gateway.bind`` is a bare mode string
    and ``gateway.port`` IS present and a valid 1-65535 int; (3) — B-400 —
    OpenClaw's own grounded default, :data:`_DEFAULT_GATEWAY_PORT` (18789), when
    ``gateway.port`` is genuinely ABSENT (the single most common real shape, since the
    field is ``.optional()``): before this, an absent ``gateway.port`` made this check
    report UNKNOWN ("nothing to look up") even against a real, world-open listener on
    OpenClaw's own real default port — a coverage blind spot, not a false FAIL, but one
    that defeated corroboration on the most common config shape. A ``gateway.port`` that
    IS present but not a valid port (a string, an out-of-range int, ...) is a genuine
    config error and is never silently treated as "absent" — it stays its own distinct
    UNKNOWN (see the port-resolution block below), never masked by the default.
    """
    cfg = ctx.config
    if not cfg:
        return _finding(
            "B340",
            UNKNOWN,
            "No config loaded — cannot corroborate gateway.bind against the actual "
            "listening socket.",
            "Run on the host with ~/.openclaw present.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    gw_present = isinstance(cfg, dict) and "gateway" in cfg
    gw = cfg.get("gateway") if gw_present else None
    if gw_present and not isinstance(gw, dict):
        return _finding(
            "B340",
            UNKNOWN,
            "gateway config value is present but malformed (not an object) — cannot "
            "corroborate it against the actual listening socket.",
            "Fix `gateway` to be a config object, or remove the key.",
        )

    bind_raw = dig(cfg, "gateway.bind", "")
    declared_class = _declared_bind_class(cfg)
    if declared_class == "ambiguous":
        return _finding(
            "B340",
            UNKNOWN,
            f"gateway.bind={bind_raw!r} is a profile whose actual bind cannot be "
            "determined from the config alone ('auto' resolves differently inside a "
            "container vs. bare metal; a 'custom' profile with no valid "
            "gateway.customBindHost cannot even start) — nothing to corroborate.",
            "Set gateway.bind to an explicit profile ('loopback'/'lan'/'tailnet'), or "
            "give a 'custom' profile a valid gateway.customBindHost, so this check can "
            "state what is actually declared.",
        )
    declared_loopback = declared_class == "loopback"
    # Port source, in order: an embedded host:port in gateway.bind (the shape every
    # fixture in this repo uses), falling back to the sibling gateway.port (the shape
    # the CURRENT OpenClaw schema actually uses when gateway.bind is a bare mode
    # string — see the docstring's "Port source" note; grounded against the dist,
    # manifest entry in tests/grounded_schema_paths.txt).
    bind_port_raw = _parse_bind_port_raw(bind_raw)
    port = _parse_bind_port(bind_raw)
    if port is None and bind_port_raw is not None:
        # B-374 follow-up (C-135 round 2): gateway.bind DID name a port substring, but
        # it is not a valid 1-65535 decimal port -- a distinct UNKNOWN from "no port
        # declared at all" below (never "gateway is not running").
        return _finding(
            "B340",
            UNKNOWN,
            f"gateway.bind={bind_raw!r} names a port ({bind_port_raw!r}) that is not a "
            "valid TCP port (1-65535) — cannot look up which listening socket to "
            "corroborate it against.",
            "Set gateway.bind to a valid host:port (port 1-65535), or set gateway.port "
            "to a valid port, so this check can corroborate it against the actual "
            "listening socket.",
        )
    used_default_port = False
    if port is None:
        gw_port = dig(cfg, "gateway.port")
        if gw_port is None:
            # B-400: genuinely ABSENT (the key is missing, or explicitly
            # null) -- gateway.port is `.optional()` in the real schema, and this is
            # by far the most common real-config shape for it. Fall back to OpenClaw's
            # own grounded default (_DEFAULT_GATEWAY_PORT) instead of reporting
            # UNKNOWN outright, mirroring the vendor's own resolveGatewayPort()
            # precedence. Never applies when gateway.port IS present but malformed --
            # see the `else` branch below, which stays a distinct UNKNOWN.
            port = _DEFAULT_GATEWAY_PORT
            used_default_port = True
        elif isinstance(gw_port, int) and not isinstance(gw_port, bool):
            if 1 <= gw_port <= 65535:
                port = gw_port
            else:
                # Same distinction as above, sourced from gateway.port instead.
                return _finding(
                    "B340",
                    UNKNOWN,
                    f"gateway.port={gw_port!r} is not a valid TCP port (1-65535) — "
                    f"cannot look up which listening socket to corroborate "
                    f"gateway.bind={bind_raw!r} against.",
                    "Set gateway.port to a valid port (1-65535) so this check can "
                    "corroborate the declared bind against the actual listening "
                    "socket.",
                )
        else:
            # Present, but not a number at all (a string, list, dict, ...) -- a real
            # config error. Never silently treated the same as "absent -> use the
            # grounded default"; that would mask a genuine misconfiguration instead of
            # surfacing it.
            return _finding(
                "B340",
                UNKNOWN,
                f"gateway.port={gw_port!r} is not a valid TCP port (1-65535) — "
                f"cannot look up which listening socket to corroborate "
                f"gateway.bind={bind_raw!r} against.",
                "Set gateway.port to a valid port (1-65535) so this check can "
                "corroborate the declared bind against the actual listening "
                "socket.",
            )

    sockets_result = getattr(ctx, "sockets", None)
    if sockets_result is None:
        return _finding(
            "B340",
            UNKNOWN,
            "The effective-bind socket scan was not run (audit(include_sockets=True), "
            "or the CLI's --no-sockets was passed) — cannot corroborate gateway.bind "
            "against reality.",
            "Run the full CLI audit (omit --no-sockets) so this check can read "
            "/proc/net/tcp{,6} and corroborate the declared bind.",
        )
    if not sockets_result.available:
        return _finding(
            "B340",
            UNKNOWN,
            f"Could not read the host's listening-socket table: {sockets_result.reason}.",
            "Run ClawSecCheck on Linux with /proc mounted (the standard case) so this "
            "check can corroborate the declared bind against reality.",
        )

    port_source = (
        f"gateway.port unset — falling back to OpenClaw's own default port {port}"
        if used_default_port
        else f"the port gateway.bind={bind_raw!r} declares"
    )
    matches = _sockets.listeners_for_port(sockets_result, port)
    if not matches:
        return _finding(
            "B340",
            UNKNOWN,
            f"Nothing is listening on port {port} ({port_source}) — the gateway is not "
            "running, or is listening elsewhere; nothing to corroborate.",
            "Start the gateway and re-run the audit so this check can corroborate "
            "gateway.bind against the actual listening socket.",
        )

    classes = {_sockets.classify_host(m.host) for m in matches}
    effective_loopback = classes <= {"loopback"}
    evidence = [
        f"gateway.bind={bind_raw!r} (declared class={declared_class!r})",
        "effective listener(s): "
        + ", ".join(f"{m.host}:{m.port} ({_sockets.classify_host(m.host)})" for m in matches),
    ]
    if used_default_port:
        evidence.append(
            f"gateway.port was not set in config — corroborated against OpenClaw's "
            f"own grounded default port {_DEFAULT_GATEWAY_PORT}, not a value read "
            "from this config"
        )

    if declared_loopback and not effective_loopback:
        non_loopback = [m for m in matches if _sockets.classify_host(m.host) != "loopback"]
        proc_root = getattr(ctx, "proc_root", None) or "/proc"
        # One /proc walk serves every non-loopback listener on this port (B-374
        # follow-up) instead of re-scanning /proc/*/fd once per listener.
        inode_index = _sockets.build_inode_index(proc_root=proc_root)
        identities = [
            _sockets.identify_listener_process(
                getattr(m, "inode", ""), proc_root=proc_root, index=inode_index
            )
            for m in non_loopback
        ]
        confirmed_gateway = [
            m
            for m, ident in zip(non_loopback, identities)
            if _classify_listener_identity(ident) == "gateway"
        ]
        if not confirmed_gateway:
            # B-374: NONE of the non-loopback listeners on this port could be
            # POSITIVELY tied to the OpenClaw gateway process itself -- a foreign
            # process sharing the port number (Docker's userland proxy is the
            # live-reproduced example), or an identity this reader has no
            # permission/evidence to resolve either way (permission denied reading
            # another user's /proc is the normal case). Keeping FAIL here -- as the
            # original C-135 bug-1 fix did -- is itself an unproven guess in the FAIL
            # direction, which Golden Rule #5 forbids. Report UNKNOWN instead; this is
            # a deliberate, accepted false-negative trade (see the function
            # docstring): B2/B70 still assess the DECLARED posture regardless.
            reasons = []
            for m, ident in zip(non_loopback, identities):
                if ident is None:
                    reasons.append(f"{m.host}:{m.port} — process identity unresolvable")
                else:
                    reasons.append(
                        f"{m.host}:{m.port} held by pid {ident.pid} ({ident.name}) — "
                        "not identifiable as the OpenClaw gateway"
                    )
            return _finding(
                "B340",
                UNKNOWN,
                f"gateway.bind={bind_raw!r} declares a loopback bind, and a non-loopback "
                f"listener was found on port {port}, but it could not be positively tied "
                "to the OpenClaw gateway process itself: " + "; ".join(reasons) + ". This "
                "could be gateway.bind lying (env override/launch wrapper/reverse proxy), "
                "or an unrelated process coincidentally sharing the port number — not "
                "distinguishable from a config file and a /proc read alone.",
                f"Confirm what is actually listening on port {port} (e.g. `lsof -i "
                f":{port}` or `ss -tlnp` as root) to determine whether gateway.bind is "
                "being honored, then re-run this audit.",
                evidence=evidence + reasons,
            )
        return _finding(
            "B340",
            FAIL,
            f"gateway.bind={bind_raw!r} declares a loopback bind, but the gateway is "
            f"ACTUALLY listening on a non-loopback address on port {port} — the config "
            "lies and the port is reachable from the network (env override, launch "
            "wrapper, or a reverse proxy re-publishing it).",
            "Find why the running gateway does not match the declared bind (an "
            "env-var override or launch wrapper is the usual cause) and align it with "
            "gateway.bind, or update gateway.bind to state reality.",
            evidence=evidence
            + [
                f"{m.host}:{m.port} confirmed via pid {ident.pid} ({ident.name})"
                for m, ident in zip(non_loopback, identities)
                if _classify_listener_identity(ident) == "gateway"
            ],
            scored=True,
        )
    if not declared_loopback and effective_loopback:
        # B-374 follow-up (item 4): when the DECLARED-remote classification actually
        # comes from Tailscale serve/funnel (which requires a loopback gateway.bind —
        # see _gateway_remote_exposure_reason's docstring), name that reason instead
        # of telling the owner to "set gateway.bind to loopback" when it may already
        # BE loopback and Tailscale's own relay path is what exposes it.
        exposure_reason = _gateway_remote_exposure_reason(cfg)
        if exposure_reason is not None and exposure_reason.startswith("gateway.tailscale.mode="):
            detail = (
                f"{exposure_reason} publishes the gateway externally regardless of "
                f"gateway.bind={bind_raw!r} — the gateway is currently only listening "
                f"loopback-only on port {port} on this host, but Tailscale's own "
                "serve/funnel relay is what actually exposes it, not this machine's "
                "socket."
            )
            fix = (
                "Confirm the Tailscale serve/funnel exposure is intentional — it "
                "publishes the gateway regardless of gateway.bind. Disable "
                "gateway.tailscale.mode if that is not intended."
            )
        else:
            detail = (
                f"gateway.bind={bind_raw!r} declares a non-loopback bind, but the "
                f"gateway is currently only listening on loopback on port {port} — the "
                "config is dangerous even though nothing is exposed right now."
            )
            fix = (
                "Set gateway.bind to loopback (127.0.0.1) so the declared and actual "
                "posture match, or confirm the non-loopback bind is intentional before "
                "it takes effect."
            )
        return _finding(
            "B340",
            WARN,
            detail,
            fix,
            evidence=evidence,
            scored=False,
        )
    if declared_loopback:
        return _finding(
            "B340",
            PASS,
            f"gateway.bind={bind_raw!r} is loopback and the gateway is ACTUALLY "
            f"listening loopback-only on port {port} (corroborates B2).",
            "Keep gateway.bind loopback and re-run this corroboration after any config "
            "or deployment change.",
            evidence=evidence,
            scored=False,
        )
    return _finding(
        "B340",
        PASS,
        f"gateway.bind={bind_raw!r} declares a non-loopback bind and the gateway is "
        f"ACTUALLY listening non-loopback on port {port} — the declared exposure is "
        "real, and already assessed by B2/B70.",
        "See B2/B70 for the auth/exposure posture of this bind.",
        evidence=evidence,
        scored=False,
    )


# B384/B385 (F-197): desktop.host is a SECOND network listener beside the gateway -- a
# VNC/RFB service (default port 5900) that desktop.host.enabled opts into, plus an
# absolute path to a VNC password file. Grounded against the installed OpenClaw 2026.9.5
# dist (zod-schema-DN2u5FdA.mjs, src/config/zod-schema.desktop.ts + host-source-
# v64nW4u1.mjs, src/gateway/desktop/{host-source,managed-linux}.ts). Before this, nothing
# read `desktop.{enabled,port,managed,passwordFile}` at all (re-verified 2026-09-16: grep
# -rn "desktop" clawseccheck/checks/*.py clawseccheck/*.py finds only unrelated prose in
# pdf.py/logscan.py).
#
# RE-GROUNDING CORRECTION vs. the task's own framing: the tracker entry assumed a
# `desktop.host` HOST-RESTRICTION field analogous to `gateway.bind`, so a config could
# "declare" a non-loopback bind. The real schema has no such field -- OpenClaw's own
# managed desktop is unconditionally launched `-localhost yes` (buildTigerVncArgv,
# host-source-v64nW4u1.mjs), and OpenClaw's own probe of the desktop connects only to
# `127.0.0.1:port` (inspectHostDesktop, same file). There is nothing here for an operator
# to widen. The real gap is corroborative, same spirit as B340: does reality match that
# always-loopback assumption? Two ways it would not: (1) a bug/version skew in the
# vendor's own `-localhost yes` enforcement for a MANAGED desktop -- checkable, because
# the managed child process has one grounded, fixed name, `Xtigervnc`
# (spawnRun("Xtigervnc", ...), same file); (2) an UNMANAGED desktop.host, which connects
# to "an already-running VNC server" the operator set up entirely outside OpenClaw --
# nothing in OpenClaw enforces loopback for that at all, so an operator who left it
# reachable is a real, live gap this closes.
#
# B384 FAILs only when BOTH hold: (a) desktop.host.managed is true, AND (b) a
# non-loopback listener on the resolved port is POSITIVELY confirmed (the same
# /proc/*/fd inode -> kernel-resolved-exe correlation B340 uses, see
# _classify_desktop_listener_identity) to run the exact binary OpenClaw's managed-desktop
# supervisor spawns -- an exact /proc/<pid>/exe basename match, never a substring/comm
# guess (comm is attacker-settable and truncates at 15 chars). Everything else --
# unmanaged, unconfirmed, or both -- WARNs instead (scored=False).
#
# C-135 FALSE-POSITIVE FOUND AND FIXED (2026-09-20): the first cut FAILed on identity
# match alone, without checking `managed`. `Xtigervnc` is not an OpenClaw-exclusive
# binary name -- it is the literal binary Debian/Ubuntu's `tigervnc-standalone-server`
# package installs at /usr/bin/Xtigervnc, and what `vncserver`/`tigervncserver` spawn --
# i.e. the natural choice for exactly the UNMANAGED use case bullet (2) above describes
# (operator's own, pre-existing, intentionally-non-loopback VNC server for LAN access,
# gated by VNC password auth). A config with `managed` false/absent and a real
# `/usr/bin/Xtigervnc` listener bound non-loopback -- benign and disclosed by name in
# bullet (2) -- reproducibly FAILed and told the operator to "disable
# desktop.host.managed" even though it was never true. Binary-name identity proves the
# process runs TigerVNC; it does NOT prove OpenClaw is the one supervising it, so FAIL
# additionally requires the config's own `managed` flag. The same port-number-alone
# match that C-135 caught as a false-FAIL risk for B340 (Docker's userland proxy sharing
# 8080) applies here just as much, and there is no reliable positive-identity signal for
# an arbitrary THIRD-PARTY VNC server (Golden Rule #4 forbids inventing one) -- so the
# unmanaged-but-confirmed-vnc shape WARNs, disclosing the ambiguity by name, rather than
# FAILing on a guess. This is a deliberate, disclosed accepted-uncertainty trade for the
# C-135 reviewer, not a guess dressed up as a FAIL.
#
# B385 is the simpler, unambiguous sibling: desktop.host.passwordFile is the SOLE
# credential TigerVNC's `-SecurityTypes VncAuth -PasswordFile` uses (buildTigerVncArgv);
# its DES-based obfuscation is not a real secret boundary once the file itself is
# readable, so this is an ordinary at-rest-credential-file permission check, same idiom
# as B182/B193 (`_file_readable_by_others`, which never counts a user-private group as an
# exposure, per B-127). The file's CONTENT is never read (only its existence and mode
# bits, per §8).
_DESKTOP_DEFAULT_VNC_PORT = 5900  # grounded: DEFAULT_HOST_DESKTOP_PORT, host-source-v64nW4u1.mjs


def _classify_desktop_listener_identity(identity: "object | None") -> str:
    """Classify a resolved ``sockets.ProcessIdentity`` (or ``None``) for B384.

    "vnc"        -- the KERNEL-RESOLVED /proc/<pid>/exe basename is exactly "Xtigervnc",
                    the literal binary name OpenClaw's managed-desktop supervisor spawns
                    (buildTigerVncArgv, host-source-v64nW4u1.mjs) -- positively OpenClaw's
                    own managed VNC child.
    "other"      -- exe resolved to a different binary: a positively-identified process
                    that is NOT OpenClaw's managed desktop (an unrelated program, or a
                    third-party VNC server the operator runs unmanaged).
    "unresolved" -- identity is None, or exe could not be read (permission denied reading
                    another UID's /proc/<pid>/exe is the common, expected case). Never
                    trusts `name`/`comm` alone: comm is attacker-settable and truncates at
                    15 chars -- same doctrine as `_classify_listener_identity` above.
    """
    if identity is None or not getattr(identity, "exe", ""):
        return "unresolved"
    if Path(identity.exe).name == "Xtigervnc":
        return "vnc"
    return "other"


def check_desktop_host_exposure(ctx: Context) -> Finding:
    """B384 (F-197): corroborate desktop.host's always-loopback design assumption
    against the actual listening socket on its resolved port. See the module comment
    above for the full grounding and severity rationale.

    PASS    -- desktop.host is absent, not enabled, or enabled and every listener found
               on the resolved port is loopback-only (matches the vendor's own design).
    WARN    -- enabled, and a non-loopback listener was found on the resolved port, but
               either it could not be positively tied to the Xtigervnc binary, or it
               was, but desktop.host.managed is not true so OpenClaw cannot be
               positively identified as the one supervising it (an operator's own,
               separately-run TigerVNC server matches the same binary name).
               scored=False (an unproven guess in the FAIL direction, Golden Rule #5).
    FAIL    -- enabled, desktop.host.managed is true, AND a non-loopback listener on the
               resolved port is POSITIVELY confirmed to run the Xtigervnc binary --
               the vendor's own `-localhost yes` enforcement did not hold for OpenClaw's
               own managed desktop.
    UNKNOWN -- no config, malformed desktop.host, an invalid desktop.host.port, the
               socket scan was not run / unavailable, or nothing is listening on the
               resolved port yet (Labs feature enabled but the gateway not restarted).
    """
    cfg = ctx.config
    if not cfg:
        return _finding(
            "B384",
            UNKNOWN,
            "No config loaded — cannot assess desktop.host's network exposure.",
            "Run on the host with ~/.openclaw present.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    desktop = dig(cfg, "desktop.host")
    if desktop is None:
        return _finding(
            "B384",
            PASS,
            "desktop.host is not configured — the experimental gateway-host desktop "
            "source (a second, VNC/RFB network listener beside the gateway) is off by "
            "default and absent here.",
            "No action needed unless you intend to use the Desktop lab feature.",
        )
    if not isinstance(desktop, dict):
        return _finding(
            "B384",
            UNKNOWN,
            "desktop.host is present but malformed (not an object) — cannot assess its "
            "network exposure.",
            "Fix `desktop.host` to be a config object, or remove the key.",
        )
    if desktop.get("enabled") is not True:
        return _finding(
            "B384",
            PASS,
            "desktop.host.enabled is not true — the gateway-host VNC/RFB desktop source "
            "is off.",
            "No action needed unless you intend to use the Desktop lab feature.",
        )

    port_raw = desktop.get("port")
    if port_raw is None:
        port = _DESKTOP_DEFAULT_VNC_PORT
        used_default_port = True
    elif (
        isinstance(port_raw, int)
        and not isinstance(port_raw, bool)
        and 1 <= port_raw <= 65535
    ):
        port = port_raw
        used_default_port = False
    else:
        return _finding(
            "B384",
            UNKNOWN,
            f"desktop.host.port={port_raw!r} is not a valid TCP port (1-65535) — cannot "
            "look up which listening socket to corroborate.",
            "Set desktop.host.port to a valid port (1-65535), or remove it to use "
            f"OpenClaw's own default ({_DESKTOP_DEFAULT_VNC_PORT}).",
        )

    sockets_result = getattr(ctx, "sockets", None)
    if sockets_result is None:
        return _finding(
            "B384",
            UNKNOWN,
            "The listening-socket scan was not run (audit(include_sockets=True), or the "
            "CLI's --no-sockets was passed) — cannot corroborate desktop.host against "
            "reality.",
            "Run the full CLI audit (omit --no-sockets) so this check can read "
            "/proc/net/tcp{,6} and corroborate desktop.host's exposure.",
        )
    if not sockets_result.available:
        return _finding(
            "B384",
            UNKNOWN,
            f"Could not read the host's listening-socket table: {sockets_result.reason}.",
            "Run ClawSecCheck on Linux with /proc mounted (the standard case) so this "
            "check can corroborate desktop.host's exposure against reality.",
        )

    port_source = (
        f"OpenClaw's own default VNC port {port}"
        if used_default_port
        else f"the configured desktop.host.port {port}"
    )
    matches = _sockets.listeners_for_port(sockets_result, port)
    managed = desktop.get("managed") is True
    if not matches:
        return _finding(
            "B384",
            UNKNOWN,
            f"desktop.host.enabled is true, but nothing is listening on port {port} "
            f"({port_source}) yet — the Labs feature needs a gateway restart after "
            "being enabled, or the desktop has not started.",
            "Restart the gateway and re-run the audit so this check can corroborate the "
            "listener.",
        )

    classes = {_sockets.classify_host(m.host) for m in matches}
    evidence = [
        f"desktop.host.enabled=true, managed={managed!r}, resolved port {port} "
        f"({port_source})",
        "effective listener(s): "
        + ", ".join(f"{m.host}:{m.port} ({_sockets.classify_host(m.host)})" for m in matches),
    ]
    if classes <= {"loopback"}:
        return _finding(
            "B384",
            PASS,
            f"desktop.host is enabled and the actual listener on port {port} is "
            "loopback-only, matching OpenClaw's own design (a managed desktop is always "
            "launched with `-localhost yes`; an unmanaged one is expected to be a "
            "loopback-only VNC server too).",
            "Keep it loopback-only.",
            evidence=evidence,
        )

    non_loopback = [m for m in matches if _sockets.classify_host(m.host) != "loopback"]
    proc_root = getattr(ctx, "proc_root", None) or "/proc"
    inode_index = _sockets.build_inode_index(proc_root=proc_root)
    identities = [
        _sockets.identify_listener_process(
            getattr(m, "inode", ""), proc_root=proc_root, index=inode_index
        )
        for m in non_loopback
    ]
    confirmed_vnc = [
        m
        for m, ident in zip(non_loopback, identities)
        if _classify_desktop_listener_identity(ident) == "vnc"
    ]
    # FAIL requires BOTH: the binary is positively Xtigervnc, AND the config itself says
    # OpenClaw is supervising it (managed=True). Binary identity alone is not enough —
    # Xtigervnc is the stock Debian/Ubuntu tigervnc-standalone-server binary, so an
    # operator's own unmanaged VNC server matches it too (C-135, see module comment).
    if confirmed_vnc and managed:
        return _finding(
            "B384",
            FAIL,
            f"desktop.host.enabled is true, desktop.host.managed is true, and the "
            f"VNC/RFB desktop listener on port {port} — confirmed as running the "
            "Xtigervnc binary OpenClaw's managed-desktop supervisor spawns — is "
            "ACTUALLY reachable on a non-loopback address. This is a second network "
            "listener beside the gateway, gated only by VNC password auth "
            "(desktop.host.passwordFile, see B385), not OpenClaw's own channel auth.",
            "Find why the managed desktop is not loopback-only (an env override or a "
            "TigerVNC config outside OpenClaw's control is the usual cause) and restart "
            "the gateway once fixed.",
            evidence=evidence
            + [
                f"{m.host}:{m.port} confirmed via pid {ident.pid} (exe={ident.exe})"
                for m, ident in zip(non_loopback, identities)
                if _classify_desktop_listener_identity(ident) == "vnc"
            ],
            scored=True,
        )

    reasons = []
    for m, ident in zip(non_loopback, identities):
        classification = _classify_desktop_listener_identity(ident)
        if classification == "unresolved":
            reasons.append(f"{m.host}:{m.port} — process identity unresolvable")
        elif classification == "vnc":
            # confirmed_vnc is non-empty here only when `managed` is not True (the
            # managed+confirmed combination returned FAIL above already).
            reasons.append(
                f"{m.host}:{m.port} held by pid {ident.pid} (exe={ident.exe}) — runs "
                "the exact binary OpenClaw's managed desktop spawns, but "
                "desktop.host.managed is not true, so this is just as consistent with "
                "an operator-run TigerVNC server entirely outside OpenClaw's control"
            )
        else:
            reasons.append(
                f"{m.host}:{m.port} held by pid {ident.pid} (exe={ident.exe}) — not "
                "identifiable as OpenClaw's managed desktop"
            )
    return _finding(
        "B384",
        WARN,
        f"desktop.host.enabled is true, and a non-loopback listener was found on port "
        f"{port} ({port_source}), but it could not be positively tied to OpenClaw's "
        "own managed desktop process: " + "; ".join(reasons) + ". This could be the "
        "VNC server desktop.host relies on (managed or an existing one) actually "
        "reachable from the network rather than loopback-only, or an unrelated process "
        "coincidentally sharing the port — not distinguishable from a config file and a "
        "/proc read alone.",
        f"Confirm what is listening on port {port} (e.g. `ss -tlnp` as root, or `lsof "
        f"-i :{port}`). If desktop.host.managed is not set, the VNC server is entirely "
        "external to OpenClaw and nothing here enforces loopback for it — bind it to "
        "127.0.0.1 explicitly.",
        evidence=evidence + reasons,
        scored=False,
    )


def check_desktop_host_password_file(ctx: Context) -> Finding:
    """B385 (F-197): desktop.host.passwordFile's at-rest permissions. See the module
    comment above `_DESKTOP_DEFAULT_VNC_PORT` for the full grounding.

    FAIL    -- the file exists and is readable by another local account
               (`_file_readable_by_others` -- world-readable, or group-readable with a
               group known to have members beyond the owner; a user-private group is not
               flagged, per B-127).
    PASS    -- the file exists and only its owner can read it, or passwordFile is not
               set at all (nothing to check).
    UNKNOWN -- passwordFile is set but the file does not exist / could not be stat'ed, or
               the platform is non-POSIX (NTFS ACLs -- never a false PASS).

    Never reads the file's CONTENT (still a VNC-obfuscated password, §8-sensitive) --
    only whether it exists and its mode bits.
    """
    cfg = ctx.config
    if not cfg:
        return _finding(
            "B385",
            UNKNOWN,
            "No config loaded — cannot assess desktop.host.passwordFile.",
            "Run on the host with ~/.openclaw present.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    desktop = dig(cfg, "desktop.host")
    if desktop is None:
        return _finding(
            "B385",
            PASS,
            "desktop.host is not configured, so there is no VNC passwordFile to assess.",
            "No action needed unless you enable the Desktop lab feature.",
        )
    if not isinstance(desktop, dict):
        return _finding(
            "B385",
            UNKNOWN,
            "desktop.host is present but malformed (not an object) — cannot assess its "
            "passwordFile.",
            "Fix `desktop.host` to be a config object, or remove the key.",
        )
    raw_path = desktop.get("passwordFile")
    if not (isinstance(raw_path, str) and raw_path.strip()):
        return _finding(
            "B385",
            PASS,
            "desktop.host.passwordFile is not set — no VNC password file to assess.",
            "No action needed.",
        )
    if not _is_posix():
        return _finding(
            "B385",
            UNKNOWN,
            "On Windows, file security uses NTFS ACLs, not POSIX mode bits — "
            "desktop.host.passwordFile's at-rest permissions are UNKNOWN, never a false "
            "PASS.",
            f"Check the ACLs yourself: `icacls {raw_path}` should not grant read to "
            "Users / Everyone / Authenticated Users.",
        )
    pw_path = Path(raw_path)
    try:
        exists = pw_path.is_file()
    except OSError:
        exists = False
    if not exists:
        return _finding(
            "B385",
            UNKNOWN,
            f"desktop.host.passwordFile is set to {raw_path!r}, but no readable file "
            "exists there — cannot assess its permissions.",
            "If this install does use the Desktop lab feature, ensure the password "
            "file is readable by the audit so a future run can check its permissions.",
        )
    why = _file_readable_by_others(pw_path)
    if why:
        return _finding(
            "B385",
            FAIL,
            f"desktop.host.passwordFile ({raw_path}) is {why}. This is the sole "
            "credential gating the gateway-host VNC/RFB desktop listener (TigerVNC "
            "VncAuth's DES-based obfuscation is not a real secret boundary once the "
            "file itself can be read) — anyone who can read it can unlock remote "
            "control of the desktop.",
            f"Run `chmod 600 {raw_path}`. If you cannot rule out that it was already "
            "read, regenerate it (your VNC server's password tool, e.g. "
            "`tigervncpasswd -f`) so a copy taken while it was readable stops working.",
            evidence=[f"{raw_path} is {why}"],
        )
    return _finding(
        "B385",
        PASS,
        f"desktop.host.passwordFile ({raw_path}) exists and only its owner can read it.",
        "No action needed.",
    )


def check_audit_target_divergence(ctx: Context) -> Finding:
    """B183 — the running agent may be reading a DIFFERENT config file than the one audited.

    B-281 (ENV-1). Every other check in this catalog describes ``ctx.config_path``. That is
    only useful if the agent is running that same file. OpenClaw's own resolver
    (``resolveConfigPath``, dist/paths-BMBAvkNf.js:136-152) consults
    ``OPENCLAW_CONFIG_PATH`` first and unconditionally, reaches a different home through
    ``OPENCLAW_HOME`` (home-dir-CJKEsOtx.js:34-42), and follows ``OPENCLAW_STATE_DIR`` —
    which is exactly what ``openclaw --profile <name>`` sets. It also prefers an EXISTING
    legacy ``clawdbot.json`` over the canonical name, so the target can move with no
    environment variable set at all.

    Left unreported, a stale hardened ``~/.openclaw/openclaw.json`` scores A while the live
    agent runs a wide-open profile — a lying PASS across the whole catalog at once, the same
    family as the E-052 phantom-path findings.

    WARN    — the path the product would resolve differs (by ``realpath``) from the audited
              one. Both paths are named.
    PASS    — the two resolve to the same file.
    UNKNOWN — the audited home is not this machine's default state directory (a fixture or
              ``--home`` scan), or the resolution could not be completed.

    Never FAIL: a divergence is a signal to re-point the audit, not a proven
    misconfiguration — the other file may be perfectly hardened.

    Three deliberate constraints, each of which would otherwise produce a spurious finding:

    * **``realpath`` comparison, not presence.** ``OPENCLAW_CONFIG_PATH`` explicitly set to
      the file we already audit, or reaching it through a symlink, is NOT a divergence. A
      naive "the variable is set → warn" would fire on a correct setup.
    * **Gated on the default state directory** (``audits_default_state_dir``). Under
      ``--home``/fixtures the user deliberately targeted a file and a warning would be
      noise; it also keeps the auditor's own environment from steering a fixture scan.
    * **A shell export in an ALREADY-RUNNING agent leaves no on-disk trace and is not
      observable from here.** That is a process boundary. So the quiet result is reported
      honestly and never as an affirmative all-clear beyond what was actually checked.
    """
    from ..collector import (  # noqa: PLC0415
        audits_default_state_dir,
        resolve_product_config_path,
    )

    audited = ctx.config_path
    if audited is None:
        return _finding(
            "B183",
            UNKNOWN,
            "The audited config path was not recorded, so it cannot be compared against "
            "the path OpenClaw itself would resolve.",
            "Re-run the audit with a current build of this skill.",
        )

    # B-349: every branch below names the audited file RELATIVE to the audited home in
    # `detail` -- an absolute path there is hashed by `baseline.fingerprint()`, which made
    # a fingerprint suppression for this finding die the moment the profile moved.
    # B-757 follow-up: `evidence=`/the fix text used to keep the absolute form on the
    # reasoning that the report header printed it once anyway ("Audited config: ..."), so
    # "nothing was lost". That premise is gone -- the header is home-relative now too
    # (B-757) -- so evidence/fix route through `_username_safe_path` below instead of
    # carrying the one remaining full absolute path in this finding.
    audited_rel = _detail_path(audited, ctx.home)

    if not audits_default_state_dir(ctx.home):
        return _finding(
            "B183",
            UNKNOWN,
            f"This scan targets {audited_rel} under an explicitly chosen home, which is "
            "not this machine's default OpenClaw state directory, so it cannot be "
            "compared against the path the running agent would resolve — the environment "
            "of this process describes a different subject.",
            "Run the audit with no --home argument to have it check whether the agent's "
            "own config resolution points somewhere else.",
            evidence=[f"audited: {_username_safe_path(audited)}"],
        )

    product, reason = resolve_product_config_path()
    if product is None:
        return _finding(
            "B183",
            UNKNOWN,
            f"OpenClaw's own config path could not be resolved ({reason}), so it cannot be "
            f"confirmed that the agent reads the audited file {audited_rel}.",
            "Check that HOME (or OPENCLAW_HOME) is set to a real directory, then re-run.",
            evidence=[f"audited: {_username_safe_path(audited)}"],
        )

    try:
        same = os.path.realpath(str(audited)) == os.path.realpath(str(product))
    except (OSError, ValueError):
        same = str(audited) == str(product)

    if not same:
        return _finding(
            "B183",
            WARN,
            "The audited config file is NOT the one OpenClaw would load. Every other "
            f"finding in this report describes {audited_rel} under the audited home, but "
            f"the agent resolves a different file ({reason}) — so a clean grade here says "
            "nothing about the configuration the agent is actually running. Both paths "
            "are named in full in this finding's evidence and in the fix below.",
            f"Re-run the audit against the live target: {command_prefix()} --home "
            f"{_username_safe_path(product.parent)}. If the audited file is the intended "
            "one instead, unset "
            "OPENCLAW_CONFIG_PATH / OPENCLAW_HOME / OPENCLAW_STATE_DIR (these are what "
            "`openclaw --profile` sets) so the agent and the audit agree.",
            evidence=[f"audited: {_username_safe_path(audited)}", f"OpenClaw resolves: {_username_safe_path(product)}"],
        )

    return _finding(
        "B183",
        PASS,
        f"The audited config file ({audited_rel}) is the same file OpenClaw's own resolver "
        "selects from this environment, so the rest of this report describes the "
        "configuration the agent loads on its next start.",
        "Keep OPENCLAW_CONFIG_PATH / OPENCLAW_HOME / OPENCLAW_STATE_DIR unset, or re-run "
        "the audit with --home pointed at the profile you actually run.",
        evidence=[f"audited: {_username_safe_path(audited)}", f"resolved via {reason}"],
    )


# B-282 (ENV-6): break-glass environment toggles that relax a security control.
#
# Each entry is (variable, predicate, what it does) and each was grounded in the installed
# dist individually — the three toggles use THREE DIFFERENT truthiness rules and collapsing
# them into one would misreport at least two:
#
#   OPENCLAW_ALLOW_INSECURE_PRIVATE_WS  strict `=== "1"` (connection-details-BBobR8Xp.js:27)
#   OPENCLAW_LOAD_SHELL_ENV             isTruthyEnvValue {1,on,true,yes}
#                                       (shell-env-DaE9Xx3-.js:200-202 → env-CKdem44B.js:46)
#
# DELIBERATELY EXCLUDED, both would be false positives:
#
#   OPENCLAW_SHOW_SECRETS — its sense is INVERTED. status.scan-Bm3xXn8C.js:34 reads
#     `showSecrets: process.env.OPENCLAW_SHOW_SECRETS?.trim() !== "0"`, so display is ON by
#     default and the ONLY value that changes anything is "0", which HARDENS the `openclaw
#     status` output. Flagging this variable as "set" would warn about a setting identical
#     to the default, and warn hardest at the exact moment the user had improved matters.
#   OPENCLAW_CLI_CONTAINER_BYPASS — not a sandbox escape but the CLI's container-DELEGATION
#     recursion guard, injected by OpenClaw itself when exec'ing into the container
#     (startup-trace-Bc2ebu8Y.js:176-177). Its set state is the normal condition inside any
#     containerized install, so a check on it would fire on every correct deployment.
_ENV6_TOGGLES = (
    (
        "OPENCLAW_ALLOW_INSECURE_PRIVATE_WS",
        lambda v: v.strip() == "1",
        "lets the gateway accept a plaintext ws:// URL to a non-loopback address, so "
        "gateway credentials and chat traffic cross the network unencrypted",
    ),
    (
        "OPENCLAW_LOAD_SHELL_ENV",
        None,  # is_truthy_env_value; bound at call time to keep this table a leaf
        "makes the agent run your login shell to fill in credential variables that are "
        "missing from its own config, widening where its secrets can come from",
    ),
)


def check_env_breakglass_toggles(ctx: Context) -> Finding:
    """B192 — a break-glass environment toggle relaxes a security control.

    B-282 (ENV-6). Read from the two GLOBAL runtime dotenv files OpenClaw loads into
    ``process.env`` (``~/.openclaw/.env`` and ``~/.config/openclaw/gateway.env`` —
    dist/dotenv-global-mWLbBl_z.js:85-111), and from this process's own environment only
    when the audited home is this user's own.

    WARN    — a toggle is observably on. Never FAIL: both are DOCUMENTED break-glass
              switches. ``OPENCLAW_ALLOW_INSECURE_PRIVATE_WS`` is sanctioned in OpenClaw's
              own gateway security docs for trusted private networks and its plugin docs
              instruct users to set it. A FAIL would punish following the vendor's manual.
    PASS    — a global dotenv file exists and none of the toggles are on in it.
    UNKNOWN — no global dotenv file exists AND the audited home is not this user's own, so
              there is nothing to have read. Also UNKNOWN, ``engine_degraded=True``
              (B-657), when a global dotenv file WAS read but exceeded the collector's
              byte cap (``ctx.dotenv_truncated``) — a toggle past the cut would silently
              disable a protection with no disclosure. Not gated on the shared
              ``limit_hits_for(ctx, LIMIT_DOMAIN_ENV)``: this check's only evidence source
              (``dotenv_override``) never reads a systemd unit's environment, and that
              domain also covers unit-file truncation this check never touches.

    **Scope, stated exactly.** A variable exported in the shell that launched an
    already-running agent leaves no on-disk trace and is not detectable from here — that
    is a process boundary. The two global dotenv files cover the *persistent* delivery
    paths, which are also the ones that survive a restart and therefore the ones an
    attacker or a compromised agent would use; a shell export dies with the shell. The
    residual is a false NEGATIVE, never a false positive. Accordingly this check never
    claims "no toggle is set" — only that none was found in the persistent locations.
    """
    from ..collector import dotenv_override, is_truthy_env_value  # noqa: PLC0415

    hits: "list[str]" = []
    for name, strict, what in _ENV6_TOGGLES:
        raw, source = dotenv_override(ctx, name)
        if raw is None:
            continue
        on = strict(raw) if strict is not None else is_truthy_env_value(raw)
        if on:
            hits.append(f"{name} is on ({_detail_path(source, ctx.home)}) — it {what}")

    if hits:
        return _finding(
            "B192",
            WARN,
            "A break-glass environment toggle is switched on in a file OpenClaw loads at "
            "startup: " + "; ".join(hits) + ". These are legitimate escape hatches, but "
            "each one disables a protection that is on by default, and a value written to "
            "a dotenv file persists across restarts.",
            "Remove the variable from the dotenv file once the situation that needed it "
            "is over, so the protection returns on the next agent start. If it is needed "
            "permanently, record why — a persistent break-glass is a standing exception, "
            "not a default.",
            evidence=hits,
        )

    if ctx.dotenv_found and ctx.dotenv_truncated:
        # B-657 (C-135 round 2): "none of the toggles are on" is a claim about a
        # COMPLETED read of every global dotenv file. A file the collector DID read but
        # cut at its byte cap can hide a real OPENCLAW_ALLOW_INSECURE_PRIVATE_WS/
        # OPENCLAW_LOAD_SHELL_ENV past the cut -- present-but-unread, not genuinely
        # absent, the same DEGRADED_CHECK_CAP consequence as the B6/B172 fix (f748869).
        return _finding(
            "B192",
            UNKNOWN,
            "No break-glass environment toggle was found in the global dotenv file(s) "
            "that were read, but at least one of them exceeded the collector's byte cap "
            "("
            + ", ".join(_detail_path(p, ctx.home) for p in ctx.dotenv_files)
            + ") — a toggle past the cut would not have been seen.",
            "Keep OpenClaw's global dotenv files (~/.openclaw/.env, "
            "~/.config/openclaw/gateway.env) under the collector's size cap, then "
            "re-run the audit.",
            engine_degraded=True,
        )

    if ctx.dotenv_found:
        return _finding(
            "B192",
            PASS,
            "No break-glass environment toggle is switched on in the global dotenv files "
            "OpenClaw loads at startup ("
            + ", ".join(_detail_path(p, ctx.home) for p in ctx.dotenv_files)
            + ").",
            "Keep OPENCLAW_ALLOW_INSECURE_PRIVATE_WS and OPENCLAW_LOAD_SHELL_ENV out of "
            "the global dotenv files except while actively working around a problem.",
        )

    from ..collector import audits_this_users_own_home  # noqa: PLC0415

    if audits_this_users_own_home(ctx.home):
        return _finding(
            "B192",
            PASS,
            "No global dotenv file is present and no break-glass environment toggle is "
            "set in this process's environment.",
            "Keep it that way outside of active debugging.",
        )

    return _finding(
        "B192",
        UNKNOWN,
        "No global dotenv file was found for the audited home, and this process's "
        "environment describes a different subject, so it cannot be determined whether a "
        "break-glass toggle is set for the agent that runs this configuration.",
        "Run the audit on the machine and account the agent runs as, with no --home "
        "argument, to have the persistent toggle locations checked.",
    )


def check_shell_env_fallback(ctx: Context) -> Finding:
    """B324 — env.shellEnv.enabled (E-060 item 7): agent-startup login-shell import.

    The CONFIG-KEY half of the same OR condition B192 already checks the ENV-VAR half
    of: OpenClaw enables its shell-env fallback when EITHER the
    ``OPENCLAW_LOAD_SHELL_ENV`` dotenv toggle is on (B192) OR
    ``env.shellEnv.enabled === true`` in openclaw.json (this check) — grounded directly
    against the dist: ``call-Bj6Erfmh.js:101`` / ``io-By0s-a_s.js:5268``:
    ``shouldEnableShellEnvFallback(env) || cfg.env?.shellEnv?.enabled === true``. When
    on, OpenClaw loads environment variables from the user's login shell at agent
    startup, so ``~/.bashrc``/``~/.zshrc`` content becomes agent-startup input — a
    persistence foothold or a PATH-hijack planted there becomes an agent-startup
    vector, not only an interactive-shell one.

    WARN-only, never FAIL: OpenClaw's own field description calls this a legitimate,
    commonly-wanted feature ("Keep this enabled when you depend on profile-defined
    secrets or PATH customizations" — schema-DRyO1XBt.js:91), mirroring B192's own
    break-glass framing for the sibling toggle.

    Scope, stated exactly: ``shouldEnableShellEnvFallback()`` also fires from the
    ``OPENCLAW_LOAD_SHELL_ENV`` runtime environment variable (B192's surface, not
    config) — a static config audit cannot observe that path, so this check's absence
    of a finding here does NOT mean shell-env loading is off, only that the openclaw.json
    key itself does not request it. That residual is a false NEGATIVE (already covered
    by B192 for the env-var path), never a false positive this check would introduce.

    WARN    — env.shellEnv.enabled == true.
    PASS    — env.shellEnv.enabled is absent or false.
    UNKNOWN — no config found at all, or present but unparseable/unreadable.
    """
    if not ctx.config_found:
        return _finding(
            "B324",
            UNKNOWN,
            "No openclaw.json found -- env.shellEnv.enabled cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B324", ctx)
    if unreadable is not None:
        return unreadable

    enabled = dig(ctx.config, "env.shellEnv.enabled")
    if enabled is True:
        return _finding(
            "B324",
            WARN,
            "env.shellEnv.enabled=true — OpenClaw loads environment variables from "
            "the user's login shell (~/.bashrc, ~/.zshrc, …) at agent startup, so "
            "shell rc file content becomes agent-startup input.",
            "Confirm this is needed (e.g. profile-defined secrets or PATH "
            "customizations the agent depends on); disable it in a locked-down "
            "service environment with explicit env management instead.",
        )

    return _finding(
        "B324",
        PASS,
        "env.shellEnv.enabled is absent or false — openclaw.json does not request "
        "login-shell environment import at startup (the OPENCLAW_LOAD_SHELL_ENV "
        "env-var path is checked separately by B192).",
        "Keep it that way unless a specific workflow depends on profile-defined "
        "secrets or PATH customizations from the login shell.",
    )


def _b323_is_literal_path_override(key: object, value: object) -> bool:
    """True if *key* normalizes to PATH and *value* is a literal, non-empty string.

    "Literal" excludes a value containing a genuine, unresolved ``${ALL_CAPS}``
    substitution reference -- see ``_b323_contains_env_var_reference()`` for the
    faithful port of OpenClaw's own ``containsEnvVarReference()``
    (``env-substitution-CATXLg7n.js:102-112``): OpenClaw itself never applies such a
    value, so flagging it here would be a false positive on a config that merely
    references another variable indirectly. A value that merely *contains* the
    substring ``${`` without forming a real reference (wrong case, bad name, no
    closing brace, or an escaped ``$${...}``) is NOT excluded -- OpenClaw applies
    it verbatim, so it must still be flagged.
    """
    if not isinstance(key, str) or key.strip().upper() != "PATH":
        return False
    if not isinstance(value, str) or not value.strip():
        return False
    return not _b323_contains_env_var_reference(value)


def check_env_vars_path_override(ctx: Context) -> Finding:
    """B323 — env.vars.PATH / env.<KEY> catchall: an explicit PATH override.

    Narrowed on grounding from the epic's original framing ("report any env.vars /
    env.<KEY> catchall key OpenClaw's own blocklist doesn't already block"). Two
    catchall shapes reach the process environment identically —
    ``config-env-vars-DlUfO5Q_.js:43-59`` ``collectConfigEnvVarsByTarget()`` reads
    ``env.vars.<KEY>`` (a Zod ``record(string(), string())``,
    ``zod-schema-O9ml_nmo.js:1004``) AND any other ``env.<KEY>`` sibling except
    ``shellEnv``/``vars`` (a Zod ``.catchall(string())`` on the ``env`` object itself,
    ``zod-schema-O9ml_nmo.js:1005``) — and both funnel through the same
    ``isBlockedConfigEnvVar()`` gate (``config-env-vars-DlUfO5Q_.js:36-38``), which
    unions ``isDangerousHostEnvVarName()`` + ``isDangerousHostEnvOverrideVarName()``
    (``host-env-security-CWC2ZCy4.js:5-316``, ~254 explicit keys + 7 prefixes + 1
    regex — NODE_OPTIONS/PYTHONPATH/BASH_ENV/GIT_EXTERNAL_DIFF/RUSTC_WRAPPER/
    SSLKEYLOGFILE/EDITOR/HOME/AWS_*/GH_TOKEN/etc.). That blocklist is comprehensive
    enough that a check flagging every *other* residual key would false-WARN on the
    feature's own legitimate purpose (arbitrary app/API-key vars) — a Golden Rule #5
    violation. The one concrete, groundable gap is ``PATH`` itself: it does not
    appear anywhere in ``blockedEverywhereKeys``/``blockedOverrideOnlyKeys``
    (host-env-security-CWC2ZCy4.js:5-316) — the file's only literal ``"PATH"`` match
    is inside ``sanitizeHostEnvOverridesWithDiagnostics()`` (:497), a *different*,
    host-exec-override subsystem this config path never reaches.

    WARN-only, never FAIL: whether a config-declared PATH has any effect depends on a
    runtime fact this static auditor cannot observe. ``applyConfigEnvVars()``
    (``config-env-vars-DlUfO5Q_.js:~118-152``) never overwrites a key that already
    holds a non-empty value in the environment it is applied against, and every
    grounded live call site (``pre-bootstrap-8G8HyMEQ.js:195,332``,
    ``io-By0s-a_s.js:5267`` ``finalizeLoadedRuntimeConfig``,
    ``call-Bj6Erfmh.js:79`` ``resolveGatewayDispatchEnvVars``) defaults to
    ``process.env``, which always carries a non-empty ``PATH`` in a realistic launch
    — so this is closer to C5's own "declared trust expansion, real-world
    exploitability uncertain" WARN precedent (host-filesystem PATH/install-dir
    hijacking) than to B186's narrow-and-deterministic writable-root FAIL. A value
    containing an unresolved ``${...}`` substitution token is skipped, mirroring
    ``containsEnvVarReference()`` (``env-substitution-CATXLg7n.js:102-112``) — the
    config is referencing another variable indirectly, not hardcoding a literal path.

    WARN    — ``env.vars.PATH`` or the ``env.<KEY>`` catchall sets a literal
              (non-``${...}``) non-empty string value for a key that normalizes
              (case-insensitively) to ``PATH``.
    PASS    — no such entry.
    UNKNOWN — no openclaw.json found, or present but unparseable/unreadable.
    """
    if not ctx.config_found:
        return _finding(
            "B323",
            UNKNOWN,
            "No openclaw.json found -- env.vars.PATH / env.<KEY> catchall PATH override "
            "cannot be assessed.",
            "Run the audit against the OpenClaw profile directory (its openclaw.json).",
        )
    unreadable = _config_unreadable("B323", ctx)
    if unreadable is not None:
        return unreadable

    env_cfg = ctx.config.get("env") if isinstance(ctx.config, dict) else None
    hits: "list[str]" = []
    if isinstance(env_cfg, dict):
        vars_block = env_cfg.get("vars")
        if isinstance(vars_block, dict):
            for key, value in vars_block.items():
                if _b323_is_literal_path_override(key, value):
                    hits.append(f"env.vars.{key}={value!r}")
        for key, value in env_cfg.items():
            if key in ("shellEnv", "vars"):
                continue
            if _b323_is_literal_path_override(key, value):
                hits.append(f"env.{key}={value!r}")

    if hits:
        return _finding(
            "B323",
            WARN,
            "openclaw.json explicitly sets PATH via the env.vars / env.<KEY> catchall "
            "mechanism (" + "; ".join(hits) + "). OpenClaw's own config-env-var "
            "blocklist covers ~254 dangerous keys/prefixes but does not include PATH "
            "itself, so this value is not filtered the way NODE_OPTIONS/PYTHONPATH/"
            "BASH_ENV and similar keys are.",
            "Confirm this is intentional. In practice it is usually inert -- OpenClaw "
            "never overwrites an env var that already holds a non-empty value at the "
            "point this is applied, and every normal launch already has a non-empty "
            "PATH -- but a launcher that starts the agent with an empty or unset PATH "
            "would let this value take effect unfiltered. Remove it unless there is a "
            "specific, documented reason to override the agent's PATH.",
            evidence=hits,
        )

    return _finding(
        "B323",
        PASS,
        "No env.vars.PATH or env.<KEY> catchall PATH entry found in openclaw.json.",
        "Keep it that way; if PATH customization is genuinely needed, prefer scoping "
        "it narrowly (e.g. a per-tool wrapper) and reviewing it periodically.",
    )


# B350: a sentinel, because `gateway` being ABSENT and `gateway` being present-but-null
# are different facts and `.get("gateway")` collapses them to the same None.
_B350_ABSENT = object()


def check_gateway_operator_terminal(ctx: Context) -> Finding:
    """B350 - the operator terminal: a PTY-backed shell served to Control UI and mobile.

    Grounded against the INSTALLED dist (openclaw@2026.7.1-2), not the recon, and
    independently re-verified against the RUNTIME rather than the schema alone.

    SHAPE. ``gateway.terminal`` is ``{enabled?: boolean, shell?: string,
    detachedSessionTimeoutSeconds?: number}`` - object only, ``$strict``, with no boolean
    shorthand (plugin-sdk/config-schema.d.ts:4499-4503, and the runtime zod builder at
    zod-schema-O9ml_nmo.js:1365-1369, which wraps no ``union([boolean(), object()])``).
    That is the OPPOSITE of ``tools.codeMode``, which really is boolean-or-object, so the
    two must not be read with the same helper.

    DEFAULT. There is no zod ``.default(false)`` - ``enabled`` is a bare
    ``boolean().optional()``. The false default is FUNCTIONAL, enforced by strict equality
    at three independent runtime sites: launch-BmPwk1y9.js:103, launch-BmPwk1y9.js:154 and
    server.impl-qYPVZMND.js:1002 all test ``=== true``. That is why this check tests
    ``is not True`` rather than truthiness: it matches the vendor's own gate exactly, so a
    truthy non-bool is not "on" here for the same reason it is not "on" there.

    NO SECOND LOCATION. ``terminal`` occurs exactly ONCE in the 4,896-line declaration,
    under top-level ``gateway`` - absent from ``agents``, ``agents.list``,
    ``agents.profiles`` and ``presets``, and read at runtime from the single source
    ``config.gateway?.terminal`` (launch-BmPwk1y9.js:88-107). The contrast is the evidence
    that this is deliberate rather than an omission: ``codeMode`` IS defined both
    top-level and per-agent, so the schema author wires per-agent overrides where they are
    intended and did not here.

    ``.shell`` pins the interpreter; unset, the runtime resolves ``$SHELL`` as a login
    shell (``-l``), falling back to ``cmd.exe`` on win32 and to ``/bin/bash -l`` when
    ``$SHELL`` is itself unset (launch-BmPwk1y9.js:9-30).

    PASS - ``gateway.terminal.enabled`` is absent or not true. That is the shipped
           default, and it is what every config on this machine's fleet carries today.
    WARN - it is true. The detail names the REACH: whether the gateway is proven
           reachable beyond loopback, proven loopback-only, or not resolvable from a
           config file alone.

    WHY THE VERDICT DOES NOT BRANCH ON THE BIND. ``_gateway_remote_exposure_reason``
    returns ``None`` for BOTH "proven loopback" and "no claim possible" (the ``auto``
    profile, and ``custom`` with an unresolvable host - see its docstring, which is
    deliberate and correct). Deciding WHETHER to report on that value would therefore
    turn an unresolvable bind into a silent PASS, which is the fail-open shape this
    project keeps finding. Turning the terminal on is the owner's explicit act and is
    reportable on its own; the bind only changes how urgent it is, so it belongs in the
    detail. The reach sentence is built from ``parse_bind_host``/``LOOPBACK`` first so
    that a proven-loopback bind is described as such rather than lumped in with the
    unresolvable case.

    WHY THE SANDBOX MITIGATION IS NAMED RATHER THAN COMPUTED. The refusal is real and
    verified in code, not just prose: ``resolveTerminalLaunch`` returns
    ``{ok: false, block: {kind: "sandboxed"}}`` when
    ``resolveSandboxConfigForAgent(config, agentId).mode === "all"``
    (launch-BmPwk1y9.js:55-62), whose own comment calls it fail-closed. But it is
    PER-AGENT and resolved at launch, so claiming it statically means proving EVERY agent
    is fully sandboxed - including agents added after this audit ran - and a wrong proof
    in either direction is worse than naming the condition. The fix text names it so the
    owner can check the one thing this reader cannot.

    DECLARED LIMITS, both in the over-reporting direction, so neither can hide a real
    exposure. (1) A config with ``enabled: true`` whose only reachable agents all run
    ``sandbox.mode: "all"`` still WARNs here, per the paragraph above. (2) There is a
    transient state this reader cannot see at all: ``createTerminalLaunchPolicy`` keeps
    ``terminalDisabledUntilRestart`` / ``terminalDisabledUntilCommit`` windows
    (launch-BmPwk1y9.js:80-179) in which a snapshot showing ``enabled: true`` is
    functionally disabled until the gateway restarts or commits. A single static config
    snapshot has no way to observe that, and the honest consequence is a WARN that is
    momentarily early rather than a silence that is wrong.

    Never FAILs. This is a configured-capability disclosure, not a proven compromise; a
    FAIL tier would need its own independent C-135 pass against real configs first.

    WHY ``.shell`` IS INTERPOLATED VERBATIM (§8). It is an absolute path and it reaches a
    report a user may paste in public, so the question is fair - but ``_detail_path``'s
    contract already answers it: a scan-root path must be made relative, while "a path the
    CONFIG itself declares in absolute form is deliberately left verbatim: that string is a
    function of the audited subject, so it belongs in the finding's identity (and in the
    text, since it is what the owner has to go fix)". ``gateway.terminal.shell`` is exactly
    that case. It is also not credential-bearing - unlike B80's gateway token, where only
    the LENGTH is read - so there is nothing here to route through ``logsafe.redact``.
    Measured: a ``.shell`` carrying newlines, ANSI escapes, 5,000 characters, non-ASCII, or
    a non-string type produces no raise and puts no newline or escape into the detail.
    """
    unreadable = _config_unreadable("B350", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    # The fail-open branch this check would otherwise have had, and did have when first
    # written. `_config_unreadable` only covers "openclaw.json present and unparseable";
    # on a host with NO openclaw.json at all, `config_parse_error` is False and
    # `ctx.config` is `{}` (see `_surface_absent`'s docstring), so falling straight
    # through would report "the terminal is not enabled" about a config nobody read. A
    # malformed `gateway` value (null, a list, a number) is the same hazard by another
    # route -- every dig() below would silently degrade to its default. Both take the
    # B32 precedent: UNKNOWN, with not_applicable set ONLY when the config locus was
    # read completely and is genuinely empty.
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B350",
            UNKNOWN,
            "No config was read, so whether the operator terminal is enabled could not "
            "be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    gw = cfg.get("gateway", _B350_ABSENT)
    if gw is _B350_ABSENT:
        # A config that WAS read and simply carries no gateway block. The terminal
        # cannot be on: `enabled` defaults to false and the vendor gates the feature on
        # `gateway?.terminal?.enabled === true`, which an absent block cannot satisfy.
        # This is a real PASS, not an absence of knowledge -- and saying otherwise would
        # be inconsistent with `{"gateway": {}}`, which reaches the ordinary PASS below
        # while encoding the identical fact. Measured: 72 of the 651 fixture homes are
        # this shape, so the distinction is not hypothetical.
        return _finding(
            "B350",
            PASS,
            "No gateway block is configured, so no operator terminal is served.",
            "Nothing to do; if you later add a gateway block, leave "
            "gateway.terminal.enabled off unless you need an operator shell.",
        )
    if not isinstance(gw, dict):
        # Present but malformed (null, a list, a number, a bare string). Every dig()
        # below would degrade to its default without raising, which is indistinguishable
        # from "terminal simply not configured" -- a verdict over ground never read.
        return _finding(
            "B350",
            UNKNOWN,
            f"The gateway config is present but is not an object (found "
            f"{type(gw).__name__}), so whether the operator terminal is enabled could "
            f"not be determined.",
            "Fix the gateway block in openclaw.json so it is a JSON object, then re-run "
            "the audit.",
        )
    enabled = dig(cfg, "gateway.terminal.enabled")
    if enabled is not True:
        return _finding(
            "B350",
            PASS,
            "The gateway operator terminal is not enabled (gateway.terminal.enabled is "
            "absent or not true), so no browser- or mobile-reachable shell is served.",
            "Keep it off unless you specifically need an operator shell; it is off by "
            "default.",
        )

    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    if bind_host in LOOPBACK:
        reach = (
            "the gateway is bound to loopback, so the shell is reachable only from this "
            "host"
        )
    else:
        reason = _gateway_remote_exposure_reason(cfg)
        if reason:
            reach = f"the gateway is reachable beyond loopback ({reason}), so the shell is too"
        else:
            reach = (
                "the gateway bind cannot be resolved from config alone, so whether the "
                "shell is reachable off-host is not established here"
            )

    shell = dig(cfg, "gateway.terminal.shell")
    which = (
        f"it launches the pinned interpreter {shell!r}"
        if isinstance(shell, str) and shell.strip()
        else "it launches the host login shell ($SHELL), since gateway.terminal.shell is unset"
    )
    return _finding(
        "B350",
        WARN,
        f"gateway.terminal.enabled is true: OpenClaw serves a PTY-backed shell running "
        f"with the gateway process environment to Control UI and mobile clients, and "
        f"{which}. Right now {reach}.",
        "Set gateway.terminal.enabled to false unless an operator shell is genuinely "
        "needed. If it is needed, keep the gateway on loopback (or behind your own "
        "authenticated tunnel) and confirm the agents it can target run with "
        "sandbox.mode 'all' - OpenClaw refuses the terminal for fully-sandboxed agents, "
        "which is the one mitigation this audit cannot verify for you.",
    )


_B389_COMPUTER_PLUGIN_ID = "cua-computer"


def _b389_sandbox_mode(cfg: dict, entry) -> str:
    """Same per-scope resolution as ``toolpolicy._sandbox_mode`` (not imported — this
    check only needs the coarse ``== "all"`` reading B68 already uses, not the full
    tri-state ``_sandbox_confines``/B-712 machinery): a per-agent ``sandbox.mode``
    override, else ``agents.defaults.sandbox.mode``."""
    scoped = entry.get("sandbox") if isinstance(entry, dict) else None
    mode = scoped.get("mode") if isinstance(scoped, dict) else None
    if mode is None:
        mode = dig(cfg, "agents.defaults.sandbox.mode")
    return mode if isinstance(mode, str) else ""


def check_gateway_computer_plugin_reach(ctx: Context) -> Finding:
    """B389 — the Gateway's own unmanaged-desktop `computer` control
    route, reachable via the `computer.invoke`/`computer.status` RPC methods without
    passing through `gateway.nodes.commands.deny` or any per-action confirmation.

    Grounded against the LIVE installed dist (openclaw@2026.9.5, 2026-09-19), not the
    schema recon or the changelog.

    THE SURFACE. `method-scopes-CF6Mdynq.mjs:2954-2965` declares three new Gateway RPC
    methods: `computer.status` (operator.read), `computer.invoke` (operator.write) and
    `desktop.release` (operator.admin). `computer.invoke`/`computer.status`
    (`computer-B53mi_iF.mjs:29-61`) dispatch straight to
    `context.gatewayComputerService`, which is `createGatewayComputerService`
    (`computer-service-B8rKHvOb.mjs`) — the Gateway process's OWN, ambient desktop
    session, prepared without ever checking `desktop.host.enabled` (that only gates the
    separate MANAGED-desktop branch inside `prepare()`; the plain/unmanaged path needs
    no `desktop.host` config at all, refuting the "gated on desktop.host" half of the
    original candidate wording).

    THE GAP. `invoke()` never imports or calls `isNodeCommandAllowed`/
    `resolveNodeCommandAllowlist` — the predicate every OTHER command-shaped route
    (paired remote nodes, `computer-transport-CwEUIeg3.mjs:189-198`; exec approvals;
    fs) consults, and the one that actually reads `gateway.nodes.commands.deny`
    (`node-command-policy-5uuS2pOn.mjs:297-298`). So a config that sets
    `gateway.nodes.commands.deny: ["computer.act"]` — believing it has closed the
    `computer` capability everywhere — does not touch this route at all: it is not a
    node-command invocation, it is the Gateway's own desktop. There is also no
    per-action confirmation gate on this path (measured: no `confirm`/`approval` symbol
    anywhere in `computer-service-B8rKHvOb.mjs`) — the only gates are the operator RPC
    scope and `configuredProvider()` below.

    WHY THIS NEVER FIRES BY ACCIDENT. `configuredProvider()`
    (`computer-service-B8rKHvOb.mjs:110-115`) requires, as one conjunction: the plugin
    registry's resolved `plugin.enabled === true` AND `config.plugins?.enabled !== false`
    AND, separately, `config.plugins?.entries?.["cua-computer"]?.enabled === true` read
    off the RAW config — an EXPLICIT entry, not merely the bundled plugin's own
    `enabledByDefault: true` (`extensions/cua-computer/openclaw.plugin.json`) taking
    effect with no config touch at all. So despite shipping enabled-by-default, the
    Gateway-desktop route this check reports on requires the owner to have explicitly
    written `plugins.entries.cua-computer.enabled: true` — the same "owner's explicit
    act, not the shipped default" shape B350 (`gateway.terminal.enabled`) already
    reports on, which is why this stays a WARN-only disclosure rather than a bare
    "plugin ships enabled" alarm.

    WHY IT ALSO GATES ON `toolgrant.granted('computer', scope)`. The plugin-enabled
    condition alone only proves an AUTHENTICATED OPERATOR (Control UI, mobile, any
    other `operator.write`-scoped RPC client — a human using an admin feature by
    design) could drive the desktop; that is not itself a misconfiguration. What turns
    it into a PROMPT-INJECTABLE surface is an AGENT itself holding the `computer` tool
    (`computer-tool-w_NM7BHT.mjs:277,295` — an agent-hosted run can call
    `computer.invoke` over the SAME Gateway RPC, via `callGatewayTool`, using its own
    delegated authority). `computer` is an ordinary core tool id
    (`toolgrant._CORE_TOOL_GROUPS["group:nodes"]`/`["group:openclaw"]`) but is granted
    by NONE of the `minimal`/`coding`/`messaging` profiles — only `profile: "full"` or
    an explicit `allow`/`alsoAllow` naming it (or the group) reaches it, so
    `toolgrant.granted(cfg, "computer", scope)` is the right, already-vendor-validated
    question to ask per scope (differentially re-verified for this exact tool id against
    the live 2026.9.5 resolver via `tests/_toolgrantoracle.py`, 2026-09-19 — its own
    committed battery does not cover `"computer"`).

    WHY SANDBOX IS THE ONE CONFIG-VISIBLE MITIGATION NAMED IN THE TRIGGER, NOT ONLY IN
    THE FIX TEXT (unlike B350). `resolveSandboxToolPolicyForAgent` is called for a
    sandboxed session with `containedToolNames: ["computer"]`
    (`worker-turn-execution-CxTBWFYa.mjs:112`, `workspace-result-finalize-C4Pt3pQL.mjs:626`)
    specifically to route the agent's `computer` tool through a CONTAINED desktop rather
    than the ambient one this check is about — so a scope proven fully sandboxed
    (`agents.defaults.sandbox.mode`/per-agent `sandbox.mode` `== "all"`) is genuinely
    mitigated, not merely hoped to be. Same coarse `== "all"` reading B68's composite
    predicate already uses (not the fuller `non-main`-undecidable tri-state
    `toolpolicy._sandbox_confines` models) — narrowing, not closing: `sandbox.mode:
    "non-main"` is left on the WARN side rather than invented as a proof either way.

    PASS    — the trigger is PROVEN false: `plugins.enabled` is explicitly `false`, or
              `plugins.entries.cua-computer.enabled` is absent/not `True` (the shipped
              default requires this exact opt-in), or the plugin is on but no declared
              scope is granted `computer` while unsandboxed.
    WARN    — `plugins.entries.cua-computer.enabled` is `True`, `plugins.enabled` is
              not `false`, and at least one scope (global or a declared agent) is
              granted `computer` and is not proven fully sandboxed. Names the scopes.
    UNKNOWN — the config was not read/parseable, or `plugins`/`plugins.entries` is
              present but not an object (Golden Rule #4 — every downstream dig()/`.get()`
              would otherwise silently degrade to "absent").

    Never FAIL: a configured-capability disclosure requiring its own explicit opt-in
    plus an explicit tool grant is not, on config evidence alone, a proven compromise —
    a FAIL tier needs its own independent C-135 pass first, matching B350/B358/B360's
    own reasoning for the same Gateway-capability-disclosure shape.

    DECLARED LIMIT, in the over-reporting direction only: `resolveSandboxToolPolicyForAgent`'s
    `deny`/`allow` layers on TOP of `containedToolNames` are not modelled here (the same
    scope this project's toolpolicy/toolgrant leaves to their own callers) — an operator
    who additionally denies `computer` inside `tools.sandbox.tools.deny` for an
    already-non-`all`-sandboxed scope is not read as closing it. That can only cost a
    finding, never invent one.
    """
    unreadable = _config_unreadable("B389", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B389",
            UNKNOWN,
            "No config was read, so whether the Gateway's unmanaged-desktop `computer` "
            "control route is reachable could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )

    plugins_block = cfg.get("plugins")
    if plugins_block is not None and not isinstance(plugins_block, dict):
        return _finding(
            "B389",
            UNKNOWN,
            f"The plugins config is present but is not an object (found "
            f"{type(plugins_block).__name__}), so whether the cua-computer plugin is "
            "enabled could not be determined.",
            "Fix the plugins block in openclaw.json so it is a JSON object, then "
            "re-run the audit.",
        )

    plugins_kill_switch_off = isinstance(plugins_block, dict) and plugins_block.get("enabled") is False
    entry = _plugins(cfg).get(_B389_COMPUTER_PLUGIN_ID)
    entry_enabled = isinstance(entry, dict) and entry.get("enabled") is True

    if plugins_kill_switch_off or not entry_enabled:
        return _finding(
            "B389",
            PASS,
            "plugins.entries.cua-computer.enabled is not true (or plugins.enabled is "
            "false), so the Gateway's unmanaged-desktop computer.invoke/computer.status "
            "route is not configured — it ships enabled-by-default at the plugin level, "
            "but this specific Gateway route additionally requires an explicit "
            "plugins.entries.cua-computer.enabled: true.",
            "Keep it that way unless you specifically need remote/agent desktop "
            "control; if you do, also set gateway.nodes.commands.deny with the "
            "understanding that it does not cover this route.",
        )

    scopes = [("global", {}, _toolgrant.GLOBAL_SCOPE)]
    for agent in agent_roster(cfg):
        entry_dict = agent.entry if isinstance(agent.entry, dict) else {}
        scopes.append((agent.path, entry_dict, agent.id))

    warn_scopes = []
    for label, entry_dict, grant_id in scopes:
        if not _toolgrant.granted(cfg, "computer", grant_id):
            continue
        if _b389_sandbox_mode(cfg, entry_dict) == "all":
            continue
        warn_scopes.append(label)

    if not warn_scopes:
        return _finding(
            "B389",
            PASS,
            "plugins.entries.cua-computer.enabled is true, but no declared scope is "
            "granted the `computer` tool while unsandboxed, so no agent can reach the "
            "Gateway's unmanaged-desktop control route as a tool call. (An authenticated "
            "Gateway operator could still call computer.invoke directly — that is the "
            "feature's intended admin use, not something this check flags.)",
            "If you later grant `computer` to an agent, also confirm that agent's "
            "sandbox.mode is 'all' or accept that this route bypasses "
            "gateway.nodes.commands.deny and has no per-action confirmation.",
        )

    return _finding(
        "B389",
        WARN,
        "plugins.entries.cua-computer.enabled is true and the `computer` tool is "
        f"granted, unsandboxed, at {', '.join(warn_scopes)}: an agent there can drive "
        "the Gateway process's own unmanaged desktop session over computer.invoke, a "
        "route that gateway.nodes.commands.deny does not gate and that carries no "
        "per-action confirmation.",
        "Remove the `computer` tool grant from that scope, set its sandbox.mode to "
        "'all' (sandboxed sessions route `computer` through a contained desktop "
        "instead), or set plugins.entries.cua-computer.enabled to false if desktop "
        "control is not actually needed.",
        evidence=warn_scopes,
    )


def check_local_model_service_command(ctx: Context) -> Finding:
    """B355 (C-408) — models.providers.<id>.localService.command auto-spawns a binary at
    provider startup, with config-chosen args/cwd/env. Grounded on the installed dist's
    zod schema (``ModelProviderLocalServiceSchema``, ``zod-schema.core-*.mjs``): the
    object is ``.strict().optional()`` with ``command: string().min(1)`` required
    alongside it, and siblings ``args``/``cwd``/``env``/``healthUrl``/``readyTimeoutMs``/
    ``idleStopMs``. ``env`` values carry the schema's own ``sensitive`` marker.

    **The original stub's FAIL premise (a relative command) is REFUTED by the runtime,
    not the schema.** The zod type has no absolute-path constraint -- `command` is a bare
    non-empty string, so a relative value loads fine -- but the actual local-service
    launcher (``provider-local-service-*.mjs``) calls `validateLocalServiceConfig` before
    every spawn, which does `if (!path.isAbsolute(service.command)) throw ...`. So a
    relative command never silently executes via a PATH/cwd lookup; the provider's local
    service fails to start and OpenClaw logs an error. That closes the exec-hijack angle
    the original stub worried about for the relative case -- it is a functionality bug,
    not a security exposure -- so a relative command is deliberately NOT reported here:
    it can never reach the spawn this check exists to examine.

    What the runtime does NOT check is WHO can write the absolute path it is about to
    exec. Same shape B352 (``tools.exec.pathPrepend``) already established for a sibling
    surface, and the same tier: WARN, never FAIL -- "someone else can write it" is a
    property of the filesystem at audit time, and a FAIL tier needs its own independent
    C-135 pass against real configs, which this stub explicitly deferred (CLAUDE.md's
    "WARN/INFO ship first" allowance for this task).

    WARN — an absolute `command` (or its containing directory) is group/world-writable
           by an account other than the owner (`_dir_replaceable_by_others`, the same
           predicate B352/C5 use — sticky dirs and owner-singleton groups excluded).
    PASS — a `command` is configured and safely owned, or no provider declares one.
    UNKNOWN — the config was not read, or is present but malformed.
    """
    unreadable = _config_unreadable("B355", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B355",
            UNKNOWN,
            "No config was read, so whether any model provider auto-spawns a local "
            "service binary could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    providers = dig(cfg, "models.providers")
    if providers is not None and not isinstance(providers, dict):
        return _finding(
            "B355",
            UNKNOWN,
            f"models.providers is present but is not an object (found "
            f"{type(providers).__name__}), so whether any provider auto-spawns a local "
            f"service binary could not be determined.",
            "Fix the models.providers block in openclaw.json so it is a JSON object, "
            "then re-run the audit.",
            config_field_paths={"models.providers"},
        )

    writable: list[str] = []
    safe: list[str] = []
    relative_count = 0
    if isinstance(providers, dict):
        for pid, pspec in providers.items():
            if not isinstance(pspec, dict):
                continue
            svc = pspec.get("localService")
            if not isinstance(svc, dict):
                continue
            command = svc.get("command")
            if not isinstance(command, str) or not command.strip():
                continue
            command = command.strip()
            path_ref = f"models.providers.{pid}.localService.command"
            if not os.path.isabs(command):
                # Never reaches the spawn this check examines -- see the docstring's
                # grounding note. Not a security signal; counted only so the PASS
                # fallback below does not claim "nothing is declared" about a config
                # that declares one, just one that cannot run.
                relative_count += 1
                continue
            cmd_path = Path(command)
            why = _dir_replaceable_by_others(cmd_path) or _dir_replaceable_by_others(cmd_path.parent)
            if why:
                writable.append(f"{path_ref} ({command}) is {why}")
            else:
                safe.append(f"{path_ref} ({command})")

    if writable:
        return _finding(
            "B355",
            WARN,
            f"{len(writable)} model-provider local-service command(s) are a binary-"
            f"hijack surface: {'; '.join(sorted(writable)[:3])}. OpenClaw spawns this "
            "exact path at provider startup, with config-chosen args/cwd/env — another "
            "local account replacing it runs arbitrary code as whoever runs OpenClaw, "
            "with no approval prompt.",
            "Move the binary to a directory only your account can write (owner-only "
            "mode, owner-only parent directory), or point localService.command at a "
            "package-managed install path instead of a shared/writable location.",
            evidence=sorted(writable)[:8] or None,
        )
    if safe:
        return _finding(
            "B355",
            PASS,
            f"{len(safe)} model-provider local-service command(s) are configured and "
            f"owner-only: {'; '.join(sorted(safe)[:4])}.",
            "Nothing to do. Re-check if any of those paths later becomes writable by "
            "another account.",
            evidence=sorted(safe)[:8] or None,
        )
    if relative_count:
        return _finding(
            "B355",
            PASS,
            f"{relative_count} model-provider local-service command(s) are a relative "
            "path, which OpenClaw's own launcher refuses to spawn (it requires an "
            "absolute path) — so no binary is actually auto-spawned by any of them.",
            "Not a security exposure, but the provider's local service will not start "
            "until localService.command is changed to an absolute path.",
        )
    return _finding(
        "B355",
        PASS,
        "No model provider declares a localService.command, so no binary is "
        "auto-spawned at provider startup.",
        "Nothing to do.",
    )


def _gateway_http_reach(cfg: dict, surface: str) -> str:
    """Disclosure clause for a gateway-HTTP-surface finding: whether *surface* (a short
    noun phrase, e.g. "this endpoint", "the Control UI") is reachable beyond loopback.

    Same idiom as ``check_gateway_operator_terminal`` (B350) — reuses
    ``_gateway_remote_exposure_reason`` rather than re-deriving the classification, so
    B340/B350/B358/B360 can never disagree about what counts as "exposed".
    """
    bind_host = parse_bind_host(dig(cfg, "gateway.bind", ""))
    if bind_host in LOOPBACK:
        return f"the gateway is bound to loopback, so {surface} is reachable only from this host"
    reason = _gateway_remote_exposure_reason(cfg)
    if reason:
        return f"the gateway is reachable beyond loopback ({reason}), so {surface} is too"
    return (
        f"the gateway bind cannot be resolved from config alone, so whether {surface} "
        "is reachable off-host is not established here"
    )


def check_chat_completions_endpoint(ctx: Context) -> Finding:
    """B358 (C-410) — gateway.http.endpoints.chatCompletions: an OpenAI-compatible
    ``POST /v1/chat/completions`` endpoint, off by default. Grounded on the installed
    dist (openclaw@2026.9.3, ``zod-schema-CTg_faEc.mjs:928-937``):
    ``chatCompletions: strictObject({ enabled: boolean().optional(), images:
    strictObject({...ResponsesEndpointUrlFetchShape}).optional() }).optional()``, where
    ``ResponsesEndpointUrlFetchShape`` (:530-537) is ``{allowUrl, urlAllowlist,
    allowedMimes, maxBytes, maxRedirects, timeoutMs}``. Both ``enabled`` and
    ``allowUrl`` default to false (``schema-DbKC3IUo.mjs:845,847`` and
    ``DEFAULT_OPENAI_IMAGE_LIMITS`` in ``openai-http--Ewj8T0W.mjs``).

    **The original stub's FAIL premise — "allowUrl=true with no urlAllowlist is SSRF
    to cloud metadata endpoints / internal services" — is REFUTED by the runtime, not
    the schema, and was caught before it was ever committed.** The image-URL fetch
    (``extractImageContentFromSource`` → ``fetchWithGuard``, both
    ``input-files-DS7n4SJk.mjs``) always calls ``fetchWithSsrFGuard``
    (``fetch-guard-B8Mfb56t.mjs``) with ``policy: {allowPrivateNetwork: false,
    hostnameAllowlist: limits.urlAllowlist}`` — ``allowPrivateNetwork`` is hardcoded
    false regardless of config, and the guard's private-IP predicate
    (``ssrf-B1sxrDMt.mjs``) imports a dedicated ``isCloudMetadataIpAddress`` alongside
    RFC1918/loopback/link-local/CGNAT checks. The check is DNS-PINNED and re-applied
    on every redirect hop inside the same guarded-fetch loop (defeats DNS rebinding
    and redirect-based bypass), not just on the initial URL. So an absent
    ``urlAllowlist`` does not expose the internal network or cloud metadata — that
    path is unconditionally closed by the vendor. What an EMPTY/absent allowlist
    actually means (``matchesHostnameAllowlist``: an empty list matches everything) is
    narrower: the gateway will fetch an attacker-chosen *public* URL server-side, an
    open-proxy-shaped capability, not an SSRF-to-internal one. That does not clear the
    FAIL bar (Golden Rule #5) — reporting it as SSRF to metadata/internal services
    would have been a spurious FAIL — so this stays a disclosure at WARN.

    PASS    — the endpoint is not enabled (the shipped default).
    WARN    — enabled, and ``images.allowUrl`` is not true: a remote, OpenAI-shaped
              ingress exists (anything reaching the gateway's HTTP surface can drive
              agent turns through it, outside whatever per-channel restrictions
              — allowed senders, DM policy — a configured channel would apply), but
              no server-side URL fetch.
    WARN    — enabled and ``images.allowUrl`` is true: same ingress, plus the gateway
              will fetch an attacker-chosen URL server-side (private/internal/cloud-
              metadata targets are blocked by the runtime unconditionally). The
              wording distinguishes a non-empty ``images.urlAllowlist`` (fetch scoped
              to named public hosts) from an absent/empty one (any public host).
    UNKNOWN — the config was not read, or ``chatCompletions``/``images`` is present
              but not an object.
    """
    unreadable = _config_unreadable("B358", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B358",
            UNKNOWN,
            "No config was read, so whether the gateway's OpenAI-compatible "
            "chat-completions endpoint is enabled could not be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    node = dig(cfg, "gateway.http.endpoints.chatCompletions")
    if node is not None and not isinstance(node, dict):
        return _finding(
            "B358",
            UNKNOWN,
            f"gateway.http.endpoints.chatCompletions is present but is not an object "
            f"(found {type(node).__name__}), so whether the endpoint is enabled could "
            "not be determined.",
            "Fix the gateway.http.endpoints.chatCompletions block in openclaw.json so "
            "it is a JSON object, then re-run the audit.",
            config_field_paths={"gateway.http.endpoints.chatCompletions"},
        )
    if dig(cfg, "gateway.http.endpoints.chatCompletions.enabled") is not True:
        return _finding(
            "B358",
            PASS,
            "gateway.http.endpoints.chatCompletions.enabled is absent or not true, so "
            "the OpenAI-compatible chat-completions endpoint is not served (the "
            "shipped default).",
            "Nothing to do; keep it off unless an OpenAI-compatible client "
            "integration genuinely needs it.",
        )
    images = dig(cfg, "gateway.http.endpoints.chatCompletions.images")
    if images is not None and not isinstance(images, dict):
        return _finding(
            "B358",
            UNKNOWN,
            "gateway.http.endpoints.chatCompletions.enabled is true, but its images "
            f"block is present and not an object (found {type(images).__name__}), so "
            "whether server-side image-URL fetching is enabled could not be "
            "determined.",
            "Fix the gateway.http.endpoints.chatCompletions.images block in "
            "openclaw.json so it is a JSON object, then re-run the audit.",
            config_field_paths={"gateway.http.endpoints.chatCompletions.images"},
        )

    reach = _gateway_http_reach(cfg, "this endpoint")
    if dig(cfg, "gateway.http.endpoints.chatCompletions.images.allowUrl") is True:
        allowlist = dig(cfg, "gateway.http.endpoints.chatCompletions.images.urlAllowlist")
        scoped = isinstance(allowlist, list) and bool(allowlist)
        scope_clause = (
            "scoped to an explicit images.urlAllowlist"
            if scoped
            else "with no images.urlAllowlist, so any public hostname is fetchable"
        )
        return _finding(
            "B358",
            WARN,
            "gateway.http.endpoints.chatCompletions.enabled is true and "
            f"images.allowUrl is true, {scope_clause}: an OpenAI-shaped request can "
            "pass an image_url and the gateway will fetch it server-side "
            "(private/internal/cloud-metadata targets are blocked unconditionally by "
            f"the gateway's own SSRF guard). Right now {reach}.",
            "Set images.urlAllowlist to the specific hostnames image URLs are "
            "expected to come from, or set images.allowUrl to false if server-side "
            "URL fetching is not needed (data URIs keep working either way).",
            config_field_paths={
                "gateway.http.endpoints.chatCompletions.images.allowUrl",
                "gateway.http.endpoints.chatCompletions.images.urlAllowlist",
            },
        )
    return _finding(
        "B358",
        WARN,
        "gateway.http.endpoints.chatCompletions.enabled is true: the gateway serves "
        "an OpenAI-compatible POST /v1/chat/completions endpoint, a remote ingress "
        f"that can drive agent turns outside any configured channel. Right now "
        f"{reach}.",
        "Keep this endpoint off unless an OpenAI-compatible client integration "
        "genuinely needs it, and keep the gateway behind auth (B2/B70).",
    )


def check_gateway_remote_ssh_host_key_policy(ctx: Context) -> Finding:
    """B359 (C-410) — gateway.remote.sshHostKeyPolicy: how THIS machine verifies the
    SSH host key when it connects OUT to a remote OpenClaw gateway over an SSH tunnel
    (the remote-gateway-link feature). Grounded on the installed dist
    (openclaw@2026.9.3, ``zod-schema-CTg_faEc.mjs:473``):
    ``union([literal("strict"), literal("openssh")]).optional()``. Default "strict"
    — corroborated by both the schema description ("'strict' requires an already
    trusted host key") and ``FIELD_PLACEHOLDERS["gateway.remote.sshHostKeyPolicy"]``
    (``schema-DbKC3IUo.mjs:2823``), which shows "strict" as the field's own example
    value.

    This is a CLIENT-side setting for the machine initiating the SSH tunnel — unlike
    B358/B360 it says nothing about whether THIS host's own gateway is exposed, so it
    does not use ``_gateway_http_reach``.

    PASS    — "strict" (the default) or absent.
    WARN    — "openssh": host-key verification is delegated to the effective OpenSSH
              configuration (``~/.ssh/config``, ``known_hosts``,
              ``StrictHostKeyChecking``) instead of requiring an already-trusted key —
              anything able to intercept the first connection to the remote gateway's
              address (DNS/routing spoofing) can MITM it undetected.
    UNKNOWN — present but neither known literal (a malformed/future value this audit
              cannot reason about), or the config was not read.
    """
    unreadable = _config_unreadable("B359", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B359",
            UNKNOWN,
            "No config was read, so the remote-gateway SSH host-key policy could not "
            "be determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    remote = dig(cfg, "gateway.remote")
    if remote is not None and not isinstance(remote, dict):
        return _finding(
            "B359",
            UNKNOWN,
            f"gateway.remote is present but is not an object (found "
            f"{type(remote).__name__}), so the SSH host-key policy could not be "
            "determined.",
            "Fix the gateway.remote block in openclaw.json so it is a JSON object, "
            "then re-run the audit.",
            config_field_paths={"gateway.remote"},
        )
    policy = dig(cfg, "gateway.remote.sshHostKeyPolicy")
    if policy is None or policy == "strict":
        return _finding(
            "B359",
            PASS,
            "gateway.remote.sshHostKeyPolicy is 'strict' (or unset, which defaults to "
            "'strict') — connecting to a remote gateway over SSH requires an already "
            "trusted host key.",
            "Nothing to do.",
        )
    if policy == "openssh":
        return _finding(
            "B359",
            WARN,
            "gateway.remote.sshHostKeyPolicy is 'openssh': host-key verification for "
            "the remote-gateway SSH tunnel is delegated to the effective OpenSSH "
            "configuration instead of requiring an already-trusted key. Anything "
            "able to intercept the first connection to the remote gateway's address "
            "(DNS/routing spoofing) can MITM it undetected.",
            "Set gateway.remote.sshHostKeyPolicy to 'strict' unless you "
            "specifically manage host-key trust through OpenSSH's own config/"
            "known_hosts and StrictHostKeyChecking.",
            config_field_paths={"gateway.remote.sshHostKeyPolicy"},
        )
    return _finding(
        "B359",
        UNKNOWN,
        f"gateway.remote.sshHostKeyPolicy is {policy!r}, neither 'strict' nor "
        "'openssh' — not a value this audit recognizes, so its effect could not be "
        "determined.",
        "Set gateway.remote.sshHostKeyPolicy to 'strict' (recommended) or "
        "'openssh'.",
        config_field_paths={"gateway.remote.sshHostKeyPolicy"},
    )


def check_control_ui_embed_sandbox(ctx: Context) -> Finding:
    """B360 (C-410) — gateway.controlUi.embedSandbox: the iframe sandbox policy for
    hosted Control UI embeds. Grounded on the installed dist (openclaw@2026.9.3,
    ``zod-schema-CTg_faEc.mjs:849-853``): ``union([literal("strict"),
    literal("scripts"), literal("trusted")]).optional()``. Default "scripts" per the
    schema description (``schema-DbKC3IUo.mjs:830``): "'strict' disables scripts,
    'scripts' allows interactive embeds while keeping origin isolation (default), and
    'trusted' adds `allow-same-origin` for same-site documents that intentionally
    need stronger privileges."

    "trusted" is the one value that removes origin isolation from an embedded
    iframe, so any XSS in whatever page hosts the embed reaches the Control UI's own
    origin — the operator's authenticated session. Same gateway-reachability
    disclosure as B358/B350 (``_gateway_http_reach``), since an outside document can
    only reach the embed at all when the gateway itself is reachable.

    PASS    — "strict", "scripts" (the default), or absent.
    WARN    — "trusted".
    UNKNOWN — present but none of the three known literals, or the config was not
              read.
    """
    unreadable = _config_unreadable("B360", ctx)
    if unreadable is not None:
        return unreadable
    cfg = ctx.config
    if not isinstance(cfg, dict) or not cfg:
        return _finding(
            "B360",
            UNKNOWN,
            "No config was read, so the Control UI embed sandbox policy could not be "
            "determined.",
            "Run the audit on the host where ~/.openclaw lives.",
            not_applicable=_surface_absent(ctx, LIMIT_DOMAIN_CONFIG),
        )
    control_ui = dig(cfg, "gateway.controlUi")
    if control_ui is not None and not isinstance(control_ui, dict):
        return _finding(
            "B360",
            UNKNOWN,
            f"gateway.controlUi is present but is not an object (found "
            f"{type(control_ui).__name__}), so the embed sandbox policy could not be "
            "determined.",
            "Fix the gateway.controlUi block in openclaw.json so it is a JSON "
            "object, then re-run the audit.",
            config_field_paths={"gateway.controlUi"},
        )
    mode = dig(cfg, "gateway.controlUi.embedSandbox")
    if mode is None or mode in ("strict", "scripts"):
        state = "unset, which defaults to 'scripts'" if mode is None else f"{mode!r}"
        return _finding(
            "B360",
            PASS,
            f"gateway.controlUi.embedSandbox is {state} — hosted Control UI embeds "
            "keep origin isolation from their embedding page.",
            "Nothing to do.",
        )
    if mode == "trusted":
        reach = _gateway_http_reach(cfg, "the Control UI — and any embed of it")
        return _finding(
            "B360",
            WARN,
            "gateway.controlUi.embedSandbox is 'trusted': hosted Control UI embeds "
            "get allow-same-origin, so an XSS in whatever page hosts the embed "
            "reaches the Control UI's own origin — the operator's authenticated "
            f"session. Right now {reach}.",
            "Set gateway.controlUi.embedSandbox to 'scripts' (the default) unless "
            "the embedding document is fully trusted and genuinely needs "
            "same-origin privileges.",
            config_field_paths={"gateway.controlUi.embedSandbox"},
        )
    return _finding(
        "B360",
        UNKNOWN,
        f"gateway.controlUi.embedSandbox is {mode!r}, not one of 'strict'/'scripts'/"
        "'trusted' — not a value this audit recognizes, so its effect could not be "
        "determined.",
        "Set gateway.controlUi.embedSandbox to 'strict', 'scripts' (recommended "
        "default), or 'trusted' only if genuinely needed.",
        config_field_paths={"gateway.controlUi.embedSandbox"},
    )


# B374 (C-526): the 9.4 "cloud ready workers" defaults, grounded verbatim
# against the INSTALLED 2026.9.4 dist (not the recon, which omits the cloudWorkers
# namespace entirely — see tests/grounded_schema_paths.txt / dist_verified_paths.txt).
# dist/service-DTQsk1L5.mjs's `createPreparedWorkerPool` (~:216-221):
#   target:   profile.readyWorkers ?? DEFAULT_READY_WORKERS
#   maxTotal: config?.preparedPool?.maxTotal ?? DEFAULT_MAX_TOTAL
# with (same file, ~:217-218) `DEFAULT_READY_WORKERS = 1` / `DEFAULT_MAX_TOTAL = 4` — and
# the schema's own help text (dist/zod-schema.cloud-workers-CfJaNmxt.mjs) says the same
# thing in prose ("Target ... (default: 1)" / "Gateway-wide cap ... (default: 4)").
_B374_DEFAULT_READY_WORKERS = 1
_B374_DEFAULT_MAX_TOTAL = 4


def check_cloudworkers_prepared_pool(ctx: Context) -> Finding:
    """B374 — cloudWorkers 9.4 prepared-pool: a default-on, warm,
    off-machine worker reserve.

    ``cloudWorkers`` provisions off-machine execution environments from a
    plugin-supplied provider (`CloudWorkerProfileShape.provider`: "Worker provider id
    registered by a plugin"). 9.4 added a PREPARED POOL on top of that: unless disabled,
    OpenClaw keeps ``readyWorkers`` machines (default 1, per eligible project/profile)
    running and warm, up to ``preparedPool.maxTotal`` (default 4, gateway-wide) — see the
    module comment above for the exact grounding.

    Gated, not universal. The pool only ever targets a nonzero count once a real
    ``cloudWorkers.profiles.<id>`` entry exists (the runtime's own gate:
    ``configured: Boolean(profile && normalizeCapabilityProviderId(profile.provider)
    === record.providerId)``) — a vanilla install with no cloud-worker plugin/profile
    gets nothing, hence UNKNOWN below rather than a blanket WARN on every config.

    WARN/advisory only (a reserve existing is not itself a
    hole, so no FAIL tier and no C-135 pass; unscored, mirroring B12/check_local_first).
    Each active reserve is a RUNNING remote machine — the 9.4 CHANGELOG's own words:
    "Ready workers incur provider running-machine charges until deleted" — held warm
    with the eligible project's source already prepared on it before any session binds,
    and eligibility reaches past the operator's own repos to "public GitHub repository
    sessions" per that same changelog, so a session against a public (not necessarily
    owned) repository can also cause a reserve to be provisioned.

    Deliberately config-only. 9.4 also added a state-DB table,
    ``node_worker_prepared_workspaces``, materializing ``workspace_dir``/``home_dir`` on
    disk for a prepared workspace. Verified NOT to apply here: that table lives under
    ``src/node-host/`` (`node-worker-prepared-workspace-store.ts`, bundled into
    `dist/daemon-G2kqiA9m.mjs` in 2026.9.5) and is absent from this machine's own
    ``~/.openclaw/state/openclaw.sqlite`` (confirmed absent on 2026.9.4, and again on
    2026.9.5 on 2026-09-19, on a live gateway that dispatches, but does not itself run as, a
    cloud worker node) — it
    materializes on the REMOTE node's own state DB, never the local gateway's. So it never lands in
    ``skillprovenance.py``'s ``WORKSPACE_DIRS`` or the derived-agent-workspace invariant
    ``tests/test_b610_derived_agent_workspaces.py`` pins, and this check has no local
    on-disk row to read; only ``worker_environments`` (local, no workspace_dir/home_dir
    columns) tracks anything about these environments on the audited machine, and
    reading it is a separate, larger state-DB-reader piece of work, out of scope here.
    """
    unreadable = _config_unreadable("B374", ctx)
    if unreadable is not None:
        return unreadable

    cfg = ctx.config
    profiles = dig(cfg, "cloudWorkers.profiles")
    valid_profiles = (
        {pid: prof for pid, prof in profiles.items() if isinstance(prof, dict)}
        if isinstance(profiles, dict)
        else {}
    )
    if not valid_profiles:
        return _finding(
            "B374",
            UNKNOWN,
            "cloudWorkers.profiles is not configured, so no cloud worker provider is "
            "available and the 9.4 prepared-pool reserve cannot be active.",
            "—",
        )

    max_total_raw = dig(cfg, "cloudWorkers.preparedPool.maxTotal")
    max_total = (
        max_total_raw
        if isinstance(max_total_raw, (int, float))
        and not isinstance(max_total_raw, bool)
        and max_total_raw >= 0
        else None
    )
    effective_max_total = max_total if max_total is not None else _B374_DEFAULT_MAX_TOTAL

    if effective_max_total == 0:
        return _finding(
            "B374",
            PASS,
            f"cloudWorkers.preparedPool.maxTotal is 0 — the gateway-wide prepared-worker "
            f"reserve is disabled ({len(valid_profiles)} cloud worker profile(s) "
            "configured).",
            "Keep it at 0 unless a warm reserve is genuinely wanted.",
        )

    active, disabled, evidence = [], [], []
    for pid in sorted(valid_profiles):
        prof = valid_profiles[pid]
        rw_raw = prof.get("readyWorkers")
        explicit = (
            isinstance(rw_raw, (int, float))
            and not isinstance(rw_raw, bool)
            and rw_raw >= 0
        )
        rw = rw_raw if explicit else _B374_DEFAULT_READY_WORKERS
        if rw > 0:
            active.append(pid)
            shown = str(rw) if explicit else f"unset (defaults to {rw})"
            evidence.append(f"profile '{pid}': readyWorkers={shown} — reserve active")
        else:
            disabled.append(pid)
            evidence.append(f"profile '{pid}': readyWorkers=0 — reserve disabled")

    if not active:
        return _finding(
            "B374",
            PASS,
            "Every configured cloud worker profile disables its ready reserve "
            f"(readyWorkers: 0): {', '.join(disabled)}.",
            "Keep readyWorkers at 0 on profiles that should not pre-warm a reserve.",
            evidence,
        )

    return _finding(
        "B374",
        WARN,
        f"cloudWorkers prepared-pool reserve is active for {len(active)} profile(s) "
        f"({', '.join(active)}), gateway-wide cap {effective_max_total}: each is a "
        "RUNNING off-machine worker held warm with the eligible project's source "
        "already prepared on it before any session binds, so it keeps incurring "
        "provider running-machine charges and stays a live remote target until deleted "
        "— and this is the DEFAULT posture (readyWorkers defaults to 1 per profile) "
        "unless explicitly disabled.",
        "Set cloudWorkers.profiles.<id>.readyWorkers: 0 on profiles that should not "
        "pre-warm a reserve, or cloudWorkers.preparedPool.maxTotal: 0 to disable the "
        "gateway-wide reserve; either stops new reserves while preserving snapshot "
        "reuse and active sessions.",
        evidence,
    )
