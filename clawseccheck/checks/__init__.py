"""Check engine: Block A (Lethal Trifecta) + Block B (hardening) + advisory.

Every check is read-only and grounded on real OpenClaw config fields
(see docs/specs/openclaw-audit-skill-spec.md v2). Heuristics are conservative:
we FAIL only on positive evidence, WARN on likely-insecure defaults, and
UNKNOWN when the config cannot tell us (excluded from score — honesty).
"""

from __future__ import annotations

import base64
import binascii
import html
import ipaddress
import json
import os
import re
import shutil
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlparse

from .. import attest as _attest
from .. import trajectory as _trajectory
from ..catalog import (
    ATTESTED,
    BY_ID,
    CRITICAL,
    FAIL,
    HIGH,
    LOW,
    MEDIUM,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..scanbudget import (
    DEFAULT_AUDIT_BUDGET_S,
    DEFAULT_CHECK_BUDGET_S,
    ScanBudgetExceeded,
    audit_budget_exceeded,
    audit_deadline,
    check_deadline,
)
from ..collector import (
    _MAX_BYTES_PER_SKILL,
    _OWN_SKILL_NAMES,
    BOOTSTRAP_FILES,
    SKILL_DIRS,
    Context,
    _read_skill_text,
    classify_bytes,
    dig,
    read_skill_python,
    read_skill_shell,
    read_skill_js,
)
from ..safeio import walk_dir_safely
from ..skillast import (
    analyze_javascript,
    analyze_python,
    analyze_python_package,
    analyze_shell,
)
from ..skillast import simulate_effects as _simulate_effects
from ..textnorm import (
    confusable_in_ascii_context,
    normalize_for_scan,
    obfuscation_signals,
)

# I-022 R2: shared leaf — helpers/constants reused across topic modules and by
# sibling modules. Imported explicitly (not star) so every private stays importable
# via the aggregator (CLAUDE.md §3.1-a: no __all__ here).
from . import _shared
from ._shared import (
    _is_posix,
    _perms_loose,
    LOOPBACK,
    EXPOSED_BINDS,
    parse_bind_host,
    SECRET_KEY_RE,
    SECRET_PATTERNS,
    INPUT_TOOL_HINTS,
    SENSITIVE_TOOL_HINTS,
    OUTBOUND_TOOL_HINTS,
    _meta,
    _finding,
    _channels,
    _UNTRUSTED_INPUT_POLICIES,
    _open_channels,
    _external_input_channels,
    _MAX_WALK_DEPTH,
    _secret_paths,
    _enabled_tools,
    _hint,
    _POWERFUL_PROFILES,
    _profile_is_powerful,
    _real_exec_enabled,
    _web_fetch_enabled,
    _active_channels,
    _untrusted_input_channels,
    _agent_legs,
    _LEG_KEYS,
    _has_approval_gate,
    _is_public_ip,
    _OWN_ENGINE_MARKERS,
    _is_own_source,
    _DESTRUCTIVE_HINTS,
    _agent_is_powerful,
    _TIER_NAME,
    _safe_mtime,
)

from ._shared import (_plugins,)
from ._host import (
    _HOST_ATTEST_HINTS,
    _HOST_CLASS_LABEL,
    _MONITORING_HINTS,
    _attested_host_monitors,
    _host_finding,
    check_audit_log,
    check_monitoring,
    check_host_network_ids,
    check_host_audit,
    check_host_file_integrity,
    check_host_edr,
    check_host_firewall,
    check_host_egress_posture,
    check_incident_readiness,
)

from ._shared import (_JSONL_SCAN_CAP, _MCP_REMOTE_TRANSPORTS, _custom, _mcp_has_remote, _mcp_servers, _mcp_url_is_local, _read_jsonl_tail,)
from ._egress import (
    _EXT_SKILL_HINTS,
    _USER_CONTENT_HOSTS,
    _weak_allowlist_entries,
    check_browser_ssrf,
    check_cachetrace_redaction,
    check_config_audit_log,
    check_config_health_integrity,
    check_data_atrest,
    check_discovery_mdns_mode,
    check_egress,
    check_egress_inventory,
    check_leak,
    check_webfetch_redirects,
)

from ._shared import (_trifecta_legs,)
from ._agents import (
    _B21_OBEY_RE,
    _B21_SAFE_STANCE_RE,
    _B21_SOURCE_RE,
    _B30_HISTORY_KEY,
    _B30_NAME_MATCH_KEY,
    _DELEGATION_TIER,
    _WEB_FETCH_SKILL_HINTS,
    _b21_has_trust_boundary,
    _has_subagents,
    _reassembly,
    check_agent_separation,
    check_delegation_reassembly,
    check_multiagent_exposure,
    check_sender_identity,
    check_session_visibility,
    check_subagent_spawn_limits,
    check_subagents,
    check_subagents_allow_agents,
    check_tool_output_trust,
    check_untrusted_context,
)

from ._capability import (
    _AUTO_GATE_BLAST,
    _B31_BYPASS_CANDIDATES,
    _B31_WRITE_CLASS,
    _B71_INEFFECTIVE_RE,
    _FS_WRITE_TOOL_HINTS,
    _approval_bypass_actors,
    _b31_collect_deny_lists,
    _has_heartbeat_signal,
    check_attestation_mismatch,
    check_capability_blast_radius,
    check_declared_effective_proven,
    check_effective_tools,
    check_exec_applypatch_workspace,
    check_exec_strict_inline_eval,
    check_fs_write_exposure,
    check_node_denycommands_ineffective,
    check_path_safety,
)

from ._config import (
    CLOUD_PROVIDERS,
    _B32_CONTROL_PLANE_TOOLS,
    _C015_EXTRA_SECRET_PATTERNS,
    _C015_MAX_BYTES,
    _C015_MAX_SCAN_FILES,
    _C015_TEXT_EXTS,
    _DANGER_AGENT_SANDBOX,
    _DANGER_FIXED,
    _MISSING_LEG_ACTIVATORS,
    _c015_candidate_files,
    _c015_has_secret,
    _capabilities_attested,
    _distance_note,
    _meaningful_tool_surface,
    _model_names,
    _multi_agent_note,
    _peragent_sandbox_evidence,
    _trusted_proxies_ok,
    check_control_plane_mutation,
    check_controlui_origins,
    check_credential_blast_radius,
    check_dangerous_overrides,
    check_gateway,
    check_gateway_rate_limit,
    check_least_privilege,
    check_local_first,
    check_proxy_header_forging,
    check_sandbox,
    check_secrets,
    check_secrets_at_rest_home,
    check_tls,
    check_trifecta,
    check_trustedproxy_loopback,
)

from ._shared import (INJECTION_PATTERNS, _FM_BLOCK_BARE_RE, _FM_BLOCK_HEADERED_RE, _HOOK_EXEC_RE, _skill_frontmatter_block,)
from ._lifecycle import (
    _APPROVAL_BYPASS_RE,
    _CRITICAL_BOOTSTRAP,
    _FLOATING_REF_RE,
    _HOOK_POLICY_FIX_VERSION,
    _IDENTITY_TARGETS,
    _KNOWN_ADVISORIES,
    _NON_ENTRY_KEYS,
    _PINNED_REF_RE,
    _POSTINSTALL_RE,
    _SOFT_BOOTSTRAP,
    _VERSION_LEADING_INTS_RE,
    _iter_entries,
    _parse_version,
    _writable_identity_files,
    _writable_skill_dirs,
    check_approval_bypass,
    check_autonomy,
    check_backups,
    check_bootstrap_injection,
    check_bootstrap_write_protection,
    check_cron_scheduler,
    check_hook_policy_bypass,
    check_human_approval,
    check_install_policy,
    check_known_vulns,
    check_memory_poisoning,
    check_offboarding_hygiene,
    check_self_modification,
    check_session_approval_policy,
    check_supply_chain,
    check_update_pinning,
    check_version,
)

from ._content import (
    _ANY_HEADING_RE,
    _B102_EDGE_RUN_RE,
    _B102_EDGE_SAMPLE,
    _B102_MAX_ADJACENCY_JOINS,
    _B102_MIN_EDGE_LEN,
    _B58_BASE64_RE,
    _B58_CSS_RE,
    _B58_HIDDEN_STYLE_RE,
    _B58_HIDDEN_TAG_RE,
    _B58_HTML_COMMENT_RE,
    _B58_JS_HEX_RE,
    _B58_JS_OCTAL_RE,
    _B58_JS_UHEX_RE,
    _B58_JS_UNI_RE,
    _B58_URL_OR_EMAIL_RE,
    _B59_HTML_ATTR_RE,
    _B59_HTML_TAG_RE,
    _B59_IMG_TEXT_ATTR_RE,
    _B59_MD_IMG_RE,
    _B59_MD_LINK_RE,
    _B60_SELF_REF_RE,
    _B60_TARGET_AGENT_RE,
    _B60_TARGET_EVERY_RE,
    _B60_VERB_RE,
    _B60_WINDOW,
    _B61_CONFIG_PATH_RE,
    _B61_EXFIL_SINK_RE,
    _B61_READ_VERB_RE,
    _B61_WINDOW,
    _B62_DESCRIPTION_RE,
    _B62_EXPECTED,
    _B62_HIGH_SURPRISE,
    _B62_IMPORT_CRED_RE,
    _B62_IMPORT_EXEC_RE,
    _B62_IMPORT_NET_RE,
    _B62_IMPORT_WRITE_RE,
    _B62_PERMISSIVE_KEYWORDS,
    _B63_ACTION_RE,
    _B63_DECODED_SUPPRESS_RE,
    _B63_SECRECY_RE,
    _B63_SEMANTIC_WINDOW,
    _B63_SOFT_SUPPRESS_RE,
    _B63_WINDOW,
    _B64URL_BLOB_RE,
    _B64_ACTIONABLE_CONT_RE,
    _B64_BLOB_RE,
    _B64_HIGH_CONFIDENCE_RE,
    _B64_QUOTE_OPEN_RE,
    _B64_REPORT_FRAME_RE,
    _B64_REPORT_WINDOW,
    _B64_WEAK_SIGNAL_RE,
    _B65_ACTION_RE,
    _B65_DELAY_RE,
    _B65_QUERY_RE,
    _B65_TRIGGER_RE,
    _B65_WINDOW,
    _B66_ROLE_START_RE,
    _B66_WEAKEN_RE,
    _B66_WINDOW,
    _B67_CHANNEL_SRC_RE,
    _B67_TRUST_RE,
    _B67_WINDOW,
    _B74_DEFENSIVE_FRAME_RE,
    _B74_FALSE_PROVENANCE_RE,
    _B74_ROLE_BLOCK_RE,
    _B74_TURN_DIRECTIVE_RE,
    _B95_UNPINNED_PKG_RE,
    _B98_DANGEROUS_PRIMITIVE_RE,
    _BROAD_NEGATION_RE,
    _BROAD_NEGATION_WINDOW,
    _CLICKFIX_IMPERATIVE_RE,
    _CLICKFIX_PROXIMITY_WINDOW,
    _CLICKFIX_REMOTE_FETCH_RE,
    _CRED_RE,
    _DECODED_BAD_RE,
    _DEFENSIVE_HEADING_RE,
    _DEP_PKG_NAME_RE,
    _EVENT_HOOK_PATH_RE,
    _EXFIL_RE,
    _FENCE_ANNOTATION_RE,
    _FENCE_OPEN_RE,
    _FM_CROSS_SKILL_SQUAT_RE,
    _FM_METADATA_KEY_RE,
    _FM_METADATA_LINE_RE,
    _FM_TAG_RE,
    _FM_YAML_BOOL_RE_CACHE,
    _HOOK_ENV_READ_RE,
    _HOOK_MINIFIED_LINE,
    _HOOK_MUTATE_RE,
    _HOOK_NET_SINK_RE,
    _IMMEDIATE_NEGATOR_RE,
    _INSTALL_HEADING_RE,
    _INSTALL_IPV4_HOST_RE,
    _INSTALL_URL_FIELDS,
    _IOC_ONION_RE,
    _KNOWN_NAMES,
    _LIFECYCLE_HOOK_RE,
    _MANIFEST_HEADER_RE,
    _NEGATION_RE,
    _NEGATION_WINDOW,
    _PKG_JSON_DEP_RE,
    _PKG_JSON_UNPINNED_RE,
    _PKG_JSON_UNPINNED_VER_RE,
    _PTH_IMPORT_LINE_RE,
    _PYPROJECT_DEP_LINE_RE,
    _PYPROJECT_DEP_SECTION_RE,
    _REQS_FILE_RE,
    _REQ_PINNED_SUFFIX_RE,
    _REQ_UNPINNED_RE,
    _SENSITIVE_BASENAMES,
    _SENSITIVE_BROWSER_SEGMENTS,
    _SENSITIVE_PATH_SEGMENTS,
    _SENTENCE_BREAK_RE,
    _SETUP_CMDCLASS_RE,
    _SITECUSTOMIZE_FILENAMES,
    _SKILL_FRONTMATTER_NAME_RE,
    _SKILL_TOOLS_LINE_RE,
    _SQUAT_STRIP_PREFIXES,
    _SQUAT_STRIP_SUFFIXES,
    _SYMLINK_SCAN_CAP,
    _TELEMETRY_URL_KEY_RE,
    _TRUST_WIDENING_FILE_EXTS,
    _TRUST_WIDENING_KV_RE,
    _TYPOSQUAT_MIN_KNOWN_LEN,
    _XFILE_B64_FRAGMENT_RE,
    _XFILE_DECODE_SINK_RE,
    _XFILE_LITERAL_CAP,
    _XFILE_STRING_LITERAL_RE,
    _XFILE_WINDOW_MAX_FRAGS,
    _b102_leading_run,
    _b102_trailing_run,
    _b58_base64_variants,
    _b58_decode_html_entities,
    _b58_decode_js_css,
    _b58_decode_percent,
    _b58_decode_variants,
    _b58_extract_actionable,
    _b58_hidden_segments,
    _b59_markdown_url,
    _b59_split_srcset,
    _b59_url_has_data_query,
    _b60_has_propagation,
    _b62_actual_families,
    _b62_classify_category,
    _b62_extract_declaration,
    _b62_surprising_families,
    _b63_decoded_actionable,
    _b63_scan,
    _b64_actionable_continuation,
    _b64_classify,
    _b64_reported_or_quoted,
    _b65_scan,
    _b66_scan,
    _b67_has_source_contract,
    _b74_forged_turn_has_directive,
    _b74_turn_content,
    _candidate_tokens,
    _check_markdown_image_exfil,
    _check_unicode_obfuscation,
    _decode_codepoint,
    _defensive_context,
    _defensive_section,
    _dep_names_in_skill,
    _enumerate_symlinks,
    _fence_is_annotated,
    _fence_ranges,
    _fm_metadata_obj,
    _fm_metadata_obj_multiline,
    _fm_tag_is_suspicious,
    _fm_yaml_bool,
    _frontmatter_name,
    _has_cred_exfil_cross_skill,
    _in_fence,
    _install_entry_findings,
    _install_host_is_public_ip,
    _install_url_target,
    _is_code_example,
    _levenshtein,
    _nearest_heading,
    _negation_context,
    _negation_governs_trigger,
    _normalize_for_squat,
    _obf_clip,
    _reassembles_to_payload,
    _scan_b59_html_attr,
    _sentence_scoped_segment,
    _skill_declared_tools,
    _skill_is_unreachable,
    _squat_hits,
    _symlink_scan_roots,
    _symlink_target_sensitive,
    _try_b64_decode,
    _under_defensive_heading,
    _under_install_heading,
    _unpinned_deps_in_skill,
    _whole_text_is_defensive,
    check_agent_snooping,
    check_capability_intent_mismatch,
    check_clickfix_setup_section,
    check_conditional_sleeper_trigger,
    check_config_trust_widening,
    check_cross_file_boundary_payload,
    check_cross_file_payload,
    check_cross_skill_combined_effect,
    check_dependency_confusion,
    check_dormant_capability,
    check_dynamic_dispatch_obfuscation,
    check_event_hook_interceptor,
    check_forged_provenance,
    check_frontmatter_hygiene,
    check_image_attr_injection,
    check_import_from_writable,
    check_install_directive_supply_chain,
    check_instruction_hierarchy_override,
    check_lifecycle_hooks_extended,
    check_manifest_absent,
    check_markdown_image_exfil,
    check_per_source_trust_contracts,
    check_persona_jailbreak,
    check_prompt_self_replication,
    check_pth_persistence,
    check_silent_instruction,
    check_symlink_escape,
    check_trigger_homoglyph,
    check_unicode_obfuscation,
    check_unsafe_deserialization,
)

from ._vet import (
    SKILL_CONTENT_RING,
    _AGENT_CONTEXT_FILES_RE,
    _AUTONOMY_RE,
    _CONCAT_STRIP_RE,
    _CRON_PERSIST_RE,
    _DAEMONIZE_RE,
    _DESTRUCTIVE_CMD_RE,
    _FM_HOMEPAGE_RE,
    _HTML_TAG_RE,
    _IOC_IPURL_RE,
    _LOCAL_SINK_CHANNELS,
    _PERSIST_WINDOW,
    _PERSIST_WRITE_VERB_RE,
    _PIPE_SHELL_RE,
    _PLUGIN_MANIFEST,
    _PS_ENC_RE,
    _QUOTED_CONCAT_RE,
    _REPUTABLE_INSTALL_HOSTS,
    _RUNTIME_FETCH_NOUN_RE,
    _RUNTIME_FETCH_URL_RE,
    _RUNTIME_FETCH_VERB_RE,
    _RUNTIME_FETCH_WINDOW,
    _SAFETY_EXAMPLE_RE,
    _SAFETY_EXAMPLE_WINDOW,
    _SELF_MOD_RE,
    _SINK_LOG_RE,
    _SINK_REPORT_RE,
    _SINK_TEMPFILE_RE,
    _SKILL_BROAD_TRIGGER_RE,
    _SKILL_CRIT,
    _SKILL_HIGH,
    _SKILL_INJECTION,
    _SKILL_LOCAL_CHAIN_RE,
    _SKILL_PERSISTENCE_HIGH,
    _SKILL_PERSISTENCE_WARN,
    _SKILL_SAFETY_SUBVERSION,
    _SOURCE_GIT_RE,
    _SOURCE_IP_RE,
    _SOURCE_KNOWN_BAD,
    _SOURCE_KNOWN_GOOD,
    _SOURCE_PASTE_HOSTS,
    _TOOL_FAMILY,
    _URL_HOST_RE,
    _VET_MERGE_RANK,
    _WS_RE,
    _agent_config_write_hits,
    _blank_fences,
    _decoded_payloads,
    _has_cred_exfil_outside_fence,
    _in_example_context,
    _local_sink_exfil_hits,
    _locate_plugin_root,
    _parse_source_target,
    _powershell_encoded_payloads,
    _run_content_ring,
    _runtime_fetch_matches,
    _skill_own_host,
    _skill_tool_overgrant,
    _url_matches_own_host,
    check_installed_skills,
    detect_vet_type,
    vet_skill,
    vet_source,
)


# -- A1-local capability detection ------------------------------------------------
# These enrich the trifecta reading WITHOUT widening the shared _enabled_tools /
# _external_input_channels / _channels helpers, which ~15 other checks rely on.
# Keeping the broader, more aggressive reading local to A1 (and B46, which shares
# _trifecta_legs) bounds the blast radius of the fix.


# ---------- F-022: typosquatting detection for skill / dependency names ----------
# Detects supply-chain impersonation via ASCII edit-distance (OWASP AST02/AST04).
# Distinct from C-038 which catches Unicode homoglyphs in MCP server names.
# Severity: WARN (heuristic — near-miss name is suspicious, not proof).


# C-040: Persistence / rogue-agent detectors (SkillSpector RA1–RA2 parity).
#
# A skill that establishes PERSISTENCE on the host — rewriting its own code, injecting
# instructions into known agent-context files, installing cron/startup jobs, or
# daemonizing itself — poses a distinct threat from B61 (cross-agent config READING)
# and F-005 (data exfiltration): it survives removal / agent restarts and turns the
# host into a persistent beachhead.
#
# HIGH (hard FAIL alongside the rest of _SKILL_HIGH):
#   - self-modification:      a skill writing to __file__ at runtime
#   - agent-config injection: writing to known agent-context files (SOUL.md, MEMORY.md,
#                              CLAUDE.md, AGENTS.md, .claude/settings.json, openclaw.json,
#                              ~/.bashrc / ~/.zshrc / ~/.profile)
#   - cron/startup install:   crontab -e/-l, @reboot, systemctl enable, launchctl load,
#                              /etc/cron.* or ~/Library/LaunchAgents writes
#
# WARN (lower-confidence, backgrounding / daemonize):
#   - nohup … &, disown, setsid — a skill detaching a process from the terminal
#
# Conservative gating: a skill that merely writes to its OWN data file (open("out.json","w"))
# and mentions "cron" in documentation prose must stay clean.  The self-mod pattern fires
# ONLY when the write target is literally `__file__`; the agent-config pattern fires ONLY
# when a known context-file NAME appears in a write-mode open/write_text call; the cron
# pattern fires on scheduling verbs + cron paths, not bare cron mentions.
#
# C-041 _is_code_example is applied so documented anti-patterns stay clean.


_MANIFEST_FILENAMES = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "constraints.txt",
        "package.json",
        "pyproject.toml",
    }
)


# ---------- C-041: code-example false-positive reducer ----------
# Fenced code blocks (``` or ~~~) in Markdown skill prose that DOCUMENT a dangerous
# pattern (e.g. a security skill's own README showing "curl … | sh" as a "don't do
# this" example) must not cause B13 to FAIL.  We compute fence spans once per blob,
# then check whether a regex match's start position falls inside a fence or near an
# explicit negation-context marker.  Conservative: only neutralise when the evidence
# is clearly illustrative, not live instruction.


def _suspicious_pipe_hosts(blob: str) -> list[str]:
    hosts = []
    for host in _PIPE_SHELL_RE.findall(blob):
        h = host.lower()
        # exact host or a real subdomain only — NOT a lookalike suffix
        # (e.g. "evilastral.sh" must NOT match "astral.sh").
        if not any(h == r or h.endswith("." + r) for r in _REPUTABLE_INSTALL_HOSTS):
            hosts.append(host)
    return hosts


def _has_cred_exfil(blob: str) -> bool:
    """A single line that touches a secret path AND ships it outward."""
    return any(_CRED_RE.search(ln) and _EXFIL_RE.search(ln) for ln in blob.splitlines())


# ---------- vet_plugin: pre-install vet for OpenClaw plugins (E-020 / F-071) ----------
# A plugin is a CONTAINER: an openclaw.plugin.json manifest + bundled skills + JS/TS
# runtime code + npm packaging. This engine adds only the plugin-SPECIFIC manifest and
# packaging checks and DISPATCHES bundled content to the existing engines (vet_skill per
# bundled skill dir, vet_mcp per embedded MCP spec file) — never a second analyzer.
# Grounding: every manifest / package.json field read here is documented in the
# workspace recon doc §11 (openclaw-schema-recon.md, C-140).

# Packaging/metadata JSON that is never an embedded MCP server spec.
_PLUGIN_MCP_SKIP = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        _PLUGIN_MANIFEST,
        "tsconfig.json",
        "jsconfig.json",
    }
)
# Directories never swept inside a plugin: third-party deps + VCS/cache noise. The
# node_modules exclusion is disclosed as a coverage note, not silently applied.
_PLUGIN_SKIP_DIRS = frozenset({"node_modules", ".git", "__pycache__"})
_PLUGIN_FILE_CAP = 400  # B-074: a cap hit is disclosed and downgrades to UNKNOWN
_PLUGIN_SNIFF_BYTES = 512
_VET_RANK_STATUS = {3: FAIL, 2: WARN, 1: UNKNOWN, 0: PASS}


def _plugin_finding(severity, status, detail, fix, ev=None) -> Finding:
    return Finding(
        "PLUGIN-VET",
        "Plugin pre-install vet",
        severity,
        status,
        detail,
        fix,
        "Plugin Trust",
        False,
        ev or [],
    )


def vet_plugin(path: str | Path) -> Finding:
    """Vet an OpenClaw plugin BEFORE installing it (container-dispatcher).

    Plugin-specific checks (manifest sanity, npm lifecycle scripts, dependency
    pinning, native-executable stowaways) run here; bundled skills are dispatched to
    vet_skill() — they land on the skill auto-load surface via the
    ~/.openclaw/plugin-skills symlink farm — and embedded MCP server specs to
    vet_mcp(). Plugin runtime code is JS/TS and is NOT deeply analyzed (design
    decision D2); that limit is disclosed in the evidence, never hidden by a PASS.
    """
    import json as _json

    p = Path(str(path)).expanduser()
    if not p.exists():
        return _plugin_finding(
            HIGH,
            UNKNOWN,
            f"no plugin found at {p}",
            f"Point --vet-plugin at a plugin root (a dir carrying {_PLUGIN_MANIFEST}).",
        )
    root = _locate_plugin_root(p)
    if root is None:
        return _plugin_finding(
            HIGH,
            UNKNOWN,
            f"not an OpenClaw plugin: no {_PLUGIN_MANIFEST} found under {p}",
            "A plugin root carries openclaw.plugin.json; for a skill directory use --vet.",
        )
    try:
        manifest = _json.loads(
            (root / _PLUGIN_MANIFEST).read_text(encoding="utf-8", errors="replace")
        )
    except (OSError, ValueError) as exc:
        return _plugin_finding(
            HIGH,
            UNKNOWN,
            f"could not parse {_PLUGIN_MANIFEST}: {exc}",
            "Inspect the manifest manually — the host would refuse this plugin too.",
        )
    if not isinstance(manifest, dict):
        return _plugin_finding(
            HIGH,
            UNKNOWN,
            f"{_PLUGIN_MANIFEST} is not a JSON object",
            "Inspect the manifest manually — the host would refuse this plugin too.",
        )

    warns: list[str] = []
    notes: list[str] = []  # coverage / informational evidence — never verdict-moving
    subs: list[Finding] = []  # dispatched engine findings (vet_skill / vet_mcp)

    # -- manifest sanity (required fields per recon §11.2; host blocks activation on error)
    pid = manifest.get("id")
    if not isinstance(pid, str) or not pid or not isinstance(manifest.get("configSchema"), dict):
        warns.append(
            "invalid manifest: required id/configSchema missing or wrong type — "
            "the host treats this as a plugin error and blocks activation"
        )
    pid = pid if isinstance(pid, str) and pid else root.name

    # -- npm packaging (recon §11.3/§11.4)
    pkg: dict = {}
    pkg_path = root / "package.json"
    if pkg_path.is_file():
        try:
            loaded = _json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            loaded = None
        if isinstance(loaded, dict):
            pkg = loaded
        else:
            warns.append("unreadable/unparseable package.json — npm packaging not assessed")
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    lifecycle = [k for k in ("preinstall", "install", "postinstall") if k in scripts]
    if lifecycle:
        warns.append(
            "npm lifecycle script(s) declared: "
            + ", ".join(lifecycle)
            + " — `openclaw plugins install` runs npm with --ignore-scripts, so "
            "these only ever execute for manual `npm install` victims"
        )
    deps = pkg.get("dependencies") if isinstance(pkg.get("dependencies"), dict) else {}
    # A missing lockfile is NOT a warn: bundled host extensions legitimately ship exact
    # pins with no per-plugin lockfile (verified on the 66-plugin real fleet — 21 would
    # have false-WARNed). Only *floating* version ranges are an actionable signal.
    if (
        deps
        and not (root / "npm-shrinkwrap.json").is_file()
        and not (root / "package-lock.json").is_file()
    ):
        notes.append(
            f"coverage: {len(deps)} runtime dependency(ies) without a lockfile "
            "in the package — transitive pins not verifiable here"
        )
    floating = sorted(
        f"{n}@{v}"
        for n, v in deps.items()
        if isinstance(v, str)
        and (v.strip().startswith(("^", "~", ">", "<", "*")) or v.strip() in ("latest", ""))
    )
    if floating:
        extra = f" (+{len(floating) - 4} more)" if len(floating) > 4 else ""
        warns.append("floating dependency version(s): " + ", ".join(floating[:4]) + extra)

    # -- coverage disclosure (D2): JS/TS runtime entry points are outside this vet's depth
    oc = pkg.get("openclaw") if isinstance(pkg.get("openclaw"), dict) else {}
    entries: list[str] = []
    for key in ("extensions", "runtimeExtensions"):
        val = oc.get(key)
        if isinstance(val, list):
            entries.extend(str(x) for x in val)
    if entries:
        notes.append(
            "coverage: plugin runtime code is JS/TS ("
            + ", ".join(entries[:3])
            + ") — not deeply analyzed by this vet; review the entry files before trusting"
        )
    notes.append("coverage: node_modules/ (third-party npm deps) excluded from the content scan")
    npm_spec = dig(pkg, "openclaw.install.npmSpec")
    if isinstance(npm_spec, str) and npm_spec and "@" not in npm_spec.lstrip("@"):
        notes.append(
            f"install spec is a bare package name ({npm_spec}) — resolves to latest at install time"
        )

    # -- bundled skills -> vet_skill (the plugin-skills auto-load surface, recon §11.1)
    skill_dirs: list[Path] = []
    try:
        root_res = root.resolve()
    except OSError:
        root_res = root
    skills_field = manifest.get("skills")
    if isinstance(skills_field, list):
        for entry in skills_field:
            d = root / str(entry)
            try:
                escaped = not d.resolve().is_relative_to(root_res)
            except OSError:
                escaped = True
            if escaped:
                warns.append(f"manifest skills entry escapes the plugin root: {str(entry)!r}")
                continue
            if not d.is_dir():
                notes.append(f"manifest skills entry not present in the package: {str(entry)!r}")
                continue
            if (d / "SKILL.md").is_file():
                skill_dirs.append(d)
            else:
                kids = [c for c in sorted(d.iterdir()) if c.is_dir() and not c.is_symlink()]
                skill_dirs.extend(kids if kids else [d])
    for sd in skill_dirs:
        try:
            sf = vet_skill(sd)
        except Exception:  # noqa: BLE001 — a dispatched engine must never break the vet
            warns.append(f"bundled skill {sd.name!r} could not be vetted")
            continue
        sf.detail = f"[bundled skill {sd.name!r}] {sf.detail}"
        subs.append(sf)

    # -- capped tree sweep (skips node_modules; symlinks never followed) for embedded
    #    MCP specs and native-executable stowaways outside the dispatched skill dirs
    truncated = False
    swept: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _PLUGIN_SKIP_DIRS)
        for fn in sorted(filenames):
            fp = Path(dirpath) / fn
            if fp.is_symlink():
                continue
            swept.append(fp)
            if len(swept) >= _PLUGIN_FILE_CAP:
                truncated = True
                break
        if truncated:
            break
    if truncated:
        notes.append(
            f"scan hit the {_PLUGIN_FILE_CAP}-file cap — files beyond the cap were NOT scanned"
        )

    def _under_skills(fp: Path) -> bool:
        return any(sd in fp.parents for sd in skill_dirs)

    for fp in swept:
        if _under_skills(fp):
            continue  # bundled-skill content already dispatched to vet_skill above
        if fp.suffix == ".json" and fp.name not in _PLUGIN_MCP_SKIP:
            try:
                data = _json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = None
            servers = None
            if isinstance(data, dict):
                servers = (
                    data.get("mcpServers")
                    if isinstance(data.get("mcpServers"), dict)
                    else dig(data, "mcp.servers")
                )
            if isinstance(servers, dict) and servers:
                try:
                    mcp_findings = vet_mcp(fp)
                except Exception:  # noqa: BLE001 — a dispatched engine must never break the vet
                    mcp_findings = []
                for mf in mcp_findings:
                    mf.detail = f"[embedded MCP spec {fp.name}] {mf.detail}"
                    subs.append(mf)
        try:
            size = fp.stat().st_size
            with open(fp, "rb") as fh:
                head = fh.read(_PLUGIN_SNIFF_BYTES)
        except OSError:
            continue
        _cls, fmt = classify_bytes(head, size)
        if fmt in ("ELF", "PE", "class") or (fmt or "").startswith("Mach-O"):
            warns.append(
                "native executable bundled in the plugin (stowaway): "
                f"{fp.relative_to(root)} ({fmt})"
            )

    # -- verdict: same merge rank as the skill vet; UNKNOWN floor on a capped sweep
    sub_rank = max((_VET_MERGE_RANK.get(f.status, 0) for f in subs), default=0)
    rank = max(sub_rank, 2 if warns else 0, 1 if truncated else 0)
    status = _VET_RANK_STATUS[rank]

    n_mcp = sum(1 for f in subs if f.id == "MCP-VET")
    summary = f"plugin '{pid}' ({len(skill_dirs)} bundled skill(s), {n_mcp} embedded MCP spec(s))"
    actionable = [f for f in subs if f.status in (FAIL, WARN, UNKNOWN)]
    evidence = warns + [f"{f.status}: {f.detail}" for f in actionable] + notes

    if status == FAIL:
        worst = max(subs, key=lambda f: _VET_MERGE_RANK.get(f.status, 0))
        sev = CRITICAL if worst.severity == CRITICAL else HIGH
        finding = _plugin_finding(
            sev,
            FAIL,
            f"dangerous bundled content in {summary}: {worst.detail}",
            "Do NOT install this plugin. " + (worst.fix or "Review the flagged content."),
            evidence,
        )
    elif status == WARN:
        head_sig = warns[0] if warns else actionable[0].detail
        label = "supply-chain / packaging signals" if warns else "bundled-content signals"
        finding = _plugin_finding(
            MEDIUM,
            WARN,
            f"{label} in {summary}: {head_sig}",
            "Review the flagged signals before installing; prefer pinned, shrinkwrapped, "
            "source-readable plugins.",
            evidence,
        )
    elif status == UNKNOWN:
        finding = _plugin_finding(
            HIGH,
            UNKNOWN,
            f"{summary}: content could not be fully assessed",
            "Review the undisclosed portion manually or re-run against the unpacked plugin.",
            evidence,
        )
    else:
        finding = _plugin_finding(
            LOW,
            PASS,
            f"{summary}: no manifest, packaging, or bundled-content signals",
            "Still skim the JS/TS entry files — plugin runtime code is outside this vet's depth.",
            evidence,
        )
    finding.ring_findings = actionable
    return finding


# ---------- vet_mcp: supply-chain / trust vetting for MCP servers ----------
# Install-vector commands that are pipe-to-run dangerous (execute arbitrary code).
_VET_MCP_DANGEROUS_CMDS = frozenset({"curl", "wget", "bash", "sh", "iex", "powershell"})
# Package-runner commands where an unpinned spec is a pull-latest-each-run risk.
_VET_MCP_RUNNER_CMDS = frozenset({"npx", "npm", "uvx", "pnpm", "bunx"})
# Detect @latest or a package name with no @<version> pin.
# "@latest" explicit, OR a bare package name without any "@" version suffix.
_VET_MCP_UNPINNED_PKG_RE = re.compile(
    r"@latest"
    r"|^(?!-)[^@\s]+$",  # bare package name: no "@" at all (not a flag like -y)
    re.I,
)
# Broad oauth scopes that signal wide permissions.
_VET_MCP_BROAD_SCOPE_RE = re.compile(r"\*|all|admin|write|full", re.I)

# ---------------------------------------------------------------------------
# F-007: MCP least-privilege cross-check (LP1 only)
#
# Grounding decision (§4 grounding wall, recon doc §1/§4 + skillspector-parity.md):
#   The only declarable permission field in a real openclaw.json MCP server spec
#   is oauth.scope (confirmed real, recon §1/§4).  There is NO "permissions",
#   "capabilities", "tools", or "scopes" field in the static config schema.
#
#   Code-capability surface: command + args (real fields).  We detect five
#   capability families via regex over the joined command string:
#     shell     — subprocess/Popen/os.system/bash/sh invocations or direct cmds
#     network   — requests/urllib/socket/fetch/curl/wget patterns
#     file_write— open(.*, "w")/write_text/fsync/shutil.copy
#     env_read  — os.environ/getenv/os.getenv patterns
#     mcp       — @modelcontextprotocol / mcp-server in the package name
#
#   LP rules shipped:
#     LP1 (under-declared): oauth.scope IS present AND appears read-only, but the
#          command exercises elevated capabilities (shell/network/file_write) that
#          the declared scope does not cover → suspicious.
#          The check ONLY fires when oauth.scope is explicitly set.
#
#   LP rules NOT shipped:
#     LP3 (capable-but-no-scope): DROPPED — absent oauth.scope is normal for MCP
#          servers (scope is only needed for OAuth flows).  Emitting LP3 would flag
#          every non-OAuth server and produce massive false-positives.
#     LP2 (wildcard scope): ALREADY covered by _VET_MCP_BROAD_SCOPE_RE in the
#          existing oauth.scope block of _vet_mcp_server — not duplicated here.
#     LP4 (over-declared): deferred — no grounded scope-vocab mapping exists;
#          emitting it would fabricate knowledge (§4).
# ---------------------------------------------------------------------------

# Capability-detection patterns applied to the full joined command+args string.
# Each pattern is (family_name, compiled_re).
_LP_CAP_FAMILIES: list[tuple[str, re.Pattern[str]]] = [
    (
        "shell",
        re.compile(
            r"\b(?:subprocess|popen|os\.system|execvp?e?|"
            r"bash|sh|cmd\.exe|powershell|iex)\b",
            re.I,
        ),
    ),
    (
        "network",
        re.compile(
            r"\b(?:requests?\.(?:get|post|put|delete|head|patch)|"
            r"urllib\.request|socket\.connect|fetch|"
            r"curl|wget|httpx|aiohttp)\b",
            re.I,
        ),
    ),
    (
        "file_write",
        re.compile(
            r'\bopen\s*\([^)]*["\']w["\']|'
            r"\b(?:write_text|write_bytes|fsync|shutil\.copy|shutil\.move)\b",
            re.I,
        ),
    ),
    (
        "env_read",
        re.compile(
            r"\bos\.environ\b|\bos\.getenv\b|\bgetenv\b",
            re.I,
        ),
    ),
    (
        "mcp",
        re.compile(
            r"@modelcontextprotocol/|mcp-server|mcp_server",
            re.I,
        ),
    ),
]

# A scope string that looks read-only (contains "read"/"view"/"list"/"get" but
# NOT "write"/"exec"/"admin"/"shell"/"network"/"full"/"all"/"*").
_LP_SCOPE_READONLY_RE = re.compile(r"\b(?:read|view|list|get|fetch|query|search)\b", re.I)
_LP_SCOPE_WRITE_RE = re.compile(
    r"\b(?:write|exec|admin|shell|network|full|all|post|put|delete|patch)\b"
    r"|\*",
    re.I,
)


def _lp_detect_caps(cmd_line: str) -> list[str]:
    """Return list of capability family names detected in *cmd_line*."""
    return [fam for fam, pat in _LP_CAP_FAMILIES if pat.search(cmd_line)]


def _vet_mcp_least_privilege(name: str, spec: dict) -> tuple[list[str], list[str]]:
    """F-007: MCP least-privilege cross-check (LP1 only).

    Returns (dangerous_reasons, suspicious_reasons).

    LP1: oauth.scope IS present AND appears read-only, but the command exercises
         elevated capabilities (shell/network/file_write) that the scope does not
         cover — under-declared scope.

    Grounding note (§4):
      - Absent oauth.scope is NORMAL for MCP servers (scope is optional, only
        needed for OAuth flows) — NO finding is emitted when scope is absent.
        The whole helper short-circuits to empty when oauth.scope is absent.
      - LP3 ("capable but no scope") is DROPPED: absent scope is the common case,
        not a least-privilege violation.  Emitting LP3 would flag every non-OAuth
        MCP server and cause massive false-positives.
      - LP2 (wildcard scope) is already covered by _VET_MCP_BROAD_SCOPE_RE in the
        existing oauth.scope block of _vet_mcp_server — not duplicated here.
      - LP4 (over-declared) is deferred — no grounded scope-vocab mapping exists.
    """
    dangerous: list[str] = []
    suspicious: list[str] = []

    if not isinstance(spec, dict):
        return dangerous, suspicious

    # Guard: only run LP cross-check when oauth.scope is explicitly declared.
    # Absent scope is normal for non-OAuth MCP servers — emit nothing.
    oauth = spec.get("oauth") or {}
    if not isinstance(oauth, dict):
        return dangerous, suspicious
    scope = str(oauth.get("scope") or "").strip()
    if not scope:
        return dangerous, suspicious

    # LP2 (broad/wildcard scope) is already handled by _VET_MCP_BROAD_SCOPE_RE
    # in _vet_mcp_server — do not double-report here.

    # LP1: scope IS present and looks read-only — check whether the command
    # exercises elevated capabilities that exceed a read-only grant.
    if not (_LP_SCOPE_READONLY_RE.search(scope) and not _LP_SCOPE_WRITE_RE.search(scope)):
        # Scope already has write/exec/network tokens, or is not recognisably
        # read-only — LP1 does not apply.
        return dangerous, suspicious

    # Build full command string for capability scanning.
    cmd = str(spec.get("command", ""))
    args = spec.get("args") or []
    if not isinstance(args, list):
        args = []
    full_cmd = " ".join([cmd] + [str(a) for a in args])

    caps = _lp_detect_caps(full_cmd)
    # Only flag elevated capabilities (shell/network/file_write).
    # env_read and mcp are low-risk relative to a read-only scope.
    elevated_caps = [c for c in caps if c in ("shell", "network", "file_write")]
    if elevated_caps:
        elevated_str = "/".join(elevated_caps)
        suspicious.append(
            f"{name}: oauth.scope='{scope}' appears read-only but command "
            f"exercises {elevated_str} capabilities — under-declared scope (LP1)"
        )

    return dangerous, suspicious


# ---------------------------------------------------------------------------
# C-038: MCP tool-poisoning detector (TP1–TP3)
#
# Grounding decision (§4 grounding wall, recon doc §4 + skillspector-parity.md):
#   The OpenClaw MCP config schema (mcp.servers.<name>) exposes: command, args,
#   env, transport, url, oauth.scope (all confirmed real fields, recon doc §1/§4).
#   There is NO documented "tools", "description", or "inputSchema" sub-key in the
#   static openclaw.json spec file — tool metadata comes from the live server
#   handshake, which we never perform offline.
#
#   Therefore:
#     TP2 (obfuscation/homoglyph in the server NAME) ships unconditionally — the
#          server name IS read from the spec file and IS in our scan surface.
#     TP1/TP3 (hidden instructions + param-description injection) scan tool
#          metadata ONLY IF spec.get("tools") is present in the parsed dict.
#          When absent → no signal (not a false PASS, not a fabricated finding).
#          In practice, since no current fleet config embeds "tools" inline, these
#          legs produce no output on real configs and zero false-positive FAILs.
# ---------------------------------------------------------------------------

# TP2: mixed-script / RTL-override / invisible chars in identifiers (suspicious).
# Reuses normalize_for_scan / obfuscation_signals from textnorm.

# TP1: hidden instructions in tool descriptions — keyword boosts signal danger.
_C038_HIDDEN_INSTR_RE = re.compile(
    r"(?:SYSTEM\s*:|IGNORE\s+PREVIOUS|OVERRIDE\s+(?:ALL\s+)?INSTRUCTIONS?|"
    r"<\|im_start\|>\s*system)",
    re.I,
)
# TP1: HTML comment / markdown comment hiding.
_C038_COMMENT_RE = re.compile(r"<!--.*?-->|\[//\]:\s*#\s*\(", re.DOTALL | re.I)
# TP1: data-URI embedding.
_C038_DATA_URI_RE = re.compile(r"data:[^;,]{0,40};base64,", re.I)

# TP3: imperative injection in param defaults or descriptions.
_C038_PARAM_INJECT_RE = re.compile(
    r"ignore\s+previous|<\|im_start\|>|"
    r"(?:curl|wget|nc|netcat|bash)\s+https?://|"
    r"https?://[^\s\"']{0,80}(?:\?|&)[^\s\"']{0,40}=",
    re.I,
)


def _vet_mcp_tool_poisoning(name: str, spec: dict) -> tuple[list[str], list[str]]:
    """C-038: MCP tool-poisoning TP1–TP3.

    Returns (dangerous_reasons, suspicious_reasons).

    TP2 is unconditional (server name is always available).
    TP1/TP3 run only when spec contains a 'tools' key (tool metadata present
    inline in the spec file — currently ungrounded for production configs;
    kept for future configs that may embed tool descriptions).
    """
    dangerous: list[str] = []
    suspicious: list[str] = []

    # ---- TP2: homoglyph / mixed-script / bidi-override in server NAME ----
    # The server name is a real field we can inspect offline.
    signals = obfuscation_signals(name)
    if signals:
        norm_name = normalize_for_scan(name)
        if norm_name != name:
            suspicious.append(
                f"{name}: server name contains obfuscation / homoglyph characters "
                f"({'; '.join(signals)}) — may impersonate a trusted server"
            )

    # ---- TP1 / TP3: tool metadata — only if embedded inline in the spec ----
    # (Grounding: not a standard field in openclaw.json; guard prevents FP.)
    tools = spec.get("tools")
    if not isinstance(tools, list):
        return dangerous, suspicious

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_name = str(tool.get("name", "<unnamed>"))
        description = str(tool.get("description", ""))
        norm_desc = normalize_for_scan(description)

        # TP1a: HTML/markdown comment hiding in description.
        if _C038_COMMENT_RE.search(description):
            dangerous.append(
                f"{name}/{tool_name}: tool description contains hidden comment "
                "(HTML/markdown comment block — potential hidden instruction)"
            )

        # TP1b: data-URI in description.
        if _C038_DATA_URI_RE.search(description):
            dangerous.append(
                f"{name}/{tool_name}: tool description contains data-URI "
                "(potential base64-encoded hidden payload)"
            )

        # TP1c: base64 blobs that decode to shell/download payloads.
        b64_hits = _decoded_payloads(description)
        for hit in b64_hits[:2]:
            dangerous.append(
                f"{name}/{tool_name}: tool description base64 blob decodes to "
                f"shell/download payload: {hit[:60]}"
            )

        # TP1d: keyword-boost injection phrases in normalized description.
        if _C038_HIDDEN_INSTR_RE.search(norm_desc):
            dangerous.append(
                f"{name}/{tool_name}: tool description contains injection keyword "
                f"(SYSTEM:/IGNORE PREVIOUS/OVERRIDE — prompt injection risk)"
            )

        # TP3: injection in parameter descriptions / defaults.
        input_schema = tool.get("inputSchema") or {}
        if isinstance(input_schema, dict):
            props = input_schema.get("properties") or {}
            if isinstance(props, dict):
                for param_name, param_def in props.items():
                    if not isinstance(param_def, dict):
                        continue
                    param_desc = str(param_def.get("description", ""))
                    param_default = str(param_def.get("default", ""))
                    for text, label in ((param_desc, "description"), (param_default, "default")):
                        if _C038_PARAM_INJECT_RE.search(normalize_for_scan(text)):
                            dangerous.append(
                                f"{name}/{tool_name}: parameter '{param_name}' "
                                f"{label} contains injection directive or exfil URL"
                            )
                            break

    return dangerous, suspicious


def _vet_mcp_server(name: str, spec: dict) -> tuple[list[str], list[str]]:
    """Return (dangerous_reasons, suspicious_reasons) for one MCP server spec.

    Grounded on real MCP fields: command, args, env, transport, url, oauth.scope.
    Reuses _mcp_server_risks for existing B24 signals and adds supply-chain signals.
    """
    dangerous: list[str] = []
    suspicious: list[str] = []

    if not isinstance(spec, dict):
        return dangerous, suspicious

    # ---- Re-use existing B24 risk signals ----
    b24_fails, b24_warns = _mcp_server_risks(name, spec)
    # Demote b24 FAIL env-wildcard / tokenPassthrough to dangerous; warns to suspicious.
    dangerous.extend(b24_fails)
    suspicious.extend(b24_warns)

    cmd = str(spec.get("command", "")).strip().lower()
    # Strip path components to get just the binary name.
    cmd_base = cmd.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    args = spec.get("args") or []
    if not isinstance(args, list):
        args = []
    args_strs = [str(a) for a in args]

    # ---- Install vector: pipe-to-run ----
    if cmd_base in _VET_MCP_DANGEROUS_CMDS:
        dangerous.append(
            f"{name}: command '{cmd_base}' is a pipe-to-run install vector "
            "(executes arbitrary code directly)"
        )

    # ---- Install vector: package runner with unpinned spec ----
    if cmd_base in _VET_MCP_RUNNER_CMDS:
        # Look at non-flag args for a package spec that has no pinned version.
        pkg_args = [a for a in args_strs if not a.startswith("-")]
        for arg in pkg_args:
            if _VET_MCP_UNPINNED_PKG_RE.search(arg):
                suspicious.append(
                    f"{name}: '{cmd_base} {arg}' is unpinned — pulls latest each run "
                    "(supply-chain risk)"
                )
                break  # one signal per server is enough

    # ---- Transport / URL: remote trust surface ----
    url = str(spec.get("url") or spec.get("endpoint") or "")
    transport = str(spec.get("transport") or "")
    is_remote_transport = transport.lower() in ("streamable-http", "sse")

    if url.startswith("http://") and not _mcp_url_is_local(url):
        dangerous.append(
            f"{name}: url uses plaintext HTTP ({url[:60]}) — credentials/data sent in clear"
        )
    elif url and not url.startswith("http"):
        # Non-HTTP URL present — note it as suspicious (unknown scheme).
        suspicious.append(f"{name}: url uses non-HTTPS scheme ({url[:60]})")

    # Remote transport or non-loopback URL -> note enlarged trust surface.
    # (Already handled in b24_warns for remote https without allowedHosts; avoid duplicate.)
    if is_remote_transport and not url:
        suspicious.append(
            f"{name}: transport='{transport}' is a remote/streaming transport "
            "(larger trust surface than stdio)"
        )

    # ---- Secret exposure via env ----
    env = spec.get("env") or {}
    if isinstance(env, dict):
        secret_keys = [k for k in env if SECRET_KEY_RE.search(str(k)) and str(k) != "*"]
        wildcard_keys = [k for k in env if str(k) == "*" or str(env[k]) == "*"]
        if wildcard_keys:
            # Already caught by b24_fails but add a clearer vet message if not already there.
            if not any("passthrough" in r.lower() or "wildcard" in r.lower() for r in dangerous):
                dangerous.append(
                    f"{name}: env contains wildcard passthrough — ALL env vars "
                    "(including host secrets) forwarded to MCP server"
                )
        elif len(secret_keys) >= 3:
            # Many secret-like keys: broad passthrough.
            suspicious.append(
                f"{name}: env forwards {len(secret_keys)} secret-like vars "
                f"({', '.join(secret_keys[:3])}…) — server receives your secrets"
            )
    elif env == "*":
        if not any("passthrough" in r.lower() or "wildcard" in r.lower() for r in dangerous):
            dangerous.append(f"{name}: env='*' — ALL env vars forwarded to MCP server")

    # ---- oauth.scope wildcard / broad ----
    oauth = spec.get("oauth") or {}
    if isinstance(oauth, dict):
        scope = str(oauth.get("scope") or "")
        if scope and _VET_MCP_BROAD_SCOPE_RE.search(scope):
            suspicious.append(
                f"{name}: oauth.scope='{scope}' is broad/wildcard — server has wide permissions"
            )

    # ---- C-038 TP1–TP3: MCP tool-poisoning ----
    tp_dangerous, tp_suspicious = _vet_mcp_tool_poisoning(name, spec)
    dangerous.extend(tp_dangerous)
    suspicious.extend(tp_suspicious)

    # ---- F-007: least-privilege cross-check (LP1 / LP3) ----
    lp_dangerous, lp_suspicious = _vet_mcp_least_privilege(name, spec)
    dangerous.extend(lp_dangerous)
    suspicious.extend(lp_suspicious)

    return dangerous, suspicious


# Route one MCP vet reason to a risk-dossier axis by its wording. Conservative: an
# unclassifiable reason falls back by severity at the caller (dangerous→danger,
# suspicious→build), so a signal is never dropped or silently downgraded.
_MCP_AXIS_CONNECTIONS = (
    "plaintext http", "non-https", "url uses", "transport=", "remote/streaming",
    "passthrough", "wildcard", "secret-like", "forwards", "receives your secrets",
    "sent in clear", "larger trust surface",
)
_MCP_AXIS_BEHAVIOR = (
    "injection directive", "exfil", "tool-poisoning", "poison", "tool description",
    "tool name", "tool '",
)
_MCP_AXIS_BUILD = (
    "unpinned", "@latest", "supply-chain", "oauth.scope", "least-privilege",
    "broad/wildcard", "wide permissions", "read-only",
)


def _mcp_reason_axis(reason: str) -> str | None:
    """Best-effort axis for one MCP vet reason; None → let the caller default by severity."""
    r = reason.lower()
    if "pipe-to-run" in r or "pipe-to-shell" in r:
        return "danger"
    if any(k in r for k in _MCP_AXIS_CONNECTIONS):
        return "connections"
    if any(k in r for k in _MCP_AXIS_BEHAVIOR):
        return "behavior"
    if any(k in r for k in _MCP_AXIS_BUILD):
        return "build"
    return None


def _load_mcp_spec_file(path: Path) -> dict[str, dict] | None:
    """Load a JSON file and normalise to {name: spec}.

    Accepts:
      - A single server spec dict  -> {"<filename stem>": spec}
      - A {name: spec} map         -> as-is (if all values are dicts)
      - A full config with mcp.servers  -> extracted servers dict

    Returns None if the file cannot be parsed as any of those shapes.
    """
    import json as _json

    try:
        data = _json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    # Full config: mcp.servers.<name>
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        servers = mcp.get("servers")
        if isinstance(servers, dict) and servers:
            return servers

    # mcpServers top-level (common alternative key)
    mcp_servers = data.get("mcpServers")
    if isinstance(mcp_servers, dict) and mcp_servers:
        return mcp_servers

    # Single server spec: top-level contains "command", "url", or "transport"
    # (these are MCP server spec fields, not wrapper keys).
    if "command" in data or ("url" in data and "transport" in data):
        stem = path.stem
        return {stem: data}

    # {name: spec} map: all values must be dicts
    if data and all(isinstance(v, dict) for v in data.values()):
        return data

    return None


def vet_mcp(target: str | Path | None = None, home: str | Path = "~/.openclaw") -> list[Finding]:
    """Vet MCP servers for supply-chain / trust risk BEFORE trusting them.

    Args:
        target: one of —
            None         -> vet ALL servers from the config at *home*.
            str/Path     -> if it points to an existing file: load as a JSON
                           spec (single server, {name:spec} map, or full config).
                           Otherwise treat as a server NAME and vet that one
                           server from the config at *home*.
        home: path to the OpenClaw home dir (default: ~/.openclaw).

    Returns a list of Finding objects — one per server — using a synthetic
    "MCP-VET" id (not a scored audit check). Each Finding's status is:
        PASS       — no supply-chain / trust signals detected.
        WARN       — suspicious signals (e.g. unpinned package, remote transport).
        FAIL       — dangerous signals (e.g. pipe-to-run, plaintext HTTP, wildcard env).
        UNKNOWN    — spec could not be parsed.
    """
    # Resolve servers to vet.
    servers: dict[str, dict] = {}

    if target is not None:
        p = Path(str(target)).expanduser()
        if p.is_file():
            loaded = _load_mcp_spec_file(p)
            if loaded is None:
                return [
                    Finding(
                        id="MCP-VET",
                        title="MCP supply-chain / trust vet",
                        severity=HIGH,
                        status=UNKNOWN,
                        detail=f"Could not parse '{p}' as a valid MCP server spec or config.",
                        fix="Provide a JSON file containing a server spec, a {name:spec} map, "
                        "or a full config with mcp.servers.",
                        framework="MCP Trust",
                        scored=False,
                    )
                ]
            servers = loaded
        else:
            # Treat target as a server name — load from config.
            name = str(target)
            home_path = Path(str(home)).expanduser()
            cfg_file = home_path / "openclaw.json"
            import json as _json

            try:
                cfg = _json.loads(cfg_file.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                cfg = {}
            all_servers = _mcp_servers(cfg)
            if name in all_servers:
                servers = {name: all_servers[name]}
            else:
                return [
                    Finding(
                        id="MCP-VET",
                        title="MCP supply-chain / trust vet",
                        severity=HIGH,
                        status=UNKNOWN,
                        detail=f"Server '{name}' not found in config at {cfg_file}.",
                        fix="Check the server name or point --vet-mcp at a JSON file.",
                        framework="MCP Trust",
                        scored=False,
                    )
                ]
    else:
        # Vet all servers from config at home.
        home_path = Path(str(home)).expanduser()
        cfg_file = home_path / "openclaw.json"
        import json as _json

        try:
            cfg = _json.loads(cfg_file.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            cfg = {}
        servers = _mcp_servers(cfg)

    if not servers:
        return [
            Finding(
                id="MCP-VET",
                title="MCP supply-chain / trust vet",
                severity=HIGH,
                status=UNKNOWN,
                detail="No MCP servers configured.",
                fix="Configure MCP servers under mcp.servers.<name> in openclaw.json.",
                framework="MCP Trust",
                scored=False,
            )
        ]

    findings: list[Finding] = []
    for sname, spec in servers.items():
        dangerous, suspicious = _vet_mcp_server(sname, spec)

        if dangerous:
            status = FAIL
            all_reasons = dangerous + suspicious
            fix = (
                "Do NOT trust this server until you have reviewed its source. "
                "Remove pipe-to-run commands (curl/wget/bash/sh), switch to HTTPS, "
                "eliminate wildcard env passthrough, and pin package specs to exact versions."
            )
        elif suspicious:
            status = WARN
            all_reasons = suspicious
            fix = (
                "Review before trusting: pin package specs to exact versions "
                "(avoid @latest / bare package names), prefer stdio transport over "
                "remote/SSE, and minimise secret env var exposure."
            )
        else:
            status = PASS
            all_reasons = []
            fix = "No supply-chain signals detected — keep specs pinned and env vars minimal."

        # Reasons are collected with a "<sname>: " prefix; strip it so the server name
        # appears once (as the finding title), not repeated on every line.
        _pfx = f"{sname}: "
        clean = [r[len(_pfx) :] if r.startswith(_pfx) else r for r in all_reasons[:6]]
        more = f" (+{len(all_reasons) - 6} more)" if len(all_reasons) > 6 else ""
        detail = ("; ".join(clean) + more) if clean else "no supply-chain / trust risks detected"
        # Split the reasons across risk-dossier axes with their own severity, so the
        # dossier can show (e.g.) an unpinned spec under Build and a wildcard-env under
        # Connections rather than lumping everything under Danger. {axis: [[status, text]]}.
        axis_reasons: dict[str, list] = {}
        for reason_status, reasons in ((FAIL, dangerous), (WARN, suspicious)):
            for r in reasons:
                disp = r[len(_pfx) :] if r.startswith(_pfx) else r
                axis = _mcp_reason_axis(r) or ("danger" if reason_status == FAIL else "build")
                axis_reasons.setdefault(axis, []).append([reason_status, disp])
        findings.append(
            Finding(
                id="MCP-VET",
                title=sname,
                severity=HIGH,
                status=status,
                detail=detail,
                fix=fix,
                framework="MCP Trust",
                scored=False,
                evidence=clean,
                axis_reasons=axis_reasons,
            )
        )

    return findings


def _mcp_has_tool_restrictions(spec: dict) -> bool:
    tools = spec.get("tools")
    return isinstance(tools, list) and len(tools) > 0


def check_mcp(ctx: Context) -> Finding:
    servers = _mcp_servers(ctx.config)
    if not servers:
        return _finding("B15", UNKNOWN, "No MCP servers configured.", "—")
    names = ", ".join(list(servers)[:5])
    n = len(servers)
    if all(_mcp_has_tool_restrictions(spec) for spec in servers.values()):
        return _finding(
            "B15",
            PASS,
            f"{n} MCP server(s) configured ({names}). "
            "All servers have explicit tool allowlists configured.",
            "Keep per-server tool allowlists tight and review them after updates.",
        )
    # Frame by transport so a local stdio server isn't described as a "remote" risk (C-057).
    if any(_mcp_has_remote(spec) for spec in servers.values()):
        return _finding(
            "B15",
            WARN,
            f"{n} MCP server(s) configured ({names}). "
            "Remote MCP servers can carry prompt injection, SSRF and data exposure.",
            "Verify each MCP server's source and trust boundary, restrict its tool "
            "reachability, and avoid untrusted remote MCP endpoints.",
        )
    return _finding(
        "B15",
        WARN,
        f"{n} MCP server(s) configured ({names}). "
        "Local (stdio) MCP servers run as subprocesses with the agent's "
        "privileges; a malicious or compromised server can read local data and "
        "act through the agent's tools.",
        "Verify each MCP server's source and trust boundary, pin its "
        "package/command to a known version, and restrict its tool reachability.",
    )


# ---------- B24: MCP server hardening ----------
# Unpinned / dangerous install specs for stdio commands.
_MCP_UNPINNED_RE = re.compile(
    r"(?:npx|pip(?:x)?|uvx)\b[^\n]*?"  # npx / pip / pipx / uvx prefix
    r"(?:"
    r"@latest"  # explicit @latest tag
    r"|https?://"  # URL argument
    r"|(?<![a-zA-Z0-9._-])(?!@[0-9])@(?![0-9])[a-zA-Z]"  # @scope but not pinned @1.2.3
    r")",
    re.I,
)
_MCP_CURL_RE = re.compile(r"\bcurl\b[^\n]*?https?://", re.I)

# Broad secret env vars.
_MCP_SECRET_ENV_RE = re.compile(
    r"^(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_[A-Z_]+|AZURE_[A-Z_]+|GCP_[A-Z_]+|"
    r"GOOGLE_[A-Z_]*(?:API_)?KEY|GITHUB_TOKEN|GITLAB_TOKEN|SECRET[_A-Z]*|"
    r"API_KEY[_A-Z]*|TOKEN[_A-Z]*)$",
    re.I,
)

# Metadata / internal IPs in allowedHosts.
_MCP_META_IP_RE = re.compile(
    r"^(?:"
    r"169\.254\.\d+\.\d+"  # link-local / AWS metadata
    r"|10\.\d+\.\d+\.\d+"  # RFC-1918 /8
    r"|192\.168\.\d+\.\d+"  # RFC-1918 /16
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"  # RFC-1918 /12
    r"|localhost|127\.\d+\.\d+\.\d+"  # loopback
    r"|::1"  # IPv6 loopback
    r")$",
    re.I,
)


def _mcp_server_risks(name: str, spec: dict) -> tuple[list[str], list[str]]:
    """Return (fail_reasons, warn_reasons) for one MCP server spec dict.

    Conservative: FAIL only on unambiguous positive evidence of a known-risky
    pattern; WARN for likely-insecure defaults that may be intentional.
    """
    fails: list[str] = []
    warns: list[str] = []

    if not isinstance(spec, dict):
        return fails, warns

    # ---- stdio command using npx/pip/curl with URL or @latest/unpinned spec ----
    cmd = spec.get("command", "")
    args = spec.get("args") or []
    if isinstance(args, list):
        full_cmd = " ".join([str(cmd)] + [str(a) for a in args])
    else:
        full_cmd = str(cmd)

    # B-073: detection runs on the raw command, but the string echoed into evidence
    # is host-only-sanitized so a credential embedded in a URL arg
    # (e.g. npx --registry https://TOKEN@reg/pkg) never reaches the report (§8).
    from ..logsafe import redact_urls_in_text  # noqa: PLC0415
    safe_cmd = redact_urls_in_text(full_cmd)[:80]
    if _MCP_UNPINNED_RE.search(full_cmd):
        warns.append(f"{name}: stdio command uses unpinned/URL spec ({safe_cmd})")
    if _MCP_CURL_RE.search(full_cmd):
        warns.append(f"{name}: stdio command uses curl with URL ({safe_cmd})")

    # ---- env passthrough ----
    env = spec.get("env") or {}
    if isinstance(env, dict):
        for key, val in env.items():
            if key == "*" or val == "*":
                fails.append(f"{name}: env passthrough '*' (all env vars exposed)")
                break
            if _MCP_SECRET_ENV_RE.match(str(key)):
                warns.append(f"{name}: env passes broad secret var {key}")
    elif env == "*":
        fails.append(f"{name}: env passthrough '*' (all env vars exposed)")

    # ---- tokenPassthrough / token-passthrough ----
    if spec.get("tokenPassthrough") is True or spec.get("token-passthrough") is True:
        fails.append(f"{name}: tokenPassthrough=true (host token forwarded to MCP server)")

    # ---- allowedHosts ----
    allowed_hosts = spec.get("allowedHosts") or []
    if isinstance(allowed_hosts, list):
        for host in allowed_hosts:
            h = str(host)
            if h == "*":
                fails.append(f"{name}: allowedHosts contains '*' (unrestricted SSRF surface)")
                break
            if _MCP_META_IP_RE.match(h):
                fails.append(f"{name}: allowedHosts contains internal/metadata IP {h}")
                break
    elif isinstance(allowed_hosts, str) and allowed_hosts == "*":
        fails.append(f"{name}: allowedHosts='*' (unrestricted SSRF surface)")

    # ---- remote https URL with no allowlist ----
    url = spec.get("url") or spec.get("endpoint") or ""
    if isinstance(url, str) and url.startswith("https://"):
        # Only flag when there is no allowedHosts restriction configured at all
        if not allowed_hosts:
            warns.append(f"{name}: remote MCP endpoint {url[:60]} with no allowedHosts restriction")

    return fails, warns


def check_mcp_hardening(ctx: Context) -> Finding:
    """B24 — MCP server hardening.

    Inspects each configured MCP server spec for positive evidence of risky
    patterns. FAIL only on unambiguous danger signals; WARN for likely-insecure
    defaults; PASS when servers exist but none trigger; UNKNOWN when no MCP.
    """
    servers = _mcp_servers(ctx.config)
    if not servers:
        return _finding("B24", UNKNOWN, "No MCP servers configured.", "—")

    all_fails: list[str] = []
    all_warns: list[str] = []
    for name, spec in servers.items():
        f, w = _mcp_server_risks(name, spec)
        all_fails.extend(f)
        all_warns.extend(w)

    n = len(servers)
    names_preview = ", ".join(list(servers)[:5])

    # Detail is a summary only; the per-server specifics go in evidence so the renderer
    # does not print the same line twice (in the "why" and again as a bullet) — C-057.
    if all_fails:
        ev = all_fails[:6]
        if len(all_fails) > 6:
            ev = ev + [f"(+{len(all_fails) - 6} more issue(s) not shown)"]
        return _finding(
            "B24",
            FAIL,
            f"{n} MCP server(s) ({names_preview}) have dangerous hardening issues — see evidence.",
            "Remove wildcard env passthrough, disable tokenPassthrough, restrict "
            "allowedHosts to specific safe hosts, and pin MCP package specs to "
            "exact versions.",
            evidence=ev,
        )

    if all_warns:
        ev = all_warns[:6]
        if len(all_warns) > 6:
            ev = ev + [f"(+{len(all_warns) - 6} more issue(s) not shown)"]
        return _finding(
            "B24",
            WARN,
            f"{n} MCP server(s) ({names_preview}) have likely-insecure settings — see evidence.",
            "Pin MCP package specs to exact versions (avoid @latest/URLs), restrict "
            "allowedHosts to known-safe hosts, and avoid forwarding broad secret env vars.",
            evidence=ev,
        )

    return _finding(
        "B24",
        PASS,
        f"{n} MCP server(s) configured ({names_preview}); no hardening issues detected.",
        "Keep MCP server specs pinned, env vars minimal, and allowedHosts restricted.",
    )


def check_mcp_external_endpoint(ctx: Context) -> Finding:
    """C047 — advisory UNKNOWN for non-local MCP server URLs.

    A remote MCP endpoint can act as an exfiltration sink, but config alone cannot
    prove whether it is legitimate or attacker-controlled. This is UNKNOWN-only on
    non-local URLs and PASS when MCP is absent or limited to local/stdio endpoints.
    """
    servers = _mcp_servers(ctx.config)
    external = []
    # B-073: keep only scheme://host of the endpoint in evidence — userinfo, path,
    # and query can each carry a token (https://user:token@host/mcp/<token>?key=...) (§8).
    from ..logsafe import sanitize_url_host_only  # noqa: PLC0415
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        url = spec.get("url") or spec.get("endpoint")
        if not isinstance(url, str) or not url.strip():
            continue
        if _mcp_url_is_local(url):
            continue
        external.append(f"{name}: non-local MCP URL {_obf_clip(sanitize_url_host_only(url.strip()))}")

    if external:
        return _finding(
            "C047",
            UNKNOWN,
            "Non-local MCP server endpoint(s) require manual review: " + "; ".join(external[:4]),
            "Review each non-local MCP server URL, confirm the owner and trust boundary, "
            "and prefer localhost/stdio or a Unix socket when a remote endpoint is not required.",
            external,
        )
    return _finding(
        "C047",
        PASS,
        "No non-local MCP server URLs detected.",
        "Keep MCP endpoints local where possible and review any future remote URLs before enabling them.",
    )


_B30_PROVIDERS_WITH_NAME_MATCH = ("discord", "slack")


# ---------- B38: Browser Control / Cookie & SSRF Exposure ----------
# browser.ssrfPolicy.dangerouslyAllowPrivateNetwork (bool) — lets the agent browser
# reach internal/metadata IPs (cloud-credential theft via 169.254.169.254).
# browser.noSandbox (bool) — browser runs without OS sandbox.
# browser.ssrfPolicy.hostnameAllowlist (array) — restrict outbound browser targets.
# browser.headless (bool) — informational; headless adds stealth but not a FAIL alone.


# ---------- B39: Session Visibility / Cross-user Transcript Leak ----------
# session.dmScope — controls which DM peers share a session.
#   "main"                  : ALL DM peers share ONE session (cross-user contamination).
#   "per-peer"              : one session per DM peer (safe).
#   "per-channel-peer"      : one session per channel+peer combo (safe).
#   "per-account-channel-peer": most granular (safe).
#
# tools.sessions.visibility — controls which sessions a tool can read.
#   "self"  : only own session (safe).
#   "tree"  : own session tree (safe).
#   "agent" : any session of the same agent (cross-user leak risk).
#   "all"   : all sessions across all agents (cross-user leak risk).


# ---------- B26: untrusted-context exposure (channels.contextVisibility) ----------
# Real field: channels.defaults.contextVisibility (default for all channels) and
# channels.<provider>.contextVisibility (per-channel override).
# Values:
#   "all"             — model sees quoted replies / thread roots / fetched group
#                       history from ANY sender, including untrusted ones
#                       (documented default when field is absent -> prompt-injection surface)
#   "allowlist"       — only supplemental context from allowlisted senders
#   "allowlist_quote" — allowlist + one explicit quoted reply
_B26_SAFE_VALUES = frozenset({"allowlist", "allowlist_quote"})


# ---------- B41: Credential blast-radius assessment ----------


# ---------- B50–B54: Host Watch Posture (read-only host-monitor detection) ----------
# These read ctx.host (populated by audit(include_host=True) via hostwatch.detect).
# In hermetic/test mode ctx.host is None -> UNKNOWN (excluded from the score).


# ---------- B43/B44: attestation layer (v0.26.0) ----------
# Both read ctx.attestation — the agent's self-report (--attest). With no attestation
# they return UNKNOWN, so the default static audit and its score are unchanged. Their
# findings carry ATTESTED confidence (set on the CheckMeta) — weaker than a config fact.


def check_plugin_permission_mode(ctx: Context) -> Finding:
    """B57 (NC-8) — plugin permissionMode=approve-all.

    Grounded (docs.openclaw.ai/gateway/security): plugins "run in-process with the
    Gateway — treat them as trusted code", and `plugins.entries.<name>.config.permissionMode
    = approve-all` is an audit-tracked dangerous flag that auto-approves every plugin
    permission prompt, removing the last gate before trusted-code actions.

    UNKNOWN — no plugins installed (plugins.entries absent).
    FAIL    — any installed plugin sets config.permissionMode == "approve-all".
    PASS    — no plugin uses approve-all.
    """
    cfg = ctx.config
    plugins = _plugins(cfg)
    if not plugins:
        return _finding(
            "B57",
            UNKNOWN,
            "No plugins are installed (plugins.entries absent), so plugin permission "
            "modes are not applicable.",
            "When you install plugins, set each plugins.entries.<name>.config.permissionMode "
            "to 'ask' (never 'approve-all').",
        )
    offenders = []
    for name, entry in plugins.items():
        if not isinstance(entry, dict):
            continue
        if dig(entry, "config.permissionMode") == "approve-all":
            offenders.append(
                f"plugins.entries.{name}.config.permissionMode=approve-all — auto-approves "
                "every plugin permission prompt (plugins run in-process as trusted code)"
            )
    if offenders:
        return _finding(
            "B57",
            FAIL,
            "One or more installed plugins set config.permissionMode=approve-all, "
            "auto-approving every plugin permission prompt (plugins run in-process as "
            "trusted code, so this removes the last gate).",
            "Set permissionMode to 'ask' for the listed plugin(s) so each privileged "
            "action is confirmed.",
            evidence=offenders,
        )
    return _finding(
        "B57",
        PASS,
        "No installed plugin sets config.permissionMode=approve-all.",
        "Keep plugin permissionMode at 'ask'.",
    )


# B60 — Prompt self-replication / propagation directive (ATLAS AML.T0061)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# B61 — Cross-agent config snooping / credential theft (F-006)
# ---------------------------------------------------------------------------
#
# Grounded against recon doc §1/§4 and skillspector-parity.md §3 (agent_snooping
# AS1–AS3). We detect skills that read ANOTHER agent's config file to steal
# credentials.
#
# Grounded foreign-agent config paths (confirmed real from recon doc + our own
# fleet configs): ~/.claude/mcp.json, ~/.codex/mcp.json, ~/.gemini/mcp.json,
# ~/.openclaw/openclaw.json, ~/.openclaw/mcp_config.json.
# NOT grounded (dropped): .cursor/.continue/.cline/.aider — not in recon doc.
#
# FAIL  — foreign-config path co-occurs with a read/exfil verb (cat/grep/open/
#          read or an existing exfil sink) on the same or adjacent line.
# WARN  — path literal present but no read verb detected.
# UNKNOWN — no installed skills.
#
# Conservative gating (path + verb) maintains zero-false-positive-FAIL guarantee.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# B62 (F-019): Capability–intent mismatch
# ---------------------------------------------------------------------------
# Keyword vocabulary: maps a declared-category label → frozenset of capability
# families that are EXPECTED for that category. Capabilities NOT in the set are
# "surprising" and may trigger a WARN when the declaration is CLEAR+NARROW.
#
# Capability family names (used in effect_profiles + import scan):
#   "network"  — outbound HTTP/socket/urllib/requests/aiohttp
#   "exec"     — subprocess/os.system/eval/exec, i.e. process execution
#   "write"    — filesystem write (open-for-write / shutil.copy / os.rename / etc.)
#   "read"     — filesystem read  (benign for most categories — never surprises)
#   "cred"     — credential / env-var / secret-store access
#
# PERMISSIVE categories (vague / generic): never flag regardless of capabilities.


# ---------------------------------------------------------------------------
# B63 — Silent-instruction detector (C-075)
# ---------------------------------------------------------------------------
#
# Detects directives that instruct the agent to hide its actions from the
# user — undermining human-oversight transparency (OWASP LLM06 Excessive Agency,
# NIST AI 600-1 §4.2).  These are ALWAYS malicious in a healthy agent setup; no legitimate
# skill or bootstrap file needs to say "don't tell the user".
#
# Detection uses a dual-signal proximity gate:
#   Signal A — a secrecy/suppression verb phrase ("don't tell", "silently",
#              "without notifying", "suppress output", "скрой от пользователя")
#   Signal B — an action/execution context ("execute", "run", "send", "delete",
#              "exfiltrate", "the user", "пользователю", "output")
#
# FAIL  — Signal A + Signal B within _B63_WINDOW chars (positive evidence of
#         hiding intent with an action target; always malicious).
# WARN  — Signal A alone, no co-located action context (bare secrecy phrase;
#         could be documentation — human review needed).
# PASS  — no silent-instruction patterns found.
# UNKNOWN — nothing to inspect (no bootstrap, no skills).
#
# Code-fence dampening (C-041) is applied so documented examples of attacks
# do not fire.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# B64 — Instruction-hierarchy override detector (C-076)
# ---------------------------------------------------------------------------
#
# Detects authority override phrases that attempt to bypass system prompts,
# safety controls, or guidelines (OWASP LLM Top 10, NIST AI 600-1).
# FAIL on high-confidence override patterns.
# WARN on weaker signals.
# PASS when no override patterns found.
# UNKNOWN when no bootstrap files, installed skills, or MCP tools found.
#
# Code-fence dampening is applied so documented examples of attacks
# do not fire.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# B65 — Conditional sleeper-trigger detector (C-080)
# ---------------------------------------------------------------------------
#
# Detects instructions that are gated behind user-provided triggers, for example:
# "If the user asks, send ...". These are classic "sleeper" patterns: hidden
# malicious behavior that only activates on a trigger phrase.
#
# WARN — conditional trigger + user-query intent + sensitive action in close
# proximity.
# PASS — no conditioned trigger found.
# UNKNOWN — nothing to inspect.
#
# Code-fence dampening prevents documented examples from firing.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# B66 — Persona / role jailbreak detector (C-078)
# ---------------------------------------------------------------------------
#
# Detects role-switch instructions that attempt to reset policy assumptions
# ("you are DAN/FreeBot", "ignore constraints", "no restrictions").
#
# WARN — persona override token/pattern + scope-reset hint in proximity.
# PASS — no jailbreak persona pattern.
# UNKNOWN — nothing to inspect.
#
# Code-fence dampening prevents documented examples from firing.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# B58 — Unicode-obfuscated injection / hidden-text evasion
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# B59 — Markdown-image data-exfil via remote URL
# ---------------------------------------------------------------------------


# ---------- B67: per-source tool-output trust contracts (C-092) ----------
# Complements B21 (generic trust boundary): checks for CHANNEL-SPECIFIC declarations.
# A bootstrap can have B21=PASS (generic "treat output as data") but B67=WARN when
# individual high-risk channels (browser, email, MCP, search, docs) are not called out.


# ── B68–B73 (v1.20.0): advisory WARN-only config-fact checks ──────────────────


# ---------------------------------------------------------------------------
# B75 — MCP tool-inheritance bypass (attested)
# ---------------------------------------------------------------------------


def check_mcp_tool_inheritance(ctx: Context) -> Finding:
    """B75 — MCP tool-inheritance bypass check (attestation-based).

    Grounded on GitHub issue #63399: globally-registered mcp.servers tools were
    auto-injected into ALL agents, bypassing per-agent tools.allow/deny filters.
    A narrow-role agent still receives every MCP tool namespace.

    UNKNOWN — no attestation provided (config alone cannot prove per-agent MCP reach).
    WARN    — one or more attested agents hold MCP-namespaced tools that leak past
              the per-agent filter (evidence: agent name + tool count).
    PASS    — attestation present but no agent shows unexpected MCP tool bleed.

    Advisory (scored=False): never FAILs — WARN only, consistent with §5.
    """
    agents = _attest.attested_agents(ctx.attestation)
    if not agents:
        # No attestation -> cannot determine per-agent MCP reachability.
        return _finding(
            "B75",
            UNKNOWN,
            "No attestation provided — cannot determine whether MCP tools bypass "
            "per-agent tool filters at runtime (GitHub issue #63399).",
            "Run with --attest and include each agent's real tool list. "
            "MCP tools may be accessible to all agents regardless of per-agent "
            "tools.allow/deny configuration.",
        )

    mcp_servers = _mcp_servers(ctx.config)
    has_mcp = bool(mcp_servers)

    bleed_ev: list[str] = []
    for agent in agents:
        name = agent["name"]
        tools = agent["tools"]
        # MCP tools are namespaced: mcp__server__verb or server__verb (double underscore)
        mcp_tools = [t for t in tools if "__" in t]
        if mcp_tools:
            count = len(mcp_tools)
            sample = ", ".join(mcp_tools[:3])
            extra = f" (+{count - 3} more)" if count > 3 else ""
            bleed_ev.append(f"agent '{name}' holds {count} MCP-namespaced tool(s): {sample}{extra}")

    if bleed_ev and has_mcp:
        ev_summary = "; ".join(bleed_ev[:3])
        extra = f" (+{len(bleed_ev) - 3} more)" if len(bleed_ev) > 3 else ""
        return _finding(
            "B75",
            WARN,
            "MCP tools appear accessible to named agents despite per-agent tool "
            "filters — consistent with OpenClaw issue #63399 (MCP bypass): " + ev_summary + extra,
            "Verify each agent's effective tool list with 'openclaw tools list --agent <name>'. "
            "Until issue #63399 is resolved, treat every named agent as having access to all "
            "registered MCP tools and apply compensating controls (least-privilege roles, "
            "sandbox.tools restrictions).",
            bleed_ev,
        )

    return _finding(
        "B75",
        PASS,
        "Attested agents do not show unexpected MCP-namespaced tools, or no MCP "
        "servers are configured.",
        "Keep per-agent tool inventories minimal. Re-run after adding MCP servers "
        "to verify no unintended tool bleed.",
    )


# B76 — High-blast MCP tool-inheritance bypass (scored, attested)
# ---------------------------------------------------------------------------


def check_mcp_bypass_highblast(ctx: Context) -> Finding:
    """B76 — High-blast MCP tool-inheritance bypass (attestation-based, scored).

    Grounded on OpenClaw #63399: globally-registered mcp.servers tools bypass
    per-agent filters and are injected into ALL agents at runtime.

    B75 (scored=False) flags any MCP bleed broadly.  B76 (scored=True) targets only
    the subset that materially raises attack blast radius: agents holding MCP-namespaced
    tools whose verb classifies as EXEC, EGRESS, DESTRUCTIVE, or MAILBOX_CONFIG.
    These are the primitives that enable code execution, exfiltration, irreversible
    deletion, or persistent mailbox takeover.

    classify_verb() strips MCP namespace before matching so provider names cannot
    inflate the verdict (e.g. 'mcp__SendGrid__list_templates' → verb='list_templates'
    → REVERSIBLE, not EGRESS).

    UNKNOWN — no attestation provided.
    WARN    — one or more attested agents hold high-blast MCP tools + mcp.servers set.
    PASS    — no high-blast MCP tools found, or no mcp.servers configured.
    """
    agents = _attest.attested_agents(ctx.attestation)
    if not agents:
        return _finding(
            "B76",
            UNKNOWN,
            "No attestation provided — cannot determine whether high-blast MCP tools "
            "bypass per-agent filters at runtime (OpenClaw #63399).",
            "Run with --attest including each agent's real tool list. High-blast MCP "
            "tools (EXEC/EGRESS/DESTRUCTIVE/MAILBOX_CONFIG verbs) may be reachable by "
            "all agents regardless of per-agent tool configuration.",
        )

    mcp_servers = _mcp_servers(ctx.config)
    if not mcp_servers:
        return _finding(
            "B76",
            PASS,
            "No MCP servers configured — high-blast MCP tool inheritance bypass not applicable.",
            "This check activates when mcp.servers (or mcpServers) are registered.",
        )

    blast_ev: list[str] = []
    for agent in agents:
        name = agent["name"]
        tools = agent["tools"]
        mcp_tools = [t for t in tools if "__" in t]
        high_blast = [
            t for t in mcp_tools if _attest.classify_verb(t) in _attest.HIGH_BLAST_CLASSES
        ]
        if high_blast:
            count = len(high_blast)
            sample = ", ".join(high_blast[:3])
            extra = f" (+{count - 3} more)" if count > 3 else ""
            blast_ev.append(f"agent '{name}' holds {count} high-blast MCP tool(s): {sample}{extra}")

    if blast_ev:
        ev_summary = "; ".join(blast_ev[:3])
        extra_ev = f" (+{len(blast_ev) - 3} more agents)" if len(blast_ev) > 3 else ""
        return _finding(
            "B76",
            WARN,
            "Attested agents hold high-blast MCP tools that bypass per-agent filters "
            "(OpenClaw #63399 — EXEC/EGRESS/DESTRUCTIVE/MAILBOX_CONFIG verbs): "
            + ev_summary
            + extra_ev,
            "High-blast MCP tools increase the blast radius of prompt-injection or "
            "rogue-agent attacks. Until #63399 is resolved: disable MCP servers not "
            "needed by all agents, use sandbox.tools restrictions, or add per-source "
            "deny lists via toolsBySender.",
            blast_ev,
        )

    return _finding(
        "B76",
        PASS,
        "No attested agent holds high-blast MCP tools despite MCP servers configured.",
        "Current MCP tool inventory contains only low-blast verbs (search/read/draft). "
        "Re-run after adding MCP servers or changing tool configurations.",
    )


# ---------- B88: SKILL.md frontmatter authoring hygiene (F-082 a + e-gap) ----------
# Two deterministic frontmatter-scoped lints, each covering only what an existing check
# does NOT — the E-008 "coordinate, don't duplicate" rule:
#   (a) An HTML/XML-tag-shaped value `<tag …>` inside the SKILL.md frontmatter — a metadata
#       injection surface: it renders as markup in a viewer, can break a YAML/JSON validator,
#       and can smuggle an instruction the model reads. B58 owns invisible-unicode
#       obfuscation and B59 owns markup in the BODY; neither flags a tag in a frontmatter value.
#   (e-gap) Cross-skill trigger-squatting in the frontmatter (description) — wording that
#       displaces OTHER skills ("use this skill instead of other skills", "ignore other
#       skills", "the only skill you need"). F-051 already owns the broad-trigger family
#       ("always use this skill", "on every request"); B88 covers only the cross-skill-squat
#       phrasing F-051 does not, so the two never double-report.
# WARN-only advisory (scored=False, MEDIUM). Reads ctx.installed_skills; UNKNOWN when there
# is no SKILL.md frontmatter to inspect (so a frontmatter-free vet never false-WARNs).
# Grounding (§4): SKILL.md frontmatter fields are documented in the workspace recon doc
# (openclaw-schema-recon.md, "SKILL.md frontmatter" section) — the vet reads the block, it
# does not depend on any specific optional field being present.


# ---------- B89: dormant-capability skill (F-092 (b), narrowed) ----------
# A skill that is unreachable by BOTH the user (user-invocable:false) AND the model
# (disable-model-invocation:true) yet still ships executable code (py/shell/js) is a
# dormant-capability shape: inert code nobody can trigger, staged for later activation.
# Grounding (§4, recon §13): the bare "both invocation paths disabled" combo is used by
# legitimate skills, so it is NOT a decoy signal on its own — B89 requires the skill to also
# CARRY CODE. `user-invocable` has two real shapes (top-level YAML on Claude-Code skills;
# nested `metadata.openclaw.user-invocable` on OpenClaw skills) — both are read. WARN-only.
# Zero-FP: our own skill is user-invocable=true (never unreachable); clawstealth is
# model-disabled but user-invocable (never both) — neither fires.


# ---------------------------------------------------------------------------
# SKILL_CONTENT_RING — single source of truth for content-security ring checks.
#
# Most of these read ctx.installed_skills (and optionally ctx.bootstrap,
# ctx.installed_skill_py, ctx.effect_profiles) and are therefore meaningful
# both in the full audit (where they already appear in CHECKS below) AND in
# the pre-install vet path (vet_skill), which populates ctx.installed_skills
# before running them.
#
# Rules for membership:
#   - Must return UNKNOWN (never a false FAIL) on a skill-free ctx. The content
#     checks get this by keying off ctx.installed_skills; the filesystem members
#     (B42 dir perms, B87 symlink escape) get it by resolving their scan roots
#     from ctx.home — the vetted dir in --vet, the installed skill dirs +
#     workspace in the full audit — and returning UNKNOWN when none exist.
#   - Must keep its existing calibration / severity — no upgrades here.
#   - B67 (per-source trust contracts) is included; it returns UNKNOWN when
#     ctx.bootstrap is empty, which is the correct result for a --vet run that
#     has no bootstrap files to inspect.
# ---------------------------------------------------------------------------


CHECKS = [
    check_trifecta,
    check_secrets,
    check_secrets_at_rest_home,
    check_gateway,
    check_least_privilege,
    check_sandbox,
    check_supply_chain,
    check_bootstrap_injection,
    check_memory_poisoning,
    check_human_approval,
    check_leak,
    check_audit_log,
    check_tls,
    check_local_first,
    check_installed_skills,
    check_egress,
    check_egress_inventory,
    check_mcp,
    check_mcp_hardening,
    check_mcp_external_endpoint,
    check_proxy_header_forging,
    check_monitoring,
    check_autonomy,
    check_subagents,
    check_data_atrest,
    check_bootstrap_write_protection,
    check_self_modification,
    check_backups,
    check_version,
    check_tool_output_trust,
    check_approval_bypass,
    check_update_pinning,
    check_path_safety,
    check_sender_identity,
    check_control_plane_mutation,
    check_browser_ssrf,
    check_session_visibility,
    check_untrusted_context,
    check_known_vulns,
    check_credential_blast_radius,
    check_effective_tools,
    check_host_network_ids,
    check_host_audit,
    check_host_file_integrity,
    check_host_edr,
    check_host_firewall,
    check_host_egress_posture,
    check_capability_blast_radius,
    check_attestation_mismatch,
    check_declared_effective_proven,
    check_agent_separation,
    check_multiagent_exposure,
    check_delegation_reassembly,
    check_dangerous_overrides,
    check_fs_write_exposure,
    check_controlui_origins,
    check_plugin_permission_mode,
    check_hook_policy_bypass,
    check_cron_scheduler,
    # Content-security ring — single source of truth (also consumed by vet_skill).
    # SKILL_CONTENT_RING is defined just above; changing it updates both the full audit
    # and the --vet path so they can never drift apart.
    *SKILL_CONTENT_RING,
    check_exec_applypatch_workspace,
    check_exec_strict_inline_eval,
    check_trustedproxy_loopback,
    check_node_denycommands_ineffective,
    check_subagents_allow_agents,
    check_discovery_mdns_mode,
    check_mcp_tool_inheritance,
    check_mcp_bypass_highblast,
    check_config_audit_log,
    check_config_health_integrity,
    check_session_approval_policy,
    check_gateway_rate_limit,
    check_subagent_spawn_limits,
    check_cachetrace_redaction,
    check_webfetch_redirects,
    check_incident_readiness,
    check_offboarding_hygiene,  # B104 — decommissioning/offboarding hygiene (F-089)
]


def _check_error_finding(chk, exc: BaseException) -> Finding:
    """Degrade a crashing check to one UNKNOWN finding (B-101).

    A single check raising a non-OSError (KeyError/TypeError/re.error/RecursionError,
    …) must not sink the whole audit — that is both an availability failure and an
    evasion primitive (a malicious skill/config crafted to crash one check would
    otherwise suppress the entire report). Only the exception *type* is surfaced —
    never its message — so a path or config value in the error text can't leak (§8).
    """
    name = getattr(chk, "__name__", "unknown_check")
    return Finding(
        id=f"ERR:{name}",
        title=f"Check '{name}' could not run",
        severity=MEDIUM,
        status=UNKNOWN,
        detail=(
            "This check raised an unexpected internal error and was skipped, so its "
            "result is UNKNOWN (it neither passed nor failed). The rest of the audit "
            "ran normally. Re-run with --debug to see the full traceback."
        ),
        fix=(
            "Please report this check name and your OpenClaw version; re-run with "
            "--debug for the traceback."
        ),
        framework="Engine robustness",
        scored=False,
        evidence=[f"error type: {type(exc).__name__}"],
    )


def _check_budget_finding(chk, kind: str, seconds: float | None = None) -> Finding:
    """A check hit the wall-clock budget (C-159) — degrade it to one UNKNOWN finding.

    kind="check": this check overran its own per-check budget (POSIX hard timeout).
    kind="audit": the whole-audit budget was already spent before this check ran (the
    cooperative fallback on platforms without a hard timeout — see scanbudget.py).
    """
    name = getattr(chk, "__name__", "unknown_check")
    why = (
        "the overall audit time budget was exhausted before this check ran"
        if kind == "audit"
        else f"it exceeded its {seconds:g}s wall-clock budget"
    )
    return Finding(
        id=f"ERR:{name}",
        title=f"Check '{name}' timed out",
        severity=MEDIUM,
        status=UNKNOWN,
        detail=(
            f"This check was skipped because {why}, so its result is UNKNOWN (it neither "
            "passed nor failed). The rest of the audit ran normally. This only bounds a "
            "pathological / hostile input; it is not itself a finding."
        ),
        fix="Re-run on a quieter machine; report the check name if it recurs on a normal config.",
        framework="Engine robustness",
        scored=False,
        evidence=[f"scan budget: {kind}"],
    )


def run_all(ctx: Context, check_budget_s: float = DEFAULT_CHECK_BUDGET_S,
            audit_budget_s: float = DEFAULT_AUDIT_BUDGET_S) -> list[Finding]:
    # Per-check isolation (B-101) + wall-clock budget (C-159): a crashing OR hanging
    # check degrades to one UNKNOWN finding instead of aborting the audit. Catch
    # ScanBudgetExceeded before the generic Exception; catch Exception (not
    # BaseException) so KeyboardInterrupt / SystemExit still propagate.
    findings: list[Finding] = []
    deadline = audit_deadline(audit_budget_s)
    for chk in CHECKS:
        if audit_budget_exceeded(deadline):
            findings.append(_check_budget_finding(chk, "audit"))
            continue
        try:
            with check_deadline(check_budget_s):
                findings.append(chk(ctx))
        except ScanBudgetExceeded:
            findings.append(_check_budget_finding(chk, "check", check_budget_s))
        except Exception as exc:  # noqa: BLE001 — a bad check must not sink the audit
            findings.append(_check_error_finding(chk, exc))
    return findings
