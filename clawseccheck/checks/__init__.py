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
    _nfkc_ascii_fold_changed,
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
    _CRED_RE,
    _EXFIL_RE,
    _KNOWN_EXFIL_HOST_RE,
    _SECRET_PATH_RE,
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
    _is_secret_reference,
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
    check_systemd_persistence,
)

from ._shared import (_JSONL_SCAN_CAP, _MCP_REMOTE_TRANSPORTS, _custom, _mcp_has_remote, _mcp_servers, _mcp_url_is_local, _read_jsonl_tail, correlation_indicators, _CORR_INDICATOR_CAP,)
from ._egress import (
    _EXT_SKILL_HINTS,
    _USER_CONTENT_HOSTS,
    _other_can_reach_read,
    _weak_allowlist_entries,
    check_browser_ssrf,
    check_outbound_proxy,
    check_cachetrace_redaction,
    check_config_audit_log,
    check_config_health_integrity,
    check_data_atrest,
    check_discovery_mdns_mode,
    check_egress,
    check_egress_inventory,
    check_leak,
    check_log_threat_hunt,
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
    check_wildcard_group_ingress,
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
    _pattern_hits_real_secret,
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
    check_clawhub_lock_verification,
    check_codex_project_trust,
    check_cron_scheduler,
    check_declared_skill_reconciliation,
    check_hook_policy_bypass,
    check_human_approval,
    check_install_policy,
    check_known_vulns,
    check_memory_poisoning,
    check_offboarding_hygiene,
    check_pending_device_pairing_scope,
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
    _B66_CORE_RE,
    _B66_RESET_RE,
    _B66_ROLE_START_RE,
    _B66_WEAK_RE,
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
    _CLICKFIX_TRUSTED_INSTALLERS,
    _clickfix_trusted_installer,
    _DECODED_BAD_RE,
    _DECODED_STRONG_RE,
    _DECODED_TOOL_CMD_RE,
    _decoded_is_payload,
    _DEFENSIVE_HEADING_RE,
    _DEP_PKG_NAME_RE,
    _EVENT_HOOK_PATH_RE,
    _FENCE_ANNOTATION_RE,
    _FENCE_OPEN_RE,
    _FM_CROSS_SKILL_SQUAT_RE,
    _FM_HOMEPAGE_RE,
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
    _b62_declaration_text,
    _b62_disclosed_families,
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
    check_cross_file_plaintext_payload,
    check_cross_skill_combined_effect,
    check_dependency_confusion,
    check_dormant_capability,
    check_dynamic_dispatch_obfuscation,
    check_event_hook_interceptor,
    check_forged_provenance,
    check_frontmatter_hygiene,
    check_hex_private_key_exposure,
    check_identity_file_injection,
    check_image_attr_injection,
    check_import_from_writable,
    check_install_directive_supply_chain,
    check_instruction_hierarchy_override,
    check_interpreter_interpolation_injection,
    check_lifecycle_hooks_extended,
    check_manifest_absent,
    check_markdown_image_exfil,
    check_overt_secret_exfil,
    check_per_source_trust_contracts,
    check_persona_jailbreak,
    check_prompt_self_replication,
    check_pth_persistence,
    check_prose_bulk_exfil,
    check_remote_code_dependency,
    check_self_privesc_directive,
    check_silent_instruction,
    check_social_engineering_phishing,
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
    _fetch_prohibition_governs,
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

from ._mcp import (
    _C038_COMMENT_RE,
    _C038_DATA_URI_RE,
    _C038_HIDDEN_INSTR_RE,
    _C038_PARAM_INJECT_RE,
    _LP_CAP_FAMILIES,
    _LP_SCOPE_READONLY_RE,
    _LP_SCOPE_WRITE_RE,
    _MCP_AXIS_BEHAVIOR,
    _MCP_AXIS_BUILD,
    _MCP_AXIS_CONNECTIONS,
    _MCP_CURL_RE,
    _MCP_META_IP_RE,
    _MCP_SECRET_ENV_RE,
    _MCP_UNPINNED_RE,
    _PLUGIN_FILE_CAP,
    _PLUGIN_MCP_SKIP,
    _PLUGIN_SKIP_DIRS,
    _PLUGIN_SNIFF_BYTES,
    _VET_MCP_BROAD_SCOPE_RE,
    _VET_MCP_DANGEROUS_CMDS,
    _VET_MCP_RUNNER_CMDS,
    _VET_MCP_UNPINNED_PKG_RE,
    _VET_RANK_STATUS,
    _load_mcp_spec_file,
    _lp_detect_caps,
    _mcp_has_tool_restrictions,
    _mcp_reason_axis,
    _mcp_server_risks,
    _plugin_finding,
    _vet_mcp_least_privilege,
    _vet_mcp_server,
    _vet_mcp_tool_poisoning,
    check_mcp,
    check_mcp_bypass_highblast,
    check_mcp_external_endpoint,
    check_mcp_hardening,
    check_mcp_server_exfil_host_in_args,
    check_mcp_tool_inheritance,
    check_plugin_permission_mode,
    check_codex_plugin_hooks,
    check_orphaned_plugin_caches,
    vet_mcp,
    vet_plugin,
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


# B76 — High-blast MCP tool-inheritance bypass (scored, attested)
# ---------------------------------------------------------------------------


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
    check_identity_file_injection,
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
    check_mcp_server_exfil_host_in_args,
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
    check_outbound_proxy,
    check_session_visibility,
    check_untrusted_context,
    check_wildcard_group_ingress,
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
    # B105 — cross-skill Signal-A/Signal-B combined effect (B-096). Deliberately OUTSIDE
    # SKILL_CONTENT_RING: it correlates across ctx.installed_skills, which only ever has
    # multiple entries at full-audit scope — the --vet path builds a single-entry context
    # where the correlation is structurally impossible, so it's registered here directly.
    check_cross_skill_combined_effect,
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
    check_log_threat_hunt,  # B164 — content-scan the agent's own log corpus (F-124/E-044)
    check_offboarding_hygiene,  # B104 — decommissioning/offboarding hygiene (F-089)
    check_codex_project_trust,  # B136 — Codex CLI project trust_level="trusted"
    check_pending_device_pairing_scope,  # B138 — dangling high-scope pending device pairing
    check_systemd_persistence,  # B150 — systemd user-unit Restart=always persistence
    check_codex_plugin_hooks,  # B151 — codex connector shell hooks in the plugin doc-cache
    check_orphaned_plugin_caches,  # B152 — on-disk plugin cache not in plugins.entries
    check_clawhub_lock_verification,  # B135 — accepted-despite-failed-verification install
    check_declared_skill_reconciliation,  # B158 — declared-but-unresolved skill-load source (F-119)
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
