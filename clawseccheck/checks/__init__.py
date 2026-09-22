"""Check engine: Block A (Lethal Trifecta) + Block B (hardening) + advisory.

Every check is read-only and grounded on real OpenClaw config fields
(see docs/specs/openclaw-audit-skill-spec.md v2). Heuristics are conservative:
we FAIL only on positive evidence, WARN on likely-insecure defaults, and
UNKNOWN when the config cannot tell us (excluded from score — honesty).
"""

from __future__ import annotations

import ast
import base64
import binascii
import html
import inspect
import ipaddress
import json
import logging
import os
import re
import shutil
import textwrap
import traceback
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
    # B-288: root-`hooks` session-key/agent-routing policy family + the gateway
    # remote-exposure label RISK-20 composes it with.
    _active_channels,
    _agent_is_powerful,
    _agent_legs,
    _agent_tools_widenings,
    _agents_without_exec_gate,
    _bind_mentions_docker_sock,
    _bind_mode_is_ro,
    _canon_tool,
    _canonical_ipv4,
    _channel_has_implicit_default_account,
    _channels,
    _channels_with_context_visibility_all,
    _config_unreadable,
    _CRED_RE,
    _DESTRUCTIVE_HINTS,
    _enabled_tools,
    _EXFIL_RE,
    EXPOSED_BINDS,
    _external_input_channels,
    _finding,
    _exec_policy_is_gated,
    _gateway_remote_exposure_reason,
    _has_approval_gate,
    _hint,
    _layer_exec_policy,
    _hooks_agent_ids_unrestricted,
    _hooks_allowed_session_key_prefixes,
    _hooks_session_key_exposures,
    _IMPLICIT_DEFAULT_ACCOUNT_KEYS,
    INPUT_TOOL_HINTS,
    _is_own_source,
    _is_posix,
    _is_public_ip,
    _is_secret_reference,
    _KNOWN_EXFIL_HOST_RE,
    _LEG_KEYS,
    LOOPBACK,
    _loopback_ip,
    _LoopbackHostSet,
    _MAX_WALK_DEPTH,
    _meta,
    _norm_group_policy,
    _open_channels,
    OUTBOUND_TOOL_HINTS,
    OUTBOUND_TOOL_IDS,
    _OWN_ENGINE_MARKERS,
    parse_bind_host,
    _perms_loose,
    _POWERFUL_PROFILES,
    _profile_is_powerful,
    _real_exec_enabled,
    _resolve_sandbox_scope,
    _safe_mtime,
    _sandbox_browser_binds,
    _sandbox_browser_enabled,
    _sandbox_docker_binds,
    _sandbox_has_writable_bind,
    SECRET_KEY_RE,
    _SECRET_PATH_RE,
    _secret_paths,
    SECRET_PATTERNS,
    SENSITIVE_TOOL_HINTS,
    _skill_corpus_complete,
    _surface_absent,
    _TIER_NAME,
    _unclassified_leg_verbs,
    _untrusted_input_channels,
    _UNTRUSTED_INPUT_POLICIES,
    _username_safe_path,
    _web_fetch_enabled,
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
    check_host_scheduled_persistence,
    check_bundled_root_override,
    check_unit_embedded_gateway_secret,
    check_audit_trail_signals,
    _fmt_epoch_ms,
)

from ._shared import (_JSONL_SCAN_CAP, _MCP_REMOTE_TRANSPORTS, _custom, _mcp_has_remote, _mcp_servers, _mcp_tool_texts, _mcp_url_is_local, _read_jsonl_tail, correlation_indicators, _CORR_INDICATOR_CAP,)
from ._shared import (_RETIRED_CONFIG_KEYS, _retired_keys_present,)
from ._shared import (_key_advice, _openclaw_generation, _retired_key_note, _MCP_DATA_CAP_RE, _MCP_FS_PKG_RE, _MCP_BROAD_FS_ROOTS, _mcp_fs_root_is_broad, _mcp_sensitive_reason, _mcp_leg_contributions, _node_commands, _node_allow_skills,)
from ._shared import (_MCP_INTAKE_CAP_RE, _mcp_intake_reason,)
# B-297: the wildcard-group ingress predicate — risk.py's ingress leg reaches it only
# through this aggregator (CLAUDE.md §3.1-a), never by importing a topic module.
from ._shared import (_allow_from_is_present, _effective_group_allow_from, _is_wildcard_allow_entry, _open_wildcard_group_channels, _resolved_channel_nodes, _wildcard_group_gap, _wildcard_group_is_reachable,)
from ._egress import (
    _EXT_SKILL_HINTS,
    _USER_CONTENT_HOSTS,
    _ancestors_allow_other_access,
    _other_can_reach_read,
    _weak_allowlist_entries,
    check_browser_ssrf,
    check_browser_extra_args,
    check_browser_evaluate_enabled,
    check_browser_executable_path,
    check_browser_existing_session_profile,
    check_browser_cdp_control_port,
    check_browser_extension_relay_legacy_auth,
    _cdp_url_classify,
    _cdp_url_display,
    _cdp_allow_origins_findings,
    _offhost_cdp_endpoints,
    _chrome_switch_name,
    _remote_debug_bind_class,
    _whatwg_url,
    check_outbound_proxy,
    check_provider_baseurl,
    check_otel_content_capture_egress,
    check_memory_search_remote_egress,
    check_secrets_egress_proxy,
    check_attachments_ttl,
    check_cachetrace_redaction,
    check_config_audit_log,
    check_config_health_integrity,
    check_data_atrest,
    check_state_db_atrest,
    check_debug_proxy_capture,
    _other_can_reach_write,
    check_discovery_mdns_mode,
    check_egress,
    check_egress_inventory,
    check_leak,
    check_log_threat_hunt,
    check_webfetch_redirects,
)

from ._shared import (_trifecta_legs, _trifecta_leg_sources,)  # B-493
from ._shared import (  # C-462
    _FS_GOVERNED_TOOL_IDS,
    _fs_reads_are_confined,
)
from ._shared import (  # B-667
    SENSITIVE_TOOL_IDS,
    _attested_tool_id_sources,
    _tool_id_sources,
)
from ._shared import (  # B-666
    _CRED_STORE_MAX_BYTES,
    _CRED_STORE_MAX_FILES,
    _CRED_STORE_MAX_NAMES,
    _credential_store_state,
)
from ._shared import (_unpolicied_open_wildcard_group_channels,)  # B-371
from ._agents import (
    _ACTIONS_ALLOW_UNDETERMINED,
    _B21_OBEY_RE,
    _B21_SAFE_STANCE_RE,
    _B21_SOURCE_RE,
    _B30_HISTORY_KEY,
    _B30_NAME_MATCH_KEY,
    _DELEGATION_TIER,
    _MESSAGE_CROSS_CONTEXT_GUARDED_ACTIONS,
    _WEB_FETCH_SKILL_HINTS,
    _b21_has_trust_boundary,
    _disk_subagent_disclosure,
    _has_subagents,
    _message_actions_allow_for_scope,
    _message_actions_guarded_reachable,
    _reassembly,
    check_embedded_agent_project_settings_policy,
    check_agent_separation,
    check_agent_to_agent_pivot,
    check_channel_allow_bots,
    check_channel_mention_gate_bypass,
    check_cross_context_send,
    check_delegation_reassembly,
    check_multiagent_exposure,
    check_sender_identity,
    check_session_reset_triggers,
    check_session_scope_global,
    check_session_visibility,
    check_subagent_spawn_limits,
    check_subagents,
    check_subagents_allow_agents,
    check_swarm_fanout_limits,
    check_tool_output_trust,
    check_untrusted_context,
    check_wildcard_group_ingress,
)

from ._capability import (
    _b352_effective_prepends,
    _b352_risky,
    check_exec_path_prepend,
    _b351_normalize_agent_id,
    _b351_resolvable_agents,
    _b351_enabled,
    _b351_raw_code_mode,
    check_code_mode_tool_surface,
    _AUTO_GATE_BLAST,
    _B31_BYPASS_CANDIDATES,
    _B31_WRITE_CLASS,
    _B55_FS_WRITE_TOOLS,
    _B71_INEFFECTIVE_RE,
    _FS_WRITE_TOOL_HINTS,
    _ToolPolicyView,
    _agent_profile_widenings,
    _approval_bypass_actors,
    _b31_collect_deny_lists,
    _b55_write_tools_granted,
    _b68_fs_tools_granted,
    _has_heartbeat_signal,
    _tool_policy_view,
    check_attestation_mismatch,
    check_capability_blast_radius,
    check_declared_effective_proven,
    check_effective_tools,
    check_elevated_default_full,
    check_exec_applypatch_workspace,
    check_exec_strict_inline_eval,
    check_fs_write_exposure,
    check_node_allowskills_default_on,
    check_node_denycommands_ineffective,
    check_path_safety,
    _b378_normalize_path_for_compare,
    check_agent_cwd_relocation,
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
    _is_owner_wildcard_allow_from,
    _DANGER_FIXED_2026_8_1,
    _MISSING_LEG_ACTIVATORS,
    _c015_candidate_files,
    _c015_has_secret,
    _capabilities_attested,
    _is_constraining_proxy_entry,
    _distance_note,
    _meaningful_tool_surface,
    _model_names,
    _multi_agent_note,
    _persistence_note,
    _net_is_private,
    _pattern_hits_real_secret,
    _peragent_sandbox_evidence,
    _trusted_proxies_ok,
    _NATIVE_UNCONDITIONAL_CRITICAL_CHECK_IDS,
    _is_native_unconditional_critical_check_id,
    _ENV6_TOGGLES,
    _b323_is_literal_path_override,
    check_env_vars_path_override,
    check_audit_target_divergence,
    check_audit_suppressions,
    check_cloudworkers_prepared_pool,
    check_control_plane_mutation,
    check_env_breakglass_toggles,
    check_shell_env_fallback,
    check_chat_completions_endpoint,
    check_control_ui_embed_sandbox,
    check_controlui_origins,
    check_credential_blast_radius,
    check_config_externally_managed,
    check_retired_config_keys_invalid,
    check_dangerous_overrides,
    check_desktop_host_exposure,
    check_desktop_host_password_file,
    check_effective_bind,
    check_gateway,
    check_gateway_computer_plugin_reach,
    check_gateway_operator_terminal,
    check_gateway_rate_limit,
    check_gateway_remote_ssh_host_key_policy,
    check_hook_template_content,
    check_hook_transform_modules,
    check_hooks_enable_toggles,
    check_least_privilege,
    check_local_first,
    check_local_model_service_command,
    check_privileged_commands_exposure,
    check_proxy_header_forging,
    check_redactor_blind_secret_paths,
    check_sandbox,
    check_secrets,
    check_secrets_at_rest_home,
    check_tls,
    check_trifecta,
    check_trustedproxy_loopback,
)

from ._shared import (INJECTION_PATTERNS, LOG_SCAN_INJECTION_PATTERNS, _FM_BLOCK_BARE_RE, _FM_BLOCK_HEADERED_RE, _HOOK_EXEC_RE, _skill_frontmatter_block,)
from ._shared import (_B323_ENV_VAR_NAME_RE, _b323_parse_env_token_at, _b323_contains_env_var_reference,)  # B-397: relocated from _config (reused by B326 too)
from ._shared import (_SYMLINK_KNOB_RETIRED_MIN, _workshop_symlink_knob,)  # B-783
from ._shared import (_CROSS_CONTEXT_DEFAULT_ALLOW_MIN, _CROSS_CONTEXT_DENY_MEASURED_MIN, _cross_context_default,)  # B-833
from ._lifecycle import (
    _APPROVAL_BYPASS_RE,
    _B182_ENV_OVERRIDES,
    _B184_CODELOAD_ENV_VARS,
    _B184_REGISTRY_ENV_VARS,
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
    _b135_is_pending_security,
    _b135_reasons_are_inconclusive,
    _b135_records_adverse_security,
    _b181_confined_path,
    _b181_recorded_files,
    _b182_audits_this_users_own_home,
    _b182_candidate_stores,
    _b182_readable_by_others,
    _b184_is_canonical,
    _iter_entries,
    _parse_version,
    _writable_identity_files,
    _writable_skill_dirs,
    _b325_feed_host_is_canonical,
    _b328_creation_only_bypass_root,
    check_marketplace_feed_provenance,
    check_exec_safe_bin_trusted_dirs,
    check_approval_bypass,
    check_autonomy,
    check_backups,
    check_bootstrap_injection,
    check_bootstrap_write_protection,
    check_clawhub_lock_verification,
    check_clawhub_registry_provenance,
    check_codex_project_trust,
    check_cron_job_content,
    check_cron_run_log_orphans,
    check_cron_scheduler,
    check_declared_skill_reconciliation,
    check_dependency_tree_hooks,
    check_exec_approvals_grants,
    check_hook_policy_bypass,
    check_human_approval,
    check_install_policy,
    check_install_policy_gate,
    check_secrets_provider_exec,
    check_known_vulns,
    check_legacy_state_migration_pending,
    check_memory_poisoning,
    check_memory_reconsumption_injection,
    check_offboarding_hygiene,
    check_paired_device_operator_authority,
    check_pending_device_pairing_scope,
    check_restart_handoff_stale,
    check_self_modification,
    check_clawhub_token_store,
    check_session_approval_policy,
    check_skill_install_tamper,
    check_skill_library_reachability,
    check_skill_workshop_autonomy,
    check_skill_symlink_target_writability,
    check_skill_load_hot_reload,
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
    _B62_AMBIG_BENIGN_ADJ,
    _B62_DESCRIPTION_RE,
    _B62_EXPECTED,
    _B62_HIGH_SURPRISE,
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
    _B66_AUTHORITY_NEUTRALIZE_RE,
    _B66_CORE_RE,
    _B66_MODE_DECLARATION_RE,
    _B66_RESET_RE,
    _B66_ROLE_START_RE,
    _B66_WEAK_RE,
    _B66_WINDOW,
    _B67_CHANNEL_SRC_RE,
    _B67_TRUST_RE,
    _B67_WINDOW,
    _B170_ELEVATE_RE,
    _B170_SOURCE_RE,
    _B170_WINDOW,
    _B74_DEFENSIVE_FRAME_RE,
    _B74_FALSE_PROVENANCE_RE,
    _B74_ROLE_BLOCK_RE,
    _B74_TURN_DIRECTIVE_RE,
    _B95_UNPINNED_PKG_RE,
    _B98_DANGEROUS_PRIMITIVE_RE,
    _BACKUP_TRANSPORT_VERB_RE,
    _BROAD_NEGATION_RE,
    _BROAD_NEGATION_WINDOW,
    _CLICKFIX_IMPERATIVE_RE,
    _CLICKFIX_PROXIMITY_WINDOW,
    _CLICKFIX_REMOTE_FETCH_RE,
    _CLICKFIX_TRUSTED_INSTALLERS,
    _clickfix_public_ip_fetch,
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
    _b62_env_key_is_credential,
    _b62_extract_declaration,
    _b62_src_reads_cred,
    _b62_surprising_families,
    _b63_decoded_actionable,
    _b63_scan,
    _b64_actionable_continuation,
    _b64_classify,
    _b64_reported_or_quoted,
    _b65_scan,
    _b66_authority_override_scan,
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
    _verb_class_matches,
    _whole_text_is_defensive,
    check_agent_snooping,
    check_capability_intent_mismatch,
    check_chunked_file_assembly_exec,
    check_clickfix_setup_section,
    check_cloud_metadata_credential_fetch,
    check_conditional_sleeper_trigger,
    check_config_trust_widening,
    check_cross_file_boundary_payload,
    check_cross_file_payload,
    check_cross_file_plaintext_payload,
    check_cross_skill_combined_effect,
    check_deaddrop_resolver,
    check_dependency_confusion,
    check_dormant_capability,
    check_dotfile_exfil_directive,
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
    check_model_artifact_provenance,
    check_offensive_tooling_directive,
    check_overt_secret_exfil,
    check_per_source_trust_contracts,
    check_persona_jailbreak,
    check_prompt_self_replication,
    check_pth_persistence,
    check_python_runtime_persist_install,
    check_prose_bulk_exfil,
    check_prose_host_fingerprint_exfil,
    check_remote_code_dependency,
    check_self_erase_directive,
    check_self_modification_directive,
    check_self_privesc_directive,
    check_silent_instruction,
    check_sitecustomize_pythonstartup_scoped_install,
    check_social_engineering_phishing,
    check_symlink_escape,
    check_tool_output_trust_inversion,
    check_trigger_homoglyph,
    check_tunnel_enrollment,
    check_undocumented_helper_directive,
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
    coverage_gap_finding,
    _runtime_fetch_matches,
    _skill_own_host,
    _skill_tool_overgrant,
    _url_matches_own_host,
    check_installed_skills,
    detect_vet_type,
    detect_vet_type_with_reason,
    resolve_skill_target,
    vet_skill,
    vet_source,
)

from ._mcp import (
    _C038_COMMENT_RE,
    _B331_AUTHORITY_BASE_RE,
    _B331_CONFIDENTIAL_RE,
    _B331_DATA_URI_RE,
    _B331_DATA_URI_SAFE_MIME_RE,
    _B331_DISREGARD_FORGET_RE,
    _B331_EXFIL_PARAM_RE,
    _B331_PREAMBLE_RE,
    _B331_ROLE_TAG_RE,
    _C038_DATA_URI_RE,
    _C038_HIDDEN_INSTR_RE,
    _C038_PARAM_INJECT_RE,
    _HOST_SANITIZE_DISREGARD_RE,
    _HOST_SANITIZE_IGNORE_RE,
    _HOST_SANITIZE_PLACEHOLDER,
    _HOST_SANITIZE_TEXT_LIMIT,
    _INSTR_OVERRIDE_SRC,
    _LP_CAP_FAMILIES,
    _LP_SCOPE_READONLY_RE,
    _LP_SCOPE_WRITE_RE,
    _MCP_AXIS_BEHAVIOR,
    _MCP_AXIS_BUILD,
    _MCP_AXIS_CONNECTIONS,
    _B332_CLONE_JACCARD,
    _B332_CLONE_MIN_NAMES,
    _B332_GENERIC_TOOL_NAMES,
    _B332_MAX_TOTAL_NAMES,
    _B332_MIN_SPECIFIC_LEN,
    _B332_MIN_WARN_LEN,
    _B332_ZERO_WIDTH_RE,
    _B333_HINT_KEYS,
    _MCP_CONN_STRING_CREDENTIAL_RE,
    _MCP_CURL_RE,
    _MCP_META_IP_RE,
    _MCP_RING_SKIP_IDS,
    _MCP_RING_SKIP_STATUSES,
    _MCP_SECRET_ENV_RE,
    _MCP_SURFACE_SENTINEL_HOME,
    _MCP_UNPINNED_RE,
    _PARAM_EXFIL_DEST_RE,
    _PARAM_OVERRIDE_INSTR_RE,
    _PARAM_OVERRIDE_LOOSE_RE,
    _PARAM_JAILBREAK_PERSONA,
    _PARAM_ROLE_FORGERY_RE,
    _PARAM_SENTENCE_SPLIT_RE,
    _PLUGIN_FILE_CAP,
    _PLUGIN_MCP_SKIP,
    _PLUGIN_SKIP_DIRS,
    _PLUGIN_SNIFF_BYTES,
    _VET_MCP_BROAD_SCOPE_RE,
    _VET_MCP_DANGEROUS_CMDS,
    _VET_MCP_RUNNER_CMDS,
    _VET_MCP_SCOPE_LIST_SEP_RE,
    _VET_MCP_SCOPE_SEGMENT_SEP_RE,
    _VET_MCP_UNPINNED_PKG_RE,
    _VET_RANK_STATUS,
    _b331_authority_hit,
    _b331_authority_verdict,
    _b331_data_uri_hit,
    _b331_exfil_param_hit,
    _b331_findings,
    _b331_secrecy_hit,
    _b331_tool_findings,
    _b332_bare_tool_name,
    _b332_clone_server_pairs,
    _b332_collisions,
    _b332_finding_from_surfaces,
    _b332_homoglyph_signal,
    _b332_is_generic,
    _b332_unique_names,
    _b333_hinted_tool_names,
    _b333_modern_surface_verdict,
    _b333_waived_tool_names,
    _mcp_codex_annotations,
    _mcp_codex_approval_mode,
    _mcp_codex_is_loopback_server,
    _mcp_codex_normalize_mode,
    _mcp_codex_requires_approval,
    _mcp_is_per_requester,
    _mcp_normalize_tool_filter,
    _mcp_tool_allowed,
    _mcp_tool_filter_matches,
    _b333_surface_verdict,
    _host_sanitize_simulated,
    _load_mcp_spec_file,
    _lp_detect_caps,
    _mcp_has_tool_restrictions,
    _mcp_reason_axis,
    _mcp_server_risks,
    _mcp_value_looks_secret,
    _merge_mcp_surface_ring,
    _param_override_reason,
    _plugin_finding,
    _vet_mcp_least_privilege,
    _vet_mcp_scope_is_broad,
    _vet_mcp_server,
    _vet_mcp_tool_poisoning,
    check_acp_backend_inventory,
    check_agent_runtime_id_inventory,
    check_mcp,
    check_mcp_bypass_highblast,
    check_mcp_external_endpoint,
    check_mcp_hardening,
    check_mcp_host_sanitizer_gap,
    check_mcp_server_exfil_host_in_args,
    check_mcp_tool_inheritance,
    check_mcp_tool_name_shadowing,
    check_mcp_codex_preapproved_tools,
    check_mcp_unenforced_annotations,
    check_plugin_app_server_command,
    check_plugin_clawhub_trust,
    check_plugin_hook_grants,
    check_plugin_permission_mode,
    check_plugin_slots_and_deny,
    check_plugin_tool_result_middleware,
    check_codex_plugin_hooks,
    check_compiled_tool_poisoning,
    check_orphaned_plugin_caches,
    check_undeclared_plugin_load_path,
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
#
#   CORRECTED 2026-07-20 (F-133/B185) — the premise above is STALE. The reasoning
#   "tool metadata comes from the live server handshake, which we never perform
#   offline" was sound when written, but it is now false as a statement about our
#   EVIDENCE: OpenClaw records the tool definitions it actually sent to the model into
#   the trajectory sidecar as a `context.compiled` event, with `description` copied
#   VERBATIM (dist selection-JInn13lc.js:752/14035, run-attempt-CXZNKJ6y.js:5228). A
#   description poisoned by a LIVE MCP server is therefore already on the user's disk
#   and is readable with no network call at all.
#
#   What stays true: TP1/TP3 as written here still see only inline config, and still
#   produce no output on real configs. What changed: that is no longer the whole
#   picture, and it must not be read as "poisoned live tool descriptions are
#   undetectable offline". `check_compiled_tool_poisoning` (B185, in checks/_mcp.py)
#   covers the runtime surface by reading `context.compiled`. It is strictly POST HOC
#   — it proves what WAS delivered in sessions that already ran, and can never
#   pre-clear a live MCP server.
# ---------------------------------------------------------------------------

# TP2: mixed-script / RTL-override / invisible chars in identifiers (suspicious).
# Reuses normalize_for_scan / obfuscation_signals from textnorm.


_B30_PROVIDERS_WITH_NAME_MATCH = ("discord", "slack")


# ---------- B38: Browser Control / Cookie & SSRF Exposure ----------
# browser.ssrfPolicy.dangerouslyAllowPrivateNetwork (bool) — lets the agent browser
# reach internal/metadata IPs (cloud-credential theft via 169.254.169.254).
# browser.noSandbox (bool) — browser runs without OS sandbox.
# browser.ssrfPolicy.allowedHostnames (array) — restrict outbound browser targets.
#   B-515: the installed dist honours TWO sibling keys under ssrfPolicy and merges
#   them at runtime — allowedHostnames (current) and hostnameAllowlist (which the
#   vendor itself labels legacy/alternate). B38 reads BOTH and combines them, so an
#   allowlist counts as present when EITHER holds a non-empty list; keying on the
#   legacy field alone warned at operators who had configured the current one.
#   See check_browser_ssrf in checks/_egress.py.
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
# Defined in checks/_vet.py, imported above, spliced into CHECKS below. This block
# explains it; the tuple itself is not here.
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
    check_redactor_blind_secret_paths,  # B381 — secret-shaped value at a redactor-blind config path (C-405)
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
    check_mcp_unenforced_annotations,  # B333 — MCP safety-hint annotations, per build (F-143/W2.1)
    check_mcp_codex_preapproved_tools,  # B353 — MCP server pre-approves every tool (F-185)
    check_mcp_host_sanitizer_gap,  # B331 — MCP tool-description injection past the host sanitizer (F-144/W2.2)
    check_mcp_tool_name_shadowing,  # B332 — cross-server tool-name collision/homoglyph/near-miss (F-145/W2.3)
    # B369-B370 (C-413) — runtime-exec inventory: acp.backend routes agent turns to a
    # plugin backend; agentRuntime.id names the external process that runs a model's
    # turns (real path corrected from the filed task's models.providers.*.agentRuntime.id
    # to agents.{defaults,entries.<id>}.models.<ref>.agentRuntime.id).
    check_acp_backend_inventory,
    check_agent_runtime_id_inventory,
    check_proxy_header_forging,
    check_monitoring,
    check_autonomy,
    check_subagents,
    check_data_atrest,
    check_state_db_atrest,  # B188 — state DB device keys/auth tokens readable at rest (B-293)
    check_debug_proxy_capture,  # B190 — debug-proxy env cluster + captured traffic on disk (B-295)
    check_bootstrap_write_protection,
    check_self_modification,
    check_skill_workshop_autonomy,  # B175 — skills.workshop autonomous authoring + approvalPolicy=auto
    # B367-B368 (C-413) — skills.load.allowSymlinkTargets widens where executable skill
    # code loads from via a symlink; skills.load.watch hot-reloads skill definitions with
    # no gateway restart to interrupt a planted/mutated file.
    check_skill_symlink_target_writability,
    check_skill_load_hot_reload,
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
    check_provider_baseurl,  # B178 — models.providers.<id>.baseUrl cleartext http:// leak
    # B365-B366 (C-412) — raw-content egress: diagnostics.otel content capture ships full
    # model turns to a network collector (gated on a 4-key conjunction traced from the
    # runtime, not the schema description); memory.search.remote sends every embedded
    # memory chunk to a configured third-party endpoint (global + per-agent scope).
    check_otel_content_capture_egress,
    check_memory_search_remote_egress,
    # B387 (F-196) — secrets.egressProxy (new in OpenClaw 2026.8.1, re-grounded on
    # 2026.9.5): WARN when the proxy is enabled with no allowedHosts, since OpenClaw's
    # own docs say omitting it (not an empty array — that is lockdown) leaves
    # non-sentinel proxy traffic unrestricted. Never FAIL: both allowedHosts and
    # bypassHosts already reject a wildcard at config-load time (EgressProxyExactHostSchema
    # / normalizeExactAllowedHost), so there is no FAIL-worthy wildcard shape to catch.
    check_secrets_egress_proxy,
    # B390 (F-201) -- attachments.ttlHours (straight rename of pre-8.1 media.ttlHours):
    # WARN when unset, since OpenClaw's own runtime sweep gate
    # (`params.ttlHours !== void 0 && ...`) never runs the expiry check at all without
    # it, so staged incoming media (screenshots, voice notes, forwarded files)
    # accumulates on disk indefinitely. PASS on any set number. Never FAIL: a
    # data-hygiene gap, not a proven compromise. See the check's own docstring for the
    # full grounding against the installed 2026.9.5 dist (the internal recon's own
    # descriptions map omits the `attachments` namespace).
    check_attachments_ttl,
    check_session_visibility,
    # B361-B364 (C-411) — remote-ingress / multi-user session hardening: unrestricted
    # cross-agent session-tool access reachable from an open channel; session.scope
    # sharing one session across senders; cross-provider message egress (global +
    # per-agent, since an agent can widen past a safe global default); disclosure of
    # any inbound-phrase session-reset trigger.
    check_agent_to_agent_pivot,
    check_session_scope_global,
    check_cross_context_send,
    check_session_reset_triggers,
    # B371/B372 (C-525, split out of C-411) — requireMention/chatmode mention-gate
    # bypass and allowBots bot-authored-input admission, both scoped to channels
    # that admit non-owner senders; nesting is genuinely heterogeneous per
    # provider (root/account/groups/rooms/guilds.channels/groups.topics/channels),
    # see _mention_gate_scopes in checks/_shared.py for the grounding trail.
    check_channel_mention_gate_bypass,
    check_channel_allow_bots,
    check_untrusted_context,
    check_wildcard_group_ingress,
    check_known_vulns,
    check_credential_blast_radius,
    check_retired_config_keys_invalid,  # B382 — retired config key the installed build rejects (F-184)
    check_config_externally_managed,  # B373 — OPENCLAW_CONFIG_READONLY / Nix mode (C-527)
    check_effective_tools,
    check_host_network_ids,
    check_host_audit,
    check_host_file_integrity,
    check_host_edr,
    check_host_firewall,
    check_host_egress_posture,
    check_capability_blast_radius,
    check_elevated_default_full,  # B326 — agents.defaults.elevatedDefault="full" bypasses approval
    check_attestation_mismatch,
    check_declared_effective_proven,
    check_agent_separation,
    check_multiagent_exposure,
    check_embedded_agent_project_settings_policy,  # B327 — agents.defaults.embeddedAgent.projectSettingsPolicy (E-060 item 10)
    check_delegation_reassembly,
    check_dangerous_overrides,
    check_privileged_commands_exposure,  # B171 — commands.bash/config/mcp/plugins gate (B-235)
    check_hook_template_content,  # B169 — hooks.mappings[] template content scan (B-231)
    check_hook_transform_modules,  # B380 — hooks.mappings[].transform.module inventory/writability (C-406)
    check_fs_write_exposure,
    check_controlui_origins,
    check_plugin_permission_mode,
    check_plugin_app_server_command,  # B167 — plugin appServer.command remote-fetch scan (B-231)
    check_plugin_hook_grants,  # B341 — per-plugin-entry prompt-mutation / transcript-read grants
    check_plugin_slots_and_deny,  # B342 — plugin slot ownership + allow/deny contradiction
    check_hook_policy_bypass,
    check_cron_scheduler,
    check_cron_job_content,  # B168 — cron job store payload.message/trigger.script scan (B-231)
    check_cron_run_log_orphans,  # B189 — cron run log without a surviving job definition (B-294)
    check_exec_approvals_grants,  # B172 — standing exec-approvals.json allow-always grant inventory (B-236)
    # Content-security ring — single source of truth (also consumed by vet_skill).
    # SKILL_CONTENT_RING is DEFINED in checks/_vet.py and imported at the top of this
    # file; the block above documents it, it does not declare it. Splicing it here is
    # what keeps the full audit and the --vet path from drifting apart.
    # (Said precisely because the earlier wording — "defined just above" — sent a reader
    # looking for the tuple in this file, where it is not.)
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
    check_node_allowskills_default_on,  # B386 — paired-node skill push default-on (F-199)
    check_subagents_allow_agents,
    check_discovery_mdns_mode,
    check_mcp_tool_inheritance,
    check_mcp_bypass_highblast,
    check_config_audit_log,
    check_config_health_integrity,
    check_session_approval_policy,
    check_gateway_rate_limit,
    check_effective_bind,  # B340 — corroborate declared gateway.bind against the actual listening socket (F-156)
    # B384/B385 (F-197): desktop.host is a second network listener beside the gateway
    # (a VNC/RFB service, default port 5900) plus its passwordFile credential — both
    # completely unread before this. B384 corroborates the always-loopback design
    # assumption against the actual listening socket (sockets.py, same spirit as
    # B340); B385 checks the password file's at-rest permissions (same idiom as
    # B182/B193).
    check_desktop_host_exposure,
    check_desktop_host_password_file,
    # B350 — the gateway operator terminal: a PTY-backed shell carrying the gateway
    # process environment, served to Control UI and mobile clients. WARN-only.
    check_gateway_operator_terminal,
    # B389 — the Gateway's own unmanaged-desktop `computer`
    # control route (computer.invoke/computer.status), which bypasses
    # gateway.nodes.commands.deny and has no per-action confirmation. WARN-only,
    # unscored advisory; requires both the plugin's explicit opt-in and an agent
    # scope granted `computer` while unsandboxed.
    check_gateway_computer_plugin_reach,
    # B351 — code mode: the model is handed exec+wait over a catalog bridge instead of
    # the ordinary tool surface. Walks agents.list, which can enable it independently.
    check_code_mode_tool_surface,
    # B352 — tools.exec.pathPrepend: what OpenClaw exports ahead of $PATH for every
    # exec run. Skips scopes where host=node, which the runtime ignores.
    check_exec_path_prepend,
    # B378 — agents.defaults.cwd / agents.entries.<id>.cwd (new
    # in OpenClaw 2026.9.1): relocates the task/exec working directory away from the
    # workspace, which OpenClaw's own sandbox guard rejects unless the run is
    # unsandboxed. WARN-only; PASS only when cwd provably matches that scope's own
    # declared workspace.
    check_agent_cwd_relocation,
    # B355 (C-408) — models.providers.*.localService.command: a binary OpenClaw spawns
    # at provider startup. WARN when writable by another account; the relative-path
    # case the original stub worried about is refuted (the runtime refuses to spawn
    # a relative command at all) and is not reported here.
    check_local_model_service_command,
    # B358 (C-410) — gateway.http.endpoints.chatCompletions: WARN on the OpenAI-shaped
    # remote ingress; WARN (never FAIL) when images.allowUrl is also on — the vendor's
    # own SSRF guard unconditionally blocks private/internal/metadata targets, so an
    # absent urlAllowlist is open-proxy-shaped (any public host), not SSRF.
    check_chat_completions_endpoint,
    # B359 (C-410) — gateway.remote.sshHostKeyPolicy: WARN when host-key verification
    # for the remote-gateway SSH tunnel is delegated to OpenSSH instead of pinned.
    check_gateway_remote_ssh_host_key_policy,
    # B360 (C-410) — gateway.controlUi.embedSandbox="trusted": WARN when a hosted
    # Control UI embed gets allow-same-origin (XSS in the embed reaches the operator).
    check_control_ui_embed_sandbox,
    check_subagent_spawn_limits,
    check_swarm_fanout_limits,  # B392 (F-200) — beside B81, FAIL-capable at the vendor hard ceiling
    check_cachetrace_redaction,
    # B-281/B-282 (ENV-1/ENV-6): is the audited file the one the agent loads, and is a
    # break-glass toggle left on in a file OpenClaw loads at startup. Both WARN-only.
    check_audit_target_divergence,
    check_env_breakglass_toggles,
    check_shell_env_fallback,  # B324 — env.shellEnv.enabled agent-startup shell import (E-060 item 7)
    check_env_vars_path_override,  # B323 — env.vars.PATH / env.<KEY> catchall PATH override (E-060 item 6)
    check_webfetch_redirects,
    check_incident_readiness,
    check_log_threat_hunt,  # B164 — content-scan the agent's own log corpus (F-124/E-044)
    check_memory_reconsumption_injection,  # B180 — injected directive found in agent memory (F-127/E-044 Phase 5)
    check_offboarding_hygiene,  # B104 — decommissioning/offboarding hygiene (F-089)
    check_codex_project_trust,  # B136 — Codex CLI project trust_level="trusted"
    check_pending_device_pairing_scope,  # B138 — dangling high-scope pending device pairing
    check_paired_device_operator_authority,  # B176 — standing operator authority in devices/paired.json (B-243)
    check_systemd_persistence,  # B150 — systemd user-unit Restart=always persistence
    check_host_scheduled_persistence,  # B379 — systemd timer / system cron naming OpenClaw, outside C048's scope (F-178)
    check_codex_plugin_hooks,  # B151 — codex connector shell hooks in the plugin doc-cache
    check_orphaned_plugin_caches,  # B152 — on-disk plugin cache not in plugins.entries
    check_undeclared_plugin_load_path,  # B348 — plugins.load.paths entry not in plugins.entries (F-161)
    check_clawhub_lock_verification,  # B135 — accepted-despite-failed-verification install
    check_skill_install_tamper,  # B181 — installed skill modified since its recorded install hash (B-257)
    check_clawhub_token_store,  # B182 — ClawHub CLI plaintext token store perms, outside the OpenClaw home (B-259)
    check_legacy_state_migration_pending,  # B356 — unmigrated allowFrom/device-auth legacy state files (C-409)
    check_restart_handoff_stale,  # B357 — supervisor restart-handoff file outlived its own expiry (C-409)
    check_clawhub_registry_provenance,  # B184 — WHICH ClawHub issued the B135/B177/B181 verdicts (B-291, ENV-5)
    check_declared_skill_reconciliation,  # B158 — declared-but-unresolved skill-load source (F-119)
    check_skill_library_reachability,  # B354 — shared skill-library/upload surface bypasses filesystem discovery (B-725)
    check_audit_suppressions,  # B173 — security.audit.suppressions self-blinds native audit (B-237)
    check_install_policy_gate,  # B174 — security.installPolicy.* gate + exec-hook escape flags (B-238)
    check_dependency_tree_hooks,  # B349 — obfuscated install-lifecycle hook target in the dependency tree (F-167)
    check_hooks_enable_toggles,  # B179 — hooks.enabled / hooks.internal(.load.extraDirs) enable-toggle inventory (B-250)
    check_plugin_clawhub_trust,  # B177 — OpenClaw's own persisted per-plugin ClawHub trust verdict (B-240)
    check_plugin_tool_result_middleware,  # B187 — non-bundled plugin declares agentToolResultMiddleware (B-292, RT-2)
    check_bundled_root_override,  # B186 — bundled skills/hooks code-load root relocated by env override (B-289, ENV-3)
    check_unit_embedded_gateway_secret,  # B193 — gateway credential inlined in a systemd user unit (B-290, ENV-4)
    check_secrets_provider_exec,  # B194 — secrets.providers.* exec-source escape flags (E-060 item 1)
    check_browser_extra_args,  # B195 — browser.extraArgs dangerous Chrome launch flags (E-060 item 2)
    check_browser_evaluate_enabled,  # B196 — browser.evaluateEnabled arbitrary-JS sink (E-060 item 3)
    check_browser_executable_path,  # B321 — browser.executablePath / profiles.*.executablePath / mcpCommand / mcpArgs (E-060 item 4, B-653)
    check_browser_existing_session_profile,  # B322 — browser.profiles.*.userDataDir / cdpUrl / driver:"existing-session" (E-060 item 5)
    check_browser_cdp_control_port,  # B330 — unauthenticated CDP control port: off-host cdpUrl / --remote-allow-origins (C-298)
    check_browser_extension_relay_legacy_auth,  # B383 — browser.extensionRelay.allowLegacyAuth accepts legacy relay auth by default (F-195)
    check_marketplace_feed_provenance,  # B325 — marketplaces.feeds non-canonical registry (E-060 item 8)
    check_exec_safe_bin_trusted_dirs,  # B328 — tools.exec.safeBinTrustedDirs writable-dir promotion (E-060 item 11)
    # B191 (F-134, DISK-1) is DELIBERATELY NOT REGISTERED HERE. It is cataloged in
    # catalog.py and its function lives in checks/_host.py (§3.1 owning-module map), but
    # it runs ONLY under `--behavioral` (behavioral.analyze() calls check_audit_trail_
    # signals directly) — matching the T1/T2/T3 precedent, not a default audit()/CHECKS
    # entry. See BEHAVIORAL_CHECK_IDS in behavioral.py.
    # B185 (F-133) — poisoned tool descriptions in what OpenClaw ACTUALLY SENT to the
    # model, recovered post-hoc from the trajectory's `context.compiled` event.
    #
    # Deliberately NOT in SKILL_CONTENT_RING despite scanning injection-shaped text.
    # The ring is the per-skill content-security unit that `--vet` runs against a
    # CANDIDATE SKILL DIRECTORY (`vet_skill` builds `Context(home=<the skill dir>)`).
    # This check reads the audit HOME's session logs, so in a vet context it would glob
    # a skill directory for trajectory sidecars, find none, and return UNKNOWN on every
    # vetted skill — a category error that adds no signal to a pre-install verdict. It
    # belongs to the full audit only, the same reasoning B105 records for itself.
    check_compiled_tool_poisoning,  # B185 — poisoned tool description already delivered to the model (F-133, RT-1)
    check_cloudworkers_prepared_pool,  # B374 — cloudWorkers 9.4 prepared-pool default-on warm reserve (C-526)
]


# C-523: static (never executed) finding-id -> check-function map, for --explain/--retest.
#
# catalog.BY_ID maps an id to its CheckMeta (metadata only) — nothing anywhere maps an id
# to the CALLABLE that produces it. Building that by running every check to see what id it
# emits would cost exactly what --retest exists to avoid paying. Instead this reads each
# check's own SOURCE for the literal id it constructs a Finding with — the same technique
# scripts/gen_checks_docs.py already uses (AST over source, never exec) for risk.py's
# RiskPath extraction.
#
# Verified against all 190 functions in CHECKS (2026-09, C-523), and cross-checked by hand
# against catalog.BY_ID (not just trusted from a read): every one passes its id as a plain
# string literal to _finding(...)/_custom(...)/_config_unreadable(...)/_host_finding(...) —
# the four _shared.py/_host.py helpers that construct or forward a Finding's id — with the
# SAME id on every branch. A couple (check_markdown_image_exfil, check_unicode_obfuscation,
# check_subagents' _disk_subagent_disclosure helper) delegate to a same-module helper
# function instead of calling one of those four directly; _finding_ids_for recurses into a
# same-module callee (bounded by _seen) exactly for that shape.
#
# CHECKS_BY_ID's key set is a PROPER SUBSET of catalog.BY_ID's, not equal to it: B191 and
# T1-T3 are real catalog ids (behavioral.py's detectors) that, per that module's own
# docstring, are "never in CHECKS" by design — they run only under --behavioral, and a
# fired one is folded into the score as a cap-only signal rather than appearing in CHECKS'
# per-run findings list. --explain/--retest give those ids a distinct, accurate error
# rather than a bare "unknown id" (cli.py). tests/test_c523_checks_by_id_completeness.py
# pins the exact expected gap set — if a future check doesn't fit any of the four shapes
# above, or the gap set grows for an undocumented reason, it fails loudly there.
_ID_CARRYING_CALLS = frozenset({"_finding", "_custom", "_config_unreadable", "_host_finding"})


def _literal_ids_in_tree(tree) -> "set[str]":
    ids: "set[str]" = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in _ID_CARRYING_CALLS and node.args):
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                ids.add(first.value)
    return ids


def _finding_ids_for(fn, module, _seen=None) -> "set[str]":
    """The finding id(s) *fn*'s own source shows it can produce. Never calls *fn*."""
    _seen = _seen if _seen is not None else set()
    if fn in _seen:
        return set()
    _seen.add(fn)
    try:
        source = textwrap.dedent(inspect.getsource(fn))
        tree = ast.parse(source)
    except (OSError, TypeError, SyntaxError):
        return set()
    ids = _literal_ids_in_tree(tree)
    if ids:
        return ids
    # No direct _finding/_custom/_config_unreadable call in *fn*'s own body -- it may
    # DELEGATE its whole verdict to a same-module helper. Recurse into any locally-defined
    # function it calls (bounded by _seen so a cycle or a large fan-out can't loop/explode).
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            callee = getattr(module, node.func.id, None)
            if callable(callee) and inspect.getmodule(callee) is module:
                found = _finding_ids_for(callee, module, _seen)
                if found:
                    return found
    return set()


def _build_checks_by_id() -> "dict[str, object]":
    mapping: "dict[str, object]" = {}
    for chk in CHECKS:
        for fid in _finding_ids_for(chk, inspect.getmodule(chk)):
            mapping[fid] = chk
    return mapping


CHECKS_BY_ID = _build_checks_by_id()


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
        # B-399: redundant with the `ERR:` id prefix `_degraded_signal` already keys on,
        # set anyway so the flag stays the single source of truth for "this UNKNOWN is
        # engine-side" across every producer, not just this one.
        engine_degraded=True,
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
        # B-399: see the matching note in _check_error_finding above.
        engine_degraded=True,
    )


def run_all(ctx: Context, check_budget_s: float = DEFAULT_CHECK_BUDGET_S,
            audit_budget_s: float = DEFAULT_AUDIT_BUDGET_S,
            on_check_done=None) -> list[Finding]:
    # C-510 item 2: a plain audit gives no progress feedback while it can
    # spend up to ~3 minutes on hostile content (a slow check, or several, chewing
    # through their own check_budget_s) -- a silent terminal for that long is
    # indistinguishable from a hang, and a user who kills what they believe is a stuck
    # process is exactly the mid-write condition that produces corrupt monitor/baseline
    # state elsewhere in this tool. `on_check_done`, when given, is called as
    # `on_check_done(done_count, total_count)` after EVERY check completes -- normally,
    # budget-exceeded, or crashed alike, so a caller narrating progress sees the true
    # count including degraded checks, never a lower one that reads as "fewer checks
    # than the catalog". Optional and default None (a no-op call is skipped entirely,
    # not just silenced) so every existing caller -- every test in this suite calls
    # `audit()`/`run_all()` directly -- is byte-for-byte unaffected; only the CLI's
    # interactive default-audit path installs one (cli.py).
    #
    # Per-check isolation (B-101) + wall-clock budget (C-159): a crashing OR hanging
    # check degrades to one UNKNOWN finding instead of aborting the audit. This is the
    # DESIGNATED handler for a per-check deadline: ScanBudgetExceeded derives from
    # BaseException (B-352), so it reaches here past every inner `except Exception` in
    # the check's call graph rather than being swallowed into a lying PASS, and the
    # generic `except Exception` below (deliberately not BaseException, so
    # KeyboardInterrupt / SystemExit still propagate) can no longer shadow it.
    findings: list[Finding] = []
    deadline = audit_deadline(audit_budget_s)
    total = len(CHECKS)
    for done, chk in enumerate(CHECKS, start=1):
        if audit_budget_exceeded(deadline):
            findings.append(_check_budget_finding(chk, "audit"))
            if on_check_done is not None:
                on_check_done(done, total)
            continue
        try:
            with check_deadline(check_budget_s):
                findings.append(chk(ctx))
        except ScanBudgetExceeded:
            findings.append(_check_budget_finding(chk, "check", check_budget_s))
        except Exception as exc:  # noqa: BLE001 — a bad check must not sink the audit
            # B-767: the finding tells the user to "re-run with --debug for the
            # traceback", but nothing ever wrote one -- the exception is caught right
            # here and never reaches main()'s top-level `--debug: raise`. logger.debug
            # is a no-op unless --debug set the logger to DEBUG (logsafe.get_logger),
            # so this costs nothing on a normal run.
            #
            # traceback.format_exc() is rendered to a plain string and passed as a %s
            # ARG, never via exc_info=True: logsafe._RedactingFilter redacts
            # record.getMessage() (the formatted message, args included), but a
            # Formatter renders exc_info SEPARATELY via formatException() and appends
            # it after the filter has already run -- exc_info=True would ship an
            # unredacted traceback straight past the one thing that exists to stop it.
            logging.getLogger("clawseccheck").debug(
                "check %s crashed:\n%s",
                getattr(chk, "__name__", "unknown_check"),
                traceback.format_exc(),
            )
            findings.append(_check_error_finding(chk, exc))
        if on_check_done is not None:
            on_check_done(done, total)
    return findings
