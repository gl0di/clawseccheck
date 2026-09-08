"""C-433 — one module per watched dimension: its snapshot builder AND its diff arm.

`monitor.py` grew to 4,916 lines and its size exemption had been restated three times.
Three earlier attempts to split it were rejected for the same reason, and the reason was
right: `snapshot()` builds a dimension and `diff()` compares it, so a split BY FUNCTION
separates the two halves that must always change together. The split that works is the
one this package makes — **per dimension**, each module owning both halves.

Layering, top to bottom, mirroring `checks/`:

    _shared.py          the vocabulary every dimension reuses (leaf: no package imports)
    _<dimension>.py     one dimension's signature builder, its helpers, and its diff arm
    __init__.py         this aggregator

`monitor.py` imports from here one way — the same arrangement as `monitorstore.py`, and
the reason the supporting names moved DOWN rather than being imported back up: an arm
importing `monitor` while `monitor` imports the arm is a cycle.

**No `__all__` on this package or on any submodule** — the `checks/` package's §3.1-a rule,
here for the same reason: tests import private helpers and regex constants by name, and a
narrow `__all__` would hide every one of them. Every submodule name is re-exported below,
underscore-prefixed privates included.
"""

from __future__ import annotations

from ._shared import (  # noqa: F401
    NOTE_CATEGORY_ORDER,
    NOTE_CONFIG_BLIND,
    NOTE_INSPECTION_CAPPED,
    NOTE_NO_PRIOR_RECORD,
    NOTE_RECORD_DAMAGED,
    NOTE_UNDETERMINED,
    _DIMENSION_LABELS,
    _DIMENSION_NAME_CAP,
    _both_dims,
    _dim,
    _frontier,
    _h,
    _name_dimensions,
    RAW_DEGRADED,
    RAW_HELD,
    RAW_NO_FIGURE,
    RAW_NO_SCOPE,
    RAW_SCOPE_MOVED,
    _num,
    _num_or_none,
    raw_backstop,
)

from ._behavioral import _diff_behavioral  # noqa: F401

from ._bootstrap import (  # noqa: F401
    _diff_bootstrap_added,
    _diff_bootstrap_changed,
    _diff_bootstrap_moved,
    _diff_bootstrap_removed,
)

from ._channels import (  # noqa: F401
    _CHANNEL_ALLOWLIST_KEYS,
    _CHANNEL_SCOPE_KEYS,
    _CHANNEL_SECRET_KEYS,
    _channel_entry,
    _channel_scope_nodes,
    _channel_sig,
    _diff_channels,
)

from ._checks import (  # noqa: F401
    _diff_check_transitions,
    _diff_vanished_checks,
)

from ._configfile import (  # noqa: F401
    _config_file_digest,
    _config_resolved_digest,
    _diff_config_digest_unmoved,
    _diff_config_journal,
    _note_unmodelled_config_edit,
)

from ._coverage import (  # noqa: F401
    _COVERAGE_ALREADY_ANNOUNCED,
    _COVERAGE_DIGITS_RE,
    _COVERAGE_MAX_ENTRIES,
    _COVERAGE_NAME_CAP,
    _coverage_key,
    _coverage_live_text,
    _coverage_signature,
    _diff_coverage,
)

from ._credentials import (  # noqa: F401
    _CRED_NAME_CAP,
    _credentials_sig,
    _diff_credentials,
    _credential_names,
)

from ._execpolicy import (  # noqa: F401
    _MODE_POLICY,
    _SANDBOX_ALWAYS,
    _SANDBOX_NEVER,
    _SECURITY_RANK,
    _describe,
    _diff_exec_policy,
    _diff_scope,
    _every_request_is_prompted,
    _exec_policy_sig,
    _human_reviews_a_miss,
    _misses_can_still_run,
    _resolve_mode_from_policy,
    _resolve_scope,
    _undetermined_reason,
)

from ._gateway import (  # noqa: F401
    _diff_gateway_bind_moved,
    _gateway_bind,
    _note_gateway_bind_unreadable,
)

from ._host import (  # noqa: F401
    _HOST_CLASS_NAMES,
    _diff_host_monitors,
    _name_host_classes,
)

from ._hostpersist import (  # noqa: F401
    _HOST_PERSIST_INFRA,
    _HOST_PERSIST_LABELS,
    _diff_host_persist,
)

from ._install import _diff_openclaw_install  # noqa: F401

from ._mcp import (  # noqa: F401
    _RUNNER_LEAD_SUBCOMMANDS_BY_CMD,
    _RUNNER_LEAD_VALUE_MARKERS_BY_CMD,
    _VALUE_FLAGS_BY_CMD,
    _diff_mcp_detail,
    _diff_mcp_servers,
    _extract_args_pkg,
    _mcp_detail_sig,
    _mcp_observed_surfaces,
    _mcp_sig,
    _tool_surface_hash,
)

from ._memory import (  # noqa: F401
    _MEMORY_FILE_NAMES,
    _MEMORY_MAX_BYTES,
    _MEMORY_MAX_FILES,
    _MEMORY_SIGNAL_VERSION,
    _MEMORY_TEXT_EXTS,
    _MEMORY_URL_RE,
    _SIGNAL_CLASS_LABELS,
    _append_memory_alerts,
    _extract_memory_signals,
    _has_memory_name,
    _memory_injection_patterns,
    _memory_tight_signal_patterns,
    _signal_class_label,
    _snapshot_memory_files,
    _snapshot_memory_text,
)

from ._native import _diff_native_findings  # noqa: F401

from ._plugins import (  # noqa: F401
    _PLUGIN_ID_ALIASES,
    _diff_plugins,
    _plugin_id,
    _plugins_sig,
)

from ._provenance import (  # noqa: F401
    _diff_skill_provenance,
    _prov_comparable,
    _prov_compare_records,
    _prov_legacy_names,
    _prov_not_compared,
    _prov_records_seen,
    _prov_searched_roots,
    changed_skills,
)

from ._score import (  # noqa: F401
    _diff_score,
    _raw_score_scope,
)

from ._skills import (  # noqa: F401
    _SCAN_TRUNCATED_RE,
    _SKILL_VERSION_RE,
    _b62_families,
    _diff_skills_added,
    _diff_skills_common,
    _diff_skills_removed,
    _note_skills_capped,
    _note_skills_frontier_partial,
    _note_skills_prev_capped,
    _scan_truncated_skills,
    _skill_sig,
)
