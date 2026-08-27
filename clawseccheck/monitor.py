"""Lightweight built-in monitoring: scheduled re-audit + change detection.

Complements the B16 check (which asks "do you HAVE monitoring?"). This is an
optional, opt-in way to GET some: run the deterministic audit on a schedule,
store a compact snapshot, and alert on what CHANGED since last time — the moments
threats actually appear (a new/modified installed skill, SOUL.md drift, any change to
a file under <workspace>/memory/, a dropped score — capped OR uncapped — and a check
leaving PASS for FAIL, WARN or UNKNOWN).

It is the only part of ClawSecCheck that persists state: a single JSON snapshot
(default ~/.clawseccheck/state.json). Everything else stays read-only.
"""
from __future__ import annotations

import hashlib
import json  # noqa: F401  (re-export; see tests/monitor_public_api.txt)
import re
from pathlib import Path

# PASS/WARN/FAIL are re-exports, not uses: they were importable as
# `clawseccheck.monitor.FAIL` before C-433 moved the checks arm into
# `monitordims/_checks.py`, and tests/monitor_public_api.txt pins that they stay.
from .catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN  # noqa: F401
# Re-exports whose only readers moved into monitordims/. Kept importable from here
# because they were before the split — see tests/monitor_public_api.txt.
from .hostpersist import FAMILY_LABELS as _hp_FAMILY_LABELS  # noqa: F401
from .hostpersist import FAMILY_SYSTEM_CRON as _hp_FAMILY_SYSTEM_CRON  # noqa: F401
from .hostpersist import FAMILY_SYSTEMD as _hp_FAMILY_SYSTEMD  # noqa: F401
from .logsafe import redact_urls_in_text, sanitize_url_host_only  # noqa: F401
from .openclawdist import compare_versions as _version_order  # noqa: F401
from .configjournal import find_by_hash as _journal_find_by_hash
from .configjournal import newest_hash as _journal_newest_hash
from .configjournal import read_writes as _journal_read
# B-541: the key vocabulary of the provenance dimension, imported rather than restated.
# `skillprovenance` is a documented LEAF (it imports nothing from this package), so a
# top-level import cannot create a cycle — and a second copy of a rule is exactly what
# went wrong the last three times this area was repaired.
#
# Kept HERE, not folded into the monitordims re-export below, for one reason: these four
# were importable as `clawseccheck.monitor.PROV_*` before C-433 split the dimensions out,
# and a refactor advertised as "every name stays importable" does not get to quietly drop
# four of them because nothing in tests/ happens to use them today.
from .skillprovenance import KEY_SEP as PROV_KEY_SEP  # noqa: F401
from .skillprovenance import ROOT_MARK as PROV_ROOT_MARK  # noqa: F401
from .skillprovenance import _is_record_key as _prov_is_record_key  # noqa: F401
from .skillprovenance import _is_root_key as _prov_is_root_key  # noqa: F401
from .monitordims import (  # noqa: F401  (re-export: `monitor` is the import site
    # every consumer already uses; see monitordims/__init__.py for why the names moved
    # DOWN into the package rather than being imported back up out of it)
    NOTE_CATEGORY_ORDER,
    NOTE_CONFIG_BLIND,
    NOTE_INSPECTION_CAPPED,
    NOTE_NO_PRIOR_RECORD,
    NOTE_RECORD_DAMAGED,
    NOTE_UNDETERMINED,
    _CHANNEL_ALLOWLIST_KEYS,
    _CHANNEL_SCOPE_KEYS,
    _CHANNEL_SECRET_KEYS,
    _DIMENSION_LABELS,
    _DIMENSION_NAME_CAP,
    _HOST_PERSIST_INFRA,
    _HOST_PERSIST_LABELS,
    _MEMORY_FILE_NAMES,
    _MEMORY_MAX_BYTES,
    _MEMORY_MAX_FILES,
    _MEMORY_SIGNAL_VERSION,
    _MEMORY_TEXT_EXTS,
    _MEMORY_URL_RE,
    _PLUGIN_ID_ALIASES,
    _RUNNER_LEAD_SUBCOMMANDS_BY_CMD,
    _RUNNER_LEAD_VALUE_MARKERS_BY_CMD,
    _SCAN_TRUNCATED_RE,
    _SIGNAL_CLASS_LABELS,
    _SKILL_VERSION_RE,
    _VALUE_FLAGS_BY_CMD,
    _append_memory_alerts,
    _b62_families,
    _both_dims,
    _channel_entry,
    _channel_scope_nodes,
    _channel_sig,
    _config_file_digest,
    _config_resolved_digest,
    _diff_behavioral,
    _diff_bootstrap_added,
    _diff_bootstrap_changed,
    _diff_bootstrap_moved,
    _diff_bootstrap_removed,
    _diff_channels,
    _diff_check_transitions,
    _diff_config_digest_unmoved,
    _diff_config_journal,
    _diff_gateway_bind_moved,
    _diff_host_monitors,
    _diff_host_persist,
    _diff_mcp_detail,
    _diff_mcp_servers,
    _diff_native_findings,
    _diff_openclaw_install,
    _diff_plugins,
    _diff_score,
    _diff_skill_provenance,
    _diff_skills_added,
    _diff_skills_common,
    _diff_skills_removed,
    _diff_vanished_checks,
    _dim,
    _extract_args_pkg,
    _extract_memory_signals,
    _frontier,
    _gateway_bind,
    _h,
    _has_memory_name,
    _mcp_detail_sig,
    _mcp_observed_surfaces,
    _mcp_sig,
    _memory_injection_patterns,
    _memory_tight_signal_patterns,
    _name_dimensions,
    _note_gateway_bind_unreadable,
    _note_skills_capped,
    _note_skills_frontier_partial,
    _note_skills_prev_capped,
    _note_unmodelled_config_edit,
    _num,
    _plugin_id,
    _plugins_sig,
    _prov_comparable,
    _prov_compare_records,
    _prov_legacy_names,
    _prov_not_compared,
    _prov_records_seen,
    _prov_searched_roots,
    _raw_score_scope,
    _scan_truncated_skills,
    _signal_class_label,
    _skill_sig,
    _snapshot_memory_files,
    _snapshot_memory_text,
    _tool_surface_hash,
    annotations,
    changed_skills,
)
from .monitorstore import (  # noqa: F401  (re-export: 48 test modules and
    # several siblings import these from `monitor`; see monitorstore's docstring)
    BASELINE_ABSENT,
    BASELINE_CORRUPT,
    BASELINE_DIGEST_CHARS,
    BASELINE_OK,
    CHAIN_ABSENT,
    CHAIN_BAD_PATH,
    CHAIN_EMPTY,
    CHAIN_NOT_A_FILE,
    CHAIN_NO_ENTRIES,
    CHAIN_UNREADABLE,
    DEFAULT_EVENTS,
    DEFAULT_STATE,
    SCHEMA_VERSION,
    _JOURNAL_KEEP,
    _JOURNAL_MAX_LINES,
    _REFERENCE_VOLATILE_KEYS,
    _chain_hash,
    _iter_jsonl,
    _last_chain_hash,
    _now_iso,
    _rotate_journal,
    _schema_ok,
    baseline_reference,
    baseline_witness_event,
    chain_provenance_note,
    load_events,
    load_events_with_problem,
    load_state,
    read_baseline,
    record_events,
    save_state,
    snapshot_reference,
    verify_baseline,
    verify_chain,
)


def _ignore_hash(home: Path) -> str:
    """Return sha256 of the .clawseccheckignore file contents, or '' if absent."""
    p = home / ".clawseccheckignore"
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

# F-147 (Wave 3, rug-pull): bumped 2 -> 3 for the new OPTIONAL `mcp_detail.<server>.
# surface_tool_sigs` key. As with the 1 -> 2 bump (see git history, v3.11.0's
# _skill_sig str-vs-dict sniffing), this build carries no version-keyed migration
# function — every dimension that reads a shape newer than what an old snapshot has
# already degrades gracefully via a presence/type guard (`_both_dims`, and the
# `surface_tool_sigs in ps and in cs` gate in `diff()`), so an old snapshot compared
# against a new-format one simply skips the new comparison for one run rather than
# misreading "key absent" as "new X appeared". SNAPSHOT_VERSION itself is a stamp for
# humans/tests, not something diff() branches on.
#
# F-173: bumped 6 -> 7 for the OPTIONAL `behavioral_fired` / `behavioral_undetermined` /
# `behavioral_capped` keys. Same degradation rule as every bump before it — an older
# baseline simply lacks them and the arm stands down for one run.
#
# F-174: 7 -> 8 for `openclaw_install` and `skill_provenance`. The task warned against
# shipping many new dimensions at once, because upgrade safety is per-dimension and each new
# one is skipped for exactly one post-upgrade run. That cost is real but bounded and, since
# C-418, DISCLOSED: the `watched` manifest tells the user how many comparisons their
# baseline predates, rather than letting them fall into a bare all-clear.
SNAPSHOT_VERSION = 8


# B-270 — emitted (rendered AND journaled) when a prior baseline existed but could not be
# used. Kept here, next to the predicate that decides it, so the screen and the journal
# cannot drift apart: report.py renders whatever alert list the CLI passes to the journal.
BASELINE_CORRUPT_ALERT = (
    "HIGH",
    "The previous monitor baseline could not be read (truncated, unreadable, or not a "
    "valid snapshot). Any change made between the last good run and this one could NOT be "
    "compared and is therefore NOT reported. Investigate why the state file was lost — a "
    "baseline that disappears is itself worth explaining.",
)


_VALUE_FLAGS_BY_CMD["podman"] = set(_VALUE_FLAGS_BY_CMD["docker"])


# B-269 — dimensions of the snapshot that are built from ``ctx.config``. When
# openclaw.json cannot be read/parsed the collector falls back to ``ctx.config = {}`` and
# every one of these collapses to empty, which ``diff()`` used to read as fact.
_CONFIG_DIMENSIONS = ("mcp", "mcp_detail", "channels", "gateway_bind", "plugins")

# B-269 — dimensions collected from disk that an unreadable config can still SHRINK,
# because the config declares extra roots to scan: ``agents.defaults.workspace`` /
# ``agents.list[].workspace`` add bootstrap + memory roots, ``skills.load.extraDirs`` adds
# skill roots. Verified first-hand: with those keys set, a chmod 000 on openclaw.json drops
# the custom-workspace SOUL.md and the extra-dir skill out of the collected view, which the
# old code reported as "Skill 'helper' was removed."
#
# The invariant that makes the repair sound: an unreadable config can only make an entry
# DISAPPEAR from the collected view, never appear. So on a blind run a disappearance here
# is untrustworthy, while an addition or a content change is still real evidence.
# Checked, not assumed: every config consumer in the collection path only ever EXTENDS the
# set of roots to scan — _read_installed_skills appends _config_workspace_dirs,
# _config_extra_skill_dirs and _config_plugin_load_paths to `roots`, and the bootstrap scan
# appends _config_workspace_dirs to `_ws_dirs`. No config key narrows or filters discovery,
# so ctx.config == {} yields a subset, never a superset.
#
# F-174 adds `skill_provenance` here rather than to _CONFIG_DIMENSIONS above, and the
# distinction is the whole reason the two lists exist. Its records come off disk
# (`<workspace>/.clawhub/lock.json`), but WHICH workspaces are searched is config-derived:
# `agents.defaults.workspace` and `agents.list[].workspace` ADD roots and nothing in the
# config can ever remove one. So a blind run sees a subset of the ROOTS, which is exactly
# the shrinkable contract. `tests/test_f174_skill_provenance.py` pins that superset
# invariant; if a config key could ever narrow the search, the treatment would be unsound
# and the dimension would have to move up to _CONFIG_DIMENSIONS.
#
# **A subset of the roots is not automatically a subset of the RECORDS**, and an earlier
# version of this comment claimed it was. Two workspaces can each hold a skill of the same
# NAME, so which record wins is a merge decision, not a set operation — with last-wins,
# merely adding a workspace to openclaw.json flipped the winner and the diff read the swap
# as "the skill was replaced with different content", a false HIGH on an ordinary config
# edit. That framing is now historical: B-541 removed the election from the verdict path
# entirely — `read_provenance` emits one entry per (root, skill) pair and each record is
# compared with itself, so first-wins survives only in the legacy name-keyed fallback that a
# single post-upgrade run takes. The PLACEMENT is unchanged and still right, but it no longer
# rests on "the winner does not depend on the config": it rests on the plainer fact that the
# config can only ADD workspace roots, never remove one, so a blind run sees a SUBSET of the
# roots — which is exactly the shrinkable contract. Re-grounded because the sentence that
# used to carry this argument described a mechanism the tree no longer has.
#
# `openclaw_install` is in NEITHER list, deliberately: it is resolved from PATH, so an
# unreadable config cannot move it. Its own failure mode is different and is handled at the
# diff instead — see the presence gate there.
#
# F-179: `host_persist` is in NEITHER list for a related but distinct reason. It is read from
# the HOST — `~/.config/systemd/user`, the shell startup files, `/etc/cron.*`, `sys.path` —
# so an unreadable `openclaw.json` cannot shrink it either, which rules out
# `_CONFIG_DIMENSIONS`. It is not `_SHRINKABLE_DIMENSIONS` either, and that one is worth
# stating because the name invites it: that list means "config can only ADD roots, so a
# SHRINK is a real signal". On the host the asymmetry does not hold — a user deleting a
# systemd unit and an attacker deleting one to cover a track are the same edit, so BOTH
# directions are reported and neither is privileged.
_SHRINKABLE_DIMENSIONS = ("skills", "bootstrap", "memory", "skill_provenance")


# C-417 — every snapshot key THIS build reads out of a stored baseline, persisted with
# the snapshot itself.
#
# The graceful-degradation rule documented at SNAPSHOT_VERSION has a blind spot: a
# baseline written by an older build simply lacks the newer key, the presence guard
# (`_both_dims`, `_frontier`, a bare `.get`) turns that into a skip, and the screen is
# byte-identical to a genuine all-clear. The user is told nothing changed about something
# that was never examined. Persisting this manifest lets a later run say "your baseline
# predates this" instead — the difference between "we looked and it is fine" and "we
# could not look", which is the distinction this whole epic exists to restore.
#
# **Membership is the whole point, and the first version of this list got it exactly
# backwards.** It held only the thirteen always-present dimensions — the ones that never
# suffer the blind spot — and omitted every optional key, which is the entire population
# the field is for: `skills_frontier_partial` (its absence downgrades a CRITICAL to a
# HIGH), `raw_score_scope` (its absence suppresses the score-drop alert outright),
# `skills_capped` / `memory_capped` / `skills_capped_count` (truncation frontiers),
# `config_baseline` / `config_parse_error` / `config_ever_seen` (the blind-run state), and
# `grade` (alert text). An independent adversarial pass found this; the guard that was
# supposed to prevent it was checking only `_both_dims` literals, all of which were
# already present, so it was vacuously green.
#
# Nothing READS this field yet, on purpose: Phase 0 of the monitor epic is store-only, so
# it cannot emit an alert by construction. The consumer arrives with the phase that needs it.
#
# **Absence does not mean the same thing for all of them, and the consumer must not assume
# it does.** Most are written on every run, so their absence from a stored baseline can
# only mean that baseline predates them — the "your baseline predates this" message is
# sound. A named minority is written CONDITIONALLY, so absence is a real, current state
# and that message would be a fabrication: `host` (absent = no supported host detected),
# `config_parse_error` and `config_baseline` (both absent = this was NOT a blind run — see
# `_degrade_snapshot`, the only writer of either), the three F-170 config-journal keys, and
# the three F-173 `behavioral_*` keys (absent = the shell did not run the behavioural layer
# this invocation, or it raised). A consumer that treats a missing `config_parse_error` as
# "we don't know whether that run was blind" would invert the meaning of a key that says
# "it wasn't". The split is pinned in tests/test_c417_snapshot_enablers.py's `_CONDITIONAL`
# — deliberately as a named list rather than a count, because the count in this comment had
# already rotted once (it still said 22/19/3 after F-170 shipped three more).
#
# Kept honest mechanically: tests/test_c417_snapshot_enablers.py derives the keys this
# module reads off a stored snapshot straight from the AST and asserts EXACT equality with
# this tuple — subset in either direction is how the first version passed while being
# wrong. Sorted, so the persisted list is stable across runs.
WATCHED_DIMENSIONS = (
    # F-173. Conditional: present only when the shell handed `snapshot()` a behavioural
    # result, so their absence says "that layer did not run", never "your baseline is old".
    "behavioral_capped",
    "behavioral_fired",
    "behavioral_incomplete",
    "behavioral_undetermined",
    "bootstrap",
    "channels",
    "checks",
    "checks_degraded",
    "checks_not_applicable",
    "config_baseline",
    "config_ever_seen",
    "config_file_sha256",
    "config_journal_head",
    "config_parse_error",
    # B-659 made this a READ dimension: the disclosure that the settings file moved
    # in a namespace this build does not model consults it, so an $include fragment
    # edit counts too. B-527 landed it store-only; registering it here is what the
    # C-417 manifest guard requires the moment something reads it back.
    "config_resolved_sha256",
    "config_written_by",
    "gateway_bind",
    "grade",
    # B-511: whether the grade above was EARNED. diff() reads it off the stored
    # baseline to decide whether there is a verdict to compare at all, so it is a
    # watched dimension like any other. Written unconditionally, hence not in
    # _CONDITIONAL: its absence means a snapshot older than this build, which diff()
    # treats as ungraded rather than assuming the number was shown.
    "graded",
    "host",
    # F-179. Conditional: absent when the shell did not hand `snapshot()` a host scan.
    #
    # SNAPSHOT_VERSION deliberately does NOT move for this. It was bumped to 9 while this
    # landed and the full suite caught it: B-527 already settled the convention, and
    # `test_snapshot_version_unchanged_field_is_purely_additive` states it — membership in
    # WATCHED_DIMENSIONS is what tells a pre-existing baseline the key was never recorded,
    # and `diff()` never branches on the version at all. The three version literals a bump
    # forces you to edit are tripwires, not chores; needing to touch them is the signal to
    # stop and ask whether the bump is doing anything.
    "host_persist",
    "ignore_hash",
    "mcp",
    "mcp_detail",
    "memory",
    "memory_capped",
    "native_count",
    # F-174. Both conditional: `openclaw_install` is absent when no OpenClaw package can be
    # located on PATH (which a cron job's minimal PATH really does produce — verified),
    # `skill_provenance` when no ClawHub lock file was found in any workspace.
    "openclaw_install",
    "plugins",
    "raw_score",
    "raw_score_scope",
    "scope",
    "score",
    "skill_provenance",
    "skills",
    "skills_capped",
    "skills_capped_count",
    "skills_frontier_partial",
    # Self-referential on purpose: C-418 reads the stored manifest to tell a user their
    # baseline predates a comparison this build makes, so the manifest is itself a key read
    # off a stored baseline and belongs in its own list. Its absence from an older baseline
    # is precisely what that note reports.
    "watched",
)


def _degrade_snapshot(snap: dict, prev: "dict | None") -> None:
    """B-269/FIX2 (C-135 follow-up): mark and repair a snapshot taken while openclaw.json
    was unreadable, OR simply ABSENT this run after having previously been present (see
    ``snapshot()``'s widened blind predicate) — both leave the collector with the same
    collapsed ``ctx.config = {}`` view, so both need the same repair.

    Writing the collapsed (empty) config view into the baseline is what made ``diff()``
    fabricate "MCP server 'X' was removed." / "Gateway bind changed: '127.0.0.1' -> ''"
    against a byte-identical config, and then fire a burst of "NEW MCP server connected"
    CRITICALs the moment the file became readable again — all while the score *rose*,
    because the checks that would have failed had silently become UNKNOWN and UNKNOWN is
    excluded from the score denominator.

    The state is *unknown*, not empty, so the last known-good values are carried forward
    rather than overwritten:

    * ``_CONFIG_DIMENSIONS`` are taken wholesale from the previous snapshot.
    * ``_SHRINKABLE_DIMENSIONS`` are union-merged — previous entries survive, this run's
      values win wherever both sides have the key.

    Nothing is lost, only deferred: the next run that CAN read the config compares against
    this preserved baseline, so a real change made during the blind window is reported
    then, in the right direction, instead of being drowned in fabricated ones.

    ``config_baseline`` records whether a baseline actually existed to carry (``carried``)
    or the blind run had nothing to fall back on (``unknown`` — e.g. the very first monitor
    run was blind, or the previous run was blind too and never had a baseline itself).
    ``diff()`` refuses to compare config dimensions against an ``unknown`` baseline rather
    than treating emptiness as fact.

    This does NOT change scoring: the run's measured ``score``/``grade``/``checks`` are left
    exactly as the audit produced them (per GR#4 the UNKNOWN-exclusion design is correct).
    ``diff()`` declines to *compare* them across a blind boundary instead.
    """
    snap["config_parse_error"] = True
    have_baseline = isinstance(prev, dict) and (
        not prev.get("config_parse_error") or prev.get("config_baseline") == "carried"
    )
    if not have_baseline:
        snap["config_baseline"] = "unknown"
        return
    snap["config_baseline"] = "carried"
    for key in _CONFIG_DIMENSIONS:
        if key in prev:
            snap[key] = prev[key]
    for key in _SHRINKABLE_DIMENSIONS:
        prev_dim, curr_dim = prev.get(key), snap.get(key)
        if isinstance(prev_dim, dict) and isinstance(curr_dim, dict):
            snap[key] = {**prev_dim, **curr_dim}


def snapshot(ctx, findings, score, prev: "dict | None" = None,
             behavioral: "dict | None" = None, install: "dict | None" = None,
             provenance: "dict | None" = None, host_persist: "dict | None" = None) -> dict:
    """Build the drift snapshot for this run.

    *prev* is the previously saved snapshot, used to preserve the baseline when this run
    could not read openclaw.json (B-269 — see ``_degrade_snapshot``) and to carry forward
    the "was a real config ever seen" bit that decides whether a config that is simply
    ABSENT this run counts as blind too (C-135 FIX2 — see the ``config_ever_seen`` /
    ``config_missing_blind`` computation below). Passing None keeps the historical
    behaviour for a first run or a caller with no stored state.

    *behavioral* (F-173) is the REDUCED result of ``behavioral.analyze`` — ``{"fired":
    [...], "undetermined": [...], "capped": bool}`` — computed by the caller, never here.
    This module deliberately does not import ``behavioral``: the containment idiom for a
    subsystem that can raise on a schema-drifted config lives in the shell (``cli.py``
    already wraps the identical call that way for ``--full``'s cap-only signal, and
    ``pipeline.run_behavioral`` does the same), and importing it here would put a
    layer-3 concern inside a layer-1/2 module.

    Passing None writes no ``behavioral_*`` key at all, and that absence is load-bearing:
    it is how ``diff_with_notes`` tells "the layer did not run" from "it ran and found
    nothing". Writing an empty list for a layer that never executed would be the
    clean-verdict-about-an-unexamined-surface shape this whole epic exists to remove — and
    on the *next* run it would read as "the signal cleared", inventing a resolution.
    """
    native = getattr(ctx, "native", None)
    native_count = len(getattr(native, "findings", []) or []) if native else 0
    # B-268: capture each collection's truncation frontier alongside the collection itself,
    # so diff() can tell "absent from disk" from "absent from the capped view".
    _mem_capped: list[str] = []
    snap = {
        "version": SNAPSHOT_VERSION,
        # C-417: when this baseline was taken, from the same producer the event journal
        # uses (_now_iso), so "what happened since the last run" is answerable by
        # comparing the two directly instead of inferring it from file mtimes.
        "ts": _now_iso(),
        # C-417: which dimensions this build can compare — see WATCHED_DIMENSIONS. A
        # list, not the tuple, because that is what survives a JSON round-trip.
        "watched": list(WATCHED_DIMENSIONS),
        "score": score.score,
        # B-273: the UNCAPPED weighted pass-rate, recorded alongside the displayed score.
        # `score` is `min(raw, FAIL_CAPS[worst_failing_severity])` (scoring.py:80-87), so on
        # a config with an open CRITICAL FAIL it is pinned at 49 and stops moving — the
        # drop backstop in diff() was comparing a constant. Storing raw_score gives that
        # backstop a signal that still responds once the cap saturates.
        "raw_score": getattr(score, "raw_score", None),
        # C-135/FIX1: the scope raw_score was computed over — see _raw_score_scope(). Lets
        # diff() refuse to trust a raw-score fall across a denominator that moved (an
        # upgrade shipping new checks), rather than comparing two incomparable numbers.
        "raw_score_scope": _raw_score_scope(findings),
        "grade": score.grade,
        # B-511: whether this run EARNED that grade. E-077 withholds the letter unless all
        # five layers ran, and since C-426 the default run does not — so `score`/`grade`
        # above are computed values the user was never shown. They stay recorded, because
        # a later complete run needs something to compare against and writing null is
        # worse than useless: `_num()` defaults an absent score to 0, which would fabricate
        # a catastrophic drop on a config that did not change. What was missing is the flag
        # saying they are not a verdict, so diff() can decline to republish them.
        "graded": bool(getattr(score, "graded", True)),
        "checks": {f.id: f.status for f in findings
                   if not getattr(f, "suppressed", False)},
        # B-500: WHY a check is UNKNOWN, recorded because the status alone cannot say.
        # "The surface is confirmed absent" (no MCP server configured yet) and "the check
        # lost its footing" are the same string in `checks`, and they call for opposite
        # treatment: the first walking to WARN is a user configuring a feature for the
        # first time — announcing that as a regression is the false alarm this dimension
        # is most likely to produce — while the second is a real loss of coverage.
        # Two sorted id lists rather than a dict per check: only a minority of ids are ever
        # in either, so this costs a fraction of what widening `checks` itself would, and
        # it leaves the `checks` shape every existing consumer reads untouched.
        "checks_not_applicable": sorted(
            f.id for f in findings
            if not getattr(f, "suppressed", False) and getattr(f, "not_applicable", False)),
        # B-500: which optional subsystems actually RAN. Two runs taken under different
        # scopes are not comparable — `--no-host` alone turns five checks from WARN to
        # UNKNOWN on a machine where nothing changed — and without this the drift engine
        # reads the operator's own choice as a regression.
        #
        # The EFFECTIVE flags off `ctx`, not the CLI's `cli_opt_outs` string list: the
        # latter is populated only on the CLI path, so a library caller passing
        # `include_host=False` produced the identical false alerts with an empty opt-out
        # list. What matters is what ran, not how it was asked for.
        "scope": sorted(name for name, on in (
            ("host", getattr(ctx, "include_host", False)),
            ("sockets", getattr(ctx, "include_sockets", False)),
            ("deptree", getattr(ctx, "include_deptree", False)),
            ("native", getattr(ctx, "native", None) is not None),
        ) if on),
        "checks_degraded": sorted(
            f.id for f in findings
            if not getattr(f, "suppressed", False) and getattr(f, "engine_degraded", False)),
        "skills": _skill_sig(ctx),
        "bootstrap": {n: _h(t) for n, t in ctx.bootstrap.items()},
        "memory": _snapshot_memory_files(ctx, capped=_mem_capped),
        "native_count": native_count,
        "ignore_hash": _ignore_hash(ctx.home),
        # Agent Watch — connection / trust surface, so drift in what the agent is
        # joined to (MCP servers, channels, gateway bind) raises an alert.
        "mcp": _mcp_sig(ctx),
        # Rug-pull detection (RP1-RP3): per-server structured fields for fine-grained
        # privilege/transport/endpoint drift analysis (added F-008).
        "mcp_detail": _mcp_detail_sig(ctx),
        "channels": _channel_sig(ctx),
        "gateway_bind": _gateway_bind(ctx),
        "plugins": _plugins_sig(ctx),
    }
    snap["memory_capped"] = sorted(_mem_capped)
    # B-268: the skills frontier comes from the collector (which is where the cap lives).
    # `skills_capped` lists names present on disk but never read; `skills_frontier_partial`
    # says that list is itself incomplete, in which case diff() must not use it as a
    # completeness oracle and suppresses skill removals wholesale.
    snap["skills_capped"] = sorted(getattr(ctx, "skills_capped_names", None) or ())
    snap["skills_capped_count"] = int(getattr(ctx, "skills_capped_count", 0) or 0)
    snap["skills_frontier_partial"] = bool(getattr(ctx, "skills_frontier_partial", False))

    # F-173: the behavioural layer, reduced to what a drift comparison can honestly use.
    #
    # `fired` is `behavioral.grade_cap_signal()`'s output and MUST NOT be the raw
    # `result["findings"]`. behavioral.py's own comment calls a bare B191 divergence under a
    # rotated cap "expected, near-certain-benign background noise", and raw findings here
    # would put that in the drift stream on every run, forever. `grade_cap_signal` applies
    # `_B191_STRONG_SUB_SIGNALS`; that filter is the entire reason this dimension can exist.
    #
    # Re-grounded 2026-08-26, because the measurement this cited had drifted: `files_capped`
    # is still True but the window is 60 of 88 files, not 93, and B191 currently reads PASS
    # with `grade_cap_signal()` empty. The divergence is the hazard the filter holds off, not
    # something happening right now — stated in the present tense it read as a live fact.
    #
    # `undetermined` is a first-class dimension rather than an afterthought because on the
    # real machine it is the ONLY one of the three carrying live data: measured
    # T1 PASS / T2 PASS / T3 UNKNOWN / B191 PASS, so `fired` is empty and T3's UNKNOWN is
    # the fact the user is currently never told.
    if isinstance(behavioral, dict):
        snap["behavioral_fired"] = sorted(behavioral.get("fired") or ())
        snap["behavioral_undetermined"] = sorted(behavioral.get("undetermined") or ())
        snap["behavioral_capped"] = bool(behavioral.get("capped"))
        # F-182 follow-up: the FULL incompleteness verdict, not just the cap. See the note
        # at the newly-fired arm for the measurement that made this necessary.
        snap["behavioral_incomplete"] = bool(behavioral.get("incomplete"))

    # F-174: the two supply-chain subjects, both handed in by the caller for the same reason
    # `behavioral` is — the shell owns discovery (one of them reads PATH) and this module
    # stays a pure function of what it is given. Absent means "this run did not establish
    # it", never "there is none", and the diff arms are gated on presence accordingly.
    if isinstance(install, dict) and install:
        snap["openclaw_install"] = install
    if isinstance(provenance, dict):
        snap["skill_provenance"] = provenance
    # F-179: the host's own startup/scheduling surface, handed in by the shell for the same
    # reason as the two above — `hostpersist.scan` walks `/etc` and `sys.path`, which is
    # discovery, and this module stays a pure function of what it is given.
    if isinstance(host_persist, dict) and host_persist:
        snap["host_persist"] = host_persist

    host = getattr(ctx, "host", None)
    if host and host.get("supported"):
        snap["host"] = {cls: info.get("status")
                        for cls, info in (host.get("classes") or {}).items()}

    # C-135 FIX2: sticky "was a real config ever seen" bit, carried forward across an
    # arbitrarily long run of blind snapshots (same "once True, stays True" pattern as
    # ``config_baseline == 'carried'``). It is what lets the widened blind predicate below
    # tell "openclaw.json used to be readable and just vanished" (a benign atomic-replace
    # window — `jq ... > tmp && mv tmp openclaw.json` — a `mv openclaw.json
    # openclaw.json.bak` mid-troubleshooting, or a home not yet mounted on a cron-driven
    # run) apart from "this home never had an openclaw.json at all" (a non-OpenClaw setup,
    # or the very first run ever). Only the former is treated as blind — a user who
    # genuinely never configured OpenClaw must never get a permanent "Could not read
    # openclaw.json" alert, which is exactly the false alarm B-269 exists to prevent.
    prev_had_config = bool(isinstance(prev, dict) and prev.get("config_ever_seen"))
    snap["config_ever_seen"] = bool(getattr(ctx, "config_found", False)) or prev_had_config

    parse_error = bool(getattr(ctx, "config_parse_error", False))
    # C-135 FIX2: collector.py defines config_parse_error = config_found and not parsed_ok,
    # so a config that is simply ABSENT this run (config_found False) leaves
    # config_parse_error False too — B-269's original guard never fired for it, so
    # _degrade_snapshot() never ran, trust_removals stayed True in diff(), and the same
    # collapsed ctx.config = {} view B-269 already knows is untrustworthy got written into
    # the baseline as fact: a full fabrication burst (skill/MCP/channel "removed", gateway
    # bind "changed") followed by a CRITICAL "NEW ... connected" burst the moment the file
    # reappeared unchanged. Gated on prev_had_config (see above) so a config-less setup is
    # unaffected.
    config_missing_blind = (not getattr(ctx, "config_found", False)) and prev_had_config
    if parse_error or config_missing_blind:
        _degrade_snapshot(snap, prev)
    else:
        # C-417: the digest describes the bytes THIS run read, so a run that could not
        # read the file stores no digest at all. Deliberately not carried forward from
        # `prev` the way _degrade_snapshot carries the config dimensions: a stale digest
        # sitting beside a fresh `ts` would assert we read the config at a time we did
        # not — the same clean-verdict-about-an-unread-surface shape B-269 exists to
        # prevent. An absent key reads as "no digest for this run"; a carried one reads
        # as a fact.
        digest = _config_file_digest(ctx)
        if digest:
            snap["config_file_sha256"] = digest
        # B-527: the resolved-config digest, store-only like config_file_sha256 was at
        # C-417 — no diff() arm reads it yet, so it cannot alert. It closes the gap this
        # task exists for on its own (an $include fragment edit moves it even when the
        # root file's bytes do not), and a later phase can wire a comparison in once one
        # is wanted, the same staged shape C-417 used for config_file_sha256 itself.
        # B-527 follow-up: gated on a config having actually been READ, not merely on the
        # helper returning something. `collector.Context.config` defaults to `{}` — a dict —
        # so on a home with no openclaw.json and no prior baseline this arm runs (that state
        # is not `config_missing_blind`, which needs `prev_had_config`) and stored
        # sha256("{}") beside an ABSENT config_file_sha256. A digest for a file nobody read
        # is the clean-verdict-about-unread-ground shape B-269 exists to prevent, and it
        # became load-bearing the moment B-659 started comparing this field: the empty-config
        # digest would later "move" to a real one and be reported as a change the run could
        # not explain. The gate belongs here rather than in the helper, whose `{}` handling
        # is correct for a config file that genuinely contains `{}`.
        resolved_digest = (_config_resolved_digest(ctx)
                           if getattr(ctx, "config_found", False) else "")
        if resolved_digest:
            snap["config_resolved_sha256"] = resolved_digest
        # F-170: OpenClaw's own config-write journal, captured HERE rather than compared
        # live in diff(), for two reasons. It keeps `diff` a pure function of two stored
        # snapshots — everything it concludes stays reproducible from the state file
        # alone. And it lets the comparison run on HASHES instead of clocks: our `ts` is
        # local time while the journal's is UTC with a `Z`, so a string compare between
        # them is a silent timezone bug waiting for a user east of Greenwich.
        # Scoped to the config file THIS audit read — see configjournal._same_config.
        _journal = _journal_read(ctx.home, config_path=getattr(ctx, "config_path", None))
        if _journal.present:
            # The newest journaled write, as a cursor. `prev.head != curr.head` means the
            # journal advanced between runs, which is what makes "changed and reverted"
            # expressible at all.
            # Only a REAL hash. `newest_hash` returns "" when the window holds no usable
            # record — an empty journal, a `copytruncate` rotation, every record filtered
            # out as belonging to another config — and "" is still a str, so storing it
            # made a VANISHED cursor indistinguishable from an ADVANCED one. That fired a
            # false "changed and changed back" on a byte-identical config, which is the
            # exact thing this module's own docstring says rotation must never produce.
            # Absent means "no cursor", and the arm that needs one stands down.
            _head = _journal_newest_hash(_journal.writes)
            if _head:
                snap["config_journal_head"] = _head
            _by = _journal_find_by_hash(_journal.writes, digest) if digest else None
            if _by is not None:
                # Attribution for THIS run's config bytes. Only the three fields that are
                # safe to render — see configjournal.ConfigWrite on why the path and cwd
                # are never carried at all.
                snap["config_written_by"] = {
                    "ts": _by.ts, "pid": _by.pid, "argv0": _by.argv0,
                    # What this write STARTED from. Without it, attribution names the
                    # newest write regardless of how many happened in between — so a hand
                    # edit followed by any OpenClaw write handed the resulting CRITICAL
                    # alert OpenClaw's own provenance, exonerating whoever really did it,
                    # in a record that reaches the tamper-evident journal.
                    "previous_hash": _by.previous_hash,
                }
    return snap


def diff(prev: dict | None, curr: dict) -> list[tuple[str, str]]:
    """Return (level, message) alerts. Empty on first run or no change.

    A thin shim over ``diff_with_notes``, kept because ``diff`` is public API (it is in the
    package ``__all__`` and fifteen test modules call it). Callers that need to know what
    was NOT compared — the CLI does, so it can stop printing an unqualified all-clear over
    unexamined ground — should call ``diff_with_notes`` instead.
    """
    return diff_with_notes(prev, curr)[0]


def diff_with_notes(prev: dict | None, curr: dict
                    ) -> "tuple[list[tuple[str, str]], list[tuple[str, str]]]":
    """Return ``(alerts, notes)``.

    *alerts* are drift events, unchanged. *notes* are ``(category, sentence)`` pairs
    recording every comparison this run DECLINED to make — see the NOTE_* constants. A note
    is never an alert: it does not describe a change, does not reach the tamper-evident
    event journal, and cannot move a score. It exists so that "no new threats" can stop
    meaning "no new threats in the parts we looked at, and silence about the rest".
    """
    # B-270: a usable baseline is a NON-EMPTY DICT — the same predicate ``read_baseline``
    # applies, restated here because ``diff`` is public API and a caller can hand it
    # anything. The old bare truthiness check let a truthy non-dict (``[1,2,3]``, ``42``,
    # ``"abc"``) straight through to ``prev.get("skills", {})``, which raised
    # AttributeError; because the crash preceded ``save_state`` the poisoned file was never
    # replaced, so the run failed identically forever (measured: rc=1 on three consecutive
    # runs, state.json unchanged). An empty dict still returns no alerts, as before — but
    # the CLI no longer describes that as a clean comparison.
    if not isinstance(prev, dict) or not prev:
        # No note here: the CLI already tells absent from corrupt (BASELINE_ABSENT vs
        # BASELINE_CORRUPT) and says so in words. A note would be a second, vaguer voice
        # for a state that is already named precisely.
        return [], []
    alerts: list[tuple[str, str]] = []
    notes: list[tuple[str, str]] = []

    def note(category: str, sentence: str) -> None:
        notes.append((category, sentence))

    # C-418: several comparisons are gated on a SUB-key inside a dimension rather than on
    # the dimension itself, so the `watched` manifest above cannot see them — it lists
    # top-level snapshot keys only. Each of these gates is individually correct and each
    # was individually invisible: a tool server gaining `exfil` in its observed surface,
    # a skill update expanding what it can do, a channel allowlist changing shape, all
    # produced a bare all-clear. Counted per name and reported once per reason, so a home
    # with twenty servers gets one line rather than twenty.
    _skill_caps_unknown: set = set()
    _skill_ver_unknown: set = set()
    _mcp_pkg_unknown: set = set()
    _mcp_tools_unknown: set = set()
    _mcp_surface_unknown: set = set()
    _chan_partial: set = set()

    def pair_or_note(key: str, human: str) -> "tuple[dict, dict] | None":
        """``_both_dims`` plus a note saying why the comparison was skipped.

        Splits the one None into the two states it conflates, because they call for
        opposite actions: a key ABSENT from the old baseline heals itself on the next run
        and needs nothing from the user, while a key present but of the wrong type means
        the state file is damaged and will stay damaged until it is deleted. Absent from
        BOTH sides is neither — that surface was never recorded on this platform or in this
        setup, so there is no gap to disclose and no note.
        """
        pair = _both_dims(prev, curr, key)
        if pair is not None:
            return pair
        # ABSENT from both, not merely non-dict on both. The looser test swallowed
        # prev-damaged + curr-absent — precisely the state whose note tells the user to
        # delete the state file — and returned the bare all-clear over it.
        if key not in prev and key not in curr:
            return None
        if key not in prev:
            note(NOTE_NO_PRIOR_RECORD,
                 f"{human} had nothing to compare against — your saved record predates "
                 f"this, and will cover it from the next run onwards.")
        else:
            note(NOTE_RECORD_DAMAGED,
                 f"{human} could not be compared — the saved record for them is damaged. "
                 f"Delete the monitor state file to start a fresh baseline.")
        return None

    # --- B-269: was either side collected while openclaw.json was unreadable? ---------
    prev_blind = bool(prev.get("config_parse_error"))
    curr_blind = bool(curr.get("config_parse_error"))
    # A blind snapshot only carries a usable config baseline when there was a good one to
    # carry forward (see _degrade_snapshot); otherwise its config dimensions are empty
    # because nothing is known, not because nothing is configured.
    prev_config_usable = not prev_blind or prev.get("config_baseline") == "carried"
    compare_config = not curr_blind and prev_config_usable
    # A blind run's disappearances are collection artifacts, not events. _degrade_snapshot
    # already union-merges the shrinkable dimensions so these sets come out empty, but the
    # guard is kept independent of it so a caller that builds a snapshot without passing
    # *prev* still cannot fabricate a removal.
    trust_removals = not curr_blind

    # Two runs taken under different --no-* flags describe different subjects. The whole
    # transition family stands down rather than reporting the operator's own choice as
    # drift; an independent pass reproduced 5 false alerts in each direction from
    # --no-host/--no-sockets alone, on a machine where nothing had changed.
    _p_opt, _c_opt = prev.get("scope"), curr.get("scope")
    _same_scope_flags = (_p_opt is None or _c_opt is None
                         or sorted(_p_opt) == sorted(_c_opt))
    if not _same_scope_flags:
        note(NOTE_UNDETERMINED,
             "Check results were not compared: this run and the last were taken with "
             "different options, so they do not cover the same ground.")

    # B-511: a run whose grade was withheld has no verdict to compare. Printing
    # "Security score dropped: A 97 -> A 96." underneath the same run's own
    # "No grade yet - 3 of 5 layers did not run" was E-077's headline invariant
    # contradicting itself out loud — and on the DEFAULT path, since C-426 made the bare
    # run ungraded. Absent on either side means a snapshot written before this flag was
    # recorded: read as UNGRADED rather than assumed graded, so a legacy baseline can
    # never republish a number its run declined to show. Costs one run's score
    # comparison after the upgrade and then self-heals — the same trade the raw_score
    # backstop below already makes for the same reason.
    _both_graded = bool(prev.get("graded")) and bool(curr.get("graded"))
    if not _both_graded:
        note(NOTE_UNDETERMINED,
             "The score was not compared: at least one of these two runs did not earn a "
             "grade, so there is no verdict to compare it against.")


    # C-418: the blind-config family. Each of these is a comparison declined, and each used
    # to vanish into the all-clear. The HIGH alert below explains the CAUSE; these say what
    # the cause cost.
    if not trust_removals:
        note(NOTE_CONFIG_BLIND,
             "Anything that disappeared was not reported: this run could not read your "
             "settings file, so an item missing from view may simply be hidden rather "
             "than gone.")
    if not compare_config:
        note(NOTE_CONFIG_BLIND,
             "Your connections — tool servers, chat channels and the gateway address — "
             "were not compared with last time.")
    if prev_blind or curr_blind:
        note(NOTE_CONFIG_BLIND,
             "The score and the individual check results were not compared: one of the "
             "two runs saw less than the other, so the numbers do not describe the same "
             "ground.")

    # C-418 reading C-417's manifest: the GENERIC form of "your baseline predates this".
    #
    # A release that adds a comparison opens a presence gate on every existing baseline —
    # the older snapshot simply lacks the key, the gate skips, and the screen is identical
    # to a genuine all-clear. Instrumenting each gate individually would mean a new note
    # site with every such release, and the one that got forgotten would be invisible again.
    # Comparing the recorded manifest against what this build reads covers that family at
    # once, including gates that do not exist yet.
    #
    # TOP-LEVEL keys only, though — `watched` lists snapshot keys, so it is blind to a gate
    # sitting on a sub-key INSIDE a dimension (a server's `surface_tool_sigs`, a skill's
    # `caps`). Those are instrumented individually further down. An earlier version of this
    # comment claimed the manifest subsumed them; it does not, and believing it would have
    # left a rug-pull sitting under a bare all-clear.
    #
    # Self-healing by construction: this run writes the current manifest, so the note
    # appears exactly once after an upgrade and never again.
    # C-441: both arms NAME what was skipped. The absent arm used to say only "this run
    # cannot say which comparisons it was able to make" — on the one upgrade path this note
    # exists to serve, and the names were derivable the whole time. A baseline that predates
    # the manifest still carries its own keys, and a key this build watches that is not
    # among them is exactly a comparison that had nothing to compare against. So the two
    # arms differ only in where the previous coverage is read FROM: the recorded manifest
    # when there is one, the snapshot's own keys when there is not.
    _prev_watched = prev.get("watched")
    _from_manifest = isinstance(_prev_watched, list)
    _prev_covered = _prev_watched if _from_manifest else list(prev)
    # `watched` itself is excluded when deriving from the snapshot's keys: its absence is
    # the PRECONDITION of this branch, not a separate comparison that was skipped. Counting
    # it would double-count the very thing the sentence is already explaining.
    _unknown_to_prev = [k for k in WATCHED_DIMENSIONS
                        if k not in _prev_covered and not (k == "watched" and not _from_manifest)]
    if _unknown_to_prev:
        _names = _name_dimensions(_unknown_to_prev)
        if _from_manifest:
            note(NOTE_NO_PRIOR_RECORD,
                 f"{len(_unknown_to_prev)} thing(s) this version watches were not recorded "
                 f"by the run that saved your baseline, so they had nothing to compare "
                 f"against this once: {_names}. The next run compares them.")
        else:
            note(NOTE_NO_PRIOR_RECORD,
                 f"Your saved record predates coverage tracking, so {len(_unknown_to_prev)} "
                 f"thing(s) had nothing to compare against this once: {_names}. The next "
                 "run compares them.")
    elif not _from_manifest:
        # A pre-manifest baseline that nonetheless recorded everything this build watches.
        # Still worth one line — the reader is owed the reason this run had to derive the
        # answer — but it must not imply a coverage gap, because there is not one.
        note(NOTE_NO_PRIOR_RECORD,
             "Your saved record predates coverage tracking, but it recorded everything "
             "this version watches, so nothing was skipped.")

    if curr_blind:
        unknown = sum(1 for s in (curr.get("checks") or {}).values() if s == UNKNOWN)
        alerts.append((
            "HIGH",
            "Could not read openclaw.json this run — MCP, channel and gateway drift were "
            f"NOT evaluated and {unknown} check(s) report UNKNOWN. This run covers less "
            "ground than the last full one, so its score/grade are not comparable: a "
            "higher number here means reduced coverage, not improved security. The last "
            "known-good values were kept as the drift baseline. Fix or restore "
            "openclaw.json and re-run to resume full drift detection."))
    elif prev_blind:
        alerts.append((
            "INFO",
            "openclaw.json is readable again — full drift detection resumed; "
            + ("MCP/channel/gateway state was compared against the last known-good "
               "baseline." if prev_config_usable else
               "no known-good config baseline existed (the previous run could not read it "
               "either), so MCP/channel/gateway drift is measured from this run onward.")))

    def _skill_entry(v):
        if isinstance(v, dict):
            return v.get("hash", ""), v.get("caps"), v.get("version")
        return v, None, None          # legacy bare-hash snapshot

    def _skill_changed(p, c) -> bool:
        """B-267: did this skill change? Prefer the full-directory ``tree`` fingerprint.

        The scanned-text ``hash`` is a strict subset of the tree — TEXT-only, capped — so
        where the two disagree the tree is right and the hash is blind. Only when a side
        lacks ``tree`` (a legacy bare-hash snapshot, or one written before this fix) does
        the comparison fall back to the old hash, rather than fabricating a diff against a
        key that was never recorded. That fallback is self-healing: the first snapshot
        written after upgrade carries a tree, so at most one run stays on the old signal.
        """
        p_tree = p.get("tree") if isinstance(p, dict) else None
        c_tree = c.get("tree") if isinstance(c, dict) else None
        if p_tree and c_tree:
            return p_tree != c_tree
        return _skill_entry(p)[0] != _skill_entry(c)[0]

    def _ver_tuple(s: str) -> tuple:
        toks = re.split(r"[.\-+]", s)
        return tuple((0, int(t)) if t.isdigit() else (1, t) for t in toks)

    # B-304: `_both_dims` — not `_dim` on each side independently — because comparing a
    # genuinely populated `cs` against a `ps` that only LOOKS empty (a corrupted/hand-
    # edited `skills` field coerced to {} by `_dim`) fabricated a CRITICAL "NEW skill
    # installed ... this is when malware lands" for every already-installed, unchanged
    # skill. Measured first-hand: a state.json holding `"skills": ["not", "a", "dict"]`
    # (well-formed JSON, so `read_baseline` reports it BASELINE_OK, not BASELINE_CORRUPT —
    # the top-level payload IS a usable dict, only this one field is not) reported every
    # real skill on disk as newly installed. `mcp`/`mcp_detail`/`channels`/`host` already
    # use this same guard for exactly this reason (their own docstring: "comparing a real
    # side against a coerced {} would report every live entry as newly appeared"); this
    # extends it to `skills` so a corrupted dimension costs one silent, self-healing run
    # (the next save_state() overwrites it with a real dict) rather than a false malware
    # alarm on every installed skill.
    _skills_pair = pair_or_note("skills", "Installed skills")
    ps, cs = _skills_pair if _skills_pair is not None else ({}, {})
    # B-268: the skills truncation frontier on each side (see snapshot()). `ctx.installed_
    # skills` is capped at _MAX_SKILLS and its fill order is filename order — attacker-
    # controlled — so a flood of early-sorting skill dirs evicts real ones from the view.
    # Diffed as ground truth that produced a phantom "Skill 's299' was removed" while s299
    # sat on disk untouched (measured: 310 skills + one aaa*-named addition).
    prev_sk_capped = _frontier(prev, "skills_capped")
    curr_sk_capped = _frontier(curr, "skills_capped")
    prev_sk_partial = bool(prev.get("skills_frontier_partial"))
    curr_sk_partial = bool(curr.get("skills_frontier_partial"))
    _note_skills_prev_capped(note, prev_sk_capped)
    _note_skills_frontier_partial(curr, curr_sk_capped, curr_sk_partial, note)
    _diff_skills_added(alerts, cs, prev_sk_capped, prev_sk_partial, ps)
    _diff_skills_common(_skill_caps_unknown, _skill_changed, _skill_entry, _skill_ver_unknown, _ver_tuple, alerts, cs, ps)
    _diff_skills_removed(alerts, cs, curr_sk_capped, curr_sk_partial, ps, trust_removals)

    # B-268 disclosure. The FN twin is the serious half: a 300-skill flood hid a skill
    # exfiltrating an SSH key at Grade A, and replaced a live HIGH poisoning alert with
    # five fabricated "removed" lines. Since fill order is filename order, an attacker can
    # choose which skills fall outside the audited set. An all-clear over that view is not
    # honest, so the truncation is stated explicitly.
    _sk_capped_n = int(curr.get("skills_capped_count") or len(curr_sk_capped))
    _note_skills_capped(_sk_capped_n, alerts, curr_sk_capped)

    # B-304: same `_both_dims` reasoning as `skills` immediately above — a corrupted
    # `bootstrap` field on one side must not make every file on the OTHER, real side read
    # as "New bootstrap file appeared". `_dim` on each side independently used to do
    # exactly that (measured: `"bootstrap": "a string"` on prev reported every current
    # bootstrap file as newly appeared).
    _bootstrap_pair = pair_or_note("bootstrap", "Your agent's startup instruction files")
    pb, cb = _bootstrap_pair if _bootstrap_pair is not None else ({}, {})
    _diff_bootstrap_changed(alerts, cb, pb)

    # C-135 FIX1: ctx.bootstrap is keyed "<workspace-label>/<NAME>.md", where the label
    # depends on scan order plus a resolved-path de-dup (collector.py). The exact same
    # inode, with byte-identical content still read by the agent, can land under a
    # DIFFERENT key after a benign refactor — e.g. deleting now-redundant symlinks so
    # files resolve under their real mount label, or renaming the workspace dir and
    # updating the config to match. A bare key-set diff cannot tell that apart from a real
    # deletion. Pair each removed key with an added key carrying the IDENTICAL content
    # hash and treat the pair as a MOVE — neither a removal nor a new file — before either
    # loop below runs. This cannot mask a genuine deletion: if identical content is still
    # present under another key, the agent is still reading it, so there is nothing left
    # to alert on either direction. (Measured separation: a benign rename pairs every
    # removed/added key as a move; a genuine deletion of guardrail files has no added side
    # to pair with at all.)
    _boot_removed, _boot_added = pb.keys() - cb.keys(), cb.keys() - pb.keys()
    _boot_moved_from: "set[str]" = set()
    _boot_moved_to: "set[str]" = set()
    _diff_bootstrap_moved(_boot_added, _boot_moved_from, _boot_moved_to, _boot_removed, cb, pb)

    _diff_bootstrap_added(_boot_added, _boot_moved_to, alerts)
    _diff_bootstrap_removed(_boot_moved_from, _boot_removed, alerts, trust_removals)

    _append_memory_alerts(prev, curr, alerts, trust_removals=trust_removals, notes=notes)

    _diff_score(_both_graded, _same_scope_flags, alerts, curr, curr_blind, note, prev, prev_blind)

    # B-304: same `_both_dims` reasoning again — a corrupted `checks` field on prev must
    # not make every currently-FAILing check read as "Now FAILING" (a claim of a fresh
    # transition this run cannot actually see). `_dim` on each side independently used to
    # do exactly that (measured: `"checks": None` on prev reported every real FAIL,
    # including CRITICAL ones, as "Now FAILING" against a config that never changed).
    _checks_pair = pair_or_note("checks", "Individual check results")
    pc, cc = _checks_pair if _checks_pair is not None else ({}, {})
    # B-500 — the transition matrix, and why each silent cell is silent.
    #
    #   prev \ curr |  PASS  |  WARN  |  FAIL  | UNKNOWN | gone
    #   PASS        | silent | ALERT  | ALERT  | ALERT   | ALERT/note
    #   WARN        | silent | silent | ALERT  | ALERT*  | ALERT/note
    #   FAIL        | silent | silent | silent | ALERT*  | ALERT/note
    #   UNKNOWN     | silent | ALERT* | ALERT  | silent  | ALERT/note
    #   absent      | silent | silent | ALERT  | silent  |   —
    #
    #   * gated on the reason, not the status — see `_na` below.
    #
    # Silent cells, each for a reason and not by omission: anything INTO PASS is an
    # improvement; WARN->WARN and FAIL->FAIL are the same verdict restated; UNKNOWN->UNKNOWN
    # is unchanged blindness (the C-418 coverage note carries that, an alert per run would
    # be a standing false alarm); `absent -> WARN/UNKNOWN` is a check this version added, so
    # there is no earlier verdict to have regressed from.
    #
    # Before this, only two of the twenty-five cells alerted. On the real machine 78 of 184
    # checks sit in WARN or UNKNOWN, so for 42% of the subject nothing short of a full FAIL
    # was ever announced — and going grey is both cheaper for an attacker than going red and
    # RAISES the displayed score, since UNKNOWN leaves the score's denominator entirely.
    #
    # `_na` / `_deg`: which UNKNOWNs are a confirmed-absent surface and which are a broken
    # check. The status alone cannot tell them apart, and treating them alike is the false
    # alarm this arm is most likely to produce — a user configuring their first MCP server
    # walks UNKNOWN->WARN benignly. An older baseline carries neither list, so the arms that
    # need them stand down for one run rather than guess.
    _p_na, _c_na = prev.get("checks_not_applicable"), curr.get("checks_not_applicable")
    _reasons_known = isinstance(_p_na, list) and isinstance(_c_na, list)
    _na_prev, _na_curr = set(_p_na or ()), set(_c_na or ())
    _deg_curr = set(curr.get("checks_degraded") or ())
    if pc and cc and not _reasons_known:
        note(NOTE_NO_PRIOR_RECORD,
             "Checks that stopped being determinable were not compared — your saved record "
             "does not say which of them were simply not applicable.")

    # B-500: comparisons whose OUTCOME is real but whose CAUSE we cannot evidence. They
    # become coverage notes rather than alerts — see the arms below for why.
    _checks_alerts_from = len(alerts)
    _went_dark: list = []
    _newly_visible: list = []
    def _check_sev(cid: str, fallback: str = "MEDIUM") -> str:
        return getattr(BY_ID[cid], "severity", fallback) if cid in BY_ID else fallback

    def _check_title(cid: str) -> str:
        return BY_ID[cid].title if cid in BY_ID else cid
    _diff_check_transitions(_check_sev, _check_title, _deg_curr, _na_curr, _na_prev, _newly_visible, _reasons_known, _same_scope_flags, _went_dark, alerts, cc, curr_blind, pc, prev_blind)

    # B-660: this was the one arm in diff() gated on neither the scope flags nor presence.
    #
    # `native_count` is written as `len(native.findings) if native else 0`, and `_num`
    # defaults a missing key to 0 — so "the native audit did not run last time" and "the
    # native audit found fewer problems last time" arrived here as the same input. Two
    # measured fabrications, both on a machine where nothing moved:
    #
    #   * a `--monitor --no-native` run followed by an ordinary one: prev 0, curr N ->
    #     "openclaw security audit reports N more issue(s) than last time";
    #   * a baseline written before this key existed: same sentence, and the `watched`
    #     manifest recorded the absence correctly while this arm never consulted it.
    #
    # Latent rather than live on the maintainer's fleet only because `openclaw security
    # audit` reports zero findings there, so `0 > 0` is False. That is why it survived
    # every gate: `monitor_fp_gate.py` diffs two snapshots of an unchanged home taken the
    # SAME way, and this needs the two runs to differ in how they were taken.
    #
    # Fixed the way its siblings already are, and deliberately not by changing `_num`'s
    # default — other callers rely on 0 there. Presence on both sides, plus the same
    # `_same_scope_flags` guard B-500 added to the check-transition arms after --no-host
    # produced "No longer determinable: Host firewall active" on an unchanged machine.
    # bool excluded for the same reason `_num` excludes it: True < 2 compares as 1, so a
    # corrupted field would silently fabricate a delta out of nothing.
    def _count(v: object) -> "int | None":
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    _p_native, _c_native = _count(prev.get("native_count")), _count(curr.get("native_count"))
    _both_native = _p_native is not None and _c_native is not None
    _diff_native_findings(_both_native, _c_native, _p_native, _same_scope_flags, alerts, note)

    prev_ih = prev.get("ignore_hash", "")
    curr_ih = curr.get("ignore_hash", "")
    if prev_ih != curr_ih:
        alerts.append(("HIGH",
                       "your .clawseccheckignore changed — a suppression was added/removed "
                       "(review to ensure a real hole is not hidden)."))

    # --- Agent Watch: connection / trust-surface drift (guarded so an old snapshot
    #     without these keys never produces spurious 'new X' alerts after upgrade) ---
    _checks_alerts_to = len(alerts)
    # F-170: the config-derived alerts start here and end just before the host block.
    # Marked by index so a journaled write can be attributed to exactly those and not to
    # skill, memory or host drift, which the same config edit did not cause.
    _config_alerts_from = len(alerts)
    # Indices inside that span whose evidence is NOT the config file — see the RP6/RP7
    # block below. Kept as an exclusion set rather than by narrowing the span, because the
    # trajectory-derived alerts are interleaved with config-derived ones inside the same
    # per-server loop.
    _trajectory_alerts: set = set()
    _mcp_pair = pair_or_note("mcp", "Connected tool servers")
    _diff_mcp_servers(_mcp_pair, alerts, compare_config)

    # --- Rug-pull detection (RP1-RP3): fine-grained MCP server manifest drift ---
    # Only runs when BOTH snapshots carry the structured mcp_detail key (guarded so an
    # old snapshot without this key never produces spurious alerts after upgrade).
    _detail_pair = pair_or_note("mcp_detail", "What each tool server launches and asks for")
    _diff_mcp_detail(_detail_pair, _mcp_pkg_unknown, _mcp_surface_unknown, _mcp_tools_unknown, _trajectory_alerts, alerts, compare_config)

    _chan_pair = pair_or_note("channels", "The ways your agent can be contacted")
    _diff_channels(_chan_pair, _chan_partial, alerts, compare_config)

    # B-270: both sides must be STRINGS, not merely present — `cb in EXPOSED_BINDS` raises
    # TypeError on an unhashable (list/dict) value from a corrupted snapshot, and a
    # non-string bind is not a bind address we can reason about anyway.
    _pgb, _cgb = prev.get("gateway_bind"), curr.get("gateway_bind")
    _note_gateway_bind_unreadable(_cgb, _pgb, compare_config, note, prev)
    _diff_gateway_bind_moved(_cgb, _pgb, alerts, compare_config)

    # B-659: the plugin trust surface. A plugin runs inside the agent, so an id becoming
    # allowed, a deny being lifted, or the global switch opening are all trust grants.
    #
    # Inside the config-alert span on purpose, so F-170's attribution stamps these the same
    # way it stamps an MCP or gateway change — a config edit is what causes them.
    #
    # DIRECTION IS THE WHOLE CALIBRATION. Only loosening is reported: an id ADDED to allow,
    # an id REMOVED from deny, `enabled` going false -> true. Tightening is the user doing
    # the right thing, and announcing it would train them to ignore this dimension.
    # Reordering cannot fire at all, because the signature sorts.
    #
    # MEDIUM is a ceiling, and it is the epic's constraint rather than timidity: this fleet
    # configures `plugins.entries` (three of them) and has no `allow`/`deny` at all, so the
    # loosening arms have FIXTURE evidence only — and no HIGH or CRITICAL alert may ship on
    # fixture evidence alone. Raise it when a real config exercises it, not before.
    #
    # `entries` is INFO and separate: the installed dist documents that block as "updated by
    # provider setup flows", i.e. OpenClaw writes it whenever the user configures a
    # provider. Treating a routine write as a trust change is how a dimension earns itself a
    # permanent place in the user's ignore list.
    _plug_pair = _both_dims(prev, curr, "plugins")
    _diff_plugins(_plug_pair, alerts, compare_config)

    _config_alerts_to = len(alerts)

    _note_unmodelled_config_edit(_checks_alerts_from, _checks_alerts_to, _config_alerts_from, _config_alerts_to, _trajectory_alerts, alerts, compare_config, curr, curr_blind, note, prev, prev_blind)

    # ------------------------------------------------------------------ F-179: the host
    # The machine's own startup and scheduling files. NOT gated on `compare_config`: this
    # surface is read from the host, so an unreadable `openclaw.json` says nothing about
    # it, and skipping it on a blind run would hide the one thing a blind run can still
    # see. See `hostpersist.py` for what is readable and — more importantly — what is not.
    #
    # SEVERITY, and why it differs by family rather than being uniform. An entry APPEARING
    # is an execution entry point that did not exist at the last check, which is the shape
    # of the published attack (a host job rewriting an identity file), so it is MEDIUM
    # across the board. A MODIFICATION splits: `~/.config/systemd/user` and `/etc/cron.*`
    # are infrastructure that changes rarely and whose every line can start a process, so a
    # modification there is MEDIUM too; a shell startup file or a `.pth` is edited by
    # humans and by ordinary package managers (`pip install -e` writes a `.pth`, every
    # version manager appends to `.bashrc`), so a modification there is INFO — recorded,
    # counted by `--brief`, and deliberately below the cron recipe's `--fail-on medium`
    # threshold, because a watch that pages on `pip install` gets switched off.
    #
    # MEDIUM is a ceiling here for the same reason the `plugins` arm above states: no HIGH
    # or CRITICAL may ship on evidence this thin. Nothing on this fleet has yet been
    # observed to move, so every arm below is calibrated from reasoning about the surface,
    # not from measured drift. That is exactly what the C-135 pass is for.
    #
    # REMOVAL is INFO in every family. It can be track-covering, but it is far more often a
    # user tidying up, and there is no discriminator available to a digest comparison.
    # ABSENCE IS HANDLED BESPOKE, not through `pair_or_note`, and the reason is a real
    # fabrication that the generic helper produced here. `host_persist` is CONDITIONAL: the
    # shell may hand `snapshot()` nothing, so "recorded last time, absent now" is a routine
    # state, not damage. `pair_or_note` classified exactly that as `record_damaged` and told
    # the user *"the saved record for them is damaged. Delete the monitor state file"* —
    # advice that destroys a working baseline over a scan that simply did not run. Measured,
    # not theorised. Same bespoke shape `openclaw_install` uses a few arms below, for the
    # same reason. The reverse direction (absent in the baseline, present now) IS worth a
    # note and keeps one: that is the honest first-run-after-upgrade message.
    _hp_pair = _both_dims(prev, curr, "host_persist")
    _diff_host_persist(_hp_pair, alerts, curr, note, prev)

    _host_pair = pair_or_note("host", "Security tools running on this machine")
    _diff_host_monitors(_host_pair, alerts, note)

    # C-418: the sub-key gates, reported once per reason with a count. Ordered loudest
    # first — a tool server's observed surface is the live rug-pull signature, a skill's
    # capability set is what an update quietly widens.
    if _mcp_surface_unknown:
        note(NOTE_UNDETERMINED,
             f"The tools actually offered to your model by {len(_mcp_surface_unknown)} "
             f"server(s) were not compared — no session transcript was available for one "
             f"of the two runs, so a server that started offering new tools would not show.")
    if _mcp_tools_unknown:
        note(NOTE_NO_PRIOR_RECORD,
             f"The tool list declared by {len(_mcp_tools_unknown)} server(s) was not "
             f"compared with last time.")
    if _mcp_pkg_unknown:
        note(NOTE_NO_PRIOR_RECORD,
             f"Which package {len(_mcp_pkg_unknown)} server(s) launch was not compared — "
             f"your saved record predates that detail, so a swap under a trusted name "
             f"would not show.")
    if _skill_caps_unknown:
        note(NOTE_NO_PRIOR_RECORD,
             f"What {len(_skill_caps_unknown)} skill(s) are able to do was not compared "
             f"with last time, so an update that widened them would not show.")
    if _skill_ver_unknown:
        note(NOTE_NO_PRIOR_RECORD,
             f"Version numbers were not compared for {len(_skill_ver_unknown)} skill(s) — "
             f"they do not declare one on both sides.")
    if _chan_partial:
        note(NOTE_NO_PRIOR_RECORD,
             f"Some settings of {len(_chan_partial)} contact channel(s) had nothing to "
             f"compare against — they are recorded on only one of the two runs.")
    # B-500: a check that ran last time and not this time. The comparison loop walks the
    # CURRENT set only, so before this these ids were never visited at all.
    #
    # Two very different causes, told apart rather than merged. `run_all` isolates each
    # check and, on a crash or timeout, replaces the catalog id with an `ERR:<funcname>`
    # key — so a check that blows up does not go UNKNOWN, it VANISHES and a stranger
    # appears beside it. A CRITICAL FAIL that becomes a crash therefore disappeared in
    # complete silence. The scoring layer normally catches this via DEGRADED_CHECK_CAP,
    # but that cap is 49 and the real machine already scores 49, so on the host this was
    # measured on the cap could not move anything.
    #
    # No `ERR:` key means the id simply no longer exists in this build — a catalog change
    # across an upgrade. That is not an event and must not alert; it gets a note, and it
    # self-heals on the next run.
    _vanished = set(pc) - set(cc)
    # An id can also vanish because a new ignore rule suppressed it — suppressed findings
    # are excluded from the snapshot entirely. The ignore-hash change is already alerted
    # separately; attributing the disappearance to a crash on top of it would be a second,
    # false explanation for something the user just did deliberately.
    _ignore_moved = prev.get("ignore_hash", "") != curr.get("ignore_hash", "")
    _diff_vanished_checks(_check_sev, _check_title, _ignore_moved, _same_scope_flags, _vanished, alerts, cc, curr_blind, note, pc, prev_blind)

    # B-500: the two outcome-real / cause-unevidenced families, disclosed rather than
    # asserted. This is the C-418 mechanism doing exactly what it was built for: the
    # silence is ended without a claim the evidence does not support.
    if _went_dark:
        note(NOTE_UNDETERMINED,
             f"{len(_went_dark)} check(s) that previously reported a problem can no longer "
             f"determine their state, so the score no longer counts them against you.")
    if _newly_visible:
        note(NOTE_UNDETERMINED,
             f"{len(_newly_visible)} check(s) began reporting a problem they could not "
             f"determine last time — it may be new, or it may have been there unseen.")

    # ---- F-173: the behavioural layer ------------------------------------------------
    #
    # `--behavioral` and `--monitor` were mutually exclusive by construction (the
    # behavioural branch returns before the monitor one), so four of the `logs` subject's
    # seven checks never ran under a scheduled watch and the all-clear covered none of that
    # ground. This arm ends the silence. It is deliberately asymmetric, and each asymmetry
    # is a separate decision:
    #
    # 1. APPEARANCE is reported, DISAPPEARANCE never is. The evidence window rotates — 60
    #    of 88 trajectory files on this machine as of 2026-08-26 — so a pattern leaving it
    #    is not evidence it stopped happening. "T1 cleared" would be a resolution we
    #    invented; a real one shows up as a check status change in `checks`, which is
    #    compared elsewhere.
    # 2. It reports through `alerts` at INFO, not through `note()`, even though the task
    #    that specified it said "notes, never alerts". Notes collapse to a bare count
    #    unless `--verbose` (see report._not_compared_lines, and its measured reason), so a
    #    detector that fired would have been INVISIBLE on a default run. INFO is below the
    #    HIGH default of the C-419 exit-code threshold, so this still cannot page anyone,
    #    and it never touches the score — the F-154 cap-only discipline is preserved
    #    because nothing here reaches `scoring.compute`.
    #
    #    Two channels it DOES reach, named here because an earlier version of this list
    #    read as exhaustive while naming only what the alert cannot do. `record_events`
    #    applies no severity filter, so an INFO behavioural alert is appended to
    #    `events.jsonl` — which is hash-chained, so it is permanent — and `render_brief`
    #    counts every journal entry, so it shows up in `--brief`'s "N event(s) recorded"
    #    line. Verified by running it: an INFO baseline-reference entry lands in the journal
    #    and is counted by `--brief` as "none above MEDIUM". Neither is a defect; both are
    #    the difference between "cannot page you" and "leaves no trace", and only the first
    #    was true.
    # 3. It stands down when either side was blind. Structural, not measured: T3's
    #    "declared" capability set is read out of the config, so a collapsed `ctx.config`
    #    could in principle widen "observed minus declared" and fabricate a firing. The
    #    experiment was run and could NOT discriminate — with `ctx.config = {}` the real
    #    machine returns byte-identical verdicts, because its T3 is UNKNOWN in both views.
    #    An inconclusive experiment is not a licence to drop the guard.
    _c_fired = curr.get("behavioral_fired")
    _p_fired = prev.get("behavioral_fired")
    _diff_behavioral(_c_fired, _check_title, _p_fired, alerts, curr, curr_blind, note, prev, prev_blind)

    # ---- F-174: the OpenClaw installation itself --------------------------------------
    #
    # B33 and C4 read `meta.lastTouchedVersion` — a string the agent writes about itself.
    # This compares the artifact on disk instead.
    #
    # **Wholesale appearance or disappearance is never an alert**, and this is not caution
    # for its own sake: the install is located from PATH, and a cron job's PATH really is
    # minimal. Verified — `env -i PATH=/usr/bin:/bin` cannot find the openclaw the same
    # machine resolves interactively. So the very schedule this feature exists to serve
    # would otherwise have reported "OpenClaw was uninstalled" on its first cron run and
    # "OpenClaw appeared" the first time someone ran it by hand. It gets a note.
    _p_inst, _c_inst = _both_dims(prev, curr, "openclaw_install") or (None, None)
    _diff_openclaw_install(_c_inst, _p_inst, alerts, curr, note, prev)

    # ---- F-174: where each installed skill came from -----------------------------------
    #
    # B181 already reads these digests for a point-in-time verdict; this watches them MOVE,
    # which is how an update is detected with no cooperation from the user. Removals honour
    # `trust_removals` for the same B-269 reason every other collected dimension does: the
    # workspace roots are config-derived, so a blind run sees a subset.
    # NOT `pair_or_note`. That helper's absent-from-curr branch says "the saved record for
    # them is damaged. Delete the monitor state file to start a fresh baseline." — which is
    # false here and whose remedy destroys the user's whole drift history. This key is
    # absent whenever THIS run found no install records: no lock file in any workspace
    # searched, an unreadable or oversized one, or a blind run whose only workspace came
    # from the config. The saved record is fine; the current run is the one that came up
    # empty. An independent pass found this by reading the two branches side by side —
    # `openclaw_install` right above got bespoke, correct absence handling and its sibling
    # was routed through a generic helper carrying the opposite meaning.
    _prov = _both_dims(prev, curr, "skill_provenance")
    _diff_skill_provenance(_prov, prev, curr, alerts, note, trust_removals)

    # ---- F-170: OpenClaw's own config-write journal, as a second witness ---------------
    #
    # Everything here is derived from the two STORED snapshots, so it stays reproducible
    # from the state file alone, and every comparison is over hashes rather than clocks
    # (our `ts` is local, the journal's is UTC — a string compare between them is a
    # timezone bug waiting for a user east of Greenwich).
    _p_digest, _c_digest = prev.get("config_file_sha256"), curr.get("config_file_sha256")
    _p_head, _c_head = prev.get("config_journal_head"), curr.get("config_journal_head")
    _journal_seen = isinstance(_c_head, str)

    _diff_config_journal(_c_digest, _c_head, _config_alerts_from, _config_alerts_to, _journal_seen, _p_digest, _trajectory_alerts, alerts, curr)

    _diff_config_digest_unmoved(_c_digest, _c_head, _p_digest, _p_head, alerts)

    return alerts, notes
