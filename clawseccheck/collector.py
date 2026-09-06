"""Read-only collection of OpenClaw config, bootstrap files, and related host artifacts.

This module never writes, never makes a network call, and imports nothing beyond the
stdlib — but "reads only config and bootstrap files" undersells its real scope, which
every check needs to draw on. The ``LIMIT_DOMAIN_*`` constants below name every domain
it reads from: ``~/.openclaw/openclaw.json``, workspace bootstrap markdown, installed
skill/plugin text, the cron job store, exec-approvals state, the OpenClaw dotenv files
and systemd ``EnvironmentFile=`` lines, subagent-run and audit-event trails. Each read
is bounded (size caps, no execution of anything read) — see the individual
``_collect_*`` functions and ``SECURITY_MODEL.md`` for the full, itemized capability
surface. No network. No writes. Pure stdlib.
"""
from __future__ import annotations

import codecs
import errno
import math
import hashlib
import io
import json
import re
import os
import sqlite3
import stat
import zipfile
import tarfile
import gzip
import bz2
import lzma
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from .configloader import (
    ConfigLoadError as _ConfigLoadError,
    load_openclaw_config as _load_openclaw_config,
)
from .safeio import walk_dir_safely, is_safe_tar_member
from .skilldiscovery import (
    config_extra_skill_dirs as _config_extra_skill_dirs,
    config_plugin_load_paths as _config_plugin_load_paths,
    iter_discovered_skill_dirs as _iter_discovered_skill_dirs,
)
from .textnorm import normalize_for_scan, obfuscation_signals

# Bootstrap / prompt files injected into the system prompt as "trusted context".
# The native `openclaw security audit` does not inspect these files; checks
# B6/B7/B9 cover that gap.
#
# B-365: BOOT.md is the ONE bootstrap file with an automatic EXECUTION trigger, not
# merely an injection surface — the bundled `boot-md` hook (`gateway:startup` event)
# runs it once per agent workspace on every gateway restart, no user turn involved
# (grounded against the installed dist's own docs, `~/.npm-global/lib/node_modules/
# openclaw/`: docs/concepts/agent-workspace.md:85, docs/automation/hooks.md:229,280,
# docs/cli/hooks.md:31,101, docs/reference/templates/BOOT.md). Before this fix it was
# absent here, so an attacker who could write one file into the workspace got a
# directive-injection surface the whole content ring (B6/B7/B9 and friends, which all
# iterate ctx.bootstrap) never saw at all. Adding it here is enough — those checks
# already scan every ctx.bootstrap entry by name, so BOOT.md is now covered by the
# SAME generic detection as SOUL.md/AGENTS.md/TOOLS.md, with no new check id needed.
# (The `boot-md` hook itself ships DISABLED by default and must be explicitly enabled
# via `openclaw hooks enable boot-md`, i.e. `hooks.internal.entries.boot-md.enabled` /
# `hooks.internal.enabled` in openclaw.json — reading that toggle to gate severity is
# left for a follow-up task, not this fix.)
BOOTSTRAP_FILES = [
    "SOUL.md", "AGENTS.md", "TOOLS.md", "MEMORY.md", "IDENTITY.md",
    "USER.md", "HEARTBEAT.md", "BOOTSTRAP.md", "memory.md", "BOOT.md",
]

WORKSPACE_DIRS = ["workspace-home", "workspace-work", "workspace"]

# ---------------------------------------------------------------------------
# B-281 (ENV-1): the audit target is a RESOLVED path, not a hardcoded filename.
#
# Grounded against the installed dist (~/.npm-global/lib/node_modules/openclaw/dist),
# not the recon doc:
#   paths-BMBAvkNf.js:18-21   CONFIG_FILENAME / LEGACY_CONFIG_FILENAMES /
#                             LEGACY_STATE_DIRNAMES / NEW_STATE_DIRNAME
#   paths-BMBAvkNf.js:112-116 resolveCanonicalConfigPath  — OPENCLAW_CONFIG_PATH first
#   paths-BMBAvkNf.js:136-152 resolveConfigPath           — the 4-branch ladder
#   paths-BMBAvkNf.js:175-190 resolveDefaultConfigCandidates
#   paths-BMBAvkNf.js:44-62   resolveStateDir             — OPENCLAW_STATE_DIR, then
#                             ~/.openclaw, then an EXISTING ~/.clawdbot, else ~/.openclaw
#   home-dir-CJKEsOtx.js:34-58 resolveRawHomeDir/resolveRequiredHomeDir — OPENCLAW_HOME
#                             beats HOME/USERPROFILE; "", "undefined" and "null" are
#                             rejected as unset (normalize$1, :13-17)
OPENCLAW_CONFIG_FILENAME = "openclaw.json"
# Historical name from the clawdbot era. `resolveConfigPath` prefers an EXISTING legacy
# file over the canonical one, so a migrated user can have OpenClaw reading a file this
# tool would never have opened — with no environment variable set at all.
OPENCLAW_LEGACY_CONFIG_FILENAMES = ("clawdbot.json",)
OPENCLAW_NEW_STATE_DIRNAME = ".openclaw"
OPENCLAW_LEGACY_STATE_DIRNAMES = (".clawdbot",)

# The three variables that can point OpenClaw at a different config file than the one we
# audit. Read-only, by NAME only — values are paths, never secrets, but they are still
# routed through the report's normal path handling and never logged raw.
OPENCLAW_PATH_ENV_VARS = ("OPENCLAW_CONFIG_PATH", "OPENCLAW_HOME", "OPENCLAW_STATE_DIR")

# Where OpenClaw discovers installed skills (we read their CONTENT, never run them).
SKILL_DIRS = ["skills", "workspace/skills", "workspace-home/skills",
              "workspace-work/skills", ".agents/skills"]
# B-265: the ONLY own-skill directory name we still recognise. "clawshield" was a dead
# legacy namespace (renamed away in v0.16.0) that protected nothing and handed an attacker
# a free cloak. Note this set is never a self-exclusion decision on its own — it only
# selects which *shape* of `_is_own_source` layout check applies; the engine markers below
# are what actually grant the exclusion.
_OWN_SKILL_NAMES = {"clawseccheck"}

# Distinctive symbols that only ClawSecCheck's own signature engine (the checks/ package)
# contains. Used to recognise our own source so neither --vet nor the installed-skill audit
# flags the scanner's embedded attack signatures + red-team payloads as malware.
_OWN_ENGINE_MARKERS = ("def check_installed_skills", "def vet_skill", "_SKILL_CRIT")
_MAX_SKILLS = 300
# B-268: how many cap-evicted skill NAMES are retained as the truncation frontier. Names
# are cheap (a directory basename), but the frontier must not itself become an unbounded
# allocation on a deliberate 100k-skill flood. Past this point ctx.skills_frontier_partial
# goes True and consumers must stop using the name list as a completeness oracle. Set well
# above _MAX_SKILLS so any plausible real fleet keeps an EXACT frontier.
_MAX_SKILL_FRONTIER_NAMES = 5_000
# B-144 follow-up: raised 60_000 -> 200_000 -> 1_000_000, all three caps kept in lock-
# step. _MAX_FILE_BYTES must move WITH _MAX_BYTES_PER_SKILL, not independently — a
# single file over _MAX_FILE_BYTES is dropped whole by collect_skill_files before the
# per-skill budget logic ever sees it, so raising only the per-skill cap has no effect
# on a skill with one large file. Regex/entropy scanning 1MB is still low-single-digit
# milliseconds per check (DEFAULT_CHECK_BUDGET_S is 15s); the cross-file reassembly
# checks (B90/B154) are independently bounded by their own fragment/window caps
# regardless of blob size. Confirmed on a real config: a legitimate ~152KB skill
# (clawstealth) was hitting the old 60KB cap and reading as UNKNOWN purely from asymmetry
# with _MAX_PY_BYTES_PER_SKILL (already 200KB) before that first bump.
_MAX_BYTES_PER_SKILL = 1_000_000
_MAX_FILE_BYTES = 1_000_000
_MAX_FILES_PER_SKILL = 500
_MAX_PY_BYTES_PER_SKILL = 1_000_000  # cap on Python source kept per skill for AST analysis
_ARCHIVE_FILE_LIMIT = _MAX_FILES_PER_SKILL
_ARCHIVE_MAX_FILE_BYTES = _MAX_FILE_BYTES
_ARCHIVE_MAX_TOTAL_BYTES = 20_000_000
_ARCHIVE_MAX_EXPANSION_RATIO = 100

# B-153: openclaw.json is user/agent-authored structured config (MCP server lists,
# capability grants, agent definitions, …) rather than a skill payload, so it gets its
# OWN — slightly larger — cap instead of reusing _MAX_FILE_BYTES verbatim: a real config
# with many servers/agents can legitimately run a few hundred KB larger than a single
# skill file, and the read happens exactly ONCE per audit (unlike per-skill-file reads),
# so a larger single cap doesn't reopen the memory-scaling hole B-153 closes. Still
# bounded — a 500MB config caps at 5MB read, not unbounded RSS growth.
_MAX_CONFIG_BYTES = 5_000_000

# B-231 sub-item 1: the cron job store (~/.openclaw/cron/jobs.json, or the SQLite-backed
# cron_jobs table when the legacy JSON file is absent) is read-only, symlink-safe, and
# capped the same way as the config/bootstrap reads above — a huge/padded store must not
# load whole into memory or feed an unbounded number of jobs into the content-ring scan.
_MAX_CRON_BYTES = _MAX_CONFIG_BYTES
_MAX_CRON_JOBS = 200

# B-294: the cron RUN-LOG table (cron_run_logs) is append-per-run and pruned only by
# OpenClaw's own pruneCronRunLogRows, so a long-lived box can hold many thousands of rows.
# Bounded the same way as the job store above -- the consuming check only needs enough rows
# to establish WHICH job_ids have an execution trail, not the full history.
_MAX_CRON_RUN_LOGS = 500

# B-236 (B172): the standing exec-approvals store (~/.openclaw/exec-approvals.json) is
# read-only and size/entry-capped the same way as the cron store above.
_MAX_EXEC_APPROVALS_BYTES = _MAX_CONFIG_BYTES
_MAX_EXEC_APPROVALS_AGENTS = 200

# B-240 (B177): the persisted installed_plugin_index.install_records_json column (OpenClaw's
# own ClawHub trust verdict per plugin) is read-only and size/entry-capped the same way as
# the cron/exec-approvals stores above — a huge/padded blob must not load whole into memory
# or feed an unbounded number of records into the finding text.
_MAX_PLUGIN_TRUST_BYTES = _MAX_CONFIG_BYTES
_MAX_PLUGIN_TRUST_RECORDS = 500

# B-292 (RT-2): the SIBLING installed_plugin_index.plugins_json column, on the exact same
# row and read over the exact same read-only connection as install_records_json above (both
# columns are declared TEXT NOT NULL in the one CREATE TABLE that defines this table --
# openclaw-state-db-DzSsA9Ji.js:995-1008 -- so there is no schema version where the table
# exists but this column does not). Unlike install_records_json (a dict keyed by pluginId),
# plugins_json is a JSON ARRAY -- one full index record per installed plugin -- so it gets
# its own byte/record cap rather than reusing _MAX_PLUGIN_TRUST_RECORDS.
_MAX_PLUGIN_INDEX_BYTES = _MAX_CONFIG_BYTES
_MAX_PLUGIN_INDEX_RECORDS = 500

# B-296 (DISK-5 increment 1): the subagent-spawn registry (``subagent_runs`` in the same
# shared state SQLite DB) is read-only and row-capped the same way as the stores above. This
# is a DISCLOSURE surface (prove N spawns ran despite config silence), not a forensic dump,
# so the cap stays modest — enough to name a handful of examples without holding an unbounded
# number of ``task``/``outcome_json`` blobs in memory.
_MAX_SUBAGENT_RUNS = 50
# A subagent's own delegated task text is free-form and may be long (or, worst case, carry
# arbitrary/sensitive content it was asked to act on) — cap it defensively at read time. The
# disclosure check (checks/_agents.py) never echoes this field into evidence text anyway
# (see its docstring), but the collector caps it independently so nothing downstream can
# accidentally hold or print an unbounded blob.
_MAX_SUBAGENT_TASK_CHARS = 500
# B-709: on the MODERN (OpenClaw 2026.8.2+) subagent_runs shape, the only outcome signal is
# `$.execution.outcome.status`, and the vendor itself constrains it to exactly these four
# values (subagent-registry.store.sqlite-B_lUfEus.js:362). Anything else — including the
# key being entirely absent, which is the normal in-flight-run shape — is treated as "no
# outcome yet", never as a fifth value.
_SUBAGENT_OUTCOME_STATUSES = frozenset({"ok", "error", "timeout", "unknown"})

# F-134 (DISK-1, B191): OpenClaw's OWN runtime audit trail (``audit_events`` in the shared
# state SQLite DB) is bounded on the WRITE side by the shipped runtime itself — pruned to a
# 30-day / 100,000-row retention window on every insert (audit-event-store-D1P32Q4Y.js:6-7,
# 52-57: AUDIT_EVENT_RETENTION_MS / AUDIT_EVENT_MAX_ROWS) — but this collector still bounds
# its OWN read the same way every other sqlite reader in this module does, so a long-lived,
# very active box can't feed an unbounded row set into a check. The real box this was
# grounded against holds 502 rows total, comfortably under this cap.
_MAX_AUDIT_EVENTS = 1000

# B-111: an archive member name is attacker-controlled and NOT OS-length-limited (unlike a
# real filesystem path) — a crafted zip/tar entry can carry a multi-KB name. It flows
# uncapped into ctx.limit_hits / ctx.path_traversal_violations / ctx.file_manifest keys,
# which are joined straight into report evidence text (see B13 in the checks engine). Cap it at the
# point of entry so every downstream consumer inherits the bound.
_UNTRUSTED_NAME_CAP = 120


def _note_skill_gap(ctx, skill_dir: Path, entry: str) -> None:
    """Attribute a coverage gap to the skill it belongs to.

    B-551: `unreadable_files` entries are paths relative to their own skill directory, so
    `lib/payload.sh` alone cannot say whose it is. `report._skill_inventory` builds a FRESH
    per-skill Context and copies only the four content maps, so the gap recorded on the main
    ctx was structurally invisible to it — and the row for the skill whose payload directory
    had just been reported unreadable came out `NO KNOWN ISSUE / PASS`, in the same report
    that said B13 could not read it. Found by the independent adversarial pass; the row was
    *created* by making that skill collectable at all, so the false-clean claim moved out of
    B13 and into the inventory rather than disappearing.

    Keyed the same way `unreadable_manifests` is keyed (the skill DIRECTORY's name), so both
    bridges agree about who owns a file.
    """
    if ctx is None:
        return
    owner = skill_dir.name if skill_dir.is_dir() else skill_dir.parent.name
    ctx.skill_coverage_gaps.setdefault(owner, []).append(entry)


def _note_skill_traversal(ctx, skill_dir: Path, entry: str) -> None:
    """Attribute an archive path-traversal violation to the skill it belongs to.

    B-751, and the same shape as :func:`_note_skill_gap` directly above — which is the point.
    B-551 found that `report._skill_inventory` builds a FRESH per-skill Context copying only
    the content maps, so a signal recorded on the main ctx is structurally invisible to it. It
    fixed that for coverage gaps and nobody carried it to this signal, so the inventory row for
    a skill shipping a CONFIRMED zip-slip read `SUSPICIOUS - Insecure temp-file handling`: the
    cascade could not see the escape, so it fell through to the next arm.

    Keyed by the skill DIRECTORY's PATH, deliberately NOT by its name the way
    `_note_skill_gap` above keys its own map. That difference is the finding: colliding
    basenames are de-duplicated into `skills/<name>` / `<name>#2` before they reach
    `installed_skills`, so a name-keyed map joins to the wrong entry on any home carrying the
    same skill name under two load roots — and this map drives a CONVICTION, so a slipped
    join convicts an innocent skill rather than misplacing a note. `_note_skill_gap` has the
    same latent slip with a milder payload; filed separately rather than changed here.
    """
    if ctx is None:
        return
    owner = skill_dir if skill_dir.is_dir() else skill_dir.parent
    ctx.skill_traversal_violations.setdefault(str(owner), []).append(entry)


def _exists_but_not_regular(path: Path) -> bool:
    """True for a directory entry that is present but is not a regular file.

    Deliberately `lstat`, never `open`: a FIFO blocks forever on read with no writer, so the
    one thing this must not do is try to read the thing it is reporting. A vanished entry
    (the walk listed it, it is gone now) answers False — same errno discipline as the
    unreadable-directory branch: "gone" is not "hidden".
    """
    try:
        return not stat.S_ISREG(path.lstat().st_mode)
    except (OSError, ValueError):
        return False


def _cap_name(name: str) -> str:
    """Bound an attacker-controlled archive member name before it reaches evidence text."""
    if len(name) <= _UNTRUSTED_NAME_CAP:
        return name
    return name[:_UNTRUSTED_NAME_CAP] + "...(truncated)"


# ---------------------------------------------------------------------------------------
# W-DB2 round-3: DOMAIN-SCOPED limit hits.
#
# ``ctx.limit_hits`` was one undifferentiated bucket that ~50 unrelated collectors wrote
# into, while consumers asked it a question it could not answer: "was MY scan truncated?"
# B13 (installed-skill safety, HIGH + scored) treated ANY non-empty bucket as proof that
# the SKILL scan was incomplete, so a cap hit in a completely unrelated collector turned a
# genuine skill-scan PASS into a HIGH UNKNOWN whose detail text was simply false. Measured
# on a benign home (one clean skill, one benign daily cron job): 499 run-log rows -> B13
# PASS; 500 rows -> B13 UNKNOWN "Skill scanning was truncated ... coverage is incomplete",
# with the skill scan having completed in full both times.
#
# The fix is to tag each entry with the SCAN it truncated, so a consumer can filter to its
# own domain. ``LimitHit`` is a ``str`` subclass, so every existing consumer that treats
# the bucket as ``list[str]`` (substring tests, ``"; ".join(...)``, JSON/SARIF dumps,
# monitor's regex parse) keeps working byte-for-byte with no change.
LIMIT_DOMAIN_SKILL = "skill"          # installed-skill discovery/content scan  (B13)
LIMIT_DOMAIN_CRON = "cron"            # cron job store + execution trail        (B168/B189)
LIMIT_DOMAIN_PLUGIN = "plugin"        # installed-plugin trust index
LIMIT_DOMAIN_APPROVALS = "approvals"  # exec-approvals store
LIMIT_DOMAIN_ENV = "env"              # dotenv / systemd EnvironmentFile
LIMIT_DOMAIN_CONFIG = "config"        # openclaw.json itself
LIMIT_DOMAIN_BOOTSTRAP = "bootstrap"  # AGENTS.md / SOUL.md & friends
LIMIT_DOMAIN_AGENTS = "agents"        # subagent_runs disk-disclosure (B-296 / B18)
LIMIT_DOMAIN_AUDIT = "audit"          # audit_events runtime trail (F-134 / B191)

LIMIT_DOMAINS = (
    LIMIT_DOMAIN_SKILL,
    LIMIT_DOMAIN_CRON,
    LIMIT_DOMAIN_PLUGIN,
    LIMIT_DOMAIN_APPROVALS,
    LIMIT_DOMAIN_ENV,
    LIMIT_DOMAIN_CONFIG,
    LIMIT_DOMAIN_BOOTSTRAP,
    LIMIT_DOMAIN_AGENTS,
    LIMIT_DOMAIN_AUDIT,
)


class LimitHit(str):
    """A ``limit_hits`` entry that also remembers WHICH scan it truncated.

    Deliberately a ``str`` subclass, not a dataclass: the bucket has many consumers
    (report/SARIF/dossier/monitor and several tests) that treat it as ``list[str]``, and
    all of them must keep working unchanged. ``.domain`` is purely additive — a consumer
    that does not care never sees it, and one that does reads it via ``limit_hits_for``.

    (No ``__slots__``: CPython forbids a non-empty ``__slots__`` on a ``str`` subclass.)
    """

    domain: str

    def __new__(cls, message: str, domain: str) -> "LimitHit":
        obj = super().__new__(cls, message)
        obj.domain = domain
        return obj


def note_limit(sink, domain: str, message: str) -> None:
    """Append a DOMAIN-TAGGED limit-hit to *sink* (a ``ctx.limit_hits``-shaped list).

    Every ``limit_hits`` writer in the package goes through here; ``tests/
    test_limit_hit_domains.py`` fails the build if a bare ``limit_hits.append(...)``
    reappears, so an untagged writer cannot silently re-contaminate a consumer.
    """
    sink.append(LimitHit(message, domain))


def _note_unreadable_manifest(ctx, owner: str) -> None:
    """Record that *owner*'s own SKILL.md is present but not a regular file (B-654).

    The same five writes `collect_skill_files` already performed inline for this exact
    fact (a dangling symlink, a FIFO) once a directory had already been yielded and
    walked: the detail-bearing `unreadable_files` entry, the per-skill coverage gap, the
    file manifest, the absent-vs-unreadable bridge B13's `unreadable`/absent-manifest
    branches read (`unreadable_manifests`), and the domain-scoped limit hit. Extracted
    into one place so a second call site — `_iter_skill_dirs_guarded`, which sees this
    fact at DISCOVERY time, before a directory is ever added to `ctx.installed_skills` —
    cannot describe the same fact a different way. That drift is exactly how B-549
    attempt 3 went wrong one layer up (a `limit_hits`-only note landed on the generic
    truncation branch instead of the correct `unreadable` one).

    *rel* is always `f"{owner}/SKILL.md"`, never a bare "SKILL.md": at discovery time
    `owner` never enters `ctx.installed_skills` (the directory is neither yielded nor
    truncated — see `iter_discovered_skill_dirs`'s docstring), so an unprefixed name
    would point at nothing a reader could act on. `owner` is always a bare directory
    NAME, never a path (collector.py's own `Disclosure.subject` precedent) — these
    records reach SARIF and a report a user pastes into an issue.
    """
    if ctx is None:
        return
    rel = f"{owner}/SKILL.md"
    detail = f"{rel} (not a regular file — nothing to read at rest)"
    ctx.unreadable_files.append(detail)
    ctx.skill_coverage_gaps.setdefault(owner, []).append(detail)
    ctx.file_manifest.setdefault(rel, "not-a-regular-file")
    ctx.unreadable_manifests.add(owner)
    note_limit(
        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
        f"Could not read {_cap_name(rel)}: not a regular file",
    )


def limit_hits_for(ctx, *domains: str) -> list[str]:
    """The limit hits that truncated one of *domains* — i.e. "was MY scan truncated?".

    UNTAGGED entries are INCLUDED, deliberately. A plain ``str`` in the bucket carries no
    evidence about which scan it belongs to, and Golden Rule #4 says an unknown must not be
    resolved into a convenient answer: dropping it would turn "we cannot tell whether your
    scan was complete" into a clean PASS. Including it is the conservative direction (at
    worst an over-broad UNKNOWN, never a fake PASS), and it keeps hand-built test contexts
    that assign a plain ``list[str]`` behaving exactly as they did before.
    """
    wanted = set(domains)
    return [
        h for h in (getattr(ctx, "limit_hits", None) or [])
        if getattr(h, "domain", None) is None or getattr(h, "domain") in wanted
    ]


@dataclass(frozen=True)
class Disclosure:
    """One inert fact about how far THIS run reached. Never a verdict, never a gap.

    B-617. Three qualifiers were each computed honestly and each read by exactly one
    renderer, so the surfaces a human and a CI consumer actually read never saw them.
    This is the single channel they share.

    Deliberately NOT a ``str`` subclass, and that is the whole design. ``limit_hits`` is
    one (see ``LimitHit``) and it was a notepad until ``dossier.py`` read its truthiness
    into a verdict leg; a plain string can be ``"; ".join``-ed into a finding detail or
    truth-tested into a gate by any future edit, and ``_MODE_C_VERDICT`` turns any status
    it acquires into an install gate — the exact defect B-526 was filed to fix. A record
    that is not a string cannot be spliced into prose by accident, and
    ``tests/test_b617_disclosure_channel.py`` fails the build if anything outside the
    renderers reads ``ctx.disclosures`` at all.

    ``subject`` is a NAME, never a path. ``collector`` knows the absolute path and must
    not hand it on: an absolute path carries the username, the mount points and the
    directory layout, and these records reach SARIF and a report a user pastes into an
    issue. This follows ``report._credential_surface_rel``'s precedent — say WHAT was
    found, never WHERE on disk.
    """

    kind: str      # stable machine key, e.g. "workspace_outside_home"
    subject: str   # the thing this is about, as a bare name
    detail: str    # one plain-English sentence; no absolute path, ever


def note_disclosure(sink, kind: str, subject: str, detail: str) -> None:
    """Append a `Disclosure` to *sink* (a ``ctx.disclosures``-shaped list), de-duplicated.

    De-duplication is on the whole record: two agents can resolve to the same out-of-home
    workspace, and one fact stated twice reads as two findings.
    """
    if sink is None:
        return
    rec = Disclosure(kind=kind, subject=subject, detail=detail)
    if rec not in sink:
        sink.append(rec)


class _ScopedLimitSink:
    """A ``limit_hits``-shaped view that stamps a fixed domain on everything appended.

    ``skilldiscovery`` is a LEAF (it imports nothing from the package, by §3's dependency
    flow) so it cannot call ``note_limit`` itself. Rather than push the tag into the leaf
    or leave its one writer untagged, the collector hands it a pre-scoped sink. Only the
    operations that module and ``_config_workspace_dirs`` actually use are implemented —
    ``append`` and the ``in``/iterate/len trio — so a wrong assumption fails loudly instead
    of silently writing an untagged entry.
    """

    __slots__ = ("_backing", "_domain")

    def __init__(self, backing: list, domain: str) -> None:
        self._backing = backing
        self._domain = domain

    def append(self, message: str) -> None:
        note_limit(self._backing, self._domain, message)

    def __contains__(self, message: object) -> bool:
        return message in self._backing

    def __iter__(self):
        return iter(self._backing)

    def __len__(self) -> int:
        return len(self._backing)


# B-303: a non-traversable directory (most commonly the whole audited home, e.g. an
# operator's ``chmod 000 ~/.openclaw``) makes ANY bare ``is_dir()``/``is_file()``/
# ``is_symlink()`` on an entry beneath it raise an uncaught ``PermissionError`` — stat()
# needs execute/search permission on every ancestor directory, not just on the target
# itself. Several pre-checks in this module ran that stat before any try/except existed
# to catch it, so the ONE bad directory took the WHOLE audit down with a traceback
# instead of producing a report. These three helpers are the single place that absorbs
# that class of failure: a permission problem is reported exactly like "this path does
# not exist", which is not a new behaviour invented for this bug — every caller below
# already treats "not found" as the trigger for its own honest UNKNOWN (Golden Rule #4;
# e.g. ``ctx.cron_found`` / ``ctx.installed_skills`` / ``ctx.bootstrap`` staying empty is
# documented, in each collector, to degrade its consuming check to UNKNOWN rather than a
# fake PASS). Recording the OSError in ``ctx.errors`` (when a Context is available) keeps
# that degrade from being silent, matching how every other permission failure in this
# module is surfaced.
def _safe_is_dir(p: Path, ctx: Context | None = None, what: str | None = None,
                  domain: str | None = None) -> bool:
    """``Path.is_dir()`` that answers False instead of raising on a permission error.

    B-404: when *domain* is given (alongside *ctx*), a genuine OSError also
    becomes a domain-tagged ``limit_hits`` entry, not just a ``ctx.errors`` note — so a
    consumer asking "was MY scan complete?" (``limit_hits_for``) can see a root that could
    be confirmed to exist but could not be stat'd (e.g. a permission-denied skill root),
    distinct from a root that simply is not there (which stays silent, exactly as before).
    Purely additive: every existing caller that never passes *domain* keeps writing only
    to ``ctx.errors``, unchanged.
    """
    try:
        return p.is_dir()
    except OSError as exc:
        if ctx is not None:
            ctx.errors.append(f"could not check {what or p}: {exc}")
            if domain is not None:
                note_limit(
                    ctx.limit_hits, domain,
                    f"could not check {what or p} ({exc.__class__.__name__}) — not scanned",
                )
        return False


def _safe_is_file(p: Path, ctx: Context | None = None, what: str | None = None) -> bool:
    """``Path.is_file()`` sibling of ``_safe_is_dir`` — see its docstring (B-303)."""
    try:
        return p.is_file()
    except OSError as exc:
        if ctx is not None:
            ctx.errors.append(f"could not check {what or p}: {exc}")
        return False


def _safe_is_symlink(p: Path, ctx: Context | None = None, what: str | None = None) -> bool:
    """``Path.is_symlink()`` sibling of ``_safe_is_dir`` — see its docstring (B-303)."""
    try:
        return p.is_symlink()
    except OSError as exc:
        if ctx is not None:
            ctx.errors.append(f"could not check {what or p}: {exc}")
        return False


# F-087: padding-anomaly evasion signal. When a file is sliced by the text-scan cap,
# the discarded tail is sampled (bounded — never re-reads gigabytes) and measured for
# Shannon entropy. Low-entropy filler (a repeated byte, long whitespace/newline runs, a
# giant comment block) is the shape of deliberate cap-evasion padding (standard §2.5,
# "omnicogg"); a real high-entropy binary asset stays the honest UNKNOWN it is today.
_ENTROPY_SAMPLE_BYTES = 65_536      # sample at most 64 KiB of the cut tail
_ENTROPY_MIN_SAMPLE = 2_048         # below this, entropy is too noisy to judge
# bits/byte. Empirically calibrated (not guessed): a repeated short benign English
# line measures ~3.84, varied prose ~4.3, base64-of-random ~6.0 — but a single
# repeated byte measures 0.0 and a whitespace run ~1.0. 3.0 cleanly separates
# genuinely degenerate/uniform filler (the "omnicogg" padding shape) from any text
# with ordinary character variety, even repetitive documentation. Err toward
# honest-UNKNOWN on the boundary rather than widen and risk a false WARN.
_PADDING_ENTROPY_THRESHOLD = 3.0

def _shannon_entropy_bits(s: str) -> float:
    """Shannon entropy (bits per byte) over the UTF-8 byte histogram of *s*.

    Stdlib-only, single pass, bounded by the caller's sample slice — never call this
    on more than a small bounded sample of a large tail.
    """
    data = s.encode("utf-8", "replace")
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


@dataclass
class Context:
    home: Path
    config: dict = field(default_factory=dict)
    bootstrap: dict = field(default_factory=dict)   # filename -> text
    errors: list[str] = field(default_factory=list)
    config_mode: int | None = None                  # octal perms of openclaw.json, or None
    config_found: bool = False                       # openclaw.json present (vs non-OpenClaw setup)
    config_parse_error: bool = False                 # openclaw.json present but unparseable (B-166)
    # B-306 safe-symlink split: WHY config_parse_error is (or was) considered — the raw
    # loader message for a genuine-blind config, or a note that a dotfiles-style symlink
    # was safely followed. Distinguishes the two states config_parse_error conflates so a
    # readable-but-relocated config is never mistaken for a dark one. None when the config
    # parsed cleanly with no relocation.
    config_parse_reason: "str | None" = None
    # B-306 safe-symlink split: True when openclaw.json is a symlink whose target leaves
    # its config directory AND that target is a readable regular file owned by the auditing
    # user (a benign stow/chezmoi/yadm/bare-git dotfiles layout). The collector follows it
    # and audits the real bytes; this flag exempts the run from CONFIG_BLIND_CAP and drives
    # the report's "symlinks outside ~/.openclaw" note. NEVER set for corrupt/unreadable
    # bytes — those stay genuine-blind (config_parse_error True, cap intact).
    config_symlink_escapes_home: bool = False
    # B-281 (ENV-1): the config file this audit ACTUALLY read (or, when absent, the
    # canonical path it looked for). Every verdict in the report describes this file and
    # only this file, so it is reported verbatim rather than left implicit behind a bare
    # `config_found` bool. May be a legacy `clawdbot.json` — see resolve_config_in_home.
    config_path: "Path | None" = None
    # C-417: sha256 hex of the config file's bytes AS THIS AUDIT READ THEM, captured by
    # the loader on its own read rather than by a second one later. --monitor persists it
    # in the drift baseline, so it must describe the same bytes every other field in that
    # snapshot describes; a re-read at snapshot time would silently pair one file's digest
    # with another file's parsed values whenever anything wrote in between. None when the
    # config was absent or did not load. Covers the ROOT file only — see
    # configloader.load_openclaw_config's `root_digest`.
    config_sha256: "str | None" = None
    # B-282 (ENV-2/ENV-6): keys parsed from the two GLOBAL runtime dotenv files, with
    # first-wins precedence already applied. `dotenv_sources` maps key -> the file it came
    # from, for evidence. NEVER includes the workspace .env, whose OPENCLAW_* keys the
    # product provably discards (see _collect_global_dotenv).
    dotenv_values: dict = field(default_factory=dict)
    dotenv_sources: dict = field(default_factory=dict)
    dotenv_files: list = field(default_factory=list)  # global dotenv files found and read
    dotenv_found: bool = False                        # at least one global dotenv exists
    # B-289/B-290 (ENV-3/ENV-4): the environment the OpenClaw *service* actually runs
    # with, read off disk from OpenClaw-related systemd user units — `Environment=` lines
    # plus any file named by `EnvironmentFile=`. This is the artifact that matters: the
    # gateway runs under systemd with its OWN environment, so the auditing process's
    # os.environ describes a different process entirely (see env_evidence).
    # `unit_env_inline` maps each key that came from an INLINE `Environment=` line to the
    # unit file that inlined it — OpenClaw's own service audit treats an inline value
    # differently from an EnvironmentFile-sourced one (service-audit-bKq3tdW1.js:247).
    # It deliberately stores the unit path rather than the value: a caller that needs to
    # reason about an inlined secret must never be handed a second copy of it (§8).
    unit_env_values: dict = field(default_factory=dict)
    unit_env_sources: dict = field(default_factory=dict)
    unit_env_inline: dict = field(default_factory=dict)
    unit_env_files: list = field(default_factory=list)  # unit files found and read
    unit_env_found: bool = False       # at least one OpenClaw-related unit was read
    unit_env_unreadable: bool = False  # a candidate unit existed but could not be read
    native: object = None                           # NativeResult from openclaw security audit
    host: object = None                             # hostwatch.detect() result; set by audit(include_host=True)
    include_host: bool = False                      # host-filesystem scanning enabled (audit(include_host=True) / not --no-host)
    # F-156: sockets.scan_listening_sockets() result; set by audit(include_sockets=True).
    # None (the hermetic default) means the runtime socket scan was not run at all —
    # check_effective_bind reports UNKNOWN, exactly like ctx.host is None for B50-B54.
    sockets: object = None
    include_sockets: bool = False  # /proc/net/tcp{,6} listening-socket scan enabled
    # F-164: --exhaustive widens the DoS/ReDoS-guard ceilings scanbudget.limits_for()
    # hands back (traj/log scan caps, per-check/audit wall-clock budgets) instead of
    # today's defaults. No behavior of its own here — same pattern as include_sockets
    # above — just a flag other code (scanbudget.limits_for, run_all callers) can read.
    exhaustive: bool = False
    # C-135 bug 1: the proc_root audit() was called with (default "/proc"), carried on ctx
    # so check_effective_bind's best-effort PID correlation (sockets.identify_listener_process)
    # reads from the SAME root a test injected for the socket scan itself, rather than a
    # second, independent "/proc" hardcode. Always set by audit(), not just when
    # include_sockets=True, so it is available whenever ctx.sockets happens to be populated.
    proc_root: str = "/proc"
    # F-167: deptree.scan_dep_tree() result for the OpenClaw install; set by
    # audit(include_deptree=True), exactly as `sockets` above is set by
    # include_sockets. B349 READS this and never walks the filesystem itself --
    # hermetic-by-default, and one walk per audit rather than one per check call.
    # (Without this, B349's PATH discovery ran on every Context: measured at 2.4s,
    # 102% of a whole audit's runtime, and it reached into the real machine's global
    # npm install from tests that had built a Context over a fixture home.)
    dep_tree: object = None
    include_deptree: bool = False  # OpenClaw dependency-tree walk enabled
    # Root override for that walk. None means "discover it from PATH"
    # (deptree.find_package_root); tests and fixtures set a synthetic tree, exactly as
    # proc_root lets a test drive B340 without a real /proc.
    openclaw_pkg_root: "Path | None" = None
    # B-502: the INSTALLED OpenClaw package's own version string (openclawdist, via
    # deptree.find_package_root("openclaw")); set by audit(include_dist=True), exactly as
    # `dep_tree` above is set by include_deptree. None is the hermetic default AND covers
    # "the lookup ran but PATH did not resolve openclaw" -- check_version (C4) cannot tell
    # those two apart from this field alone, and by design does not need to: both fall
    # back to the SAME presence-only verdict C4 has always produced, so a Context built
    # without opting in (every pre-existing test, and the fixture-corpus fingerprint
    # manifest) stays byte-identical. Only a REAL version string here unlocks the
    # rollback-direction comparison against `meta.lastTouchedVersion`.
    installed_dist_version: "str | None" = None
    include_dist: bool = False  # installed OpenClaw package version lookup enabled
    # B-231 sub-item 1: normalized cron jobs (from ~/.openclaw/cron/jobs.json, or the
    # SQLite-backed cron_jobs table when the JSON file is absent). Each entry is a plain
    # dict: id, name, enabled, delete_after_run, trigger_script, payload_kind,
    # payload_message — the same shape regardless of which backing store it came from,
    # and (B-709) regardless of which of the two observed cron_jobs COLUMN shapes the
    # SQLite table itself has (see _collect_cron's docstring).
    cron_jobs: list = field(default_factory=list)
    cron_found: bool = False        # a cron store (JSON or SQLite) was found and read
    cron_parse_error: bool = False  # a cron store was found but could not be parsed/read
    # B-294 (DISK-3): a cron store was found and read successfully but yielded ZERO job
    # definitions. Distinct from `not cron_found` (no store at all) and from a populated
    # store. Before this flag existed, an EMPTY cron_jobs table was indistinguishable from
    # a CLEAN one, so B168 emitted PASS with pass_confidence="verified" over a store it had
    # never actually seen a single row of.
    cron_store_empty: bool = False
    # B-294 follow-up: the job-definition set that was read is INCOMPLETE, so "this job id
    # has no definition" cannot be concluded from it. Two distinct causes, both silent
    # before these flags existed:
    #   cron_jobs_truncated  — the read hit the _MAX_CRON_JOBS row cap, so definitions past
    #                          the cap were never seen. The SQLite branch has no ORDER BY,
    #                          so which jobs get dropped is storage order, not recency,
    #                          while the run-log read takes the MOST RECENT rows — the two
    #                          sets are sampled on different axes and cannot be differenced.
    #   cron_store_shadowed  — a legacy ~/.openclaw/cron/jobs.json exists and was used as
    #                          the definition source, but the SQLite cron_jobs table also
    #                          holds rows. In the shipped dist that file is only a store-key
    #                          identity (loadCronJobsStoreWithConfigJobs ->
    #                          cronStoreKey(path.resolve(storePath)), store-ScQ9SjOe.js:710)
    #                          and the rows themselves live in SQLite (replaceCronRows,
    #                          store-ScQ9SjOe.js:647). Nothing in the dist ever unlinks
    #                          jobs.json, so an upgraded install keeps a stale one forever
    #                          and reading it yields definitions the runtime does not use.
    #                          Counted PER PARTITION (store_key), matching the runtime's own
    #                          WHERE store_key = ? (store-ScQ9SjOe.js:643-645): rows filed
    #                          under a DIFFERENT cron.store are not a shadow of this file.
    cron_jobs_truncated: bool = False

    # F-183: the machine-owned config store (`config_machine_state` in the state DB).
    # `_read` False means the store could not be consulted at all -- UNDETERMINED. An
    # empty dict with `_read` True means it WAS consulted and none of the allowlisted
    # keys is set, which is a different and much stronger statement.
    config_machine_state: dict = field(default_factory=dict)
    config_machine_state_read: bool = False
    config_machine_state_unparsed: set = field(default_factory=set)
    cron_store_shadowed: bool = False
    # B-294: the cron EXECUTION trail (cron_run_logs in ~/.openclaw/state/openclaw.sqlite,
    # OR (B-709) its task_runs successor on a database that has run the migration -- see
    # _collect_cron_run_logs's docstring, and note it selects on the OBSERVED TABLES, not
    # on an OpenClaw version: the state DB's migration ladder does not map onto the product
    # version, which is why neither this comment nor the code names one), which deliberately
    # OUTLIVES the job definition —
    # one-shot (`kind:"at"`) jobs default to deleteAfterRun TRUE, the legacy table has no
    # foreign key to cron_jobs, and the only cron_jobs delete in the dist (replaceCronRows)
    # never touches it. Each entry is a plain dict: job_id, status, session_id, session_key,
    # run_id, run_at_ms, ts -- the SAME keys regardless of which backing table it came from
    # (session_id is always None on the task_runs path; it has no successor column there).
    # NOTE: the run record carries no copy of the job's original payload.message, so this is
    # a PIVOT (what ran, when, under which session) — never the erased job's content.
    cron_run_logs: list = field(default_factory=list)
    cron_run_logs_found: bool = False        # the cron_run_logs table was present and read
    cron_run_logs_parse_error: bool = False  # table present but could not be read
    # B-295 (DISK-4): debug-proxy traffic-capture METADATA from the same state DB. Row
    # COUNTS only -- capture_events.headers_json holds bearer tokens and .data_text holds
    # request bodies, so no captured content is ever read (§8). See _collect_capture_state.
    capture_tables_found: bool = False       # capture_events table present and counted
    capture_parse_error: bool = False        # present but could not be read
    capture_event_rows: int = 0              # captured request/response flows on disk
    capture_blob_rows: int = 0               # captured bodies on disk
    # B-236 (B172): standing exec-approvals.json grants, one dict per agent present in
    # the store's `agents` map: {agent_id, security, ask, allow_always_count}. Populated
    # regardless of whether allow_always_count is 0 -- the consuming check filters.
    exec_approvals_grants: list = field(default_factory=list)
    exec_approvals_found: bool = False        # exec-approvals.json present and read
    exec_approvals_parse_error: bool = False  # present but could not be parsed/read
    # B-240 (B177): OpenClaw's OWN persisted per-plugin ClawHub trust verdict, read from
    # the installed_plugin_index.install_records_json column in the shared state SQLite DB
    # (~/.openclaw/state/openclaw.sqlite) -- OR, since OpenClaw's state-consolidation-v13
    # migration (2026.8.2+), the successor row config_machine_state.value_json where
    # state_key = 'plugins.installedIndex' (index.installRecords, keyed by pluginId), which
    # _collect_plugin_trust prefers when present and usable. See that function's docstring
    # for the dual-shape selection rule. Each entry: {plugin_id, disposition, scan_status,
    # moderation_state, reasons (list[str]), pending, stale} — disposition is one of
    # "clean" | "review-recommended" | "review-required" | "blocked" | None (no verdict
    # persisted for that install yet). Same dict shape regardless of which sink it came from.
    plugin_trust_records: list = field(default_factory=list)
    plugin_trust_found: bool = False        # a usable trust-index row was found and read
    plugin_trust_parse_error: bool = False  # present but could not be read/parsed (locked/corrupt)
    # B-292 (RT-2): the SIBLING plugins_json column -- installed_plugin_index.plugins_json,
    # or (2026.8.2+) config_machine_state['plugins.installedIndex'].index.plugins, read over
    # the exact same connection and the exact same row/state-key as plugin_trust_records
    # above; see _collect_plugin_trust's docstring for the selection rule. Each entry is one
    # installed plugin's full index record: {plugin_id, origin ("bundled" | "global" | ... --
    # OpenClaw's own provenance tag, NOT a trust verdict), enabled, manifest_path, root_dir,
    # source, contracts (dict: OpenClaw plugin-contract name -> list[str] of registered ids
    # under that contract, e.g. {"agentToolResultMiddleware": [...]})}. This is an INVENTORY
    # OF NAMES, never a behavior spec -- see checks/_mcp.py::check_plugin_tool_result_middleware
    # for the full grounding, the mass-false-positive trap (67 of 69 plugins on a stock
    # install are origin="bundled"), and the two attack narratives this column explicitly
    # CANNOT support (custom baseURL, command-alias hijack target). Same dict shape
    # regardless of which sink it came from.
    plugin_index_records: list = field(default_factory=list)
    plugin_index_found: bool = False        # a usable plugin-index row was found and read
    plugin_index_parse_error: bool = False  # present but could not be read/parsed (locked/corrupt)
    # B-296 (DISK-5 increment 1): rows from the subagent-spawn registry (``subagent_runs`` in
    # the shared state SQLite DB), most-recent first. Each entry is a plain dict:
    # child_session_key, model, agent_dir, workspace_dir, spawn_mode, run_timeout_seconds,
    # task (capped, see _MAX_SUBAGENT_TASK_CHARS), outcome (parsed outcome_json dict, or None
    # when the run has not ended / no outcome was recorded yet), ended_reason, created_at.
    # B-709: on the MODERN (OpenClaw 2026.8.2+) table shape, agent_dir/workspace_dir/
    # spawn_mode/task are permanently None -- that schema does not carry them at all (see
    # _collect_subagent_runs's docstring). A one-time LIMIT_DOMAIN_AGENTS disclosure names
    # this per collection run; a consumer must not read the None as "no workspace recorded".
    # DISCLOSURE ONLY — see checks/_agents.py::_disk_subagent_disclosure for the consumer;
    # there is deliberately no FAIL-capable predicate anywhere over this data (CLAUDE.md GR#5,
    # the task's own out-of-tree-workspace_dir / model-fallback traps).
    subagent_runs: list = field(default_factory=list)
    subagent_runs_found: bool = False        # state DB + subagent_runs table present and read
    subagent_runs_parse_error: bool = False  # present but no row could be reliably parsed
    # F-134 (DISK-1, B191): rows from OpenClaw's OWN runtime audit trail (``audit_events`` in
    # the shared state SQLite DB), most-recent first. Each entry is a plain dict: kind,
    # action, status, error_code, actor_type, actor_id, agent_id, session_key, session_id,
    # run_id, tool_call_id, tool_name, occurred_at. GR#5: the table stores ONLY those
    # columns — no argv, no command string, no file path, no target host — so this is a
    # metadata-only observability source, never content evidence. See checks/_host.py::
    # check_audit_trail_signals (B191) for the consumer.
    audit_events: list = field(default_factory=list)
    audit_events_found: bool = False        # state DB + audit_events table present and read
    audit_events_parse_error: bool = False  # present but could not be read
    audit_events_truncated: bool = False     # the row-sample read hit the _MAX_AUDIT_EVENTS cap
    # Coverage stats over the FULL table (COUNT(*)/MIN/MAX(occurred_at)), independent of the
    # row-sample cap above — "how far back does this reach" must not be limited by how many
    # rows the signal-detection sample happened to keep.
    audit_events_total_rows: int = 0
    audit_events_oldest_ms: int | None = None
    audit_events_newest_ms: int | None = None
    installed_skills: dict = field(default_factory=dict)  # skill name -> concatenated text
    installed_skill_py: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for AST
    installed_skill_shell: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for .sh/.bash
    installed_skill_js: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for .js/.ts
    # skill name -> that skill's own resolved directory (the dir containing its SKILL.md).
    # F-131: lets a per-skill Context be scoped to JUST that skill (mirrors vet_skill's
    # Context(home=<skill dir>)) instead of the whole OpenClaw home, so home-wide-walking
    # ring checks (B42 install-policy, B87 symlink-escape) don't cross-attribute another
    # skill's evidence onto this one.
    installed_skill_dirs: dict = field(default_factory=dict)
    # B-404: every skill-load root _read_installed_skills actually confirmed
    # exists and walked — the hardcoded SKILL_DIRS entries, any config-declared workspace/
    # extraDirs/plugins.load.paths root, the personal ~/.agents/skills tier, a bundled-root
    # env override, and plugin-skills — resolved-path deduped in the same order the walk
    # used. This is the single source of truth for "was there anywhere to look"; cli.py's
    # sweep_installed_skills reads it instead of re-deriving its own, narrower root list
    # (the bug this field exists to close: a second, flat iterdir()-only guess over just
    # the static SKILL_DIRS silently missed every grouped/config-declared root and then
    # still reported the sweep complete).
    installed_skill_roots: list = field(default_factory=list)
    # B-507: names excluded from installed_skills because _is_own_source() content-
    # verified them as ClawSecCheck's own install (B-265) -- a tool must not grade its
    # own package, but the exclusion used to be completely silent, so "Skills (N
    # installed)" undercounted by exactly this many with no trace anywhere in the
    # output. report.py discloses this list instead of a silently shrunk count.
    self_excluded_skills: list = field(default_factory=list)
    # B-507: names discovered via the `plugin-skills` symlink root specifically (see the
    # B-161 comment in _read_installed_skills) -- that root is DELIBERATELY made of
    # symlinks into a plugin's own bundled skills/ dir (e.g. an OpenClaw core
    # extension's skill living inside OpenClaw's own npm package), not something the
    # user separately installed or can remove independently of the plugin. report.py
    # labels these "bundled" rather than folding them into a plain "(N installed)" count
    # that implies the user chose each one.
    installed_skill_bundled: set = field(default_factory=set)
    attestation: dict = field(default_factory=dict)  # agent self-report (--attest); see attest.py
    _collected_skill_files: dict[str, list[dict]] = field(default_factory=dict)

    # F-018: per-skill aggregated effect profiles from the abstract effect simulator.
    # Populated by check_installed_skills; keyed by skill name.
    # Each value is a list of entry-point result dicts (see skillast.simulate_effects).
    effect_profiles: dict = field(default_factory=dict)

    # Integrity & analysis metadata blocks
    limit_hits: list[str] = field(default_factory=list)
    # B-617: inert run-level disclosures (see `Disclosure`). Read ONLY by the
    # renderers; never by a check, never by scoring. Kept beside limit_hits because
    # they are neighbours in meaning and opposites in weight.
    disclosures: list = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)
    polyglots: list[str] = field(default_factory=list)
    binary_files: list[str] = field(default_factory=list)
    stowaway_files: list[str] = field(default_factory=list)  # F-054: native executables bundled in a skill
    total_files_inspected: int = 0
    excluded_binary_files_count: int = 0
    archives_unpacked: int = 0
    path_traversal_violations: list[str] = field(default_factory=list)
    #: B-751: the same list, keyed by the owning skill DIRECTORY's path (``str(Path)``).
    #: The flat list above holds `<path relative to the skill dir>::<member>`, so two
    #: skills that each ship a `bundle.zip` produce identical strings and neither can be
    #: attributed. Exactly the B-551 problem one signal over.
    #:
    #: Keyed by PATH and not by the directory's NAME, which is how `_note_skill_gap` keys
    #: its own map and was how this started. That is wrong here and its own C-135 caught
    #: it: `installed_skills` de-duplicates colliding basenames into `skills/archive-demo`,
    #: `...#2` and so on (see the key computation below), so on a home with the same skill
    #: name under two load roots the name-keyed map lined up with the WRONG entry —
    #: measured, it convicted a skill shipping nothing but a SKILL.md as DANGEROUS while
    #: the one that really shipped the zip-slip rendered the old temp-file WARN. A path is
    #: unique by construction, so the join cannot slip.
    skill_traversal_violations: dict[str, list[str]] = field(default_factory=dict)
    file_manifest: dict[str, str] = field(default_factory=dict)  # file relpath -> status
    # B-616: relpaths whose text came from one of the decode ladder's ASSUMED rungs
    # (`latin-1`, or — B-537 — a guessed legacy multi-byte codec such as `shift_jis`;
    # see `_decode_ladder`) rather than a self-identifying encoding (utf-8, BOM/shape-
    # confirmed utf-16). `file_manifest`'s "(<codec>-assumed)" qualifier records the same
    # fact per file but had exactly one reader (sarif.py); this is the ctx-level signal
    # dossier.py reads to keep a prose-dependent axis from reading PASS over text nobody
    # actually understood. Never the `(lossy)` (None-encoding) rung — that one keeps a
    # UTF-8 reading and pays only per bad character, which is a different, much weaker
    # claim.
    assumed_encoding_files: list[str] = field(default_factory=list)
    symlink_skips: list[str] = field(default_factory=list)        # F-061: skipped symlinks / path-escapes
    # B-458: files that are PRESENT in the skill but could not be opened (permissions,
    # a dangling target, an I/O error). Distinct from every cap channel: nothing was
    # truncated and no limit was reached — the file was simply never read, so its
    # content is unknown rather than partially known. Kept separate from limit_hits'
    # generic "truncated / split oversized files" remediation, which would be false
    # advice here (mirrors how padding_anomalies earns its own narrower channel).
    unreadable_files: list[str] = field(default_factory=list)
    # B-551: the same facts, attributed to the skill they belong to. `unreadable_files`
    # entries are paths relative to their own skill directory, so `lib/payload.sh` alone
    # cannot say whose it is — which is why `report._skill_inventory`, building a fresh
    # per-skill Context, could not carry the coverage gap and stamped `NO KNOWN ISSUE` on
    # the very skill whose payload directory the same report said it never read. Keyed by
    # skill name so a per-skill consumer can take exactly its own.
    skill_coverage_gaps: dict = field(default_factory=dict)
    # B-461: skill names whose SKILL.md itself could not be read. Without this, B88 sees an
    # empty text blob and reports the manifest as ABSENT ("no SKILL.md frontmatter block
    # found — this skill will not appear to the agent"), which is a false statement about a
    # file that is present and well-formed and merely unopenable.
    unreadable_manifests: set = field(default_factory=set)
    filename_obfuscations: list[str] = field(default_factory=list)  # F-061: homoglyph/RTL/zero-width filenames
    # F-087: skill names whose text-scan was truncated by a LOW-ENTROPY cut tail — the
    # shape of deliberate cap-evasion padding, distinct from limit_hits (which fires on
    # ANY cap — archive/py/text — including a genuine high-entropy oversized asset).
    padding_anomalies: list[str] = field(default_factory=list)

    # B-268: the _MAX_SKILLS truncation frontier. `installed_skills` is a capped VIEW of
    # the filesystem, and a consumer that diffs it against a previous view (monitor.py) or
    # prints its length as an inventory total (report.py) was reading that view as ground
    # truth. These three fields make the partiality explicit and machine-readable:
    #   skills_capped_names — directory names DISCOVERED but not read because the cap was
    #     already full. Bounded by _MAX_SKILL_FRONTIER_NAMES so a 100k-skill flood cannot
    #     turn the frontier itself into an unbounded allocation.
    #   skills_capped_count — the true number skipped, exact even when the name list above
    #     was itself truncated.
    #   skills_frontier_partial — True when skills_capped_names is incomplete, i.e. a
    #     consumer may NOT use "absent from the name list" to conclude "absent from disk".
    skills_capped_names: list[str] = field(default_factory=list)
    skills_capped_count: int = 0
    skills_frontier_partial: bool = False

    # C-289 (A1): per-scan memo for `trajaudit.analyze(ctx)` — five call sites
    # (`scoring.compute` x3 via `project`, `audit()` itself, both reading through
    # `grade_cap_signal`) do the exact same trajectory-sidecar I/O against the exact
    # same, unmutated `ctx` within one audit run. Deliberately last: has a default, so
    # no positional `Context(...)` constructor call anywhere in the package/tests shifts
    # position; `repr=False`/`compare=False` keep `__repr__`/`__eq__` byte-identical to
    # before this field existed. Not a `functools.lru_cache`/`WeakKeyDictionary` on
    # `analyze` itself: `Context` is an unfrozen, `eq=True` dataclass, so
    # `__hash__ is None` and both would raise `TypeError`. `trajaudit.analyze` reads this
    # via `getattr(ctx, "_trajaudit_cache", None)` and skips caching entirely when it is
    # absent, so a duck-typed stub `ctx` in a test keeps working unchanged. A fresh
    # `Context` (e.g. report.py's per-skill blast-radius re-scan) always gets a fresh,
    # empty dict — nothing here can leak a cached result across two different `Context`
    # objects.
    _trajaudit_cache: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def bootstrap_blob(self) -> str:
        return "\n".join(self.bootstrap.values())


def _read_with_limit(file_obj: io.BufferedIOBase, byte_limit: int) -> tuple[bytes, bool]:
    """Read up to ``byte_limit`` bytes from ``file_obj`` without over-allocation."""
    if byte_limit < 0:
        raise ValueError("byte_limit must be >= 0")

    out = bytearray()
    while True:
        chunk = file_obj.read(byte_limit + 1 - len(out))
        if not chunk:
            return bytes(out), False
        out.extend(chunk)
        if len(out) > byte_limit:
            return bytes(out[:byte_limit]), True


def _pyc_fmt(data: bytes) -> str | None:
    r"""Name a would-be-binary file 'pyc' when it carries the CPython bytecode magic
    (``<version-low-byte>\r\r\n`` — bytes 1..3 are ``\x0d\x0d\x0a`` for every 3.x release,
    since the 16-bit magic's high byte is 0x0d). F-116: consulted ONLY on the binary return
    paths, so a benign text file that merely starts with ``#\r\r\n`` (which stays high-
    printable-ratio TEXT) is never misnamed pyc."""
    return "pyc" if len(data) >= 4 and data[1:4] == b"\x0d\x0d\x0a" else None


# How many leading bytes classify_bytes samples when deciding text vs binary. Named
# because B-533 turns on the fact that this is a fixed offset with no regard for
# character boundaries — see the decode comment there.
_TEXT_SAMPLE_BYTES = 4096


def _looks_like_utf16(chunk: bytes) -> bool:
    """Do these bytes plausibly *are* UTF-16, rather than merely decode as it?

    B-533: a UTF-16 decode raises only on an unpaired surrogate, so almost any byte
    string "decodes" — which made a non-raising decode worthless as evidence and let
    mojibake win over a correct UTF-8 reading. Two positive signals instead: a byte-order
    mark, or the interleaved-NUL shape ASCII-range text has in UTF-16 (every other byte
    zero). Text outside the ASCII range without a BOM is not claimed here; it decodes as
    UTF-8 or it is binary.
    """
    if chunk[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    head = chunk[:512]
    if len(head) < 4:
        return False
    even_nul = sum(1 for b in head[0::2] if b == 0)
    odd_nul = sum(1 for b in head[1::2] if b == 0)
    half = len(head) // 2
    if half == 0:
        return False
    # One side essentially all NUL and the other essentially none: the UTF-16 shape.
    return (odd_nul / half >= 0.9 and even_nul / half <= 0.1) or \
           (even_nul / half >= 0.9 and odd_nul / half <= 0.1)


# Above this share of a file's non-ASCII bytes failing UTF-8, the file is a legacy
# codepage rather than a UTF-8 document carrying damage. Measured (see
# `_is_predominantly_utf8`) the two populations do not overlap anywhere near this value:
# genuine cp1251/cp1252/latin-1 prose scores 1.0000, and UTF-8 with stray bytes in it
# scores <= 0.0079. The threshold sits in the empty space between them, not on a tail.
_LEGACY_DAMAGE_RATIO = 0.5


# Share of non-control characters a decoded sample must clear to be judged text rather
# than binary. Shared by `classify_bytes` and `_try_structured_multibyte` so the
# classifier's verdict and the ladder's rung acceptance are the same decision, not two
# thresholds that can drift apart.
_PRINTABLE_RATIO_THRESHOLD = 0.85


def _printable_ratio(decoded: str) -> float:
    """Share of `decoded` that is not a Unicode control/format/surrogate/private/
    unassigned character (categories Cc, Cf, Cs, Co, Cn) — the same gate
    `classify_bytes` applies to its whole-sample decode, factored out so
    `_try_structured_multibyte` (B-537) can apply it per-candidate before a rung is
    trusted. An empty string has nothing to be binary about, so it scores 1.0."""
    if not decoded:
        return 1.0
    printable = 0
    for char in decoded:
        if char in ("\t", "\n", "\r"):
            printable += 1
        else:
            if unicodedata.category(char) not in ("Cc", "Cf", "Cs", "Co", "Cn"):
                printable += 1
    return printable / len(decoded)


# B-537: shift-jis/cp932 Japanese (and, incidentally, other CJK legacy multi-byte
# codepages) reintroduced the exact defect B-533 fixed for UTF-8 CJK. Root cause: shift-jis
# lead bytes occupy 0x81-0x9F, which is precisely latin-1's C1 control block (Unicode
# category Cc) — decoding a shift-jis document as latin-1 (the single-byte rung below)
# therefore scores roughly half its characters Cc, well under `_PRINTABLE_RATIO_THRESHOLD`,
# and the file classifies BINARY and drops out of content scanning entirely. Every other
# legacy CJK encoding this ladder already read correctly (big5, gb2312, euc_kr,
# iso2022_jp) escapes only because ITS lead bytes happen to sit above 0xA0 and so score
# high under latin-1 by the same accident the UTF-16 fallback relied on before B-533 — not
# because the ladder recognised the encoding.
#
# These are the codecs Python's stdlib ships incremental decoders for that can plausibly
# carry a legacy CJK document; tried in this order because shift_jis/cp932 are the
# regression this bug is about and a wrong-but-structurally-valid match earlier in the
# list (e.g. cp932 reading euc_jp bytes as half-width-katakana mojibake) still lands on
# TEXT, which is the only thing `classify_bytes` needs from this rung — the specific
# label is best-effort disclosure, not a claim of correctness (same status as the
# existing `latin-1` rung's guess).
_LEGACY_MULTIBYTE_CODECS = ("shift_jis", "cp932", "euc_jp", "big5", "gb18030", "euc_kr")

# Below this many bytes, a structural "the codec did not raise" decode is not enough
# evidence: gb18030 in particular is a near-total mapping (built to cover almost all of
# Unicode), so a short run of random bytes has a real chance of both decoding cleanly
# AND scoring above the printable gate by chance alone -- a risk latin-1 (which never
# raises regardless of length) does not add, but a validating codec inherits if its
# valid-sequence space is wide enough. Measured (Monte Carlo, NUL-free uniform random
# bytes, 20,000 trials per length): below 128 bytes this rung newly admits blobs latin-1
# alone would have correctly rejected as BINARY (0.24% at 64 bytes, mostly via gb18030);
# at 128 bytes and above, across 20,000 trials each up to 8192 bytes, it adds ZERO cases
# latin-1 did not already accept. This floor sits with a wide margin above that boundary,
# not on it, and below the size of any realistic prose file this rung exists to recover.
_MULTIBYTE_MIN_SAMPLE_BYTES = 256


def _try_structured_multibyte(data: bytes) -> "tuple[str, str] | None":
    """The first `_LEGACY_MULTIBYTE_CODECS` candidate that both decodes `data` without
    raising and scores >= `_PRINTABLE_RATIO_THRESHOLD`, or None if no candidate clears
    both bars.

    Unlike the latin-1 rung below (which never raises and so is not itself evidence of
    anything), a structured multi-byte codec's byte-sequence rules CAN reject — lead and
    trail bytes must pair up correctly — so "it decoded" is real, if imperfect, positive
    evidence the bytes are that encoding's shape. That is why this rung is tried BEFORE
    latin-1: latin-1 would otherwise always accept first and this rung would never run.

    Only called from the NUL-free branch of `_decode_ladder`, on data already found not
    to be predominantly UTF-8 — i.e. exactly the population that would otherwise fall to
    the unconditional latin-1 guess.
    """
    if len(data) < _MULTIBYTE_MIN_SAMPLE_BYTES:
        return None
    for name in _LEGACY_MULTIBYTE_CODECS:
        try:
            decoded = codecs.getincrementaldecoder(name)().decode(data, False)
        except UnicodeDecodeError:
            continue
        if _printable_ratio(decoded) >= _PRINTABLE_RATIO_THRESHOLD:
            return decoded, name
    return None


def _is_predominantly_utf8(data: bytes) -> bool:
    """Is this a UTF-8 document with a few bad bytes, or is it a legacy single-byte file?

    Asked only once whole-file UTF-8 has already failed and the UTF-16 rungs have been
    ruled out — i.e. exactly when the ladder is about to assume a codepage.

    B-538 (repair): the latin-1 rung is all-or-nothing, so before this gate ONE invalid
    byte anywhere in a NUL-free file demoted the WHOLE file to a latin-1 re-read. That
    turned a per-character cost into a per-file one and handed an attacker a silencer:
    appending ``\\xff`` to a Russian SKILL.md re-read all of it as mojibake, so B64
    (multilingual prompt injection) and every other non-ASCII-keyed check went quiet
    while `file_manifest` still reported the file as scanned. Measured on the
    reproduction: 1,470 correctly-decoded Cyrillic characters -> 0, ring findings
    ``B156 B64`` -> ``B13``.

    Two independent reasons to keep reading the file as UTF-8; either one is enough:

    (a) **The sample says so.** If the leading `_TEXT_SAMPLE_BYTES` decode as UTF-8, the
        file is a UTF-8 file by the same evidence `classify_bytes` uses to call it TEXT
        at all. Judging the whole file by a byte outside that sample lets the classifier
        and the readers disagree about what the file is, which is the B-538 defect.
    (b) **The damage is not at scale.** The sample is a fixed prefix, so a byte planted
        at offset 200 defeats (a) as easily as one appended at the end — (a) alone would
        have moved the attack, not stopped it. So also ask what share of the non-ASCII
        bytes UTF-8 actually fails on. In a legacy codepage essentially every non-ASCII
        byte is invalid UTF-8 (ratio 1.0); in a UTF-8 document they overwhelmingly form
        valid sequences and only the planted bytes fail (ratio ~0.0004). The ratio, not
        the count, is what separates them: 20 stray bytes in a UTF-8 file still score
        0.0079, while a single stray byte is not evidence of a codepage either.

    A file with no non-ASCII bytes at all returns False: there are no characters for the
    latin-1 rung to get wrong, so the byte-preserving read is the better one and this
    gate has nothing to protect.

    B-546 (superseded as `_decode_ladder`'s gate, kept as a function): both terms of the
    ratio above are counted over the WHOLE file, and every invalid byte an attacker adds
    ANYWHERE increments both -- so padding walks the ratio across the threshold
    regardless of where the real payload sits. Measured: 2 appended bytes flipped a
    homoglyph document's rung and 2,941 appended bytes did the same to a 1,470-character
    Cyrillic body, in both cases destroying the very non-ASCII characters this rung
    exists to protect. `_decode_ladder` now calls `_decode_ladder_regions` instead,
    which asks the same question per CONTIGUOUS REGION so a padding-inflated region
    elsewhere cannot vote on how a different region is read. This function is left
    exactly as it was -- it is still correct on the question it actually answers ("is
    the WHOLE file predominantly UTF-8"), and it stays directly exercised by
    `test_is_predominantly_utf8_separates_the_two_populations`
    (tests/test_b538_reader_decode_ladder.py, a different task's file).
    """
    try:
        codecs.getincrementaldecoder("utf-8")().decode(data[:_TEXT_SAMPLE_BYTES], False)
        return True
    except UnicodeDecodeError:
        pass
    non_ascii = len(data.translate(None, bytes(range(128))))
    if not non_ascii:
        return False
    damaged = data.decode("utf-8", errors="replace").count("�")
    return damaged / non_ascii < _LEGACY_DAMAGE_RATIO


# B-546: match string for `_utf8_byte_regions` -- a maximal run of the low-surrogate
# code points `errors="surrogateescape"` substitutes for a byte strict UTF-8 rejects.
_SURROGATE_ESCAPE_RE = re.compile("[\udc80-\udcff]+")


def _utf8_byte_regions(data: bytes) -> "list[tuple[bool, int, int]]":
    """Split `data` into ordered ``(is_valid_utf8, start, end)`` byte spans.

    Found in ONE linear pass rather than by repeatedly re-decoding the remaining tail on
    each `UnicodeDecodeError` (which is worst-case O(n^2) on a file with many scattered
    bad bytes -- exactly the shape an attacker controls, and exactly the kind of hang
    `scanbudget.py` exists to catch rather than rely on here). `errors="surrogateescape"`
    (PEP 383) maps each byte the strict decoder would reject to one low-surrogate code
    point (U+DC80-U+DCFF) and never raises, so the whole file decodes natively in a
    single pass; a maximal run of those surrogate code points in the output marks
    exactly the bytes strict UTF-8 would have rejected -- one escaped code point per
    rejected byte, finer-grained than but consistent with the "one U+FFFD per maximal
    ill-formed subsequence" `errors="replace"` uses elsewhere in this ladder. Every
    non-surrogate run round-trips through a plain `.encode("utf-8")`, which is how the
    byte offsets below are recovered without a second decode pass over the same bytes.
    """
    if not data:
        return []
    decoded = data.decode("utf-8", errors="surrogateescape")
    regions: "list[tuple[bool, int, int]]" = []
    pos = 0
    byte_pos = 0
    for m in _SURROGATE_ESCAPE_RE.finditer(decoded):
        if m.start() > pos:
            valid_len = len(decoded[pos:m.start()].encode("utf-8"))
            regions.append((True, byte_pos, byte_pos + valid_len))
            byte_pos += valid_len
        invalid_len = m.end() - m.start()  # one original byte per surrogate code point
        regions.append((False, byte_pos, byte_pos + invalid_len))
        byte_pos += invalid_len
        pos = m.end()
    if pos < len(decoded):
        valid_len = len(decoded[pos:].encode("utf-8"))
        regions.append((True, byte_pos, byte_pos + valid_len))
    return regions


# How close two invalid-UTF-8 runs must be, in bytes, before they are treated as ONE
# damaged region rather than two independent ones. Genuine legacy prose is not one
# unbroken run of bad bytes: every ASCII space, digit, or punctuation mark between two
# non-ASCII words is itself valid UTF-8 (a single ASCII byte always is, and even a
# legacy multi-byte codepage's bytes occasionally pair up into an "accidentally valid"
# UTF-8 sequence by pure coincidence), so a byte-exact split fragments a real
# cp1251/shift-jis/cp932/euc-jp/big5/gb18030/euc-kr document into hundreds of runs a
# few bytes apart. Measured, on real documents in each of those encodings (the same
# corpus `test_b537_shift_jis_multibyte_classification.py` and this ladder's cp1251
# fixtures already exercise): the largest gap between two consecutive invalid runs
# inside genuine legacy prose was 11 bytes. This sits roughly 6x above that, so an
# embedded acronym, number, or short English word does not needlessly split one legacy
# region into several, while staying far below any realistic separation between an
# attacker's padding and the real payload elsewhere in the same document -- a large
# valid stretch (the case this fix defends) is never bridged, because it is not
# sandwiched between two runs close enough to qualify.
_REGION_BRIDGE_BYTES = 64


def _merge_bridged_invalid_runs(runs: "list[tuple[int, int]]") -> "list[tuple[int, int]]":
    """Collapse consecutive ``(start, end)`` invalid-byte runs into ONE span wherever the
    valid gap between them is <= `_REGION_BRIDGE_BYTES`. `runs` must already be in file
    order, as `_utf8_byte_regions` produces them."""
    if not runs:
        return []
    merged = [list(runs[0])]
    for start, end in runs[1:]:
        if start - merged[-1][1] <= _REGION_BRIDGE_BYTES:
            merged[-1][1] = end
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


# B-546 (round 2): an ABSOLUTE size floor on the merged span -- the first cut of this
# fix -- broke a genuinely short legacy file. Measured on the real regression
# (`test_every_reader_gets_the_decoded_text_not_just_the_ring`, a 53-byte cp1251
# comment: `# Настройка плагина: описание параметров.\n` + one ASCII code line): after
# `_merge_bridged_invalid_runs` correctly reassembles its four word-runs into ONE
# 38-byte span (bridging was never the problem -- `_REGION_BRIDGE_BYTES=64` already
# spans every gap in it), 38 bytes still cannot clear a 256-byte floor, because the
# floor is bigger than the entire file. No bridge distance fixes that: the file has no
# MORE bytes to bridge in. Size was never the right discriminator for "is this a
# confident legacy guess" -- density is, which is what `_is_predominantly_utf8` already
# measured, just over the WHOLE file. This asks the identical question (damaged bytes /
# non-ASCII bytes, against the same `_LEGACY_DAMAGE_RATIO`) over a WINDOW around the
# region instead: for a short file the window clips to the file and the two questions
# coincide (ratio ~1.0 for the 53-byte case, correctly legacy); for a region embedded in
# a much larger document, bytes outside the window cannot move its ratio no matter how
# many of them there are, which is what actually stops the padding attack (a distant
# 2,941-byte pad or a distant 2-byte homoglyph flip both stay OUTSIDE a real payload
# region's own window). `_TEXT_SAMPLE_BYTES` is reused as the radius rather than adding
# a second magic number -- it is already this ladder's answer to "how much of a
# document is enough to judge by" (`classify_bytes`'s own sample).
_REGION_RATIO_RADIUS_BYTES = _TEXT_SAMPLE_BYTES


def _region_reads_as_legacy(data: bytes, start: int, end: int) -> bool:
    """Is the ``[start, end)`` region -- plus up to `_REGION_RATIO_RADIUS_BYTES` of
    context on each side, clipped to the file -- dense enough with invalid-UTF-8 bytes
    to trust a legacy-codepage guess for it?

    Same arithmetic as `_is_predominantly_utf8` (damaged / non-ASCII bytes, against
    `_LEGACY_DAMAGE_RATIO`), but the denominator is a bounded WINDOW around one region
    instead of the whole file -- see `_REGION_RATIO_RADIUS_BYTES` for why that is the
    fix and bridging alone was not.
    """
    window = data[max(0, start - _REGION_RATIO_RADIUS_BYTES):min(len(data), end + _REGION_RATIO_RADIUS_BYTES)]
    non_ascii = len(window.translate(None, bytes(range(128))))
    if not non_ascii:
        return False
    damaged = window.decode("utf-8", errors="replace").count("�")
    return damaged / non_ascii >= _LEGACY_DAMAGE_RATIO


def _decode_ladder_regions(data: bytes) -> "tuple[str, str | None]":
    """The B-546 replacement for the old whole-file `_is_predominantly_utf8` gate.

    Called only from `_decode_ladder`'s NUL-free legacy branch, on data whose whole-file
    UTF-8 decode has already failed. Rather than deciding ONE rung for the entire file,
    this finds the byte spans that actually fail UTF-8 (`_utf8_byte_regions`), bridges
    the ones close enough together into one damaged region
    (`_merge_bridged_invalid_runs`), and only then asks whether that MERGED region --
    not the whole file -- is dense enough with invalid bytes, in its own local
    neighbourhood, to trust a legacy-codepage guess (`_region_reads_as_legacy`).

    A region that fails that test -- an isolated stray byte surrounded by valid content
    far past the window radius, or an attacker's padding sitting apart from anything
    else non-ASCII -- is decoded lossily (`errors="replace"`) instead of guessed: per
    the DoD, a region that cannot be confidently decoded stays scannable rather than
    silently adopting a rung that could be wrong. A region that passes gets the SAME two
    rungs the old whole-file gate used, unchanged (`_try_structured_multibyte` first,
    then the byte-preserving latin-1 guess) -- just scoped to that region's own bytes,
    so a padding-inflated region elsewhere in the file cannot vote on how this one is
    read. `_try_structured_multibyte` keeps its own internal `_MULTIBYTE_MIN_SAMPLE_BYTES`
    floor unchanged (a short span still cannot validate a multi-byte codec with
    confidence); `_merge_bridged_invalid_runs` existing to reassemble fragmented runs
    into one contiguous span is what lets a genuine multi-byte-legacy document clear
    THAT floor at all.

    The returned encoding name is the first assumed rung actually used, in file order --
    a file needing two DIFFERENT guessed codecs in two different regions is a
    degenerate case no existing fixture produces; the manifest disclosure exists to say
    "at least one region here was guessed", not to enumerate every rung used.
    """
    regions = _utf8_byte_regions(data)
    invalid_runs = [(start, end) for is_valid, start, end in regions if not is_valid]
    merged = _merge_bridged_invalid_runs(invalid_runs)
    legacy_spans = [(s, e) for s, e in merged if _region_reads_as_legacy(data, s, e)]

    parts: "list[str]" = []
    assumed_encoding: "str | None" = None
    cursor = 0
    for start, end in legacy_spans:
        if start > cursor:
            parts.append(data[cursor:start].decode("utf-8", errors="replace"))
        chunk = data[start:end]
        structured = _try_structured_multibyte(chunk)
        if structured is not None:
            decoded, name = structured
        else:
            decoded, name = chunk.decode("latin-1"), "latin-1"
        parts.append(decoded)
        if assumed_encoding is None:
            assumed_encoding = name
        cursor = end
    # Reachable only once the whole-file UTF-8 attempt at the top of `_decode_ladder`
    # has already failed, so `merged` (and thus `legacy_spans` or at least one lossy
    # gap) is never empty here in practice -- the loop and this tail slice are written
    # to stay correct standalone regardless (e.g. a test calling this helper directly).
    if cursor < len(data):
        parts.append(data[cursor:].decode("utf-8", errors="replace"))

    return "".join(parts), assumed_encoding


def _decode_ladder(data: bytes) -> tuple[str | None, str | None]:
    """Decode bytes the way the scanner must read them: (text, encoding-used).

    Both are None when no rung fits. The encoding name is returned because the rungs are
    not equally trustworthy — see the latin-1 branch — and the manifest claim in
    `collect_skill_files` has to say which one carried the file.

    The single decode ladder — UTF-8, then BOM/shape-confirmed UTF-16, then a legacy
    single-byte reading *only for files that really are single-byte* — shared by the
    classifier and by every reader that feeds the content ring. That last rung is gated,
    per contiguous region (B-546), by `_decode_ladder_regions`: a region that is still
    predominantly UTF-8 stays UTF-8 and pays per character, which it reports by
    returning a None encoding.

    B-538: it used to live inside `classify_bytes` and nowhere else. The four skill
    readers (`_read_skill_text`, `read_skill_python`, `read_skill_shell`,
    `read_skill_js`) decoded the very same bytes with a bare
    ``.decode("utf-8", errors="replace")``, so a file the classifier had correctly read
    as cp1251 or UTF-16 reached the ring as mojibake while `file_manifest` recorded it
    ``scanned-text``. Measured on a 12.5 KB cp1251 SKILL.md: 9,801 U+FFFD in the text the
    ring received, and B58 (Unicode obfuscation — a check that can only fire on the
    non-ASCII bytes themselves) downgraded WARN -> PASS against its byte-identical UTF-8
    twin. A BOM'd UTF-16 file was worse than partial: even the ASCII payload was
    destroyed, and B156/B160/B64/B58 all vanished from a skill reported as scanned.

    An incremental decoder is used so an incomplete trailing sequence is buffered rather
    than raised on — `classify_bytes` passes a sample cut at a fixed offset (B-533), and
    a reader can be handed bytes truncated at a cap. Only a genuinely invalid byte
    reaches the fallbacks.
    """
    try:
        return codecs.getincrementaldecoder("utf-8")().decode(data, False), "utf-8"
    except UnicodeDecodeError:
        pass

    # A real invalid sequence, not a truncated tail. Only now consider UTF-16, and only
    # when the bytes actually look like UTF-16 — accepting any non-raising UTF-16 decode
    # is what let arbitrary bytes through as text-shaped garbage in the first place.
    # Nearly every byte pair is valid UTF-16, so "it did not raise" carries almost no
    # evidence; a BOM or the interleaved-NUL shape of ASCII-range text does.
    if _looks_like_utf16(data):
        # B-538: when there IS a BOM it names the byte order, so honour it instead of
        # trying LE first — a big-endian body decoded as little-endian does not raise, it
        # silently yields byte-swapped CJK. Harmless while only the printable ratio read
        # the result; not harmless now that the ring reads it.
        if data[:2] == b"\xff\xfe":
            order = ("utf-16le",)
        elif data[:2] == b"\xfe\xff":
            order = ("utf-16be",)
        else:
            order = ("utf-16le", "utf-16be")
        for encoding in order:
            try:
                decoded = codecs.getincrementaldecoder(encoding)().decode(data, False)
            except UnicodeDecodeError:
                continue
            # Drop the decoded BOM: left in place it prefixes the very first line, which
            # is where a SKILL.md's `---` frontmatter fence has to be.
            return (decoded[1:] if decoded[:1] == "\ufeff" else decoded), encoding
    elif b"\x00" not in data:
        # B-538 (repair): guard the rung before explaining it. Because the rung is
        # all-or-nothing, taking it costs EVERY non-ASCII character in the file, not just
        # the byte that failed — which made one attacker-planted byte a silencer for every
        # non-ASCII-keyed check. A file that is still predominantly UTF-8 therefore keeps a
        # UTF-8 reading and pays per character, disclosed as `(lossy)` by the None
        # encoding; the legacy rungs below are for files -- or, since B-546, REGIONS of a
        # file -- that really are single- or multi-byte legacy.
        #
        # B-546: the first version of this gate (`_is_predominantly_utf8`) decided that
        # question once, for the WHOLE file, from a ratio an attacker could walk across
        # by padding anywhere in the file -- see that function's docstring for the
        # measurements. `_decode_ladder_regions` asks it per CONTIGUOUS REGION instead
        # (`_try_structured_multibyte` then the byte-preserving latin-1 guess, same as
        # before, just scoped to a region rather than the whole file), so padding placed
        # away from the real payload can no longer vote on how the payload's own region
        # is read. See its docstring for the two rungs, the merge/floor mechanics, and
        # why `b"\xee"` (cp1251 `о`, latin-1 `î`, nothing in the bytes says which) is
        # still an assumption the caller must disclose, never a claimed read.
        return _decode_ladder_regions(data)

    return None, None


def decode_scanned_text(data: bytes) -> str | None:
    """The decoded text of `data`, or None when no rung of the ladder reads it.

    Thin wrapper over `_decode_ladder` for the callers that only need the text.
    """
    return _decode_ladder(data)[0]


def classify_bytes(data: bytes, file_size: int) -> tuple[str, str | None]:
    """Classify data as "TEXT" or "BINARY" and return (classification, format_name)."""
    fmt = None
    if data.startswith(b"\x7fELF"):
        fmt = "ELF"
    elif data.startswith(b"MZ"):
        fmt = "PE"
    elif data.startswith(b"\xce\xfa\xed\xfe"):
        fmt = "Mach-O (32 LSB)"
    elif data.startswith(b"\xcf\xfa\xed\xfe"):
        fmt = "Mach-O (64 LSB)"
    elif data.startswith(b"\xfe\xed\xfa\xce"):
        fmt = "Mach-O (32 MSB)"
    elif data.startswith(b"\xfe\xed\xfa\xcf"):
        fmt = "Mach-O (64 MSB)"
    elif data.startswith(b"\xc0\xde\xc0\xde"):
        fmt = "Mach-O (FAT LSB)"
    elif data.startswith(b"\xca\xfe\xba\xbe"):
        if file_size < 50000 and len(data) >= 10:
            major_version = int.from_bytes(data[6:8], "big")
            constant_pool_count = int.from_bytes(data[8:10], "big")
            if 45 <= major_version <= 100 and constant_pool_count > 0:
                fmt = "class"
        if not fmt:
            fmt = "Mach-O (FAT MSB)"
    elif data.startswith(b"\x00asm"):
        fmt = "wasm"  # F-116: WebAssembly module — unambiguous magic, a loose .wasm is a stowaway
    elif data.startswith(b"PK\x03\x04"):
        fmt = "ZIP"
    elif data.startswith(b"PK\x05\x06"):
        fmt = "ZIP"
    elif data.startswith(b"PK\x07\x08"):
        fmt = "ZIP"
    elif data.startswith(b"\x1f\x8b"):
        fmt = "gzip"
    elif data.startswith(b"BZh"):
        fmt = "bz2"
    elif data.startswith(b"\xfd7zXZ\x00"):
        fmt = "xz"
    elif len(data) >= 262 and data[257:262] == b"ustar":
        fmt = "tar"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        fmt = "PNG"
    elif data.startswith(b"\xff\xd8\xff"):
        fmt = "JPEG"
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        fmt = "GIF"
    elif data.startswith(b"%PDF-"):
        fmt = "PDF"

    if fmt is not None:
        return "BINARY", fmt

    # Decode a bounded sample as text.
    #
    # B-533: the sample is cut at a FIXED offset, so it must be decoded incrementally.
    # `bytes.decode` is strict about the tail, and a multi-byte character straddling the
    # cut made it raise. ASCII is one byte per character, so the cut can never split one
    # and English prose was structurally immune. Everything else could raise, and what
    # happened next was pure accident: the UTF-16 fallback below "succeeded" into
    # mojibake, and the printable gate then judged the mojibake rather than the file.
    # Measured, on documents where the cut really does split a character:
    #
    #   3-byte scripts (Chinese, Japanese, Korean)  mojibake ratio 0.667 -> BINARY, always
    #   2-byte scripts (Cyrillic, Greek, Hebrew)    mojibake ratio 1.000 -> TEXT, by luck
    #   Arabic                                       utf-16le fails, utf-16be carries it
    #
    # So CJK was reliably broken and the rest merely got away with it — the same wrong
    # cut, a different roll. Do not read the 2-byte rows as "those were fine".
    #
    # The cost was never the "Binary files found" WARN itself — and as of B-615 it is
    # not cosmetic either: it drives checks/_vet.py's CAUTION verdict and exit code for
    # any binary `classify_bytes` did NOT recognise as inert media (see ctx.binary_files
    # at the decompress call site; recognised PNG/JPEG/GIF are disclosed instead and
    # don't reach it). The real, separate cost stands regardless: a BINARY verdict drops
    # the file from content scanning, so a CJK skill's prose went unscanned past this
    # sample size — injection and exfiltration instructions in it were invisible.
    #
    # B-538: the ladder itself now lives in `decode_scanned_text` so the readers that
    # feed the content ring use the SAME one — this function's verdict and their reading
    # of the file must come from one decision, or the manifest claims a coverage the ring
    # never got. Only the sample size is this function's business.
    decoded = decode_scanned_text(data[:_TEXT_SAMPLE_BYTES])

    if decoded is None:
        return "BINARY", _pyc_fmt(data)

    if not decoded:
        return "TEXT", None

    # B-537: shares `_printable_ratio`/`_PRINTABLE_RATIO_THRESHOLD` with
    # `_try_structured_multibyte` so the classifier's verdict and the decode ladder's
    # rung-acceptance gate are one decision, not two thresholds that can drift apart.
    if _printable_ratio(decoded) >= _PRINTABLE_RATIO_THRESHOLD:
        return "TEXT", None
    else:
        return "BINARY", _pyc_fmt(data)


def check_mismatch(filename: str, classification: str, format_name: str | None, data: bytes) -> str | None:
    ext = Path(filename).suffix.lower()
    text_extensions = {".py", ".json", ".txt", ".md", ".sh", ".bash", ".zsh", ".js", ".ts", ".mjs", ".cjs", ".ps1"}
    
    if ext in text_extensions:
        if data.startswith(b"MZ") or data.startswith(b"\x7fELF") or data.startswith(b"PK\x03\x04"):
            return "MISMATCH_EXTENSION"
            
    binary_ext_to_format = {
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".pdf": "PDF",
        ".zip": "ZIP",
        ".gz": "gzip",
        ".bz2": "bz2",
        ".xz": "xz",
        ".tar": "tar",
        ".class": "class",
    }
    if ext in binary_ext_to_format:
        expected_format = binary_ext_to_format[ext]
        if format_name is not None and format_name != expected_format:
            return "MISMATCH_EXTENSION"
            
    return None


def check_polyglot(filename: str, format_name: str | None, data: bytes) -> str | None:
    if format_name != "ZIP":
        idx = data.find(b"PK\x03\x04")
        if idx > 0:
            return "POLYGLOT_DETECTED"

    if format_name in ("PNG", "JPEG", "GIF"):
        header = data[:1024].lower()
        html_tags = (b"<html>", b"<script", b"<body>", b"<iframe>", b"</a>", b"</div>")
        for tag in html_tags:
            if tag in header:
                return "POLYGLOT_DETECTED"

    ext = Path(filename).suffix.lower()
    archive_extensions = {".zip", ".tar", ".gz", ".bz2", ".xz"}
    if ext not in archive_extensions and len(data) > 0:
        tail = data[-1024:]
        if b"PK\x01\x02" in tail or b"PK\x05\x06" in tail:
            return "POLYGLOT_DETECTED"

    return None


def decompress_and_classify(
    ctx: Context | None,
    skill_dir: Path,
    file_bytes: bytes,
    file_relpath: str,
    depth: int,
    archive_stats: dict
) -> list[tuple[str, bytes, str, str | None]]:
    """Recursively decompress and classify files from an archive."""
    try:
        classification, format_name = classify_bytes(file_bytes, len(file_bytes))
    except Exception as e:
        if ctx is not None:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                f"Classification failed for {file_relpath}: {e}",
            )
            ctx.file_manifest[file_relpath] = "binary-strings"
        return [(file_relpath, file_bytes, "BINARY", None)]

    if format_name not in ("ZIP", "tar", "gzip", "bz2", "xz"):
        return [(file_relpath, file_bytes, classification, format_name)]
        
    if depth > 3:
        if ctx is not None:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                f"Depth limit hit (>3) at {file_relpath}",
            )
            ctx.file_manifest[file_relpath] = "capped(depth)"
        return [(file_relpath, file_bytes, classification, format_name)]
        
    if ctx is not None:
        ctx.archives_unpacked += 1
        
    compressed_size = len(file_bytes)
    results = []
    
    # ZIP
    if format_name == "ZIP":
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                namelist = zf.namelist()
                if len(namelist) + archive_stats["total_files_count"] > _ARCHIVE_FILE_LIMIT:
                    if ctx is not None:
                        note_limit(
                            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                            f"Max files limit hit (>500) in {file_relpath}",
                        )
                        ctx.file_manifest[file_relpath] = "capped(files)"
                    return [(file_relpath, file_bytes, classification, format_name)]

                for member_name in namelist:
                    # B-111: member_name is attacker-controlled and NOT length-limited like a
                    # real filesystem path — use a capped display name for evidence/manifest
                    # text; the real (uncapped) member_name still drives zf.getinfo/zf.open.
                    member_disp = _cap_name(member_name)
                    if not is_safe_tar_member(skill_dir, member_name):
                        if ctx is not None:
                            ctx.path_traversal_violations.append(f"{file_relpath}::{member_disp}")
                            _note_skill_traversal(ctx, skill_dir, f"{file_relpath}::{member_disp}")
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "unsafe-path"
                        return [(file_relpath, file_bytes, classification, format_name)]

                    if member_name.endswith("/"):
                        continue

                    try:
                        member_info = zf.getinfo(member_name)
                        if member_info.is_dir():
                            continue

                        if member_info.file_size > _ARCHIVE_MAX_FILE_BYTES:
                            if ctx is not None:
                                note_limit(
                                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                                    f"Max file decompressed size hit (>200,000) for {member_disp} in {file_relpath}",
                                )
                                ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "capped(size)"
                            continue

                        with zf.open(member_name, "r") as zfp:
                            member_bytes, truncated = _read_with_limit(zfp, _ARCHIVE_MAX_FILE_BYTES)
                    except Exception:
                        continue

                    if truncated:
                        if ctx is not None:
                            note_limit(
                                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                                f"Max file decompressed size hit (>200,000) for {member_disp} in {file_relpath}",
                            )
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "capped(size)"
                        continue

                    archive_stats["total_files_count"] += 1
                    archive_stats["cumulative_decompressed_size"] += len(member_bytes)

                    if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                        if ctx is not None:
                            note_limit(
                                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                                f"Max cumulative size hit (>20MB) in {file_relpath}",
                            )
                            ctx.file_manifest[file_relpath] = "capped(size)"
                        return [(file_relpath, file_bytes, classification, format_name)]

                    if compressed_size > 10240:
                        ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                        if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                            if ctx is not None:
                                note_limit(
                                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                                    f"Max expansion ratio hit (>100x) in {file_relpath}",
                                )
                                ctx.file_manifest[file_relpath] = "capped(ratio)"
                            return [(file_relpath, file_bytes, classification, format_name)]

                    sub_rel = f"{file_relpath}::{member_disp}"
                    sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
                    results.extend(sub_results)

                if ctx is not None:
                    ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                    f"ZIP decompression failed in {file_relpath}: {e}",
                )
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    # TAR
    elif format_name == "tar":
        try:
            with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tf:
                members = tf.getmembers()
                if len(members) + archive_stats["total_files_count"] > _ARCHIVE_FILE_LIMIT:
                    if ctx is not None:
                        note_limit(
                            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                            f"Max files limit hit (>500) in {file_relpath}",
                        )
                        ctx.file_manifest[file_relpath] = "capped(files)"
                    return [(file_relpath, file_bytes, classification, format_name)]
                    
                for member in members:
                    # B-111: member.name is attacker-controlled and NOT length-limited like a
                    # real filesystem path — use a capped display name for evidence/manifest
                    # text; the real (uncapped) member.name still drives tf.extractfile.
                    member_disp = _cap_name(member.name)
                    if not is_safe_tar_member(skill_dir, member.name):
                        if ctx is not None:
                            ctx.path_traversal_violations.append(f"{file_relpath}::{member_disp}")
                            _note_skill_traversal(ctx, skill_dir, f"{file_relpath}::{member_disp}")
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "unsafe-path"
                            return [(file_relpath, file_bytes, classification, format_name)]

                    if not member.isreg():
                        if ctx is not None and (member.issym() or member.islnk()):
                            # F-061-style disclosure: a symlink/hardlink member inside an
                            # archive is dropped just like a symlink hit by walk_dir_safely
                            # on a real directory — record it the same way so --vet on an
                            # archive surfaces "N symlink member(s) not followed" too.
                            tgt = member.linkname or "?"
                            reason = f"symlink -> {tgt}"
                            ctx.symlink_skips.append(f"{file_relpath}::{member_disp}: {reason}")
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "skipped:" + reason.split(" ", 1)[0]
                        continue

                    try:
                        if member.size > _ARCHIVE_MAX_FILE_BYTES:
                            if ctx is not None:
                                note_limit(
                                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                                    f"Max file decompressed size hit (>200,000) for {member_disp} in {file_relpath}",
                                )
                                ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "capped(size)"
                            continue

                        f_obj = tf.extractfile(member)
                        if f_obj is None:
                            continue
                        member_bytes = f_obj.read(member.size)
                    except Exception:
                        continue

                    if len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                        if ctx is not None:
                            note_limit(
                                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                                f"Max file decompressed size hit (>200,000) for {member_disp} in {file_relpath}",
                            )
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "capped(size)"
                        continue
                        
                    archive_stats["total_files_count"] += 1
                    archive_stats["cumulative_decompressed_size"] += len(member_bytes)
                    
                    if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                        if ctx is not None:
                            note_limit(
                                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                                f"Max cumulative size hit (>20MB) in {file_relpath}",
                            )
                            ctx.file_manifest[file_relpath] = "capped(size)"
                        return [(file_relpath, file_bytes, classification, format_name)]
                        
                    if compressed_size > 10240:
                        ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                        if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                            if ctx is not None:
                                note_limit(
                                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                                    f"Max expansion ratio hit (>100x) in {file_relpath}",
                                )
                                ctx.file_manifest[file_relpath] = "capped(ratio)"
                            return [(file_relpath, file_bytes, classification, format_name)]
                            
                    sub_rel = f"{file_relpath}::{member_disp}"
                    sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
                    results.extend(sub_results)
                if ctx is not None:
                    ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                    f"tar decompression failed in {file_relpath}: {e}",
                )
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    # GZIP
    elif format_name == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(file_bytes), mode="rb") as gz:
                member_bytes, truncated = _read_with_limit(gz, _ARCHIVE_MAX_FILE_BYTES)

            if truncated or len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                if ctx is not None:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"Max file decompressed size hit (>200,000) in {file_relpath}",
                    )
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]
                
            archive_stats["total_files_count"] += 1
            archive_stats["cumulative_decompressed_size"] += len(member_bytes)
            
            if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                if ctx is not None:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"Max cumulative size hit (>20MB) in {file_relpath}",
                    )
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]

            if compressed_size > 10240:
                ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                    if ctx is not None:
                        note_limit(
                            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                            f"Max expansion ratio hit (>100x) in {file_relpath}",
                        )
                        ctx.file_manifest[file_relpath] = "capped(ratio)"
                    return [(file_relpath, file_bytes, classification, format_name)]

            sub_rel = file_relpath[:-3] if file_relpath.lower().endswith(".gz") else f"{file_relpath}::extracted"
            sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
            results.extend(sub_results)
            if ctx is not None:
                ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                    f"gzip decompression failed in {file_relpath}: {e}",
                )
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    # BZIP2
    elif format_name == "bz2":
        try:
            with bz2.BZ2File(io.BytesIO(file_bytes), mode="rb") as bzf:
                member_bytes, truncated = _read_with_limit(bzf, _ARCHIVE_MAX_FILE_BYTES)

            if truncated or len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                if ctx is not None:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"Max file decompressed size hit (>200,000) in {file_relpath}",
                    )
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]
                
            archive_stats["total_files_count"] += 1
            archive_stats["cumulative_decompressed_size"] += len(member_bytes)
            
            if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                if ctx is not None:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"Max cumulative size hit (>20MB) in {file_relpath}",
                    )
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]

            if compressed_size > 10240:
                ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                    if ctx is not None:
                        note_limit(
                            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                            f"Max expansion ratio hit (>100x) in {file_relpath}",
                        )
                        ctx.file_manifest[file_relpath] = "capped(ratio)"
                    return [(file_relpath, file_bytes, classification, format_name)]

            sub_rel = file_relpath[:-4] if file_relpath.lower().endswith(".bz2") else f"{file_relpath}::extracted"
            sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
            results.extend(sub_results)
            if ctx is not None:
                ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                    f"bz2 decompression failed in {file_relpath}: {e}",
                )
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    # XZ
    elif format_name == "xz":
        try:
            with lzma.open(io.BytesIO(file_bytes), mode="rb") as xf:
                member_bytes, truncated = _read_with_limit(xf, _ARCHIVE_MAX_FILE_BYTES)

            if truncated or len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                if ctx is not None:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"Max file decompressed size hit (>200,000) in {file_relpath}",
                    )
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]
                
            archive_stats["total_files_count"] += 1
            archive_stats["cumulative_decompressed_size"] += len(member_bytes)
            
            if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                if ctx is not None:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"Max cumulative size hit (>20MB) in {file_relpath}",
                    )
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]

            if compressed_size > 10240:
                ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                    if ctx is not None:
                        note_limit(
                            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                            f"Max expansion ratio hit (>100x) in {file_relpath}",
                        )
                        ctx.file_manifest[file_relpath] = "capped(ratio)"
                    return [(file_relpath, file_bytes, classification, format_name)]

            sub_rel = file_relpath[:-3] if file_relpath.lower().endswith(".xz") else f"{file_relpath}::extracted"
            sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
            results.extend(sub_results)
            if ctx is not None:
                ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                    f"xz decompression failed in {file_relpath}: {e}",
                )
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    return results


# B-615: formats `classify_bytes` positively RECOGNISES as ordinary, inert media — a
# logo, a screenshot, a rendered doc. Bundling one is normal skill authoring, not a
# stowaway (F-054 already owns native executables/pyc/wasm, a separate branch below)
# and not an opaque blob (an unrecognised binary still lands in `ctx.binary_files` and
# still WARNs — that signal is real and stays). Deliberately narrow: archive formats
# (ZIP/tar/gzip/bz2/xz) are excluded even though `classify_bytes` recognises them too,
# because an archive that reached here failed or was capped during decompression, so it
# is genuinely unresolved content, not inert media.
#
# PDF is deliberately NOT in this set despite being one of `classify_bytes`'s
# recognised formats. A PNG/JPEG/GIF magic-byte match means the whole file IS a raster
# image — the format has no capability for active content. A PDF magic-byte match
# means only that the file STARTS with a valid header; the format itself can carry
# `/JavaScript`, `/OpenAction`, `/Launch` actions and embedded files, none of which the
# 8-byte `%PDF-` signature says anything about. "Recognised" would silently become
# "presumed safe" for exactly the one format here where that presumption can be wrong,
# so a PDF stays in `ctx.binary_files` and keeps WARNing like any other opaque binary.
_RECOGNISED_INERT_MEDIA_FORMATS = frozenset({"PNG", "JPEG", "GIF"})

def _png_end_offset(data: bytes) -> int | None:
    """Byte offset immediately after a PNG's IEND chunk (length+type+CRC), reached by
    structurally walking the chunk stream -- never by searching for `IEND` as a
    substring, which a polyglot can defeat by placing a forged chunk after a real
    payload. Returns None on a malformed/truncated stream or if IEND is never reached.
    """
    sig = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(sig):
        return None
    pos = len(sig)
    n = len(data)
    while pos + 8 <= n:
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        chunk_end = pos + 8 + length + 4  # len field + type + data + crc
        if chunk_end > n:
            return None
        if ctype == b"IEND":
            return chunk_end
        pos = chunk_end
    return None


def _jpeg_end_offset(data: bytes) -> int | None:
    """Byte offset immediately after a JPEG's EOI (0xFFD9) marker, reached by walking
    segments from SOI (each non-entropy segment carries its own declared length, so an
    embedded EXIF thumbnail -- itself a nested mini-JPEG with its own SOI/EOI -- is
    skipped whole as opaque APPn payload rather than confusing a substring search) and,
    once inside entropy-coded scan data, honouring byte-stuffing (`FF 00`) and restart
    markers (`FF D0`-`FF D7`) so those bytes are never mistaken for the real EOI.
    """
    if not data.startswith(b"\xff\xd8"):
        return None
    n = len(data)
    pos = 2
    while pos < n:
        if data[pos] != 0xFF:
            return None
        m = pos
        while m < n and data[m] == 0xFF:  # marker fill bytes
            m += 1
        if m >= n:
            return None
        marker = data[m]
        pos = m + 1
        if marker == 0xD9:  # EOI
            return pos
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # TEM / RSTn: no payload
            continue
        if pos + 2 > n:
            return None
        seg_len = int.from_bytes(data[pos:pos + 2], "big")
        if seg_len < 2:
            return None
        seg_end = pos + seg_len
        if seg_end > n:
            return None
        if marker == 0xDA:  # SOS: entropy-coded data follows, no declared length
            pos = seg_end
            while pos < n:
                if data[pos] == 0xFF:
                    if pos + 1 >= n:
                        return None
                    nxt = data[pos + 1]
                    if nxt == 0x00:
                        pos += 2  # byte-stuffed literal 0xFF in scan data
                        continue
                    if 0xD0 <= nxt <= 0xD7:
                        pos += 2  # restart marker inside entropy data
                        continue
                    break  # a real marker follows: end of this scan
                pos += 1
            continue
        pos = seg_end
    return None


def _gif_end_offset(data: bytes) -> int | None:
    """Byte offset immediately after a GIF's trailer byte (0x3B), reached by walking
    the block structure (extension/image-descriptor sub-block chains, each terminated
    by a declared 0x00 length) rather than searching for 0x3B as a substring -- LZW-
    compressed pixel data routinely contains that byte value by chance.
    """
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return None
    n = len(data)
    pos = 6
    if pos + 7 > n:
        return None
    packed = data[pos + 4]
    pos += 7
    if packed & 0x80:  # global color table present
        pos += 3 * (2 ** ((packed & 0x07) + 1))
        if pos > n:
            return None

    def _skip_subblocks(p: int) -> int | None:
        while p < n:
            length = data[p]
            p += 1
            if length == 0:
                return p
            p += length
            if p > n:
                return None
        return None

    while pos < n:
        marker = data[pos]
        if marker == 0x3B:  # trailer
            return pos + 1
        if marker == 0x21:  # extension introducer
            if pos + 2 > n:
                return None
            pos = _skip_subblocks(pos + 2)
            if pos is None:
                return None
        elif marker == 0x2C:  # image descriptor
            if pos + 10 > n:
                return None
            ipacked = data[pos + 9]
            pos += 10
            if ipacked & 0x80:  # local color table present
                pos += 3 * (2 ** ((ipacked & 0x07) + 1))
                if pos > n:
                    return None
            pos += 1  # LZW minimum code size
            if pos > n:
                return None
            pos = _skip_subblocks(pos)
            if pos is None:
                return None
        else:
            return None
    return None


_MEDIA_END_OFFSET_FNS = {
    "PNG": _png_end_offset,
    "JPEG": _jpeg_end_offset,
    "GIF": _gif_end_offset,
}


def _media_is_well_terminated(fmt: str, data: bytes) -> bool:
    """True only if `data` genuinely IS the recognised format, start to end -- not
    merely starts with its magic bytes.

    B-615, round 2: the magic-byte check alone was defeated by a real, live attack --
    a valid PNG with a payload appended after the image data classified identically to
    a clean one (`binary_files=[]` either way), because the discriminator asked nothing
    about what followed the header. Each format defines its own end-of-data terminator
    (PNG's IEND chunk + CRC, JPEG's EOI marker, GIF's trailer byte); the offset
    functions above locate it by walking the real container structure (declared
    chunk/segment/block lengths), not by searching for the terminator bytes as a
    substring -- a substring search is exactly what a polyglot can defeat, either by an
    appended payload landing before a coincidental match or by forging a second, fake
    terminator after the payload to make an `endswith`-style check pass.

    Zero trailing bytes are tolerated, not "a few bytes of padding": measured against
    4,092 real local files (4,000 system PNGs under /usr/share/icons + /usr/share/
    pixmaps + installed Python package data, 89 system JPEGs, 3 system GIFs), every
    single one ended EXACTLY at its terminator -- nothing measured pads, so no slack is
    invented on the assumption that some encoder might. Any trailing byte at all, or a
    malformed/truncated container the walker cannot reach a terminator in, means the
    file is treated as an unrecognised/opaque binary -- the safe direction, since a
    false CAUTION on an unusual-but-benign image is recoverable and a false INSTALL on
    a polyglot is not.
    """
    fn = _MEDIA_END_OFFSET_FNS.get(fmt)
    if fn is None:
        return False
    end = fn(data)
    return end is not None and end == len(data)


def collect_skill_files(skill_dir: Path, ctx: Context | None = None) -> list[dict]:
    """Collect (and archive-decompress/classify) the files that make up one skill.

    B-152: *skill_dir* may also be a single **file** — e.g. a bare skill archive
    (.zip/.tar.gz/.tgz/.tar.bz2/.tar.xz) passed directly to --vet/--vet-skill instead
    of an installed skill directory. In that case the file itself is the sole entry
    walked below, so it goes through the exact same archive-decompression / size-cap /
    mismatch-polyglot bookkeeping as an archive found while walking a directory
    (previously only reachable when the archive was *inside* a scanned skill dir).
    """
    if ctx is not None:
        cache_key = str(skill_dir)
        cached = ctx._collected_skill_files.get(cache_key)
        if cached is not None:
            return cached

    if skill_dir.is_file():
        # Anchor relative paths / traversal checks on the parent dir, same as
        # is_safe_tar_member expects a directory, never the archive file itself.
        base_dir = skill_dir.parent
        files = [skill_dir]
    else:
        base_dir = skill_dir
        _skips: list = []
        _capped: list = []
        _unreadable_dirs: list = []
        files = walk_dir_safely(
            base_dir, exclude_pycache=True, exclude_vcs=True, max_files=_MAX_FILES_PER_SKILL,
            skips=_skips, capped=_capped, unreadable_dirs=_unreadable_dirs,
        )
        if ctx is not None and _capped:
            # The walk stopped at _MAX_FILES_PER_SKILL and the rest of the skill was never
            # looked at. `walk_dir_safely` has always offered this sentinel -- its own
            # docstring calls it "GR#4: no silent completeness claim over a capped scan" --
            # and this call site was the one that did not take it, while its sibling in
            # `_skill_signature` did. So a skill could bury a payload behind enough benign
            # files to end the walk, and B13 would then report "no shell-exec / exfiltration
            # / obfuscation patterns found" over a tree it had stopped reading. That needs no
            # permission trick and no obfuscation, only file count.
            #
            # Routed through the same `limit_hits` channel the size-cap branch below uses, so
            # every consumer that already asks "was MY scan truncated?" (limit_hits_for,
            # dossier._danger_coverage_gap, B13's coverage-gap branch) sees it with no new
            # plumbing.
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                f"only the first {_MAX_FILES_PER_SKILL} file(s) of this skill were scanned",
            )
        if ctx is not None and _unreadable_dirs:
            # B-549: a subdirectory that could not be listed. Routed into the SAME channel
            # B-458 built for an unreadable file, because it is the same fact one level up:
            # the content is present and unknown, not absent. Keeping it in `symlink_skips`
            # instead would have described it as "symlink / path-escape not followed" (false)
            # and, worse, as a WARN — while an unreadable *file* correctly forces the Danger
            # axis to UNKNOWN. A directory hides strictly more than a file, so it cannot
            # carry the weaker verdict.
            #
            # Measured before the fix, through the real `--vet-skill`: `chmod 000` on a
            # subdirectory holding a `curl | sh` payload gave `INSTALL` / `Danger PASS` /
            # exit 0, and `--json` carried no coverage key at all. False-positive surface
            # measured the same way B-458's was, before landing: **0 unreadable directories**
            # across 4,741 real ones (`~/.openclaw` 3,083 · `~/.claude/skills` 28 ·
            # `fixtures/` 1,630). A branch that fires on nothing benign and on every hidden
            # subtree is the same trade B-458 already took.
            for dpath, reason, err in _unreadable_dirs:
                try:
                    rel = str(Path(dpath).relative_to(base_dir))
                except (ValueError, OSError):
                    rel = dpath
                if err == errno.ENOENT:
                    # The directory did not become unreadable — it stopped existing between
                    # `os.walk` listing it and descending into it. Recorded, but never as a
                    # coverage gap: "present and unreadable" and "gone" are different facts,
                    # and only the first one hides anything.
                    #
                    # Found by the independent C-135 pass on this very fix, which is the only
                    # reason it is not shipping: a skill with NO unreadable path and no payload
                    # went INSTALL/exit 0 -> CAUTION/exit 1 when an ordinary scratch subdir was
                    # removed mid-scan (a ClawHub update under --vet-all, a `git checkout` in a
                    # skill repo, a pytest/npm temp dir being cleaned). That is a false FAIL on
                    # the documented `--vet ... || fail` install gate, i.e. a Golden Rule #5
                    # blocker, and the sentence was false twice over — nothing "could not be
                    # READ", and the remediation asserted a hidden subtree where there was none.
                    #
                    # Not a silencer (the FP fix that opens a false negative): to make ENOENT
                    # fire, a directory has to exist at listing time and be gone at descent
                    # time. `rmdir` needs it empty, so every file under it was already
                    # unlinked — the bytes are off disk at the moment the scanner looks, and a
                    # static reader cannot be blinded to content that no longer exists.
                    # Restoring it afterwards needs a process running during the scan. That
                    # precondition is absent by construction for `--vet`/`--advise` (an inert,
                    # not-yet-installed tree cannot race itself) but NOT for the audit path or
                    # `--vet-all` over installed skills on a live machine, where an attacker's
                    # agent may be running — so the claim is "no worse than before" there, not
                    # "impossible": pre-fix, ENOENT was recorded nowhere at all. The independent
                    # C-135 pass tried dangling/looping symlinks, a directory replaced by a file
                    # (ENOTDIR), and PATH_MAX nesting (ENAMETOOLONG) — every one lands on the
                    # disclosing side above. `file_manifest` keeps the observation (it reaches
                    # SARIF's inventory and drives no verdict anywhere), so the fact is not
                    # lost, only demoted out of the grade.
                    ctx.file_manifest.setdefault(rel + "/", "vanished-during-scan")
                    continue
                # Every other errno stays on the disclosing side — EACCES/EPERM is the defect
                # itself, and EIO/ELOOP/ENAMETOOLONG are genuine "present but unread" too.
                # Fail-closed by default: a new errno nobody anticipated discloses rather than
                # hides, which is the direction B-458 already chose one level down.
                # B-551: the same channel now carries two shapes — a directory the walk could
                # not list, and an entry inside a listed directory that could not even be
                # classified (no `x` on the parent). Label by what can actually be verified
                # rather than by which branch recorded it: claiming "directory not entered"
                # about a regular file would be the same kind of small lie this whole task is
                # about. The probe is itself guarded, because the reason we are here is that
                # stat calls on this path fail.
                try:
                    is_dir = Path(dpath).is_dir()
                except OSError:
                    is_dir = False
                label = "directory not entered" if is_dir else "could not be read"
                suffix = "/" if is_dir else ""
                ctx.unreadable_files.append(f"{rel}{suffix} ({label}): {reason}")
                _note_skill_gap(ctx, skill_dir, f"{rel}{suffix} ({label}): {reason}")
                ctx.file_manifest.setdefault(rel + suffix, "unreadable")
                if is_dir and rel in (".", ""):
                    # The skill ROOT is what could not be listed, so whether SKILL.md exists is
                    # unknown — and B88 defaults to "absent". Without this bridge the dossier
                    # contradicted itself in adjacent rows: Danger said "an unreadable path is
                    # not an absent one" while Build quality said "no SKILL.md frontmatter block
                    # found ... this skill will not appear to the agent", and that WARN owns the
                    # top `Fix (top):` line — so the user was told to repair frontmatter that was
                    # perfectly valid and merely behind a closed door. B-461 built exactly this
                    # bridge for the unreadable *file* case; the directory case has to cross it
                    # too or the two paths disagree about the same fact.
                    ctx.unreadable_manifests.add(
                        skill_dir.name if skill_dir.is_dir() else skill_dir.parent.name
                    )
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                    f"Could not {'list' if is_dir else 'read'} {_cap_name(rel)}{suffix}: "
                    f"{reason}",
                )
        if ctx is not None and _skips:
            # F-061: a skill shipping `data -> ~/.ssh/id_rsa` or `-> ../../openclaw.json` used to
            # be skipped silently. Record the skip + its target so it surfaces as a WARN.
            for spath, reason in _skips:
                try:
                    rel = str(Path(spath).relative_to(base_dir))
                except (ValueError, OSError):
                    rel = spath
                ctx.symlink_skips.append(f"{rel}: {reason}")
                ctx.file_manifest.setdefault(rel, "skipped:" + reason.split(" ", 1)[0])
    collected = []

    def _rel(p: Path) -> str:
        try:
            return str(p.relative_to(base_dir))
        except (ValueError, OSError):
            return p.name

    def _note_unreadable(p: Path, exc: OSError) -> None:
        """B-458: record a file that is PRESENT but could not be read.

        Golden Rule #4 in its sharpest form. These three read sites used to be bare
        ``except OSError: continue`` — the file vanished from the scan with no
        bookkeeping at all, so B13 went on to assert "no malware signature or known-bad
        indicator" about content it had never seen. Measured: ``chmod 000`` on a
        credential-exfiltration script inside a skill flipped that skill from
        ``Grade F (DANGEROUS)``/exit 1 to ``Grade A (NO KNOWN ISSUE)``/exit 0, and
        ``--advise`` from DO-NOT-INSTALL to INSTALL — i.e. making a payload unreadable
        was a way to buy a clean bill of health, and `--vet ... || fail` (documented in
        docs/USAGE.md as an install gate) went green on a skill nothing had opened.

        The size-cap branch a few lines below already did exactly this bookkeeping; the
        disclosure machinery simply was never wired to the permission-error path.
        """
        if ctx is None:
            return
        rel = _rel(p)
        ctx.unreadable_files.append(f"{rel}: {exc.strerror or exc}")
        _note_skill_gap(ctx, skill_dir, f"{rel}: {exc.strerror or exc}")
        ctx.file_manifest[rel] = "unreadable"
        if p.name.lower() == "skill.md":
            # Keyed the same way vet_skill/the skill sweep key ctx.installed_skills (the
            # skill DIRECTORY's name), so B88 can tell "unreadable" from "absent".
            owner = skill_dir.name if skill_dir.is_dir() else skill_dir.parent.name
            ctx.unreadable_manifests.add(owner)
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
            f"Could not read {_cap_name(rel)}: {exc.strerror or exc}",
        )

    for f in files:
        if not f.is_file():
            # B-549: the walk yields everything os.walk did not classify as a directory, so a
            # FIFO, a socket or a device node lands here — and this `continue` dropped it with
            # no bookkeeping. Measured through `--vet-skill` on a skill whose `run.sh` was a
            # FIFO: INSTALL / "no least-privilege, pinning, or authoring-hygiene issue found" /
            # exit 0, i.e. a positive clean over a file the scanner structurally cannot read.
            # The agent will still execute it and take its bytes from whoever writes the pipe.
            #
            # Only `lstat` is consulted (via is_file()); a FIFO is never opened, because
            # reading one blocks forever with no writer — which is also why "scan it anyway"
            # is not an option and disclosure is the only honest answer.
            #
            # False-positive surface measured before landing: 0 non-regular files (symlinks
            # excluded, they have their own channel) across 9,480 real ones — ~/.openclaw
            # 8,222, ~/.claude/skills 30, fixtures/ 1,228.
            if ctx is not None and _exists_but_not_regular(f):
                if f.name.lower() == "skill.md":
                    # B-461's absent-vs-unreadable bridge, which `_note_unreadable` below
                    # already crosses and this path did not. Caught by the independent C-135
                    # pass with a FIFO named SKILL.md: Danger correctly reported an unread
                    # path while Build quality announced "no SKILL.md frontmatter block
                    # found ... this skill will not appear to the agent" one row down, and
                    # that WARN owns the top `Fix (top):` line — so the user was told to add
                    # a `description:` field to a named pipe.
                    #
                    # B-654: routed through the shared helper so this call site and
                    # `_iter_skill_dirs_guarded`'s discovery-time one agree byte-for-byte.
                    owner = skill_dir.name if skill_dir.is_dir() else skill_dir.parent.name
                    _note_unreadable_manifest(ctx, owner)
                else:
                    rel = _rel(f)
                    ctx.unreadable_files.append(
                        f"{rel} (not a regular file — nothing to read at rest)"
                    )
                    _note_skill_gap(
                        ctx, skill_dir, f"{rel} (not a regular file — nothing to read at rest)"
                    )
                    ctx.file_manifest.setdefault(rel, "not-a-regular-file")
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"Could not read {_cap_name(rel)}: not a regular file",
                    )
            continue

        if ctx is not None:
            ctx.total_files_inspected += 1

        try:
            st_size = f.stat().st_size
        except OSError as exc:
            _note_unreadable(f, exc)
            continue

        relpath = str(f.relative_to(base_dir))

        # Read the first 4096 bytes to classify
        try:
            with open(f, "rb") as fp:
                header = fp.read(4096)
        except OSError as exc:
            _note_unreadable(f, exc)
            continue

        classification, format_name = classify_bytes(header, st_size)
        
        is_archive = format_name in ("ZIP", "tar", "gzip", "bz2", "xz")
        
        if is_archive:
            if st_size > 10 * 1024 * 1024:
                if ctx is not None:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"Compressed size of archive {f.name} exceeds 10MB",
                    )
                    ctx.file_manifest[relpath] = "capped(size)"
                continue
        else:
            if st_size > _MAX_FILE_BYTES:
                if ctx is not None:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                        f"File {f.name} size exceeds {_MAX_FILE_BYTES} bytes",
                    )
                    ctx.file_manifest[relpath] = "capped(size)"
                continue

        # Read the whole file bytes
        try:
            file_bytes = f.read_bytes()
        except OSError as exc:
            _note_unreadable(f, exc)
            continue

        archive_stats = {
            "total_files_count": 0,
            "cumulative_decompressed_size": 0,
            "compressed_size": len(file_bytes),
        }
        
        # Recursively decompress and classify
        extracted = decompress_and_classify(
            ctx, base_dir, file_bytes, relpath, depth=1, archive_stats=archive_stats
        )
        
        for sub_relpath, sub_bytes, sub_class, sub_fmt in extracted:
            mismatch_err = check_mismatch(sub_relpath, sub_class, sub_fmt, sub_bytes)
            if mismatch_err and ctx is not None:
                ctx.mismatches.append(f"{sub_relpath}: {mismatch_err}")
                
            polyglot_err = check_polyglot(sub_relpath, sub_fmt, sub_bytes)
            if polyglot_err and ctx is not None:
                ctx.polyglots.append(f"{sub_relpath}: {polyglot_err}")
                
            if sub_class == "BINARY":
                if ctx is not None:
                    ctx.excluded_binary_files_count += 1
                    # B-615: a RECOGNISED, WELL-TERMINATED inert media file (PNG/JPEG/
                    # GIF, magic bytes at the start AND the format's own terminator
                    # reached with nothing trailing it — see _media_is_well_terminated)
                    # does not join `ctx.binary_files` — that list drives the
                    # "unexpected binary" WARN in checks/_vet.py, and a bundled logo or
                    # screenshot is ordinary skill content, not a suspicious one. It
                    # still wasn't content-scanned (excluded_binary_files_count above
                    # already says so honestly), so the fact is disclosed on the B-617
                    # channel instead — never read by a check, never gates a verdict.
                    # A magic-byte match alone is NOT enough: round 2 of this bug was a
                    # live PNG-plus-appended-payload polyglot that the magic-only check
                    # let through as INSTALL. An unrecognised, malformed, or trailing-
                    # content binary keeps its current weight below.
                    if sub_fmt in _RECOGNISED_INERT_MEDIA_FORMATS and _media_is_well_terminated(sub_fmt, sub_bytes):
                        note_disclosure(
                            ctx.disclosures,
                            "recognised_binary_media",
                            sub_relpath,
                            f"{sub_relpath} is a recognised, well-terminated {sub_fmt} "
                            "file; it was not content-scanned (binary) but is not "
                            "flagged as an unexpected binary.",
                        )
                    else:
                        ctx.binary_files.append(sub_relpath)
                    # F-054: a native executable (ELF/PE/Mach-O/JVM class) bundled inside a
                    # skill is a stowaway — skills are text/config; a compiled binary the
                    # prose doesn't need has no business here. Recorded for a WARN.
                    if sub_fmt in ("ELF", "PE", "class", "pyc", "wasm") or (sub_fmt or "").startswith("Mach-O"):
                        ctx.stowaway_files.append(f"{sub_relpath} ({sub_fmt})")
            
            # B-538: decode ONCE, here, and carry the text forward. The manifest entry
            # below is a claim about what the readers will actually receive, so it has to
            # be derived from the decode they get — not from the classifier's verdict on
            # a 4096-byte sample, which is how a UTF-16 file whose every reader saw
            # nothing but mojibake was still recorded `scanned-text`.
            sub_text, sub_enc = _decode_ladder(sub_bytes) if sub_class == "TEXT" else (None, None)
            if sub_class == "TEXT" and sub_text is None:
                # No rung of the ladder reads these bytes whole. Scan them anyway,
                # lossily: dropping the file would trade a false coverage claim for a
                # blind spot, which is the B-533 defect. The claim shrinks; the scan
                # does not.
                sub_text = sub_bytes.decode("utf-8", errors="replace")

            # How much the manifest is entitled to claim for this file. `scanned-text`
            # is reserved for a determined encoding — anything else says so, because a
            # PASS from the content ring is only as good as the characters it was given.
            qualifier = ""
            if sub_class == "TEXT":
                if sub_enc is None:
                    qualifier = "(lossy)"
                elif sub_enc == "latin-1" or sub_enc in _LEGACY_MULTIBYTE_CODECS:
                    # B-537: a guessed multi-byte codec is the SAME epistemic status as
                    # latin-1 -- validated structurally, never confirmed -- so it gets its
                    # own named qualifier rather than falling through to the bare
                    # `scanned-text` claim (which would say "read" without saying
                    # "assumed") or silently borrowing latin-1's label for a different
                    # codec (which would misname the assumption actually made).
                    qualifier = f"({sub_enc}-assumed)"
                    # B-616: ctx-level twin of the manifest qualifier above — the manifest
                    # string had exactly one reader (sarif.py); this is what lets
                    # dossier.py keep a prose-dependent axis from reading PASS over text
                    # this run never actually understood.
                    if ctx is not None and sub_relpath not in ctx.assumed_encoding_files:
                        ctx.assumed_encoding_files.append(sub_relpath)

            # Map statuses here!
            if ctx is not None:
                if sub_relpath not in ctx.file_manifest:
                    if sub_relpath.lower().endswith(".py"):
                        ctx.file_manifest[sub_relpath] = "scanned-ast" + qualifier
                    elif sub_class == "TEXT":
                        ctx.file_manifest[sub_relpath] = "scanned-text" + qualifier
                    else:
                        if sub_fmt not in ("ZIP", "tar", "gzip", "bz2", "xz"):
                            ctx.file_manifest[sub_relpath] = "binary-strings"

            collected.append({
                "relpath": sub_relpath,
                "content": sub_bytes,
                "text": sub_text,
                "classification": sub_class,
                "format": sub_fmt,
            })

    # F-061: flag filenames carrying homoglyph / RTL-override / zero-width obfuscation
    # (e.g. a Cyrillic-lookalike `helper.py`). Same detector used for MCP server names.
    if ctx is not None:
        for item in collected:
            if obfuscation_signals(item["relpath"]):
                ctx.filename_obfuscations.append(item["relpath"])

    if ctx is not None:
        ctx._collected_skill_files[str(skill_dir)] = collected

    return collected


# B-086: extensions/names scanned before the size/file cap can be hit. SKILL.md is
# always the highest-signal file; executable/script extensions are the next most
# likely place a real payload lives. Everything else keeps its original (alphabetical)
# relative order — the sort is stable, so ties are unaffected.
_HIGH_PRIORITY_SCAN_EXTS = (".sh", ".bash", ".py", ".mjs", ".js", ".ps1")


def _skill_scan_priority(item: dict) -> tuple[int, str]:
    relpath = item.get("relpath", "")
    name = Path(relpath).name
    if name == "SKILL.md":
        tier = 0
    elif name.lower().endswith(_HIGH_PRIORITY_SCAN_EXTS):
        tier = 1
    else:
        tier = 2
    return (tier, relpath)


# B-305 follow-up (C-135 adversarial finding, round 2): this function injects a
# "# file: <name>\n" section header ahead of every concatenated file's content
# (used below). checks/_shared.py's `_MANIFEST_HEADER_RE` reads that literal shape
# to recover per-file section boundaries, and checks/_content.py's
# `_pos_in_source_code_section` trusts each boundary it finds to EXEMPT everything
# up to the next header from the natural-language-directive ring (an unfenced
# `.py`/`.sh` file is source code, never a live instruction). The bug: this
# function concatenates each file's RAW, attacker-controlled bytes verbatim, with
# no escaping of a "# file:"-shaped line the file's own content already contains —
# so a single-file skill can write its own "# file: notes.py" line inside e.g. its
# SKILL.md body and, once concatenated, that forged line is byte-for-byte
# indistinguishable from a header THIS function actually inserted. From blob text
# alone there is no lexical property that tells the two apart (a keyword/regex
# patch at the consuming end would be the exact whack-a-mole this project's
# CLAUDE.md warns against — and provably unsound here, since real and forged
# headers are identical strings). The only sound fix is structural: make the
# header un-forgeable by construction. Since THIS function is the sole place that
# ever legitimately writes a "# file: <name>" line, escaping every confusable line
# already present in a file's OWN text — before concatenation — guarantees every
# such line surviving in the assembled blob is one this function itself inserted.
#
# ROUND 2 (the C-135 reviewer broke round 1): round 1 matched the literal ASCII
# prefix "# file:" against the RAW, pre-normalization line. But every consuming
# check runs `normalize_for_scan()` on the assembled blob BEFORE `_MANIFEST_
# HEADER_RE.finditer()` — and `normalize_for_scan` strips invisible/bidi
# characters (and folds Tag-block "ASCII smuggling" runs, and confusable
# homoglyphs) as its very first steps. So a line that does NOT literally start
# with "# file:" in raw form (e.g. a zero-width space, or an entirely
# Tag-block-encoded "# file: evil.py" run that is *invisible* until decoded) can
# still normalize to a real header at scan time, reopening the exact bypass the
# round-1 fix targeted. The fix is again structural, not a wider keyword list:
# escape a RAW line whenever its *normalized* form — the exact text the
# consuming regex actually matches against — starts with the header prefix,
# regardless of which raw characters (literal, invisible, or Tag-encoded)
# produce that normalized shape. Escaping still only ever prepends one literal
# backslash to the RAW line (leaving every original character, visible or
# invisible, in place) so: (a) the line stays fully scannable by every content
# check, and (b) B58's own `obfuscation_signals()` — which reads the RAW text
# for zero-width/bidi/Tag-run evidence — is completely unaffected; only the
# header-matching prefix is defeated, nothing is stripped or hidden from any
# other detector.
_MANIFEST_HEADER_PREFIX = "# file:"


def _escape_embedded_header_lines(text: str) -> str:
    """Neutralize any line in *text* that would be shaped like the '# file:
    <name>' section header `_read_skill_text` injects ONCE IT IS NORMALIZED
    the same way every consuming check normalizes the assembled blob before
    matching `_MANIFEST_HEADER_RE` against it (B-305/C-135 — see the comment
    above for why raw-text-only matching is unsound).

    Decides per RAW line using `normalize_for_scan(line)` — the identical
    de-obfuscation pass (invisible/bidi strip, Tag-block fold, confusable fold)
    every consuming check already applies — so a line can never look
    header-shaped at scan time without also looking header-shaped here. When a
    line's normalized form starts with the header prefix, a literal backslash
    is prepended to the RAW line (its original characters — including any
    invisible/confusable/Tag-block ones — are left completely untouched), which
    survives normalization (backslash passes through every step unchanged) and
    moves the *normalized* line's first character off '#', so
    `_MANIFEST_HEADER_RE` can no longer match there.

    `normalize_for_scan` only ever substitutes or deletes individual code
    points — it never inserts, deletes, or reorders the U+000A line-terminator
    itself — so a raw line and its normalized counterpart are always at the
    same line index; if that invariant is ever violated (e.g. a future
    textnorm.py change), this degrades to a plain literal-prefix check on the
    raw line rather than risk misaligned per-line indexing.
    """
    raw_lines = text.split("\n")
    normalized = normalize_for_scan(text)
    norm_lines = normalized.split("\n")
    if len(norm_lines) != len(raw_lines):
        return "\n".join(
            ("\\" + line) if line.startswith(_MANIFEST_HEADER_PREFIX) else line
            for line in raw_lines
        )
    changed = False
    for i, norm_line in enumerate(norm_lines):
        if norm_line.startswith(_MANIFEST_HEADER_PREFIX):
            raw_lines[i] = "\\" + raw_lines[i]
            changed = True
    return "\n".join(raw_lines) if changed else text


def _collected_text(item: dict) -> str:
    """The text a reader must scan for one collected file.

    B-538: `collect_skill_files` already decoded these bytes with the full ladder and
    recorded the manifest claim from that result, so the readers have to use THAT string.
    Decoding a second time here with a bare `errors="replace"` is exactly what turned a
    correctly-classified cp1251 or UTF-16 file into mojibake *after* the manifest had
    promised `scanned-text`.

    The fallback covers items built outside `collect_skill_files` (tests, other callers)
    and runs the same ladder, so no path can quietly go back to a UTF-8-only reading.
    """
    text = item.get("text")
    if text is not None:
        return text
    content = item["content"]
    decoded = decode_scanned_text(content)
    return decoded if decoded is not None else content.decode("utf-8", errors="replace")


def _read_skill_text(skill_dir: Path, ctx: Context | None = None) -> str:
    """Concatenate the text/code files of one installed skill (capped, read-only).

    B-086: files are scanned in RISK-PRIORITY order, not the raw alphabetical walk
    order — SKILL.md first, then executable/script extensions, then everything
    else (stable within each tier). A padded low-risk decoy file (e.g. `AAA_ref.md`)
    can no longer push a genuinely higher-signal file out of the scan budget just
    by sorting first alphabetically. Does not mutate collect_skill_files's own
    (cached) ordering — only this local copy.

    B-305/C-135: every file's own text is escaped (`_escape_embedded_header_lines`)
    before the real header is prepended, so a file cannot forge a "# file: <name>"
    boundary of its own — see that function's docstring.
    """
    collected = sorted(collect_skill_files(skill_dir, ctx), key=_skill_scan_priority)
    parts = []
    total = 0
    file_count = 0
    truncated = False

    for item in collected:
        if total >= _MAX_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            truncated = True  # B-074: more content existed than we scanned
            break
        if item["classification"] != "TEXT":
            continue

        text = _collected_text(item)
        budget = _MAX_BYTES_PER_SKILL - total
        if len(text) > budget:
            truncated = True  # this file was sliced — its tail is unscanned
            # F-087: sample the CUT tail (bounded — never re-reads the whole file) and
            # measure its entropy. Low-entropy filler is the shape of deliberate
            # cap-evasion padding; a real high-entropy asset leaves no anomaly signal.
            tail_sample = text[budget : budget + _ENTROPY_SAMPLE_BYTES]
            if (
                ctx is not None
                and len(tail_sample) >= _ENTROPY_MIN_SAMPLE
                and _shannon_entropy_bits(tail_sample) < _PADDING_ENTROPY_THRESHOLD
            ):
                ctx.padding_anomalies.append(skill_dir.name)
        chunk = text[:budget]
        safe_chunk = _escape_embedded_header_lines(chunk)
        parts.append(f"# file: {Path(item['relpath']).name}\n{safe_chunk}")
        total += len(chunk)
        file_count += 1

    # B-074: silent truncation reads as "fully covered" and lets a payload padded past the
    # cap escape. Record the cap hit so check_installed_skills surfaces UNKNOWN, not PASS.
    if truncated and ctx is not None:
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
            f"text scan of skill '{skill_dir.name}' hit the "
            f"{_MAX_BYTES_PER_SKILL // 1000}KB/{_MAX_FILES_PER_SKILL}-file cap — "
            "content beyond the cap was NOT scanned",
        )

    return "\n".join(parts)


# B-267: budgets for skill_tree_signature() — the CHANGE-DETECTION walk, deliberately
# separate from and far wider than the malware-SCAN budgets above. The scan caps exist to
# bound regex/AST/entropy work on attacker-supplied content; fingerprinting costs one
# streamed sha256 per file, so it can cover ground the scanner never will. Measured on the
# real ~/.openclaw: the largest installed skill is 2,190 files / 7.5MB and fingerprints in
# ~0.65s — comfortably inside both budgets, and paid only on a --monitor run (snapshot() is
# the sole caller), never on a plain audit.
_SIG_MAX_FILES = 20_000
_SIG_MAX_TOTAL_BYTES = 200_000_000
_SIG_CHUNK = 1 << 20


def skill_tree_signature(skill_dir: Path) -> dict:
    """Fingerprint EVERY file under one skill directory, independent of the scan budget.

    Returns ``{"digest": str, "files": int, "bytes": int, "complete": bool}``.

    B-267: ``_read_skill_text`` builds the blob the audit SCANS — TEXT-classified files
    only, truncated at ``_MAX_BYTES_PER_SKILL``, with any single file over
    ``_MAX_FILE_BYTES`` dropped whole before the budget logic ever sees it. Hashing that
    blob (which is what monitor's ``_skill_sig`` used to do, alone) answers "did the part
    we scanned change?", and monitor was reporting the answer as "did the skill change?".
    Those differ precisely where it matters: swapping ``bin/helper`` (non-TEXT), appending
    a directive to a file past the per-skill budget, or editing inside an oversized
    ``REFERENCE.md`` all leave the scanned blob byte-identical. Verified first-hand — all
    three produced ZERO monitor alerts before this function existed.

    Change detection does not need the scan budget, so this walk does not inherit it. Each
    file contributes ``relpath\\0size\\0sha256(content)`` to a canonical, sorted fold, so
    the digest moves on any content edit, size change, addition, removal or rename —
    including in regions no scanner will ever read.

    ``complete`` is False when the walk itself hit ``_SIG_MAX_FILES`` /
    ``_SIG_MAX_TOTAL_BYTES``, i.e. part of the tree was never fingerprinted. An UNCHANGED
    digest is proof of no change only when ``complete`` is True; callers must treat the
    incomplete case as unknown rather than as evidence of stability (same discipline B-074
    applies to a truncated scan).

    NARROWS, does not close — two blind spots remain, both inherited deliberately:

    * ``__pycache__`` and VCS metadata (``.git``/``.hg``/``.svn``) are excluded, matching
      ``collect_skill_files``'s existing B-125 boundary. They are already outside the
      audited surface, and including them would fire a "skill CHANGED" alert on every
      ``git status`` or interpreter run — a false positive on ordinary use. A payload
      parked *only* inside ``.git/`` is therefore still invisible here, exactly as it is
      to every other part of the audit.
    * Symlinks are skipped (``walk_dir_safely``), so re-pointing a symlink inside a skill
      does not move the digest. Symlink entries are separately surfaced as tamper signals
      by F-061's ``symlink_skips``.

    Read-only and never raises: an unreadable file folds in a stable ``unreadable`` marker
    (stable, so a persistently chmod-000 file does not flap an alert every run) rather
    than being dropped silently, which would make it indistinguishable from a deletion.
    """
    capped: list = []
    files = walk_dir_safely(
        skill_dir,
        exclude_pycache=True,
        exclude_vcs=True,
        max_files=_SIG_MAX_FILES,
        capped=capped,
    )
    entries: list[tuple[str, str]] = []
    total = 0
    complete = not capped
    for f in sorted(files):
        try:
            rel = str(f.relative_to(skill_dir))
        except (ValueError, OSError):
            rel = f.name
        try:
            if not f.is_file():
                continue
            size = f.stat().st_size
        except OSError:
            entries.append((rel, "unreadable"))
            continue
        if total + size > _SIG_MAX_TOTAL_BYTES:
            # Budget exhausted: record the file's existence and size (both still real
            # evidence) but not its content digest, and declare the walk incomplete.
            entries.append((rel, f"{size}:uncovered"))
            complete = False
            continue
        digest = hashlib.sha256()
        try:
            with open(f, "rb") as fh:
                while True:
                    chunk = fh.read(_SIG_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError:
            entries.append((rel, "unreadable"))
            continue
        total += size
        entries.append((rel, f"{size}:{digest.hexdigest()}"))

    fold = hashlib.sha256()
    for rel, mark in sorted(entries):
        fold.update(rel.encode("utf-8", "replace"))
        fold.update(b"\x00")
        fold.update(mark.encode("ascii", "replace"))
        fold.update(b"\n")
    return {
        "digest": fold.hexdigest()[:32],
        "files": len(entries),
        "bytes": total,
        "complete": complete,
    }


def _ipynb_code_source(text: str, skill_name: str, ctx: "Context | None") -> str | None:
    """F-116: concatenate the source of a Jupyter notebook's `code` cells so the AST/taint
    engine (which otherwise sees only .py/.sh/.js) can analyze them. Returns joined Python
    source, or None when the notebook JSON can't be parsed — in which case a limit_hit is
    recorded so the AST layer degrades to UNKNOWN (AST_UNANALYZABLE), never a false PASS."""
    try:
        nb = json.loads(text)
        cells = nb["cells"]
        if not isinstance(cells, list):
            raise ValueError("cells is not a list")
    except (ValueError, KeyError, TypeError):
        if ctx is not None:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                f"notebook in skill '{skill_name}' could not be parsed — its code cells "
                "were NOT analyzed (AST_UNANALYZABLE)",
            )
        return None
    parts: list[str] = []
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        src = cell.get("source")
        if isinstance(src, list):
            parts.append("".join(s for s in src if isinstance(s, str)))
        elif isinstance(src, str):
            parts.append(src)
    return "\n".join(parts)


# ── B-548: which analyzer owns a file ────────────────────────────────────────
# The three readers below used to answer this from the file NAME alone, so an
# executable script with no extension — `urlgo`, `install`, `scripts/post_install`
# — landed in no bucket at all. That is not silence: every downstream coverage
# predicate short-circuits on an empty bucket and dossier.py then prints the
# POSITIVE claim "no executable code to analyze". Our own bad fixture shows the
# contradiction it produces — `fixtures/bad_b335_no_extension_installer` prints a
# WARN saying its `install` file writes auto-execution persistence, and one line
# below, that there was no executable code to analyse.
#
# Extension stays the fast path AND keeps priority: a file whose suffix any reader
# already claims is routed exactly as before, so this change cannot move a single
# file that is collected today. Only files claimed by NOTHING reach the shebang.
#
# Why the shebang and not the executable bit, counted over `fixtures/` plus the
# installed skills on the author's machine (1,298 files, 1,115 uncollected today):
#
#   uncollected files carrying a shebang        1   (the b335 fixture)
#   uncollected files with +x and no shebang    0
#
# Read that second row as "this machine has no subject", NOT as a fleet result:
# the installed-skills directory here holds two entries, so the corpus is really
# `fixtures/`. The exec bit is rejected on a stronger argument than the count —
# it does not survive a git checkout or a tarball, so a payload loses it in
# transit and a benign file gains one by accident.
#
# WHAT THIS DELIBERATELY DOES NOT CLOSE (independent C-135, 2026-08-23). A file
# with NEITHER an extension nor a shebang is still collected by nothing, and
# skills name the interpreter in SKILL.md prose (`Run `python3 bin/lint``), so
# that shape is the common one, not the exotic one. Measured: a bundled
# `bin/lint` that reads ~/.openclaw/credentials.json and posts it to a remote
# host still renders INSTALL with Danger PASS. The same holds for a payload
# given a data suffix (`setup.json` carrying `#!/bin/bash`), which the
# _NON_CODE_SUFFIXES gate below excludes before the shebang is read. Both are
# exactly as invisible as they were before this change — neither is a regression
# — and both are B-612, which routes on the interpreter the SKILL.md names.
# `tests/test_b548_language_by_content.py` pins both as open, so this fix cannot
# be read as broader than it is.
#
# A DISCLOSURE ARM WAS BUILT HERE AND RETRACTED, same review. It recorded a
# `note_limit` for a shebang naming an interpreter we do not parse (perl, ruby).
# Three independent defects, any one fatal: (a) LIMIT_DOMAIN_SKILL's only
# renderer is the size/file-cap verdict, so a two-line Ruby CSV formatter printed
# "Content beyond the size/file cap was not scanned ... split oversized files" —
# a fabricated cause, and it moved a benign skill from `1 safe`/rc 0 to
# `1 partially scanned`/rc 1 (Golden Rule #5); (b) the same text was printed for
# a `.md` excluded by suffix, calling python3 "an interpreter this scanner does
# not analyze"; (c) it never reached the screen at all when a real FAIL outranked
# it. The scanner did not read ruby before this change either, so coverage never
# moved — only the claim did. `ctx.limit_hits` carries verdict weight
# (dossier._danger_coverage_gap leg 2); it is not a notepad. If this disclosure
# is wanted, it needs its own non-verdict channel, the precedent being
# NPM_DEPTREE_SKILL_COVERAGE_NOTE (C-358: evidence only, never detail).
_PY_SUFFIXES = (".py", ".ipynb")
_SH_SUFFIXES = (".sh", ".bash", ".zsh")
_JS_SUFFIXES = (".js", ".ts", ".mjs", ".cjs")

# Interpreter stems, after the basename is lowercased and a trailing version
# ("3", "3.11", "20") is stripped. Deliberately strict: an interpreter we do not
# model is NOT guessed into a bucket — a `#!/usr/bin/env ruby` file handed to
# analyze_shell would produce findings about a language nobody parsed. It is
# disclosed instead (see read_skill_python).
# Suffixes that name DATA or PROSE. A file with one of these never reaches the
# shebang route, however its first bytes read. Two reasons, and the second is the
# load-bearing one: a `README.md` opening with `#!` is a Markdown heading, not a
# script — `#` starts a comment or a heading in a dozen formats — and the prose
# surface is already scanned by the content ring, so routing it to the AST layer
# would double-count it under a language nobody wrote it in. Measured count of
# such files across fixtures + the real fleet: zero. The rule is here because a
# discriminator with no subject today is still the wrong discriminator.
_NON_CODE_SUFFIXES = (
    ".md", ".markdown", ".rst", ".txt", ".json", ".jsonl", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".csv", ".tsv", ".xml", ".html", ".htm", ".css",
    ".lock", ".log", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".tar", ".whl", ".so", ".dylib",
    ".dll", ".exe", ".class", ".pyc", ".pyi",
)

_SHEBANG_SH_STEMS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
_SHEBANG_JS_STEMS = frozenset({"node", "nodejs", "deno", "bun"})
_VERSION_TAIL_RE = re.compile(r"[0-9.]+$")


def _shebang_language(text: str) -> str | None:
    """The analyzer a `#!` line names: "py", "sh", "js", or None.

    None covers both "no shebang" and "an interpreter we do not model", and callers do
    NOT distinguish them. An earlier revision did, to disclose the second as a coverage
    gap; that arm was retracted (see the block comment above) because the scanner never
    read those languages either way, so the disclosure moved the claim without moving
    the coverage — and it moved a benign skill's exit code with it.
    """
    if not text.startswith("#!"):
        return None
    line = text.splitlines()[0][:256] if text else ""
    tokens = line[2:].strip().split()
    if not tokens:
        return None
    interp = tokens[0]
    if PurePosixPath(interp).name.lower() == "env":
        # `#!/usr/bin/env python3`, and its two real variants: `env -S python3 -u`
        # (a flag) and `env VAR=1 python3` (an assignment). Skip both to reach the
        # interpreter; anything else is the interpreter.
        interp = ""
        for tok in tokens[1:]:
            if tok.startswith("-") or ("=" in tok and "/" not in tok):
                continue
            interp = tok
            break
        if not interp:
            return None
    stem = PurePosixPath(interp).name.lower()
    if stem.startswith("python"):
        return "py"
    stem = _VERSION_TAIL_RE.sub("", stem) or stem
    if stem == "pypy":
        return "py"
    if stem in _SHEBANG_SH_STEMS:
        return "sh"
    if stem in _SHEBANG_JS_STEMS:
        return "js"
    return None


def _file_language(relpath: str, text: str) -> str | None:
    """Which of the three readers owns *relpath*, extension first then shebang."""
    rel = relpath.lower()
    if rel.endswith(_PY_SUFFIXES):
        return "py"
    if rel.endswith(_SH_SUFFIXES):
        return "sh"
    if rel.endswith(_JS_SUFFIXES):
        return "js"
    if rel.endswith(_NON_CODE_SUFFIXES):
        return None
    return _shebang_language(text)


def read_skill_python(skill_dir: Path, ctx: Context | None = None) -> list[tuple[str, str]]:
    """Collect the Python source files of one skill for read-only AST analysis.

    Returns a list of (relative-path, source) pairs. F-116: Jupyter `.ipynb` notebooks are
    included — their code cells are routed to the SAME engine as `.py`.
    """
    collected = collect_skill_files(skill_dir, ctx)
    out: list[tuple[str, str]] = []
    total = 0
    file_count = 0
    truncated = False

    for item in collected:
        if total >= _MAX_PY_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            truncated = True
            break
        if item["classification"] != "TEXT":
            continue
        rel = item["relpath"].lower()
        text = _collected_text(item)
        if _file_language(item["relpath"], text) != "py":
            continue

        if rel.endswith(".ipynb"):
            # F-116: route the notebook's code cells through the same AST/taint engine as .py.
            src = _ipynb_code_source(text, skill_dir.name, ctx)
            if src is None:
                continue  # malformed notebook -> limit_hit recorded; degrade to UNKNOWN
            text = src
        out.append((item["relpath"], text))
        total += len(text)
        file_count += 1

    # B-074: record when Python collection was capped so the AST/taint layer's blind spot
    # (unscanned .py beyond the cap) surfaces as UNKNOWN rather than a clean PASS.
    if truncated and ctx is not None:
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
            f"Python scan of skill '{skill_dir.name}' hit the "
            f"{_MAX_PY_BYTES_PER_SKILL // 1000}KB/{_MAX_FILES_PER_SKILL}-file cap — "
            ".py content beyond the cap was NOT analyzed",
        )

    return out


def read_skill_shell(skill_dir: Path, ctx: Context | None = None) -> list[tuple[str, str]]:
    """Collect the shell source files (.sh/.bash/.zsh) of one skill for a read-only
    regex/token pass (F-050). Returns a list of (relative-path, source) pairs. Same byte /
    file caps as the Python collector so a padded bundle can't blow up the scan."""
    collected = collect_skill_files(skill_dir, ctx)
    out: list[tuple[str, str]] = []
    total = 0
    file_count = 0
    truncated = False
    for item in collected:
        if total >= _MAX_PY_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            truncated = True
            break
        if item["classification"] != "TEXT":
            continue
        text = _collected_text(item)
        if _file_language(item["relpath"], text) != "sh":
            continue
        out.append((item["relpath"], text))
        total += len(text)
        file_count += 1

    # B-074: record when shell collection was capped so a padded shell payload beyond the
    # cap surfaces as UNKNOWN rather than a clean PASS (mirrors read_skill_python).
    if truncated and ctx is not None:
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
            f"shell scan of skill '{skill_dir.name}' hit the "
            f"{_MAX_PY_BYTES_PER_SKILL // 1000}KB/{_MAX_FILES_PER_SKILL}-file cap — "
            "shell content beyond the cap was NOT scanned",
        )

    return out


def read_skill_js(skill_dir: Path, ctx: Context | None = None) -> list[tuple[str, str]]:
    """Collect the JS/TS source files (.js/.ts/.mjs/.cjs) of one skill for a read-only
    lexical pass (F-064). Returns a list of (relative-path, source) pairs. Same byte /
    file caps as the Python and shell collectors so a padded bundle can't blow up the scan."""
    collected = collect_skill_files(skill_dir, ctx)
    out: list[tuple[str, str]] = []
    total = 0
    file_count = 0
    truncated = False
    for item in collected:
        if total >= _MAX_PY_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            truncated = True
            break
        if item["classification"] != "TEXT":
            continue
        text = _collected_text(item)
        if _file_language(item["relpath"], text) != "js":
            continue
        out.append((item["relpath"], text))
        total += len(text)
        file_count += 1

    # B-074: record when JS collection was capped so a padded JS payload beyond the cap
    # surfaces as UNKNOWN rather than a clean PASS (mirrors read_skill_python/read_skill_shell).
    if truncated and ctx is not None:
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
            f"js scan of skill '{skill_dir.name}' hit the "
            f"{_MAX_PY_BYTES_PER_SKILL // 1000}KB/{_MAX_FILES_PER_SKILL}-file cap — "
            "js content beyond the cap was NOT scanned",
        )

    return out


# OpenClaw's own default when an agent id is absent or blank — `DEFAULT_AGENT_ID = "main"`
# in `dist/monitor.account-*.js`. Ours must agree or the "is this the default agent?" test
# below picks a different branch than the product does.
DEFAULT_AGENT_ID = "main"


# Spelled with BOTH cases instead of `re.IGNORECASE`, deliberately. JS's `/i` without
# the `u` flag does not case-fold non-ASCII, while Python's IGNORECASE does — so
# `re.IGNORECASE` accepted U+0130 `İ`, U+0131 `ı` and U+017F `ſ` as valid ASCII
# letters and returned them unsanitised. Measured against the real dist function over a
# 65,504-codepoint BMP sweep: those three were the ONLY divergences, and an id like
# `İstanbul` is a perfectly ordinary Turkish agent name whose workspace we would then
# have kept looking for in the wrong directory.
_JS_TRIM_CHARS = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)

_VALID_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_INVALID_AGENT_ID_CHARS_RE = re.compile(r"[^a-z0-9_-]+")


def _normalize_agent_id(value) -> str:
    """OpenClaw's `normalizeAgentId`, transcribed from the copy the workspace resolver binds.

    ```js
    /** Normalize user or config agent ids to the filesystem-safe canonical form. */
    function normalizeAgentId(value) {
        const trimmed = (value ?? "").trim();
        if (!trimmed) return DEFAULT_AGENT_ID;
        const normalized = normalizeLowercaseStringOrEmpty(trimmed);
        if (VALID_ID_RE.test(trimmed)) return normalized;
        return normalized.replace(INVALID_CHARS_RE, "-").replace(LEADING_DASH_RE, "")
                         .replace(TRAILING_DASH_RE, "").slice(0, 64) || DEFAULT_AGENT_ID;
    }
    ```

    with `VALID_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i` and `INVALID_CHARS_RE = /[^a-z0-9_-]+/g`.

    **There are SIX copies of this function in the dist and they do not agree.** Two
    (`monitor.account-*.js`, `telegram-ingress-spool-*.js`) are a bare
    `trim().toLowerCase() || DEFAULT_AGENT_ID`; the other four sanitise. The first version of
    this port transcribed a bare one — found by grepping for the first definition rather than
    by following what the caller binds — and asserted in its own docstring that the product
    "does not sanitise the value as a path segment". The opposite is true, and the function's
    own comment says so. The copy that matters is the one in the same module as
    `resolveAgentWorkspaceDir` (`config-utils-*.js`), which is the sanitising one.

    Getting this wrong left the hole open for ordinary ids: `Work Laptop` becomes
    `work-laptop`, so OpenClaw uses `workspace-work-laptop` while we derived
    `workspace-work laptop` and read nothing. Measured end to end — `installed_skills == {}`
    against a control of `{'evil': ...}`. It also closed a hazard by accident: a sanitised id
    can no longer contain a path separator, so a derived root cannot escape the state dir
    through the id at all.

    Note `VALID_ID_RE` is tested against the TRIMMED original (case-insensitively) while the
    value returned is the lowercased one — an id that is already valid is never sliced.
    """
    # `String.trim()`, not `str.strip()`: Python strips \x1c-\x1f and \x85 which JS keeps,
    # and keeps \ufeff which JS strips. Only observable when the difference exposes an
    # outer dash to VALID_ID_RE, but "only observable sometimes" is how a transcription
    # bug hides.
    trimmed = (value if isinstance(value, str) else "").strip(_JS_TRIM_CHARS)
    if not trimmed:
        return DEFAULT_AGENT_ID
    normalized = trimmed.lower()
    if _VALID_AGENT_ID_RE.match(trimmed):
        return normalized
    normalized = _INVALID_AGENT_ID_CHARS_RE.sub("-", normalized)
    return normalized.strip("-")[:64] or DEFAULT_AGENT_ID


@dataclass(frozen=True)
class AgentEntry:
    """One agent from the roster, in whichever shape the config declares it.

    ``id``    the agent's id: the RECORD KEY under ``agents.entries``, or the entry's own
              ``id`` field under legacy ``agents.list`` (``None`` when it has none).
    ``entry`` the agent's own config object. Under ``agents.entries`` this is a NEW dict
              with ``id`` injected, so a caller that reads ``entry["id"]`` keeps working.
    ``path``  the config path this entry actually sits at, for evidence strings:
              ``agents.entries.web`` or ``agents.list[0]``. Never build that label by hand
              -- a 2026.8.1 user pointed at ``agents.list[0]`` is pointed at a key their
              file does not contain.
    ``index`` position. For ``agents.list`` it is the ORIGINAL array index, matching the
              vendor's ``source.index`` and the user's own file, so a label built from it
              is byte-identical to the one this tool emitted before B-699. For
              ``agents.entries`` there is no vendor equivalent: it is our own enumeration
              order over the record, offered only as a last-resort display fallback for a
              nameless entry.
    """

    id: "str | None"
    entry: dict
    path: str
    index: int

    def labelled(self, name) -> str:
        """``agents.list[<name>]`` / ``agents.entries.<name>`` -- the CALLER's own name for
        this agent, placed in the container it really came from.

        Use this, not ``path``, wherever the existing label carries meaning that a position
        does not. B351 labels an entry by the id the runtime RESOLVES it to, which is not
        the same thing as where it sits: an entry with no ``id`` resolves to ``main``, and
        ``agents.list[main]`` is the honest label while ``agents.list[0]`` is merely true.
        Rewriting those to ``path`` erased that distinction and its own test caught it.
        """
        if self.path.startswith("agents.entries."):
            return f"agents.entries.{name}"
        return f"agents.list[{name}]"


def agent_roster(cfg) -> "list[AgentEntry]":
    """Every declared agent, from EITHER roster shape. The one place that knows both.

    B-699. OpenClaw 2026.8.1 replaced ``agents.list`` (an ARRAY whose entries carry an
    ``id`` field) with ``agents.entries`` (a RECORD keyed by id, which REJECTS an ``id``
    field inside an entry). We read only the array, so on a 2026.8.1 config every
    per-agent check saw an empty roster -- and several then asserted a clean verdict about
    it. Measured on our own shipped bad-fixtures: `bad_b4_peragent_sandbox` went B4 FAIL ->
    PASS "Execution is sandboxed", `warn_b409_profile_alsoallow_widening` went A1 WARN ->
    PASS. Golden Rule #4, on configs our own fixtures call dangerous.

    Both shapes are read, permanently. OpenClaw's migration is DEFERRED -- it runs inside
    ``openclaw doctor --fix`` -- so an un-migrated config still carries ``agents.list`` on
    disk while the new schema rejects it, and a user on an older OpenClaw is not migrating
    at all. Switching outright would trade the fake PASS for a silent UNKNOWN on every
    un-migrated config. Same rule and same shape as ``checks/_shared.py::_mcp_servers``,
    which merges ``mcp.servers`` with the legacy spellings behind one accessor.

    A faithful port of ``readAgentRosterProperty`` + ``listAgentEntriesWithSource``
    (``dist/agent-scope-config-*.js``), whose semantics were EXECUTED rather than read --
    the first reading of them was wrong twice:

    * **The KEY wins over an entry's own ``id``.** ``listAgentEntriesWithSource`` builds
      ``{...entry, id}``, so ``{web: {id: "OTHER"}}`` is agent ``web``. The legacy module
      ``legacy-*.js`` still carries the opposite (``Object.assign({id}, entry)``, entry
      wins); the modern one governs. Measured, not inferred.
    * **``entries`` is chosen when the KEY is present, not when the value is usable.**
      ``{"entries": null}`` and ``{"entries": "junk"}`` both yield an EMPTY roster and the
      ``list`` beside them is NOT consulted. Reading it as "try entries, else list" would
      make us disagree with the runtime about which agents exist.

    The one deliberate divergence: an element of ``agents.list`` that is a JSON array is
    kept by the vendor (its guard is ``typeof entry === "object"``) and dropped here, because
    every consumer calls ``.get()`` on what it receives. Unreachable in a schema-valid
    config -- ``safeParse`` rejects a non-object list element -- and dropping is the safe
    direction for the one shape that can only arrive on a hand-edited file.

    Index labels use the ORIGINAL array position, not the position after filtering: a
    ``list`` of ``[null, {...}]`` labels the surviving entry ``agents.list[1]``, matching
    the vendor's ``source.index`` and the user's own file.
    """
    if not isinstance(cfg, dict):
        return []
    agents = cfg.get("agents")
    if not isinstance(agents, dict):
        return []
    if "entries" in agents:
        value = agents["entries"]
        if not isinstance(value, dict):
            return []
        return [
            AgentEntry(id=key, entry={**val, "id": key},
                       path=f"agents.entries.{key}", index=order)
            for order, (key, val) in enumerate(
                (k, v) for k, v in value.items()
                if isinstance(k, str) and isinstance(v, dict))
        ]
    if "list" in agents:
        # Read through `dig` so the legacy path stays a dig() path and keeps its entry in
        # `tests/grounded_schema_paths.txt` -- where it is registered in
        # `_NOT_IN_CURRENT_SCHEMA`, because `agents.list` no longer resolves against
        # 2026.8.2 (measured: `_dist_accepts("agents.list", ...)` -> False).
        # `agents.entries` is still NOT read that way, but the ORIGINAL reason has
        # expired: the deferral was that the manifest entry needed vouching by
        # `tests/dist_verified_paths.txt` while that snapshot was stamped 2026.7.1-2. It
        # has since been regenerated against 2026.8.2, where `agents.entries` DOES
        # resolve (measured -> True, against a bogus-key control -> False). So this is
        # now ordinary outstanding work with no blocker, not a step waiting on the
        # upgrade -- do not read this comment as saying it cannot be done yet.
        value = dig(cfg, "agents.list")
        if not isinstance(value, list):
            return []
        out: "list[AgentEntry]" = []
        for index, val in enumerate(value):
            if not isinstance(val, dict):
                continue
            aid = val.get("id")
            out.append(AgentEntry(
                id=aid if isinstance(aid, str) else None,
                entry=val,
                path=f"agents.list[{index}]",
                index=index,
            ))
        return out
    return []


def _default_agent_id(agents_list) -> str:
    """OpenClaw's `resolveDefaultAgentId`: the entry flagged `default`, else the FIRST one.

    ```js
    const chosen = (agents.find((agent) => agent?.default) ?? agents[0])?.id;
    return normalizeAgentId(chosen);
    ```

    The "else the first one" half is the part that is easy to get wrong and changes the
    answer completely: with a SINGLE entry in `agents.list`, that entry IS the default agent,
    so its workspace is the ordinary `workspace` directory and nothing is derived at all. A
    first measurement of this defect used a one-agent config and drew the wrong conclusion
    from it (B-610).
    """
    chosen = None
    for entry in agents_list:
        if isinstance(entry, dict) and entry.get("default"):
            chosen = entry
            break
    if chosen is None and agents_list:
        # `agents[0]` unconditionally, NOT the first dict. A truthy non-object entry survives
        # JS's own `listAgentEntries` filter (it drops only falsy ones), and `"junk"?.id` is
        # `undefined`, which normalises to the default id. Skipping to the first dict picked a
        # different default agent than the product does, and therefore derived a different set
        # of workspaces.
        chosen = agents_list[0]
    return _normalize_agent_id(chosen.get("id") if isinstance(chosen, dict) else None)


def _derived_agent_workspaces(cfg: dict) -> "list[str]":
    """The workspace directories OpenClaw DERIVES for configured agents (B-610).

    `resolveAgentWorkspaceDir` (`dist/config-utils-*.js`) has four branches in priority
    order, and until B-610 this project implemented only the first two:

    1. the agent's own `workspace`, if set;
    2. for the DEFAULT agent, `agents.defaults.workspace` or the plain `workspace` dir;
    3. otherwise, if `agents.defaults.workspace` is set, ``join(that, id)``;
    4. otherwise ``join(stateDir, "workspace-" + id)``.

    Rules 3 and 4 were never constructed, so every NON-default agent's entire workspace —
    its `skills/`, its bootstrap files, its memory — was invisible to the audit whenever the
    user had not hand-written a `workspace` path for it. Measured end to end: the same
    malicious SKILL.md produced B13 under `workspace` and nothing at all under
    `workspace-personal` with a matching two-agent config.

    Returns raw strings; the caller resolves them against *home* and de-duplicates, so a
    derived path that coincides with one already searched costs nothing.

    Only entries carrying a **string** `id` get a derived path, matching
    `listAgentWorkspaceDirs`, which skips the rest. An entry's explicit `workspace` is still
    collected by the caller whether or not it has an id — narrowing that would scan less than
    before, and no fix for a blind spot may open a new one.

    NOT implemented, and disclosed rather than left implicit: `resolveDefaultAgentWorkspaceDir`
    also honours the `OPENCLAW_PROFILE` environment variable, under which the DEFAULT agent's
    workspace becomes `workspace-{profile}`. The environment an agent runs under is not
    knowable from a config file, so that one stays a documented limit.
    """
    # B-699: BOTH roster shapes. Reading only `agents.list` made this return [] on a
    # 2026.8.1 config, so every non-default agent's derived workspace stopped being
    # scanned -- the same blind spot B-610 opened this function to close.
    roster = agent_roster(cfg)
    if not roster:
        return []
    default_workspace = dig(cfg, "agents.defaults.workspace")
    fallback = default_workspace.strip() if isinstance(default_workspace, str) else ""
    # `agent_roster` injects the record KEY as `id` on the entries shape, so
    # `_default_agent_id` keeps reading `entry["id"]` and needs no change.
    default_id = _default_agent_id([a.entry for a in roster])
    out: list[str] = []
    for entry in (a.entry for a in roster):
        if not isinstance(entry.get("id"), str):
            continue
        own = entry.get("workspace")
        if isinstance(own, str) and own.strip():
            continue  # rule 1 — the caller already collects it
        agent_id = _normalize_agent_id(entry.get("id"))
        if agent_id == default_id:
            continue  # rule 2 — `fallback`, or the plain `workspace` in WORKSPACE_DIRS
        out.append(str(Path(fallback) / agent_id) if fallback else f"workspace-{agent_id}")
    return out


def _config_workspace_dirs(
    home: Path, cfg: dict, limit_hits: list[str] | None = None,
    disclosures: list | None = None,
) -> list[Path]:
    """Absolute workspace dir(s) declared in openclaw.json (B-161).

    OpenClaw's ``agents.defaults.workspace`` — and any per-agent
    ``agents.list[].workspace`` override — can point the agent's workspace outside the
    hardcoded WORKSPACE_DIRS names. Bootstrap files and a ``skills/`` dir living there
    would otherwise be invisible, so a malicious SOUL.md / skill in a custom workspace
    scored clean. Returns de-duplicated absolute, RESOLVED dirs (relative paths resolved
    against *home*). Never raises; blank / non-string values are skipped. When the value
    points at the default location it resolves to a path SKILL_DIRS already covers, so
    nothing is scanned twice (see the resolved-path de-dup in the callers).

    B-169: real OpenClaw does not confine ``workspace`` under the user's home
    (``resolveUserPath`` has no home-check), so a workspace that resolves OUTSIDE *home*
    is legitimate and MUST still be scanned — rejecting it would be a false-positive
    FAIL/skip (Golden Rule #5). Instead, when *limit_hits* is given and a workspace
    resolves outside *home*, one de-duplicated disclosure line is appended so the report
    stays transparent about the scan's actual scope.
    """
    if not isinstance(cfg, dict):
        return []
    raw: list[str] = []
    dv = dig(cfg, "agents.defaults.workspace")
    if isinstance(dv, str) and dv.strip():
        raw.append(dv)
    # B-699: BOTH roster shapes. This is a SCAN-SURFACE read, not a verdict: a per-agent
    # workspace missed here takes its skills, bootstrap files and memory out of the audit
    # entirely, and the content ring then reports clean about files it never opened.
    for agent in agent_roster(cfg):
        w = agent.entry.get("workspace")
        if isinstance(w, str) and w.strip():
            raw.append(w)
    # B-610: the two rules OpenClaw applies when an agent has NO explicit workspace.
    raw.extend(_derived_agent_workspaces(cfg))
    try:
        resolved_home = home.resolve()
    except (OSError, ValueError, RuntimeError):
        resolved_home = home
    out: list[Path] = []
    seen: set[Path] = set()
    for r in raw:
        p = Path(r).expanduser()
        if not p.is_absolute():
            p = home / p
        try:
            resolved = p.resolve()
        except (OSError, ValueError, RuntimeError):
            # An unusable workspace path — embedded null byte (ValueError), symlink loop /
            # over-deep (RuntimeError), or an OS error — must be skipped, never crash the
            # audit. Dropping it here also stops a later is_dir() from raising on it (C-135).
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if limit_hits is not None or disclosures is not None:
            try:
                in_home = resolved.is_relative_to(resolved_home)
            except (OSError, ValueError):
                in_home = False
            if not in_home:
                if limit_hits is not None:
                    msg = (
                        f"custom workspace '{resolved.name}' resolves outside the audited "
                        f"--home ({resolved}) — bootstrap/skills read from there are outside "
                        "the scoped audit"
                    )
                    if msg not in limit_hits:
                        note_limit(
                            limit_hits, LIMIT_DOMAIN_SKILL,
                            msg,
                        )
                # B-617: DUAL-WRITE, and the two sinks say deliberately different things.
                # The limit_hits entry above is left byte-identical because three
                # consumers already depend on its exact text and truthiness — B13's
                # UNKNOWN (checks/_vet.py), dossier leg 2, and cli.sweep_installed_skills
                # — so changing it would move verdicts. It also interpolates the ABSOLUTE
                # path, which is why it must never be rendered into human text (sarif.py
                # copies limit_hits verbatim and already carries `/home/<user>/...`).
                # The disclosure below is the renderable half: a bare name, no path.
                note_disclosure(
                    disclosures,
                    "workspace_outside_home",
                    resolved.name,
                    f"the workspace '{resolved.name}' resolves outside the audited "
                    "--home, and this run read bootstrap files and skills from it",
                )
        out.append(resolved)
    return out


def _is_own_source(p: Path) -> bool:
    """True if `p` is ClawSecCheck's own source tree (repo root, install dir, or the
    package dir itself). A security auditor necessarily ships attack signatures and
    red-team payloads as *data*, so a naive malware scan of its own source self-flags.

    Recognition is by structure (package layout) AND distinctive engine symbols — not
    by name alone — so a look-alike skill that merely calls itself "clawseccheck" is
    still scanned normally and cannot use the name to dodge detection.

    B-265: this is the single self-identity oracle for BOTH surfaces. It used to be
    reachable only from `vet_skill` (it lived in `checks/_shared.py`, a Layer-2 module
    the Layer-1 collector must not import), while skill *discovery* self-excluded on the
    bare directory basename. That let `mv evil-skill clawshield` erase a skill from
    `ctx.installed_skills` — and therefore from the whole audit and from --monitor —
    with no frontmatter edit, while --vet pointed at the same bytes still said
    "F (DANGEROUS)". Moving it down here (the same precedent as `_OWN_SKILL_NAMES`,
    already collector-resident) keeps the import direction legal and makes the two
    surfaces agree. `checks/_shared.py` re-imports it, so `vet_skill`'s behaviour and
    the `clawseccheck.checks` aggregator re-export (§3.1-a) are unchanged.

    HONEST SCOPE — this CLOSES the rename-only cloak but does not make self-exclusion
    unforgeable: an attacker who copies our actual engine sources (all of
    `_OWN_ENGINE_MARKERS` present, in a `checks/` package laid out like ours) alongside
    a payload would still be excluded. That residual is strictly narrower than the old
    one — it costs the attacker shipping our whole engine rather than one `mv` — and it
    is bounded further by `check_installed_skills` being only one of the surfaces that
    sees a skill. Making exclusion tamper-proof needs a signed/attested identity, not a
    content heuristic; tracked separately, not solvable inside a static string test.

    C-135 residual, accepted deliberately: an own install that ships the DOCS but not the
    engine (a hand-made partial copy — `SKILL.md` + `README.md` + `docs/` under a
    `clawseccheck/` dir with no `clawseccheck/checks/`) is no longer excluded, so the
    audit scans our own prose, which necessarily quotes attack payloads, and self-flags.
    Not a shipped shape: both documented installs put the engine on disk (ClawHub installs
    the whole tree — pyproject `packages` includes `clawseccheck.checks` — and the pipx
    route creates no skill dir at all), and a docs-only copy has no working console script.
    Verified against the real `~/.openclaw` install, which recognises correctly. Left
    unmitigated on purpose: every candidate fix keys on copyable doc content, which is
    exactly the forgeable-identity mistake this change exists to remove. Failing closed
    (scan what we cannot verify) is the safe direction; the old behaviour here was a
    lying PASS that let a payload hide behind a copy of our README. Pinned by
    `tests/test_b265_ownname_content_exclusion.py::test_docs_only_own_install_is_scanned`.
    """
    # The engine is the checks/ package (current) or a legacy single-file checks.py.
    # Read every engine source so the markers are found regardless of which topic module
    # the I-022 split scattered them into.
    # B-303: every is_dir()/is_file()/glob() below goes through the _safe_* helpers (or a
    # try/except) — a non-traversable *p* (e.g. an ancestor chmod 000) must answer "not
    # our own source", never crash the whole audit with an uncaught PermissionError.
    if _safe_is_dir(p / "clawseccheck" / "checks"):  # repo root / install dir (package)
        try:
            sources = sorted((p / "clawseccheck" / "checks").glob("*.py"))
        except OSError:
            return False
    elif _safe_is_file(p / "clawseccheck" / "checks.py"):  # repo root / install dir (legacy)
        sources = [p / "clawseccheck" / "checks.py"]
    elif p.name.lower() in _OWN_SKILL_NAMES and _safe_is_dir(p / "checks"):  # package dir
        try:
            sources = sorted((p / "checks").glob("*.py"))
        except OSError:
            return False
    elif p.name.lower() in _OWN_SKILL_NAMES and _safe_is_file(p / "checks.py"):  # package dir (legacy)
        sources = [p / "checks.py"]
    else:
        return False
    try:
        head = "\n".join(s.read_text(encoding="utf-8", errors="replace") for s in sources)
    except OSError:
        return False
    return all(m in head for m in _OWN_ENGINE_MARKERS)


def _iter_skill_dirs_guarded(base: Path, allow_symlink: bool, ctx: Context):
    """``iter_discovered_skill_dirs`` that degrades to a limit hit instead of raising.

    B-289: skill roots used to be either inside the audited home or named by the config,
    so an unreadable entry was a remote possibility. OPENCLAW_BUNDLED_SKILLS_DIR makes the
    root an ARBITRARY absolute path chosen by whoever set the variable, and a directory
    containing an entry this process cannot stat is then reachable — the discovery walk
    raises ``PermissionError`` and takes the WHOLE audit down with it.

    Found by the adversarial pass, not by a fixture: pointing the override at ``/tmp`` is
    enough on a stock Ubuntu box, because ``/tmp/snap-private-tmp`` is root-only. That
    turns "an attacker who can write the systemd unit" into "an attacker who can stop the
    audit from producing any report at all" — a denial-of-audit for the price of one line.

    A partial walk is recorded as a limit hit, never swallowed: consumers of
    ``ctx.installed_skills`` treat a limit hit as "this view is incomplete" and report
    UNKNOWN rather than a clean PASS over a scan that never finished.

    B-654: also collects, without changing the population or the walk at all, every
    directory whose own SKILL.md exists but is not a regular file — the fall-through
    ``iter_discovered_skill_dirs`` already takes without yielding or truncating. Those
    names get the same five writes ``collect_skill_files`` performs for the identical
    fact once a directory HAS been yielded, via the shared ``_note_unreadable_manifest``,
    so B13's existing ``unreadable`` branch (never a new one) turns this into UNKNOWN
    instead of a clean PASS over a directory nothing read.
    """
    unassessable: list[str] = []
    it = _iter_discovered_skill_dirs(
        base,
        allow_symlink_entries=allow_symlink,
        # skilldiscovery is a leaf and cannot import note_limit; hand it a pre-scoped sink
        # so its _MAX_DIRS cap hit lands tagged like every other skill-coverage limit.
        limit_hits=_ScopedLimitSink(ctx.limit_hits, LIMIT_DOMAIN_SKILL),
        unassessable=unassessable,
    )
    while True:
        try:
            item = next(it)
        except StopIteration:
            break
        except OSError as exc:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_SKILL,
                f"skill discovery under '{base}' stopped early ({exc.__class__.__name__}) "
                "— skills beyond that point were NOT scanned",
            )
            break
        yield item
    for name in unassessable:
        _note_unreadable_manifest(ctx, name)


def _read_installed_skills(home: Path, ctx: Context) -> None:
    seen: set[str] = set()
    # (base_dir, allow_symlink_entries). The hardcoded roots refuse symlinked skill dirs —
    # a planted symlink is a tamper signal — but plugin-skills entries are *deliberately*
    # symlinks into a plugin's bundled skills/ dir, so those get dereferenced (B-161).
    roots: list[tuple[Path, bool]] = [(home / rel, False) for rel in SKILL_DIRS]
    # OpenClaw also loads personal cross-agent skills from ~/.agents/skills. Only add
    # this global root when auditing an actual profile directory under the user's home;
    # fixture/custom --home scans must remain hermetic and never absorb unrelated skills.
    try:
        user_home = Path.home().resolve()
        audited_home = home.resolve()
    except (OSError, ValueError, RuntimeError):
        user_home = None
        audited_home = None
    if (
        user_home is not None
        and audited_home is not None
        and audited_home.parent == user_home
        and audited_home.name.startswith(".openclaw")
    ):
        roots.append((user_home / ".agents" / "skills", False))
    for cw in _config_workspace_dirs(home, ctx.config, limit_hits=ctx.limit_hits,
                                    disclosures=ctx.disclosures):
        roots.append((cw / "skills", False))
    roots.extend((path, False) for path in _config_extra_skill_dirs(home, ctx.config))
    # F-119: plugins.load.paths (a real dist key) — a path-loaded plugin bundles skills under
    # <plugin>/skills/ that enter the auto-load surface; discover them so they're scanned like
    # any other installed skill instead of being silently invisible.
    roots.extend((pp / "skills", False) for pp in _config_plugin_load_paths(home, ctx.config))
    # B-289 (ENV-3): OPENCLAW_BUNDLED_SKILLS_DIR relocates the bundled skills root, and
    # resolveBundledSkillsDir (bundled-dir-BQFrcRIS.js:22-24) honours it unconditionally.
    # The relocated directory is a real auto-load root, so its skills go through the SAME
    # content scanners as every other tier rather than a second engine. Only a relocation
    # evidenced by a persistent artifact is followed — the auditing shell's environment is
    # not the agent's (see persistent_env_evidence). Note this ADDS a load root: the
    # default bundled-dist tier is still not scanned (SKILL_TIER_ORDER omits it), so this
    # is an unenumerated-root fix, not a stale-snapshot one.
    for _var, _kind, _value, _src in bundled_root_overrides(ctx):
        if _kind != "skills":
            continue  # a hooks root holds hook modules, not SKILL.md dirs — B186 discloses it
        try:
            _override = Path(_value).expanduser()
        except (OSError, ValueError, RuntimeError):
            continue
        if _safe_is_dir(_override, ctx, what=f"bundled skills root '{_override}'",
                        domain=LIMIT_DOMAIN_SKILL):
            roots.append((_override, False))
    plugin_skills = home / "plugin-skills"
    if _safe_is_dir(plugin_skills, ctx, what=f"'{plugin_skills}'", domain=LIMIT_DOMAIN_SKILL):
        roots.append((plugin_skills, True))
    seen_roots: set[Path] = set()
    for base, allow_symlink in roots:
        # B-303: a load root that exists but is not traversable (most commonly the whole
        # home, e.g. chmod 000) must be skipped like a root that does not exist at all —
        # ctx.installed_skills then simply stays emptier, which check_installed_skills
        # (B13) already degrades to UNKNOWN for, never a crash or a fake clean PASS.
        # B-404: unlike a root that genuinely does not exist, a root that
        # exists but could not be stat'd (permission denied) is a REAL enumeration
        # failure — domain=LIMIT_DOMAIN_SKILL records it so a consumer asking "was this
        # scan complete" (limit_hits_for) can see it, instead of it reading identically
        # to "nothing configured here".
        if not _safe_is_dir(base, ctx, what=f"skill root '{base}'", domain=LIMIT_DOMAIN_SKILL):
            continue
        try:
            base_key = base.resolve()
        except (OSError, ValueError, RuntimeError):
            base_key = base
        if base_key in seen_roots:
            continue
        seen_roots.add(base_key)
        # B-404: the single source of truth for "which roots did the real
        # discovery engine confirm and walk" — see the field's docstring on Context.
        ctx.installed_skill_roots.append(base)
        for sd, target in _iter_skill_dirs_guarded(base, allow_symlink, ctx):
            if len(ctx.installed_skills) >= _MAX_SKILLS:
                # B-268: this used to `return` — the collection stopped dead, leaving
                # ctx.installed_skills a silently truncated view with no trace that more
                # existed. Two consumers then read that view as filesystem ground truth:
                # monitor's skill diff reported every uncollected name as "was removed"
                # (measured: 310 skills + one early-sorting addition => a phantom
                # "Skill 's299' was removed"), and the inventory line printed its length
                # as the installed total. Worse, discovery order is filename order, which
                # is ATTACKER-CONTROLLED: flooding aaa*-named skills pushes a real one out
                # of the scanned set entirely, and nothing recorded a limit hit, so B13
                # still reported a clean verdict over a scan that never saw it.
                #
                # Keep walking so the frontier is EXACT — the skipped dirs are only
                # enumerated (a bounded directory listing, already capped by
                # skilldiscovery's _MAX_DIRS), never read, so the cap still does its job
                # of bounding content work.
                ctx.skills_capped_count += 1
                if len(ctx.skills_capped_names) < _MAX_SKILL_FRONTIER_NAMES:
                    ctx.skills_capped_names.append(sd.name)
                else:
                    ctx.skills_frontier_partial = True
                continue
            # B-265: self-exclusion is CONTENT-verified, never basename-verified. Test the
            # resolved `target` (the real bytes), not `sd` — a symlinked plugin-skills entry
            # must be judged by what it points at. A malicious skill renamed to an own-skill
            # name now enters the inventory and is audited like any other.
            if _is_own_source(target):
                # B-507: excluded, but no longer SILENTLY excluded -- record the name so
                # report.py can disclose it instead of the inventory count just quietly
                # shrinking by one with no trace anywhere in the output. Deduped: the
                # same own-skill dir could in principle be reachable from two roots.
                if sd.name not in ctx.self_excluded_skills:
                    ctx.self_excluded_skills.append(sd.name)
                continue
            key = sd.name
            if key in seen:
                try:
                    rel = sd.relative_to(base).as_posix()
                except ValueError:
                    rel = sd.name
                key = f"{base.name}/{rel}"
                suffix = 2
                original = key
                while key in seen:
                    key = f"{original}#{suffix}"
                    suffix += 1
            seen.add(key)
            if base == plugin_skills:
                # B-507: this root is DELIBERATELY symlinks into a plugin's own bundled
                # skills/ dir (see the B-161 comment above `plugin_skills = ...`) -- e.g.
                # an OpenClaw core extension's browser-automation/canvas skill living
                # inside OpenClaw's own npm package, not something the user separately
                # installed or can remove independently of the plugin. report.py labels
                # these "bundled" rather than folding them into a plain "(N installed)"
                # count that implies the user chose each one, same as a marketplace
                # skill. Scoped to exactly this root: it is the only skill root this
                # codebase already documents as symlink-into-bundled-dir; other roots
                # (plugins.load.paths, a bundled_root_overrides relocation) are not
                # labeled bundled here because that would be a new, unverified claim
                # about their provenance rather than one already established in-code.
                ctx.installed_skill_bundled.add(key)
            try:
                ctx.installed_skills[key] = _read_skill_text(target, ctx)
                ctx.installed_skill_py[key] = read_skill_python(target, ctx)
                ctx.installed_skill_shell[key] = read_skill_shell(target, ctx)
                ctx.installed_skill_js[key] = read_skill_js(target, ctx)
                ctx.installed_skill_dirs[key] = target
            except OSError as exc:
                ctx.errors.append(f"could not read skill {key}: {exc}")

    # B-268: record the cap hit, mirroring what skilldiscovery.py already does for its
    # sibling _MAX_DIRS cap. This is what makes check_installed_skills (B13) degrade to
    # UNKNOWN instead of reporting a clean PASS over a scan that never reached the skills
    # beyond the cap — the existing B-074 discipline, which this cap alone was bypassing.
    if ctx.skills_capped_count:
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_SKILL,
            f"installed-skill collection hit the {_MAX_SKILLS}-skill cap — "
            f"{ctx.skills_capped_count} further skill director"
            f"{'y was' if ctx.skills_capped_count == 1 else 'ies were'} NOT read",
        )


# Skill-load tiers in PRECEDENCE order, HIGHEST-WINS first. Grounded against the dist loader
# (openclaw dist workspace-*.js — every discovered skill is merged into one global Map keyed by
# declared `name:`, so the LAST-merged root silently overwrites — "shadows" — any same-named
# skill from an earlier root, with NO warning). Precedence highest→lowest: workspace >
# project-agent > personal-agent > managed (~/.openclaw/skills) > bundled(dist) > extraDirs /
# plugins.load.paths. The audit sees the home-rooted tiers below; the bundled-dist tier lives
# outside the home and is not scanned.
SKILL_TIER_ORDER = ("workspace", "project-agent", "personal-agent", "managed", "extra/plugin")


def skill_load_roots(
    home: Path, cfg: dict | None = None, *, user_home: Path | None = None
) -> list[tuple[Path, str]]:
    """Return ``(root_dir, tier)`` for every skill-load root the audit can see, in PRECEDENCE
    order — highest-precedence (the tier that WINS a name collision) FIRST. Resolved-path
    de-duped so one physical dir is never listed twice (the highest-precedence alias wins).
    Read-only; never raises. Used by B104 to flag cross-tier NAME shadowing (a planted
    higher-precedence copy silently overriding a trusted skill). ``user_home`` adds the
    personal ``~/.agents/skills`` tier — pass it only when auditing a real ``~/.openclaw``
    profile, so fixture/custom --home scans stay hermetic (mirrors ``_read_installed_skills``)."""
    cfg = cfg if isinstance(cfg, dict) else {}
    ordered: list[tuple[Path, str]] = []
    # workspace tier (highest): default workspace names under home + any custom workspace.
    for rel in ("workspace/skills", "workspace-home/skills", "workspace-work/skills"):
        ordered.append((home / rel, "workspace"))
    for cw in _config_workspace_dirs(home, cfg):
        ordered.append((cw / "skills", "workspace"))
    # agent tiers.
    ordered.append((home / ".agents" / "skills", "project-agent"))
    if user_home is not None:
        ordered.append((user_home / ".agents" / "skills", "personal-agent"))
    # managed tier (~/.openclaw/skills).
    ordered.append((home / "skills", "managed"))
    # extra/plugin tier (lowest): skills.load.extraDirs + plugins.load.paths + plugin-skills.
    for d in _config_extra_skill_dirs(home, cfg):
        ordered.append((d, "extra/plugin"))
    for pp in _config_plugin_load_paths(home, cfg):
        ordered.append((pp / "skills", "extra/plugin"))
    ordered.append((home / "plugin-skills", "extra/plugin"))
    # Resolved-path de-dup — keep the first (highest-precedence) occurrence of each dir.
    out: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for path, tier in ordered:
        try:
            key = path.resolve()
        except (OSError, ValueError, RuntimeError):
            key = path
        if key in seen:
            continue
        seen.add(key)
        out.append((path, tier))
    return out


def _collect_cron(home: Path, ctx: Context) -> None:
    """B-231 sub-item 1: read-only, symlink-safe, size/entry-capped collection of the
    OpenClaw cron job store into ``ctx.cron_jobs``.

    Two backing stores exist (grounded against the openclaw dist): the legacy JSON file
    ``~/.openclaw/cron/jobs.json`` (``{"version": 1, "jobs": [CronJobSchema, ...]}``,
    each job's ``payload``/``trigger`` sub-objects carrying ``message``/``script``), and
    the SQLite-backed ``cron_jobs`` table in ``~/.openclaw/state/openclaw.sqlite``. The
    JSON file is preferred when present; the SQLite table is a read-only fallback. Neither
    present leaves ``ctx.cron_found`` False, so a consuming check reports UNKNOWN, never a
    fake PASS.

    B-709: the SQLite table itself has TWO observed column shapes, and which one a given
    install has is decided by PROBING ``PRAGMA table_info(cron_jobs)`` once, then branching
    on COLUMN PRESENCE -- never by trying one SELECT and catching
    ``sqlite3.OperationalError`` to fall back to the other, because an exception-driven
    fallback cannot distinguish "this is the other schema" from "a genuine read failure"
    (same failure shape as `agent_roster()`'s dual-shape read, which picks on key presence
    for the identical reason):

    * LEGACY -- ``job_id``, ``name``, ``enabled``, ``delete_after_run``, ``trigger_script``,
      ``payload_kind``, ``payload_message`` columns, each holding its own scalar.
    * MODERN (OpenClaw 2026.8.2+) -- ``delete_after_run``/``trigger_script``/
      ``payload_message`` no longer exist as columns; they live inside the ``job_json``
      TEXT column (``deleteAfterRun`` top-level, ``payload.script``/``payload.message``/
      ``payload.text`` depending on ``payload.kind``). ``job_id``/``name``/``enabled``/
      ``payload_kind`` stay real, unchanged columns. Only these three named keys are ever
      pulled out of ``job_json`` -- the blob itself is never stored or emitted (§8; the
      same state DB holds live OAuth tokens under ``authProfiles.store``).

    Neither shape recognised (an unrelated ``cron_jobs`` table) is reported the same way a
    genuinely corrupt store is -- ``cron_found=True`` + ``cron_parse_error=True`` -- rather
    than inventing a third flag a consumer would also have to learn.

    Both branches resolve candidate files through ``safeio.walk_dir_safely`` — symlinks
    and path-escapes are skipped, matching every other collector read.

    B-294: a store that is present but holds ZERO jobs now sets ``ctx.cron_store_empty``.
    That case used to be indistinguishable from a clean populated store, so B168 answered
    PASS/``pass_confidence="verified"`` having scanned nothing. The execution trail is read
    separately by ``_collect_cron_run_logs`` (called first, so it runs for the legacy-JSON
    branch too — the run logs live in SQLite regardless of which store holds the jobs).
    """
    _collect_cron_run_logs(home, ctx)
    cron_dir = home / "cron"
    json_candidates = (
        walk_dir_safely(cron_dir, max_files=50)
        if _safe_is_dir(cron_dir, ctx, what=f"'{cron_dir}'") else []
    )
    jobs_json = next((p for p in json_candidates if p.name == "jobs.json"), None)
    if jobs_json is not None:
        try:
            with open(jobs_json, "rb") as fp:
                raw, truncated = _read_with_limit(fp, _MAX_CRON_BYTES)
            if truncated:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_CRON,
                    f"cron store '{jobs_json}' exceeded the "
                    f"{_MAX_CRON_BYTES // 1_000_000}MB cap — content beyond the cap "
                    "was NOT scanned",
                )
            store = json.loads(raw.decode("utf-8", errors="replace"))
            jobs = store.get("jobs") if isinstance(store, dict) else None
            if not isinstance(jobs, list):
                jobs = []
            ctx.cron_found = True
            for job in jobs[:_MAX_CRON_JOBS]:
                if not isinstance(job, dict):
                    continue
                payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
                trigger = job.get("trigger") if isinstance(job.get("trigger"), dict) else {}
                ctx.cron_jobs.append({
                    "id": job.get("id"),
                    "name": job.get("name"),
                    "enabled": job.get("enabled"),
                    "delete_after_run": job.get("deleteAfterRun"),
                    "trigger_script": trigger.get("script"),
                    "payload_kind": payload.get("kind"),
                    "payload_message": payload.get("message"),
                })
            if len(jobs) > _MAX_CRON_JOBS:
                ctx.cron_jobs_truncated = True
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_CRON,
                    f"cron store '{jobs_json}' has {len(jobs)} jobs — only the first "
                    f"{_MAX_CRON_JOBS} were scanned",
                )
            ctx.cron_store_empty = not ctx.cron_jobs  # B-294: read, but nothing to scan
            _flag_shadowed_cron_store(home, ctx, jobs_json)
            _flag_cron_store_config_mismatch(ctx, jobs_json)
        except (OSError, ValueError) as exc:
            ctx.errors.append(f"could not parse {jobs_json}: {exc}")
            ctx.cron_found = True
            ctx.cron_parse_error = True
        return

    # No legacy JSON store -- fall back to the SQLite-backed cron_jobs table.
    state_dir = home / "state"
    sqlite_candidates = (
        walk_dir_safely(state_dir, max_files=100)
        if _safe_is_dir(state_dir, ctx, what=f"'{state_dir}'") else []
    )
    db_path = next((p for p in sqlite_candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return  # neither store present -> cron_found stays False (UNKNOWN, not a fake PASS)

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
            # B-709: PROBE the real column shape before picking a SELECT -- do NOT try the
            # modern query and fall back to the legacy one on `sqlite3.OperationalError:
            # no such column`. An exception-driven fallback cannot tell "this is the other
            # schema" apart from "a genuine read failure" (a locked db, a corrupt page, an
            # I/O error would raise the very same way), so it would silently swallow a real
            # error as a shape mismatch and read nothing while reporting nothing wrong --
            # the fail-open family this repo keeps getting bitten by. `agent_roster()`
            # already picks its own dual shape this way: on KEY PRESENCE, never on whether
            # a value turns out usable.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(cron_jobs)")}
            if not columns:
                return  # no cron_jobs table at all -- same honest "not found" as before

            if "job_json" in columns:
                # MODERN shape (OpenClaw 2026.8.2+). delete_after_run/trigger_script/
                # payload_message no longer have their own columns -- they live inside the
                # job_json blob, grounded against the installed dist:
                #   deleteAfterRun  top-level bool, optional (plugin-entry-DhKN3bwq.d.ts:6380
                #                   `CronJobBase.deleteAfterRun?: boolean`)
                #   trigger_script  payload.script, only when payload.kind == "script"
                #   payload_message payload.message when payload.kind == "agentTurn",
                #                   payload.text when payload.kind == "systemEvent"
                #                   (both: persisted-shape-C6m3w-m0.js:100)
                # job_id/name/enabled/payload_kind stay real, unchanged columns.
                cur = conn.execute(
                    "SELECT job_id, name, enabled, payload_kind, job_json "
                    "FROM cron_jobs LIMIT ?",
                    (_MAX_CRON_JOBS + 1,),
                )
                rows = cur.fetchall()
                modern = True
            elif "delete_after_run" in columns:
                # LEGACY shape -- unchanged from before B-709.
                cur = conn.execute(
                    "SELECT job_id, name, enabled, delete_after_run, trigger_script, "
                    "payload_kind, payload_message FROM cron_jobs LIMIT ?",
                    # W-DB2 round-3 off-by-one fix: ask for ONE MORE row than the cap and
                    # use its presence as the truncation probe. `LIMIT n` + `len(rows) >= n`
                    # cannot tell a store holding exactly n jobs (a COMPLETE read, nothing
                    # dropped) from one holding n+1, so exactly 200 jobs was reported
                    # truncated: the unread-remainder guard below then suppressed a genuine
                    # B189 orphan WARN and manufactured a limit_hits entry claiming rows
                    # were "NOT read" when every row had been read. The probe row is
                    # discarded (`rows[:cap]`), so the scanned set is still capped at
                    # _MAX_CRON_JOBS.
                    (_MAX_CRON_JOBS + 1,),
                )
                rows = cur.fetchall()
                modern = False
            else:
                # Neither shape recognised. Do NOT guess a mapping for an unknown layout --
                # this is the same honest "found but could not be parsed/read" verdict
                # `cron_parse_error` already produces for a genuinely corrupt store, so it
                # reuses that flag rather than adding a third one a consumer would also
                # have to learn. The actual columns seen are recorded (not invented data --
                # they are literal facts about the table) so a human can diagnose it.
                ctx.cron_found = True
                ctx.cron_parse_error = True
                ctx.errors.append(
                    f"cron_jobs table in '{db_path}' has neither the legacy "
                    "('delete_after_run') nor the modern ('job_json') column shape -- "
                    f"columns seen: {sorted(columns)}; not read"
                )
                return
        finally:
            conn.close()

        ctx.cron_found = True
        if len(rows) > _MAX_CRON_JOBS:
            rows = rows[:_MAX_CRON_JOBS]
            # Asymmetric-cap guard. This SELECT has no ORDER BY, so the rows that survive the
            # cap are whichever ones SQLite returns first (storage order), while
            # _collect_cron_run_logs takes the MOST RECENT runs. Differencing two sets
            # sampled on different axes invents "orphans". Mirrors the run-log reader's own
            # probe below, and the JSON branch's limit_hits, which this branch
            # previously lacked entirely — making the truncation invisible.
            ctx.cron_jobs_truncated = True
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_CRON,
                f"cron_jobs table in '{db_path}' returned the {_MAX_CRON_JOBS}-row cap "
                "— further job definitions were NOT read",
            )

        if modern:
            for job_id, name, enabled, payload_kind, job_json in rows:
                job_spec = None
                if isinstance(job_json, (str, bytes)):
                    try:
                        parsed = json.loads(job_json)
                    except (TypeError, ValueError):
                        parsed = None
                    if isinstance(parsed, dict):
                        job_spec = parsed
                    else:
                        # Malformed / non-object job_json for this one job -- record it
                        # and move on. This is per-JOB (like the legacy JSON branch
                        # silently skipping a non-dict array entry), never the store-level
                        # cron_parse_error: one bad row must not blind the scan of every
                        # other job in the same table.
                        ctx.errors.append(
                            f"job_json for cron job '{job_id}' in '{db_path}' is not "
                            "valid JSON -- that job's deleteAfterRun/trigger_script/"
                            "payload_message could not be extracted"
                        )
                        # ...but the row still enters ctx.cron_jobs with empty content, so
                        # B168 would count it in "Scanned N cron job(s)" having read none
                        # of it -- a completed-walk claim over a walk that did not finish.
                        # A ctx.errors line alone cannot prevent that: no check reads
                        # ctx.errors, whereas LIMIT_DOMAIN_CRON is the channel B168/B189
                        # already consult via limit_hits_for(). Disclose it there.
                        note_limit(
                            ctx.limit_hits, LIMIT_DOMAIN_CRON,
                            f"cron job '{job_id}' in '{db_path}' has unparseable "
                            "job_json — its payload/trigger content was NOT scanned",
                        )
                # Named-key extraction only (§8) -- job_json is never stored or emitted
                # whole; only the three grounded keys below are pulled out of it.
                delete_after_run = job_spec.get("deleteAfterRun") if job_spec else None
                payload_obj = job_spec.get("payload") if job_spec else None
                payload_obj = payload_obj if isinstance(payload_obj, dict) else {}
                trigger_script = (
                    payload_obj.get("script") if payload_kind == "script" else None
                )
                if payload_kind == "agentTurn":
                    payload_message = payload_obj.get("message")
                elif payload_kind == "systemEvent":
                    payload_message = payload_obj.get("text")
                else:
                    payload_message = None
                ctx.cron_jobs.append({
                    "id": job_id,
                    "name": name,
                    "enabled": bool(enabled) if enabled is not None else None,
                    "delete_after_run": delete_after_run,
                    "trigger_script": trigger_script,
                    "payload_kind": payload_kind,
                    "payload_message": payload_message,
                })
        else:
            for job_id, name, enabled, delete_after_run, trigger_script, payload_kind, payload_message in rows:
                ctx.cron_jobs.append({
                    "id": job_id,
                    "name": name,
                    "enabled": bool(enabled) if enabled is not None else None,
                    "delete_after_run": bool(delete_after_run) if delete_after_run is not None else None,
                    "trigger_script": trigger_script,
                    "payload_kind": payload_kind,
                    "payload_message": payload_message,
                })
        ctx.cron_store_empty = not ctx.cron_jobs  # B-294: read, but nothing to scan
    except sqlite3.Error as exc:
        # A state DB that exists but has no cron_jobs table yet (a fresh install where
        # cron was never touched) is not a corrupt store -- treat like "not found" so the
        # check reports the same honest UNKNOWN as no store at all, not a parse error.
        # (Now mostly a defense-in-depth net: the table_info probe above already returns
        # early on a genuinely absent table before any SELECT runs.)
        if "no such table" not in str(exc).lower():
            ctx.errors.append(f"could not read cron_jobs from {db_path}: {exc}")
            ctx.cron_found = True
            ctx.cron_parse_error = True


def _cron_store_key_candidates(jobs_json: Path) -> list:
    """Return the ``cron_jobs.store_key`` spellings that denote the audited store file.

    The runtime's partition key is ``cronStoreKey(storePath) { return path.resolve(storePath); }``
    (key-BBZ40bDq.js:5-7) — an identity resolve, so the key is just the absolute store path.

    Two spellings are returned because Node's ``path.resolve`` is **purely lexical**
    (normalize + absolutize, no filesystem access) while Python's ``Path.resolve`` also
    follows symlinks. They diverge whenever the OpenClaw home is reached through a
    symlinked parent — a dotfiles checkout or a mounted volume. Binding only the
    symlink-resolved spelling would therefore miss the runtime's actual key on exactly
    those installs and silently stop detecting shadowing, so both are matched.
    ``os.path.abspath`` is the faithful Node analogue; ``Path.resolve`` is the fallback
    for the reverse case (the key was written from an already-resolved path).
    """
    spellings = [os.path.abspath(str(jobs_json))]
    try:
        resolved = str(jobs_json.resolve())
    except OSError:  # unresolvable path -- the lexical spelling still stands
        resolved = ""
    if resolved and resolved not in spellings:
        spellings.append(resolved)
    return spellings


def _flag_cron_store_config_mismatch(ctx: Context, jobs_json: Path) -> None:
    """Set ``ctx.cron_store_shadowed`` when ``cron.store`` points somewhere this collector
    never reads.

    W-DB2 round-4 scoped ``_flag_shadowed_cron_store``'s SQLite count to the DEFAULT
    ``<home>/cron/jobs.json`` path's own ``store_key`` candidates, to stop unrelated rows
    filed under a genuinely different store from manufacturing a false shadow. That fix
    exposed a worse gap: ``_collect_cron`` ALWAYS reads the default ``jobs.json`` when one
    exists and never once looks at ``cron.store`` (``string().optional()``,
    zod-schema-O9ml_nmo.js:1221; description schema-DRyO1XBt.js:986). A host with an
    explicit ``cron.store`` pointing elsewhere, plus a stale default ``jobs.json`` left over
    from before that setting was added, gets scanned on the WRONG file entirely — with the
    scoped shadow check now correctly reporting "no rows shadowed" for the default path,
    because the runtime's actual jobs live under a store_key this function never queried.
    The result was a "verified" PASS over a job payload never read.

    This is deliberately blunt rather than clever: when ``cron.store`` resolves to a path
    that differs from the one just scanned, this collector has NOT read the store the
    runtime actually uses, full stop -- no SQLite lookup can rescue that, because the
    configured store might not even be SQLite-backed. Flag it unconditionally.
    """
    # F-183: `cron.store` left openclaw.json for the machine-owned state store in
    # OpenClaw 2026.8.1, so reading only the config silently stopped this check firing on
    # a current build — the shadow it exists to catch would go unreported. The state value
    # wins where present; the config key remains authoritative on builds that still have
    # one, and on any machine whose state store could not be read.
    configured = (ctx.config_machine_state or {}).get("cron.store")
    if not isinstance(configured, str) or not configured.strip():
        configured = dig(ctx.config, "cron.store")
    if not isinstance(configured, str) or not configured.strip():
        return
    configured_abs = os.path.abspath(os.path.expanduser(configured))
    scanned_abs = os.path.abspath(str(jobs_json))
    if configured_abs == scanned_abs:
        return
    ctx.cron_store_shadowed = True
    note_limit(
        ctx.limit_hits, LIMIT_DOMAIN_CRON,
        f"cron.store is configured to '{configured}', but the store actually scanned was "
        f"'{jobs_json}' — the configured store was NOT read",
    )


def _flag_shadowed_cron_store(home: Path, ctx: Context, jobs_json: Path) -> None:
    """Set ``ctx.cron_store_shadowed`` when the legacy ``~/.openclaw/cron/jobs.json`` was
    used as the job-definition source but the SQLite ``cron_jobs`` table ALSO holds rows.

    ``_collect_cron`` prefers the JSON store and returns before it ever opens SQLite, which
    is correct for a genuinely legacy install but wrong for an upgraded one. In the shipped
    dist the job rows live in SQLite — ``loadCronJobsStoreWithConfigJobs`` resolves the
    store path only to derive a key (``cronStoreKey(path.resolve(storePath))``,
    store-ScQ9SjOe.js:710) and then reads ``loadCronRows`` from the database; writes go
    through ``replaceCronRows`` (store-ScQ9SjOe.js:647). Grepped the dist's cron modules
    (store-ScQ9SjOe.js, run-log-DIhrTrSU.js, key-BBZ40bDq.js) for unlink/rm/writeFile: there
    are none, so nothing ever removes a stale jobs.json. An install that predates the SQLite
    migration therefore keeps a file that the runtime no longer reads, and differencing run
    logs against it makes live jobs look erased.

    COUNT ONLY — no job content is read here, so this cannot contradict or silently replace
    what B168 scanned out of the JSON file. Read-only, symlink-safe, never raises: any
    sqlite3 error (including a state DB predating the table) simply leaves the flag False.

    W-DB2 round-4: the count is SCOPED TO THE AUDITED PARTITION. ``cron_jobs`` is
    partitioned by ``store_key`` (``store_key TEXT NOT NULL``,
    openclaw-state-db-DzSsA9Ji.js:1421-1422) and the runtime reads exactly one partition —
    ``loadCronRows`` filters ``WHERE store_key = ?`` (store-ScQ9SjOe.js:643-645). An
    unscoped ``COUNT(*)`` was therefore blind to WHICH store the rows belonged to. A config
    that sets an explicit ``cron.store`` (a documented key — schema-DRyO1XBt.js:986) parks
    its rows under a different key, and those rows are NOT what this jobs.json resolves to:
    for the audited path ``loadCronJobsStoreWithConfigJobs`` loads zero rows and returns an
    empty store (store-ScQ9SjOe.js:709-723). Counting them declared a shadow that does not
    exist and emitted a limit_hit asserting rows "were NOT read" that the runtime would
    never have read for this store either.

    UNATTRIBUTABLE ROWS ARE COUNTED, deliberately — the conservative direction. A row whose
    ``store_key`` is NULL/blank, or a table whose schema predates the column entirely,
    cannot be assigned to a partition; since it still MIGHT be the row the runtime loads,
    dropping it would trade a false positive for a false negative (a real shadow going
    unflagged, which is the failure mode this function exists to prevent). Only rows
    positively attributed to a DIFFERENT store are excluded.
    """
    state_dir = home / "state"
    candidates = (
        walk_dir_safely(state_dir, max_files=100)
        if _safe_is_dir(state_dir, ctx, what=f"'{state_dir}'") else []
    )
    db_path = next((p for p in candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return
    keys = _cron_store_key_candidates(jobs_json)
    placeholders = ",".join("?" * len(keys))
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM cron_jobs WHERE store_key IN "
                    f"({placeholders}) OR store_key IS NULL OR TRIM(store_key) = ''",
                    keys,
                ).fetchone()
            except sqlite3.OperationalError as exc:
                if "no such column" not in str(exc).lower():
                    raise
                # Schema predates the store_key partition column: NO row can be attributed,
                # so count them all rather than let the whole table vanish from the count.
                row = conn.execute("SELECT COUNT(*) FROM cron_jobs").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return  # no table / unreadable -> nothing proven, leave the flag False
    if row and row[0]:
        ctx.cron_store_shadowed = True
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_CRON,
            f"legacy cron store '{jobs_json}' was used for job definitions, but the "
            f"cron_jobs table in '{db_path}' holds {row[0]} row(s) for that same store "
            f"path which were NOT read",
        )


def _collect_cron_run_logs(home: Path, ctx: Context) -> None:
    """B-294 (DISK-3): read-only collection of the cron EXECUTION trail into
    ``ctx.cron_run_logs``.

    Grounded against the installed dist (openclaw-state-db-DzSsA9Ji.js:
    ``CREATE TABLE IF NOT EXISTS cron_run_logs`` — columns store_key, job_id, seq, ts,
    status, error, summary, diagnostics_summary, delivery_status, delivery_error,
    delivered, session_id, session_key, run_id, run_at_ms, duration_ms, next_run_at_ms,
    model, provider, total_tokens, entry_json, created_at; PK (store_key, job_id, seq)).
    Written by ``appendCronRunLog`` (server-cron-Cwg2hJro.js), pruned by
    ``pruneCronRunLogRows`` (run-log-DIhrTrSU.js).

    WHY this table matters and the job definitions are not enough: the execution trail
    deliberately OUTLIVES the definition. One-shot (``schedule.kind === "at"``) jobs default
    to ``deleteAfterRun`` TRUE (jobs-qB_gTO89.js:834, normalize-BMkddmz2.js:409), the runner
    deletes the row after a SUCCESSFUL run (server-cron-Cwg2hJro.js:1340), ``deleteAfterRun``
    is exposed to the AGENT ITSELF as a schedulable option (cron-tool-C9qaFGtt.js:495), and
    the legacy table has NO foreign key to ``cron_jobs`` — the only cron_jobs delete in the
    dist (``replaceCronRows``, store-ScQ9SjOe.js:648) never touches it. So a job that was
    added, ran, and self-erased leaves no definition for B168 to scan, but its run trail
    survives here.

    B-709: on the installed OpenClaw 2026.8.2, ``cron_run_logs`` DOES NOT EXIST AT ALL. The
    live state DB carries a completed migration record whose id is literally
    ``state:cron-run-logs-to-task-runs:v1`` — the vendor naming its own destination, not an
    inference — and cron executions now live as rows in the generic ``task_runs`` table
    (``runtime = 'cron'``, also ``task_kind = 'automation_run'``). Verified empirically: a
    live ``task_runs`` row's ``source_id`` equals the ``job_id`` of a live ``cron_jobs`` row
    for the same job, so ``source_id`` is the cron job_id. Column mapping onto the SAME
    output dict keys this function has always produced:

    ===============  =========================================
    old (legacy)      task_runs (modern) successor
    ===============  =========================================
    job_id            source_id (filtered to runtime='cron')
    status             status
    run_id             run_id
    session_key        child_session_key
    run_at_ms          started_at
    ts                 created_at
    session_id         NO SUCCESSOR -- left None
    ===============  =========================================

    ``session_id`` has no analogue in ``task_runs`` and is deliberately left ``None`` on
    the modern path rather than backfilled from a different column — inventing a value
    there would misattribute a run to a session it was never recorded under.

    Same dual-shape discipline as ``_collect_cron``'s ``cron_jobs`` reader: the two SQLite
    TABLES are probed for existence via ``PRAGMA table_info(<name>)`` (zero rows back means
    absent, no exception raised either way), not by trying one SELECT and catching
    ``sqlite3.OperationalError``, which cannot distinguish "the other schema" from "a
    genuine read failure". When BOTH tables exist (a mid-migration DB), the LEGACY table
    wins — it is the one this reader was originally grounded against, and preferring it
    keeps behaviour stable on such a machine.

    DELIBERATELY NOT read on the legacy path: ``entry_json`` — it is
    ``JSON.stringify(entry)`` of the RUN RECORD (jobId/status/summary/session/model/timing
    — run-log-DIhrTrSU.js:97 ``bindCronRunLogRow``), NOT a copy of the job's original
    ``payload.message``. Content-scanning it for the erased directive would be unreliable,
    so this collector takes only the structural/pivot columns: which job ran, when, and
    under which session. ``task_runs`` is never ``SELECT *``'d either — the same state DB
    holds live OAuth tokens (§8).

    Opened READ-ONLY (``file:...?mode=ro`` + ``PRAGMA query_only = 1``), the same pattern
    ``_collect_plugin_trust`` uses on this exact database. Neither table present leaves
    ``cron_run_logs_found`` False — UNKNOWN downstream, never a fake PASS (Golden Rule #4).
    """
    state_dir = home / "state"
    sqlite_candidates = (
        walk_dir_safely(state_dir, max_files=100)
        if _safe_is_dir(state_dir, ctx, what=f"'{state_dir}'") else []
    )
    db_path = next((p for p in sqlite_candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return  # no state DB -> cron_run_logs_found stays False (UNKNOWN, not a fake PASS)

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
            # B-709: PROBE which of the two tables exist before picking a SELECT -- do NOT
            # try the legacy query and fall back to the modern one on
            # `sqlite3.OperationalError: no such table`. An exception-driven fallback
            # cannot tell "this DB uses the other schema" apart from "a genuine read
            # failure" (a locked db, a corrupt page, an I/O error raise the same way), so
            # it would silently swallow a real error as a shape mismatch -- the same
            # fail-open family `_collect_cron`'s B-709 fix already guards against there.
            # `PRAGMA table_info(name)` on a table that does not exist returns zero rows
            # (no exception) -- the same presence-by-metadata idiom `_collect_cron` uses,
            # and unlike a `SELECT ... FROM sqlite_master` probe it is not itself parsed by
            # `scripts/state_db_drift_gate.py`'s SELECT/FROM extractor as a third table
            # this reader expects to exist.
            legacy_present = bool(list(conn.execute("PRAGMA table_info(cron_run_logs)")))
            if legacy_present:
                # LEGACY table -- unchanged from before B-709. Preferred even when
                # task_runs also exists (a mid-migration DB): this is the table the
                # reader was originally grounded against.
                cur = conn.execute(
                    "SELECT job_id, status, session_id, session_key, run_id, run_at_ms, ts "
                    "FROM cron_run_logs ORDER BY ts DESC LIMIT ?",
                    # Same off-by-one fix as the cron_jobs read: one extra row is the
                    # truncation probe, so a table holding EXACTLY the cap is not reported
                    # as having had "older run history NOT read" when all of it was read.
                    (_MAX_CRON_RUN_LOGS + 1,),
                )
                rows = cur.fetchall()
                modern = False
            elif list(conn.execute("PRAGMA table_info(task_runs)")):
                # MODERN successor (OpenClaw 2026.8.2+). Filtered to runtime='cron' so a
                # non-cron task_runs row (e.g. runtime='subagent') is never mistaken for a
                # cron execution -- that would invent cron history that never happened.
                cur = conn.execute(
                    "SELECT source_id, status, run_id, child_session_key, started_at, "
                    "created_at FROM task_runs WHERE runtime = ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    ("cron", _MAX_CRON_RUN_LOGS + 1),
                )
                rows = cur.fetchall()
                modern = True
            else:
                return  # neither table -> same honest "not found" as before B-709
        finally:
            conn.close()
    except sqlite3.Error as exc:
        # A state DB predating either table is not a corrupt store -- same honest
        # UNKNOWN as "not found" (mirrors _collect_cron / _collect_plugin_trust).
        if "no such table" not in str(exc).lower():
            ctx.errors.append(f"could not read cron run logs from {db_path}: {exc}")
            ctx.cron_run_logs_found = True
            ctx.cron_run_logs_parse_error = True
        return

    ctx.cron_run_logs_found = True
    run_logs_truncated = len(rows) > _MAX_CRON_RUN_LOGS
    rows = rows[:_MAX_CRON_RUN_LOGS]  # discard the probe row; the scanned set stays capped
    if modern:
        for source_id, status, run_id, child_session_key, started_at, created_at in rows:
            ctx.cron_run_logs.append({
                "job_id": source_id,
                "status": status,
                "session_id": None,  # B-709: no successor column on task_runs
                "session_key": child_session_key,
                "run_id": run_id,
                "run_at_ms": started_at,
                "ts": created_at,
            })
    else:
        for job_id, status, session_id, session_key, run_id, run_at_ms, ts in rows:
            ctx.cron_run_logs.append({
                "job_id": job_id,
                "status": status,
                "session_id": session_id,
                "session_key": session_key,
                "run_id": run_id,
                "run_at_ms": run_at_ms,
                "ts": ts,
            })
    if run_logs_truncated:
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_CRON,
            f"cron run-log table in '{db_path}' returned the {_MAX_CRON_RUN_LOGS}-row cap "
            "— older run history was NOT read",
        )


# F-183. The three machine-owned config values OpenClaw 2026.8.1 moved OUT of
# openclaw.json and into its own state database. This is a new CATEGORY of schema change:
# the setting did not move within the JSON, it left the JSON, so every `dig(cfg, ...)`
# reader of these keys is looking somewhere the runtime no longer writes.
#
# An EXPLICIT allowlist, never a table dump. The same database holds live OAuth tokens
# under `authProfiles.store` and `auth.sharedStore` -- measured on a real machine, both
# rows present -- so a generic reader, a debug dump, or an evidence string carrying a
# value would turn a security audit into a credential leak (§8).
# A single value is read whole, so it needs a bound like every other reader here
# (`_MAX_CRON_JOBS`, `_MAX_CONFIG_BYTES`). Measured: a hostile or corrupt store can hold a
# multi-megabyte `hooks.internal.installs` record, and an unbounded read of it is the one
# denial-of-service surface this reader has. 256 KB is far above any real record and far
# below anything that matters for memory.
_MAX_MACHINE_STATE_VALUE_BYTES = 256 * 1024

CONFIG_MACHINE_STATE_KEYS = (
    "plugins.bundledDiscovery",   # enum: compat | allowlist -- the allowlist OFF SWITCH
    "cron.store",                 # JSON-encoded string: where the real cron store lives
    "hooks.internal.installs",    # the record shape the old config key held
)


def _collect_config_machine_state(home: Path, ctx: Context) -> None:
    """Read the allowlisted rows of ``config_machine_state`` into ``ctx``.

    Three fields, because "could not look" and "looked, nothing there" are different
    answers and collapsing them is exactly the lying-clean this exists to prevent:

    * ``config_machine_state_read``      the table was opened and queried at all
    * ``config_machine_state``           key -> parsed value, for the keys that were set
    * ``config_machine_state_unparsed``  keys whose row exists but whose ``value_json``
                                         is not valid JSON -- present, and NOT readable,
                                         which is neither "set to X" nor "not set"

    Opened READ-ONLY (``file:...?mode=ro`` + ``PRAGMA query_only = 1``), the same pattern
    the cron and plugin-trust readers already use on this exact database.

    Why it matters, grounded in the dist rather than argued: the runtime's own
    ``readBundledDiscoveryMode`` calls ``readConfigMachineState("plugins.bundledDiscovery")``
    (``bundled-discovery-state-*.js``) -- the STATE store, not the config -- and
    ``withBundledPluginEnablementCompat`` then does
    ``const bypassAllowlist = readBundledDiscoveryMode() === "compat"``, leaving ``allowSet``
    undefined so every bundled plugin becomes eligible (``bundled-compat-*.js``). And the
    value can appear without the user ever writing it: ``migrateLegacyConfigMachineState``
    (``state-migrations.config-machine-state-*.js``) pushes ``["plugins.bundledDiscovery",
    "compat"]`` on upgrade when ``plugins.allow`` is non-empty and
    ``meta.lastTouchedVersion`` predates ``BUNDLED_DISCOVERY_STATE_CUTOVER_VERSION =
    "2026.7.2"``. So the population that loses its allowlist is exactly the population that
    took the trouble to write one.
    """
    state_dir = home / "state"
    capped: list = []
    candidates = (
        walk_dir_safely(state_dir, max_files=100, capped=capped)
        if _safe_is_dir(state_dir, ctx, what=f"'{state_dir}'") else []
    )
    db_path = next((p for p in candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        # `read` stays False -> UNDETERMINED, never "not compat". But a walk that stopped
        # early is not the same fact as an empty state dir, and reporting them alike would
        # be a silent completeness claim over a capped scan (GR#4). Five sibling readers
        # take the `_EXEMPT` route in tests/test_paired_call_sites.py; that list says in
        # its own words that it is debt and not to be extended, so this one discloses.
        if capped:
            ctx.errors.append(
                f"stopped listing '{state_dir}' after 100 entries without finding "
                "openclaw.sqlite; the machine-owned config store was not read"
            )
        return

    placeholders = ",".join("?" for _ in CONFIG_MACHINE_STATE_KEYS)
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
            rows = conn.execute(
                # The key list is bound, not interpolated, and there is no `SELECT *`:
                # this query cannot return a row this tool is not allowed to see.
                f"SELECT state_key, value_json FROM config_machine_state "
                f"WHERE state_key IN ({placeholders})",
                CONFIG_MACHINE_STATE_KEYS,
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        # A state DB predating the table is not a corrupt store -- the same honest
        # UNDETERMINED as "no DB", mirroring _collect_cron_run_logs.
        if "no such table" not in str(exc).lower():
            ctx.errors.append(f"could not read config_machine_state from {db_path}: {exc}")
        return

    ctx.config_machine_state_read = True
    for state_key, value_json in rows:
        if not isinstance(state_key, str):
            continue
        if isinstance(value_json, (str, bytes)) and \
                len(value_json) > _MAX_MACHINE_STATE_VALUE_BYTES:
            # Over the cap is "present and not read", never "absent": a consumer must not
            # answer "not set" about a row it declined to parse.
            ctx.config_machine_state_unparsed.add(state_key)
            continue
        try:
            ctx.config_machine_state[state_key] = json.loads(value_json)
        except (TypeError, ValueError):
            # Present but unreadable. Recording it as absent would let a consumer answer
            # "not set" about a row that exists.
            ctx.config_machine_state_unparsed.add(state_key)


def _collect_capture_state(home: Path, ctx: Context) -> None:
    """B-295 (DISK-4): read-only METADATA about OpenClaw's debug-proxy traffic capture,
    stored in the shared state database (~/.openclaw/state/openclaw.sqlite).

    Grounded against the installed dist (openclaw-state-db-DzSsA9Ji.js, verbatim
    ``CREATE TABLE IF NOT EXISTS``): ``capture_events`` (id, session_id, ts, source_scope,
    source_process, protocol, direction, kind, flow_id, method, host, path, status,
    close_code, content_type, headers_json, data_text, data_blob_id, data_sha256,
    error_text, meta_json), ``capture_blobs`` (blob_id, content_type, encoding, size_bytes,
    sha256, data, created_at) and ``capture_sessions``. ``env-DNgUBPBb.js`` marks the legacy
    ``state/debug-proxy/capture.sqlite`` path ``@deprecated Capture storage now lives in the
    shared state database``, confirming these rows land in the shared DB.

    COUNTS ONLY — deliberately. ``headers_json`` carries bearer tokens and ``data_text``
    carries request bodies, so §8 makes reading them a disclosure hazard, and flagging the
    hosts a developer legitimately captured (provider APIs, ClawHub) would be a false
    "exfil" signal. This collector therefore reads ``COUNT(*)`` and nothing else: no host,
    no header, no body, no blob ever leaves the database. That is enough to answer the
    question the check asks — "was your agent's traffic recorded to disk in plaintext, and
    how much" — without reading a single captured byte.

    Opened READ-ONLY (``file:...?mode=ro`` + ``PRAGMA query_only = 1``), the same pattern
    ``_collect_plugin_trust`` and ``_collect_cron_run_logs`` use on this exact database.
    Absent DB or absent tables leave ``capture_tables_found`` False -> UNKNOWN downstream.
    """
    state_dir = home / "state"
    sqlite_candidates = (
        walk_dir_safely(state_dir, max_files=100)
        if _safe_is_dir(state_dir, ctx, what=f"'{state_dir}'") else []
    )
    db_path = next((p for p in sqlite_candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return  # no state DB -> capture_tables_found stays False (UNKNOWN, not a fake PASS)

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
            events = conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0]
            try:
                blobs = conn.execute("SELECT COUNT(*) FROM capture_blobs").fetchone()[0]
            except sqlite3.Error:
                blobs = 0
        finally:
            conn.close()
    except sqlite3.Error as exc:
        # A state DB predating the capture tables is not corrupt -- same honest UNKNOWN as
        # "not found" (mirrors _collect_cron / _collect_plugin_trust).
        if "no such table" not in str(exc).lower():
            ctx.errors.append(f"could not read capture_events from {db_path}: {exc}")
            ctx.capture_tables_found = True
            ctx.capture_parse_error = True
        return

    ctx.capture_tables_found = True
    ctx.capture_event_rows = int(events or 0)
    ctx.capture_blob_rows = int(blobs or 0)


def _collect_exec_approvals(home: Path, ctx: Context) -> None:
    """B-236 (B172): read-only collection of the standing OpenClaw exec-approvals
    store (~/.openclaw/exec-approvals.json) into ``ctx.exec_approvals_grants``.

    Grounded against the installed dist (exec-approvals-BIKWP8_V.js): the file is a
    single top-level JSON object (written by OpenClaw itself via JSON.stringify --
    never JSON5, so this reads it with plain ``json.loads``, not the config loader)
    shaped ``{version, socket, defaults: {security, ask, askFallback, autoAllowSkills},
    agents: {<agentId>: {security, ask, askFallback, allowlist: [{pattern, argPattern?,
    source, id, ...}]}}}``. An ``agents.<id>.allowlist[]`` entry with
    ``source == "allow-always"`` is a durable per-command exec approval persisted by a
    historical "always allow" click -- a standing grant living entirely outside
    openclaw.json that no check previously read (grep for "exec-approvals" across
    clawseccheck/ was zero hits before this).

    IMPORTANT (adversarially corrected during B-236's own review): OpenClaw computes
    the EFFECTIVE exec policy as minSecurity(tools.exec.security, execApprovals.security)
    + maxAsk(tools.exec.ask, execApprovals.ask) (bash-tools*.js:581-582;
    exec-approvals-BIKWP8_V.js:1126-1140 -- runtime comment "Stricter values from
    tools.exec and ...exec-approvals both apply"). A standing grant can only TIGHTEN
    the openclaw.json gate, never loosen it -- so this collector exists to make a
    persisted grant VISIBLE/inventoried (check_exec_approvals_grants, B172), not to
    imply it bypasses tools.exec (it provably does not).

    The file lives directly under ``home`` (a single fixed filename, not a
    subdirectory to walk), so this checks ``is_symlink()`` itself rather than reusing
    ``walk_dir_safely`` -- a symlinked store is treated as absent (never followed),
    matching that helper's own symlink policy without walking the whole home tree just
    to find one top-level file.

    ``ctx.exec_approvals_found`` stays False when the file is absent -- a consuming
    check reports UNKNOWN, never a fake PASS (Golden Rule #4, the B-228 pattern).
    """
    target = home / "exec-approvals.json"
    try:
        skip = target.is_symlink() or not target.is_file()
    except OSError as exc:
        # B-303: same class of exposure as _safe_is_dir/_safe_is_file — a non-traversable
        # ancestor (typically the whole home) must degrade this to "not found" (->
        # ctx.exec_approvals_found stays False -> UNKNOWN downstream), never crash.
        ctx.errors.append(f"could not check '{target}': {exc}")
        skip = True
    if skip:
        return
    try:
        with open(target, "rb") as fp:
            raw, truncated = _read_with_limit(fp, _MAX_EXEC_APPROVALS_BYTES)
        if truncated:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_APPROVALS,
                f"exec-approvals store '{target}' exceeded the "
                f"{_MAX_EXEC_APPROVALS_BYTES // 1_000_000}MB cap — content beyond the "
                "cap was NOT scanned",
            )
        store = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(store, dict):
            raise ValueError("exec-approvals.json root is not a JSON object")
        agents = store.get("agents")
        if not isinstance(agents, dict):
            agents = {}
        ctx.exec_approvals_found = True
        for agent_id, agent in list(agents.items())[:_MAX_EXEC_APPROVALS_AGENTS]:
            if not isinstance(agent, dict):
                continue
            allowlist = agent.get("allowlist")
            allow_always_count = 0
            if isinstance(allowlist, list):
                allow_always_count = sum(
                    1 for e in allowlist
                    if isinstance(e, dict) and e.get("source") == "allow-always"
                )
            security = agent.get("security")
            ask = agent.get("ask")
            ctx.exec_approvals_grants.append({
                "agent_id": agent_id if isinstance(agent_id, str) else str(agent_id),
                "security": security if isinstance(security, str) else None,
                "ask": ask if isinstance(ask, str) else None,
                "allow_always_count": allow_always_count,
            })
    except (OSError, ValueError) as exc:
        ctx.errors.append(f"could not parse {target}: {exc}")
        ctx.exec_approvals_found = True
        ctx.exec_approvals_parse_error = True


def _plugin_trust_record_from(plugin_id, rec: dict) -> dict:
    """Build one ``ctx.plugin_trust_records`` entry from a raw install-record dict.

    Shared by BOTH sinks (legacy ``installed_plugin_index.install_records_json`` and the
    OC-82 ``config_machine_state['plugins.installedIndex']`` successor, fallback leg
    included) so the output shape cannot drift between them — see
    ``_collect_plugin_trust``'s docstring for the selection rule.
    """
    disposition = rec.get("clawhubTrustDisposition")
    reasons = rec.get("clawhubTrustReasons")
    return {
        "plugin_id": plugin_id if isinstance(plugin_id, str) else str(plugin_id),
        "disposition": disposition if isinstance(disposition, str) else None,
        "scan_status": rec.get("clawhubTrustScanStatus")
        if isinstance(rec.get("clawhubTrustScanStatus"), str) else None,
        "moderation_state": rec.get("clawhubTrustModerationState")
        if isinstance(rec.get("clawhubTrustModerationState"), str) else None,
        "reasons": [r for r in reasons if isinstance(r, str)]
        if isinstance(reasons, list) else [],
        "pending": rec.get("clawhubTrustPending")
        if isinstance(rec.get("clawhubTrustPending"), bool) else None,
        "stale": rec.get("clawhubTrustStale")
        if isinstance(rec.get("clawhubTrustStale"), bool) else None,
    }


def _plugin_index_record_from(rec: dict) -> dict:
    """Build one ``ctx.plugin_index_records`` entry from a raw plugin-index-array dict.

    Shared by BOTH sinks -- see ``_plugin_trust_record_from`` and
    ``_collect_plugin_trust``'s docstring.
    """
    plugin_id = rec.get("pluginId")
    origin = rec.get("origin")
    enabled = rec.get("enabled")
    contributions = rec.get("contributions")
    contracts_raw = (
        contributions.get("contracts")
        if isinstance(contributions, dict) else None
    )
    contracts: dict = {}
    if isinstance(contracts_raw, dict):
        for key, values in contracts_raw.items():
            if isinstance(key, str) and isinstance(values, list):
                contracts[key] = [v for v in values if isinstance(v, str)]
    return {
        "plugin_id": plugin_id if isinstance(plugin_id, str) else str(plugin_id),
        "origin": origin if isinstance(origin, str) else None,
        "enabled": enabled if isinstance(enabled, bool) else None,
        "manifest_path": rec.get("manifestPath")
        if isinstance(rec.get("manifestPath"), str) else None,
        "root_dir": rec.get("rootDir")
        if isinstance(rec.get("rootDir"), str) else None,
        "source": rec.get("source")
        if isinstance(rec.get("source"), str) else None,
        "contracts": contracts,
    }


def _plugin_index_object_is_valid(index_obj: object) -> bool:
    """OC-82/C-135: does ``index_obj`` (the ``value_json -> index`` sub-object of
    ``config_machine_state['plugins.installedIndex']``) pass the SAME acceptance test
    the runtime's OWN parser applies before it trusts a row
    (``installed-plugin-index-store-*.js:75-93`` — symbol
    ``extractPluginInstallRecordsFromInstalledPluginIndex``, re-verified present in
    openclaw@2026.9.1; line numbers read on 2026.8.2, filename globbed because it
    rehashes every release)?

    That parser requires, on top of a numeric top-level ``revision`` (checked
    separately by the caller): ``version === 1``, a non-empty ``hostContractVersion``,
    a non-empty ``compatRegistryVersion``, ``migrationVersion === 1``, a non-empty
    ``policyHash``, a numeric ``generatedAtMs``, a valid ``plugins`` array, and (when
    present) a valid ``installRecords`` map. ANY failure there returns null and the
    runtime discards the WHOLE row — so a row failing this must not be trusted by this
    tool either; checking ``revision`` alone let a row the runtime itself would reject
    be treated here as authoritative (the concrete case: ``installRecords`` naming a
    plugin absent from ``plugins`` is a MODELLED, tolerated runtime state — see
    ``installed-plugin-index-store-*.js:131-136`` — not evidence this row is
    bad; it is the "index" object's OWN internal field validity that must be checked).

    Measured on a real machine (2026.8.2): all nine ``index`` fields present with the
    right types, zero orphan install records.
    """
    if not isinstance(index_obj, dict):
        return False

    def _is_exactly_one(v: object) -> bool:
        return isinstance(v, (int, float)) and not isinstance(v, bool) and v == 1

    def _nonempty_str(v: object) -> bool:
        return isinstance(v, str) and v != ""

    generated_at_ms = index_obj.get("generatedAtMs")
    plugins_val = index_obj.get("plugins")
    install_records_val = index_obj.get("installRecords")
    return (
        _is_exactly_one(index_obj.get("version"))
        and _is_exactly_one(index_obj.get("migrationVersion"))
        and _nonempty_str(index_obj.get("hostContractVersion"))
        and _nonempty_str(index_obj.get("compatRegistryVersion"))
        and _nonempty_str(index_obj.get("policyHash"))
        and isinstance(generated_at_ms, (int, float))
        and not isinstance(generated_at_ms, bool)
        and isinstance(plugins_val, list)
        and (
            "installRecords" not in index_obj
            or isinstance(install_records_val, dict)
        )
    )


def _collect_plugin_trust(home: Path, ctx: Context) -> None:
    """B-240 (B177) + B-292 (RT-2) + OC-82: read-only collection of the persisted
    installed-plugin index into TWO independent ``ctx`` fields:
    ``ctx.plugin_trust_records`` (OpenClaw's own ClawHub trust verdict) and
    ``ctx.plugin_index_records`` (the full per-plugin index record — origin/enabled/
    contracts).

    TWO backing shapes exist, probed in this order over the SAME read-only connection:

    A. (OC-82, OpenClaw 2026.8.2+) ``config_machine_state.value_json`` where
       ``state_key = 'plugins.installedIndex'``. The ``state-consolidation-v13``
       migration folded the whole ``installed_plugin_index`` table into this one KV row.
       Grounded against the installed dist: writer
       ``installed-plugin-index-store-*.js:63-71`` (``INSERT ... ON CONFLICT DO
       UPDATE``), key constant ``installed-plugin-index-store-*.js:10``, reader
       ``installed-plugin-index-record-reader-*.js:57-58``, and the vendor's own
       shipped docs (``docs/reference/database-schemas.md:213`` states the fold plainly;
       ``:723-741`` is a downgrade script reconstructing the old table by
       ``json_extract`` from this exact key). Measured on a real machine: ``value_json``
       decodes to ``{"index": {...}, "revision": <int>}``; ``index.installRecords`` is a
       dict keyed by pluginId (2 entries observed); ``index.plugins`` is a list (61
       entries observed); ``index.diagnostics`` is a list.
    B/C. (legacy) ``installed_plugin_index.install_records_json`` /
       ``.plugins_json`` where ``index_key = 'installed-plugin-index'`` — the original
       table, unchanged from before OC-82. See the historical grounding kept below.

    SELECTION RULE — a predicate over the OBSERVED ROW, never ``PRAGMA user_version`` or
    an OpenClaw version string (the state DB's own migration ladder does not map onto
    OpenClaw releases 1:1):

    * A returns a row whose parsed JSON is a dict with a NUMERIC ``revision`` AND an
      ``index`` object that passes ``_plugin_index_object_is_valid`` -> A is the source
      for BOTH ``plugin_trust_records`` and ``plugin_index_records``; B/C are never
      consulted (their ``SELECT``s stay in this source file only as the OTHER-generation
      branch a mid-migration/pre-OC-82 database satisfies — see
      ``scripts/state_db_drift_gate.py``). The numeric-``revision`` requirement mirrors
      the runtime's OWN rejection of a row it did not write
      (``installed-plugin-index-store-*.js:118``); the ``index``-object check
      mirrors the runtime's OWN parser (``installed-plugin-index-store-*.js:75-93``),
      which additionally requires ``version === 1``,
      ``hostContractVersion``, ``compatRegistryVersion``, ``migrationVersion === 1``,
      ``policyHash``, ``generatedAtMs``, a valid ``plugins`` array, and a fully-valid
      ``installRecords`` map — ANY failure there returns null and the runtime discards
      the WHOLE row. A row the runtime itself would discard must not be one this tool
      trusts either (C-135: checking ``revision`` alone let a downgraded/foreign-
      generation row be trusted here and ignored by the runtime).
    * A absent (no ``config_machine_state`` table, or no row for that key, or the SELECT
      itself failed) -> legacy path, byte-for-byte as before OC-82.
    * Neither present -> both ``*_found`` pairs stay False -> UNKNOWN, exactly as today.
      This must never regress into a fake PASS (Golden Rule #4).
    * A PRESENT but its ``value_json`` is not valid JSON, or parses to something other
      than a dict, or ``revision`` is missing/non-numeric, or ``index`` fails the
      validity check above -> ``plugin_trust_found = plugin_trust_parse_error = True``
      (and likewise the index pair). Present-and-unreadable is reported as such, NEVER
      silently treated as absent-and-therefore-falling-back to the legacy columns — a
      hand-downgraded DB can carry both shapes, and a broken modern row must not be
      masked by a legacy read that happens to succeed.
    * A over the byte cap -> disclosed and marked unreadable WITHOUT attempting a
      partial parse (a mid-JSON slice makes ``json.loads`` raise, so slicing first would
      just relabel a truncation bug as a parse-error bug).

    EXTRACTION from shape A's ``value_json -> index``:

    * ``plugin_trust_records``: if the key ``installRecords`` is present and a dict,
      iterate it exactly like legacy ``install_records_json``. ELSE (key absent)
      assemble it from ``plugins[*].installRecord`` keyed by ``plugins[*].pluginId`` --
      grounded in what the runtime itself does
      (``installed-plugin-index-store-*.js:92`` ->
      ``installed-plugin-index-*.js:1214-1219``). Inert on the machine this was
      grounded against (0 of 61 plugin entries carry ``installRecord``), implemented
      anyway so this reader has no blind spot the runtime does not have.
    * ``plugin_index_records``: iterate ``index.plugins`` (a LIST) -- a different
      iteration idiom from ``installRecords`` (a DICT) on purpose; they are not
      interchangeable shapes.

    Per-record output keeps the EXACT keys/types/coercions the legacy path has always
    produced (see ``_plugin_trust_record_from`` / ``_plugin_index_record_from``, shared by
    both sinks) -- deliberately NOT extended with ``manifestHash`` even though shape A
    carries it; that is a separate change to the record contract.

    Disclosed via ``note_limit(ctx.limit_hits, LIMIT_DOMAIN_PLUGIN, ...)``, in addition to
    the (unchanged) byte/record caps: (1) shape A is a persisted CACHE the runtime wrote at
    its last refresh, not a live read of what the gateway currently has loaded; (2) when
    ``len(installRecords) < len(plugins)``, that the ClawHub trust verdict is only defined
    over the plugins that actually carry an install record -- on the grounding machine
    that is 2 of 61, so without this line a "no untrusted plugin found" PASS reads as a
    claim about all 61 when it is really a claim about 2.

    ``config_machine_state`` is never ``SELECT *``'d: the same table holds live OAuth
    tokens under ``authProfiles.store``/``auth.sharedStore`` (§8; ``collector.py``'s
    module docstring), so the query below names ``value_json`` explicitly and binds the
    state key as a parameter, never string-interpolated.

    --- Historical grounding (legacy B/C path, unchanged) ---

    OpenClaw persists a single-row ``installed_plugin_index`` table (primary key
    ``index_key = 'installed-plugin-index'``) in the shared state SQLite database,
    resolved to ``~/.openclaw/state/openclaw.sqlite`` (openclaw-state-db-DzSsA9Ji.js:
    resolveOpenClawStateSqlitePath -> <stateDir>/state/openclaw.sqlite). The table's
    ``CREATE TABLE`` statement (openclaw-state-db-DzSsA9Ji.js:995-1008) declares BOTH
    ``install_records_json`` and ``plugins_json`` ``TEXT NOT NULL`` in the one statement
    that defines this table — there is no schema version where the table exists but
    either column is absent or NULL.

    ``install_records_json`` (B177) is a JSON object keyed by pluginId
    (installed-plugin-index-store-CWgFGnm0.js: readPersistedInstalledPluginIndexFromSqlite);
    each install record MAY carry ``clawhubTrustDisposition`` ("clean" |
    "review-recommended" | "review-required" | "blocked" — types.openclaw-CXjMEWAQ.d.ts:
    1308), ``clawhubTrustScanStatus``, ``clawhubTrustModerationState``,
    ``clawhubTrustReasons`` (string[]), ``clawhubTrustPending``, ``clawhubTrustStale``
    (installed-plugin-index-records-C_n191FN.js: CLAWHUB_TRUST_INSTALL_RECORD_FIELDS) —
    OpenClaw's own ClawHub malware-scan/moderation verdict for that install, computed at
    install/refresh time (clawhub-install-trust-DdnykQnp.js).

    ``plugins_json`` (B-292 / RT-2) is a JSON ARRAY — one full index record per installed
    plugin, built by ``buildInstalledPluginIndexRecords``/``buildContributionInfo``
    (installed-plugin-index-N4jxqS0-.js:1241-1256, :1330-1390): each record carries
    ``pluginId``, ``origin`` ("bundled" | "global" | ... — provenance, NOT a trust verdict),
    ``enabled``, ``manifestPath``, ``manifestHash``, ``rootDir``, ``source``, and
    ``contributions.contracts`` — a dict of OpenClaw plugin-contract name (e.g.
    ``agentToolResultMiddleware``) -> ``normalizeSortedUniqueStringEntries(values)`` (a
    sorted, deduplicated array of plain strings; :1241). This is an INVENTORY OF NAMES that
    the plugin registered, never a behavior spec, and two narrower readings of it are
    explicitly refuted by the same normalization: ``contributions.providers`` carries no
    ``baseURL`` field at all (channels/providers/modelCatalogProviders are all normalized to
    bare string ids — B178 already covers the real provider-baseURL surface, which lives in
    config, not here), and ``commandAliases`` is normalized to
    ``alias.name`` ONLY (:1254) — the mapping TARGET is stripped before persistence, so this
    column can show that an alias name exists and never what it invokes. See
    ``checks/_mcp.py::check_plugin_tool_result_middleware`` for the consuming check and the
    mass-false-positive trap (67 of 69 plugins on a stock install are ``origin: "bundled"``).

    The same state database also has ``auth_profile_stores``/``auth_profile_state`` tables
    (columns: store_key, store_json/state_json, updated_at) that plausibly hold live MCP
    OAuth credentials — this collector deliberately reads ONLY installed_plugin_index and
    config_machine_state's allowlisted ``plugins.installedIndex`` key, never those tables;
    openclaw.sqlite itself should stay 0600 regardless.

    B-293 corrected a factually WRONG claim that stood here: this comment used to assert
    that "B11 already covers general config/state-file permissions". It does not. B11 reads
    only ``ctx.config_mode``, which collector sets from ``cfg_path.stat()`` — openclaw.json's
    mode ALONE. Nothing stat'ed the state database until B188
    (``checks/_egress.py::check_state_db_atrest``), which is now the check that covers this
    file's at-rest permissions.

    Opened READ-ONLY via the ``file:...?mode=ro`` URI plus ``PRAGMA query_only = 1`` — this
    collector never writes to the shared state database. Reuses the exact
    ``walk_dir_safely(state_dir)`` + filename-match pattern ``_collect_cron`` already uses
    for the same file (symlink-safe, path-escape-safe).

    ``ctx.plugin_trust_found`` / ``ctx.plugin_index_found`` stay False when the state DB,
    the table, or the index row is absent — a consuming check reports UNKNOWN, never a fake
    PASS (Golden Rule #4). ``ctx.plugin_trust_parse_error`` / ``ctx.plugin_index_parse_error``
    are set when the DB/table/row exist but that column could not be read or parsed (locked
    DB, corrupt file, malformed JSON) — also surfaced as UNKNOWN downstream, never a crash.
    On the legacy path each column's found/parse-error pair is independent: a corrupt
    ``plugins_json`` cell, OR the ``plugins_json`` column being entirely absent from the
    table (an unexpected schema shape, not one any known OpenClaw version ships, but not
    ruled out for a hand-modified or pre-existing older table), does not blind the
    ``install_records_json`` (B177) reader, and vice versa. This is enforced by issuing the
    two columns' ``SELECT``s separately (each in its own ``try``/``except sqlite3.Error``)
    rather than one combined query — a combined query previously meant one column's "no
    such column" error failed the query as a whole and incorrectly flipped BOTH
    ``*_found`` flags (B-292/RT-2 round 2). On the modern (shape A) path the two columns
    necessarily share one fate, since both are extracted from the same JSON blob.
    """
    state_dir = home / "state"
    sqlite_candidates = (
        walk_dir_safely(state_dir, max_files=100)
        if _safe_is_dir(state_dir, ctx, what=f"'{state_dir}'") else []
    )
    db_path = next((p for p in sqlite_candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return  # no state DB -> both *_found stay False (UNKNOWN, not a fake PASS)

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        # Cannot even open the file as a database -- a shared root cause (not sqlite,
        # unreadable, etc.), so both columns genuinely are unreadable together here.
        ctx.errors.append(f"could not open {db_path}: {exc}")
        ctx.plugin_trust_found = True
        ctx.plugin_trust_parse_error = True
        ctx.plugin_index_found = True
        ctx.plugin_index_parse_error = True
        return

    try:
        try:
            conn.execute("PRAGMA query_only = 1")
        except sqlite3.Error as exc:
            # C-135 round-2 residual (RT-2): this PRAGMA used to share one try/except with
            # the connect() call above; the two-SELECT split (see the note below) left it
            # uncovered, so a PRAGMA-level failure would crash the whole audit uncaught
            # instead of degrading to UNKNOWN. No real config was found to trigger this
            # (garbage-bytes files and an active writer lock both still let the PRAGMA
            # succeed), but it costs nothing to guard: same shared-root-cause handling as
            # the connect() failure above, since a PRAGMA failure here means the same
            # thing -- the database is unusable for both columns, not just one.
            ctx.errors.append(f"could not set query_only on {db_path}: {exc}")
            ctx.plugin_trust_found = True
            ctx.plugin_trust_parse_error = True
            ctx.plugin_index_found = True
            ctx.plugin_index_parse_error = True
            return

        # ---- Probe A (OC-82, tried FIRST): the config_machine_state successor row.
        # Named column only, key bound as a parameter -- never SELECT * (see docstring).
        try:
            state_row = conn.execute(
                "SELECT value_json FROM config_machine_state WHERE state_key = ?",
                ("plugins.installedIndex",),
            ).fetchone()
        except sqlite3.Error as exc:
            state_row = None
            # "no such table" (a pre-OC-82 state DB with no config_machine_state table
            # at all) is the same honest "A absent" as no matching row -- falls through
            # to the legacy probes below, same carve-out _collect_cron/_collect_cron_run_logs
            # already use. Any other error is logged for diagnostics but treated the same
            # way (we never obtained a row to call "present"), since we cannot yet call it
            # a broken A row -- only a row we HAVE cannot be silently treated as absent.
            if "no such table" not in str(exc).lower():
                ctx.errors.append(
                    "could not read config_machine_state for plugins.installedIndex "
                    f"from {db_path}: {exc}"
                )
        state_value_json = state_row[0] if state_row is not None else None

        if state_value_json is None:
            # ---- Probes B/C (legacy): install_records_json's OWN SELECT, independent of
            # plugins_json. B-292/RT-2 fix: a merged single-query read let a schema shape
            # missing ONE column (e.g. "no such column: plugins_json") take down BOTH
            # *_found flags, contradicting this function's own independence claim below.
            # Two separate SELECTs mean a column-absence error (or a genuine per-column
            # read failure) is attributed to that column's ctx fields only -- never its
            # sibling's.
            try:
                trust_row = conn.execute(
                    "SELECT install_records_json FROM installed_plugin_index "
                    "WHERE index_key = 'installed-plugin-index'"
                ).fetchone()
            except sqlite3.Error as exc:
                trust_row = None
                # "no such table" (state DB predates the plugin index entirely) is the
                # same honest UNKNOWN as "not found" (mirrors _collect_cron's carve-out)
                # -- not a parse error. Any other error, including "no such column", IS a
                # genuine read failure for THIS column only.
                if "no such table" not in str(exc).lower():
                    ctx.errors.append(
                        "could not read installed_plugin_index.install_records_json from "
                        f"{db_path}: {exc}"
                    )
                    ctx.plugin_trust_found = True
                    ctx.plugin_trust_parse_error = True

            # ---- plugins_json (B-292/RT-2): its OWN SELECT, independent of the above ----
            try:
                index_row = conn.execute(
                    "SELECT plugins_json FROM installed_plugin_index "
                    "WHERE index_key = 'installed-plugin-index'"
                ).fetchone()
            except sqlite3.Error as exc:
                index_row = None
                if "no such table" not in str(exc).lower():
                    ctx.errors.append(
                        f"could not read installed_plugin_index.plugins_json from {db_path}: {exc}"
                    )
                    ctx.plugin_index_found = True
                    ctx.plugin_index_parse_error = True
        else:
            trust_row = None
            index_row = None
    finally:
        conn.close()

    # ==================================================================================
    # A present (a row came back from config_machine_state) -> A wins outright, for BOTH
    # columns. B/C are never consulted here even if they would also succeed (a
    # hand-downgraded DB can carry both shapes; the KV row is what the running gateway
    # writes -- see docstring's selection rule).
    # ==================================================================================
    if state_value_json is not None:
        byte_len = (
            len(state_value_json) if isinstance(state_value_json, (str, bytes)) else None
        )
        if byte_len is not None and byte_len > _MAX_PLUGIN_TRUST_BYTES:
            # Over the cap -- disclose and mark unreadable WITHOUT attempting a partial
            # parse: slicing a JSON object blob mid-document makes json.loads raise, so a
            # slice-then-parse would just relabel this same outcome as a "parse error"
            # while pretending the cap wasn't the real cause.
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                "config_machine_state['plugins.installedIndex'] in "
                f"{db_path} exceeded the {_MAX_PLUGIN_TRUST_BYTES // 1_000_000}MB cap — "
                "content was NOT scanned (no partial parse was attempted)",
            )
            ctx.plugin_trust_found = True
            ctx.plugin_trust_parse_error = True
            ctx.plugin_index_found = True
            ctx.plugin_index_parse_error = True
        else:
            try:
                state_obj = json.loads(state_value_json)
            except (TypeError, ValueError) as exc:
                ctx.errors.append(
                    "could not parse config_machine_state['plugins.installedIndex'] in "
                    f"{db_path}: {exc}"
                )
                state_obj = None

            revision = state_obj.get("revision") if isinstance(state_obj, dict) else None
            revision_is_number = (
                isinstance(revision, (int, float)) and not isinstance(revision, bool)
            )
            # C-135: the runtime's own parser rejects the WHOLE row unless "index" also
            # passes its field-validity check (see _plugin_index_object_is_valid) --
            # checking "revision" alone let a row the runtime itself discards be
            # trusted here, and let an unrelated "installRecords names a plugin absent
            # from plugins" state (a MODELLED, tolerated runtime condition) be
            # misread as corruption instead of what it actually is.
            index_probe = state_obj.get("index") if isinstance(state_obj, dict) else None
            index_probe_is_valid = _plugin_index_object_is_valid(index_probe)

            if not isinstance(state_obj, dict) or not revision_is_number or not index_probe_is_valid:
                # Present but unusable: the row exists, but either it is not a JSON
                # object, its "revision" is missing/non-numeric, or its "index" object
                # fails the runtime's own validity check -- the same fields the
                # runtime itself checks before trusting a row
                # (installed-plugin-index-store-*.js:75-93,118). Reported as
                # present-and-unreadable, NEVER silently as absent (which would fall
                # through to the legacy columns above and mask a broken modern row with
                # a legacy read that happens to still succeed).
                if isinstance(state_obj, dict):
                    ctx.errors.append(
                        "config_machine_state['plugins.installedIndex'] in "
                        f"{db_path} has a missing/non-numeric 'revision' or an "
                        "'index' object that fails OpenClaw's own field-validity "
                        "check -- not trusted"
                    )
                ctx.plugin_trust_found = True
                ctx.plugin_trust_parse_error = True
                ctx.plugin_index_found = True
                ctx.plugin_index_parse_error = True
            else:
                # ---- A is the source for BOTH columns. ----
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                    "plugin trust/index data comes from a persisted CACHE -- "
                    f"config_machine_state['plugins.installedIndex'] in {db_path}, "
                    "written at the runtime's last refresh -- this collector reads "
                    "that row and cannot certify it still matches what the gateway "
                    "currently has loaded",
                )

                index_obj = index_probe  # already validated as a dict above
                plugins_list = index_obj.get("plugins")
                plugins_list = plugins_list if isinstance(plugins_list, list) else []

                install_records_val = index_obj.get("installRecords")
                if "installRecords" in index_obj and isinstance(install_records_val, dict):
                    installs = install_records_val
                else:
                    # FALLBACK leg (grounded: installed-plugin-index-store-*.js:92
                    # -> installed-plugin-index-*.js:1214-1219) -- assemble the
                    # trust map from each plugin's own installRecord when the top-level
                    # installRecords key is absent. This is what the runtime itself does;
                    # inert on the grounding machine (0 of 61 plugins carry
                    # installRecord), implemented anyway so this reader has no blind spot
                    # the runtime does not have.
                    installs = {}
                    for p in plugins_list:
                        if not isinstance(p, dict):
                            continue
                        pid = p.get("pluginId")
                        rec = p.get("installRecord")
                        if isinstance(pid, str) and isinstance(rec, dict):
                            installs[pid] = rec

                ctx.plugin_trust_found = True
                for plugin_id, rec in list(installs.items())[:_MAX_PLUGIN_TRUST_RECORDS]:
                    if not isinstance(rec, dict):
                        continue
                    ctx.plugin_trust_records.append(_plugin_trust_record_from(plugin_id, rec))
                if len(installs) > _MAX_PLUGIN_TRUST_RECORDS:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                        "config_machine_state['plugins.installedIndex'] in "
                        f"{db_path} has {len(installs)} install record(s) — only the "
                        f"first {_MAX_PLUGIN_TRUST_RECORDS} were scanned",
                    )

                ctx.plugin_index_found = True
                for rec in plugins_list[:_MAX_PLUGIN_INDEX_RECORDS]:
                    if not isinstance(rec, dict):
                        continue
                    ctx.plugin_index_records.append(_plugin_index_record_from(rec))
                if len(plugins_list) > _MAX_PLUGIN_INDEX_RECORDS:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                        "config_machine_state['plugins.installedIndex'] in "
                        f"{db_path} has {len(plugins_list)} plugin record(s) — only "
                        f"the first {_MAX_PLUGIN_INDEX_RECORDS} were scanned",
                    )

                # THE MOST IMPORTANT disclosure: the ClawHub trust verdict is only
                # defined over the plugins that actually carry an install record. On the
                # grounding machine that is 2 of 61 -- without this, a "no untrusted
                # plugin found" PASS reads as a claim about all 61 plugins when it is
                # really a claim about 2.
                if len(installs) < len(plugins_list):
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                        "config_machine_state['plugins.installedIndex'] in "
                        f"{db_path} lists {len(plugins_list)} plugin(s) but carries "
                        f"install records for only {len(installs)} — the ClawHub "
                        "trust verdict is only defined over those; the rest have no "
                        "verdict on record",
                    )
        return

    # ==================================================================================
    # Legacy path (A absent): behaviour byte-for-byte as before OC-82.
    # ==================================================================================
    trust_raw = trust_row[0] if trust_row is not None else None
    index_raw = index_row[0] if index_row is not None else None

    # ---- install_records_json (B177: OpenClaw's own ClawHub trust verdict) ----
    if trust_raw is not None:
        raw = trust_raw
        if len(raw) > _MAX_PLUGIN_TRUST_BYTES:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                f"installed_plugin_index.install_records_json in {db_path} exceeded the "
                f"{_MAX_PLUGIN_TRUST_BYTES // 1_000_000}MB cap — content beyond the cap was "
                "NOT scanned",
            )
            raw = raw[:_MAX_PLUGIN_TRUST_BYTES]

        try:
            installs = json.loads(raw)
        except ValueError as exc:
            ctx.errors.append(f"could not parse install_records_json in {db_path}: {exc}")
            ctx.plugin_trust_found = True
            ctx.plugin_trust_parse_error = True
            installs = None
        if installs is not None and not isinstance(installs, dict):
            ctx.plugin_trust_found = True
            ctx.plugin_trust_parse_error = True
            installs = None

        if installs is not None:
            ctx.plugin_trust_found = True
            for plugin_id, rec in list(installs.items())[:_MAX_PLUGIN_TRUST_RECORDS]:
                if not isinstance(rec, dict):
                    continue
                ctx.plugin_trust_records.append(_plugin_trust_record_from(plugin_id, rec))
            if len(installs) > _MAX_PLUGIN_TRUST_RECORDS:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                    f"installed_plugin_index in {db_path} has {len(installs)} install "
                    f"record(s) — only the first {_MAX_PLUGIN_TRUST_RECORDS} were scanned",
                )

    # ---- plugins_json (B-292 / RT-2: full per-plugin index record) ----
    if index_raw is not None:
        raw2 = index_raw
        if len(raw2) > _MAX_PLUGIN_INDEX_BYTES:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                f"installed_plugin_index.plugins_json in {db_path} exceeded the "
                f"{_MAX_PLUGIN_INDEX_BYTES // 1_000_000}MB cap — content beyond the cap "
                "was NOT scanned",
            )
            raw2 = raw2[:_MAX_PLUGIN_INDEX_BYTES]

        try:
            plugins = json.loads(raw2)
        except ValueError as exc:
            ctx.errors.append(f"could not parse plugins_json in {db_path}: {exc}")
            ctx.plugin_index_found = True
            ctx.plugin_index_parse_error = True
            plugins = None
        if plugins is not None and not isinstance(plugins, list):
            ctx.plugin_index_found = True
            ctx.plugin_index_parse_error = True
            plugins = None

        if plugins is not None:
            ctx.plugin_index_found = True
            for rec in plugins[:_MAX_PLUGIN_INDEX_RECORDS]:
                if not isinstance(rec, dict):
                    continue
                ctx.plugin_index_records.append(_plugin_index_record_from(rec))
            if len(plugins) > _MAX_PLUGIN_INDEX_RECORDS:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_PLUGIN,
                    f"installed_plugin_index.plugins_json in {db_path} has "
                    f"{len(plugins)} plugin record(s) — only the first "
                    f"{_MAX_PLUGIN_INDEX_RECORDS} were scanned",
                )


def _parse_subagent_outcome(raw) -> "tuple[dict | None, bool]":
    """Best-effort parse of one ``subagent_runs.outcome_json`` cell.

    Returns ``(outcome, ok)``. ``ok`` is False ONLY when *raw* is a non-empty string that
    failed to parse as JSON — a genuinely unexpected cell shape. A NULL/blank cell (the run
    has not ended yet, or no outcome was ever recorded) is ``(None, True)``: that is normal,
    not corruption, and must not be confused with a parse failure by the caller (which
    invalidates the whole row's disclosure — see ``_collect_subagent_runs``). A value that
    parses but is not a JSON object (bare ``null``/number/string) is also ``(None, True)``:
    syntactically valid, just no outcome fields to surface.
    """
    if raw is None:
        return None, True
    if not isinstance(raw, str) or not raw.strip():
        return None, True
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None, False
    if isinstance(parsed, dict):
        return parsed, True
    return None, True


def _parse_subagent_modern_payload(raw) -> "tuple[dict, bool]":
    """B-709: parse one MODERN ``subagent_runs.payload_json`` cell (the consolidated blob
    that replaced the ``model``/``run_timeout_seconds``/``outcome_json``/``ended_reason``
    columns on OpenClaw 2026.8.2+) into a plain dict, for named-key extraction only (§8 —
    the blob carries far more than the handful of keys this collector takes, and the same
    state DB holds live OAuth tokens under ``authProfiles.store``/``auth.sharedStore``, so
    it is never stored or emitted whole).

    Returns ``(fields, ok)``, mirroring ``_parse_subagent_outcome``'s contract but over the
    WHOLE row rather than one sub-field: ``ok`` is False ONLY when *raw* is a non-empty
    string that fails to parse as JSON, or is some other non-string, non-``None`` shape —
    the row is then genuinely unreadable and the caller drops it whole, the same
    whole-row-drop the legacy path already applies to an unparseable ``outcome_json``. A
    ``None``/blank cell, or one that parses to the empty object (the column's own SQL
    default, ``payload_json TEXT NOT NULL DEFAULT '{}'``, i.e. a freshly-registered run with
    nothing recorded yet) is ``({}, True)`` — that is the NORMAL still-running shape, not
    corruption. A syntactically valid but non-object payload (bare null/number/string) is
    also ``({}, True)``: nothing to extract, but not an error either.
    """
    if raw is None:
        return {}, True
    if not isinstance(raw, str):
        return {}, False
    if not raw.strip():
        return {}, True
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}, False
    if isinstance(parsed, dict):
        return parsed, True
    return {}, True


def _collect_subagent_runs(home: Path, ctx: Context) -> None:
    """B-296 (DISK-5 increment 1): read-only collection of the OpenClaw subagent-spawn
    registry (``subagent_runs`` in ``~/.openclaw/state/openclaw.sqlite``) into
    ``ctx.subagent_runs``.

    Grounded against the installed dist (``subagent-registry-state-CP7kKu69.js``,
    ``openclaw-state-db-DzSsA9Ji.js`` — verbatim ``CREATE TABLE IF NOT EXISTS subagent_runs``,
    PK ``run_id``): columns ``run_id, child_session_key, controller_session_key,
    requester_session_key, requester_display_key, requester_origin_json, task, task_name,
    cleanup, label, model, agent_dir, workspace_dir, run_timeout_seconds, spawn_mode,
    created_at, started_at, ..., outcome_json, archive_at_ms, cleanup_completed_at,
    cleanup_handled, ..., ended_reason, ...``. See ``docs/research/openclaw-schema-recon.md``
    §28 for the full insert/retention grounding; the two facts that shape this collector:

    INSERT SEMANTICS (population was UNPROVEN at filing time — GR#4 required grounding
    before shipping): a row is written SYNCHRONOUSLY at spawn time, before the subagent does
    any work. ``subagent-registry-DexSZ4w1.js`` (the register path): ``params.runs.set(runId,
    entry)`` followed immediately by ``params.persistOrThrow()`` (-> ``saveSubagentRegistryToSqlite``
    -> an upsert into ``subagent_runs`` keyed on ``run_id``), with the newly-set entry rolled
    back on a persist failure. So a row proves a spawn was REGISTERED — not necessarily that
    it ran to completion; ``outcome_json`` is what distinguishes the two (absent/null while
    the run is still in flight).

    RETENTION IS SHORT — do not imply durable forensic history. The same module's periodic
    sweep deletes a completed run's row via the whole-snapshot
    ``deleteFrom("subagent_runs").where("run_id","not in", runIds)`` replace once
    ``archiveAtMs`` (``now + agents.defaults.subagents.archiveAfterMinutes`` — default 60
    MINUTES after the run was SPAWNED/REGISTERED (``resolveArchiveAfterMs``), NEVER
    recomputed at completion — a long-running run's window can already be nearly spent
    by the time it ends) has passed, or ~5 minutes after
    cleanup completes for session-mode runs with no ``archiveAtMs`` at all
    (``SESSION_RUN_TTL_MS = 5 * 60_000``). The one documented exception: a run registered
    with ``cleanup:"keep"`` (non-session spawn mode) gets NO ``archiveAtMs`` and the sweep
    skips it outright — kept until something else (e.g. the owning session's own lifecycle)
    removes it. So: a populated table proves RECENT (or explicitly kept) activity, never a
    complete history of every subagent ever spawned.

    WAL LAG: opened READ-ONLY (``file:...?mode=ro`` + ``PRAGMA query_only = 1``), the same
    pattern every other reader of this database uses. A reader connection sees the last
    COMMITTED snapshot, including anything already committed into the WAL file (SQLite
    readers do not require a checkpoint) — so this never needs special WAL handling, but a
    row committed a moment after this connection opened is legitimately invisible. That is
    read-consistency, not absence: the caller (``checks/_agents.py``) must never treat
    ``rows == 0`` as proof no subagent has ever run, only as "none observed in this snapshot".

    ``ctx.subagent_runs_found`` stays False when the state DB or the table itself is absent
    (a fresh/pre-subagent install) — the consuming check reports UNKNOWN, never a fake PASS
    (Golden Rule #4). ``ctx.subagent_runs_parse_error`` is set only when NOT ONE row could be
    reliably parsed (every ``outcome_json`` cell present failed to decode as JSON) — a row
    whose outcome merely parses to "no outcome yet" is not an error and is kept; a run mixed
    with some good and some bad rows keeps the good ones (matches the tolerant per-record
    style ``_collect_plugin_trust`` already uses, rather than letting one corrupt cell blind
    the whole disclosure to otherwise-trustworthy sibling rows).

    B-709: on the installed OpenClaw 2026.8.2, the real ``subagent_runs`` columns are ONLY
    ``run_id, child_session_key, controller_session_key, requester_session_key, created_at,
    payload_json`` — the old SELECT above threw ``sqlite3.OperationalError: no such column:
    model`` on every run, so ``ctx.errors`` carried that line and B18 reported UNKNOWN even
    on a machine that had really spawned subagents. Grounded against the vendor's OWN
    canonical read of this table (``dist/subagent-registry.store.sqlite-B_lUfEus.js:341-351``,
    which aliases the JSON payload straight back to the retired column names — as
    authoritative a mapping as exists):

    ===================  =========================================
    old (legacy) column   MODERN payload_json JSON path
    ===================  =========================================
    model                  $.model
    run_timeout_seconds    $.runTimeoutSeconds
    ended_reason           $.endedReason
    outcome_json           $.execution.outcome.status (a STATUS STRING, one of
                            "ok"|"error"|"timeout"|"unknown" — :362 — not a blob)
    child_session_key,     real columns, unchanged (:337, :340)
    created_at
    ===================  =========================================

    ``agent_dir``, ``workspace_dir``, ``spawn_mode`` and ``task`` appear NOWHERE in that
    canonical read — they are GONE, not moved (``task`` is literally the pre-v13 schema
    marker in the migration gate, ``dist/openclaw-state-db-*.js:1900`` — the
    ``workspace_attestations`` marker re-verified present in openclaw@2026.9.1, line
    read on 2026.8.2). They are set
    ``None`` on the modern path, and a consumer must not read that ``None`` as "no
    workspace" — a ONE-TIME (per collection run, not per row) disclosure is emitted via
    ``note_limit(ctx.limit_hits, LIMIT_DOMAIN_AGENTS, ...)`` naming exactly which fields are
    unavailable on this schema, so ``limit_hits_for(ctx, LIMIT_DOMAIN_AGENTS)`` lets a
    consumer tell "no workspace was ever recorded" apart from "this schema cannot say".

    Which shape a given install has is decided by PROBING ``PRAGMA table_info(subagent_runs)``
    once and branching on COLUMN PRESENCE — never by trying one SELECT and catching
    ``sqlite3.OperationalError``, which cannot distinguish "this is the other schema" from "a
    genuine read failure" (same reasoning as ``_collect_cron``'s ``cron_jobs`` dual-shape
    reader). ``model`` present -> LEGACY (checked first: the one real fixture this repo has
    seen that names both ``model`` and ``payload_json`` on the same table is the ORIGINAL
    B-296 grounding, predating this migration, and legacy must keep winning on it — same
    "legacy wins when both tables/shapes exist" precedent ``_collect_cron_run_logs`` uses).
    ``payload_json`` present (and no ``model``) -> MODERN. Neither -> the same honest
    found=True/``subagent_runs_parse_error``=True verdict a genuinely unreadable store
    already gets, with the columns actually seen recorded (never a guessed mapping).

    Named-key extraction only on the modern path (§8) — ``payload_json`` itself is never
    stored or emitted whole, only the four keys above are pulled out of it.
    """
    state_dir = home / "state"
    sqlite_candidates = (
        walk_dir_safely(state_dir, max_files=100)
        if _safe_is_dir(state_dir, ctx, what=f"'{state_dir}'") else []
    )
    db_path = next((p for p in sqlite_candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return  # no state DB -> subagent_runs_found stays False (UNKNOWN, not a fake PASS)

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
            # B-709: probe the real column shape before picking a SELECT -- see the
            # docstring above for why an exception-driven fallback is rejected.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(subagent_runs)")}
            if not columns:
                return  # no subagent_runs table at all -- same honest "not found" as before

            if "model" in columns:
                # LEGACY shape -- unchanged from before B-709. Preferred even when
                # payload_json also exists (a mid-migration / dual-column table): this is
                # the shape this reader was originally grounded against.
                cur = conn.execute(
                    "SELECT child_session_key, model, agent_dir, workspace_dir, spawn_mode, "
                    "run_timeout_seconds, task, outcome_json, ended_reason, created_at "
                    "FROM subagent_runs ORDER BY created_at DESC LIMIT ?",
                    # Same off-by-one truncation probe every other capped SELECT here uses:
                    # one extra row is requested purely to detect "more exist", discarded.
                    (_MAX_SUBAGENT_RUNS + 1,),
                )
                rows = cur.fetchall()
                modern = False
            elif "payload_json" in columns:
                # MODERN shape (OpenClaw 2026.8.2+). Only the real columns
                # (child_session_key, created_at) plus the opaque payload_json blob exist;
                # model/run_timeout_seconds/outcome_json/ended_reason are extracted from
                # the blob per-row below (named-key extraction only, §8).
                cur = conn.execute(
                    "SELECT child_session_key, created_at, payload_json "
                    "FROM subagent_runs ORDER BY created_at DESC LIMIT ?",
                    (_MAX_SUBAGENT_RUNS + 1,),
                )
                rows = cur.fetchall()
                modern = True
            else:
                # Neither shape recognised. Do NOT guess a mapping for an unknown layout --
                # the same honest "found but could not be read" verdict a genuinely corrupt
                # store already gets, reusing that flag rather than adding a third one a
                # consumer would also have to learn. The columns actually seen are recorded
                # (literal facts about the table, not invented data) for diagnosis.
                ctx.errors.append(
                    f"subagent_runs table in '{db_path}' has neither the legacy ('model') "
                    f"nor the modern ('payload_json') column shape -- columns seen: "
                    f"{sorted(columns)}; not read"
                )
                ctx.subagent_runs_found = True
                ctx.subagent_runs_parse_error = True
                return
        finally:
            conn.close()
    except sqlite3.Error as exc:
        # A state DB predating the subagent registry table is not a corrupt store -- same
        # honest UNKNOWN as "not found" (mirrors _collect_cron/_collect_plugin_trust). Now
        # mostly defense-in-depth: the table_info probe above already returns early on a
        # genuinely absent table before any SELECT runs.
        if "no such table" not in str(exc).lower():
            ctx.errors.append(f"could not read subagent_runs from {db_path}: {exc}")
            ctx.subagent_runs_found = True
            ctx.subagent_runs_parse_error = True
        return

    ctx.subagent_runs_found = True
    truncated = len(rows) > _MAX_SUBAGENT_RUNS
    rows = rows[:_MAX_SUBAGENT_RUNS]  # discard the probe row; scanned set stays capped

    if modern and rows:
        # B-709: the lost-field disclosure -- ONE per collection run (not per row), only on
        # the modern path, only when at least one row was actually read. Wording matched as
        # closely as the code allows to what other consumers of this schema-change expect.
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_AGENTS,
            f"subagent_runs in '{db_path}' uses the consolidated payload schema: "
            "agent_dir, workspace_dir, spawn_mode and task are not present on this "
            "state schema — NOT read",
        )

    good: list[dict] = []
    bad_count = 0
    if modern:
        for child_session_key, created_at, payload_json in rows:
            fields, ok = _parse_subagent_modern_payload(payload_json)
            if not ok:
                # Whole payload unreadable -- there is nothing else on this row to fall
                # back on (unlike the legacy columns, every extracted field lives inside
                # this one blob), so the whole row is dropped, same as an unparseable
                # legacy outcome_json.
                bad_count += 1
                continue
            model = fields.get("model")
            run_timeout_seconds = fields.get("runTimeoutSeconds")
            ended_reason = fields.get("endedReason")
            execution = fields.get("execution")
            outcome_obj = execution.get("outcome") if isinstance(execution, dict) else None
            status = outcome_obj.get("status") if isinstance(outcome_obj, dict) else None
            # Out-of-vocabulary / absent status (still running, or an unrecognised value)
            # is "no outcome yet" -- normal, never surfaced as a fabricated fifth value.
            outcome = {"status": status} if status in _SUBAGENT_OUTCOME_STATUSES else None
            good.append({
                "child_session_key": child_session_key,
                "model": model,
                "agent_dir": None,       # B-709: gone, not moved -- see docstring
                "workspace_dir": None,   # B-709: gone, not moved -- see docstring
                "spawn_mode": None,      # B-709: gone, not moved -- see docstring
                "run_timeout_seconds": run_timeout_seconds,
                "task": None,            # B-709: gone, not moved -- see docstring
                "outcome": outcome,
                "ended_reason": ended_reason,
                "created_at": created_at,
            })
    else:
        for (child_session_key, model, agent_dir, workspace_dir, spawn_mode,
             run_timeout_seconds, task, outcome_json, ended_reason, created_at) in rows:
            outcome, ok = _parse_subagent_outcome(outcome_json)
            if not ok:
                bad_count += 1
                continue
            task_text = task if isinstance(task, str) else None
            if task_text is not None and len(task_text) > _MAX_SUBAGENT_TASK_CHARS:
                task_text = task_text[:_MAX_SUBAGENT_TASK_CHARS] + "...(truncated)"
            good.append({
                "child_session_key": child_session_key,
                "model": model,
                "agent_dir": agent_dir,
                "workspace_dir": workspace_dir,
                "spawn_mode": spawn_mode,
                "run_timeout_seconds": run_timeout_seconds,
                "task": task_text,
                "outcome": outcome,
                "ended_reason": ended_reason,
                "created_at": created_at,
            })

    if not good and bad_count:
        # Every row's payload was unparseable -- nothing here can be asserted reliably
        # (GR#4: no fabricated facts). Fall back to the honest UNKNOWN, matching the "table
        # absent" branch, rather than surface a disclosure built on undecodable data.
        ctx.subagent_runs_parse_error = True
        return

    ctx.subagent_runs = good
    if truncated:
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_AGENTS,
            f"subagent_runs table in '{db_path}' returned the {_MAX_SUBAGENT_RUNS}-row cap "
            "— older spawns were NOT read",
        )


def _collect_audit_events(home: Path, ctx: Context) -> None:
    """F-134 (DISK-1, B191): read-only collection of OpenClaw's OWN runtime audit trail
    (``audit_events`` in the shared state SQLite database) into ``ctx.audit_events``.

    Grounded against the installed dist, verbatim ``CREATE TABLE IF NOT EXISTS audit_events``
    (``openclaw-state-db-DzSsA9Ji.js:509-527``): ``sequence, event_id, source_id,
    source_sequence, occurred_at, kind, action, status, error_code, actor_type, actor_id,
    agent_id, session_key, session_id, run_id, tool_call_id, tool_name``. Written by
    ``recordAuditEvent`` (``audit-event-store-D1P32Q4Y.js:60``), fed by
    ``projectToolExecutionEventToAudit`` / ``projectAgentEvent``
    (``server-runtime-subscriptions-OlWMLbPY.js``). ``grep -rn "audit_events"`` across this
    package was zero hits before this collector.

    GR#5 HARD BLOCKER — read this before adding a new consumer of ``ctx.audit_events``.
    The table stores ``tool_name`` alone: there is no argv, no command string, no file
    path, no target host anywhere in the schema (verified column-by-column above). A
    benign ``bash`` build step and exfiltration-staging ``bash`` are the SAME row shape.
    Nothing downstream may build a volumetric or tool-name-presence rule ("bash ran N
    times") from this data — that would false-FAIL essentially every real config,
    including a benign one (measured on the real box: 344 of 502 rows are plain ``bash``).
    This collector only ever feeds the two narrow, near-zero-FP signals ``status=='blocked'``
    /``error_code=='tool_blocked'`` and ``tool_name=='unknown'``, plus a session-id
    corroboration join — see ``checks/_host.py::check_audit_trail_signals``.

    RETENTION IS DOCUMENTED, not "uncapped": ``AUDIT_EVENT_RETENTION_MS`` (30 days) and
    ``AUDIT_EVENT_MAX_ROWS`` (100,000) are pruned on every insert
    (``audit-event-store-D1P32Q4Y.js:6-7,52-57``) — an explicit, knowable bound, unlike the
    trajectory sidecar's *silent* ``_MAX_FILES`` (60) file-count drop (``trajectory.py``).
    That asymmetry is the whole point of reading this table at all: it can outlive a
    disabled or rotated-out trajectory source for the SAME sessions (F-134's corroboration
    use — see ``behavioral.py``).

    ``ctx.audit_events_total_rows``/``_oldest_ms``/``_newest_ms`` are read over the FULL
    table (cheap aggregate query, index-backed — ``idx_audit_events_time``) independent of
    the row-sample cap below, so "how far back does this reach" is never limited by how
    many rows the signal-detection sample kept. The row SAMPLE (``ctx.audit_events``,
    capped at ``_MAX_AUDIT_EVENTS``, most-recent-first) is what the two narrow signals and
    the session-id corroboration read.

    Opened READ-ONLY (``file:...?mode=ro`` + ``PRAGMA query_only = 1``), the same pattern
    every other reader of this database uses. Absent DB or absent table leaves
    ``audit_events_found`` False — UNKNOWN downstream, never a fake PASS (Golden Rule #4).
    An empty table (pruned down to nothing, or a fresh install) is NOT the same as absent:
    it is recorded distinctly via ``audit_events_total_rows == 0`` so a consumer can tell
    "never read" apart from "read, and currently empty".
    """
    state_dir = home / "state"
    sqlite_candidates = (
        walk_dir_safely(state_dir, max_files=100)
        if _safe_is_dir(state_dir, ctx, what=f"'{state_dir}'") else []
    )
    db_path = next((p for p in sqlite_candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return  # no state DB -> audit_events_found stays False (UNKNOWN, not a fake PASS)

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
            agg_row = conn.execute(
                "SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at) FROM audit_events"
            ).fetchone()
            cur = conn.execute(
                "SELECT kind, action, status, error_code, actor_type, actor_id, agent_id, "
                "session_key, session_id, run_id, tool_call_id, tool_name, occurred_at "
                "FROM audit_events ORDER BY sequence DESC LIMIT ?",
                # Same off-by-one truncation probe every other capped SELECT here uses: one
                # extra row is requested purely to detect "more exist", then discarded.
                (_MAX_AUDIT_EVENTS + 1,),
            )
            rows = cur.fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        # A state DB predating the audit_events table is not a corrupt store -- same
        # honest UNKNOWN as "not found" (mirrors _collect_cron_run_logs/_collect_subagent_runs).
        if "no such table" not in str(exc).lower():
            ctx.errors.append(f"could not read audit_events from {db_path}: {exc}")
            ctx.audit_events_found = True
            ctx.audit_events_parse_error = True
        return

    ctx.audit_events_found = True
    total, oldest_ms, newest_ms = agg_row if agg_row else (0, None, None)
    ctx.audit_events_total_rows = int(total or 0)
    ctx.audit_events_oldest_ms = int(oldest_ms) if oldest_ms is not None else None
    ctx.audit_events_newest_ms = int(newest_ms) if newest_ms is not None else None

    truncated = len(rows) > _MAX_AUDIT_EVENTS
    rows = rows[:_MAX_AUDIT_EVENTS]  # discard the probe row; the scanned sample stays capped
    for (kind, action, status, error_code, actor_type, actor_id, agent_id, session_key,
         session_id, run_id, tool_call_id, tool_name, occurred_at) in rows:
        ctx.audit_events.append({
            "kind": kind,
            "action": action,
            "status": status,
            "error_code": error_code,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "agent_id": agent_id,
            "session_key": session_key,
            "session_id": session_id,
            "run_id": run_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "occurred_at": occurred_at,
        })
    if truncated:
        ctx.audit_events_truncated = True
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_AUDIT,
            f"audit_events table in '{db_path}' returned the {_MAX_AUDIT_EVENTS}-row cap — "
            "older audit rows were NOT read (the coverage stats above are exact; the row "
            "sample used for signal detection is not)",
        )


def _env_str(env: "dict[str, str]", name: str) -> "str | None":
    """A trimmed env value, or None when OpenClaw would treat it as unset.

    Mirrors ``normalize$1`` (home-dir-CJKEsOtx.js:13-17): empty/whitespace-only and the
    literal strings ``"undefined"`` / ``"null"`` are unset. The path vars additionally go
    through ``?.trim()`` at every dist call site, so trimming here is not an extra
    liberty — it is what the product does.
    """
    raw = env.get(name)
    if not isinstance(raw, str):
        return None
    trimmed = raw.strip()
    if not trimmed or trimmed in ("undefined", "null"):
        return None
    return trimmed


def _expand_user_path(raw: str, home_dir: Path) -> Path:
    """Mirror ``resolveUserPath`` → ``resolveHomeRelativePath`` (paths-BMBAvkNf.js:68-73).

    A leading ``~`` expands against the EFFECTIVE home (which OPENCLAW_HOME may itself
    have moved), not against the OS home — which is why *home_dir* is passed in rather
    than calling ``Path.expanduser()``. Relative paths are resolved against the process
    cwd exactly as ``path.resolve`` does.
    """
    if raw == "~" or raw.startswith("~/") or raw.startswith("~\\"):
        return Path(str(home_dir) + raw[1:])
    return Path(raw)


def openclaw_effective_home(env: "dict[str, str] | None" = None) -> Path:
    """The home directory OpenClaw would resolve — ``resolveRequiredHomeDir``.

    Order (home-dir-CJKEsOtx.js:31-58): ``OPENCLAW_HOME`` (with a leading ``~`` expanded
    against the OS home), then ``HOME``, then ``USERPROFILE``, then ``os.homedir()``.
    Termux's ``PREFIX``/``ANDROID_DATA`` branch is deliberately NOT mirrored: it only
    fires on Android under com.termux, and guessing at it would be a fabricated fact.
    """
    env = os.environ if env is None else env
    os_home = _env_str(env, "HOME") or _env_str(env, "USERPROFILE")
    os_home_path = Path(os_home) if os_home else Path.home()
    explicit = _env_str(env, "OPENCLAW_HOME")
    if explicit is None:
        return os_home_path
    return _expand_user_path(explicit, os_home_path)


def openclaw_state_dir(env: "dict[str, str] | None" = None,
                       home_dir: "Path | None" = None) -> Path:
    """Mirror ``resolveStateDir`` (paths-BMBAvkNf.js:44-62).

    ``OPENCLAW_STATE_DIR`` wins; otherwise ``~/.openclaw`` when it exists, else an
    EXISTING legacy ``~/.clawdbot``, else ``~/.openclaw``. The existence probes are the
    product's own (``fs.existsSync``), so mirroring them is required for fidelity — they
    are read-only stats on the auditing user's own home.
    """
    env = os.environ if env is None else env
    home_dir = openclaw_effective_home(env) if home_dir is None else home_dir
    override = _env_str(env, "OPENCLAW_STATE_DIR")
    if override is not None:
        return _expand_user_path(override, home_dir)
    new_dir = home_dir / OPENCLAW_NEW_STATE_DIRNAME
    try:
        if new_dir.exists():
            return new_dir
        for legacy in OPENCLAW_LEGACY_STATE_DIRNAMES:
            legacy_dir = home_dir / legacy
            if legacy_dir.exists():
                return legacy_dir
    except OSError:
        pass
    return new_dir


def resolve_config_in_home(home: Path) -> "tuple[Path, bool]":
    """The config file OpenClaw would read *inside this specific home dir*.

    Returns ``(path, found)``. ``openclaw.json`` wins when present; otherwise an existing
    legacy ``clawdbot.json`` is preferred, mirroring the "prefer an existing candidate"
    half of ``resolveConfigPath`` (paths-BMBAvkNf.js:141-147). When neither exists the
    canonical name is returned with ``found=False`` so the caller's error message names
    the file a user would actually create.

    This is deliberately ENV-FREE and confined to *home*: it is the hermetic half of the
    resolver, safe to run under ``--home``/fixture scans, and it can never retarget the
    audit somewhere the caller did not ask for. The environment-driven half is reported
    by ``resolve_product_config_path`` and never silently followed.
    """
    canonical = home / OPENCLAW_CONFIG_FILENAME
    try:
        if canonical.is_file():
            return canonical, True
        for name in OPENCLAW_LEGACY_CONFIG_FILENAMES:
            legacy = home / name
            if legacy.is_file():
                return legacy, True
    except OSError:
        pass
    return canonical, False


def resolve_product_config_path(env: "dict[str, str] | None" = None) -> "tuple[Path | None, str]":
    """The config path the INSTALLED OpenClaw would read, given *env*.

    Faithful mirror of ``resolveConfigPath`` (paths-BMBAvkNf.js:136-152) plus the
    ``resolveConfigPathCandidate``/``resolveDefaultConfigCandidates`` fallback it defers
    to (:118-133, :175-190). Returns ``(path, reason)`` where *reason* names the branch
    that decided, for evidence. ``(None, reason)`` when it cannot be determined.

    This function READS the process environment. It never changes what is audited — the
    caller compares it against the audited path and reports a divergence. Silently
    retargeting the scan on an environment variable would mean the printed grade
    described a subject the user never named, which is a worse failure than the one this
    exists to catch.
    """
    env = os.environ if env is None else env
    try:
        home_dir = openclaw_effective_home(env)
    except (OSError, RuntimeError):
        return None, "the effective home directory could not be resolved"

    override = _env_str(env, "OPENCLAW_CONFIG_PATH")
    if override is not None:
        return _expand_user_path(override, home_dir), "OPENCLAW_CONFIG_PATH is set"

    state_override = _env_str(env, "OPENCLAW_STATE_DIR")
    state_dir = openclaw_state_dir(env, home_dir)

    # Prefer an existing candidate under the state dir (canonical, then legacy names).
    for name in (OPENCLAW_CONFIG_FILENAME,) + OPENCLAW_LEGACY_CONFIG_FILENAMES:
        cand = state_dir / name
        try:
            if cand.exists():
                if name != OPENCLAW_CONFIG_FILENAME:
                    return cand, f"a legacy {name} exists in the resolved state directory"
                if state_override is not None:
                    return cand, "OPENCLAW_STATE_DIR is set"
                return cand, "the default state directory"
        except OSError:
            continue

    if state_override is not None:
        return state_dir / OPENCLAW_CONFIG_FILENAME, "OPENCLAW_STATE_DIR is set"

    # stateDir == defaultStateDir here (we resolved both the same way), so the dist falls
    # through to resolveConfigPathCandidate → resolveDefaultConfigCandidates.
    for base in (home_dir / OPENCLAW_NEW_STATE_DIRNAME,) + tuple(
        home_dir / d for d in OPENCLAW_LEGACY_STATE_DIRNAMES
    ):
        for name in (OPENCLAW_CONFIG_FILENAME,) + OPENCLAW_LEGACY_CONFIG_FILENAMES:
            cand = base / name
            try:
                if cand.exists():
                    return cand, "an existing default config candidate"
            except OSError:
                continue
    return state_dir / OPENCLAW_CONFIG_FILENAME, "the canonical default path"


def audits_default_state_dir(home: Path, env: "dict[str, str] | None" = None) -> bool:
    """True when *home* is the state dir a bare, env-free ``openclaw`` would use.

    This is the hermeticity gate for B183. It is an audited-home-IDENTITY test, not argv
    sniffing — the same doctrine as ``_b182_audits_this_users_own_home`` — so it behaves
    identically whether the user typed ``--home ~/.openclaw`` or typed nothing.

    It is deliberately STRICTER than B182's predicate: it requires the exact default
    directory rather than any ``~/.openclaw*`` sibling. Auditing ``~/.openclaw-work`` is
    an explicit act of targeting one profile, and a divergence warning there would be
    telling the user something they already know — the spurious-finding case the task
    brief calls out. Under a fixture scan this is False, so B183 reports UNKNOWN and can
    never manufacture an environment-driven finding (Golden Rule #5).

    The reference default is computed with the OPENCLAW_* path variables STRIPPED. That
    is not a detail: computing it from the live environment would let the very variable
    that causes a divergence decide that no divergence can be reported. Setting
    ``OPENCLAW_STATE_DIR`` (what ``openclaw --profile`` does) moves the "default", so
    ``~/.openclaw`` stops matching it and the check falls silent on the single most
    likely shape of the bug it exists to catch. Caught by
    ``test_b183_warns_on_a_state_dir_profile``. The question here is only "is this home
    the canonical one for this OS user", which the OS home answers on its own.

    The CANONICAL ``~/.openclaw`` also opens the gate, even when it does not exist. It is
    the CLI's ``--home`` default, so landing there is not an act of targeting anything —
    typing nothing produces it. Requiring an exact match against the resolved state dir
    instead would go silent on the env-free migration case: a user with only
    ``~/.clawdbot`` gets a bare run pointed at a non-existent ``~/.openclaw`` while the
    agent happily reads ``~/.clawdbot/clawdbot.json``, which is precisely the divergence
    worth reporting. Found by an adversarial probe, pinned by
    ``test_b183_warns_on_a_legacy_state_dir_with_no_env_set``.
    """
    env = os.environ if env is None else env
    env_free = {k: v for k, v in env.items() if k not in OPENCLAW_PATH_ENV_VARS}
    try:
        audited = home.resolve()
        candidates = {
            openclaw_state_dir(env_free).resolve(),
            (openclaw_effective_home(env_free) / OPENCLAW_NEW_STATE_DIRNAME).resolve(),
        }
    except (OSError, ValueError, RuntimeError):
        return False
    return audited in candidates


def audits_this_users_own_home(home: Path) -> bool:
    """True when *home* is one of THIS user's own OpenClaw profile directories.

    The looser sibling of ``audits_default_state_dir``: it admits ``~/.openclaw-work``
    and friends, because for a *process environment* read the question is only "does this
    process's env describe the audited home at all". Mirrors the predicate B182 has used
    since B-241 (``checks/_lifecycle.py``), which delegates here so there is one
    definition rather than two that can drift.
    """
    try:
        user_home = Path.home().resolve()
        audited = home.resolve()
    except (OSError, ValueError, RuntimeError):
        return False
    return audited.parent == user_home and audited.name.startswith(OPENCLAW_NEW_STATE_DIRNAME)


# ---------------------------------------------------------------------------
# B-282 (ENV-2/ENV-6): the two GLOBAL runtime dotenv files.
#
# Grounded against dotenv-global-mWLbBl_z.js:85-111 (loadGlobalRuntimeDotEnvFiles) and
# utils-CRO4LGEB.js:61-71 (resolveConfigDir). EXACTLY two files are loaded into
# process.env:
#     <configDir>/.env                   (configDir defaults to ~/.openclaw)
#     ~/.config/openclaw/gateway.env     (skipped when OPENCLAW_STATE_DIR moves the
#                                         state env away from its default — :90/:98)
#
# The WORKSPACE .env is NOT one of them and must never be read as one. loadDotEnv
# (dotenv-eb21SB3p.js:218-223) passes the workspace file through an entryFilter of
# `!shouldBlockWorkspaceDotEnvKey`, and BLOCKED_WORKSPACE_DOTENV_PREFIXES
# (:177-185) contains the literal "OPENCLAW_" — so EVERY OPENCLAW_* key in a workspace
# .env is dropped before it can reach process.env. OPENCLAW_CACHE_TRACE is additionally
# in BLOCKED_WORKSPACE_DOTENV_KEYS (:128). The global loader, by contrast, is called with
# NO entryFilter (:222), so every OPENCLAW_* key in the two files above is admitted.
#
# DO NOT "widen" this to the workspace .env. It would be a guaranteed false positive on a
# key the product provably discards.
_MAX_DOTENV_BYTES = 256_000
_MAX_DOTENV_ENTRIES = 500

# parseBooleanValue's token sets, verbatim (boolean-CrriykWV.js:3-16). Anything outside
# BOTH sets is ambiguous and returns None, which lets the config value stand — the same
# `?? config?.enabled` fall-through the dist performs. No heuristic guessing.
_DOTENV_TRUTHY = frozenset({"true", "1", "yes", "on"})
_DOTENV_FALSY = frozenset({"false", "0", "no", "off"})

# env-CKdem44B.js:46-55 isTruthyEnvValue — a DIFFERENT predicate from parseBooleanValue:
# binary rather than tri-state (no falsy set; anything unrecognised is simply false).
# OPENCLAW_LOAD_SHELL_ENV uses this one (shell-env-DaE9Xx3-.js:200-202). Collapsing the
# two would misreport both.
_ENV_TRUTHY_BINARY = frozenset({"1", "on", "true", "yes"})


def parse_boolean_value(raw: "str | None") -> "bool | None":
    """Mirror ``parseBooleanValue`` (boolean-CrriykWV.js:22-30) — tri-state.

    None means "ambiguous or unset", i.e. the config value survives.
    """
    if not isinstance(raw, str):
        return None
    token = raw.strip().lower()
    if token in _DOTENV_TRUTHY:
        return True
    if token in _DOTENV_FALSY:
        return False
    return None


def is_truthy_env_value(raw: "str | None") -> bool:
    """Mirror ``isTruthyEnvValue`` (env-CKdem44B.js:46-55) — binary, no falsy set."""
    if not isinstance(raw, str):
        return False
    return raw.strip().lower() in _ENV_TRUTHY_BINARY


def _parse_dotenv(text: str) -> "dict[str, str]":
    """A conservative subset of dotenv's parser, for KEY=VALUE lines only.

    OpenClaw uses the npm ``dotenv`` package (dotenv-global-mWLbBl_z.js:8,22), whose full
    grammar includes multi-line quoted values and escape handling. This mirrors the
    unambiguous majority case — ``KEY=value``, optional ``export`` prefix, ``#`` comments,
    matched single/double quotes on one line — and simply DOES NOT REPORT anything it
    cannot parse. Under-reading a key yields an UNKNOWN or a silent PASS (a false
    negative); mis-parsing one would yield a false WARN. Only the former is acceptable.

    Keys are admitted on the same portable-identifier rule the product applies via
    ``normalizeEnvVarKey(raw, {portable: true})`` (host-env-security-CWC2ZCy4.js:414-419).
    """
    out: "dict[str, str]" = {}
    for line in text.splitlines():
        if len(out) >= _MAX_DOTENV_ENTRIES:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        # PORTABLE_ENV_VAR_KEY: a POSIX-portable identifier. A key the product would
        # reject is not a key the product will honour, so it is not evidence.
        if not key or not (key[0].isalpha() or key[0] == "_"):
            continue
        if not all(c.isalnum() or c == "_" for c in key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        elif "#" in value:
            # An unquoted inline comment. dotenv strips it; keep the same behaviour so a
            # trailing note cannot make a falsy value look ambiguous.
            value = value.split("#", 1)[0].strip()
        out[key] = value
    return out


def global_dotenv_paths(home: Path, env: "dict[str, str] | None" = None) -> "list[Path]":
    """The two global runtime dotenv files, expressed relative to the AUDITED home.

    ``home/.env`` is the ``<configDir>/.env`` slot and ``home.parent/.config/openclaw/
    gateway.env`` is the gateway slot — ``home.parent`` is ``~`` for a real OpenClaw home,
    the same idiom B150/B182 use to reach ``~/.config``. Deriving both from *home* rather
    than from ``os.environ`` keeps fixture and ``--home`` scans hermetic: the auditor's own
    environment can never steer which files a scan reads.

    The gateway file is skipped exactly when the dist skips it — an explicitly non-default
    ``OPENCLAW_STATE_DIR`` (dotenv-global-mWLbBl_z.js:90,98) — and only when the audited
    home is this user's own, since otherwise the process env says nothing about it.
    """
    env = os.environ if env is None else env
    paths = [home / ".env"]
    skip_gateway = False
    if audits_this_users_own_home(home):
        state_override = _env_str(env, "OPENCLAW_STATE_DIR")
        if state_override is not None:
            try:
                default_state_env = (
                    openclaw_effective_home(env) / OPENCLAW_NEW_STATE_DIRNAME / ".env"
                )
                skip_gateway = (
                    _expand_user_path(state_override, openclaw_effective_home(env)) / ".env"
                ).resolve() != default_state_env.resolve()
            except (OSError, ValueError, RuntimeError):
                skip_gateway = False
    if not skip_gateway:
        paths.append(home.parent / ".config" / "openclaw" / "gateway.env")
    return paths


def _collect_global_dotenv(home: Path, ctx: Context) -> None:
    """Read the two global dotenv files into ``ctx.dotenv_values`` (B-282).

    First-wins across files, mirroring ``loadParsedDotEnvFiles``
    (dotenv-global-mWLbBl_z.js:39-72): the first file to define a key is the one that
    applies, and a key already present in ``process.env`` blocks the file value entirely
    (``preExistingKeys.has(key)`` :44-46, ``process.env[key] === void 0`` :66).

    That precedence is why an observed override is reported as WARN, never FAIL: the file
    value applies on the NEXT agent start, and only if nothing already exported that key.

    Symlinked dotenv files are read like any other collector target only when they are
    real files; a symlink is skipped, matching ``_collect_exec_approvals``.
    """
    for path in global_dotenv_paths(home):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            with open(path, "rb") as fp:
                raw, truncated = _read_with_limit(fp, _MAX_DOTENV_BYTES)
        except OSError as exc:
            ctx.errors.append(f"could not read {path}: {exc}")
            continue
        ctx.dotenv_found = True
        ctx.dotenv_files.append(str(path))
        if truncated:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_ENV,
                f"dotenv file '{path}' exceeded the {_MAX_DOTENV_BYTES // 1000}KB cap — "
                "content beyond the cap was NOT scanned",
            )
        for key, value in _parse_dotenv(raw.decode("utf-8", errors="replace")).items():
            if key in ctx.dotenv_values:
                continue  # first-wins
            ctx.dotenv_values[key] = value
            ctx.dotenv_sources[key] = str(path)


def dotenv_override(ctx: Context, key: str) -> "tuple[str | None, str | None]":
    """The observed value of *key* and where it came from, or ``(None, None)``.

    The hermetic on-disk files are authoritative. The live process environment is only
    consulted when the audited home is this user's own (``audits_this_users_own_home``) —
    under a fixture or ``--home`` scan the auditor's environment describes a different
    subject entirely, and letting it steer a verdict would be exactly the
    environment-driven false positive Golden Rule #5 forbids.
    """
    value = ctx.dotenv_values.get(key)
    if value is not None:
        return value, ctx.dotenv_sources.get(key)
    if audits_this_users_own_home(ctx.home):
        raw = os.environ.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw, "the current process environment"
    return None, None


# ---------------------------------------------------------------------------
# B-289/B-290 (ENV-3/ENV-4): the systemd user unit's OWN environment.
#
# Why this exists at all: OpenClaw's gateway runs as a systemd user service, so the
# environment that decides its behaviour is the unit's, not the auditing shell's. Reading
# `os.environ` and calling it "the agent's environment" would be a category error — the
# variable an attacker plants in the unit is invisible there, and a variable the operator
# happens to have exported in their own shell is not the service's. Every verdict that
# moves on env evidence therefore keys on a PERSISTENT, on-disk artifact only
# (`persistent_env_evidence` below).
#
# Grounded against the installed dist, not the recon:
#   systemd-B4Oq2owH.js:276-287   readSystemdServiceRuntime's own unit walk: trim each
#                                 line, skip blanks and '#', then `Environment=` ->
#                                 parseSystemdEnvAssignment, `EnvironmentFile=` -> spec list
#   systemd-unit-DVDnVbxX.js:70-99  parseSystemdEnvAssignment — strip one matched wrapping
#                                 quote pair with backslash escapes, split at the FIRST
#                                 '=' (index must be > 0)
#   systemd-unit-DVDnVbxX.js:101-110 parseSystemdEnvAssignments — splitArgsPreservingQuotes
#                                 with escapeMode "backslash", quoteChars ' and ",
#                                 quoteStart "item-start" (a quote only opens a run at the
#                                 start of an item), then one assignment per token
#   systemd-B4Oq2owH.js:400-402   expandSystemdSpecifier — ONLY "%h" is expanded
#   systemd-B4Oq2owH.js:403-405   parseEnvironmentFileSpecs — same quote-preserving split
#   systemd-B4Oq2owH.js:430-447   resolveSystemdEnvironmentFiles — optional leading '-',
#                                 relative specs resolved against the unit's directory,
#                                 unreadable files skipped silently
#   systemd-B4Oq2owH.js:406-418   parseEnvironmentFileLine — '#'/';' comments, split at the
#                                 first '=', strip one matched wrapping quote pair
#   systemd-B4Oq2owH.js:294-297   merge order: {...inline, ...fromFiles} — an
#                                 EnvironmentFile value OVERRIDES the inline one
#
# Anything this parser cannot reproduce with confidence is simply not reported. Under-
# reading a key costs a false negative; mis-parsing one would cost a false WARN, and only
# the former is acceptable here (same rule as _parse_dotenv).
_MAX_UNIT_BYTES = 256_000
_MAX_UNIT_FILES = 40
_MAX_ENV_FILES = 40
_MAX_UNIT_ENV_ENTRIES = 500


def _split_preserving_quotes(raw: str) -> "list[str]":
    """Mirror ``splitArgsPreservingQuotes(raw, {escapeMode:"backslash", quoteStart:"item-start"})``.

    A quote character opens a quoted run only at the START of an item
    (systemd-unit-DVDnVbxX.js:102-105); once an item has begun, a quote is a literal.
    """
    items: "list[str]" = []
    cur = ""
    started = False
    quote: "str | None" = None
    escape = False
    for ch in raw:
        if escape:
            cur += ch
            escape = False
            started = True
            continue
        if ch == "\\":
            escape = True
            started = True
            continue
        if quote is not None:
            if ch == quote:
                quote = None
            else:
                cur += ch
            continue
        if ch in ("'", '"') and not started:
            quote = ch
            started = True
            continue
        if ch.isspace():
            if started:
                items.append(cur)
                cur = ""
                started = False
            continue
        cur += ch
        started = True
    if started:
        items.append(cur)
    return items


def _portable_env_key(key: str) -> "str | None":
    """A POSIX-portable identifier, or None. Same rule as ``_parse_dotenv``.

    A key the product would reject (normalizeEnvVarKey with {portable: true},
    host-env-security-CWC2ZCy4.js:414-419) is not a key the product will honour, so it is
    not evidence.
    """
    key = key.strip()
    if not key or not (key[0].isalpha() or key[0] == "_"):
        return None
    if not all(c.isalnum() or c == "_" for c in key):
        return None
    return key


def parse_systemd_env_assignments(raw: str) -> "list[tuple[str, str]]":
    """Parse the right-hand side of one ``Environment=`` line into (key, value) pairs.

    systemd allows several space-separated assignments on one line, each optionally
    quoted as a whole (``Environment="A=b c" D=e``) — the real unit on a stock install
    uses exactly that shape. Mirrors parseSystemdEnvAssignments
    (systemd-unit-DVDnVbxX.js:101-110); tokens without a '=' past position 0 are dropped,
    as the dist drops them.
    """
    out: "list[tuple[str, str]]" = []
    for token in _split_preserving_quotes(raw):
        key, sep, value = token.partition("=")
        if not sep:
            continue
        norm = _portable_env_key(key)
        if norm is None:
            continue
        out.append((norm, value))
    return out


def _parse_environment_file(text: str) -> "list[tuple[str, str]]":
    """Mirror ``parseEnvironmentFileLine`` (systemd-B4Oq2owH.js:406-418) over a whole file."""
    out: "list[tuple[str, str]]" = []
    for line in text.splitlines():
        if len(out) >= _MAX_UNIT_ENV_ENTRIES:
            break
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#") or trimmed.startswith(";"):
            continue
        eq = trimmed.find("=")
        if eq <= 0:
            continue
        norm = _portable_env_key(trimmed[:eq])
        if norm is None:
            continue
        value = trimmed[eq + 1:].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        out.append((norm, value))
    return out


def systemd_user_unit_dir(home: Path) -> Path:
    """``~/.config/systemd/user`` expressed relative to the AUDITED home.

    ``home.parent`` is ``~`` for a real OpenClaw profile directory — the same idiom B150
    and B182 already use to reach ``~/.config`` — so a fixture or ``--home`` scan reads
    the fixture's own units and never this machine's.
    """
    return home.parent / ".config" / "systemd" / "user"


def systemd_unit_is_openclaw_related(unit_name: str, exec_start: str) -> bool:
    """True if the unit's file name or ExecStart= line mentions 'openclaw'.

    The single definition; ``checks/_host.py`` B150 delegates here rather than keeping a
    second copy that could drift.
    """
    return "openclaw" in unit_name.lower() or "openclaw" in exec_start.lower()


def _read_environment_file(spec: str, unit_path: Path, home: Path, ctx: Context) -> None:
    """Read one ``EnvironmentFile=`` spec into ``ctx.unit_env_values``.

    Mirrors resolveSystemdEnvironmentFiles (systemd-B4Oq2owH.js:430-447): an optional
    leading '-' (ignore-if-missing) is stripped, ``%h`` expands to the user's home, a
    relative path resolves against the unit's own directory, and an unreadable file is
    skipped silently. Any OTHER ``%`` specifier is left unexpanded and the spec dropped —
    guessing at it would read the wrong file.
    """
    pathname = spec[1:].strip() if spec.startswith("-") else spec
    if not pathname:
        return
    pathname = pathname.replace("%h", str(home.parent))
    if "%" in pathname:
        return
    candidate = Path(pathname)
    if not candidate.is_absolute():
        candidate = unit_path.parent / candidate
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return
        with open(candidate, "rb") as fp:
            raw, truncated = _read_with_limit(fp, _MAX_UNIT_BYTES)
    except OSError as exc:
        ctx.errors.append(f"could not read {candidate}: {exc}")
        return
    if truncated:
        note_limit(
            ctx.limit_hits, LIMIT_DOMAIN_ENV,
            f"EnvironmentFile '{candidate}' exceeded the {_MAX_UNIT_BYTES // 1000}KB cap — "
            "content beyond the cap was NOT scanned",
        )
    for key, value in _parse_environment_file(raw.decode("utf-8", errors="replace")):
        if key not in ctx.unit_env_values and len(ctx.unit_env_values) >= _MAX_UNIT_ENV_ENTRIES:
            break
        # File values override inline ones, matching the dist's merge order
        # (systemd-B4Oq2owH.js:294-297). The inline map is NOT updated, so a caller can
        # still tell an inline-embedded secret from a file-backed one.
        ctx.unit_env_values[key] = value
        ctx.unit_env_sources[key] = f"{candidate} (EnvironmentFile= of {unit_path.name})"


def _collect_systemd_unit_env(home: Path, ctx: Context) -> None:
    """Read the environment of OpenClaw-related systemd user units (B-289/B-290).

    Silent on any host without ``~/.config/systemd/user`` — macOS, Windows, a container,
    or simply a user who never installed the service. ``ctx.unit_env_unreadable`` records
    the distinct "a unit is there but we could not read it" state so a consuming check can
    say UNKNOWN instead of inventing a clean PASS.
    """
    units_dir = systemd_user_unit_dir(home)
    try:
        units_dir_is_dir = units_dir.is_dir()
    except OSError as exc:
        # B-303: an ancestor (e.g. a non-traversable home) can make even this existence
        # check raise. Distinct from "not installed" — record it the same way an
        # unreadable directory listing already is below, so a consuming check says
        # UNKNOWN instead of the false "not installed" a silent return would imply.
        ctx.errors.append(f"could not check {units_dir}: {exc}")
        ctx.unit_env_unreadable = True
        return
    if not units_dir_is_dir:
        return
    try:
        unit_files = sorted(
            p for p in units_dir.iterdir()
            if p.is_file() and not p.is_symlink() and p.suffix == ".service"
        )[:_MAX_UNIT_FILES]
    except OSError as exc:
        ctx.errors.append(f"could not list {units_dir}: {exc}")
        ctx.unit_env_unreadable = True
        return

    pending_files: "list[tuple[str, Path]]" = []
    for unit_path in unit_files:
        try:
            with open(unit_path, "rb") as fp:
                raw, truncated = _read_with_limit(fp, _MAX_UNIT_BYTES)
        except OSError:
            ctx.unit_env_unreadable = True
            continue
        text = raw.decode("utf-8", errors="replace")
        if truncated:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_ENV,
                f"systemd unit '{unit_path.name}' exceeded the "
                f"{_MAX_UNIT_BYTES // 1000}KB cap — content beyond the cap was NOT scanned",
            )

        exec_start = ""
        env_lines: "list[str]" = []
        file_specs: "list[str]" = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("ExecStart=") and not exec_start:
                exec_start = stripped[len("ExecStart="):].strip()
            elif stripped.startswith("Environment="):
                env_lines.append(stripped[len("Environment="):].strip())
            elif stripped.startswith("EnvironmentFile="):
                spec = stripped[len("EnvironmentFile="):].strip()
                if spec:
                    file_specs.append(spec)
        if not systemd_unit_is_openclaw_related(unit_path.name, exec_start):
            continue

        ctx.unit_env_found = True
        ctx.unit_env_files.append(str(unit_path))
        for raw_line in env_lines:
            if len(ctx.unit_env_values) >= _MAX_UNIT_ENV_ENTRIES:
                break
            for key, value in parse_systemd_env_assignments(raw_line):
                ctx.unit_env_values[key] = value
                ctx.unit_env_inline[key] = str(unit_path)
                ctx.unit_env_sources[key] = f"{unit_path} (Environment=)"
        for spec in file_specs:
            for token in _split_preserving_quotes(spec):
                if len(pending_files) >= _MAX_ENV_FILES:
                    break
                pending_files.append((token, unit_path))

    # Bounded: a unit is attacker-writable in the threat model this check exists for, and
    # `EnvironmentFile=` accepts arbitrary absolute paths, so an unbounded spec list would
    # be a cheap way to turn one 256KB file into hundreds of thousands of open() calls.
    for token, unit_path in pending_files:
        _read_environment_file(token, unit_path, home, ctx)


def persistent_env_evidence(ctx: Context, key: str) -> "tuple[str | None, str | None]":
    """The value of *key* as delivered by a PERSISTENT on-disk artifact, and its source.

    Consults, in the order the product resolves them for a service-run agent:

    1. the systemd unit's ``Environment=`` / ``EnvironmentFile=`` — already in
       ``process.env`` when the agent starts, which is exactly why the global dotenv
       loader then skips the key (``preExistingKeys.has(key)``,
       dotenv-global-mWLbBl_z.js:44-46 / :66);
    2. the two global runtime dotenv files.

    It deliberately does NOT fall back to ``os.environ``. This function backs verdict-
    moving decisions — softening B2's exposed-gateway FAIL, and B186's override
    disclosure — and the auditing shell's environment is not the service's. Letting an
    exported variable in the operator's terminal clear a CRITICAL finding about a
    separate long-running process would be keying a verdict on something outside the
    audited subject entirely. Where no persistent artifact carries the key, the honest
    answer is "unknown", not "authenticated" (Golden Rule #5, and the ENV-3 trap that
    ``os.environ`` alone manufactures a lying PASS).

    ``dotenv_override`` keeps its own os.environ leg for the callers that want a
    best-effort read of this user's own live setup; the two are intentionally different.
    """
    value = ctx.unit_env_values.get(key)
    if isinstance(value, str) and value.strip():
        return value, ctx.unit_env_sources.get(key)
    value = ctx.dotenv_values.get(key)
    if isinstance(value, str) and value.strip():
        return value, ctx.dotenv_sources.get(key)
    return None, None


def env_evidence_readable(ctx: Context) -> bool:
    """True when at least one env-bearing artifact was actually read.

    The discriminator between "no override is set" and "we could not see whether one is
    set". A check that cannot tell those apart must report UNKNOWN.
    """
    return bool(ctx.unit_env_found or ctx.dotenv_found)


# The two bundled-root relocation variables OpenClaw honours UNCONDITIONALLY (B-289).
#   bundled-dir-BQFrcRIS.js:22-24  resolveBundledSkillsDir — `const override =
#       process.env.OPENCLAW_BUNDLED_SKILLS_DIR?.trim(); if (override) return override;`
#       returns BEFORE every legitimate resolution path, with no existence or trust check.
#   workspace-zj1TEEka.js:54-56    resolveBundledHooksDir — identical shape.
#
# OPENCLAW_BUNDLED_PLUGINS_DIR is deliberately ABSENT from this tuple and must never be
# added: bundled-dir-DKbeVv7V.js:124-134 resolves the override and then gates it through
# resolveTrustedExistingOverride (:77-85), which requires the realpath to be pathContains-ed
# by a trusted bundled-plugin root under the package root AND to pass
# hasUsableBundledPluginTree. `OPENCLAW_BUNDLED_PLUGINS_DIR=/tmp/evil` is REJECTED; the only
# bypass (shouldTrustTestBundledPluginsDirOverride, :32-34) requires VITEST. OpenClaw
# hardened exactly one of the three. Flagging it would be a false positive on the benign
# internal uses at bundled-ClxzUaje.js:145 and dist/plugin-sdk/qa-runner-runtime.js.
OPENCLAW_BUNDLED_ROOT_ENV_VARS = (
    ("OPENCLAW_BUNDLED_SKILLS_DIR", "skills"),
    ("OPENCLAW_BUNDLED_HOOKS_DIR", "hooks"),
)


def bundled_root_overrides(ctx: Context) -> "list[tuple[str, str, str, str]]":
    """Observed bundled-root relocations, as (var, kind, value, source).

    Persistent artifacts only — see ``persistent_env_evidence``.
    """
    out: "list[tuple[str, str, str, str]]" = []
    for var, kind in OPENCLAW_BUNDLED_ROOT_ENV_VARS:
        value, source = persistent_env_evidence(ctx, var)
        if value is None:
            continue
        value = value.strip()
        if not value:
            continue  # `?.trim()` falsy — the dist falls through to normal resolution
        out.append((var, kind, value, source or "an environment file"))
    return out


# B-306 safe-symlink split: the exact substring the config loader emits when it declines
# to FOLLOW a top-level openclaw.json symlink whose resolved target leaves the config dir
# (configloader.load_openclaw_config). Used only to ROUTE to the structural gate below —
# never as the decision itself, so wording is not load-bearing and this can't regress into
# the keyword-widening pattern the project avoids.
_CONFIG_SYMLINK_ESCAPE_MARKER = "symlink escapes its config directory"


def _recover_escaped_config_symlink(
    ctx: Context, cfg_path: Path, message: str
) -> "tuple[dict, int | None] | None":
    """Safely follow a dotfiles-style openclaw.json symlink the loader declined.

    ``configloader.load_openclaw_config`` refuses to FOLLOW a top-level config symlink
    whose resolved target leaves the config directory, purely for its own read-safety.
    That refusal is right for the loader, but it collapses a perfectly READABLE, SAFE
    config into ``ctx.config_parse_error`` -> B-306 ``CONFIG_BLIND_CAP`` -> a false F on
    the very common dotfiles layout (stow/chezmoi/yadm/bare-git symlink openclaw.json out
    to a version-controlled repo).

    ``ctx.config_parse_error`` conflates two states that must be told apart by STRUCTURE,
    never by any text/keyword match:

      * corrupt / truncated / genuinely unreadable bytes -> truly blind; the cap is
        correct; this helper returns ``None`` and the caller keeps that behavior.
      * a readable REGULAR file the tool merely DECLINED to follow, owned by the auditing
        user -> NOT blind; follow it here and audit the real bytes.

    Returns ``(parsed_config, config_mode)`` on a safe follow (recording the reason on
    *ctx* for the report), else ``None`` so the caller keeps the genuine config-blind path
    (cap intact).
    """
    if _CONFIG_SYMLINK_ESCAPE_MARKER not in message:
        return None
    # Structural gate #1: the top-level config path must itself be a symlink. Only the
    # symlink-escape branch of the loader emits the marker for a symlinked top-level
    # config; a regular-file top level whose $include escaped is (a) not a symlink here and
    # (b) would re-raise on the retry below anyway. So this both routes precisely and cannot
    # be spoofed by attacker-controlled text inside a $include path string.
    try:
        if not os.path.islink(cfg_path):
            return None
        target = cfg_path.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        return None
    # Structural gate #2: the resolved target is a REGULAR file (not a dir/device/fifo/
    # socket) that the auditing user OWNS. Anything else stays genuine-blind.
    try:
        if not os.path.isfile(target):
            return None
        if os.stat(target).st_uid != os.geteuid():
            return None
    except (OSError, AttributeError):
        # No stat/geteuid (e.g. non-POSIX) or an unreadable target -> stay conservative.
        return None
    # Structural gate #3: the bytes must actually load. Re-load against the RESOLVED
    # target, whose own parent is now the config dir, so the loader's within-roots guard is
    # satisfied and $include resolution roots at the dotfiles repo (the correct trust root
    # for a dotfiles-managed config). Any failure here == genuinely unreadable -> None ->
    # genuine-blind cap preserved.
    _digest: list = []
    try:
        parsed = _load_openclaw_config(target, root_byte_limit=_MAX_CONFIG_BYTES,
                                       root_digest=_digest)
    except (OSError, _ConfigLoadError, RecursionError):
        return None
    # C-417: the recovered symlink target IS the file this audit read, so its bytes are
    # what the digest must describe — not the link.
    ctx.config_sha256 = _digest[0] if _digest else None
    try:
        mode = target.stat().st_mode & 0o777
    except OSError:
        mode = None
    ctx.config_symlink_escapes_home = True
    ctx.config_parse_reason = (
        "openclaw.json is a symlink whose target leaves its config directory; the target"
        " is a readable regular file you own, so it was followed and audited"
    )
    return parsed, mode


def _bootstrap_identity(f: Path) -> object:
    """Return a de-duplication key that identifies the FILE, not the path spelling.

    ``BOOTSTRAP_FILES`` deliberately lists two case variants of the same name
    (``MEMORY.md`` and ``memory.md``) because on a case-SENSITIVE filesystem those are
    two genuinely different files and an attacker may plant either. Probing both is
    correct there.

    De-duplicating those probes on ``Path.resolve()`` is not. ``resolve()`` is
    ``posixpath.realpath`` — pure string manipulation over the path components; it
    resolves symlinks and ``..``, but it never asks the filesystem for a name's on-disk
    casing. On a case-INsensitive filesystem (macOS/APFS by default, Windows) both
    probes open the *same* inode while producing two resolved strings that differ only
    in case, so the de-dup misses and the file's content is read — and reported — twice
    under two ``ctx.bootstrap`` keys. Findings that join their evidence over
    ``ctx.bootstrap`` then render the same file twice, and ``bootstrap_blob`` doubles.

    Keying on filesystem identity ``(st_dev, st_ino)`` instead fixes that at the source,
    with no behaviour change where the two names really are two files: their inodes
    differ, so both are still collected. It also collapses hardlinks, which a
    path-string key cannot. ``stat()`` follows symlinks, matching what ``resolve()``
    did for the symlink-back-to-root case.

    Falls back to the resolved path when ``stat()`` fails or when ``st_ino`` is not
    meaningful (some filesystems and platforms report 0), so the key is never weaker
    than the path-based one it replaces.
    """
    try:
        real = f.resolve()
    except OSError:
        real = f
    try:
        st = f.stat()
    except OSError:
        return real
    if not st.st_ino:
        return real
    return (st.st_dev, st.st_ino)


def collect(home: Path | str = "~/.openclaw") -> Context:
    home = Path(home).expanduser()
    ctx = Context(home=home)

    cfg_path, cfg_found = resolve_config_in_home(home)
    ctx.config_path = cfg_path
    ctx.config_found = cfg_found
    parsed_ok = False
    if cfg_found:
        _cfg_digest: list = []
        try:
            parsed = _load_openclaw_config(cfg_path, root_byte_limit=_MAX_CONFIG_BYTES,
                                           root_digest=_cfg_digest)
        except (OSError, _ConfigLoadError, RecursionError) as exc:
            message = str(exc)
            # B-306 safe-symlink recovery: a dotfiles-style openclaw.json symlink whose
            # target leaves the config dir is NOT a dark config when that target is a
            # readable regular file the user owns — follow it and audit the real bytes
            # instead of hard-capping to F. Returns None for genuinely corrupt/unreadable
            # bytes, which fall through to the unchanged genuine-blind path below.
            recovered = _recover_escaped_config_symlink(ctx, cfg_path, message)
            if recovered is not None:
                parsed, ctx.config_mode = recovered
                ctx.config = parsed
                parsed_ok = True
            else:
                ctx.errors.append(f"could not parse {cfg_path}: {message}")
                ctx.config_parse_reason = message
                if "cap" in message or "exceeds" in message:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_CONFIG,
                        message,
                    )
        else:
            ctx.config = parsed
            ctx.config_sha256 = _cfg_digest[0] if _cfg_digest else None
            try:
                ctx.config_mode = cfg_path.stat().st_mode & 0o777
            except OSError as exc:
                ctx.errors.append(f"could not stat {cfg_path}: {exc}")
            parsed_ok = True
    else:
        ctx.errors.append(f"config not found: {cfg_path}")

    # B-166: "config present but unparseable" (read error, size-cap truncation, decode/
    # JSON/recursion error, or a non-object top level) is a distinct, machine-visible state
    # from "no config file". Surfaced in --json/--sarif and trips --exit-code so a broken
    # config can't silently pass a CI gate as an UNKNOWN-only run. A valid empty "{}" is
    # NOT an error (parsed_ok stays True).
    ctx.config_parse_error = ctx.config_found and not parsed_ok

    # Scan the home root first, then workspace sub-directories.  The root is
    # included so bootstrap files that live outside the three named workspace
    # dirs are not invisible (§6: never hardcode one layout).
    # Filesystem identity is tracked (see _bootstrap_identity) so a symlink from a
    # workspace dir back to a root file — or the same inode reached under two case
    # spellings on a case-insensitive filesystem — is not read twice.
    _seen_bootstrap: set[object] = set()
    _ws_dirs: list[tuple[str, Path]] = [("", home)]
    _ws_dirs += [(ws, home / ws) for ws in WORKSPACE_DIRS]
    # B-161: also scan any config-declared custom workspace(s) for bootstrap files, so a
    # SOUL.md/AGENTS.md living outside the hardcoded names is not invisible. The
    # resolved-path de-dup below keeps a file that also lives under a hardcoded dir from
    # being read (or counted) twice.
    for _cw in _config_workspace_dirs(home, ctx.config, limit_hits=ctx.limit_hits,
                                    disclosures=ctx.disclosures):
        _ws_dirs.append((_cw.name or "workspace", _cw))
    for _ws, wdir in _ws_dirs:
        # B-303: wdir == home for the first entry, so a non-traversable *home* (e.g.
        # `chmod 000 ~/.openclaw`) used to raise an uncaught PermissionError right here
        # (or, for home itself, one line down on the first bootstrap filename) and take
        # the WHOLE audit down. A directory this process cannot even stat is reported the
        # same way a directory that does not exist already is — skipped, with a
        # bootstrap-domain limit hit recording WHY, so check_installed_skills'/the
        # bootstrap checks' existing "ctx.bootstrap empty -> UNKNOWN" fallback fires
        # honestly instead of the process crashing.
        try:
            wdir_is_dir = wdir.is_dir()
        except OSError as exc:
            note_limit(
                ctx.limit_hits, LIMIT_DOMAIN_BOOTSTRAP,
                f"could not check workspace dir '{wdir}' ({exc.__class__.__name__}) — "
                "bootstrap files there were NOT scanned",
            )
            ctx.errors.append(f"could not check {wdir}: {exc}")
            continue
        if not wdir_is_dir:
            continue
        for name in BOOTSTRAP_FILES:
            f = wdir / name
            try:
                f_is_file = f.is_file()
            except OSError as exc:
                note_limit(
                    ctx.limit_hits, LIMIT_DOMAIN_BOOTSTRAP,
                    f"could not check '{f}' ({exc.__class__.__name__}) — this bootstrap "
                    "file was NOT scanned",
                )
                ctx.errors.append(f"could not check {f}: {exc}")
                continue
            if not f_is_file:
                continue
            ident = _bootstrap_identity(f)
            if ident in _seen_bootstrap:
                continue
            _seen_bootstrap.add(ident)
            key = name if _ws == "" else f"{_ws}/{name}"
            try:
                # B-103: cap the read like the skill path — a huge/padded bootstrap
                # file must not load whole into memory (memory DoS) or turn the B58
                # quadratic regex unbounded. _read_with_limit streams up to the cap
                # (never over-allocates); a slice records a limit_hit so checks over
                # ctx.bootstrap surface UNKNOWN instead of scanning a clipped file.
                with open(f, "rb") as fp:
                    raw, truncated = _read_with_limit(fp, _MAX_FILE_BYTES)
                # B-305/C-135 (round 2, Finding 2): unlike ctx.installed_skills,
                # NO "# file: <name>" section header is ever legitimately inserted
                # into bootstrap text — `bootstrap_blob` just joins raw file
                # contents with "\n" — so a header-shaped line found here can only
                # ever be attacker-forged. Escaping is therefore always safe
                # (never neutralizes a genuine header, because there is none), and
                # closes the same `_pos_in_source_code_section` bypass for this
                # ingestion path that `_read_skill_text` closes for skills.
                ctx.bootstrap[key] = _escape_embedded_header_lines(
                    raw.decode("utf-8", errors="replace")
                )
                if truncated:
                    note_limit(
                        ctx.limit_hits, LIMIT_DOMAIN_BOOTSTRAP,
                        f"bootstrap file '{key}' exceeded the "
                        f"{_MAX_FILE_BYTES // 1000}KB cap — content beyond the cap "
                        "was NOT scanned",
                    )
            except OSError as exc:
                ctx.errors.append(f"could not read {f}: {exc}")

    _collect_global_dotenv(home, ctx)
    # Must precede _read_installed_skills: a bundled-skills-root relocation observed here
    # adds a load root that the content scanners then cover (B-289).
    _collect_systemd_unit_env(home, ctx)
    # F-183: before _collect_cron -- its cron.store shadow check reads this.
    _collect_config_machine_state(home, ctx)
    _collect_cron(home, ctx)
    _collect_exec_approvals(home, ctx)
    _collect_plugin_trust(home, ctx)
    _collect_capture_state(home, ctx)  # B-295: debug-proxy capture row counts (metadata only)
    _collect_subagent_runs(home, ctx)  # B-296: subagent-spawn registry disclosure for B18
    _collect_audit_events(home, ctx)   # F-134 (DISK-1): runtime audit_events trail, --behavioral only
    _read_installed_skills(home, ctx)
    return ctx


def dig(d: dict, path: str, default=None):
    """Nested lookup by dotted path; returns default if any segment is missing."""
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur
