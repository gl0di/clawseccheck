"""Read-only enumeration of the agent's own log/transcript sinks (E-044 Phase 1 substrate).

"All logs" here means the corpus the OpenClaw agent itself PRODUCES — not the host's OS
logs (journald / bash_history are out of scope; see the workspace design doc §1.1, which
grounds that boundary against the real dist). The sinks this module knows about:

  - ``logging.file``                    — config-declared primary JSONL log
  - ``diagnostics.cacheTrace.filePath`` — config-declared cache-trace transcript JSONL
                                           (NOT ``logging.cacheTrace.*``, which does not
                                           exist in the dist — see B82 in checks/_egress.py)
  - trajectory sidecars                 — ``agents/*/sessions/*.trajectory.jsonl``
                                           (on by default; reuses ``trajectory.find_trajectory_files``)
  - session transcripts                 — ``agents/*/sessions/*.jsonl`` (NOT the trajectory
                                           sidecar files, which are already covered above)
  - config-audit log                    — ``logs/config-audit.jsonl`` (B77 already reads it)
  - generic rotated/ad-hoc logs         — ``logs/*.log``
  - memory files                        — ``<workspace>/memory/**`` (same convention
                                           ``check_data_atrest`` (B19, checks/_egress.py) knows)
  - install backups                     — ``<home>/.openclaw-install-backups/**`` (same
                                           convention B19 knows)

Layer 1 leaf: depends only on ``collector`` (Context/dig/WORKSPACE_DIRS), ``trajectory``
(``find_trajectory_files`` — reused, not re-implemented), ``safeio`` (symlink-safe
traversal), and stdlib. Never imports ``checks/`` (Layer 2) or any Layer-3 module —
``logscan.py``, the sibling leaf that reads these sinks, has the same constraint, and this
module's job is scoped even narrower: it never opens a file, it only enumerates paths.

Bounded by design (DoS guard, same spirit as the 200-file caps elsewhere in the codebase):
overall sink count is capped at ``_MAX_SINKS``, each source sub-enumeration is capped too,
and every candidate is deduplicated by resolved path so the same file is never counted
twice across two different sources (most importantly: a ``*.trajectory.jsonl`` file is
claimed ONLY by the dedicated trajectory source, never also by the generic transcript
glob, which explicitly excludes that suffix).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .collector import Context, WORKSPACE_DIRS, dig
from .safeio import walk_dir_safely
from .trajectory import find_trajectory_files

# Overall cap across every source combined (DoS guard — mirrors the 200-file caps used
# elsewhere in the codebase, e.g. checks/_egress.py's _collect_atrest_transcripts).
_MAX_SINKS = 200
# Per-source sub-cap so one pathologically large source can't starve the others out of
# the overall budget before they get a turn.
_MAX_PER_SOURCE = 200

# Same conventional backup directory name check_data_atrest (B19, checks/_egress.py)
# already reads — the path CONVENTION is reused here (Layer 1 can't import a Layer-2
# check function), not the code.
_BACKUP_DIRNAME = ".openclaw-install-backups"


@dataclass(frozen=True)
class LogSink:
    """One discovered log/transcript file — a path, never file content."""

    path: Path
    kind: str  # trajectory|config_log|cache_trace|transcript|config_audit|memory|backup
    source: str  # config|convention|env


def _is_regular_readable_file(path: Path) -> bool:
    """Best-effort existence/type guard. Never raises, never reads content."""
    try:
        if path.is_symlink():
            return False
        return path.is_file()
    except OSError:
        return False


def _config_path_sink(ctx: Context, dotted_path: str, kind: str) -> "LogSink | None":
    """Resolve a config-declared file path (``logging.file`` /
    ``diagnostics.cacheTrace.filePath``) to a LogSink, or None when unset / not a real
    file.

    Deliberately path-based, not gated on ``diagnostics.cacheTrace.enabled``: a trace file
    written during an earlier debugging session still exists — and still holds transcript
    content worth scanning — after tracing is switched back off.
    """
    value = dig(ctx.config, dotted_path)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        p = Path(value).expanduser()
    except (TypeError, ValueError):
        return None
    if not p.is_absolute():
        p = ctx.home / p
    if not _is_regular_readable_file(p):
        return None
    return LogSink(path=p, kind=kind, source="config")


def _transcript_sinks(home: Path, budget: int) -> list[LogSink]:
    """``agents/*/sessions/*.jsonl`` — session transcripts, NOT trajectory sidecars.

    A trajectory sidecar file also matches ``*.jsonl`` under the same directory (it is
    named ``<session>.trajectory.jsonl``), so it is explicitly excluded here — it is
    already discovered as its own dedicated ``trajectory``-kind sink.
    """
    out: list[LogSink] = []
    agents_dir = home / "agents"
    if not agents_dir.is_dir() or agents_dir.is_symlink():
        return out
    try:
        agent_dirs = sorted(p for p in agents_dir.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return out
    for agent_dir in agent_dirs:
        if len(out) >= budget:
            break
        sessions_dir = agent_dir / "sessions"
        if not sessions_dir.is_dir() or sessions_dir.is_symlink():
            continue
        try:
            files = sorted(sessions_dir.glob("*.jsonl"))
        except OSError:
            continue
        for f in files:
            if len(out) >= budget:
                break
            if f.name.endswith(".trajectory.jsonl"):
                continue  # already covered by the dedicated trajectory source
            if not _is_regular_readable_file(f):
                continue
            out.append(LogSink(path=f, kind="transcript", source="convention"))
    return out


def _config_audit_sink(home: Path) -> "LogSink | None":
    """``logs/config-audit.jsonl`` — the same file B77 (check_config_audit_log) reads."""
    p = home / "logs" / "config-audit.jsonl"
    if not _is_regular_readable_file(p):
        return None
    return LogSink(path=p, kind="config_audit", source="convention")


def _generic_log_sinks(home: Path, budget: int) -> list[LogSink]:
    """Bare ``<home>/logs/*.log`` files (excluding config-audit.jsonl — its own kind).

    Bucketed as ``config_log`` — the same kind as the config-declared ``logging.file`` —
    since the LogSink taxonomy has no more specific kind for a bare rotated/ad-hoc log
    file sitting under the conventional ``logs/`` directory.
    """
    out: list[LogSink] = []
    logs_dir = home / "logs"
    if not logs_dir.is_dir() or logs_dir.is_symlink():
        return out
    try:
        files = sorted(logs_dir.glob("*.log"))
    except OSError:
        return out
    for f in files:
        if len(out) >= budget:
            break
        if not _is_regular_readable_file(f):
            continue
        out.append(LogSink(path=f, kind="config_log", source="convention"))
    return out


def _memory_sinks(home: Path, budget: int) -> list[LogSink]:
    """Workspace memory-dir files — the same ``<workspace>/memory`` convention
    ``check_data_atrest`` (B19, checks/_egress.py) already knows. Symlink-safe, capped."""
    out: list[LogSink] = []
    for ws in WORKSPACE_DIRS:
        if len(out) >= budget:
            break
        mem_dir = home / ws / "memory"
        if not mem_dir.is_dir() or mem_dir.is_symlink():
            continue
        remaining = budget - len(out)
        for f in walk_dir_safely(mem_dir, exclude_pycache=True, exclude_vcs=True, max_files=remaining):
            out.append(LogSink(path=f, kind="memory", source="convention"))
    return out


def _backup_sinks(home: Path, budget: int) -> list[LogSink]:
    """``<home>/.openclaw-install-backups/**`` — the same convention B19 already knows.
    Symlink-safe, capped."""
    backup_dir = home / _BACKUP_DIRNAME
    if not backup_dir.is_dir() or backup_dir.is_symlink():
        return []
    return [
        LogSink(path=f, kind="backup", source="convention")
        for f in walk_dir_safely(backup_dir, exclude_pycache=True, exclude_vcs=True, max_files=budget)
    ]


def discover_log_sinks(ctx: Context) -> list[LogSink]:
    """Enumerate the agent's own log/transcript sinks — paths only, nothing is read.

    Bounded to ``_MAX_SINKS`` total; deduplicated by resolved path so the same file is
    never counted twice across sources. Returns ``[]`` when ``ctx.home`` is not usable.
    """
    home = getattr(ctx, "home", None)
    if not isinstance(home, Path):
        return []

    sinks: list[LogSink] = []
    seen: set[str] = set()

    def _add_many(candidates) -> None:
        for sink in candidates:
            if len(sinks) >= _MAX_SINKS:
                return
            try:
                key = str(sink.path.resolve())
            except OSError:
                key = str(sink.path)
            if key in seen:
                continue
            seen.add(key)
            sinks.append(sink)

    config_log = _config_path_sink(ctx, "logging.file", "config_log")
    if config_log is not None:
        _add_many([config_log])

    cache_trace = _config_path_sink(ctx, "diagnostics.cacheTrace.filePath", "cache_trace")
    if cache_trace is not None:
        _add_many([cache_trace])

    traj_files = find_trajectory_files(home, max_files=_MAX_PER_SOURCE)
    _add_many(
        LogSink(path=f, kind="trajectory", source="convention")
        for f in traj_files
        if _is_regular_readable_file(f)
    )

    audit_sink = _config_audit_sink(home)
    if audit_sink is not None:
        _add_many([audit_sink])

    _add_many(_transcript_sinks(home, _MAX_PER_SOURCE))
    _add_many(_generic_log_sinks(home, _MAX_PER_SOURCE))
    _add_many(_memory_sinks(home, _MAX_PER_SOURCE))
    _add_many(_backup_sinks(home, _MAX_PER_SOURCE))

    return sinks
