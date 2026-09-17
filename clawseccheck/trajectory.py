"""Read-only scan of OpenClaw trajectory sidecars for log-observed tool use.

OpenClaw writes a per-session trajectory sidecar next to each session file:
``<home>/agents/<agent>/sessions/<session>.trajectory.jsonl`` (on by default; see
``docs/tools/trajectory.md``). Each line is a JSON envelope with a ``type``
discriminator; ``type == "tool.call"`` records carry the tool VERB in ``data.name``.
Grounded against a live install — see ``docs/research/openclaw-schema-recon.md`` §9.1.

This module extracts the SET of tool verbs the agent actually invoked (``data.name``)
so a check can report *proven* — log-observed, not self-reported — tool use. It is the
log-observed upgrade to the attestation self-report path.

It also reads ``type == "context.compiled"`` records, whose ``data.tools[]`` carries the
tool DEFINITIONS OpenClaw actually sent to the model — see
``read_compiled_tool_descriptions`` (F-133/B185).

Security (§8): this reads the user's own logs, which may contain secrets. It reads ONLY
``data.name`` (the tool identity, not a secret), the version marker, the top-level
``sessionKey``'s ORIGIN KIND (see ``parse_session_origin`` — never the peer id it
embeds), and the named ``data.tools[]`` sub-fields listed in
``read_compiled_tool_descriptions`` — it NEVER reads ``data.arguments``,
``data.output``, ``data.result``, ``data.contentItems`` (the sensitive call/return
payloads) nor ``context.compiled``'s ``systemPrompt``/``prompt``/``messages`` siblings
(the user's own conversation). Stdlib-only, read-only, no network.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Version gate: only parse the format we have grounded. Any other value -> we don't guess.
_TRACE_SCHEMA = "openclaw-trajectory"
_SCHEMA_VERSION = 1

# Bounds so a large/padded fleet of session logs can't blow up the scan (DoS guard).
_MAX_FILES = 60
_MAX_BYTES_PER_FILE = 8_000_000

# ---------------------------------------------------------------------------
# B-732: OpenClaw locates a session's trajectory sidecar through a POINTER file
# (``<session>.trajectory-path.json``) that names the runtime file by an absolute path,
# not only by the ``agents/*/sessions/*.trajectory.jsonl`` glob this module used alone
# before. Grounded against the installed dist (``paths-*.mjs``, ``cleanup-*.mjs``):
#
#   isTrajectoryPointerArtifactName(name) = name.endsWith(".trajectory-path.json")
#   TRAJECTORY_POINTER_FILE_MAX_BYTES = 65536
#   resolveTrajectoryPointerFilePath(sessionFile) =
#       sessionFile.endsWith(".jsonl") ? sessionFile.slice(0,-6)+".trajectory-path.json" : ...
#   safeTrajectorySessionFileName(sessionId) =
#       (/[^A-Za-z0-9_-]/g -> "_", sliced to 120) or "session" if nothing alnum survives
#   validation (cleanup-*.mjs): traceSchema === "openclaw-trajectory-pointer" &&
#       schemaVersion === 1 && sessionId === <expected> && typeof runtimeFile === "string"
#       && runtimeFile.trim() !== ""
#
# A pointer is attacker-writable (anything that can write into agents/*/sessions/ can
# write one), and the vendor's own reader `path.resolve()`s runtimeFile unconditionally
# -- so unlike the runtime-content read below, following one is a read-PRIMITIVE, not a
# convenience. This module refuses to open a resolved target outside the audited home
# rather than following it; see `_resolve_pointer_target`.
_POINTER_SUFFIX = ".trajectory-path.json"
_POINTER_TRACE_SCHEMA = "openclaw-trajectory-pointer"
_POINTER_SCHEMA_VERSION = 1
_POINTER_MAX_BYTES = 65536  # TRAJECTORY_POINTER_FILE_MAX_BYTES, paths-*.mjs

# C-135: no per-pointer bound existed before max_files trimmed the FINAL union, so a
# directory salted with many pointer files paid real I/O (stat/read/json.loads/resolve)
# per pointer regardless of max_files. Same cap and name as trajectorystore.py's own
# independent pointer scan (_MAX_POINTER_SCAN=500) -- not shared code (that module
# counts, this one resolves and opens), but the same number for the same reason.
_MAX_POINTER_SCAN = 500

_UNSAFE_SESSION_CHARS_RE = re.compile(r"[^A-Za-z0-9_-]")
_SESSION_HAS_ALNUM_RE = re.compile(r"[A-Za-z0-9]")


def _safe_trajectory_session_file_name(session_id: str) -> str:
    """Port of the vendor's ``safeTrajectorySessionFileName`` (``paths-*.mjs``).

    Differentially verified by EXECUTING the real function (node) over 8 cases --
    a plain UUID, empty string, all-punctuation, a 200-char run, non-ASCII letters,
    path-traversal-shaped input, embedded spaces, and mixed-case/hyphen/underscore --
    0 disagreements. A pure, 2-line function; this is the proportionate level of
    verification for it, not the multi-thousand-case batteries a stateful policy
    resolver (toolgrant.py/toolpolicy.py) needs.
    """
    safe = _UNSAFE_SESSION_CHARS_RE.sub("_", session_id)[:120]
    return safe if _SESSION_HAS_ALNUM_RE.search(safe) else "session"


def _resolve_pointer_target(pointer_path: Path, home_resolved: Path) -> "tuple[str, Path | None]":
    """Read, validate and resolve one trajectory pointer file.

    Returns ``(status, path)``:

      "resolved"     -- a valid pointer whose ``runtimeFile`` resolves INSIDE
                         *home_resolved* and exists. ``path`` is that resolved Path.
      "missing"      -- valid and in-home, but the named file does not exist (or could
                         not be stat()ed) -- e.g. the 8.1-era JSONL-to-SQLite migration
                         archived it away (trajectorystore.py's ``corroborate()`` is the
                         module that explains THAT asymmetry; this module only reports
                         the fact, never guesses a cause).
      "out_of_home"  -- valid, but ``runtimeFile`` resolves OUTSIDE the audited home.
                         REFUSED -- ``path`` is the escaping target, for disclosure only,
                         never opened.
      "invalid"      -- unreadable, oversized (> _POINTER_MAX_BYTES), not JSON, not a
                         dict, fails the vendor's own schema/session-id validation, or
                         names a target that is not itself SHAPED like a trajectory
                         sidecar (C-135: confinement to home alone is not enough --
                         without this, a pointer could redirect the scan onto ANY
                         in-home file, e.g. a credentials store, which is then opened
                         and read line-by-line by every caller, not merely path-listed).
                         The shape check runs on the RESOLVED path's name, not the raw
                         pre-resolution string (C-135 round 4: `Path.resolve()` follows a
                         symlink in the FINAL path component too, so a symlink named
                         `decoy.trajectory.jsonl` pointing at a real credentials file
                         passed a raw-string check but not this one -- the resolved
                         basename is what every caller actually opens).
                         ``path`` is None. Real disk evidence a session existed, but not
                         ours to follow -- never counted as "missing" (that would claim
                         a real target is gone when we could not even read the claim).

    C-135, disclosed rather than silently accepted: this validates confinement and shape
    at DISCOVERY time, not at the moment a caller actually opens the file — a pointer
    naming an in-home, correctly-suffixed path that currently resolves cleanly could still
    be REPLACED by a symlink to something outside home between this check and a caller's
    open() (TOCTOU). Closing that fully needs every caller of the returned paths to open
    with O_NOFOLLOW/re-verify, which is a larger change than this task's own scope (a
    locator, not every reader); the local-attacker model here is the same one this whole
    module already accepts (an attacker able to write into agents/*/sessions/ can already
    forge a trajectory sidecar's CONTENT there directly).
    """
    # B-549 precedent (collector.py): a FIFO/socket/device node glob-matched as
    # `*.trajectory-path.json` would `read_bytes()` and block forever (a FIFO with no
    # writer) or read unbounded data (a character device) — the stat()-based size check
    # below does not save this, since e.g. a FIFO's st_size is 0. `is_file()` is a stat,
    # not an open, so it cannot itself hang; it must run before ANY read of this path.
    try:
        if not pointer_path.is_file():
            return "invalid", None
        pointer_size = pointer_path.stat().st_size
    except OSError:
        return "invalid", None
    if pointer_size > _POINTER_MAX_BYTES:
        return "invalid", None
    try:
        raw = pointer_path.read_bytes()
    except OSError:
        return "invalid", None
    if len(raw) > _POINTER_MAX_BYTES:
        return "invalid", None
    try:
        rec = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return "invalid", None
    if not isinstance(rec, dict):
        return "invalid", None
    if rec.get("traceSchema") != _POINTER_TRACE_SCHEMA:
        return "invalid", None
    if rec.get("schemaVersion") != _POINTER_SCHEMA_VERSION:
        return "invalid", None
    session_id = rec.get("sessionId")
    if not isinstance(session_id, str) or not session_id:
        return "invalid", None
    # The vendor validates sessionId against an externally-known expected value (it is
    # looking UP a pointer for a session it already knows); a bare scan has no such
    # external value, so the pointer's own FILENAME is the claim -- mirroring how the
    # vendor's writer derived that filename from the sessionId in the first place
    # (resolveTrajectoryPointerFilePath <- safeTrajectorySessionFileName(sessionId)).
    # Known, disclosed limitation: the vendor's regex runs over JS UTF-16 CODE UNITS;
    # this port runs over Python Unicode CODEPOINTS. The two agree for every sessionId
    # shape actually observed (OpenClaw generates these as UUIDs -- ASCII only), and
    # diverge only for a sessionId containing an astral-plane character, which would
    # make a genuine vendor-written pointer fail this check -- a coverage gap (that
    # session's trajectory is skipped, unless the plain glob still finds it), never a
    # confinement bypass, since a REJECTED pointer is never followed.
    name = pointer_path.name
    if not name.endswith(_POINTER_SUFFIX):
        return "invalid", None
    stem = name[: -len(_POINTER_SUFFIX)]
    if _safe_trajectory_session_file_name(session_id) != stem:
        return "invalid", None
    target = rec.get("runtimeFile")
    if not isinstance(target, str) or not target.strip():
        return "invalid", None
    # C-135 round 4 (independent, post-commit): the shape check used to run on this raw,
    # PRE-resolution string, which `Path.resolve()` below does not preserve -- `resolve()`
    # follows a symlink in ANY path component, including the final one. An attacker able to
    # write into agents/*/sessions/ (the threat model this whole function already assumes)
    # could name a symlink `decoy.trajectory.jsonl` -> `../../../credentials/store.json`:
    # the raw string passes this check, `resolve()` then follows the symlink to the real
    # (non-trajectory) target, which still lands `in_home` -- so the file this function's
    # own docstring says the shape check exists to keep out (opened and read line-by-line
    # by every caller) got through anyway. Checking the RESOLVED name closes it: a symlink
    # can point ANYWHERE, but resolve() always returns the real target's own basename, and
    # that is what every caller actually opens.
    try:
        resolved = Path(target).expanduser().resolve()
    except (OSError, ValueError, RuntimeError):
        return "invalid", None
    if not resolved.name.endswith(".trajectory.jsonl"):
        return "invalid", None
    try:
        in_home = resolved.is_relative_to(home_resolved)
    except (OSError, ValueError):
        in_home = False
    if not in_home:
        return "out_of_home", resolved
    try:
        exists = resolved.is_file()
    except OSError:
        exists = False
    return ("resolved", resolved) if exists else ("missing", resolved)


def explicit_path_problem(explicit_path: str | None) -> str | None:
    """Why an explicitly-named --behavioral PATH cannot be read, or None if it is fine.

    B-462: when the user names a file, a bad path is THEIR fact, not the host's. A typo
    used to fall through to the generic "no trajectory sidecars found ... run on a host
    where an OpenClaw agent has produced session trajectories" — blaming the machine,
    never echoing the path, and exiting 0 under a green tick.

    Shared by `analyze` and the CLI's exit-code decision so the two cannot disagree, and
    so deciding the exit code costs a stat rather than a second full `analyze()` pass over
    every trajectory file.

    B-686: moved here from ``behavioral.py``. Both trajectory modes take the same
    kind of argument and must answer a bad one the same way; leaving the predicate
    in one of them and importing it from the other would be a sibling dependency
    for a question that belongs to neither. It sits beside ``resolve_explicit_file``,
    which answers the adjacent half ("could I open it?"). ``behavioral`` re-exports
    the name, so every existing importer still resolves.

    The path is echoed unredacted, matching every other line these renderers print.
    ``report._redact_home_paths`` is for artifacts handed to someone else -- the
    dashboard card, SARIF, the CLI's stderr notes -- while an on-screen report keeps
    full paths on purpose: "a real path is exactly what an owner debugging their own
    config needs to see" (see that function's own docstring).
    """
    if not explicit_path:
        return None
    p = Path(explicit_path).expanduser()
    # B-683: `Path.exists()` swallows ENOENT/ENOTDIR/EBADF/ELOOP and NOT EACCES, so a
    # path under a directory this process cannot stat made it RAISE — and the one
    # function whose entire job is to name a path problem answered one of them with
    # "unexpected internal error (PermissionError) ... open an issue", i.e. by asking to
    # be bug-reported for the caller's own directory mode. Ask stat directly and name
    # each errno, rather than reading a boolean that cannot represent the third case.
    try:
        p.stat()
    except (FileNotFoundError, NotADirectoryError):
        return f"{explicit_path}: no such file or directory"
    except PermissionError:
        return f"{explicit_path}: permission denied"
    except OSError as exc:
        return f"{explicit_path}: {exc.strerror or exc}"
    # Reached only after a successful stat, so the parent is readable and this cannot
    # raise for the same reason.
    if p.is_dir():
        return f"{explicit_path}: is a directory, not a trajectory file"
    return None


def resolve_explicit_file(explicit_path) -> "tuple[list, bool]":
    """``(files, path_unreadable)`` for a user-named trajectory path.

    B-683. This was four copies of ``files = [p] if p.is_file() else []`` across this
    module and ``trajaudit.py``, and every one of them had the same two defects.

    ``Path.is_file()`` swallows ENOENT/ENOTDIR/EBADF/ELOOP and **not EACCES**, so a path
    under a directory the process cannot stat *raised* — out past every branch to the
    top-level handler, which printed "unexpected internal error (PermissionError) ...
    open an issue", soliciting a bug report for the caller's own directory mode.

    And catching it is only half the fix: falling back to an empty ``files`` on its own
    leaves ``present`` False, which every caller renders as "no trajectory data" — a
    statement about the agent's history sourced from a file nobody was allowed to open.
    The second return value is what keeps "there is nothing here" and "I could not look"
    apart, so a caller can say which one it means.

    One implementation rather than four, because the four had already drifted in what
    they recorded and a fifth copy is the obvious next step otherwise.
    """
    p = Path(explicit_path).expanduser()
    try:
        return ([p], False) if p.is_file() else ([], False)
    except OSError:
        return [], True


def find_trajectory_files(
    home: Path, *, max_files: int = _MAX_FILES, stats: dict | None = None
) -> list[Path]:
    """Return trajectory sidecar paths under *home* (newest-first, capped at *max_files*).

    Read-only glob of the grounded sidecar layout
    ``agents/*/sessions/*.trajectory.jsonl`` (recon §9.1), UNIONED (B-732) with every
    session a POINTER file (``agents/*/sessions/*.trajectory-path.json``) names, since
    OpenClaw itself locates a session's trajectory that way, not only by this glob —
    see ``_resolve_pointer_target`` for the validation/confinement this follows. A
    session with only a runtime file (no pointer) or only a pointer (no runtime file
    scanned by the glob, e.g. a differently-named target) is found either way; the union
    is deduplicated by resolved path so a session with BOTH is not counted twice. Returns
    ``[]`` on any error, or when *home* is not a ``Path``, so callers can treat "no on-disk
    record" uniformly. Only paths are returned — no file contents are read here (§8).

    If ``stats`` (a dict) is provided, it is populated with ``files_total`` (the number of
    trajectory sidecars found before the cap was applied) and ``files_capped`` (True when
    *max_files* caused files to be dropped, i.e. ``files_total > max_files``). This mirrors
    ``safeio.walk_dir_safely``'s ``capped`` out-param (B-244): the per-BYTE scan cap is
    already disclosed (C-180 ``truncated``), but the per-FILE cap silently dropped the
    oldest sessions with no signal a caller could surface — B-245 closes that gap. The
    default (``None``) keeps the original behaviour for existing callers.

    B-732 adds four more ``stats`` keys, additive and equally optional: ``pointer_
    targets_missing`` (a valid, in-home pointer whose named file does not exist — NEVER
    folded into "no trajectory sidecars"; see ``trajectorystore.corroborate()`` for what
    this asymmetry usually means), ``pointer_out_of_home`` (a valid pointer whose
    ``runtimeFile`` resolves OUTSIDE *home* — refused, never opened; disclosed so the
    refusal is a fact a caller can report, not a silent drop), ``pointer_invalid``
    (a pointer that could not be read, was oversized, or failed schema/session-id
    validation — real disk evidence a session existed, but not ours to follow or to
    count as "missing", which would claim a real target is gone when we could not even
    read the claim), and ``pointer_scan_capped`` (True when more than
    ``_MAX_POINTER_SCAN`` pointer files were present and the excess were never even
    opened — a DoS guard, mirroring ``trajectorystore.py``'s own independent pointer
    cap of the same size).
    """
    if not isinstance(home, Path):
        if stats is not None:
            stats["files_total"] = 0
            stats["files_capped"] = False
            stats["pointer_targets_missing"] = 0
            stats["pointer_out_of_home"] = 0
            stats["pointer_invalid"] = 0
            stats["pointer_scan_capped"] = False
        return []
    try:
        files = list(home.glob("agents/*/sessions/*.trajectory.jsonl"))
    except OSError:
        if stats is not None:
            stats["files_total"] = 0
            stats["files_capped"] = False
            stats["pointer_targets_missing"] = 0
            stats["pointer_out_of_home"] = 0
            stats["pointer_invalid"] = 0
            stats["pointer_scan_capped"] = False
        return []

    try:
        home_resolved = home.resolve()
    except (OSError, ValueError, RuntimeError):
        home_resolved = home
    # `seen_resolved` is built lazily, on the FIRST pointer that actually resolves --
    # not unconditionally up front. The common case today (pointer-based location is a
    # newer OpenClaw mechanism) is zero pointer files, and a host with a large
    # trajectory history would otherwise pay one resolve() syscall per glob-found file
    # for a dedup set nothing ever consults.
    seen_resolved: "set[Path] | None" = None
    pointer_targets_missing = 0
    pointer_out_of_home = 0
    pointer_invalid = 0
    pointer_scan_capped = False
    scanned = 0
    try:
        pointer_it = home.glob(f"agents/*/sessions/*{_POINTER_SUFFIX}")
    except OSError:
        pointer_it = iter(())
    try:
        # C-135: iterated LAZILY with an early break, mirroring trajectorystore.py's
        # own _pointer_files -- `list(home.glob(...))` first would fully enumerate and
        # construct a Path per match (real work) for every entry BEFORE the cap could
        # apply, so a directory salted with far more than _MAX_POINTER_SCAN pointers
        # would still pay the enumeration cost the cap exists to avoid.
        for p in pointer_it:
            if scanned >= _MAX_POINTER_SCAN:
                pointer_scan_capped = True
                break
            scanned += 1
            status, target = _resolve_pointer_target(p, home_resolved)
            if status == "resolved":
                if seen_resolved is None:
                    seen_resolved = set()
                    for f in files:
                        try:
                            seen_resolved.add(f.resolve())
                        except (OSError, ValueError, RuntimeError):
                            pass
                if target not in seen_resolved:
                    seen_resolved.add(target)
                    # C-135: re-anchor onto the CALLER's own `home` Path, not
                    # `home_resolved` — a glob result is naturally prefixed by `home`
                    # itself (however it was passed in, resolved or not), and a
                    # downstream consumer that does `path.relative_to(home)`
                    # (incident.py's tamper-evidence hashing) must see the same
                    # prefix shape from a pointer-found file as from a glob-found
                    # one, or a symlinked ancestor of `home` (a worktree, a
                    # symlinked /tmp) makes relative_to() raise and the entry
                    # silently drops. resolved is already PROVEN inside
                    # home_resolved above; relative_to here is informational
                    # reshaping, not a second security check.
                    try:
                        files.append(home / target.relative_to(home_resolved))
                    except ValueError:
                        files.append(target)
            elif status == "missing":
                pointer_targets_missing += 1
            elif status == "out_of_home":
                pointer_out_of_home += 1
            else:
                pointer_invalid += 1
    except OSError:
        # C-135: a directory becoming unreadable (permission change, concurrent
        # removal, a transient I/O error) mid-enumeration stops this exactly like
        # hitting the cap does -- some in-home pointers were never even looked at.
        # Reuses `pointer_scan_capped` rather than inventing a second, narrower flag:
        # to a caller, "hit the count cap" and "the scan itself was interrupted" both
        # mean the same thing operationally (pointer counts are a lower bound, not
        # exhaustive) -- the distinct CAUSE is not worth a second stats key.
        pointer_scan_capped = True

    # Per-path mtime lookup that never raises: list.sort() evaluates the key for
    # every element before comparing any of them, so if the plain
    # `p.stat().st_mtime` lambda raised on ONE path (a broken symlink — e.g. a
    # session archived to cold storage and left dangling — or a file removed by
    # the live agent between the glob above and this sort), the whole sort
    # aborted and `files` stayed in arbitrary os.scandir order. `files[:max_files]`
    # then dropped an arbitrary subset while the caller-facing message claims the
    # OLDEST sessions were skipped (B-245 false positive: a real recent session
    # could be silently excluded while the report claims the gap is confined to
    # the oldest history). Isolating the failure per-path keeps the sort total: an
    # unreadable path sorts as the oldest entry (so it lands in the dropped tail
    # exactly where a bogus/gone entry belongs) and every real path still sorts by
    # its true mtime.
    def _mtime_or_oldest(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return float("-inf")

    files.sort(key=_mtime_or_oldest, reverse=True)
    if stats is not None:
        stats["files_total"] = len(files)
        stats["files_capped"] = len(files) > max_files
        stats["pointer_targets_missing"] = pointer_targets_missing
        stats["pointer_out_of_home"] = pointer_out_of_home
        stats["pointer_invalid"] = pointer_invalid
        stats["pointer_scan_capped"] = pointer_scan_capped
    return files[:max_files]


def read_proven_tools_by_origin(
    home: Path,
    *,
    max_files: int = _MAX_FILES,
    max_bytes_per_file: int = _MAX_BYTES_PER_FILE,
    explicit_path: str | None = None,
) -> tuple[dict, dict]:
    """Return ``(by_origin, meta)`` — proven tool verbs BUCKETED by session origin.

    ``by_origin`` maps ``(origin_kind, origin_channel)`` -> the set of raw ``data.name``
    values proven in sessions of that origin, where the pair is
    ``parse_session_origin()``'s bucketed read of the record's top-level ``sessionKey``
    (``(None, None)`` for a record whose key is absent or unparseable — the honest
    UNKNOWN bucket, never folded into a named origin). ``meta`` is exactly the meta
    ``read_proven_tools`` documents.

    F-135 exists because the flat ``read_proven_tools`` set cannot answer the only
    question that separates signal from noise here: *which surface* the session that ran
    a verb was opened from. On a real host 867 proven ``bash`` calls sit in the log and
    every one of them came from the owner's own DM or dashboard — a consumer that can
    only see "bash was proven somewhere" cannot tell that apart from a group sender
    reaching exec, and would fire on the owner's own machine.

    §8: the bucket key carries the origin KIND and the channel id only. The
    ``sessionKey``'s peer-id segment (real PII) is never read into it — see
    ``parse_session_origin``. Per-verb payloads are still never touched.

    ``explicit_path`` (B-770) scans a single given ``.trajectory.jsonl`` file instead of
    globbing *home* — mirrors ``read_events``'s own parameter of the same name, so T3
    (``behavioral.check_capability_drift``, the sole caller of ``read_proven_tools`` that
    takes a ``--behavioral PATH``) can be confined to exactly the file the user named
    instead of silently falling back to a home-wide scan.
    """
    by_origin: dict = {}
    meta = {
        "present": False, "files_scanned": 0, "unknown_version": False,
        "unknown_schema": False,
        "files_total": 0, "files_capped": False,
        "pointer_targets_missing": 0, "pointer_out_of_home": 0, "pointer_invalid": 0,
        "pointer_scan_capped": False,
        "path_unreadable": False,
    }
    if explicit_path:
        files, meta["path_unreadable"] = resolve_explicit_file(explicit_path)
        meta["files_total"] = len(files)
    else:
        stats: dict = {}
        files = find_trajectory_files(home, max_files=max_files, stats=stats)
        meta["files_total"] = stats.get("files_total", 0)
        meta["files_capped"] = stats.get("files_capped", False)
        meta["pointer_targets_missing"] = stats.get("pointer_targets_missing", 0)
        meta["pointer_out_of_home"] = stats.get("pointer_out_of_home", 0)
        meta["pointer_invalid"] = stats.get("pointer_invalid", 0)
        meta["pointer_scan_capped"] = stats.get("pointer_scan_capped", False)
    if not files:
        return by_origin, meta
    meta["present"] = True

    for path in files:
        try:
            read = 0
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    read += len(line)
                    if read > max_bytes_per_file:
                        break
                    # Cheap pre-filter: skip the big model/context lines without JSON-parsing
                    # them; tool.call lines are small and carry the marker text.
                    if '"tool.call"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    if rec.get("traceSchema") != _TRACE_SCHEMA:
                        # B-716: this used to be a bare drop with no signal -- the
                        # SAME asymmetry `schemaVersion` (just below) already closed.
                        # A trajectory sidecar is append-only per session, so an
                        # OpenClaw upgrade mid-session is the NORMAL way a file ends
                        # up with SOME records on this schema and some not; a mixed
                        # file must not read as a clean, complete scan.
                        meta["unknown_schema"] = True
                        continue
                    if rec.get("schemaVersion") != _SCHEMA_VERSION:
                        meta["unknown_version"] = True
                        continue
                    if rec.get("type") != "tool.call":
                        continue
                    data = rec.get("data")
                    name = data.get("name") if isinstance(data, dict) else None
                    if isinstance(name, str) and name.strip():
                        origin = parse_session_origin(rec.get("sessionKey"))
                        by_origin.setdefault(origin, set()).add(name.strip())
        except OSError:
            continue
        meta["files_scanned"] += 1

    return by_origin, meta


def read_proven_tools(
    home: Path,
    *,
    max_files: int = _MAX_FILES,
    max_bytes_per_file: int = _MAX_BYTES_PER_FILE,
    explicit_path: str | None = None,
) -> tuple[set[str], dict]:
    """Return ``(verbs, meta)`` for tool verbs observed in trajectory sidecars under *home*.

    ``verbs`` is the set of raw ``data.name`` values from ``tool.call`` records in files
    whose ``traceSchema``/``schemaVersion`` match the grounded format. ``meta`` reports
    ``present`` (any trajectory file found), ``files_scanned``, ``unknown_version``
    (a trajectory line carried an unrecognised schema version — caller should treat the
    proven set as incomplete / UNKNOWN rather than authoritative), ``files_total`` (the
    number of trajectory sidecars found before the per-file cap), and ``files_capped``
    (True when the per-file cap dropped the oldest sessions — B-245: this proven-tool set
    is then incomplete too, same as ``unknown_version``).

    Only ``data.name`` is read; call/return payloads are never touched.

    F-135: this is now the origin-agnostic UNION of ``read_proven_tools_by_origin``
    rather than a second copy of the same scan loop. Deliberately a union, not a
    re-scan — the flat set every existing caller (B84, T3) reads is unchanged by
    construction, and there is one place where a parsing/version rule can drift.

    ``explicit_path`` (B-770) — see ``read_proven_tools_by_origin``, which this forwards
    it to unchanged.
    """
    by_origin, meta = read_proven_tools_by_origin(
        home, max_files=max_files, max_bytes_per_file=max_bytes_per_file,
        explicit_path=explicit_path,
    )
    verbs: set[str] = set()
    for names in by_origin.values():
        verbs |= names
    return verbs, meta


# Event types read_events() understands. Every other `type` value is skipped —
# never guessed at (§4: no fabricated facts about an ungrounded event shape).
_EVENT_TYPES = ("tool.call", "tool.result", "prompt.submitted")


# ---------------------------------------------------------------------------
# F-133 / B185 — the tool DEFINITIONS OpenClaw actually sent to the model.
# ---------------------------------------------------------------------------
#
# GROUNDING (installed dist, verified first-hand — not the recon doc, which is silent
# on this event):
#   * `selection-JInn13lc.js:14035` — trajectoryRecorder.recordEvent("context.compiled",
#     {systemPrompt, prompt, messages, tools: toTrajectoryToolDefinitions(...), ...}),
#     plus `providerVisibleTools` at :14040 when `toolSearch.compacted`.
#   * `run-attempt-CXZNKJ6y.js:5228` — recordCodexTrajectoryContext, the SECOND emission
#     path (Codex harness), same event type and same `tools` shape. Both are covered.
#   * `toTrajectoryToolDefinitions` (selection:752, run-attempt:5272) returns
#     {name, description, parameters}. `description` is copied VERBATIM — only
#     `parameters`/`inputSchema` goes through a sanitizer. So whatever text a tool
#     provider put in a description is on disk, unmodified.
#   * The MCP leg is complete in the dist: `client.listTools()`
#     (agent-bundle-mcp-runtime--G82BMQs.js:881) populates the catalog, and
#     agent-bundle-mcp-materialize-D9l-gQ5S.js:164 builds the agentTool with
#     `description: tool.description || tool.fallbackDescription`, pushed at :180 into
#     the array that becomes `effectiveTools` and then `context.compiled`.
#   * Recording is ON BY DEFAULT: selection:765
#     `if (!(parseBooleanValue(env.OPENCLAW_TRAJECTORY) ?? true)) return null;`
#
# WHY A DEDICATED READER instead of widening logscan's line cap: every real
# `context.compiled` line measured on a live host is 40–61 KB (n=268; min 40492,
# median 40854, max 60874), all far over logscan's `_MAX_LINE_LEN = 8000`, so today
# they are skipped outright. Raising that cap would push tens of KB of
# attacker-influenced text through the full regex battery — the exact ReDoS/DoS
# surface C-214 and B-192 exist to prevent. The sound fix is field-scoped extraction
# under its own bounds, which is what this is.
#
# §8: this reader extracts ONLY `data.tools[]` / `data.providerVisibleTools[]` and,
# within each entry, only `name`, `description`, and the parameter `description` /
# `default` strings under `parameters.properties`. The sibling `systemPrompt`,
# `prompt` and `messages` fields are the user's own conversation and bootstrap text —
# they are NEVER read, returned, or emitted. Honest limit: a whole-line `json.loads`
# does transiently materialize the siblings while parsing (as `trajaudit.py` already
# does for `data.arguments` under the Dave-ratified C-158 exception); the guarantee
# here is that nothing outside `tools[]` is ever read out of the parsed record or
# reaches a caller. `tests/test_b185_compiled_tool_poisoning.py` pins that property
# with sibling text that WOULD trip the detectors if it leaked.
_COMPILED_EVENT_TYPE = "context.compiled"

# The two `context.compiled` fields carrying tool definitions (dist cites above).
_COMPILED_TOOL_FIELDS = ("tools", "providerVisibleTools")

# DoS bounds (B-192's OOM lesson: bound the parse, not just the walk). Real events
# measured 40–61 KB with <=20 tools and a <=4.1 KB longest description, so these caps
# sit far above legitimate traffic and only bite on a padded/hostile line.
_MAX_COMPILED_LINE_LEN = 1_000_000
_MAX_TOOLS_PER_EVENT = 200
_MAX_TOOL_DEFS = 2_000
_MAX_DESC_CHARS = 20_000
_MAX_PARAMS_PER_TOOL = 100


def _bounded_text(value, limit: int = _MAX_DESC_CHARS) -> str:
    """Return *value* as a string truncated to *limit* chars (non-strings -> "")."""
    if not isinstance(value, str):
        return ""
    return value[:limit]


def _compiled_tool_entry(tool, field: str) -> dict | None:
    """Project one trajectory tool definition onto the §8-allowed named fields.

    Returns ``{name, description, params, field}`` where ``params`` is a list of
    ``(param_name, description, default)`` triples read from ``parameters.properties``
    — the trajectory's spelling of what C-038's TP3 leg calls ``inputSchema.properties``
    (dist `toTrajectoryToolDefinitions` renames the key on the way to disk). Returns
    ``None`` for a malformed entry — never a guess.
    """
    if not isinstance(tool, dict):
        return None
    name = tool.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    params: list[tuple[str, str, str]] = []
    parameters = tool.get("parameters")
    if isinstance(parameters, dict):
        props = parameters.get("properties")
        if isinstance(props, dict):
            for param_name, param_def in list(props.items())[:_MAX_PARAMS_PER_TOOL]:
                if not isinstance(param_def, dict):
                    continue
                params.append((
                    str(param_name)[:200],
                    _bounded_text(param_def.get("description")),
                    _bounded_text(param_def.get("default")),
                ))
    return {
        "name": name.strip()[:200],
        "description": _bounded_text(tool.get("description")),
        "params": params,
        "field": field,
    }


def read_compiled_tool_descriptions(
    home: Path,
    *,
    max_files: int = _MAX_FILES,
    max_bytes_per_file: int = _MAX_BYTES_PER_FILE,
    explicit_path: str | None = None,
) -> tuple[list[dict], dict]:
    """Return ``(tool_defs, meta)`` — the tool definitions actually sent to the model.

    Reads ``type == "context.compiled"`` records from the trajectory sidecars under
    *home* and returns the DEDUPLICATED tool definitions found in ``data.tools[]`` and
    ``data.providerVisibleTools[]``. Each entry is
    ``{name, description, params, field}`` as built by ``_compiled_tool_entry``.
    Deduplication is by full content, so the 4,925 definitions a real host records
    collapse to the ~20 distinct ones actually in play.

    This is POST-HOC FORENSIC evidence: it reports what WAS sent to the model in
    sessions that already ran. It cannot pre-clear a live MCP server, and a server that
    served a clean description on the recorded runs can serve a poisoned one later.

    ``meta`` reports ``present`` (any trajectory file found), ``files_scanned``,
    ``events`` (``context.compiled`` records parsed), ``unknown_version``, and
    ``truncated`` (a per-file byte cap, an oversized line, or a per-scan definition cap
    was hit — the extracted set is then incomplete, so a clean verdict on it must not
    read as confidently complete).

    §8: only the named sub-fields above are read. ``systemPrompt``, ``prompt`` and
    ``messages`` — the user's own conversation — are never read or returned.
    """
    tool_defs: list[dict] = []
    meta = {
        "present": False, "files_scanned": 0, "events": 0,
        "unknown_version": False, "unknown_schema": False, "truncated": False,
        "files_total": 0, "files_capped": False,
        "path_unreadable": False,  # B-683
        "pointer_targets_missing": 0, "pointer_out_of_home": 0, "pointer_invalid": 0,
        "pointer_scan_capped": False,
    }

    if explicit_path:
        files, meta["path_unreadable"] = resolve_explicit_file(explicit_path)
        meta["files_total"] = len(files)
    else:
        stats: dict = {}
        files = find_trajectory_files(home, max_files=max_files, stats=stats)
        meta["files_total"] = stats.get("files_total", 0)
        meta["files_capped"] = stats.get("files_capped", False)
        meta["pointer_targets_missing"] = stats.get("pointer_targets_missing", 0)
        meta["pointer_out_of_home"] = stats.get("pointer_out_of_home", 0)
        meta["pointer_invalid"] = stats.get("pointer_invalid", 0)
        meta["pointer_scan_capped"] = stats.get("pointer_scan_capped", False)
    if not files:
        return tool_defs, meta
    meta["present"] = True

    seen: set[tuple] = set()
    for path in files:
        try:
            read = 0
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    read += len(line)
                    if read > max_bytes_per_file:
                        meta["truncated"] = True
                        break
                    # Cheap pre-filter: never JSON-parse the many other event types.
                    if f'"{_COMPILED_EVENT_TYPE}"' not in line:
                        continue
                    # Bound the parse itself (B-192): a padded line is skipped and
                    # DISCLOSED, never silently dropped and never parsed.
                    if len(line) > _MAX_COMPILED_LINE_LEN:
                        meta["truncated"] = True
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    if rec.get("traceSchema") != _TRACE_SCHEMA:
                        # B-716: mirrors schemaVersion's own disclosure just below --
                        # see that task for why a bare drop here was the bug.
                        meta["unknown_schema"] = True
                        continue
                    if rec.get("schemaVersion") != _SCHEMA_VERSION:
                        meta["unknown_version"] = True
                        continue
                    if rec.get("type") != _COMPILED_EVENT_TYPE:
                        continue
                    data = rec.get("data")
                    if not isinstance(data, dict):
                        continue
                    meta["events"] += 1
                    # §8: ONLY the tool-definition fields are touched. The sibling
                    # systemPrompt / prompt / messages keys are never referenced.
                    for field in _COMPILED_TOOL_FIELDS:
                        tools = data.get(field)
                        if not isinstance(tools, list):
                            continue
                        if len(tools) > _MAX_TOOLS_PER_EVENT:
                            meta["truncated"] = True
                        for tool in tools[:_MAX_TOOLS_PER_EVENT]:
                            entry = _compiled_tool_entry(tool, field)
                            if entry is None:
                                continue
                            key = (
                                entry["name"], entry["description"],
                                tuple(entry["params"]), entry["field"],
                            )
                            if key in seen:
                                continue
                            if len(tool_defs) >= _MAX_TOOL_DEFS:
                                meta["truncated"] = True
                                break
                            seen.add(key)
                            tool_defs.append(entry)
        except OSError:
            continue
        meta["files_scanned"] += 1

    return tool_defs, meta


# ---------------------------------------------------------------------------
# Session ORIGIN — where a session was opened FROM, bucketed by KIND only (B-298).
# ---------------------------------------------------------------------------
#
# Every trajectory record carries a top-level `sessionKey`. Grounded in the installed
# dist: `parseAgentSessionKey` (session-key-utils-A-JGvyXu.js) splits it as
# `agent:<agentId>:<rest>`, and `buildAgentPeerSessionKey` (session-key-VWT_xzM9.js)
# builds `<rest>` for an externally-delivered session as
# `<channel>:<peerKind>:<peerId>` (or `<channel>:<accountId>:direct:<peerId>` under the
# per-account-channel-peer DM scope; `direct:<peerId>` under per-peer). Non-peer
# surfaces get their own literal prefix — `dashboard:<uuid>`
# (session-create-service-14oZxrT5.js `buildDashboardSessionKey`), `main`
# (`buildAgentMainSessionKey`), `cron:` / `subagent:` / `acp:` / `explicit:` / `voice:`
# / `boot` / `global`.
#
# §8 PRIVACY — this is why the function returns a KIND, not the key. The peer id
# segment is real PII: a live host's key reads `agent:main:telegram:direct:<numeric
# telegram user id>`. Nothing here ever returns, logs or emits that segment; the only
# strings that escape are the bounded peer KIND and the lowercase channel id.
#
# Canonical peer kinds (dist session-chat-type-shared-DlB0c25q.js
# `CANONICAL_PEER_KINDS`, mirrored by session-key-utils' `SESSION_DELIVERY_PEER_KINDS`).
_PEER_KINDS = ("direct", "dm", "group", "channel")

# Literal non-peer session prefixes OpenClaw builds (see the dist cites above).
_SESSION_PREFIX_KINDS = (
    "dashboard", "cron", "subagent", "acp", "explicit", "voice", "boot", "main", "global",
)

# The origin kinds that mean "this session was opened by a MULTI-PARTY EXTERNAL
# surface" — a group chat or a broadcast channel, where a message can be authored by
# somebody who is not the owner. Deliberately EXCLUDES "direct": a 1:1 DM is
# overwhelmingly the owner talking to his own bot (measured on a real host: 1,774 of
# 3,896 records are one `telegram:direct:<owner id>` session), so arming on it would
# manufacture noise on ordinary owner traffic. See behavioral.py for the residual that
# leaves open.
EXTERNAL_ORIGIN_KINDS = ("group", "channel")


def parse_session_origin(session_key) -> tuple:
    """Return ``(kind, channel)`` for a trajectory record's top-level ``sessionKey``.

    ``kind`` is the ORIGIN bucket — one of the canonical peer kinds folded the way
    OpenClaw's own ``parseCanonicalSessionPeerShape`` folds them ("dm" -> "direct"),
    one of the literal non-peer prefixes in ``_SESSION_PREFIX_KINDS``, ``"other"`` for
    a parseable key whose shape we do not recognise, or ``None`` when the key is
    absent/unparseable (the honest UNKNOWN — §4: never guessed).

    ``channel`` is the lowercase channel id (e.g. "telegram") when the shape carries
    one, else ``None``.

    §8: the peer-id segment is NEVER returned. Neither is the account id.
    """
    if not isinstance(session_key, str):
        return (None, None)
    parts = [p.strip() for p in session_key.strip().split(":")]
    # `agent:<agentId>:<rest>` — dist `parseAgentSessionKey`.
    if len(parts) < 3 or parts[0].lower() != "agent" or not parts[1]:
        return (None, None)
    rest = parts[2:]
    if not rest[0]:
        return (None, None)
    head = rest[0].lower()

    # Peer shapes, in the SAME precedence order as the dist's own
    # `parseCanonicalSessionPeerShape`: peer-kind at index 0 (no channel segment),
    # then index 1, then index 2 (the account-scoped form). A peer id must follow the
    # kind, or it is not a delivery shape at all.
    if head in ("direct", "dm") and len(rest) >= 2 and rest[1]:
        return ("direct", None)
    if len(rest) >= 3 and rest[1].lower() in _PEER_KINDS and rest[2]:
        kind = rest[1].lower()
        return ("direct" if kind == "dm" else kind, head)
    if len(rest) >= 4 and rest[1] and rest[2].lower() in _PEER_KINDS and rest[3]:
        kind = rest[2].lower()
        return ("direct" if kind == "dm" else kind, head)

    if head in _SESSION_PREFIX_KINDS:
        return (head, None)
    # A parseable key we don't recognise — e.g. a custom `session.mainKey`, which
    # `normalizeMainKey` substitutes for the literal "main". Bucketed as "other" and
    # never armed as ingress: this fails toward a missed detection, never a false one.
    return ("other", None)


def _event_outcome(rec_type: str, data: dict) -> str | None:
    """Classify a tool.result's outcome from status/isError/success (§9.1 grounded).

    Returns "success", "failed", or None (ambiguous/not a tool.result — never guessed).
    Never reads output/result/contentItems — those are the sensitive payload (§8).
    """
    if rec_type != "tool.result":
        return None
    status = data.get("status")
    is_error = data.get("isError")
    success = data.get("success")
    if status == "failed" or is_error is True or success is False:
        return "failed"
    if status == "completed" or success is True:
        return "success"
    return None


def read_events(
    home: Path,
    *,
    max_files: int = _MAX_FILES,
    max_bytes_per_file: int = _MAX_BYTES_PER_FILE,
    explicit_path: str | None = None,
) -> tuple[list[dict], dict]:
    """Return (events, meta) — §8-safe event metadata for the behavioral engine.

    Each event is ``{type, name, ts, seq, sessionId, turnId, threadId, outcome, origin,
    originChannel}`` for ``tool.call``/``tool.result``/``prompt.submitted`` records
    (§9.1 grounded envelope). ``name`` and ``outcome`` are ``None`` where the event type
    doesn't carry them (e.g. ``prompt.submitted`` has no tool name; only ``tool.result``
    has an outcome). ``sessionId`` (top-level, not sensitive — a session identifier) lets
    a caller scope grouping to one session, since ``seq`` is a per-session counter
    (§9.1), not globally unique across trajectory files (C-170 adversarial finding).

    ``origin``/``originChannel`` (B-298) are ``parse_session_origin()``'s bucketed read
    of the top-level ``sessionKey`` — the surface the session was opened from. They let
    a detector tell an externally-delivered message apart from the owner's own typing,
    which no tool VERB NAME can express. ``origin`` is ``None`` when the key is absent
    or unparseable — an honest UNKNOWN, never a guess.

    NEVER reads ``data.arguments``/``data.output``/``data.result``/``data.contentItems``
    — the sensitive call/return payloads (§8), nor the ``sessionKey``'s peer-id segment
    (PII — see ``parse_session_origin``). Only tool/event identity, origin KIND, and
    sequencing metadata. Same version gate and DoS bounds as ``read_proven_tools``.

    ``explicit_path`` scans a single given ``.trajectory.jsonl`` file instead of
    globbing *home* (mirrors ``trajaudit.analyze``'s CLI PATH argument). ``files_total``/
    ``files_capped`` (B-245) report the per-file cap the same way ``truncated`` already
    reports the per-byte cap (C-180); with ``explicit_path`` there is no cap to hit, so
    ``files_capped`` stays False and ``files_total`` is just the (0 or 1) file scanned.
    """
    events: list[dict] = []
    meta = {
        "present": False, "files_scanned": 0, "unknown_version": False,
        "unknown_schema": False, "truncated": False,
        "files_total": 0, "files_capped": False,
        # B-683: the named path could not be opened at all.
        "path_unreadable": False,
        # B-767: a line that passed the event-type pre-filter (so it LOOKED like a
        # target event) but failed json.loads — a truncated/interrupted write, most
        # commonly. Scoped to exactly that: ordinary noise (model.completed, etc.)
        # never reaches json.loads at all, so it can't set this. A file carrying such
        # a line still counts as `files_scanned` (the OS-level read succeeded), which
        # is why this needs its own flag rather than reusing `truncated` — the byte
        # cap and a mid-record parse failure are different reasons a read is not
        # exhaustive, and behavioral.py's analysis_incompleteness() needs to name
        # each honestly.
        "unparseable_lines": False,
        "pointer_targets_missing": 0, "pointer_out_of_home": 0, "pointer_invalid": 0,
        "pointer_scan_capped": False,
    }

    if explicit_path:
        files, meta["path_unreadable"] = resolve_explicit_file(explicit_path)
        meta["files_total"] = len(files)
    else:
        stats: dict = {}
        files = find_trajectory_files(home, max_files=max_files, stats=stats)
        meta["files_total"] = stats.get("files_total", 0)
        meta["files_capped"] = stats.get("files_capped", False)
        meta["pointer_targets_missing"] = stats.get("pointer_targets_missing", 0)
        meta["pointer_out_of_home"] = stats.get("pointer_out_of_home", 0)
        meta["pointer_invalid"] = stats.get("pointer_invalid", 0)
        meta["pointer_scan_capped"] = stats.get("pointer_scan_capped", False)
    if not files:
        return events, meta
    meta["present"] = True

    for path in files:
        try:
            read = 0
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    read += len(line)
                    if read > max_bytes_per_file:
                        # C-180: surface the cap hit — a signal past this byte
                        # offset is silently unscanned, so a clean T1/T2 verdict
                        # on a capped file must not read as confidently complete.
                        meta["truncated"] = True
                        break
                    # Cheap pre-filter: skip lines that can't be one of our event
                    # types without JSON-parsing every line (most lines are other
                    # event types we don't read, e.g. model.completed).
                    if not any(f'"{t}"' in line for t in _EVENT_TYPES):
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        # B-767: this line passed the event-type pre-filter above --
                        # it looked like a target event and failed to parse, which a
                        # truncated/interrupted write produces. Silently dropping it
                        # with no trace was the gap: `files_scanned` still counts this
                        # file as fully read (below), so a caller had no way to tell
                        # "nothing here" from "something here that could not be read".
                        meta["unparseable_lines"] = True
                        continue
                    if not isinstance(rec, dict):
                        continue
                    if rec.get("traceSchema") != _TRACE_SCHEMA:
                        # B-716: mirrors schemaVersion's own disclosure just below --
                        # see that task for why a bare drop here was the bug. T1/T2/T3
                        # all read this meta via analysis_incompleteness().
                        meta["unknown_schema"] = True
                        continue
                    if rec.get("schemaVersion") != _SCHEMA_VERSION:
                        meta["unknown_version"] = True
                        continue
                    rec_type = rec.get("type")
                    if rec_type not in _EVENT_TYPES:
                        continue
                    data = rec.get("data")
                    if not isinstance(data, dict):
                        data = {}
                    name = data.get("name")
                    origin, origin_channel = parse_session_origin(rec.get("sessionKey"))
                    events.append({
                        "type": rec_type,
                        "name": name.strip() if isinstance(name, str) and name.strip() else None,
                        "ts": rec.get("ts"),
                        "seq": rec.get("seq"),
                        "sessionId": rec.get("sessionId"),
                        "turnId": data.get("turnId"),
                        "threadId": data.get("threadId"),
                        "outcome": _event_outcome(rec_type, data),
                        "origin": origin,
                        "originChannel": origin_channel,
                    })
        except OSError:
            continue
        meta["files_scanned"] += 1

    return events, meta
