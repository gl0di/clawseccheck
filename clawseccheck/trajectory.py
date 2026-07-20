"""Read-only scan of OpenClaw trajectory sidecars for log-observed tool use.

OpenClaw writes a per-session trajectory sidecar next to each session file:
``<home>/agents/<agent>/sessions/<session>.trajectory.jsonl`` (on by default; see
``docs/tools/trajectory.md``). Each line is a JSON envelope with a ``type``
discriminator; ``type == "tool.call"`` records carry the tool VERB in ``data.name``.
Grounded against a live install — see ``docs/research/openclaw-schema-recon.md`` §9.1.

This module extracts the SET of tool verbs the agent actually invoked (``data.name``)
so a check can report *proven* — log-observed, not self-reported — tool use. It is the
log-observed upgrade to the attestation self-report path.

Security (§8): this reads the user's own logs, which may contain secrets. It reads ONLY
``data.name`` (the tool identity, not a secret), the version marker, and the top-level
``sessionKey``'s ORIGIN KIND (see ``parse_session_origin`` — never the peer id it
embeds) — it NEVER reads ``data.arguments``, ``data.output``, ``data.result`` or
``data.contentItems`` (the sensitive call/return payloads). Stdlib-only, read-only,
no network.
"""
from __future__ import annotations

import json
from pathlib import Path

# Version gate: only parse the format we have grounded. Any other value -> we don't guess.
_TRACE_SCHEMA = "openclaw-trajectory"
_SCHEMA_VERSION = 1

# Bounds so a large/padded fleet of session logs can't blow up the scan (DoS guard).
_MAX_FILES = 60
_MAX_BYTES_PER_FILE = 8_000_000


def find_trajectory_files(
    home: Path, *, max_files: int = _MAX_FILES, stats: dict | None = None
) -> list[Path]:
    """Return trajectory sidecar paths under *home* (newest-first, capped at *max_files*).

    Read-only glob of the grounded sidecar layout
    ``agents/*/sessions/*.trajectory.jsonl`` (recon §9.1). Returns ``[]`` on any error, or
    when *home* is not a ``Path``, so callers can treat "no on-disk record" uniformly. Only
    paths are returned — no file contents are read here (§8).

    If ``stats`` (a dict) is provided, it is populated with ``files_total`` (the number of
    trajectory sidecars found before the cap was applied) and ``files_capped`` (True when
    *max_files* caused files to be dropped, i.e. ``files_total > max_files``). This mirrors
    ``safeio.walk_dir_safely``'s ``capped`` out-param (B-244): the per-BYTE scan cap is
    already disclosed (C-180 ``truncated``), but the per-FILE cap silently dropped the
    oldest sessions with no signal a caller could surface — B-245 closes that gap. The
    default (``None``) keeps the original behaviour for existing callers.
    """
    if not isinstance(home, Path):
        if stats is not None:
            stats["files_total"] = 0
            stats["files_capped"] = False
        return []
    try:
        files = list(home.glob("agents/*/sessions/*.trajectory.jsonl"))
    except OSError:
        if stats is not None:
            stats["files_total"] = 0
            stats["files_capped"] = False
        return []
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
    return files[:max_files]


def read_proven_tools_by_origin(
    home: Path,
    *,
    max_files: int = _MAX_FILES,
    max_bytes_per_file: int = _MAX_BYTES_PER_FILE,
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
    """
    by_origin: dict = {}
    meta = {
        "present": False, "files_scanned": 0, "unknown_version": False,
        "files_total": 0, "files_capped": False,
    }
    stats: dict = {}
    files = find_trajectory_files(home, max_files=max_files, stats=stats)
    meta["files_total"] = stats.get("files_total", 0)
    meta["files_capped"] = stats.get("files_capped", False)
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
    """
    by_origin, meta = read_proven_tools_by_origin(
        home, max_files=max_files, max_bytes_per_file=max_bytes_per_file
    )
    verbs: set[str] = set()
    for names in by_origin.values():
        verbs |= names
    return verbs, meta


# Event types read_events() understands. Every other `type` value is skipped —
# never guessed at (§4: no fabricated facts about an ungrounded event shape).
_EVENT_TYPES = ("tool.call", "tool.result", "prompt.submitted")


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
        "present": False, "files_scanned": 0, "unknown_version": False, "truncated": False,
        "files_total": 0, "files_capped": False,
    }

    if explicit_path:
        p = Path(explicit_path).expanduser()
        files = [p] if p.is_file() else []
        meta["files_total"] = len(files)
    else:
        stats: dict = {}
        files = find_trajectory_files(home, max_files=max_files, stats=stats)
        meta["files_total"] = stats.get("files_total", 0)
        meta["files_capped"] = stats.get("files_capped", False)
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
                        continue
                    if not isinstance(rec, dict):
                        continue
                    if rec.get("traceSchema") != _TRACE_SCHEMA:
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
