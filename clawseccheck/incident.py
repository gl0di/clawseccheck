"""`--incident`: a local, read-only evidence-pack builder (standard §20.2 IR playbook).

B85 already checks that a tamper-resistant tool-use trail EXISTS; this module actually
ASSEMBLES a preservation bundle from what an audit pass already collected — a
"preservation aid for step 3/6 of the incident-response playbook", never automated
remediation. It gathers pointers and hashes; it never rotates, deletes, or mutates
anything, and it never touches the network.

Every piece is reused from an existing, already-shipped producer rather than
reinvented: the findings snapshot is the same `_finding_to_dict` shape every other
JSON export uses; the skill/MCP inventory is `sbom.build_sbom()` (F-085) verbatim;
the trajectory-sidecar hashes reuse `trajectory.find_trajectory_files()` (B85's own
file-discovery, still never reading `data.arguments`/output — only whole-file
bytes for hashing, which never exposes call contents); monitor event history is
`monitor.load_events()` verbatim. The credential rotation list (B-569) is
inventory-driven rather than any single check's evidence — see
`_credential_rotation_list`'s docstring for the producer-by-producer coverage —
so it survives independent of which check passed, failed, or was asked at all;
it is still PII-safe: config paths, provider names, and file names only, never
a secret value.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from . import trajectory as _trajectory
from . import trajectorystore as _trajectorystore
from .catalog import ACTIONABLE_STATUSES
from .checks import SECRET_PATTERNS, _pattern_hits_real_secret, _secret_paths
from .incidentstore import DEFAULT_INCIDENTS, _incident_to_dict, create_incident
from .monitor import DEFAULT_EVENTS, load_events
from .monitorstore import _last_chain_hash
from .sbom import build_sbom
from .scanbudget import limits_for

INCIDENT_VERSION = 1

#: C-520: the only place a PID is ever resolved anywhere in this codebase today is
#: checks/_config.py's check_effective_bind (B340), via sockets.identify_listener_process
#: -- and even there it is never a structured Finding field, only free text baked into
#: evidence. hostpersist.py has no PID correlation at all (measured: zero "pid" hits).
#: These two exact phrasings are B340's only producers of that text -- see
#: checks/_config.py around "held by pid"/"confirmed via pid".
_PID_EVIDENCE_RE = re.compile(r"\b(?:held by pid|confirmed via pid) (\d+) \(([^)]*)\)")

#: C-135: _pid_from_findings must scan ONLY this id's evidence, never every linked
#: finding's. checks/_content.py's content-security ring echoes a SKILL's own text
#: verbatim into evidence (e.g. `evidence.append(f'{skill_name}: "{snippet}"')`) --
#: reproduced: a malicious skill whose own markdown contains the literal substring
#: "confirmed via pid 1 (systemd)" trips some unrelated prompt-injection check, and
#: that check's evidence carries the attacker's text straight through. Scanning every
#: actionable finding's evidence -- as an earlier version of this function did -- let
#: attacker-controlled skill CONTENT fabricate a PID/process link Golden Rule #4
#: forbids: this was never a real sockets.py resolution.
_PID_EVIDENCE_FINDING_ID = "B340"


def _pid_from_findings(findings) -> "tuple[str | None, str | None]":
    """Best-effort (pid, process_name) extracted from B340's own evidence text --
    deliberately never an independent fresh /proc re-scan (a fresh scan could resolve a
    DIFFERENT, now-stale PID than the one B340 actually reported: the process could have
    exited and the PID been reused, which would link the incident to a process it never
    observed) and deliberately never any OTHER finding's evidence (see
    _PID_EVIDENCE_FINDING_ID's comment -- that text can be attacker-controlled skill
    content). (None, None) when B340 isn't linked or doesn't match."""
    for f in findings:
        if f.id != _PID_EVIDENCE_FINDING_ID:
            continue
        for line in getattr(f, "evidence", None) or ():
            m = _PID_EVIDENCE_RE.search(line)
            if m:
                return m.group(1), m.group(2)
    return None, None


def open_incident_from_audit(ctx, findings, *, path: "str | Path | None" = None,
                             events: "str | Path | None" = None,
                             when: "str | None" = None) -> "tuple[dict | None, str | None]":
    """--incident-open's entry point: derive a new persisted Incident from findings this
    audit run actually produced. Filters to catalog.ACTIONABLE_STATUSES -- the same
    shared FAIL-weight/WARN vocabulary B-751/B-755 exist to keep every consumer using,
    rather than re-spelling "FAIL" as a literal here and risking the exact drift those
    fixed. *ctx* is accepted (mirroring build_incident's signature) but not read; it is
    there for callers that already have it and a possible future PID-independent link.

    Returns (record_dict, None) on success, or (None, reason) where reason is
    "no_actionable_findings" (refused -- an incident needs a real basis, never a
    fabricated one) or "write_failed".
    """
    actionable = [f for f in findings if f.status in ACTIONABLE_STATUSES]
    if not actionable:
        return None, "no_actionable_findings"

    finding_ids = [f.id for f in actionable]
    pid, process_name = _pid_from_findings(actionable)
    events_path = DEFAULT_EVENTS if events is None else events
    monitor_watermark = _last_chain_hash(Path(events_path).expanduser()) or None
    store_path = DEFAULT_INCIDENTS if path is None else path

    inc = create_incident(finding_ids, pid=pid, process_name=process_name,
                          monitor_watermark=monitor_watermark, path=store_path, when=when)
    if inc is None:
        return None, "write_failed"
    return _incident_to_dict(inc), None


def incident_timeline(monitor_watermark: "str | None",
                      events: "str | Path | None" = None) -> "tuple[list, bool]":
    """The --monitor events appended after *monitor_watermark* on the SAME hash-chained
    journal --incident-open pointed at -- a live read of the existing store, never a
    second copy (per the task's own instruction). Returns (events, watermark_found).

    watermark_found is False when *monitor_watermark* is truthy but no longer present in
    the current journal (almost always: it rotated away since the incident opened) -- in
    that case every currently-available event is still returned rather than none, but the
    caller must disclose the gap: some of them may predate the incident, and this
    function cannot tell which."""
    events_path = DEFAULT_EVENTS if events is None else events
    all_events = load_events(events_path)
    if not monitor_watermark:
        return all_events, True
    idx = next((i for i, e in enumerate(all_events)
               if e.get("chain_hash") == monitor_watermark), None)
    if idx is None:
        return all_events, False
    return all_events[idx + 1:], True


def render_incident_record(record: dict, *, timeline: "list | None" = None,
                           timeline_complete: bool = True) -> str:
    """Human-readable text for --incident-open/--incident-mark/--incident-show. *timeline*
    is only ever passed by --incident-show (the create/mark responses don't compute one)."""
    lines = [
        f"Incident {record['id']} — status: {record['status']}",
        f"created: {record['created_at']}",
    ]
    if record["finding_ids"]:
        lines.append(f"linked findings: {', '.join(record['finding_ids'])}")
    if record["pid"]:
        lines.append(f"linked process: pid {record['pid']} ({record['process_name']})")
    lines.append("history:")
    for h in record["history"]:
        lines.append(f"  {h['ts']}  -> {h['status']}")
    if timeline is not None:
        if not timeline_complete:
            lines.append(
                "monitor timeline: watermark not found in the current journal (it likely "
                "rotated away) — showing all currently-available events; some may predate "
                "this incident.")
        if timeline:
            header = ("monitor timeline (all currently-available events, completeness "
                      "not guaranteed):" if not timeline_complete else
                      "monitor timeline (events since this incident opened):")
            lines.append(header)
            for e in timeline:
                lines.append(f"  {e.get('ts')}  {e.get('severity', '')}  {e.get('message', '')}")
        elif timeline_complete:
            lines.append("monitor timeline: no events recorded since this incident opened.")
        else:
            lines.append("monitor timeline: no events in the current journal.")
    return "\n".join(lines)

_MAX_TRAJECTORY_BYTES = 8_000_000  # mirrors trajectory.py's own per-file scan cap


def _hash_trajectory_file(home: Path, path: Path, kind: str) -> "dict | None":
    """One entry of the shape :func:`_trajectory_hash_entries` returns, for a single
    file — shared by both the JSONL sidecar sweep and the SQLite database sweep so the
    byte-cap/truncation discipline can never diverge between the two containers.
    ``kind`` distinguishes which container the path came from (``"jsonl"`` or
    ``"sqlite_db"``); a raw whole-file hash either way — for the SQLite path this is a
    hash of the .sqlite file's own bytes, never a read of any row inside it (B-815: no
    ``event_json``, no ``sqlite3`` use here at all — see the module's own §8 doctrine,
    already enforced by trajectorystore.py, which this function never bypasses).
    """
    try:
        raw = path.read_bytes()
        rel = path.relative_to(home)
    except (OSError, ValueError):
        return None
    truncated = len(raw) > _MAX_TRAJECTORY_BYTES
    data = raw[:_MAX_TRAJECTORY_BYTES] if truncated else raw
    return {
        "path": str(rel),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "truncated": truncated,
        "kind": kind,
    }


def _trajectory_hash_entries(home, *, max_files: int | None = None) -> list[dict]:
    """Hash each trajectory sidecar file's raw bytes — never parses/reads call
    content. A hash lets an investigator later prove a file wasn't altered
    without this pack itself having read anything sensitive out of it.

    Files at or under ``_MAX_TRAJECTORY_BYTES`` get an honest full-file
    ``sha256``. Files over the cap are NOT silently hashed as if complete —
    the digest only covers the first ``_MAX_TRAJECTORY_BYTES`` bytes, and
    ``truncated: True`` is always surfaced so a consumer can never mistake a
    partial digest for a whole-file one (mirrors collector.py's
    ``_read_with_limit`` (bytes, truncated) contract).

    ``_MAX_TRAJECTORY_BYTES`` itself is a digest-completeness cap, not a scan cap
    (F-164 out of scope — deliberately not widened by --exhaustive). ``max_files``
    (F-164, optional) widens only the FILE-COUNT cap under --exhaustive; ``None``
    reproduces today's default (``trajectory._MAX_FILES``).

    B-815: on a SQLite-era install the JSONL locator alone returns nothing to hash even
    though real trajectory evidence exists — so this also hashes every per-agent SQLite
    trajectory *database file* (``trajectorystore.sqlite_db_paths(home)``), whole-file,
    same byte-cap/truncation discipline, never opened/read as a database (no ``sqlite3``
    import here, no ``event_json``). Each entry now carries ``"kind"``
    (``"jsonl"``/``"sqlite_db"``) so a consumer can tell the two containers apart.
    """
    if not isinstance(home, Path):
        return []
    entries: list[dict] = []
    kwargs = {} if max_files is None else {"max_files": max_files}
    for path in _trajectory.find_trajectory_files(home, **kwargs):
        entry = _hash_trajectory_file(home, path, "jsonl")
        if entry is not None:
            entries.append(entry)
    for path in _trajectorystore.sqlite_db_paths(home):
        entry = _hash_trajectory_file(home, path, "sqlite_db")
        if entry is not None:
            entries.append(entry)
    return entries


def _credential_rotation_list(ctx, findings) -> list[str]:
    """Inventory-driven, not verdict-driven (B-569). The old version returned
    B41's evidence verbatim; B41's scope is "credentials reachable by untrusted
    ingress", so a channel secret like a Telegram bot token — which never SENDS
    anything itself, so B41 never counts it — could be live in config and never
    reach this pack. Sourcing from any check's finding also inherits that
    check's verdict logic: B1 only publishes its bootstrap-secret evidence on
    FAIL, so a config secret behind tight file perms (B1 PASS, correctly — the
    permissions ARE fine) stayed invisible here even though B1's own detail
    string counts it ("N token(s) in config"). Post-compromise, "the
    permissions were fine" is irrelevant: rotation must not depend on whether a
    hardening check happened to be happy.

    Every producer of a credential-shaped finding, and whether it feeds this
    list (checked B-569 — start here, don't re-derive):
      * B41 (checks/_config.py check_credential_blast_radius) — COVERED.
        Provider names (auth.profiles) + a gateway-token marker. Kept for its
        blast-radius framing; unioned in rather than replaced.
      * checks/_shared.py _secret_paths(ctx.config) — NOW COVERED, this is the
        fix. Every SECRET_KEY_RE-matching config path holding a real inline
        value (password/secret/token/apiKey/botToken) — the same inventory B1
        counts but does not always surface — independent of file permissions
        or any check's PASS/FAIL. Paths only, never values (§8).
      * B1's bootstrap-file pattern hits (ctx.bootstrap, SECRET_PATTERNS) — NOW
        COVERED, marked uncertain. A free-text regex match against prose, not a
        structured key: this can name the FILE but not confirm the string is a
        live credential rather than an example/placeholder, so it is listed
        with that caveat rather than silently dropped — an unconfirmed
        suspicion must never read as "nothing here".
      * C015 (checks/_config.py check_secrets_at_rest_home) — NOT covered.
        It sweeps arbitrary files across the whole home (env files, workspace
        content, anything user-owned) — a materially broader, already-capped
        surface. Folding a whole-home sweep into the rotation list is a
        separate design call, not a fix to the enumeration bug closed here.
      * checks/_mcp.py's per-MCP-server env/header SECRET_KEY_RE scan —
        ALREADY COVERED, transitively. MCP server env/headers live under
        ``mcp.servers.<name>.{env,headers}`` inside the same ``ctx.config``
        dict, so ``_secret_paths(ctx.config)`` above already walks into them;
        no separate union needed.
      * checks/_lifecycle.py's exec-passEnv SECRET_KEY_RE scan — NOT
        applicable, different risk class. It flags secret-SHAPED ENV VAR
        *NAMES* declared for passthrough to exec tooling (e.g.
        ``tools.exec.passEnv: ["AWS_SECRET_ACCESS_KEY"]``); the credential
        VALUE lives in the OS environment, not in this config, so there is no
        config path here to rotate against — same reasoning B41 already
        applies to `_gateway_env_credential`.
    """
    seen: dict[str, None] = {}  # insertion-ordered de-dup, no external dep

    b41 = next((f for f in findings if f.id == "B41"), None)
    if b41 is not None and b41.evidence:
        for line in b41.evidence:
            seen.setdefault(line, None)

    for path in _secret_paths(ctx.config if isinstance(ctx.config, dict) else {}):
        seen.setdefault(f"config: {path}", None)

    for fname, text in (ctx.bootstrap or {}).items():
        if _pattern_hits_real_secret(SECRET_PATTERNS, text):
            seen.setdefault(
                f"bootstrap: {fname} (possible secret-like string, unconfirmed)",
                None,
            )

    return list(seen)


def build_incident(ctx, findings, score, *, when: str | None = None,
                   events: str | Path | None = None) -> dict:
    """Build the evidence-pack dict from an already-audited Context. Pure aside
    from the trajectory-file/event-log reads reused above — no writes, no network.

    *events* is the monitor journal to harvest, i.e. the CLI's ``--events``. B-277:
    this used to be hardcoded to ``DEFAULT_EVENTS``, so ``--incident --events X``
    silently reported the DEFAULT journal's contents instead of X's. On a host that
    monitors several agents that is worse than an empty list: the pack's ``sbom``
    described the agent named by ``--home`` while ``monitor_events`` described a
    different one, and nothing in the pack disclosed the mismatch. ``None`` keeps
    the documented default so library callers are unaffected.
    """
    from . import __version__  # noqa: PLC0415 (avoid import-order coupling)
    from .report import _finding_to_dict  # noqa: PLC0415

    if when is None:
        when = datetime.now().isoformat(timespec="seconds")
    events_path = DEFAULT_EVENTS if events is None else events
    # B-815: computed once, up front, same as events_path above -- consumed only by
    # "trajectory_corroboration" below.
    corro = _trajectorystore.corroborate(ctx.home) if isinstance(ctx.home, Path) else None

    return {
        # C-241: a machine-readable tool identifier (matches the CLI binary/package
        # name), deliberately lowercase and distinct from brand.WORDMARK's display
        # name ("ClawSecCheck", used e.g. by sarif.py's driver.name) — pinned exactly
        # by tests/test_incident.py; do not "fix" the casing to match the display name.
        "tool": "clawseccheck",
        "version": __version__,
        "purpose": (
            "Preservation aid for step 3/6 of the incident-response playbook — a local, "
            "read-only evidence bundle. It gathers pointers and hashes; it does NOT "
            "rotate, delete, or remediate anything."
        ),
        "generated_at": when,
        # C-423: an evidence pack must never imply a verdict the run was not entitled to
        # make. "graded" is always present; when False (ScoreResult.graded — see its own
        # docstring, Rule 1), "score"/"grade" are explicitly null rather than dropped, so
        # a consumer reading pack["score"]["score"] gets None, never a KeyError. "layer"
        # and "status" here are the same raw ids `layers.LAYER_ORDER`/`LAYER_STATUSES`
        # define -- structured data for a machine reader, not prose, so this pack never
        # grows its own copy of `layers.describe_layer`'s wording. `not_checked` and
        # `missing_layers` are passed through verbatim from the ScoreResult that already
        # computed them (scoring.compute -> layers.LayerLedger) -- always present, empty
        # when there is nothing to say, recording what the run could not see.
        #
        # `missing_layers` is a list of NAMED objects, not positional pairs, and matches
        # `--json`'s key for key: a reader who has learned one machine surface must not
        # have to learn a second shape for the same fact. A bare [layer, status] array
        # would also silently survive an argument swap; {"layer":…, "status":…} cannot.
        "score": {
            "score": score.score if score.graded else None,
            "grade": score.grade if score.graded else None,
            "graded": score.graded,
            "not_checked": list(score.not_checked),
            "missing_layers": [
                {"layer": layer, "status": status}
                for layer, status in score.missing_layers
            ],
        },
        "findings": [_finding_to_dict(f) for f in findings],
        "sbom": build_sbom(ctx),
        "trajectory_hashes": _trajectory_hash_entries(
            ctx.home, max_files=limits_for(ctx).traj_max_files),
        # B-815: always present, null when there is nothing to say (the same idiom
        # "score"/"grade" above already use for an ungraded run) -- names WHICH
        # container the trajectory evidence actually lives in (trajectorystore.py's
        # STATUS_LIVE/STATUS_LOCATOR_STALE/STATUS_NO_RESIDUE) so a responder reading an
        # empty `trajectory_hashes` on a SQLite-era install is told why, rather than
        # silently concluding there is nothing to preserve.
        "trajectory_corroboration": (
            {"status": corro.status, "evidence": list(corro.evidence)}
            if corro is not None
            else None
        ),
        "credential_rotation_list": _credential_rotation_list(ctx, findings),
        "monitor_events": load_events(events_path),
        # B-277: provenance. An evidence pack that quotes a journal must say WHICH
        # journal, or a reader cannot tell an empty history from the wrong host's
        # history. Recorded verbatim (an operator-supplied local path, never a
        # secret) and always present, even when the read came up empty.
        "monitor_events_source": str(events_path),
    }


def render_incident(ctx, findings, score, *, when: str | None = None,
                    events: str | Path | None = None) -> str:
    """Return the evidence pack as a stably-ordered JSON string."""
    payload = build_incident(ctx, findings, score, when=when, events=events)
    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)
