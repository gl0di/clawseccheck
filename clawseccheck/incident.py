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
from datetime import datetime
from pathlib import Path

from . import trajectory as _trajectory
from .checks import SECRET_PATTERNS, _pattern_hits_real_secret, _secret_paths
from .monitor import DEFAULT_EVENTS, load_events
from .sbom import build_sbom
from .scanbudget import limits_for

INCIDENT_VERSION = 1

_MAX_TRAJECTORY_BYTES = 8_000_000  # mirrors trajectory.py's own per-file scan cap


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
    """
    if not isinstance(home, Path):
        return []
    entries: list[dict] = []
    kwargs = {} if max_files is None else {"max_files": max_files}
    for path in _trajectory.find_trajectory_files(home, **kwargs):
        try:
            raw = path.read_bytes()
            rel = path.relative_to(home)
        except (OSError, ValueError):
            continue
        truncated = len(raw) > _MAX_TRAJECTORY_BYTES
        data = raw[:_MAX_TRAJECTORY_BYTES] if truncated else raw
        entries.append({
            "path": str(rel),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "truncated": truncated,
        })
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
