"""Post-hoc trajectory incident analysis (C-158, B85 incident-readiness).

Answers, after the fact: did an installed skill's dangerous instructions actually get
ACTED ON at runtime, or were they merely present in a static file? It correlates the
concrete high-signal indicators a static skill scan already surfaces — credential-shaped
paths, exfil hosts, and secret-named file paths a skill's text NAMES — against what the
agent actually did, read from OpenClaw's trajectory sidecar `tool.call` records
(`agents/*/sessions/*.trajectory.jsonl`, schema grounded in recon §9.1).

§8 privacy boundary (Dave-ratified for C-158): the base `trajectory.read_proven_tools`
never reads `data.arguments`. This analyzer DOES read `data.arguments`, but ONLY in memory
and ONLY to test membership of an already-known indicator (a path/host the skill named,
which the user already has from the skill scan). The report emits only the matched known
indicator + tool verb + count — it NEVER echoes the raw arguments, so no new secret value
is ever surfaced. The emitted indicator is additionally routed through `logsafe.redact`.
Stdlib-only, read-only, no network.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .checks import _CRED_RE, _EXFIL_RE
from .logsafe import redact
from .trajectory import (
    _MAX_BYTES_PER_FILE,
    _SCHEMA_VERSION,
    _TRACE_SCHEMA,
    find_trajectory_files,
)

# A file path a skill names that carries a secret-ish token in the path itself
# (fake_secrets/db_token.txt, ~/.config/app/api_key). High-signal + low-FP: a path with
# 'secret'/'token'/'credential'/'password'/'api[_-]key' in it, that a skill NAMES and the
# agent then touches, is a strong "acted on" signal for incident response.
_SECRET_PATH_RE = re.compile(
    r"[\w./~+-]*(?:secret|token|credential|password|api[_-]?key)[\w./~+-]*", re.I
)
_MIN_INDICATOR_LEN = 6  # ignore trivially-short tokens that would match anything


def skill_indicators(installed_skills: dict | None) -> dict[str, str]:
    """Map each concrete indicator an installed skill NAMES -> the skill that named it.

    Indicators: credential-shaped paths (_CRED_RE), exfil hosts (_EXFIL_RE), and
    secret-named file paths (_SECRET_PATH_RE). These are already visible in the skill's own
    text (nothing secret is invented), and are the tokens whose appearance in a runtime
    tool.call argument is strong evidence the skill's instruction was acted on.
    """
    out: dict[str, str] = {}
    for name, text in (installed_skills or {}).items():
        if not isinstance(text, str):
            continue
        for rx in (_CRED_RE, _EXFIL_RE, _SECRET_PATH_RE):
            for m in rx.finditer(text):
                tok = m.group(0).strip().strip(".,;:\"'`)(")
                if len(tok) >= _MIN_INDICATOR_LEN and tok not in out:
                    out[tok] = str(name)
    return out


def _iter_tool_calls(path: Path, *, max_bytes: int = _MAX_BYTES_PER_FILE):
    """Yield (name, arguments_blob) for grounded tool.call records in *path*.

    arguments_blob is an in-memory json.dumps of data.arguments used ONLY for membership
    testing — it is never returned to a caller that renders it. Yields ("__unknown__", "")
    once if a line carries an unrecognised schema version, so the caller can mark UNKNOWN.
    """
    try:
        read = 0
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                read += len(line)
                if read > max_bytes:
                    break
                if '"tool.call"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict) or rec.get("traceSchema") != _TRACE_SCHEMA:
                    continue
                if rec.get("schemaVersion") != _SCHEMA_VERSION:
                    yield ("__unknown__", "")
                    continue
                if rec.get("type") != "tool.call":
                    continue
                data = rec.get("data")
                if not isinstance(data, dict):
                    continue
                name = data.get("name")
                if not (isinstance(name, str) and name.strip()):
                    continue
                args = data.get("arguments")
                blob = json.dumps(args, ensure_ascii=False) if args is not None else ""
                yield (name.strip(), blob)
    except OSError:
        return


def analyze(ctx, *, explicit_path: str | None = None) -> dict:
    """Correlate installed-skill indicators against trajectory tool.call arguments.

    Returns a result dict: present/files_scanned/unknown_version/tool_calls, the set of
    observed tool verbs, and `hits` — for each (indicator, verb) whose known indicator
    appeared in a tool.call's arguments, the redacted indicator + source skill + count.
    """
    indicators = skill_indicators(getattr(ctx, "installed_skills", None))
    result = {
        "present": False,
        "files_scanned": 0,
        "unknown_version": False,
        "tool_calls": 0,
        "indicator_count": len(indicators),
        "verbs": set(),
        "hits": [],
    }

    if explicit_path:
        p = Path(explicit_path).expanduser()
        files = [p] if p.is_file() else []
    else:
        home = getattr(ctx, "home", None)
        files = find_trajectory_files(home) if isinstance(home, Path) else []
    if not files:
        return result
    result["present"] = True

    # key: (indicator, verb) -> count; keeps the report compact + deterministic
    hit_counts: dict[tuple[str, str], int] = {}
    for path in files:
        result["files_scanned"] += 1
        for name, blob in _iter_tool_calls(path):
            if name == "__unknown__":
                result["unknown_version"] = True
                continue
            result["tool_calls"] += 1
            result["verbs"].add(name)
            if not blob:
                continue
            for tok in indicators:
                if tok in blob:  # membership only — blob (raw args) is never emitted
                    hit_counts[(tok, name)] = hit_counts.get((tok, name), 0) + 1

    for (tok, verb), count in sorted(hit_counts.items()):
        result["hits"].append({
            "indicator": redact(tok),
            "skill": indicators.get(tok, "?"),
            "verb": verb,
            "count": count,
        })
    return result


def render_trajectory_analysis(ctx, *, explicit_path: str | None = None, ascii_only: bool = False) -> str:
    """Human-readable, §8-safe incident report for --analyze-trajectory."""
    r = analyze(ctx, explicit_path=explicit_path)
    warn = "[!]" if ascii_only else "⚠"
    ok = "[ok]" if ascii_only else "✓"
    q = "[?]" if ascii_only else "?"
    lines = ["Trajectory incident analysis (post-hoc, read-only)"]

    if not r["present"]:
        lines.append(f"  {q} No trajectory sidecars found "
                     "(agents/*/sessions/*.trajectory.jsonl). Nothing to analyze — run on a "
                     "host where an OpenClaw agent has produced session trajectories.")
        return "\n".join(lines)

    lines.append(
        f"  scanned {r['files_scanned']} trajectory file(s), {r['tool_calls']} tool.call "
        f"record(s); {r['indicator_count']} indicator(s) from installed skills."
    )
    if r["unknown_version"]:
        lines.append(f"  {q} Some records used an unrecognised trajectory schema version — "
                     "results are INCOMPLETE (treat as UNKNOWN, not authoritative).")

    if r["hits"]:
        lines.append(f"  {warn} INCIDENT SIGNAL — an installed skill's indicator appeared in "
                     "runtime tool-call arguments (instruction likely ACTED ON):")
        for h in r["hits"]:
            lines.append(
                f"      - skill '{h['skill']}' indicator '{h['indicator']}' seen in "
                f"{h['count']}× '{h['verb']}' tool call(s)"
            )
        lines.append("  Review those tool calls in the trajectory manually and rotate any "
                     "credential the referenced path/host could expose.")
    elif r["indicator_count"]:
        lines.append(f"  {ok} Installed skills name indicators, but NONE appeared in any "
                     "tool.call arguments — instructions present, not observed acted-on.")
    else:
        lines.append(f"  {ok} No credential/exfil/secret-path indicators found in installed "
                     "skills to correlate.")
    return "\n".join(lines)
