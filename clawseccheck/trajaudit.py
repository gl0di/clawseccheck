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

B-299 widens the INDICATOR SOURCE without widening that boundary:

* Part B (bootstrap/memory-derived indicators) stays exactly inside it — the token is
  still one the user's own file NAMES, just a bootstrap/memory file instead of a skill,
  so it is still "already known to the user" in the same sense. Only the attribution
  changes (source file instead of source skill).
* Part A (the credential-path discriminator) is the one place a token is derived from the
  arguments rather than from a file the user wrote, so it does NOT emit the matched text.
  `_CRED_RE` contains alternatives with free `[^\n]{0,60}` spans (the browser-Cookies and
  Electrum/Exodus arms), and echoing such a match would put up to 60 bytes of raw argument
  content into the report — a §8 violation. Instead the match is mapped to a CLOSED
  vocabulary of family labels (`_CRED_FAMILY_LABELS`) and only that constant is emitted,
  so nothing derived from the argument bytes can ever reach output. See
  `_cred_family` and its test-pinned invariant.

B-299 HONEST LABELLING — this NARROWS two gaps, it does not close either:

* Both new signals are ADVISORY OBSERVATIONS in this unscored, opt-in renderer. Neither
  emits a Finding, neither has a confidence tier, and neither can move the A-F grade.
* Part A does NOT make behavioral T1 work. T1 still cannot fire on a core-tools agent
  (`_T_SENSITIVE_HINTS` matches no OpenClaw core verb — see the T1 note in catalog.py),
  and `_T_SENSITIVE_HINTS` was deliberately NOT widened to fix that: restoring the
  filesystem terms was retried and rejected because it reintroduces the C-170 false
  positive (`web_search -> list_files -> slack_send`). The credential-path signal lives
  here, in a renderer that may read arguments, precisely because T1 may not.
* Part A reports that a credential store was TOUCHED. It does not show the data left the
  host, and a legitimate owner request ("check my aws profile", a `kubectl` or `npm
  publish` run) produces the same observation. The wording says so.
* Part B correlates only what the vetted narrow vocabulary can name — credential-shaped
  paths, '/'-bearing secret paths, and KNOWN drop hosts. A memory plant naming an
  arbitrary attacker host the shared list does not know is still not correlated here.
* `behavioral.py`'s session-scoped event grouping is deliberately UNCHANGED (it is the
  C-170 fix; loosening it manufactures cross-session sequences out of a per-session
  counter). The cross-session reach comes from `analyze` already globbing every sidecar,
  which it did before this change.
"""
from __future__ import annotations

import json
from pathlib import Path

from .checks import _CRED_RE, _EXFIL_RE, _SECRET_PATH_RE, correlation_indicators
from .logsafe import redact
from .trajectory import (
    _MAX_BYTES_PER_FILE,
    _SCHEMA_VERSION,
    _TRACE_SCHEMA,
    find_trajectory_files,
)

# _SECRET_PATH_RE moved to checks/_shared.py (F-124/E-044 layer-fix): logscan.py (a
# Layer-1 leaf, same shelf as this module's dependencies) needs it too and must not
# import a Layer-2 topic module, so it now lives in the shared leaf and is imported
# above via the checks aggregator, same as _CRED_RE/_EXFIL_RE already were.
_MIN_INDICATOR_LEN = 6  # ignore trivially-short tokens that would match anything

# B-299 Part A — the CLOSED vocabulary the credential-path discriminator may emit.
# Every entry is a literal anchor that appears in one of `_CRED_RE`'s alternatives
# (checks/_shared.py), mapped to a stable family name. `_cred_family` emits ONE of these
# constants and nothing else, which is what keeps Part A inside the §8 boundary described
# in the module docstring: the report never carries a byte that came from the arguments.
# Ordered most-specific-first so a match is attributed to the narrower family.
_CRED_FAMILY_LABELS: tuple[tuple[str, str], ...] = (
    (".aws/credentials", "aws-credentials-file"),
    (".ssh/id_", "ssh-private-key"),
    ("login.keychain", "macos-keychain"),
    ("find-generic-password", "macos-keychain"),
    (".ethereum/keystore", "crypto-wallet"),
    (".config/solana", "crypto-wallet"),
    ("keystore.json", "crypto-wallet"),
    ("wallet.dat", "crypto-wallet"),
    ("metamask", "crypto-wallet"),
    ("electrum", "crypto-wallet"),
    ("exodus", "crypto-wallet"),
    (".docker/config.json", "docker-registry-auth"),
    (".kube/config", "kubeconfig"),
    (".config/gcloud", "gcloud-credentials"),
    (".npmrc", "package-registry-token"),
    (".pypirc", "package-registry-token"),
    (".netrc", "netrc-credentials"),
    ("cookies", "browser-cookie-store"),
)
# Emitted when a future `_CRED_RE` alternative matches but carries none of the anchors
# above. Unreachable with today's regex (every alternative has a literal anchor) and kept
# deliberately: it guarantees the "never emit matched text" invariant survives a regex
# edit made by someone who never reads this file.
_CRED_FAMILY_FALLBACK = "credential-store"
# NO "…and then an egress verb" GATE, deliberately. The obvious way to tighten Part A is
# to require an egress-classified verb later in the same session. Measured on a real host
# (60 scanned sidecars, 976 tool.call records) that gate is a no-op dressed as precision:
# `bash` classifies EGRESS/EXEC via attest.classify_verb, and `bash` is most of what a real
# agent does, so essentially every session satisfies it. It would add sequencing machinery,
# suppress nothing, and let the report imply a corroboration it never actually performed.
# The narrowness comes from `_CRED_RE` itself instead: on that same real corpus it matched
# 0 of 976 records, while `_SECRET_PATH_RE` matched 4 and `_EXFIL_RE` matched 35 (bare
# `curl`/`nc`/`POST`/`base64` tokens) — which is exactly why Part A uses `_CRED_RE` ALONE
# and not the other two regexes `_extract_indicators` draws on.
# KNOWN LOOSE ARM, deliberately kept (adversarial pass, this task). `_CRED_RE`'s
# browser-Cookies alternative is `\bCookies\b[^\n]{0,60}(?:Chrome|Firefox|…)`, so an
# argument that merely pairs the word "cookies" with a browser name inside 60 characters
# — e.g. a `web_fetch` of `https://example.com/cookies-policy` on a page whose blob also
# says "chrome" — yields a `browser-cookie-store` OBSERVATION. Not fixed here, on purpose:
#   * `_CRED_RE` is shared (checks/_shared.py) and also drives B13/B160/logscan, so
#     narrowing it for this renderer's benefit would silently move FAIL-capable checks.
#   * Dropping the cookie family from Part A instead would trade a benign-URL observation
#     for blindness to browser-cookie theft, a common real agent-exfil shape.
# It never becomes a Finding, so it costs a line of report text, not a false FAIL — and
# the observation wording already tells the reader to confirm the access was intended.
# Measured on the real host: 0 `_CRED_RE` matches across 976 tool.call records, so this
# arm is not firing in practice. Test-pinned so nobody "fixes" it via the shared regex.
# Bound the per-record scan so a single pathological arguments blob cannot dominate the
# run. Fails toward UNDER-reporting (a family past the cap is missed), never toward a
# fabricated hit — the safe direction per Golden Rule #5.
_MAX_CRED_MATCHES_PER_BLOB = 256


def _cred_family(match_text: str) -> str:
    """Map one `_CRED_RE` match to a closed-vocabulary family label (§8, B-299 Part A).

    Returns a member of `_CRED_FAMILY_LABELS`' second column or `_CRED_FAMILY_FALLBACK` —
    NEVER any substring of *match_text*. `tests/test_b299_trajaudit_widening.py` pins that
    invariant, including for the `[^\\n]{0,60}` browser-Cookies arm whose match can carry
    arbitrary argument bytes.
    """
    low = match_text.lower()
    for anchor, label in _CRED_FAMILY_LABELS:
        if anchor in low:
            return label
    return _CRED_FAMILY_FALLBACK


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
                if len(tok) < _MIN_INDICATOR_LEN or tok in out:
                    continue
                # B-157: a _SECRET_PATH_RE hit with no path separator at all is a bare
                # English word ("secret", "password", "tokens" as prose), not a path a
                # skill named — drop it. _CRED_RE / _EXFIL_RE tokens are always
                # path/host-shaped by construction, so this only constrains
                # _SECRET_PATH_RE.
                if rx is _SECRET_PATH_RE and "/" not in tok and not tok.startswith("~"):
                    continue
                out[tok] = str(name)
    return out


def bootstrap_indicators(
    bootstrap: dict | None, *, exclude_sources: dict | None = None
) -> dict[str, str]:
    """Map each indicator a bootstrap/memory file NAMES -> the file that named it (B-299 B).

    New source, NOT the same vocabulary as `skill_indicators`. `ctx.bootstrap` is what
    `collector.py` reads from the agent's own bootstrap markdown, INCLUDING MEMORY.md.
    Closes the source gap behind the cross-session slow-burn shape: B65 already WARNs
    statically on a poisoned MEMORY.md that names a drop host, but that host never became
    a correlation indicator, so a later `tool.call` reaching it — in any session, since
    `analyze` already globs every sidecar — was never linked back to the plant.

    WHY `correlation_indicators` AND NOT `skill_indicators` (C-135 finding, this task).
    The obvious implementation — run the existing skill extraction over `ctx.bootstrap` —
    was written, then rejected on an adversarial pass. `skill_indicators` draws on the
    broad `_EXFIL_RE`, whose 6-character-plus verbs (`base64`, `netcat`, `fetch(`,
    `pastebin`, `requests.post`) survive the length filter. A perfectly ordinary TOOLS.md
    that says "base64-encode the attachment" would therefore make `base64` an indicator,
    and every `bash` call containing `base64` would correlate against it — an observation
    manufactured entirely out of the user's own operating manual. `_shared.py`'s
    `correlation_indicators` (C-221) already exists for exactly this job and already
    excludes those verbs, keeping only credential-shaped paths, '/'-bearing secret paths,
    and KNOWN drop-point hosts. Reusing it means this source cannot drift from the vetted
    one. (The pre-existing skill path keeps its broader vocabulary — narrowing THAT is a
    separate change with its own regression surface, and is not in scope here.)

    *exclude_sources* is the installed-skill map: tokens a skill already claimed are
    dropped, so one token is attributed to exactly one source and the pre-existing
    skill-correlation output is unchanged. Both sides go through `correlation_indicators`
    so the normalized keys are comparable without re-implementing its normalization.

    Keys are normalized (lowercased, tilde-stripped) by `correlation_indicators`, so
    callers must membership-test them against a LOWERCASED arguments blob.

    HONEST LABELLING: a bootstrap file legitimately naming a drop-shaped host the agent
    then legitimately calls still produces a hit here. That is why these are rendered as
    ADVISORY OBSERVATIONS naming their source file, never escalated — the B164/B180
    discipline.
    """
    out = correlation_indicators(bootstrap)
    if exclude_sources:
        for tok in correlation_indicators(exclude_sources):
            out.pop(tok, None)
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
                    # C-180: surface the cap hit the same way an unrecognised
                    # schema version already is — an unscanned remainder past
                    # this offset must not let a clean result read as complete.
                    yield ("__truncated__", "")
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
    observed tool verbs, and three independent observation lists:

    * `hits` — skill-derived correlation (the original C-158 signal), unchanged.
    * `bootstrap_hits` — B-299 Part B: the same correlation for an indicator named by a
      bootstrap/memory file instead of a skill, carrying its source file.
    * `cred_arg_hits` — B-299 Part A: a `_CRED_RE` credential-store family named directly
      in a tool.call's arguments, with NO indicator source required. Reported as an ACCESS
      observation, never as proof of exfiltration.

    All three are advisory. This renderer is unscored and opt-in (`--analyze-trajectory`),
    so nothing here can emit a Finding or move the A-F grade.
    """
    indicators = skill_indicators(getattr(ctx, "installed_skills", None))
    boot_indicators = bootstrap_indicators(
        getattr(ctx, "bootstrap", None),
        exclude_sources=getattr(ctx, "installed_skills", None),
    )
    result = {
        "present": False,
        "files_scanned": 0,
        "unknown_version": False,
        "truncated": False,
        "files_total": 0,
        "files_capped": False,
        "tool_calls": 0,
        "indicator_count": len(indicators),
        "bootstrap_indicator_count": len(boot_indicators),
        "verbs": set(),
        "hits": [],
        "bootstrap_hits": [],
        "cred_arg_hits": [],
    }

    if explicit_path:
        p = Path(explicit_path).expanduser()
        files = [p] if p.is_file() else []
        result["files_total"] = len(files)
    else:
        home = getattr(ctx, "home", None)
        stats: dict = {}
        files = find_trajectory_files(home, stats=stats) if isinstance(home, Path) else []
        result["files_total"] = stats.get("files_total", 0)
        result["files_capped"] = stats.get("files_capped", False)
    if not files:
        return result
    result["present"] = True

    # key: (indicator, verb) -> count; keeps the report compact + deterministic
    hit_counts: dict[tuple[str, str], int] = {}
    boot_counts: dict[tuple[str, str], int] = {}
    # key: (family label, verb) -> count of tool CALLS naming that family (B-299 Part A).
    # Counted once per record, not once per regex match, so one command mentioning the
    # same store five times is one access observation, not five.
    cred_counts: dict[tuple[str, str], int] = {}
    for path in files:
        result["files_scanned"] += 1
        for name, blob in _iter_tool_calls(path):
            if name == "__unknown__":
                result["unknown_version"] = True
                continue
            if name == "__truncated__":
                result["truncated"] = True
                continue
            result["tool_calls"] += 1
            result["verbs"].add(name)
            if not blob:
                continue
            for tok in indicators:
                if tok in blob:  # membership only — blob (raw args) is never emitted
                    hit_counts[(tok, name)] = hit_counts.get((tok, name), 0) + 1
            # `correlation_indicators` normalizes its keys (lowercased, tilde-stripped),
            # so this membership test must run against a lowercased blob — otherwise a
            # host named in mixed case in MEMORY.md silently never correlates.
            low_blob = blob.lower() if boot_indicators else ""
            for tok in boot_indicators:
                if tok in low_blob:
                    boot_counts[(tok, name)] = boot_counts.get((tok, name), 0) + 1
            fams: set[str] = set()
            for i, m in enumerate(_CRED_RE.finditer(blob)):
                if i >= _MAX_CRED_MATCHES_PER_BLOB:
                    break
                fams.add(_cred_family(m.group(0)))  # label only — never the match text
            for fam in fams:
                cred_counts[(fam, name)] = cred_counts.get((fam, name), 0) + 1

    for (tok, verb), count in sorted(hit_counts.items()):
        result["hits"].append({
            "indicator": redact(tok),
            "skill": indicators.get(tok, "?"),
            "verb": verb,
            "count": count,
        })
    for (tok, verb), count in sorted(boot_counts.items()):
        result["bootstrap_hits"].append({
            "indicator": redact(tok),
            "source": boot_indicators.get(tok, "?"),
            "verb": verb,
            "count": count,
        })
    for (fam, verb), count in sorted(cred_counts.items()):
        result["cred_arg_hits"].append({"family": fam, "verb": verb, "count": count})
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
    if r["bootstrap_indicator_count"]:
        lines.append(
            f"  plus {r['bootstrap_indicator_count']} indicator(s) named by the agent's "
            "own bootstrap/memory files."
        )
    if r["unknown_version"]:
        lines.append(f"  {q} Some records used an unrecognised trajectory schema version — "
                     "results are INCOMPLETE (treat as UNKNOWN, not authoritative).")
    if r["truncated"]:
        lines.append(f"  {q} A trajectory file exceeded the per-file scan cap — the "
                     "unscanned remainder was never analyzed. Results are INCOMPLETE "
                     "(treat as UNKNOWN, not authoritative).")
    if r["files_capped"]:
        # B-245: mirrors the truncated-byte caveat above (C-180), but for the per-FILE
        # cap, which previously dropped the oldest sessions with no disclosure at all.
        lines.append(
            f"  {q} Scanned the {r['files_scanned']} most recent of {r['files_total']} "
            "trajectory file(s) — the oldest session(s) were not analyzed. Results are "
            "INCOMPLETE (treat as UNKNOWN, not authoritative)."
        )

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

    if r["bootstrap_hits"]:
        lines.append(f"  {warn} OBSERVATION — a path/host named by the agent's own "
                     "bootstrap/memory files appeared in runtime tool-call arguments:")
        for h in r["bootstrap_hits"]:
            lines.append(
                f"      - file '{h['source']}' indicator '{h['indicator']}' seen in "
                f"{h['count']}× '{h['verb']}' tool call(s)"
            )
        lines.append("  This is ADVISORY, not a finding: a bootstrap file may legitimately "
                     "name a host the agent then legitimately calls. It matters when the "
                     "file itself is suspect — check whether B65/B180 flagged that file.")

    if r["cred_arg_hits"]:
        lines.append(f"  {warn} OBSERVATION — tool-call arguments named a well-known "
                     "credential store:")
        for h in r["cred_arg_hits"]:
            lines.append(
                f"      - {h['family']} named in {h['count']}× '{h['verb']}' tool call(s)"
            )
        lines.append("  This records ACCESS, not exfiltration, and no installed skill had "
                     "to name the path for it to be seen. Confirm the access was asked "
                     "for; if not, rotate what that store holds.")
    return "\n".join(lines)
