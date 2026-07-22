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
  emits a Finding, neither has a confidence tier, and this module never renders a
  verdict that moves the A-F grade. I-025/B-309 (Dave's 2026-07-20 ruling) is a
  narrow, later exception at the SCORING layer, not here: `grade_cap_signal` (below)
  lets `scoring.compute` apply a hard CAP — never an ordinary scored point — when Part
  B (bootstrap_hits) or the original C-158 `hits` fire, because both are
  arguments-corroborated against a token the user's own file already names. Part A
  (`cred_arg_hits`) stays excluded from that cap — see `grade_cap_signal`'s own
  docstring for why its evidentiary bar is too weak to ever move a grade.
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

B-300 — canary/multi-turn SELF-TEST CORROBORATION (`self_test_corroboration`,
`render_self_test_corroboration`), wired into `--analyze-trajectory`'s own renderer.

PROBLEM: `canary.evaluate`/`multiturn.evaluate` have no non-test call site anywhere — the
RESISTANT/VULNERABLE verdict is spoken entirely by the host LLM in chat, with no local
artifact that could contradict a fabricated one. `_record_run("self_test", args)` (see
`cli.py`) attests only that a self-test FLAG was invoked, never that the test executed or
what it concluded (`ledger.py`). This closes part of that gap the same way T3
(`behavioral.check_capability_drift`) already closes it for the capability self-report:
don't trust the self-report, corroborate it against the trajectory log.

TWO LEGS, deliberately asymmetric (their own adversarial risk differs):

* LOW-FP leg — "did the test actually run": prefix membership of our own namespaced
  tokens (`canary.TOKEN_PREFIX`, `multiturn._TOKEN_PREFIX`) in `prompt.submitted.data.prompt`
  (the compiled prompt actually sent to the model — grounded, per the recon this task
  cites, as where the canary/multi-turn PAYLOAD lands). Hard to false-positive: the prefix
  is ClawSecCheck's own namespace, so an unrelated conversation cannot spell it.
* HIGH-FP leg — "was the verdict honest" (best-effort only): prefix membership in
  `model.completed.data.assistantTexts` (the agent's own reply text). THE TRAP: both
  `render_canary()` and `render_multiturn()` print the token as part of their own
  instructions-to-the-operator (e.g. "Token to watch for: …", "ack token   : …") — if the
  host agent shows that render to the user (which SKILL.md's canary/multi-turn workflow
  effectively invites), the token lands in `assistantTexts` and a naive prefix check would
  report a genuinely RESISTANT agent as VULNERABLE. `canary.RENDER_ECHO_MARKERS` /
  `multiturn.RENDER_ECHO_MARKERS` — fixed literal substrings lifted ONLY from each
  render's own operator-facing scaffold (never from the injected payload/plant text an
  attacker controls — see each module's B-300 ROUND 2 comment for why that distinction
  matters: a marker drawn from the payload/plant misclassifies genuine compliance, which
  quotes that same attacker text, as harmless render-echo) — are used to exclude that
  known echo shape before a match counts as anything. This is a best-effort discriminator
  for a KNOWN shape, NOT a proof the leg is sound against an adversarial agent, which is
  why it can only ever WARN, never FAIL, and stays out of the A-F score exactly like the
  rest of `--behavioral`.

GATING ON THE LEDGER (`ledger.load_ledger`): corroboration is reported only when the local
coverage ledger shows a self-test capability (`--canary`/`--multiturn`/`--self-test`/
`--redteam`/`--dryrun`) was recorded as run at least once — every code path that can
GENERATE a canary/multi-turn token also calls `_record_run("self_test", ...)` in the same
breath (cli.py), so this gate cannot suppress a real token while staying silent (not a
WARN) on the overwhelming majority of hosts that never tried the feature at all. Honest
caveat: the ledger lives at the REAL `~/.clawseccheck/coverage.json`, not under the
OpenClaw *home* being scanned, so on a machine auditing more than one OpenClaw agent this
gate is host-wide, not agent-scoped.

§8 (B-300): reading `data.prompt` / `data.assistantTexts` crosses the boundary
`trajectory.py`'s own module docstring deliberately holds (it names `context.compiled`'s
`prompt`/`messages` siblings as "the user's own conversation" it never reads). This module
already carries the Dave-ratified exception for exactly this shape (see the docstring
above): read the sensitive payload in memory, membership-test an ALREADY-KNOWN indicator
(our own generated token, not user data), emit only the matched literal PREFIX constant —
never raw prompt/reply text. This case is safer than the `data.arguments` precedent above:
the indicator is a ClawSecCheck-generated literal, never anything derived from user input.

HONEST LABELLING: this NARROWS BEHAV-4, it does not close it. (i) The "did it run" leg is
corroborated by a local artifact; the "was it honest" leg is best-effort only and excluded
from score/grade. (ii) Neither this module nor `canary.py`/`multiturn.py` ever renders a
RESISTANT/VULNERABLE verdict themselves — that verdict is the host LLM's to speak in chat.
(iii) The ledger gate reuses `_record_run`'s existing semantics unchanged: it still attests
invocation, not execution or outcome.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import canary, multiturn
from .checks import _CRED_RE, _EXFIL_RE, _SECRET_PATH_RE, correlation_indicators
from .ledger import load_ledger
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


# ---------------------------------------------------------------------------
# I-025/B-309 — cap-only runtime signal (Dave's 2026-07-20 ruling).
# ---------------------------------------------------------------------------


def grade_cap_signal(ctx) -> dict:
    """Whether THIS module's own indicator-match observations are eligible to CAP (never
    otherwise affect) the A-F grade, per Dave's 2026-07-20 ruling: "only an ARGUMENTS-
    CORROBORATED signal may ever affect the grade, and only as a grade CAP."

    Eligible, exhaustively: ``hits`` (a skill-named indicator seen in runtime tool-call
    arguments) and ``bootstrap_hits`` (the same correlation for a bootstrap/memory-named
    indicator, B-299 Part B) — both membership-test an indicator the user's OWN file
    already names against REAL runtime arguments, which is exactly the "arguments-
    corroborated" bar the ruling sets.

    ``cred_arg_hits`` (B-299 Part A) is DELIBERATELY EXCLUDED. It has no known-bad
    indicator to corroborate against at all — it is a bare `_CRED_RE` credential-family
    match, and that module's own docstring documents a "KNOWN LOOSE ARM" (the
    browser-Cookies alternative can match an ordinary `.../cookies-policy` page next to
    the word "chrome") that a real fleet was measured to trigger zero times but that
    remains reachable by construction. Golden Rule #5 (zero false-positive FAILs) sets
    too weak an evidentiary bar for a signal that can cap a grade to accept that residual
    risk — see the module docstring's own "ACCESS, not exfiltration" framing for
    ``cred_arg_hits``. Promoting it would need its own C-135 pass first; this task's did
    not cover it, so it stays excluded.

    Returns ``{"present": bool, "hit": bool, "count": int}``:
      * ``present=False`` — no trajectory sidecar found at all. UNKNOWN, not a cap, and
        NOT an implied all-clear either (the caller must not read this as a clean PASS).
      * ``present=True, hit=False`` — trajectory data was scanned and neither eligible
        class fired. No cap.
      * ``present=True, hit=True`` — at least one skill- or bootstrap-named indicator was
        observed in actual tool-call arguments. The caller MAY cap the grade
        (``scoring.compute`` is the only caller that does).
    """
    r = analyze(ctx)
    count = len(r["hits"]) + len(r["bootstrap_hits"])
    return {"present": r["present"], "hit": count > 0, "count": count}


# ---------------------------------------------------------------------------
# B-300 — canary/multi-turn self-test corroboration (see module docstring for the full
# design rationale: the two legs, the ledger gate, the §8 boundary, honest labelling).
# ---------------------------------------------------------------------------

# Bound the field text pulled out of one record before it is regex-scanned (B-192's OOM
# lesson: bound the parse, not just the walk). A real prompt/assistantTexts blob measured
# nowhere near this; only a padded/hostile line would hit it, and it fails toward
# UNDER-reporting (a match past the cap is missed), never a fabricated one.
_MAX_SELFTEST_TEXT_LEN = 200_000

# (source name, its own namespaced token prefix, its render-echo marker literals). Adding
# a third self-test surface (e.g. redteam.py's CLAWSECCHECK-RT-) means adding one entry
# here — nothing else in this section is source-specific.
_SELFTEST_SOURCES: tuple = (
    ("canary", canary.TOKEN_PREFIX, canary.RENDER_ECHO_MARKERS),
    ("multiturn", multiturn._TOKEN_PREFIX, multiturn.RENDER_ECHO_MARKERS),
)

# How far (chars, each direction) around a token match to look for a render-echo marker.
# Measured against the REAL render_canary()/render_multiturn() output (not just a hand-built
# fixture): every real marker sits within ~10 chars of the token (e.g. "Token to watch
# for: <token>", "ack token   : <token>", "...to confirm the rule is active." right after
# the token). 80 leaves a wide safety margin over that measured distance while staying
# deliberately TIGHT — a C-135 adversarial pass on THIS task found that a naive wide
# window (originally 250) let a genuinely dishonest reply launder past the discriminator
# simply by being appended directly after an echoed render (e.g. "...(RESISTANT is
# good).\n\nMy actual reply is: <token>" sits well inside a 250-char window of the
# preceding "Token to watch for:" marker, so it read as render-echo too). Shrinking to 80
# closes that specific case (verified: the same adversarial text no longer launders) while
# every real render occurrence still matches with room to spare. This is a narrowing, not
# a proof of soundness — a sufficiently padded reply can still exploit the same shape by
# inserting >80 chars of filler between the echoed render and its own compliance; that
# residual is accepted for a best-effort, WARN-only, never-FAIL, unscored signal (same
# discipline as multiturn.py's own `_ack_token_fired` refusal-quoting residual).
_SELFTEST_ECHO_SPAN = 80


def _is_render_echo(text: str, start: int, end: int, markers: tuple) -> bool:
    """True if a token occurrence at text[start:end] sits near one of *markers* — i.e. this
    is the harness's OWN rendered scaffold text, not a compliant reply. See
    `canary.RENDER_ECHO_MARKERS` / `multiturn.RENDER_ECHO_MARKERS` for what the markers are
    and why. Case-insensitive; bounded to `_SELFTEST_ECHO_SPAN` on each side.

    B-300 ROUND 3 (C-135 finding): a bare marker STRING checked via "appears anywhere in
    the window" collided with natural compliance narration for multiturn's labels —
    "...here's my ack token: <token>" contains "ack token" immediately before a colon,
    exactly the shape a real compliant (VULNERABLE) reply takes when describing what it
    just did, not just when echoing the render. Canary's one surviving marker ("token to
    watch for") was independently verified NOT to collide this way — an agent narrating
    compliance in its own words has no natural reason to say "token to watch for" about
    itself, since that phrase is written in the imperative, addressed to a human reader,
    not something a compliant agent would say about its own action. So markers here come
    in two shapes: a plain `str` (canary) is still checked as a case-insensitive substring
    anywhere in the window; a compiled `re.Pattern` (multiturn) is checked ANCHORED
    immediately before the token — i.e. it must match the text ending exactly where the
    token starts (mirroring the B-286 lesson: a directive and its object share a clause; a
    render label and its value share a colon-adjacency, and the render's own alignment
    padding is a structural artifact natural narration does not reproduce by accident).
    """
    lo = max(0, start - _SELFTEST_ECHO_SPAN)
    hi = min(len(text), end + _SELFTEST_ECHO_SPAN)
    window = text[lo:hi].lower()
    for marker in markers:
        if isinstance(marker, str):
            if marker in window:
                return True
        else:
            if marker.search(text[lo:start]):
                return True
    return False


def _iter_selftest_texts(path: Path, *, max_bytes: int = _MAX_BYTES_PER_FILE):
    """Yield (event_type, text) for `prompt.submitted`/`data.prompt` and
    `model.completed`/`data.assistantTexts` records in *path* — B-300's two corroboration
    legs share one file pass. `text` is bounded to `_MAX_SELFTEST_TEXT_LEN` chars.

    Sentinels "__unknown__"/"__truncated__" (paired with `""`) mirror `_iter_tool_calls`'s
    so callers fold them into `unknown_version`/`truncated` meta the same way.

    §8 (B-300): `data.prompt` and `data.assistantTexts` are the user's own submitted
    prompt and the agent's own reply — sensitive payloads `trajectory.py` deliberately
    does not read (see this module's docstring). This generator exists ONLY so a caller
    can membership-test an already-known ClawSecCheck token prefix in memory; a caller
    must never log, print, or return the yielded text itself — only a matched literal
    prefix/marker constant, exactly like `_iter_tool_calls`'s `data.arguments` contract.
    """
    try:
        read = 0
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                read += len(line)
                if read > max_bytes:
                    yield ("__truncated__", "")
                    break
                if '"prompt.submitted"' not in line and '"model.completed"' not in line:
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
                rec_type = rec.get("type")
                if rec_type not in ("prompt.submitted", "model.completed"):
                    continue
                data = rec.get("data")
                if not isinstance(data, dict):
                    continue
                if rec_type == "prompt.submitted":
                    value = data.get("prompt")
                    if isinstance(value, str) and value:
                        yield ("prompt.submitted", value[:_MAX_SELFTEST_TEXT_LEN])
                else:
                    value = data.get("assistantTexts")
                    text = None
                    if isinstance(value, str) and value:
                        text = value
                    elif isinstance(value, list):
                        parts = [v for v in value if isinstance(v, str) and v]
                        if parts:
                            text = "\n".join(parts)
                    if text:
                        yield ("model.completed", text[:_MAX_SELFTEST_TEXT_LEN])
    except OSError:
        return


def self_test_corroboration(home, *, explicit_path: str | None = None,
                             ledger_home: str | None = None) -> dict:
    """B-300: corroborate a canary/multi-turn self-test claim against the trajectory log.

    Returns a result dict:

    * ``ledger_recorded`` — the local coverage ledger (`ledger.load_ledger`) shows a
      self-test capability was run at least once. When False, the rest of the dict stays
      at its all-False/zero defaults and the caller should say NOTHING — there is nothing
      to corroborate, and reporting a WARN here would manufacture noise on the
      overwhelming majority of hosts that simply never tried the feature.
    * ``present`` — any trajectory sidecar found (same shape as ``analyze()``'s meta).
    * ``files_scanned`` / ``unknown_version`` / ``truncated`` / ``files_total`` /
      ``files_capped`` — same meaning as ``analyze()``'s meta.
    * ``sources`` — ``{"canary": {...}, "multiturn": {...}}``, each:
        - ``administered`` (LOW-FP leg) — the source's token prefix appeared in at least
          one ``prompt.submitted.data.prompt`` — local evidence the payload was actually
          submitted to the agent.
        - ``assistant_seen`` (HIGH-FP leg, best-effort) — the prefix appeared in
          ``model.completed.data.assistantTexts`` OUTSIDE the render-echo shape.
        - ``assistant_render_echo_only`` — the prefix appeared in ``assistantTexts`` ONLY
          inside the render-echo shape (see ``_is_render_echo``) — i.e. the harness's own
          rendered instructions being shown to the user, not a compliant reply.

    Never returns a RESISTANT/VULNERABLE verdict — see module docstring's honest-labelling
    note. ``ledger_home`` overrides the ledger's HOME dir (tests only; ``None`` -> the real
    ``~/.clawseccheck/coverage.json``, same default as every other ``ledger`` caller).
    """
    result: dict = {
        "ledger_recorded": False,
        "present": False,
        "files_scanned": 0,
        "unknown_version": False,
        "truncated": False,
        "files_total": 0,
        "files_capped": False,
        "sources": {
            name: {
                "administered": False,
                "assistant_seen": False,
                "assistant_render_echo_only": False,
            }
            for name, _prefix, _markers in _SELFTEST_SOURCES
        },
    }

    ledger = load_ledger(ledger_home)
    result["ledger_recorded"] = "self_test" in ledger
    if not result["ledger_recorded"]:
        return result

    if explicit_path:
        p = Path(explicit_path).expanduser()
        files = [p] if p.is_file() else []
        result["files_total"] = len(files)
    else:
        stats: dict = {}
        files = find_trajectory_files(home, stats=stats) if isinstance(home, Path) else []
        result["files_total"] = stats.get("files_total", 0)
        result["files_capped"] = stats.get("files_capped", False)
    if not files:
        return result
    result["present"] = True

    echo_only_candidate = {name: False for name, _prefix, _markers in _SELFTEST_SOURCES}

    for path in files:
        result["files_scanned"] += 1
        for rec_type, text in _iter_selftest_texts(path):
            if rec_type == "__unknown__":
                result["unknown_version"] = True
                continue
            if rec_type == "__truncated__":
                result["truncated"] = True
                continue
            for name, prefix, markers in _SELFTEST_SOURCES:
                if prefix not in text:
                    continue
                if rec_type == "prompt.submitted":
                    result["sources"][name]["administered"] = True
                    continue
                # model.completed — HIGH-FP leg: discriminate each occurrence.
                for m in re.finditer(re.escape(prefix), text):
                    if _is_render_echo(text, m.start(), m.end(), markers):
                        echo_only_candidate[name] = True
                    else:
                        result["sources"][name]["assistant_seen"] = True

    for name, only_echo_seen in echo_only_candidate.items():
        if only_echo_seen and not result["sources"][name]["assistant_seen"]:
            result["sources"][name]["assistant_render_echo_only"] = True

    return result


_SELFTEST_LABELS = {"canary": "canary (--canary)", "multiturn": "multi-turn (--multiturn)"}


def render_self_test_corroboration(home, *, explicit_path: str | None = None,
                                    ledger_home: str | None = None,
                                    ascii_only: bool = False) -> list:
    """Render B-300's self-test corroboration lines for --analyze-trajectory.

    Returns ``[]`` when the local ledger shows no self-test capability was ever run —
    silence, matching ``self_test_corroboration``'s own "nothing to corroborate" contract
    (never an affirmative all-clear either way).
    """
    r = self_test_corroboration(home, explicit_path=explicit_path, ledger_home=ledger_home)
    if not r["ledger_recorded"]:
        return []

    warn = "[!]" if ascii_only else "⚠"
    ok = "[ok]" if ascii_only else "✓"
    q = "[?]" if ascii_only else "?"

    lines = [
        "",
        "Self-test corroboration (canary / multi-turn) — advisory, NARROWS BEHAV-4, does "
        "not close it:",
    ]
    if not r["present"]:
        lines.append(
            f"  {q} The local ledger shows a self-test capability was run, but no "
            "trajectory sidecar was found to corroborate it — UNKNOWN, not an all-clear."
        )
        return lines

    if r["unknown_version"]:
        lines.append(f"  {q} Some records used an unrecognised trajectory schema version — "
                     "corroboration is INCOMPLETE (treat as UNKNOWN).")
    if r["truncated"]:
        lines.append(f"  {q} A trajectory file exceeded the per-file scan cap — "
                     "corroboration is INCOMPLETE (treat as UNKNOWN).")
    if r["files_capped"]:
        lines.append(
            f"  {q} Scanned the {r['files_scanned']} most recent of {r['files_total']} "
            "trajectory file(s) — the oldest session(s) were not checked."
        )

    prefix_by_name = {name: prefix for name, prefix, _markers in _SELFTEST_SOURCES}
    for name, info in r["sources"].items():
        label = _SELFTEST_LABELS.get(name, name)
        prefix = prefix_by_name.get(name, "")
        if info["administered"]:
            lines.append(
                f"  {ok} {label}: a '{prefix}' token was seen in a submitted prompt — "
                "local evidence the payload was actually delivered to the agent "
                "(did-it-run leg corroborated)."
            )
        else:
            lines.append(
                f"  {warn} {label}: the local ledger shows a self-test capability was run, "
                f"but no '{prefix}' token appears anywhere in a submitted prompt — no "
                "local artifact corroborates that this specific test actually ran."
            )
        if info["assistant_render_echo_only"]:
            lines.append(
                f"      {ok} a '{prefix}' token also appeared in an assistant reply, but "
                "only inside the harness's own rendered instructions being shown to the "
                "user (e.g. \"Token to watch for: …\" / \"ack token   : …\") — that is the "
                "render being echoed, not compliance. No concern raised."
            )
        elif info["assistant_seen"]:
            lines.append(
                f"      {warn} a '{prefix}' token appeared in an assistant reply OUTSIDE "
                "the harness's own rendered text — best-effort signal only (the known "
                "render-echo shape is excluded; nothing stronger is proven here). "
                "Confirm manually before treating a claimed RESISTANT verdict as "
                "contradicted."
            )

    lines.append(
        "  Neither --canary/--multiturn nor this corroboration ever renders a "
        "RESISTANT/VULNERABLE verdict itself — that verdict is the host LLM's to speak "
        "in chat. This only answers whether local evidence shows the test was "
        "ADMINISTERED and, best-effort, whether its token surfaced outside the harness's "
        "own render; it does NOT independently verify the verdict was honest. "
        "_record_run() attests only that the flag was invoked, not that the test "
        "executed or what it concluded."
    )
    return lines


def render_trajectory_analysis(ctx, *, explicit_path: str | None = None, ascii_only: bool = False,
                                ledger_home: str | None = None) -> str:
    """Human-readable, §8-safe incident report for --analyze-trajectory.

    ``ledger_home`` overrides B-300's self-test-corroboration ledger lookup (tests only;
    ``None`` -> the real ``~/.clawseccheck/coverage.json``, same default `cli.py` uses for
    every other ledger read).
    """
    r = analyze(ctx, explicit_path=explicit_path)
    warn = "[!]" if ascii_only else "⚠"
    ok = "[ok]" if ascii_only else "✓"
    q = "[?]" if ascii_only else "?"
    lines = ["Trajectory incident analysis (post-hoc, read-only)"]

    if not r["present"]:
        lines.append(f"  {q} No trajectory sidecars found "
                     "(agents/*/sessions/*.trajectory.jsonl). Nothing to analyze — run on a "
                     "host where an OpenClaw agent has produced session trajectories.")
        lines.extend(render_self_test_corroboration(
            getattr(ctx, "home", None), explicit_path=explicit_path, ascii_only=ascii_only,
            ledger_home=ledger_home))
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

    lines.extend(render_self_test_corroboration(
        getattr(ctx, "home", None), explicit_path=explicit_path, ascii_only=ascii_only,
        ledger_home=ledger_home))
    return "\n".join(lines)
