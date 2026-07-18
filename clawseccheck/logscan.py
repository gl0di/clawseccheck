"""Bounded, redacted content scanner for the agent's own log sinks (E-044 Phase 1 substrate).

Reuses the check engine's OWN vetted indicator regexes — never invents a new secret /
exfil / injection pattern (design doc §2, §6: growing the regex surface grows the ReDoS
attack surface too, C-214/B-192 precedent). This is the SAME cross-package import shape
``logsafe.py`` already uses for ``SECRET_PATTERNS``/``SECRET_KEY_RE``
(``from .checks import SECRET_KEY_RE, SECRET_PATTERNS``): ``checks/__init__.py``
deliberately never imports ``logsafe``/this module at its own top level (several checks/
topic modules import ``logsafe`` LAZILY inside function bodies for exactly this reason —
see ``checks/_vet.py``'s comment on it), so importing the aggregator from this Layer-1 leaf
does not cycle.

§8-style privacy boundary: every sample string this module RETURNS has already been passed
through ``logsafe.redact()`` — a caller must never see raw log content, only redacted
evidence + counts. For trajectory-sidecar files specifically, classes 3 (dangerous
capability) and 5 (anomaly/tamper) read ONLY envelope/metadata fields (``type``, ``name``,
``seq``, ``ts``, ``traceSchema``, ``schemaVersion``) — never ``data.arguments``/``output``/
``result``/``contentItems`` (mirrors ``trajectory.py``/``behavioral.py``'s own contract).
Classes 1/2/4/6 are a plain-text scan applied uniformly to every sink kind (including
trajectory files, whose raw JSONL lines can of course also carry a leaked secret or an
injected instruction in a tool argument) — this mirrors ``trajaudit.py``'s Dave-ratified
precedent of reading trajectory ``data.arguments`` in memory ONLY to test membership of an
already-vetted indicator, never to extract or echo the payload itself.

DoS guards (first-class, per the design doc §6 / the B-192 lesson): a per-file byte cap
(~2 MiB) stops reading and marks ``truncated``; an over-long single line is skipped (never
regex-matched) and also marks ``truncated``; a cooperative per-file wall-clock deadline
(reusing ``scanbudget``'s own monotonic-deadline helpers — the same ones ``run_all`` uses
for its outer per-audit cap) marks ``timed_out`` and stops early. This deliberately does
NOT nest a second ``scanbudget.check_deadline`` (SIGALRM) timeout inside this function: the
check that calls this (``check_log_threat_hunt``, B164) already runs inside `run_all`'s own
per-check ``check_deadline`` itimer, and that context manager unconditionally disarms
``SIGALRM`` on exit — a second, nested ``check_deadline`` call in here would disarm the
OUTER per-check timeout the first time this function returns, silently removing run_all's
own hard-timeout protection for the rest of the check. The cooperative monotonic-deadline
pair carries no signal state at all, so it composes safely instead.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime

from . import attest
from . import logsafe as _logsafe
from .checks import (
    LOG_SCAN_INJECTION_PATTERNS,
    SECRET_PATTERNS,
    _B64_BLOB_RE,
    _B64URL_BLOB_RE,
    _CRED_RE,
    _EXFIL_RE,
    _KNOWN_EXFIL_HOST_RE,
    _SECRET_PATH_RE,
)
from .logdiscovery import LogSink
from .scanbudget import audit_budget_exceeded
from .textnorm import normalize_for_scan

_MAX_BYTES_PER_FILE = 2 * 1024 * 1024  # ~2 MiB per-file read cap (DoS guard)
_MAX_LINE_LEN = 8000  # a line longer than this is skipped, never regex-matched
_MAX_SAMPLES_PER_CLASS = 5

# Trajectory schema anchors (mirrors trajectory.py's own grounded constants — recon §9.1).
_TRACE_SCHEMA = "openclaw-trajectory"
_SCHEMA_VERSION = 1

SIGNAL_CLASSES = (
    "injection_against_agent",
    "exfil_evidence",
    "dangerous_capability",
    "env_compromise_ioc",
    "anomaly_tamper",
    "secrets_at_rest",
)


@dataclass
class LogScanResult:
    sink: LogSink
    counts: dict = field(default_factory=dict)  # signal_class -> hit count
    samples: list = field(default_factory=list)  # REDACTED "class: snippet" strings, capped
    truncated: bool = False
    bytes_scanned: int = 0
    timed_out: bool = False
    skill_ioc_hits: dict = field(default_factory=dict)  # normalized-tok -> count (C-221)


# C-135 (2026-07-15, real-fleet sanity pass against ~/.openclaw): a trajectory JSONL
# record is ONE JSON object per line and can embed an entire message/tool-output
# history (sender name, chat IDs, message text...) well under the 8000-char pathological-
# line cap. Passing the WHOLE line to _add_sample as "evidence" leaked all of that
# verbatim, because logsafe.redact() only masks secret-SHAPED substrings (API keys,
# password= pairs, ...) — it was never meant to sanitize arbitrary bulk prose/PII, the
# same lesson already learned the hard way for adjudication.py's judge-packet (F-113).
# Fix: every sample is a short, BOUNDED excerpt around the actual match, never the
# full line/record — bounding the blast radius regardless of how much unrelated
# sensitive content shares that line.
_SAMPLE_CONTEXT_CHARS = 60


def _windowed(text: str, start: int, end: int) -> str:
    """A short excerpt of *text* around [start, end) — never the whole string."""
    lo = max(0, start - _SAMPLE_CONTEXT_CHARS)
    hi = min(len(text), end + _SAMPLE_CONTEXT_CHARS)
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    return prefix + text[lo:hi] + suffix


def _add_sample(result: LogScanResult, signal: str, raw_snippet: str) -> None:
    """Bump *signal*'s counter and, up to the per-class cap, store a REDACTED sample.

    ``raw_snippet`` MUST already be a bounded excerpt (see ``_windowed``), never a
    whole raw line/record — it is passed through ``logsafe.redact()`` as defense in
    depth before it is ever stored on the result, but redact() alone is not a bulk-
    text sanitizer (see the C-135 note above), so the caller's own bounding is what
    actually limits the blast radius here.
    """
    result.counts[signal] = result.counts.get(signal, 0) + 1
    stored = sum(1 for s in result.samples if s.startswith(f"{signal}: "))
    if stored < _MAX_SAMPLES_PER_CLASS:
        result.samples.append(f"{signal}: {_logsafe.redact(raw_snippet)}")


_PRINTABLE_DECODE_RATIO = 0.85  # same threshold checks/_content.py's _reassembles_to_payload
# already uses for this exact discrimination — not a new number invented for this module.


def _decodes_to_printable_blob(token: str) -> bool:
    """B-249 FP fix (C-135, 2026-07-18): True only when *token* actually decodes as
    base64 (standard or URL-safe) to bytes that are overwhelmingly printable — the real
    signature of an encoded TEXT payload (a credential string, a stolen secret) as
    opposed to incidental high-entropy bytes.

    The bare shape tests this replaced (``_B64_BLOB_RE`` / ``_B64URL_BLOB_RE`` — a run of
    40+ base64-alphabet characters, nothing else) are NOT an encoding discriminator at
    all: any 40+ char run of hex digits (a git SHA, a sha256) or an ordinary hyphenated
    URL/doc-slug ("getting-started-with-local-webhook-testing-and-tunnels") also matches
    that character class, because base64's alphabet is just alnum (+ `-`/`_`). A real-fleet
    adversarial pass (C-135) reproduced BOTH as live false positives: a benign kubectl/
    ngrok devops sink (git-SHA build param) and a benign npm/docs sink (a plain-English
    slug) both flipped this WARN-only class from silent to firing on ordinary developer
    logs. This is the exact same unsound "bare blob" shape that
    ``_secrecy_credential_or_encoding_anchor`` in checks/_content.py already tried and
    RETRACTED for the same reason (two real-fleet false positives there too) — see that
    function's docstring.

    Decoding and measuring the printable-byte ratio of the RESULT (not the input) is a
    genuine test: decoding a hex SHA or an English slug as base64 yields near-random
    bytes (~30-40% printable in practice), while decoding a real base64-encoded text
    string (a credential, a token) yields ~100% printable bytes almost always. This
    reuses the SAME 0.85 threshold and the SAME "decode, then measure printable ratio"
    technique ``_reassembles_to_payload`` (checks/_content.py) already uses to make this
    exact distinction elsewhere in the codebase — not a new invented heuristic.

    Deliberately does NOT reuse ``_content.py``'s ``_try_b64_decode``: that helper does
    ``raw.decode("utf-8", "ignore")``, which silently DROPS invalid byte sequences before
    the printable check ever runs — on random/garbage bytes that drops most of the
    string, leaving a short "survivor" remainder that then reads as deceptively
    printable. The ratio here is measured over the full raw decoded bytes.

    Known accepted residual (documented, not chased further — WARN-only/scored=False,
    never grade-affecting, Golden Rule #5 is about FAIL): a genuinely base64-encoded
    ENGLISH-TEXT value in an otherwise-ordinary param (e.g. a webhook "sig=" test value)
    decodes to printable text just like a real exfiltrated secret does — the two are
    structurally identical once encoded, and no static content-shape test can tell them
    apart without semantic judgment of what the value actually is. Narrowing further by
    param name (an allowlist of "safe" names like sig/token/auth) was considered and
    rejected: it is guessable/evadable by a real attacker and is exactly the kind of
    additional narrow special case the project's C-135 history shows does not converge
    (checks/_content.py's own retraction note; delete/simplify, don't keep stacking
    conditions).
    """
    for urlsafe in (False, True):
        try:
            pad = (-len(token)) % 4
            padded = token + "=" * pad
            raw = (
                base64.urlsafe_b64decode(padded)
                if urlsafe
                else base64.b64decode(padded, validate=True)
            )
        except (binascii.Error, ValueError):
            continue
        if not raw:
            continue
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(raw) >= _PRINTABLE_DECODE_RATIO:
            return True
    return False


def _scan_line_content(
    result: LogScanResult, line: str, *, is_trajectory: bool = False, cred_seen_before: bool = False
) -> bool:
    """Classes 1 / 2 / 4 / 6 — plain-text pattern scan over one (already length-capped)
    line. Applied uniformly to every sink kind, including trajectory sidecar lines.

    ``cred_seen_before`` — True when an earlier line in THIS SAME sink already showed a
    credential-shaped path read (``_CRED_RE``); feeds the B-249 cross-line exfil-evidence
    extension below. Returns whether THIS line itself is a cred-path read, so the caller
    can fold it into the running state for the next line (mirrors how ``last_seq``/
    ``last_ts`` are threaded through ``scan_log_file``'s loop).
    """
    normalized = normalize_for_scan(line)

    # Class 1 — injection_against_agent: a narrow, cheap subset of the content-ring's
    # injection markers (INJECTION_PATTERNS, checks/_shared.py — PLUS one extra bounded
    # canonical-override pattern, LOG_SCAN_INJECTION_PATTERNS, F-127/C-135: fixes an
    # end-to-end FN where "ignore all previous instructions"/"disregard all prior
    # instructions"/"forget everything above" — the single most canonical injection
    # phrasing — missed INJECTION_PATTERNS' narrower single-modifier "ignore" form and had
    # no "disregard"/"forget" verb at all; kept OUT of INJECTION_PATTERNS itself since that
    # list is also consumed un-corroborated by B6/B58/C074, see LOG_SCAN_INJECTION_PATTERNS'
    # docstring) over de-obfuscated text. Deliberately NOT the full ~247-regex
    # SKILL_CONTENT_RING — that set is sized and calibrated for scanning trusted-author
    # skill SOURCE, not arbitrary, attacker-influenced LOG text (design doc §6 DoS-surface
    # note). Windowed over `normalized` (not `line`): normalize_for_scan can strip
    # invisible/bidi chars, so a span found in `normalized` is not guaranteed to be a valid
    # index into `line`.
    for pat in LOG_SCAN_INJECTION_PATTERNS:
        m = pat.search(normalized)
        if m:
            _add_sample(result, "injection_against_agent", _windowed(normalized, m.start(), m.end()))
            break

    # Class 2 — exfil_evidence: a secret pattern AND an exfil-transport/host token on the
    # SAME line (mirrors checks/__init__.py's own same-line `_has_cred_exfil` rule — the
    # established low-FP shape for this exact regex pair throughout the codebase).
    secret_m = next((m for m in (p.search(line) for p in SECRET_PATTERNS) if m), None)
    exfil_m = _EXFIL_RE.search(line)
    if secret_m and exfil_m:
        lo, hi = min(secret_m.start(), exfil_m.start()), max(secret_m.end(), exfil_m.end())
        _add_sample(result, "exfil_evidence", _windowed(line, lo, hi))

    # Class 2 extension (B-249): an OPAQUE base64-encoded exfil payload has no cleartext
    # secret to pair against the same-line rule above, so a beacon that carries stolen
    # data as a base64 GET/URL param (rather than a recognizable credential string) slips
    # past it entirely — this was the confirmed gap: an injection -> cred-read -> base64
    # GET-exfil-to-a-drop-host sequence produced neither exfil_evidence (no same-line
    # secret) nor env_compromise_ioc (the exfil line carries no cred-shaped path itself).
    # Corroborate ACROSS the sink instead of requiring same-line: a real credential-shaped
    # PATH read (_CRED_RE — narrow: .aws/credentials, .ssh/id_*, keychain, wallet.dat, ...)
    # EARLIER in this same sink, followed by a LATER line naming a KNOWN, low-base-rate
    # drop-point host (_KNOWN_EXFIL_HOST_RE — the same narrow host list this check's own
    # C-221 cross-artifact axis already trusts) that ALSO carries a base64-alphabet run of
    # 40+ chars (_B64_BLOB_RE / _B64URL_BLOB_RE — the SAME vetted blob regexes the content-
    # ring already uses; never a new pattern).
    #
    # CORRECTION (B-249 FP fix, C-135, 2026-07-18): a bare base64-BLOB-SHAPE match (just
    # the character class, `_B64_BLOB_RE`/`_B64URL_BLOB_RE` alone) is NOT actually a base64
    # discriminator and is NOT "materially narrower" than the retracted
    # `_secrecy_credential_or_encoding_anchor` attempt this comment used to claim it was —
    # a 40+ char run of hex digits (a git SHA) or an ordinary hyphenated URL/doc slug
    # matches that same character class trivially. A real-fleet adversarial pass confirmed
    # this fires on ordinary developer sessions: a kubectl/ngrok devops sink (cred-path
    # ~/.kube/config, then a git-SHA build param to a *.ngrok-free.app host) and an
    # npm/docs sink (cred-path ~/.npmrc, then a plain-English doc-slug URL to a
    # *.ngrok-free.app host) both flipped this WARN-only class from silent to firing. The
    # fix: additionally require the matched blob to actually DECODE (as real base64) to
    # overwhelmingly printable bytes (`_decodes_to_printable_blob` — see its docstring for
    # why this, unlike the character-class shape, is a genuine encoding test, and for the
    # one documented residual it does not close).
    if cred_seen_before:
        host_m = _KNOWN_EXFIL_HOST_RE.search(line)
        blob_m = _B64_BLOB_RE.search(line) or _B64URL_BLOB_RE.search(line)
        if host_m and blob_m and _decodes_to_printable_blob(blob_m.group(0)):
            lo, hi = min(host_m.start(), blob_m.start()), max(host_m.end(), blob_m.end())
            _add_sample(
                result,
                "exfil_evidence",
                "cred-read earlier in this sink, then an encoded param to a known drop "
                "host: " + _windowed(line, lo, hi),
            )

    # Class 4 — env_compromise_ioc: a credential-shaped path/secret-named path token AND
    # an exfil-transport/host token on the SAME line. C-135 note: the literal task spec
    # read as "any bare _CRED_RE/_SECRET_PATH_RE/_EXFIL_RE hit anywhere in the file", but
    # _EXFIL_RE alone matches very common, benign terms (curl/wget/fetch(/POST/base64) that
    # show up in perfectly ordinary tool-call text for any web/exec-capable agent. Every
    # OTHER consumer of these same regexes in this codebase already requires a same-line
    # AND pairing (never a bare hit) precisely to avoid that noise; this class keeps that
    # same, already-proven-low-FP discipline instead of a strictly-worse bare-hit reading.
    cred_m = _CRED_RE.search(line) or _SECRET_PATH_RE.search(line)
    if cred_m and exfil_m:
        lo, hi = min(cred_m.start(), exfil_m.start()), max(cred_m.end(), exfil_m.end())
        _add_sample(result, "env_compromise_ioc", _windowed(line, lo, hi))

    # Class 6 — secrets_at_rest (content half only; the world-readable-permission half is
    # applied once per FILE by the calling check, which already owns that perm-check logic
    # — B19/_other_can_reach_read in checks/_egress.py — so it is not duplicated here):
    # SECRET_PATTERNS, or a Luhn-valid credit-card-shaped digit run (logsafe's own PAN
    # candidate regex — never a new pattern). PAN/Luhn is skipped for trajectory sinks
    # specifically (C-135, 2026-07-15 real-fleet pass): trajectory JSON is saturated with
    # large numeric fields (epoch-ms timestamps, seq/thread/usage counters) and a 13-digit
    # epoch timestamp coincidentally passes the Luhn checksum often enough in practice that
    # it fired on nearly every real trajectory file sampled — pure noise, no card data
    # involved. SECRET_PATTERNS (actual credential-shaped text) still applies everywhere,
    # including trajectory sinks.
    pan_m = None
    if not is_trajectory:
        for m in _logsafe._PAN_CANDIDATE_RE.finditer(line):
            digits = "".join(ch for ch in m.group(0) if ch.isdigit())
            if 13 <= len(digits) <= 19 and _logsafe._luhn_ok(digits):
                pan_m = m
                break
    at_rest_m = secret_m or pan_m
    if at_rest_m:
        _add_sample(result, "secrets_at_rest", _windowed(line, at_rest_m.start(), at_rest_m.end()))

    return bool(_CRED_RE.search(line))


def _parse_iso_ts(ts: str):
    """Best-effort ISO-8601 parse (accepts a trailing 'Z'). Raises ValueError on failure —
    callers must catch it; never guesses a timestamp."""
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _scan_trajectory_record(result: LogScanResult, line: str, last_seq, last_ts):
    """Classes 3 (dangerous_capability) + 5 (anomaly_tamper) — trajectory JSON records
    only. Metadata-only (§8 boundary, recon §15.3): reads only traceSchema/schemaVersion/
    seq/ts/type/data.name — NEVER data.arguments/output/result/contentItems.

    Returns the updated ``(last_seq, last_ts)`` state for the next call.
    """
    try:
        rec = json.loads(line)
    except ValueError:
        return last_seq, last_ts
    if not isinstance(rec, dict):
        return last_seq, last_ts

    # Class 5a — schema/version mismatch is itself an anomaly (recon §15.3 grounded set).
    if rec.get("traceSchema") != _TRACE_SCHEMA or rec.get("schemaVersion") != _SCHEMA_VERSION:
        _add_sample(result, "anomaly_tamper", "unexpected traceSchema/schemaVersion")
        return last_seq, last_ts

    # Class 5b — seq gaps / non-monotonic seq within this file.
    # C-135 (2026-07-15, real-fleet sanity pass): one physical sidecar file can carry
    # MULTIPLE sessions back to back (confirmed against a real trajectory — every
    # "non-monotonic seq" false hit lined up exactly with a session.started record).
    # A fresh session legitimately restarts its own seq counter, so a session.started
    # record is a deliberate reset point, not tamper evidence — skip the continuity
    # checks for exactly this transition, but still re-baseline last_seq/last_ts to it.
    seq = rec.get("seq")
    is_session_boundary = rec.get("type") == "session.started"
    if isinstance(seq, int):
        if is_session_boundary:
            pass
        elif last_seq is not None and seq <= last_seq:
            _add_sample(result, "anomaly_tamper", f"non-monotonic seq ({last_seq} -> {seq})")
        elif last_seq is not None and seq != last_seq + 1:
            _add_sample(result, "anomaly_tamper", f"seq gap ({last_seq} -> {seq})")
        last_seq = seq

    # Class 5c — ts out-of-order or unparseable.
    ts = rec.get("ts")
    if isinstance(ts, str) and ts.strip():
        try:
            parsed_ts = _parse_iso_ts(ts)
        except (ValueError, TypeError):
            _add_sample(result, "anomaly_tamper", "unparseable ts")
        else:
            if last_ts is not None and parsed_ts < last_ts:
                _add_sample(result, "anomaly_tamper", "ts out-of-order")
            last_ts = parsed_ts

    # Class 3 — dangerous_capability: a HIGH-BLAST verb PROVEN in this trajectory (reuses
    # attest.classify_verb — the SAME authoritative verb taxonomy T3/B84 already build on
    # — rather than behavioral._classify_verb_role, which lives in a Layer-3 module this
    # Layer-1 leaf must not import).
    if rec.get("type") == "tool.call":
        data = rec.get("data")
        name = data.get("name") if isinstance(data, dict) else None
        if isinstance(name, str) and name.strip():
            cls = attest.classify_verb(name)
            if cls in attest.HIGH_BLAST_CLASSES:
                _add_sample(result, "dangerous_capability", f"verb classified {cls}")

    return last_seq, last_ts


def scan_log_file(sink: LogSink, deadline, skill_iocs: dict | None = None) -> LogScanResult:
    """Bounded, redacted content scan of one log sink. Read-only; never raises.

    ``deadline`` is a ``time.monotonic()``-relative deadline (e.g. from
    ``scanbudget.audit_deadline()``), or ``None`` to disable the per-file soft cap.
    ``skill_iocs`` (optional) is a normalized-token -> declaring-skill-name map (see
    ``checks.correlation_indicators``, C-221); when given, each line is also tested for
    substring membership of those tokens — a cross-artifact correlation signal — without
    ever storing the raw line, only the already-vetted token + a hit count.
    """
    result = LogScanResult(sink=sink)
    path = sink.path

    is_trajectory = sink.kind == "trajectory"
    last_seq = None
    last_ts = None
    cred_seen = False  # B-249: has an EARLIER line in this sink shown a cred-path read?

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line_bytes = len(raw_line.encode("utf-8", errors="replace"))
                if result.bytes_scanned + line_bytes > _MAX_BYTES_PER_FILE:
                    result.truncated = True
                    break
                result.bytes_scanned += line_bytes

                if deadline is not None and audit_budget_exceeded(deadline):
                    result.timed_out = True
                    break

                line = raw_line.rstrip("\n")
                if len(line) > _MAX_LINE_LEN:
                    result.truncated = True
                    # C-135 (2026-07-15, real-fleet sanity pass): a legitimate tool.result
                    # record (e.g. a large file read or web-fetch output) routinely exceeds
                    # _MAX_LINE_LEN and lands here — completely normal, not an attack. If
                    # last_seq/last_ts were left as-is, the NEXT record's seq/ts would look
                    # like it "jumped" past whatever this skipped record's seq/ts was,
                    # firing a false anomaly_tamper hit for every oversized-but-benign
                    # record in the file (confirmed against a real trajectory: every large
                    # tool.result produced a spurious "seq gap"). Reset both so continuity
                    # checking cleanly resumes from the next record instead of blaming a
                    # skip on tampering.
                    if is_trajectory:
                        last_seq, last_ts = None, None
                    continue  # pathological line — never regex-matched
                if not line.strip():
                    continue

                cred_here = _scan_line_content(
                    result, line, is_trajectory=is_trajectory, cred_seen_before=cred_seen
                )
                cred_seen = cred_seen or cred_here
                if skill_iocs:
                    low = line.lower()
                    for tok in skill_iocs:
                        if tok in low:
                            result.skill_ioc_hits[tok] = result.skill_ioc_hits.get(tok, 0) + 1
                if is_trajectory:
                    last_seq, last_ts = _scan_trajectory_record(result, line, last_seq, last_ts)
    except OSError:
        pass

    return result
