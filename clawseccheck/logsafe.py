"""Safe local logging helper for ClawSecCheck.

Provides:
  - redact(text): mask secret-looking substrings before they reach a log
  - get_logger(...): return a stdlib Logger with redaction built in as defense-in-depth

LOCAL ONLY — no network calls, no telemetry, no external dependencies.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path

from .checks import SECRET_KEY_RE, SECRET_PATTERNS
from .safeio import secure_append_text

__all__ = ["redact", "get_logger"]

# Pattern for bare key=value or key = value pairs where the key looks secret-like.
# Matches: key=value, key = value, key="value", key='value'
_KV_RE = re.compile(
    r"(?P<key>"
    + SECRET_KEY_RE.pattern
    + r")\s*=\s*['\"]?(?P<val>[^\s'\"&;,]{4,})",
    re.I,
)

# Provider-specific secret formats that the generic SECRET_PATTERNS in checks.py
# miss (B-009).  These are full-token shapes, so each match is replaced wholesale.
# Kept here (not in checks.SECRET_PATTERNS) so they only widen *redaction* and do
# not introduce new config-scan findings / false-positive FAILs.
_EXTRA_SECRET_PATTERNS = [
    re.compile(r"gh[opsur]_[A-Za-z0-9]{20,}"),                 # GitHub PAT / OAuth / app tokens
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),               # Slack tokens
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{10,}"),          # Stripe secret keys (underscores)
    re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),                 # OpenAI project keys (hyphen after proj)
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT (header.payload.sig)
    re.compile(                                                # PEM private-key blocks
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL),
]

# Candidate credit-card PAN: 13–19 digits with optional single space/hyphen
# separators, not glued to other digits.  Luhn-validated in _replace_pan so plain
# long numbers (phone numbers, ids) are left untouched.
_PAN_CANDIDATE_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _replace_pan(m: re.Match) -> str:  # type: ignore[type-arg]
    raw = m.group(0)
    digits = re.sub(r"\D", "", raw)
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return "<redacted>"
    return raw


def redact(text: str | None) -> str:
    """Return *text* with any secret-looking substrings replaced by '<redacted>'.

    Idempotent: calling twice produces the same result as calling once.
    Safe on None or empty string.
    """
    if not text:
        return text if text is not None else ""

    result = text

    # Replace value-only patterns (sk-ant-..., AKIA..., AIza..., password: <val>, ...)
    for pat in SECRET_PATTERNS:
        result = pat.sub(_replace_secret_pattern, result)

    # Provider-specific token shapes (GitHub/Slack/Stripe/OpenAI-proj/JWT/PEM).
    for pat in _EXTRA_SECRET_PATTERNS:
        result = pat.sub("<redacted>", result)

    # Credit-card PANs (Luhn-validated so we don't mask ordinary long numbers).
    result = _PAN_CANDIDATE_RE.sub(_replace_pan, result)

    # Replace key=value pairs where the key looks secret-like.
    # We must not re-redact already-redacted markers.
    result = _KV_RE.sub(_replace_kv, result)

    return result


def _replace_secret_pattern(m: re.Match) -> str:  # type: ignore[type-arg]
    """Replacement callback for SECRET_PATTERNS.

    For patterns like `password: <value>`, keep the key prefix and redact
    only the value part.  For bare token patterns, replace the whole match.
    """
    full = m.group(0)
    # If the match contains a colon or equals sign it is a key:value pattern
    # (e.g. "password: hunter2"). We want to keep the key visible and only
    # replace the value, so the log still says *what* was matched.
    # Walk the match to split at the separator.
    for sep in (":", "="):
        idx = full.find(sep)
        if idx != -1:
            prefix = full[: idx + 1]
            # trim any quotes/spaces after the separator
            rest = full[idx + 1 :].lstrip(" '\"")
            if rest == "<redacted>":
                # Value already masked on an earlier pass — leave the whole
                # match (key prefix included) untouched so redact() stays
                # idempotent instead of collapsing to a bare "<redacted>".
                return full
            if rest:
                return prefix + " <redacted>"
    # Bare token (sk-ant-..., AKIA..., AIza...) — replace entirely.
    if full == "<redacted>":
        return full
    return "<redacted>"


def _replace_kv(m: re.Match) -> str:  # type: ignore[type-arg]
    """Replacement callback for key=value patterns."""
    val = m.group("val")
    if val == "<redacted>":
        return m.group(0)
    key = m.group("key")
    return f"{key}=<redacted>"


class _RedactingFilter(logging.Filter):
    """logging.Filter that runs redact() over every log record's message."""

    def filter(self, record: logging.LogRecord) -> bool:
        # redact() the formatted message stored on the record
        try:
            record.msg = redact(str(record.msg))
            if record.args:
                # Flatten args so the formatted message can be redacted too.
                # We re-format here and drop args so the Formatter does not
                # double-format.
                record.msg = redact(record.getMessage())
                record.args = None
        except Exception:  # pragma: no cover — safety net; never raise from a filter
            pass
        return True


class _SecureFileHandler(logging.Handler):
    """File handler that always opens destination with O_NOFOLLOW and 0600 mode."""

    def __init__(self, path: str | Path):
        super().__init__()
        self.path = Path(path)
        self.terminator = "\n"

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            secure_append_text(self.path.expanduser(), msg + self.terminator)
        except Exception:  # pragma: no cover — safety net; logging should never raise
            self.handleError(record)


def get_logger(
    verbose: bool = False,
    debug: bool = False,
    logfile: str | None = None,
) -> logging.Logger:
    """Return a stdlib Logger named 'clawseccheck' with redaction built in.

    Level selection (first match wins):
      debug=True  -> DEBUG
      verbose=True -> INFO
      else         -> WARNING

    Handlers:
      Always: StreamHandler to sys.stderr.
      Only when logfile is given: FileHandler(os.path.expanduser(logfile)).

    A _RedactingFilter is attached to every handler so no secret ever reaches
    a log sink regardless of what the caller passes in.

    Idempotent: existing handlers are cleared before adding new ones so calling
    this function multiple times never multiplies handlers.

    propagate is set to False so records are not also sent to the root logger.
    """
    logger = logging.getLogger("clawseccheck")

    # Clear existing handlers to make the function idempotent.
    logger.handlers.clear()
    logger.propagate = False

    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logger.setLevel(level)

    fmt = logging.Formatter("%(levelname)s %(name)s: %(message)s")
    filt = _RedactingFilter()

    # Handler 1: stderr (always)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(fmt)
    stderr_handler.addFilter(filt)
    logger.addHandler(stderr_handler)

    # Handler 2: file (only when explicitly requested — respects "writes nothing by default")
    if logfile is not None:
        file_handler = _SecureFileHandler(os.path.expanduser(logfile))
        file_handler.setFormatter(fmt)
        file_handler.addFilter(filt)
        logger.addHandler(file_handler)

    return logger
