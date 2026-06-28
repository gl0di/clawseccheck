"""Property-based tests for logsafe.redact() — no secret ever escapes (§2.3 / §8).

The unit tests in test_logsafe.py pin specific shapes; these randomize the
secret payload AND the surrounding text across many iterations to guarantee the
invariant holds generally, not just for the hand-picked examples.

Per the test_logsafe.py convention, no contiguous secret-shaped literal exists
in this source: every secret is assembled at runtime from a randomized char
pool, so secret scanners stay quiet. RNGs are explicitly seeded so the suite is
deterministic and CI-stable (no Math.random-style flakiness). Offline, stdlib.
"""
from __future__ import annotations

import random
import string

from clawseccheck.logsafe import redact

ALNUM = string.ascii_letters + string.digits
_ITER = 200

# Secret-key names that SECRET_KEY_RE / the colon-pattern recognise (assembled,
# never a hard-coded secret value).
_KEY_NAMES = ["password", "secret", "token", "api_key", "apikey", "api-key", "bottoken"]


def _rand(pool: str, n: int, rng: random.Random) -> str:
    return "".join(rng.choice(pool) for _ in range(n))


def _mixed_case(word: str, rng: random.Random) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in word)


def _make_token(rng: random.Random) -> str:
    """A bare secret-shaped token (no key prefix), randomized within its shape."""
    kind = rng.choice(["anthropic", "openai", "aws", "google"])
    if kind == "anthropic":
        return "sk-ant-" + _rand(string.ascii_lowercase + string.digits + "-", rng.randint(8, 40), rng)
    if kind == "openai":
        return "sk-" + _rand(ALNUM, rng.randint(20, 48), rng)
    if kind == "aws":
        return "AKIA" + _rand(string.ascii_uppercase + string.digits, 16, rng)
    return "AIza" + _rand(ALNUM + "_-", rng.randint(30, 40), rng)


def _make_kv(rng: random.Random):
    """A key/value secret pair. Returns (text, secret_value_that_must_vanish)."""
    key = _mixed_case(rng.choice(_KEY_NAMES), rng)
    sep = rng.choice([":", "=", ": ", " = ", "="])
    quote = rng.choice(["", "", "'", '"'])
    value = _rand(ALNUM, rng.randint(8, 32), rng)  # >=8 -> trips SECRET_PATTERNS / _KV_RE
    return f"{key}{sep}{quote}{value}", value


_BENIGN_WORDS = ["connecting", "to", "host", "loading", "config", "from", "file",
                 "user", "bob", "ready", "done", "scanning", "agent", "ok"]


def _filler(rng: random.Random) -> str:
    return " ".join(rng.choice(_BENIGN_WORDS) for _ in range(rng.randint(0, 6)))


def _embed(secret: str, rng: random.Random) -> str:
    """Drop *secret* into a randomized surrounding context."""
    pre, post = _filler(rng), _filler(rng)
    style = rng.randint(0, 3)
    if style == 0:
        return f"{pre} {secret} {post}"
    if style == 1:
        return f'{pre} {{"k": "{secret}"}} {post}'
    if style == 2:
        return f"{pre}\n{secret}\n{post}"
    return secret


# ---------------------------------------------------------------------------
# Core invariant: a secret value never survives redaction.
# ---------------------------------------------------------------------------


def test_bare_tokens_never_escape():
    rng = random.Random(20260623)
    for _ in range(_ITER):
        token = _make_token(rng)
        out = redact(_embed(token, rng))
        assert token not in out, f"token leaked through redact(): {token[:6]}…"
        assert "<redacted>" in out


def test_key_value_secrets_never_escape():
    rng = random.Random(424242)
    for _ in range(_ITER):
        text, value = _make_kv(rng)
        out = redact(_embed(text, rng))
        assert value not in out, "secret value leaked through redact()"
        assert "<redacted>" in out


def test_many_secrets_in_one_blob_all_removed():
    rng = random.Random(7777)
    for _ in range(_ITER):
        tokens = [_make_token(rng) for _ in range(rng.randint(2, 5))]
        kvs = [_make_kv(rng) for _ in range(rng.randint(1, 3))]
        parts = [_filler(rng)]
        for t in tokens:
            parts += [t, _filler(rng)]
        for text, _ in kvs:
            parts += [text, _filler(rng)]
        blob = " ".join(parts)
        out = redact(blob)
        for t in tokens:
            assert t not in out
        for _, value in kvs:
            assert value not in out


# ---------------------------------------------------------------------------
# Robustness & algebraic properties.
# ---------------------------------------------------------------------------


def test_idempotent_over_random_secrets():
    rng = random.Random(13579)
    for _ in range(_ITER):
        text = _embed(_make_token(rng), rng) + " " + _make_kv(rng)[0]
        once = redact(text)
        assert redact(once) == once


def test_never_raises_and_returns_str_on_arbitrary_input():
    rng = random.Random(2468)
    pool = ALNUM + string.punctuation + " \t\n" + "……🔍​‮"
    for _ in range(_ITER):
        garbage = _rand(pool, rng.randint(0, 120), rng)
        out = redact(garbage)
        assert isinstance(out, str)


def test_benign_text_is_left_untouched():
    rng = random.Random(99)
    for _ in range(_ITER):
        # Built only from benign words + short (<4 char) values -> no pattern,
        # no secret-like key=value, so redact must be a no-op.
        text = _filler(rng) + " " + _rand(string.ascii_lowercase, rng.randint(0, 3), rng)
        assert redact(text) == text
        assert "<redacted>" not in redact(text)
