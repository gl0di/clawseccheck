"""B-260 — the ClawHub CLI token prefix (`clh_`) must be recognised by BOTH surfaces.

Before this, `clh_` appeared nowhere in the codebase, with two independent consequences:

  1. the provider-token detectors did not recognise it, so a ClawHub token copied into an
     OpenClaw config/bootstrap file was not a plaintext-secret finding; and
  2. `logsafe.redact()` would not mask it, so our own output could have leaked one.

(2) is the more serious half — the tool must never be the thing that leaks the token that
publishes new versions of the user's own skills.

Grounding (Golden Rule #4): the prefix is documented by the installed ClawHub CLI itself
(clawhub@0.22.0 README: `clawhub login --token clh_...`). The CLI does no client-side
format validation — `dist/cli/authToken.js` just reads `cfg?.token`, and
`dist/schema/schemas.js` types it `"string?"` — so no length/charset is claimed here.

EVERY secret-shaped value below is assembled from fragments at runtime so no contiguous
secret-looking literal exists in this source file (project law §2.3). Offline, read-only.
"""
from __future__ import annotations

from clawseccheck.checks import SECRET_PATTERNS
from clawseccheck.logsafe import redact

# Assembled at runtime — never a contiguous literal in source.
_PREFIX = "clh" + "_"


def _token(body: str = "") -> str:
    return _PREFIX + (body or ("A" * 12 + "b7" + "Z" * 10))


class TestRedaction:
    """The half that matters most: we must never emit one ourselves."""

    def test_bare_token_is_redacted(self):
        secret = _token()
        result = redact(secret)
        assert secret not in result
        assert "<redacted>" in result

    def test_token_embedded_in_a_command_line_is_redacted(self):
        secret = _token()
        text = f"running: clawhub login --token {secret} --yes"
        result = redact(text)
        assert secret not in result
        assert "<redacted>" in result
        # Surrounding context must survive — redaction, not deletion.
        assert "clawhub login" in result
        assert "--yes" in result

    def test_token_in_json_value_is_redacted(self):
        secret = _token()
        text = '{"registry": "https://clawhub.ai", "token": "' + secret + '"}'
        result = redact(text)
        assert secret not in result
        assert "<redacted>" in result

    def test_redaction_is_idempotent(self):
        text = "token here: " + _token()
        once = redact(text)
        assert once == redact(once)

    def test_hyphen_and_underscore_bodies_are_covered(self):
        for body in ("a-b-c-d-e-f-g-h", "a_b_c_d_e_f_g_h", "0123456789ab"):
            secret = _token(body)
            assert secret not in redact(secret), body


class TestDetection:
    """The detector surface — a `clh_` token in config/bootstrap text is a real finding."""

    def _matches(self, text: str) -> bool:
        return any(p.search(text) for p in SECRET_PATTERNS)

    def test_detectors_recognise_the_token(self):
        assert self._matches(_token())

    def test_detectors_recognise_it_inside_a_config_value(self):
        assert self._matches('  "clawhubToken": "' + _token() + '",')

    def test_pattern_has_no_capturing_group(self):
        """`_pattern_hits_real_secret` fires immediately on group-less patterns (the
        concrete-literal formats) and only SecretRef-filters the ones with a group. A
        `clh_`-prefixed literal can never be a `${VAR}` indirection, so it belongs in the
        group-less family — if a group were added it would silently change that path."""
        pat = next(p for p in SECRET_PATTERNS if p.pattern.startswith("clh"))
        assert pat.groups == 0

    def test_prefix_alone_is_not_enough(self):
        """A bare mention of the prefix in prose must not match — only material after it."""
        assert not self._matches("the ClawHub token prefix is " + _PREFIX)
        assert not self._matches("see `" + _PREFIX + "` in the docs")

    def test_short_suffix_does_not_match(self):
        assert not self._matches(_token("abc"))

    def test_ordinary_text_is_untouched(self):
        text = "nothing secret here, just the clawhub registry at clawhub.ai"
        assert not self._matches(text)
        assert redact(text) == text
