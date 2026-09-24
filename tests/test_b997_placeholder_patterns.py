"""B-997: widen `_PLACEHOLDER_TOKEN_RE` (skillast.py) to recognize several common
real-world placeholder shapes that previously slipped through and caused false-
positive `HARDCODED_PROVIDER_SECRET` FAILs:

- `sk-no-key-required` — the llama.cpp/LM Studio local OpenAI-compatible-server
  dummy-key idiom (a field that must be non-empty but is never actually validated).
- `sk-your-api-key-here` — the pre-existing `your[_-]?key` alternative required
  "your" and "key" to be adjacent; "your-api-key-here" has "api" between them.
- `sk-proj-YOUR_OPENAI_KEY_HERE` / `sk-ant-api03-REPLACE` — provider-prefixed,
  all-caps snake_case placeholder suffixes.
- `sk-fake-...` / `sk-mock-...` — explicit fake/mock markers, added as their OWN
  segment-anchored alternative (`[_-]` or start/end on both sides) rather than a
  bare substring match, specifically so a real secret that merely CONTAINS
  "fake"/"mock" mid-token (no delimiters) is NOT wrongly excluded.

Each addition is a NEW alternative in the regex, never a loosening of an existing
one — the pre-existing `your[_-]?key`, `changeme`, `xxxx`, `example`, `placeholder`,
`redacted`, `dummy`, `<[a-z_]+>`, `...` alternatives are all byte-for-byte unchanged.

Deliberately OUT OF SCOPE and left untouched: `sk_test_`/`sk-test-` — Stripe's own
test-mode key shape, still meaningfully secret-shaped if leaked. The regression
tests below pin that this task did not touch it.

C-135 self-assessment: see the task report. This widens a CRIT-severity, FAIL-
capable rule's EXCLUSION set (narrows detection), so the probe tests below are the
adversarial pass — each new alternative is checked against BOTH a placeholder value
it should now exclude AND a realistic secret-shaped value that merely shares its
vocabulary (contains "fake"/"mock"/"replace" as a substring) but must still FAIL.

Secret-shaped test literals are split across adjacent string-literal boundaries
(Golden Rule #3) — Python folds adjacent string literals into a single ast.Constant
at parse time, so the AST detector still sees one joined value, but no contiguous
secret-shaped substring exists in this file's raw text.

Offline, deterministic. No network calls, no writes outside tmp_path/fixtures.
"""

from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# ---------------------------------------------------------------------------
# New placeholder shapes: must NOT fire (analyze_python unit tests)
# ---------------------------------------------------------------------------


def test_no_key_required_is_clean():
    src = 'import os\nk = os.getenv("OPENAI_API_KEY", "sk-no-key-required")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_no_key_required_underscore_variant_is_clean():
    src = 'import os\nk = os.getenv("OPENAI_API_KEY", "sk_no_key_required")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_your_api_key_here_word_order_gap_is_clean():
    """The pre-existing `your[_-]?key` alternative required "your" and "key" to be
    adjacent; this phrase has "api" between them — the exact gap B-997 fixes."""
    src = 'import os\nk = os.getenv("API_KEY", "sk-your-api-key-here")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_your_api_key_here_underscore_variant_is_clean():
    src = 'import os\nk = os.getenv("API_KEY", "sk_your_api_key_here")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_all_caps_snake_case_your_provider_key_here_is_clean():
    src = 'import os\nk = os.getenv("OPENAI_API_KEY", "sk-proj-YOUR_OPENAI_KEY_HERE")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_replace_placeholder_suffix_is_clean():
    src = 'import os\nk = os.getenv("ANTHROPIC_API_KEY", "sk-ant-api03-REPLACE")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_replace_me_phrase_is_clean():
    src = 'import os\nk = os.getenv("API_KEY", "sk-REPLACE_ME-0123456789abcdef")\n'
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_fake_marker_segment_is_clean():
    src = (
        'import os\n'
        'k = os.getenv("OPENAI_API_KEY", "sk-fake-"\n'
        '    "0123456789abcdef01234567")\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


def test_mock_marker_segment_is_clean():
    src = (
        'import os\n'
        'k = os.getenv("TAVILY_API_KEY", "tvly-mock-"\n'
        '    "0123456789abcdef012345")\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" not in _rules(src)


# ---------------------------------------------------------------------------
# Adversarial probes: a real secret sharing new vocabulary must still FAIL
# ---------------------------------------------------------------------------


def test_fake_embedded_mid_token_without_delimiter_still_fires():
    """"fake" appears as a substring but is NOT its own hyphen/underscore-
    delimited segment — must NOT be excluded by the new fake/mock alternative."""
    src = (
        'import os\n'
        'k = os.getenv("OPENAI_API_KEY", "sk-1234fake5678"\n'
        '    "901234567890ab")\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" in _rules(src)


def test_mock_embedded_mid_token_without_delimiter_still_fires():
    src = (
        'import os\n'
        'k = os.getenv("OPENAI_API_KEY", "sk-1234mock5678"\n'
        '    "901234567890ab")\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" in _rules(src)


def test_realistic_secret_with_no_placeholder_vocabulary_still_fires():
    src = (
        'import os\n'
        'k = os.getenv("OPENAI_API_KEY", "sk-live-"\n'
        '    "0123456789abcdefghijklmn")\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" in _rules(src)


# ---------------------------------------------------------------------------
# Regression: sk_test_ / sk-test- deliberately untouched, out of scope
# ---------------------------------------------------------------------------


def test_sk_test_underscore_prefix_still_fires_unchanged():
    """Stripe's own test-mode key shape — still meaningfully secret-shaped if
    leaked. B-997 deliberately does not add any 'test'-word carve-out here."""
    src = (
        'import os\n'
        'k = os.getenv("STRIPE_API_KEY", "sk_test_"\n'
        '    "0123456789abcdefghijklmn")\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" in _rules(src)


def test_sk_test_hyphen_prefix_still_fires_unchanged():
    src = (
        'import os\n'
        'k = os.getenv("STRIPE_API_KEY", "sk-test-"\n'
        '    "0123456789abcdefghijklmn")\n'
    )
    assert "HARDCODED_PROVIDER_SECRET" in _rules(src)


# ---------------------------------------------------------------------------
# B13 integration: vet_skill on fixture directories
# ---------------------------------------------------------------------------


def test_vet_no_key_required_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b13_hardcoded_placeholder_no_key_required" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_your_provider_key_here_fixture_is_pass():
    skill_dir = (
        FIXTURES / "clean_b13_hardcoded_placeholder_your_provider_key_here" / "skills" / "s"
    )
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_replace_placeholder_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b13_hardcoded_placeholder_replace" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_fake_mock_placeholder_fixture_is_pass():
    skill_dir = FIXTURES / "clean_b13_hardcoded_placeholder_fake_mock" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_fake_embedded_no_delimiter_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_b13_hardcoded_fake_embedded_no_delimiter" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"


def test_vet_sk_test_prefix_fixture_is_critical_fail():
    skill_dir = FIXTURES / "bad_b13_hardcoded_sk_test_prefix" / "skills" / "s"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"
