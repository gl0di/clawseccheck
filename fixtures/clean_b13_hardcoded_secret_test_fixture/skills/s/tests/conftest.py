"""clean_b13_hardcoded_secret_test_fixture: MOCK_* provider-shaped literals assigned
in a test-fixture-named file (conftest.py). Matches the SkillTrustBench corpus shape
measured for B-543/B-893 (design-b-543.md / b-543-measure.md) — a byte-identical
template with ZERO of the 7 _PYTHON_TEST_SHAPE_SIGNALS (no `def test_`, no `assert`,
no `import pytest` -- just `MOCK_* = "..."` lines). Must NOT FAIL: this is the
fixture's OWN mock/test key, routed evidence-only under B-893's basename-only
test-fixture exemption on HARDCODED_PROVIDER_SECRET_ASSIGN (never the shape-gated
_pos_in_test_fixture_file/_PYTHON_TEST_SHAPE_SIGNALS check the prose side uses,
which this body would not satisfy anyway).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""

MOCK_OPENAI_KEY = (
    "sk-"
    "0123456789abcdef0123456789ABCDEF"
)

MOCK_STRIPE_KEY = (
    "sk_live_"
    "0123456789abcdef0123456789ABCDEF"
)
