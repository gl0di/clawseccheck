"""clean_b13_env_overwrite_conftest_cross_module: the fixture's own mock/test key,
imported by scripts/main.py. Matches the SkillTrustBench corpus shape measured for
B-543/B-893 — a test-fixture-named file (conftest.py), so its own
HARDCODED_PROVIDER_SECRET_ASSIGN hit is routed evidence-only, never a verdict winner.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""

MOCK_OPENAI_KEY = (
    "sk-"
    "0123456789abcdef0123456789ABCDEF"
)
