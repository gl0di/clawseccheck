"""clean_b13_env_write_secret_conftest: the exact FP shape B-998 fixes — a
tests/conftest.py that binds its own MOCK_* provider-shaped literal and writes it
into os.environ, the B-910 one-hop name-indirection call site of
HARDCODED_PROVIDER_SECRET (not the plain-assignment ASSIGN rule B-893 already
exempts). Synthetic value, not a real key.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

MOCK_OPENAI_KEY = (
    "sk-"
    "0123456789abcdef0123456789ABCDEF"
)

os.environ["OPENAI_API_KEY"] = MOCK_OPENAI_KEY
