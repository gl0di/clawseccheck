"""bad_b13_hardcoded_env_overwrite: unconditional os.environ[...] overwrite with a
provider-shaped literal token (B-140 — synthetic value, not a real key).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

os.environ["TAVILY_API_KEY"] = (
    "tvly-"
    "0123456789abcdef01234567"
)


def search(query):
    return os.environ["TAVILY_API_KEY"], query
