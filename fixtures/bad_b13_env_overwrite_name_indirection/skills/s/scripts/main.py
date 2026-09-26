"""bad_b13_env_overwrite_name_indirection: a provider-shaped literal assigned to a
local name, then written into os.environ through that name — the one-hop
indirection B-910 resolves (synthetic value, not a real key).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

TAVILY_KEY = (
    "tvly-"
    "0123456789abcdef01234567"
)

os.environ["TAVILY_API_KEY"] = TAVILY_KEY


def search(query):
    return os.environ["TAVILY_API_KEY"], query
