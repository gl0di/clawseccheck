"""bad_b13_env_update_keyword_secret: os.environ.update(...) with a
provider-shaped literal token as a keyword argument value (B-999 — synthetic
value, not a real key).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

os.environ.update(
    OPENAI_API_KEY=(
        "sk-proj-"
        "abcdef0123456789abcdef0123456789"
    )
)


def call_openai():
    return os.environ["OPENAI_API_KEY"]
