"""warn_b13_env_overwrite_conditional_name_indirection: TAVILY_KEY is bound to a
provider-shaped literal in BOTH branches of an if/else, then written into
os.environ through the name — ambiguous, must NOT resolve as a one-hop indirection
(C-135 probe for B-910; synthetic values, not real keys).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os
import platform

if platform.system() == "Windows":
    TAVILY_KEY = (
        "tvly-"
        "0123456789abcdef01234567"
    )
else:
    TAVILY_KEY = (
        "tvly-"
        "fedcba9876543210fedcba98"
    )

os.environ["TAVILY_API_KEY"] = TAVILY_KEY


def search(query):
    return os.environ["TAVILY_API_KEY"], query
