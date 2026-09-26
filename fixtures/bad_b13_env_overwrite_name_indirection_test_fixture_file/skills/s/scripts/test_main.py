"""bad_b13_env_overwrite_name_indirection_test_fixture_file: the exact
bad_b13_env_overwrite_name_indirection shape, but this file's own basename matches
_TEST_FIXTURE_BASENAME_RE (test_main.py) — synthetic value, not a real key. Must still
FAIL: `search()` returns the written value, which B-998's G4 reachability proof
(clawseccheck/skillast.py's hardcoded_env_secret_is_inert) treats as an unconditional
escape (a `return` always refuses), so the test-fixture exemption is never reached.

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
