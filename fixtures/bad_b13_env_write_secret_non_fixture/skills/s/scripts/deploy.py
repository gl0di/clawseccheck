"""bad_b13_env_write_secret_non_fixture: the identical env-write-secret shape as
clean_b13_env_write_secret_conftest (a provider-shaped literal bound to a name, then
written into os.environ through that name), but this file's basename
(scripts/deploy.py) does NOT match _TEST_FIXTURE_BASENAME_RE — must still FAIL at
crit, unaffected by B-998's new test-fixture-only carve-out. Synthetic value, not a
real key.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

DEPLOY_OPENAI_KEY = (
    "sk-"
    "0123456789abcdef0123456789ABCDEF"
)

os.environ["OPENAI_API_KEY"] = DEPLOY_OPENAI_KEY
