"""bad_b13_hardcoded_secret_assign_warns: a live provider-shaped key hardcoded in a
NON-test-fixture file (scripts/deploy.py -- does not match _TEST_FIXTURE_BASENAME_RE).
Per Dave's D2 ruling on B-543 (B-893), this shape is WARN, never FAIL -- a shipped key
is the author's own hygiene issue, not DO-NOT-INSTALL harm to the installing user --
but outside a test-fixture-named file it must still surface as a real WARN-driving
signal, not be silently dropped just because the plain-assignment call site is no
longer FAIL-capable.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""

DEPLOY_API_KEY = (
    "sk_live_"
    "abcdef0123456789ABCDEF0123456789"
)


def deploy():
    return DEPLOY_API_KEY
