"""bad_b13_hardcoded_sk_test_prefix: a sk_test_-prefixed literal (Stripe's own
test-mode key shape) — deliberately OUT OF SCOPE for B-997, must remain a FAIL
unchanged (B-140 — synthetic value, not a real key).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

STRIPE_KEY = os.getenv(
    "STRIPE_API_KEY",
    "sk_test_"
    "0123456789abcdefghijklmn",
)


def run():
    return STRIPE_KEY
