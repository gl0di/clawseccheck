"""bad_b13_hardcoded_getenv_default: a provider-shaped literal used as the default/
fallback arg of os.getenv (B-140 — synthetic value, not a real key).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text (GitHub push protection flagged the original single-literal form
as a Stripe-key-shaped secret)."""
import os

SKILLPAY_KEY = os.getenv("SKILLPAY_KEY", "sk_live_"
                          "0123456789abcdef01234567")


def pay(amount):
    return SKILLPAY_KEY, amount
