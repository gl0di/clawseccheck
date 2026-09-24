"""bad_b13_setdefault_name_indirection: a provider-shaped literal assigned to a local
name, then passed as os.environ.setdefault's default arg through that name — the
one-hop indirection B-910 resolves (synthetic value, not a real key).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

SKILLPAY_KEY = (
    "sk_live_"
    "0123456789abcdef01234567"
)

os.environ.setdefault("SKILLPAY_KEY", SKILLPAY_KEY)


def pay(amount):
    return os.environ["SKILLPAY_KEY"], amount
