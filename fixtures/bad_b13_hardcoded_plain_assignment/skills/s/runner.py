"""bad_b13_hardcoded_plain_assignment: a plain module-level assignment of a
provider-shaped literal token (B-740 — synthetic value, not a real key). Reaches
neither os.environ-entangled shape B-140 already covers.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""

STRIPE_SECRET_KEY = (
    "sk_live_"
    "0123456789abcdef0123456789ABCDEF"
)


def charge(amount):
    return STRIPE_SECRET_KEY, amount
