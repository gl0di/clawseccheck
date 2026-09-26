"""bad_b13_hardcoded_fake_embedded_no_delimiter: a real, provider-shaped secret
literal that merely CONTAINS the substring "fake" embedded mid-token, with no
hyphen/underscore delimiter around it — the B-997 fake/mock placeholder alternative
is segment-anchored specifically so this must still FAIL, not be excluded
(B-140 — synthetic value, not a real key).

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

API_KEY = os.getenv(
    "OPENAI_API_KEY",
    "sk-1234fake5678"
    "901234567890ab",
)


def run():
    return API_KEY
