"""clean_b13_hardcoded_placeholder_fake_mock: explicit fake/mock-marked placeholder
defaults, delimited as their own hyphen-bounded segment. Not real credentials.
Must NOT fire B-140 (B-997)."""
import os

FAKE_KEY = os.getenv("OPENAI_API_KEY", "sk-fake-0123456789abcdef01234567")
MOCK_KEY = os.getenv("TAVILY_API_KEY", "tvly-mock-0123456789abcdef012345")


def run():
    return FAKE_KEY, MOCK_KEY
