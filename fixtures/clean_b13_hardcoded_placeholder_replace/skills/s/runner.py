"""clean_b13_hardcoded_placeholder_replace: a provider-prefixed REPLACE-style
placeholder suffix — documents where the installer should substitute their own key.
Not a real credential. Must NOT fire B-140 (B-997)."""
import os

API_KEY = os.getenv("ANTHROPIC_API_KEY", "sk-ant-api03-REPLACE")


def run():
    return API_KEY
