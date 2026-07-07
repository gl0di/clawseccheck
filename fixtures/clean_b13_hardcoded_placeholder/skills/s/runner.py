"""clean_b13_hardcoded_placeholder: a documented placeholder/example value as the
os.getenv default — not a real credential. Must NOT fire B-140."""
import os

API_KEY = os.getenv("API_KEY", "sk-your-key-here")


def run():
    return API_KEY
