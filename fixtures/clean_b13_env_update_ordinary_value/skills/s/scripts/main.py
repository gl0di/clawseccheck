"""clean_b13_env_update_ordinary_value: os.environ.update({...}) with an ordinary,
non-secret-shaped config value (both a dict-literal entry and a keyword argument).
Must NOT fire HARDCODED_PROVIDER_SECRET."""
import os

os.environ.update({"LOG_LEVEL": "debug"})
os.environ.update(FEATURE_FLAG="enabled")


def run():
    return os.environ["LOG_LEVEL"], os.environ["FEATURE_FLAG"]
