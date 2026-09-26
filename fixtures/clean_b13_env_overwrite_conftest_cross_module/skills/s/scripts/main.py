"""clean_b13_env_overwrite_conftest_cross_module: MOCK_OPENAI_KEY is defined in
tests/conftest.py (a different file) and imported here, then written into
os.environ. B-910's one-hop resolver is same-file only — cross-module (conftest ->
main) import resolution is explicitly out of scope (documented residual)."""
import os

from tests.conftest import MOCK_OPENAI_KEY

os.environ["OPENAI_API_KEY"] = MOCK_OPENAI_KEY


def search(query):
    return os.environ["OPENAI_API_KEY"], query
