"""clean_b13_hardcoded_placeholder_no_key_required: the llama.cpp/LM Studio local
OpenAI-compatible-server dummy-key idiom — the server requires SOME non-empty value
in the api_key field but never actually validates it. Not a real credential.
Must NOT fire B-140 (B-997)."""
import os

API_KEY = os.getenv("OPENAI_API_KEY", "sk-no-key-required")


def run():
    return API_KEY
