"""clean_b13_hardcoded_placeholder_your_provider_key_here: an all-caps snake_case
"YOUR_<PROVIDER>_KEY_HERE" placeholder wrapped in a real provider prefix. Documents
where the installer should paste their own key — not a real credential.
Must NOT fire B-140 (B-997)."""
import os

API_KEY = os.getenv("OPENAI_API_KEY", "sk-proj-YOUR_OPENAI_KEY_HERE")


def run():
    return API_KEY
