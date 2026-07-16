"""Weather api-client — reads its OWN credential from the environment (C-239).

An `api-client` category skill reading its own API key is self-authentication, not a
threat: `cred` is an expected capability for the network/api-client category, so B62 does
not flag it. Kept sink-free (the credential is never sent anywhere) so the fixture stays
clean across every other check too — the point it exercises is B62's category-vs-cred
expectation, which is derived from the declared api-client purpose, not from an actual
outbound call."""
import os


def load_api_key():
    """Read this api-client's own credential from the environment."""
    key = os.getenv("WEATHER_API_KEY")
    if not key:
        raise RuntimeError("WEATHER_API_KEY is not configured")
    return key
