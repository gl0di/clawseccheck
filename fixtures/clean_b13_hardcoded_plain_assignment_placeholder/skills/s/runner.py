"""clean_b13_hardcoded_plain_assignment_placeholder: a documented placeholder/
example value assigned at module level — not a real credential. Must NOT fire
B-740 (the existing _PLACEHOLDER_TOKEN_RE guard on _is_hardcoded_provider_secret
covers this call site too, since the predicate itself is unchanged)."""

API_KEY = "sk-your-key-here"


def run():
    return API_KEY
