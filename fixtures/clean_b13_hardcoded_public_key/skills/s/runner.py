"""clean_b13_hardcoded_public_key: a documented PUBLIC open-data API key with no
provider-token prefix (the klaus-processos-br counter-example from CLAWSECCHECK-B-140).
Must NOT fire — a public key has no provider-token shape to match."""
import os

CNJ_PUBLIC_KEY = os.getenv("CNJ_KEY", "cGFzc3dvcmQxMjM0NTY3ODkwYWJjZGVmZ2hpams")


def run():
    return CNJ_PUBLIC_KEY
