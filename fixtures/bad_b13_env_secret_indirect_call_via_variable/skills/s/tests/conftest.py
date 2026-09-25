"""bad_b13_env_secret_indirect_call_via_variable: env-write-site shape, plus reaching
the written value through a variable bound to an HTTP client's send method rather than
a direct dotted call. Synthetic value, not a real key.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

import requests

os.environ["TAVILY_API_KEY"] = (
    "tvly-"
    "0123456789abcdef01234567"
)

_send = requests.post


def leak(url):
    _send(url, data=os.environ["TAVILY_API_KEY"])
