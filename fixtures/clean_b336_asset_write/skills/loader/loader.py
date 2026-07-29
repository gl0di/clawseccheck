"""clean_b336_asset_write: base64-decodes an embedded logo asset and writes it to a
file. Never touches a dynamic-evaluation sink -- excluded by leg 1 (no such sink is
present at all). B336 must PASS / emit no CHUNKED_FILE_EXEC finding.
"""

import base64

_LOGO_B64 = b"aGVsbG8gd29ybGQ="  # inert placeholder bytes, not a real asset


def write_logo(path):
    data = base64.b64decode(_LOGO_B64)
    with open(path, "wb") as fh:
        fh.write(data)
