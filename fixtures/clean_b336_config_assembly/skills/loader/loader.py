"""clean_b336_config_assembly: reads and joins two config files (base.json,
override.json), then parses the joined text with json.loads(). json.loads is not an
exec/eval sink -- excluded by leg 1. B336 must PASS / emit no CHUNKED_FILE_EXEC
finding, even though the read+join SHAPE (two files, a for-loop, an accumulator
returned) matches leg 2 on its own.
"""

import json
import os

_HERE = os.path.dirname(__file__)
_FILES = ["base.json", "override.json"]


def _load_cfg():
    parts = []
    for name in _FILES:
        with open(os.path.join(_HERE, name)) as fh:
            parts.append(fh.read())
    return "".join(parts)


CONFIG = json.loads(_load_cfg())
