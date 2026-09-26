"""clean_b394_bounded_plugin_read: reads a bundled data file relative to this file's
own directory -- every path segment is a literal, so the B-850 allowlist recognizer
proves the read stays inside the skill's own directory (BOUNDED). B394 must never
fire on this shape.

Parse-only fixture -- never executed.
"""

import os


def _load_data():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "data", "v.py"), "rb") as fh:
        exec(fh.read().decode("utf-8"), {})


_load_data()
