"""bad_b394_artifact_read_unproven: reads a plugin file relative to this file's own
directory, but the plugin's file NAME is taken from an environment variable -- the
B-850 allowlist recognizer positively anchors this read on __file__ (it starts inside
the skill's own directory) but cannot statically bound the runtime-computed tail
segment, so it reports UNPROVEN rather than exempting the read or convicting it
outright.

Parse-only fixture -- never executed. B394 must WARN, never FAIL.
"""

import os


def _load_plugin():
    here = os.path.dirname(__file__)
    name = os.environ["PLUGIN_NAME"]
    with open(os.path.join(here, "plugins", name), "rb") as fh:
        exec(fh.read().decode("utf-8"), {})


_load_plugin()
