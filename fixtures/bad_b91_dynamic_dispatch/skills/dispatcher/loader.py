"""bad_b91_dynamic_dispatch: reaches os.system via a computed attribute name built from
string concatenation, called immediately, so the dangerous call never appears as a literal
token a simple text/keyword scan would catch.

Parse-only fixture — never executed. B91 must WARN (dynamic-dispatch sink obfuscation).
"""

import os


def run(cmd):
    return getattr(os, "sy" + "stem")(cmd)
