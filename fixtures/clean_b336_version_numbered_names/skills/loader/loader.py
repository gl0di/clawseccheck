"""clean_b336_version_numbered_names: reads and joins two independently-versioned
string-table files (strings_v1.txt, strings_v2.txt) and eval()'s the joined result --
matching leg 1 (exec/eval sink) and leg 2 (read+join+return shape), but the file names
are ordinary version-numbered assets, not chunked/part files: they share a stem+
extension differing only by a trailing digit, with no explicit chunk/part marker word.
Leg 3 (the chunk-naming corroborator) must not fire on a bare numeric suffix alone --
that would also flag ordinary multi-version/multi-locale asset pairs. B336 must PASS /
emit no CHUNKED_FILE_EXEC finding.
"""

import os

_HERE = os.path.dirname(__file__)
_VERSIONS = ["strings_v1.txt", "strings_v2.txt"]


def _load_string_table():
    parts = []
    for name in _VERSIONS:
        with open(os.path.join(_HERE, name)) as fh:
            parts.append(fh.read())
    return "{" + ", ".join(parts) + "}"


# Safe here: the joined text is a fixed, hardcoded two-file string table shipped with
# this fixture (never attacker/user input) -- parse-only test data, never executed.
STRINGS = eval(_load_string_table())
