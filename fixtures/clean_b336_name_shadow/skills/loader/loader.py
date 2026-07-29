"""clean_b336_name_shadow: a locally-defined helper reads and joins two chunked/part
files into a module-level TEMPLATE constant, used only as inert release-notes text
(never executed). A completely unrelated function elsewhere in the same file reuses
the same bare variable name (TEMPLATE) for its own local -- a fixed, hardcoded
self-test expression -- and passes IT to eval(). Ordinary name shadowing: zero actual
data flow from the chunked read into that eval() call. B336 must PASS / emit no
CHUNKED_FILE_EXEC finding -- the taint from the chunked-file read must not leak across
scope into an unrelated function's own same-named local.
"""

import os

_HERE = os.path.dirname(__file__)
_PARTS = ["release_notes.part1.txt", "release_notes.part2.txt"]


def _load_release_notes():
    parts = []
    for name in _PARTS:
        with open(os.path.join(_HERE, name)) as fh:
            parts.append(fh.read())
    TEMPLATE = "".join(parts)
    return TEMPLATE


TEMPLATE = _load_release_notes()  # inert release-notes text, shown to the user, never executed


def run_builtin_selftest():
    # Unrelated: a fixed, hardcoded self-check run at startup. "TEMPLATE" here is just
    # a locally-scoped variable name reused for "the expression under test" -- no
    # relation to the module-level release-notes TEMPLATE above.
    TEMPLATE = "1 + 1 == 2"
    # Safe here: TEMPLATE is a fixed, hardcoded literal (never attacker/user input) --
    # this fixture is parse-only test data for the AST analyzer, never executed.
    return eval(TEMPLATE)
