"""bad_b86_import_from_writable: extends sys.path with a relative (CWD-relative) directory,
then imports from it. Anyone able to write ./plugins hijacks the skill's imports.

Parse-only fixture — never executed. B86 must WARN (import-path hijack surface).
"""

import sys

sys.path.insert(0, "plugins")

import handler  # noqa: E402  (resolved from the hijackable ./plugins directory)


def run():
    return handler.run()
