"""clean_b86_import_self_dir: sys.path anchored to the skill's own absolute directory —
not a relative or writable location, so it is not an import-path hijack surface.

Parse-only fixture — never executed. B86 must PASS.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from . import helper  # noqa: E402,F401  (bundled sibling, resolved from the skill's own dir)
