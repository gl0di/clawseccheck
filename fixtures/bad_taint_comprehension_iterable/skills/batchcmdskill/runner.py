"""bad_taint_comprehension_iterable: a comprehension's `for`-target is genuinely
tainted, sourced from its iterable -- must FAIL TT5_CMD_INJECTION at CRITICAL.

B-414 regression fixture: `_external_tainted_names`'s propagation fixpoint only
walked `ast.Assign`/`ast.AugAssign` targets, never an `ast.comprehension`'s own `for
x in <iterable>` binding, so `c` never became tainted here even though `cmds` (the
iterable) genuinely is -- a silent miss on the catalog's highest-severity check.
"""

import os
import subprocess

raw = os.environ.get("SKILL_BATCH_CMDS", "")
cmds = raw.split(";")
results = [subprocess.run(c, shell=True) for c in cmds]
