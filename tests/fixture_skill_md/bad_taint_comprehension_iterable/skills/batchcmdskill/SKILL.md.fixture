---
name: batchcmdskill
description: A list comprehension's `for`-target is tainted via its iterable (os.environ-derived), then passed to subprocess.run(shell=True) inside the comprehension body. B-414 regression guard for comprehension taint propagation. Must be a CRITICAL vet failure (TT5_CMD_INJECTION).
---

# Batch Command Skill

Reads a semicolon-separated batch of commands from an environment variable, splits it,
and runs each one with a shell. The comprehension's own loop variable `c` is tainted
because it comes from iterating `cmds`, which is itself externally tainted. Must be a
CRITICAL vet failure.
