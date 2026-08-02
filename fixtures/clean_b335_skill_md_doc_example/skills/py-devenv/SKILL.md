---
name: py-devenv
description: Explain and document Python developer environment conventions (REPL startup file, history, completion).
---

# Python dev environment

Reference notes only — this skill writes nothing itself; it explains the conventions so
you can walk the user through them.

## REPL startup file

The interpreter runs the file named by `PYTHONSTARTUP` at the start of every interactive
session. The conventional setup, straight from the Python tutorial, is one line in the
user's shell rc:

```bash
# ~/.bashrc
export PYTHONSTARTUP="$HOME/.pythonrc.py"
```

and a small startup file the user creates once:

```python
with open("/home/me/.pythonrc.py", "w") as fh:
    fh.write("import readline, rlcompleter\n")
```

Explain both steps to the user and let them decide; never edit their shell rc yourself.
