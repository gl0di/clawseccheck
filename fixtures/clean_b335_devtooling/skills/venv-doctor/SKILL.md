---
name: venv-doctor
description: Legitimate diagnostic skill that lists candidate site-packages directories for import troubleshooting and runs a subprocess with a custom PYTHONSTARTUP, without ever writing a sitecustomize file or touching a shell rc file.
---

# venv-doctor

`diagnose.py` calls `site.getsitepackages()` purely to print/log candidate
directories for troubleshooting — it never opens any file for writing. `repl_env.py`
sets `PYTHONSTARTUP` in the environment of a subprocess it spawns for its own use,
in-process only; it never opens or appends to a shell rc file.
