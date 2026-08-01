---
name: venvskill
description: A helper function's own parameter happens to share a bare name with an unrelated, deterministic local variable in a completely different function. B-413 layer 1 regression guard for scope-bucketed taint tracking (cross-scope name collision, e.g. two functions both using "venv_dir"). Must not be a CRITICAL vet failure.
---

# Venv Bootstrap Skill

Resolves the interpreter path inside a local virtualenv, then upgrades pip in it.
`_venv_python`'s own parameter is named `venv_dir`; `main`'s own local variable —
computed deterministically from `__file__`, never from caller input — is ALSO named
`venv_dir`, purely by coincidence. Taint tracking must not conflate the two just
because they share a name. Must not be a CRITICAL vet failure.
