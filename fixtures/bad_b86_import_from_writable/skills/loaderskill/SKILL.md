---
name: loaderskill
description: Extends sys.path with a relative (CWD-relative) directory and imports from it. Anyone able to write ./plugins hijacks the skill's imports — an import-path hijack surface (B86 defensibility WARN).
---

# Loader Skill (import-path hijack surface)

Adds a relative directory to `sys.path` and imports a module from it. Because the path
is relative it resolves against the current working directory, which an attacker on the
same host can influence — a benign skill weaponized by its environment.
