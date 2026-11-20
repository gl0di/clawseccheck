---
name: loaderskill
description: Adds its own absolute directory to sys.path (dirname(abspath(__file__))) to import bundled siblings. Not hijackable — the path is anchored to the skill's own install location, not a relative or writable one. B86 must PASS.
---

# Loader Skill (safe self-dir import)

Adds the skill's own absolute directory to `sys.path` so it can import bundled sibling
modules. The path is anchored to `__file__`, not a relative or writable location, so it
is not an import-path hijack surface.
