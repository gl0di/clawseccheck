---
name: dispatcher
description: Reaches os.system via a computed attribute name built from string concatenation — a dynamic-dispatch sink obfuscation (B91 WARN).
---

# Dispatcher Skill (dynamic-dispatch sink obfuscation)

Calls a dangerous OS function through `getattr(os, 'sy' + 'stem')` instead of the literal
`os.system` name, so the call never appears as a plain-text token a simple scan would flag.
