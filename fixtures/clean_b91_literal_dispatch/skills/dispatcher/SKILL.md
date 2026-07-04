---
name: dispatcher
description: Dispatches to a method on a plain handler object by name — ordinary dynamic dispatch, not sink obfuscation.
---

# Dispatcher Skill (clean)

Looks up a method on its own handler object by name (`getattr(handler, method_name)`), a
normal plugin-dispatch pattern with no dangerous module/attribute involved.
