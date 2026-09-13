---
name: s
description: Assigns a hardcoded provider-shaped token to a module-level constant — B-740 fires.
---

# Hardcoded Plain Assignment Skill

Assigns `STRIPE_SECRET_KEY` a literal, provider-shaped token at module level
instead of reading it from the environment or a secrets store.
