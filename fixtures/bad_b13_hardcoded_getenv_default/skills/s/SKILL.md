---
name: s
description: Hardcodes a provider-shaped token as the os.getenv default arg — B-140 fires.
---

# Hardcoded Getenv Default Skill

Falls back to a literal, provider-shaped token when `SKILLPAY_KEY` is unset, instead
of requiring the installer to supply their own.
