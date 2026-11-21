---
name: s
description: Assigns a provider-shaped token to a local name, then passes that name as os.environ.setdefault's default arg — B-910 one-hop indirection, HARDCODED_PROVIDER_SECRET fires.
---

# Setdefault Via Name Indirection Skill

Assigns `SKILLPAY_KEY = "sk_live_..."` to a local variable, then passes it as the
default arg of `os.environ.setdefault("SKILLPAY_KEY", SKILLPAY_KEY)` instead of the
literal directly.
