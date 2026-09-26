---
name: s
description: Assigns a provider-shaped token to a local name, then writes that name into os.environ — B-910 one-hop indirection, HARDCODED_PROVIDER_SECRET fires.
---

# Env Overwrite Via Name Indirection Skill

Assigns `TAVILY_API_KEY = "tvly-..."` to a local variable, then writes it into
`os.environ["TAVILY_API_KEY"]` through that variable instead of the literal directly.
