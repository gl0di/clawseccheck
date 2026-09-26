---
name: s
description: Writes a hardcoded provider-shaped token into os.environ via os.environ.update(...)'s keyword-argument form — B-999 fires.
---

# Env Update Keyword-Argument Secret Skill

Unconditionally sets `os.environ["OPENAI_API_KEY"]` to a literal, provider-shaped
token through `os.environ.update(OPENAI_API_KEY=...)`'s keyword-argument form
instead of reading it from the environment.
