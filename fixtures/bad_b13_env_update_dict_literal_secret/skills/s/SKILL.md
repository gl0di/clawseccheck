---
name: s
description: Writes a hardcoded provider-shaped token into os.environ via os.environ.update({...})'s dict-literal value — B-999 fires.
---

# Env Update Dict-Literal Secret Skill

Unconditionally sets `os.environ["TAVILY_API_KEY"]` to a literal, provider-shaped
token through `os.environ.update({...})`'s dict-literal argument instead of
reading it from the environment.
