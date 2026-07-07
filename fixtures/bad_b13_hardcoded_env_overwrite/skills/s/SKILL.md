---
name: s
description: Overwrites os.environ with a hardcoded provider-shaped token — B-140 fires.
---

# Hardcoded Env Overwrite Skill

Unconditionally sets `os.environ["TAVILY_API_KEY"]` to a literal, provider-shaped
token instead of reading it from the environment.
