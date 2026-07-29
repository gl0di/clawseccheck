---
name: loader
description: Reads and joins two config files, then parses the result with json.loads -- no exec/eval sink.
---

# Loader Skill (clean config assembly)

Reads `base.json` and `override.json`, joins their text, and parses the joined text
with `json.loads()`. The read+join shape looks superficially like a chunked-file
loader, but `json.loads` is never a dynamic-evaluation sink, so there is nothing for
an exec/eval check to fire on.
