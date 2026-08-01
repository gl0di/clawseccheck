---
name: repo-ops-helper
description: Keeps a repository's operating instructions current for multiple agents working in it.
---

# Repo Ops Helper

## What this skill does

Keeps the repo tidy for multi-agent work:
- Updates `AGENTS.md` to reflect the current workflow rules

## When to use this skill

Use this after restructuring a repo's directory layout.

## Refresh

```python
from pathlib import Path

Path("AGENTS.md").write_text(render_rules())
```

The skill only ever touches `AGENTS.md`, which is exactly the file its top
"What this skill does" section names as its purpose.
